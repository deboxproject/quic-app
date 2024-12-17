use quinn::{Endpoint, RecvStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Deserialize;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use log::{error, info};
use rustls::pki_types::pem::PemObject;

#[derive(Deserialize)]
struct Data {
    sender: String,
    temperature: f32,
}

pub struct ServerOptions {
    pub name: String,
    pub listen: SocketAddr,
    pub key: Option<PathBuf>,
    pub cert: Option<PathBuf>,
}

pub async fn run_server(opts: Arc<ServerOptions>) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let server_config = configure_server(&opts)?;
    info!("[{}] Server dimulai...",  opts.name);
    let endpoint = Endpoint::server(server_config, opts.listen)?;

    info!("[{}] Server berjalan pada {}",  opts.name, opts.listen);

    while let Some(connection) = endpoint.accept().await {
        info!("[{}] Permintaan koneksi...", opts.name);
        let opts = Arc::clone(&opts);
        tokio::spawn(async move {
            match connection.await {
                Ok(conn) => {
                    info!("[{}] Koneksi baru dari: {}", opts.name, conn.remote_address());
                    while let Ok(stream) = conn.accept_uni().await {
                        let opts = Arc::clone(&opts);
                        tokio::spawn(async move {
                            if let Err(e) = handle_stream(stream, &opts).await {
                                error!("[{}]Error in stream handler: {}", opts.name, e);
                            }
                        });
                    }
                }
                Err(e) => {
                    error!("[{}]Connection failed: {}", opts.name, e);
                }
            }
        });
    }

    Ok(())
}

async fn handle_stream(mut stream: RecvStream, opts: &ServerOptions) -> Result<(), Box<dyn Error>> {
    info!("[{}] Parsing data...", opts.name);
    let message = stream.read_to_end(usize::MAX).await?; // Baca data dari stream
    let data: Result<Data, _> = serde_json::from_slice(&message);
    match &data {
        Ok(data) => {
            info!("[{}] Data diterima dari device '{}' dengan temperatur: {:.2}", opts.name, data.sender, data.temperature);
        }
        Err(e) => {
            // Jika tidak dapat mem-parsing ke Message, coba log data mentah
            error!("[{}] Gagal mem-parsing JSON: {}, Data: {}", opts.name, e, String::from_utf8_lossy(&message));
        }
    }
    Ok(())
}

pub fn configure_server(opts: &ServerOptions
) -> Result<ServerConfig, Box<dyn Error + Send + Sync + 'static>> {
    let (certs, priv_key) = if let (Some(cert_path), Some(key_path)) = (&opts.cert, &opts.key) {
        let key = PrivateKeyDer::from_pem_file(key_path)?;

        let cert_chain = CertificateDer::from_pem_file(cert_path)?;
        (vec![cert_chain], key)
    } else {

            let cert_key = rcgen::generate_simple_self_signed(vec!["lambdasolusi".into()]).unwrap();
            let cert_der = CertificateDer::from(cert_key.cert);
            let priv_key = PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der());
        (vec![cert_der.clone()], priv_key.into())
    };
    let mut server_config =
        ServerConfig::with_single_cert(certs, priv_key.into())?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(1_u8.into()); // Izinkan hingga 100 stream

    Ok(server_config)

}
