use crate::GlobalOptions;
use quinn::{Endpoint, RecvStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::Deserialize;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use log::{error, info};

#[derive(Deserialize)]
struct Data {
    sender: String,
    temperature: f32,
}

pub async fn run_server(opts: Arc<GlobalOptions>) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let server_addr = opts.get_socket_addr().parse::<SocketAddr>()?;
    let (server_config, _server_cert) = configure_server()?;
    info!("[{}] Server dimulai...",  opts.name);
    let endpoint = Endpoint::server(server_config, server_addr)?;

    info!("[{}] Server berjalan pada {}",  opts.name, server_addr);

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

async fn handle_stream(mut stream: RecvStream, opts: &GlobalOptions) -> Result<(), Box<dyn Error>> {
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

pub fn configure_server(
) -> Result<(ServerConfig, CertificateDer<'static>), Box<dyn Error + Send + Sync + 'static>> {
    let cert = rcgen::generate_simple_self_signed(vec!["lambdasolusi".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_config =
        ServerConfig::with_single_cert(vec![cert_der.clone()], priv_key.into())?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(1_u8.into()); // Izinkan hingga 100 stream

    Ok((server_config, cert_der))
}
