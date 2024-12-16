use crate::GlobalOptions;
use proto::crypto::rustls::QuicClientConfig;
use proto::ClientConfig;
use quinn::Endpoint;
use rand::Rng;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use log::{error, info};
use tokio::time;
use serde::Serialize;

#[derive(Serialize)]
struct Data {
    sender: String,
    temperature: f32,
}

pub async fn run_client(server_url: String, opts: &GlobalOptions) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let server_addr = opts.get_socket_addr().parse::<SocketAddr>()?;

    info!("Connecting to server at {}", server_addr);

    let mut rng = rand::thread_rng();
    let interval = Duration::from_secs(5);

    // Configure TLS
    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");
    let rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    let client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config)?));

    let endpoint = Endpoint::client(server_addr)?;

    loop {
        info!("[{}] Mencoba koneksi...", opts.name);
        match endpoint.connect_with(client_config.clone(), server_url.parse()?, &opts.name)?.await {
            Ok(connection) => {
                info!("[{}] Server berhasil terkoneksi", opts.name);

                loop {
                    let temperature: f32 = rng.gen_range(20.0..35.0);
                    let data = Data {
                        sender: opts.name.clone(),
                        temperature: temperature,
                    };
                    info!("[{}] Kirim data temperatur: {:.2}", opts.name, data.temperature);

                    match connection.open_uni().await {
                        Ok(mut stream) => {
                            let data = serde_json::to_vec(&data)?;
                            if let Err(e) = stream.write_all(&data).await {
                                error!("[{}] Gagal mengirim data: {}", opts.name, e);
                            }
                            if let Err(e) = stream.finish() {
                                error!("[{}] Gagal menyelesaikan stream: {}", opts.name, e);
                            }
                        }
                        Err(e) => {
                            error!("[{}] Gagal membuka stream: {}", opts.name, e);
                            break;
                        }
                    }

                    time::sleep(interval).await;
                }
            }
            Err(e) => {
                eprintln!("[{}] Gagal terkoneksi: {}", opts.name, e);
                time::sleep(Duration::from_secs(5)).await; // Retry delay
            }
        }
    }
}


/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);


impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
