mod libs;

use std::io::Write;
use libs::client::run_client;
use libs::server::run_server;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use log::{info, error};
use crate::libs::client::ClientOptions;
use crate::libs::server::ServerOptions;

#[derive(StructOpt, Debug)]
pub struct GlobalOptions {
    #[structopt(short="n", long)]
    pub name: String,
}

#[derive(StructOpt, Debug)]
#[structopt(name = "aplikasi_quic", about = "Aplikasi Client-Server menggunakan QUIC")]
enum Command {
    /// Jalankan server
    Server {
        #[structopt(flatten)]
        opts: GlobalOptions,
        #[structopt(short="l", long, default_value = "[::]:4433")]
        listen: SocketAddr,
        #[structopt(short="k", long, requires="cert")]
        key: Option<PathBuf>,
        #[structopt(short="c", long, requires="key")]
        cert: Option<PathBuf>
    },
    /// Jalankan client
    Client {
        #[structopt(flatten)]
        opts: GlobalOptions,
        /// Host dari server yang akan dihubungkan
        #[structopt(short="u", long="url", default_value = "127.0.0.1:4433")]
        url: String,
        #[structopt(long)]
        ca: Option<PathBuf>,
        #[structopt(long, default_value = "[::]:0")]
        bind: SocketAddr
    },
}

impl GlobalOptions {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    env_logger::Builder::from_default_env()
        .format(|buf, record| {
            use std::time::SystemTime;
            let timestamp = SystemTime::now();
            writeln!(
                buf,
                "[{}] [{}] - {}",
                timestamp
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                record.level(),
                record.args()
            )
        })
        .filter_level(log::LevelFilter::Info)
        .init();
    match Command::from_args() {
        Command::Server { listen, key, cert, opts } => {
            info!(
                "Memulai server '{}' pada alamat {}:{}",
                opts.name, listen.ip(), listen.port()
            );
            let server_options = ServerOptions {
                listen,
                key,
                cert,
                name: opts.name.clone()
            };
            let server_options = Arc::new(server_options);
            if let Err(e) = run_server(server_options).await {
                error!("Server gagal dijalankan: {}", e);
            } else {
                info!("Server berhenti dengan sukses");
            }
        }
        Command::Client { opts, url, bind, ca } => {
            info!(
                "Memulai client '{}' untuk terhubung ke server di {}",
                opts.name, url
            );
            let client_options = ClientOptions {
                name: opts.name.clone(),
                bind,
                url,
                ca,
            };
            if let Err(e) = run_client(&client_options).await {
                error!("Client gagal dijalankan: {}", e);
            } else {
                info!("Client selesai dijalankan dengan sukses");
            }
        }
    }

    Ok(())
}
