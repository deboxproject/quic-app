mod libs;

use std::io::Write;
use libs::client::run_client;
use libs::server::run_server;
use std::error::Error;
use std::sync::Arc;
use structopt::StructOpt;
use log::{info, error};


#[derive(StructOpt, Debug)]
pub struct GlobalOptions {
    #[structopt(short="p", long, default_value = "4433")]
    pub socket_port: u16,

    #[structopt(short="b", long, default_value = "0.0.0.0")]
    pub socket_binding: String,

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
    },
    /// Jalankan client
    Client {
        #[structopt(flatten)]
        opts: GlobalOptions,
        /// Host dari server yang akan dihubungkan
        #[structopt(short="u", long, default_value = "127.0.0.1:4433")]
        server_url: String,
    },
}

impl GlobalOptions {
    pub fn get_socket_addr(&self) -> String {
        format!("{}:{}", self.socket_binding, self.socket_port)
    }
}

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
        Command::Server { opts } => {
            info!(
                "Memulai server '{}' pada alamat {}:{}",
                opts.name, opts.socket_binding, opts.socket_port
            );
            let opts = Arc::new(opts);
            if let Err(e) = run_server(opts).await {
                error!("Server gagal dijalankan: {}", e);
            } else {
                info!("Server berhenti dengan sukses");
            }
        }
        Command::Client { opts, server_url } => {
            info!(
                "Memulai client '{}' untuk terhubung ke server di {}",
                opts.name, server_url
            );
            if let Err(e) = run_client(server_url, &opts).await {
                error!("Client gagal dijalankan: {}", e);
            } else {
                info!("Client selesai dijalankan dengan sukses");
            }
        }
    }

    Ok(())
}
