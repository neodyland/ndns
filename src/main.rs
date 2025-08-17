use dotenvy::dotenv;
use hickory_server::Server;
use log::LevelFilter;
use std::sync::Arc;
use tokio::sync::Mutex;

mod config;
mod dns;

async fn main_inner() -> anyhow::Result<()> {
    let conf = config::Configure::new()?;
    let blocklist = conf.build_blocklist().await?;
    let (upstream, upstream_handle) = conf.spawn_upstream().await?;
    let handler = dns::DnsHandler::new(Arc::new(Mutex::new(upstream)), blocklist);
    let mut server = Server::new(handler);
    conf.register_sockets(&mut server).await?;
    let server_handle = server.block_until_done();
    tokio::select! {
        _ = upstream_handle => {
            log::error!("Upstream client connection closed unexpectedly.");
        }
        _ = server_handle => {
            log::info!("DNS server stopped.");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    #[cfg(debug_assertions)]
    let log_level = LevelFilter::Debug;
    #[cfg(not(debug_assertions))]
    let log_level = LevelFilter::Info;
    dotenv().ok();
    env_logger::builder()
        .filter_level(LevelFilter::Warn)
        .filter(Some("ndns"), log_level)
        .init();
    if let Err(e) = main_inner().await {
        log::error!("Error occurred: {e}");
    }
}
