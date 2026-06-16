mod config;
mod error;

use axum::{routing::get, Router};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let config = config::Config::from_env()?;
    let app = Router::new().route("/health", get(|| async { "ok" }));
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
