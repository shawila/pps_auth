mod config;
mod crypto;
mod db;
mod error;
mod models;

use axum::{routing::get, Router};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let config = config::Config::from_env()?;
    let _pool = db::connect(&config.database_url).await?;
    tracing::info!("Database connected and migrated");
    let app = Router::new().route("/health", get(|| async { "ok" }));
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("pps_auth listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
