mod config;
mod crypto;
mod db;
mod error;
mod models;
mod state;

use axum::{extract::State, routing::get, Json, Router};
use std::{net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let config = config::Config::from_env()?;
    let pool = db::connect(&config.database_url).await?;
    let app_state = Arc::new(state::AppState::new(pool, &config)?);

    let app = Router::new()
        .route("/health", get(health))
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("pps_auth listening on {addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn health(State(state): State<Arc<state::AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "base_url": state.base_url }))
}
