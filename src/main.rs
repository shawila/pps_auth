use pps_auth::build_router;
use std::{net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = pps_auth::config::Config::from_env()?;
    let pool = pps_auth::db::connect(&config.database_url).await?;
    let app_state = Arc::new(pps_auth::state::AppState::new(pool, &config)?);
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("pps_auth listening on {addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, build_router(app_state)).await?;
    Ok(())
}
