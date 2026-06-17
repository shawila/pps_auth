pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod models;
pub mod oidc;
pub mod state;

use axum::{extract::State, routing::get, Json, Router};
use std::sync::Arc;

pub fn build_router(state: Arc<state::AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/.well-known/openid-configuration", get(oidc::discovery::handler))
        .route("/.well-known/jwks.json", get(oidc::jwks::handler))
        .route("/authorize", get(oidc::authorize::handler))
        .with_state(state)
}

async fn health(State(state): State<Arc<state::AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "base_url": state.base_url }))
}
