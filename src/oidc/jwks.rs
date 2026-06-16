use axum::{extract::State, Json};
use serde_json::Value;
use std::sync::Arc;
use crate::state::AppState;

pub async fn handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(state.jwks.clone())
}
