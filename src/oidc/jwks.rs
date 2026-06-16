use axum::{extract::State, Json};
use serde_json::Value;
use std::sync::Arc;
use crate::state::AppState;

pub async fn handler(State(state): State<Arc<AppState>>) -> Json<Arc<Value>> {
    Json(Arc::clone(&state.jwks))
}
