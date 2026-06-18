use axum::{extract::State, Form, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use crate::{crypto, error::Result, models::refresh_token::RefreshToken, state::AppState};

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub token: String,
}

pub async fn handler(
    State(app): State<Arc<AppState>>,
    Form(req): Form<RevokeRequest>,
) -> Result<StatusCode> {
    let hash = crypto::hash_token(&req.token);
    RefreshToken::revoke(&app.pool, &hash).await?;
    Ok(StatusCode::OK)
}
