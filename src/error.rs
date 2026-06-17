use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized_client")]
    UnauthorizedClient,
    #[error("invalid_grant")]
    InvalidGrant(String),
    #[error("redirect_uri_mismatch")]
    RedirectUriMismatch,
    #[error("invalid_token")]
    InvalidToken,
    #[error("invalid_client")]
    InvalidClient,
    #[error("unsupported_response_type")]
    UnsupportedResponseType,
    #[error("server_error: {0}")]
    Internal(#[from] anyhow::Error),
    #[error("server_error: {0}")]
    Db(#[from] sqlx::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, desc) = match &self {
            AppError::UnauthorizedClient => (StatusCode::UNAUTHORIZED, "unauthorized_client", "Unknown client_id".to_string()),
            AppError::InvalidGrant(m) => (StatusCode::BAD_REQUEST, "invalid_grant", m.clone()),
            AppError::RedirectUriMismatch => (StatusCode::BAD_REQUEST, "redirect_uri_mismatch", "redirect_uri mismatch".to_string()),
            AppError::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid_token", "Invalid or expired token".to_string()),
            AppError::InvalidClient => (StatusCode::UNAUTHORIZED, "invalid_client", "Invalid client credentials".to_string()),
            AppError::UnsupportedResponseType => (StatusCode::BAD_REQUEST, "unsupported_response_type", "only code response_type is supported".to_string()),
            AppError::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string()),
            AppError::Db(e) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string()),
        };
        (status, Json(json!({ "error": code, "error_description": desc }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
