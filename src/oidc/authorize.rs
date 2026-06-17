use axum::{
    extract::{Query, State},
    response::Redirect,
};
use serde::Deserialize;
use std::sync::Arc;
use crate::{crypto, error::{AppError, Result}, state::{AppState, AuthSession}};

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

pub async fn handler(
    State(app): State<Arc<AppState>>,
    Query(params): Query<AuthorizeParams>,
) -> Result<Redirect> {
    if params.response_type != "code" {
        return Err(AppError::InvalidGrant("unsupported_response_type".to_string()));
    }
    if params.code_challenge_method != "S256" {
        return Err(AppError::InvalidGrant("only S256 PKCE is supported".to_string()));
    }

    let client = crate::models::oauth_client::OauthClient::find(&app.pool, &params.client_id)
        .await?
        .ok_or(AppError::UnauthorizedClient)?;

    if !client.has_redirect_uri(&params.redirect_uri) {
        return Err(AppError::RedirectUriMismatch);
    }

    let session_id = crypto::generate_token();
    let scopes = params
        .scope
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect();

    app.auth_sessions.insert(
        session_id.clone(),
        AuthSession {
            client_id: params.client_id,
            redirect_uri: params.redirect_uri,
            pkce_challenge: params.code_challenge,
            scopes,
            nonce: params.nonce,
            state: params.state,
        },
    );

    Ok(Redirect::to(&format!("/login?session={session_id}")))
}
