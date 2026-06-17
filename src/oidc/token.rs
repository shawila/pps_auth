use axum::{extract::State, Form, Json};
use jsonwebtoken::{Algorithm, Header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::OffsetDateTime;
use crate::{
    crypto,
    error::{AppError, Result},
    models::{authorization_code::AuthorizationCode, refresh_token::RefreshToken, role::Role, user::User},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub id_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
    pub email: String,
    pub name: Option<String>,
    pub roles: Vec<String>,
}

pub async fn handler(
    State(app): State<Arc<AppState>>,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>> {
    let client = crate::models::oauth_client::OauthClient::find(&app.pool, &req.client_id)
        .await?
        .ok_or(AppError::UnauthorizedClient)?;
    if !crypto::verify_hashed_secret(&req.client_secret, &client.client_secret_hash) {
        return Err(AppError::InvalidClient);
    }

    match req.grant_type.as_str() {
        "authorization_code" => code_exchange(&app, &req, &client.client_id).await,
        "refresh_token" => refresh_grant(&app, &req, &client.client_id).await,
        _ => Err(AppError::InvalidGrant("unsupported grant_type".to_string())),
    }
}

async fn code_exchange(
    app: &AppState,
    req: &TokenRequest,
    client_id: &str,
) -> Result<Json<TokenResponse>> {
    let code = req.code.as_deref().ok_or_else(|| AppError::InvalidGrant("code required".to_string()))?;
    let verifier = req.code_verifier.as_deref().ok_or_else(|| AppError::InvalidGrant("code_verifier required".to_string()))?;

    let code_hash = crypto::hash_token(code);
    let auth_code = AuthorizationCode::consume(&app.pool, &code_hash)
        .await?
        .ok_or_else(|| AppError::InvalidGrant("code expired or already used".to_string()))?;

    if auth_code.client_id != client_id {
        return Err(AppError::InvalidGrant("code was issued to a different client".to_string()));
    }
    if !crypto::verify_pkce(verifier, &auth_code.pkce_challenge) {
        return Err(AppError::InvalidGrant("invalid code_verifier".to_string()));
    }

    // Nonce is optional; the current schema does not persist it on the auth code.
    let nonce: Option<String> = None;

    issue_tokens(app, auth_code.user_id, client_id, nonce).await
}

async fn refresh_grant(
    app: &AppState,
    req: &TokenRequest,
    client_id: &str,
) -> Result<Json<TokenResponse>> {
    let rt = req.refresh_token.as_deref().ok_or_else(|| AppError::InvalidGrant("refresh_token required".to_string()))?;
    let rt_hash = crypto::hash_token(rt);

    let old_token = RefreshToken::find_valid(&app.pool, &rt_hash)
        .await?
        .ok_or_else(|| AppError::InvalidGrant("refresh_token expired or revoked".to_string()))?;

    if old_token.client_id != client_id {
        return Err(AppError::InvalidGrant("token was issued to a different client".to_string()));
    }

    RefreshToken::revoke(&app.pool, &rt_hash).await?;
    issue_tokens(app, old_token.user_id, client_id, None).await
}

async fn issue_tokens(
    app: &AppState,
    user_id: uuid::Uuid,
    client_id: &str,
    nonce: Option<String>,
) -> Result<Json<TokenResponse>> {
    let user = sqlx::query_as!(
        User,
        "SELECT id, email, name, created_at FROM pps_auth.users WHERE id = $1",
        user_id
    )
    .fetch_one(&app.pool)
    .await?;

    let roles = Role::for_user_and_client(&app.pool, user_id, client_id).await?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let exp = now + 900; // 15 minutes

    let claims = Claims {
        iss: app.base_url.clone(),
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        exp,
        iat: now,
        nonce,
        email: user.email,
        name: user.name,
        roles,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("1".to_string());
    let id_token = jsonwebtoken::encode(&header, &claims, &app.encoding_key)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("JWT encode error: {e}")))?;

    let rt_plain = crypto::generate_token();
    let rt_hash = crypto::hash_token(&rt_plain);
    RefreshToken::create(&app.pool, user_id, client_id, &rt_hash).await?;

    Ok(Json(TokenResponse {
        access_token: id_token.clone(),
        token_type: "Bearer".to_string(),
        expires_in: 900,
        id_token,
        refresh_token: rt_plain,
    }))
}
