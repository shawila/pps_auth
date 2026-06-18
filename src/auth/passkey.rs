use axum::{extract::State, Json};
use base64ct::Encoding;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use crate::{
    crypto,
    error::{AppError, Result},
    models::{authorization_code::AuthorizationCode, credential::Credential, user::User},
    state::AppState,
};

// ── Registration ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterStartRequest {
    pub email: String,
    pub session_id: String,
}

pub async fn register_start(
    State(app): State<Arc<AppState>>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<Value>> {
    let user_id = Uuid::new_v4();
    let (ccr, reg_state) = app
        .webauthn
        .start_passkey_registration(user_id, &req.email, &req.email, None)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("WebAuthn reg start: {e}")))?;

    app.pk_registrations.insert(req.session_id.clone(), reg_state);
    let response = serde_json::to_value(ccr)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize ccr: {e}")))?;
    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct RegisterFinishRequest {
    pub session_id: String,
    pub email: String,
    pub credential: RegisterPublicKeyCredential,
}

pub async fn register_finish(
    State(app): State<Arc<AppState>>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<Json<Value>> {
    let reg_state = app
        .pk_registrations
        .remove(&req.session_id)
        .map(|(_, v)| v)
        .ok_or_else(|| AppError::InvalidGrant("registration session expired".to_string()))?;

    let passkey = app
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| AppError::InvalidGrant(format!("WebAuthn reg finish: {e}")))?;

    let user = User::upsert(&app.pool, &req.email, None).await?;
    let cred_data = serde_json::to_value(&passkey)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize passkey: {e}")))?;
    let cred_id = base64ct::Base64UrlUnpadded::encode_string(passkey.cred_id().as_ref());

    Credential::upsert(&app.pool, user.id, "passkey", &cred_id, &cred_data).await?;

    Ok(Json(json!({ "status": "registered" })))
}

// ── Authentication ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuthStartRequest {
    pub session_id: String,
}

pub async fn auth_start(
    State(app): State<Arc<AppState>>,
    Json(req): Json<AuthStartRequest>,
) -> Result<Json<Value>> {
    let credentials: Vec<Passkey> = sqlx::query!(
        "SELECT credential_data FROM pps_auth.credentials WHERE type = 'passkey'"
    )
    .fetch_all(&app.pool)
    .await?
    .into_iter()
    .filter_map(|r| serde_json::from_value(r.credential_data).ok())
    .collect();

    let (rcr, auth_state) = app
        .webauthn
        .start_passkey_authentication(&credentials)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("WebAuthn auth start: {e}")))?;

    app.pk_auths.insert(req.session_id, auth_state);
    let response = serde_json::to_value(rcr)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize rcr: {e}")))?;
    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct AuthFinishRequest {
    pub session_id: String,
    pub credential: PublicKeyCredential,
}

pub async fn auth_finish(
    State(app): State<Arc<AppState>>,
    Json(req): Json<AuthFinishRequest>,
) -> Result<Json<Value>> {
    let auth_state = app
        .pk_auths
        .remove(&req.session_id)
        .map(|(_, v)| v)
        .ok_or_else(|| AppError::InvalidGrant("auth session expired".to_string()))?;

    let result = app
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| AppError::InvalidGrant(format!("WebAuthn auth failed: {e}")))?;

    let cred_id = base64ct::Base64UrlUnpadded::encode_string(result.cred_id().as_ref());
    let cred = Credential::find_by_provider(&app.pool, "passkey", &cred_id)
        .await?
        .ok_or_else(|| AppError::InvalidGrant("credential not found".to_string()))?;

    // Update counter in DB
    let mut passkey: Passkey = serde_json::from_value(cred.credential_data.clone())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("deserialize passkey: {e}")))?;
    passkey.update_credential(&result);
    let updated_data = serde_json::to_value(&passkey)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize updated passkey: {e}")))?;
    sqlx::query!(
        "UPDATE pps_auth.credentials SET credential_data = $1 WHERE type = 'passkey' AND provider_id = $2",
        updated_data,
        cred_id
    )
    .execute(&app.pool)
    .await?;

    let auth_session = app
        .auth_sessions
        .get(&req.session_id)
        .ok_or_else(|| AppError::InvalidGrant("auth session not found".to_string()))?
        .clone();

    let code_plain = crypto::generate_token();
    let code_hash = crypto::hash_token(&code_plain);
    AuthorizationCode::create(
        &app.pool,
        &auth_session.client_id,
        cred.user_id,
        &code_hash,
        &auth_session.pkce_challenge,
        &auth_session.scopes,
    )
    .await?;

    app.auth_sessions.remove(&req.session_id);

    let mut redirect_url = auth_session.redirect_uri.clone();
    redirect_url.push_str(&format!("?code={code_plain}"));
    if let Some(state) = &auth_session.state {
        redirect_url.push_str(&format!("&state={state}"));
    }

    Ok(Json(json!({ "redirect": redirect_url })))
}
