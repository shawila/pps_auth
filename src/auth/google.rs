use axum::{
    extract::{Query, State},
    response::Redirect,
};
use oauth2::{CsrfToken, PkceCodeChallenge, Scope};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use crate::{
    crypto,
    error::{AppError, Result},
    models::{authorization_code::AuthorizationCode as DbAuthCode, credential::Credential, user::User},
    state::AppState,
};

#[derive(Deserialize)]
pub struct GoogleStartQuery {
    pub session: String,
}

pub async fn start(
    State(app): State<Arc<AppState>>,
    Query(q): Query<GoogleStartQuery>,
) -> Result<Redirect> {
    if !app.auth_sessions.contains_key(&q.session) {
        return Err(AppError::InvalidGrant("auth session not found".to_string()));
    }

    let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = app
        .google_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    app.google_states.insert(csrf_token.secret().clone(), q.session);

    Ok(Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
pub struct GoogleCallbackQuery {
    pub code: String,
    pub state: String,
}

pub async fn callback(
    State(app): State<Arc<AppState>>,
    Query(q): Query<GoogleCallbackQuery>,
) -> Result<Redirect> {
    let auth_session_id = app
        .google_states
        .remove(&q.state)
        .map(|(_, v)| v)
        .ok_or_else(|| AppError::InvalidGrant("invalid state parameter".to_string()))?;

    let auth_session = app
        .auth_sessions
        .get(&auth_session_id)
        .ok_or_else(|| AppError::InvalidGrant("auth session expired".to_string()))?
        .clone();

    // Exchange Google auth code for access token using reqwest directly
    // to avoid oauth2 crate http client version compatibility issues.
    let token_resp = app.http_client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", q.code.as_str()),
            ("client_id", app.google_client.client_id().as_str()),
            ("client_secret", app.google_client_secret.as_str()),
            ("redirect_uri", &format!("{}/auth/google/callback", app.base_url)),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Google token exchange failed: {e}")))?
        .error_for_status()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Google token endpoint error: {e}")))?
        .json::<Value>()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Google token parse failed: {e}")))?;

    let access_token = token_resp["access_token"]
        .as_str()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("missing access_token in Google response")))?;

    // Fetch Google userinfo
    let userinfo: Value = app.http_client
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Userinfo fetch failed: {e}")))?
        .error_for_status()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Userinfo endpoint error: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Userinfo parse failed: {e}")))?;

    let google_sub = userinfo["sub"]
        .as_str()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("missing sub")))?
        .to_string();
    let email = userinfo["email"]
        .as_str()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("missing email")))?
        .to_string();
    let name = userinfo["name"].as_str().map(String::from);

    let user = User::upsert(&app.pool, &email, name.as_deref()).await?;
    Credential::upsert(&app.pool, user.id, "google", &google_sub, &userinfo).await?;

    let code_plain = crypto::generate_token();
    let code_hash = crypto::hash_token(&code_plain);
    DbAuthCode::create(
        &app.pool,
        &auth_session.client_id,
        user.id,
        &code_hash,
        &auth_session.pkce_challenge,
        &auth_session.scopes,
    )
    .await?;

    app.auth_sessions.remove(&auth_session_id);

    let mut redirect_url = auth_session.redirect_uri.clone();
    redirect_url.push_str(&format!("?code={code_plain}"));
    if let Some(state) = &auth_session.state {
        redirect_url.push_str(&format!("&state={state}"));
    }

    Ok(Redirect::to(&redirect_url))
}
