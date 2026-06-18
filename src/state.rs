use crate::config::Config;
use dashmap::DashMap;
use jsonwebtoken::{DecodingKey, EncodingKey};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use serde_json::Value;
use sqlx::PgPool;
use std::{fs, sync::Arc};
use url::Url;
use webauthn_rs::prelude::*;

/// Stored during an in-flight /authorize → /login → auth-method → /callback cycle.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub client_id: String,
    pub redirect_uri: String,
    pub pkce_challenge: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub state: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub jwks: Arc<Value>,
    pub base_url: String,
    pub google_client: BasicClient,
    pub google_client_secret: String,
    pub http_client: reqwest::Client,
    pub webauthn: Arc<Webauthn>,
    /// auth_session_id → AuthSession (created at /authorize, consumed after login)
    pub auth_sessions: Arc<DashMap<String, AuthSession>>,
    /// google_state → auth_session_id (for CSRF-safe Google callback)
    pub google_states: Arc<DashMap<String, String>>,
    /// session_id → PasskeyRegistration (in-flight WebAuthn registration)
    pub pk_registrations: Arc<DashMap<String, PasskeyRegistration>>,
    /// session_id → PasskeyAuthentication (in-flight WebAuthn authentication)
    pub pk_auths: Arc<DashMap<String, PasskeyAuthentication>>,
}

impl AppState {
    pub fn new(pool: PgPool, config: &Config) -> anyhow::Result<Self> {
        let encoding_key = EncodingKey::from_rsa_pem(config.jwt_private_key.as_bytes())
            .map_err(|e| anyhow::anyhow!("Invalid private key PEM: {e}"))?;
        let decoding_key = DecodingKey::from_rsa_pem(config.jwt_public_key.as_bytes())
            .map_err(|e| anyhow::anyhow!("Invalid public key PEM: {e}"))?;

        let jwks_raw = fs::read_to_string(&config.jwks_path)
            .map_err(|_| anyhow::anyhow!("Cannot read {}", config.jwks_path))?;
        let jwks: Arc<Value> = Arc::new(serde_json::from_str(&jwks_raw)?);

        let google_client = BasicClient::new(
            ClientId::new(config.google_client_id.clone()),
            Some(ClientSecret::new(config.google_client_secret.clone())),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?,
            Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string())?),
        )
        .set_redirect_uri(RedirectUrl::new(format!(
            "{}/auth/google/callback",
            config.base_url
        ))?);

        let rp_id = config.webauthn_rp_id.clone();
        let rp_origin = Url::parse(&config.webauthn_rp_origin)?;
        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)?.build()?;

        Ok(Self {
            pool,
            encoding_key,
            decoding_key,
            jwks,
            base_url: config.base_url.clone(),
            google_client,
            google_client_secret: config.google_client_secret.clone(),
            http_client: reqwest::Client::new(),
            webauthn: Arc::new(webauthn),
            auth_sessions: Arc::new(DashMap::new()),
            google_states: Arc::new(DashMap::new()),
            pk_registrations: Arc::new(DashMap::new()),
            pk_auths: Arc::new(DashMap::new()),
        })
    }
}
