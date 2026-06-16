use std::{env, fs};

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_private_key: String,
    pub jwt_public_key: String,
    pub jwks_path: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub base_url: String,
    pub port: u16,
    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        let private_path = env::var("JWT_PRIVATE_KEY_PATH")
            .unwrap_or_else(|_| "private.pem".to_string());
        let public_path = env::var("JWT_PUBLIC_KEY_PATH")
            .unwrap_or_else(|_| "public.pem".to_string());
        Ok(Self {
            database_url: env::var("DATABASE_URL")
                .map_err(|_| anyhow::anyhow!("DATABASE_URL required"))?,
            jwt_private_key: fs::read_to_string(&private_path)
                .map_err(|_| anyhow::anyhow!("Cannot read {private_path}"))?,
            jwt_public_key: fs::read_to_string(&public_path)
                .map_err(|_| anyhow::anyhow!("Cannot read {public_path}"))?,
            jwks_path: env::var("JWKS_PATH").unwrap_or_else(|_| "jwks.json".to_string()),
            google_client_id: env::var("GOOGLE_CLIENT_ID")
                .map_err(|_| anyhow::anyhow!("GOOGLE_CLIENT_ID required"))?,
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET")
                .map_err(|_| anyhow::anyhow!("GOOGLE_CLIENT_SECRET required"))?,
            base_url: env::var("PPS_AUTH_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:4000".to_string()),
            port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "4000".to_string())
                .parse()
                .map_err(|_| anyhow::anyhow!("SERVER_PORT must be a number"))?,
            webauthn_rp_id: env::var("WEBAUTHN_RP_ID")
                .unwrap_or_else(|_| "localhost".to_string()),
            webauthn_rp_origin: env::var("WEBAUTHN_RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:4000".to_string()),
        })
    }
}
