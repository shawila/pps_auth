use std::{env, fs};
use url::Url;

pub fn resolve_database_url() -> anyhow::Result<String> {
    if let Ok(url) = env::var("DATABASE_URL") {
        return Ok(url);
    }

    let user = env::var("POSTGRES_USER")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL or POSTGRES_USER required"))?;
    let password = env::var("POSTGRES_PASSWORD")
        .map_err(|_| anyhow::anyhow!("POSTGRES_PASSWORD required"))?;
    let host = env::var("POSTGRES_HOST").unwrap_or_else(|_| "postgres".to_string());
    let port: u16 = env::var("POSTGRES_PORT")
        .unwrap_or_else(|_| "5432".to_string())
        .parse()
        .unwrap_or(5432);
    let db = env::var("POSTGRES_DB")
        .map_err(|_| anyhow::anyhow!("POSTGRES_DB required"))?;

    let mut url = Url::parse(&format!("postgres://{host}"))
        .map_err(|e| anyhow::anyhow!("Failed to build DATABASE_URL: {e}"))?;
    url.set_port(Some(port))
        .map_err(|_| anyhow::anyhow!("Failed to set port"))?;
    url.set_path(&format!("/{db}"));
    url.set_username(&user)
        .map_err(|_| anyhow::anyhow!("Failed to set DB username"))?;
    url.set_password(Some(&password))
        .map_err(|_| anyhow::anyhow!("Failed to set DB password"))?;

    Ok(url.to_string())
}

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
        let base_url = env::var("PPS_AUTH_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:4000".to_string());
        let base_url_parsed = Url::parse(&base_url)
            .map_err(|_| anyhow::anyhow!("PPS_AUTH_BASE_URL is not a valid URL: {base_url}"))?;
        let webauthn_rp_id = base_url_parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("PPS_AUTH_BASE_URL has no host"))?
            .to_string();
        let webauthn_rp_origin = base_url_parsed.origin().ascii_serialization();
        Ok(Self {
            database_url: resolve_database_url()?,
            jwt_private_key: fs::read_to_string(&private_path)
                .map_err(|_| anyhow::anyhow!("Cannot read {private_path}"))?,
            jwt_public_key: fs::read_to_string(&public_path)
                .map_err(|_| anyhow::anyhow!("Cannot read {public_path}"))?,
            jwks_path: env::var("JWKS_PATH").unwrap_or_else(|_| "jwks.json".to_string()),
            google_client_id: env::var("GOOGLE_CLIENT_ID")
                .map_err(|_| anyhow::anyhow!("GOOGLE_CLIENT_ID required"))?,
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET")
                .map_err(|_| anyhow::anyhow!("GOOGLE_CLIENT_SECRET required"))?,
            base_url,
            port: env::var("PORT")
                .unwrap_or_else(|_| "4000".to_string())
                .parse()
                .map_err(|_| anyhow::anyhow!("PORT must be a number"))?,
            webauthn_rp_id,
            webauthn_rp_origin,
        })
    }
}
