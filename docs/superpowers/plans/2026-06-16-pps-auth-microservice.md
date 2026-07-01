# pps_auth OIDC Microservice — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone OIDC Authorization Server in Rust (Axum) that issues RS256 JWTs consumed by portfolio_chatbot and trading_bot via Authorization Code Flow + PKCE.

**Architecture:** Single Axum binary. PostgreSQL (separate `pps_auth` schema, shared instance with portfolio_chatbot). Private key on disk signs JWTs; public key served at `/.well-known/jwks.json`. In-memory DashMaps hold WebAuthn and Google OAuth in-flight session state.

**Tech Stack:** Rust 1.78+, Axum 0.7, sqlx 0.8, PostgreSQL 15, jsonwebtoken 9, webauthn-rs 0.5, oauth2 4.x, minijinja 2.x, argon2 0.5, dashmap 5.x.

**Spec:** `docs/superpowers/specs/2026-06-16-auth-microservice-design.md`

---

## File Map

```
pps_auth/
├── Cargo.toml
├── .env.example
├── scripts/gen_jwks.py          -- generate jwks.json from public.pem
├── migrations/
│   ├── 001_create_schema.sql
│   ├── 002_create_users.sql
│   ├── 003_create_credentials.sql
│   ├── 004_create_oauth_clients.sql
│   ├── 005_create_authorization_codes.sql
│   ├── 006_create_refresh_tokens.sql
│   └── 007_create_roles.sql
└── src/
    ├── main.rs                  -- router wiring + startup
    ├── config.rs                -- env config, reads PEM files
    ├── error.rs                 -- AppError → OIDC JSON error responses
    ├── state.rs                 -- AppState (pool, keys, webauthn, google client)
    ├── crypto.rs                -- PKCE, Argon2, token gen, token hashing
    ├── db/mod.rs                -- sqlx pool init + migrate
    ├── models/
    │   ├── mod.rs
    │   ├── user.rs
    │   ├── credential.rs
    │   ├── oauth_client.rs
    │   ├── authorization_code.rs
    │   ├── refresh_token.rs
    │   └── role.rs
    ├── oidc/
    │   ├── mod.rs
    │   ├── discovery.rs         -- GET /.well-known/openid-configuration
    │   ├── jwks.rs              -- GET /.well-known/jwks.json
    │   ├── authorize.rs         -- GET /authorize
    │   ├── token.rs             -- POST /token
    │   ├── userinfo.rs          -- GET /userinfo
    │   └── revoke.rs            -- POST /revoke
    ├── auth/
    │   ├── mod.rs
    │   ├── google.rs            -- /auth/google + /auth/google/callback
    │   └── passkey.rs           -- /auth/passkey/* (4 endpoints)
    ├── ui/
    │   ├── mod.rs
    │   ├── login.rs             -- GET /login
    │   └── templates/login.html
    └── middleware/
        ├── mod.rs
        └── bearer.rs            -- FromRequestParts extractor for Bearer JWTs
```

---

### Task 1: Project scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `.env.example`
- Create: `src/config.rs`
- Create: `src/error.rs`
- Create: `src/main.rs` (health check only)

- [ ] **Step 1: Create Cargo.toml**

```toml
[package]
name = "pps_auth"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "pps_auth"
path = "src/main.rs"

[[bin]]
name = "seed"
path = "src/bin/seed.rs"

[dependencies]
axum = { version = "0.7", features = ["macros"] }
tokio = { version = "1", features = ["full"] }
tower-http = { version = "0.5", features = ["cors", "trace"] }
sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "postgres", "uuid", "time", "json", "migrate"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4", "serde"] }
time = { version = "0.3", features = ["serde"] }
jsonwebtoken = "9"
sha2 = "0.10"
base64ct = { version = "1", features = ["alloc"] }
argon2 = "0.5"
rand = "0.8"
oauth2 = "4"
webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation"] }
minijinja = { version = "2", features = ["loader"] }
dashmap = "5"
dotenvy = "0.15"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
thiserror = "1"
anyhow = "1"
url = "2"
reqwest = { version = "0.12", features = ["json"] }

[dev-dependencies]
wiremock = "0.6"
```

- [ ] **Step 2: Create .env.example**

```
DATABASE_URL=postgres://postgres:password@localhost:5432/portfolio_chatbot
JWT_PRIVATE_KEY_PATH=private.pem
JWT_PUBLIC_KEY_PATH=public.pem
JWKS_PATH=jwks.json
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
PPS_AUTH_BASE_URL=http://localhost:4000
SERVER_PORT=4000
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_ORIGIN=http://localhost:4000
```

- [ ] **Step 3: Create src/config.rs**

```rust
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
```

- [ ] **Step 4: Create src/error.rs**

```rust
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
            AppError::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string()),
            AppError::Db(e) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", e.to_string()),
        };
        (status, Json(json!({ "error": code, "error_description": desc }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
```

- [ ] **Step 5: Create src/main.rs (health check skeleton)**

```rust
mod config;
mod error;

use axum::{routing::get, Router};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let config = config::Config::from_env()?;
    let app = Router::new().route("/health", get(|| async { "ok" }));
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

- [ ] **Step 6: Verify it compiles**

```bash
cargo build
```

Expected: compile succeeds (no tests yet).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml .env.example src/
git commit -m "feat: scaffold pps_auth with config and error types"
```

---

### Task 2: Database migrations + pool

**Files:**
- Create: `migrations/001_create_schema.sql` through `007_create_roles.sql`
- Create: `src/db/mod.rs`

- [ ] **Step 1: Write migration 001 — create schema**

`migrations/001_create_schema.sql`:
```sql
CREATE SCHEMA IF NOT EXISTS pps_auth;
```

- [ ] **Step 2: Write migration 002 — users**

`migrations/002_create_users.sql`:
```sql
CREATE TABLE pps_auth.users (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT        NOT NULL UNIQUE,
    name        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

- [ ] **Step 3: Write migration 003 — credentials**

`migrations/003_create_credentials.sql`:
```sql
CREATE TABLE pps_auth.credentials (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES pps_auth.users(id) ON DELETE CASCADE,
    type            TEXT        NOT NULL,
    provider_id     TEXT        NOT NULL,
    credential_data JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (type, provider_id)
);
```

- [ ] **Step 4: Write migration 004 — oauth_clients**

`migrations/004_create_oauth_clients.sql`:
```sql
CREATE TABLE pps_auth.oauth_clients (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           TEXT        NOT NULL UNIQUE,
    client_secret_hash  TEXT        NOT NULL,
    redirect_uris       TEXT[]      NOT NULL DEFAULT '{}',
    name                TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

- [ ] **Step 5: Write migration 005 — authorization_codes**

`migrations/005_create_authorization_codes.sql`:
```sql
CREATE TABLE pps_auth.authorization_codes (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       TEXT        NOT NULL REFERENCES pps_auth.oauth_clients(client_id),
    user_id         UUID        NOT NULL REFERENCES pps_auth.users(id),
    code_hash       TEXT        NOT NULL UNIQUE,
    pkce_challenge  TEXT        NOT NULL,
    pkce_method     TEXT        NOT NULL DEFAULT 'S256',
    scopes          TEXT[]      NOT NULL DEFAULT '{}',
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ
);
CREATE INDEX ON pps_auth.authorization_codes (code_hash);
```

- [ ] **Step 6: Write migration 006 — refresh_tokens**

`migrations/006_create_refresh_tokens.sql`:
```sql
CREATE TABLE pps_auth.refresh_tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES pps_auth.users(id),
    client_id   TEXT        NOT NULL REFERENCES pps_auth.oauth_clients(client_id),
    token_hash  TEXT        NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX ON pps_auth.refresh_tokens (token_hash);
```

- [ ] **Step 7: Write migration 007 — roles**

`migrations/007_create_roles.sql`:
```sql
CREATE TABLE pps_auth.roles (
    id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID    NOT NULL REFERENCES pps_auth.users(id) ON DELETE CASCADE,
    client_id   TEXT    REFERENCES pps_auth.oauth_clients(client_id),
    role        TEXT    NOT NULL,
    UNIQUE (user_id, client_id, role)
);
```

- [ ] **Step 8: Create src/db/mod.rs**

```rust
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
```

- [ ] **Step 9: Update src/main.rs to run migrations on startup**

Add to main.rs imports:
```rust
mod db;
```

Add to main before building the router:
```rust
let pool = db::connect(&config.database_url).await?;
tracing::info!("Database connected and migrated");
```

- [ ] **Step 10: Run migrations against your dev database**

```bash
export DATABASE_URL=postgres://postgres:password@localhost:5432/portfolio_chatbot
cargo run
```

Expected: server starts, logs "Database connected and migrated".

- [ ] **Step 11: Commit**

```bash
git add migrations/ src/db/ src/main.rs
git commit -m "feat: add database migrations and sqlx pool"
```

---

### Task 3: Crypto utilities

**Files:**
- Create: `src/crypto.rs`

- [ ] **Step 1: Write failing tests**

Create `src/crypto.rs` with only the tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use base64ct::{Base64UrlUnpadded, Encoding};

    #[test]
    fn pkce_correct_verifier_passes() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = Base64UrlUnpadded::encode_string(&hash);
        assert!(verify_pkce(verifier, &challenge));
    }

    #[test]
    fn pkce_wrong_verifier_fails() {
        assert!(!verify_pkce("wrong_verifier", "some_challenge"));
    }

    #[test]
    fn argon2_hash_and_verify_roundtrip() {
        let secret = "super-secret";
        let hash = hash_secret(secret).unwrap();
        assert!(verify_hashed_secret(secret, &hash));
        assert!(!verify_hashed_secret("wrong", &hash));
    }

    #[test]
    fn tokens_are_unique_and_43_chars() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
        assert_eq!(t1.len(), 43);
    }

    #[test]
    fn token_hash_is_deterministic() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_ne!(hash_token("abc"), hash_token("def"));
    }
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
cargo test crypto
```

Expected: compile error — functions not defined.

- [ ] **Step 3: Implement src/crypto.rs**

```rust
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Verify PKCE S256: challenge == BASE64URL-NOPAD(SHA256(verifier))
pub fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    let hash = Sha256::digest(verifier.as_bytes());
    Base64UrlUnpadded::encode_string(&hash) == challenge
}

pub fn hash_secret(secret: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("Argon2 error: {e}"))
}

pub fn verify_hashed_secret(secret: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(secret.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// 32 random bytes → 43-char base64url token (no padding).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Base64UrlUnpadded::encode_string(&bytes)
}

/// SHA-256 hash of a token for storage (tokens are high-entropy; Argon2 unnecessary).
pub fn hash_token(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    Base64UrlUnpadded::encode_string(&hash)
}
```

- [ ] **Step 4: Run tests — expect pass**

```bash
cargo test crypto
```

Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/crypto.rs
git commit -m "feat: add crypto utilities — PKCE, Argon2, token gen"
```

---

### Task 4: Models

**Files:**
- Create: `src/models/mod.rs`, `user.rs`, `credential.rs`, `oauth_client.rs`, `authorization_code.rs`, `refresh_token.rs`, `role.rs`

- [ ] **Step 1: Create src/models/mod.rs**

```rust
pub mod authorization_code;
pub mod credential;
pub mod oauth_client;
pub mod refresh_token;
pub mod role;
pub mod user;
```

- [ ] **Step 2: Create src/models/user.rs**

```rust
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub created_at: OffsetDateTime,
}

impl User {
    pub async fn find_by_email(pool: &PgPool, email: &str) -> sqlx::Result<Option<Self>> {
        sqlx::query_as!(
            Self,
            "SELECT id, email, name, created_at FROM pps_auth.users WHERE email = $1",
            email
        )
        .fetch_optional(pool)
        .await
    }

    pub async fn upsert(pool: &PgPool, email: &str, name: Option<&str>) -> sqlx::Result<Self> {
        sqlx::query_as!(
            Self,
            r#"INSERT INTO pps_auth.users (id, email, name)
               VALUES ($1, $2, $3)
               ON CONFLICT (email) DO UPDATE SET name = COALESCE(EXCLUDED.name, pps_auth.users.name)
               RETURNING id, email, name, created_at"#,
            Uuid::new_v4(),
            email,
            name
        )
        .fetch_one(pool)
        .await
    }
}
```

- [ ] **Step 3: Create src/models/credential.rs**

```rust
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub r#type: String,
    pub provider_id: String,
    pub credential_data: Value,
    pub created_at: OffsetDateTime,
}

impl Credential {
    pub async fn upsert(
        pool: &PgPool,
        user_id: Uuid,
        cred_type: &str,
        provider_id: &str,
        data: &Value,
    ) -> sqlx::Result<Self> {
        sqlx::query_as!(
            Self,
            r#"INSERT INTO pps_auth.credentials (id, user_id, type, provider_id, credential_data)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (type, provider_id)
               DO UPDATE SET credential_data = EXCLUDED.credential_data
               RETURNING id, user_id, type, provider_id, credential_data, created_at"#,
            Uuid::new_v4(),
            user_id,
            cred_type,
            provider_id,
            data
        )
        .fetch_one(pool)
        .await
    }

    pub async fn find_by_provider(
        pool: &PgPool,
        cred_type: &str,
        provider_id: &str,
    ) -> sqlx::Result<Option<Self>> {
        sqlx::query_as!(
            Self,
            "SELECT id, user_id, type, provider_id, credential_data, created_at
             FROM pps_auth.credentials WHERE type = $1 AND provider_id = $2",
            cred_type,
            provider_id
        )
        .fetch_optional(pool)
        .await
    }
}
```

- [ ] **Step 4: Create src/models/oauth_client.rs**

```rust
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct OauthClient {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: String,
    pub redirect_uris: Vec<String>,
    pub name: Option<String>,
    pub created_at: OffsetDateTime,
}

impl OauthClient {
    pub async fn find(pool: &PgPool, client_id: &str) -> sqlx::Result<Option<Self>> {
        sqlx::query_as!(
            Self,
            "SELECT id, client_id, client_secret_hash, redirect_uris, name, created_at
             FROM pps_auth.oauth_clients WHERE client_id = $1",
            client_id
        )
        .fetch_optional(pool)
        .await
    }

    pub fn has_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }
}
```

- [ ] **Step 5: Create src/models/authorization_code.rs**

```rust
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct AuthorizationCode {
    pub id: Uuid,
    pub client_id: String,
    pub user_id: Uuid,
    pub code_hash: String,
    pub pkce_challenge: String,
    pub pkce_method: String,
    pub scopes: Vec<String>,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
}

impl AuthorizationCode {
    pub async fn create(
        pool: &PgPool,
        client_id: &str,
        user_id: Uuid,
        code_hash: &str,
        pkce_challenge: &str,
        scopes: &[String],
    ) -> sqlx::Result<Self> {
        sqlx::query_as!(
            Self,
            r#"INSERT INTO pps_auth.authorization_codes
               (id, client_id, user_id, code_hash, pkce_challenge, pkce_method, scopes, expires_at)
               VALUES ($1, $2, $3, $4, $5, 'S256', $6, NOW() + INTERVAL '5 minutes')
               RETURNING id, client_id, user_id, code_hash, pkce_challenge, pkce_method,
                         scopes, expires_at, used_at"#,
            Uuid::new_v4(),
            client_id,
            user_id,
            code_hash,
            pkce_challenge,
            scopes as &[String],
        )
        .fetch_one(pool)
        .await
    }

    /// Atomically consume: marks used_at, returns None if already used or expired.
    pub async fn consume(pool: &PgPool, code_hash: &str) -> sqlx::Result<Option<Self>> {
        sqlx::query_as!(
            Self,
            r#"UPDATE pps_auth.authorization_codes
               SET used_at = NOW()
               WHERE code_hash = $1 AND used_at IS NULL AND expires_at > NOW()
               RETURNING id, client_id, user_id, code_hash, pkce_challenge, pkce_method,
                         scopes, expires_at, used_at"#,
            code_hash
        )
        .fetch_optional(pool)
        .await
    }
}
```

- [ ] **Step 6: Create src/models/refresh_token.rs**

```rust
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub token_hash: String,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

impl RefreshToken {
    pub async fn create(
        pool: &PgPool,
        user_id: Uuid,
        client_id: &str,
        token_hash: &str,
    ) -> sqlx::Result<Self> {
        sqlx::query_as!(
            Self,
            r#"INSERT INTO pps_auth.refresh_tokens (id, user_id, client_id, token_hash, expires_at)
               VALUES ($1, $2, $3, $4, NOW() + INTERVAL '30 days')
               RETURNING id, user_id, client_id, token_hash, expires_at, revoked_at"#,
            Uuid::new_v4(), user_id, client_id, token_hash
        )
        .fetch_one(pool)
        .await
    }

    pub async fn find_valid(pool: &PgPool, token_hash: &str) -> sqlx::Result<Option<Self>> {
        sqlx::query_as!(
            Self,
            r#"SELECT id, user_id, client_id, token_hash, expires_at, revoked_at
               FROM pps_auth.refresh_tokens
               WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()"#,
            token_hash
        )
        .fetch_optional(pool)
        .await
    }

    /// Returns true if found and newly revoked; false if already revoked or not found.
    pub async fn revoke(pool: &PgPool, token_hash: &str) -> sqlx::Result<bool> {
        Ok(sqlx::query!(
            "UPDATE pps_auth.refresh_tokens SET revoked_at = NOW()
             WHERE token_hash = $1 AND revoked_at IS NULL",
            token_hash
        )
        .execute(pool)
        .await?
        .rows_affected() > 0)
    }
}
```

- [ ] **Step 7: Create src/models/role.rs**

```rust
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct Role {
    pub role: String,
    pub client_id: Option<String>,
}

impl Role {
    /// Returns roles that apply globally (client_id IS NULL) OR to this specific client.
    pub async fn for_user_and_client(
        pool: &PgPool,
        user_id: Uuid,
        client_id: &str,
    ) -> sqlx::Result<Vec<String>> {
        let rows = sqlx::query_scalar!(
            "SELECT role FROM pps_auth.roles
             WHERE user_id = $1 AND (client_id IS NULL OR client_id = $2)",
            user_id,
            client_id
        )
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }
}
```

- [ ] **Step 8: Add models mod to main.rs**

Add `mod models;` to `src/main.rs`.

- [ ] **Step 9: Compile check**

```bash
cargo build
```

Expected: compiles without errors.

- [ ] **Step 10: Commit**

```bash
git add src/models/
git commit -m "feat: add sqlx models for all 6 pps_auth tables"
```

---

### Task 5: AppState + key generation

**Files:**
- Create: `src/state.rs`
- Create: `scripts/gen_jwks.py`
- Create: `src/bin/seed.rs` (stub only — completed in Task 13)
- Modify: `src/main.rs`

- [ ] **Step 1: Create scripts/gen_jwks.py**

This script converts `public.pem` → `jwks.json`. Run it once after generating keys.

```python
#!/usr/bin/env python3
"""Convert public.pem to jwks.json. Requires: pip install cryptography"""
import base64
import json
import sys
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

def b64url(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(byte_length, "big")).rstrip(b"=").decode()

pub_path = sys.argv[1] if len(sys.argv) > 1 else "public.pem"
out_path = sys.argv[2] if len(sys.argv) > 2 else "jwks.json"

with open(pub_path, "rb") as f:
    key = load_pem_public_key(f.read())

assert isinstance(key, RSAPublicKey), "Expected RSA public key"
nums = key.public_numbers()

jwks = {
    "keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "1",
        "n": b64url(nums.n),
        "e": b64url(nums.e),
    }]
}

with open(out_path, "w") as f:
    json.dump(jwks, f, indent=2)

print(f"Written {out_path}")
```

- [ ] **Step 2: Generate keys + JWKS (run once, files are gitignored)**

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
pip install cryptography
python3 scripts/gen_jwks.py
```

Expected: `private.pem`, `public.pem`, `jwks.json` created.

- [ ] **Step 3: Add key files to .gitignore**

Add to `.gitignore`:
```
private.pem
public.pem
jwks.json
.env
```

- [ ] **Step 4: Create src/state.rs**

```rust
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
    pub jwks: Value,
    pub base_url: String,
    pub google_client: BasicClient,
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
        let jwks: Value = serde_json::from_str(&jwks_raw)?;

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
            webauthn: Arc::new(webauthn),
            auth_sessions: Arc::new(DashMap::new()),
            google_states: Arc::new(DashMap::new()),
            pk_registrations: Arc::new(DashMap::new()),
            pk_auths: Arc::new(DashMap::new()),
        })
    }
}
```

- [ ] **Step 5: Create src/bin/seed.rs (stub)**

```rust
fn main() {
    println!("Seed: implement in Task 13");
}
```

- [ ] **Step 6: Update src/main.rs to wire AppState**

```rust
mod config;
mod crypto;
mod db;
mod error;
mod models;
mod state;

use axum::{extract::State, routing::get, Json, Router};
use std::{net::SocketAddr, sync::Arc};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let config = config::Config::from_env()?;
    let pool = db::connect(&config.database_url).await?;
    let app_state = Arc::new(state::AppState::new(pool, &config)?);

    let app = Router::new()
        .route("/health", get(health))
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("pps_auth listening on {addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn health(State(state): State<Arc<state::AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "base_url": state.base_url }))
}
```

- [ ] **Step 7: Compile and test health check**

```bash
cargo build
cargo run &
curl http://localhost:4000/health
# Expected: {"status":"ok","base_url":"http://localhost:4000"}
kill %1
```

- [ ] **Step 8: Commit**

```bash
git add src/state.rs src/bin/seed.rs scripts/gen_jwks.py .gitignore src/main.rs
git commit -m "feat: add AppState with RS256 keys, WebAuthn, Google OAuth client"
```

---

### Task 6: OIDC Discovery + JWKS endpoints

**Files:**
- Create: `src/oidc/mod.rs`, `src/oidc/discovery.rs`, `src/oidc/jwks.rs`

- [ ] **Step 1: Write failing test for discovery**

Create `src/oidc/discovery.rs` with tests only:

```rust
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn discovery_has_required_fields() {
        // Will test via HTTP once wired up in Task 6 Step 5
        // For now this test verifies the shape of the response struct.
        let doc = super::DiscoveryDocument {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/authorize".to_string(),
            token_endpoint: "https://auth.example.com/token".to_string(),
            userinfo_endpoint: "https://auth.example.com/userinfo".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            response_types_supported: vec!["code".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["RS256".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            grant_types_supported: vec!["authorization_code".to_string(), "refresh_token".to_string()],
        };
        assert_eq!(doc.issuer, "https://auth.example.com");
        assert!(doc.id_token_signing_alg_values_supported.contains(&"RS256".to_string()));
        assert!(doc.code_challenge_methods_supported.contains(&"S256".to_string()));
    }
}
```

- [ ] **Step 2: Implement src/oidc/discovery.rs**

```rust
use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
}

pub async fn handler(State(state): State<Arc<AppState>>) -> Json<DiscoveryDocument> {
    let base = &state.base_url;
    Json(DiscoveryDocument {
        issuer: base.clone(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        userinfo_endpoint: format!("{base}/userinfo"),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        response_types_supported: vec!["code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        grant_types_supported: vec!["authorization_code".to_string(), "refresh_token".to_string()],
    })
}

#[cfg(test)]
mod tests {
    // (tests from Step 1 here)
}
```

- [ ] **Step 3: Implement src/oidc/jwks.rs**

```rust
use axum::{extract::State, Json};
use serde_json::Value;
use std::sync::Arc;
use crate::state::AppState;

pub async fn handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(state.jwks.clone())
}
```

- [ ] **Step 4: Create src/oidc/mod.rs**

```rust
pub mod authorize;
pub mod discovery;
pub mod jwks;
pub mod revoke;
pub mod token;
pub mod userinfo;
```

(Create empty stubs for authorize, revoke, token, userinfo — fill in later tasks.)

Stub template for each:
```rust
// src/oidc/authorize.rs (stub)
pub async fn handler() -> &'static str { "TODO" }
```

- [ ] **Step 5: Wire discovery + JWKS into router in src/main.rs**

Add `mod oidc;` to `src/main.rs`. Add routes:

```rust
.route("/.well-known/openid-configuration", get(oidc::discovery::handler))
.route("/.well-known/jwks.json", get(oidc::jwks::handler))
```

- [ ] **Step 6: Test endpoints manually**

```bash
cargo run &
curl http://localhost:4000/.well-known/openid-configuration | jq .issuer
# Expected: "http://localhost:4000"
curl http://localhost:4000/.well-known/jwks.json | jq '.keys[0].kty'
# Expected: "RSA"
kill %1
```

- [ ] **Step 7: Run unit tests**

```bash
cargo test oidc::discovery
```

Expected: 1 test passes.

- [ ] **Step 8: Commit**

```bash
git add src/oidc/
git commit -m "feat: add OIDC discovery and JWKS endpoints"
```

---

### Task 7: Authorization endpoint

**Files:**
- Modify: `src/oidc/authorize.rs`

The `/authorize` endpoint validates the OIDC request, stores it as an `AuthSession` in `state.auth_sessions`, then redirects to `/login?session=<id>`.

- [ ] **Step 1: Implement src/oidc/authorize.rs**

```rust
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
```

- [ ] **Step 2: Wire into router**

In `src/main.rs`:
```rust
.route("/authorize", get(oidc::authorize::handler))
```

- [ ] **Step 3: Write integration test**

Create `tests/authorize_test.rs`:

```rust
mod common;

#[tokio::test]
async fn authorize_unknown_client_returns_401() {
    let app = common::test_app().await;
    let res = app
        .get("/authorize?response_type=code&client_id=unknown&redirect_uri=http://x&code_challenge=x&code_challenge_method=S256")
        .await;
    assert_eq!(res.status(), 401);
    let body: serde_json::Value = res.json().await;
    assert_eq!(body["error"], "unauthorized_client");
}

#[tokio::test]
async fn authorize_redirect_uri_mismatch_returns_400() {
    let app = common::test_app().await;
    common::seed_client(&app.pool, "test_client", "http://good.example/cb").await;
    let res = app
        .get("/authorize?response_type=code&client_id=test_client&redirect_uri=http://evil.example&code_challenge=abc&code_challenge_method=S256")
        .await;
    assert_eq!(res.status(), 400);
    let body: serde_json::Value = res.json().await;
    assert_eq!(body["error"], "redirect_uri_mismatch");
}

#[tokio::test]
async fn authorize_valid_request_redirects_to_login() {
    let app = common::test_app().await;
    common::seed_client(&app.pool, "test_client", "http://good.example/cb").await;
    let res = app
        .get("/authorize?response_type=code&client_id=test_client&redirect_uri=http://good.example/cb&code_challenge=abc&code_challenge_method=S256")
        .await;
    assert_eq!(res.status(), 302);
    let location = res.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("/login?session="));
}
```

- [ ] **Step 4: Create tests/common/mod.rs (test helpers)**

```rust
use std::sync::Arc;
use axum::Router;
use axum_test::TestServer;
use sqlx::PgPool;
use crate::state::AppState;

pub struct TestApp {
    pub server: TestServer,
    pub pool: PgPool,
}

impl TestApp {
    pub fn get(&self, path: &str) -> axum_test::TestRequest {
        self.server.get(path)
    }
    pub fn post(&self, path: &str) -> axum_test::TestRequest {
        self.server.post(path)
    }
}

pub async fn test_app() -> TestApp {
    dotenvy::dotenv().ok();
    let db_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must be set for tests");
    let pool = crate::db::connect(&db_url).await.unwrap();

    // Clean pps_auth tables before each test
    sqlx::query!("TRUNCATE pps_auth.authorization_codes, pps_auth.refresh_tokens, pps_auth.credentials, pps_auth.roles, pps_auth.users, pps_auth.oauth_clients CASCADE")
        .execute(&pool)
        .await
        .unwrap();

    let config = crate::config::Config::from_env().unwrap();
    let state = Arc::new(AppState::new(pool.clone(), &config).unwrap());
    let app = crate::build_router(state);
    TestApp { server: TestServer::new(app).unwrap(), pool }
}

pub async fn seed_client(pool: &PgPool, client_id: &str, redirect_uri: &str) {
    let hash = crate::crypto::hash_secret("test-secret").unwrap();
    sqlx::query!(
        "INSERT INTO pps_auth.oauth_clients (id, client_id, client_secret_hash, redirect_uris)
         VALUES (gen_random_uuid(), $1, $2, ARRAY[$3]::text[])",
        client_id, hash, redirect_uri
    )
    .execute(pool)
    .await
    .unwrap();
}
```

Add `axum-test = "0.4"` to `[dev-dependencies]` in `Cargo.toml`.

Extract router into a `build_router` function in `src/main.rs`:

```rust
pub fn build_router(state: Arc<state::AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/.well-known/openid-configuration", get(oidc::discovery::handler))
        .route("/.well-known/jwks.json", get(oidc::jwks::handler))
        .route("/authorize", get(oidc::authorize::handler))
        .with_state(state)
}
```

- [ ] **Step 5: Run tests**

```bash
TEST_DATABASE_URL=postgres://postgres:password@localhost:5432/portfolio_chatbot cargo test authorize
```

Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/oidc/authorize.rs tests/ src/main.rs Cargo.toml
git commit -m "feat: add /authorize endpoint with PKCE and redirect_uri validation"
```

---

### Task 8: Login UI

**Files:**
- Create: `src/ui/mod.rs`, `src/ui/login.rs`, `src/ui/templates/login.html`

- [ ] **Step 1: Create src/ui/templates/login.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sign in — pps_auth</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           background: #0f1117; color: #e2e8f0; min-height: 100vh;
           display: flex; align-items: center; justify-content: center; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 16px;
            padding: 40px; width: 360px; }
    h1 { font-size: 1.25rem; font-weight: 700; margin-bottom: 8px; }
    p  { font-size: 0.875rem; color: #64748b; margin-bottom: 32px; }
    .btn { display: flex; align-items: center; justify-content: center; gap: 10px;
           width: 100%; padding: 12px 20px; border-radius: 10px; border: 1px solid #334155;
           background: #0f1117; color: #e2e8f0; font-size: 0.9rem; font-weight: 500;
           cursor: pointer; text-decoration: none; margin-bottom: 12px;
           transition: background 0.15s; }
    .btn:hover { background: #1e293b; }
    .btn-google { border-color: #4285f4; }
    .divider { text-align: center; color: #475569; font-size: 0.8rem; margin: 20px 0; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Sign in</h1>
    <p>Signing in to <strong>{{ client_name }}</strong></p>

    <a class="btn btn-google" href="/auth/google?session={{ session_id }}">
      <svg width="18" height="18" viewBox="0 0 48 48">
        <path fill="#4285F4" d="M45.5 24.5c0-1.5-.1-3-.4-4.4H24v8.4h12.1c-.5 2.7-2.1 5-4.4 6.5v5.4h7.1c4.2-3.8 6.7-9.5 6.7-15.9z"/>
        <path fill="#34A853" d="M24 46c6 0 11-2 14.7-5.3l-7.1-5.4c-2 1.3-4.5 2.1-7.6 2.1-5.8 0-10.7-3.9-12.5-9.2H4.2v5.6C7.9 41.1 15.4 46 24 46z"/>
        <path fill="#FBBC05" d="M11.5 28.2c-.5-1.3-.7-2.7-.7-4.2s.3-2.9.7-4.2v-5.6H4.2C2.8 17.1 2 20.5 2 24s.8 6.9 2.2 9.8l7.3-5.6z"/>
        <path fill="#EA4335" d="M24 10.6c3.3 0 6.2 1.1 8.5 3.3l6.3-6.3C34.9 4 29.9 2 24 2 15.4 2 7.9 6.9 4.2 14.2l7.3 5.6C13.3 14.5 18.2 10.6 24 10.6z"/>
      </svg>
      Continue with Google
    </a>

    <div class="divider">or</div>

    <button class="btn" id="passkey-btn" onclick="startPasskeyAuth('{{ session_id }}')">
      🔑 Sign in with Passkey
    </button>
  </div>

  <script>
    async function startPasskeyAuth(sessionId) {
      const res = await fetch('/auth/passkey/authenticate/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId }),
      });
      const options = await res.json();
      // Decode base64url fields
      options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
      if (options.publicKey.allowCredentials) {
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
          ...c, id: base64urlToBuffer(c.id)
        }));
      }
      const credential = await navigator.credentials.get(options);
      const body = {
        session_id: sessionId,
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        response: {
          authenticatorData: bufferToBase64url(credential.response.authenticatorData),
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          signature: bufferToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null,
        },
        type: credential.type,
      };
      const finish = await fetch('/auth/passkey/authenticate/finish', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const result = await finish.json();
      if (result.redirect) window.location.href = result.redirect;
      else alert('Passkey authentication failed: ' + (result.error || 'unknown error'));
    }

    function base64urlToBuffer(b64) {
      const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - b64.length % 4);
      const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/') + pad);
      return Uint8Array.from(bin, c => c.charCodeAt(0));
    }

    function bufferToBase64url(buf) {
      return btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
  </script>
</body>
</html>
```

- [ ] **Step 2: Create src/ui/login.rs**

```rust
use axum::{
    extract::{Query, State},
    response::{Html, Redirect},
};
use minijinja::Environment;
use serde::Deserialize;
use std::sync::Arc;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LoginQuery {
    pub session: String,
}

pub async fn handler(
    State(app): State<Arc<AppState>>,
    Query(params): Query<LoginQuery>,
) -> Result<Html<String>, Redirect> {
    let auth_session = app.auth_sessions.get(&params.session);
    if auth_session.is_none() {
        return Err(Redirect::to("/"));
    }
    let client_id = auth_session.unwrap().client_id.clone();

    let mut env = Environment::new();
    env.add_template("login.html", include_str!("templates/login.html"))
        .unwrap();
    let tmpl = env.get_template("login.html").unwrap();
    let html = tmpl.render(minijinja::context! {
        session_id => params.session,
        client_name => client_id,
    })
    .unwrap();

    Ok(Html(html))
}
```

- [ ] **Step 3: Create src/ui/mod.rs**

```rust
pub mod login;
```

- [ ] **Step 4: Wire into router**

Add `mod ui;` to `src/main.rs`. Add route:

```rust
.route("/login", get(ui::login::handler))
```

- [ ] **Step 5: Test login page renders**

```bash
cargo run &
# First create a session manually via /authorize, then open the login URL
# Or test that /login with invalid session redirects to /
curl -v "http://localhost:4000/login?session=invalidsession" 2>&1 | grep "< HTTP"
# Expected: 302 redirect
kill %1
```

- [ ] **Step 6: Commit**

```bash
git add src/ui/ src/main.rs
git commit -m "feat: add hosted login page with Google and Passkey buttons"
```

---

### Task 9: Token endpoint

**Files:**
- Modify: `src/oidc/token.rs`

Handles two grant types: `authorization_code` and `refresh_token`.

- [ ] **Step 1: Implement src/oidc/token.rs**

```rust
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
    // authorization_code grant
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    // refresh_token grant
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
    // Authenticate the client
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

    // Retrieve the nonce stored in the auth_session (may have already been cleaned up)
    let nonce = app.auth_sessions.get(code).map(|s| s.nonce.clone()).flatten();

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
    let user = User::find_by_email(&app.pool, "").await; // placeholder — fetch by id
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
```

- [ ] **Step 2: Wire into router**

```rust
.route("/token", post(oidc::token::handler))
```

Add `use axum::routing::post;` to imports.

- [ ] **Step 3: Write tests**

Create `tests/token_test.rs`:

```rust
mod common;

#[tokio::test]
async fn code_exchange_returns_tokens() {
    let app = common::test_app().await;
    let (client_id, secret) = common::seed_client_with_secret(&app.pool, "app1", "http://app1.example/cb").await;
    let user_id = common::seed_user(&app.pool, "test@example.com").await;
    let (code, challenge, verifier) = common::create_auth_code(&app.pool, &client_id, user_id, "http://app1.example/cb").await;

    let res = app
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client_id),
            ("client_secret", &secret),
            ("code", &code),
            ("redirect_uri", "http://app1.example/cb"),
            ("code_verifier", &verifier),
        ])
        .await;

    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await;
    assert!(body["id_token"].is_string());
    assert!(body["refresh_token"].is_string());
}

#[tokio::test]
async fn code_reuse_returns_invalid_grant() {
    let app = common::test_app().await;
    let (client_id, secret) = common::seed_client_with_secret(&app.pool, "app1", "http://app1.example/cb").await;
    let user_id = common::seed_user(&app.pool, "test@example.com").await;
    let (code, _, verifier) = common::create_auth_code(&app.pool, &client_id, user_id, "http://app1.example/cb").await;

    let form = [
        ("grant_type", "authorization_code"), ("client_id", &client_id as &str),
        ("client_secret", &secret as &str), ("code", &code as &str),
        ("redirect_uri", "http://app1.example/cb"), ("code_verifier", &verifier as &str),
    ];

    app.post("/token").form(&form).await; // first use
    let res = app.post("/token").form(&form).await; // second use
    assert_eq!(res.status(), 400);
    let body: serde_json::Value = res.json().await;
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn wrong_pkce_verifier_returns_invalid_grant() {
    let app = common::test_app().await;
    let (client_id, secret) = common::seed_client_with_secret(&app.pool, "app1", "http://app1.example/cb").await;
    let user_id = common::seed_user(&app.pool, "test@example.com").await;
    let (code, _, _) = common::create_auth_code(&app.pool, &client_id, user_id, "http://app1.example/cb").await;

    let res = app
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"), ("client_id", &client_id as &str),
            ("client_secret", &secret as &str), ("code", &code as &str),
            ("redirect_uri", "http://app1.example/cb"), ("code_verifier", "WRONG_VERIFIER"),
        ])
        .await;
    assert_eq!(res.status(), 400);
    let body: serde_json::Value = res.json().await;
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_token_rotation_issues_new_token() {
    let app = common::test_app().await;
    let (client_id, secret) = common::seed_client_with_secret(&app.pool, "app1", "http://app1.example/cb").await;
    let user_id = common::seed_user(&app.pool, "test@example.com").await;
    let (code, _, verifier) = common::create_auth_code(&app.pool, &client_id, user_id, "http://app1.example/cb").await;

    let first_res: serde_json::Value = app
        .post("/token")
        .form(&[("grant_type", "authorization_code"), ("client_id", &client_id as &str),
                ("client_secret", &secret as &str), ("code", &code as &str),
                ("redirect_uri", "http://app1.example/cb"), ("code_verifier", &verifier as &str)])
        .await.json().await;

    let old_rt = first_res["refresh_token"].as_str().unwrap();

    let refresh_res: serde_json::Value = app
        .post("/token")
        .form(&[("grant_type", "refresh_token"), ("client_id", &client_id as &str),
                ("client_secret", &secret as &str), ("refresh_token", old_rt)])
        .await.json().await;

    assert!(refresh_res["id_token"].is_string());
    let new_rt = refresh_res["refresh_token"].as_str().unwrap();
    assert_ne!(old_rt, new_rt);

    // Old refresh token is now revoked
    let reuse_res = app
        .post("/token")
        .form(&[("grant_type", "refresh_token"), ("client_id", &client_id as &str),
                ("client_secret", &secret as &str), ("refresh_token", old_rt)])
        .await;
    assert_eq!(reuse_res.status(), 400);
}
```

Add helpers to `tests/common/mod.rs`:
```rust
use sha2::{Digest, Sha256};
use base64ct::{Base64UrlUnpadded, Encoding};

pub async fn seed_user(pool: &PgPool, email: &str) -> uuid::Uuid {
    crate::models::user::User::upsert(pool, email, Some("Test User"))
        .await.unwrap().id
}

pub async fn seed_client_with_secret(pool: &PgPool, client_id: &str, redirect_uri: &str) -> (String, String) {
    let secret = "test-secret-1234";
    let hash = crate::crypto::hash_secret(secret).unwrap();
    sqlx::query!(
        "INSERT INTO pps_auth.oauth_clients (id, client_id, client_secret_hash, redirect_uris)
         VALUES (gen_random_uuid(), $1, $2, ARRAY[$3]::text[])",
        client_id, hash, redirect_uri
    ).execute(pool).await.unwrap();
    (client_id.to_string(), secret.to_string())
}

pub async fn create_auth_code(
    pool: &PgPool,
    client_id: &str,
    user_id: uuid::Uuid,
    redirect_uri: &str,
) -> (String, String, String) {
    let verifier = "test_verifier_at_least_43_chars_long_abcdefghij";
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = Base64UrlUnpadded::encode_string(&hash);
    let code_plain = crate::crypto::generate_token();
    let code_hash = crate::crypto::hash_token(&code_plain);
    crate::models::authorization_code::AuthorizationCode::create(
        pool, client_id, user_id, &code_hash, &challenge, &[redirect_uri.to_string()]
    ).await.unwrap();
    (code_plain, challenge, verifier.to_string())
}
```

- [ ] **Step 4: Run tests**

```bash
TEST_DATABASE_URL=... cargo test token
```

Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/oidc/token.rs tests/
git commit -m "feat: add /token endpoint — code exchange, refresh, rotation"
```

---

### Task 10: Bearer middleware, UserInfo, Revoke

**Files:**
- Create: `src/middleware/bearer.rs`, `src/middleware/mod.rs`
- Modify: `src/oidc/userinfo.rs`, `src/oidc/revoke.rs`

- [ ] **Step 1: Create src/middleware/bearer.rs**

```rust
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::sync::Arc;
use crate::{error::AppError, oidc::token::Claims, state::AppState};

pub struct BearerClaims(pub Claims);

#[async_trait]
impl FromRequestParts<Arc<AppState>> for BearerClaims {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, AppError> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::InvalidToken)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::InvalidToken)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&state.base_url]);
        // aud validation: accept any aud (check per-endpoint if needed)
        validation.validate_aud = false;

        let data = jsonwebtoken::decode::<Claims>(token, &state.decoding_key, &validation)
            .map_err(|_| AppError::InvalidToken)?;

        Ok(BearerClaims(data.claims))
    }
}
```

- [ ] **Step 2: Create src/middleware/mod.rs**

```rust
pub mod bearer;
```

- [ ] **Step 3: Implement src/oidc/userinfo.rs**

```rust
use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;
use crate::{error::Result, middleware::bearer::BearerClaims, state::AppState};

pub async fn handler(
    State(_app): State<Arc<AppState>>,
    BearerClaims(claims): BearerClaims,
) -> Result<Json<Value>> {
    Ok(Json(json!({
        "sub":   claims.sub,
        "email": claims.email,
        "name":  claims.name,
        "roles": claims.roles,
    })))
}
```

- [ ] **Step 4: Implement src/oidc/revoke.rs**

```rust
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
```

- [ ] **Step 5: Wire into router**

```rust
mod middleware;
// ...
.route("/userinfo", get(oidc::userinfo::handler))
.route("/revoke", post(oidc::revoke::handler))
```

- [ ] **Step 6: Write userinfo test**

```rust
// In tests/token_test.rs

#[tokio::test]
async fn userinfo_returns_claims_for_valid_token() {
    let app = common::test_app().await;
    let (client_id, secret) = common::seed_client_with_secret(&app.pool, "app1", "http://app1.example/cb").await;
    let user_id = common::seed_user(&app.pool, "info@example.com").await;
    let (code, _, verifier) = common::create_auth_code(&app.pool, &client_id, user_id, "http://app1.example/cb").await;

    let tokens: serde_json::Value = app.post("/token")
        .form(&[("grant_type","authorization_code"),("client_id",&client_id as &str),
                ("client_secret",&secret as &str),("code",&code as &str),
                ("redirect_uri","http://app1.example/cb"),("code_verifier",&verifier as &str)])
        .await.json().await;

    let access_token = tokens["access_token"].as_str().unwrap();
    let res = app.get("/userinfo")
        .add_header("Authorization", format!("Bearer {access_token}"))
        .await;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await;
    assert_eq!(body["email"], "info@example.com");
}
```

- [ ] **Step 7: Run tests**

```bash
TEST_DATABASE_URL=... cargo test
```

Expected: all prior tests + userinfo test pass.

- [ ] **Step 8: Commit**

```bash
git add src/middleware/ src/oidc/userinfo.rs src/oidc/revoke.rs src/main.rs
git commit -m "feat: add bearer middleware, /userinfo, /revoke endpoints"
```

---

### Task 11: Google OAuth

**Files:**
- Create: `src/auth/google.rs`, `src/auth/mod.rs`

Two routes: `GET /auth/google?session=<id>` (redirect to Google) and `GET /auth/google/callback` (exchange code, upsert user, issue pps_auth code, redirect to sister app).

- [ ] **Step 1: Implement src/auth/google.rs**

```rust
use axum::{
    extract::{Query, State},
    response::Redirect,
    Json,
};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope, TokenResponse,
    reqwest::async_http_client,
};
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

    // Map the Google CSRF state back to our auth session
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
    // Verify CSRF state
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

    // Exchange code with Google
    let token_result = app
        .google_client
        .exchange_code(AuthorizationCode::new(q.code))
        .request_async(async_http_client)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Google token exchange failed: {e}")))?;

    // Fetch Google userinfo
    let userinfo: Value = reqwest::Client::new()
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(token_result.access_token().secret())
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Userinfo fetch failed: {e}")))?
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

    // Upsert user + credential
    let user = User::upsert(&app.pool, &email, name.as_deref()).await?;
    Credential::upsert(&app.pool, user.id, "google", &google_sub, &userinfo).await?;

    // Issue our own authorization code
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

    // Build redirect back to sister app
    let mut redirect_url = auth_session.redirect_uri.clone();
    redirect_url.push_str(&format!("?code={code_plain}"));
    if let Some(state) = &auth_session.state {
        redirect_url.push_str(&format!("&state={state}"));
    }

    Ok(Redirect::to(&redirect_url))
}
```

- [ ] **Step 2: Create src/auth/mod.rs**

```rust
pub mod google;
pub mod passkey;
```

(Create `src/auth/passkey.rs` as a stub — implemented in Task 12.)

- [ ] **Step 3: Wire into router**

```rust
mod auth;
// ...
.route("/auth/google", get(auth::google::start))
.route("/auth/google/callback", get(auth::google::callback))
```

- [ ] **Step 4: Commit**

```bash
git add src/auth/
git commit -m "feat: add Google OAuth upstream flow"
```

---

### Task 12: Passkey (WebAuthn)

**Files:**
- Modify: `src/auth/passkey.rs`

Four endpoints: register/start, register/finish, authenticate/start, authenticate/finish.

- [ ] **Step 1: Implement src/auth/passkey.rs**

```rust
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
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
    Ok(Json(serde_json::to_value(ccr).unwrap()))
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
    let cred_data = serde_json::to_value(&passkey).unwrap();
    let cred_id = base64ct::Base64UrlUnpadded::encode_string(passkey.cred_id().0.as_slice());

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
    // Load all passkey credentials from DB (for allow-list)
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
    Ok(Json(serde_json::to_value(rcr).unwrap()))
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

    // Find credential + user by credential ID
    let cred_id = base64ct::Base64UrlUnpadded::encode_string(result.cred_id().0.as_slice());
    let cred = Credential::find_by_provider(&app.pool, "passkey", &cred_id)
        .await?
        .ok_or_else(|| AppError::InvalidGrant("credential not found".to_string()))?;

    // Update counter in DB
    let updated_cred: Passkey = sqlx::query_scalar!(
        "SELECT credential_data FROM pps_auth.credentials WHERE type = 'passkey' AND provider_id = $1",
        cred_id
    )
    .fetch_one(&app.pool)
    .await
    .map(|v| serde_json::from_value(v).unwrap())?;

    // updated_cred.update_credential(&result) — update counter
    let mut passkey: Passkey = serde_json::from_value(cred.credential_data.clone()).unwrap();
    passkey.update_credential(&result);
    let updated_data = serde_json::to_value(&passkey).unwrap();
    sqlx::query!(
        "UPDATE pps_auth.credentials SET credential_data = $1 WHERE type = 'passkey' AND provider_id = $2",
        updated_data, cred_id
    ).execute(&app.pool).await?;

    // Retrieve auth_session and issue code
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
    ).await?;

    app.auth_sessions.remove(&req.session_id);

    let mut redirect_url = auth_session.redirect_uri.clone();
    redirect_url.push_str(&format!("?code={code_plain}"));
    if let Some(state) = &auth_session.state {
        redirect_url.push_str(&format!("&state={state}"));
    }

    Ok(Json(json!({ "redirect": redirect_url })))
}
```

- [ ] **Step 2: Wire into router**

```rust
.route("/auth/passkey/register/start",    post(auth::passkey::register_start))
.route("/auth/passkey/register/finish",   post(auth::passkey::register_finish))
.route("/auth/passkey/authenticate/start",  post(auth::passkey::auth_start))
.route("/auth/passkey/authenticate/finish", post(auth::passkey::auth_finish))
```

- [ ] **Step 3: Compile check**

```bash
cargo build
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add src/auth/passkey.rs src/main.rs
git commit -m "feat: add WebAuthn passkey registration and authentication"
```

---

### Task 13: Seed script

**Files:**
- Modify: `src/bin/seed.rs`

Seeds the three sister app OAuth clients into the database.

- [ ] **Step 1: Implement src/bin/seed.rs**

```rust
use pps_auth::crypto;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let db_url = std::env::var("DATABASE_URL")?;
    let pool = pps_auth::db::connect(&db_url).await?;

    let clients = vec![
        ("portfolio_chatbot",  vec!["http://localhost:3002/users/auth/pps_auth/callback", "https://chat.ppsoftsolutions.com/users/auth/pps_auth/callback"]),
        ("trading_bot",        vec!["http://localhost:3003/auth/callback", "https://trading.ppsoftsolutions.com/auth/callback"]),
    ];

    for (client_id, redirect_uris) in clients {
        let secret = crypto::generate_token();
        let hash = crypto::hash_secret(&secret)?;
        let uris: Vec<String> = redirect_uris.iter().map(|s| s.to_string()).collect();
        sqlx::query!(
            r#"INSERT INTO pps_auth.oauth_clients (id, client_id, client_secret_hash, redirect_uris)
               VALUES (gen_random_uuid(), $1, $2, $3)
               ON CONFLICT (client_id) DO UPDATE SET client_secret_hash = EXCLUDED.client_secret_hash"#,
            client_id,
            hash,
            &uris as &[String],
        )
        .execute(&pool)
        .await?;
        println!("client_id={client_id}  client_secret={secret}");
    }

    println!("\nSave these secrets in each sister app's .env as PPS_AUTH_CLIENT_SECRET");
    Ok(())
}
```

- [ ] **Step 2: Make src/lib.rs for bin access**

Add `src/lib.rs`:
```rust
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod middleware;
pub mod models;
pub mod oidc;
pub mod state;
pub mod ui;
pub mod auth;
```

- [ ] **Step 3: Run seed**

```bash
cargo run --bin seed
```

Expected: prints three client_id + client_secret pairs.

- [ ] **Step 4: Commit**

```bash
git add src/bin/seed.rs src/lib.rs
git commit -m "feat: add seed script for sister app OAuth clients"
```

---

### Task 14: Integration tests

**Files:**
- Create: `tests/oidc_flow_test.rs`

Full round-trip: authorize → login via Google (mocked) → token → userinfo.

- [ ] **Step 1: Write tests/oidc_flow_test.rs**

```rust
mod common;
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};

#[tokio::test]
async fn full_oidc_flow_google() {
    let mock_google = MockServer::start().await;
    Mock::given(method("POST")).and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "google-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": "ignored-here"
        })))
        .mount(&mock_google)
        .await;
    Mock::given(method("GET")).and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "google-sub-123",
            "email": "full_flow@example.com",
            "name": "Full Flow User"
        })))
        .mount(&mock_google)
        .await;

    let app = common::test_app_with_google_base(&mock_google.uri()).await;
    let (client_id, _) = common::seed_client_with_secret(&app.pool, "chatbot", "http://chatbot.test/cb").await;

    // Step 1: /authorize → get session id
    let auth_res = app.get(&format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri=http://chatbot.test/cb&code_challenge=challenge123&code_challenge_method=S256"
    )).await;
    assert_eq!(auth_res.status(), 302);
    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    let session_id = location.split("session=").nth(1).unwrap();

    // Simulate Google callback with our session
    let callback_res = app.get(&format!(
        "/auth/google/callback?code=google-code&state={session_id}"
    )).await;
    assert_eq!(callback_res.status(), 302);
    let cb_location = callback_res.headers().get("location").unwrap().to_str().unwrap();
    assert!(cb_location.contains("http://chatbot.test/cb"));
    assert!(cb_location.contains("code="));
}

#[tokio::test]
async fn discovery_and_jwks_are_consistent() {
    let app = common::test_app().await;

    let discovery: serde_json::Value = app.get("/.well-known/openid-configuration").await.json().await;
    let jwks_uri = discovery["jwks_uri"].as_str().unwrap();
    assert!(jwks_uri.ends_with("/.well-known/jwks.json"));

    let jwks: serde_json::Value = app.get("/.well-known/jwks.json").await.json().await;
    let keys = jwks["keys"].as_array().unwrap();
    assert!(!keys.is_empty());
    assert_eq!(keys[0]["alg"], "RS256");
    assert_eq!(keys[0]["kty"], "RSA");
}
```

- [ ] **Step 2: Run all tests**

```bash
TEST_DATABASE_URL=... cargo test
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add tests/oidc_flow_test.rs
git commit -m "test: add integration tests for full OIDC flow and discovery"
```

---

### Task 15: Dockerfile

**Files:**
- Create: `Dockerfile`

- [ ] **Step 1: Create Dockerfile**

```dockerfile
FROM rust:1.78-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
# Pre-cache dependencies
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release && rm -rf src
COPY src ./src
COPY migrations ./migrations
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/pps_auth .
COPY --from=builder /app/target/release/seed .
EXPOSE 4000
CMD ["./pps_auth"]
```

- [ ] **Step 2: Test Docker build**

```bash
docker build -t pps_auth .
```

Expected: image builds successfully.

- [ ] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "feat: add multi-stage Dockerfile"
```

---

## Summary

After completing all 15 tasks, `pps_auth` will be a fully functional OIDC Authorization Server with:
- RS256 JWT issuance + JWKS endpoint
- Google OAuth and Passkey authentication
- Authorization Code + PKCE flow
- Refresh token rotation with theft detection
- Seeded OAuth clients for all three sister apps
