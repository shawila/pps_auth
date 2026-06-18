use std::sync::Arc;
use axum_test::TestServer;
use sqlx::PgPool;
use sha2::{Digest, Sha256};
use base64ct::{Base64UrlUnpadded, Encoding};

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
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("DATABASE_URL or TEST_DATABASE_URL must be set");
    let pool = pps_auth::db::connect(&db_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    sqlx::query!("TRUNCATE pps_auth.authorization_codes, pps_auth.refresh_tokens, pps_auth.credentials, pps_auth.roles, pps_auth.users, pps_auth.oauth_clients CASCADE")
        .execute(&pool)
        .await
        .unwrap();

    let config = pps_auth::config::Config::from_env().unwrap();
    let state = Arc::new(pps_auth::state::AppState::new(pool.clone(), &config).unwrap());
    let app = pps_auth::build_router(state);
    TestApp { server: TestServer::new(app).unwrap(), pool }
}

pub async fn seed_client(pool: &PgPool, client_id: &str, redirect_uri: &str) {
    let hash = pps_auth::crypto::hash_secret("test-secret").unwrap();
    sqlx::query!(
        "INSERT INTO pps_auth.oauth_clients (id, client_id, client_secret_hash, redirect_uris)
         VALUES (gen_random_uuid(), $1, $2, ARRAY[$3]::text[])",
        client_id, hash, redirect_uri
    )
    .execute(pool)
    .await
    .unwrap();
}

pub async fn seed_user(pool: &PgPool, email: &str) -> uuid::Uuid {
    pps_auth::models::user::User::upsert(pool, email, Some("Test User"))
        .await.unwrap().id
}

pub async fn seed_client_with_secret(pool: &PgPool, client_id: &str, redirect_uri: &str) -> (String, String) {
    let secret = "test-secret-1234";
    let hash = pps_auth::crypto::hash_secret(secret).unwrap();
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
    let code_plain = pps_auth::crypto::generate_token();
    let code_hash = pps_auth::crypto::hash_token(&code_plain);
    pps_auth::models::authorization_code::AuthorizationCode::create(
        pool, client_id, user_id, &code_hash, &challenge, &[redirect_uri.to_string()]
    ).await.unwrap();
    (code_plain, challenge, verifier.to_string())
}
