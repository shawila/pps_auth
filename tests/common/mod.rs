use std::sync::Arc;
use axum_test::TestServer;
use sqlx::PgPool;

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
