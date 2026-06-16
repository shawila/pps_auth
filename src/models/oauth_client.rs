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
