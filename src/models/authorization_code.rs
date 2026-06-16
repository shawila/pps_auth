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
