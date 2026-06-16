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
