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
