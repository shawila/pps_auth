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
