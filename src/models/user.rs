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

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> sqlx::Result<Option<Self>> {
        sqlx::query_as!(
            Self,
            "SELECT id, email, name, created_at FROM pps_auth.users WHERE id = $1",
            id
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
