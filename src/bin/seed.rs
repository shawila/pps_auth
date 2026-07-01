use pps_auth::crypto;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let db_url = pps_auth::config::resolve_database_url()?;
    let pool = pps_auth::db::connect(&db_url).await?;

    // ── OAuth clients ────────────────────────────────────────────────────────
    let clients: Vec<(&str, Vec<&str>, bool)> = vec![
        (
            "portfolio_chatbot",
            vec!["http://localhost:3000/users/auth/pps_auth/callback"],
            true,
        ),
        (
            "trading_bot",
            vec!["https://trading.ppsoftsolutions.com/auth/callback"],
            false, // no self-sign-up; only pre-seeded users may log in
        ),
        (
            "scheduler_python",
            vec!["http://localhost:5000/auth/callback"],
            true,
        ),
    ];

    for (client_id, redirect_uris, allow_signups) in clients {
        let uris: Vec<String> = redirect_uris.iter().map(|s| s.to_string()).collect();

        // Check if client already exists — don't rotate the secret on re-runs.
        let existing = sqlx::query_scalar!(
            "SELECT client_secret_hash FROM pps_auth.oauth_clients WHERE client_id = $1",
            client_id
        )
        .fetch_optional(&pool)
        .await?;

        if existing.is_some() {
            sqlx::query!(
                r#"UPDATE pps_auth.oauth_clients
                   SET redirect_uris = $2, allow_signups = $3
                   WHERE client_id = $1"#,
                client_id,
                &uris as &[String],
                allow_signups,
            )
            .execute(&pool)
            .await?;
            println!("client_id={client_id}  (existing — secret unchanged)");
        } else {
            let secret = crypto::generate_token();
            let hash = crypto::hash_secret(&secret)?;
            sqlx::query!(
                r#"INSERT INTO pps_auth.oauth_clients
                       (id, client_id, client_secret_hash, redirect_uris, allow_signups)
                   VALUES (gen_random_uuid(), $1, $2, $3, $4)"#,
                client_id,
                hash,
                &uris as &[String],
                allow_signups,
            )
            .execute(&pool)
            .await?;
            println!("client_id={client_id}  client_secret={secret}");
        }
    }

    // ── Pre-seeded users ─────────────────────────────────────────────────────
    let users: Vec<(&str, Option<&str>)> = vec![
        ("salah.hawila@gmail.com", Some("Salah Hawila")),
    ];

    for (email, name) in users {
        sqlx::query!(
            r#"INSERT INTO pps_auth.users (id, email, name)
               VALUES (gen_random_uuid(), $1, $2)
               ON CONFLICT (email) DO NOTHING"#,
            email,
            name,
        )
        .execute(&pool)
        .await?;
        println!("user seeded: {email}");
    }

    // ── Roles ────────────────────────────────────────────────────────────────
    let roles: Vec<(&str, &str, &str)> = vec![
        ("salah.hawila@gmail.com", "portfolio_chatbot", "superuser"),
    ];

    for (email, client_id, role) in roles {
        sqlx::query!(
            r#"INSERT INTO pps_auth.roles (user_id, client_id, role)
               SELECT u.id, $2, $3
               FROM pps_auth.users u WHERE u.email = $1
               ON CONFLICT DO NOTHING"#,
            email,
            client_id,
            role,
        )
        .execute(&pool)
        .await?;
        println!("role seeded: {email} → {role} on {client_id}");
    }

    println!("\nSave these secrets in each sister app's .env as PPS_AUTH_CLIENT_SECRET");
    Ok(())
}
