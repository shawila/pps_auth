use pps_auth::crypto;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let db_url = std::env::var("DATABASE_URL")?;
    let pool = pps_auth::db::connect(&db_url).await?;

    // ── OAuth clients ────────────────────────────────────────────────────────
    let clients: Vec<(&str, Vec<&str>, bool)> = vec![
        (
            "portfolio_chatbot",
            vec!["http://localhost:3000/auth/pps_auth/callback"],
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
        let secret = crypto::generate_token();
        let hash = crypto::hash_secret(&secret)?;
        let uris: Vec<String> = redirect_uris.iter().map(|s| s.to_string()).collect();
        sqlx::query!(
            r#"INSERT INTO pps_auth.oauth_clients
                   (id, client_id, client_secret_hash, redirect_uris, allow_signups)
               VALUES (gen_random_uuid(), $1, $2, $3, $4)
               ON CONFLICT (client_id) DO UPDATE
                   SET client_secret_hash = EXCLUDED.client_secret_hash,
                       redirect_uris      = EXCLUDED.redirect_uris,
                       allow_signups      = EXCLUDED.allow_signups"#,
            client_id,
            hash,
            &uris as &[String],
            allow_signups,
        )
        .execute(&pool)
        .await?;
        println!("client_id={client_id}  client_secret={secret}");
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

    println!("\nSave these secrets in each sister app's .env as PPS_AUTH_CLIENT_SECRET");
    Ok(())
}
