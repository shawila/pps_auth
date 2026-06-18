use pps_auth::crypto;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let db_url = std::env::var("DATABASE_URL")?;
    let pool = pps_auth::db::connect(&db_url).await?;

    let clients: Vec<(&str, Vec<&str>)> = vec![
        ("portfolio_chatbot", vec!["http://localhost:3000/auth/pps_auth/callback"]),
        ("trading_bot", vec![]),
        ("scheduler_python", vec!["http://localhost:5000/auth/callback"]),
    ];

    for (client_id, redirect_uris) in clients {
        let secret = crypto::generate_token();
        let hash = crypto::hash_secret(&secret)?;
        let uris: Vec<String> = redirect_uris.iter().map(|s| s.to_string()).collect();
        sqlx::query!(
            r#"INSERT INTO pps_auth.oauth_clients (id, client_id, client_secret_hash, redirect_uris)
               VALUES (gen_random_uuid(), $1, $2, $3)
               ON CONFLICT (client_id) DO UPDATE SET client_secret_hash = EXCLUDED.client_secret_hash"#,
            client_id,
            hash,
            &uris as &[String],
        )
        .execute(&pool)
        .await?;
        println!("client_id={client_id}  client_secret={secret}");
    }

    println!("\nSave these secrets in each sister app's .env as PPS_AUTH_CLIENT_SECRET");
    Ok(())
}
