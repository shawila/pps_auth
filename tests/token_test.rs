mod common;

#[tokio::test]
async fn code_exchange_returns_tokens() {
    let app = common::test_app().await;
    let (client_id, secret) = common::seed_client_with_secret(&app.pool, "token_app1", "http://app1.example/cb").await;
    let user_id = common::seed_user(&app.pool, "test@example.com").await;
    let (code, _challenge, verifier) = common::create_auth_code(&app.pool, &client_id, user_id, "http://app1.example/cb").await;

    let res = app
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", "http://app1.example/cb"),
            ("code_verifier", verifier.as_str()),
        ])
        .await;

    assert_eq!(res.status_code().as_u16(), 200);
    let body: serde_json::Value = res.json();
    assert!(body["id_token"].is_string());
    assert!(body["refresh_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
}

#[tokio::test]
async fn code_reuse_returns_invalid_grant() {
    let app = common::test_app().await;
    let (client_id, secret) = common::seed_client_with_secret(&app.pool, "token_app2", "http://app2.example/cb").await;
    let user_id = common::seed_user(&app.pool, "reuse@example.com").await;
    let (code, _, verifier) = common::create_auth_code(&app.pool, &client_id, user_id, "http://app2.example/cb").await;

    let form_data = vec![
        ("grant_type", "authorization_code"),
        ("client_id", client_id.as_str()),
        ("client_secret", secret.as_str()),
        ("code", code.as_str()),
        ("redirect_uri", "http://app2.example/cb"),
        ("code_verifier", verifier.as_str()),
    ];

    app.post("/token").form(&form_data).await; // first use
    let res = app.post("/token").form(&form_data).await; // second use
    assert_eq!(res.status_code().as_u16(), 400);
    let body: serde_json::Value = res.json();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn wrong_pkce_verifier_returns_invalid_grant() {
    let app = common::test_app().await;
    let (client_id, secret) = common::seed_client_with_secret(&app.pool, "token_app3", "http://app3.example/cb").await;
    let user_id = common::seed_user(&app.pool, "pkce@example.com").await;
    let (code, _, _) = common::create_auth_code(&app.pool, &client_id, user_id, "http://app3.example/cb").await;

    let res = app
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", "http://app3.example/cb"),
            ("code_verifier", "WRONG_VERIFIER"),
        ])
        .await;
    assert_eq!(res.status_code().as_u16(), 400);
    let body: serde_json::Value = res.json();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_token_rotation_issues_new_token() {
    let app = common::test_app().await;
    let (client_id, secret) = common::seed_client_with_secret(&app.pool, "token_app4", "http://app4.example/cb").await;
    let user_id = common::seed_user(&app.pool, "refresh@example.com").await;
    let (code, _, verifier) = common::create_auth_code(&app.pool, &client_id, user_id, "http://app4.example/cb").await;

    let first_res: serde_json::Value = app
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", "http://app4.example/cb"),
            ("code_verifier", verifier.as_str()),
        ])
        .await.json();

    let old_rt = first_res["refresh_token"].as_str().unwrap().to_string();

    let refresh_res: serde_json::Value = app
        .post("/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("refresh_token", old_rt.as_str()),
        ])
        .await.json();

    assert!(refresh_res["id_token"].is_string());
    let new_rt = refresh_res["refresh_token"].as_str().unwrap();
    assert_ne!(old_rt.as_str(), new_rt);

    // Old refresh token is now revoked
    let reuse_res = app
        .post("/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("refresh_token", old_rt.as_str()),
        ])
        .await;
    assert_eq!(reuse_res.status_code().as_u16(), 400);
}
