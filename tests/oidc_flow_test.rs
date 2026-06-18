mod common;

#[tokio::test]
async fn discovery_and_jwks_are_consistent() {
    let app = common::test_app().await;

    let discovery: serde_json::Value = app.get("/.well-known/openid-configuration").await.json();
    let jwks_uri = discovery["jwks_uri"].as_str().unwrap();
    assert!(jwks_uri.ends_with("/.well-known/jwks.json"));

    let jwks: serde_json::Value = app.get("/.well-known/jwks.json").await.json();
    let keys = jwks["keys"].as_array().unwrap();
    assert!(!keys.is_empty());
    assert_eq!(keys[0]["alg"], "RS256");
    assert_eq!(keys[0]["kty"], "RSA");
}

/// Full OIDC Authorization Code + PKCE flow: authorize → token → userinfo.
/// Uses a directly-seeded auth code to bypass the login page UI.
#[tokio::test]
async fn full_oidc_code_flow_authorize_to_userinfo() {
    let app = common::test_app().await;
    let (client_id, secret) =
        common::seed_client_with_secret(&app.pool, "flow_client", "http://flow.test/cb").await;
    let user_id = common::seed_user(&app.pool, "flow@example.com").await;
    let (code, _, verifier) =
        common::create_auth_code(&app.pool, &client_id, user_id, "http://flow.test/cb").await;

    let tokens: serde_json::Value = app
        .post("/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", "http://flow.test/cb"),
            ("code_verifier", verifier.as_str()),
        ])
        .await
        .json();

    assert!(tokens["access_token"].is_string());
    assert!(tokens["refresh_token"].is_string());
    assert_eq!(tokens["token_type"], "Bearer");

    let access_token = tokens["access_token"].as_str().unwrap().to_string();
    let userinfo_res = app
        .get("/userinfo")
        .add_header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {access_token}"),
        )
        .await;

    assert_eq!(userinfo_res.status_code().as_u16(), 200);
    let userinfo: serde_json::Value = userinfo_res.json();
    assert_eq!(userinfo["email"], "flow@example.com");
    assert!(userinfo["sub"].is_string());
    assert!(userinfo["roles"].is_array());
}

#[tokio::test]
async fn authorize_valid_request_redirects_to_login_with_session() {
    let app = common::test_app().await;
    common::seed_client(&app.pool, "flow_client2", "http://flow2.test/cb").await;

    let res = app
        .get("/authorize?response_type=code&client_id=flow_client2&redirect_uri=http://flow2.test/cb&code_challenge=abc&code_challenge_method=S256")
        .await;

    assert_eq!(res.status_code().as_u16(), 303);
    let location = res.header("location");
    let loc_str = location.to_str().unwrap();
    assert!(loc_str.starts_with("/login?session="));
    assert!(loc_str.len() > "/login?session=".len());
}
