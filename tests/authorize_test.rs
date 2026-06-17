mod common;

#[tokio::test]
async fn authorize_unknown_client_returns_401() {
    let app = common::test_app().await;
    let res = app
        .get("/authorize?response_type=code&client_id=unknown&redirect_uri=http://x&code_challenge=x&code_challenge_method=S256")
        .await;
    assert_eq!(res.status_code().as_u16(), 401);
    let body = res.json::<serde_json::Value>();
    assert_eq!(body["error"], "unauthorized_client");
}

#[tokio::test]
async fn authorize_redirect_uri_mismatch_returns_400() {
    let app = common::test_app().await;
    common::seed_client(&app.pool, "client_mismatch_test", "http://good.example/cb").await;
    let res = app
        .get("/authorize?response_type=code&client_id=client_mismatch_test&redirect_uri=http://evil.example&code_challenge=abc&code_challenge_method=S256")
        .await;
    assert_eq!(res.status_code().as_u16(), 400);
    let body = res.json::<serde_json::Value>();
    assert_eq!(body["error"], "redirect_uri_mismatch");
}

#[tokio::test]
async fn authorize_valid_request_redirects_to_login() {
    let app = common::test_app().await;
    common::seed_client(&app.pool, "client_valid_test", "http://good.example/cb").await;
    let res = app
        .get("/authorize?response_type=code&client_id=client_valid_test&redirect_uri=http://good.example/cb&code_challenge=abc&code_challenge_method=S256")
        .await;
    // axum Redirect::to() uses 303 See Other
    assert_eq!(res.status_code().as_u16(), 303);
    let location = res.header("location");
    assert!(location.to_str().unwrap().starts_with("/login?session="));
}
