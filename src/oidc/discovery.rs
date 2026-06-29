use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub claims_supported: Vec<String>,
}

pub async fn handler(State(state): State<Arc<AppState>>) -> Json<DiscoveryDocument> {
    let base = &state.base_url;
    Json(DiscoveryDocument {
        issuer: base.clone(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        userinfo_endpoint: format!("{base}/userinfo"),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        response_types_supported: vec!["code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        grant_types_supported: vec!["authorization_code".to_string(), "refresh_token".to_string()],
        token_endpoint_auth_methods_supported: vec!["client_secret_post".to_string()],
        scopes_supported: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
        claims_supported: vec![
            "sub".to_string(), "iss".to_string(), "email".to_string(),
            "name".to_string(), "roles".to_string(), "iat".to_string(), "exp".to_string(),
        ],
    })
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn discovery_has_required_fields() {
        let doc = super::DiscoveryDocument {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/authorize".to_string(),
            token_endpoint: "https://auth.example.com/token".to_string(),
            userinfo_endpoint: "https://auth.example.com/userinfo".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            response_types_supported: vec!["code".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["RS256".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            grant_types_supported: vec!["authorization_code".to_string(), "refresh_token".to_string()],
            token_endpoint_auth_methods_supported: vec!["client_secret_post".to_string()],
            scopes_supported: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
            claims_supported: vec!["sub".to_string(), "iss".to_string(), "email".to_string()],
        };
        assert_eq!(doc.issuer, "https://auth.example.com");
        assert!(doc.id_token_signing_alg_values_supported.contains(&"RS256".to_string()));
        assert!(doc.code_challenge_methods_supported.contains(&"S256".to_string()));
    }

    #[tokio::test]
    async fn handler_derives_endpoints_from_base_url() {
        let base = "https://example.com";
        let doc = super::DiscoveryDocument {
            issuer: base.to_string(),
            authorization_endpoint: format!("{base}/authorize"),
            token_endpoint: format!("{base}/token"),
            userinfo_endpoint: format!("{base}/userinfo"),
            jwks_uri: format!("{base}/.well-known/jwks.json"),
            response_types_supported: vec!["code".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["RS256".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            grant_types_supported: vec!["authorization_code".to_string(), "refresh_token".to_string()],
            token_endpoint_auth_methods_supported: vec!["client_secret_post".to_string()],
            scopes_supported: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
            claims_supported: vec!["sub".to_string(), "iss".to_string(), "email".to_string()],
        };
        assert_eq!(doc.authorization_endpoint, "https://example.com/authorize");
        assert_eq!(doc.token_endpoint, "https://example.com/token");
        assert_eq!(doc.jwks_uri, "https://example.com/.well-known/jwks.json");
        assert!(doc.scopes_supported.contains(&"openid".to_string()));
        assert!(doc.claims_supported.contains(&"sub".to_string()));
    }
}
