use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use jsonwebtoken::{Algorithm, Validation};
use std::sync::Arc;
use crate::{error::AppError, oidc::token::Claims, state::AppState};

pub struct BearerClaims(pub Claims);

#[async_trait]
impl FromRequestParts<Arc<AppState>> for BearerClaims {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, AppError> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::InvalidToken)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::InvalidToken)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&state.base_url]);
        // aud validation: accept any aud (check per-endpoint if needed)
        validation.validate_aud = false;

        let data = jsonwebtoken::decode::<Claims>(token, &state.decoding_key, &validation)
            .map_err(|_| AppError::InvalidToken)?;

        Ok(BearerClaims(data.claims))
    }
}
