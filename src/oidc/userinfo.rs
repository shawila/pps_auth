use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;
use crate::{error::Result, middleware::bearer::BearerClaims, state::AppState};

pub async fn handler(
    State(_app): State<Arc<AppState>>,
    BearerClaims(claims): BearerClaims,
) -> Result<Json<Value>> {
    Ok(Json(json!({
        "sub":   claims.sub,
        "email": claims.email,
        "name":  claims.name,
        "roles": claims.roles,
    })))
}
