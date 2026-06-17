use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use minijinja::Environment;
use serde::Deserialize;
use std::sync::Arc;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LoginQuery {
    pub session: String,
}

pub async fn handler(
    State(app): State<Arc<AppState>>,
    Query(params): Query<LoginQuery>,
) -> Response {
    let Some(session) = app.auth_sessions.get(&params.session) else {
        return Redirect::to("/").into_response();
    };
    let client_id = session.client_id.clone();
    drop(session);

    let mut env = Environment::new();
    if env.add_template("login.html", include_str!("templates/login.html")).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Html("Template error".to_string())).into_response();
    }
    let tmpl = match env.get_template("login.html") {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Html("Template not found".to_string())).into_response(),
    };
    match tmpl.render(minijinja::context! {
        session_id => params.session,
        client_name => client_id,
    }) {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Html("Render error".to_string())).into_response(),
    }
}
