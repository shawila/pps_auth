use axum::{
    extract::{Query, State},
    response::{Html, Redirect},
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
) -> Result<Html<String>, Redirect> {
    let auth_session = app.auth_sessions.get(&params.session);
    if auth_session.is_none() {
        return Err(Redirect::to("/"));
    }
    let client_id = auth_session.unwrap().client_id.clone();

    let mut env = Environment::new();
    env.add_template("login.html", include_str!("templates/login.html"))
        .unwrap();
    let tmpl = env.get_template("login.html").unwrap();
    let html = tmpl.render(minijinja::context! {
        session_id => params.session,
        client_name => client_id,
    })
    .unwrap();

    Ok(Html(html))
}
