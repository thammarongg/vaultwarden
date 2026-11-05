//! 2FA/SSO connector pages (`/*-connector.html`) served with a 200, never a redirect.
//!
//! Workers static assets (`html_handling = "auto-trailing-slash"`) answer `/x.html` with a 307 to
//! `/x`. The desktop app loads `webauthn-connector.html` in an iframe and treats any navigation
//! of it as an external link, so the redirect opened the page in the system browser, where the
//! result has no parent window to go back to and login hangs. vaultwarden serves these files
//! directly (and without CSP / X-Frame-Options, see `src/util.rs`); this does the same by
//! reading the asset from the ASSETS binding under its extensionless name.

use axum::extract::State;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use worker::Env;

use crate::error::AppError;

pub const PAGES: [&str; 7] = [
    "/duo-redirect-connector.html",
    "/proxy-cookie-redirect-connector.html",
    "/redirect-connector.html",
    "/sso-connector.html",
    "/webauthn-connector.html",
    "/webauthn-fallback-connector.html",
    "/webauthn-mobile-connector.html",
];

#[worker::send]
pub async fn connector_page(State(env): State<Arc<Env>>, uri: Uri) -> Result<Response, AppError> {
    let path = uri.path();
    if !PAGES.contains(&path) {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let asset = format!("https://assets.local{}", path.trim_end_matches(".html"));
    let assets = env.assets("ASSETS").map_err(|e| {
        log::error!("ASSETS binding: {e}");
        AppError::Internal
    })?;
    let res = assets.fetch(asset, None).await.map_err(|e| {
        log::error!("connector asset fetch: {e}");
        AppError::Internal
    })?;
    if res.status() != StatusCode::OK {
        log::error!("connector asset {path}: status {}", res.status());
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let body = axum::body::Body::new(res.into_body());
    Ok((
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response())
}
