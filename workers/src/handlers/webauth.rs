use axum::Json;
use serde_json::{json, Value};

/// GET /webauthn
///
/// Returns an empty list of WebAuthn credentials.
/// This prevents 404 errors and key-rotation issues when passkey login is enabled.
/// Vaultwarden does not yet support passkey login, so we return an empty list.
#[worker::send]
pub async fn get_webauthn_credentials() -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    }))
}
