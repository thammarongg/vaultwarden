use axum::Json;
use serde_json::{json, Value};

/// GET /emergency-access/trusted
///
/// Returns the list of trusted emergency access contacts (grantees) for the current user.
/// This is a stub implementation that always returns an empty list since emergency access
/// is not supported in this minimal Bitwarden-compatible implementation.
///
/// In vaultwarden, when `emergency_access_allowed` is disabled, it returns an empty list.
/// We follow the same pattern here.
#[worker::send]
pub async fn get_trusted_contacts() -> Json<Value> {
    Json(json!({
        "data": [],
        "object": "list",
        "continuationToken": null
    }))
}

/// GET /emergency-access/granted
///
/// Returns the list of emergency access grants where the current user is a grantee.
/// This is a stub implementation that always returns an empty list.
#[worker::send]
pub async fn get_granted_access() -> Json<Value> {
    Json(json!({
        "data": [],
        "object": "list",
        "continuationToken": null
    }))
}
