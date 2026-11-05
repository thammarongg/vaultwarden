use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Worker error: {0}")]
    Worker(#[from] worker::Error),

    #[error("Database query failed")]
    Database,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Internal server error")]
    Internal,

    #[error("Two factor authentication required")]
    TwoFactorRequired(Value),

    #[error("API error response")]
    ApiJson { status: StatusCode, body: Value },
}

impl AppError {
    pub fn api_json(status: StatusCode, body: Value) -> Self {
        Self::ApiJson { status, body }
    }

    pub fn send_access_password_required() -> Self {
        Self::send_access_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "password_hash_b64_required",
        )
    }

    pub fn send_access_invalid() -> Self {
        Self::send_access_error(StatusCode::NOT_FOUND, "invalid_grant", "send_id_invalid")
    }

    pub fn send_access_password_invalid() -> Self {
        Self::send_access_error(
            StatusCode::NOT_FOUND,
            "invalid_grant",
            "password_hash_b64_invalid",
        )
    }

    fn send_access_error(status: StatusCode, error: &str, send_access_error_type: &str) -> Self {
        Self::api_json(
            status,
            json!({
                "kind": "expected_server",
                "error": error,
                "send_access_error_type": send_access_error_type,
            }),
        )
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::ApiJson { status, body } => (status, Json(body)).into_response(),
            AppError::TwoFactorRequired(json_body) => {
                // Return 400 Bad Request with the 2FA required JSON response as expected by clients
                (StatusCode::BAD_REQUEST, Json(json_body)).into_response()
            }
            other => {
                let status = other.status();
                if status.is_server_error() {
                    // Full detail (D1/worker/crypto messages) stays in the log only (vaultwarden #7777).
                    log::error!("{status}: {other}");
                }
                (status, Json(json!({ "error": other.client_message() }))).into_response()
            }
        }
    }
}

impl AppError {
    fn status(&self) -> StatusCode {
        match self {
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) | AppError::TwoFactorRequired(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            AppError::ApiJson { status, .. } => *status,
            AppError::Worker(_) | AppError::Database | AppError::Crypto(_) | AppError::Internal => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// Message safe to show a client: user-facing errors keep their text, internal ones are
    /// generic so database/runtime details never leave the server.
    pub fn client_message(&self) -> String {
        match self {
            AppError::NotFound(msg)
            | AppError::BadRequest(msg)
            | AppError::Unauthorized(msg)
            | AppError::TooManyRequests(msg) => msg.clone(),
            AppError::Database => "Database error".to_string(),
            AppError::Worker(_) | AppError::Crypto(_) | AppError::Internal => {
                "Internal server error".to_string()
            }
            AppError::TwoFactorRequired(_) => "Two factor authentication required".to_string(),
            AppError::ApiJson { .. } => "API error".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_access_error(
        app_error: AppError,
        expected_status: StatusCode,
        expected_error: &str,
        expected_type: &str,
    ) {
        let AppError::ApiJson { status, body } = app_error else {
            panic!("expected API JSON error");
        };

        assert_eq!(status, expected_status);
        assert_eq!(
            body,
            json!({
                "kind": "expected_server",
                "error": expected_error,
                "send_access_error_type": expected_type,
            })
        );
    }

    #[test]
    fn internal_errors_are_generic_for_clients() {
        let e = AppError::Crypto("secret detail".into());
        assert_eq!(e.client_message(), "Internal server error");
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(AppError::BadRequest("x".into()).client_message(), "x");
    }

    #[test]
    fn send_access_password_required_matches_client_contract() {
        assert_send_access_error(
            AppError::send_access_password_required(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "password_hash_b64_required",
        );
    }

    #[test]
    fn send_access_grant_failures_match_client_contract() {
        assert_send_access_error(
            AppError::send_access_invalid(),
            StatusCode::NOT_FOUND,
            "invalid_grant",
            "send_id_invalid",
        );
        assert_send_access_error(
            AppError::send_access_password_invalid(),
            StatusCode::NOT_FOUND,
            "invalid_grant",
            "password_hash_b64_invalid",
        );
    }
}
