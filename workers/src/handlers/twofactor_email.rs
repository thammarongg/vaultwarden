//! Email two-step login (phase 4) and the 2FA `userVerificationToken` used by current web vaults
//! (vaultwarden PR #7563), ported from vaultwarden `api/core/two_factor/email.rs` and
//! `auth/two_factor.rs`.
//!
//! A verification token is a short-lived JWT the server hands out after the user re-entered
//! their master password (`get-authenticator`, `get-email`); the follow-up enable/disable call
//! must present it, bound to the user, the provider data (TOTP key / email) and the expected
//! enabled state. Older clients that send `masterPasswordHash` instead are still accepted.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use chrono::Utc;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::auth::AuthUser;
use crate::crypto::{ct_eq, generate_email_token};
use crate::d1_query;
use crate::db;
use crate::error::AppError;
use crate::mail;
use crate::models::twofactor::{TwoFactor, TwoFactorType};
use crate::models::user::{PasswordOrOtpData, User};

// ---------------------------------------------------------------------------
// userVerificationToken (vaultwarden `auth::two_factor`)
// ---------------------------------------------------------------------------

const UVT_ISSUER: &str = "vaultwarden-cf|api.2fa";
const UVT_TTL_MINUTES: i64 = 5;

#[derive(Serialize, Deserialize)]
struct TwoFactorClaims<T> {
    iss: String,
    sub: String,
    enabled: bool,
    claims: T,
}

/// Each provider's claims reject unknown fields, so a token minted for one provider can't be
/// replayed against another.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatorClaims {
    authenticator_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailClaims {
    email: Option<String>,
}

fn uvt_key(env: &Env) -> Result<jwt_compact::alg::Hs256Key, AppError> {
    let secret = env.secret("JWT_SECRET")?.to_string();
    // Domain-separate from access tokens signed with the same secret.
    Ok(jwt_compact::alg::Hs256Key::new(
        format!("{secret}|2fa-verification").as_bytes(),
    ))
}

fn uvt_encode<T: Serialize>(env: &Env, user_id: &str, enabled: bool, claims: T) -> Result<String, AppError> {
    use jwt_compact::AlgorithmExt;
    let jwt = jwt_compact::Claims::new(TwoFactorClaims {
        iss: UVT_ISSUER.to_string(),
        sub: user_id.to_string(),
        enabled,
        claims,
    })
    .set_duration_and_issuance(
        &crate::auth::jwt_time_options(),
        chrono::Duration::minutes(UVT_TTL_MINUTES),
    )
    .set_not_before(Utc::now());
    jwt_compact::alg::Hs256
        .token(&jwt_compact::Header::empty(), &jwt, &uvt_key(env)?)
        .map_err(|_| AppError::Crypto("Failed to create verification token".to_string()))
}

fn uvt_decode<T: DeserializeOwned>(env: &Env, token: &str, user_id: &str, enabled: bool) -> Result<T, AppError> {
    use jwt_compact::AlgorithmExt;
    let invalid = |why: &str| AppError::BadRequest(format!("Invalid verification token: {why}"));
    let untrusted = jwt_compact::UntrustedToken::new(token).map_err(|_| invalid("malformed"))?;
    let token = jwt_compact::alg::Hs256
        .validator::<TwoFactorClaims<T>>(&uvt_key(env)?)
        .validate(&untrusted)
        .map_err(|_| invalid("signature or provider"))?;
    let opts = crate::auth::jwt_time_options();
    token
        .claims()
        .validate_expiration(&opts)
        .map_err(|_| invalid("expired"))?;
    let claims = token.into_parts().1.custom;
    if claims.iss != UVT_ISSUER {
        return Err(invalid("issuer"));
    }
    if claims.sub != user_id {
        return Err(invalid("Invalid user"));
    }
    if claims.enabled != enabled {
        return Err(invalid("Invalid state"));
    }
    Ok(claims.claims)
}

pub fn authenticator_token(env: &Env, user_id: &str, key: &str, enabled: bool) -> Result<String, AppError> {
    uvt_encode(
        env,
        user_id,
        enabled,
        AuthenticatorClaims {
            authenticator_key: key.to_string(),
        },
    )
}

pub fn validate_authenticator(env: &Env, token: &str, user_id: &str, key: &str, enabled: bool) -> Result<(), AppError> {
    let claims: AuthenticatorClaims = uvt_decode(env, token, user_id, enabled)?;
    if !claims.authenticator_key.eq_ignore_ascii_case(key) {
        return Err(AppError::BadRequest(
            "Invalid verification token: Invalid key".to_string(),
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebauthnClaims {
    webauthn_keys: Vec<i32>,
}

pub fn webauthn_token(env: &Env, user_id: &str, keys: Vec<i32>, enabled: bool) -> Result<String, AppError> {
    uvt_encode(env, user_id, enabled, WebauthnClaims { webauthn_keys: keys })
}

pub fn validate_webauthn(env: &Env, token: &str, user_id: &str, keys: &[i32], enabled: bool) -> Result<(), AppError> {
    let claims: WebauthnClaims = uvt_decode(env, token, user_id, enabled)?;
    if claims.webauthn_keys != keys {
        return Err(AppError::BadRequest(
            "Invalid verification token: Invalid keys".to_string(),
        ));
    }
    Ok(())
}

fn email_token(env: &Env, user_id: &str, email: Option<String>, enabled: bool) -> Result<String, AppError> {
    uvt_encode(env, user_id, enabled, EmailClaims { email })
}

fn validate_email(env: &Env, token: &str, user_id: &str, email: &str, enabled: bool) -> Result<(), AppError> {
    let claims: EmailClaims = uvt_decode(env, token, user_id, enabled)?;
    if enabled && claims.email.as_deref() != Some(email) {
        return Err(AppError::BadRequest(
            "Invalid verification token: Invalid email".to_string(),
        ));
    }
    Ok(())
}

/// Accept either a verification token (checked by `check`) or the master password.
pub async fn verify_token_or_password(
    user: &User,
    uvt: Option<&str>,
    master_password_hash: Option<&str>,
    check: impl FnOnce(&str) -> Result<(), AppError>,
) -> Result<(), AppError> {
    if let Some(t) = uvt.filter(|t| !t.is_empty()) {
        return check(t);
    }
    if let Some(h) = master_password_hash {
        if user.verify_master_password(h).await?.is_valid() {
            return Ok(());
        }
    }
    Err(AppError::Unauthorized("Invalid password".to_string()))
}

// ---------------------------------------------------------------------------
// Email token data (vaultwarden `EmailTokenData`, stored in twofactor.data)
// ---------------------------------------------------------------------------

const EMAIL_TOKEN_SIZE: usize = 6;
const EMAIL_ATTEMPTS_LIMIT: u64 = 3;
const EMAIL_EXPIRATION_SECS: i64 = 600;

#[derive(Serialize, Deserialize)]
pub struct EmailTokenData {
    pub email: String,
    pub last_token: Option<String>,
    pub token_sent: i64,
    pub attempts: u64,
}

impl EmailTokenData {
    fn new(email: String, token: Option<String>) -> Self {
        Self {
            email,
            last_token: token,
            token_sent: Utc::now().timestamp(),
            attempts: 0,
        }
    }

    fn from_json(s: &str) -> Result<Self, AppError> {
        serde_json::from_str(s).map_err(|_| AppError::BadRequest("Could not decode EmailTokenData".to_string()))
    }

    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// vaultwarden `obscure_email`: keep two characters of the local part.
pub fn obscure_email(email: &str) -> String {
    let (name, domain) = email.rsplit_once('@').unwrap_or((email, ""));
    let n = name.chars().count();
    let shown = if n <= 3 {
        "*".repeat(n)
    } else {
        format!("{}{}", name.chars().take(2).collect::<String>(), "*".repeat(n - 2))
    };
    format!("{shown}@{domain}")
}

pub(crate) async fn find_tf(db: &db::Db, user_id: &str, atype: TwoFactorType) -> Result<Option<TwoFactor>, AppError> {
    Ok(db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[user_id.into(), (atype as i32).into()])?
        .first(None)
        .await?)
}

async fn save_data(db: &db::Db, uuid: &str, data: &str) -> Result<(), AppError> {
    d1_query!(db, "UPDATE twofactor SET data = ?1 WHERE uuid = ?2", data, uuid)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    Ok(())
}

pub(crate) async fn load_user(db: &db::Db, user_id: &str) -> Result<User, AppError> {
    db.prepare(crate::models::user::select_user_by_id_sql())
        .bind(&[user_id.into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))
}

/// Issue a fresh login code and email it (vaultwarden `send_token`).
pub async fn send_login_token(env: &Env, db: &db::Db, user_id: &str) -> Result<(), AppError> {
    let tf = find_tf(db, user_id, TwoFactorType::Email)
        .await?
        .ok_or_else(|| AppError::BadRequest("Two factor not found".to_string()))?;
    let mut data = EmailTokenData::from_json(&tf.data)?;
    let token = generate_email_token(EMAIL_TOKEN_SIZE)?;
    data.last_token = Some(token.clone());
    data.token_sent = Utc::now().timestamp();
    save_data(db, &tf.uuid, &data.to_json()).await?;
    mail::send_twofactor_token(env, &data.email, &token).await
}

/// Check an emailed login code (vaultwarden `validate_email_code_str`).
pub async fn validate_login_code(db: &db::Db, tf: &TwoFactor, code: &str) -> Result<(), AppError> {
    let mut data = EmailTokenData::from_json(&tf.data)?;
    let invalid = || AppError::BadRequest("Token is invalid".to_string());
    let Some(issued) = data.last_token.clone() else {
        return Err(invalid());
    };
    if !ct_eq(&issued, code.trim()) {
        data.attempts = data.attempts.saturating_add(1);
        if data.attempts >= EMAIL_ATTEMPTS_LIMIT {
            data.last_token = None;
            data.attempts = 0;
        }
        save_data(db, &tf.uuid, &data.to_json()).await?;
        return Err(invalid());
    }
    data.last_token = None;
    data.attempts = 0;
    save_data(db, &tf.uuid, &data.to_json()).await?;
    if data.token_sent + EMAIL_EXPIRATION_SECS < Utc::now().timestamp() {
        return Err(AppError::BadRequest("Token has expired".to_string()));
    }
    Ok(())
}

/// `TwoFactorProviders2` entry for email: `{"Email": "ab***@example.com"}`.
pub fn login_provider_data(tf: &TwoFactor) -> Value {
    match EmailTokenData::from_json(&tf.data) {
        Ok(d) => json!({ "Email": obscure_email(&d.email) }),
        Err(_) => Value::Null,
    }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

fn require_mail(env: &Env) -> Result<(), AppError> {
    if mail::mail_enabled(env) {
        Ok(())
    } else {
        Err(AppError::BadRequest("Email 2FA is disabled".to_string()))
    }
}

/// POST /api/two-factor/get-email
#[worker::send]
pub async fn get_email(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    verify_token_or_password(&user, None, data.master_password_hash.as_deref(), |_| Ok(())).await?;
    let (enabled, email) = match find_tf(&db, &user_id, TwoFactorType::Email).await? {
        Some(tf) => (true, Some(EmailTokenData::from_json(&tf.data)?.email)),
        None => (false, None),
    };
    Ok(Json(json!({
        "email": { "enabled": enabled, "email": email },
        "userVerificationToken": email_token(&env, &user_id, email.clone(), enabled)?,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailData {
    email: String,
    user_verification_token: Option<String>,
    master_password_hash: Option<String>,
}

/// POST /api/two-factor/send-email: send a code to the address being set up.
#[worker::send]
pub async fn send_email(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<SendEmailData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    verify_token_or_password(
        &user,
        data.user_verification_token.as_deref(),
        data.master_password_hash.as_deref(),
        |t| validate_email(&env, t, &user_id, &data.email, false),
    )
    .await?;
    require_mail(&env)?;
    let email = data.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(AppError::BadRequest("Invalid email".to_string()));
    }
    let token = generate_email_token(EMAIL_TOKEN_SIZE)?;
    let pending = EmailTokenData::new(email.clone(), Some(token.clone()));
    let tf = TwoFactor::new(
        user_id.clone(),
        TwoFactorType::EmailVerificationChallenge,
        pending.to_json(),
    );
    // Setting up a new address replaces the enabled one only once it is verified.
    db.batch(vec![
        d1_query!(
            &db,
            "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
            user_id,
            TwoFactorType::EmailVerificationChallenge as i32
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            &db,
            "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, 1, ?4, 0)",
            tf.uuid,
            user_id,
            TwoFactorType::EmailVerificationChallenge as i32,
            tf.data
        )
        .map_err(|_| AppError::Database)?,
    ])
    .await?;
    mail::send_twofactor_token(&env, &email, &token).await?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableEmailData {
    email: String,
    token: String,
    user_verification_token: Option<String>,
    master_password_hash: Option<String>,
}

/// PUT/POST /api/two-factor/email: verify the code and enable email 2FA.
#[worker::send]
pub async fn enable_email(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableEmailData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    verify_token_or_password(
        &user,
        data.user_verification_token.as_deref(),
        data.master_password_hash.as_deref(),
        |t| validate_email(&env, t, &user_id, &data.email, false),
    )
    .await?;
    let tf = find_tf(&db, &user_id, TwoFactorType::EmailVerificationChallenge)
        .await?
        .ok_or_else(|| AppError::BadRequest("Two factor not found".to_string()))?;
    let mut pending = EmailTokenData::from_json(&tf.data)?;
    let Some(issued) = pending.last_token.clone() else {
        return Err(AppError::BadRequest("No token available".to_string()));
    };
    if !ct_eq(&issued, data.token.trim()) || !pending.email.eq_ignore_ascii_case(data.email.trim()) {
        return Err(AppError::BadRequest("Token is invalid".to_string()));
    }
    pending.last_token = None;
    pending.attempts = 0;
    db.batch(vec![
        d1_query!(
            &db,
            "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
            user_id,
            TwoFactorType::Email as i32
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            &db,
            "UPDATE twofactor SET atype = ?1, data = ?2, enabled = 1 WHERE uuid = ?3",
            TwoFactorType::Email as i32,
            pending.to_json(),
            tf.uuid
        )
        .map_err(|_| AppError::Database)?,
    ])
    .await?;
    crate::handlers::twofactor::generate_recovery_code_for_user(&db, &user_id).await?;
    Ok(Json(json!({ "email": pending.email, "enabled": true, "object": "twoFactorEmail" })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableEmailData {
    user_verification_token: Option<String>,
    master_password_hash: Option<String>,
}

/// DELETE /api/two-factor/email
#[worker::send]
pub async fn disable_email(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableEmailData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    if let Some(tf) = find_tf(&db, &user_id, TwoFactorType::Email).await? {
        let email = EmailTokenData::from_json(&tf.data)?.email;
        verify_token_or_password(
            &user,
            data.user_verification_token.as_deref(),
            data.master_password_hash.as_deref(),
            |t| validate_email(&env, t, &user_id, &email, true),
        )
        .await?;
        d1_query!(&db, "DELETE FROM twofactor WHERE uuid = ?1", tf.uuid)
            .map_err(|_| AppError::Database)?
            .run()
            .await?;
    }
    crate::handlers::twofactor::after_provider_removed(&db, &user_id).await?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailLoginData {
    #[serde(alias = "Email")]
    email: Option<String>,
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    auth_request_id: Option<String>,
    auth_request_access_code: Option<String>,
}

/// POST /api/two-factor/send-email-login (no bearer token): email a login code.
#[worker::send]
pub async fn send_email_login(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Json(data): Json<SendEmailLoginData>,
) -> Result<Json<Value>, AppError> {
    require_mail(&env)?;
    crate::handlers::enforce_ip_rate_limit(
        &env,
        &headers,
        "LOGIN_RATE_LIMITER",
        "send-email-login",
        "Too many requests. Please try again later.",
    )
    .await?;
    let wrong = || AppError::BadRequest("Username or password is incorrect. Try again".to_string());
    let email = data
        .email
        .as_deref()
        .map(|e| e.trim().to_lowercase())
        .filter(|e| !e.is_empty())
        .ok_or_else(wrong)?;
    let db = db::get_db(&env)?;
    let user = User::find_by_email(&db, &email).await?.ok_or_else(wrong)?;
    if let Some(hash) = data.master_password_hash.as_deref().filter(|h| !h.is_empty()) {
        if !user.verify_master_password(hash).await?.is_valid() {
            return Err(wrong());
        }
    } else if let (Some(id), Some(code)) = (data.auth_request_id.as_deref(), data.auth_request_access_code.as_deref()) {
        // Login with device: the request must be approved, unused, fresh and match its code.
        #[derive(Deserialize)]
        struct Req {
            access_code: String,
            approved: Option<i32>,
            authentication_date: Option<String>,
            fresh: i32,
        }
        let req: Req = db
            .prepare(
                "SELECT access_code, approved, authentication_date,
                        creation_date >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-5 minutes') AS fresh
                 FROM auth_requests WHERE uuid = ?1 AND user_uuid = ?2",
            )
            .bind(&[id.into(), user.id.clone().into()])?
            .first(None)
            .await?
            .ok_or_else(|| AppError::BadRequest("AuthRequest doesn't exist".to_string()))?;
        if req.approved != Some(1) || req.authentication_date.is_some() || req.fresh == 0 || !ct_eq(&req.access_code, code) {
            return Err(AppError::BadRequest("AuthRequest doesn't exist".to_string()));
        }
    } else {
        return Err(AppError::BadRequest(
            "No password hash has been submitted.".to_string(),
        ));
    }
    send_login_token(&env, &db, &user.id).await?;
    Ok(Json(json!({})))
}
