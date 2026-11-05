//! Emergency access (phase 4), ported from vaultwarden `api/core/emergency_access.rs` and
//! `db/models/emergency_access.rs`.
//!
//! Flow: the grantor invites a contact (email + invite token when mail is on, auto-accept for
//! existing accounts when it is off), the contact accepts, the grantor confirms (stores the
//! user key encrypted for the contact). The contact can then initiate recovery; after the wait
//! time it is approved automatically (on the next request by either side, and by the daily cron,
//! which also sends the reminder/timed-out emails), or the grantor approves/rejects it by hand.
//! Approved View access returns the grantor's personal items; Takeover lets the contact set a new
//! master password for the grantor (2FA removed, non-owner org memberships dropped).

use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::Env;

use crate::auth::Claims;
use crate::crypto::{generate_salt, hash_password_for_storage};
use crate::d1_query;
use crate::db;
use crate::error::AppError;
use crate::handlers::ciphers::RawJson;
use crate::mail;

pub mod status {
    pub const INVITED: i32 = 0;
    pub const ACCEPTED: i32 = 1;
    pub const CONFIRMED: i32 = 2;
    pub const RECOVERY_INITIATED: i32 = 3;
    pub const RECOVERY_APPROVED: i32 = 4;
}

pub mod access_type {
    pub const VIEW: i32 = 0;
    pub const TAKEOVER: i32 = 1;
}

/// vaultwarden `EMERGENCY_ACCESS_TIMEOUT_RANGE`.
const WAIT_DAYS: std::ops::RangeInclusive<i32> = 1..=90;

const COLS: &str = "uuid, grantor_uuid, grantee_uuid, email, key_encrypted, atype, status, wait_time_days, recovery_initiated_at, last_notification_at";

#[derive(Deserialize, Debug, Clone)]
pub struct EmergencyRow {
    pub uuid: String,
    pub grantor_uuid: String,
    pub grantee_uuid: Option<String>,
    pub email: Option<String>,
    pub key_encrypted: Option<String>,
    pub atype: i32,
    pub status: i32,
    pub wait_time_days: i32,
    pub recovery_initiated_at: Option<String>,
    pub last_notification_at: Option<String>,
}

#[derive(Deserialize)]
struct Person {
    uuid: String,
    email: String,
    name: String,
    avatar_color: Option<String>,
}

fn not_valid() -> AppError {
    AppError::BadRequest("Emergency access not valid.".to_string())
}

fn bad(msg: &str) -> AppError {
    AppError::BadRequest(msg.to_string())
}

fn type_str(atype: i32) -> &'static str {
    if atype == access_type::VIEW {
        "View"
    } else {
        "Takeover"
    }
}

fn parse_type(v: &Value) -> Result<i32, AppError> {
    let s = match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => String::new(),
    };
    match s.as_str() {
        "0" | "View" => Ok(access_type::VIEW),
        "1" | "Takeover" => Ok(access_type::TAKEOVER),
        _ => Err(bad("Invalid emergency access type.")),
    }
}

fn check_wait(days: i32) -> Result<(), AppError> {
    if WAIT_DAYS.contains(&days) {
        Ok(())
    } else {
        Err(bad("Emergency access wait time is out-of-bounds!"))
    }
}

fn to_json(e: &EmergencyRow) -> Value {
    json!({
        "id": e.uuid,
        "status": e.status,
        "type": e.atype,
        "waitTimeDays": e.wait_time_days,
        "object": "emergencyAccess",
    })
}

fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|n| n.and_utc())
        })
}

/// vaultwarden `EmergencyAccess::deadline_at`.
fn deadline(e: &EmergencyRow) -> Option<DateTime<Utc>> {
    if !WAIT_DAYS.contains(&e.wait_time_days) {
        return None;
    }
    let started = parse_date(e.recovery_initiated_at.as_deref()?)?;
    started.checked_add_signed(Duration::days(i64::from(e.wait_time_days)))
}

async fn find(
    db: &db::Db,
    where_sql: &str,
    params: &[&str],
) -> Result<Option<EmergencyRow>, AppError> {
    let binds: Vec<wasm_bindgen::JsValue> = params.iter().map(|p| (*p).into()).collect();
    Ok(db
        .prepare(format!(
            "SELECT {COLS} FROM emergency_access WHERE {where_sql}"
        ))
        .bind(&binds)?
        .first(None)
        .await?)
}

async fn as_grantor(db: &db::Db, id: &str, user_id: &str) -> Result<EmergencyRow, AppError> {
    find(db, "uuid = ?1 AND grantor_uuid = ?2", &[id, user_id])
        .await?
        .ok_or_else(not_valid)
}

async fn as_grantee(db: &db::Db, id: &str, user_id: &str) -> Result<EmergencyRow, AppError> {
    find(db, "uuid = ?1 AND grantee_uuid = ?2", &[id, user_id])
        .await?
        .ok_or_else(not_valid)
}

async fn person_by(db: &db::Db, column: &str, value: &str) -> Result<Option<Person>, AppError> {
    Ok(db
        .prepare(format!(
            "SELECT uuid, email, name, avatar_color FROM users WHERE {column} = ?1"
        ))
        .bind(&[value.into()])?
        .first(None)
        .await?)
}

async fn person(db: &db::Db, user_id: &str) -> Result<Person, AppError> {
    person_by(db, "uuid", user_id)
        .await?
        .ok_or_else(|| bad("User not found."))
}

fn display_name(p: &Person) -> &str {
    if p.name.trim().is_empty() {
        &p.email
    } else {
        &p.name
    }
}

async fn save_status(db: &db::Db, e: &EmergencyRow, new_status: i32) -> Result<(), AppError> {
    d1_query!(
        db,
        "UPDATE emergency_access SET status = ?1, updated_at = ?2 WHERE uuid = ?3",
        new_status,
        db::now_string(),
        e.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    Ok(())
}

/// Approve a recovery whose wait time has passed (vaultwarden `emergency_request_timeout_job`).
/// The update only applies while the row is still RecoveryInitiated, so concurrent callers
/// can't approve (and email) twice.
async fn apply_timeout(
    env: &Env,
    db: &db::Db,
    mut e: EmergencyRow,
) -> Result<EmergencyRow, AppError> {
    if e.status != status::RECOVERY_INITIATED {
        return Ok(e);
    }
    match deadline(&e) {
        Some(d) if d <= Utc::now() => {}
        _ => return Ok(e),
    }
    let changed = d1_query!(
        db,
        "UPDATE emergency_access SET status = ?1, updated_at = ?2 WHERE uuid = ?3 AND status = ?4",
        status::RECOVERY_APPROVED,
        db::now_string(),
        e.uuid,
        status::RECOVERY_INITIATED
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?
    .meta()
    .map_err(|_| AppError::Database)?
    .and_then(|m| m.changes)
    .unwrap_or(0);
    e.status = status::RECOVERY_APPROVED;
    if changed == 0 || !mail::mail_enabled(env) {
        return Ok(e);
    }
    let Some(grantee_id) = e.grantee_uuid.clone() else {
        return Ok(e);
    };
    if let (Ok(grantor), Ok(grantee)) = (
        person(db, &e.grantor_uuid).await,
        person(db, &grantee_id).await,
    ) {
        if let Err(err) = mail::send_emergency_recovery_timed_out(
            env,
            &grantor.email,
            display_name(&grantee),
            type_str(e.atype),
        )
        .await
        {
            log::error!("emergency access {}: timed-out mail failed: {err}", e.uuid);
        }
        if let Err(err) =
            mail::send_emergency_recovery_approved(env, &grantee.email, display_name(&grantor))
                .await
        {
            log::error!("emergency access {}: approved mail failed: {err}", e.uuid);
        }
    }
    Ok(e)
}

// ---------------------------------------------------------------------------
// Invite tokens (vaultwarden `EmergencyAccessInviteJwtClaims`, JWT_SECRET, 5 days)
// ---------------------------------------------------------------------------

const INVITE_ISSUER: &str = "vaultwarden-cf|emergencyaccessinvite";
const INVITE_TTL_HOURS: i64 = 120;

#[derive(serde::Serialize, Deserialize, Debug)]
pub struct EmergencyInviteClaims {
    pub iss: String,
    pub sub: String,
    pub email: String,
    pub emer_id: String,
    pub grantor_name: String,
    pub grantor_email: String,
}

fn jwt_key(env: &Env) -> Result<jwt_compact::alg::Hs256Key, AppError> {
    let secret = env.secret("JWT_SECRET")?.to_string();
    Ok(jwt_compact::alg::Hs256Key::new(secret.as_bytes()))
}

fn encode_invite(env: &Env, claims: EmergencyInviteClaims) -> Result<String, AppError> {
    use jwt_compact::AlgorithmExt;
    let jwt = jwt_compact::Claims::new(claims)
        .set_duration_and_issuance(
            &crate::auth::jwt_time_options(),
            chrono::Duration::hours(INVITE_TTL_HOURS),
        )
        .set_not_before(Utc::now());
    jwt_compact::alg::Hs256
        .token(&jwt_compact::Header::empty(), &jwt, &jwt_key(env)?)
        .map_err(|_| AppError::Crypto("Failed to create invite token".to_string()))
}

pub fn decode_invite(env: &Env, token: &str) -> Result<EmergencyInviteClaims, AppError> {
    use jwt_compact::AlgorithmExt;
    let invalid = || bad("Invalid or expired invitation token");
    let untrusted = jwt_compact::UntrustedToken::new(token).map_err(|_| invalid())?;
    let token = jwt_compact::alg::Hs256
        .validator::<EmergencyInviteClaims>(&jwt_key(env)?)
        .validate(&untrusted)
        .map_err(|_| invalid())?;
    let opts = crate::auth::jwt_time_options();
    token
        .claims()
        .validate_expiration(&opts)
        .map_err(|_| invalid())?;
    token
        .claims()
        .validate_maturity(&opts)
        .map_err(|_| invalid())?;
    let claims = token.into_parts().1.custom;
    if claims.iss != INVITE_ISSUER {
        return Err(invalid());
    }
    Ok(claims)
}

async fn send_invite_mail(
    env: &Env,
    to: &str,
    grantee_id: &str,
    emer_id: &str,
    grantor: &Person,
) -> Result<(), AppError> {
    let token = encode_invite(
        env,
        EmergencyInviteClaims {
            iss: INVITE_ISSUER.to_string(),
            sub: grantee_id.to_string(),
            email: to.to_string(),
            emer_id: emer_id.to_string(),
            grantor_name: grantor.name.clone(),
            grantor_email: grantor.email.clone(),
        },
    )?;
    mail::send_emergency_invite(env, to, emer_id, display_name(grantor), &token).await
}

// ---------------------------------------------------------------------------
// Lists and details
// ---------------------------------------------------------------------------

async fn grantee_details(db: &db::Db, e: &EmergencyRow) -> Result<Option<Value>, AppError> {
    let grantee = match (&e.grantee_uuid, &e.email) {
        (Some(id), _) => person_by(db, "uuid", id).await?,
        (None, Some(email)) => person_by(db, "email", email).await?,
        _ => None,
    };
    Ok(grantee.map(|g| {
        json!({
            "id": e.uuid,
            "status": e.status,
            "type": e.atype,
            "waitTimeDays": e.wait_time_days,
            "granteeId": g.uuid,
            "email": g.email,
            "name": g.name,
            "avatarColor": g.avatar_color,
            "object": "emergencyAccessGranteeDetails",
        })
    }))
}

fn list(data: Vec<Value>) -> Json<Value> {
    Json(json!({ "data": data, "object": "list", "continuationToken": null }))
}

async fn rows_where(
    db: &db::Db,
    column: &str,
    user_id: &str,
) -> Result<Vec<EmergencyRow>, AppError> {
    Ok(db
        .prepare(format!(
            "SELECT {COLS} FROM emergency_access WHERE {column} = ?1 ORDER BY created_at"
        ))
        .bind(&[user_id.into()])?
        .all()
        .await?
        .results()?)
}

/// GET /api/emergency-access/trusted (contacts I granted access to)
#[worker::send]
pub async fn get_trusted_contacts(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut out = Vec::new();
    for e in rows_where(&db, "grantor_uuid", &claims.sub).await? {
        let e = apply_timeout(&env, &db, e).await?;
        if let Some(v) = grantee_details(&db, &e).await? {
            out.push(v);
        }
    }
    Ok(list(out))
}

/// GET /api/emergency-access/granted (accounts that named me as a contact)
#[worker::send]
pub async fn get_granted_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut out = Vec::new();
    for e in rows_where(&db, "grantee_uuid", &claims.sub).await? {
        let e = apply_timeout(&env, &db, e).await?;
        let Some(g) = person_by(&db, "uuid", &e.grantor_uuid).await? else {
            continue;
        };
        out.push(json!({
            "id": e.uuid,
            "status": e.status,
            "type": e.atype,
            "waitTimeDays": e.wait_time_days,
            "grantorId": g.uuid,
            "email": g.email,
            "name": g.name,
            "avatarColor": g.avatar_color,
            "object": "emergencyAccessGrantorDetails",
        }));
    }
    Ok(list(out))
}

/// GET /api/emergency-access/{id}
#[worker::send]
pub async fn get_emergency_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let e = as_grantor(&db, &id, &claims.sub).await?;
    let e = apply_timeout(&env, &db, e).await?;
    grantee_details(&db, &e)
        .await?
        .map(Json)
        .ok_or_else(not_valid)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateData {
    r#type: Value,
    wait_time_days: i32,
    key_encrypted: Option<String>,
}

/// PUT/POST /api/emergency-access/{id}
#[worker::send]
pub async fn update_emergency_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(data): Json<UpdateData>,
) -> Result<Json<Value>, AppError> {
    let atype = parse_type(&data.r#type)?;
    check_wait(data.wait_time_days)?;
    let db = db::get_db(&env)?;
    let mut e = as_grantor(&db, &id, &claims.sub).await?;
    d1_query!(
        &db,
        "UPDATE emergency_access SET atype = ?1, wait_time_days = ?2, key_encrypted = COALESCE(?3, key_encrypted), updated_at = ?4 WHERE uuid = ?5",
        atype,
        data.wait_time_days,
        data.key_encrypted,
        db::now_string(),
        e.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    e.atype = atype;
    e.wait_time_days = data.wait_time_days;
    Ok(Json(to_json(&e)))
}

/// DELETE /api/emergency-access/{id} (+ POST .../delete): grantor or grantee removes it.
#[worker::send]
pub async fn delete_emergency_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let e = find(
        &db,
        "uuid = ?1 AND (grantor_uuid = ?2 OR grantee_uuid = ?2)",
        &[&id, &claims.sub],
    )
    .await?
    .ok_or_else(not_valid)?;
    d1_query!(&db, "DELETE FROM emergency_access WHERE uuid = ?1", e.uuid)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------
// Invite / accept / confirm
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteData {
    email: String,
    r#type: Value,
    wait_time_days: i32,
}

#[derive(Deserialize)]
struct UserState {
    uuid: String,
    has_password: i32,
}

async fn user_state(db: &db::Db, email: &str) -> Result<Option<UserState>, AppError> {
    Ok(db
        .prepare(
            "SELECT uuid, length(password_hash) > 0 AS has_password FROM users WHERE email = ?1",
        )
        .bind(&[email.into()])?
        .first(None)
        .await?)
}

/// POST /api/emergency-access/invite
#[worker::send]
pub async fn send_invite(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(data): Json<InviteData>,
) -> Result<Json<Value>, AppError> {
    let email = data.email.trim().to_lowercase();
    check_wait(data.wait_time_days)?;
    let atype = parse_type(&data.r#type)?;
    if email.is_empty() || !email.contains('@') {
        return Err(bad("Invalid email"));
    }
    let db = db::get_db(&env)?;
    let grantor = person(&db, &claims.sub).await?;
    if email == grantor.email {
        return Err(bad("You can not set yourself as an emergency contact."));
    }
    let mail_on = mail::mail_enabled(&env);
    let now = db::now_string();
    let mut stmts = Vec::new();
    let (grantee_id, new_user) = match user_state(&db, &email).await? {
        Some(u) => (u.uuid, u.has_password == 0),
        None => {
            // Placeholder account completed on register (vaultwarden `User::new(email, None)`).
            let uid = Uuid::new_v4().to_string();
            stmts.push(
                d1_query!(
                    &db,
                    "INSERT INTO users (uuid, created_at, updated_at, email, name, password_hash, salt, password_iterations, akey, security_stamp, equivalent_domains, excluded_globals, client_kdf_type, client_kdf_iter)
                     VALUES (?1, ?2, ?2, ?3, '', x'', x'', 600000, '', ?4, '[]', '[]', 0, 600000)",
                    uid,
                    now,
                    email,
                    Uuid::new_v4().to_string()
                )
                .map_err(|_| AppError::Database)?,
            );
            (uid, true)
        }
    };
    let dup = find(
        &db,
        "grantor_uuid = ?1 AND (grantee_uuid = ?2 OR email = ?3)",
        &[&claims.sub, &grantee_id, &email],
    )
    .await?;
    if dup.is_some() {
        return Err(AppError::BadRequest(format!(
            "Grantee user already invited: {email}"
        )));
    }
    if new_user {
        // Lets the invited email register even outside ALLOWED_EMAILS.
        stmts.push(
            d1_query!(
                &db,
                "INSERT OR IGNORE INTO invitations (email) VALUES (?1)",
                email
            )
            .map_err(|_| AppError::Database)?,
        );
    }
    let emer_id = Uuid::new_v4().to_string();
    // Without mail an existing account can't follow a link: accept right away.
    let (st, grantee_uuid, row_email) = if !mail_on && !new_user {
        (status::ACCEPTED, Some(grantee_id.clone()), None)
    } else {
        (status::INVITED, None, Some(email.clone()))
    };
    stmts.push(
        d1_query!(
            &db,
            "INSERT INTO emergency_access (uuid, grantor_uuid, grantee_uuid, email, key_encrypted, atype, status, wait_time_days, recovery_initiated_at, last_notification_at, updated_at, created_at)
             VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, NULL, NULL, ?8, ?8)",
            emer_id,
            claims.sub,
            grantee_uuid,
            row_email,
            atype,
            st,
            data.wait_time_days,
            now
        )
        .map_err(|_| AppError::Database)?,
    );
    db.batch(stmts).await?;
    if mail_on {
        if let Err(err) = send_invite_mail(&env, &email, &grantee_id, &emer_id, &grantor).await {
            // Like the org invites: no mail, no invite.
            d1_query!(&db, "DELETE FROM emergency_access WHERE uuid = ?1", emer_id)
                .map_err(|_| AppError::Database)?
                .run()
                .await?;
            return Err(err);
        }
    }
    Ok(Json(json!({})))
}

/// POST /api/emergency-access/{id}/reinvite
#[worker::send]
pub async fn resend_invite(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let e = as_grantor(&db, &id, &claims.sub).await?;
    if e.status != status::INVITED {
        return Err(bad(
            "The grantee user is already accepted or confirmed for emergency access",
        ));
    }
    let email = e.email.clone().ok_or_else(|| bad("Email not valid."))?;
    let grantee = user_state(&db, &email)
        .await?
        .ok_or_else(|| bad("Grantee user not found."))?;
    if mail::mail_enabled(&env) {
        let grantor = person(&db, &claims.sub).await?;
        send_invite_mail(&env, &email, &grantee.uuid, &e.uuid, &grantor).await?;
    } else if grantee.has_password != 0 {
        accept(&db, &e, &grantee.uuid, &email).await?;
    } else {
        d1_query!(
            &db,
            "INSERT OR IGNORE INTO invitations (email) VALUES (?1)",
            email
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    }
    Ok(Json(json!({})))
}

/// vaultwarden `EmergencyAccess::accept_invite`.
async fn accept(
    db: &db::Db,
    e: &EmergencyRow,
    grantee_id: &str,
    email: &str,
) -> Result<(), AppError> {
    if e.email.as_deref() != Some(email) {
        return Err(bad("User email does not match invite."));
    }
    if e.status == status::ACCEPTED {
        return Err(bad("Emergency contact already accepted."));
    }
    d1_query!(
        db,
        "UPDATE emergency_access SET status = ?1, grantee_uuid = ?2, email = NULL, updated_at = ?3 WHERE uuid = ?4",
        status::ACCEPTED,
        grantee_id,
        db::now_string(),
        e.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    Ok(())
}

/// Run when an invited email registers without mail (vaultwarden `register`).
pub fn accept_on_register_stmt(
    db: &db::Db,
    user_id: &str,
    email: &str,
) -> Result<worker::D1PreparedStatement, AppError> {
    d1_query!(
        db,
        "UPDATE emergency_access SET status = 1, grantee_uuid = ?1, email = NULL WHERE email = ?2 AND status = 0",
        user_id,
        email
    )
    .map_err(|_| AppError::Database)
}

#[derive(Deserialize)]
pub struct TokenData {
    token: String,
}

/// POST /api/emergency-access/{id}/accept
#[worker::send]
pub async fn accept_invite(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(data): Json<TokenData>,
) -> Result<Json<Value>, AppError> {
    let token = decode_invite(&env, &data.token)?;
    if token.email != claims.email {
        return Err(bad("Claim email does not match current users email"));
    }
    let db = db::get_db(&env)?;
    let e = find(&db, "uuid = ?1 AND email = ?2", &[&id, &claims.email])
        .await?
        .ok_or_else(not_valid)?;
    let grantor = person(&db, &e.grantor_uuid).await?;
    if id != token.emer_id
        || grantor.name != token.grantor_name
        || grantor.email != token.grantor_email
    {
        return Err(bad("Emergency access invitation error."));
    }
    accept(&db, &e, &claims.sub, &claims.email).await?;
    d1_query!(
        &db,
        "DELETE FROM invitations WHERE email = ?1",
        claims.email
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    if mail::mail_enabled(&env) {
        mail::send_emergency_invite_accepted(&env, &grantor.email, &claims.email).await?;
    }
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
pub struct ConfirmData {
    key: String,
}

/// POST /api/emergency-access/{id}/confirm
#[worker::send]
pub async fn confirm_emergency_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(data): Json<ConfirmData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut e = as_grantor(&db, &id, &claims.sub).await?;
    if e.status != status::ACCEPTED {
        return Err(not_valid());
    }
    let grantee_id = e
        .grantee_uuid
        .clone()
        .ok_or_else(|| bad("Grantee user not found."))?;
    let grantee = person(&db, &grantee_id).await?;
    let grantor = person(&db, &claims.sub).await?;
    d1_query!(
        &db,
        "UPDATE emergency_access SET status = ?1, key_encrypted = ?2, email = NULL, updated_at = ?3 WHERE uuid = ?4",
        status::CONFIRMED,
        data.key,
        db::now_string(),
        e.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    e.status = status::CONFIRMED;
    if mail::mail_enabled(&env) {
        mail::send_emergency_invite_confirmed(&env, &grantee.email, display_name(&grantor)).await?;
    }
    Ok(Json(to_json(&e)))
}

// ---------------------------------------------------------------------------
// Recovery: initiate / approve / reject
// ---------------------------------------------------------------------------

/// POST /api/emergency-access/{id}/initiate (grantee)
#[worker::send]
pub async fn initiate_emergency_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut e = as_grantee(&db, &id, &claims.sub).await?;
    if e.status != status::CONFIRMED || !WAIT_DAYS.contains(&e.wait_time_days) {
        return Err(not_valid());
    }
    let grantor = person(&db, &e.grantor_uuid).await?;
    let now = db::now_string();
    d1_query!(
        &db,
        "UPDATE emergency_access SET status = ?1, updated_at = ?2, recovery_initiated_at = ?2, last_notification_at = ?2 WHERE uuid = ?3",
        status::RECOVERY_INITIATED,
        now,
        e.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    e.status = status::RECOVERY_INITIATED;
    if mail::mail_enabled(&env) {
        let me = person(&db, &claims.sub).await?;
        mail::send_emergency_recovery_initiated(
            &env,
            &grantor.email,
            display_name(&me),
            type_str(e.atype),
            e.wait_time_days,
        )
        .await?;
    }
    Ok(Json(to_json(&e)))
}

/// POST /api/emergency-access/{id}/approve (grantor)
#[worker::send]
pub async fn approve_emergency_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut e = as_grantor(&db, &id, &claims.sub).await?;
    if e.status != status::RECOVERY_INITIATED {
        return Err(not_valid());
    }
    let grantee_id = e
        .grantee_uuid
        .clone()
        .ok_or_else(|| bad("Grantee user not found."))?;
    let grantee = person(&db, &grantee_id).await?;
    save_status(&db, &e, status::RECOVERY_APPROVED).await?;
    e.status = status::RECOVERY_APPROVED;
    if mail::mail_enabled(&env) {
        let grantor = person(&db, &claims.sub).await?;
        mail::send_emergency_recovery_approved(&env, &grantee.email, display_name(&grantor))
            .await?;
    }
    Ok(Json(to_json(&e)))
}

/// POST /api/emergency-access/{id}/reject (grantor): back to Confirmed.
#[worker::send]
pub async fn reject_emergency_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut e = as_grantor(&db, &id, &claims.sub).await?;
    if e.status != status::RECOVERY_INITIATED && e.status != status::RECOVERY_APPROVED {
        return Err(not_valid());
    }
    let grantee_id = e
        .grantee_uuid
        .clone()
        .ok_or_else(|| bad("Grantee user not found."))?;
    let grantee = person(&db, &grantee_id).await?;
    save_status(&db, &e, status::CONFIRMED).await?;
    e.status = status::CONFIRMED;
    if mail::mail_enabled(&env) {
        let grantor = person(&db, &claims.sub).await?;
        mail::send_emergency_recovery_rejected(&env, &grantee.email, display_name(&grantor))
            .await?;
    }
    Ok(Json(to_json(&e)))
}

// ---------------------------------------------------------------------------
// Using approved access
// ---------------------------------------------------------------------------

/// An access the grantee may use as `wanted` (vaultwarden `is_valid_request`), approving it
/// first if its wait time has run out.
async fn usable(
    env: &Env,
    db: &db::Db,
    id: &str,
    user_id: &str,
    wanted: i32,
) -> Result<EmergencyRow, AppError> {
    let e = as_grantee(db, id, user_id).await?;
    let e = apply_timeout(env, db, e).await?;
    if e.status != status::RECOVERY_APPROVED || e.atype != wanted {
        return Err(not_valid());
    }
    Ok(e)
}

/// POST /api/emergency-access/{id}/view: the grantor's personal items.
#[worker::send]
pub async fn view_emergency_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    let e = usable(&env, &db, &id, &claims.sub, access_type::VIEW).await?;
    let mut out = String::from("{\"ciphers\":");
    crate::handlers::ciphers::append_cipher_json_array_raw(
        &mut out,
        &db,
        crate::handlers::attachments::attachments_enabled(&env),
        "WHERE c.user_uuid = ?1 AND c.organization_uuid IS NULL AND c.deleted_at IS NULL",
        &[e.grantor_uuid.clone().into()],
        "ORDER BY c.updated_at DESC",
        crate::handlers::ciphers_default_row_query(&env),
    )
    .await?;
    out.push_str(&format!(
        ",\"keyEncrypted\":{},\"object\":\"emergencyAccessView\"}}",
        serde_json::to_string(&e.key_encrypted).map_err(|_| AppError::Internal)?
    ));
    Ok(RawJson(out))
}

#[derive(Deserialize)]
struct KdfRow {
    email: String,
    client_kdf_type: i32,
    client_kdf_iter: i32,
    client_kdf_memory: Option<i32>,
    client_kdf_parallelism: Option<i32>,
}

async fn grantor_kdf(db: &db::Db, user_id: &str) -> Result<KdfRow, AppError> {
    db.prepare("SELECT email, client_kdf_type, client_kdf_iter, client_kdf_memory, client_kdf_parallelism FROM users WHERE uuid = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await?
        .ok_or_else(|| bad("Grantor user not found."))
}

/// POST /api/emergency-access/{id}/takeover: what the client needs to set a new password.
#[worker::send]
pub async fn takeover_emergency_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let e = usable(&env, &db, &id, &claims.sub, access_type::TAKEOVER).await?;
    let g = grantor_kdf(&db, &e.grantor_uuid).await?;
    Ok(Json(json!({
        "kdf": g.client_kdf_type,
        "kdfIterations": g.client_kdf_iter,
        "kdfMemory": g.client_kdf_memory,
        "kdfParallelism": g.client_kdf_parallelism,
        "keyEncrypted": e.key_encrypted,
        "salt": g.email.trim().to_lowercase(),
        "object": "emergencyAccessTakeover",
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfData {
    #[serde(alias = "kdfType")]
    kdf: i32,
    #[serde(alias = "iterations")]
    kdf_iterations: i32,
    #[serde(alias = "memory")]
    kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    kdf_parallelism: Option<i32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationData {
    master_password_authentication_hash: String,
    kdf: Option<KdfData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockData {
    master_key_wrapped_user_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordData {
    new_master_password_hash: Option<String>,
    key: Option<String>,
    authentication_data: Option<AuthenticationData>,
    unlock_data: Option<UnlockData>,
}

/// POST /api/emergency-access/{id}/password: set the grantor's new master password.
#[worker::send]
pub async fn password_emergency_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(data): Json<PasswordData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let e = usable(&env, &db, &id, &claims.sub, access_type::TAKEOVER).await?;
    let g = grantor_kdf(&db, &e.grantor_uuid).await?;
    let (hash, key) = match (
        data.authentication_data,
        data.unlock_data,
        data.new_master_password_hash,
        data.key,
    ) {
        (Some(a), Some(u), _, _) => {
            if let Some(k) = &a.kdf {
                let same = k.kdf == g.client_kdf_type
                    && k.kdf_iterations == g.client_kdf_iter
                    && k.kdf_memory == g.client_kdf_memory
                    && k.kdf_parallelism == g.client_kdf_parallelism;
                if !same {
                    return Err(bad("KDF settings do not match the grantor account"));
                }
            }
            (
                a.master_password_authentication_hash,
                u.master_key_wrapped_user_key,
            )
        }
        (_, _, Some(h), Some(k)) => (h, k),
        _ => return Err(bad("Invalid request!")),
    };
    let salt = generate_salt()?;
    let iterations = crate::handlers::server_password_iterations(&env) as i32;
    let hashed = hash_password_for_storage(&hash, &salt, iterations as u32).await?;
    let now = db::now_string();
    let grantor = e.grantor_uuid.clone();
    let q = |sql: &'static str| -> Result<worker::D1PreparedStatement, AppError> {
        d1_query!(&db, sql, grantor).map_err(|_| AppError::Database)
    };
    let stmts = vec![
        d1_query!(
            &db,
            "UPDATE users SET password_hash = unhex(?1), salt = unhex(?2), password_iterations = ?3, akey = ?4, security_stamp = ?5, totp_recover = NULL, updated_at = ?6 WHERE uuid = ?7",
            hashed,
            salt,
            iterations,
            key,
            Uuid::new_v4().to_string(),
            now,
            grantor
        )
        .map_err(|_| AppError::Database)?,
        // 2FA would block the new login (vaultwarden `TwoFactor::delete_all_by_user`).
        q("DELETE FROM twofactor WHERE user_uuid = ?1")?,
        q("UPDATE devices SET twofactor_remember = NULL WHERE user_uuid = ?1")?,
        // Leave every organization where the grantor isn't an owner.
        q("DELETE FROM users_collections WHERE user_uuid = ?1 AND collection_uuid IN (
             SELECT c.uuid FROM collections c JOIN users_organizations m ON m.org_uuid = c.org_uuid
             WHERE m.user_uuid = ?1 AND m.atype != 0)")?,
        q("DELETE FROM groups_users WHERE users_organizations_uuid IN (
             SELECT uuid FROM users_organizations WHERE user_uuid = ?1 AND atype != 0)")?,
        q("DELETE FROM users_organizations WHERE user_uuid = ?1 AND atype != 0")?,
    ];
    db.batch(stmts).await?;
    crate::notifications::publish_user_logout((*env).clone(), grantor, now, None);
    Ok(Json(json!({})))
}

/// GET /api/emergency-access/{id}/policies: the grantor's org policies, so the takeover form
/// can enforce the master password policy.
#[worker::send]
pub async fn policies_emergency_access(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let e = usable(&env, &db, &id, &claims.sub, access_type::TAKEOVER).await?;
    let rows: Vec<crate::handlers::org_policies::PolicyRow> = db
        .prepare(format!(
            "SELECT {} FROM org_policies p
             JOIN users_organizations m ON m.org_uuid = p.org_uuid
             WHERE m.user_uuid = ?1 AND m.status = 2",
            crate::handlers::org_policies::POLICY_COLS_P
        ))
        .bind(&[e.grantor_uuid.clone().into()])?
        .all()
        .await?
        .results()?;
    Ok(list(
        rows.iter()
            .map(crate::handlers::org_policies::policy_json)
            .collect(),
    ))
}

// ---------------------------------------------------------------------------
// Cron (vaultwarden emergency_request_timeout_job + emergency_notification_reminder_job)
// ---------------------------------------------------------------------------

/// Approve timed-out recoveries and send the last-day reminders. Returns approvals made.
pub async fn scheduled_jobs(env: &Env) -> Result<u32, AppError> {
    let db = db::get_db(env)?;
    let rows: Vec<EmergencyRow> = db
        .prepare(format!(
            "SELECT {COLS} FROM emergency_access WHERE status = ?1 AND recovery_initiated_at IS NOT NULL"
        ))
        .bind(&[status::RECOVERY_INITIATED.into()])?
        .all()
        .await?
        .results()?;
    let mut approved = 0;
    let now = Utc::now();
    for e in rows {
        let Some(deadline) = deadline(&e) else {
            continue;
        };
        if deadline <= now {
            if apply_timeout(env, &db, e).await?.status == status::RECOVERY_APPROVED {
                approved += 1;
            }
            continue;
        }
        // Reminders only during the last 24 hours, at most once a day.
        let due = e
            .last_notification_at
            .as_deref()
            .and_then(parse_date)
            .is_none_or(|d| d + Duration::days(1) <= now);
        if now < deadline - Duration::days(1) || !due || !mail::mail_enabled(env) {
            continue;
        }
        let Some(grantee_id) = e.grantee_uuid.as_deref() else {
            continue;
        };
        d1_query!(
            &db,
            "UPDATE emergency_access SET last_notification_at = ?1 WHERE uuid = ?2",
            db::now_string(),
            e.uuid
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
        if let (Ok(grantor), Ok(grantee)) = (
            person(&db, &e.grantor_uuid).await,
            person(&db, grantee_id).await,
        ) {
            if let Err(err) = mail::send_emergency_recovery_reminder(
                env,
                &grantor.email,
                display_name(&grantee),
                type_str(e.atype),
            )
            .await
            {
                log::error!("emergency access {}: reminder mail failed: {err}", e.uuid);
            }
        }
    }
    Ok(approved)
}
