//! Account recovery (admin password reset), organization API key and event stubs (phase 3.5),
//! ported from vaultwarden `organizations.rs`. Account recovery needs mail, like upstream.

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::Env;

use crate::auth::Claims;
use crate::crypto::{generate_api_key, generate_salt, hash_password_for_storage};
use crate::d1_query;
use crate::db;
use crate::error::AppError;
use crate::handlers::org_policies::{check_reset_password_applicable, reset_password_auto_enroll};
use crate::handlers::organizations::{find_membership, find_org, require_role, MembershipRow};
use crate::models::org_access::{membership_status, membership_type};
use crate::models::user::User;

async fn load_user(db: &db::Db, user_id: &str) -> Result<User, AppError> {
    db.prepare(crate::models::user::select_user_by_id_sql())
        .bind(&[user_id.into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
}

async fn verify_password(db: &db::Db, user_id: &str, hash: Option<&str>) -> Result<User, AppError> {
    let user = load_user(db, user_id).await?;
    let hash =
        hash.ok_or_else(|| AppError::BadRequest("Missing master password hash".to_string()))?;
    if !user.verify_master_password(hash).await?.is_valid() {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }
    Ok(user)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentData {
    reset_password_key: Option<String>,
    master_password_hash: Option<String>,
}

/// PUT /api/organizations/{org_id}/users/{user_id}/reset-password-enrollment
#[worker::send]
pub async fn put_reset_password_enrollment(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, user_id)): Path<(String, String)>,
    Json(data): Json<EnrollmentData>,
) -> Result<Json<Value>, AppError> {
    if user_id != claims.sub {
        return Err(AppError::BadRequest(
            "User to enroll isn't member of required organization".to_string(),
        ));
    }
    let db = db::get_db(&env)?;
    let m = find_membership(&db, &claims.sub, &org_id)
        .await?
        .filter(|m| m.status >= membership_status::ACCEPTED)
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    check_reset_password_applicable(&env, &db, &org_id).await?;
    let key = data.reset_password_key.filter(|k| !k.is_empty());
    if key.is_none() && reset_password_auto_enroll(&env, &db, &org_id).await? {
        return Err(AppError::BadRequest(
            "Reset password can't be withdrawn due to an enterprise policy".to_string(),
        ));
    }
    if key.is_some() {
        verify_password(&db, &claims.sub, data.master_password_hash.as_deref()).await?;
    }
    d1_query!(
        &db,
        "UPDATE users_organizations SET reset_password_key = ?1 WHERE uuid = ?2",
        key,
        m.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    db::touch_user_updated_at(&db, &claims.sub, &db::now_string()).await?;
    Ok(Json(json!({})))
}

/// Admins may reset members up to their own level; owners anyone (vaultwarden rule).
async fn check_recovery_permission(
    env: &Env,
    db: &db::Db,
    me: &MembershipRow,
    target: &MembershipRow,
) -> Result<(), AppError> {
    check_reset_password_applicable(env, db, &me.org_uuid).await?;
    let ok = match me.atype {
        membership_type::OWNER => true,
        membership_type::ADMIN => target.atype != membership_type::OWNER,
        _ => false,
    };
    if !ok {
        return Err(AppError::BadRequest(
            "No permission to reset this user's password".to_string(),
        ));
    }
    Ok(())
}

async fn target_member(
    db: &db::Db,
    org_id: &str,
    member_id: &str,
) -> Result<MembershipRow, AppError> {
    let m: Option<MembershipRow> = db
        .prepare(
            "SELECT uuid, user_uuid, org_uuid, access_all, akey, status, atype, reset_password_key, external_id
             FROM users_organizations WHERE uuid = ?1 AND org_uuid = ?2",
        )
        .bind(&[member_id.into(), org_id.into()])?
        .first(None)
        .await?;
    m.ok_or_else(|| {
        AppError::BadRequest("User to reset isn't member of required organization".to_string())
    })
}

/// GET /api/organizations/{org_id}/users/{member_id}/reset-password-details
#[worker::send]
pub async fn get_reset_password_details(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let org = find_org(&db, &org_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Required organization not found".to_string()))?;
    let target = target_member(&db, &org_id, &member_id).await?;
    check_recovery_permission(&env, &db, &me, &target).await?;
    let user = load_user(&db, &target.user_uuid).await?;
    Ok(Json(json!({
        "object": "organizationUserResetPasswordDetails",
        "organizationUserId": member_id,
        "kdf": user.kdf_type,
        "kdfIterations": user.kdf_iterations,
        "kdfMemory": user.kdf_memory,
        "kdfParallelism": user.kdf_parallelism,
        "masterPasswordSalt": user.email,
        "resetPasswordKey": target.reset_password_key,
        "encryptedPrivateKey": org.private_key,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockData {
    master_key_wrapped_user_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationData {
    master_password_authentication_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverData {
    new_master_password_hash: Option<String>,
    key: Option<String>,
    authentication_data: Option<AuthenticationData>,
    unlock_data: Option<UnlockData>,
    /// Older clients only reset the password and don't send the flags.
    #[serde(default = "default_true")]
    reset_master_password: bool,
    #[serde(default)]
    reset_two_factor: bool,
}

fn default_true() -> bool {
    true
}

/// PUT /api/organizations/{org_id}/users/{member_id}/recover-account (+ legacy /reset-password)
#[worker::send]
pub async fn recover_account(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(req): Json<RecoverData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let org = find_org(&db, &org_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Required organization not found".to_string()))?;
    let target = target_member(&db, &org_id, &member_id).await?;
    check_recovery_permission(&env, &db, &me, &target).await?;
    if target.reset_password_key.is_none() {
        return Err(AppError::BadRequest(
            "Password reset not or not correctly enrolled".to_string(),
        ));
    }
    if target.status != membership_status::CONFIRMED {
        return Err(AppError::BadRequest(
            "Organization user must be confirmed for password reset functionality".to_string(),
        ));
    }
    let user = load_user(&db, &target.user_uuid).await?;
    let new_password = if req.reset_master_password {
        match (
            req.authentication_data,
            req.unlock_data,
            req.new_master_password_hash,
            req.key,
        ) {
            (Some(a), Some(u), _, _) => Some((
                a.master_password_authentication_hash,
                u.master_key_wrapped_user_key,
            )),
            (_, _, Some(hash), Some(key)) => Some((hash, key)),
            _ => {
                return Err(AppError::BadRequest(
                    "Missing fields to reset password".to_string(),
                ))
            }
        }
    } else {
        None
    };
    // vaultwarden sends the notice before changing anything; a mail failure aborts.
    crate::mail::send_admin_account_recovery(
        &env,
        &user.email,
        user.name.as_deref().unwrap_or(&user.email),
        &org.name,
        req.reset_master_password,
        req.reset_two_factor,
    )
    .await?;
    let now = db::now_string();
    let mut stmts = Vec::new();
    if let Some((hash, key)) = new_password {
        let salt = generate_salt()?;
        let iterations = crate::handlers::server_password_iterations(&env) as i32;
        let hashed = hash_password_for_storage(&hash, &salt, iterations as u32).await?;
        stmts.push(
            d1_query!(
                &db,
                "UPDATE users SET password_hash = unhex(?1), salt = unhex(?2), password_iterations = ?3, akey = ?4, security_stamp = ?5, updated_at = ?6 WHERE uuid = ?7",
                hashed,
                salt,
                iterations,
                key,
                Uuid::new_v4().to_string(),
                now,
                user.id
            )
            .map_err(|_| AppError::Database)?,
        );
    }
    if req.reset_two_factor {
        stmts.push(
            d1_query!(&db, "DELETE FROM twofactor WHERE user_uuid = ?1", user.id)
                .map_err(|_| AppError::Database)?,
        );
        stmts.push(
            d1_query!(
                &db,
                "UPDATE users SET totp_recover = NULL, updated_at = ?1 WHERE uuid = ?2",
                now,
                user.id
            )
            .map_err(|_| AppError::Database)?,
        );
        stmts.push(
            d1_query!(
                &db,
                "UPDATE devices SET twofactor_remember = NULL WHERE user_uuid = ?1",
                user.id
            )
            .map_err(|_| AppError::Database)?,
        );
    }
    if !stmts.is_empty() {
        db.batch(stmts).await?;
    }
    if req.reset_two_factor {
        crate::handlers::org_policies::enforce_2fa_policy_for_user(&db, &user.id).await?;
    }
    if req.reset_master_password {
        crate::notifications::publish_user_logout((*env).clone(), user.id, now, None);
    }
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordData {
    master_password_hash: Option<String>,
}

async fn api_key_impl(
    claims: Claims,
    env: Arc<Env>,
    org_id: String,
    data: PasswordData,
    rotate: bool,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::OWNER).await?;
    verify_password(&db, &claims.sub, data.master_password_hash.as_deref()).await?;
    #[derive(Deserialize)]
    struct Row {
        api_key: String,
        revision_date: String,
    }
    let existing: Option<Row> = db
        .prepare("SELECT api_key, revision_date FROM organization_api_key WHERE org_uuid = ?1 AND atype = 0")
        .bind(&[org_id.clone().into()])?
        .first(None)
        .await?;
    let row = match existing {
        Some(r) if !rotate => r,
        Some(_) => {
            let key = generate_api_key()?;
            let now = db::now_string();
            d1_query!(
                &db,
                "UPDATE organization_api_key SET api_key = ?1, revision_date = ?2 WHERE org_uuid = ?3 AND atype = 0",
                key,
                now,
                org_id
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await?;
            Row {
                api_key: key,
                revision_date: now,
            }
        }
        None => {
            let key = generate_api_key()?;
            let now = db::now_string();
            d1_query!(
                &db,
                "INSERT INTO organization_api_key (uuid, org_uuid, atype, api_key, revision_date) VALUES (?1, ?2, 0, ?3, ?4)",
                Uuid::new_v4().to_string(),
                org_id,
                key,
                now
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await?;
            Row {
                api_key: key,
                revision_date: now,
            }
        }
    };
    Ok(Json(json!({
        "apiKey": row.api_key,
        "revisionDate": row.revision_date,
        "object": "apiKey",
    })))
}

/// POST /api/organizations/{org_id}/api-key
#[worker::send]
pub async fn post_api_key(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<PasswordData>,
) -> Result<Json<Value>, AppError> {
    api_key_impl(claims, env, org_id, data, false).await
}

/// POST /api/organizations/{org_id}/rotate-api-key
#[worker::send]
pub async fn rotate_api_key(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<PasswordData>,
) -> Result<Json<Value>, AppError> {
    api_key_impl(claims, env, org_id, data, true).await
}

/// Event log endpoints: vaultwarden with events disabled (the default) returns empty lists.
pub async fn empty_events() -> Json<Value> {
    Json(json!({"data": [], "object": "list", "continuationToken": null}))
}
