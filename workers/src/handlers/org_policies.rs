//! Organization policies (phase 3.4), ported from vaultwarden `organizations.rs` (policy routes)
//! and `db/models/org_policy.rs`, plus the enforcement helpers other handlers call.

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::Env;

use crate::auth::Claims;
use crate::d1_query;
use crate::db;
use crate::error::AppError;
use crate::handlers::organizations::{
    find_membership, require_role, role_rank, MembershipRow, ACTIVATE_REVOKE_DIFF,
};
use crate::models::org_access::{membership_status, membership_type};

/// vaultwarden `OrgPolicyType`.
pub mod policy_type {
    pub const TWO_FACTOR: i32 = 0;
    pub const MASTER_PASSWORD: i32 = 1;
    pub const SINGLE_ORG: i32 = 3;
    pub const PERSONAL_OWNERSHIP: i32 = 5;
    pub const DISABLE_SEND: i32 = 6;
    pub const SEND_OPTIONS: i32 = 7;
    pub const RESET_PASSWORD: i32 = 8;
    pub const FILL_ASSIST: i32 = 22;
    pub const ALL: &[i32] = &[0, 1, 2, 3, 5, 6, 7, 8, 14, 15, 16, 17, 20, 22];
}

/// Placeholder org id clients use for the SSO master-password policy (vaultwarden FAKE_SSO).
const FAKE_SSO_ORG_ID: &str = "00000000-01dc-01dc-01dc-000000000000";

#[derive(Debug, Deserialize)]
pub struct PolicyRow {
    uuid: String,
    org_uuid: String,
    atype: i32,
    enabled: i32,
    data: String,
    revision_date: String,
}

const POLICY_COLS: &str = "uuid, org_uuid, atype, enabled, data, revision_date";

pub fn policy_json(p: &PolicyRow) -> Value {
    let data: Value = serde_json::from_str(&p.data).unwrap_or(Value::Null);
    let mut j = json!({
        "id": p.uuid,
        "organizationId": p.org_uuid,
        "type": p.atype,
        "data": data,
        "enabled": p.enabled != 0,
        "revisionDate": p.revision_date,
        "object": "policy",
    });
    if p.atype == policy_type::RESET_PASSWORD {
        j["canToggleState"] = json!(true);
    }
    j
}

fn default_policy_json(org_id: &str, atype: i32) -> Value {
    json!({
        "id": Uuid::new_v4().to_string(),
        "organizationId": org_id,
        "type": atype,
        "data": null,
        "enabled": false,
        "revisionDate": db::now_string(),
        "object": "policy",
    })
}

async fn find_policy(db: &db::Db, org_id: &str, atype: i32) -> Result<Option<PolicyRow>, AppError> {
    Ok(db
        .prepare(format!(
            "SELECT {POLICY_COLS} FROM org_policies WHERE org_uuid = ?1 AND atype = ?2"
        ))
        .bind(&[org_id.into(), atype.into()])?
        .first(None)
        .await?)
}

async fn policy_enabled(db: &db::Db, org_id: &str, atype: i32) -> Result<bool, AppError> {
    Ok(find_policy(db, org_id, atype)
        .await?
        .is_some_and(|p| p.enabled != 0))
}

/// Policies of the user's orgs as JSON strings for sync: `(policies, policiesNew)`;
/// the first only covers confirmed memberships, the second accepted ones too.
pub async fn sync_policies_json(db: &db::Db, user_id: &str) -> Result<(String, String), AppError> {
    let rows: Vec<(PolicyRow, i32)> = {
        #[derive(Deserialize)]
        struct Row {
            #[serde(flatten)]
            p: PolicyRow,
            status: i32,
        }
        db.prepare(
            "SELECT p.uuid, p.org_uuid, p.atype, p.enabled, p.data, p.revision_date, uo.status
             FROM org_policies p JOIN users_organizations uo ON uo.org_uuid = p.org_uuid
             WHERE uo.user_uuid = ?1 AND uo.status IN (1, 2)",
        )
        .bind(&[user_id.into()])?
        .all()
        .await?
        .results::<Row>()?
        .into_iter()
        .map(|r| (r.p, r.status))
        .collect()
    };
    let confirmed: Vec<Value> = rows
        .iter()
        .filter(|(_, s)| *s == membership_status::CONFIRMED)
        .map(|(p, _)| policy_json(p))
        .collect();
    let all: Vec<Value> = rows.iter().map(|(p, _)| policy_json(p)).collect();
    Ok((
        serde_json::to_string(&confirmed).map_err(|_| AppError::Internal)?,
        serde_json::to_string(&all).map_err(|_| AppError::Internal)?,
    ))
}

/// vaultwarden `OrgPolicy::is_applicable_to_user`: an enabled policy of `atype` in an org where
/// the user is a confirmed member below Admin (optionally ignoring `exclude_org`).
pub async fn policy_applies_to_user(
    db: &db::Db,
    user_id: &str,
    atype: i32,
    exclude_org: Option<&str>,
) -> Result<bool, AppError> {
    let row: Option<Value> = db
        .prepare(
            "SELECT 1 AS ok FROM org_policies p JOIN users_organizations uo ON uo.org_uuid = p.org_uuid
             WHERE uo.user_uuid = ?1 AND p.atype = ?2 AND p.enabled = 1 AND uo.status = 2
               AND uo.atype NOT IN (0, 1) AND p.org_uuid != COALESCE(?3, '') LIMIT 1",
        )
        .bind(&[
            user_id.into(),
            atype.into(),
            exclude_org
                .map(worker::wasm_bindgen::JsValue::from)
                .unwrap_or(worker::wasm_bindgen::JsValue::NULL),
        ])?
        .first(None)
        .await?;
    Ok(row.is_some())
}

/// Personal ownership policy: no creating/editing personal items (deleting and sharing are ok).
pub async fn enforce_personal_ownership(db: &db::Db, user_id: &str) -> Result<(), AppError> {
    if policy_applies_to_user(db, user_id, policy_type::PERSONAL_OWNERSHIP, None).await? {
        return Err(AppError::BadRequest(
            "Due to an Enterprise Policy, you are restricted from saving items to your personal vault."
                .to_string(),
        ));
    }
    Ok(())
}

/// Disable Send policy, plus the Send Options "disable hide email" switch.
pub async fn enforce_send_policies(
    db: &db::Db,
    user_id: &str,
    hide_email: bool,
) -> Result<(), AppError> {
    if policy_applies_to_user(db, user_id, policy_type::DISABLE_SEND, None).await? {
        return Err(AppError::BadRequest(
            "Due to an Enterprise Policy, you are only able to delete an existing Send."
                .to_string(),
        ));
    }
    if hide_email {
        let row: Option<Value> = db
            .prepare(
                "SELECT 1 AS ok FROM org_policies p JOIN users_organizations uo ON uo.org_uuid = p.org_uuid
                 WHERE uo.user_uuid = ?1 AND p.atype = ?2 AND p.enabled = 1 AND uo.status = 2
                   AND uo.atype NOT IN (0, 1)
                   AND COALESCE(json_extract(p.data, '$.disableHideEmail'), 0) = 1 LIMIT 1",
            )
            .bind(&[user_id.into(), policy_type::SEND_OPTIONS.into()])?
            .first(None)
            .await?;
        if row.is_some() {
            return Err(AppError::BadRequest(
                "Due to an Enterprise Policy, you are not allowed to hide your email address from recipients when creating or editing a Send."
                    .to_string(),
            ));
        }
    }
    Ok(())
}

async fn user_has_2fa(db: &db::Db, user_id: &str) -> Result<bool, AppError> {
    let row: Option<Value> = db
        .prepare("SELECT 1 AS ok FROM twofactor WHERE user_uuid = ?1 AND atype < 1000 AND enabled = 1 LIMIT 1")
        .bind(&[user_id.into()])?
        .first(None)
        .await?;
    Ok(row.is_some())
}

async fn other_active_memberships(
    db: &db::Db,
    user_id: &str,
    org_id: &str,
) -> Result<i64, AppError> {
    #[derive(Deserialize)]
    struct Cnt {
        n: i64,
    }
    let c: Option<Cnt> = db
        .prepare(
            "SELECT COUNT(*) AS n FROM users_organizations WHERE user_uuid = ?1 AND org_uuid != ?2 AND status IN (1, 2)",
        )
        .bind(&[user_id.into(), org_id.into()])?
        .first(None)
        .await?;
    Ok(c.map(|c| c.n).unwrap_or(0))
}

/// vaultwarden `OrgPolicy::check_user_allowed` for a membership about to become active
/// (`action` is join/confirm/restore/modify), with `status`/`atype` as they will be.
pub async fn check_user_allowed(
    db: &db::Db,
    m: &MembershipRow,
    atype: i32,
    status: i32,
    action: &str,
) -> Result<(), AppError> {
    if role_rank(atype) >= role_rank(membership_type::ADMIN) || status <= membership_status::INVITED
    {
        return Ok(());
    }
    if policy_enabled(db, &m.org_uuid, policy_type::TWO_FACTOR).await?
        && !user_has_2fa(db, &m.user_uuid).await?
    {
        return Err(AppError::BadRequest(format!(
            "Cannot {action} because 2FA is required (membership {})",
            m.uuid
        )));
    }
    if policy_applies_to_user(db, &m.user_uuid, policy_type::SINGLE_ORG, Some(&m.org_uuid)).await? {
        return Err(AppError::BadRequest(format!(
            "Cannot {action} because another organization policy forbids it (membership {})",
            m.uuid
        )));
    }
    if policy_enabled(db, &m.org_uuid, policy_type::SINGLE_ORG).await?
        && other_active_memberships(db, &m.user_uuid, &m.org_uuid).await? > 0
    {
        return Err(AppError::BadRequest(format!(
            "Cannot {action} because the organization policy forbids being part of other organization (membership {})",
            m.uuid
        )));
    }
    Ok(())
}

/// After a user lost their last 2FA provider: revoke their confirmed sub-admin memberships in
/// orgs requiring 2FA (vaultwarden `enforce_2fa_policy`).
pub async fn enforce_2fa_policy_for_user(db: &db::Db, user_id: &str) -> Result<(), AppError> {
    d1_query!(
        db,
        "UPDATE users_organizations SET status = status - ?1
         WHERE user_uuid = ?2 AND status = 2 AND atype NOT IN (0, 1)
           AND org_uuid IN (SELECT org_uuid FROM org_policies WHERE atype = 0 AND enabled = 1)",
        ACTIVATE_REVOKE_DIFF,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    Ok(())
}

/// Merged master-password policy of the user's orgs (vaultwarden `master_password_policy`),
/// keys in camelCase plus `Object`. Empty object when none applies.
pub async fn master_password_policy(db: &db::Db, user_id: &str) -> Result<Value, AppError> {
    #[derive(Deserialize)]
    struct Row {
        data: String,
    }
    let rows: Vec<Row> = db
        .prepare(
            "SELECT p.data FROM org_policies p JOIN users_organizations uo ON uo.org_uuid = p.org_uuid
             WHERE uo.user_uuid = ?1 AND uo.status IN (1, 2) AND p.atype = 1 AND p.enabled = 1",
        )
        .bind(&[user_id.into()])?
        .all()
        .await?
        .results()?;
    let mut merged = serde_json::Map::new();
    for r in rows {
        let Ok(Value::Object(p)) = serde_json::from_str::<Value>(&r.data) else {
            continue;
        };
        for (k, v) in p {
            let next = match (merged.get(&k), &v) {
                (Some(Value::Number(a)), Value::Number(b)) => {
                    if b.as_f64() > a.as_f64() {
                        v.clone()
                    } else {
                        Value::Number(a.clone())
                    }
                }
                (Some(Value::Bool(a)), Value::Bool(b)) => Value::Bool(*a || *b),
                (Some(existing), _) if v.is_null() => existing.clone(),
                _ => v.clone(),
            };
            merged.insert(k, next);
        }
    }
    let mut out = Value::Object(merged);
    out["Object"] = json!("masterPasswordPolicy");
    Ok(out)
}

/// PascalCase variant used in identity responses (vaultwarden `identity_master_password_policy`).
pub fn pascal_case_keys(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(mut k, v)| {
                    if let Some(first) = k.get_mut(..1) {
                        first.make_ascii_uppercase();
                    }
                    (k, v)
                })
                .collect(),
        ),
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// GET /api/organizations/{org_id}/policies
#[worker::send]
pub async fn list_policies(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let rows: Vec<PolicyRow> = db
        .prepare(format!(
            "SELECT {POLICY_COLS} FROM org_policies WHERE org_uuid = ?1"
        ))
        .bind(&[org_id.into()])?
        .all()
        .await?
        .results()?;
    let data: Vec<Value> = rows.iter().map(policy_json).collect();
    Ok(Json(
        json!({"data": data, "object": "list", "continuationToken": null}),
    ))
}

/// GET /api/organizations/{org_id}/policies/token?token= (invite-link flow; needs mail)
pub async fn list_policies_token() -> Result<Json<Value>, AppError> {
    Err(AppError::BadRequest(
        "Invitation links are not enabled on this server".to_string(),
    ))
}

/// GET /api/organizations/{org_id}/policies/master-password
#[worker::send]
pub async fn get_master_password_policy(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    if org_id.eq_ignore_ascii_case(FAKE_SSO_ORG_ID) {
        return Ok(Json(default_policy_json(
            &org_id,
            policy_type::MASTER_PASSWORD,
        )));
    }
    let db = db::get_db(&env)?;
    find_membership(&db, &claims.sub, &org_id)
        .await?
        .filter(|m| m.status >= membership_status::ACCEPTED)
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    Ok(Json(
        match find_policy(&db, &org_id, policy_type::MASTER_PASSWORD).await? {
            Some(p) => policy_json(&p),
            None => default_policy_json(&org_id, policy_type::MASTER_PASSWORD),
        },
    ))
}

fn parse_policy_type(raw: &str) -> Result<i32, AppError> {
    raw.parse::<i32>()
        .ok()
        .filter(|t| policy_type::ALL.contains(t))
        .ok_or_else(|| AppError::BadRequest("Invalid or unsupported policy type".to_string()))
}

/// GET /api/organizations/{org_id}/policies/{pol_type}
#[worker::send]
pub async fn get_policy(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, pol_type)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    if pol_type == "master-password" {
        return get_master_password_policy(claims, State(env), Path(org_id)).await;
    }
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let atype = parse_policy_type(&pol_type)?;
    Ok(Json(match find_policy(&db, &org_id, atype).await? {
        Some(p) => policy_json(&p),
        None => default_policy_json(&org_id, atype),
    }))
}

#[derive(Deserialize)]
pub struct PolicyData {
    enabled: bool,
    data: Option<Value>,
}

/// Accepts `{policy: {...}}` (current clients) and the bare `{enabled, data}` shape.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum PutPolicy {
    Wrapped { policy: PolicyData },
    Bare(PolicyData),
}

/// PUT /api/organizations/{org_id}/policies/{pol_type} (+ /vnext)
#[worker::send]
pub async fn put_policy(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, pol_type)): Path<(String, String)>,
    Json(body): Json<PutPolicy>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let atype = parse_policy_type(&pol_type)?;
    let data = match body {
        PutPolicy::Wrapped { policy } => policy,
        PutPolicy::Bare(p) => p,
    };
    let current = find_policy(&db, &org_id, atype).await?;
    let currently_enabled = current.as_ref().is_some_and(|p| p.enabled != 0);

    if atype == policy_type::FILL_ASSIST && data.enabled {
        if !currently_enabled && !policy_enabled(&db, &org_id, policy_type::SINGLE_ORG).await? {
            return Err(AppError::BadRequest(
                "Turn on the Single organization policy because it is required for the Activate fill assist policy.".to_string(),
            ));
        }
        let url = data
            .data
            .as_ref()
            .and_then(|d| d.get("rulesUrl").or_else(|| d.get("RulesUrl")))
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if url.is_empty() {
            return Err(AppError::BadRequest(
                "The RulesUrl field is required.".to_string(),
            ));
        }
        if !url.starts_with("https://") || url.len() <= "https://".len() {
            return Err(AppError::BadRequest("RulesUrl must use HTTPS.".to_string()));
        }
    }
    if atype == policy_type::SINGLE_ORG
        && !data.enabled
        && currently_enabled
        && policy_enabled(&db, &org_id, policy_type::FILL_ASSIST).await?
    {
        return Err(AppError::BadRequest(
            "Turn off the Activate fill assist policy because it requires the Single organization policy.".to_string(),
        ));
    }

    let now = db::now_string();
    let mut stmts = Vec::new();
    if atype == policy_type::TWO_FACTOR && data.enabled {
        // Revoke confirmed sub-admin members without 2FA (vaultwarden enforce_2fa_policy_for_org).
        stmts.push(
            d1_query!(
                &db,
                "UPDATE users_organizations SET status = status - ?1
                 WHERE org_uuid = ?2 AND status = 2 AND atype NOT IN (0, 1)
                   AND NOT EXISTS (SELECT 1 FROM twofactor t WHERE t.user_uuid = users_organizations.user_uuid AND t.atype < 1000 AND t.enabled = 1)",
                ACTIVATE_REVOKE_DIFF,
                org_id
            )
            .map_err(|_| AppError::Database)?,
        );
    }
    if atype == policy_type::SINGLE_ORG && data.enabled {
        // Revoke active sub-admin members that belong to another organization.
        stmts.push(
            d1_query!(
                &db,
                "UPDATE users_organizations SET status = status - ?1
                 WHERE org_uuid = ?2 AND status IN (1, 2) AND atype NOT IN (0, 1)
                   AND EXISTS (SELECT 1 FROM users_organizations o WHERE o.user_uuid = users_organizations.user_uuid
                               AND o.org_uuid != ?2 AND o.status IN (1, 2))",
                ACTIVATE_REVOKE_DIFF,
                org_id
            )
            .map_err(|_| AppError::Database)?,
        );
    }
    let data_json = serde_json::to_string(&data.data).map_err(|_| AppError::Internal)?;
    let id = current
        .as_ref()
        .map(|p| p.uuid.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    stmts.push(
        d1_query!(
            &db,
            "INSERT INTO org_policies (uuid, org_uuid, atype, enabled, data, revision_date) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(uuid) DO UPDATE SET enabled = excluded.enabled, data = excluded.data, revision_date = excluded.revision_date",
            id,
            org_id,
            atype,
            data.enabled as i32,
            data_json,
            now
        )
        .map_err(|_| AppError::Database)?,
    );
    stmts.push(
        d1_query!(
            &db,
            "UPDATE users SET updated_at = ?1 WHERE uuid IN (SELECT user_uuid FROM users_organizations WHERE org_uuid = ?2)",
            now,
            org_id
        )
        .map_err(|_| AppError::Database)?,
    );
    db.batch(stmts).await?;
    let p = find_policy(&db, &org_id, atype)
        .await?
        .ok_or(AppError::Internal)?;
    Ok(Json(policy_json(&p)))
}
