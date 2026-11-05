//! Organizations and collections (phase 3.1), ported from vaultwarden
//! `src/api/core/organizations.rs`. Access rules live in `models::org_access`.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;
use worker::{D1PreparedStatement, Env};

use crate::auth::Claims;
use crate::d1_query;
use crate::db;
use crate::error::AppError;
use crate::models::org_access::{membership_status, membership_type, with_access};
use crate::models::user::User;

// ---------------------------------------------------------------------------
// Rows and helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct OrgRow {
    pub uuid: String,
    pub name: String,
    pub billing_email: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MembershipRow {
    pub uuid: String,
    pub user_uuid: String,
    pub org_uuid: String,
    pub access_all: i32,
    pub akey: String,
    pub status: i32,
    pub atype: i32,
    pub reset_password_key: Option<String>,
    pub external_id: Option<String>,
}

const MEMBERSHIP_COLS: &str =
    "uuid, user_uuid, org_uuid, access_all, akey, status, atype, reset_password_key, external_id";

/// vaultwarden's ordering of membership types: Owner > Admin > Manager(=Custom) > User.
pub fn role_rank(atype: i32) -> i32 {
    match atype {
        membership_type::OWNER => 4,
        membership_type::ADMIN => 3,
        membership_type::MANAGER | membership_type::CUSTOM => 2,
        _ => 1,
    }
}

/// Owners and admins (and access_all members) have full access to all org collections.
pub fn has_full_access(m: &MembershipRow) -> bool {
    m.access_all != 0 || role_rank(m.atype) >= role_rank(membership_type::ADMIN)
}

/// Revoked memberships keep their previous status minus this offset (vaultwarden).
pub const ACTIVATE_REVOKE_DIFF: i32 = 128;

/// Status as reported to clients: every revoked state is `-1`.
pub fn client_status(status: i32) -> i32 {
    if status < membership_status::REVOKED {
        membership_status::REVOKED
    } else {
        status
    }
}

/// vaultwarden reports Manager as Custom to clients.
fn type_for_client(atype: i32) -> i32 {
    if atype == membership_type::MANAGER {
        membership_type::CUSTOM
    } else {
        atype
    }
}

pub async fn find_org(db: &db::Db, org_id: &str) -> Result<Option<OrgRow>, AppError> {
    Ok(db
        .prepare("SELECT uuid, name, billing_email, private_key, public_key FROM organizations WHERE uuid = ?1")
        .bind(&[org_id.into()])?
        .first(None)
        .await?)
}

pub async fn find_membership(
    db: &db::Db,
    user_id: &str,
    org_id: &str,
) -> Result<Option<MembershipRow>, AppError> {
    Ok(db
        .prepare(format!(
            "SELECT {MEMBERSHIP_COLS} FROM users_organizations WHERE user_uuid = ?1 AND org_uuid = ?2"
        ))
        .bind(&[user_id.into(), org_id.into()])?
        .first(None)
        .await?)
}

/// Confirmed membership with at least `min_type`'s rank, else 404 like vaultwarden's guards.
pub async fn require_role(
    db: &db::Db,
    user_id: &str,
    org_id: &str,
    min_type: i32,
) -> Result<MembershipRow, AppError> {
    let m = find_membership(db, user_id, org_id)
        .await?
        .filter(|m| m.status == membership_status::CONFIRMED)
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    if role_rank(m.atype) < role_rank(min_type) {
        return Err(AppError::Unauthorized(
            "You don't have permission to perform this action".to_string(),
        ));
    }
    Ok(m)
}

/// Organization JSON; `use_reset_password` mirrors vaultwarden (`CONFIG.mail_enabled()`).
pub fn org_json_with(org: &OrgRow, use_reset_password: bool) -> Value {
    json!({
        "id": org.uuid,
        "name": org.name,
        "seats": null,
        "maxCollections": null,
        "maxStorageGb": i16::MAX,
        "use2fa": true,
        "useCustomPermissions": true,
        "useDirectory": false,
        "useEvents": false,
        "useGroups": true,
        "useTotp": true,
        "usePolicies": true,
        "useScim": false,
        "useSso": false,
        "useKeyConnector": false,
        "usePasswordManager": true,
        "useSecretsManager": false,
        "selfHost": true,
        "useApi": true,
        "useDisableSMAdsForUsers": true,
        "useInviteLinks": false,
        "useMyItems": false,
        "useOrganizationDomains": false,
        "usePam": false,
        "usePhishingBlocker": false,
        "hasPublicAndPrivateKeys": org.private_key.is_some() && org.public_key.is_some(),
        "useResetPassword": use_reset_password,
        "allowAdminAccessToAllCollectionItems": true,
        "limitCollectionCreation": true,
        "limitCollectionDeletion": true,
        "limitItemDeletion": false,
        "businessName": org.name,
        "businessAddress1": null,
        "businessAddress2": null,
        "businessAddress3": null,
        "businessCountry": null,
        "businessTaxNumber": null,
        "maxAutoscaleSeats": null,
        "maxAutoscaleSmSeats": null,
        "maxAutoscaleSmServiceAccounts": null,
        "secretsManagerPlan": null,
        "smSeats": null,
        "smServiceAccounts": null,
        "billingEmail": org.billing_email,
        "planType": 6,
        "usersGetPremium": true,
        "object": "organization",
    })
}

/// `profile.organizations[]` entry: vaultwarden `Membership::to_json`.
fn profile_org_json(m: &MembershipRow, org: &OrgRow, use_reset_password: bool) -> Value {
    let t = type_for_client(m.atype);
    json!({
        "id": m.org_uuid,
        "identifier": null,
        "name": org.name,
        "seats": 20,
        "maxCollections": null,
        "usersGetPremium": true,
        "use2fa": true,
        "useDirectory": false,
        "useEvents": false,
        "useGroups": true,
        "useTotp": true,
        "useScim": false,
        "usePolicies": true,
        "useApi": true,
        "selfHost": true,
        "hasPublicAndPrivateKeys": org.private_key.is_some() && org.public_key.is_some(),
        "resetPasswordEnrolled": m.reset_password_key.is_some(),
        "useResetPassword": use_reset_password,
        "ssoBound": false,
        "useSso": false,
        "useKeyConnector": false,
        "useSecretsManager": false,
        "usePasswordManager": true,
        "useCustomPermissions": true,
        "useActivateAutofillPolicy": false,
        "useAdminSponsoredFamilies": false,
        "useRiskInsights": false,
        "useDisableSMAdsForUsers": true,
        "useInviteLinks": false,
        "useMyItems": false,
        "useOrganizationDomains": false,
        "usePam": false,
        "usePhishingBlocker": false,
        "organizationUserId": m.uuid,
        "providerId": null,
        "providerName": null,
        "providerType": null,
        "familySponsorshipFriendlyName": null,
        "familySponsorshipAvailable": false,
        "productTierType": 3,
        "keyConnectorEnabled": false,
        "keyConnectorUrl": null,
        "familySponsorshipLastSyncDate": null,
        "familySponsorshipValidUntil": null,
        "familySponsorshipToDelete": null,
        "accessSecretsManager": false,
        "limitCollectionCreation": role_rank(m.atype) < role_rank(membership_type::MANAGER) || m.access_all == 0,
        "limitCollectionDeletion": true,
        "limitItemDeletion": false,
        "allowAdminAccessToAllCollectionItems": true,
        "userIsClaimedByOrganization": false,
        "permissions": {
            "accessEventLogs": false,
            "accessImportExport": false,
            "accessReports": false,
            "createNewCollections": t == membership_type::CUSTOM && m.access_all != 0,
            "editAnyCollection": t == membership_type::CUSTOM && m.access_all != 0,
            "deleteAnyCollection": t == membership_type::CUSTOM && m.access_all != 0,
            "manageGroups": false,
            "managePolicies": false,
            "manageSso": false,
            "manageUsers": false,
            "manageResetPassword": false,
            "manageScim": false
        },
        "maxStorageGb": i16::MAX,
        "userId": m.user_uuid,
        "key": (!m.akey.is_empty()).then_some(&m.akey),
        "status": m.status,
        "type": t,
        "enabled": true,
        "object": "profileOrganization",
    })
}

#[derive(Deserialize)]
struct MembershipOrgRow {
    #[serde(flatten)]
    m: MembershipRow,
    name: String,
    billing_email: String,
    private_key: Option<String>,
    public_key: Option<String>,
}

/// All `profile.organizations` entries of a user (every membership, like vaultwarden).
pub async fn profile_organizations(
    env: &Env,
    db: &db::Db,
    user_id: &str,
) -> Result<Vec<Value>, AppError> {
    let use_reset_password = crate::mail::mail_enabled(env);
    let rows: Vec<MembershipOrgRow> = db
        .prepare(
            "SELECT uo.uuid, uo.user_uuid, uo.org_uuid, uo.access_all, uo.akey, uo.status, uo.atype,
                    uo.reset_password_key, uo.external_id,
                    o.name, o.billing_email, o.private_key, o.public_key
             FROM users_organizations uo JOIN organizations o ON o.uuid = uo.org_uuid
             WHERE uo.user_uuid = ?1",
        )
        .bind(&[user_id.into()])?
        .all()
        .await?
        .results()?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let org = OrgRow {
                uuid: r.m.org_uuid.clone(),
                name: r.name,
                billing_email: r.billing_email,
                private_key: r.private_key,
                public_key: r.public_key,
            };
            profile_org_json(&r.m, &org, use_reset_password)
        })
        .collect())
}

/// Sync `collections` array (collectionDetails) for the user bound to `?1`, as a JSON string.
pub async fn sync_collections_json(db: &db::Db, user_id: &str) -> Result<String, AppError> {
    #[derive(Deserialize)]
    struct Row {
        j: String,
    }
    let sql = format!(
        "{}SELECT COALESCE(json_group_array(json(x.j)), '[]') AS j FROM (
            SELECT json_object(
                'id', co.uuid, 'organizationId', co.org_uuid, 'name', co.name, 'externalId', co.external_id,
                'type', 0, 'defaultUserCollectionEmail', NULL,
                'readOnly', CASE WHEN u.read_only THEN json('true') ELSE json('false') END,
                'hidePasswords', CASE WHEN u.hide_passwords THEN json('true') ELSE json('false') END,
                'manage', CASE WHEN u.manage THEN json('true') ELSE json('false') END,
                'object', 'collectionDetails') AS j
            FROM collections co JOIN ucol u ON u.collection_uuid = co.uuid
         ) x",
        with_access("?1")
    );
    let row: Option<Row> = db.prepare(sql).bind(&[user_id.into()])?.first(None).await?;
    Ok(row.map(|r| r.j).unwrap_or_else(|| "[]".to_string()))
}

fn collection_json(id: &str, org_id: &str, name: &str, external_id: &Option<String>) -> Value {
    json!({
        "externalId": external_id,
        "id": id,
        "organizationId": org_id,
        "name": name,
        "type": 0,
        "defaultUserCollectionEmail": null,
        "object": "collection",
    })
}

#[derive(Debug, Deserialize, Clone)]
struct CollectionRow {
    uuid: String,
    org_uuid: String,
    name: String,
    external_id: Option<String>,
}

async fn find_collection(
    db: &db::Db,
    org_id: &str,
    col_id: &str,
) -> Result<CollectionRow, AppError> {
    db.prepare("SELECT uuid, org_uuid, name, external_id FROM collections WHERE uuid = ?1 AND org_uuid = ?2")
        .bind(&[col_id.into(), org_id.into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("Collection not found".to_string()))
}

/// True when the user (bound to `?1`) may manage collection `col_id`: full-access members, or
/// managers whose access to it is manage / read-write. Mirrors vaultwarden ManagerHeaders.
async fn can_manage_collection(
    db: &db::Db,
    user_id: &str,
    m: &MembershipRow,
    col_id: &str,
) -> Result<bool, AppError> {
    if has_full_access(m) {
        return Ok(true);
    }
    if role_rank(m.atype) < role_rank(membership_type::MANAGER) {
        return Ok(false);
    }
    let row: Option<Value> = db
        .prepare(format!(
            "{}SELECT 1 AS ok FROM ucol WHERE collection_uuid = ?2 AND manage = 1",
            with_access("?1")
        ))
        .bind(&[user_id.into(), col_id.into()])?
        .first(None)
        .await?;
    Ok(row.is_some())
}

fn now() -> String {
    db::now_string()
}

pub async fn touch_org_members(db: &db::Db, org_id: &str) -> Result<(), AppError> {
    d1_query!(
        db,
        "UPDATE users SET updated_at = ?1 WHERE uuid IN (SELECT user_uuid FROM users_organizations WHERE org_uuid = ?2 AND status = 2)",
        now(),
        org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Organization lifecycle
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgKeyData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgCreateData {
    name: String,
    billing_email: String,
    collection_name: String,
    key: String,
    keys: Option<OrgKeyData>,
}

/// POST /api/organizations
#[worker::send]
pub async fn create_organization(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(data): Json<OrgCreateData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    if crate::handlers::org_policies::policy_applies_to_user(
        &db,
        &claims.sub,
        crate::handlers::org_policies::policy_type::SINGLE_ORG,
        None,
    )
    .await?
    {
        return Err(AppError::BadRequest(
            "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization.".to_string(),
        ));
    }
    let org_id = Uuid::new_v4().to_string();
    let member_id = Uuid::new_v4().to_string();
    let col_id = Uuid::new_v4().to_string();
    let (private_key, public_key) = match data.keys {
        Some(k) => (Some(k.encrypted_private_key), Some(k.public_key)),
        None => (None, None),
    };
    let billing_email = data.billing_email.to_lowercase();
    db.batch(vec![
        d1_query!(
            &db,
            "INSERT INTO organizations (uuid, name, billing_email, private_key, public_key) VALUES (?1, ?2, ?3, ?4, ?5)",
            org_id,
            data.name,
            billing_email,
            private_key,
            public_key
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            &db,
            "INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, akey, status, atype) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)",
            member_id,
            claims.sub,
            org_id,
            data.key,
            membership_status::CONFIRMED,
            membership_type::OWNER
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            &db,
            "INSERT INTO collections (uuid, org_uuid, name) VALUES (?1, ?2, ?3)",
            col_id,
            org_id,
            data.collection_name
        )
        .map_err(|_| AppError::Database)?,
    ])
    .await?;
    db::touch_user_updated_at(&db, &claims.sub, &now()).await?;
    let org = find_org(&db, &org_id).await?.ok_or(AppError::Internal)?;
    Ok(Json(org_json_with(&org, crate::mail::mail_enabled(&env))))
}

/// GET /api/organizations/{org_id}
#[worker::send]
pub async fn get_organization(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::OWNER).await?;
    let org = find_org(&db, &org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Can't find organization details".to_string()))?;
    Ok(Json(org_json_with(&org, crate::mail::mail_enabled(&env))))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgUpdateData {
    name: String,
    billing_email: String,
}

/// PUT|POST /api/organizations/{org_id}
#[worker::send]
pub async fn put_organization(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<OrgUpdateData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::OWNER).await?;
    d1_query!(
        &db,
        "UPDATE organizations SET name = ?1, billing_email = ?2 WHERE uuid = ?3",
        data.name,
        data.billing_email.to_lowercase(),
        org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    touch_org_members(&db, &org_id).await?;
    let org = find_org(&db, &org_id).await?.ok_or(AppError::Internal)?;
    Ok(Json(org_json_with(&org, crate::mail::mail_enabled(&env))))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordData {
    master_password_hash: Option<String>,
}

async fn verify_password(db: &db::Db, user_id: &str, hash: Option<&str>) -> Result<(), AppError> {
    let user: User = db
        .prepare(crate::models::user::select_user_by_id_sql())
        .bind(&[user_id.into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let hash =
        hash.ok_or_else(|| AppError::BadRequest("Missing master password hash".to_string()))?;
    if !user.verify_master_password(hash).await?.is_valid() {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }
    Ok(())
}

/// Statements deleting an organization and everything that references it.
fn delete_org_statements(db: &db::Db, org_id: &str) -> Result<Vec<D1PreparedStatement>, AppError> {
    let binds = [org_id.into()];
    let mut stmts = db::delete_ciphers_statements(db, "organization_uuid = ?1", &binds)?;
    for sql in [
        "DELETE FROM ciphers_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM users_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM collections_groups WHERE collections_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM groups_users WHERE groups_uuid IN (SELECT uuid FROM groups WHERE organizations_uuid = ?1)",
        "DELETE FROM collections_groups WHERE groups_uuid IN (SELECT uuid FROM groups WHERE organizations_uuid = ?1)",
        "DELETE FROM groups WHERE organizations_uuid = ?1",
        "DELETE FROM collections WHERE org_uuid = ?1",
        "DELETE FROM org_policies WHERE org_uuid = ?1",
        "DELETE FROM organization_api_key WHERE org_uuid = ?1",
        "DELETE FROM auth_requests WHERE organization_uuid = ?1",
        "DELETE FROM sends WHERE organization_uuid = ?1",
        "DELETE FROM users_organizations WHERE org_uuid = ?1",
        "DELETE FROM organizations WHERE uuid = ?1",
    ] {
        stmts.push(db.prepare(sql).bind(&binds)?);
    }
    Ok(stmts)
}

/// DELETE /api/organizations/{org_id} and POST /api/organizations/{org_id}/delete
#[worker::send]
pub async fn delete_organization(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<PasswordData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::OWNER).await?;
    verify_password(&db, &claims.sub, data.master_password_hash.as_deref()).await?;
    if crate::handlers::attachments::attachments_enabled(env.as_ref()) {
        let keys = crate::handlers::attachments::list_attachment_keys_for_org(&db, &org_id).await?;
        crate::handlers::attachments::delete_storage_objects(env.as_ref(), &keys).await?;
    }
    touch_org_members(&db, &org_id).await?;
    db.batch(delete_org_statements(&db, &org_id)?).await?;
    Ok(Json(json!({})))
}

/// POST /api/organizations/{org_id}/leave
#[worker::send]
pub async fn leave_organization(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = find_membership(&db, &claims.sub, &org_id)
        .await?
        .filter(|m| m.status == membership_status::CONFIRMED)
        .ok_or_else(|| {
            AppError::BadRequest(
                "You need to be a Member of the Organization to call this endpoint".to_string(),
            )
        })?;
    if m.atype == membership_type::OWNER {
        #[derive(Deserialize)]
        struct Cnt {
            n: i64,
        }
        let c: Option<Cnt> = db
            .prepare("SELECT COUNT(*) AS n FROM users_organizations WHERE org_uuid = ?1 AND atype = 0 AND status = 2")
            .bind(&[org_id.clone().into()])?
            .first(None)
            .await?;
        if c.map(|c| c.n).unwrap_or(0) <= 1 {
            return Err(AppError::BadRequest(
                "The last owner can't leave".to_string(),
            ));
        }
    }
    delete_membership(&db, &m).await?;
    db::touch_user_updated_at(&db, &claims.sub, &now()).await?;
    Ok(Json(json!({})))
}

/// Remove a membership plus the member's collection/group links (vaultwarden `Membership::delete`).
pub async fn delete_membership(db: &db::Db, m: &MembershipRow) -> Result<(), AppError> {
    db.batch(vec![
        d1_query!(
            db,
            "DELETE FROM users_collections WHERE user_uuid = ?1 AND collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?2)",
            m.user_uuid,
            m.org_uuid
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(db, "DELETE FROM groups_users WHERE users_organizations_uuid = ?1", m.uuid)
            .map_err(|_| AppError::Database)?,
        d1_query!(db, "DELETE FROM users_organizations WHERE uuid = ?1", m.uuid)
            .map_err(|_| AppError::Database)?,
    ])
    .await?;
    Ok(())
}

/// GET /api/organizations/{org_id}/keys
#[worker::send]
pub async fn get_org_keys(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::USER).await?;
    let org = find_org(&db, &org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    // vaultwarden answers /keys with the public key only; the encrypted private key is only
    // handed out for account recovery (reset-password-details).
    Ok(Json(json!({
        "object": "organizationPublicKey",
        "publicKey": org.public_key,
    })))
}

/// GET /api/organizations/{org_id}/public-key
#[worker::send]
pub async fn get_org_public_key(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::USER).await?;
    let org = find_org(&db, &org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    Ok(Json(json!({
        "object": "organizationPublicKey",
        "publicKey": org.public_key,
    })))
}

/// POST /api/organizations/{org_id}/keys (only when the org has no key pair yet)
#[worker::send]
pub async fn post_org_keys(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<OrgKeyData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let org = find_org(&db, &org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    if org.private_key.is_some() && org.public_key.is_some() {
        return Err(AppError::BadRequest(
            "Organization Keys already exist".to_string(),
        ));
    }
    d1_query!(
        &db,
        "UPDATE organizations SET private_key = ?1, public_key = ?2 WHERE uuid = ?3",
        data.encrypted_private_key,
        data.public_key,
        org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    Ok(Json(json!({
        "object": "keys",
        "publicKey": data.public_key,
        "privateKey": data.encrypted_private_key,
    })))
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

/// GET /api/collections
#[worker::send]
pub async fn get_user_collections(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let rows: Vec<CollectionRow> = db
        .prepare(format!(
            "{}SELECT co.uuid, co.org_uuid, co.name, co.external_id FROM collections co
             JOIN ucol u ON u.collection_uuid = co.uuid",
            with_access("?1")
        ))
        .bind(&[claims.sub.into()])?
        .all()
        .await?
        .results()?;
    let data: Vec<Value> = rows
        .iter()
        .map(|c| collection_json(&c.uuid, &c.org_uuid, &c.name, &c.external_id))
        .collect();
    Ok(Json(
        json!({"data": data, "object": "list", "continuationToken": null}),
    ))
}

/// GET /api/organizations/{org_id}/collections
#[worker::send]
pub async fn get_org_collections(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::MANAGER).await?;
    let rows: Vec<CollectionRow> = db
        .prepare("SELECT uuid, org_uuid, name, external_id FROM collections WHERE org_uuid = ?1")
        .bind(&[org_id.into()])?
        .all()
        .await?
        .results()?;
    let data: Vec<Value> = rows
        .iter()
        .map(|c| collection_json(&c.uuid, &c.org_uuid, &c.name, &c.external_id))
        .collect();
    Ok(Json(
        json!({"data": data, "object": "list", "continuationToken": null}),
    ))
}

/// Access entries (users/groups) of every collection of an org, as JSON maps.
async fn collection_access_entries(
    db: &db::Db,
    org_id: &str,
) -> Result<(Vec<(String, Value)>, Vec<(String, Value)>, Vec<Value>), AppError> {
    #[derive(Deserialize)]
    struct UserEntry {
        collection_uuid: String,
        member_uuid: String,
        read_only: i32,
        hide_passwords: i32,
        manage: i32,
    }
    #[derive(Deserialize)]
    struct GroupEntry {
        collections_uuid: String,
        groups_uuid: String,
        read_only: i32,
        hide_passwords: i32,
        manage: i32,
    }
    #[derive(Deserialize)]
    struct ManageAll {
        uuid: String,
    }
    let users: Vec<UserEntry> = db
        .prepare(
            "SELECT uc.collection_uuid, uo.uuid AS member_uuid, uc.read_only, uc.hide_passwords, uc.manage
             FROM users_collections uc
             JOIN collections co ON co.uuid = uc.collection_uuid
             JOIN users_organizations uo ON uo.user_uuid = uc.user_uuid AND uo.org_uuid = co.org_uuid
             WHERE co.org_uuid = ?1",
        )
        .bind(&[org_id.into()])?
        .all()
        .await?
        .results()?;
    let groups: Vec<GroupEntry> = db
        .prepare(
            "SELECT cg.collections_uuid, cg.groups_uuid, cg.read_only, cg.hide_passwords, cg.manage
             FROM collections_groups cg JOIN collections co ON co.uuid = cg.collections_uuid
             WHERE co.org_uuid = ?1",
        )
        .bind(&[org_id.into()])?
        .all()
        .await?
        .results()?;
    // Confirmed owners/admins/access_all members implicitly manage every collection.
    let manage_all: Vec<ManageAll> = db
        .prepare(
            "SELECT uuid FROM users_organizations WHERE org_uuid = ?1 AND status = 2 AND (atype IN (0, 1) OR access_all = 1)",
        )
        .bind(&[org_id.into()])?
        .all()
        .await?
        .results()?;
    Ok((
        users
            .into_iter()
            .map(|u| {
                (
                    u.collection_uuid,
                    json!({"id": u.member_uuid, "readOnly": u.read_only != 0, "hidePasswords": u.hide_passwords != 0, "manage": u.manage != 0}),
                )
            })
            .collect(),
        groups
            .into_iter()
            .map(|g| {
                (
                    g.collections_uuid,
                    json!({"id": g.groups_uuid, "readOnly": g.read_only != 0, "hidePasswords": g.hide_passwords != 0, "manage": g.manage != 0}),
                )
            })
            .collect(),
        manage_all
            .into_iter()
            .map(|m| json!({"id": m.uuid, "readOnly": false, "hidePasswords": false, "manage": true}))
            .collect(),
    ))
}

#[derive(Deserialize)]
struct UcolRow {
    collection_uuid: String,
    read_only: i32,
    hide_passwords: i32,
    manage: i32,
}

async fn user_collection_flags(
    db: &db::Db,
    user_id: &str,
    org_id: &str,
) -> Result<Vec<UcolRow>, AppError> {
    Ok(db
        .prepare(format!(
            "{}SELECT u.collection_uuid, u.read_only, u.hide_passwords, u.manage FROM ucol u
             JOIN collections co ON co.uuid = u.collection_uuid WHERE co.org_uuid = ?2",
            with_access("?1")
        ))
        .bind(&[user_id.into(), org_id.into()])?
        .all()
        .await?
        .results()?)
}

fn access_details_json(
    col: &CollectionRow,
    flags: Option<&UcolRow>,
    assigned: bool,
    users: Vec<Value>,
    groups: Vec<Value>,
) -> Value {
    let (ro, hp, mg) = flags
        .map(|f| (f.read_only != 0, f.hide_passwords != 0, f.manage != 0))
        .unwrap_or((false, false, false));
    let mut j = collection_json(&col.uuid, &col.org_uuid, &col.name, &col.external_id);
    j["readOnly"] = json!(ro);
    j["hidePasswords"] = json!(hp);
    j["manage"] = json!(mg);
    j["assigned"] = json!(assigned);
    j["users"] = json!(users);
    j["groups"] = json!(groups);
    j["unmanaged"] = json!(false);
    j["object"] = json!("collectionAccessDetails");
    j
}

/// GET /api/organizations/{org_id}/collections/details
#[worker::send]
pub async fn get_org_collections_details(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = require_role(&db, &claims.sub, &org_id, membership_type::USER).await?;
    let full = has_full_access(&m);
    let cols: Vec<CollectionRow> = db
        .prepare("SELECT uuid, org_uuid, name, external_id FROM collections WHERE org_uuid = ?1")
        .bind(&[org_id.clone().into()])?
        .all()
        .await?
        .results()?;
    let flags = user_collection_flags(&db, &claims.sub, &org_id).await?;
    let (users, groups, manage_all) = collection_access_entries(&db, &org_id).await?;
    let mut data = Vec::new();
    for col in &cols {
        let f = flags.iter().find(|f| f.collection_uuid == col.uuid);
        let assigned = full || f.is_some();
        if !assigned {
            continue;
        }
        let mut u: Vec<Value> = users
            .iter()
            .filter(|(c, _)| c == &col.uuid)
            .map(|(_, v)| v.clone())
            .collect();
        u.extend(manage_all.iter().cloned());
        let g: Vec<Value> = groups
            .iter()
            .filter(|(c, _)| c == &col.uuid)
            .map(|(_, v)| v.clone())
            .collect();
        data.push(access_details_json(col, f, assigned, u, g));
    }
    Ok(Json(
        json!({"data": data, "object": "list", "continuationToken": null}),
    ))
}

/// GET /api/organizations/{org_id}/collections/{col_id}/details
#[worker::send]
pub async fn get_org_collection_detail(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, col_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = require_role(&db, &claims.sub, &org_id, membership_type::MANAGER).await?;
    let col = find_collection(&db, &org_id, &col_id).await?;
    if !can_manage_collection(&db, &claims.sub, &m, &col_id).await? {
        return Err(AppError::NotFound("Collection not found".to_string()));
    }
    let flags = user_collection_flags(&db, &claims.sub, &org_id).await?;
    let f = flags.iter().find(|f| f.collection_uuid == col.uuid);
    let (users, groups, manage_all) = collection_access_entries(&db, &org_id).await?;
    let mut u: Vec<Value> = users
        .iter()
        .filter(|(c, _)| c == &col.uuid)
        .map(|(_, v)| v.clone())
        .collect();
    u.extend(manage_all);
    let g: Vec<Value> = groups
        .iter()
        .filter(|(c, _)| c == &col.uuid)
        .map(|(_, v)| v.clone())
        .collect();
    Ok(Json(access_details_json(&col, f, true, u, g)))
}

/// GET /api/organizations/{org_id}/collections/{col_id}/users
#[worker::send]
pub async fn get_collection_users(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, col_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = require_role(&db, &claims.sub, &org_id, membership_type::MANAGER).await?;
    find_collection(&db, &org_id, &col_id).await?;
    if !can_manage_collection(&db, &claims.sub, &m, &col_id).await? {
        return Err(AppError::NotFound("Collection not found".to_string()));
    }
    let (users, _, _) = collection_access_entries(&db, &org_id).await?;
    let data: Vec<Value> = users
        .into_iter()
        .filter(|(c, _)| c == &col_id)
        .map(|(_, v)| v)
        .collect();
    Ok(Json(json!(data)))
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AccessSelection {
    id: String,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionData {
    name: String,
    external_id: Option<String>,
    #[serde(default)]
    groups: Vec<AccessSelection>,
    #[serde(default)]
    users: Vec<AccessSelection>,
}

/// Statements replacing a collection's user/group access lists. `users[].id` are membership ids.
fn collection_access_statements(
    db: &db::Db,
    org_id: &str,
    col_id: &str,
    data: &CollectionData,
) -> Result<Vec<D1PreparedStatement>, AppError> {
    let mut stmts = vec![
        d1_query!(
            db,
            "DELETE FROM users_collections WHERE collection_uuid = ?1",
            col_id
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            db,
            "DELETE FROM collections_groups WHERE collections_uuid = ?1",
            col_id
        )
        .map_err(|_| AppError::Database)?,
    ];
    for u in &data.users {
        // Owners/admins/access_all members always have full access; vaultwarden skips them.
        stmts.push(
            d1_query!(
                db,
                "INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage)
                 SELECT user_uuid, ?2, ?3, ?4, ?5 FROM users_organizations
                 WHERE uuid = ?1 AND org_uuid = ?6 AND atype NOT IN (0, 1) AND access_all = 0",
                u.id,
                col_id,
                u.read_only as i32,
                u.hide_passwords as i32,
                u.manage as i32,
                org_id
            )
            .map_err(|_| AppError::Database)?,
        );
    }
    for g in &data.groups {
        stmts.push(
            d1_query!(
                db,
                "INSERT INTO collections_groups (collections_uuid, groups_uuid, read_only, hide_passwords, manage)
                 SELECT ?1, uuid, ?2, ?3, ?4 FROM groups WHERE uuid = ?5 AND organizations_uuid = ?6",
                col_id,
                g.read_only as i32,
                g.hide_passwords as i32,
                g.manage as i32,
                g.id,
                org_id
            )
            .map_err(|_| AppError::Database)?,
        );
    }
    Ok(stmts)
}

/// POST /api/organizations/{org_id}/collections
#[worker::send]
pub async fn post_organization_collections(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<CollectionData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = require_role(&db, &claims.sub, &org_id, membership_type::MANAGER).await?;
    // vaultwarden: limitCollectionCreation -> only full-access members may create collections.
    if !has_full_access(&m) && role_rank(m.atype) < role_rank(membership_type::MANAGER) {
        return Err(AppError::Unauthorized(
            "You don't have permission to create collections".to_string(),
        ));
    }
    let col_id = Uuid::new_v4().to_string();
    let mut stmts = vec![d1_query!(
        &db,
        "INSERT INTO collections (uuid, org_uuid, name, external_id) VALUES (?1, ?2, ?3, ?4)",
        col_id,
        org_id,
        data.name,
        data.external_id
    )
    .map_err(|_| AppError::Database)?];
    stmts.extend(collection_access_statements(&db, &org_id, &col_id, &data)?);
    // A manager who creates a collection gets manage access to it (vaultwarden behavior).
    if !has_full_access(&m) {
        stmts.push(
            d1_query!(
                &db,
                "INSERT OR REPLACE INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage) VALUES (?1, ?2, 0, 0, 1)",
                claims.sub,
                col_id
            )
            .map_err(|_| AppError::Database)?,
        );
    }
    db.batch(stmts).await?;
    touch_org_members(&db, &org_id).await?;
    Ok(Json(collection_json(
        &col_id,
        &org_id,
        &data.name,
        &data.external_id,
    )))
}

/// PUT|POST /api/organizations/{org_id}/collections/{col_id}
#[worker::send]
pub async fn put_organization_collection(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, col_id)): Path<(String, String)>,
    Json(data): Json<CollectionData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = require_role(&db, &claims.sub, &org_id, membership_type::MANAGER).await?;
    find_collection(&db, &org_id, &col_id).await?;
    if !can_manage_collection(&db, &claims.sub, &m, &col_id).await? {
        return Err(AppError::NotFound("Collection not found".to_string()));
    }
    let mut stmts = vec![d1_query!(
        &db,
        "UPDATE collections SET name = ?1, external_id = ?2 WHERE uuid = ?3 AND org_uuid = ?4",
        data.name,
        data.external_id.as_deref().filter(|e| !e.trim().is_empty()),
        col_id,
        org_id
    )
    .map_err(|_| AppError::Database)?];
    stmts.extend(collection_access_statements(&db, &org_id, &col_id, &data)?);
    db.batch(stmts).await?;
    touch_org_members(&db, &org_id).await?;
    let col = find_collection(&db, &org_id, &col_id).await?;
    Ok(Json(collection_json(
        &col.uuid,
        &col.org_uuid,
        &col.name,
        &col.external_id,
    )))
}

fn delete_collection_statements(
    db: &db::Db,
    col_id: &str,
) -> Result<Vec<D1PreparedStatement>, AppError> {
    let binds = [col_id.into()];
    let mut out = Vec::new();
    for sql in [
        "DELETE FROM ciphers_collections WHERE collection_uuid = ?1",
        "DELETE FROM users_collections WHERE collection_uuid = ?1",
        "DELETE FROM collections_groups WHERE collections_uuid = ?1",
        "DELETE FROM collections WHERE uuid = ?1",
    ] {
        out.push(db.prepare(sql).bind(&binds)?);
    }
    Ok(out)
}

/// DELETE /api/organizations/{org_id}/collections/{col_id} (+ POST .../delete)
#[worker::send]
pub async fn delete_organization_collection(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, col_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = require_role(&db, &claims.sub, &org_id, membership_type::MANAGER).await?;
    find_collection(&db, &org_id, &col_id).await?;
    if !can_manage_collection(&db, &claims.sub, &m, &col_id).await? {
        return Err(AppError::NotFound("Collection not found".to_string()));
    }
    touch_org_members(&db, &org_id).await?;
    db.batch(delete_collection_statements(&db, &col_id)?)
        .await?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkCollectionIds {
    ids: Vec<String>,
}

/// DELETE /api/organizations/{org_id}/collections (bulk)
#[worker::send]
pub async fn bulk_delete_organization_collections(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkCollectionIds>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = require_role(&db, &claims.sub, &org_id, membership_type::MANAGER).await?;
    let mut stmts = Vec::new();
    for col_id in &data.ids {
        find_collection(&db, &org_id, col_id).await?;
        if !can_manage_collection(&db, &claims.sub, &m, col_id).await? {
            return Err(AppError::NotFound("Collection not found".to_string()));
        }
        stmts.extend(delete_collection_statements(&db, col_id)?);
    }
    touch_org_members(&db, &org_id).await?;
    if !stmts.is_empty() {
        db.batch(stmts).await?;
    }
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------
// Members (read-only listing for 3.1; management lands in 3.2)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OrgUsersQuery {
    #[serde(default)]
    include_collections: bool,
    #[serde(default)]
    include_groups: bool,
}

/// GET /api/organizations/{org_id}/users
#[worker::send]
pub async fn get_members(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Query(q): Query<OrgUsersQuery>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::MANAGER).await?;
    let data = members_json(&db, &org_id, None, q.include_collections, q.include_groups).await?;
    Ok(Json(
        json!({"data": data, "object": "list", "continuationToken": null}),
    ))
}

/// vaultwarden `Membership::to_json_user_details` for every member (or one when `only` is set).
pub async fn members_json(
    db: &db::Db,
    org_id: &str,
    only: Option<&str>,
    include_collections: bool,
    include_groups: bool,
) -> Result<Vec<Value>, AppError> {
    #[derive(Deserialize)]
    struct Row {
        #[serde(flatten)]
        m: MembershipRow,
        name: Option<String>,
        email: String,
        avatar_color: Option<String>,
        has_master_password: i32,
        two_factor_enabled: i32,
        invited_by_email: Option<String>,
    }
    let rows: Vec<Row> = db
        .prepare(
            "SELECT uo.uuid, uo.user_uuid, uo.org_uuid, uo.access_all, uo.akey, uo.status, uo.atype,
                    uo.reset_password_key, uo.external_id, uo.invited_by_email,
                    NULLIF(u.name, '') AS name, u.email, u.avatar_color,
                    (length(u.password_hash) > 0) AS has_master_password,
                    EXISTS (SELECT 1 FROM twofactor t WHERE t.user_uuid = u.uuid AND t.enabled = 1 AND t.atype < 1000) AS two_factor_enabled
             FROM users_organizations uo JOIN users u ON u.uuid = uo.user_uuid
             WHERE uo.org_uuid = ?1 AND (?2 IS NULL OR uo.uuid = ?2)",
        )
        .bind(&[
            org_id.into(),
            only.map(worker::wasm_bindgen::JsValue::from)
                .unwrap_or(worker::wasm_bindgen::JsValue::NULL),
        ])?
        .all()
        .await?
        .results()?;
    let (col_users, _, _) = if include_collections {
        collection_access_entries(db, org_id).await?
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    #[derive(Deserialize)]
    struct GroupLink {
        users_organizations_uuid: String,
        groups_uuid: String,
    }
    let group_links: Vec<GroupLink> = if include_groups {
        db.prepare(
            "SELECT gu.users_organizations_uuid, gu.groups_uuid FROM groups_users gu
             JOIN groups g ON g.uuid = gu.groups_uuid WHERE g.organizations_uuid = ?1",
        )
        .bind(&[org_id.into()])?
        .all()
        .await?
        .results()?
    } else {
        Vec::new()
    };
    Ok(rows
        .into_iter()
        .map(|r| {
            let t = type_for_client(r.m.atype);
            let collections: Vec<Value> = col_users
                .iter()
                .filter(|(_, v)| v["id"] == json!(r.m.uuid))
                .map(|(c, v)| {
                    let mut v = v.clone();
                    v["id"] = json!(c);
                    v
                })
                .collect();
            let groups: Vec<String> = group_links
                .iter()
                .filter(|g| g.users_organizations_uuid == r.m.uuid)
                .map(|g| g.groups_uuid.clone())
                .collect();
            let status = client_status(r.m.status);
            json!({
                "id": r.m.uuid,
                "userId": r.m.user_uuid,
                "name": r.name,
                "email": r.email,
                "externalId": r.m.external_id,
                "avatarColor": r.avatar_color,
                "groups": groups,
                "collections": collections,
                "status": status,
                "type": t,
                "accessAll": r.m.access_all != 0,
                "twoFactorEnabled": r.two_factor_enabled != 0,
                "resetPasswordEnrolled": r.m.reset_password_key.is_some(),
                "hasMasterPassword": r.has_master_password != 0,
                "permissions": {
                    "accessEventLogs": false,
                    "accessImportExport": false,
                    "accessReports": false,
                    "createNewCollections": t == membership_type::CUSTOM && r.m.access_all != 0,
                    "editAnyCollection": t == membership_type::CUSTOM && r.m.access_all != 0,
                    "deleteAnyCollection": t == membership_type::CUSTOM && r.m.access_all != 0,
                    "manageGroups": false,
                    "managePolicies": false,
                    "manageSso": false,
                    "manageUsers": false,
                    "manageResetPassword": false,
                    "manageScim": false
                },
                "ssoBound": false,
                "managedByOrganization": false,
                "claimedByOrganization": false,
                "usesKeyConnector": false,
                "accessSecretsManager": false,
                "invitedByEmail": r.invited_by_email,
                "object": "organizationUserUserDetails",
            })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Stubs the web vault calls (billing, plans, groups/policies until 3.3/3.4)
// ---------------------------------------------------------------------------

/// GET /api/plans
pub async fn get_plans() -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [{
            "object": "plan",
            "type": 0,
            "product": 0,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 0,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        }, {
            "object": "plan",
            "type": 0,
            "product": 1,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 1,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        }],
        "continuationToken": null
    }))
}

/// GET /api/organizations/{org_id}/billing/vnext/warnings
pub async fn get_billing_warnings() -> Json<Value> {
    Json(json!({"freeTrial": null, "inactiveSubscription": null, "resellerRenewal": null}))
}

/// GET /api/organizations/{org_id}/billing/vnext/self-host/metadata
pub async fn get_billing_metadata() -> Json<Value> {
    Json(json!({
        "isEligibleForSelfHost": true,
        "isManaged": false,
        "isOnSecretsManagerStandalone": false,
        "isSubscriptionUnpaid": false,
        "hasSubscription": true,
        "hasOpenInvoice": false,
        "invoiceDueDate": null,
        "invoiceCreatedDate": null,
        "subPeriodEndDate": null,
        "isSubscriptionCanceled": false,
        "organizationOccupiedSeats": 0
    }))
}

/// GET /api/organizations/{identifier}/auto-enroll-status
pub async fn get_auto_enroll_status() -> Json<Value> {
    Json(json!({"id": null, "resetPasswordEnabled": false}))
}

/// The set of collection ids (in `org_id`) the user may add/remove ciphers to/from.
pub async fn writable_collection_ids(
    db: &db::Db,
    user_id: &str,
    org_id: &str,
) -> Result<HashSet<String>, AppError> {
    Ok(user_collection_flags(db, user_id, org_id)
        .await?
        .into_iter()
        .filter(|f| f.read_only == 0)
        .map(|f| f.collection_uuid)
        .collect())
}

/// All collection ids of an organization.
pub async fn org_collection_ids(db: &db::Db, org_id: &str) -> Result<HashSet<String>, AppError> {
    #[derive(Deserialize)]
    struct Row {
        uuid: String,
    }
    Ok(db
        .prepare("SELECT uuid FROM collections WHERE org_uuid = ?1")
        .bind(&[org_id.into()])?
        .all()
        .await?
        .results::<Row>()?
        .into_iter()
        .map(|r| r.uuid)
        .collect())
}

// ---------------------------------------------------------------------------
// Invite tokens (vaultwarden `InviteJwtClaims`, signed with JWT_SECRET, 5 days)
// ---------------------------------------------------------------------------

const INVITE_ISSUER: &str = "vaultwarden-cf|invite";
const INVITE_TTL_HOURS: i64 = 120;

#[derive(serde::Serialize, Deserialize, Debug)]
pub struct InviteClaims {
    pub iss: String,
    pub sub: String,
    pub email: String,
    pub org_id: String,
    pub member_id: String,
    pub invited_by_email: Option<String>,
}

pub fn encode_invite(env: &Env, claims: InviteClaims) -> Result<String, AppError> {
    use jwt_compact::AlgorithmExt;
    let now = chrono::Utc::now();
    let jwt = jwt_compact::Claims::new(claims)
        .set_duration_and_issuance(
            &crate::auth::jwt_time_options(),
            chrono::Duration::hours(INVITE_TTL_HOURS),
        )
        .set_not_before(now);
    let secret = env.secret("JWT_SECRET")?.to_string();
    jwt_compact::alg::Hs256
        .token(
            &jwt_compact::Header::empty(),
            &jwt,
            &jwt_compact::alg::Hs256Key::new(secret.as_bytes()),
        )
        .map_err(|_| AppError::Crypto("Failed to create invite token".to_string()))
}

pub fn decode_invite(env: &Env, token: &str) -> Result<InviteClaims, AppError> {
    use jwt_compact::AlgorithmExt;
    let invalid = || AppError::BadRequest("Invalid or expired invitation token".to_string());
    let secret = env.secret("JWT_SECRET")?.to_string();
    let untrusted = jwt_compact::UntrustedToken::new(token).map_err(|_| invalid())?;
    let token = jwt_compact::alg::Hs256
        .validator::<InviteClaims>(&jwt_compact::alg::Hs256Key::new(secret.as_bytes()))
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

/// Email an invitation for membership `member_id` (mail mode only).
async fn send_member_invite(
    env: &Env,
    db: &db::Db,
    org_id: &str,
    member_id: &str,
    user_id: &str,
    email: &str,
    invited_by: Option<String>,
) -> Result<(), AppError> {
    let org = find_org(db, org_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Error looking up organization".to_string()))?;
    #[derive(Deserialize)]
    struct Row {
        has_keys: i32,
    }
    let has_existing_user = db
        .prepare("SELECT (private_key IS NOT NULL) AS has_keys FROM users WHERE uuid = ?1")
        .bind(&[user_id.into()])?
        .first::<Row>(None)
        .await?
        .is_some_and(|r| r.has_keys != 0);
    let token = encode_invite(
        env,
        InviteClaims {
            iss: INVITE_ISSUER.to_string(),
            sub: user_id.to_string(),
            email: email.to_string(),
            org_id: org_id.to_string(),
            member_id: member_id.to_string(),
            invited_by_email: invited_by,
        },
    )?;
    crate::mail::send_invite(
        env,
        email,
        org_id,
        member_id,
        &org.name,
        &token,
        has_existing_user,
    )
    .await
}

// ---------------------------------------------------------------------------
// Member management (phase 3.2). Mail is not wired yet, so this follows vaultwarden's
// no-SMTP behavior: existing accounts are Accepted on invite, new emails get an
// `invitations` row plus a placeholder user that is completed on registration.
// ---------------------------------------------------------------------------

/// Number or string, as clients send membership types either way.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum NumberOrString {
    Number(i64),
    String(String),
}

impl NumberOrString {
    fn as_i32(&self) -> Option<i32> {
        match self {
            NumberOrString::Number(n) => i32::try_from(*n).ok(),
            NumberOrString::String(s) => s.parse().ok(),
        }
    }
}

/// Map a client-requested type to the stored one. Custom (4) is stored as Manager (3) until
/// custom-role permissions land (vaultwarden with custom roles disabled).
fn requested_type(raw: &NumberOrString) -> Result<i32, AppError> {
    match raw.as_i32() {
        Some(t @ (membership_type::OWNER | membership_type::ADMIN | membership_type::USER)) => {
            Ok(t)
        }
        Some(membership_type::MANAGER | membership_type::CUSTOM) => Ok(membership_type::MANAGER),
        _ => Err(AppError::BadRequest("Invalid type".to_string())),
    }
}

fn wants_access_all(new_type: i32, raw: &NumberOrString, permissions: &Value) -> bool {
    role_rank(new_type) >= role_rank(membership_type::ADMIN)
        || (new_type == membership_type::MANAGER
            && raw.as_i32() == Some(membership_type::CUSTOM)
            && [
                "editAnyCollection",
                "deleteAnyCollection",
                "createNewCollections",
            ]
            .iter()
            .all(|k| permissions.get(*k) == Some(&json!(true))))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberCollection {
    id: String,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteData {
    emails: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
    r#type: NumberOrString,
    collections: Option<Vec<MemberCollection>>,
    #[serde(default)]
    permissions: Value,
}

async fn find_user_id_by_email(
    db: &db::Db,
    email: &str,
) -> Result<Option<(String, bool)>, AppError> {
    #[derive(Deserialize)]
    struct Row {
        uuid: String,
        has_password: i32,
    }
    let row: Option<Row> = db
        .prepare(
            "SELECT uuid, (length(password_hash) > 0) AS has_password FROM users WHERE email = ?1",
        )
        .bind(&[email.into()])?
        .first(None)
        .await?;
    Ok(row.map(|r| (r.uuid, r.has_password != 0)))
}

fn member_collections_stmts(
    db: &db::Db,
    org_id: &str,
    user_id: &str,
    collections: &[MemberCollection],
) -> Result<Vec<D1PreparedStatement>, AppError> {
    collections
        .iter()
        .map(|c| {
            d1_query!(
                db,
                "INSERT OR REPLACE INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage)
                 SELECT ?1, uuid, ?2, ?3, ?4 FROM collections WHERE uuid = ?5 AND org_uuid = ?6",
                user_id,
                c.read_only as i32,
                c.hide_passwords as i32,
                c.manage as i32,
                c.id,
                org_id
            )
            .map_err(|_| AppError::Database)
        })
        .collect()
}

fn member_groups_stmts(
    db: &db::Db,
    org_id: &str,
    member_id: &str,
    groups: &[String],
) -> Result<Vec<D1PreparedStatement>, AppError> {
    groups
        .iter()
        .map(|g| {
            d1_query!(
                db,
                "INSERT OR IGNORE INTO groups_users (groups_uuid, users_organizations_uuid)
                 SELECT uuid, ?1 FROM groups WHERE uuid = ?2 AND organizations_uuid = ?3",
                member_id,
                g,
                org_id
            )
            .map_err(|_| AppError::Database)
        })
        .collect()
}

async fn check_collections_exist(
    db: &db::Db,
    org_id: &str,
    collections: &[MemberCollection],
) -> Result<(), AppError> {
    let ids = org_collection_ids(db, org_id).await?;
    if collections.iter().any(|c| !ids.contains(&c.id)) {
        return Err(AppError::BadRequest(
            "Collection not found in Organization".to_string(),
        ));
    }
    Ok(())
}

/// POST /api/organizations/{org_id}/users/invite
#[worker::send]
pub async fn invite_members(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<InviteData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let new_type = requested_type(&data.r#type)?;
    if new_type != membership_type::USER && me.atype != membership_type::OWNER {
        return Err(AppError::BadRequest(
            "Only Owners can invite Managers, Admins or Owners".to_string(),
        ));
    }
    let access_all = wants_access_all(new_type, &data.r#type, &data.permissions);
    let collections = data.collections.unwrap_or_default();
    check_collections_exist(&db, &org_id, &collections).await?;
    let now = now();
    let mail = crate::mail::mail_enabled(&env);

    for raw_email in &data.emails {
        let email = raw_email.trim().to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Err(AppError::BadRequest(format!("Invalid email: {email}")));
        }
        let mut stmts = Vec::new();
        let mut status = membership_status::INVITED;
        let user_id = match find_user_id_by_email(&db, &email).await? {
            Some((uid, has_password)) => {
                if find_membership(&db, &uid, &org_id).await?.is_some() {
                    return Err(AppError::BadRequest(format!(
                        "User already in organization: {email}"
                    )));
                }
                if has_password {
                    // Without mail the invite can't be accepted from a link: accept it now.
                    if !mail {
                        status = membership_status::ACCEPTED;
                    }
                } else {
                    stmts.push(
                        d1_query!(
                            &db,
                            "INSERT OR IGNORE INTO invitations (email) VALUES (?1)",
                            email
                        )
                        .map_err(|_| AppError::Database)?,
                    );
                }
                uid
            }
            None => {
                let uid = Uuid::new_v4().to_string();
                stmts.push(
                    d1_query!(
                        &db,
                        "INSERT OR IGNORE INTO invitations (email) VALUES (?1)",
                        email
                    )
                    .map_err(|_| AppError::Database)?,
                );
                // Placeholder account (vaultwarden `User::new(email, None)`), completed on register.
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
                uid
            }
        };
        let member_id = Uuid::new_v4().to_string();
        stmts.push(
            d1_query!(
                &db,
                "INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, akey, status, atype, invited_by_email)
                 VALUES (?1, ?2, ?3, ?4, '', ?5, ?6, ?7)",
                member_id,
                user_id,
                org_id,
                access_all as i32,
                status,
                new_type,
                claims.email
            )
            .map_err(|_| AppError::Database)?,
        );
        if !access_all {
            stmts.extend(member_collections_stmts(
                &db,
                &org_id,
                &user_id,
                &collections,
            )?);
        }
        stmts.extend(member_groups_stmts(&db, &org_id, &member_id, &data.groups)?);
        let created_user = stmts.len() > 1 && find_user_id_by_email(&db, &email).await?.is_none();
        db.batch(stmts).await?;
        if mail {
            if let Err(e) = send_member_invite(
                &env,
                &db,
                &org_id,
                &member_id,
                &user_id,
                &email,
                Some(claims.email.clone()),
            )
            .await
            {
                // vaultwarden: undo the invite (and the placeholder account) when the mail fails.
                let m = find_member_in_org(&db, &org_id, &member_id).await?;
                delete_membership(&db, &m).await?;
                if created_user {
                    db.batch(vec![
                        d1_query!(&db, "DELETE FROM invitations WHERE email = ?1", email)
                            .map_err(|_| AppError::Database)?,
                        d1_query!(
                            &db,
                            "DELETE FROM users WHERE uuid = ?1 AND length(password_hash) = 0",
                            user_id
                        )
                        .map_err(|_| AppError::Database)?,
                    ])
                    .await?;
                }
                return Err(e);
            }
        }
    }
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkMemberIds {
    ids: Vec<String>,
}

async fn find_member_in_org(
    db: &db::Db,
    org_id: &str,
    member_id: &str,
) -> Result<MembershipRow, AppError> {
    db.prepare(format!(
        "SELECT {MEMBERSHIP_COLS} FROM users_organizations WHERE uuid = ?1 AND org_uuid = ?2"
    ))
    .bind(&[member_id.into(), org_id.into()])?
    .first(None)
    .await?
    .ok_or_else(|| {
        AppError::BadRequest("The specified user isn't a member of the organization".to_string())
    })
}

async fn confirmed_owner_count(db: &db::Db, org_id: &str) -> Result<i64, AppError> {
    #[derive(Deserialize)]
    struct Cnt {
        n: i64,
    }
    let c: Option<Cnt> = db
        .prepare("SELECT COUNT(*) AS n FROM users_organizations WHERE org_uuid = ?1 AND atype = 0 AND status = 2")
        .bind(&[org_id.into()])?
        .first(None)
        .await?;
    Ok(c.map(|c| c.n).unwrap_or(0))
}

/// Re-sending invitations needs mail; without it, accounts that registered since the
/// invite are moved to Accepted (vaultwarden `_reinvite_member` without SMTP).
async fn reinvite_impl(
    env: &Env,
    db: &db::Db,
    org_id: &str,
    member_id: &str,
    invited_by: &str,
) -> Result<(), AppError> {
    let m = find_member_in_org(db, org_id, member_id).await?;
    if m.status != membership_status::INVITED {
        return Err(AppError::BadRequest(
            "The user is already accepted or confirmed to the organization".to_string(),
        ));
    }
    if crate::mail::mail_enabled(env) {
        #[derive(Deserialize)]
        struct Email {
            email: String,
        }
        let email = db
            .prepare("SELECT email FROM users WHERE uuid = ?1")
            .bind(&[m.user_uuid.clone().into()])?
            .first::<Email>(None)
            .await?
            .ok_or_else(|| AppError::BadRequest("User not found".to_string()))?
            .email;
        return send_member_invite(
            env,
            db,
            org_id,
            &m.uuid,
            &m.user_uuid,
            &email,
            Some(invited_by.to_string()),
        )
        .await;
    }
    #[derive(Deserialize)]
    struct Row {
        has_password: i32,
    }
    let u: Option<Row> = db
        .prepare("SELECT (length(password_hash) > 0) AS has_password FROM users WHERE uuid = ?1")
        .bind(&[m.user_uuid.clone().into()])?
        .first(None)
        .await?;
    if u.map(|u| u.has_password != 0).unwrap_or(false) {
        d1_query!(
            db,
            "UPDATE users_organizations SET status = 1 WHERE uuid = ?1",
            m.uuid
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    }
    Ok(())
}

fn bulk_result(results: Vec<(String, Result<(), AppError>)>) -> Json<Value> {
    let data: Vec<Value> = results
        .into_iter()
        .map(|(id, r)| {
            json!({
                "object": "OrganizationBulkConfirmResponseModel",
                "id": id,
                "error": r
                    .err()
                    .map(|e| {
                        log::warn!("bulk member operation on {id} failed: {e}");
                        e.client_message()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect();
    Json(json!({"data": data, "object": "list", "continuationToken": null}))
}

/// POST /api/organizations/{org_id}/users/{member_id}/reinvite
#[worker::send]
pub async fn reinvite_member(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    reinvite_impl(&env, &db, &org_id, &member_id, &claims.email).await?;
    Ok(Json(json!({})))
}

/// POST /api/organizations/{org_id}/users/reinvite
#[worker::send]
pub async fn bulk_reinvite_members(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkMemberIds>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let mut out = Vec::new();
    for id in data.ids {
        let r = reinvite_impl(&env, &db, &org_id, &id, &claims.email).await;
        out.push((id, r));
    }
    Ok(bulk_result(out))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptData {
    token: String,
    reset_password_key: Option<String>,
}

/// POST /api/organizations/{org_id}/users/{member_id}/accept (token from the invite email)
#[worker::send]
pub async fn accept_invite(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(data): Json<AcceptData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let invite = decode_invite(&env, &data.token)?;
    if !invite.email.eq_ignore_ascii_case(&claims.email) {
        return Err(AppError::BadRequest(
            "Invitation was issued to a different account".to_string(),
        ));
    }
    if invite.org_id != org_id || invite.member_id != member_id {
        return Err(AppError::BadRequest(
            "Error accepting the invitation".to_string(),
        ));
    }
    let m = find_member_in_org(&db, &org_id, &member_id)
        .await
        .map_err(|_| AppError::BadRequest("Error accepting the invitation".to_string()))?;
    if m.user_uuid != claims.sub {
        return Err(AppError::BadRequest(
            "Error accepting the invitation".to_string(),
        ));
    }
    if m.status != membership_status::INVITED {
        return Err(AppError::BadRequest(
            "User already accepted the invitation".to_string(),
        ));
    }
    let auto_enroll =
        crate::handlers::org_policies::reset_password_auto_enroll(&env, &db, &org_id).await?;
    let reset_key = data.reset_password_key.filter(|k| !k.is_empty());
    if auto_enroll && reset_key.is_none() {
        return Err(AppError::BadRequest(
            "Reset password key is required, but not provided.".to_string(),
        ));
    }
    crate::handlers::org_policies::check_user_allowed(
        &db,
        &m,
        m.atype,
        membership_status::ACCEPTED,
        "join",
    )
    .await?;
    let reset_key = if auto_enroll { reset_key } else { None };
    db.batch(vec![
        d1_query!(
            &db,
            "UPDATE users_organizations SET status = 1, reset_password_key = ?1,
                invited_by_email = COALESCE(invited_by_email, ?2) WHERE uuid = ?3",
            reset_key,
            invite.invited_by_email.clone(),
            m.uuid
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            &db,
            "DELETE FROM invitations WHERE email = ?1",
            claims.email.to_lowercase()
        )
        .map_err(|_| AppError::Database)?,
    ])
    .await?;
    if let (Some(inviter), true) = (invite.invited_by_email, crate::mail::mail_enabled(&env)) {
        let org_name = find_org(&db, &org_id)
            .await?
            .map(|o| o.name)
            .unwrap_or_default();
        if let Err(e) =
            crate::mail::send_invite_accepted(&env, &inviter, &claims.email, &org_name).await
        {
            log::warn!("invite-accepted email failed: {e}");
        }
    }
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmData {
    id: Option<String>,
    key: Option<String>,
}

async fn confirm_impl(
    env: &Env,
    db: &db::Db,
    me: &MembershipRow,
    member_id: &str,
    key: &str,
) -> Result<(), AppError> {
    if key.is_empty() || member_id.is_empty() {
        return Err(AppError::BadRequest(
            "Key or UserId is not set, unable to process request".to_string(),
        ));
    }
    let m = find_member_in_org(db, &me.org_uuid, member_id).await?;
    if m.atype != membership_type::USER && me.atype != membership_type::OWNER {
        return Err(AppError::BadRequest(
            "Only Owners can confirm Managers, Admins or Owners".to_string(),
        ));
    }
    if m.status != membership_status::ACCEPTED {
        return Err(AppError::BadRequest("User in invalid state".to_string()));
    }
    crate::handlers::org_policies::check_user_allowed(
        db,
        &m,
        m.atype,
        membership_status::CONFIRMED,
        "confirm",
    )
    .await?;
    let now = now();
    db.batch(vec![
        d1_query!(
            db,
            "UPDATE users_organizations SET status = 2, akey = ?1 WHERE uuid = ?2",
            key,
            m.uuid
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            db,
            "UPDATE users SET updated_at = ?1 WHERE uuid = ?2",
            now,
            m.user_uuid
        )
        .map_err(|_| AppError::Database)?,
    ])
    .await?;
    if crate::mail::mail_enabled(env) {
        #[derive(Deserialize)]
        struct Email {
            email: String,
        }
        let email = db
            .prepare("SELECT email FROM users WHERE uuid = ?1")
            .bind(&[m.user_uuid.clone().into()])?
            .first::<Email>(None)
            .await?;
        let org_name = find_org(db, &me.org_uuid)
            .await?
            .map(|o| o.name)
            .unwrap_or_default();
        if let Some(e) = email {
            if let Err(err) = crate::mail::send_invite_confirmed(env, &e.email, &org_name).await {
                log::warn!("invite-confirmed email failed: {err}");
            }
        }
    }
    crate::notifications::publish_user_update(
        env.clone(),
        m.user_uuid,
        crate::notifications::UpdateType::SyncOrgKeys,
        now,
        None,
    );
    Ok(())
}

/// POST /api/organizations/{org_id}/users/{member_id}/confirm
#[worker::send]
pub async fn confirm_member(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(data): Json<ConfirmData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    confirm_impl(
        env.as_ref(),
        &db,
        &me,
        &member_id,
        data.key.as_deref().unwrap_or(""),
    )
    .await?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
pub struct BulkConfirmData {
    keys: Option<Vec<ConfirmData>>,
}

/// POST /api/organizations/{org_id}/users/confirm
#[worker::send]
pub async fn bulk_confirm_members(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkConfirmData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let mut out = Vec::new();
    for c in data.keys.unwrap_or_default() {
        let id = c.id.unwrap_or_default();
        let r = confirm_impl(env.as_ref(), &db, &me, &id, c.key.as_deref().unwrap_or("")).await;
        out.push((id, r));
    }
    Ok(bulk_result(out))
}

/// GET /api/organizations/{org_id}/users/mini-details
#[worker::send]
pub async fn get_members_mini(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::MANAGER).await?;
    #[derive(Deserialize)]
    struct Row {
        uuid: String,
        user_uuid: String,
        atype: i32,
        status: i32,
        name: Option<String>,
        email: String,
    }
    let rows: Vec<Row> = db
        .prepare(
            "SELECT uo.uuid, uo.user_uuid, uo.atype, uo.status, NULLIF(u.name, '') AS name, u.email
             FROM users_organizations uo JOIN users u ON u.uuid = uo.user_uuid WHERE uo.org_uuid = ?1",
        )
        .bind(&[org_id.into()])?
        .all()
        .await?
        .results()?;
    let data: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.uuid,
                "userId": r.user_uuid,
                "type": type_for_client(r.atype),
                "status": client_status(r.status),
                "name": r.name,
                "email": r.email,
                "object": "organizationUserUserMiniDetails",
            })
        })
        .collect();
    Ok(Json(
        json!({"data": data, "object": "list", "continuationToken": null}),
    ))
}

/// GET /api/organizations/{org_id}/users/{member_id}
#[worker::send]
pub async fn get_member(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
    Query(q): Query<OrgUsersQuery>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let include_groups = q.include_groups;
    let mut list = members_json(
        &db,
        &org_id,
        Some(&member_id),
        q.include_collections || include_groups,
        include_groups,
    )
    .await?;
    let mut m = list.pop().ok_or_else(|| {
        AppError::BadRequest("The specified user isn't a member of the organization".to_string())
    })?;
    m["object"] = json!("organizationUserDetails");
    Ok(Json(m))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditMemberData {
    r#type: NumberOrString,
    collections: Option<Vec<MemberCollection>>,
    groups: Option<Vec<String>>,
    #[serde(default)]
    permissions: Value,
}

/// PUT|POST /api/organizations/{org_id}/users/{member_id}
#[worker::send]
pub async fn edit_member(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(data): Json<EditMemberData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let new_type = requested_type(&data.r#type)?;
    let m = find_member_in_org(&db, &org_id, &member_id).await?;
    let access_all = wants_access_all(new_type, &data.r#type, &data.permissions);
    let admin_rank = role_rank(membership_type::ADMIN);
    if new_type != m.atype
        && (role_rank(m.atype) >= admin_rank || role_rank(new_type) >= admin_rank)
        && me.atype != membership_type::OWNER
    {
        return Err(AppError::BadRequest(
            "Only Owners can grant and remove Admin or Owner privileges".to_string(),
        ));
    }
    if m.atype == membership_type::OWNER && me.atype != membership_type::OWNER {
        return Err(AppError::BadRequest(
            "Only Owners can edit Owner users".to_string(),
        ));
    }
    if m.atype == membership_type::OWNER
        && new_type != membership_type::OWNER
        && m.status == membership_status::CONFIRMED
        && confirmed_owner_count(&db, &org_id).await? <= 1
    {
        return Err(AppError::BadRequest(
            "Can't delete the last owner".to_string(),
        ));
    }
    crate::handlers::org_policies::check_user_allowed(&db, &m, new_type, m.status, "modify")
        .await?;
    let collections = data.collections.unwrap_or_default();
    check_collections_exist(&db, &org_id, &collections).await?;
    let mut stmts = vec![
        d1_query!(
            &db,
            "UPDATE users_organizations SET atype = ?1, access_all = ?2 WHERE uuid = ?3",
            new_type,
            access_all as i32,
            m.uuid
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            &db,
            "DELETE FROM users_collections WHERE user_uuid = ?1 AND collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?2)",
            m.user_uuid,
            org_id
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(&db, "DELETE FROM groups_users WHERE users_organizations_uuid = ?1", m.uuid)
            .map_err(|_| AppError::Database)?,
    ];
    if !access_all {
        stmts.extend(member_collections_stmts(
            &db,
            &org_id,
            &m.user_uuid,
            &collections,
        )?);
    }
    stmts.extend(member_groups_stmts(
        &db,
        &org_id,
        &m.uuid,
        &data.groups.unwrap_or_default(),
    )?);
    stmts.push(
        d1_query!(
            &db,
            "UPDATE users SET updated_at = ?1 WHERE uuid = ?2",
            now(),
            m.user_uuid
        )
        .map_err(|_| AppError::Database)?,
    );
    db.batch(stmts).await?;
    Ok(Json(json!({})))
}

async fn delete_member_impl(
    env: &Env,
    db: &db::Db,
    me: &MembershipRow,
    member_id: &str,
) -> Result<(), AppError> {
    let m = find_member_in_org(db, &me.org_uuid, member_id)
        .await
        .map_err(|_| {
            AppError::BadRequest("User to delete isn't member of the organization".to_string())
        })?;
    if m.atype != membership_type::USER && me.atype != membership_type::OWNER {
        return Err(AppError::BadRequest(
            "Only Owners can delete Admins or Owners".to_string(),
        ));
    }
    if m.atype == membership_type::OWNER
        && m.status == membership_status::CONFIRMED
        && confirmed_owner_count(db, &me.org_uuid).await? <= 1
    {
        return Err(AppError::BadRequest(
            "Can't delete the last owner".to_string(),
        ));
    }
    delete_membership(db, &m).await?;
    // Drop a pending invitation once no other org still waits for this email.
    d1_query!(
        db,
        "DELETE FROM invitations WHERE email = (SELECT email FROM users WHERE uuid = ?1)
           AND NOT EXISTS (SELECT 1 FROM users_organizations WHERE user_uuid = ?1 AND status = 0)",
        m.user_uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    let now = now();
    d1_query!(
        db,
        "UPDATE users SET updated_at = ?1 WHERE uuid = ?2",
        now,
        m.user_uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    crate::notifications::publish_user_update(
        env.clone(),
        m.user_uuid,
        crate::notifications::UpdateType::SyncOrgKeys,
        now,
        None,
    );
    Ok(())
}

/// DELETE /api/organizations/{org_id}/users/{member_id} (+ POST .../delete)
#[worker::send]
pub async fn delete_member(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    delete_member_impl(env.as_ref(), &db, &me, &member_id).await?;
    Ok(Json(json!({})))
}

/// DELETE /api/organizations/{org_id}/users (bulk)
#[worker::send]
pub async fn bulk_delete_members(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkMemberIds>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let mut out = Vec::new();
    for id in data.ids {
        let r = delete_member_impl(env.as_ref(), &db, &me, &id).await;
        out.push((id, r));
    }
    Ok(bulk_result(out))
}

/// POST /api/organizations/{org_id}/users/public-keys
#[worker::send]
pub async fn bulk_public_keys(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkMemberIds>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    #[derive(Deserialize)]
    struct Row {
        uuid: String,
        user_uuid: String,
        public_key: Option<String>,
    }
    let ids = serde_json::to_string(&data.ids).map_err(|_| AppError::Internal)?;
    let rows: Vec<Row> = db
        .prepare(
            "SELECT uo.uuid, uo.user_uuid, u.public_key FROM users_organizations uo
             JOIN users u ON u.uuid = uo.user_uuid
             WHERE uo.org_uuid = ?1 AND uo.uuid IN (SELECT value FROM json_each(?2))",
        )
        .bind(&[org_id.into(), ids.into()])?
        .all()
        .await?
        .results()?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "object": "organizationUserPublicKeyResponseModel",
                "id": r.uuid,
                "userId": r.user_uuid,
                "key": r.public_key,
            })
        })
        .collect();
    Ok(Json(
        json!({"data": out, "object": "list", "continuationToken": null}),
    ))
}

async fn revoke_impl(
    db: &db::Db,
    me: &MembershipRow,
    member_id: &str,
    revoke: bool,
) -> Result<(), AppError> {
    let m = find_member_in_org(db, &me.org_uuid, member_id).await?;
    if m.uuid == me.uuid {
        return Err(AppError::BadRequest(if revoke {
            "You cannot revoke yourself".to_string()
        } else {
            "You cannot restore yourself".to_string()
        }));
    }
    if m.atype == membership_type::OWNER && me.atype != membership_type::OWNER {
        return Err(AppError::BadRequest(
            "Only owners can revoke and restore other owners".to_string(),
        ));
    }
    let new_status = if revoke {
        if m.status <= membership_status::REVOKED {
            return Err(AppError::BadRequest("Already revoked".to_string()));
        }
        if m.atype == membership_type::OWNER
            && m.status == membership_status::CONFIRMED
            && confirmed_owner_count(db, &me.org_uuid).await? <= 1
        {
            return Err(AppError::BadRequest(
                "Organization must have at least one confirmed owner".to_string(),
            ));
        }
        m.status - ACTIVATE_REVOKE_DIFF
    } else {
        if m.status >= membership_status::INVITED {
            return Err(AppError::BadRequest("Already active".to_string()));
        }
        let restored = m.status + ACTIVATE_REVOKE_DIFF;
        crate::handlers::org_policies::check_user_allowed(db, &m, m.atype, restored, "restore")
            .await?;
        restored
    };
    db.batch(vec![
        d1_query!(
            db,
            "UPDATE users_organizations SET status = ?1 WHERE uuid = ?2",
            new_status,
            m.uuid
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            db,
            "UPDATE users SET updated_at = ?1 WHERE uuid = ?2",
            now(),
            m.user_uuid
        )
        .map_err(|_| AppError::Database)?,
    ])
    .await?;
    Ok(())
}

/// PUT /api/organizations/{org_id}/users/{member_id}/revoke
#[worker::send]
pub async fn revoke_member(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    revoke_impl(&db, &me, &member_id, true).await?;
    Ok(Json(json!({})))
}

/// PUT /api/organizations/{org_id}/users/{member_id}/restore (+ /restore/vnext)
#[worker::send]
pub async fn restore_member(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    revoke_impl(&db, &me, &member_id, false).await?;
    Ok(Json(json!({})))
}

/// PUT /api/organizations/{org_id}/users/revoke
#[worker::send]
pub async fn bulk_revoke_members(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkMemberIds>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let mut out = Vec::new();
    for id in data.ids {
        let r = revoke_impl(&db, &me, &id, true).await;
        out.push((id, r));
    }
    Ok(bulk_result(out))
}

/// PUT /api/organizations/{org_id}/users/restore
#[worker::send]
pub async fn bulk_restore_members(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkMemberIds>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let me = require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let mut out = Vec::new();
    for id in data.ids {
        let r = revoke_impl(&db, &me, &id, false).await;
        out.push((id, r));
    }
    Ok(bulk_result(out))
}

/// Placeholder account (created by an invite, no master password yet) for `email`, and whether
/// an invitation is still pending for it. Registration completes the placeholder in place and,
/// when invited, bypasses ALLOWED_EMAILS (vaultwarden `_register` without SMTP).
pub async fn invited_placeholder(
    db: &db::Db,
    email: &str,
) -> Result<Option<(String, bool)>, AppError> {
    #[derive(Deserialize)]
    struct Row {
        uuid: String,
        invited: i32,
    }
    let row: Option<Row> = db
        .prepare(
            "SELECT u.uuid, EXISTS (SELECT 1 FROM invitations i WHERE i.email = u.email) AS invited
             FROM users u WHERE u.email = ?1 AND length(u.password_hash) = 0",
        )
        .bind(&[email.into()])?
        .first(None)
        .await?;
    Ok(row.map(|r| (r.uuid, r.invited != 0)))
}

/// Statements run after an invited user registered.
pub fn accept_invitations_stmts(
    db: &db::Db,
    user_id: &str,
    email: &str,
) -> Result<Vec<D1PreparedStatement>, AppError> {
    Ok(vec![
        d1_query!(
            db,
            "UPDATE users_organizations SET status = 1 WHERE user_uuid = ?1 AND status = 0",
            user_id
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(db, "DELETE FROM invitations WHERE email = ?1", email)
            .map_err(|_| AppError::Database)?,
    ])
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkAccessData {
    collection_ids: Vec<String>,
    #[serde(default)]
    groups: Vec<AccessSelection>,
    #[serde(default)]
    users: Vec<AccessSelection>,
}

/// POST /api/organizations/{org_id}/collections/bulk-access
#[worker::send]
pub async fn bulk_access_collections(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkAccessData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = require_role(&db, &claims.sub, &org_id, membership_type::MANAGER).await?;
    #[derive(Deserialize)]
    struct Row {
        uuid: String,
    }
    let group_ids: HashSet<String> = db
        .prepare("SELECT uuid FROM groups WHERE organizations_uuid = ?1")
        .bind(&[org_id.clone().into()])?
        .all()
        .await?
        .results::<Row>()?
        .into_iter()
        .map(|r| r.uuid)
        .collect();
    if let Some(g) = data.groups.iter().find(|g| !group_ids.contains(&g.id)) {
        return Err(AppError::BadRequest(format!(
            "Invalid group: Group {} does not belong to organization {org_id}!",
            g.id
        )));
    }
    let access = CollectionData {
        name: String::new(),
        external_id: None,
        groups: data.groups.clone(),
        users: data.users.clone(),
    };
    let mut stmts = Vec::new();
    for col_id in &data.collection_ids {
        find_collection(&db, &org_id, col_id).await?;
        if !can_manage_collection(&db, &claims.sub, &m, col_id).await? {
            return Err(AppError::NotFound("Collection not found".to_string()));
        }
        stmts.extend(collection_access_statements(&db, &org_id, col_id, &access)?);
    }
    if !stmts.is_empty() {
        db.batch(stmts).await?;
    }
    touch_org_members(&db, &org_id).await?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkCollectionsData {
    organization_id: String,
    cipher_ids: Vec<String>,
    collection_ids: Vec<String>,
    #[serde(default)]
    remove_collections: bool,
}

/// POST /api/ciphers/bulk-collections: add/remove many org ciphers to/from collections.
#[worker::send]
pub async fn bulk_cipher_collections(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(data): Json<BulkCollectionsData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let org_id = &data.organization_id;
    find_membership(&db, &claims.sub, org_id)
        .await?
        .filter(|m| m.status == membership_status::CONFIRMED)
        .ok_or_else(|| {
            AppError::BadRequest(
                "You need to be a Member of the Organization to call this endpoint".to_string(),
            )
        })?;
    let writable = writable_collection_ids(&db, &claims.sub, org_id).await?;
    if data.collection_ids.iter().any(|c| !writable.contains(c)) {
        return Err(AppError::NotFound("Resource not found".to_string()));
    }
    let cipher_ids = serde_json::to_string(&data.cipher_ids).map_err(|_| AppError::Internal)?;
    let col_ids = serde_json::to_string(&data.collection_ids).map_err(|_| AppError::Internal)?;
    // Ciphers the user can write in this org, resolved before any link changes.
    #[derive(Deserialize)]
    struct Ids {
        ids: String,
    }
    let ids = db
        .prepare(format!(
            "{}SELECT COALESCE(json_group_array(a.cipher_uuid), '[]') AS ids FROM access a
             JOIN ciphers c ON c.uuid = a.cipher_uuid
             WHERE a.read_only = 0 AND c.organization_uuid = ?2
               AND a.cipher_uuid IN (SELECT value FROM json_each(?3))",
            with_access("?1")
        ))
        .bind(&[
            claims.sub.clone().into(),
            org_id.clone().into(),
            cipher_ids.into(),
        ])?
        .first::<Ids>(None)
        .await?
        .map(|r| r.ids)
        .unwrap_or_else(|| "[]".to_string());
    let sql = if data.remove_collections {
        "DELETE FROM ciphers_collections WHERE cipher_uuid IN (SELECT value FROM json_each(?1))
           AND collection_uuid IN (SELECT value FROM json_each(?2))"
    } else {
        "INSERT OR IGNORE INTO ciphers_collections (cipher_uuid, collection_uuid)
         SELECT c.value, k.value FROM json_each(?1) c, json_each(?2) k"
    };
    let now = now();
    db.batch(vec![
        db.prepare(sql)
            .bind(&[ids.clone().into(), col_ids.into()])?,
        d1_query!(
            &db,
            "UPDATE ciphers SET updated_at = ?1 WHERE uuid IN (SELECT value FROM json_each(?2))",
            now,
            ids
        )
        .map_err(|_| AppError::Database)?,
    ])
    .await?;
    touch_org_members(&db, org_id).await?;
    Ok(Json(json!({})))
}

/// POST /api/organizations/domain/sso/verified (no SSO here: nothing to prefill)
pub async fn sso_verified_domains() -> Json<Value> {
    Json(json!({"object": "list", "data": [], "continuationToken": null}))
}

/// GET /api/organizations/{org_id}/collections as plain JSON (for export).
pub async fn org_collections_json(db: &db::Db, org_id: &str) -> Result<Vec<Value>, AppError> {
    let rows: Vec<CollectionRow> = db
        .prepare("SELECT uuid, org_uuid, name, external_id FROM collections WHERE org_uuid = ?1")
        .bind(&[org_id.into()])?
        .all()
        .await?
        .results()?;
    Ok(rows
        .iter()
        .map(|c| collection_json(&c.uuid, &c.org_uuid, &c.name, &c.external_id))
        .collect())
}
