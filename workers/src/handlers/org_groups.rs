//! Organization groups (phase 3.3), ported from vaultwarden `organizations.rs` (groups routes)
//! and `db/models/group.rs`. Group-derived cipher/collection access lives in `org_access`.

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::{D1PreparedStatement, Env};

use crate::auth::Claims;
use crate::d1_query;
use crate::db;
use crate::error::AppError;
use crate::handlers::organizations::{
    has_full_access, org_collection_ids, require_role, touch_org_members,
};
use crate::models::org_access::{membership_type, with_access};

#[derive(Debug, Deserialize)]
struct GroupRow {
    uuid: String,
    organizations_uuid: String,
    name: String,
    external_id: Option<String>,
}

fn group_json(g: &GroupRow) -> Value {
    json!({
        "id": g.uuid,
        "organizationId": g.organizations_uuid,
        "name": g.name,
        "externalId": g.external_id,
        "object": "group",
    })
}

async fn find_group(db: &db::Db, org_id: &str, group_id: &str) -> Result<GroupRow, AppError> {
    db.prepare(
        "SELECT uuid, organizations_uuid, name, external_id FROM groups WHERE uuid = ?1 AND organizations_uuid = ?2",
    )
    .bind(&[group_id.into(), org_id.into()])?
    .first(None)
    .await?
    .ok_or_else(|| AppError::BadRequest("Group not found".to_string()))
}

#[derive(Deserialize)]
struct GroupColRow {
    groups_uuid: String,
    collections_uuid: String,
    read_only: i32,
    hide_passwords: i32,
    manage: i32,
}

async fn group_collections(db: &db::Db, org_id: &str) -> Result<Vec<GroupColRow>, AppError> {
    Ok(db
        .prepare(
            "SELECT cg.groups_uuid, cg.collections_uuid, cg.read_only, cg.hide_passwords, cg.manage
             FROM collections_groups cg JOIN groups g ON g.uuid = cg.groups_uuid
             WHERE g.organizations_uuid = ?1",
        )
        .bind(&[org_id.into()])?
        .all()
        .await?
        .results()?)
}

fn group_details_json(g: &GroupRow, cols: &[GroupColRow]) -> Value {
    let collections: Vec<Value> = cols
        .iter()
        .filter(|c| c.groups_uuid == g.uuid)
        .map(|c| {
            json!({
                "id": c.collections_uuid,
                "readOnly": c.read_only != 0,
                "hidePasswords": c.hide_passwords != 0,
                "manage": c.manage != 0,
            })
        })
        .collect();
    let mut j = group_json(g);
    j["collections"] = json!(collections);
    j["object"] = json!("groupDetails");
    j
}

/// GET /api/organizations/{org_id}/groups and .../groups/details
async fn groups_impl(
    claims: Claims,
    env: Arc<Env>,
    org_id: String,
    details: bool,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = require_role(&db, &claims.sub, &org_id, membership_type::MANAGER).await?;
    let mut allowed = has_full_access(&m) || group_full_access(&db, &m.uuid).await?;
    if !allowed && !details {
        // Managers that can manage at least one collection may list groups (to assign access).
        let row: Option<Value> = db
            .prepare(format!(
                "{}SELECT 1 AS ok FROM ucol u JOIN collections co ON co.uuid = u.collection_uuid
                 WHERE co.org_uuid = ?2 AND u.manage = 1 LIMIT 1",
                with_access("?1")
            ))
            .bind(&[claims.sub.clone().into(), org_id.clone().into()])?
            .first(None)
            .await?;
        allowed = row.is_some();
    }
    if !allowed {
        return Err(AppError::NotFound("Resource not found.".to_string()));
    }
    let groups: Vec<GroupRow> = db
        .prepare("SELECT uuid, organizations_uuid, name, external_id FROM groups WHERE organizations_uuid = ?1")
        .bind(&[org_id.clone().into()])?
        .all()
        .await?
        .results()?;
    let data: Vec<Value> = if details {
        let cols = group_collections(&db, &org_id).await?;
        groups
            .iter()
            .map(|g| group_details_json(g, &cols))
            .collect()
    } else {
        groups.iter().map(group_json).collect()
    };
    Ok(Json(
        json!({"data": data, "object": "list", "continuationToken": null}),
    ))
}

async fn group_full_access(db: &db::Db, member_id: &str) -> Result<bool, AppError> {
    let row: Option<Value> = db
        .prepare(
            "SELECT 1 AS ok FROM groups_users gu JOIN groups g ON g.uuid = gu.groups_uuid
             WHERE gu.users_organizations_uuid = ?1 AND g.access_all = 1 LIMIT 1",
        )
        .bind(&[member_id.into()])?
        .first(None)
        .await?;
    Ok(row.is_some())
}

#[worker::send]
pub async fn get_groups(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    groups_impl(claims, env, org_id, false).await
}

#[worker::send]
pub async fn get_groups_details(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    groups_impl(claims, env, org_id, true).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupCollection {
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
pub struct GroupRequest {
    name: String,
    #[serde(default)]
    access_all: bool,
    external_id: Option<String>,
    #[serde(default)]
    collections: Vec<GroupCollection>,
    #[serde(default)]
    users: Vec<String>,
}

async fn validate_group_request(
    db: &db::Db,
    org_id: &str,
    data: &GroupRequest,
) -> Result<(), AppError> {
    let cols = org_collection_ids(db, org_id).await?;
    if let Some(c) = data.collections.iter().find(|c| !cols.contains(&c.id)) {
        return Err(AppError::BadRequest(format!(
            "Invalid collection: Collection {} does not belong to organization {org_id}!",
            c.id
        )));
    }
    #[derive(Deserialize)]
    struct Row {
        uuid: String,
    }
    let members: std::collections::HashSet<String> = db
        .prepare("SELECT uuid FROM users_organizations WHERE org_uuid = ?1")
        .bind(&[org_id.into()])?
        .all()
        .await?
        .results::<Row>()?
        .into_iter()
        .map(|r| r.uuid)
        .collect();
    if let Some(m) = data.users.iter().find(|m| !members.contains(*m)) {
        return Err(AppError::BadRequest(format!(
            "Invalid member: Member {m} does not belong to organization {org_id}!"
        )));
    }
    Ok(())
}

/// Statements (re)writing a group's collection and member links.
fn group_links_stmts(
    db: &db::Db,
    group_id: &str,
    data: &GroupRequest,
) -> Result<Vec<D1PreparedStatement>, AppError> {
    let mut out = vec![
        d1_query!(
            db,
            "DELETE FROM collections_groups WHERE groups_uuid = ?1",
            group_id
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            db,
            "DELETE FROM groups_users WHERE groups_uuid = ?1",
            group_id
        )
        .map_err(|_| AppError::Database)?,
    ];
    for c in &data.collections {
        out.push(
            d1_query!(
                db,
                "INSERT INTO collections_groups (collections_uuid, groups_uuid, read_only, hide_passwords, manage) VALUES (?1, ?2, ?3, ?4, ?5)",
                c.id,
                group_id,
                c.read_only as i32,
                c.hide_passwords as i32,
                c.manage as i32
            )
            .map_err(|_| AppError::Database)?,
        );
    }
    for m in &data.users {
        out.push(
            d1_query!(
                db,
                "INSERT OR IGNORE INTO groups_users (groups_uuid, users_organizations_uuid) VALUES (?1, ?2)",
                group_id,
                m
            )
            .map_err(|_| AppError::Database)?,
        );
    }
    Ok(out)
}

/// POST /api/organizations/{org_id}/groups
#[worker::send]
pub async fn post_group(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<GroupRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    validate_group_request(&db, &org_id, &data).await?;
    let group_id = Uuid::new_v4().to_string();
    let now = db::now_string();
    let external_id = data.external_id.clone().filter(|e| !e.trim().is_empty());
    let mut stmts = vec![d1_query!(
        &db,
        "INSERT INTO groups (uuid, organizations_uuid, name, access_all, external_id, creation_date, revision_date) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        group_id,
        org_id,
        data.name,
        data.access_all as i32,
        external_id,
        now
    )
    .map_err(|_| AppError::Database)?];
    stmts.extend(group_links_stmts(&db, &group_id, &data)?);
    db.batch(stmts).await?;
    touch_org_members(&db, &org_id).await?;
    Ok(Json(group_json(
        &find_group(&db, &org_id, &group_id).await?,
    )))
}

/// PUT|POST /api/organizations/{org_id}/groups/{group_id}
#[worker::send]
pub async fn put_group(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, group_id)): Path<(String, String)>,
    Json(data): Json<GroupRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    find_group(&db, &org_id, &group_id).await?;
    validate_group_request(&db, &org_id, &data).await?;
    let mut stmts = vec![d1_query!(
        &db,
        "UPDATE groups SET name = ?1, access_all = ?2, revision_date = ?3 WHERE uuid = ?4",
        data.name,
        data.access_all as i32,
        db::now_string(),
        group_id
    )
    .map_err(|_| AppError::Database)?];
    stmts.extend(group_links_stmts(&db, &group_id, &data)?);
    db.batch(stmts).await?;
    touch_org_members(&db, &org_id).await?;
    Ok(Json(group_json(
        &find_group(&db, &org_id, &group_id).await?,
    )))
}

/// GET /api/organizations/{org_id}/groups/{group_id}
#[worker::send]
pub async fn get_group(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, group_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    Ok(Json(group_json(
        &find_group(&db, &org_id, &group_id).await?,
    )))
}

/// GET /api/organizations/{org_id}/groups/{group_id}/details
#[worker::send]
pub async fn get_group_details(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, group_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let g = find_group(&db, &org_id, &group_id).await?;
    let cols = group_collections(&db, &org_id).await?;
    Ok(Json(group_details_json(&g, &cols)))
}

/// GET /api/organizations/{org_id}/groups/{group_id}/users -> membership ids
#[worker::send]
pub async fn get_group_members(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, group_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    find_group(&db, &org_id, &group_id)
        .await
        .map_err(|_| AppError::BadRequest("Group could not be found!".to_string()))?;
    #[derive(Deserialize)]
    struct Row {
        users_organizations_uuid: String,
    }
    let ids: Vec<String> = db
        .prepare("SELECT users_organizations_uuid FROM groups_users WHERE groups_uuid = ?1")
        .bind(&[group_id.into()])?
        .all()
        .await?
        .results::<Row>()?
        .into_iter()
        .map(|r| r.users_organizations_uuid)
        .collect();
    Ok(Json(json!(ids)))
}

fn delete_group_stmts(db: &db::Db, group_id: &str) -> Result<Vec<D1PreparedStatement>, AppError> {
    let binds = [group_id.into()];
    let mut out = Vec::new();
    for sql in [
        "DELETE FROM collections_groups WHERE groups_uuid = ?1",
        "DELETE FROM groups_users WHERE groups_uuid = ?1",
        "DELETE FROM groups WHERE uuid = ?1",
    ] {
        out.push(db.prepare(sql).bind(&binds)?);
    }
    Ok(out)
}

/// DELETE /api/organizations/{org_id}/groups/{group_id} (+ POST .../delete)
#[worker::send]
pub async fn delete_group(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path((org_id, group_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    find_group(&db, &org_id, &group_id).await?;
    touch_org_members(&db, &org_id).await?;
    db.batch(delete_group_stmts(&db, &group_id)?).await?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
pub struct BulkGroupIds {
    ids: Vec<String>,
}

/// DELETE /api/organizations/{org_id}/groups (bulk)
#[worker::send]
pub async fn bulk_delete_groups(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkGroupIds>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_role(&db, &claims.sub, &org_id, membership_type::ADMIN).await?;
    let mut stmts = Vec::new();
    for id in &data.ids {
        find_group(&db, &org_id, id).await?;
        stmts.extend(delete_group_stmts(&db, id)?);
    }
    touch_org_members(&db, &org_id).await?;
    if !stmts.is_empty() {
        db.batch(stmts).await?;
    }
    Ok(Json(json!({})))
}
