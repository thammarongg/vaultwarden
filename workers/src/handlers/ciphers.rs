use crate::d1_query;
use axum::extract::Path;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::{extract::State, Extension, Json};
use chrono::{DateTime, Utc};
use log; // Used for warning logs on parse failures
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
use worker::{wasm_bindgen::JsValue, Env};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::handlers::attachments;
use crate::models::cipher::{
    Cipher, CipherDBModel, CipherData, CipherRequestData, CreateCipherRequest, PartialCipherData,
};
use crate::models::user::{PasswordOrOtpData, User};
use crate::notifications::{self, UpdateType};
use crate::BaseUrl;

/// A wrapper for raw JSON strings that implements IntoResponse.
/// Use this to return pre-built JSON without re-parsing/re-serializing.
pub struct RawJson(pub String);

impl IntoResponse for RawJson {
    fn into_response(self) -> Response {
        ([(header::CONTENT_TYPE, "application/json")], self.0).into_response()
    }
}

/// Helper to fetch a cipher by id for a user or return NotFound.
async fn fetch_cipher_for_user(
    db: &crate::db::Db,
    cipher_id: &str,
    user_id: &str,
) -> Result<CipherDBModel, AppError> {
    db.prepare(crate::models::cipher::CipherDBModel::select_for_user_sql())
        .bind(&[cipher_id.to_string().into(), user_id.to_string().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))
}

/// Validates that an optional folder belongs to the user. An absent or empty folder ID clears
/// the cipher's folder assignment and therefore requires no ownership check.
async fn validate_folder_ownership(
    db: &crate::db::Db,
    folder_id: Option<&str>,
    user_id: &str,
) -> Result<(), AppError> {
    let Some(folder_id) = folder_id.filter(|folder_id| !folder_id.is_empty()) else {
        return Ok(());
    };

    let folder_exists: Option<Value> = db
        .prepare("SELECT uuid AS id FROM folders WHERE uuid = ?1 AND user_uuid = ?2")
        .bind(&[folder_id.to_string().into(), user_id.to_string().into()])?
        .first(None)
        .await?;

    if folder_exists.is_none() {
        return Err(AppError::BadRequest(
            "Invalid folder: Folder does not exist or belongs to another user".to_string(),
        ));
    }

    Ok(())
}

/// Organization write checks shared by create/update/share (vaultwarden
/// `share_cipher_by_uuid` + `update_cipher_from_data`).
///
/// With `collection_ids = Some(..)` every collection must belong to `org_id` and be writable
/// by the user; with `None` (no collections supplied) the user needs full org access.
async fn check_org_write(
    db: &crate::db::Db,
    user_id: &str,
    org_id: &str,
    collection_ids: Option<&[String]>,
) -> Result<(), AppError> {
    use crate::handlers::organizations as orgs;
    let member = orgs::find_membership(db, user_id, org_id)
        .await?
        .filter(|m| m.status == crate::models::org_access::membership_status::CONFIRMED)
        .ok_or_else(|| {
            AppError::Unauthorized("You don't have permission to add item to organization".into())
        })?;
    match collection_ids {
        Some(ids) if !ids.is_empty() => {
            let writable = orgs::writable_collection_ids(db, user_id, org_id).await?;
            let existing = orgs::org_collection_ids(db, org_id).await?;
            for id in ids {
                if !existing.contains(id) {
                    return Err(AppError::BadRequest(
                        "Invalid collection ID provided".into(),
                    ));
                }
                if !writable.contains(id) {
                    return Err(AppError::Unauthorized(
                        "No rights to modify the collection".into(),
                    ));
                }
            }
            Ok(())
        }
        _ if orgs::has_full_access(&member) => Ok(()),
        _ => Err(AppError::Unauthorized(
            "You don't have permission to add item to organization".into(),
        )),
    }
}

/// Statements adding `cipher_id` to `collection_ids` (already validated).
fn add_to_collections_stmts(
    db: &crate::db::Db,
    cipher_id: &str,
    collection_ids: &[String],
) -> Result<Vec<worker::D1PreparedStatement>, AppError> {
    collection_ids
        .iter()
        .map(|col| {
            d1_query!(
                db,
                "INSERT OR IGNORE INTO ciphers_collections (cipher_uuid, collection_uuid) VALUES (?1, ?2)",
                cipher_id,
                col
            )
            .map_err(|_| AppError::Database)
        })
        .collect()
}

/// Load a cipher as the user sees it, with attachments, for API responses.
async fn cipher_response(
    db: &crate::db::Db,
    env: &Env,
    cipher_id: &str,
    user_id: &str,
) -> Result<Cipher, AppError> {
    let mut cipher: Cipher = fetch_cipher_for_user(db, cipher_id, user_id).await?.into();
    attachments::hydrate_cipher_attachments(db, env, &mut cipher).await?;
    Ok(cipher)
}

/// Like [`fetch_cipher_for_user`] but fails unless the user may modify the cipher.
async fn fetch_writable_cipher_for_user(
    db: &crate::db::Db,
    cipher_id: &str,
    user_id: &str,
) -> Result<CipherDBModel, AppError> {
    let c = fetch_cipher_for_user(db, cipher_id, user_id).await?;
    if c.read_only != 0 {
        return Err(AppError::Unauthorized(
            "Cipher is not write accessible".to_string(),
        ));
    }
    Ok(c)
}

/// Create a personal or organization cipher. `collection_ids` is `Some` for
/// `/ciphers/create` and `/ciphers/admin` (ShareCipherData) and `None` for `POST /ciphers`.
async fn create_cipher_impl(
    claims: Claims,
    env: Arc<Env>,
    data: CipherRequestData,
    collection_ids: Option<Vec<String>>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();

    validate_folder_ownership(&db, data.folder_id.as_deref(), &claims.sub).await?;
    let org_id = data.organization_id.clone().filter(|o| !o.is_empty());
    let collection_ids = collection_ids.unwrap_or_default();
    if org_id.is_none() {
        crate::handlers::org_policies::enforce_personal_ownership(&db, &claims.sub).await?;
    }
    if let Some(org_id) = &org_id {
        let cols = (!collection_ids.is_empty()).then_some(collection_ids.as_slice());
        check_org_write(&db, &claims.sub, org_id, cols).await?;
    }

    let cipher_data = CipherData::new(data.name, data.notes, data.type_fields);
    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;
    let id = Uuid::new_v4().to_string();

    let mut stmts = crate::models::cipher::create_cipher_stmts(
        &db,
        &id,
        &claims.sub,
        org_id.as_deref(),
        data.r#type,
        &data_value,
        data.folder_id.as_deref(),
        data.favorite.unwrap_or(false),
        None,
        &now,
        &now,
    )
    .map_err(|_| AppError::Database)?;
    if org_id.is_some() {
        stmts.extend(add_to_collections_stmts(&db, &id, &collection_ids)?);
    }
    db.batch(stmts).await?;

    let cipher = cipher_response(&db, env.as_ref(), &id, &claims.sub).await?;
    db::touch_user_updated_at(&db, &claims.sub, &now).await?;
    let audience =
        crate::models::org_access::cipher_audience(&db, std::slice::from_ref(&id), &claims.sub)
            .await?;
    crate::models::org_access::notify_audience(env.as_ref(), &db, audience, &now).await?;

    notifications::publish_cipher_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncCipherCreate,
        cipher.id.clone(),
        cipher.updated_at.clone(),
        Some(claims.device),
    );

    Ok(Json(cipher))
}

/// POST /api/ciphers/create and POST /api/ciphers/admin
#[worker::send]
pub async fn create_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CreateCipherRequest>,
) -> Result<Json<Cipher>, AppError> {
    create_cipher_impl(claims, env, payload.cipher, Some(payload.collection_ids)).await
}

/// Reject updates based on stale client data when the last known revision is provided.
fn check_revision(last_known: Option<&str>, existing: &CipherDBModel) -> Result<(), AppError> {
    let Some(dt) = last_known else {
        return Ok(());
    };
    match DateTime::parse_from_rfc3339(dt) {
        Ok(client_dt) => match DateTime::parse_from_rfc3339(&existing.updated_at) {
            Ok(server_dt) => {
                if server_dt.signed_duration_since(client_dt).num_seconds() > 1 {
                    return Err(AppError::BadRequest(
                        "The client copy of this cipher is out of date. Resync the client and try again."
                            .to_string(),
                    ));
                }
            }
            Err(err) => log::warn!(
                "Error parsing server revisionDate '{}' for cipher {}: {}",
                existing.updated_at,
                existing.id,
                err
            ),
        },
        Err(err) => log::warn!("Error parsing lastKnownRevisionDate '{}': {}", dt, err),
    }
    Ok(())
}

/// Update a cipher's content (and per-user folder/favorite). When `share_to` is set, a
/// personal cipher moves into that organization and is added to the given collections.
async fn update_cipher_impl(
    claims: Claims,
    env: Arc<Env>,
    id: String,
    payload: CipherRequestData,
    share_to: Option<Vec<String>>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();

    let existing = fetch_writable_cipher_for_user(&db, &id, &claims.sub).await?;
    validate_folder_ownership(&db, payload.folder_id.as_deref(), &claims.sub).await?;
    check_revision(payload.last_known_revision_date.as_deref(), &existing)?;

    let new_org = payload.organization_id.clone().filter(|o| !o.is_empty());
    if existing.organization_id.is_some() && existing.organization_id != new_org {
        return Err(AppError::BadRequest(
            "Organization mismatch. Please resync the client before updating the cipher".into(),
        ));
    }
    // Moving a personal cipher into an organization (share, or PUT with organizationId).
    let moving_to_org = existing.organization_id.is_none() && new_org.is_some();
    if new_org.is_none() {
        crate::handlers::org_policies::enforce_personal_ownership(&db, &claims.sub).await?;
    }
    if let Some(org_id) = &new_org {
        if moving_to_org || share_to.is_some() {
            check_org_write(&db, &claims.sub, org_id, share_to.as_deref()).await?;
        }
    }

    let cipher_data = CipherData::new(payload.name, payload.notes, payload.type_fields);
    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;
    let favorite = payload.favorite.unwrap_or(false);

    {
        use crate::models::cipher::{
            set_favorite_stmts, set_folder_stmts, share_cipher_stmts, update_cipher_stmt,
            CipherColumns,
        };
        let cols = CipherColumns::from_blob(payload.r#type, &data_value);
        let collections = share_to.clone().unwrap_or_default();
        let mut stmts = if moving_to_org {
            share_cipher_stmts(
                &db,
                &id,
                &claims.sub,
                new_org.as_deref().unwrap_or_default(),
                payload.r#type,
                &cols,
                &collections,
                &now,
            )
            .map_err(|_| AppError::Database)?
        } else {
            let mut v = vec![update_cipher_stmt(
                &db,
                &id,
                &claims.sub,
                new_org.as_deref(),
                payload.r#type,
                &cols,
                &now,
            )
            .map_err(|_| AppError::Database)?];
            if new_org.is_some() {
                v.extend(add_to_collections_stmts(&db, &id, &collections)?);
            }
            v
        };
        stmts.extend(
            set_folder_stmts(&db, &id, &claims.sub, payload.folder_id.as_deref())
                .map_err(|_| AppError::Database)?,
        );
        stmts.extend(
            set_favorite_stmts(&db, &id, &claims.sub, favorite).map_err(|_| AppError::Database)?,
        );
        db.batch(stmts).await?;
    }

    if let Some(attachments2) = &payload.attachments2 {
        for (attachment_id, attachment) in attachments2 {
            let result = d1_query!(
                &db,
                "UPDATE attachments SET file_name = ?1, akey = ?2 WHERE id = ?3 AND cipher_uuid = ?4",
                attachment.file_name,
                attachment.key,
                attachment_id,
                id
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await;

            if let Err(e) = result {
                log::warn!(
                    "Failed to update attachment {} for cipher {}: {:?}",
                    attachment_id,
                    id,
                    e
                );
            }
        }
    }

    let cipher = cipher_response(&db, env.as_ref(), &id, &claims.sub).await?;
    db::touch_user_updated_at(&db, &claims.sub, &now).await?;
    let audience =
        crate::models::org_access::cipher_audience(&db, std::slice::from_ref(&id), &claims.sub)
            .await?;
    crate::models::org_access::notify_audience(env.as_ref(), &db, audience, &now).await?;

    notifications::publish_cipher_update(
        (*env).clone(),
        claims.sub,
        if moving_to_org {
            UpdateType::SyncCipherCreate
        } else {
            UpdateType::SyncCipherUpdate
        },
        cipher.id.clone(),
        cipher.updated_at.clone(),
        Some(claims.device),
    );

    Ok(Json(cipher))
}

/// PUT|POST /api/ciphers/{id} (and /admin)
#[worker::send]
pub async fn update_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(_base_url)): Extension<BaseUrl>,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    update_cipher_impl(claims, env, id, payload, None).await
}

/// PUT|POST /api/ciphers/{id}/share
#[worker::send]
pub async fn share_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(payload): Json<CreateCipherRequest>,
) -> Result<Json<Cipher>, AppError> {
    if payload
        .cipher
        .organization_id
        .as_deref()
        .unwrap_or("")
        .is_empty()
    {
        return Err(AppError::BadRequest(
            "Cipher OrganizationId is required.".into(),
        ));
    }
    if payload.collection_ids.is_empty() {
        return Err(AppError::BadRequest(
            "You must select at least one collection.".into(),
        ));
    }
    update_cipher_impl(
        claims,
        env,
        id,
        payload.cipher,
        Some(payload.collection_ids),
    )
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareSelectedData {
    ciphers: Vec<CipherRequestData>,
    collection_ids: Vec<String>,
}

/// PUT /api/ciphers/share (bulk move to organization)
#[worker::send]
pub async fn share_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(data): Json<ShareSelectedData>,
) -> Result<Json<Value>, AppError> {
    if data.ciphers.is_empty() {
        return Err(AppError::BadRequest(
            "You must select at least one cipher.".into(),
        ));
    }
    if data.collection_ids.is_empty() {
        return Err(AppError::BadRequest(
            "You must select at least one collection.".into(),
        ));
    }
    if data
        .ciphers
        .iter()
        .any(|c| c.id.is_none() || c.organization_id.as_deref().unwrap_or("").is_empty())
    {
        return Err(AppError::BadRequest(
            "Request missing ids field or OrganizationId".into(),
        ));
    }
    const MINI_FIELDS: &[&str] = &[
        "id",
        "organizationId",
        "type",
        "data",
        "name",
        "notes",
        "login",
        "card",
        "identity",
        "secureNote",
        "sshKey",
        "bankAccount",
        "driversLicense",
        "passport",
        "fields",
        "passwordHistory",
        "attachments",
        "organizationUseTotp",
        "revisionDate",
        "creationDate",
        "deletedDate",
        "reprompt",
        "key",
    ];
    let mut out = Vec::with_capacity(data.ciphers.len());
    for mut c in data.ciphers {
        let id = c.id.take().unwrap_or_default();
        c.last_known_revision_date = None;
        let Json(cipher) = update_cipher_impl(
            claims.clone(),
            env.clone(),
            id,
            c,
            Some(data.collection_ids.clone()),
        )
        .await?;
        let mut v = serde_json::to_value(&cipher).map_err(|_| AppError::Internal)?;
        if let Some(o) = v.as_object_mut() {
            o.retain(|k, _| MINI_FIELDS.contains(&k.as_str()));
            o.insert("object".into(), "cipherMini".into());
        }
        out.push(v);
    }
    Ok(Json(
        serde_json::json!({"data": out, "object": "list", "continuationToken": null}),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionIdsData {
    #[serde(alias = "CollectionIds")]
    collection_ids: Vec<String>,
}

/// Replace the collections of an organization cipher (vaultwarden `post_collections_update`).
async fn update_collections_impl(
    claims: &Claims,
    env: &Env,
    id: &str,
    data: CollectionIdsData,
) -> Result<Cipher, AppError> {
    let db = db::get_db(env)?;
    let now = db::now_string();
    let existing = fetch_cipher_for_user(&db, id, &claims.sub).await?;
    if existing.read_only != 0 {
        return Err(AppError::BadRequest("Collection cannot be changed".into()));
    }
    let org_id = existing
        .organization_id
        .clone()
        .ok_or_else(|| AppError::BadRequest("Cipher is not owned by an organization".into()))?;
    use crate::handlers::organizations as orgs;
    let writable = orgs::writable_collection_ids(&db, &claims.sub, &org_id).await?;
    let existing_cols = orgs::org_collection_ids(&db, &org_id).await?;
    let posted: std::collections::HashSet<String> = data.collection_ids.into_iter().collect();
    #[derive(Deserialize)]
    struct Cc {
        collection_uuid: String,
    }
    let current: std::collections::HashSet<String> = db
        .prepare("SELECT collection_uuid FROM ciphers_collections WHERE cipher_uuid = ?1")
        .bind(&[id.into()])?
        .all()
        .await?
        .results::<Cc>()?
        .into_iter()
        .map(|c| c.collection_uuid)
        .collect();
    let audience_before =
        crate::models::org_access::cipher_audience(&db, &[id.to_string()], &claims.sub).await?;
    let mut stmts = Vec::new();
    for col in posted.symmetric_difference(&current) {
        if !existing_cols.contains(col) {
            return Err(AppError::BadRequest(
                "Invalid collection ID provided".into(),
            ));
        }
        if !writable.contains(col) {
            return Err(AppError::Unauthorized(
                "No rights to modify the collection".into(),
            ));
        }
        let sql = if posted.contains(col) {
            "INSERT OR IGNORE INTO ciphers_collections (cipher_uuid, collection_uuid) VALUES (?1, ?2)"
        } else {
            "DELETE FROM ciphers_collections WHERE cipher_uuid = ?1 AND collection_uuid = ?2"
        };
        stmts.push(db.prepare(sql).bind(&[id.into(), col.clone().into()])?);
    }
    stmts.push(
        d1_query!(
            &db,
            "UPDATE ciphers SET updated_at = ?1 WHERE uuid = ?2",
            now,
            id
        )
        .map_err(|_| AppError::Database)?,
    );
    db.batch(stmts).await?;

    let mut audience =
        crate::models::org_access::cipher_audience(&db, &[id.to_string()], &claims.sub).await?;
    for u in audience_before {
        if !audience.contains(&u) {
            audience.push(u);
        }
    }
    crate::models::org_access::notify_audience(env, &db, audience, &now).await?;
    db::touch_user_updated_at(&db, &claims.sub, &now).await?;
    notifications::publish_cipher_update(
        env.clone(),
        claims.sub.clone(),
        UpdateType::SyncCipherUpdate,
        id.to_string(),
        now,
        Some(claims.device.clone()),
    );
    cipher_response(&db, env, id, &claims.sub).await
}

/// PUT|POST /api/ciphers/{id}/collections and /collections-admin
#[worker::send]
pub async fn update_cipher_collections(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(data): Json<CollectionIdsData>,
) -> Result<Json<Cipher>, AppError> {
    Ok(Json(
        update_collections_impl(&claims, env.as_ref(), &id, data).await?,
    ))
}

/// PUT|POST /api/ciphers/{id}/collections_v2
#[worker::send]
pub async fn update_cipher_collections_v2(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(data): Json<CollectionIdsData>,
) -> Result<Json<Value>, AppError> {
    let cipher = update_collections_impl(&claims, env.as_ref(), &id, data).await?;
    Ok(Json(serde_json::json!({
        "object": "optionalCipherDetails",
        "unavailable": false,
        "cipher": cipher,
    })))
}

#[derive(Deserialize)]
pub struct OrgIdQuery {
    #[serde(rename = "organizationId")]
    organization_id: String,
}

/// GET /api/ciphers/organization-details?organizationId= (full-access members only) and
/// GET /api/ciphers/organization-details/assigned (ciphers the user can see in that org).
async fn org_details_impl(
    claims: Claims,
    env: Arc<Env>,
    org_id: String,
    assigned_only: bool,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    use crate::handlers::organizations as orgs;
    let m = orgs::require_role(
        &db,
        &claims.sub,
        &org_id,
        crate::models::org_access::membership_type::USER,
    )
    .await?;
    if !assigned_only && !orgs::has_full_access(&m) {
        return Err(AppError::NotFound("Resource not found.".into()));
    }
    let mut body = String::from("{\"data\":");
    append_cipher_json_array_raw(
        &mut body,
        &db,
        attachments::attachments_enabled(env.as_ref()),
        "WHERE c.organization_uuid = ?2",
        &[claims.sub.into(), org_id.into()],
        "",
        crate::handlers::ciphers_default_row_query(env.as_ref()),
    )
    .await?;
    body.push_str(",\"object\":\"list\",\"continuationToken\":null}");
    Ok(RawJson(body))
}

#[worker::send]
pub async fn get_org_details(
    claims: Claims,
    State(env): State<Arc<Env>>,
    axum::extract::Query(q): axum::extract::Query<OrgIdQuery>,
) -> Result<RawJson, AppError> {
    org_details_impl(claims, env, q.organization_id, false).await
}

#[worker::send]
pub async fn get_org_details_assigned(
    claims: Claims,
    State(env): State<Arc<Env>>,
    axum::extract::Query(q): axum::extract::Query<OrgIdQuery>,
) -> Result<RawJson, AppError> {
    org_details_impl(claims, env, q.organization_id, true).await
}

/// GET /api/ciphers - list all non-trashed ciphers for current user
#[worker::send]
pub async fn list_ciphers(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    build_cipher_list_response(
        &db,
        env.as_ref(),
        "WHERE c.deleted_at IS NULL",
        &[claims.sub.clone().into()],
        "ORDER BY c.updated_at DESC",
    )
    .await
}

/// GET /api/ciphers/{id}
#[worker::send]
pub async fn get_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let cipher = fetch_cipher_for_user(&db, &id, &claims.sub).await?;
    let mut cipher: Cipher = cipher.into();

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;

    Ok(Json(cipher))
}

/// GET /api/ciphers/{id}/details
#[worker::send]
pub async fn get_cipher_details(
    claims: Claims,
    state: State<Arc<Env>>,
    id: Path<String>,
) -> Result<Json<Cipher>, AppError> {
    get_cipher(claims, state, id).await
}

/// PUT/POST /api/ciphers/{id}/partial
#[worker::send]
pub async fn update_cipher_partial(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(payload): Json<PartialCipherData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;

    validate_folder_ownership(&db, payload.folder_id.as_deref(), user_id).await?;

    // Ensure cipher exists and belongs to user
    fetch_cipher_for_user(&db, &id, user_id).await?;

    let now = db::now_string();

    let mut stmts = vec![d1_query!(
        &db,
        &format!(
            "{}UPDATE ciphers SET updated_at = ?1 WHERE uuid = ?2 AND {}",
            crate::models::org_access::with_access("?3"),
            crate::models::org_access::WRITABLE
        ),
        now,
        id,
        user_id,
    )
    .map_err(|_| AppError::Database)?];
    stmts.extend(
        crate::models::cipher::set_folder_stmts(&db, &id, user_id, payload.folder_id.as_deref())
            .map_err(|_| AppError::Database)?,
    );
    stmts.extend(
        crate::models::cipher::set_favorite_stmts(&db, &id, user_id, payload.favorite)
            .map_err(|_| AppError::Database)?,
    );
    db.batch(stmts).await?;

    let now = db::now_string();
    db::touch_user_updated_at(&db, user_id, &now).await?;

    let cipher = fetch_cipher_for_user(&db, &id, user_id).await?;
    let mut cipher: Cipher = cipher.into();

    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;

    Ok(Json(cipher))
}

/// Soft delete a single cipher (PUT /api/ciphers/{id}/delete)
/// Sets deleted_at to current timestamp
#[worker::send]
pub async fn soft_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    fetch_writable_cipher_for_user(&db, &id, &claims.sub).await?;
    let audience =
        crate::models::org_access::cipher_audience(&db, std::slice::from_ref(&id), &claims.sub)
            .await?;
    let now = db::now_string();

    d1_query!(
        &db,
        &format!(
            "{}UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE uuid = ?2 AND {}",
            crate::models::org_access::with_access("?3"),
            crate::models::org_access::WRITABLE
        ),
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    crate::models::org_access::notify_audience(env.as_ref(), &db, audience, &now).await?;
    db::touch_user_updated_at(&db, &claims.sub, &now).await?;

    notifications::publish_cipher_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncCipherUpdate,
        id,
        now,
        Some(claims.device),
    );

    Ok(Json(()))
}

/// Soft delete multiple ciphers (PUT /api/ciphers/delete)
/// Accepts raw JSON body and uses json_each with path to extract ids directly.
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn soft_delete_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let bulk_ids: Vec<String> = serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v.get("ids").cloned())
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    let audience = crate::models::org_access::cipher_audience(&db, &bulk_ids, &claims.sub).await?;

    d1_query!(
        &db,
        &format!("{}UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE uuid IN (SELECT value FROM json_each(?3, '$.ids')) AND {}", crate::models::org_access::with_access("?2"), crate::models::org_access::WRITABLE),
        now,
        claims.sub,
        body
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    crate::models::org_access::notify_audience(env.as_ref(), &db, audience, &now).await?;
    db::touch_user_updated_at(&db, &claims.sub, &now).await?;

    notifications::publish_user_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncCiphers,
        now,
        Some(claims.device),
    );

    Ok(Json(()))
}

/// Hard delete a single cipher (DELETE /api/ciphers/{id} or POST /api/ciphers/{id}/delete)
/// Permanently removes the cipher from database
#[worker::send]
pub async fn hard_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    fetch_writable_cipher_for_user(&db, &id, &claims.sub).await?;
    let audience =
        crate::models::org_access::cipher_audience(&db, std::slice::from_ref(&id), &claims.sub)
            .await?;
    let now = db::now_string();

    if attachments::attachments_enabled(env.as_ref()) {
        let id_json = serde_json::to_string(&[&id]).map_err(|_| AppError::Internal)?;
        let keys = attachments::list_attachment_keys_for_cipher_ids_json(
            &db,
            &id_json,
            "$",
            Some(&claims.sub),
        )
        .await?;
        attachments::delete_storage_objects(env.as_ref(), &keys).await?;
    }

    db.batch(
        // Write access was checked above; the condition can't use the access CTE because
        // deleting `ciphers_collections` first would revoke collection-based access mid-batch.
        db::delete_ciphers_statements(&db, "uuid = ?1", &[id.clone().into()])
            .map_err(|_| AppError::Database)?,
    )
    .await?;

    crate::models::org_access::notify_audience(env.as_ref(), &db, audience, &now).await?;
    db::touch_user_updated_at(&db, &claims.sub, &now).await?;

    notifications::publish_cipher_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncLoginDelete,
        id,
        now,
        Some(claims.device),
    );

    Ok(Json(()))
}

/// Hard delete multiple ciphers (DELETE /api/ciphers or POST /api/ciphers/delete)
/// Accepts raw JSON body and uses json_each with path to extract ids directly.
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn hard_delete_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let bulk_ids: Vec<String> = serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v.get("ids").cloned())
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    let audience = crate::models::org_access::cipher_audience(&db, &bulk_ids, &claims.sub).await?;

    // Resolve the writable ids first (see hard_delete_cipher for why the delete itself
    // can't filter through the access CTE).
    #[derive(Deserialize)]
    struct Ids {
        ids: String,
    }
    let writable_ids = db
        .prepare(format!(
            "{}SELECT COALESCE(json_group_array(cipher_uuid), '[]') AS ids FROM access
             WHERE read_only = 0 AND cipher_uuid IN (SELECT value FROM json_each(?2, '$.ids'))",
            crate::models::org_access::with_access("?1")
        ))
        .bind(&[claims.sub.clone().into(), body.clone().into()])?
        .first::<Ids>(None)
        .await
        .map_err(db::map_d1_json_error)?
        .map(|r| r.ids)
        .unwrap_or_else(|| "[]".to_string());

    if attachments::attachments_enabled(env.as_ref()) {
        let keys = attachments::list_attachment_keys_for_cipher_ids_json(
            &db,
            &body,
            "$.ids",
            Some(&claims.sub),
        )
        .await?;
        attachments::delete_storage_objects(env.as_ref(), &keys).await?;
    }

    db.batch(
        db::delete_ciphers_statements(
            &db,
            "uuid IN (SELECT value FROM json_each(?1))",
            &[writable_ids.into()],
        )
        .map_err(|_| AppError::Database)?,
    )
    .await
    .map_err(db::map_d1_json_error)?;

    crate::models::org_access::notify_audience(env.as_ref(), &db, audience, &now).await?;
    db::touch_user_updated_at(&db, &claims.sub, &now).await?;

    notifications::publish_user_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncCiphers,
        now,
        Some(claims.device),
    );

    Ok(Json(()))
}

/// Restore a single cipher (PUT /api/ciphers/{id}/restore)
/// Clears the deleted_at timestamp
#[worker::send]
pub async fn restore_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    fetch_writable_cipher_for_user(&db, &id, &claims.sub).await?;
    let audience =
        crate::models::org_access::cipher_audience(&db, std::slice::from_ref(&id), &claims.sub)
            .await?;
    let now = db::now_string();

    // Update the cipher to clear deleted_at
    d1_query!(
        &db,
        &format!(
            "{}UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE uuid = ?2 AND {}",
            crate::models::org_access::with_access("?3"),
            crate::models::org_access::WRITABLE
        ),
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let restored = fetch_cipher_for_user(&db, &id, &claims.sub).await?;
    let mut cipher: Cipher = restored.into();
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;

    crate::models::org_access::notify_audience(env.as_ref(), &db, audience, &now).await?;
    db::touch_user_updated_at(&db, &claims.sub, &cipher.updated_at).await?;

    notifications::publish_cipher_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncCipherUpdate,
        cipher.id.clone(),
        cipher.updated_at.clone(),
        Some(claims.device),
    );

    Ok(Json(cipher))
}

/// Restore multiple ciphers (PUT /api/ciphers/restore)
/// Accepts raw JSON body and uses json_each with path to extract ids directly.
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn restore_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let bulk_ids: Vec<String> = serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v.get("ids").cloned())
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    let audience = crate::models::org_access::cipher_audience(&db, &bulk_ids, &claims.sub).await?;

    // Single bulk UPDATE using json_each() with path
    d1_query!(
        &db,
        &format!("{}UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE uuid IN (SELECT value FROM json_each(?3, '$.ids')) AND {}", crate::models::org_access::with_access("?2"), crate::models::org_access::WRITABLE),
        now,
        claims.sub,
        body
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(db::map_d1_json_error)?;

    crate::models::org_access::notify_audience(env.as_ref(), &db, audience, &now).await?;
    db::touch_user_updated_at(&db, &claims.sub, &now).await?;

    notifications::publish_user_update(
        (*env).clone(),
        claims.sub.clone(),
        UpdateType::SyncCiphers,
        now,
        Some(claims.device),
    );

    build_cipher_list_response(
        &db,
        env.as_ref(),
        "WHERE c.uuid IN (SELECT value FROM json_each(?2, '$.ids'))",
        &[claims.sub.into(), body.into()],
        "",
    )
    .await
}

/// Archive a single cipher (PUT /api/ciphers/{id}/archive)
#[worker::send]
pub async fn archive_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    fetch_cipher_for_user(&db, &id, &claims.sub).await.map_err(|_| {
        AppError::BadRequest(
            "Cipher was not archived. Ensure the provided ID is correct and you have permission to archive it."
                .to_string(),
        )
    })?;
    let now = db::now_string();

    let mut stmts = vec![d1_query!(
        &db,
        &format!(
            "{}UPDATE ciphers SET updated_at = ?1 WHERE uuid = ?2 AND {}",
            crate::models::org_access::with_access("?3"),
            crate::models::org_access::WRITABLE
        ),
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?];
    stmts.extend(
        crate::models::cipher::set_archived_stmts(&db, &id, &claims.sub, Some(&now))
            .map_err(|_| AppError::Database)?,
    );
    db.batch(stmts).await?;

    let updated = fetch_cipher_for_user(&db, &id, &claims.sub).await?;
    let mut cipher: Cipher = updated.into();
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;

    db::touch_user_updated_at(&db, &claims.sub, &cipher.updated_at).await?;

    notifications::publish_cipher_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncCipherUpdate,
        cipher.id.clone(),
        cipher.updated_at.clone(),
        Some(claims.device),
    );

    Ok(Json(cipher))
}

/// Unarchive a single cipher (PUT /api/ciphers/{id}/unarchive)
#[worker::send]
pub async fn unarchive_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    fetch_cipher_for_user(&db, &id, &claims.sub).await.map_err(|_| {
        AppError::BadRequest(
            "Cipher was not unarchived. Ensure the provided ID is correct and you have permission to unarchive it."
                .to_string(),
        )
    })?;
    let now = db::now_string();

    let mut stmts = vec![d1_query!(
        &db,
        &format!(
            "{}UPDATE ciphers SET updated_at = ?1 WHERE uuid = ?2 AND {}",
            crate::models::org_access::with_access("?3"),
            crate::models::org_access::WRITABLE
        ),
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?];
    stmts.extend(
        crate::models::cipher::set_archived_stmts(&db, &id, &claims.sub, None)
            .map_err(|_| AppError::Database)?,
    );
    db.batch(stmts).await?;

    let updated = fetch_cipher_for_user(&db, &id, &claims.sub).await?;
    let mut cipher: Cipher = updated.into();
    attachments::hydrate_cipher_attachments(&db, env.as_ref(), &mut cipher).await?;

    db::touch_user_updated_at(&db, &claims.sub, &cipher.updated_at).await?;

    notifications::publish_cipher_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncCipherUpdate,
        cipher.id.clone(),
        cipher.updated_at.clone(),
        Some(claims.device),
    );

    Ok(Json(cipher))
}

/// Archive multiple ciphers (PUT /api/ciphers/archive)
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn archive_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();

    db.batch(vec![
        d1_query!(
            &db,
            &format!("{}UPDATE ciphers SET updated_at = ?1 WHERE uuid IN (SELECT value FROM json_each(?3, '$.ids')) AND {}", crate::models::org_access::with_access("?2"), crate::models::org_access::WRITABLE),
            now,
            claims.sub,
            body
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            &db,
            &format!(
                "{}INSERT OR REPLACE INTO archives (user_uuid, cipher_uuid, archived_at)
                 SELECT ?2, uuid, ?1 FROM ciphers WHERE {} AND uuid IN (SELECT value FROM json_each(?3, '$.ids'))",
                crate::models::org_access::with_access("?2"),
                crate::models::org_access::VISIBLE
            ),
            now,
            claims.sub,
            body
        )
        .map_err(|_| AppError::Database)?,
    ])
    .await
    .map_err(db::map_d1_json_error)?;

    db::touch_user_updated_at(&db, &claims.sub, &now).await?;

    notifications::publish_user_update(
        (*env).clone(),
        claims.sub.clone(),
        UpdateType::SyncCiphers,
        now,
        Some(claims.device),
    );

    build_cipher_list_response(
        &db,
        env.as_ref(),
        "WHERE c.uuid IN (SELECT value FROM json_each(?2, '$.ids'))",
        &[claims.sub.into(), body.into()],
        "",
    )
    .await
}

/// Unarchive multiple ciphers (PUT /api/ciphers/unarchive)
/// Expected JSON: {"ids": ["cipher_id1", "cipher_id2", ...]}
#[worker::send]
pub async fn unarchive_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<RawJson, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();

    db.batch(vec![
        d1_query!(
            &db,
            &format!("{}UPDATE ciphers SET updated_at = ?1 WHERE uuid IN (SELECT value FROM json_each(?3, '$.ids')) AND {}", crate::models::org_access::with_access("?2"), crate::models::org_access::WRITABLE),
            now,
            claims.sub,
            body
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            &db,
            "DELETE FROM archives WHERE user_uuid = ?1 AND cipher_uuid IN (SELECT value FROM json_each(?2, '$.ids'))",
            claims.sub,
            body
        )
        .map_err(|_| AppError::Database)?,
    ])
    .await
    .map_err(db::map_d1_json_error)?;

    db::touch_user_updated_at(&db, &claims.sub, &now).await?;

    notifications::publish_user_update(
        (*env).clone(),
        claims.sub.clone(),
        UpdateType::SyncCiphers,
        now,
        Some(claims.device),
    );

    build_cipher_list_response(
        &db,
        env.as_ref(),
        "WHERE c.uuid IN (SELECT value FROM json_each(?2, '$.ids'))",
        &[claims.sub.into(), body.into()],
        "",
    )
    .await
}

/// Handler for POST /api/ciphers
/// Accepts flat JSON structure (camelCase) as sent by Bitwarden clients
/// when creating a cipher without collection assignments.
#[worker::send]
pub async fn create_cipher_simple(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    create_cipher_impl(claims, env, payload, None).await
}

/// Move selected ciphers to a folder (POST/PUT /api/ciphers/move)
/// Accepts raw JSON body and uses json_extract/json_each to extract values directly.
/// Expected JSON: {"folderId": "optional-folder-id-or-null", "ids": ["cipher_id1", ...]}
/// The folderId is optional and treated as null if not provided in vaultwarden.
/// D1/SQLite's json_extract returns SQL NULL for non-existent paths, which is identical to the behavior in vaultwarden.
#[worker::send]
pub async fn move_cipher_selected(
    claims: Claims,
    State(env): State<Arc<Env>>,
    body: String,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Validate folder exists and belongs to user (if folder_id is provided)
    // Uses json_extract to get folderId from request body
    let folder_invalid: Option<Value> = db
        .prepare(
            "SELECT 1 WHERE NULLIF(json_extract(?1, '$.folderId'), '') IS NOT NULL 
             AND NOT EXISTS (
                 SELECT 1 FROM folders WHERE uuid = NULLIF(json_extract(?1, '$.folderId'), '') AND user_uuid = ?2
             )",
        )
        .bind(&[body.clone().into(), user_id.clone().into()])?
        .first(None)
        .await
        .map_err(db::map_d1_json_error)?;

    if folder_invalid.is_some() {
        return Err(AppError::BadRequest(
            "Invalid folder: Folder does not exist or belongs to another user".to_string(),
        ));
    }

    // Update folder_id for all ciphers that belong to the user and are in the ids list
    // Uses json_extract for folderId and json_each for ids array
    let binds = [body.into(), now.clone().into(), user_id.clone().into()];
    db.batch(vec![
        db.prepare(format!(
            "{}DELETE FROM folders_ciphers
             WHERE cipher_uuid IN (SELECT cipher_uuid FROM access WHERE cipher_uuid IN (SELECT value FROM json_each(?1, '$.ids')))
               AND folder_uuid IN (SELECT uuid FROM folders WHERE user_uuid = ?3)",
            crate::models::org_access::with_access("?3")
        ))
        .bind(&binds)?,
        db.prepare(format!(
            "{}INSERT INTO folders_ciphers (cipher_uuid, folder_uuid)
             SELECT cipher_uuid, NULLIF(json_extract(?1, '$.folderId'), '') FROM access
             WHERE cipher_uuid IN (SELECT value FROM json_each(?1, '$.ids'))
               AND NULLIF(json_extract(?1, '$.folderId'), '') IS NOT NULL",
            crate::models::org_access::with_access("?3")
        ))
        .bind(&binds)?,
        db.prepare(
            format!("{}UPDATE ciphers SET updated_at = ?2 WHERE uuid IN (SELECT value FROM json_each(?1, '$.ids')) AND {}", crate::models::org_access::with_access("?3"), crate::models::org_access::WRITABLE),
        )
        .bind(&binds)?,
    ])
    .await
    .map_err(db::map_d1_json_error)?;

    // Update user's revision date
    db::touch_user_updated_at(&db, user_id, &now).await?;
    notifications::publish_user_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncCiphers,
        now,
        Some(claims.device),
    );

    Ok(Json(()))
}

#[derive(Deserialize)]
pub struct PurgeQuery {
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
}

/// Purge the user's vault - delete all ciphers and folders
/// POST /api/ciphers/purge
///
/// This is a destructive operation that requires password verification.
/// In vaultwarden, this endpoint also supports purging organization vaults,
/// but this simplified version only supports personal vault purge.
#[worker::send]
pub async fn purge_vault(
    claims: Claims,
    State(env): State<Arc<Env>>,
    axum::extract::Query(query): axum::extract::Query<PurgeQuery>,
    Json(payload): Json<PasswordOrOtpData>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;
    let org_id = query.organization_id.filter(|o| !o.is_empty());
    if let Some(org_id) = &org_id {
        // vaultwarden: only owners may purge an organization vault.
        crate::handlers::organizations::require_role(
            &db,
            user_id,
            org_id,
            crate::models::org_access::membership_type::OWNER,
        )
        .await?;
    }

    // Get the user from the database
    let user: Value = db
        .prepare(crate::models::user::select_user_by_id_sql())
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    // Validate password (OTP not supported in this simplified version)
    let provided_hash = payload
        .master_password_hash
        .ok_or_else(|| AppError::BadRequest("Missing master password hash".to_string()))?;

    let verification = user.verify_master_password(&provided_hash).await?;

    if !verification.is_valid() {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    if let Some(org_id) = org_id {
        let audience: Vec<String> = {
            #[derive(Deserialize)]
            struct Row {
                user_uuid: String,
            }
            db.prepare("SELECT user_uuid FROM users_organizations WHERE org_uuid = ?1 AND status = 2 AND user_uuid != ?2")
                .bind(&[org_id.clone().into(), user_id.clone().into()])?
                .all()
                .await?
                .results::<Row>()?
                .into_iter()
                .map(|r| r.user_uuid)
                .collect()
        };
        if attachments::attachments_enabled(env.as_ref()) {
            let keys = attachments::list_attachment_keys_for_org(&db, &org_id).await?;
            attachments::delete_storage_objects(env.as_ref(), &keys).await?;
        }
        db.batch(
            db::delete_ciphers_statements(&db, "organization_uuid = ?1", &[org_id.into()])
                .map_err(|_| AppError::Database)?,
        )
        .await?;
        let now = db::now_string();
        crate::models::org_access::notify_audience(env.as_ref(), &db, audience, &now).await?;
        db::touch_user_updated_at(&db, user_id, &now).await?;
        notifications::publish_user_update(
            (*env).clone(),
            claims.sub,
            UpdateType::SyncVault,
            now,
            Some(claims.device),
        );
        return Ok(Json(()));
    }

    if attachments::attachments_enabled(env.as_ref()) {
        let keys = attachments::list_attachment_keys_for_user(&db, user_id).await?;
        attachments::delete_storage_objects(env.as_ref(), &keys).await?;
    }

    // Delete all user's ciphers (both active and soft-deleted) and folders
    let binds = [user_id.clone().into()];
    let mut stmts = db::delete_ciphers_statements(&db, "user_uuid = ?1", &binds)
        .map_err(|_| AppError::Database)?;
    for sql in [
        // Favorites/archives of the user's own ciphers went with them; those on organization
        // ciphers stay (vaultwarden only deletes the user's ciphers and folders).
        "DELETE FROM folders_ciphers WHERE folder_uuid IN (SELECT uuid FROM folders WHERE user_uuid = ?1)",
        "DELETE FROM folders WHERE user_uuid = ?1",
    ] {
        stmts.push(db.prepare(sql).bind(&binds)?);
    }
    db.batch(stmts).await?;

    // Update user's revision date to trigger client sync
    let now = db::now_string();
    db::touch_user_updated_at(&db, user_id, &now).await?;

    notifications::publish_user_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncVault,
        now,
        Some(claims.device),
    );

    Ok(Json(()))
}

#[derive(Deserialize)]
struct CipherJsonArrayRow {
    ciphers_json: String,
}

/// Build the SQL expression for a single cipher as JSON, as seen by the user bound to `?1`.
///
/// Must be used in a query of the form `{with_access("?1")} SELECT ... FROM ciphers c
/// JOIN access a ON a.cipher_uuid = c.uuid ...` (see [`cipher_from_clause`]). Mirrors
/// vaultwarden's `Cipher::to_json` (cipherDetails, user sync).
fn cipher_json_expr(attachments_enabled: bool) -> String {
    let attachments_expr = if attachments_enabled {
        "
            (
                SELECT CASE WHEN COUNT(1)=0 THEN NULL ELSE json_group_array(
                    json_object(
                        'id', at.id,
                        'url', NULL,
                        'fileName', at.file_name,
                        'size', CAST(at.file_size AS TEXT),
                        'sizeName',
                            CASE
                                WHEN at.file_size < 1024 THEN printf('%d B', at.file_size)
                                WHEN at.file_size < 1048576 THEN printf('%.1f KB', at.file_size / 1024.0)
                                WHEN at.file_size < 1073741824 THEN printf('%.1f MB', at.file_size / 1048576.0)
                                WHEN at.file_size < 1099511627776 THEN printf('%.1f GB', at.file_size / 1073741824.0)
                                ELSE printf('%.1f TB', at.file_size / 1099511627776.0)
                            END,
                        'key', at.akey,
                        'object', 'attachment'
                    )
                ) END
                FROM attachments at
                WHERE at.cipher_uuid = c.uuid
            )
        "
    } else {
        "NULL"
    };

    format!(
        "json_object(
            'object', 'cipherDetails',
            'id', c.uuid,
            'userId', c.user_uuid,
            'organizationId', c.organization_uuid,
            'folderId', (SELECT fc.folder_uuid FROM folders_ciphers fc JOIN folders fo ON fo.uuid = fc.folder_uuid
                          WHERE fc.cipher_uuid = c.uuid AND fo.user_uuid = ?1 LIMIT 1),
            'type', c.atype,
            'favorite', CASE WHEN EXISTS (SELECT 1 FROM favorites f WHERE f.cipher_uuid = c.uuid AND f.user_uuid = ?1)
                             THEN json('true') ELSE json('false') END,
            'edit', CASE WHEN a.read_only THEN json('false') ELSE json('true') END,
            'viewPassword', CASE WHEN a.hide_passwords THEN json('false') ELSE json('true') END,
            'permissions', json_object(
                'delete', CASE WHEN a.read_only THEN json('false') ELSE json('true') END,
                'restore', CASE WHEN a.read_only THEN json('false') ELSE json('true') END),
            'organizationUseTotp', CASE WHEN c.organization_uuid IS NULL THEN json('false') ELSE json('true') END,
            'collectionIds', CASE WHEN c.organization_uuid IS NULL THEN json('[]') ELSE (
                SELECT COALESCE(json_group_array(cc.collection_uuid), json('[]')) FROM ciphers_collections cc
                WHERE cc.cipher_uuid = c.uuid AND cc.collection_uuid IN (SELECT collection_uuid FROM ucol)) END,
            'revisionDate', c.updated_at,
            'creationDate', c.created_at,
            'deletedDate', c.deleted_at,
            'archivedDate', (SELECT ar.archived_at FROM archives ar WHERE ar.cipher_uuid = c.uuid AND ar.user_uuid = ?1),
            'attachments', {attachments_expr},
            'name', c.name,
            'notes', c.notes,
            'fields', COALESCE(json(c.fields), json('[]')),
            'passwordHistory', COALESCE(json(c.password_history), json('[]')),
            'reprompt', COALESCE(c.reprompt, 0),
            'login', CASE WHEN c.atype = 1 THEN json(c.data) ELSE NULL END,
            'secureNote', CASE WHEN c.atype = 2 THEN json(c.data) ELSE NULL END,
            'card', CASE WHEN c.atype = 3 THEN json(c.data) ELSE NULL END,
            'identity', CASE WHEN c.atype = 4 THEN json(c.data) ELSE NULL END,
            'sshKey', CASE WHEN c.atype = 5 THEN json(c.data) ELSE NULL END,
            'bankAccount', CASE WHEN c.atype = 6 THEN json(c.data) ELSE NULL END,
            'driversLicense', CASE WHEN c.atype = 7 THEN json(c.data) ELSE NULL END,
            'passport', CASE WHEN c.atype = 8 THEN json(c.data) ELSE NULL END,
            'key', c.\"key\"
        )",
        attachments_expr = attachments_expr,
    )
}

/// `FROM` clause for cipher JSON queries: every cipher visible to the user bound to `?1`.
const CIPHER_FROM: &str = "FROM ciphers c JOIN access a ON a.cipher_uuid = c.uuid";

/// Build SQL that returns ciphers as a JSON array string (using json_group_array).
/// `where_clause` may reference `c.*` (vaultwarden columns) and `a.*` (access flags).
fn cipher_json_array_sql(
    attachments_enabled: bool,
    where_clause: &str,
    order_clause: &str,
) -> String {
    let cipher_expr = cipher_json_expr(attachments_enabled);
    let with = crate::models::org_access::with_access("?1");
    // Use a subquery to ensure ORDER BY is applied before json_group_array
    format!(
        "{with}SELECT COALESCE(json_group_array(json(sub.cipher_json)), '[]') AS ciphers_json
        FROM (
            SELECT {cipher_expr} AS cipher_json
            {CIPHER_FROM}
            {where_clause}
            {order_clause}
        ) sub",
    )
}

fn cipher_json_rows_sql(
    attachments_enabled: bool,
    where_clause: &str,
    order_clause: &str,
) -> String {
    let cipher_expr = cipher_json_expr(attachments_enabled);
    let with = crate::models::org_access::with_access("?1");
    format!(
        "{with}SELECT {cipher_expr} AS cipher_json
        {CIPHER_FROM}
        {where_clause}
        {order_clause}",
    )
}

fn is_sqlite_toobig(err: &worker::Error) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("sqlite_toobig") || msg.contains("string or blob too big")
}

/// Build a `{"data":[...],"object":"list","continuationToken":null}` response
/// using raw SQL JSON construction (no Rust-side parsing).
async fn build_cipher_list_response(
    db: &crate::db::Db,
    env: &Env,
    where_clause: &str,
    params: &[JsValue],
    order_clause: &str,
) -> Result<RawJson, AppError> {
    let include_attachments = attachments::attachments_enabled(env);
    let force_row_query = super::ciphers_default_row_query(env);
    let mut response = String::new();
    response.push_str("{\"data\":");
    append_cipher_json_array_raw(
        &mut response,
        db,
        include_attachments,
        where_clause,
        params,
        order_clause,
        force_row_query,
    )
    .await?;
    response.push_str(",\"object\":\"list\",\"continuationToken\":null}");
    Ok(RawJson(response))
}

/// Append ciphers JSON array to an existing buffer.
/// This avoids JSON parsing in Rust, significantly reducing CPU time.
pub(crate) async fn append_cipher_json_array_raw(
    out: &mut String,
    db: &crate::db::Db,
    attachments_enabled: bool,
    where_clause: &str,
    params: &[JsValue],
    order_clause: &str,
    force_row_query: bool,
) -> Result<(), AppError> {
    if force_row_query {
        return append_from_rows(
            out,
            db,
            attachments_enabled,
            where_clause,
            params,
            order_clause,
        )
        .await;
    }

    let sql = cipher_json_array_sql(attachments_enabled, where_clause, order_clause);

    let row: Result<Option<CipherJsonArrayRow>, worker::Error> =
        db.prepare(&sql).bind(params)?.first(None).await;

    match row {
        Ok(row) => {
            if let Some(r) = row {
                out.reserve(r.ciphers_json.len());
                out.push_str(&r.ciphers_json);
            } else {
                out.push_str("[]");
            }
            Ok(())
        }
        Err(err) if is_sqlite_toobig(&err) => {
            append_from_rows(
                out,
                db,
                attachments_enabled,
                where_clause,
                params,
                order_clause,
            )
            .await
        }
        Err(err) => Err(db::map_d1_json_error(err)),
    }
}

/// Append ciphers JSON array to an existing buffer row by row.
/// This avoids JSON array exceeding the maximum size that can be returned in a single string.
///
/// Uses `raw_js_value()` to bypass Serde deserialization entirely, which should reduce
/// CPU time for large payloads. Each row from `raw_js_value()` is a JS array `[cipher_json]`
/// where the first element is the JSON string we need.
pub(crate) async fn append_from_rows(
    out: &mut String,
    db: &crate::db::Db,
    attachments_enabled: bool,
    where_clause: &str,
    params: &[JsValue],
    order_clause: &str,
) -> Result<(), AppError> {
    use js_sys::Array;
    use wasm_bindgen::JsCast;

    let sql = cipher_json_rows_sql(attachments_enabled, where_clause, order_clause);

    // Use raw_js_value() to get Vec<JsValue> without Serde deserialization.
    // Each JsValue is a JS array: [cipher_json_string]
    let raw_rows: Vec<JsValue> = db
        .prepare(&sql)
        .bind(params)?
        .raw_js_value()
        .await
        .map_err(db::map_d1_json_error)?;

    if raw_rows.is_empty() {
        out.push_str("[]");
        return Ok(());
    }

    out.push('[');
    for (idx, row_js) in raw_rows.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        // Each row is a JS array [column0, column1, ...]. We only select one column (cipher_json).
        let row_array = row_js
            .dyn_ref::<Array>()
            .ok_or_else(|| AppError::Internal)?;
        let cipher_json_js = row_array.get(0);
        let cipher_json = cipher_json_js
            .as_string()
            .ok_or_else(|| AppError::Internal)?;
        out.push_str(&cipher_json);
    }
    out.push(']');
    Ok(())
}

/// GET /api/organizations/{org_id}/export (admins): `{collections, ciphers}`.
#[worker::send]
pub async fn export_organization(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(org_id): Path<String>,
) -> Result<RawJson, AppError> {
    use crate::handlers::organizations as orgs;
    let db = db::get_db(&env)?;
    orgs::require_role(
        &db,
        &claims.sub,
        &org_id,
        crate::models::org_access::membership_type::ADMIN,
    )
    .await?;
    let collections = orgs::org_collections_json(&db, &org_id).await?;
    let mut body = String::from("{\"collections\":");
    body.push_str(&serde_json::to_string(&collections).map_err(|_| AppError::Internal)?);
    body.push_str(",\"ciphers\":");
    append_cipher_json_array_raw(
        &mut body,
        &db,
        attachments::attachments_enabled(env.as_ref()),
        "WHERE c.organization_uuid = ?2",
        &[claims.sub.into(), org_id.into()],
        "",
        crate::handlers::ciphers_default_row_query(env.as_ref()),
    )
    .await?;
    body.push('}');
    Ok(RawJson(body))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgImportCollection {
    name: String,
    id: Option<String>,
    external_id: Option<String>,
}

#[derive(Deserialize)]
pub struct OrgImportRelation {
    key: usize,
    value: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgImportData {
    ciphers: Vec<CipherRequestData>,
    #[serde(default)]
    collections: Vec<OrgImportCollection>,
    #[serde(default)]
    collection_relationships: Vec<OrgImportRelation>,
}

/// POST /api/ciphers/import-organization?organizationId= (vaultwarden `post_org_import`)
#[worker::send]
pub async fn import_organization(
    claims: Claims,
    State(env): State<Arc<Env>>,
    axum::extract::Query(q): axum::extract::Query<OrgIdQuery>,
    Json(data): Json<OrgImportData>,
) -> Result<Json<()>, AppError> {
    use crate::handlers::organizations as orgs;
    use crate::models::org_access::{membership_status, membership_type};
    let db = db::get_db(&env)?;
    let org_id = q.organization_id;
    let m = orgs::find_membership(&db, &claims.sub, &org_id)
        .await?
        .filter(|m| m.status == membership_status::CONFIRMED)
        .ok_or_else(|| {
            AppError::BadRequest(
                "You need to be a Member of the Organization to call this endpoint".into(),
            )
        })?;
    let is_admin = orgs::role_rank(m.atype) >= orgs::role_rank(membership_type::ADMIN);
    let existing = orgs::org_collection_ids(&db, &org_id).await?;
    let writable = orgs::writable_collection_ids(&db, &claims.sub, &org_id).await?;
    let now = db::now_string();
    let mut stmts = Vec::new();
    let mut collections = Vec::with_capacity(data.collections.len());
    for col in data.collections {
        let id = match col.id.filter(|id| existing.contains(id)) {
            Some(id) => {
                if !is_admin && !writable.contains(&id) {
                    return Err(AppError::BadRequest(
                        "The current user isn't allowed to manage this collection".into(),
                    ));
                }
                id
            }
            None => {
                if !orgs::has_full_access(&m) {
                    return Err(AppError::BadRequest(
                        "The current user isn't allowed to create new collections".into(),
                    ));
                }
                let id = Uuid::new_v4().to_string();
                stmts.push(
                    d1_query!(
                        &db,
                        "INSERT INTO collections (uuid, org_uuid, name, external_id) VALUES (?1, ?2, ?3, ?4)",
                        id,
                        org_id,
                        col.name,
                        col.external_id
                    )
                    .map_err(|_| AppError::Database)?,
                );
                id
            }
        };
        collections.push(id);
    }
    let mut ciphers = Vec::with_capacity(data.ciphers.len());
    for cd in data.ciphers {
        let id = Uuid::new_v4().to_string();
        let r#type = cd.r#type;
        let blob = serde_json::to_value(CipherData::new(cd.name, cd.notes, cd.type_fields))
            .map_err(|_| AppError::Internal)?;
        stmts.extend(
            crate::models::cipher::create_cipher_stmts(
                &db,
                &id,
                &claims.sub,
                Some(&org_id),
                r#type,
                &blob,
                None,
                false,
                None,
                &now,
                &now,
            )
            .map_err(|_| AppError::Database)?,
        );
        ciphers.push(id);
    }
    for rel in data.collection_relationships {
        let (Some(cid), Some(col)) = (ciphers.get(rel.key), collections.get(rel.value)) else {
            return Err(AppError::BadRequest(
                "Invalid collection relationship".into(),
            ));
        };
        stmts.push(
            d1_query!(
                &db,
                "INSERT OR IGNORE INTO ciphers_collections (cipher_uuid, collection_uuid) VALUES (?1, ?2)",
                cid,
                col
            )
            .map_err(|_| AppError::Database)?,
        );
    }
    db::execute_in_batches(&db, stmts, crate::handlers::get_batch_size(&env)).await?;
    let audience = crate::models::org_access::cipher_audience(&db, &ciphers, &claims.sub).await?;
    crate::models::org_access::notify_audience(env.as_ref(), &db, audience, &now).await?;
    db::touch_user_updated_at(&db, &claims.sub, &now).await?;
    notifications::publish_user_update(
        (*env).clone(),
        claims.sub,
        UpdateType::SyncVault,
        now,
        Some(claims.device),
    );
    Ok(Json(()))
}
