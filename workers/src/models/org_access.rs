//! Per-user access to organization data, mirroring vaultwarden's rules
//! (`Cipher::get_access_restrictions`, `Collection::to_json_details`, `Membership::has_full_access`).
//!
//! The SQL fragments below are common table expressions parameterized by the placeholder of
//! the requesting user's uuid (e.g. `"?1"`). Combine them with [`with_access`].
//!
//! - `mem`: the user's *confirmed* memberships.
//! - `access`: every cipher the user can see, with effective `read_only`, `hide_passwords`
//!   and `manage` flags. Personal ciphers and ciphers in a full-access org/group have no
//!   restrictions; otherwise flags are AND-ed (read_only, hide_passwords) or OR-ed (manage)
//!   across the collections the cipher is in. User collection permissions override group ones.
//! - `ucol`: every collection the user can see, with the flags vaultwarden reports in sync.

/// Membership types as stored in `users_organizations.atype`.
pub mod membership_type {
    pub const OWNER: i32 = 0;
    pub const ADMIN: i32 = 1;
    pub const USER: i32 = 2;
    pub const MANAGER: i32 = 3;
    pub const CUSTOM: i32 = 4;
}

/// Membership statuses as stored in `users_organizations.status`.
pub mod membership_status {
    #[allow(dead_code)]
    pub const REVOKED: i32 = -1;
    pub const INVITED: i32 = 0;
    #[allow(dead_code)]
    pub const ACCEPTED: i32 = 1;
    pub const CONFIRMED: i32 = 2;
}

/// `mem` CTE: confirmed memberships of user `u`.
pub fn mem_cte(u: &str) -> String {
    format!(
        "mem AS (SELECT uuid AS mem_uuid, org_uuid, atype, access_all FROM users_organizations \
         WHERE user_uuid = {u} AND status = 2)"
    )
}

/// `access` CTE (requires `mem`).
pub fn access_cte(u: &str) -> String {
    format!(
        "acc AS (
            SELECT uuid AS cipher_uuid, 0 AS ro, 0 AS hp, 1 AS mg, 1 AS full FROM ciphers WHERE user_uuid = {u}
            UNION ALL
            SELECT c.uuid, 0, 0, 1, 1 FROM ciphers c JOIN mem m ON m.org_uuid = c.organization_uuid
              WHERE m.atype IN (0, 1) OR m.access_all = 1
            UNION ALL
            SELECT c.uuid, 0, 0, 1, 1 FROM ciphers c JOIN mem m ON m.org_uuid = c.organization_uuid
              JOIN groups_users gu ON gu.users_organizations_uuid = m.mem_uuid
              JOIN groups g ON g.uuid = gu.groups_uuid AND g.access_all = 1
            UNION ALL
            SELECT cc.cipher_uuid, uc.read_only, uc.hide_passwords, uc.manage, 0
              FROM users_collections uc
              JOIN collections co ON co.uuid = uc.collection_uuid
              JOIN mem m ON m.org_uuid = co.org_uuid
              JOIN ciphers_collections cc ON cc.collection_uuid = uc.collection_uuid
              WHERE uc.user_uuid = {u}
            UNION ALL
            SELECT cc.cipher_uuid, cg.read_only, cg.hide_passwords, cg.manage, 0
              FROM mem m
              JOIN groups_users gu ON gu.users_organizations_uuid = m.mem_uuid
              JOIN collections_groups cg ON cg.groups_uuid = gu.groups_uuid
              JOIN ciphers_collections cc ON cc.collection_uuid = cg.collections_uuid
              WHERE NOT EXISTS (SELECT 1 FROM users_collections uc2
                                WHERE uc2.collection_uuid = cg.collections_uuid AND uc2.user_uuid = {u})
        ),
        access AS (
            SELECT cipher_uuid,
                   CASE WHEN MAX(full) = 1 THEN 0 ELSE MIN(ro) END AS read_only,
                   CASE WHEN MAX(full) = 1 THEN 0 ELSE MIN(hp) END AS hide_passwords,
                   CASE WHEN MAX(full) = 1 THEN 1 ELSE MAX(mg) END AS manage
            FROM acc GROUP BY cipher_uuid
        )"
    )
}

/// `ucol` CTE (requires `mem`): collections visible to user `u` with sync flags.
pub fn ucol_cte(u: &str) -> String {
    format!(
        "ucol_raw AS (
            SELECT co.uuid AS collection_uuid, 0 AS ro, 0 AS hp,
                   CASE WHEN m.atype IN (0, 1, 3) THEN 1 ELSE 0 END AS mg, 1 AS full
              FROM collections co JOIN mem m ON m.org_uuid = co.org_uuid
              WHERE m.atype IN (0, 1) OR m.access_all = 1
            UNION ALL
            SELECT co.uuid, 0, 0, CASE WHEN m.atype = 3 THEN 1 ELSE 0 END, 1
              FROM collections co JOIN mem m ON m.org_uuid = co.org_uuid
              JOIN groups_users gu ON gu.users_organizations_uuid = m.mem_uuid
              JOIN groups g ON g.uuid = gu.groups_uuid AND g.access_all = 1
            UNION ALL
            SELECT uc.collection_uuid, uc.read_only, uc.hide_passwords,
                   CASE WHEN m.atype = 3 AND (uc.manage = 1 OR (uc.read_only = 0 AND uc.hide_passwords = 0)) THEN 1 ELSE 0 END, 0
              FROM users_collections uc
              JOIN collections co ON co.uuid = uc.collection_uuid
              JOIN mem m ON m.org_uuid = co.org_uuid
              WHERE uc.user_uuid = {u}
            UNION ALL
            SELECT cg.collections_uuid, cg.read_only, cg.hide_passwords,
                   CASE WHEN m.atype = 3 AND (cg.manage = 1 OR (cg.read_only = 0 AND cg.hide_passwords = 0)) THEN 1 ELSE 0 END, 0
              FROM mem m
              JOIN groups_users gu ON gu.users_organizations_uuid = m.mem_uuid
              JOIN collections_groups cg ON cg.groups_uuid = gu.groups_uuid
              WHERE NOT EXISTS (SELECT 1 FROM users_collections uc2
                                WHERE uc2.collection_uuid = cg.collections_uuid AND uc2.user_uuid = {u})
        ),
        ucol AS (
            SELECT collection_uuid,
                   CASE WHEN MAX(full) = 1 THEN 0 ELSE MIN(ro) END AS read_only,
                   CASE WHEN MAX(full) = 1 THEN 0 ELSE MIN(hp) END AS hide_passwords,
                   MAX(mg) AS manage
            FROM ucol_raw GROUP BY collection_uuid
        )"
    )
}

/// Condition on `ciphers.uuid`: the requesting user may modify/delete the cipher
/// (vaultwarden `is_write_accessible_to_user`). Requires [`with_access`].
pub const WRITABLE: &str = "uuid IN (SELECT cipher_uuid FROM access WHERE read_only = 0)";

/// Condition on `ciphers.uuid`: the requesting user can see the cipher. Requires [`with_access`].
pub const VISIBLE: &str = "uuid IN (SELECT cipher_uuid FROM access)";

/// `WITH mem, access, ucol` prefix for a query run on behalf of user placeholder `u`.
pub fn with_access(u: &str) -> String {
    format!("WITH {}, {}, {} ", mem_cte(u), access_cte(u), ucol_cte(u))
}

/// User ids (confirmed members) who can see any of the organization ciphers whose uuids are in
/// the JSON array bound to `?1` (vaultwarden `Cipher::update_users_revision` audience).
/// Personal ciphers yield no rows; the acting user is filtered out by the caller.
pub const CIPHER_AUDIENCE_SQL: &str = "SELECT DISTINCT uo.user_uuid FROM ciphers c
     JOIN users_organizations uo ON uo.org_uuid = c.organization_uuid AND uo.status = 2
     WHERE c.uuid IN (SELECT value FROM json_each(?1))
       AND (uo.atype IN (0, 1) OR uo.access_all = 1
            OR EXISTS (SELECT 1 FROM users_collections uc JOIN ciphers_collections cc ON cc.collection_uuid = uc.collection_uuid
                       WHERE uc.user_uuid = uo.user_uuid AND cc.cipher_uuid = c.uuid)
            OR EXISTS (SELECT 1 FROM groups_users gu JOIN groups g ON g.uuid = gu.groups_uuid
                       WHERE gu.users_organizations_uuid = uo.uuid AND g.access_all = 1)
            OR EXISTS (SELECT 1 FROM groups_users gu JOIN collections_groups cg ON cg.groups_uuid = gu.groups_uuid
                       JOIN ciphers_collections cc ON cc.collection_uuid = cg.collections_uuid
                       WHERE gu.users_organizations_uuid = uo.uuid AND cc.cipher_uuid = c.uuid))";

/// Other users (not `acting_user`) who can see any of `cipher_ids` (org ciphers only).
pub async fn cipher_audience(
    db: &crate::db::Db,
    cipher_ids: &[String],
    acting_user: &str,
) -> Result<Vec<String>, crate::error::AppError> {
    #[derive(serde::Deserialize)]
    struct Row {
        user_uuid: String,
    }
    if cipher_ids.is_empty() {
        return Ok(Vec::new());
    }
    let ids = serde_json::to_string(cipher_ids).map_err(|_| crate::error::AppError::Internal)?;
    let rows: Vec<Row> = db
        .prepare(CIPHER_AUDIENCE_SQL)
        .bind(&[ids.into()])?
        .all()
        .await?
        .results()?;
    Ok(rows
        .into_iter()
        .map(|r| r.user_uuid)
        .filter(|u| u != acting_user)
        .collect())
}

/// Bump `users.updated_at` for `users` so their next sync picks up org changes.
pub async fn touch_users(
    db: &crate::db::Db,
    users: &[String],
    now: &str,
) -> Result<(), crate::error::AppError> {
    if users.is_empty() {
        return Ok(());
    }
    let ids = serde_json::to_string(users).map_err(|_| crate::error::AppError::Internal)?;
    crate::d1_query!(
        db,
        "UPDATE users SET updated_at = ?1 WHERE uuid IN (SELECT value FROM json_each(?2))",
        now,
        ids
    )?
    .run()
    .await?;
    Ok(())
}

/// Touch and notify every other user who can see `cipher_ids`: one `SyncCiphers` user update
/// each (clients re-sync). `audience` must be computed before a hard delete.
pub async fn notify_audience(
    env: &worker::Env,
    db: &crate::db::Db,
    audience: Vec<String>,
    now: &str,
) -> Result<(), crate::error::AppError> {
    touch_users(db, &audience, now).await?;
    for user in audience {
        crate::notifications::publish_user_update(
            env.clone(),
            user,
            crate::notifications::UpdateType::SyncCiphers,
            now.to_string(),
            None,
        );
    }
    Ok(())
}
