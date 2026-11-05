use crate::d1_query;
use crate::error::AppError;
use chrono::Utc;
use worker::{D1Database, D1DatabaseSession, D1PreparedStatement, D1Result, Env, Error};

/// Unified database handle that wraps either a raw `D1Database` or a `D1DatabaseSession`.
///
/// When read replication is enabled, all queries go through a session to benefit from
/// sequential consistency and reduced read latency via global replicas.
pub enum Db {
    #[allow(dead_code)]
    Raw(D1Database),
    Session(D1DatabaseSession),
}

impl Db {
    pub fn prepare<T: Into<String>>(&self, query: T) -> D1PreparedStatement {
        match self {
            Db::Raw(db) => db.prepare(query),
            Db::Session(s) => s.prepare(query),
        }
    }

    pub async fn batch(
        &self,
        statements: Vec<D1PreparedStatement>,
    ) -> Result<Vec<D1Result>, Error> {
        match self {
            Db::Raw(db) => db.batch(statements).await,
            Db::Session(s) => s.batch(statements).await,
        }
    }
}

/// Obtain a session-backed database handle for business logic.
///
/// Uses `first-primary` so the first query hits the primary database, ensuring freshness.
/// This prevents stale reads when another device fetches data immediately after a write
/// triggered a WebSocket notification.
pub fn get_db(env: &Env) -> Result<Db, AppError> {
    let raw = env.d1("vault1").map_err(AppError::Worker)?;
    let session = raw
        .with_session(Some("first-primary"))
        .map_err(AppError::Worker)?;
    Ok(Db::Session(session))
}

/// Obtain a session-backed database handle optimized for read-only paths (e.g. auth).
///
/// Uses `first-unconstrained` so the first read may hit any replica (lowest latency).
/// Suitable when there is no preceding write that must be immediately visible.
pub fn get_db_unconstrained(env: &Env) -> Result<Db, AppError> {
    let raw = env.d1("vault1").map_err(AppError::Worker)?;
    let session = raw.with_session(None).map_err(AppError::Worker)?;
    Ok(Db::Session(session))
}

/// Obtain a raw (non-session) database handle — only for cases that cannot use sessions.
#[allow(dead_code)]
pub fn get_db_raw(env: &Env) -> Result<D1Database, AppError> {
    env.d1("vault1").map_err(AppError::Worker)
}

/// Map D1 JSON parsing errors to 400 while leaving other errors untouched.
pub fn map_d1_json_error(err: Error) -> AppError {
    let msg = err.to_string();
    if msg.to_ascii_lowercase().contains("malformed json") {
        AppError::BadRequest("Malformed JSON in request body".to_string())
    } else {
        AppError::Worker(err)
    }
}

pub fn now_string() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// This is a helper function to update the user's `updated_at` field.
/// `now` is the current timestamp in the format "YYYY-MM-DDTHH:MM:SS.SSSZ".
/// This should be called after any operation that modifies user data (ciphers, folders, etc.)
pub async fn touch_user_updated_at(db: &Db, user_id: &str, now: &str) -> Result<(), AppError> {
    d1_query!(
        db,
        "UPDATE users SET updated_at = ?1 WHERE uuid = ?2",
        now,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    Ok(())
}

/// Child tables that reference `ciphers(uuid)` without ON DELETE CASCADE (vaultwarden schema).
/// `(table, column)` pairs.
const CIPHER_CHILD_TABLES: &[(&str, &str)] = &[
    ("attachments", "cipher_uuid"),
    ("attachments_pending", "cipher_id"),
    ("folders_ciphers", "cipher_uuid"),
    ("favorites", "cipher_uuid"),
    ("archives", "cipher_uuid"),
    ("ciphers_collections", "cipher_uuid"),
];

/// Statements that delete the ciphers matching `cond` (SQL over `ciphers` columns, using
/// `?1..?n` placeholders) together with their child rows, children first. D1 enforces foreign
/// keys and the vaultwarden schema has no cascades, so callers must use this instead of a bare
/// `DELETE FROM ciphers`. Run the result with `db.batch(...)` (atomic).
///
/// `cond` must not depend on child rows (e.g. the `org_access` CTEs read
/// `ciphers_collections`, which is deleted first): resolve such ids beforehand.
pub fn delete_ciphers_statements(
    db: &Db,
    cond: &str,
    binds: &[wasm_bindgen::JsValue],
) -> Result<Vec<D1PreparedStatement>, Error> {
    let mut out = Vec::with_capacity(CIPHER_CHILD_TABLES.len() + 1);
    for (table, column) in CIPHER_CHILD_TABLES {
        out.push(
            db.prepare(format!(
                "DELETE FROM {table} WHERE {column} IN (SELECT uuid FROM ciphers WHERE {cond})"
            ))
            .bind(binds)?,
        );
    }
    out.push(
        db.prepare(format!("DELETE FROM ciphers WHERE {cond}"))
            .bind(binds)?,
    );
    Ok(out)
}

/// Delete a user and every row that references it (vaultwarden schema, no cascades).
/// Storage objects (R2/KV) must be removed by the caller beforehand.
pub async fn delete_user_rows(db: &Db, user_id: &str) -> Result<(), AppError> {
    let uid: wasm_bindgen::JsValue = user_id.into();
    let binds = [uid.clone()];
    let mut stmts = delete_ciphers_statements(db, "user_uuid = ?1", &binds)?;
    for sql in [
        "DELETE FROM folders_ciphers WHERE folder_uuid IN (SELECT uuid FROM folders WHERE user_uuid = ?1)",
        "DELETE FROM favorites WHERE user_uuid = ?1",
        "DELETE FROM archives WHERE user_uuid = ?1",
        "DELETE FROM folders WHERE user_uuid = ?1",
        "DELETE FROM sends_pending WHERE user_id = ?1",
        "DELETE FROM sends WHERE user_uuid = ?1",
        "DELETE FROM auth_requests WHERE user_uuid = ?1",
        "DELETE FROM devices WHERE user_uuid = ?1",
        "DELETE FROM twofactor WHERE user_uuid = ?1",
        "DELETE FROM twofactor_incomplete WHERE user_uuid = ?1",
        "DELETE FROM emergency_access WHERE grantor_uuid = ?1 OR grantee_uuid = ?1",
        "DELETE FROM users_collections WHERE user_uuid = ?1",
        "DELETE FROM groups_users WHERE users_organizations_uuid IN (SELECT uuid FROM users_organizations WHERE user_uuid = ?1)",
        "DELETE FROM users_organizations WHERE user_uuid = ?1",
        "DELETE FROM sso_users WHERE user_uuid = ?1",
        "DELETE FROM users WHERE uuid = ?1",
    ] {
        stmts.push(db.prepare(sql).bind(&binds)?);
    }
    db.batch(stmts).await?;
    Ok(())
}

/// Execute D1 statements in batches, allowing batch_size 0 to run everything at once.
pub async fn execute_in_batches(
    db: &Db,
    statements: Vec<D1PreparedStatement>,
    batch_size: usize,
) -> Result<(), AppError> {
    if statements.is_empty() {
        return Ok(());
    }

    if batch_size == 0 {
        db.batch(statements).await?;
    } else {
        for chunk in statements.chunks(batch_size) {
            db.batch(chunk.to_vec()).await?;
        }
    }

    Ok(())
}

/// Replacement for `worker::query!` that works with our `Db` enum (and any type with `.prepare()`).
#[macro_export]
macro_rules! d1_query {
    ($db:expr, $query:expr) => {
        $db.prepare($query)
    };
    ($db:expr, $query:expr, $($args:expr),* $(,)?) => {{
        || -> worker::Result<worker::d1::D1PreparedStatement> {
            let prepared = $db.prepare($query);
            let serializer = worker::d1::serde_wasm_bindgen::Serializer::new()
                .serialize_missing_as_null(true);
            let bindings = &[$(
                ::serde::ser::Serialize::serialize(&$args, &serializer)
                    .map_err(|e| worker::Error::Internal(e.into()))?
            ),*];
            worker::d1::D1PreparedStatement::bind(prepared, bindings)
        }()
    }};
}
