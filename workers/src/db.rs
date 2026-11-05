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
        "UPDATE users SET updated_at = ?1 WHERE id = ?2",
        now,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
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
