//! Purge handler for cleaning up soft-deleted ciphers
//!
//! This module handles the automatic cleanup of ciphers that have been
//! soft-deleted (marked with deleted_at) for longer than the configured
//! retention period.

use crate::db::now_string;
use crate::handlers::attachments::{
    attachments_enabled, delete_storage_objects, list_attachment_keys_for_soft_deleted_before,
};
use crate::models::auth_request::AuthRequest;
use crate::models::send::SendDB;
use crate::notifications::{self, UpdateType};
use chrono::{Duration, Utc};

use std::collections::HashSet;
use worker::Env;

use crate::d1_query;
/// Default number of days to keep soft-deleted items before purging
const DEFAULT_PURGE_DAYS: i64 = 30;
/// Retain pending attachments for at most this many days before cleanup
const PENDING_RETENTION_DAYS: i64 = 1;
/// Retain auth requests for at most this many minutes before cleanup
const AUTH_REQUEST_RETENTION_MINUTES: i64 = 15;

/// Get the purge threshold days from environment variable or use default
fn get_purge_days(env: &Env) -> i64 {
    env.var("TRASH_AUTO_DELETE_DAYS")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(DEFAULT_PURGE_DAYS)
}

/// Purge pending attachments older than the configured retention window.
pub async fn purge_stale_pending_attachments(env: &Env) -> Result<u32, worker::Error> {
    let db = crate::db::get_db(env).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let now = Utc::now();
    let pending_cutoff = now - Duration::days(PENDING_RETENTION_DAYS);
    let pending_cutoff_str = pending_cutoff.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let pending_count_result = d1_query!(
        &db,
        "SELECT COUNT(*) as count FROM attachments_pending WHERE created_at < ?1",
        pending_cutoff_str
    )
    .map_err(|e| worker::Error::RustError(e.to_string()))?
    .first::<CountResult>(None)
    .await?;

    let pending_count = pending_count_result.map(|r| r.count).unwrap_or(0);

    if pending_count > 0 {
        d1_query!(
            &db,
            "DELETE FROM attachments_pending WHERE created_at < ?1",
            pending_cutoff_str
        )
        .map_err(|e| worker::Error::RustError(e.to_string()))?
        .run()
        .await?;
        log::info!(
            "Purged {} pending attachment(s) older than {} day(s)",
            pending_count,
            PENDING_RETENTION_DAYS
        );
    } else {
        log::info!("No pending attachments to purge");
    }

    Ok(pending_count)
}

/// Purge soft-deleted ciphers that are older than the configured threshold.
///
/// This function:
/// 1. Calculates the cutoff timestamp based on TRASH_AUTO_DELETE_DAYS env var (default: 30 days)
/// 2. Deletes all ciphers where deleted_at is not null and older than the cutoff
/// 3. Updates the affected users' updated_at to trigger client sync
/// 4. If TRASH_AUTO_DELETE_DAYS is set to 0 or negative, skips purging (disabled)
///
/// Returns the number of purged records on success.
pub async fn purge_deleted_ciphers(env: &Env) -> Result<u32, worker::Error> {
    let purge_days = get_purge_days(env);

    // If purge_days is 0 or negative, auto-purge is disabled
    if purge_days <= 0 {
        log::info!("Auto-purge is disabled (TRASH_AUTO_DELETE_DAYS <= 0)");
        return Ok(0);
    }

    let db = crate::db::get_db(env).map_err(|e| worker::Error::RustError(e.to_string()))?;

    // Calculate the cutoff timestamp
    let now = Utc::now();
    let cutoff = now - Duration::days(purge_days);
    let cutoff_str = cutoff.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    log::info!(
        "Purging soft-deleted ciphers older than {} days (before {})",
        purge_days,
        cutoff_str
    );

    // First, get the list of affected user IDs before deletion
    let affected_users_result: Vec<AffectedUser> = d1_query!(
        &db,
        "SELECT DISTINCT user_id FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1 AND user_id IS NOT NULL",
        cutoff_str
    )
    .map_err(|e| worker::Error::RustError(e.to_string()))?
    .all()
    .await?
    .results()?;

    let affected_user_ids: HashSet<String> = affected_users_result
        .into_iter()
        .filter_map(|u| u.user_id)
        .collect();

    // Count the records to be deleted (for logging purposes)
    let count_result = d1_query!(
        &db,
        "SELECT COUNT(*) as count FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
        cutoff_str
    )
    .map_err(|e| worker::Error::RustError(e.to_string()))?
    .first::<CountResult>(None)
    .await?;

    let count = count_result.map(|r| r.count).unwrap_or(0);

    if count > 0 {
        if attachments_enabled(env) {
            let keys = list_attachment_keys_for_soft_deleted_before(&db, &cutoff_str)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            delete_storage_objects(env, &keys)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
        }

        // Delete the records
        d1_query!(
            &db,
            "DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
            cutoff_str
        )
        .map_err(|e| worker::Error::RustError(e.to_string()))?
        .run()
        .await?;

        log::info!("Successfully purged {} soft-deleted cipher(s)", count);

        // Update the affected users' updated_at to trigger client sync
        for user_id in &affected_user_ids {
            d1_query!(
                &db,
                "UPDATE users SET updated_at = ?1 WHERE id = ?2",
                now_str,
                user_id
            )
            .map_err(|e| worker::Error::RustError(e.to_string()))?
            .run()
            .await?;

            notifications::publish_user_update(
                env.clone(),
                user_id.clone(),
                UpdateType::SyncVault,
                now_str.clone(),
                None,
            );
        }

        log::info!(
            "Updated revision date for {} affected user(s)",
            affected_user_ids.len()
        );
    } else {
        log::info!("No soft-deleted ciphers to purge");
    }

    Ok(count)
}

pub async fn purge_expired_sends(env: &Env) -> Result<u32, worker::Error> {
    let db = crate::db::get_db(env).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let now = now_string();

    let expired = SendDB::find_expired(&db)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    if expired.is_empty() {
        log::info!("No expired sends to purge");
        return Ok(0);
    }

    let count = expired.len() as u32;

    if attachments_enabled(env) {
        let keys: Vec<String> = expired.iter().filter_map(|s| s.storage_key()).collect();
        if !keys.is_empty() {
            delete_storage_objects(env, &keys)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
        }
    }

    let mut user_ids = std::collections::HashSet::new();
    for send in &expired {
        user_ids.insert(send.user_id.clone());
    }

    for send in &expired {
        send.delete(&db)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
    }

    for uid in &user_ids {
        let _ = db
            .prepare("UPDATE users SET updated_at = ?1 WHERE id = ?2")
            .bind(&[now.clone().into(), uid.clone().into()])
            .map_err(|e| worker::Error::RustError(e.to_string()))?
            .run()
            .await;
    }

    log::info!("Purged {} expired send(s)", count);
    Ok(count)
}

pub async fn purge_expired_auth_requests(env: &Env) -> Result<u32, worker::Error> {
    let db = crate::db::get_db(env).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let cutoff = (Utc::now() - Duration::minutes(AUTH_REQUEST_RETENTION_MINUTES))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let count = AuthRequest::delete_created_before(&db, &cutoff)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    if count > 0 {
        log::info!(
            "Purged {} auth request(s) older than {} minute(s)",
            count,
            AUTH_REQUEST_RETENTION_MINUTES
        );
    } else {
        log::info!("No expired auth requests to purge");
    }

    Ok(count)
}

pub async fn purge_stale_pending_sends(env: &Env) -> Result<u32, worker::Error> {
    let db = crate::db::get_db(env).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let cutoff = (Utc::now() - chrono::Duration::days(1))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    if attachments_enabled(env) {
        let stale = SendDB::find_stale_pending(&db, &cutoff)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        let keys: Vec<String> = stale.iter().filter_map(|p| p.storage_key()).collect();
        if !keys.is_empty() {
            delete_storage_objects(env, &keys)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
        }
    }

    let count = SendDB::delete_stale_pending(&db, &cutoff)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;

    if count > 0 {
        log::info!("Purged {} stale pending send(s)", count);
    } else {
        log::info!("No stale pending sends to purge");
    }

    Ok(count)
}

/// Helper struct for affected user query result
#[derive(serde::Deserialize)]
struct AffectedUser {
    user_id: Option<String>,
}

/// Helper struct for count query result
#[derive(serde::Deserialize)]
struct CountResult {
    count: u32,
}
