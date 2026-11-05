use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use chrono::{Duration, NaiveDateTime, Utc};

use crate::d1_query;
use crate::{crypto::ct_eq, db, error::AppError, models::device::DeviceType};

pub const AUTH_REQUEST_EXPIRY_MINUTES: i64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub id: String,
    pub user_id: String,
    pub request_device_identifier: String,
    pub device_type: i32,
    pub request_ip: String,
    pub response_device_id: Option<String>,
    pub access_code: String,
    pub public_key: String,
    pub enc_key: Option<String>,
    pub master_password_hash: Option<String>,
    pub approved: Option<i32>,
    pub creation_date: String,
    pub response_date: Option<String>,
    pub authentication_date: Option<String>,
}

impl AuthRequest {
    pub fn new(
        user_id: String,
        request_device_identifier: String,
        device_type: i32,
        request_ip: String,
        access_code: String,
        public_key: String,
    ) -> Self {
        let now = db::now_string();

        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            request_device_identifier,
            device_type,
            request_ip,
            response_device_id: None,
            access_code,
            public_key,
            enc_key: None,
            master_password_hash: None,
            approved: None,
            creation_date: now,
            response_date: None,
            authentication_date: None,
        }
    }

    pub fn to_json(&self, origin: &str) -> Value {
        json!({
            "id": self.id,
            "publicKey": self.public_key,
            "requestDeviceType": DeviceType::from_i32(self.device_type).display_name(),
            "requestIpAddress": self.request_ip,
            "key": self.enc_key,
            "masterPasswordHash": self.master_password_hash,
            "creationDate": self.creation_date,
            "responseDate": self.response_date,
            "requestApproved": self.request_approved_value(),
            "origin": origin,
            "object": "auth-request",
        })
    }

    pub fn to_pending_device_json(&self) -> Value {
        json!({
            "id": self.id,
            "creationDate": self.creation_date,
        })
    }

    pub fn request_approved_value(&self) -> Value {
        match self.approved {
            // bitwarden/server will map null to false, but Vaultwarden won't.
            Some(1) => Value::Bool(true),
            _ => Value::Bool(false),
        }
    }

    pub fn is_approved(&self) -> bool {
        self.approved == Some(1)
    }

    pub fn set_approved(&mut self, approved: bool) {
        self.approved = Some(if approved { 1 } else { 0 });
    }

    pub fn check_access_code(&self, access_code: &str) -> bool {
        ct_eq(&self.access_code, access_code)
    }

    /// Whether this auth request has expired (creation_date + EXPIRY_MINUTES has passed).
    pub fn is_expired(&self) -> bool {
        let Ok(created) =
            NaiveDateTime::parse_from_str(&self.creation_date, "%Y-%m-%dT%H:%M:%S%.3fZ")
        else {
            return true; // unparseable date → treat as expired
        };
        let created_utc = created.and_utc();
        Utc::now() >= created_utc + Duration::minutes(AUTH_REQUEST_EXPIRY_MINUTES)
    }

    pub async fn insert(&self, db: &crate::db::Db) -> Result<(), AppError> {
        d1_query!(
            db,
            "INSERT INTO auth_requests (id, user_id, request_device_identifier, device_type, request_ip, response_device_id, access_code, public_key, enc_key, master_password_hash, approved, creation_date, response_date, authentication_date)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            &self.id,
            &self.user_id,
            &self.request_device_identifier,
            self.device_type,
            &self.request_ip,
            self.response_device_id.as_deref(),
            &self.access_code,
            &self.public_key,
            self.enc_key.as_deref(),
            self.master_password_hash.as_deref(),
            self.approved,
            &self.creation_date,
            self.response_date.as_deref(),
            self.authentication_date.as_deref()
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        Ok(())
    }

    // Only update fields that change after creation (approval/response).
    // Immutable fields (user_id, request_device_identifier, device_type, request_ip,
    // access_code, public_key, creation_date) are excluded.
    pub async fn update(&self, db: &crate::db::Db) -> Result<(), AppError> {
        d1_query!(
            db,
            "UPDATE auth_requests
             SET response_device_id = ?1,
                 enc_key = ?2,
                 master_password_hash = ?3,
                 approved = ?4,
                 response_date = ?5,
                 authentication_date = ?6
             WHERE id = ?7",
            self.response_device_id.as_deref(),
            self.enc_key.as_deref(),
            self.master_password_hash.as_deref(),
            self.approved,
            self.response_date.as_deref(),
            self.authentication_date.as_deref(),
            &self.id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        Ok(())
    }

    pub async fn delete(&self, db: &crate::db::Db) -> Result<(), AppError> {
        d1_query!(db, "DELETE FROM auth_requests WHERE id = ?1", &self.id)
            .map_err(|_| AppError::Database)?
            .run()
            .await
            .map_err(|_| AppError::Database)?;

        Ok(())
    }

    pub async fn find_by_id(db: &crate::db::Db, id: &str) -> Result<Option<Self>, AppError> {
        let row: Option<Value> = d1_query!(db, "SELECT * FROM auth_requests WHERE id = ?1", id)
            .map_err(|_| AppError::Database)?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;

        row.map(|row| serde_json::from_value(row).map_err(|_| AppError::Internal))
            .transpose()
    }

    pub async fn find_by_id_and_user(
        db: &crate::db::Db,
        id: &str,
        user_id: &str,
    ) -> Result<Option<Self>, AppError> {
        let row: Option<Value> = d1_query!(
            db,
            "SELECT * FROM auth_requests WHERE id = ?1 AND user_id = ?2",
            id,
            user_id
        )
        .map_err(|_| AppError::Database)?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

        row.map(|row| serde_json::from_value(row).map_err(|_| AppError::Internal))
            .transpose()
    }

    pub async fn list_pending_by_user(
        db: &crate::db::Db,
        user_id: &str,
    ) -> Result<Vec<Self>, AppError> {
        let cutoff = (Utc::now() - Duration::minutes(AUTH_REQUEST_EXPIRY_MINUTES))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let rows: Vec<Value> = d1_query!(
            db,
            "SELECT * FROM auth_requests
             WHERE user_id = ?1 AND approved IS NULL AND creation_date > ?2
             ORDER BY creation_date DESC",
            user_id,
            &cutoff
        )
        .map_err(|_| AppError::Database)?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

        rows.into_iter()
            .map(|row| serde_json::from_value(row).map_err(|_| AppError::Internal))
            .collect()
    }

    pub async fn delete_created_before(db: &crate::db::Db, cutoff: &str) -> Result<u32, AppError> {
        let result = d1_query!(
            db,
            "DELETE FROM auth_requests WHERE creation_date < ?1",
            cutoff
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        let changes = result
            .meta()
            .map_err(|_| AppError::Database)?
            .and_then(|m| m.changes)
            .unwrap_or(0) as u32;

        Ok(changes)
    }
}
