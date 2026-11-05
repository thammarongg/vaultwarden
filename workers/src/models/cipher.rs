use std::collections::HashMap;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Map, Value};

use crate::models::attachment::AttachmentResponse;

// Cipher types:
//   Login = 1,
//   SecureNote = 2,
//   Card = 3,
//   Identity = 4,
//   SshKey = 5,
//   BankAccount = 6,
//   DriversLicense = 7,
//   Passport = 8

/// Common cipher type-specific fields shared across multiple cipher structures.
/// These represent the encrypted content fields that vary based on cipher type.
/// Used with `#[serde(flatten)]` to embed these fields into other structs.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CipherTypeFields {
    // Only one of these should exist, depending on cipher type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_account: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drivers_license: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passport: Option<Value>,
    // Common fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reprompt: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// This struct represents the data stored in the `data` column of the `ciphers` table.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherData {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(flatten)]
    pub type_fields: CipherTypeFields,
}

impl CipherTypeFields {
    fn normalize_for_storage(mut self) -> Self {
        self.password_history = {
            match self.password_history {
                Some(Value::Array(entries)) => Some(Value::Array(
                    entries
                        .into_iter()
                        .filter_map(normalize_password_history_entry)
                        .collect(),
                )),
                Some(_) => Some(Value::Array(Vec::new())),
                None => None,
            }
        };
        self
    }
}

impl CipherData {
    pub fn new(name: String, notes: Option<String>, type_fields: CipherTypeFields) -> Self {
        Self {
            name,
            notes,
            type_fields: type_fields.normalize_for_storage(),
        }
    }
}

fn normalize_password_history_entry(entry: Value) -> Option<Value> {
    match entry {
        Value::Object(map) if matches!(map.get("password"), Some(Value::String(_))) => {
            Some(Value::Object(map))
        }
        _ => None,
    }
}

// Custom deserialization function for booleans
fn deserialize_bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    // A visitor is used to handle different data types
    struct BoolOrIntVisitor;

    impl<'de> de::Visitor<'de> for BoolOrIntVisitor {
        type Value = bool;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a boolean or an integer 0 or 1")
        }

        // Handles boolean values
        fn visit_bool<E>(self, value: bool) -> Result<bool, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        // Handles integer values (0 or 1)
        fn visit_u64<E>(self, value: u64) -> Result<bool, E>
        where
            E: de::Error,
        {
            match value {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(de::Error::invalid_value(
                    de::Unexpected::Unsigned(value),
                    &"0 or 1",
                )),
            }
        }
    }

    deserializer.deserialize_any(BoolOrIntVisitor)
}

// Custom deserialization function for cipher types
fn deserialize_cipher_type<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = i32::deserialize(deserializer)?;
    match value {
        1..=8 => Ok(value), // Valid cipher types: Login, SecureNote, Card, Identity, SshKey, BankAccount, DriversLicense, Passport
        _ => Err(de::Error::invalid_value(
            de::Unexpected::Signed(value as i64),
            &"a valid cipher type (1=Login, 2=SecureNote, 3=Card, 4=Identity, 5=SshKey, 6=BankAccount, 7=DriversLicense, 8=Passport)",
        )),
    }
}

// The struct that is stored in the database and used in handlers.
// For serialization to JSON for the client, we implement a custom `Serialize`.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i32,
    pub data: Value,
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,

    // Bitwarden specific field for API responses
    #[serde(default = "default_object")]
    pub object: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub organization_use_totp: bool,
    #[serde(default = "default_true")]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub edit: bool,
    #[serde(default = "default_true")]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub view_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attachments: Option<Vec<AttachmentResponse>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CipherDBModel {
    pub id: String,
    /// NULL for organization ciphers.
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub r#type: i32,
    pub data: String,
    pub favorite: i32,
    pub folder_id: Option<String>,
    pub deleted_at: Option<String>,
    pub archived_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Effective access flags for the requesting user (see `org_access`).
    #[serde(default)]
    pub read_only: i32,
    #[serde(default)]
    pub hide_passwords: i32,
    #[serde(default)]
    pub manage: i32,
    /// JSON array of the cipher's collections visible to the requesting user.
    #[serde(default)]
    pub collection_ids: Option<String>,
}

impl CipherDBModel {
    /// SQL returning one `CipherDBModel` row for cipher `?1` as seen by user `?2`
    /// (personal or organization cipher); no row if the user can't see it.
    pub fn select_for_user_sql() -> String {
        format!(
            "{}SELECT w.id, w.user_id, w.organization_id, w.type, w.data,
                    EXISTS (SELECT 1 FROM favorites f WHERE f.cipher_uuid = w.id AND f.user_uuid = ?2) AS favorite,
                    (SELECT fc.folder_uuid FROM folders_ciphers fc JOIN folders fo ON fo.uuid = fc.folder_uuid
                       WHERE fc.cipher_uuid = w.id AND fo.user_uuid = ?2 LIMIT 1) AS folder_id,
                    w.deleted_at,
                    (SELECT ar.archived_at FROM archives ar WHERE ar.cipher_uuid = w.id AND ar.user_uuid = ?2) AS archived_at,
                    w.created_at, w.updated_at, a.read_only, a.hide_passwords, a.manage,
                    (SELECT json_group_array(cc.collection_uuid) FROM ciphers_collections cc
                       WHERE cc.cipher_uuid = w.id AND cc.collection_uuid IN (SELECT collection_uuid FROM ucol)) AS collection_ids
             FROM wk_ciphers w JOIN access a ON a.cipher_uuid = w.id
             WHERE w.id = ?1",
            crate::models::org_access::with_access("?2")
        )
    }
}

impl From<CipherDBModel> for Cipher {
    fn from(val: CipherDBModel) -> Self {
        let is_org = val.organization_id.is_some();
        let collection_ids = if val.organization_id.is_some() {
            Some(
                val.collection_ids
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                    .unwrap_or_default(),
            )
        } else {
            None
        };
        Cipher {
            id: val.id,
            user_id: val.user_id,
            organization_id: val.organization_id,
            r#type: val.r#type,
            data: serde_json::from_str(&val.data).unwrap_or_default(),
            favorite: val.favorite != 0,
            folder_id: val.folder_id,
            deleted_at: val.deleted_at,
            archived_at: val.archived_at,
            created_at: val.created_at,
            updated_at: val.updated_at,
            object: default_object(),
            organization_use_totp: is_org,
            edit: val.read_only == 0,
            view_password: val.hide_passwords == 0,
            collection_ids,
            attachments: None,
        }
    }
}

impl Serialize for Cipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut response_map = Map::new();

        response_map.insert("object".to_string(), json!(self.object));
        response_map.insert("id".to_string(), json!(self.id));
        if self.user_id.is_some() {
            response_map.insert("userId".to_string(), json!(self.user_id));
        }
        response_map.insert("organizationId".to_string(), json!(self.organization_id));
        response_map.insert("folderId".to_string(), json!(self.folder_id));
        response_map.insert("type".to_string(), json!(self.r#type));
        response_map.insert("favorite".to_string(), json!(self.favorite));
        response_map.insert("edit".to_string(), json!(self.edit));
        response_map.insert("viewPassword".to_string(), json!(self.view_password));
        // new key "permissions" used by clients since v2025.6.0
        response_map.insert(
            "permissions".to_string(),
            json! ({
                "delete": self.edit,   // if edit is true, allow delete
                "restore": self.edit,  // if edit is true, allow restore
            }),
        );
        response_map.insert(
            "organizationUseTotp".to_string(),
            json!(self.organization_use_totp),
        );
        response_map.insert(
            "collectionIds".to_string(),
            json!(&self.collection_ids.as_deref().unwrap_or(&[])),
        );
        response_map.insert("revisionDate".to_string(), json!(self.updated_at));
        response_map.insert("creationDate".to_string(), json!(self.created_at));
        response_map.insert("deletedDate".to_string(), json!(self.deleted_at));
        response_map.insert("archivedDate".to_string(), json!(self.archived_at));
        response_map.insert("attachments".to_string(), json!(self.attachments));

        if let Some(data_obj) = self.data.as_object() {
            let data_clone = data_obj.clone();

            response_map.insert(
                "name".to_string(),
                data_clone.get("name").cloned().unwrap_or(Value::Null),
            );
            response_map.insert(
                "notes".to_string(),
                data_clone.get("notes").cloned().unwrap_or(Value::Null),
            );
            response_map.insert(
                "fields".to_string(),
                data_clone
                    .get("fields")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            );
            response_map.insert(
                "passwordHistory".to_string(),
                data_clone
                    .get("passwordHistory")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            );
            response_map.insert(
                "reprompt".to_string(),
                data_clone
                    .get("reprompt")
                    .cloned()
                    .unwrap_or(Value::Number(serde_json::Number::from_f64(0.0).unwrap())),
            );
            response_map.insert(
                "key".to_string(),
                data_clone.get("key").cloned().unwrap_or(Value::Null),
            );

            let mut login = Value::Null;
            let mut secure_note = Value::Null;
            let mut card = Value::Null;
            let mut identity = Value::Null;
            let mut ssh_key = Value::Null;
            let mut bank_account = Value::Null;
            let mut drivers_license = Value::Null;
            let mut passport = Value::Null;

            match self.r#type {
                1 => login = data_clone.get("login").cloned().unwrap_or(Value::Null),
                2 => secure_note = data_clone.get("secureNote").cloned().unwrap_or(Value::Null),
                3 => card = data_clone.get("card").cloned().unwrap_or(Value::Null),
                4 => identity = data_clone.get("identity").cloned().unwrap_or(Value::Null),
                5 => ssh_key = data_clone.get("sshKey").cloned().unwrap_or(Value::Null),
                6 => {
                    bank_account = data_clone
                        .get("bankAccount")
                        .cloned()
                        .unwrap_or(Value::Null)
                }
                7 => {
                    drivers_license = data_clone
                        .get("driversLicense")
                        .cloned()
                        .unwrap_or(Value::Null)
                }
                8 => passport = data_clone.get("passport").cloned().unwrap_or(Value::Null),
                _ => {}
            }

            response_map.insert("login".to_string(), login);
            response_map.insert("secureNote".to_string(), secure_note);
            response_map.insert("card".to_string(), card);
            response_map.insert("identity".to_string(), identity);
            response_map.insert("sshKey".to_string(), ssh_key);
            response_map.insert("bankAccount".to_string(), bank_account);
            response_map.insert("driversLicense".to_string(), drivers_license);
            response_map.insert("passport".to_string(), passport);
        } else {
            response_map.insert("name".to_string(), Value::Null);
            response_map.insert("notes".to_string(), Value::Null);
            response_map.insert("fields".to_string(), json!([]));
            response_map.insert("passwordHistory".to_string(), json!([]));
            response_map.insert("reprompt".to_string(), Value::Null);
            response_map.insert("login".to_string(), Value::Null);
            response_map.insert("secureNote".to_string(), Value::Null);
            response_map.insert("card".to_string(), Value::Null);
            response_map.insert("identity".to_string(), Value::Null);
            response_map.insert("sshKey".to_string(), Value::Null);
            response_map.insert("bankAccount".to_string(), Value::Null);
            response_map.insert("driversLicense".to_string(), Value::Null);
            response_map.insert("passport".to_string(), Value::Null);
        }

        Value::Object(response_map).serialize(serializer)
    }
}

fn default_object() -> String {
    "cipherDetails".to_string()
}

fn default_true() -> bool {
    true
}

/// Represents the "Cipher" object within incoming request payloads.
/// Used for create, update, import, and key rotation scenarios.
/// Aligned with vaultwarden's CipherData structure.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequestData {
    // Id is optional as it is included only in bulk share / key rotation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    // Folder id is not included in import (determined by folder_relationships)
    #[serde(default, deserialize_with = "super::deser_opt_nonempty_str")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(alias = "organizationID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    #[serde(deserialize_with = "deserialize_cipher_type")]
    pub r#type: i32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: Option<bool>,
    #[serde(flatten)]
    pub type_fields: CipherTypeFields,
    /// Used during key rotation to update attachment keys and encrypted filenames.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments2: Option<HashMap<String, Attachments2Data>>,
    // The revision datetime (in ISO 8601 format) of the client's local copy
    // Used to prevent updating a cipher when client doesn't have the latest version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_revision_date: Option<String>,
}

/// Attachment metadata sent by clients during key rotation.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Attachments2Data {
    pub file_name: String,
    pub key: String,
}

/// Represents the full request payload for creating a cipher with collections.
/// Supports both camelCase and PascalCase for compatibility with different clients.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCipherRequest {
    #[serde(alias = "Cipher")]
    pub cipher: CipherRequestData,
    #[serde(default)]
    #[serde(alias = "CollectionIds")]
    pub collection_ids: Vec<String>,
}

/// Response for listing ciphers (GET /api/ciphers)
/// Now we don't use this struct, we use RawJson instead. But we keep it here for reference.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct CipherListResponse {
    pub data: Vec<Value>,
    pub object: String,
    pub continuation_token: Option<String>,
}

/// Request body for updating a cipher partially (PUT /api/ciphers/{id}/partial)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialCipherData {
    #[serde(default, deserialize_with = "super::deser_opt_nonempty_str")]
    pub folder_id: Option<String>,
    pub favorite: bool,
}

// ---------------------------------------------------------------------------
// Storage in the vaultwarden schema
// ---------------------------------------------------------------------------
//
// The Worker models a cipher as one JSON blob (`CipherData`: name, notes, <typeKey>, fields,
// passwordHistory, reprompt, key). vaultwarden splits it into columns: `name`, `notes`,
// `fields` (JSON), `data` (JSON of the type-specific object only), `password_history` (JSON),
// `reprompt`, `key`. Per-user state lives in `favorites`, `folders_ciphers` and `archives`.
// Reads go through the `wk_ciphers` view, which rebuilds the blob (see sql/schema.sql).

/// JSON key of the type-specific object for a cipher type.
pub fn type_data_key(atype: i32) -> &'static str {
    match atype {
        1 => "login",
        2 => "secureNote",
        3 => "card",
        4 => "identity",
        5 => "sshKey",
        6 => "bankAccount",
        7 => "driversLicense",
        8 => "passport",
        _ => "unknownType",
    }
}

/// Drop the client-side `response` key from an object or from every object in an array
/// (vaultwarden `clean_cipher_data`).
fn strip_response_keys(mut value: Value) -> Value {
    match &mut value {
        Value::Object(map) => {
            map.remove("response");
        }
        Value::Array(items) => {
            for item in items.iter_mut().filter_map(Value::as_object_mut) {
                item.remove("response");
            }
        }
        _ => {}
    }
    value
}

/// Column values for one row of `ciphers` (vaultwarden layout).
#[derive(Debug, Clone)]
pub struct CipherColumns {
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<String>,
    pub data: String,
    pub password_history: Option<String>,
    pub reprompt: Option<i32>,
    pub key: Option<String>,
}

impl CipherColumns {
    /// Split the Worker's cipher JSON blob into vaultwarden's columns.
    pub fn from_blob(atype: i32, blob: &Value) -> Self {
        let get = |k: &str| blob.get(k).filter(|v| !v.is_null());
        let mut type_data = get(type_data_key(atype)).cloned().unwrap_or(Value::Null);
        if let Some(obj) = type_data.as_object_mut() {
            obj.remove("response");
            if let Some(uris) = obj.remove("uris") {
                obj.insert("uris".to_string(), strip_response_keys(uris));
            }
        }
        Self {
            name: get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            notes: get("notes").and_then(Value::as_str).map(str::to_string),
            fields: get("fields").map(|f| strip_response_keys(f.clone()).to_string()),
            data: type_data.to_string(),
            password_history: get("passwordHistory").map(Value::to_string),
            reprompt: get("reprompt").and_then(Value::as_i64).map(|r| r as i32),
            key: get("key").and_then(Value::as_str).map(str::to_string),
        }
    }
}

/// `INSERT INTO ciphers` for a new row (vaultwarden layout).
#[allow(clippy::too_many_arguments)]
pub fn insert_cipher_stmt(
    db: &crate::db::Db,
    id: &str,
    user_id: Option<&str>,
    organization_id: Option<&str>,
    atype: i32,
    cols: &CipherColumns,
    created_at: &str,
    updated_at: &str,
) -> Result<worker::D1PreparedStatement, worker::Error> {
    crate::d1_query!(
        db,
        "INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, atype, name, notes, fields, data, password_history, reprompt, \"key\")
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        id,
        created_at,
        updated_at,
        user_id,
        organization_id,
        atype,
        cols.name,
        cols.notes,
        cols.fields,
        cols.data,
        cols.password_history,
        cols.reprompt,
        cols.key,
    )
}

/// `UPDATE ciphers` content columns of a user's cipher (vaultwarden layout).
#[allow(clippy::too_many_arguments)]
pub fn update_cipher_stmt(
    db: &crate::db::Db,
    id: &str,
    user_id: &str,
    _organization_id: Option<&str>,
    atype: i32,
    cols: &CipherColumns,
    updated_at: &str,
) -> Result<worker::D1PreparedStatement, worker::Error> {
    // Ownership (user_uuid / organization_uuid) never changes here; sharing a personal cipher
    // into an organization goes through `share_cipher_stmts`. The update only applies when the
    // user bound to ?11 may write the cipher (personal owner or non-read-only org access).
    crate::d1_query!(
        db,
        &format!(
            "{}UPDATE ciphers SET atype = ?1, name = ?2, notes = ?3, fields = ?4, data = ?5, password_history = ?6, reprompt = ?7, \"key\" = ?8, updated_at = ?9
             WHERE uuid = ?10 AND {}",
            crate::models::org_access::with_access("?11"),
            crate::models::org_access::WRITABLE
        ),
        atype,
        cols.name,
        cols.notes,
        cols.fields,
        cols.data,
        cols.password_history,
        cols.reprompt,
        cols.key,
        updated_at,
        id,
        user_id,
    )
}

/// Share a personal cipher into an organization: vaultwarden `share_cipher_by_uuid`.
/// Replaces the content (re-encrypted with the org key by the client), moves ownership to the
/// org and assigns the collections. Caller must check the user may write to every collection.
#[allow(clippy::too_many_arguments)]
pub fn share_cipher_stmts(
    db: &crate::db::Db,
    id: &str,
    user_id: &str,
    organization_id: &str,
    atype: i32,
    cols: &CipherColumns,
    collection_ids: &[String],
    updated_at: &str,
) -> Result<Vec<worker::D1PreparedStatement>, worker::Error> {
    let mut out = vec![crate::d1_query!(
        db,
        "UPDATE ciphers SET user_uuid = NULL, organization_uuid = ?1, atype = ?2, name = ?3, notes = ?4, fields = ?5, data = ?6, password_history = ?7, reprompt = ?8, \"key\" = ?9, updated_at = ?10
         WHERE uuid = ?11 AND user_uuid = ?12 AND organization_uuid IS NULL",
        organization_id,
        atype,
        cols.name,
        cols.notes,
        cols.fields,
        cols.data,
        cols.password_history,
        cols.reprompt,
        cols.key,
        updated_at,
        id,
        user_id,
    )?];
    for col in collection_ids {
        out.push(crate::d1_query!(
            db,
            "INSERT OR IGNORE INTO ciphers_collections (cipher_uuid, collection_uuid)
             SELECT ?1, uuid FROM collections WHERE uuid = ?2 AND org_uuid = ?3",
            id,
            col,
            organization_id
        )?);
    }
    Ok(out)
}

/// Put a cipher in `folder_id` (or no folder) for `user_id`: vaultwarden `move_to_folder`.
pub fn set_folder_stmts(
    db: &crate::db::Db,
    cipher_id: &str,
    user_id: &str,
    folder_id: Option<&str>,
) -> Result<Vec<worker::D1PreparedStatement>, worker::Error> {
    let folder_id = folder_id.filter(|f| !f.is_empty());
    Ok(vec![
        crate::d1_query!(
            db,
            "DELETE FROM folders_ciphers WHERE cipher_uuid = ?1 AND folder_uuid IN (SELECT uuid FROM folders WHERE user_uuid = ?2)",
            cipher_id,
            user_id
        )?,
        crate::d1_query!(
            db,
            "INSERT INTO folders_ciphers (cipher_uuid, folder_uuid) SELECT ?1, ?2 WHERE ?2 IS NOT NULL",
            cipher_id,
            folder_id
        )?,
    ])
}

/// Mark/unmark a cipher as favorite for `user_id`: vaultwarden `set_favorite`.
pub fn set_favorite_stmts(
    db: &crate::db::Db,
    cipher_id: &str,
    user_id: &str,
    favorite: bool,
) -> Result<Vec<worker::D1PreparedStatement>, worker::Error> {
    Ok(vec![
        crate::d1_query!(
            db,
            "DELETE FROM favorites WHERE user_uuid = ?1 AND cipher_uuid = ?2",
            user_id,
            cipher_id
        )?,
        crate::d1_query!(
            db,
            "INSERT INTO favorites (user_uuid, cipher_uuid) SELECT ?1, ?2 WHERE ?3",
            user_id,
            cipher_id,
            favorite as i32
        )?,
    ])
}

/// Archive (Some(ts)) or unarchive (None) a cipher for `user_id`.
pub fn set_archived_stmts(
    db: &crate::db::Db,
    cipher_id: &str,
    user_id: &str,
    archived_at: Option<&str>,
) -> Result<Vec<worker::D1PreparedStatement>, worker::Error> {
    Ok(vec![
        crate::d1_query!(db, "DELETE FROM archives WHERE user_uuid = ?1 AND cipher_uuid = ?2", user_id, cipher_id)?,
        crate::d1_query!(
            db,
            "INSERT INTO archives (user_uuid, cipher_uuid, archived_at) SELECT ?1, ?2, ?3 WHERE ?3 IS NOT NULL",
            user_id,
            cipher_id,
            archived_at
        )?,
    ])
}

/// All statements to create a cipher row plus its per-user folder/favorite/archive state.
#[allow(clippy::too_many_arguments)]
pub fn create_cipher_stmts(
    db: &crate::db::Db,
    id: &str,
    user_id: &str,
    organization_id: Option<&str>,
    atype: i32,
    blob: &Value,
    folder_id: Option<&str>,
    favorite: bool,
    archived_at: Option<&str>,
    created_at: &str,
    updated_at: &str,
) -> Result<Vec<worker::D1PreparedStatement>, worker::Error> {
    let cols = CipherColumns::from_blob(atype, blob);
    // Organization ciphers have no owning user (vaultwarden: user_uuid NULL).
    let owner = if organization_id.is_some() {
        None
    } else {
        Some(user_id)
    };
    let mut out = vec![insert_cipher_stmt(
        db,
        id,
        owner,
        organization_id,
        atype,
        &cols,
        created_at,
        updated_at,
    )?];
    if folder_id.is_some_and(|f| !f.is_empty()) {
        out.extend(set_folder_stmts(db, id, user_id, folder_id)?);
    }
    if favorite {
        out.extend(set_favorite_stmts(db, id, user_id, true)?);
    }
    if archived_at.is_some() {
        out.extend(set_archived_stmts(db, id, user_id, archived_at)?);
    }
    Ok(out)
}
