//! WebAuthn (security key / passkey) two-step login (phase 4), the wasm counterpart of
//! vaultwarden `api/core/two_factor/webauthn.rs` (which uses webauthn-rs).
//!
//! Like vaultwarden, keys are a second factor only: attestation is not verified ("none"),
//! user verification is discouraged, the credential's public key comes from the attested
//! credential data. Signatures are verified with WebCrypto (ES256, RS256, EdDSA).
//! Registrations are stored as one JSON list in `twofactor` (atype 7); entries imported from
//! vaultwarden (webauthn-rs `Passkey` JSON) are read too and rewritten in this format on use.

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use js_sys::{Array, Object, Reflect, Uint8Array};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{js_sys, Env};

use crate::auth::AuthUser;
use crate::crypto::{ct_eq, get_crypto, subtle_crypto};
use crate::d1_query;
use crate::db;
use crate::error::AppError;
use crate::handlers::twofactor_email::{
    find_tf, load_user, validate_webauthn, verify_token_or_password, webauthn_token,
};
use crate::models::twofactor::{TwoFactor, TwoFactorType};
use crate::models::user::PasswordOrOtpData;

const TIMEOUT_MS: u64 = 60_000;
const FLAG_UP: u8 = 0x01;
const FLAG_AT: u8 = 0x40;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;

fn bad(msg: &str) -> AppError {
    AppError::BadRequest(msg.to_string())
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Accept base64url (with or without padding) and standard base64.
fn b64_any(s: &str) -> Option<Vec<u8>> {
    let t = s.trim();
    URL_SAFE_NO_PAD
        .decode(t.trim_end_matches('='))
        .or_else(|_| URL_SAFE.decode(t))
        .or_else(|_| STANDARD.decode(t))
        .ok()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn random_bytes(n: u32) -> Result<Vec<u8>, AppError> {
    let bytes = Uint8Array::new_with_length(n);
    get_crypto()?
        .get_random_values_with_array_buffer_view(&bytes)
        .map_err(|_| AppError::Crypto("random".to_string()))?;
    Ok(bytes.to_vec())
}

/// Relying party: id = host of BASE_URL, origin = scheme://host[:port].
fn relying_party(env: &Env) -> Result<(String, String), AppError> {
    let base = crate::mail::domain(env);
    let (scheme, rest) = base
        .split_once("://")
        .ok_or_else(|| bad("Configured BASE_URL is not compatible with Webauthn"))?;
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map(|(h, _)| h)
        .unwrap_or(authority);
    if host.is_empty() {
        return Err(bad("Configured BASE_URL is not compatible with Webauthn"));
    }
    Ok((host.to_string(), format!("{scheme}://{authority}")))
}

// ---------------------------------------------------------------------------
// Minimal CBOR (RFC 8949) reader: enough for attestation objects and COSE keys
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Cbor {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Simple(u8),
}

impl Cbor {
    fn get(&self, key: &Cbor) -> Option<&Cbor> {
        match self {
            Cbor::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn int(&self) -> Option<i128> {
        match self {
            Cbor::Int(i) => Some(*i),
            _ => None,
        }
    }
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn arg(&mut self, info: u8) -> Option<u64> {
        Some(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().ok()?)),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().ok()?)),
            27 => u64::from_be_bytes(self.take(8)?.try_into().ok()?),
            _ => return None,
        })
    }

    fn item(&mut self, depth: u8) -> Option<Cbor> {
        if depth > 16 {
            return None;
        }
        let head = self.take(1)?[0];
        let (major, info) = (head >> 5, head & 0x1f);
        if major == 7 {
            return match info {
                20..=23 => Some(Cbor::Simple(info)),
                _ => None,
            };
        }
        let arg = self.arg(info)?;
        let len = usize::try_from(arg).ok()?;
        Some(match major {
            0 => Cbor::Int(i128::from(arg)),
            1 => Cbor::Int(-1 - i128::from(arg)),
            2 => Cbor::Bytes(self.take(len)?.to_vec()),
            3 => Cbor::Text(String::from_utf8(self.take(len)?.to_vec()).ok()?),
            4 => {
                let mut v = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    v.push(self.item(depth + 1)?);
                }
                Cbor::Array(v)
            }
            5 => {
                let mut v = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    let k = self.item(depth + 1)?;
                    let val = self.item(depth + 1)?;
                    v.push((k, val));
                }
                Cbor::Map(v)
            }
            _ => return None,
        })
    }
}

/// Decode one CBOR item; returns it and the number of bytes consumed.
fn cbor_decode(buf: &[u8]) -> Option<(Cbor, usize)> {
    let mut r = Reader { buf, pos: 0 };
    let item = r.item(0)?;
    Some((item, r.pos))
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// A stored credential in this server's format.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Cred {
    cred_id: String,
    alg: i64,
    jwk: Value,
    counter: u32,
    #[serde(default)]
    backup_eligible: bool,
    #[serde(default)]
    backup_state: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Registration {
    id: i32,
    name: String,
    #[serde(default)]
    migrated: bool,
    credential: Value,
}

impl Registration {
    fn to_json(&self) -> Value {
        json!({ "id": self.id, "name": self.name, "migrated": self.migrated })
    }

    fn cred(&self) -> Option<Cred> {
        parse_credential(&self.credential)
    }
}

/// Our `{"cf": Cred}` format, or webauthn-rs `Passkey` JSON (`{"cred": {...}}`) from vaultwarden.
fn parse_credential(v: &Value) -> Option<Cred> {
    if let Some(c) = v.get("cf") {
        return serde_json::from_value(c.clone()).ok();
    }
    let c = v.get("cred")?;
    let cred_id = b64url(&b64_any(c.get("cred_id")?.as_str()?)?);
    let key = c.get("cred")?.get("key")?;
    let (alg, jwk) = if let Some(ec) = key.get("EC_EC2") {
        if ec.get("curve")?.as_str()? != "SECP256R1" {
            return None;
        }
        let x = b64url(&b64_any(ec.get("x")?.as_str()?)?);
        let y = b64url(&b64_any(ec.get("y")?.as_str()?)?);
        (-7, json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}))
    } else if let Some(rsa) = key.get("RSA") {
        let n = b64url(&b64_any(rsa.get("n")?.as_str()?)?);
        let e = b64url(&b64_any(rsa.get("e")?.as_str()?)?);
        (-257, json!({"kty": "RSA", "n": n, "e": e}))
    } else if let Some(okp) = key.get("EC_OKP") {
        let x = b64url(&b64_any(okp.get("x")?.as_str()?)?);
        (-8, json!({"kty": "OKP", "crv": "Ed25519", "x": x}))
    } else {
        return None;
    };
    Some(Cred {
        cred_id,
        alg,
        jwk,
        counter: c.get("counter").and_then(Value::as_u64).unwrap_or(0) as u32,
        backup_eligible: c.get("backup_eligible").and_then(Value::as_bool).unwrap_or(false),
        backup_state: c.get("backup_state").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// COSE_Key (RFC 9053) -> (alg, JWK).
fn cose_to_jwk(key: &Cbor) -> Result<(i64, Value), AppError> {
    let int = |k: i128| key.get(&Cbor::Int(k)).and_then(Cbor::int);
    let bytes = |k: i128| key.get(&Cbor::Int(k)).and_then(Cbor::bytes).map(b64url);
    let kty = int(1).ok_or_else(|| bad("Invalid credential public key"))?;
    let alg = int(3).ok_or_else(|| bad("Invalid credential public key"))? as i64;
    let unsupported = || bad("Unsupported credential algorithm");
    let jwk = match (kty, alg) {
        (2, -7) if int(-1) == Some(1) => json!({
            "kty": "EC", "crv": "P-256",
            "x": bytes(-2).ok_or_else(unsupported)?, "y": bytes(-3).ok_or_else(unsupported)?,
        }),
        (3, -257) => json!({
            "kty": "RSA", "n": bytes(-1).ok_or_else(unsupported)?, "e": bytes(-2).ok_or_else(unsupported)?,
        }),
        (1, -8) if int(-1) == Some(6) => json!({
            "kty": "OKP", "crv": "Ed25519", "x": bytes(-2).ok_or_else(unsupported)?,
        }),
        _ => return Err(unsupported()),
    };
    Ok((alg, jwk))
}

/// ECDSA signatures arrive DER-encoded; WebCrypto wants r || s (32 bytes each for P-256).
fn der_to_raw_p256(der: &[u8]) -> Option<Vec<u8>> {
    let mut p = 0;
    let mut next = |n: usize| -> Option<&[u8]> {
        let s = der.get(p..p + n)?;
        p += n;
        Some(s)
    };
    if next(1)?[0] != 0x30 {
        return None;
    }
    let len = next(1)?[0];
    if len & 0x80 != 0 {
        next(usize::from(len & 0x7f))?;
    }
    let mut out = Vec::with_capacity(64);
    for _ in 0..2 {
        if next(1)?[0] != 0x02 {
            return None;
        }
        let l = usize::from(next(1)?[0]);
        let mut v = next(l)?;
        while v.len() > 32 && v[0] == 0 {
            v = &v[1..];
        }
        if v.len() > 32 {
            return None;
        }
        out.extend(std::iter::repeat_n(0u8, 32 - v.len()));
        out.extend_from_slice(v);
    }
    Some(out)
}

fn js_err(what: &str) -> impl Fn(JsValue) -> AppError + '_ {
    move |e| AppError::Crypto(format!("{what}: {e:?}"))
}

fn obj(pairs: &[(&str, JsValue)]) -> Result<Object, AppError> {
    let o = Object::new();
    for (k, v) in pairs {
        Reflect::set(&o, &JsValue::from_str(k), v).map_err(js_err("set"))?;
    }
    Ok(o)
}

/// Verify `signature` over `data` with the credential's public key (WebCrypto).
async fn verify_signature(cred: &Cred, signature: &[u8], data: &[u8]) -> Result<bool, AppError> {
    let subtle = subtle_crypto()?;
    let jwk = js_sys::JSON::parse(&cred.jwk.to_string()).map_err(js_err("jwk"))?;
    let (import_alg, verify_alg, sig) = match cred.alg {
        -7 => (
            obj(&[("name", "ECDSA".into()), ("namedCurve", "P-256".into())])?,
            obj(&[("name", "ECDSA".into()), ("hash", "SHA-256".into())])?,
            match der_to_raw_p256(signature) {
                Some(s) => s,
                None => return Ok(false),
            },
        ),
        -257 => (
            obj(&[("name", "RSASSA-PKCS1-v1_5".into()), ("hash", "SHA-256".into())])?,
            obj(&[("name", "RSASSA-PKCS1-v1_5".into())])?,
            signature.to_vec(),
        ),
        -8 => (
            obj(&[("name", "Ed25519".into())])?,
            obj(&[("name", "Ed25519".into())])?,
            signature.to_vec(),
        ),
        _ => return Ok(false),
    };
    let usages = Array::of1(&JsValue::from_str("verify"));
    let key = JsFuture::from(
        subtle
            .import_key_with_object("jwk", jwk.unchecked_ref::<Object>(), &import_alg, false, &usages)
            .map_err(js_err("importKey"))?,
    )
    .await
    .map_err(js_err("importKey"))?;
    let verify: js_sys::Function = Reflect::get(&subtle, &JsValue::from_str("verify"))
        .map_err(js_err("verify"))?
        .dyn_into()
        .map_err(|_| AppError::Crypto("verify".to_string()))?;
    let args = Array::new();
    args.push(&verify_alg);
    args.push(&key);
    args.push(&Uint8Array::from(sig.as_slice()));
    args.push(&Uint8Array::from(data));
    let promise: js_sys::Promise = verify
        .apply(&subtle, &args)
        .map_err(js_err("verify"))?
        .dyn_into()
        .map_err(|_| AppError::Crypto("verify".to_string()))?;
    Ok(JsFuture::from(promise)
        .await
        .map_err(js_err("verify"))?
        .as_bool()
        .unwrap_or(false))
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

async fn registrations(db: &db::Db, user_id: &str) -> Result<(Option<TwoFactor>, Vec<Registration>), AppError> {
    match find_tf(db, user_id, TwoFactorType::Webauthn).await? {
        Some(tf) => {
            let regs: Vec<Registration> = serde_json::from_str(&tf.data).unwrap_or_default();
            Ok((Some(tf), regs))
        }
        None => Ok((None, Vec::new())),
    }
}

async fn save_registrations(db: &db::Db, user_id: &str, regs: &[Registration]) -> Result<(), AppError> {
    let data = serde_json::to_string(regs).map_err(|_| AppError::Internal)?;
    db.batch(vec![
        d1_query!(
            db,
            "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
            user_id,
            TwoFactorType::Webauthn as i32
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            db,
            "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, 1, ?4, 0)",
            Uuid::new_v4().to_string(),
            user_id,
            TwoFactorType::Webauthn as i32,
            data
        )
        .map_err(|_| AppError::Database)?,
    ])
    .await?;
    Ok(())
}

async fn put_state(db: &db::Db, user_id: &str, atype: TwoFactorType, state: &Value) -> Result<(), AppError> {
    db.batch(vec![
        d1_query!(
            db,
            "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
            user_id,
            atype as i32
        )
        .map_err(|_| AppError::Database)?,
        d1_query!(
            db,
            "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, 1, ?4, ?5)",
            Uuid::new_v4().to_string(),
            user_id,
            atype as i32,
            state.to_string(),
            chrono::Utc::now().timestamp()
        )
        .map_err(|_| AppError::Database)?,
    ])
    .await?;
    Ok(())
}

/// Take (read and delete) a pending challenge state no older than the timeout.
async fn take_state(db: &db::Db, user_id: &str, atype: TwoFactorType) -> Result<Value, AppError> {
    let tf = find_tf(db, user_id, atype)
        .await?
        .ok_or_else(|| bad("Can't recover challenge"))?;
    d1_query!(db, "DELETE FROM twofactor WHERE uuid = ?1", tf.uuid)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    if tf.last_used + (TIMEOUT_MS as i64 / 1000) * 5 < chrono::Utc::now().timestamp() {
        return Err(bad("Challenge expired"));
    }
    serde_json::from_str(&tf.data).map_err(|_| bad("Can't recover challenge"))
}

fn keys_of(regs: &[Registration]) -> Vec<i32> {
    regs.iter().map(|r| r.id).collect()
}

// ---------------------------------------------------------------------------
// Client data / authenticator data checks
// ---------------------------------------------------------------------------

struct AuthData<'a> {
    flags: u8,
    counter: u32,
    rest: &'a [u8],
}

fn parse_auth_data<'a>(auth: &'a [u8], rp_hashes: &[Vec<u8>]) -> Result<AuthData<'a>, AppError> {
    if auth.len() < 37 {
        return Err(bad("Invalid authenticator data"));
    }
    if !rp_hashes.iter().any(|h| ct_eq_bytes(&auth[..32], h)) {
        return Err(bad("Webauthn RP id mismatch"));
    }
    let flags = auth[32];
    if flags & FLAG_UP == 0 {
        return Err(bad("User not present"));
    }
    Ok(AuthData {
        flags,
        counter: u32::from_be_bytes([auth[33], auth[34], auth[35], auth[36]]),
        rest: &auth[37..],
    })
}

fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq::constant_time_eq(a, b)
}

fn check_client_data(raw: &[u8], kind: &str, challenge: &str, origin: &str) -> Result<(), AppError> {
    let cd: Value = serde_json::from_slice(raw).map_err(|_| bad("Invalid client data"))?;
    if cd.get("type").and_then(Value::as_str) != Some(kind) {
        return Err(bad("Invalid client data type"));
    }
    let got = cd.get("challenge").and_then(Value::as_str).and_then(b64_any);
    let want = b64_any(challenge);
    if got.is_none() || got != want {
        return Err(bad("Webauthn challenge mismatch"));
    }
    if cd.get("origin").and_then(Value::as_str) != Some(origin) {
        return Err(bad("Webauthn origin mismatch"));
    }
    Ok(())
}

/// Read a field that clients send as `clientDataJson`, `clientDataJSON` or PascalCase.
fn field<'a>(v: &'a Value, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|n| v.get(*n).and_then(Value::as_str))
}

// ---------------------------------------------------------------------------
// Endpoints (vaultwarden routes and JSON shapes)
// ---------------------------------------------------------------------------

fn webauthn_json(regs: &[Registration]) -> Value {
    json!({
        "enabled": !regs.is_empty(),
        "keys": regs.iter().map(Registration::to_json).collect::<Vec<_>>(),
    })
}

/// POST /api/two-factor/get-webauthn
#[worker::send]
pub async fn get_webauthn(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    relying_party(&env)?;
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    verify_token_or_password(&user, None, data.master_password_hash.as_deref(), |_| Ok(())).await?;
    let (tf, regs) = registrations(&db, &user_id).await?;
    let enabled = tf.is_some_and(|t| t.enabled);
    Ok(Json(json!({
        "webAuthn": { "enabled": enabled, "keys": regs.iter().map(Registration::to_json).collect::<Vec<_>>() },
        "userVerificationToken": webauthn_token(&env, &user_id, keys_of(&regs), enabled)?,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenData {
    user_verification_token: String,
}

/// POST /api/two-factor/get-webauthn-challenge: registration options.
#[worker::send]
pub async fn get_webauthn_challenge(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<TokenData>,
) -> Result<Json<Value>, AppError> {
    let (rp_id, _) = relying_party(&env)?;
    let db = db::get_db(&env)?;
    let user = load_user(&db, &user_id).await?;
    let (tf, regs) = registrations(&db, &user_id).await?;
    let enabled = tf.is_some_and(|t| t.enabled);
    validate_webauthn(&env, &data.user_verification_token, &user_id, &keys_of(&regs), enabled)?;
    let challenge = b64url(&random_bytes(32)?);
    put_state(&db, &user_id, TwoFactorType::WebauthnRegisterChallenge, &json!({ "challenge": challenge })).await?;
    let user_handle = Uuid::parse_str(&user_id).map(|u| b64url(u.as_bytes())).unwrap_or_else(|_| b64url(user_id.as_bytes()));
    let exclude: Vec<Value> = regs
        .iter()
        .filter_map(Registration::cred)
        .map(|c| json!({ "type": "public-key", "id": c.cred_id }))
        .collect();
    let display = user.name.clone().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| user.email.clone());
    Ok(Json(json!({
        "options": {
            "rp": { "id": rp_id, "name": crate::mail::domain(&env) },
            "user": { "id": user_handle, "name": user.email, "displayName": display },
            "challenge": challenge,
            "pubKeyCredParams": [
                { "type": "public-key", "alg": -7 },
                { "type": "public-key", "alg": -257 },
                { "type": "public-key", "alg": -8 },
            ],
            "timeout": TIMEOUT_MS,
            "attestation": "none",
            "excludeCredentials": exclude,
            "authenticatorSelection": {
                "residentKey": "discouraged",
                "requireResidentKey": false,
                "userVerification": "discouraged",
            },
            "status": "ok",
            "errorMessage": "",
        }
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableData {
    id: i32,
    name: String,
    device_response: Value,
    user_verification_token: String,
}

/// POST/PUT /api/two-factor/webauthn: finish registering a key.
#[worker::send]
pub async fn activate_webauthn(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableData>,
) -> Result<Json<Value>, AppError> {
    let (rp_id, origin) = relying_party(&env)?;
    let db = db::get_db(&env)?;
    let (_, mut regs) = registrations(&db, &user_id).await?;
    let keys = keys_of(&regs);
    validate_webauthn(&env, &data.user_verification_token, &user_id, &keys, !keys.is_empty())?;
    let state = take_state(&db, &user_id, TwoFactorType::WebauthnRegisterChallenge).await?;
    let challenge = state.get("challenge").and_then(Value::as_str).unwrap_or_default();

    let resp = data.device_response.get("response").ok_or_else(|| bad("Invalid device response"))?;
    let client_data = field(resp, &["clientDataJson", "clientDataJSON", "ClientDataJson"])
        .and_then(b64_any)
        .ok_or_else(|| bad("Invalid client data"))?;
    check_client_data(&client_data, "webauthn.create", challenge, &origin)?;
    let att_obj = field(resp, &["attestationObject", "AttestationObject"])
        .and_then(b64_any)
        .ok_or_else(|| bad("Invalid attestation object"))?;
    let (att, _) = cbor_decode(&att_obj).ok_or_else(|| bad("Invalid attestation object"))?;
    let auth = att
        .get(&Cbor::Text("authData".to_string()))
        .and_then(Cbor::bytes)
        .ok_or_else(|| bad("Invalid attestation object"))?;
    let ad = parse_auth_data(auth, &[sha256(rp_id.as_bytes())])?;
    if ad.flags & FLAG_AT == 0 || ad.rest.len() < 18 {
        return Err(bad("Missing attested credential data"));
    }
    let id_len = usize::from(u16::from_be_bytes([ad.rest[16], ad.rest[17]]));
    let cred_id = ad
        .rest
        .get(18..18 + id_len)
        .ok_or_else(|| bad("Invalid credential id"))?;
    let (cose, _) = cbor_decode(&ad.rest[18 + id_len..]).ok_or_else(|| bad("Invalid credential public key"))?;
    let (alg, jwk) = cose_to_jwk(&cose)?;
    let cred_id = b64url(cred_id);
    if regs.iter().filter_map(Registration::cred).any(|c| c.cred_id == cred_id) {
        return Err(bad("This key is already registered"));
    }
    let cred = Cred {
        cred_id,
        alg,
        jwk,
        counter: ad.counter,
        backup_eligible: ad.flags & FLAG_BE != 0,
        backup_state: ad.flags & FLAG_BS != 0,
    };
    regs.retain(|r| r.id != data.id);
    regs.push(Registration {
        id: data.id,
        name: data.name,
        migrated: false,
        credential: json!({ "cf": cred }),
    });
    save_registrations(&db, &user_id, &regs).await?;
    crate::handlers::twofactor::generate_recovery_code_for_user(&db, &user_id).await?;
    Ok(Json(json!({ "webAuthn": webauthn_json(&regs) })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteData {
    id: Option<i32>,
    user_verification_token: String,
}

/// DELETE /api/two-factor/webauthn (one key) and /api/two-factor/webauthn/all.
async fn delete_impl(env: &Env, user_id: &str, data: DeleteData, all: bool) -> Result<Json<Value>, AppError> {
    let db = db::get_db(env)?;
    let (tf, mut regs) = registrations(&db, user_id).await?;
    if tf.is_none() {
        return Err(bad("Webauthn data not found!"));
    }
    validate_webauthn(env, &data.user_verification_token, user_id, &keys_of(&regs), true)?;
    let before = regs.len();
    if all {
        regs.clear();
    } else {
        let id = data.id.ok_or_else(|| bad("Missing key id"))?;
        regs.retain(|r| r.id != id);
    }
    if regs.len() == before {
        return Err(bad("Webauthn entry not found"));
    }
    if regs.is_empty() {
        d1_query!(
            &db,
            "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
            user_id,
            TwoFactorType::Webauthn as i32
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    } else {
        save_registrations(&db, user_id, &regs).await?;
    }
    crate::handlers::twofactor::after_provider_removed(&db, user_id).await?;
    Ok(Json(json!({ "webAuthn": webauthn_json(&regs) })))
}

#[worker::send]
pub async fn delete_webauthn(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DeleteData>,
) -> Result<Json<Value>, AppError> {
    delete_impl(&env, &user_id, data, false).await
}

#[worker::send]
pub async fn delete_all_webauthn(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DeleteData>,
) -> Result<Json<Value>, AppError> {
    delete_impl(&env, &user_id, data, true).await
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

/// Start a login: store a challenge and return the assertion options for `TwoFactorProviders2`.
pub async fn start_login(env: &Env, db: &db::Db, user_id: &str, tf: &TwoFactor) -> Result<Value, AppError> {
    let (rp_id, _) = relying_party(env)?;
    let regs: Vec<Registration> = serde_json::from_str(&tf.data).unwrap_or_default();
    let allow: Vec<Value> = regs
        .iter()
        .filter_map(Registration::cred)
        .map(|c| json!({ "type": "public-key", "id": c.cred_id }))
        .collect();
    if allow.is_empty() {
        return Ok(Value::Null);
    }
    let challenge = b64url(&random_bytes(32)?);
    let app_id = format!("{}/app-id.json", crate::mail::domain(env));
    put_state(db, user_id, TwoFactorType::WebauthnLoginChallenge, &json!({ "challenge": challenge, "appid": app_id })).await?;
    Ok(json!({
        "challenge": challenge,
        "timeout": TIMEOUT_MS,
        "rpId": rp_id,
        "allowCredentials": allow,
        "userVerification": "discouraged",
        "extensions": { "appid": app_id },
    }))
}

/// Check the assertion sent as the 2FA token (vaultwarden `validate_webauthn_login`).
pub async fn validate_login(env: &Env, db: &db::Db, user_id: &str, tf: &TwoFactor, token: &str) -> Result<(), AppError> {
    let (rp_id, origin) = relying_party(env)?;
    let state = take_state(db, user_id, TwoFactorType::WebauthnLoginChallenge).await?;
    let challenge = state.get("challenge").and_then(Value::as_str).unwrap_or_default();
    let app_id = state.get("appid").and_then(Value::as_str).unwrap_or_default();
    let rsp: Value = serde_json::from_str(token).map_err(|_| bad("Invalid webauthn response"))?;
    let raw_id = field(&rsp, &["rawId", "id", "RawId", "Id"])
        .and_then(b64_any)
        .ok_or_else(|| bad("Invalid webauthn response"))?;
    let resp = rsp.get("response").or_else(|| rsp.get("Response")).ok_or_else(|| bad("Invalid webauthn response"))?;
    let client_data = field(resp, &["clientDataJson", "clientDataJSON", "ClientDataJson"])
        .and_then(b64_any)
        .ok_or_else(|| bad("Invalid client data"))?;
    let auth = field(resp, &["authenticatorData", "AuthenticatorData"])
        .and_then(b64_any)
        .ok_or_else(|| bad("Invalid authenticator data"))?;
    let sig = field(resp, &["signature", "Signature"])
        .and_then(b64_any)
        .ok_or_else(|| bad("Invalid signature"))?;
    check_client_data(&client_data, "webauthn.get", challenge, &origin)?;
    let ad = parse_auth_data(&auth, &[sha256(rp_id.as_bytes()), sha256(app_id.as_bytes())])?;

    let mut regs: Vec<Registration> = serde_json::from_str(&tf.data).unwrap_or_default();
    let raw_id = b64url(&raw_id);
    let idx = regs
        .iter()
        .position(|r| r.cred().is_some_and(|c| ct_eq(&c.cred_id, &raw_id)))
        .ok_or_else(|| bad("Credential not present"))?;
    let mut cred = regs[idx].cred().ok_or_else(|| bad("Credential not present"))?;
    let mut signed = auth.clone();
    signed.extend_from_slice(&sha256(&client_data));
    if !verify_signature(&cred, &sig, &signed).await? {
        return Err(bad("Invalid webauthn signature"));
    }
    // A counter that doesn't move forward means a cloned key (0 = authenticator has none).
    if (ad.counter != 0 || cred.counter != 0) && ad.counter <= cred.counter {
        return Err(bad("Webauthn counter did not increase"));
    }
    cred.counter = ad.counter;
    cred.backup_eligible |= ad.flags & FLAG_BE != 0;
    cred.backup_state = ad.flags & FLAG_BS != 0;
    regs[idx].credential = json!({ "cf": cred });
    save_registrations(db, user_id, &regs).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_reads_nested_maps() {
        // {"fmt": "none", "authData": h'0102', "attStmt": {}}
        let buf = [
            0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e', 0x68, b'a', b'u', b't', b'h',
            b'D', b'a', b't', b'a', 0x42, 1, 2, 0x67, b'a', b't', b't', b'S', b't', b'm', b't', 0xa0,
        ];
        let (v, used) = cbor_decode(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(v.get(&Cbor::Text("authData".into())).and_then(Cbor::bytes), Some(&[1u8, 2][..]));
        assert_eq!(cbor_decode(&[0x38, 0x18]).unwrap().0, Cbor::Int(-25));
        assert!(cbor_decode(&[0x5f]).is_none());
    }

    #[test]
    fn der_signature_to_raw() {
        let mut der = vec![0x30, 0x45, 0x02, 0x21, 0x00];
        der.extend([0xaa; 32]);
        der.extend([0x02, 0x20]);
        der.extend([0xbb; 32]);
        let raw = der_to_raw_p256(&der).unwrap();
        assert_eq!(&raw[..32], &[0xaa; 32]);
        assert_eq!(&raw[32..], &[0xbb; 32]);
    }

    #[test]
    fn imported_passkey_is_readable() {
        let v = json!({"cred": {"cred_id": "AQID", "cred": {"type_": "ES256", "key": {"EC_EC2": {"curve": "SECP256R1", "x": "AQ", "y": "Ag"}}}, "counter": 5}});
        let c = parse_credential(&v).unwrap();
        assert_eq!((c.cred_id.as_str(), c.alg, c.counter), ("AQID", -7, 5));
    }
}
