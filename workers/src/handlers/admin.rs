//! Admin page (phase 4), a server-rendered port of vaultwarden's `/admin` (`src/api/admin.rs`).
//!
//! Enabled when the `ADMIN_TOKEN` secret is set (otherwise `/admin` says it is disabled, like
//! upstream). Login posts the token; the session is an HttpOnly, Secure, SameSite=Strict cookie
//! holding a 20-minute HS256 JWT. State-changing requests are POST forms and must come from this
//! origin. Pages: settings (read-only), users, organizations, diagnostics. User actions:
//! invite, deauthorize sessions, disable/enable, remove 2FA, resend invite, delete.
//! Organization action: delete.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::Env;

use crate::crypto::ct_eq;
use crate::d1_query;
use crate::db;
use crate::error::AppError;

const COOKIE: &str = "VW_ADMIN";
const SESSION_MINUTES: i64 = 20;
const ISSUER: &str = "vaultwarden-cf|admin";

fn admin_token(env: &Env) -> Option<String> {
    env.secret("ADMIN_TOKEN")
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
}

#[derive(serde::Serialize, Deserialize)]
struct AdminClaims {
    iss: String,
    sub: String,
}

fn session_key(env: &Env) -> Result<jwt_compact::alg::Hs256Key, AppError> {
    let secret = env.secret("JWT_SECRET")?.to_string();
    Ok(jwt_compact::alg::Hs256Key::new(
        format!("{secret}|admin-session").as_bytes(),
    ))
}

fn new_session(env: &Env) -> Result<String, AppError> {
    use jwt_compact::AlgorithmExt;
    let jwt = jwt_compact::Claims::new(AdminClaims {
        iss: ISSUER.to_string(),
        sub: "admin_panel".to_string(),
    })
    .set_duration_and_issuance(
        &crate::auth::jwt_time_options(),
        chrono::Duration::minutes(SESSION_MINUTES),
    );
    jwt_compact::alg::Hs256
        .token(&jwt_compact::Header::empty(), &jwt, &session_key(env)?)
        .map_err(|_| AppError::Crypto("admin session".to_string()))
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn has_session(env: &Env, headers: &HeaderMap) -> bool {
    use jwt_compact::AlgorithmExt;
    let Some(raw) = cookie_value(headers, COOKIE) else {
        return false;
    };
    let Ok(key) = session_key(env) else {
        return false;
    };
    let Ok(untrusted) = jwt_compact::UntrustedToken::new(&raw) else {
        return false;
    };
    let Ok(token) = jwt_compact::alg::Hs256
        .validator::<AdminClaims>(&key)
        .validate(&untrusted)
    else {
        return false;
    };
    token
        .claims()
        .validate_expiration(&crate::auth::jwt_time_options())
        .is_ok()
        && token.claims().custom.iss == ISSUER
}

fn secure_cookie(env: &Env) -> &'static str {
    if crate::mail::domain(env).starts_with("https://") {
        "; Secure"
    } else {
        ""
    }
}

/// POSTs must come from our own origin (the SameSite=Strict cookie already blocks most CSRF).
fn check_origin(env: &Env, headers: &HeaderMap) -> Result<(), AppError> {
    let base = crate::mail::domain(env);
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| {
            headers
                .get(header::REFERER)
                .and_then(|v| v.to_str().ok())
                .map(|r| r.split('/').take(3).collect::<Vec<_>>().join("/"))
        });
    // `wrangler dev` rewrites Origin/Host to the configured route, so also accept an origin whose
    // authority is this request's Host.
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let same_host = |o: &str| {
        o.split_once("://")
            .is_some_and(|(_, a)| !host.is_empty() && a == host)
    };
    match origin {
        Some(o) if o == base || same_host(&o) => Ok(()),
        other => {
            log::warn!("admin: refused POST from origin {other:?} (expected {base})");
            Err(AppError::BadRequest("Invalid origin".to_string()))
        }
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(title: &str, nav: bool, flash: Option<&str>, body: &str) -> Response {
    let nav_html = if nav {
        r#"<nav><a href="/admin">Settings</a><a href="/admin/users/overview">Users</a><a href="/admin/organizations/overview">Organizations</a><a href="/admin/diagnostics">Diagnostics</a><a href="/admin/logout" class="right">Log out</a></nav>"#
    } else {
        ""
    };
    let flash_html = flash
        .map(|f| format!(r#"<p class="flash">{}</p>"#, esc(f)))
        .unwrap_or_default();
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{t} - Vaultwarden Admin</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f5f7;color:#1f2937}}
header{{background:#175ddc;color:#fff;padding:12px 24px;font-weight:600}}
nav{{display:flex;gap:16px;padding:10px 24px;background:#fff;border-bottom:1px solid #e5e7eb}}nav a{{color:#175ddc;text-decoration:none}}nav .right{{margin-left:auto}}
main{{padding:20px 24px;max-width:1200px}}table{{border-collapse:collapse;width:100%;background:#fff}}th,td{{border-bottom:1px solid #e5e7eb;padding:6px 8px;text-align:left;font-size:14px;vertical-align:top}}
th{{background:#f9fafb}}form.inline{{display:inline}}button{{font-size:12px;margin:1px;padding:3px 8px;border:1px solid #cbd5e1;background:#fff;border-radius:4px;cursor:pointer}}button.danger{{color:#b91c1c;border-color:#fca5a5}}
.flash{{background:#ecfdf5;border:1px solid #6ee7b7;padding:8px 12px}}.muted{{color:#6b7280;font-size:12px}}input[type=text],input[type=password],input[type=email]{{padding:6px;width:320px}}
dl{{display:grid;grid-template-columns:260px 1fr;gap:6px 16px;background:#fff;padding:12px}}dt{{font-weight:600}}
</style></head><body><header>Vaultwarden Admin Panel</header>{nav_html}<main><h2>{t}</h2>{flash_html}{body}</main></body></html>"#,
        t = esc(title)
    );
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::REFERRER_POLICY, "same-origin"),
        ],
        Html(html),
    )
        .into_response()
}

fn redirect(to: &str, set_cookie: Option<String>) -> Response {
    let mut resp = (StatusCode::SEE_OTHER, [(header::LOCATION, to.to_string())]).into_response();
    if let Some(c) = set_cookie {
        if let Ok(v) = c.parse() {
            resp.headers_mut().insert(header::SET_COOKIE, v);
        }
    }
    resp
}

fn flash_redirect(to: &str, msg: &str) -> Response {
    let q: String = msg
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect();
    redirect(&format!("{to}?msg={q}"), None)
}

fn disabled_page() -> Response {
    page(
        "Admin panel disabled",
        false,
        None,
        "<p>The admin panel is disabled. Set the <code>ADMIN_TOKEN</code> secret to enable it.</p>",
    )
}

fn login_page(error: Option<&str>) -> Response {
    let mut resp = page(
        "Log in",
        false,
        error,
        r#"<form method="post" action="/admin"><p><input type="password" name="token" placeholder="Admin token" autofocus required autocomplete="current-password"></p><p><button type="submit">Enter</button></p></form>"#,
    );
    if error.is_some() {
        *resp.status_mut() = StatusCode::UNAUTHORIZED;
    }
    resp
}

/// Gate for every authenticated admin route.
fn guard(env: &Env, headers: &HeaderMap) -> Result<(), Response> {
    if admin_token(env).is_none() {
        return Err(disabled_page());
    }
    if !has_session(env, headers) {
        return Err(login_page(None));
    }
    Ok(())
}

#[derive(Deserialize, Default)]
pub struct Msg {
    msg: Option<String>,
}

// ---------------------------------------------------------------------------
// Login / logout / settings
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginForm {
    token: String,
}

/// POST /admin
#[worker::send]
pub async fn login(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(expected) = admin_token(&env) else {
        return disabled_page();
    };
    if crate::handlers::enforce_ip_rate_limit(
        &env,
        &headers,
        "LOGIN_RATE_LIMITER",
        "admin",
        "Too many requests. Please try again later.",
    )
    .await
    .is_err()
    {
        return login_page(Some("Too many attempts, try again in a minute."));
    }
    if !ct_eq(form.token.trim(), expected.trim()) {
        log::warn!("Invalid admin token");
        return login_page(Some("Invalid admin token, please try again."));
    }
    match new_session(&env) {
        Ok(jwt) => redirect(
            "/admin",
            Some(format!(
                "{COOKIE}={jwt}; Path=/admin; Max-Age={}; HttpOnly; SameSite=Strict{}",
                SESSION_MINUTES * 60,
                secure_cookie(&env)
            )),
        ),
        Err(_) => login_page(Some("Could not create a session.")),
    }
}

/// GET /admin/logout
#[worker::send]
pub async fn logout(State(env): State<Arc<Env>>) -> Response {
    redirect(
        "/admin",
        Some(format!(
            "{COOKIE}=; Path=/admin; Max-Age=0; HttpOnly; SameSite=Strict{}",
            secure_cookie(&env)
        )),
    )
}

fn var(env: &Env, name: &str) -> String {
    env.var(name).map(|v| v.to_string()).unwrap_or_default()
}

/// GET /admin: read-only settings (configuration lives in wrangler.toml and secrets).
#[worker::send]
pub async fn admin_page(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<Msg>,
) -> Response {
    if let Err(r) = guard(&env, &headers) {
        return r;
    }
    let secret_set = |n: &str| {
        if env.secret(n).is_ok() {
            "set"
        } else {
            "not set"
        }
    };
    let allowed = env
        .secret("ALLOWED_EMAILS")
        .map(|s| s.to_string())
        .unwrap_or_default();
    let rows = [
        ("Domain (BASE_URL)", esc(&crate::mail::domain(&env))),
        (
            "User registration disabled",
            esc(&var(&env, "DISABLE_USER_REGISTRATION")),
        ),
        ("Allowed signup emails (ALLOWED_EMAILS)", esc(&allowed)),
        (
            "Mail (Resend)",
            if crate::mail::mail_enabled(&env) {
                "enabled".into()
            } else {
                "disabled".into()
            },
        ),
        ("Mail sender (MAIL_FROM)", esc(&var(&env, "MAIL_FROM"))),
        (
            "Attachments (R2)",
            if crate::handlers::attachments::attachments_enabled(&env) {
                "enabled".into()
            } else {
                "disabled".into()
            },
        ),
        (
            "JWT_SECRET / JWT_REFRESH_SECRET",
            format!(
                "{} / {}",
                secret_set("JWT_SECRET"),
                secret_set("JWT_REFRESH_SECRET")
            ),
        ),
        ("RESEND_API_KEY", secret_set("RESEND_API_KEY").to_string()),
    ];
    let dl: String = rows
        .iter()
        .map(|(k, v)| format!("<dt>{}</dt><dd>{v}</dd>", esc(k)))
        .collect();
    page(
        "Settings",
        true,
        q.msg.as_deref(),
        &format!(
            r#"<p class="muted">Settings are deployment configuration: change them in <code>wrangler.toml</code> (vars) or with <code>wrangler secret put</code>, then redeploy.</p><dl>{dl}</dl>
<h3>Invite user</h3><form method="post" action="/admin/invite"><input type="email" name="email" placeholder="user@example.com" required> <button type="submit">Invite</button></form>
<p class="muted">An invited email may register even when it is not in ALLOWED_EMAILS.</p>"#
        ),
    )
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UserRow {
    uuid: String,
    email: String,
    name: String,
    created_at: String,
    enabled: i32,
    has_password: i32,
    twofactor: i64,
    items: i64,
    attachments: i64,
    attachment_bytes: i64,
    orgs: i64,
    last_active: Option<String>,
}

const USERS_SQL: &str = "SELECT u.uuid, u.email, u.name, u.created_at, u.enabled,
       length(u.password_hash) > 0 AS has_password,
       (SELECT COUNT(*) FROM twofactor t WHERE t.user_uuid = u.uuid AND t.atype < 1000 AND t.atype != 5) AS twofactor,
       (SELECT COUNT(*) FROM ciphers c WHERE c.user_uuid = u.uuid) AS items,
       (SELECT COUNT(*) FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid WHERE c.user_uuid = u.uuid) AS attachments,
       (SELECT COALESCE(SUM(a.file_size), 0) FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid WHERE c.user_uuid = u.uuid) AS attachment_bytes,
       (SELECT COUNT(*) FROM users_organizations m WHERE m.user_uuid = u.uuid) AS orgs,
       (SELECT MAX(d.updated_at) FROM devices d WHERE d.user_uuid = u.uuid) AS last_active
  FROM users u";

async fn load_users(env: &Env) -> Result<Vec<UserRow>, AppError> {
    let db = db::get_db(env)?;
    Ok(db
        .prepare(format!("{USERS_SQL} ORDER BY u.created_at"))
        .all()
        .await?
        .results()?)
}

fn user_json(u: &UserRow) -> Value {
    json!({
        "id": u.uuid,
        "email": u.email,
        "name": u.name,
        "createdAt": u.created_at,
        "lastActive": u.last_active,
        "userEnabled": u.enabled != 0,
        "invited": u.has_password == 0,
        "twoFactorEnabled": u.twofactor > 0,
        "cipherCount": u.items,
        "attachmentCount": u.attachments,
        "attachmentSize": u.attachment_bytes,
        "organizationCount": u.orgs,
        "object": "user",
    })
}

fn size_name(bytes: i64) -> String {
    let b = bytes as f64;
    if b >= 1048576.0 {
        format!("{:.1} MB", b / 1048576.0)
    } else if b >= 1024.0 {
        format!("{:.1} KB", b / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn action(path: &str, label: &str, danger: bool, confirm: Option<&str>) -> String {
    let onsubmit = confirm
        .map(|c| format!(r#" onsubmit="return confirm('{}')""#, esc(c)))
        .unwrap_or_default();
    format!(
        r#"<form class="inline" method="post" action="{path}"{onsubmit}><button type="submit"{}>{label}</button></form>"#,
        if danger { r#" class="danger""# } else { "" }
    )
}

/// GET /admin/users/overview
#[worker::send]
pub async fn users_overview(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<Msg>,
) -> Response {
    if let Err(r) = guard(&env, &headers) {
        return r;
    }
    let users = match load_users(&env).await {
        Ok(u) => u,
        Err(_) => return page("Users", true, Some("Could not load users."), ""),
    };
    let rows: String = users
        .iter()
        .map(|u| {
            let id = esc(&u.uuid);
            let mut acts = String::new();
            if u.has_password == 0 {
                acts += &action(&format!("/admin/users/{id}/invite/resend"), "Resend invite", false, None);
            }
            acts += &action(&format!("/admin/users/{id}/deauth"), "Deauthorize sessions", false, Some("Log this user out of every device?"));
            if u.enabled != 0 {
                acts += &action(&format!("/admin/users/{id}/disable"), "Disable", true, Some("Disable this user?"));
            } else {
                acts += &action(&format!("/admin/users/{id}/enable"), "Enable", false, None);
            }
            if u.twofactor > 0 {
                acts += &action(&format!("/admin/users/{id}/remove-2fa"), "Remove 2FA", true, Some("Remove every 2FA method of this user?"));
            }
            acts += &action(&format!("/admin/users/{id}/delete"), "Delete", true, Some("Delete this user and all of their data? This can't be undone."));
            format!(
                "<tr><td><b>{}</b><br>{}<div class=muted>{}</div></td><td>{}</td><td>{}</td><td>{} ({} files, {})</td><td>{}</td><td>{}</td><td>{}{}</td><td>{acts}</td></tr>",
                esc(&u.name),
                esc(&u.email),
                id,
                esc(&u.created_at),
                esc(u.last_active.as_deref().unwrap_or("never")),
                u.items,
                u.attachments,
                size_name(u.attachment_bytes),
                u.orgs,
                if u.twofactor > 0 { "yes" } else { "no" },
                if u.enabled == 0 { "<br><b>disabled</b>" } else { "" },
                if u.has_password == 0 { "<br><i>invited</i>" } else { "" },
            )
        })
        .collect();
    page(
        "Users",
        true,
        q.msg.as_deref(),
        &format!(
            "<table><tr><th>User</th><th>Created</th><th>Last active</th><th>Items (attachments)</th><th>Orgs</th><th>2FA</th><th>Status</th><th>Actions</th></tr>{rows}</table>"
        ),
    )
}

/// GET /admin/users (JSON, like upstream `get_users_json`)
#[worker::send]
pub async fn users_json(State(env): State<Arc<Env>>, headers: HeaderMap) -> Response {
    if let Err(r) = guard(&env, &headers) {
        return r;
    }
    match load_users(&env).await {
        Ok(users) => Json(Value::Array(users.iter().map(user_json).collect())).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn user_exists(db: &db::Db, id: &str) -> Result<Option<(String, String)>, AppError> {
    #[derive(Deserialize)]
    struct R {
        email: String,
        name: String,
    }
    Ok(db
        .prepare("SELECT email, name FROM users WHERE uuid = ?1")
        .bind(&[id.into()])?
        .first::<R>(None)
        .await?
        .map(|r| (r.email, r.name)))
}

async fn user_action(env: &Env, id: &str, what: &str) -> Result<String, AppError> {
    let db = db::get_db(env)?;
    let (email, _) = user_exists(&db, id)
        .await?
        .ok_or_else(|| AppError::NotFound("User doesn't exist".to_string()))?;
    let now = db::now_string();
    let new_stamp = Uuid::new_v4().to_string();
    match what {
        "deauth" => {
            db.batch(vec![
                d1_query!(
                    &db,
                    "UPDATE users SET security_stamp = ?1, updated_at = ?2 WHERE uuid = ?3",
                    new_stamp,
                    now,
                    id
                )
                .map_err(|_| AppError::Database)?,
                d1_query!(&db, "DELETE FROM devices WHERE user_uuid = ?1", id)
                    .map_err(|_| AppError::Database)?,
            ])
            .await?;
            crate::notifications::publish_user_logout(env.clone(), id.to_string(), now, None);
            Ok(format!("Sessions of {email} deauthorized."))
        }
        "disable" => {
            db.batch(vec![
                d1_query!(&db, "UPDATE users SET enabled = 0, security_stamp = ?1, updated_at = ?2 WHERE uuid = ?3", new_stamp, now, id)
                    .map_err(|_| AppError::Database)?,
                d1_query!(&db, "DELETE FROM devices WHERE user_uuid = ?1", id).map_err(|_| AppError::Database)?,
            ])
            .await?;
            crate::notifications::publish_user_logout(env.clone(), id.to_string(), now, None);
            Ok(format!("{email} disabled."))
        }
        "enable" => {
            d1_query!(
                &db,
                "UPDATE users SET enabled = 1, updated_at = ?1 WHERE uuid = ?2",
                now,
                id
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await?;
            Ok(format!("{email} enabled."))
        }
        "remove-2fa" => {
            db.batch(vec![
                d1_query!(&db, "DELETE FROM twofactor WHERE user_uuid = ?1", id)
                    .map_err(|_| AppError::Database)?,
                d1_query!(
                    &db,
                    "UPDATE users SET totp_recover = NULL, updated_at = ?1 WHERE uuid = ?2",
                    now,
                    id
                )
                .map_err(|_| AppError::Database)?,
                d1_query!(
                    &db,
                    "UPDATE devices SET twofactor_remember = NULL WHERE user_uuid = ?1",
                    id
                )
                .map_err(|_| AppError::Database)?,
            ])
            .await?;
            crate::handlers::org_policies::enforce_2fa_policy_for_user(&db, id).await?;
            Ok(format!("2FA removed for {email}."))
        }
        "delete" => {
            let sole_owner: Option<Value> = db
                .prepare(
                    "SELECT 1 AS x FROM users_organizations m WHERE m.user_uuid = ?1 AND m.status = 2 AND m.atype = 0
                       AND (SELECT COUNT(*) FROM users_organizations o WHERE o.org_uuid = m.org_uuid AND o.status = 2 AND o.atype = 0) <= 1",
                )
                .bind(&[id.into()])?
                .first(None)
                .await?;
            if sole_owner.is_some() {
                return Err(AppError::BadRequest(
                    "Can't delete the last owner of an organization: delete the organization first"
                        .to_string(),
                ));
            }
            crate::push::unregister_push_devices_by_user(env, id).await;
            if crate::handlers::attachments::attachments_enabled(env) {
                let keys =
                    crate::handlers::attachments::list_attachment_keys_for_user(&db, id).await?;
                crate::handlers::attachments::delete_storage_objects(env, &keys).await?;
            }
            crate::handlers::sends::delete_user_sends(&db, env, id).await?;
            db::delete_user_rows(&db, id).await?;
            d1_query!(&db, "DELETE FROM invitations WHERE email = ?1", email)
                .map_err(|_| AppError::Database)?
                .run()
                .await?;
            Ok(format!("{email} deleted."))
        }
        _ => Err(AppError::NotFound("Unknown action".to_string())),
    }
}

/// POST /admin/users/{id}/{action}
#[worker::send]
pub async fn post_user_action(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path((id, what)): Path<(String, String)>,
) -> Response {
    if let Err(r) = guard(&env, &headers) {
        return r;
    }
    if let Err(e) = check_origin(&env, &headers) {
        return e.into_response();
    }
    let msg = match user_action(&env, &id, &what).await {
        Ok(m) => m,
        Err(e) => format!("Failed: {}", e.client_message()),
    };
    flash_redirect("/admin/users/overview", &msg)
}

/// POST /admin/users/{id}/invite/resend
#[worker::send]
pub async fn resend_invite(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = guard(&env, &headers) {
        return r;
    }
    if let Err(e) = check_origin(&env, &headers) {
        return e.into_response();
    }
    let result: Result<String, AppError> = async {
        let db = db::get_db(&env)?;
        let (email, _) = user_exists(&db, &id)
            .await?
            .ok_or_else(|| AppError::NotFound("User doesn't exist".to_string()))?;
        send_admin_invite(&env, &email).await?;
        Ok(format!("Invitation sent to {email}."))
    }
    .await;
    flash_redirect(
        "/admin/users/overview",
        &result.unwrap_or_else(|e| format!("Failed: {}", e.client_message())),
    )
}

async fn send_admin_invite(env: &Env, email: &str) -> Result<(), AppError> {
    if !crate::mail::mail_enabled(env) {
        return Ok(());
    }
    let text = format!(
        "You have been invited to join {0}.\n\nCreate your account here: {0}/#/signup?email={1}\n\nIf you do not wish to join, you can safely ignore this email.",
        crate::mail::domain(env),
        email.replace('+', "%2B").replace('@', "%40")
    );
    crate::mail::send_email(env, email, "Join AsDevWishes Vault", &text).await
}

#[derive(Deserialize)]
pub struct InviteForm {
    email: String,
}

/// POST /admin/invite: placeholder account + invitation (vaultwarden `invite_user`).
#[worker::send]
pub async fn invite_user(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Form(form): Form<InviteForm>,
) -> Response {
    if let Err(r) = guard(&env, &headers) {
        return r;
    }
    if let Err(e) = check_origin(&env, &headers) {
        return e.into_response();
    }
    let result: Result<String, AppError> = async {
        let email = form.email.trim().to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Err(AppError::BadRequest("Invalid email".to_string()));
        }
        let db = db::get_db(&env)?;
        let exists: Option<Value> = db
            .prepare("SELECT uuid FROM users WHERE email = ?1")
            .bind(&[email.clone().into()])?
            .first(None)
            .await?;
        if exists.is_some() {
            return Err(AppError::BadRequest("User already exists".to_string()));
        }
        let now = db::now_string();
        db.batch(vec![
            d1_query!(&db, "INSERT OR IGNORE INTO invitations (email) VALUES (?1)", email)
                .map_err(|_| AppError::Database)?,
            d1_query!(
                &db,
                "INSERT INTO users (uuid, created_at, updated_at, email, name, password_hash, salt, password_iterations, akey, security_stamp, equivalent_domains, excluded_globals, client_kdf_type, client_kdf_iter)
                 VALUES (?1, ?2, ?2, ?3, '', x'', x'', 600000, '', ?4, '[]', '[]', 0, 600000)",
                Uuid::new_v4().to_string(),
                now,
                email,
                Uuid::new_v4().to_string()
            )
            .map_err(|_| AppError::Database)?,
        ])
        .await?;
        send_admin_invite(&env, &email).await?;
        Ok(format!("{email} invited."))
    }
    .await;
    flash_redirect(
        "/admin",
        &result.unwrap_or_else(|e| format!("Failed: {}", e.client_message())),
    )
}

// ---------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct OrgRow {
    uuid: String,
    name: String,
    billing_email: String,
    members: i64,
    items: i64,
    collections: i64,
    group_count: i64,
    attachment_bytes: i64,
}

/// GET /admin/organizations/overview
#[worker::send]
pub async fn organizations_overview(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<Msg>,
) -> Response {
    if let Err(r) = guard(&env, &headers) {
        return r;
    }
    let orgs: Result<Vec<OrgRow>, AppError> = async {
        let db = db::get_db(&env)?;
        Ok(db
            .prepare(
                "SELECT o.uuid, o.name, o.billing_email,
                        (SELECT COUNT(*) FROM users_organizations m WHERE m.org_uuid = o.uuid) AS members,
                        (SELECT COUNT(*) FROM ciphers c WHERE c.organization_uuid = o.uuid) AS items,
                        (SELECT COUNT(*) FROM collections c WHERE c.org_uuid = o.uuid) AS collections,
                        (SELECT COUNT(*) FROM \"groups\" g WHERE g.organizations_uuid = o.uuid) AS group_count,
                        (SELECT COALESCE(SUM(a.file_size), 0) FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid WHERE c.organization_uuid = o.uuid) AS attachment_bytes
                   FROM organizations o ORDER BY o.name",
            )
            .all()
            .await?
            .results()?)
    }
    .await;
    let Ok(orgs) = orgs else {
        return page(
            "Organizations",
            true,
            Some("Could not load organizations."),
            "",
        );
    };
    let rows: String = orgs
        .iter()
        .map(|o| {
            format!(
                "<tr><td><b>{}</b><div class=muted>{}</div></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&o.name),
                esc(&o.uuid),
                esc(&o.billing_email),
                o.members,
                o.items,
                o.collections,
                o.group_count,
                size_name(o.attachment_bytes),
                action(&format!("/admin/organizations/{}/delete", esc(&o.uuid)), "Delete", true, Some("Delete this organization, its collections and items? This can't be undone.")),
            )
        })
        .collect();
    page(
        "Organizations",
        true,
        q.msg.as_deref(),
        &format!(
            "<table><tr><th>Organization</th><th>Billing email</th><th>Members</th><th>Items</th><th>Collections</th><th>Groups</th><th>Attachments</th><th>Actions</th></tr>{rows}</table>"
        ),
    )
}

/// POST /admin/organizations/{id}/delete
#[worker::send]
pub async fn delete_organization(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = guard(&env, &headers) {
        return r;
    }
    if let Err(e) = check_origin(&env, &headers) {
        return e.into_response();
    }
    let result: Result<String, AppError> = async {
        let db = db::get_db(&env)?;
        crate::handlers::organizations::find_org(&db, &id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization doesn't exist".to_string()))?;
        if crate::handlers::attachments::attachments_enabled(&env) {
            let keys = crate::handlers::attachments::list_attachment_keys_for_org(&db, &id).await?;
            crate::handlers::attachments::delete_storage_objects(&env, &keys).await?;
        }
        crate::handlers::organizations::touch_org_members(&db, &id).await?;
        db.batch(crate::handlers::organizations::delete_org_statements(
            &db, &id,
        )?)
        .await?;
        Ok("Organization deleted.".to_string())
    }
    .await;
    flash_redirect(
        "/admin/organizations/overview",
        &result.unwrap_or_else(|e| format!("Failed: {}", e.client_message())),
    )
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// GET /admin/diagnostics
#[worker::send]
pub async fn diagnostics(State(env): State<Arc<Env>>, headers: HeaderMap) -> Response {
    if let Err(r) = guard(&env, &headers) {
        return r;
    }
    let tables = [
        "users",
        "ciphers",
        "folders",
        "attachments",
        "sends",
        "devices",
        "organizations",
        "users_organizations",
        "collections",
        "groups",
        "org_policies",
        "emergency_access",
        "twofactor",
        "auth_requests",
        "invitations",
    ];
    let counts: Result<Vec<(String, i64)>, AppError> = async {
        let db = db::get_db(&env)?;
        // One row of scalar subqueries: D1 caps the number of terms in a compound SELECT.
        let sql = format!(
            "SELECT {}",
            tables
                .iter()
                .map(|t| format!(r#"(SELECT COUNT(*) FROM "{t}") AS "{t}""#))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let row: Value = db.prepare(sql).first(None).await?.unwrap_or_default();
        Ok(tables
            .iter()
            .map(|t| {
                (
                    t.to_string(),
                    row.get(*t).and_then(Value::as_i64).unwrap_or(0),
                )
            })
            .collect())
    }
    .await;
    let counts_html: String = match counts {
        Ok(c) => c
            .iter()
            .map(|(n, c)| format!("<dt>{}</dt><dd>{c}</dd>", esc(n)))
            .collect(),
        Err(e) => {
            log::error!("admin diagnostics: {e}");
            "<dt>Database</dt><dd>error</dd>".to_string()
        }
    };
    let server_time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    page(
        "Diagnostics",
        true,
        None,
        &format!(
            r#"<dl><dt>Server</dt><dd>vaultwarden-cf (Cloudflare Workers + D1 + R2), crate {ver}</dd><dt>Server time</dt><dd>{server_time}</dd><dt>Domain</dt><dd>{dom}</dd><dt>Mail</dt><dd>{mail}</dd></dl><h3>Rows</h3><dl>{counts_html}</dl>"#,
            ver = env!("CARGO_PKG_VERSION"),
            dom = esc(&crate::mail::domain(&env)),
            mail = if crate::mail::mail_enabled(&env) {
                "enabled (Resend)"
            } else {
                "disabled"
            },
        ),
    )
}
