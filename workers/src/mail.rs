//! Outbound email (phase 3), provider-agnostic with Resend as the first provider.
//!
//! Enabled when the `RESEND_API_KEY` secret and the `MAIL_FROM` var are both set. Without them the
//! server behaves like vaultwarden without SMTP (invites auto-accept existing accounts, account
//! recovery is unavailable). `MAIL_API_URL` overrides the Resend endpoint (local tests point it at
//! a mock server). Templates mirror vaultwarden's `src/static/templates/email/*.hbs` text.

use serde_json::json;
use worker::{Env, Fetch, Method, Request, RequestInit};

use crate::error::AppError;

const RESEND_API_URL: &str = "https://api.resend.com";

fn non_empty_var(env: &Env, name: &str) -> Option<String> {
    env.var(name)
        .ok()
        .map(|v| v.to_string())
        .or_else(|| env.secret(name).ok().map(|v| v.to_string()))
        .filter(|v| !v.trim().is_empty())
}

/// vaultwarden `CONFIG.mail_enabled()`.
pub fn mail_enabled(env: &Env) -> bool {
    non_empty_var(env, "RESEND_API_KEY").is_some() && non_empty_var(env, "MAIL_FROM").is_some()
}

/// Public URL of the web vault (BASE_URL), without a trailing slash.
pub fn domain(env: &Env) -> String {
    non_empty_var(env, "BASE_URL")
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string()
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Send one email. Errors are returned so callers can roll back (vaultwarden does for invites).
pub async fn send_email(env: &Env, to: &str, subject: &str, text: &str) -> Result<(), AppError> {
    let (Some(key), Some(from)) = (
        non_empty_var(env, "RESEND_API_KEY"),
        non_empty_var(env, "MAIL_FROM"),
    ) else {
        return Err(AppError::BadRequest("Email is not configured".to_string()));
    };
    let base = non_empty_var(env, "MAIL_API_URL").unwrap_or_else(|| RESEND_API_URL.to_string());
    let html = format!(
        "<div style=\"font-family:-apple-system,Segoe UI,Roboto,sans-serif;font-size:15px;line-height:1.5\">{}</div>",
        escape_html(text)
            .split("\n\n")
            .map(|p| format!("<p>{}</p>", p.replace('\n', "<br>")))
            .collect::<String>()
    );
    let body = json!({
        "from": from,
        "to": [to],
        "subject": subject,
        "text": text,
        "html": html,
    })
    .to_string();
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(body.into()));
    let mut req = Request::new_with_init(&format!("{}/emails", base.trim_end_matches('/')), &init)
        .map_err(AppError::Worker)?;
    let headers = req.headers_mut().map_err(AppError::Worker)?;
    headers
        .set("Authorization", &format!("Bearer {key}"))
        .map_err(AppError::Worker)?;
    headers
        .set("Content-Type", "application/json")
        .map_err(AppError::Worker)?;
    let mut resp = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&resp.status_code()) {
        let detail = resp.text().await.unwrap_or_default();
        log::error!(
            "Email to {to} failed ({}): {}",
            resp.status_code(),
            detail.chars().take(300).collect::<String>()
        );
        return Err(AppError::BadRequest(
            "Error sending email, please try again later".to_string(),
        ));
    }
    Ok(())
}

/// application/x-www-form-urlencoded value encoding (what `url::form_urlencoded` produces).
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

const FOOTER: &str = "\n\n===\nThis email was sent by AsDevWishes Vault (vault.asdevwishes.com).";

/// vaultwarden `send_org_invite`.
pub async fn send_invite(
    env: &Env,
    to: &str,
    org_id: &str,
    member_id: &str,
    org_name: &str,
    token: &str,
    has_existing_user: bool,
) -> Result<(), AppError> {
    let pairs = [
        ("email", to),
        ("organizationName", org_name),
        ("organizationId", org_id),
        ("organizationUserId", member_id),
        ("token", token),
        // The web vault rejects the link client-side unless both are present.
        ("initOrganization", "false"),
        (
            "orgUserHasExistingUser",
            if has_existing_user { "true" } else { "false" },
        ),
    ];
    let query = pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", form_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let url = format!("{}/#/accept-organization/?{query}", domain(env));
    let text = format!(
        "You have been invited to join the {org_name} organization.\n\nClick here to join: {url}\n\nIf you do not wish to join this organization, you can safely ignore this email.{FOOTER}"
    );
    send_email(env, to, &format!("Join {org_name}"), &text).await
}

/// vaultwarden `send_invite_accepted` (to the inviter).
pub async fn send_invite_accepted(
    env: &Env,
    to: &str,
    new_user_email: &str,
    org_name: &str,
) -> Result<(), AppError> {
    let text = format!(
        "Your invitation for {new_user_email} to join {org_name} was accepted.\nPlease log in to {} to confirm them.{FOOTER}",
        domain(env)
    );
    send_email(env, to, "Invitation accepted", &text).await
}

/// vaultwarden `send_invite_confirmed`.
pub async fn send_invite_confirmed(env: &Env, to: &str, org_name: &str) -> Result<(), AppError> {
    let text = format!(
        "This email is to notify you that you have been confirmed as a user of {org_name}.\nAny collections and logins being shared with you by this organization will now appear in your vault at {}.{FOOTER}",
        domain(env)
    );
    send_email(
        env,
        to,
        &format!("Invitation to {org_name} confirmed"),
        &text,
    )
    .await
}

/// vaultwarden `send_admin_account_recovery`.
pub async fn send_admin_account_recovery(
    env: &Env,
    to: &str,
    user_name: &str,
    org_name: &str,
    reset_password: bool,
    reset_2fa: bool,
) -> Result<(), AppError> {
    let mut text = String::new();
    if reset_password {
        text.push_str(&format!(
            "The master password for {user_name} has been changed.\n"
        ));
    }
    if reset_2fa {
        text.push_str("Your two-step verification providers have been reset.\n");
    }
    text.push_str("\nIf you did not initiate this request, please reach out to your administrator immediately.");
    text.push_str(FOOTER);
    send_email(
        env,
        to,
        &format!("Admin account recovery from {org_name} organization"),
        &text,
    )
    .await
}
