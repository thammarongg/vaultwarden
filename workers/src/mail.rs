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

const BRAND: &str = "AsDevWishes Vault";
const BRAND_COLOR: &str = "#175ddc";

/// Branded HTML version of a plain-text email (the text part is sent unchanged).
///
/// The text templates keep vaultwarden's wording; this derives the layout from them:
/// a paragraph ending in `label: https://...` becomes a button, `code is: 123456` becomes a
/// code box, other URLs become links, and the `===` footer moves to the card's footer.
pub(crate) fn render_html(subject: &str, text: &str) -> String {
    let (body, footer) = match text.split_once("\n\n===\n") {
        Some((b, f)) => (b, f.trim()),
        None => (text, ""),
    };
    let mut blocks = String::new();
    let mut fallback_link = None;
    for para in body.split("\n\n").map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((label, url)) = para.rsplit_once(": ").filter(|(_, u)| {
            (u.starts_with("https://") || u.starts_with("http://"))
                && !u.contains(char::is_whitespace)
        }) {
            let label = label.trim_start_matches("Click here to ").trim();
            let label = if label.is_empty() { "Open" } else { label };
            let mut chars = label.chars();
            let label: String = chars
                .next()
                .map(|c| c.to_uppercase().chain(chars).collect())
                .unwrap_or_default();
            blocks.push_str(&format!(
                r#"<table role="presentation" cellspacing="0" cellpadding="0" style="margin:24px 0"><tr><td style="border-radius:8px;background:{BRAND_COLOR}"><a href="{u}" style="display:inline-block;padding:12px 28px;font-size:16px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:8px">{l}</a></td></tr></table>"#,
                u = escape_html(url),
                l = escape_html(&label),
            ));
            fallback_link = Some(url.to_string());
            continue;
        }
        if let Some((lead, code)) = para.split_once("code is: ") {
            let code = code.split_whitespace().next().unwrap_or_default();
            blocks.push_str(&format!(
                r#"<p style="margin:0 0 12px">{}</p><div style="margin:8px 0 20px;padding:16px;text-align:center;background:#eef2ff;border:1px solid #c7d2fe;border-radius:8px;font-family:SFMono-Regular,Menlo,Consolas,monospace;font-size:32px;font-weight:700;letter-spacing:8px;color:#1e3a8a">{}</div>"#,
                escape_html(&format!("{}code is:", lead)),
                escape_html(code),
            ));
            continue;
        }
        blocks.push_str(&format!(
            r#"<p style="margin:0 0 16px">{}</p>"#,
            linkify(&escape_html(para)).replace('\n', "<br>")
        ));
    }
    let fallback = fallback_link
        .map(|u| {
            format!(
                r#"<p style="margin:16px 0 0;font-size:12px;color:#6b7280">Button not working? Copy this link into your browser:<br><span style="word-break:break-all;color:#374151">{}</span></p>"#,
                escape_html(&u)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>{subject}</title></head>
<body style="margin:0;padding:0;background:#f3f4f6">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f3f4f6;padding:24px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#ffffff;border-radius:12px;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2937">
<tr><td style="background:{BRAND_COLOR};padding:18px 28px"><span style="font-size:18px;font-weight:700;color:#ffffff">&#128274; {BRAND}</span></td></tr>
<tr><td style="padding:28px 28px 8px"><h1 style="margin:0 0 18px;font-size:20px;line-height:1.3;color:#111827">{subject}</h1><div style="font-size:15px;line-height:1.6">{blocks}</div>{fallback}</td></tr>
<tr><td style="padding:20px 28px 26px;border-top:1px solid #e5e7eb;font-size:12px;line-height:1.5;color:#6b7280">{footer}<br>If you didn't expect this email, you can ignore it.</td></tr>
</table></td></tr></table></body></html>"#,
        subject = escape_html(subject),
        footer = linkify(&escape_html(footer)),
    )
}

/// Turn bare http(s) URLs in already-escaped text into links.
fn linkify(escaped: &str) -> String {
    let mut out = String::with_capacity(escaped.len());
    let mut rest = escaped;
    while let Some(i) = rest.find("http") {
        let (before, tail) = rest.split_at(i);
        out.push_str(before);
        if !(tail.starts_with("https://") || tail.starts_with("http://")) {
            out.push_str("http");
            rest = &tail[4..];
            continue;
        }
        let end = tail
            .find(|c: char| c.is_whitespace() || c == ')' || c == '<')
            .unwrap_or(tail.len());
        let url = tail[..end].trim_end_matches(['.', ',']);
        out.push_str(&format!(
            r#"<a href="{url}" style="color:{BRAND_COLOR}">{url}</a>"#
        ));
        rest = &tail[url.len()..];
    }
    out.push_str(rest);
    out
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
    let html = render_html(subject, text);
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

// ---------------------------------------------------------------------------
// Emergency access (vaultwarden `send_emergency_access_*`)
// ---------------------------------------------------------------------------

/// vaultwarden `send_emergency_access_invite`.
pub async fn send_emergency_invite(
    env: &Env,
    to: &str,
    emer_id: &str,
    grantor_name: &str,
    token: &str,
) -> Result<(), AppError> {
    let query = [
        ("id", emer_id),
        ("name", grantor_name),
        ("email", to),
        ("token", token),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={}", form_encode(v)))
    .collect::<Vec<_>>()
    .join("&");
    let url = format!("{}/#/accept-emergency/?{query}", domain(env));
    let text = format!(
        "You have been invited to become an emergency contact for {grantor_name}. To accept this invite, click the following link:\n\nClick here to join: {url}\n\nIf you do not wish to become an emergency contact for {grantor_name}, you can safely ignore this email.{FOOTER}"
    );
    send_email(
        env,
        to,
        &format!("Emergency access for {grantor_name}"),
        &text,
    )
    .await
}

pub async fn send_emergency_invite_accepted(
    env: &Env,
    to: &str,
    grantee_email: &str,
) -> Result<(), AppError> {
    let text = format!(
        "This email is to notify you that {grantee_email} has accepted your invitation to become an emergency access contact.\n\nTo confirm this user, log into the web vault ({}), go to settings and confirm the user.\n\nIf you do not wish to confirm this user, you can also remove them on the same page.{FOOTER}",
        domain(env)
    );
    send_email(
        env,
        to,
        &format!("Emergency access contact {grantee_email} accepted"),
        &text,
    )
    .await
}

pub async fn send_emergency_invite_confirmed(
    env: &Env,
    to: &str,
    grantor_name: &str,
) -> Result<(), AppError> {
    let text = format!(
        "This email is to notify you that you have been confirmed as an emergency access contact for {grantor_name}.\n\nYou can now initiate emergency access requests from the web vault ({}).{FOOTER}",
        domain(env)
    );
    send_email(
        env,
        to,
        &format!("Emergency access contact for {grantor_name} confirmed"),
        &text,
    )
    .await
}

pub async fn send_emergency_recovery_initiated(
    env: &Env,
    to: &str,
    grantee_name: &str,
    atype: &str,
    wait_time_days: i32,
) -> Result<(), AppError> {
    let text = format!(
        "{grantee_name} has initiated an emergency access request to {atype} your account. You may login on the web vault ({}) and manually approve or reject this request.\n\nIf you do nothing, the request will automatically be approved after {wait_time_days} day(s).{FOOTER}",
        domain(env)
    );
    send_email(
        env,
        to,
        &format!("Emergency access request by {grantee_name} initiated"),
        &text,
    )
    .await
}

pub async fn send_emergency_recovery_reminder(
    env: &Env,
    to: &str,
    grantee_name: &str,
    atype: &str,
) -> Result<(), AppError> {
    let text = format!(
        "{grantee_name} has a pending emergency access request to {atype} your account. You may login on the web vault ({}) and manually approve or reject this request.\n\nIf you do nothing, the request will automatically be approved after 1 day(s).{FOOTER}",
        domain(env)
    );
    send_email(
        env,
        to,
        &format!("Emergency access request by {grantee_name} is pending"),
        &text,
    )
    .await
}

pub async fn send_emergency_recovery_approved(
    env: &Env,
    to: &str,
    grantor_name: &str,
) -> Result<(), AppError> {
    let text = format!(
        "{grantor_name} has approved your emergency access request. You may now login on the web vault ({}) and access their account.{FOOTER}",
        domain(env)
    );
    send_email(
        env,
        to,
        &format!("Emergency access request for {grantor_name} approved"),
        &text,
    )
    .await
}

pub async fn send_emergency_recovery_rejected(
    env: &Env,
    to: &str,
    grantor_name: &str,
) -> Result<(), AppError> {
    let text = format!("{grantor_name} has rejected your emergency access request.{FOOTER}");
    send_email(
        env,
        to,
        &format!("Emergency access request to {grantor_name} rejected"),
        &text,
    )
    .await
}

pub async fn send_emergency_recovery_timed_out(
    env: &Env,
    to: &str,
    grantee_name: &str,
    atype: &str,
) -> Result<(), AppError> {
    let text = format!(
        "{grantee_name} has been granted emergency access to {atype} your account. You may login on the web vault ({}) and manually revoke this request.{FOOTER}",
        domain(env)
    );
    send_email(
        env,
        to,
        &format!("Emergency access request by {grantee_name} granted"),
        &text,
    )
    .await
}

/// vaultwarden `send_token` (email 2FA code).
pub async fn send_twofactor_token(env: &Env, to: &str, token: &str) -> Result<(), AppError> {
    let text = format!(
        "Your two-step verification code is: {token}\n\nUse this code to complete logging in with AsDevWishes Vault.{FOOTER}"
    );
    send_email(env, to, "AsDevWishes Vault Login Verification Code", &text).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_has_button_code_and_escaping() {
        let h = render_html(
            "Join <Family>",
            "You have been invited to join the <Family> organization.\n\nClick here to join: https://vault.example/#/accept?a=1&b=2\n\n===\nThis email was sent by AsDevWishes Vault (vault.example).",
        );
        assert!(h.contains(r#"href="https://vault.example/#/accept?a=1&amp;b=2""#));
        assert!(h.contains(">Join</a>"));
        assert!(h.contains("&lt;Family&gt;") && !h.contains("<Family>"));
        let c = render_html(
            "Code",
            "Your two-step verification code is: 482913\n\nUse it.",
        );
        assert!(c.contains(">482913</div>"));
    }

    /// `MAIL_PREVIEW_DIR=/tmp/x cargo test --lib mail::tests::write_previews` writes sample HTML.
    #[test]
    fn write_previews() {
        let Ok(dir) = std::env::var("MAIL_PREVIEW_DIR") else {
            return;
        };
        let samples = [
            ("org-invite", "Join Family", format!("You have been invited to join the Family organization.\n\nClick here to join: https://vault.asdevwishes.com/#/accept-organization/?email=mom%40example.com&organizationName=Family&token=eyJhbGciOi...\n\nIf you do not wish to join this organization, you can safely ignore this email.{FOOTER}")),
            ("2fa-code", "AsDevWishes Vault Login Verification Code", format!("Your two-step verification code is: 482913\n\nUse this code to complete logging in with AsDevWishes Vault.{FOOTER}")),
            ("emergency-invite", "Emergency access for Thammarong", format!("You have been invited to become an emergency contact for Thammarong. To accept this invite, click the following link:\n\nClick here to join: https://vault.asdevwishes.com/#/accept-emergency/?id=1&name=Thammarong&token=eyJhbGciOi...\n\nIf you do not wish to become an emergency contact for Thammarong, you can safely ignore this email.{FOOTER}")),
            ("emergency-initiated", "Emergency access request by Somchai initiated", format!("Somchai has initiated an emergency access request to Takeover your account. You may login on the web vault (https://vault.asdevwishes.com) and manually approve or reject this request.\n\nIf you do nothing, the request will automatically be approved after 7 day(s).{FOOTER}")),
        ];
        for (name, subject, text) in samples {
            std::fs::write(format!("{dir}/{name}.html"), render_html(subject, &text)).unwrap();
        }
    }
}
