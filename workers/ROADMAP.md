# vaultwarden on Cloudflare Workers — roadmap

Goal: a Bitwarden-compatible server that runs entirely on Cloudflare
(Workers + D1 + R2 + Durable Objects), with feature parity with vaultwarden
for: personal vault, import from an existing vaultwarden, Organizations /
Collections / Sharing, Emergency access, Admin page, and 2FA beyond TOTP.

Base: [qaz741wsd856/warden-worker](https://github.com/qaz741wsd856/warden-worker)
@ `7a9f6b9` (v0.7.2, MIT, see `LICENSE`), imported into this fork under `workers/`.
The vaultwarden server code in the parent directory (`../src`, `../migrations/sqlite`)
is the reference implementation for porting features.

## Deployment (current)

- Worker: `vaultwarden-cf` → https://vault.asdevwishes.com (custom domain; workers.dev disabled)
- D1: `vaultwarden-cf` (binding `vault1`, APAC)
- R2: `vaultwarden-cf-attachments` (binding `ATTACHMENTS_BUCKET`)
- Durable Objects: `HeavyDo` (CPU offload), `NotifyDo` (WebSocket live sync)
- Secrets: `JWT_SECRET`, `JWT_REFRESH_SECRET`, `ALLOWED_EMAILS`
- Web vault: bw_web_builds `v2026.6.4` downloaded into `public/web-vault/` (not committed)

## Phases

1. **Base on workers.dev** — done. Personal vault, folders, attachments (R2),
   Send, devices, TOTP 2FA, live sync.
2. **Import from vaultwarden** — script that reads a vaultwarden SQLite file
   (`db.sqlite3`) and writes D1 SQL. Needs a column-by-column map between
   `../migrations/sqlite` (final schema) and `sql/schema.sql`.
3. **Organizations / Collections / Sharing** (team use, full vaultwarden parity) — done locally
   (branch `phase3-orgs`), pending web-vault check and deploy.
   Reference: `../src/api/core/organizations.rs`, `../src/api/core/ciphers.rs`,
   `../src/db/models/{organization,collection,group,org_policy,cipher}.rs`.
   - 3.1 Orgs, collections, org ciphers (create/share/collections/org-details/admin aliases/purge),
     sync `profile.organizations` + `collections`; per-user access via `src/models/org_access.rs`.
   - 3.2 Members: invite, reinvite, accept (invite token), confirm, edit, remove, revoke/restore,
     leave, mini-details, public-keys. Invited emails may register outside ALLOWED_EMAILS.
   - 3.3 Groups: CRUD, members, collection access, accessAll; group-derived access in the CTEs.
   - 3.4 Policies: list/get/put/token/master-password; enforced: 2FA required (revokes on enable
     and when a member drops their last 2FA), single org (revokes, blocks joining/creating orgs),
     personal ownership (personal create/edit/import), disable Send, Send options, master
     password policy in the login response. Bulk collection access, bulk-collections,
     org export, import-organization. Custom roles: upstream enables no custom permission yet,
     Custom is stored as Manager like upstream.
   - 3.5 Account recovery (enroll, details, recover-account incl. 2FA reset), org API key
     (create/rotate), event endpoints return empty lists (vaultwarden default, events off).
   Mail: `src/mail.rs`, Resend HTTP API. Enabled when secret `RESEND_API_KEY` and var `MAIL_FROM`
   are set (`MAIL_API_URL` overrides the endpoint for tests). Sending domain
   vault.asdevwishes.com (DKIM + Resend-managed `send.vault` CNAME). Without mail the server
   follows vaultwarden's no-SMTP behavior (existing accounts auto-accepted, registration accepts
   invites, account recovery unavailable).
   Tests: `tests/smoke_orgs.py` (no mail) and `tests/smoke_mail.py` (mock mail API), both run by
   `tests/run_local.sh`.
   Known gaps: org attachments don't count against a storage quota; no "removed from org" email
   when a policy revokes a member; events are not recorded.

4. **Emergency access, Admin page, more 2FA** — `../src/api/core/emergency_access.rs`,
   `../src/api/admin.rs`, `../src/api/core/two_factor/*`. Email 2FA and invites need
   an email sender (Cloudflare Email Service `send_email` binding); WebAuthn needs a
   wasm-compatible verifier.

## Decisions

- Schema: `sql/schema.sql` mirrors vaultwarden's SQLite schema exactly (checked by
  `tests/schema_check.sh`); the Rust models read through `wk_*` views. Only deviation:
  DATETIME stored as ISO-8601 (the importer converts). See AGENTS.md "Database schema".
- Plan: Workers Free for now (heavy endpoints offloaded to `HeavyDo`); revisit at phase 3.

## Backlog from the daily security/update watch

- Port vaultwarden #7563 (2FA userVerificationToken) before moving the web vault past
  v2026.6.4 (web vault 2026.7.1+ needs it to toggle 2FA).
- Port #7837 (delete auth requests with the user — done by `db::delete_user_rows`),
  #7450 (attachment v2 quota), #7777 (don't leak internal errors to clients).
- `cargo update -p ctutils -p tokio` (RUSTSEC-2026-0385/0386).

## Open decisions

- Upstream: how to keep pulling fixes from warden-worker now that the schema diverged.
