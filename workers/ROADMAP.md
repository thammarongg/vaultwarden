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
3. **Organizations / Collections / Sharing** (team use, full vaultwarden parity) — in progress.
   Reference: `../src/api/core/organizations.rs` (65 routes), `../src/api/core/ciphers.rs`
   (share/collections), `../src/db/models/{organization,collection,group,org_policy,cipher}.rs`.
   Vertical slices, each with smoke tests + a real web-vault check before merging:
   Status: 3.1 done; 3.2 done except invite emails / invite-token accept (needs mailer); 3.3-3.5 todo.
   - 3.1 Owner-only org: create/get/update/delete org, keys/public-key, plans/billing stubs;
     collections CRUD; org ciphers (create with collections, share personal -> org, edit,
     collections assignment, delete, restore); `/api/ciphers/organization-details`; sync with
     `profile.organizations`, `collections`, per-user cipher access (owner / access_all /
     users_collections / groups) and per-user favorite/folder/archive (replaces the owner-only
     `wk_ciphers` assumption).
   - 3.2 Members: invite (+ email), reinvite, accept (invite token), confirm (bulk), edit role
     and collections, remove, revoke/restore, leave, mini-details, public-keys; invited emails
     may register even when not in ALLOWED_EMAILS (`invitations` table).
   - 3.3 Groups: CRUD, members, collection access; group-derived cipher access.
   - 3.4 Custom roles (manage_users/groups/policies/... flags), policies list/get/put and
     enforcement (2FA required, single org, personal ownership, send options, master password,
     reset password), org export, import-organization, bulk-collections, collections bulk-access.
   - 3.5 Account recovery (admin reset password), org API key, events (minimal).
   Notes: access rules are SQL CTEs in `src/models/org_access.rs` (one query per request, no N+1);
   org cipher changes bump `updated_at` and send a SyncCiphers push to every other member who can
   see the cipher. Org attachments don't count against any per-user storage quota yet.
   Email: provider-agnostic mailer; first provider Resend (HTTP API, secret `RESEND_API_KEY`,
   domain asdevwishes.com verified at Resend). Workers plan stays Free (Cloudflare Email Sending
   to arbitrary recipients needs Paid). Without a configured mailer the server follows
   vaultwarden's no-SMTP behavior (existing users auto-accepted, invitations table for new ones).
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
