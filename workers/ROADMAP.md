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
3. **Organizations / Collections / Sharing** — port from
   `../src/api/core/organizations.rs`, `../src/db/models/{organization,collection,group}.rs`.
   Largest phase: new D1 tables, membership/ACL checks in sync and cipher handlers.
4. **Emergency access, Admin page, more 2FA** — `../src/api/core/emergency_access.rs`,
   `../src/api/admin.rs`, `../src/api/core/two_factor/*`. Email 2FA and invites need
   an email sender (Cloudflare Email Service `send_email` binding); WebAuthn needs a
   wasm-compatible verifier.

## Open decisions

- Schema strategy: converge `sql/schema.sql` toward vaultwarden's SQLite schema
  (easier import and porting) or keep warden-worker's schema and map at import time.
- Plan: Workers Free (10 ms CPU/request, heavy work offloaded to `HeavyDo`) vs
  Workers Paid ($5/month). Organization sync on large vaults may need Paid.
- Upstream: how to keep pulling fixes from warden-worker and from vaultwarden.
