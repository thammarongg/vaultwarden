# Repository Guidelines

## Overview
Warden is a minimal, Bitwarden-compatible backend that runs on Cloudflare Workers (inspired by Vaultwarden).
This crate lives in a vaultwarden fork (AGPL-3.0); porting logic from the parent crate (`../src`) is intended.
The D1 schema mirrors vaultwarden's SQLite schema (see "Database schema" below).
The bundled web UI is shipped as prebuilt artifacts under `public/web-vault/`.
It typically should not be edited.
Unsupported/"won't implement" features are listed in `README.md`.

## Project Structure & Module Organization
- `src/`: Rust backend (Axum router + request handlers).
  - `src/handlers/`: endpoint implementations grouped by feature.
  - `src/models/`: request/response payload types and database models.
  - `src/durable/`: Durable Objects.
    - `HeavyDo` directly reuses the existing Axum router/handlers stack (no duplicated business logic) to offload CPU-heavy endpoints.
    - `NotifyDo` for websocket notifications.
- `src/entry.js`: Wrangler entrypoint (routing + R2 attachment streaming + optional DO offload).
- `migrations/`: incremental D1 migrations on top of `sql/schema.sql` (none yet).
- `sql/`: base schema (`sql/schema.sql`) and optional seed SQL.
- `scripts/`: helper scripts (apply web-vault overrides, seed equivalent domains).
- `docs/`: deployment and D1 backup/restore playbooks.

## Build, Test, and Development Commands
Prereqs: Rust toolchain from `rust-toolchain.toml`, Node.js, and Wrangler.
- `cargo fmt` / `cargo fmt -- --check`: format Rust.
- `cargo clippy --target wasm32-unknown-unknown --no-deps`: lint for the Workers WASM target.
- `cargo test`: run unit tests (currently none).
- Local dev: `wrangler dev --local --persist-to .wrangler/state`.
- Apply migrations (remote): `wrangler d1 migrations apply vault1 --remote`.
- Deploy: `wrangler deploy` (or `wrangler deploy --env dev`).

## Coding Style & Naming Conventions
- Rust: keep routing in `src/router.rs` and endpoint logic in `src/handlers/*`.
- Rust formatting: `rustfmt` (default settings).
- JS: keep edge-only concerns in `src/entry.js` (streaming, request sharding/offload).
- Naming: Rust `snake_case`; files follow feature names (e.g., `handlers/ciphers.rs`).

## Testing Guidelines
There is no established test suite yet.
If adding tests, prefer unit tests in-module (`#[cfg(test)] mod tests`).
Avoid Cloudflare bindings/network.

## Commit & Pull Request Guidelines
- Commits follow Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`.
- PRs should describe behavior changes and list operational impacts:
  D1 migrations, new env vars/secrets, R2/DO bindings.

## Security & Configuration
- Do not commit secrets.
  Use `.env` locally and Cloudflare/GitHub Secrets for deploy:
  `JWT_SECRET`, `JWT_REFRESH_SECRET`, `D1_DATABASE_ID`.

## Database schema
- `sql/schema.sql` section 1 is vaultwarden's SQLite schema verbatim (regenerate from `../migrations/sqlite`; never hand-edit). `bash tests/schema_check.sh` must pass.
- Section 2: Workers-only tables (`attachments_pending`, `sends_pending`, `global_equivalent_domains`), indexes, and read-only `wk_*` views that expose vaultwarden tables in the Rust models' field names.
- Read through `wk_*` views (or `USER_COLS` / `FOLDER_COLS`); write to the real tables with vaultwarden column names (`uuid`, `user_uuid`, `atype`, `akey`, ...).
- Ciphers: the Rust side keeps one JSON blob; `models::cipher::CipherColumns::from_blob` splits it into vaultwarden's columns. Favorite/folder/archive live in `favorites` / `folders_ciphers` / `archives` (use the `set_*_stmts` helpers).
- D1 enforces foreign keys and vaultwarden has no cascades: delete through `db::delete_ciphers_statements` / `db::delete_user_rows`.
- Stored formats: BOOLEAN 0/1, password hashes/salts as BLOB (hex in Rust, `unhex()`/`hex()` in SQL). DATETIME stays ISO-8601 (`YYYY-MM-DDTHH:MM:SS.sssZ`), unlike diesel; an importer must convert.
- Tests: `bash tests/run_local.sh` (local wrangler dev + `tests/smoke.py`, ~7 min because of login rate limits).
