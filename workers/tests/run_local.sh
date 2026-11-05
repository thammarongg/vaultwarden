#!/usr/bin/env bash
#
# Resets the local D1 database, applies sql/schema.sql, starts `wrangler dev --local`, runs
# tests/smoke.py, then stops the server. Local state only: never touches remote resources.
#
# Env: PORT (default 8787), WRANGLER_VERSION (default latest), SKIP_BUILD=1 to reuse build/.
set -euo pipefail

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

PORT="${PORT:-8787}"
WRANGLER="npx -y wrangler@${WRANGLER_VERSION:-latest}"
LOG="$(mktemp -t wrangler-dev.XXXXXX)"
BASE_URL="http://127.0.0.1:${PORT}"

if lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port ${PORT} is already in use; stop that server or set PORT." >&2
  exit 1
fi

# wrangler dev needs the [assets] directory to exist; the API tests don't use its contents.
[ -e public/web-vault ] || mkdir -p public/web-vault

if [ ! -f .dev.vars ]; then
  cat >.dev.vars <<'VARS'
JWT_SECRET=local-test-jwt-secret-not-for-production
JWT_REFRESH_SECRET=local-test-refresh-secret-not-for-production
ALLOWED_EMAILS=*@example.com
VARS
fi

SERVER_PID=""
cleanup() {
  if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    # wrangler spawns workerd as a child; stop the whole group.
    kill -- "-${SERVER_PID}" 2>/dev/null || kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "== Resetting local D1 state"
rm -rf .wrangler/state
$WRANGLER d1 execute vaultwarden-cf --local --file sql/schema.sql >/dev/null

echo "== Starting wrangler dev on port ${PORT} (log: ${LOG})"
# BASE_URL is overridden so upload/download URLs point here rather than at production.
EXTRA_ARGS=()
[ "${SKIP_BUILD:-0}" = "1" ] && EXTRA_ARGS+=(--no-bundle)
set -m
$WRANGLER dev --local --port "${PORT}" --ip 127.0.0.1 --test-scheduled \
  --var "BASE_URL:${BASE_URL}" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} >"${LOG}" 2>&1 &
SERVER_PID=$!
set +m

echo "== Waiting for the server (includes the release build)"
for _ in $(seq 1 600); do
  if curl -fsS -o /dev/null --max-time 5 "${BASE_URL}/api/alive" 2>/dev/null; then
    READY=1
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    break
  fi
  sleep 1
done
if [ "${READY:-0}" != "1" ]; then
  echo "Server did not become ready. Last log lines:" >&2
  tail -n 40 "${LOG}" >&2
  exit 1
fi

STATUS=0
SMOKE_BASE_URL="${BASE_URL}" python3 -I tests/smoke.py || STATUS=$?

# Handlers swallow nothing here, but the cron purge only reports failures in the log.
if grep -E 'Purge .* failed' "${LOG}" >&2; then
  echo "FAIL: a scheduled purge job reported an error (see above)" >&2
  STATUS=1
fi

if [ "${STATUS}" -ne 0 ]; then
  echo "== Last server log lines" >&2
  tail -n 60 "${LOG}" >&2
fi

cleanup
SERVER_PID=""
trap - EXIT

if [ "${STATUS}" -eq 0 ]; then
  rm -f "${LOG}"
  echo "run_local: PASS"
else
  echo "run_local: FAIL (full log: ${LOG})" >&2
fi
exit "${STATUS}"
