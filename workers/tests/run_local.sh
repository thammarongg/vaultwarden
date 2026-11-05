#!/usr/bin/env bash
#
# Resets the local D1 database, applies sql/schema.sql, starts `wrangler dev --local`, runs
# tests/smoke.py, smoke_orgs.py, smoke_emergency.py and smoke_2fa.py, then restarts it with mail enabled (mock API) for
# tests/smoke_mail.py. Local state only: never touches remote resources.
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

# start_server LOGFILE [extra --var args...]: start wrangler dev and wait until it answers.
start_server() {
  local log="$1"
  shift
  echo "== Starting wrangler dev on port ${PORT} (log: ${log})"
  # BASE_URL is overridden so upload/download URLs point here rather than at production.
  local extra=()
  [ "${SKIP_BUILD:-0}" = "1" ] && extra+=(--no-bundle)
  set -m
  $WRANGLER dev --local --port "${PORT}" --ip 127.0.0.1 --test-scheduled \
    --var "BASE_URL:${BASE_URL}" "$@" ${extra[@]+"${extra[@]}"} >"${log}" 2>&1 &
  SERVER_PID=$!
  set +m
  echo "== Waiting for the server (includes the release build)"
  local ready=0
  for _ in $(seq 1 600); do
    if curl -fsS -o /dev/null --max-time 5 "${BASE_URL}/api/alive" 2>/dev/null; then
      ready=1
      break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  if [ "${ready}" != "1" ]; then
    echo "Server did not become ready. Last log lines:" >&2
    tail -n 40 "${log}" >&2
    exit 1
  fi
}

STATUS=0
start_server "${LOG}"
SMOKE_BASE_URL="${BASE_URL}" python3 -I tests/smoke.py || STATUS=$?
[ "${STATUS}" -eq 0 ] && { SMOKE_BASE_URL="${BASE_URL}" python3 -I tests/smoke_orgs.py || STATUS=$?; }
[ "${STATUS}" -eq 0 ] && { SMOKE_BASE_URL="${BASE_URL}" python3 -I tests/smoke_emergency.py || STATUS=$?; }
# WebAuthn needs ECDSA signing: `cryptography` via uv (skipped with a warning when uv is missing).
if [ "${STATUS}" -eq 0 ]; then
  if command -v uv >/dev/null 2>&1; then
    SMOKE_BASE_URL="${BASE_URL}" uv run -q --with cryptography python tests/smoke_2fa.py || STATUS=$?
  else
    echo "WARNING: uv not found, tests/smoke_2fa.py skipped" >&2
  fi
fi

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

# Second server with mail enabled, pointed at the mock mail API that smoke_mail.py runs.
MAIL_LOG="$(mktemp -t wrangler-dev-mail.XXXXXX)"
MAIL_MOCK_PORT="${MAIL_MOCK_PORT:-8799}"
if [ "${STATUS}" -eq 0 ]; then
  start_server "${MAIL_LOG}" --var "RESEND_API_KEY:local-test-key" \
    --var "MAIL_API_URL:http://127.0.0.1:${MAIL_MOCK_PORT}"
  SMOKE_BASE_URL="${BASE_URL}" MAIL_MOCK_PORT="${MAIL_MOCK_PORT}" python3 -I tests/smoke_mail.py || STATUS=$?
  if [ "${STATUS}" -ne 0 ]; then
    echo "== Last server log lines (mail)" >&2
    tail -n 60 "${MAIL_LOG}" >&2
  fi
  cleanup
  SERVER_PID=""
fi
trap - EXIT

if [ "${STATUS}" -eq 0 ]; then
  rm -f "${LOG}" "${MAIL_LOG}"
  echo "run_local: PASS"
else
  echo "run_local: FAIL (logs: ${LOG} ${MAIL_LOG})" >&2
fi
exit "${STATUS}"
