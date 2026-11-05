#!/usr/bin/env bash
#
# Migration check: run a real vaultwarden (docker), fill it with data, import its db.sqlite3 and
# files into a fresh local D1/R2 with scripts/import_vaultwarden.py, then check the Worker serves
# the same vault. Local only: never touches remote resources.
#
# Env: PORT (Worker, default 8787), VW_PORT (default 8798), VW_IMAGE (default vaultwarden/server:1.37.5),
#      WRANGLER_VERSION (default: .wrangler-version).
set -euo pipefail

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

PORT="${PORT:-8787}"
VW_PORT="${VW_PORT:-8798}"
VW_IMAGE="${VW_IMAGE:-vaultwarden/server:1.37.5}"
WRANGLER="npx -y wrangler@${WRANGLER_VERSION:-$(cat .wrangler-version)}"
WORK="$(mktemp -d -t vw-import.XXXXXX)"
STATE="${WORK}/wrangler-state"
NAME="vw-import-check-$$"
SERVER_PID=""

cleanup() {
  docker rm -f "${NAME}" >/dev/null 2>&1 || true
  if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill -- "-${SERVER_PID}" 2>/dev/null || kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

wait_up() {
  local url="$1" tries="$2"
  for _ in $(seq 1 "${tries}"); do
    curl -fsS -o /dev/null --max-time 3 "${url}" 2>/dev/null && return 0
    sleep 2
  done
  echo "server at ${url} did not come up" >&2
  return 1
}

echo "== Starting ${VW_IMAGE} on port ${VW_PORT}"
mkdir -p "${WORK}/vw-data"
docker run -d --name "${NAME}" -p "127.0.0.1:${VW_PORT}:80" -v "${WORK}/vw-data:/data" \
  -e SIGNUPS_ALLOWED=true -e ORG_GROUPS_ENABLED=true -e DOMAIN="http://127.0.0.1:${VW_PORT}" \
  -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 "${VW_IMAGE}" >/dev/null
wait_up "http://127.0.0.1:${VW_PORT}/alive" 60

python3 -I tests/import_check.py seed "http://127.0.0.1:${VW_PORT}" "${WORK}/expect.json"

echo "== Stopping vaultwarden and exporting"
docker stop "${NAME}" >/dev/null
python3 -I scripts/import_vaultwarden.py --db "${WORK}/vw-data/db.sqlite3" --data-dir "${WORK}/vw-data" \
  --out "${WORK}/import.sql" --r2-script "${WORK}/r2.sh" --r2-flags "--local --persist-to ${STATE}"

echo "== Fresh local D1 + import"
$WRANGLER d1 execute vaultwarden-cf --local --persist-to "${STATE}" --file sql/schema.sql >/dev/null
$WRANGLER d1 execute vaultwarden-cf --local --persist-to "${STATE}" --file "${WORK}/import.sql" >/dev/null
bash "${WORK}/r2.sh" >/dev/null

echo "== Starting wrangler dev on port ${PORT}"
[ -e public/web-vault ] || mkdir -p public/web-vault
set -m
$WRANGLER dev --local --port "${PORT}" --ip 127.0.0.1 --persist-to "${STATE}" \
  --var "BASE_URL:http://127.0.0.1:${PORT}" >"${WORK}/wrangler.log" 2>&1 &
SERVER_PID=$!
set +m
wait_up "http://127.0.0.1:${PORT}/api/alive" 300

if ! python3 -I tests/import_check.py verify "http://127.0.0.1:${PORT}" "${WORK}/expect.json"; then
  grep -iE 'error|panic' "${WORK}/wrangler.log" | tail -20 >&2 || true
  exit 1
fi
echo "import_check: PASS"
