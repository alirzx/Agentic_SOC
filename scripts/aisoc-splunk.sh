#!/usr/bin/env bash
# Bring up the demo stack + Splunk live-ingest spine (no seed data).
# Rebuilds api + connectors (+ ingest/fusion/web) from local source so Splunk
# schema and purge/bootstrap scripts match the repo.
#
# If proxy.golang.org is blocked (403), set:
#   export GOPROXY=https://goproxy.cn,direct
#   export GOSUMDB=off
# Or skip rebuilding ingest and reuse the last local/GHCR image:
#   export AISOC_SKIP_INGEST_BUILD=1
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose --project-directory "$ROOT"
  -f infra/compose/docker-compose.demo.yml
  -f infra/compose/docker-compose.splunk.yml)

# Prefer a China/public mirror chain when the official Go proxy 403s.
GOPROXY_VALUE="${GOPROXY:-https://proxy.golang.org,https://goproxy.io,https://goproxy.cn,direct}"
GOSUMDB_VALUE="${GOSUMDB:-sum.golang.org}"
BUILD_ARGS=(--build-arg "GOPROXY=${GOPROXY_VALUE}" --build-arg "GOSUMDB=${GOSUMDB_VALUE}")

BUILD_TARGETS=(api connectors fusion web)
if [[ "${AISOC_SKIP_INGEST_BUILD:-0}" != "1" ]]; then
  BUILD_TARGETS+=(ingest-worker)
else
  echo "==> Skipping ingest-worker build (AISOC_SKIP_INGEST_BUILD=1); using existing image"
fi

echo "==> Building ${BUILD_TARGETS[*]} from local source"
echo "    GOPROXY=${GOPROXY_VALUE}"
"${COMPOSE[@]}" build "${BUILD_ARGS[@]}" "${BUILD_TARGETS[@]}"

echo "==> Starting AiSOC + Splunk ingest spine (api + connectors + ingest + fusion + web)"
"${COMPOSE[@]}" up -d --remove-orphans --force-recreate \
  api connectors ingest-worker fusion web "$@"

echo "==> Waiting for connectors health"
for i in $(seq 1 30); do
  if docker exec aisoc-demo-connectors python -c \
    'import urllib.request; urllib.request.urlopen("http://localhost:8003/livez")' \
    2>/dev/null; then
    echo "    connectors healthy (/livez)"
    break
  fi
  sleep 2
done

echo "==> Waiting for fusion health"
for i in $(seq 1 30); do
  if docker exec aisoc-demo-fusion python -c \
    'import urllib.request; urllib.request.urlopen("http://localhost:8003/health")' \
    2>/dev/null; then
    echo "    fusion healthy (/health)"
    break
  fi
  sleep 2
done

echo "==> Bootstrapping tenant/user only (no demo incidents)"
"${COMPOSE[@]}" --profile bootstrap run --rm --no-deps bootstrap \
  python -m app.scripts.seed_demo --bootstrap-only

echo "==> Sanity: API → connectors + fusion DNS"
docker exec aisoc-demo-api python -c \
  'import urllib.request; print("connectors", urllib.request.urlopen("http://connectors:8003/livez").status); print("fusion", urllib.request.urlopen("http://fusion:8003/health").status)'

echo "==> Done. Open http://localhost:${AISOC_WEB_PORT:-5000}"
echo "    Connect Splunk: Connectors → Add → Splunk SIEM"
echo "    After Sync, open Alerts → Alerts tab (not Entities) for the per-alert list"
echo "    Purge leftover seed rows: pnpm aisoc:purge-demo"
