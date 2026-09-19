#!/usr/bin/env bash
# Bring up the demo stack + Splunk live-ingest spine (no seed data).
# Rebuilds api + connectors from local source so Splunk schema (username/
# password, custom SPL) and purge/bootstrap scripts match the repo.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose --project-directory "$ROOT"
  -f infra/compose/docker-compose.demo.yml
  -f infra/compose/docker-compose.splunk.yml)

echo "==> Building api + connectors from local source"
"${COMPOSE[@]}" build api connectors

echo "==> Starting AiSOC + Splunk ingest spine (api + connectors + ingest + fusion)"
"${COMPOSE[@]}" up -d --remove-orphans --force-recreate \
  api connectors ingest-worker fusion "$@"

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

echo "==> Bootstrapping tenant/user only (no demo incidents)"
"${COMPOSE[@]}" --profile bootstrap run --rm --no-deps bootstrap \
  python -m app.scripts.seed_demo --bootstrap-only

echo "==> Sanity: API → connectors DNS"
docker exec aisoc-demo-api python -c \
  'import urllib.request; print(urllib.request.urlopen("http://connectors:8003/livez").status)'

echo "==> Done. Open http://localhost:${AISOC_WEB_PORT:-5000}"
echo "    Connect Splunk: Connectors → Add → Splunk SIEM"
echo "    Custom SPL: search index=notable | table _time source search_name severity ..."
echo "    Purge leftover seed rows: pnpm aisoc:purge-demo"
