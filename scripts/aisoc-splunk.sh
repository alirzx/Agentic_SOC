#!/usr/bin/env bash
# Bring up the slim demo stack + Splunk live-ingest overlay (no seed data).
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

echo "==> Starting AiSOC + Splunk ingest spine"
"${COMPOSE[@]}" up -d --remove-orphans --force-recreate api connectors "$@"

echo "==> Bootstrapping tenant/user only (no demo incidents)"
"${COMPOSE[@]}" --profile bootstrap run --rm --no-deps bootstrap \
  python -m app.scripts.seed_demo --bootstrap-only

echo "==> Done. Open http://localhost:${AISOC_WEB_PORT:-5000}"
echo "    Connect Splunk: Connectors → Add → Splunk SIEM"
echo "    Use Username/Password (leave Token empty) + Custom SPL"
echo "    Purge leftover seed rows: pnpm aisoc:purge-demo"
