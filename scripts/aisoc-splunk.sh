#!/usr/bin/env bash
# Bring up the slim demo stack + Splunk live-ingest overlay (no seed data).
# Rebuilds the API image from local source so scripts like purge_demo_data and
# seed_demo --bootstrap-only are present (GHCR :latest may lag the repo).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose --project-directory "$ROOT"
  -f infra/compose/docker-compose.demo.yml
  -f infra/compose/docker-compose.splunk.yml)

echo "==> Building api image from local source (Splunk live scripts)"
"${COMPOSE[@]}" build api

echo "==> Starting AiSOC + Splunk ingest spine"
"${COMPOSE[@]}" up -d --remove-orphans --force-recreate api "$@"

echo "==> Bootstrapping tenant/user only (no demo incidents)"
"${COMPOSE[@]}" --profile bootstrap run --rm --no-deps bootstrap \
  python -m app.scripts.seed_demo --bootstrap-only

echo "==> Done. Open http://localhost:${AISOC_WEB_PORT:-5000}"
echo "    Connect Splunk: Connectors → Add → Splunk SIEM"
echo "    Purge leftover seed rows: pnpm aisoc:purge-demo"
