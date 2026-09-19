#!/usr/bin/env bash
# Bring up the slim demo stack + Splunk live-ingest overlay (no seed data).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose --project-directory "$ROOT"
  -f infra/compose/docker-compose.demo.yml
  -f infra/compose/docker-compose.splunk.yml)

echo "==> Starting AiSOC + Splunk ingest spine"
"${COMPOSE[@]}" up -d --remove-orphans "$@"

echo "==> Bootstrapping tenant/user (no demo incidents)"
"${COMPOSE[@]}" --profile bootstrap up bootstrap

echo "==> Done. Open http://localhost:${AISOC_WEB_PORT:-5000}"
echo "    Connect Splunk: Connectors → Add → Splunk SIEM"
echo "    Purge leftover seed rows: pnpm aisoc:purge-demo"
