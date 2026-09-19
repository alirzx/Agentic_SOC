#!/usr/bin/env bash
# Delete seeded demo alerts/cases so the dashboard shows live connector data only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose --project-directory "$ROOT"
  -f infra/compose/docker-compose.demo.yml
  -f infra/compose/docker-compose.splunk.yml)

if ! docker ps --format '{{.Names}}' | grep -qx 'aisoc-demo-api'; then
  echo "aisoc-demo-api is not running. Start the stack first: pnpm aisoc:splunk"
  exit 1
fi

echo "==> Purging seeded demo data"
"${COMPOSE[@]}" exec -T api python -m app.scripts.purge_demo_data
echo "==> Done"
