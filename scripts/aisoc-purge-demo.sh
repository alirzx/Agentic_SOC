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

echo "==> Ensuring api image has purge_demo_data (rebuild if needed)"
if ! "${COMPOSE[@]}" exec -T api python -c "import app.scripts.purge_demo_data" 2>/dev/null; then
  echo "    module missing in running image — rebuilding api from local source"
  "${COMPOSE[@]}" build api
  "${COMPOSE[@]}" up -d --force-recreate --no-deps api
  # wait for healthy
  for _ in $(seq 1 30); do
    if "${COMPOSE[@]}" exec -T api python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" 2>/dev/null; then
      break
    fi
    sleep 2
  done
fi

echo "==> Purging seeded demo data"
"${COMPOSE[@]}" exec -T api python -m app.scripts.purge_demo_data
echo "==> Done"
