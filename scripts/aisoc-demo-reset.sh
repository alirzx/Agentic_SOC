#!/usr/bin/env bash
# Force-clear leftover aisoc-demo containers/ports, then bring the demo stack up.
# Use this when Docker reports "port is already allocated" for 5432/5433/6379/6380/etc.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose --project-directory "$ROOT" -f infra/compose/docker-compose.demo.yml)

echo "==> Removing leftover aisoc-demo containers (any project)"
mapfile -t IDS < <(docker ps -aq --filter "name=aisoc-demo" || true)
if ((${#IDS[@]} > 0)); then
  docker rm -f "${IDS[@]}" || true
fi

echo "==> compose down --remove-orphans"
"${COMPOSE[@]}" down -v --remove-orphans || true

echo "==> Ports that still look busy (host):"
ss -lntp 2>/dev/null | grep -E ':(5432|5433|15432|6379|6380|16379|9092|9093|19092)\b' || true

echo "==> compose up -d"
"${COMPOSE[@]}" up -d --remove-orphans

echo "==> status"
"${COMPOSE[@]}" ps

echo
echo "Next: pnpm aisoc:doctor"
echo "Console: http://localhost:5000  (or http://<vm-ip>:5000)"
