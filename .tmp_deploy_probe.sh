#!/bin/bash
set -euo pipefail
cd /home/api/Agentic_SOC
echo "=== git status ==="
git rev-parse --abbrev-ref HEAD 2>/dev/null || true
git log -1 --oneline 2>/dev/null || true
git status -sb 2>/dev/null | head -20 || true
echo "=== compose images ==="
docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedSince}}' | grep -E 'aisoc-(api|web|agents)' | head -20
echo "=== web ports ==="
docker ps --format '{{.Names}} {{.Status}} {{.Ports}}' | grep -E 'aisoc-demo' | head -25
