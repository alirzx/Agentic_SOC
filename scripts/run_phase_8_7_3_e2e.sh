#!/usr/bin/env bash
# Phase 8.7.3 — Run live Splunk E2E on Linux VM (authoritative environment).
# Prerequisites: repo cloned on VM, .env with SPLUNK_PASSWORD set, Python deps installed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "=== Phase 8.7.3 Splunk E2E (VM) ==="
echo "Repo: $ROOT"
echo ""
python3 scripts/test_splunk_gateway.py
echo ""
python3 scripts/run_siem_investigation_probe.py --timeout 300
echo ""
python3 scripts/run_agentic_eval.py --dataset golden-siem --limit 1
echo ""
echo "=== Phase 8.7.3 complete ==="
