#!/usr/bin/env bash
# Source-only, no-network prebuild check for API + Agents privacy integration.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3.11}"
TEST_TIMEOUT="${AISOC_PRIVACY_TEST_TIMEOUT_SECONDS:-45}"
RUNNER="${AISOC_PRIVACY_TEST_RUNNER:-poetry}"
echo "Privacy prebuild source checks; no network, Docker build, or provider calls."

"$PYTHON_BIN" -m compileall -q services/api/app/services/privacy_llm.py services/api/app/api/v1/endpoints services/agents/app/privacy services/agents/app/api
bash -n services/agents/scripts/privacy_gateway_curl_smoke.sh

if ! command -v "$RUNNER" >/dev/null 2>&1; then
  echo "BLOCKED: $RUNNER unavailable; existing environments are required." >&2
  exit 3
fi

(
  cd services/api
  timeout "$TEST_TIMEOUT" "$RUNNER" run python -m pytest -q tests/test_privacy_llm_api_boundary.py
)
(
  cd services/agents
  timeout "$TEST_TIMEOUT" "$RUNNER" run python -m pytest -q \
    tests/test_privacy_final_ownership.py \
    tests/test_privacy_remote_adapter.py \
    tests/test_privacy_remote_contract.py \
    tests/test_privacy_remote_sdk_contract.py
)
echo "PASS: bounded offline privacy prebuild checks completed."
