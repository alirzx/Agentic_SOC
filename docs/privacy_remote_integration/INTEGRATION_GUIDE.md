# Integration Guide

## Install

Agents uses the repository's normal HTTPX dependency and its internal REST
client. No external DLP package or Gateway Git checkout is required:

```bash
cd services/agents
poetry install --with dev
```

Do not install the Gateway backend into the SOC environment.

## Configure Agentic SOC

```dotenv
AISOC_LLM_PRIVACY_ENABLED=1
AISOC_LLM_PRIVACY_REQUIRED=1
AISOC_PRIVACY_BACKEND=remote
AISOC_PRIVACY_REMOTE_URL=https://privacy-gateway.internal.example
AISOC_PRIVACY_REMOTE_PROFILE=agentic-soc-v1
AISOC_PRIVACY_REMOTE_API_KEY=<secret-manager-injected-service-credential>
AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS=30
AISOC_PRIVACY_CONTEXT_TTL_SECONDS=3600
AISOC_LLM_PRIVACY_STREAM_MAX_CHARS=1000000
# Mount this path in the agents container when the Gateway uses a private CA:
SSL_CERT_FILE=/run/secrets/privacy-gateway-ca.pem
```

Do not set `AISOC_PRIVACY_TOKEN_KEY` for Remote mode. It belongs only to the
legacy Local backend. Production startup validates the URL, profile, service
credential, timeout, TTL, and HTTPS requirement before marking the service
ready.

The Gateway client configured by `DLP_CLIENTS_JSON` must authorize the exact
canonical tenant UUIDs that the SOC trusted resolver produces.

## Gateway connectivity check

Use an explicitly authorized synthetic test tenant. This never contacts an LLM
provider:

```bash
export AISOC_PRIVACY_TEST_TENANT_ID=11111111-1111-1111-1111-111111111111
python3 services/agents/scripts/check_remote_privacy_gateway.py
bash services/agents/scripts/privacy_gateway_curl_smoke.sh
```

It checks health, readiness, policy availability, context create/get/delete,
encode/decode equality, classify statistics, and exits nonzero on any failure.
It never prints the credential, Context ID, or payload bodies.
See `CURL_SMOKE_RUNBOOK.md` for cross-host/container execution and selectable
negative checks. See `SOC_E2E_VERIFICATION.md` for controlled provider stages.

## Later deployment verification

```bash
docker compose config --quiet
docker compose up -d --build agents
docker compose logs --since=5m agents
```

Expected ordinary logs are `privacy.remote.operation` with sanitized counts and
latencies. Detailed HUMAN TRACE payload events remain off unless deliberately
enabled for controlled debugging.

These commands are operator steps unless explicitly recorded in
`TEST_REPORT.md`; configuration validation alone is not deployment evidence.

## Focused tests

```bash
cd services/agents
python -m pytest -q \
  tests/test_privacy_remote_adapter.py \
  tests/test_privacy_remote_contract.py \
  tests/test_privacy_remote_rest_contract.py \
  tests/test_privacy_remote_tool_calls.py \
  tests/test_auto_triage_llm_payload.py
```

Perform a real provider probe only after the Gateway tests pass and only with
approved synthetic credentials/data. It is not part of the offline suite.
