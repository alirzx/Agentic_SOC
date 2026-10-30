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

## Environment matrix

“Server required” means required for protected external-provider traffic, not
for deterministic/offline development. Secrets must be injected by the
deployment secret mechanism, never committed in `.env` or Compose source.

| Variable | Component | Required | Local use | Server use | Default | Purpose / security notes |
|---|---|---|---|---|---|---|
| `AISOC_LLM_PRIVACY_ENABLED` | API + Agents | Server | `0` or `1` | `1` | `0` | Enables protection; production/provider startup guards reject unsafe disablement |
| `AISOC_LLM_PRIVACY_REQUIRED` | API + Agents | Server | normally `0` | `1` | `0` | Explicit fail-closed/HTTPS guard even if environment naming is wrong |
| `AISOC_PRIVACY_BACKEND` | API + Agents | Server | `remote` for Gateway integration; Agents may use `local` rollback | `remote` | `local` | API protected calls accept Remote only; no silent Remote→Local fallback |
| `AISOC_PRIVACY_REMOTE_URL` | API + Agents | Remote | local dev or private URL | private HTTPS/VPN DNS | empty | Must not contain URL credentials; HTTPS when required/production |
| `AISOC_PRIVACY_REMOTE_PROFILE` | API + Agents | Remote | same as server | `agentic-soc-v1` | `agentic-soc-v1` | Must exist in Gateway profile directory |
| `AISOC_PRIVACY_REMOTE_API_KEY` | API + Agents | Remote | synthetic dev client | secret-injected service credential | empty | Bearer secret; Gateway stores only its SHA-256 digest in client config |
| `AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS` | API + Agents + smoke | Remote | optional | required/tuned | `30` | Whole HTTP request timeout; valid application range is >0 to 600 seconds |
| `AISOC_PRIVACY_CONTEXT_TTL_SECONDS` | API + Agents | Remote | optional | required/tuned | `3600` | Valid range 60–86400 and cannot exceed Gateway policy maximum |
| `AISOC_PRIVACY_TOKEN_KEY` | Agents only | Local backend | required for Local privacy | not used in Remote | empty | Separate stable ≥32-byte Local pseudonym key; never share with Gateway master key |
| `AISOC_LLM_PRIVACY_STREAM_MAX_CHARS` | Agents | Protected streaming | optional | recommended | `1000000` | Logging-independent memory/safety cap; protected stream buffers before one Decode |
| `AISOC_LLM_HUMAN_TRACE_ENABLED` | Agents | No | controlled debug only | `0` | `0` | Intentionally logs tenant-sensitive payload stages; never routine production telemetry |
| `AISOC_LLM_HUMAN_TRACE_MAX_CHARS` | Agents | Trace only | optional | trace off | `50000` | Logging-only truncation; does not alter provider payloads |
| `AISOC_AGENTS_TENANT_SIGNING_KEY` | API + Agents | Manual/direct Agent workflows | required for API proxy integration | secret-injected | empty | Same separate ≥32-byte HMAC key in both services; not a DLP key |
| `AISOC_AGENTS_ALLOW_UNSIGNED_TENANT_HEADER` | Agents direct API | No | explicit dev only | must be `0` | `0` | Application refuses `1` in production |
| `SSL_CERT_FILE` | API + Agents | Private CA | system store or mounted PEM | trusted public CA chain | Debian system CA path | Standard HTTPX/OpenSSL trust; never set to a private key or disable verification |
| `AISOC_PRIVACY_CA_BUNDLE_HOST` | Compose override | Private CA | absolute public-CA PEM path | deployment-specific | unset | Host source for read-only mount into both SOC clients |
| `AISOC_PRIVACY_EXTERNAL_NETWORK` | Compose override | Same-host option | optional | optional | `aisoc-privacy` | Existing external network name; routing only, not TLS |
| `AISOC_PRIVACY_REMOTE_CA_FILE` | curl smoke only | No | optional | operator diagnostic | unset | Curl-specific CA PEM; not consumed by API or Agents |
| `AISOC_PRIVACY_REMOTE_CONNECT_TIMEOUT_SECONDS` | curl smoke only | No | optional | operator diagnostic | `5` | Curl connection timeout; application uses the request-timeout variable above |
| `AISOC_PRIVACY_TEST_TENANT_ID` | smoke scripts only | Smoke | authorized synthetic UUID | authorized synthetic UUID | unset | Must appear in Gateway service-client tenant allowlist |
| `AISOC_PRIVACY_TEST_UNAUTHORIZED_TENANT_ID` | curl negative smoke | No | distinct synthetic UUID | distinct synthetic UUID | unset | Must not be in the allowlist; never use a real tenant for negative tests |

Gateway operator requirements:

| Variable | Required production value / default | Security purpose |
|---|---|---|
| `DLP_DEV_MODE` | `false` / false | Prevents development credentials and memory-only deployment |
| `DLP_UI_ENABLED` | `false` / false | Browser API-key console is development-only |
| `DLP_STORE_BACKEND` | `redis` / `memory` | Non-development startup rejects memory storage |
| `DLP_REDIS_URL` | authenticated `rediss://...` / local Redis URL | Private persistent Context store; never publish Redis |
| `DLP_MASTER_KEY_B64` | secret-manager value / none | Must decode to exactly 32 bytes; continuity is required for active Contexts |
| `DLP_CLIENTS_JSON` | explicit client array / `[]` | SHA-256 key digest, client ID, canonical tenant allowlist, `allow_tenantless=false`, `allow_secret_decode=false` |
| `DLP_PROFILE_DIR` | directory containing `agentic-soc-v1` / repository profiles | Policy/profile source |
| `DLP_CONTEXT_TTL` | operator value / `3600` | Default Context lifetime |
| `DLP_MAX_CONTEXT_TTL` | operator value / `86400` | Upper TTL bound |
| `DLP_MAX_PAYLOAD_BYTES` | capacity-reviewed / `67108864` | Per-request body limit |
| `DLP_MAX_ENTRIES` | capacity-reviewed / `1000000` | Context mapping limit |

## Topology examples

Local SOC processes with a local development Gateway (synthetic data only):

```dotenv
AISOC_LLM_PRIVACY_ENABLED=1
AISOC_LLM_PRIVACY_REQUIRED=0
AISOC_PRIVACY_BACKEND=remote
AISOC_PRIVACY_REMOTE_URL=http://127.0.0.1:8484
AISOC_PRIVACY_REMOTE_API_KEY=<local-development-service-key>
AISOC_PRIVACY_REMOTE_PROFILE=agentic-soc-v1
```

Local SOC with a Gateway on another private machine:

```dotenv
AISOC_LLM_PRIVACY_ENABLED=1
AISOC_LLM_PRIVACY_REQUIRED=1
AISOC_PRIVACY_BACKEND=remote
AISOC_PRIVACY_REMOTE_URL=https://privacy-gateway.lab.example
AISOC_PRIVACY_REMOTE_API_KEY=<injected-lab-service-key>
SSL_CERT_FILE=/run/secrets/aisoc-dlp-ca.pem
```

Production SOC and Gateway on the same Docker host use the external-network and
private-CA overrides, but still address a certificate-valid TLS endpoint:

```dotenv
AISOC_LLM_PRIVACY_ENABLED=1
AISOC_LLM_PRIVACY_REQUIRED=1
AISOC_PRIVACY_BACKEND=remote
AISOC_PRIVACY_REMOTE_URL=https://privacy-gateway.internal.example
AISOC_PRIVACY_REMOTE_API_KEY=<injected-production-service-key>
AISOC_PRIVACY_CA_BUNDLE_HOST=/absolute/path/to/public-ca-chain.pem
AISOC_PRIVACY_EXTERNAL_NETWORK=aisoc-privacy
```

Production SOC with a Gateway on another host uses the same settings except the
URL resolves/routs over the private network or VPN; no Docker network is shared:

```dotenv
AISOC_LLM_PRIVACY_ENABLED=1
AISOC_LLM_PRIVACY_REQUIRED=1
AISOC_PRIVACY_BACKEND=remote
AISOC_PRIVACY_REMOTE_URL=https://privacy-gateway.vpn.example
AISOC_PRIVACY_REMOTE_API_KEY=<injected-production-service-key>
AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS=30
AISOC_PRIVACY_CONTEXT_TTL_SECONDS=3600
SSL_CERT_FILE=/run/secrets/aisoc-dlp-ca.pem
```

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
The Agents image copies the Python checker to
`/app/scripts/check_remote_privacy_gateway.py`, so the same check can run inside
the actual container/network namespace. The curl script remains a host/operator
tool; the slim Agents image intentionally does not install curl.
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
