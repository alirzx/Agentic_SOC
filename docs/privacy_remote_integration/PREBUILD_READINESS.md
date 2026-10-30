# Pre-build DLP readiness gate

This branch prepares **SOC only** for manual integration with independent
Gateway `alirzx/Agent_Data_privacy_gateway` main at
`91e5150b384f380dc26a48b7301a76f7a8f936d8`.
That Gateway repository was **not changed**.

## Architecture and endpoints

Agents uses `app/privacy/rest_client.py`; API uses its own HTTPX REST transport
in `services/api/app/services/privacy_llm.py`. Neither service installs an
external DLP Python package or Gateway Git repository.
Both call the Gateway's `POST /v1/contexts`, `POST /v1/encode`,
`POST /v1/decode`, and `DELETE /v1/contexts/{id}`.
Agents can keep a context across a complete authorized workflow; API uses
one Context per HTTP LLM call. The model provider is called by SOC, **not**
by the Gateway. The Gateway's /v1/policies response contains objects with
`name` and `version`, not plain strings.

## Environment

Set `AISOC_LLM_PRIVACY_ENABLED=1`,
`AISOC_LLM_PRIVACY_REQUIRED=1`, and
`AISOC_PRIVACY_BACKEND=remote` for BOTH API and Agents.
Also supply the same `AISOC_PRIVACY_REMOTE_URL` (HTTPS VPN/private DNS),
`AISOC_PRIVACY_REMOTE_API_KEY` (Bearer service credential),
`AISOC_PRIVACY_REMOTE_PROFILE=agentic-soc-v1`,
`AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS`, and
`AISOC_PRIVACY_CONTEXT_TTL_SECONDS`.
`AISOC_PRIVACY_TEST_TENANT_ID` is needed only by operator smoke scripts
and must be permitted by Gateway `DLP_CLIENTS_JSON`.
Never commit real credentials or a populated `.env`.

Both clients now require HTTPS when either a production environment OR
`AISOC_LLM_PRIVACY_REQUIRED=1` is configured.

The Gateway host requires a configured service-client SHA-256 hash and
tenant allowlist, a valid encryption master key, Redis for production, and
a TLS termination point. The SOC host needs the Gateway's issuing CA chain
in its container trust store if that CA is private.

## Private CA

For root Compose, only if using a private CA bundle:

```sh
export AISOC_PRIVACY_CA_BUNDLE_HOST=/absolute/path/to/gateway-ca.pem
docker compose -f docker-compose.yml \
  -f infra/compose/privacy-ca.override.yml config --quiet
```

The override mounts a public CA certificate chain read-only into **both**
API and Agents at `/run/secrets/aisoc-dlp-ca.pem` and exports
`SSL_CERT_FILE`. It must NOT contain a private TLS key. On a public CA,
the standard container CA store needs no override. For the demo Compose
the API/Agents service names may differ: validate it independently before
using the override.

## Offline prebuild gate

From repository root, with existing Poetry environments:

```sh
bash scripts/privacy_prebuild_check.sh
```

This runs compilation, script syntax validation, focused API/Agents unit
tests and the non-skipped HTTPX MockTransport contract. The script has bounded
timeouts.
It does NOT perform a Docker build, dependency installation, live Gateway,
Redis, VPN, or provider calls. Run additional existing workflow regressions
before claiming complete coverage.

The API `pyproject.toml` configures `pythonpath = ["."]` under pytest
to make both `poetry run pytest` and `poetry run python -m pytest`
resolve `app` from `services/api`.

## Manual acceptance before staging

1. Run all relevant API/Agents focused regression groups and record actual
   results. The static eight-path inventory is **not** a runtime test.
2. Verify Docker Compose config and build both images with the required
   registry access; smoke-import `app.privacy.rest_client` inside Agents and
   verify that no Gateway Git checkout is fetched during the build.
3. From inside **each container**, verify Gateway HTTPS, CA chain, health,
   readiness, policy discovery, and authenticated Context create/encode/
   decode/delete. Use only synthetic tenants and identities.
4. Test 2 authorized/unauthorized tenants and Context isolation. Confirm
   bearer credentials are injected securely.
5. Capture provider-visible synthetic requests from Auto-Triage,
   four-Agent Investigator, and each of the eight API workflows; confirm
   protection and restoration.
6. Simulate Gateway timeout and Decode failure; no original identity must
   reach the provider on Encode failure and no undecoded response may escape.
7. Verify normal SOC decisions, Cost Governor, streaming, tools, cases, Jira,
   and rollout/rollback gates.

## Evidence state

The original pre-build evidence predates the direct REST migration. Current
migration commands and outcomes are appended to `TEST_REPORT.md`; older rows
remain historical and do not validate the new transport. Do not claim
production readiness until build and live integration pass.

## Final source audit snapshot — 2026-10-30

| Component | Source status | Issue/correction | Validation | Remaining gate |
|---|---|---|---|---|
| Agents Remote transport | Ready for build | Internal HTTPX client; strict status/schema/binding; boolean stats rejected | focused mocked REST/lifecycle tests | live TLS/Auth/Redis |
| API Remote boundary | Ready for build | Added exact Context/Encode/Decode binding, typed stats, immutable alias guidance | focused mocked boundary tests | live provider/Gateway |
| LLM input contract | Ready for build | Multipart/non-string messages now fail before provider rather than validating a stringified copy | contract tests | provider compatibility smoke |
| Tenant propagation | Ready for build | Legacy investigation ownership fixed; API signs canonical tenants; Copilot/Contextual/NL draft route through authenticated API | HMAC, ownership, static routing tests | authenticated container E2E |
| Streaming/tools | Source reviewed | protected stream remains bounded/full-buffer Decode; tools decode then alias/schema/permission validate | existing focused tests | cancellation/live tool smoke |
| Auto-Triage | Ready for build | Removed normalized RBA-score heuristic; added concise evidence/time/rule/MITRE/Sysmon/authorization guidance without changing schema | prompt/payload/disposition tests | real synthetic provider run |
| Packaging | Ready for build | Docker fallback HTTPX range matches pyproject; container copies Python Gateway checker; no external Gateway SDK | packaging/static import tests | image build/import |
| Compose/TLS/network | Config-ready | both services receive DLP settings; API+Agents share signing key; optional CA and external-network overrides | root/demo/override `config --quiet` | actual network/certificate |
| Gateway deployment | External blocker | all-interface `8484` publication contradicts loopback docs; release lacks hardened metrics/audit/key rotation | read-only source audit | Gateway operator remediation/acceptance |

Source/configuration status for this SOC checkout is `SOURCE_READY`,
`CONFIG_READY`, and `STATIC_VALIDATION_PASSED`. The remaining state is
`BUILD_PENDING`, `LIVE_GATEWAY_TEST_PENDING`, `E2E_PENDING`,
`SERVER_DEPLOYMENT_PENDING`, and `PR_PENDING`. `BLOCKED` applies only to the
inaccessible organizational remote/teammate branch and to Gateway-side
production hardening; it does not convert the completed SOC source checks into
runtime evidence.

### Deployment-file comparison with accessible `main`

| File | Feature difference classification | Current correction | Pending check |
|---|---|---|---|
| `docker-compose.yml` | Required Privacy integration | additive API/Agents env; shared internal tenant-signing key | build/start |
| `infra/compose/docker-compose.demo.yml` | Required Privacy integration | same additive env with existing demo topology preserved | build/start |
| `privacy-ca.override.yml` | Required optional configuration | read-only public CA mount into API and Agents | real private CA handshake |
| `privacy-network.override.yml` | Required optional same-host configuration | adds one external network without replacing existing networks | attach Gateway TLS endpoint |
| `services/agents/Dockerfile` | Required packaging plus valid fallback alignment | internal REST import, checker copy, pyproject-matching HTTPX range | Docker build |
| `services/api/Dockerfile` | No feature difference | unchanged | Docker build |
| Agents `pyproject.toml` / lock | No net dependency-version change from accessible main | external Gateway SDK absent; direct HTTPX already declared | Poetry/image resolution |
| API `pyproject.toml` | Valid test-path-only change | `pythonpath=["."]`; no runtime dependency change | API image/tests |
| `.env.example` | Required documentation | one canonical privacy-required setting; smoke-only CA/connect variables labelled | operator secret injection |
| `Makefile` | Unchanged | existing bounded prebuild script is sufficient; no duplicate target added | none |

## Next-session operator handoff

The following stages are commands for a separately authorized build/runtime
session. They were **not** executed by this source audit.

### Stage 1 — Final local preflight

Set no real secrets in tracked files. Recheck the worktree and focused offline
groups, then validate every Compose combination:

```bash
cd /mnt/X/Soorin/Agentic_SOC
git status --short --branch
git diff --check
(cd services/agents && ../../.venv/bin/python -m pytest -q \
  tests/test_privacy_remote_adapter.py tests/test_privacy_remote_contract.py \
  tests/test_privacy_remote_rest_contract.py tests/test_privacy_remote_tool_calls.py \
  tests/test_llm_contract_no_bypass.py tests/test_auto_triage_llm_payload.py)
(cd services/api && DEBUG=0 ../../.venv/bin/python -m pytest -q \
  tests/test_privacy_llm_api_boundary.py tests/test_privacy_api_workflow_inventory.py \
  tests/test_agents_tenant_auth.py tests/test_playbook_privacy_proxy.py)
docker compose -f docker-compose.yml config --quiet
docker compose --project-directory . -f infra/compose/docker-compose.demo.yml config --quiet
```

Success: zero test/config/diff failures and no unexpected tracked files. If an
existing Poetry environment is available, also run
`bash scripts/privacy_prebuild_check.sh`. Do not install packages merely to
hide a missing-environment failure.

### Stage 2 — Docker image build

Use the slim local topology to build only the changed services first:

```bash
docker compose --project-directory . \
  -f infra/compose/docker-compose.demo.yml build api agents
```

Success: both images build; Agents smoke-imports
`PrivacyGatewayRESTClient`; `/app/scripts/check_remote_privacy_gateway.py`
exists. Roll back by retaining the previous image tags; do not delete working
volumes.

### Stage 3 — SOC local startup

First resolve the documented host-port conflicts. In an untracked `.env`, set
the Local integration values and a unique ≥32-byte signing key shared by API
and Agents:

```dotenv
AISOC_LLM_PRIVACY_ENABLED=1
AISOC_LLM_PRIVACY_REQUIRED=0
AISOC_PRIVACY_BACKEND=remote
AISOC_PRIVACY_REMOTE_URL=http://privacy-api:8484
AISOC_PRIVACY_REMOTE_API_KEY=<synthetic-local-service-key>
AISOC_PRIVACY_TEST_TENANT_ID=<authorized-synthetic-uuid>
AISOC_AGENTS_TENANT_SIGNING_KEY=<separate-random-32-plus-byte-key>
AISOC_LLM_HUMAN_TRACE_ENABLED=0
AISOC_PRIVACY_EXTERNAL_NETWORK=aisoc-privacy
```

```bash
docker network inspect aisoc-privacy >/dev/null 2>&1 || docker network create aisoc-privacy
docker compose --project-directory . \
  -f infra/compose/docker-compose.demo.yml \
  -f infra/compose/privacy-network.override.yml \
  up -d postgres redis zookeeper kafka api agents
docker compose --project-directory . -f infra/compose/docker-compose.demo.yml ps
```

Success: API and Agents become healthy without provider calls. This HTTP and
`REQUIRED=0` setup is local synthetic testing only, never a server template.

### Stage 4 — Gateway local startup

In the independent Gateway repository, configure a development-only `.env`
with a 32-byte Base64 master key, a SHA-256 service-key digest, the exact
synthetic tenant allowlist, Redis, and `agentic-soc-v1`; then start its existing
Compose project:

```bash
cd /mnt/X/Soorin/data_privacy_gateway
docker compose up -d redis privacy-api
docker compose ps
GATEWAY_CONTAINER="$(docker compose ps -q privacy-api)"
docker network connect --alias privacy-api aisoc-privacy "$GATEWAY_CONTAINER"
```

The one-time `network connect` is the local-session equivalent of a reviewed
Gateway-side external-network override; prefer the override for repeatable
deployments.
Success: `/health` and `/ready` are healthy; Redis remains unpublished. Rollback
is `docker compose down` without `-v`, preserving state for diagnosis.

### Stage 5 — SOC-to-Gateway network validation

From both SOC containers, resolve `privacy-api`, reach port 8484, and verify the
health response without disabling TLS in server topologies. For the local HTTP
topology:

```bash
docker compose --project-directory /mnt/X/Soorin/Agentic_SOC \
  -f /mnt/X/Soorin/Agentic_SOC/infra/compose/docker-compose.demo.yml \
  exec agents python -c 'import urllib.request; print(urllib.request.urlopen("http://privacy-api:8484/health", timeout=5).status)'
```

Success: HTTP 200 from the container namespace. DNS/route failure is a network
configuration issue; do not weaken certificate verification.

### Stage 6 — Authenticated Gateway API smoke tests

Run the copied no-provider checker inside Agents:

```bash
docker compose --project-directory /mnt/X/Soorin/Agentic_SOC \
  -f /mnt/X/Soorin/Agentic_SOC/infra/compose/docker-compose.demo.yml \
  exec agents python /app/scripts/check_remote_privacy_gateway.py
```

Success: health, readiness, policy, Context create/get, classify, Encode,
Decode, and delete all print `PASS`; no key, Context ID, or payload body prints.
Then run the documented unauthorized-tenant and second-client curl negatives
from a controlled operator environment.

### Stage 7 — Auto-Triage integration test

After injecting an approved provider key and synthetic-only data, optionally
enable HUMAN TRACE in a controlled log sink and run:

```bash
docker compose --project-directory /mnt/X/Soorin/Agentic_SOC \
  -f /mnt/X/Soorin/Agentic_SOC/infra/compose/docker-compose.demo.yml \
  exec agents python -m app.scripts.privacy_provider_probe --privacy on
```

Success: the curated synthetic `llm_payload` path is reported, provider-visible
identities are aliases/redactions, the local verdict schema is unchanged, and
exact identities restore only locally. Disable HUMAN TRACE immediately after.

### Stage 8 — Investigator integration test

Use an authenticated core-API user to launch a synthetic case investigation.
Verify the API adds signed tenant headers, all four agents share one Context,
polling/report routes enforce ownership, and the final report is locally
rehydrated. Success requires no raw identity in provider capture and one
Context delete after the workflow.

```bash
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $AISOC_TEST_USER_JWT" \
  -H 'Content-Type: application/json' \
  -d '{"alert_summary":"Synthetic password spray investigation"}' \
  "http://127.0.0.1:8888/api/v1/cases/$AISOC_TEST_CASE_ID/investigate"
```

### Stage 9 — Remaining API and Agent workflow tests

Exercise the inventory in `LLM_EGRESS_INVENTORY.md`: Copilot and Contextual
through the authenticated core streaming proxy, NL playbook draft through the
authenticated API proxy, Deep Explain with a signed internal caller, router,
runtime/shadow, tools, and all eight API-owned calls. Success means every real
provider request has a preceding Encode and every local result a successful
Decode.

### Stage 10 — Security and failure-mode tests

Repeat with unauthorized tenant, wrong service key, expired Context, Gateway
timeout, malformed 2xx response, Redis outage, Encode failure, Decode failure,
unknown/corrupted alias, oversized protected stream, cancellation, and malformed
tool arguments. Success means zero provider calls after failed Encode and zero
local output/tool execution after failed Decode. Keep `reveal_credentials=false`.

### Stage 11 — Container and platform regression

Run API/Agents health, core customer flows, cost/telemetry single-count checks,
and the normal bounded service regression suites. Confirm HUMAN TRACE is off,
ordinary logs contain no credentials/Context IDs/payloads, and existing
deterministic/privacy-off development remains intentional.

### Stage 12 — PR readiness

Re-run secret scanning, `git diff --check`, changed-file review, focused tests,
Compose config, and documentation links. Record build/live results separately
from historical evidence. Only then request authorization to commit/push/open a
PR; this audit intentionally leaves an uncommitted working tree.

### Stage 13 — Server deployment configuration handoff

Switch to `AISOC_LLM_PRIVACY_REQUIRED=1`, a private HTTPS/VPN DNS endpoint, a
verified public/private CA chain, production Redis, explicit tenant allowlists,
secret-manager injection, `DLP_DEV_MODE=false`, and `DLP_UI_ENABLED=false`.
Resolve the Gateway `8484` exposure and production-hardening blockers first.
Deploy canary tenants, monitor sanitized latency/error/count telemetry, and
retain previous SOC image tags/config plus a controlled privacy-enabled Local
rollback plan. Never roll back to unprotected external-provider egress.
