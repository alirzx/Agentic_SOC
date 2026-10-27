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
