# SOC-to-Gateway End-to-End Verification

This is a manual staging runbook. It must use synthetic alerts, approved test
tenants, a controlled provider account, and access-controlled logs. Passing
offline mocks is not live validation.

## Stage A — Gateway API connectivity

Run the Python smoke and curl smoke from the Gateway host, SOC host, and agents
container as described in `CURL_SMOKE_RUNBOOK.md`:

```bash
python3 services/agents/scripts/check_remote_privacy_gateway.py
bash services/agents/scripts/privacy_gateway_curl_smoke.sh
```

Confirm health, ready store, `agentic-soc-v1`, Context binding, classify,
Encode, exact Decode, unknown aliases zero, and delete.

## Stage B — SOC Remote Adapter

Use the existing provider probe with synthetic data only after Stage A:

```bash
cd services/agents
PYTHONPATH=. python3 -m app.scripts.privacy_provider_probe --privacy on
```

In a provider-spy environment, capture the four HUMAN TRACE stages for one
short controlled run. `INTERNAL_INPUT` may contain the synthetic canonical
host/user; `PROVIDER_INPUT` must contain only aliases/redactions;
`PROVIDER_RESPONSE` must still be protected; `LOCAL_RESPONSE` must exactly
restore authorized identities. Disable HUMAN TRACE immediately afterward.

## Stage C — Auto-Triage

Publish one synthetic Splunk notable through the normal connector/ingest/fusion
route with a serialized `llm_payload` containing rule name/description, SPL,
macro context, host/user/IP, severity, risk, MITRE annotations, authorization,
change ticket, timestamps, and nested rule-specific fields. Verify:

- evidence source is recorded as curated `llm_payload`;
- provider capture has no canonical protected identity;
- MITRE, severity, risk, authorization, and provenance remain readable;
- output uses one official verdict value and passes the existing threshold and
  prompt-injection gates;
- malformed/missing payload takes the compact fallback and never serializes the
  raw OCSF envelope;
- Gateway failure yields deterministic/manual-review handling, never a
  fabricated benign or false-positive decision.

## Stage D — Four-agent Investigator

Use the existing synchronous endpoint with an authenticated/signed tenant
identity and a synthetic alert:

```bash
curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  -H 'X-Tenant-Id: <canonical-test-tenant-uuid>' \
  -H 'X-AiSOC-Tenant-Signature: <server-generated-signature>' \
  --data '{"alertId":"synthetic-alert-001","alert_summary":"Synthetic lateral movement investigation","raw_alert":{"hostname":"dc01.corp.example","username":"CORP\\alice"},"tenant_id":"ignored-body-value"}' \
  'https://<agents-host>/api/v1/agents/investigate'
```

Verify Recon, Forensic, Responder, and ReportWriter share the authorized Remote
Context and that each decoded result is available to the next step. The body
tenant must not override the authenticated tenant.

## Stage E — Other agents surfaces

Exercise Router (`POST /api/v1/cases/<id>/triage`), Contextual AI
(`/api/v1/contextual/action` and `/action/stream`), Copilot
(`/api/v1/copilot/chat` and `/chat/stream`), Deep Explain
(`POST /api/v1/explain`), NL playbook drafting, Tool Calling, Runtime, and
Shadow with synthetic data. For each, verify one Context per logical workflow,
canonical tenant binding, Encode before provider, Decode before local use, and
cleanup on success/error. Attempt a Copilot conversation continuation and GET
from a second signed tenant; both must return not found and listing must omit it.

## Stage F — Controlled real provider

With an approved low-budget provider credential, retain only the minimum
access-controlled capture necessary to compare:

```text
synthetic internal input
  -> Gateway-protected provider input
  -> protected provider response
  -> exact local restoration
```

Provider-visible captures must not include the original synthetic protected
identities. Never place organizational secrets in the test or report.

## Stage G — Cross-server deployment

From the actual agents container verify private DNS, VPN route, firewall,
certificate hostname/chain, service authentication, tenant authorization,
Gateway readiness, Redis readiness, bounded timeouts, and synchronized clocks:

```bash
getent hosts <gateway-vpn-dns>
curl --fail --silent --show-error --connect-timeout 5 --max-time 30 \
  --cacert /run/secrets/privacy-gateway-ca.pem \
  https://<gateway-vpn-dns>/health
date -u
```

Then run the full curl smoke inside the container. A host-side `curl` alone is
not evidence of container-side connectivity. Record actual command/status/time
without credentials, Context IDs, headers, or payload bodies.

## Completion gate

Staging validation requires all stages plus the negative tests for invalid
credential, unauthorized tenant, invalid/expired Context, cross-client access,
malformed request, and Gateway timeout/unavailability. Docker image build,
Redis-backed concurrency, real provider Auto-Triage, and real provider
Investigator remain explicitly pending until operators execute them.
