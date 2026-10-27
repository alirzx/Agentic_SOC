# Curl Smoke Runbook

`services/agents/scripts/privacy_gateway_curl_smoke.sh` validates the real
Gateway REST contract without contacting an LLM provider. It uses only fixed
synthetic SOC values, keeps its temporary files mode `0600` under a mode `0700`
directory, deletes the test Context in a trap, and never prints the service
credential, Context ID, headers, or payload bodies.

## Configuration

```bash
export AISOC_PRIVACY_REMOTE_URL='https://<gateway-vpn-dns>'
export AISOC_PRIVACY_REMOTE_API_KEY='<service-credential>'
export AISOC_PRIVACY_REMOTE_PROFILE='agentic-soc-v1'
export AISOC_PRIVACY_TEST_TENANT_ID='11111111-1111-1111-1111-111111111111'
export AISOC_PRIVACY_REMOTE_CONNECT_TIMEOUT_SECONDS=5
export AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS=30
```

The test tenant must be a synthetic canonical UUID authorized for this service
client by the Gateway. For a private CA, set
`AISOC_PRIVACY_REMOTE_CA_FILE=/path/to/ca-bundle.pem`. The script never uses
`curl -k`; a certificate or hostname failure is a test failure.

Run:

```bash
bash services/agents/scripts/privacy_gateway_curl_smoke.sh
```

The positive flow checks, in order: health, readiness, policy objects, Context
create/get, classify, Encode protection, exact authorized Decode, unknown-alias
count, and Context delete. Every request has bounded connect/request timeouts
and an expected HTTP status.

## Where to run it

1. On the Gateway machine, use its production TLS listener/private DNS name.
2. On the SOC host, use the same VPN/private DNS name the deployment will use.
3. Inside the deployed agents container/network namespace, run the mounted
   script with secrets injected through the normal runtime mechanism.

Host-side success proves only the host route. It does not prove container DNS,
container routes, egress policy, CA mounts, or container firewall rules. The
container-side run is mandatory before staging traffic.

## Selectable negative checks

Use only synthetic tenants/credentials created for validation:

```bash
bash services/agents/scripts/privacy_gateway_curl_smoke.sh --negative invalid-credential
bash services/agents/scripts/privacy_gateway_curl_smoke.sh --negative unauthorized-tenant
bash services/agents/scripts/privacy_gateway_curl_smoke.sh --negative invalid-context
bash services/agents/scripts/privacy_gateway_curl_smoke.sh --negative malformed
```

For owner isolation, configure a second valid service credential belonging to a
different Gateway client. The script creates a Context with the primary client
and expects the second client to receive HTTP 403:

```bash
export AISOC_PRIVACY_TEST_SECOND_API_KEY='<other-synthetic-client-credential>'
bash services/agents/scripts/privacy_gateway_curl_smoke.sh --negative cross-tenant
```

For expiry, provide an already expired synthetic Context ID created by an
operator-controlled short-TTL setup. The Gateway contract returns HTTP 400 for
missing/expired Contexts:

```bash
export AISOC_PRIVACY_TEST_EXPIRED_CONTEXT_ID='ctx_<expired-synthetic-id>'
bash services/agents/scripts/privacy_gateway_curl_smoke.sh --negative expired
```

For unavailability, point `AISOC_PRIVACY_REMOTE_URL` at a deliberately closed
test listener and run `--negative unavailable`. Do not alter production
firewall rules to manufacture the failure.

## Expected output and cleanup

Successful lines have only `PASS <operation>`. Failures have an operation,
safe error class/status, and a nonzero exit. If the process is interrupted, the
trap attempts Context deletion with the primary credential and then removes
the restricted temporary directory. Review Gateway metadata-only audit logs to
confirm create/encode/decode/delete; never enable payload logging for this test.
