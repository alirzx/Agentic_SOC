# Privacy Gateway API Contract

The server contract was verified read-only against Gateway `main` commit
`91e5150b384f380dc26a48b7301a76f7a8f936d8`. Agents calls this contract through
`app.privacy.rest_client.PrivacyGatewayRESTClient`; API uses its independent
`app.services.privacy_llm` HTTPX boundary. No external DLP Python package or
Gateway repository is installed during an SOC build. The Gateway backend and
all Context/Alias storage remain a separate service.

## Endpoints

| Method | Path | Auth | SOC use |
|---|---|---|---|
| GET | `/health` | none | Liveness smoke check |
| GET | `/ready` | none | Storage readiness smoke check |
| GET | `/v1/policies` | Bearer | Verify configured profile |
| POST | `/v1/contexts` | Bearer | Create tenant/workflow context |
| GET | `/v1/contexts/{id}` | Bearer | Smoke inspection only |
| DELETE | `/v1/contexts/{id}` | Bearer | Workflow cleanup |
| POST | `/v1/encode` | Bearer | Protect provider-visible data |
| POST | `/v1/decode` | Bearer | Restore provider output locally |
| POST | `/v1/classify` | Bearer | Smoke diagnostics only |

The Agents REST client implements Context create/delete, Encode, and Decode.
Health, readiness, policy, context inspection, and classify are exercised by
the connectivity scripts with direct HTTP requests.

`GET /health` returns `{"status":"ok","service":"soorin-data-privacy-gateway"}`.
`GET /ready` returns `{"status":"ready","store":"<configured-backend>"}`;
the storage name is configuration-dependent. `GET /v1/policies` returns
objects, not profile-name strings:

```json
{"policies":[{"name":"agentic-soc-v1","version":"1.0.0"}]}
```

## Context request

```json
{
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "profile": "agentic-soc-v1",
  "ttl_seconds": 3600
}
```

The tenant is resolved through the SOC trusted resolver before this request.
The adapter verifies the returned tenant and profile. It tracks the returned
absolute `expires_at` and policy version. It never creates its own Context ID.

```json
{
  "context_id": "ctx_<gateway-generated-id>",
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "profile": "agentic-soc-v1",
  "policy_version": "1.0.0",
  "expires_at": "<ISO-8601 timestamp>"
}
```

## Encode and Decode

LangChain calls use `format=messages`. The adapter serializes role, content,
tool calls, tool call IDs, additional kwargs, response/usage metadata, and
multipart content without mutating the caller's objects. Raw HTTP calls use
`format=json` on the complete final provider body so tool definitions and
structured response schemas are protected too.

Encode always supplies the current context, profile, and canonical tenant.
Typed registrations are limited to values taken from known structured fields;
prose is not guessed into a type. The Gateway enforces the 250-registration
maximum. The adapter adds privacy guidance only after encoding.

```json
{
  "context_id": "<created-context-id>",
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "profile": "agentic-soc-v1",
  "purpose": "llm-egress",
  "format": "json",
  "payload": {"hostname":"dc01.corp.example","username":"CORP\\alice","src_ip":"10.20.3.7"},
  "registrations": []
}
```

Both SOC REST clients explicitly set normal decode to `purpose=llm-response`
and `reveal_credentials=false`. Credential aliases therefore restore as
`[PROTECTED_CREDENTIAL]`, never as the original secret. A nonzero
`unknown_aliases` count is a safety failure: the SOC does not release that
response or execute tool arguments from it.

```json
{
  "context_id": "<created-context-id>",
  "format": "json",
  "payload": "<encoded-payload>",
  "purpose": "llm-response",
  "reveal_credentials": false
}
```

Encode responses contain `context_id`, `policy_version`, `format`, `payload`,
`expires_at`, and integer `stats`. Decode responses contain `context_id`,
`format`, `payload`, and integer `stats`. Classify requests contain `profile`,
`format`, `payload`, and `registrations`; responses contain at least integer
`total_detected` and an object `counts`.

## Failure contract

| Condition | Category |
|---|---|
| 400 | `invalid_context_or_policy` |
| 401 | `invalid_service_credential` |
| 403 | `unauthorized_tenant_or_context` |
| 413 | `payload_too_large` |
| 422 | `invalid_request_schema` |
| 503 | `storage_unavailable` |
| other 5xx | `gateway_server_error` |
| timeout | `gateway_timeout` |
| connection failure | `gateway_unavailable` |

Stable categories are logged without upstream exception text, response bodies,
or payloads. The Agents transport requires exact success status codes and JSON
objects before the backend validates binding, expiry, payload, and statistics.
Encode failure occurs before provider egress. Decode failure never returns the
protected provider response. Remote mode never silently falls back to Local or
disabled privacy.

## Raw chat body compatibility

The direct HTTP wrapper accepts a reviewed allowlist of OpenAI-compatible model
configuration fields, including tools, tool choice, response format, token
limits, sampling controls, and reasoning effort. It rejects unknown fields and
Authorization/Proxy-Authorization header overrides before network egress.
