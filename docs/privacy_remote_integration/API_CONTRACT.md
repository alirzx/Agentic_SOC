# Privacy Gateway API Contract

The server contract was verified read-only against Gateway `main` commit
`91e5150b384f380dc26a48b7301a76f7a8f936d8`. Agents calls this contract through
`app.privacy.rest_client.PrivacyGatewayRESTClient`; API uses its independent
`app.services.privacy_llm` HTTPX boundary. No external DLP Python package or
Gateway repository is installed during an SOC build. The Gateway backend and
all Context/Alias storage remain a separate service.

## Endpoints

| Method | Path | Auth | SOC caller / trigger | Contract and failure behavior |
|---|---|---|---|---|
| GET | `/health` | none | Python/curl smoke scripts; liveness only | `status=ok`; never authorizes inference |
| GET | `/ready` | none | Python/curl smoke scripts; storage readiness | `status=ready` plus store name; never authorizes inference |
| GET | `/v1/policies` | Bearer | Python/curl smoke scripts; profile discovery | objects with `name`/`version`; missing profile fails smoke |
| POST | `/v1/contexts` | Bearer | Agents `RemotePrivacyBackend.start`; API `safe_chat_post` | tenant/profile/TTL; exact `201`; binding/expiry validated before Encode |
| GET | `/v1/contexts/{id}` | Bearer | curl smoke inspection only | service-principal/tenant ownership; not an inference call |
| DELETE | `/v1/contexts/{id}` | Bearer | Agents context exit; API per-call `finally`; smoke cleanup | exact `204` in Agents; TTL is secondary cleanup |
| POST | `/v1/encode` | Bearer | Agents/API immediately before provider egress | exact `200`; binding/payload/stats validated; failure blocks provider |
| POST | `/v1/decode` | Bearer | Agents/API after complete provider response | exact `200`; binding/payload/stats validated; failure releases nothing |
| POST | `/v1/classify` | Bearer | curl smoke diagnostics only | diagnostic counts; not used for inference decisions |

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

LangChain calls use `format=messages`. The adapter serializes role, string
content, tool calls, tool call IDs, additional kwargs, and response/usage
metadata without mutating the caller's objects. The centralized
`LLMInputContract` rejects multipart/non-string message content before provider
egress because validating a stringified copy while sending a structured object
would be unsafe. Raw HTTP calls use `format=json` on the complete final provider
body, where JSON multipart fields, tool definitions, and structured response
schemas remain part of the protected body.

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
or payloads. Both SOC transports require exact success status codes and JSON
objects, then validate context/format binding, expiry where returned, payload
shape, and integer statistics. The API boundary also adds system-level alias
guidance to a deep-copied provider body before Encode; the caller's body is not
modified.
Encode failure occurs before provider egress. Decode failure never returns the
protected provider response. Remote mode never silently falls back to Local or
disabled privacy.

## Raw chat body compatibility

The direct HTTP wrapper accepts a reviewed allowlist of OpenAI-compatible model
configuration fields, including tools, tool choice, response format, token
limits, sampling controls, and reasoning effort. It rejects unknown fields and
Authorization/Proxy-Authorization header overrides before network egress.
