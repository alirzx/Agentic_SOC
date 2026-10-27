# Privacy Gateway API Contract

The SOC consumes `soorin-privacy-sdk` `0.1.0`, pinned to Gateway commit
`1f759f2f95dbc74c7f22db6671f26d74daea8776`. Only the SDK is installed in the
agents image; the Gateway backend remains a separate service.

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

The SOC uses `AsyncPrivacyClient.create_context`, `encode`, `decode`, and
`delete_context`. Health, readiness, policy, context inspection, and classify
are exercised by the connectivity script with an internal `httpx` client.

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

The SDK fixes normal decode to `purpose=llm-response` and
`reveal_credentials=false`. Credential aliases therefore restore as
`[PROTECTED_CREDENTIAL]`, never as the original secret. A nonzero
`unknown_aliases` count is a safety failure: the SOC does not release that
response or execute tool arguments from it.

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

Stable categories are logged without SDK exception text or payloads. Encode
failure occurs before provider egress. Decode failure never returns the
protected provider response. Remote mode never silently falls back to Local or
disabled privacy.

## Raw chat body compatibility

The direct HTTP wrapper accepts a reviewed allowlist of OpenAI-compatible model
configuration fields, including tools, tool choice, response format, token
limits, sampling controls, and reasoning effort. It rejects unknown fields and
Authorization/Proxy-Authorization header overrides before network egress.
