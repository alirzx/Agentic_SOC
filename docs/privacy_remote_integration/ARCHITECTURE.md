# Remote Privacy Gateway Architecture

## Boundary

All tenant-bearing chat inference leaves `services/agents` through one of
three functions in `app/llm/contract.py`:

```text
SOC workflow
  -> canonical tenant resolution
  -> async_privacy_context (one workflow-owned Gateway context)
  -> safe_ainvoke | safe_astream | safe_chat_completions_request
  -> internal HTTPX REST client -> Gateway Encode
  -> existing model/provider route
  -> Remote Decode (purpose=llm-response, reveal_credentials=false)
  -> validated local response
```

The Agents and API services each own a small internal HTTPX client and remain
independently deployable. No external DLP Python package or Gateway Git checkout
is installed into either service. The independent Gateway performs detection,
tokenization, encryption, and mapping storage; SOC transports do not duplicate
those functions. Provider credentials remain between the SOC and its configured
inference provider and are never sent to the Privacy Gateway.

## Production data and Auto-Triage evidence

```text
Splunk notable -> connector llm_payload -> ingest/OCSF -> Kafka raw_events
  -> Fusion promotes RawAlert.llm_payload -> PostgreSQL alerts.llm_payload
  -> Kafka aisoc.alerts.fused -> FusedAlertTriageWorker
  -> InvestigationState.raw_alert["llm_payload"]
  -> Auto-Triage curated evidence composer -> Remote Encode -> provider
```

`llm_payload` is primary only for Auto-Triage. It carries the rule, SPL and
macro context, typed entities, time provenance, annotations, and rule-specific
alert fields produced by the Splunk connector. Other agents retain their
specialized context bundles, tools, and upstream outputs.

Historical alerts with no usable `llm_payload` use a compact fallback of the
summary, severity, risk, IOCs, MITRE techniques, and safe supplemental fields.
The fallback excludes `raw_event` and never walks or serializes the raw OCSF
envelope. Both paths sanitize attacker-controlled strings and place evidence
inside a per-run nonce fence.

## Context ownership

The active backend is stored in a `ContextVar`, so concurrent requests, Kafka
records, tenants, and shadow runs cannot share ambient mutable state.

| Boundary | Context lifetime |
|---|---|
| Fused alert Auto-Triage | One triage run |
| Router sequential/parallel run | Whole router run, including branches |
| Four-agent Investigator | Recon through ReportWriter |
| Runtime orchestrator | Whole runtime pipeline |
| Full investigation graph | Whole graph stream/run |
| Contextual/Explain/Copilot request | One request or stream |
| NL playbook draft | One draft request |

Nested scopes reuse the same context only for the same canonical tenant.
Cross-tenant nesting is rejected. Remote contexts are created before model
work and deleted in the async context manager's `finally` block. Context IDs
are generated only by the Gateway; logs use a short SHA-256 correlation value,
not the raw ID.

The Gateway uses an absolute TTL. The SOC checks the returned expiration before
each encode/decode and fails closed if expired. It does not decode a provider
response with a replacement context. Concurrent operations share one context;
the Gateway's Redis CAS resolves mapping updates. SOC retries are bounded to
two attempts for transport timeouts/unavailability and 409/502/503/504.

Copilot conversation records additionally carry a trusted tenant owner.
Creation, continuation, retrieval, and listing all enforce that owner; a
conversation ID from another tenant is treated as not found. The anonymous
demo namespace is available only outside recognized production environments.

## LLM path inventory

| Workflow | Entry point | Central boundary | Context source / response use |
|---|---|---|---|
| Auto-Triage | `run_auto_triage` | `safe_ainvoke` | Curated `llm_payload`; typed verdict |
| Four-agent Investigator | `InvestigatorOrchestrator.run/stream` | `safe_ainvoke` | Specialized shared state; decoded JSON/report |
| Router | `RouterOrchestrator.run/stream` | `safe_ainvoke` | Shared `InvestigationState`; sequential/parallel |
| Runtime LLM agents | `SocOrchestrator.run` | `safe_ainvoke` | `AgentContext`; structured steps |
| Tool loop | `run_with_tools` | `safe_ainvoke` | Decoded and schema-validated args before execution |
| Contextual AI | `/api/v1/contextual` | `safe_ainvoke`, `safe_astream` | Request-specific prompt; buffered remote stream |
| Deep Explain | `/api/v1/explain` | raw HTTP safe boundary | Alert explanation; decoded summary |
| Copilot | `/api/v1/copilot/chat` | raw HTTP safe boundary | Signed/canonical request tenant |
| NL query | translator | raw HTTP safe boundary | Sanitized NL query context |
| NL playbook draft | `draft_playbook` | `safe_ainvoke` | Tenant draft request |
| Full graph/manual investigation | graph/API runners | Shared boundaries above | Workflow-scoped context |
| Shadow runtime | shadow consumer/runtime | Shared boundaries above | Separate record/run context |

The MITRE corpus startup embedding path uses an embedding-only provider client and
only the bundled public ATT&CK corpus. It is not tenant chat inference and is
explicitly allowlisted by the static no-bypass gate. No tenant evidence is sent
on that path.

`services/api` uses its own direct HTTPX Gateway boundary for its eight
provider-calling workflows because it cannot share the Agents `ContextVar`.
See `LLM_EGRESS_INVENTORY.md` for the source-backed split. There is no
cross-service Python import.

## Streaming, tools, cache, and telemetry

Remote streams remain bounded and buffered. Provider chunks are combined,
decoded once, and only then emitted, so aliases split across chunks cannot leak
or restore partially. Buffer overflow or decode failure emits no protected
partial response.

Provider tool-call arguments are part of the decoded response. Unknown aliases
raise a typed privacy error before execution, and `ToolRegistry` validates the
decoded argument object against the registered JSON Schema immediately before
calling a tool. Existing runtime permission, approval, and shadow/read-only
controls remain downstream and unchanged.

Tool schemas are validated when registered. Before `bind_tools`, their
model-visible descriptions and examples pass through the active privacy
Context; function names and JSON Schema structural semantics must remain
unchanged or the provider call is rejected. Per-call LangChain provider kwargs
use the same projection, and unknown kwargs fail before egress.

The response cache is disabled for Remote mode because protected responses are
context-bound. Local/disabled modes keep their existing behavior. Cost is
recorded once at the central provider-call boundary. Payload HUMAN TRACE remains
explicitly opt-in and credential-scrubbed; ordinary remote events contain only
tenant/model/policy, latency, counts, a hashed context correlation, and stable
error categories.

## Cross-machine topology

```text
Machine A: API and agents containers
       | HTTPS over private network/VPN, Bearer service authentication
       v
Machine B: Privacy Gateway :8484 -> private Redis encrypted context store
       |
       +-- Machine A calls its existing inference provider after Encode
```

Docker service DNS does not cross independent hosts. Configure a routable VPN
DNS name or address in `AISOC_PRIVACY_REMOTE_URL`. Production/required-mode
startup rejects a plain HTTP Gateway URL. A public CA uses normal container
trust; a private CA is supplied through the documented `SSL_CERT_FILE` mount.
