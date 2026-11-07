# Source-Backed LLM Egress Inventory

This inventory was produced from Graphify queries plus repository searches for
LangChain invocation, provider clients, and chat-completions URLs. “Protected”
means the request is inside an authorized `async_privacy_context`, encoded
before provider egress, and decoded before local use. Offline tests use only
synthetic data and mocked providers.

## Agents service centralized boundary

| Workflow | Entry point / source | Trusted tenant source | Boundary / payload | Context ownership and local validation | Status |
|---|---|---|---|---|---|
| Auto-Triage | `workers/fused_alert_consumer.py` → `run_auto_triage` | DB-resolved tenant from fused record | `safe_ainvoke`; LangChain messages | worker owns one async Context; Decode precedes typed verdict parser/auto-close gates | Protected |
| Recon | `investigator/recon_agent.py:run_recon` | enclosing Investigator Context | `safe_ainvoke`; messages | shared workflow Context; decoded structured result before state update | Protected |
| Forensic | `investigator/forensic_agent.py:run_forensic` | enclosing Investigator Context | `safe_ainvoke`; messages | shared workflow Context; decoded structured result before state update | Protected |
| Responder | `investigator/responder_agent.py:run_responder` | enclosing Investigator Context | `safe_ainvoke`; messages | shared workflow Context; decoded action proposal before state update | Protected |
| Report Writer | `investigator/report_writer_agent.py:run_report_writer` | enclosing Investigator Context | `safe_ainvoke`; messages | shared workflow Context; decoded report before artifact use | Protected |
| Four-agent Investigator | `InvestigatorOrchestrator.run/stream` | authenticated manual request or authorized workflow state | centralized calls above | one Context spans graph run/stream; cleanup on exit/cancellation | Protected |
| Router sequential/parallel | case triage or legacy investigation API → `RouterOrchestrator` | signed/authenticated request; body tenant cannot authorize | `safe_ainvoke`; messages | one Context spans fan-out; agent results decoded before aggregation | Protected |
| Runtime LLM agents | `SocOrchestrator.run` | canonical outer `AgentContext` | `safe_ainvoke`; messages | one outer Context; structured result parsed only after Decode | Protected |
| Full investigation graph | `graph/runner.py:run_full_investigation` | canonical `InvestigationState.tenant_id` | centralized calls above | graph-lifetime Context; decoded data enters state | Protected |
| Escalation graph | `graph/runner.py:run_escalation` | canonical alert state | centralized calls above | graph-lifetime Context; decoded decision only | Protected |
| Tool calling | `agents/tool_loop.py:run_with_tools` | enclosing authorized workflow | protected schemas/options + `safe_ainvoke` | Decode → residual-alias check → JSON Schema → permission/tool execution | Protected |
| Deep Explain | `/api/v1/explain` | authenticated request state or signed header | `safe_chat_completions_request`; final HTTP JSON | request Context; complete response decoded before NDJSON emission | Protected/fallback |
| Contextual AI | browser URL → authenticated core streaming proxy → `/api/v1/contextual/action[/stream]` | `AuthUser.tenant_id` signed by core API | `safe_ainvoke` / `safe_astream` | request Context; privacy-on stream buffers, size-checks, then decodes once | Protected/fallback |
| Copilot | browser URL → authenticated core streaming proxy → `/api/v1/copilot/chat[/stream]` | signed `AuthUser.tenant_id` plus conversation ownership | `safe_chat_completions_request`; final HTTP JSON | request Context; decoded reply before storage/return | Protected/fallback |
| Shadow runtime | `runtime/shadow_consumer.py` → runtime | canonical fused record tenant | centralized calls above | runtime Context; decoded shadow result, dry-run posture preserved | Protected |
| Manual investigation | legacy `/investigations`, `/cases/{id}/investigate`, `/agents/investigate` | API signs authenticated tenant with the shared API↔Agents HMAC key | Investigator/graph centralized calls | run owner stored and enforced on polling/reports | Protected |
| NL query enhancement | `nl_query/translator.py:enhance_with_llm` | caller-bound Context; no current production caller | `safe_chat_completions_request`; HTTP JSON | decoded query validated by grammar before use | Protected when invoked in Context |
| NL playbook drafting | authenticated core API proxy → Agents `draft_from_nl` | `AuthUser.tenant_id` signed with API↔Agents HMAC | `safe_ainvoke`; messages | request Context; decoded draft passes playbook schema validation | Protected |

The startup MITRE embedding client is the sole agents-service allowlist entry.
It sends bundled public ATT&CK text, not tenant evidence. Connecting it to
tenant-private text requires a separate embedding privacy design.

## API service: independently protected provider boundary

The API service has a separate process, so it does not share the Agents
`ContextVar`. Its `app.services.privacy_llm.safe_chat_post` uses the same
remote Gateway endpoints with a trusted authenticated tenant UUID.

All eight paths send complete OpenAI-compatible JSON through `safe_chat_post`.
The API creates one Context per call, validates the exact Encode response, calls
the provider once, validates/decodes the complete response, and deletes the
Context in `finally`. It has no protected incremental streaming path.

| Workflow | Entry point | Trusted tenant | Encoding / decoding and validation |
|---|---|---|---|
| Hunts generation | `api/v1/endpoints/hunts.py:_generate_queries` | `AuthUser.tenant_id` | final JSON Encode; decoded JSON-object query set |
| Detection translation | `api/v1/endpoints/translation.py:_llm_translate` | `AuthUser.tenant_id` | final JSON Encode; decoded translation parsed/validated |
| Knowledge-base synthesis | `api/v1/endpoints/knowledge_base.py:_synthesise` | `AuthUser.tenant_id`; chunks are tenant-query scoped | final JSON Encode; decoded text answer |
| Phishing triage | `api/v1/endpoints/phishing.py:_triage` | `AuthUser.tenant_id` | final JSON Encode; decoded JSON triage result |
| Detection loop | `api/v1/endpoints/detection_loop.py:_llm_draft_sigma` | `AuthUser.tenant_id`; alert/rule DB queries also tenant-scoped | final JSON Encode; decoded Sigma draft |
| NL detection | `api/v1/endpoints/nl_detection.py:_llm_translate` | `AuthUser.tenant_id` | final JSON Encode; decoded JSON rule candidates |
| NL query enhancement | `api/v1/endpoints/nl_query.py:_enhance_via_api_privacy` | `AuthUser.tenant_id` | final JSON Encode; decoded queries pass ES|QL/KQL/SPL grammar validation |
| Alert explanation | `services/alert_explain.py:_call_llm` | tenant-scoped stored `Alert.tenant_id` | final JSON Encode; decoded message before explanation result |

The API-side client is REST-contract based and does not duplicate the
Gateway detector or its tokenization/alias store. When remote privacy is
enabled, Context creation/Encode must succeed before any provider request,
and Decode must succeed before local use. API services must deploy with the
same Gateway host, service credential, profile, and canonical tenant allowlist
as Agents.

Both service boundaries use internal HTTPX clients. There is no external DLP
Python dependency and no cross-service Python import; the shared compatibility
point is the published Gateway REST schema.

**Validation status:** Source integration only. These changes have not yet
been proven by live Gateway, real-provider, cross-server VPN, Docker build,
or full-platform regression tests. Run the focused synthetic tests and
the integration runbook before enabling external production egress.
