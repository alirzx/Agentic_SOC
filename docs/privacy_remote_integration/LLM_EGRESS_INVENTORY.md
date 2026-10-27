# Source-Backed LLM Egress Inventory

This inventory was produced from Graphify queries plus repository searches for
LangChain invocation, provider SDKs, and chat-completions URLs. “Protected”
means the request is inside an authorized `async_privacy_context`, encoded
before provider egress, and decoded before local use. Offline tests use only
synthetic data and mocked providers.

## Agents service centralized boundary

| Workflow | Entry point / caller | Provider boundary | Trusted tenant source | Restore | Offline evidence | Status |
|---|---|---|---|---|---|---|
| Auto-Triage | fused worker → `run_auto_triage` | `safe_ainvoke` | canonical fused-alert tenant resolved from DB | typed verdict after Decode | payload, worker, remote contract tests | Protected |
| Four-agent Investigator | `InvestigatorOrchestrator.run/stream` | `safe_ainvoke` | authenticated manual request or authorized workflow state | each agent response before next step | structured/investigator/privacy tests | Protected |
| Router sequential/parallel | case triage API → `RouterOrchestrator` | `safe_ainvoke` | authenticated request tenant; body cannot override | agent results before aggregation | router/privacy tests | Protected |
| Runtime LLM agents | `SocOrchestrator.run` | `safe_ainvoke` | canonical outer `AgentContext` | structured result | runtime privacy tests | Protected |
| Full investigation graph | graph runner | centralized calls above | canonical graph state | before graph state update | graph privacy tests | Protected |
| Escalation graph | graph/worker path | centralized calls above | canonical alert state | before decision use | graph/worker tests | Protected |
| Tool calling | `run_with_tools` | protected schema binding + `safe_ainvoke` | enclosing authorized workflow | Decode → alias check → JSON Schema → permissions/tool | remote tool tests | Protected |
| Deep Explain | `/api/v1/explain` | `safe_chat_completions_request` | authenticated request tenant | decoded HTTP JSON | API-context/raw HTTP tests | Protected |
| Contextual AI | `/api/v1/contextual/action[/stream]` | `safe_ainvoke` / buffered `safe_astream` | authenticated request tenant | before response/stream emission | API-context/stream tests | Protected |
| Copilot | `/api/v1/copilot/chat[/stream]` | `safe_chat_completions_request` | authenticated request tenant plus conversation ownership | decoded message before storage/return | raw HTTP and two-tenant tests | Protected |
| Shadow runtime | shadow consumer → runtime | centralized calls above | canonical fused record tenant | before shadow result use | shadow/runtime privacy tests | Protected |
| Manual investigation | `/api/v1/cases/{id}/investigate` and `/api/v1/agents/investigate` | Investigator centralized calls | authenticated request tenant; body cannot authorize | before report/action use | tenant and endpoint regressions | Protected |
| NL query enhancement | agents translator | `safe_chat_completions_request` | caller-bound Context; no current production caller | decoded query draft | no-bypass/raw HTTP tests | Protected when called correctly |
| NL playbook drafting | playbook API → drafter | `safe_ainvoke` | authenticated request tenant | decoded draft before schema validation | API-context/drafter tests | Protected |

The startup MITRE embedding client is the sole agents-service allowlist entry.
It sends bundled public ATT&CK text, not tenant evidence. Connecting it to
tenant-private text requires a separate embedding privacy design.

## Confirmed provider clients outside the agents boundary

The following pre-existing `services/api` paths call chat-completions directly
with `httpx`. They do not import the agents contract, do not create a Remote
Privacy Context, and do not Decode provider output. They are therefore a
confirmed cross-service coverage gap, not a claim of protection:

| API-owned path | Function | Data class | Current status |
|---|---|---|---|
| `api/v1/endpoints/hunts.py` | `_generate_queries` | analyst hypothesis / MITRE | Unprotected direct provider call |
| `api/v1/endpoints/translation.py` | `_llm_translate` | detection rule text | Unprotected direct provider call |
| `api/v1/endpoints/knowledge_base.py` | `_synthesise` | question and retrieved chunks | Unprotected direct provider call |
| `api/v1/endpoints/phishing.py` | `_triage` | email/artifact content and URLs | Unprotected direct provider call |
| `api/v1/endpoints/detection_loop.py` | `_llm_draft_sigma` | Sigma, alert fields, analyst note | Unprotected direct provider call |
| `api/v1/endpoints/nl_detection.py` | `_llm_translate` | threat description and techniques | Unprotected direct provider call |
| `api/v1/endpoints/nl_query.py` | `enhance_with_llm` call path | analyst natural-language query | Unprotected direct provider call |
| `services/alert_explain.py` | `_call_llm` | alert explanation context | Unprotected direct provider call |

This branch does not pretend these calls are covered. Closing the gap requires
a shared cross-service privacy client or routing these API features through an
authenticated agents-service provider boundary with canonical tenant identity.
Copying tokenization logic into `services/api` is not acceptable. Until that
architecture is implemented and tested, platform-wide “all LLM calls are
protected” is a blocked claim even though the agents-service integration is
ready for manual Gateway testing.
