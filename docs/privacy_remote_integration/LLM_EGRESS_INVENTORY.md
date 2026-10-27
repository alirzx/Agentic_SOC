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

## API service: independently protected provider boundary

The API service has a separate process, so it does not share the Agents
`ContextVar`. Its `app.services.privacy_llm.safe_chat_post` uses the same
remote Gateway endpoints with a trusted authenticated tenant UUID.

| Workflow | Caller tenant | Protected boundary |
|---|---|---|
| Hunts generation | `AuthUser.tenant_id` | `safe_chat_post` |
| Detection translation | `AuthUser.tenant_id` | `safe_chat_post` |
| Knowledge-base synthesis | `AuthUser.tenant_id` | `safe_chat_post` |
| Phishing triage | `AuthUser.tenant_id` | `safe_chat_post` |
| Detection loop | `AuthUser.tenant_id` | `safe_chat_post` |
| NL detection | `AuthUser.tenant_id` | `safe_chat_post` |
| NL query enhancement | `AuthUser.tenant_id` | API-scoped helper and `safe_chat_post` |
| Alert explanation | stored `Alert.tenant_id` | `safe_chat_post` |

The API-side client is REST-contract based and does not duplicate the
Gateway detector or its tokenization/alias store. When remote privacy is
enabled, Context creation/Encode must succeed before any provider request,
and Decode must succeed before local use. API services must deploy with the
same Gateway host, service credential, profile, and canonical tenant allowlist
as Agents.

**Validation status:** Source integration only. These changes have not yet
been proven by live Gateway, real-provider, cross-server VPN, Docker build,
or full-platform regression tests. Run the focused synthetic tests and
the integration runbook before enabling external production egress.
