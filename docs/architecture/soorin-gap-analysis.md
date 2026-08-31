# Soorin Agentic SOC — Architecture Gap Analysis

**Status:** baseline for phase-by-phase implementation  
**Date:** 2026-08-31  
**Spec:** `Soorin_Agentic_SOC_Specification.md` (source of truth; not edited)  
**Repo inspected:** AiSOC monorepo at `7.7.0` (Python/FastAPI + LangGraph + Next.js + Go ingest)

This document is Step 2 of the spec's Cursor implementation instructions. **No existing
implementation is overwritten.** Spec contracts are layered onto the current stack.

**Implementation landed (2026-08-31):** `services/agents/app/runtime/` plus
`packages/types/src/agentic-soc.ts`. Progress: `PROGRESS.md`. Live Kafka/LangGraph
paths are unchanged.

## Binding architecture decision

The spec's recommended runtime is NestJS + TypeORM. This repository is **not** that
stack. Canonical code is:

| Spec assumption | What this repo actually is |
|---|---|
| NestJS modules | FastAPI services (`services/api`, `services/agents`, …) |
| TypeORM entities | SQLAlchemy + raw SQL (`aisoc_cases`) |
| NestJS DI AgentRegistry | Python Protocol + Pydantic in `services/agents` |
| Elasticsearch-first SIEM | OCSF ingest → Kafka → fusion; 83 connectors including Elastic/Splunk |
| Chatbot → Router → Planner → Answer | Alert → Kafka → fusion → LangGraph investigation ledger |

Rewriting the platform in NestJS would violate spec §91 Step 1 ("do not overwrite
existing implementation without review") and destroy a working ingest/fusion/agent
spine. **Implementation language for new contracts is Python (Pydantic v2), with a
TypeScript mirror in `packages/types`.** NestJS module names map 1:1 onto Python
packages under `services/agents/app/runtime/`.

## Classification legend

| Class | Meaning |
|---|---|
| **EXISTING** | Present and production-used |
| **REUSABLE** | Keep as-is; new code calls it |
| **MODIFY** | Keep, but wrap or extend to match spec contracts |
| **NEW** | Spec requires it; not present as a first-class unit |
| **DEPRECATED** | Spec forbids it, or we will not build it |

---

## EXISTING (keep)

| Capability | Location |
|---|---|
| SIEM / connector ingest (83 connectors) | `services/connectors/` |
| OCSF normalize + Kafka `aisoc.raw_events` | `services/ingest/` |
| Fusion: dedup, correlate, ML, confidence, narrative | `services/fusion/` |
| Four branded agents (Detect / Triage / Hunt / Respond) | `services/agents/app/agents/__init__.py` |
| LangGraph orchestrators (router, escalation, investigator) | `services/agents/app/orchestrator/`, `graph/`, `investigator/` |
| Deterministic planner + signal router | `orchestrator/planner.py`, `orchestrator/router.py` |
| LLM factory / LiteLLM aliases / BYOK | `app/llm/factory.py`, `security/llm_resolver.py` |
| Structured LLM output + fail-closed contract | `app/llm/structured_output.py`, `contract.py` |
| Prompt-injection nonce fence + L0 demotion | `app/prompting/envelope.py` |
| Investigation ledger (runs / events / artifacts + SHA-256) | `investigator/ledger.py`, API models `investigation.py` |
| Hash-chained platform audit log | `services/api/app/models/audit.py` |
| Cost telemetry + per-tenant governor + circuit breaker | `core/cost_telemetry.py`, `core/cost_governor.py` |
| Tool loop (max 4 iters) + OpenAI-schema tool registry | `agents/tool_loop.py`, `tools/registry.py` |
| Playbook SSRF guard | `playbook/ssrf_guard.py` |
| HITL approvals (`AgentApproval`) + dry-run default SOAR | `api/.../approvals.py`, `services/actions/` |
| Tenant isolation (query-layer + RLS) | API endpoints + `migrations/002_rls.sql` |
| Neo4j entity graph at ingest | `services/ingest/internal/graph/` |
| Threat intel service + enrichment | `services/threatintel/`, `services/enrichment/` |
| Asset inventory | `services/api/app/models/asset.py` |
| Report PDF/HTML + executive digest | `investigator/report_writer_agent.py`, `api/.../reports.py` |
| Golden dataset (200 incidents) + eval harness | `services/agents/tests/eval_data/`, `scripts/run_evals.py` |
| Copilot / chat | `app/api/copilot.py`, `apps/web/.../copilot` |
| Redis working memory + entity-risk | `memory/working.py`, fusion `entity_risk.py` |
| Alert `idempotency_key` + Kafka idempotent run ids | Alert model, `fused_alert_consumer.py` |

## REUSABLE (call, do not rewrite)

- LLM Gateway → `make_chat_model` / `safe_ainvoke`
- Audit writes → investigation ledger `record_event` + API `AuditLog`
- Correlation → fusion `Correlator` (wrap as Correlation Agent)
- TI lookup → `enrich_ioc` + threatintel HTTP
- Asset lookup → API `/assets`
- Approvals → existing `AgentApproval` rows
- Cost / loop limits → `CostGovernor` + `InvestigationBudget`
- Reports → existing PDF pipeline, wrapped by Report Package contract
- Graph blast-radius → API `graph_service`

## MODIFY (wrap / extend, do not replace)

| Gap | Why | Approach |
|---|---|---|
| Agents are functions / façades, not `Agent.execute(AgentContext)` | Spec §8 contract | Adapter classes in `app.runtime.adapters` |
| No versioned AgentRegistry (`triage:v1.0`) | Spec §9 | `AgentRegistry` over adapters; façades stay public |
| Three orchestrators coexist | Spec wants one SOC orchestrator + state machine | Runtime dispatches by incident state; graphs stay |
| Dual case tables / status vocabularies | `cases` vs `aisoc_cases` | Spec incident states live in runtime SM; map to case status |
| `Tool` has no `riskLevel` / `requiresApproval` / `allowedAgents` | Spec §24–27 | `SocTool` + `ToolPermissionEngine` wrapping existing registry |
| Evidence is `InvestigationArtifact`, not first-class Evidence+provenance | Spec §31–32 | Evidence model in runtime; persist via ledger artifacts |
| Fusion confidence is 0–1 / 3-band | Spec risk is 0–100 / 5-band + EMERGENCY | New deterministic `RiskEngine`; fusion score remains a factor |
| Case transitions skip TRIAGING→CORRELATING→DECISION→VALIDATING | Spec §28 | New `IncidentStateMachine`; map onto case when persisting |
| SIEM/asset/identity tools are APIs, not agent tools | Spec §26 | Register tenant-scoped tools with pagination + query limits |
| Hypothesis lives on hunts, not in the investigation loop | Spec §63–64 | Hypothesis model on AgentResult; hunt workbench unchanged |
| Decision/Validation/Report are not versioned agents | Spec §18, §21, §22 | Adapter agents; Respond stays dry-run |
| In-memory run stores on some agent APIs | Spec wants durable | Runtime audit always goes through ledger protocol |

## NEW (build in this program)

Sprint-ordered. Each item is a contract or engine, not a second product.

1. **Agent / AgentContext / AgentResult / NextTask** Pydantic contracts
2. **AgentRegistry + AgentRuntime** (audit-wrapped `execute`)
3. **SocTool + ToolContext + ToolPermissionEngine**
4. **IncidentStateMachine** (spec states + legal transitions)
5. **Idempotency + incident lock** interfaces (Redis with in-memory fallback)
6. **Kafka incident-lifecycle event schemas** (typed; producers later)
7. **Hypothesis** create / test / reject model on the investigation path
8. **Deterministic RiskEngine** (spec formula + bands; LLM explains only)
9. **Decision policy** (risk thresholds → auto / recommend / approval / critical)
10. **ValidationAgent** (post-response effectiveness checks)
11. **IncidentReportPackage** (forced `uncertainties` section)
12. **Evidence provenance graph** (Finding → Evidence → ToolExecution → Source)
13. **AttackStory** typed package (wraps `aisoc_attack_chains`)
14. **PromptVersion** identifier on every LLM call metadata
15. **TypeScript mirror** of the contracts in `packages/types`

## DEPRECATED / will not build

Per spec §88 and this repo's existing posture:

- NestJS rewrite of the monorepo
- 20+ autonomous agents / multi-agent swarm as a product surface (`app.swarm` stays eval-only)
- LLM-assigned final risk score
- LLM direct DB / shell / raw SQL
- Automatic destructive response (dry-run remains default)
- Unbounded agent loops
- Full raw SIEM logs in prompts
- Vector DB expansion as an MVP prerequisite (Qdrant already used for TI only)
- A second `Incident` ORM that duplicates `Case` as the operator object

---

## MVP Definition of Done vs current repo

| # | Spec §87 item | Status | Notes |
|---|---|---|---|
| 1 | SIEM alert received | **Met** | 83 connectors → ingest |
| 2 | Alert normalized | **Met** | OCSF |
| 3 | Incident created | **Partial** | `Case` / fused incident id; no `soc_incidents` |
| 4 | State machine runs | **Partial** | Case forward-only map; not spec states |
| 5 | Triage Agent runs | **Met** | Heuristic + LLM auto-triage |
| 6 | Investigation Agent tool-calls | **Partial** | 4 analyst tools; no SIEM search tool |
| 7 | SIEM tools | **Partial** | Ingest yes; agent `siem.search*` no |
| 8 | Asset tools | **Partial** | REST yes; agent tools no |
| 9 | TI tools | **Partial** | `enrich_ioc` yes; campaign/malware search thin |
| 10 | Evidence stored | **Met** | Ledger artifacts |
| 11 | Evidence provenance | **Partial** | SHA-256 hashes; no Finding→Source graph |
| 12 | Correlation | **Met** | Fusion correlator |
| 13 | Deterministic Risk Engine | **Partial** | Fusion 3-band confidence ≠ spec 5-band risk |
| 14 | Decision Agent recommendation | **Partial** | Responder plan JSON; not a Decision agent |
| 15 | Human approval | **Met** | `AgentApproval` + copilot default |
| 16 | Structured report | **Partial** | Report writer; no forced Uncertainties package |
| 17 | PDF/HTML | **Met** | |
| 18 | AgentRuns audited | **Met** | Ledger + audit hash chain |
| 19 | Token usage recorded | **Met** | |
| 20 | Cost tracking | **Met** | |
| 21 | Agent loop limit | **Met** | Tool loop 4; budget 120s |
| 22 | Tool permission | **Gap** | No riskLevel / allowedAgents |
| 23 | Tenant isolation | **Met** | |
| 24 | Prompt injection defense | **Met** | |
| 25 | Idempotency | **Partial** | Alert + Kafka; not incident-lock |
| 26 | Unit tests | **Met** | |
| 27 | Integration tests | **Met** | |
| 28 | Golden dataset eval | **Met** | 200 synthetic incidents |

**Tally:** 18 met · 9 partial · 1 hard gap (tool permission). MVP is a **contract-alignment** program, not a greenfield SOC.

---

## Sprint mapping (what we implement)

| Sprint | Spec §57 | In this repo |
|---|---|---|
| 1 Agent Runtime | Interface, context, result, registry, runtime, tool registry, LLM gateway, audit | `services/agents/app/runtime/` wrapping existing LLM/ledger/tools |
| 2 Incident Engine | Incident, SM, Kafka events, Redis locks, evidence, timeline | State machine + evidence model + lock/idempotency; Case remains the persisted incident |
| 3 AI SOC | Triage, Investigation, TI, Correlation agents | Versioned adapters over existing runners |
| 4 Risk & Decision | Risk engine, Decision, Policy, Approval | New deterministic scorer + policy; approvals reused |
| 5 Response | Response tools, SOAR, isolation, IOC block, Validation | Permission-gated tools; live exec stays in `services/actions` dry-run default; ValidationAgent |
| 6 Intelligence & Reporting | Attack graph, MITRE, Report, PDF, dashboards | Typed AttackStory + IncidentReportPackage on existing graph/PDF |

## What we will not touch in this program

- Connector implementations and marketplace manifests
- Fusion Kafka consumer topology
- Four-agent public façade export set (tests lock it)
- Eval harness golden JSON (synthetic vs real honesty)
- Marketing site / Fly deploy unless a runtime bug is found
- The specification markdown itself
