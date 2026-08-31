# Phase 7 — Agentic SOC Shadow Mode

**Date:** 2026-08-31  
**Spec:** Soorin Agentic SOC + Phase 7 brief  
**Constraint:** existing production behaviour must not change. Rollback = `AGENTIC_SOC_ENABLED=false`.

This document is the pre-implementation gap analysis. Code follows it; it does not replace LangGraph, fusion, Case, or ingestion.

---

## Current production flow

```text
Connectors
  → services/ingest (OCSF) → Kafka aisoc.raw_events
  → services/fusion (dedup / correlate / confidence / narrative)
  → Kafka aisoc.alerts.fused
       ├─ services/agents FusedAlertTriageWorker
       │     group_id = aisoc-agents-triage
       │     copilot auto-triage + Investigation Ledger
       │     optional LangGraph escalation (AISOC_AGENT_ESCALATE_TO_GRAPH)
       └─ services/realtime (WS fan-out)

Case / alert lifecycle lives in services/api (Postgres + RLS).
SOAR / live actions live in services/actions (dry-run default).
LLM calls go through app.llm.factory + LiteLLM.
```

**Do not modify:** ingest, fusion consumer topology, `FusedAlertTriageWorker.triage()`, LangGraph graphs, Case status machine, actions executors, LLM factory.

---

## Agentic shadow flow

```text
Kafka aisoc.alerts.fused
  └─ NEW consumer group aisoc-agents-agentic-shadow
        │  (separate from aisoc-agents-triage — both see every message)
        ▼
  AgenticShadowService
        │  flags: AGENTIC_SOC_ENABLED && AGENTIC_SOC_SHADOW_MODE
        │  idempotency Redis SET NX  agentic-shadow:{tenantId}:{alertId}
        │  bounded asyncio.Queue + Semaphore (MAX_CONCURRENT_RUNS)
        ▼
  create AgenticShadowRun (CREATED → RUNNING)
        ▼
  AgentContext(metadata.shadow_mode=true, fail_soft=true)
        ▼
  SocOrchestrator  (triage → investigation → TI → correlation → risk/decision → dry-run response → report)
        ▼
  persist result + AgenticComparison  (COMPLETED | FAILED | TIMEOUT)
```

No Case/Alert row is updated. No `services/actions` call. Destructive tools are intercepted in the **tool registry**, not only in the agent.

---

## Integration point

| Piece | Where | How |
|---|---|---|
| Feature flags | `os.getenv` (same pattern as `AISOC_AGENT_KAFKA_DISABLE`) | `AGENTIC_SOC_*` — no new config framework |
| Kafka | **new** consumer in `services/agents` lifespan | Same topic, **new group id**. Existing worker file is not edited except `main.py` lifespan start/stop |
| Persistence | existing Postgres | New tables `agentic_shadow_runs` (+ RLS). Writers in agents via asyncpg (same pool pattern as the ledger). Readers in `services/api` |
| Redis | existing `REDIS_URL` | Idempotency + optional lock; in-process fallback when Redis is absent |
| LLM / tools | existing factory + `SocToolRegistry` | Shadow metadata forces dry-run on write tools |
| API | `GET /api/v1/soc/agentic/shadow-runs*` | Same auth/`cases:read`/RLS as investigations |
| UI | `/agentic/shadow-runs` | Read-only dashboard |

---

## Failure isolation strategy

1. Shadow worker is a **second** asyncio task. Exceptions inside it are caught and logged; they never propagate into `FusedAlertTriageWorker`.
2. `AgenticShadowService.run()` is fail-closed for *itself* (status `FAILED` / `TIMEOUT`) and fail-open for production (always returns without raising to the Kafka loop).
3. Orchestrator `fail_soft`: a single agent exception becomes a failed `AgentResult` and the pipeline continues.
4. DB/Redis outages: persist no-ops + log; the shadow run still finishes in memory and is counted as failed if nothing durable landed.
5. Process crash would take both workers (same container). That is accepted — we do **not** add a microservice. Kafka at-least-once redelivers to each group independently.

---

## Feature flags

| Variable | Default | Meaning |
|---|---|---|
| `AGENTIC_SOC_ENABLED` | `false` | Master switch. `false` → consumer not started, service is a no-op |
| `AGENTIC_SOC_SHADOW_MODE` | `true` | When enabled, force dry-run tools and forbid Case mutation |
| `AGENTIC_SOC_AUTO_RESPONSE` | `false` | Ignored while shadow mode is on (tool layer still dry-runs) |
| `AGENTIC_SOC_MAX_CONCURRENT_RUNS` | `10` | Semaphore + queue size floor |
| `AGENTIC_SOC_TIMEOUT_SECONDS` | `120` | `asyncio.wait_for` around the orchestrator |

Rollback: set `AGENTIC_SOC_ENABLED=false`. No migration revert required (tables stay unused).

---

## Observability

Structured logs (`structlog`) on every run with `shadow_run_id`, `alert_id`, `case_id`, `tenant_id`, agent, state, tool_calls, tokens, cost, latency, risk, confidence, decision, recommended_actions, error.

Prometheus counters/histograms (prometheus-client, already a dependency of `services/agents`):

- `agentic_shadow_runs_total`
- `agentic_shadow_success_total` / `failed_total` / `timeout_total`
- `agentic_shadow_duration_ms`
- `agentic_shadow_tool_calls`
- `agentic_shadow_input_tokens` / `output_tokens`
- `agentic_shadow_risk_score` / `agentic_shadow_confidence`

---

## Rollback strategy

1. Set `AGENTIC_SOC_ENABLED=false` (compose/helm/env).
2. Restart `services/agents` (or wait for next deploy).
3. Existing triage consumer, fusion, ingest, Case API, LangGraph are unchanged.
4. Leave migration `050_agentic_shadow_runs.sql` in place — unused tables are inert.

---

## Gaps this phase does **not** close

- Live SIEM `siem.search` beyond the existing Splunk evidence tool (investigation adapter still used, fail-soft).
- Persisting spec `IncidentState` onto `aisoc_cases` (Case remains source of truth).
- Replacing LangGraph as the production investigator.
- Autonomous response (explicitly forbidden in shadow mode).
