# Agentic SOC Capability Audit (2026-10-14)

Phase Zero inventory against the production-grade mission spec.
Status values: **Complete** | **Partial** | **Missing**.

## Architecture summary (as found)

```text
Connectors → IngestClient → services/ingest (OCSF) → Kafka raw_events
  → services/fusion (dedup → correlate → score → AlertSink Postgres)
  → Kafka aisoc.alerts.fused
  → FusedAlertTriageWorker (BC → memory → triage → escalate → promote_to_case)
  → optional AgenticShadowConsumer (AGENTIC_SOC_ENABLED)
Playbooks / services/actions: separate from auto-triage (API / approval / dry-run)
```

Stack preserved: FastAPI, LangGraph, Next.js, OpenAI-compatible LLM, Kafka spine.

| Capability | Existing implementation | Status | Required changes |
|---|---|---|---|
| Alert normalization | `services/connectors` + `services/ingest` OCSF | Complete | Preserve |
| Deduplication | `RawAlert.fingerprint`, `Deduplicator`, `AlertSink` idempotent insert | Partial | Occurrence + last_seen on dup; SET NX race guard |
| Noise suppression | BC YAML hot path, outcome memory, override:v2 | Partial | Explainable BC suppress persist; owner/expiry on rules |
| Alert correlation | Redis `Correlator` + attack-chain + RBA | Partial | event_time last_seen; correlator tests; durable incident link later |
| Asset enrichment | Graph criticality, CMDB API; not on triage hot path | Partial | Document gap; no fabricated assets |
| Tier 1 triage | `auto_triage_agent` + deterministic fallback + worker | Partial | Pydantic schema-validate LLM verdict |
| Tier 2 investigation | LangGraph escalation + separate InvestigatorOrchestrator | Partial | Preserve dual stack; budget enforcement later |
| Risk scoring | Fusion confidence, entity risk, runtime risk (shadow) | Partial | Document distinction; no conflicting single score claim |
| Case lifecycle | `case_promoter` + funnel stages + `AISOC_AGENT_AUTO_CASE` | Complete | Expand acceptance tests; preserve gates |
| Feedback loop | `/alert-override`, override learning, memory | Complete | Preserve approval-token workflow |
| Response dispatcher | PlaybookEngine API; actions service; triage read-only | Complete | Keep separation; no triage→playbook |
| Monitoring and metrics | Funnel KPIs, costs dashboard, shadow runs | Complete | Mark unlabeled quality rates provisional |
| Shadow mode | `AGENTIC_SOC_*` + Postgres shadow store | Partial | Off by default; enable for rollout |

## Non-goals of this wave

- Rebuild fusion or agents scaffolds
- Second Kafka topic tree
- NestJS / alternate agent framework
- Permanent global IP allowlists
- Auto-executing privileged playbook actions from triage

## Implementation wave (2026-10-14 change set)

Upgrade-in-place (no scaffold rebuild):

| Change | Paths |
|---|---|
| Dedup NX + occurrence/last_seen | `services/fusion/app/services/deduplicator.py`, `alert_sink.py`, `fusion_engine.py`, migration `057_alerts_occurrence_count.sql` |
| Explainable BC suppress | `services/agents/app/workers/business_context.py`, `case_promoter.py`, `fused_alert_consumer.py` |
| Tier-1 schema validation | `services/agents/app/agents/auto_triage_agent.py` (`TriageVerdictSchema`) |
| `likely_tp` canonical | `services/agents/app/agents/dispositions.py` |
| Correlation last_seen | `services/fusion/app/services/correlator.py` |
| Tests | `test_deduplicator.py`, `test_correlator.py`, `test_case_promoter.py`, `test_auto_triage_schema.py`, BC/hotpath, fused worker playbook assert |

Verified locally: agents critical suite **65 passed**; fusion dedup/correlator/model **23 passed**.
