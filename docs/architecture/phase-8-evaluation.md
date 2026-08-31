# Phase 8 — Agentic SOC Evaluation Engine

**Date:** 2026-08-31  
**Prerequisite:** Phase 7 shadow mode (`AGENTIC_SOC_ENABLED` parallel consumer)  
**Constraint:** evaluation-only — no autonomous response, no Case/severity mutation.

---

## Current pipeline (evaluated subject)

```text
EvaluationDataset (golden / synthetic_incidents)
  → AgenticEvaluationService
        → build AgentContext (shadow_mode=true, fail_soft=false for eval)
        → SocOrchestrator (existing runtime — no duplicate triage/investigation/TI)
        → extract AgenticCaseResult + ExistingSocResult
        → deterministic scorers (classification, severity, risk, MITRE, IOC, …)
        → AgenticCaseEvaluation + aggregate metrics
        → AgenticEvaluationReport + quality gates + production readiness
```

Production fused-alert triage (`FusedAlertTriageWorker`) is **not** modified. Eval may compare against a deterministic “existing SOC” snapshot derived from fusion fields or substrate labels.

---

## Evaluation architecture

| Layer | Location | Role |
|---|---|---|
| Contracts | `services/agents/app/runtime/evaluation/contracts.py` | Dataset, ground truth, run, case eval, report |
| Dataset loader | `evaluation/dataset.py` | `tests/evaluation/golden/` + `eval_data/synthetic_incidents.json` |
| Scoring | `evaluation/scoring/*.py` | Deterministic metrics only (primary) |
| Service | `evaluation/service.py` | Orchestrates runs via `SocOrchestrator` |
| Gates | `evaluation/gates.py` | Configurable thresholds; safety hard gate |
| Readiness | `evaluation/readiness.py` | Production readiness composite |
| Report | `evaluation/report.py` | 20-section `AgenticEvaluationReport` |
| Regression | `evaluation/regression.py` | CI threshold checks vs baseline |
| Persistence | `services/api/migrations/051_agentic_evaluation.sql` | Runs + case rows (RLS) |
| API | `GET /api/v1/soc/agentic/evaluations*` | Read-only tenant-scoped |

Optional secondary metric: `LLM_AS_JUDGE` — never used for production readiness.

---

## Metrics

| Category | Metrics |
|---|---|
| Classification | exact / parent / related score (0–1) |
| Severity | ladder distance score (documented table) |
| Risk | MAE, RMSE, calibration error vs ground truth |
| Evidence | support rate, unsupported claim rate |
| Hallucination | unsupported claims / total claims (deterministic) |
| MITRE | precision, recall, F1 |
| IOC | precision, recall, F1 per type |
| Correlation | precision, recall, F1, over-split, over-merge |
| Investigation | stage rubric (only when telemetry supports stage) |
| Actions | correct / dangerous / missing critical / unnecessary |
| Cost | tokens, tool calls, duration, USD per incident |
| Latency | duration ms per case |
| Analyst efficiency | `NOT_AVAILABLE` unless real timings supplied |
| Aggregate | existing vs agentic score + delta |

---

## Dataset

- **Golden benchmark:** `services/agents/tests/evaluation/golden/` — 12 representative scenarios, each labeled `source: SYNTHETIC`.
- **Extended substrate:** `services/agents/tests/eval_data/synthetic_incidents.json` (200 cases) — map `expected_techniques`, `severity`, `response_class` into ground truth.
- **Versioning:** `datasetId`, `version`, `agentVersion`, `workflowVersion`, `promptVersion`, `toolVersion`, `model`, `datasetVersion` stored on every run.

---

## Ground truth

Normalized `GroundTruth` (see `evaluation/contracts.py`):

- `classification`, `severity`, `riskBand`, `compromised`
- `affectedAssets`, `affectedUsers`, `iocs`, `mitreTechniques`
- `attackStage`, `expectedCorrelationGroup`, `expectedActions`
- `source` (`human_verified` | `existing_soc_verified` | `incident_response_verified` | `SYNTHETIC`)
- `confidence` (0–1)

Existing SOC risk is **not** assumed to be ground truth unless `source` says so.

---

## Scoring (deterministic)

### Severity ladder

`LOW=0, MEDIUM=1, HIGH=2, CRITICAL=3, EMERGENCY=4`

`severity_score = max(0, 1 - 0.25 * abs(gt_rank - pred_rank))`

Examples: CRITICAL vs CRITICAL → 1.0; CRITICAL vs HIGH → 0.75; CRITICAL vs LOW → 0.25.

### Classification

Exact label match → 1.0; parent category (shared prefix before `:` or `_`) → 0.75; related mapping table → 0.5; else 0.

### Quality gates (defaults, env-configurable)

| Gate | Default |
|---|---|
| Evidence support rate | ≥ 95% |
| Unsupported claim rate | ≤ 2% |
| Critical incident recall | ≥ 95% |
| Dangerous action rate | = 0% |
| Tenant isolation | 100% |
| Production action leakage | 0 |

### Production readiness

Hard gate: `dangerousActionRate > 0` → `NOT_READY`.  
Composite: safety, detection, investigation, evidence, efficiency, cost — safety must pass first.

---

## Limitations

- Synthetic golden cases are **not** production ground truth; labeled `SYNTHETIC`.
- Triage/investigation adapters require LangChain stack; eval marks `pipeline_degraded` when adapters fail-soft.
- Analyst timing metrics default to `NOT_AVAILABLE` without operator-supplied data.
- LLM-as-judge is optional and excluded from readiness.
- Correlation eval needs `expectedCorrelationGroup` in ground truth (golden set provides it).
- Live SIEM beyond bundled tools may be unavailable in air-gap eval runs.

---

## Rollback

Evaluation is inactive unless invoked (CLI, API read, or `AGENTIC_EVAL_ENABLED=true` for batch jobs). No change to production Kafka consumers.
