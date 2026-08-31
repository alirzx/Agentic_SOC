# Benchmark Audit — Existing SOC Proxy Leakage

## Executive finding

**Your suspicion is correct.** On `synthetic_incidents.json` (200 cases), `Existing SOC Score ≈ 1.0` is **not** evidence that production SOC outperforms Agentic SOC. It is **substrate self-consistency** — the evaluation compares ground truth labels to a proxy that copies the same labels from each case row.

This invalidates `delta = agentic - existing` for agent optimization and production-readiness decisions.

## Data flow (leakage)

```text
synthetic_incidents.json case row
        │
        ├─► ground_truth_from_case()
        │       classification ← response_class
        │       severity       ← severity
        │       mitre          ← expected_techniques
        │       actions        ← response_class
        │
        └─► existing_snapshot_from_case()   ← "Existing SOC" proxy
                classification ← response_class
                severity       ← severity
                mitre          ← expected_techniques
                actions        ← response_class
                        │
                        ▼
              score vs ground truth
                        │
                        ▼
              classification = 1.0
              severity       = 1.0
              mitre F1       = 1.0
              existing_overall ≈ 1.0   (always)
```

**No fusion worker, triage worker, or LangGraph path runs for "Existing SOC" in Phase 8 evaluation.**

## What is valid vs invalid

| Comparison | Valid for optimization? | Notes |
|------------|-------------------------|-------|
| Agentic vs **Ground Truth** | Yes | True accuracy target |
| **Heuristic Agentic** vs Ground Truth | Yes | Fair deterministic baseline |
| **LLM Agentic** vs Ground Truth | Yes | Fair LLM baseline (when live LLM works) |
| Agentic vs **Existing proxy** | **No** | Tautological on synthetic substrate |
| `delta_vs_existing` on 200-case run | **No** | Misleading (e.g. -0.475) |

## Relationship to prior eval harness

The v1.4 substrate suites (`mitre_accuracy`, `investigation_completeness`, `response_quality`) were already documented as **self-consistency gates**, not live-agent accuracy (`apps/docs/docs/benchmark.md`, `docs/audit/REALITY_REPORT.md`).

Phase 8 added `existing_snapshot_from_case` which **re-introduced the same circular pattern** under the label "Existing SOC" — worse because it reads like a competitive baseline.

## Code anchors

| File | Role |
|------|------|
| `dataset.py` → `ground_truth_from_case` | Builds GT from case labels |
| `result_extract.py` → `existing_snapshot_from_case` | Copies same labels into "existing" |
| `scoring/case.py` | `existing_overall = (cls + sev + mitre_f1) / 3` |
| `benchmark_audit.py` | Detects leakage; sets `existing_score_valid` |

## Audit API

```python
from app.runtime.evaluation.benchmark_audit import audit_dataset, audit_case_leakage

audit = audit_dataset(cases)
# audit["existing_score_valid"] == False on synthetic_incidents.json
# audit["interpretation"] == "SUBSTRATE_SELF_CONSISTENCY_NOT_EXISTING_SOC"
```

Evaluation runs now include `benchmark_audit` in `aggregate_metrics` and `comparison_summary`.

## Correct workflow (your diagram)

```text
Phase 8.5 ✅
     ↓
Benchmark Audit ✅  ← you are here
     ↓
Phase 8.6 LLM Agent
     ↓
1-case real LLM (valid API)
     ↓
12-case benchmark
     ↓
Failure Attribution (use heuristic vs LLM vs GT, NOT existing proxy)
     ↓
Agent Optimization
     ↓
200-case (only after audit + live LLM path validated)
```

## What a fair "Existing SOC" baseline would require

One of:

1. **Run production path** — fusion output + `FusedAlertTriageWorker` / heuristic triage on each case (no label fields in input).
2. **Held-out labels** — separate `ground_truth.*` from `existing_soc_result.*` in dataset JSON (not present today).
3. **Replay stored production snapshots** — if historical fused-alert + triage outputs exist per incident.

Until then, use **`heuristic_agentic_score`** as the in-repo deterministic competitor.

## Golden dataset (12 cases)

Same leakage pattern when cases use `response_class` + `expected_techniques` for both GT and existing proxy. Golden cases are still valid for **Agent vs GT** and **security tests**; existing proxy score remains invalid.

## Recommendation

- Do **not** optimize prompts/agents based on `delta_vs_existing` or `existing_score` on `soc-benchmark-v1`.
- Treat `substrate_self_consistency_score` as a CI sanity check only.
- Report: `heuristic_agentic`, `llm_agentic`, `agentic_score` vs ground truth; `delta_valid_for_optimization` uses heuristic baseline when audit flags leakage.
