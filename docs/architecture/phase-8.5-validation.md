# Phase 8.5 — Agentic SOC Runtime Validation & Benchmark

## Canonical runtime

| Environment | Path | When to use |
|-------------|------|-------------|
| **Poetry** (preferred) | `services/agents/pyproject.toml` | Local dev: `cd services/agents && poetry install && poetry run python ../../scripts/run_agentic_eval.py` |
| **Docker** | `docker-compose.yml` agents service | Production-like stack with LiteLLM gateway |
| **CI** | `.github/workflows/` + `scripts/run_evals.py` suite `#12` | Deterministic stub orchestrator (no external LLM by default) |

Dependencies are declared in `services/agents/pyproject.toml`: `langchain-core`, `langgraph`, `langchain-openai`, `langchain-community`, `openai`, `asyncpg`, etc.

## Evaluation command

```bash
# From repo root (loads .env automatically)
python scripts/run_agentic_eval.py --dataset golden --limit 12

# Fail-fast if prerequisites missing (default)
python scripts/run_agentic_eval.py --dataset golden --limit 1

# Diagnostics only (degraded pipeline — not for baselines)
python scripts/run_agentic_eval.py --dataset golden --limit 1 --diagnostics

# Require live LLM gateway
AISOC_EVAL_REQUIRE_LLM=1 python scripts/run_agentic_eval.py --dataset golden --limit 1
```

Reports are written to `reports/agentic/evaluation-{run_id}.json` and `.md`.

## LLM configuration

Evaluation uses `app.llm.factory` (`make_chat_model`, `resolve_base_url`) — the same abstraction as production.

For OpenAI-compatible providers (e.g. Arvan Cloud AI / DeepSeek V4):

```env
OPENAI_BASE_URL=https://arvancloudai.ir/gateway/models/DeepSeek-V4-Flash/<token>/v1
OPENAI_API_KEY=<api-key>
AISOC_MODEL_PIN_TRIAGE=DeepSeek-V4-Flash
AISOC_MODEL_PIN_INVESTIGATION=DeepSeek-V4-Flash
AISOC_MODEL_PIN_REPORT=DeepSeek-V4-Flash
```

**Note:** Current runtime adapters (`TriageRuntimeAgent`, `InvestigationRuntimeAgent`) wrap deterministic `run_triage` / `run_investigation` heuristics. LLM pins apply when agents invoke `make_chat_model` directly; cost will show `NOT_AVAILABLE` until live LLM calls are recorded by `CostTracker`.

## Pipeline verification

`app.runtime.evaluation.pipeline_verify.verify_pipeline()` returns:

```json
{
  "ok": true,
  "eval_valid": true,
  "dependencies": {},
  "adapters": {},
  "llm_gateway": {},
  "ti": {},
  "evidence": {},
  "risk": {},
  "report": {}
}
```

`eval_valid = false` when core imports fail. `AISOC_EVAL_REQUIRE_LLM=1` also requires `OPENAI_BASE_URL` + `OPENAI_API_KEY`.

## Fail-fast semantics

| State | Baseline update | Production readiness |
|-------|-----------------|-------------------|
| `eval_valid=true`, `pipeline_degraded=false` | Allowed | May pass gates |
| `PIPELINE_DEGRADED` | **Blocked** | Not valid |
| Prerequisites missing | Fail-fast (unless `--diagnostics`) | Not valid |

## Stage metrics

Eight required stages: triage, investigation, ti, correlation, evidence_graph, risk, decision, report.

`pipeline_completeness = completed_required_stages / 8`. Less than 1.0 marks `PIPELINE_DEGRADED`.

## Golden dataset

`services/agents/tests/evaluation/golden/` — 12 scenarios, all `dataset_type=SYNTHETIC`.

## Regression

- Baseline: `services/agents/tests/evaluation/regression_baseline.json`
- CI suite: `scripts/run_evals.py --suite agentic_eval` (deterministic stub, 2 cases)
- `update_baseline()` refuses degraded runs (`can_update_baseline()` guard)

## Limitations

- Synthetic golden data is not production validation.
- Analyst efficiency defaults to `NOT_AVAILABLE` (never fabricated).
- Zero cost/tokens means `NOT_AVAILABLE`, not free.
- Negative agentic vs existing delta is valid signal — classify failure before optimizing agents.
