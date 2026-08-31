# Phase 8.6 — Real LLM Tool-Using Agent Layer

## Overview

Runtime triage and investigation agents (`v2.0`) invoke the existing `app.llm.factory` + `safe_ainvoke` path. Heuristic `run_triage` / `run_investigation` remain as explicit fallback with `execution_mode=FALLBACK_HEURISTIC`.

## Architecture

```
Fused Alert → AgentContext → Triage LLM Agent → Investigation LLM Agent (tool loop)
    → TI → Correlation → Decision (deterministic risk) → Report
```

- Tools: existing `SocToolRegistry` only (no second registry)
- Shadow mode / dry-run preserved
- Cost: `CostTracker` bound in `SocOrchestrator.run()`

## Configuration

```env
OPENAI_BASE_URL=...
OPENAI_API_KEY=...
AISOC_MODEL_PIN_TRIAGE=DeepSeek-V4-Flash
AISOC_MODEL_PIN_INVESTIGATION=DeepSeek-V4-Flash
AGENTIC_MAX_INVESTIGATION_ITERATIONS=12
AGENTIC_MAX_TOOL_CALLS=20
AGENTIC_MAX_LLM_CALLS=15
AGENTIC_MAX_INVESTIGATION_SECONDS=90
```

## Registered read-only tools

| Tool | Backend |
|------|---------|
| `search_ti` | `enrich_ioc` |
| `ti.lookup_ip` / `ti.lookup_hash` | `enrich_ioc` |
| `ti.search_attack_technique` | MITRE lookup |
| `siem.get_related_events` | `fetch_related_alerts` |
| `siem.get_case` | `fetch_case` |
| `extract_iocs` | regex extraction |
| `map_to_mitre` | keyword mapping |

## Evaluation

Three-way comparison in `metric_details.comparison_modes`:

- `existing` — substrate proxy
- `heuristic_agentic` — `run_triage` + `run_investigation`
- `llm_agentic` — live orchestrator path when `execution_mode=LLM`

## Prompt versioning

`app/runtime/llm_agents/prompts.py` — `prompt_id`, `prompt_version`, `prompt_hash` stored in evaluation metadata.

## Tests

`tests/test_agentic_llm_agents.py` — prompt injection policy, tool abuse, claim validation.
