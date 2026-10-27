# Remote Privacy Integration Test Report

This report distinguishes executed offline checks from infrastructure-dependent
checks. Test data is synthetic. No production Splunk payload or paid-provider
request is used.

## Baseline

| Category | Command/result | Status |
|---|---|---|
| SOC focused baseline | 90 passed, 2 failed | FAIL (pre-existing graph budget semantics) |
| Gateway Python 3.11 compile | Failed at `engine.py:203` before fix | FAIL (confirmed compatibility defect) |
| Gateway async suite | First async request did not complete within a bounded run in this environment | NOT RUN to completion |

The SOC baseline failures are `test_runner_node_step_budget_stops_early` and
`test_runner_does_not_keep_benign_after_budget_exhaustion`; neither touches
privacy or Auto-Triage evidence composition.

## Implemented offline checks

The final executed commands/counts are recorded before branch finalization.
Focused coverage includes:

- remote context create/reuse/cleanup and cross-tenant rejection;
- real SDK request schema over `httpx.MockTransport`;
- LangChain messages, multipart content, metadata, Windows principals/paths;
- `safe_ainvoke`, buffered `safe_astream`, and complete raw HTTP bodies;
- encode/create/decode failure and unsupported-serialization no-bypass;
- unknown aliases and decoded tool arguments;
- unsafe `extra_body` and Authorization override rejection;
- Remote response-cache disablement and single cost record;
- curated `llm_payload`, fallback, injection sanitization, and deterministic
  formatting;
- existing Investigator, Router, Runtime, Contextual, Explain, Copilot, graph,
  worker, shadow, and tool-loop regressions.

## External checks

| Check | Status | Requirement |
|---|---|---|
| Live `/health`, `/ready`, policies, contexts, encode/decode/classify | NOT RUN | Reachable authorized Gateway host |
| Redis-backed concurrency/performance | NOT RUN | Live Gateway + Redis |
| Real-provider Auto-Triage | NOT RUN | Prior gates plus approved provider credential |
| Real-provider four-agent Investigator | NOT RUN | Prior Auto-Triage pass plus approved budget |
| Production deployment | NOT RUN | Host access and deployment authorization |

Use `services/agents/scripts/check_remote_privacy_gateway.py` for the live
non-provider check. Do not mark live checks passed from mocked responses.
