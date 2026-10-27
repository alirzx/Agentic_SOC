# Remote Privacy Integration Test Report

All completed tests below used synthetic data and mocked providers/Gateway
transport. No production host, Redis, paid provider, Docker build, container
startup, or real organizational payload was used.

## Executed in the final hardening pass

| Command | Passed | Failed | Skipped | Timed out | Status |
|---|---:|---:|---:|---:|---|
| Final focused Remote/SDK/tool/API-tenant/trace/payload/smoke/packaging group | 93 | 0 | 0 | 0 | PASS |
| `pytest -q tests/test_privacy_remote_adapter.py` | 27 | 0 | 0 | 0 | PASS |
| `pytest -q tests/test_privacy_remote_contract.py` | 12 | 0 | 0 | 0 | PASS |
| `pytest -q tests/test_privacy_remote_tool_calls.py` | 3 | 0 | 0 | 0 | PASS |
| `pytest -q tests/test_privacy_api_context.py` | 15 | 0 | 0 | 0 | PASS |
| `pytest -q tests/test_llm_human_trace.py` | 10 | 0 | 0 | 0 | PASS |
| `pytest -q tests/test_privacy_gateway_smoke_contract.py` | 6 | 0 | 0 | 0 | PASS |
| SDK on `PYTHONPATH`; `pytest -q tests/test_privacy_remote_sdk_contract.py` | 1 | 0 | 0 | 0 | PASS |
| `pytest -q tests/test_auto_triage_llm_payload.py tests/test_auto_triage_dispositions.py` | 22 | 0 | 0 | 0 | PASS |
| tool/contract group (`test_tool_calling`, remote tools, extra, HTTP) | 26 | 0 | 0 | 0 | PASS |
| cost/structured/gateway group | 31 | 0 | 0 | 0 | PASS |
| no-bypass + canonical-tenant group | 21 | 0 | 0 | 0 | PASS |
| packaging + smoke parser + fake-curl group | 9 | 0 | 0 | 0 | PASS |
| canonical-tenant + API-context group after request-tenant hardening | 27 | 0 | 0 | 0 | PASS |
| Local privacy/compose/scripts/NL group | 35 | 0 | 0 | 0 | PASS |
| runtime/router/stream/shadow privacy group | 40 | 0 | 0 | 0 | PASS |
| alert/investigate/triage endpoint group, 30-second bound | at least 31 progress dots | 0 observed | 0 observed | 1 command | TIMEOUT |
| two known graph-runner budget cases | 0 | 2 | 0 | 0 | FAIL (baseline) |
| Python `compileall` for changed agents packages/scripts | n/a | n/a | n/a | 0 | PASS |
| `bash -n services/agents/scripts/privacy_gateway_curl_smoke.sh` | n/a | n/a | n/a | 0 | PASS |
| `poetry check --lock` | n/a | n/a | n/a | 0 | PASS |
| root and demo `docker compose ... config --quiet` | 2 configs | 0 | 0 | 0 | PASS |
| Ruff on changed Python sources/tests | n/a | 0 findings | n/a | 0 | PASS |
| docs build | 0 | 0 | 1 | 0 | NOT RUN (`pnpm` unavailable; no install attempted) |

Counts from commands with overlapping files are not summed into a unique-test
total. LangGraph emitted one pending-deprecation warning in several groups; it
did not change results.

The two graph-runner failures are unchanged from `main`:
`test_runner_node_step_budget_stops_early` and
`test_runner_does_not_keep_benign_after_budget_exhaustion`. They concern budget
semantics, not privacy code. The endpoint group was not rerun after its timeout,
per the bounded-testing rule.

## Security acceptance evidence

- Encode/serialization/invalid tenant/production misconfiguration prevent
  provider invocation.
- Gateway unavailable, unauthorized Context, invalid model-visible kwargs, and
  schema-semantic changes fail closed.
- Decode failure and unknown/corrupted aliases release no protected response;
  unknown aliases never reach tools.
- Tool descriptions are projected before binding; decoded arguments are schema
  validated before authorized execution, and malformed schemas are rejected at
  registration.
- Copilot creation, continuation, listing, and retrieval are tenant-owned.
- Protected streaming buffers across chunk boundaries, enforces a size cap, and
  performs one Decode before emission.
- Remote cache is disabled; provider calls record cost once even when Decode
  later fails; blocked calls do not enter the provider boundary.
- Gateway service credentials, provider keys, token keys, Authorization
  headers, Context IDs, and cache material are absent from payload traces and
  ordinary remote logs.
- Curl smoke policy parsing uses real Gateway object entries and the full shell
  flow passes against a fake `curl` transport without opening a socket.

## Historical evidence from the implementation commit

Earlier bounded runs on commit `31bbe6d` reported 131 passing privacy/contract
tests, 52 passing Auto-Triage/worker/tool tests, and 79 passing Local Privacy
tests. Those groups overlap and are historical context only, not substituted
for the final commands above.

## Not executed

| Check | Status | Required environment |
|---|---|---|
| Real Gateway health/ready/policies | NOT RUN | VPN/private Gateway host |
| Real Context/encode/decode/classify/delete | NOT RUN | authorized synthetic tenant/client |
| Container-side cross-server curl | NOT RUN | built/deployed agents image |
| Docker image build/start | NOT RUN | explicitly excluded from this pass |
| Redis-backed concurrency/performance | NOT RUN | live Gateway and private Redis |
| Real provider Auto-Triage | NOT RUN | approved provider and synthetic alert |
| Real provider Investigator | NOT RUN | approved budget/provider and synthetic case |
| Controlled staging rollout | NOT RUN | deployment authorization |

Mocks prove request shape and local fail-closed behavior; they do not prove VPN,
TLS, service authorization, Redis health, provider behavior, or deployment.
