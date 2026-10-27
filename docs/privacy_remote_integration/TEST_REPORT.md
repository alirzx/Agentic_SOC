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

## Direct HTTPX REST migration — 2026-10-27

The rows above are historical SDK-era evidence. They were preserved rather
than rewritten. The commands below validate the SDK-free transport introduced
after that evidence was recorded. Test groups overlap and must not be summed as
a unique-test count.

| Command / focused group | Passed | Failed | Skipped | Timed out | Status |
|---|---:|---:|---:|---:|---|
| Remote REST/packaging/adapter/contract/tool/tenant group | 93 | 0 | 0 | 0 | PASS |
| LLM no-bypass/gateway/HTTP/trace/smoke/config/NL group | 62 | 0 | 0 | 0 | PASS |
| Auto-Triage/router/runtime/structured-Investigator group | 67 | 0 | 0 | 0 | PASS |
| Fused worker/playbook/runtime/shadow group | 85 | 0 | 0 | 0 | PASS |
| API `test_privacy_llm_api_boundary.py` + eight-path inventory | 19 | 0 | 0 | 0 | PASS |
| `bash scripts/privacy_prebuild_check.sh` | 70 (10 API + 60 Agents) | 0 | 0 | 0 | PASS |
| Required Python 3.11 `compileall` paths | n/a | 0 | n/a | 0 | PASS |
| `poetry check --lock` | n/a | 0 | n/a | 0 | PASS |
| Root and demo `docker compose ... config --quiet` | 2 configs | 0 | 0 | 0 | PASS |
| Ruff on changed Python source/tests | n/a | 0 findings | n/a | 0 | PASS |
| Bash syntax for curl smoke and pre-build scripts | n/a | 0 | n/a | 0 | PASS |
| Active runtime/install SDK-reference scan | n/a | 0 references | n/a | 0 | PASS |
| Additional API tenant endpoint group in shared root environment | 0 | 3 collection errors | 0 | 0 | BLOCKED (environment) |
| `docker compose build agents` | 0 | 0 | 0 | 0 | NOT RUN (execution environment rejected image build) |

The additional API endpoint command did not execute tests: the inherited
`DEBUG=release` value was invalid for API Settings and the shared root virtual
environment lacks the API-only `python-jose` dependency. Setting `DEBUG=0`
allowed the required privacy boundary and inventory command to pass 19/19. No
dependency was installed to force the optional endpoint group to collect.

The existing Poetry executable is 1.7.1 while the checked-in lock was generated
by Poetry 2.4.1. A bounded no-update resolver attempt required package metadata
and timed out. Because the removed package's sole dependency (`httpx`) was
already direct and locked, the lock received the minimal equivalent update:
only the external package/source block was removed and the installed Poetry
locker supplied the new manifest content hash. `poetry check --lock` passes and
no unrelated package version changed.

The new non-skipped `test_privacy_remote_rest_contract.py` verifies actual
HTTPX request serialization with `MockTransport`: method/path, Bearer header,
tenant/profile/TTL, typed registrations, Encode purpose, Decode
`reveal_credentials=false`, response parsing, delete cleanup, invalid JSON,
malformed success, HTTP 400/401/403/413/422/503 mapping, timeout, connection
failure, cleanup failure, required response fields/typed stats, and Encode/Decode
response binding. Other focused tests retain cancellation,
cross-tenant Context isolation, expiry, provider no-egress on Encode failure,
Decode fail-closed, unknown aliases, bounded streaming, tool safety, and model
semantics coverage.

No real Gateway, Redis, VPN, provider, container image, or deployment was used
in this migration validation. The independent Gateway repository remained
read-only.
