# PLAN-20261027-0001: Privacy Gateway Direct REST Migration

## Objective

Remove the external `soorin-privacy-sdk` dependency from the Agents service and
replace it with a small internal HTTPX client while preserving the existing
privacy backend interface, fail-closed behavior, tenant isolation, LLM provider
routing, agent workflows, and Gateway REST contract.

## Scope

1. Add `services/agents/app/privacy/rest_client.py` with direct, authenticated,
   bounded HTTPX calls for Context create/delete, Encode, and Decode.
2. Refactor `RemotePrivacyBackend` to own or accept the internal client without
   changing its workflow lifecycle, serialization, reconstruction, alias, retry,
   or telemetry behavior.
3. Remove the external package from `pyproject.toml`, `poetry.lock`, Docker
   fallback installation, and Docker import checks.
4. Replace the skipped SDK contract test with a non-skipped MockTransport REST
   contract test; update packaging, lifecycle, failure, pre-build, and workflow
   regressions.
5. Audit the API service's existing direct REST boundary and all eight protected
   API workflows without coupling the two independently deployable services.
6. Update privacy integration, pre-build, deployment, rollback, inventory, and
   test documentation to describe the SDK-free HTTPS architecture.

## Security invariants

- Context creation and Encode failures prevent provider egress.
- Decode failures never release protected output or tool arguments.
- Canonical trusted tenants remain bound to one workflow Context.
- Production or required-mode Remote Privacy rejects plain HTTP.
- Service credentials, Authorization headers, payloads, and raw Context IDs are
  never logged.
- Protected streaming remains bounded and buffered until Decode succeeds.
- Gateway detection, tokenization, mapping, encryption, and policy logic remain
  server-side.

## Verification

- Compile the affected Agents and API Python packages.
- Run direct REST contract, remote adapter/contract/tool, tenant/context,
  LLM-boundary, Auto-Triage, Router, Investigator, and API privacy tests with
  bounded execution.
- Run `scripts/privacy_prebuild_check.sh`, `poetry check --lock`, focused Ruff,
  Compose configuration checks, SDK-reference scans, and `git diff --check`.
- Run a bounded Agents Docker build only if the local Docker/network environment
  supports it; otherwise record that deployment gate as not tested.
- Refresh the code graph, review staged files explicitly, commit logical changes,
  push the original feature branch to both remotes, and verify identical heads.

## Out of scope

- Changes to the independent Gateway repository or its privacy engine.
- Provider-routing, agent business-logic, UI, or unrelated repository refactors.
- Real Gateway, real provider, or production deployment claims without operator
  credentials and an explicitly authorized live test environment.
