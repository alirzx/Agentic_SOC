# Workspace TKG integration sprint

Local work on feat/workspace-tkg-integration in both repositories. Both trees were clean and matched personal remote main at preflight. Agentic_SOC 10b64a115e4fd969fc8d1b314370a9ef08d520f0. TKG 75119697d7fdd9f877c481456ba6dffc375df52a. TKG graphify query identified the graph tool, receipt and knowledge handlers. Agentic_SOC had no generated graph.

## Progress

- [x] Verify repositories, personal remote SHAs, instructions and feature branches.
- [x] Freeze durable alert deliveries, enforce workspace bindings and handle replay.
- [x] Wire authorized read tools through Recon and preserve evidence.
- [x] Validate resolved Compose overlays and local contract, database and runtime fixtures.
- [ ] Qualify built images and perform the separately authorized Server 55 rollout and end-to-end acceptance.

## Continuation on 2026-11-24

Agentic_SOC started at `7b87d1ae0f93a3bcab8c4eff68d7a71f44c53854`, one commit ahead of local main. TKG started at `75119697d7fdd9f877c481456ba6dffc375df52a`, even with local main, with the previous MCP, Preview and Compose work in its working tree. Both continued on `feat/workspace-tkg-integration`.

### Delivery and isolation

Splunk connector records travel through Go Ingest, Kafka and Fusion. The alert INSERT and enqueue trigger share a Postgres transaction. Binding, Connector and workspace IDs are matched in SQL. RLS fails closed for the restricted application role without a transaction-local workspace. Fusion still refuses invalid tenants instead of moving alerts to Demo. The trigger ignores disposition and case membership. Backfill processes one workspace-scoped UUID page, returns a resumable cursor and defaults to dry-run.

The worker freezes exact curated bytes and hash at claim time and increments a durable lease fence. Preview verifies v1 canonical identity and the immutable source tuple. Newer servers also return server-derived KB and source IDs, which the worker checks when present. Both HTTP calls have fixed deadlines and execute outside the Postgres transaction. Lease ownership and binding enablement are rechecked before Ingest. An in-flight HTTP request can finish after a disable operation. Frozen replay relies on TKG checksum idempotency if delivery is uncertain. An expired final attempt transitions to quarantine instead of remaining in submitting. Ordinary ingestion carries a source credential only. Receipt diagnostics use a separately mounted admin credential and preserve TKG's delivery-state field. Accepted receipts remain pending until reconciliation establishes materialization.

Use trusted database UUIDs for the Demo and CAO rows. A connector references an owning workspace through a composite FK. Each enabled binding maps its workspace to a distinct TKG KB, source and immutable source tuple. Point cleartext files to `/run/secrets/tkg/<role>/<workspace_uuid>/<binding_uuid>` in the intended container only. API and Agents mount reader files. The worker mounts ingest files. Use a dedicated, least-privilege database login for the worker with SELECT on bindings and SELECT/UPDATE on deliveries. For a worker serving multiple workspaces, grant a policy to that operator-provisioned role on those two tables only. Keep the normal application role subject to the workspace RLS policy. Run backfill through a separately authorized operator connection with alert read and enqueue access. Keep diagnostics mounted only for the explicit receipts command. Test all role grants using the actual deployment roles before enabling the profile.

Case TKG Evaluation resolves an explicit workspace binding. Curated mode uses `SecurityAlert/soc_alert_row_id`. A designated legacy binding can opt into `legacy_notable` for read-only lookup. Manual curated sync queues deliveries for the worker. It has no graph admin rights. The UI's ordinary Evaluate action stays read-only for workspace bindings.

### Recon tool contract

Every tool uses a workspace-bound read PAT. Entity reads require a UUID established by exact resolution or an authorized graph traversal. Search candidates do not confer entity authority. The active signed grant is server-side and tool schemas reject tenant, source and KB overrides.

| Tool | Request | Response | Verification |
|---|---|---|---|
| `tkg.resolve_entity` | POST `/api/v1/kbs/{kb}/knowledge/resolve`, scoped alert identity established by the bearer and grant | v1 identity envelope and exact candidate | Registry and real Rust admission test |
| `tkg.get_entity_context` | POST `/api/v1/kbs/{kb}/knowledge/context`, entity UUID, optional world and knowledge time, bounded limit | v2 facts, provenance, temporal bounds and completeness | Registry and real Rust context read |
| `tkg.search_history` | POST `/api/v1/kbs/{kb}/search`, bounded query and top-k, optional knowledge time | candidates and retrieval metadata | Registry plus TKG retrieval fixtures |
| `tkg.get_timeline` | POST `/api/v1/kbs/{kb}/mcp`, `tools/call` with entity UUID, window, optional knowledge time and predicate | v1 structured graph evidence and original text | Registry and stored PostgreSQL graph rows |
| `tkg.get_neighbors` | POST same MCP path, one-hop entity UUID with predicate, object type, world or knowledge time | v1 graph facts, direction and source IDs, plus original text | Registry and stored PostgreSQL graph rows |

The signed alert path reaches the existing LangGraph investigator. The regular case route also signs the case scope. Its background task verifies workspace and case membership and selects the newest eligible attached alert as a bounded starting point. The optional RouterOrchestrator, direct ad hoc WebSocket path, and standalone structured investigation runtime have no TKG grant path. Recon's deterministic historical preflight feeds a bounded model loop. Forensic and Responder receive provider-safe source observations. Responder stays advisory. Report validation removes unknown KB/evidence ID pairs before publication.

The synthetic registry test executed resolve, context and search, then a model-selected neighbor read and the related entity's timeline. It recorded five logical tools, seven HTTP requests including MCP setup, and three LLM assessments. One fixture fact resolved to `00000000-0000-0000-0000-000000000003/00000000-0000-0000-0000-000000000009`. Partial context and truncated graph results remained explicit. The test boundary verified that the original synthetic hostname was absent from provider input and its DLP alias was present. Cost telemetry uses the existing estimated provider price rather than a billing-system reservation.

### Server 55 preflight

Use the actual deployment environment file on each host. These commands inspect configuration without starting or changing services.

```sh
docker network inspect aisoc-tkg --format '{{.Name}} {{.Driver}} {{.Internal}}'
docker compose --project-directory . -p aisoc-demo \
  -f infra/compose/docker-compose.demo.yml \
  -f infra/compose/privacy-network.override.yml \
  -f infra/compose/privacy-ca.override.yml \
  -f infra/compose/tkg-network.override.yml --profile tkg-sync config --quiet

docker compose -f docker-compose.production.yml \
  -f docker-compose.models-production.yml \
  -f docker-compose.models-isolated.yml \
  -f docker-compose.tkg-network.override.yml config --quiet
```

The SOC and TKG projects share only `aisoc-tkg`. Its TKG app alias is `soorin-tkg:1516`. The SOC API, Agents and one sync worker join it. TKG DB and model services retain their existing internal networks. SOC DLP keeps its own network. The worker uses the API Dockerfile, including `COPY . .`, with `python -m app.services.tkg.worker run`, 0.5 CPU and 256 MiB. A qualified image must contain the matching worker module. Configure HTTPS with certificate verification for rollout. For a private CA include `infra/compose/tkg-ca.override.yml` and set `AISOC_TKG_CA_FILE_HOST` to the approved CA bundle. The HTTP alias is a same-host private bridge configuration. Provision and inspect the actual isolated network, deployment secrets and role grants before changing flags.

Begin the rollout with reviewed image and database grants, migration on a backup-verified target, disabled bindings verified against trusted workspace/connector IDs, credential-scope checks, one synthetic delivery and materialization, bounded historical dry-run, limited backfill, automatic ingestion, then Recon preflight and iterative tool use. Live DNS, PAT provisioning, production database roles, network attachment and Server 55 end-to-end behavior require on-host verification. No live connector ingestion or real-data backfill was exercised.

### Verification

| Check | Pass | Fail | Skip or scope |
|---|---:|---:|---|
| SOC SQL migration chain | 105 migration files | 0 | Disposable PostgreSQL |
| SOC API, workspaces, case sync, outbox | 74 | 0 | Real Postgres, mocked worker HTTP, actual TKG Python Preview adapter |
| SOC Agents, signed alert and case routes, Recon, Auto-Triage, privacy | 120 | 0 | Real FastAPI routes with controlled peers and provider |
| SOC focused Fusion | 52 | 0 | Sink, deduplication, promotion and DLQ |
| SOC broader Fusion | 197 | 0 | 1 integration test deselected and the lake-writer file excluded |
| TKG server test binary | 634 | 0 | 2 ignored live external tests |
| TKG Python contracts, adapters and identity | 71 | 0 | 32 subtests also passed |
| Docker Compose configuration | 2 resolved stacks | 0 | Configuration only with synthetic values |

From the SOC API directory, set `TKG_TEST_POSTGRES_DSN` to a disposable DSN and `TKG_TEST_CHAIN_DSN` to a separate disposable database after migrations. Set `TKG_TEST_CHECKOUT` to the adjacent TKG repository path. The commands below use the existing service virtual environments.

```sh
# SOC API
python -m app.scripts.run_migrations
python -m pytest -q tests/test_workspaces.py tests/test_agents_investigation_proxy_contract.py \
  tests/test_agents_tenant_auth.py tests/api/v1/test_tkg*.py
TKG_TEST_FROZEN_ALERT_OUT=/tmp/tkg-generated-soc-fixture.json \
  python -m pytest -q tests/api/v1/test_tkg_outbox.py -k frozen_record

# SOC Agents
python -m pytest -q tests/test_tkg_workspace_recon.py tests/test_alert_investigat*.py \
  tests/test_investigate_router_flag.py tests/test_structured_investigation.py \
  tests/test_investigation_completeness.py tests/test_auto_triage*.py \
  tests/test_canonical_tenant_privacy.py tests/test_runtime_llm_privacy.py \
  tests/test_orchestrator_router_privacy.py tests/test_privacy_remote_rest_contract.py

# SOC Fusion
python -m pytest -q tests/test_alert_sink.py tests/test_promoter.py \
  tests/test_consumer_dlq.py tests/test_deduplicator.py
python -m pytest -q -m 'not integration' --ignore=tests/test_lake_writer.py

# TKG. Use a disposable TKG DSN in UTOPIA_DATABASE_URL.
UTOPIA_MODEL_TEST_MODE=1 UTOPIA_TEST_REQUIRE_DB=1 \
  AISOC_TKG_TEST_FROZEN_ALERT=/tmp/tkg-generated-soc-fixture.json \
  cargo test --locked -p utopia-server
python -m pytest -q soorin/tests/contracts soorin/tests/adapters soorin/tests/identity
```

The broader Fusion run timed out during asyncio teardown after `tests/test_lake_writer.py::test_flushes_when_batch_full` had passed. Focused Fusion coverage completed successfully.

The Rust acceptance run used the cached Rust builder with `cargo test --locked --offline --no-run -p utopia-server`, then ran the resulting test binary in the cached Python image with the repository mounted at its build-time path. The two ignored tests require the live OCR provider and a public RSS endpoint. TKG used the model-test configuration. The frozen alert traversed the actual Rust Preview, Ingest, receipt replay, document processing, graph materialization, exact Resolve, Context and KB-scoped MCP reads. The agent planner test used deterministic HTTP fixtures and a mocked provider. A single live stack test through Connector, Kafka, worker, TKG and Agents remains outstanding.

### Change inventory

- SOC alert delivery and authorization. `services/api/migrations/094_workspace_tkg.sql`, `services/api/app/services/tkg/{binding,evaluation,projection,worker}.py`.
- SOC case evaluation and API grants. `services/api/app/api/v1/endpoints/{agents,cases,case_tkg_evaluation}.py`, `services/api/app/services/agents_tenant_auth.py`, `services/api/app/services/tkg_evaluation/{client,runner,sync}.py`.
- SOC history execution and citations. `services/agents/app/api/investigate.py`, `services/agents/app/integrations/tkg/{binding,recon,tools}.py`, `services/agents/app/investigator/{claim_validation,recon_agent,report_writer_agent}.py`.
- SOC acceptance and operator material. `services/api/tests/api/v1/test_tkg_outbox.py`, `services/agents/tests/{test_alert_investigation_tenant_boundary,test_tkg_workspace_recon}.py`, `.env.example`, `infra/compose/tkg-ca.override.yml`, and this report.
- TKG transport and coverage. `crates/utopia-server/src/api/{soc_curated,soc_runtime_tests,tools_graph,mcp_tests}.rs`, `web/src/docs/mcp.md`, and `docker-compose.tkg-network.override.yml`.

Both branches retain their starting HEADs with reviewed changes in the working trees. Personal SOC remote main and feature matched local refs. Personal TKG remote main matched the local base. The personal TKG remote returned no feature branch. No commits, pushes, merges, deployments or production database operations were performed during this continuation.

## Sprint 3 qualification on 2026-11-25

Started from clean feature checkouts at SOC `86e99dc7` and TKG `65c9892`. Deployment classification and measured acceptance are tracked in `docs/deployment/SERVER55_TKG_QUALIFICATION.md`.

## Sprint 4

- [x] Verified the three starting revisions and fetched the authorized remotes.
- [x] Merged the verified SOC main into the existing integration branch.
- [ ] Qualify durable acknowledgment, receipt polling and the stateful Recon path.
- [ ] Record merge and deployment gates in the Sprint 4 qualification report.
