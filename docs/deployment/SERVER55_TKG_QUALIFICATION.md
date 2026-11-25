# Server 55 TKG qualification

Sprint 4 changes and current gates are recorded in the [Sprint 4 qualification report](TKG_SPRINT4_FINAL_QUALIFICATION.md). The earlier baseline and measurements below describe Sprint 3.

Date of local qualification is 2026-11-25 in Asia/Tehran. Scope is the existing Agentic_SOC and Soorin TKG feature branches. The tests used disposable PostgreSQL, read-only source mounts, synthetic Splunk records and TKG model-test mode.

## Review findings

| Severity | Location | Root cause and risk | Repair and evidence |
|---|---|---|---|
| P0 | SOC `RawAlert.fingerprint` and `AlertSink.persist` | The Splunk finding UID can be the vendor external ID. Two connectors in the same tenant can therefore collide. Optional display collapse could also suppress separate durable Splunk records. | Fingerprint includes the authenticated connector ID for new Splunk records. Legacy lookup requires the same connector. Display grouping cannot suppress persistence for scoped Splunk records. The real Fusion SQL test keeps a legacy row and admits a second connector with the same vendor ID. PostgreSQL verifies both expected outbox rows. |
| P0 | SOC `tkg.worker.request_json` and `deliver` | TKG's temporary normalizer saturation and permanent admission conflicts both use HTTP 409. Incomplete receipt acknowledgments also risked terminal quarantine after admission. | Retry only the recognized normalizer markers on 409. Other conflicts remain terminal. Retry invalid acknowledgments using the frozen payload. Bounded tests cover both retry markers, a terminal conflict and a stale worker racing a newer lease. |
| P0 deployment check | SOC `IngestEvents` and final Compose | The connector batch route trusts the caller-supplied tenant header and connector ID on its service network. An externally reachable route would let an unauthenticated caller supply those fields. | The comparer rejects non-loopback host publication. The operator must verify reverse-proxy routes and admission to the trusted SOC network. No public route was exercised. |
| P1 | SOC `tkg.projection.freeze` | The projection read only one nested envelope and omitted the vendor revision ID. Compact legacy records could lose source metadata. | Recover the vendor record through bounded nesting. Verify trusted OCSF tenant and connector fields when present, preserve vendor source revision ID and accept compact known shapes. The corpus exercises six variants and eight quarantine reasons per tier. |
| P1 | SOC `Session.lookup`, `Session.execute`, `prompt_evidence` | Authority could be updated before the byte budget admitted the evidence. Context responses were scoped by KB and tenant but their requested root could differ. Some lineage and stop reasons were also missing. | Scope-check the root, validate bounded result shapes and authorize pivots only after retaining evidence. Preserve typed references and report logical, transport, LLM, iteration, and spend limits separately. Tests cover discarded evidence and MCP setup under a one-request budget. |
| P1 | SOC `test_privacy_packaging_contract.py` | A test expected pip fallback literals although the maintained Dockerfile installs Poetry's locked main dependencies. | Test verifies the installed dependency group, dependency check and internal privacy-client import. Packaging source and DLP configuration are preserved. |
| P1 | SOC `tests/test_lake_writer.py` | Async executor teardown hung in the command sandbox after a fake-client test passed. | All 11 lake-writer tests and the full Fusion unit selection pass with normal process permissions. No production lifecycle change was needed. |
| P2 | SOC `tkg.worker`, `Session.execute`, and Compose qualification | Existing events lacked useful timings and actual Compose preservation was difficult to compare without dumping interpolated secrets. | Add delivery and read timing logs scoped by opaque IDs. The configuration check compares the pre-TKG and final stacks in memory and prints no interpolated values. |

## Data flow and boundaries

Splunk polls through the connector. Go Ingest stamps OCSF with the tenant header and connector fields supplied by the trusted Connector service and produces a connector-scoped event identifier. Kafka carries the normalized event to Fusion. Fusion preserves the alert identity and writes PostgreSQL. The insert trigger records the outbox snapshot in the same transaction. True positives, false positives, benign, review, auto-closed, suppressed and case-free records follow that path.

The worker claims with skip-locked and freezes a verified body with SHA-256. It checks its lease and enabled binding again after Preview. An in-flight HTTP request can finish after a disable or expired lease. The stale claimant cannot overwrite a newer result, and TKG deduplicates exact byte replay by source and checksum. TKG HTTP 200 admission creates a receipt. Materialization has a separate transition to bound and requires document processing and graph projection. Until then Recon can see pending or absent evidence. Operator receipt refresh needs separate diagnostic credentials. Connector deduplication still preserves the first durable version of a notable. A later upstream revision of the same alert is outside the current one-delivery-per-alert-row workflow.

The migrated RLS test checks restricted application access. The same-tenant Fusion test uses two distinct connector IDs, source IDs and KBs. The SOC corpus alternates between independent synthetic Demo and CAO workspace bindings. Real TKG tests exercise unauthorized KB reads, source-token checks, reader PAT revocation, native revisions, evidence linkage, and exact resolution. The synthesized cross-repository HTTP corpus is normalized to the existing dedicated TKG test source for the Rust test. Its HTTP results therefore qualify admission and materialization in a single authorized KB, while workspace isolation is checked in the separate boundary tests.

## Five-tool contract

All reads use a KB-scoped reader PAT. The workspace is derived before tool dispatch. Source and KB IDs are configured by the binding. Tool arguments cannot override them.

| Tool | Endpoint and inputs | Output and qualification |
|---|---|---|
| `tkg.resolve_entity` | POST `/api/v1/kbs/{kb}/knowledge/resolve` with the signed alert-row ID and source tuple | Versioned identity response. Conflicting, ambiguous and incomplete responses cannot authorize a graph pivot. Rust and registry pass. |
| `tkg.get_entity_context` | POST `/api/v1/kbs/{kb}/knowledge/context` with retained entity UUID, optional world and knowledge time and bounded limit | Versioned facts with exact requested root, evidence, conflict and truncation metadata. Rust and registry pass. |
| `tkg.search_history` | POST `/api/v1/kbs/{kb}/search` with bounded query and top-k | Results remain candidates. Empty and fallback states remain explicit. Rust search and registry pass. |
| `tkg.get_timeline` | POST `/api/v1/kbs/{kb}/mcp`, JSON-RPC `tools/call` for `timeline` with entity UUID and bounded window | Versioned structured facts and original text. Stored IDs and temporal filters exercised by the Rust suite. Rust and registry pass. |
| `tkg.get_neighbors` | Same MCP path with `neighbors`, entity UUID and bounded filter | Direction, related entity, facts and document/chunk lineage. Retention and depth gate pivots. Rust and registry pass. |

The deterministic Recon test used a mocked provider. Resolve returned a root UUID, Context returned partial evidence and search returned an empty candidate set. The first model response selected Neighbors after observing the root. The second selected Timeline only after the peer UUID appeared in the validated observation. The test used five logical tool calls, seven HTTP requests including initialize and tools/list, and three model calls including the final assessment. The iteration budget ended the loop. It retained the sanitized fixture citation `00000000-0000-0000-0000-000000000003/00000000-0000-0000-0000-000000000009`. The model-facing payload contained a protected hostname, typed temporal facts and bounded evidence references. Separate tests verify scope and transport budget, DLP failure handling, and claim validation. Live provider decision quality remains unmeasured.

## Corpus

The tiers reuse the TKG schema-derived synthetic Splunk generator with real OCSF envelope field names. The corpus includes current and legacy nested shapes, enriched and compact bodies, fractional time and offsets, event/update clock pairs, multiple upstream IDs, high-cardinality event reference lists and varied dispositions. No customer records are included.

| SOC tier | Alert rows and deliveries | Canonical previews | Worker quarantines | Replayed inserts | Isolation failures |
|---|---:|---:|---:|---:|---:|
| Small | 64 | 56 | 8 | 8 | 0 |
| Medium | 640 | 632 | 8 | 80 | 0 |

Each tier quarantined one missing identity, invalid time, scope mismatch, conflicting API alert ID, malformed JSON, oversize body, unsupported source type and corrupt event identifier list. PostgreSQL rejects a mismatched binding/connector owner through a composite foreign key. No invalid corpus record was submitted to the HTTP client.

## Local performance

Measurements are synthetic developer baselines. They are neither Server 55 limits nor provider/model capacity tests. The host exposed 12 logical CPUs and about 15 GiB memory. Rust acceptance containers were allowed six CPUs. SOC timings include one insert at a time against loopback PostgreSQL. Canonical previews in the SOC corpus use the TKG Python adapter directly.

| SOC series, ms | Small p50 / p95 / max | Medium p50 / p95 / max |
|---|---:|---:|
| PostgreSQL alert plus outbox insert | 0.569 / 0.917 / 29.749 | 0.472 / 0.857 / 26.027 |
| Worker-shaped frozen projection | 0.051 / 0.088 / 0.104 | 0.044 / 0.068 / 0.102 |
| TKG Python Preview adapter | 1.850 / 3.920 / 5.635 | 1.596 / 3.309 / 4.479 |

### Rust HTTP admission and bounded materialization

Both HTTP tiers used the same code with the Python normalizer copied to the disposable container filesystem. The Rust handlers were called through their real Axum routes with PostgreSQL and scoped source tokens. Model-test mode and serial submissions kept the run bounded. Each tier processed six receipts through the graph and then verified exact Resolve and meaningful Context using a read PAT.

| HTTP tier | Admitted | Receipt replays | Bound and resolved | Pending by test design | Admission and sample elapsed |
|---|---:|---:|---:|---:|---:|
| Small | 56 | 7 | 6 | 50 | 19.85 s |
| Medium | 632 | 79 | 6 | 626 | 165.19 s |

There were no unresolved records among the 12 materialized samples. The remaining accepted records were left pending intentionally. Effective admission was approximately 2.82 and 3.83 records per second, respectively, including Preview, sampled replays and the bounded materialization work. An initial medium attempt against the host-mounted Python tree exceeded the 150-second test deadline. The rerun had a 240-second cap.

| TKG series, ms | Small p50 / p95 / max | Medium p50 / p95 / max |
|---|---:|---:|
| Preview | 117.78 / 228.27 / 243.98 | 116.26 / 127.87 / 231.57 |
| Ingest | 122.41 / 225.72 / 232.25 | 119.87 / 135.41 / 238.47 |
| Receipt processing to bound, six samples | 530.74 / 564.00 / 1,208.39 | 497.12 / 570.26 / 1,177.10 |
| First Context, six samples | 25.99 / 28.58 / 30.00 | 27.21 / 27.46 / 28.64 |

Peak child RSS was approximately 150 MiB small and 147 MiB medium. User/system CPU time was 18.75/2.38 seconds small and 148.01/17.57 seconds medium. These exclude independent PostgreSQL and production model-service resource usage. Per-tool Resolve, Search, Timeline and Neighbors latency, full worker queue lag, live connection use and full Recon latency were not isolated in the benchmark. Keep the default one delivery per second for operator acceptance and measure backpressure on the real model and database stack before raising it.

## Operator preflight

### Sprint 4 runtime and rollout sequence

1. Check reviewed SOC and TKG revisions, verify rendered Compose using the actual private runtime override, and inventory image digests and migrations. Back up both databases and rehearse restoration in an isolated environment. Apply TKG migration `10009_receipt_status_pat.sql` with the migration role and confirm TKG health before rebuilding and rolling SOC API, Agents and Fusion. Apply SOC `095_tkg_receipt_reconciliation.sql` after `094_workspace_tkg.sql`. Complete the Fusion writer replacement before enabling new deliveries.
2. Keep TKG and DLP on their existing private networks. From API and Agents, verify DLP hostname, TLS validation, CA bundle, protected multi-turn probe and unauthorized-workspace rejection. Resolve `soorin-tkg` from authorized services and check its private listener on port 1516. Check private CA verification when using HTTPS. Verify reverse-proxy routing and network membership for `/v1/ingest` and `/v1/ingest/batch`.
3. Verify each workspace's connector ownership and explicit immutable KB/source mapping. Confirm read-only mounts for reader PATs in API and Agents, source tokens in `tkg-sync`, and `receipt_status` PATs in `tkg-reconcile`. Use independent database users and credential files for submission and polling. Confirm the reconciler has no table ownership, role inheritance granting extra access, `BYPASSRLS`, or superuser privileges. Check that its PAT owner has Viewer access to the assigned KB only and that revoked or foreign-KB tokens fail.
4. Inspect the built Agents image with its regular service user. Verify all six Markdown files under `app/investigator/prompts/recon` and the eight registry hashes in `app/llm/prompts.lock.json`. Use existing build scripts and approved package and model images. Preserve the previous images and flag configuration.
5. With DLP required and tested, enable the sync worker for a synthetic workspace and keep its default one submission per second. Enable `tkg-reconcile` and verify one valid receipt progresses from pending to bound with its original ID. Confirm worker replay after an uncertain acknowledgment leaves one receipt and alert delivery. Check stable counts and retry/quarantine reasons across successive queue measurements.
6. Enable the agent's signed investigator path and Standard Recon with bounded preflight. Send multiple authored synthetic alerts through the private connector to exercise automatic Case creation, canonical membership, two authorized roots, isolation across workspaces, graph evidence, and RunSummary. Enable the planner loop after the preflight baseline is sound. Qualify Deep Case on an explicit acceptance case with separate model approval and cost allowance.
7. Observe queue depth, oldest accepted-receipt age, TKG and Postgres CPU/RSS, model pressure, worker retries, and time from ingestion to bound and first valid Context. Pause flag expansion if backlog age rises across measurements, quarantine increases, or DLP cannot protect the workflow. For rollback, disable planner and historical reads, stop new submissions, and decide whether polling can safely finish already-admitted receipts before reverting images. Keep immutable bindings, frozen requests and receipt IDs intact. Re-run DLP and scope probes after rollback.

### Reconciler database role

Provision a dedicated login through the operator's secret manager. The following example assumes `aisoc_tkg_reconcile` already exists and has no inherited application rights. Run as the owning migration administrator. Use the deployment database and schema explicitly.

```sql
GRANT USAGE ON SCHEMA public TO aisoc_tkg_reconcile;
GRANT SELECT (id, tenant_id, instance, kb_id, source_id, tkg_tenant,
              source_system, source_instance, connector_id, enabled)
  ON workspace_tkg_bindings TO aisoc_tkg_reconcile;
GRANT SELECT (id, tenant_id, binding_id, state, receipt_id, receipt_status,
              receipt_delivery_state, receipt_accepted_at, created_at,
              reconcile_after, reconcile_fence, reconcile_failures)
  ON tkg_alert_deliveries TO aisoc_tkg_reconcile;
GRANT UPDATE (state, receipt_status, receipt_delivery_state, updated_at,
              error_code, reconcile_after, reconcile_fence, reconcile_failures)
  ON tkg_alert_deliveries TO aisoc_tkg_reconcile;
CREATE POLICY tkg_reconcile_bindings ON workspace_tkg_bindings
  FOR SELECT TO aisoc_tkg_reconcile USING (enabled);
CREATE POLICY tkg_reconcile_deliveries ON tkg_alert_deliveries
  FOR ALL TO aisoc_tkg_reconcile
  USING (receipt_id IS NOT NULL AND state IN ('pending_materialization','bound','quarantined'))
  WITH CHECK (receipt_id IS NOT NULL AND state IN ('pending_materialization','bound','quarantined'));
```

Validate the role by selecting receipt identifiers, running one fenced poll, and verifying that `payload`, `snapshot`, general alerts and credential tables are inaccessible. Its diagnostic PAT can poll the payload-free individual status endpoint only. Use `AISOC_TKG_RECONCILE_DATABASE_URL` independently from `AISOC_TKG_WORKER_DATABASE_URL`.

### Recon and polling controls

| Control | Standard | Deep Case |
|---|---:|---:|
| Planner iterations and total model calls | 8 / 9 | 11 / 12 |
| Logical tools and HTTP requests | 12 / 32 | 15 / 48 |
| Planner and assessment output tokens | 512 / 2,048 | 768 / 3,072 |
| Overall deadline and retained case seeds | 120 s / 5 | 240 s / 10 |
| Resolve, graph tool and Search deadlines | 10 s / 15 s / 30 s | 15 s / 20 s / 45 s |
| MCP setup deadline | 10 s | 15 s |

Set `AISOC_TKG_RECON_PROFILE` to `standard` or `deep_case`. The history and planner switches default off. The state keeps server-issued roots, retained observations, examined seeds, concise objectives and distinct query keys through one run. The signed Case route uses workspace-owned case membership, explicit alert exclusions and source-diverse ordering. The signed alert route continues to use its single alert. The grant is a purpose-, workspace- and resource-bound service HMAC. It relies on trusted service routing and key rotation for replay control and is not a public bearer credential. Alternate router execution does not enable this TKG history path. The planner and final assessment use the existing DLP boundary. Search excerpts and tool outcomes count against bounded context. Citation validation checks that the final assessment could see a linked fact in the run's scope and that any cited entity and knowledge time agree. Retained claims require analyst review. Historical coverage remains partial when only some roots or bindings have usable evidence.

The Reconciler defaults off. It uses a 30-second interval, up to 30 due receipts per pass, one concurrent request and a 10-second request deadline. Claims use an ordered queue, skip-locked, a 40-second lease and a fence. Each pass checks a receipt once. Recoverable TKG states remain pending. Definitive terminal failures go to quarantine. Poll errors back off up to 900 seconds. Pending-age warning and alert defaults are five and 30 minutes. Manual `receipts` and scoped `backfill` remain available. Review frozen payload hashes and receipt IDs before replaying admitted work. Native TKG document revisions remain supported. SOC still delivers the first immutable alert row, and verdict, Case membership and UI updates never create a source revision.

`.env.example` lists the runtime knobs. `AISOC_TKG_WORKER_*` defaults are six attempts, a 60-second lease, two HTTP calls with 15 seconds each, 10-second DB connection and 15-second SQL deadlines, a five-second idle sleep, one delivery per second, retry jitter under 300 seconds and reconnect jitter under 30 seconds. `AISOC_TKG_RECONCILE_*` configures polling and alert ages independently. Blank optional values retain their profile or service default. Invalid lease and deadline combinations fail configuration validation. The one-megabyte successful response limit and four-kilobyte conflict envelope are fixed transport bounds. Credential files are reread per request or delivery so rotation does not rewrite queued payloads.

Set `AISOC_TKG_RECON_PREFLIGHT_SEEDS` to bound initial source reads. Standard and Deep Case budget fields use the `AISOC_TKG_RECON_` prefix. Admission checks token size after DLP protection and reserves assessment capacity. The cost check uses local estimates. Unknown gateway aliases require both `AISOC_TKG_RECON_UNKNOWN_INPUT_USD_PER_1K` and `AISOC_TKG_RECON_UNKNOWN_OUTPUT_USD_PER_1K`; the gate refuses provider calls when pricing is unknown. Provider-side proxy retries and billing remain an operator concern. Use a remote DLP TTL longer than the configured Recon horizon plus the DLP request window. The complete Investigator may need a larger workflow-wide TTL. Aliases stay within one context, and expired or unresolved aliases fail before a read or provider call can proceed.

The two workers export aggregate Prometheus text to `/tmp/aisoc-tkg-sync.prom` and `/tmp/aisoc-tkg-reconcile.prom` inside their own containers. Inspect them through approved operations access or configure a private collector. Queue and latency metrics use fixed state labels. Logs correlate workspace, delivery, receipt and run UUIDs without request data or raw Search excerpts.

Run the configuration comparer from the checked-out SOC directory after reviewing both HEADs. It invokes only `docker compose config` and suppresses interpolated output. The local run used synthetic environment and runtime override inputs. Use the actual server-only override for the operator run.

```bash
git status -sb
git rev-parse HEAD
git -C "$TKG_CHECKOUT" status -sb
git -C "$TKG_CHECKOUT" rev-parse HEAD
python3 scripts/qualify_tkg_compose.py \
  --tkg-checkout "$TKG_CHECKOUT" --runtime-override "$SOC_RUNTIME_OVERRIDE" \
  --soc-env "$SOC_COMPOSE_ENV" --tkg-env "$TKG_COMPOSE_ENV" --private-ca
docker network inspect aisoc-privacy aisoc-tkg --format '{{.Name}} {{.Driver}} {{.Internal}}'
docker ps --format '{{.Names}} {{.Image}} {{.Status}}'
docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}'
```

Record image IDs of the running API, Agents, Fusion and TKG app before a change. Compare build contexts and exact rendered flags against the approved images. Rebuild the affected service images from aligned revisions and retain the previous digests. Avoid a mixed-version Fusion writer rollout because older writers do not understand the new connector-scoped fingerprint. Reuse qualified model images. Confirm each DSN and secret mount through its service identity without printing values. Verify that the reverse proxy does not route public traffic to `/v1/ingest` or `/v1/ingest/batch`, and restrict the SOC service network to trusted workloads. Verify the existing DLP TLS hostname and CA with the protected-workflow probe documented in the SOC build runbook. Qualify `soorin-tkg` DNS, port 1516 and the chosen HTTPS origin from each participating service after network attachment.

Review applied migrations and validate the rollback procedure against a restored backup. The existing 094 tables use RLS and the migration adds no change to live data in this sprint. Confirm the dedicated worker grants, workspace-to-connector foreign keys, unique immutable KB/source bindings, minimal reader PAT, distinct ingest token, and separately mounted receipt-reader credential. Keep the integration flags disabled until bindings and credentials are verified. A read-only queue preflight is below. Run it using an approved diagnostic role and transaction scope.

```sql
BEGIN READ ONLY;
SELECT state, count(*) AS deliveries, min(created_at) AS oldest
FROM tkg_alert_deliveries
GROUP BY state;
ROLLBACK;
```

Start the operator acceptance with one synthetic notable in a dedicated workspace and retrieve its bound receipt, graph context and signed Recon result. Measure oldest pending age, retry/quarantine rate, first bound receipt, first Resolve and first Context. Establish the actual queue budget before increasing concurrency. A growing oldest pending age over consecutive samples or a rising quarantine count calls for investigation before raising submit rates. Retain the disabled flag configuration for rollback and keep stable source IDs and frozen payload bytes.

## Readiness

**BLOCKED for opening controlled Server 55 acceptance until the actual runtime override, image digests, least-privilege database roles and on-host gateway connectivity are verified.** Local tests establish source and contract readiness. A complete live Connector → Go Ingest → Kafka → Fusion → worker → TKG → Recon run and the resulting CPU, RSS, queue-depth, retry and model-backed retrieval latency remain to be measured. The local toolchain had a Kafka image but no Go binary or cached Go builder image. The large tier and sustained production-shaped model load were skipped. No production host was accessed.

## Repository state

- Agentic_SOC is on `feat/workspace-tkg-integration` at `86e99dc782cebfd22f1c9ae34fe98ddbd5a02bee`. Changes cover the Fusion model/sink, SOC projection and worker, Recon tool adapter, evidence formatting, integration tests, the Compose checker and the qualification report.
- Soorin TKG is on `feat/workspace-tkg-integration` at `65c989206fef53515b6a3c77d3727b2c7ee4efa0`. The change is limited to the opt-in corpus test in `crates/utopia-server/src/api/soc_runtime_tests.rs`.
- Deleted files, commits, pushes, merges and deployments during Sprint 3 are zero.

## Test commands and disposition

Run SOC tests from their service directories with the service virtual environments. The database-backed selections used the migrated disposable PostgreSQL chain and a second disposable database for TKG and isolated fixture schemas.

```sh
# SOC API
python -m app.scripts.run_migrations
python -m pytest -q -s tests/test_workspaces.py tests/test_agents_tenant_auth.py \
  tests/test_agents_investigation_proxy_contract.py tests/api/v1/test_tkg*.py

# SOC Fusion
AISOC_RUN_INTEGRATION=1 python -m pytest -q

# SOC Agents
python -m pytest -q tests/test_tkg_workspace_recon.py tests/test_alert_investigat*.py \
  tests/test_investigate_router_flag.py tests/test_structured_investigation.py \
  tests/test_investigation_completeness.py tests/test_auto_triage*.py \
  tests/test_*privacy*.py tests/test_router_report.py tests/test_claim_validation.py

# TKG
python -m pytest -p no:cacheprovider -q soorin/tests/contracts soorin/tests/adapters soorin/tests/identity
cargo run --locked -p utopia-store --example migrate
cargo test --locked --offline --no-run -p utopia-server
cargo test --locked -p utopia-server
```

For the API selection set `TKG_TEST_CHECKOUT`, `TKG_TEST_POSTGRES_DSN` and `TKG_TEST_CHAIN_DSN` to the adjacent checkout and the disposable databases. Set `TKG_TEST_CURATED_CORPUS_DIR` to a writable disposable directory and `TKG_TEST_FROZEN_ALERT_OUT` to a disposable file to export the actual SOC request bytes. For the TKG corpus selection set `AISOC_TKG_TEST_FROZEN_ALERT` and `AISOC_TKG_TEST_CURATED_CORPUS` to those exports. Then run `cargo test --locked -p utopia-server api::soc_runtime_tests::receipt_replay_materialization_binding_and_tenant_isolation -- --exact --nocapture` for each tier with `UTOPIA_MODEL_TEST_MODE=1`, `UTOPIA_TEST_REQUIRE_DB=1` and the disposable TKG DSN. Locally the Rust builder ran offline and the resulting test binary ran in the cached Python image.

| Selection | Result |
|---|---|
| SOC migration runner | PASS, 105 files applied |
| SOC API and qualification corpus | PASS, 81 tests |
| SOC Fusion, including the marked database integration | PASS, 211 tests |
| SOC Agents, runtime, claim validation and privacy | PASS, 254 tests |
| TKG Python contracts and identity | PASS, 71 tests and 32 subtests |
| Compose config with both network overlays and both private-CA overlays | PASS with synthetic runtime inputs. A deliberately non-loopback ingest listener was refused. |
| Rust full server | PASS, 634 tests. Two live external tests skipped. The initial unseeded run failed with 77 missing-schema errors and was superseded by the seeded run. |
| Real Rust admission corpus | PASS, independently for both tiers. The initial slow medium attempt with the host-mounted normalizer timed out. |
| CI templates | TKG template inspected and left intact. The SOC feature checkout tracks no root Actions workflow definitions. Remote workflows, full TKG workspace lint and Rust formatting were not run. |
| Local static validation | Python Ruff imports and syntax plus Git whitespace checks. The cached Rust builder had no rustfmt component. |
| External and deployment tests | SKIP the live OCR and public RSS tests. NOT RUN the real Server 55 stack, real Splunk, external model traffic and the large corpus. |

The SOC API test uses real PostgreSQL and Python Preview, with controlled HTTP only for worker fault cases. TKG corpus tests invoke the actual Rust handlers and document/graph processing against PostgreSQL. The model-selection and DLP tests use controlled providers and synthetic protected identities.

```sh
git diff --check
git -C "$TKG_CHECKOUT" diff --check
git diff --name-status
git ls-files --others --exclude-standard
git -C "$TKG_CHECKOUT" diff --name-status
```

## Exact change inventory

### Agentic_SOC

- Modified `TKG-SPRINT.md`
- Modified `services/agents/app/integrations/tkg/recon.py`
- Modified `services/agents/app/integrations/tkg/tools.py`
- Modified `services/agents/tests/test_privacy_packaging_contract.py`
- Modified `services/agents/tests/test_tkg_workspace_recon.py`
- Modified `services/api/app/services/tkg/projection.py`
- Modified `services/api/app/services/tkg/worker.py`
- Modified `services/api/tests/api/v1/test_tkg_outbox.py`
- Modified `services/fusion/app/models/alert.py`
- Modified `services/fusion/app/services/alert_sink.py`
- Modified `services/fusion/tests/test_alert_sink.py`
- Added `docs/deployment/SERVER55_TKG_QUALIFICATION.md`
- Added `scripts/qualify_tkg_compose.py`

### Soorin TKG

- Modified `crates/utopia-server/src/api/soc_runtime_tests.rs`
