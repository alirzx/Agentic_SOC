# Sprint 4 final qualification — checkpoint review

Status: **source release candidate. CI, merge, and Server 55 qualification remain open.**
Reviewed SOC checkpoint `5b745039d7e15fb8909d5a6345f014065a5756b3`
and TKG checkpoint `50f323e7fd56091e20ac311ba017d662acb464d4`.
This record replaces the missing qualification document linked by the Server 55 runbook.
The checkpoint evidence is separated from the release verification below.

## Existing analyst surfaces

| Question | Source finding at `b2266d61` |
|---|---|
| Case TKG Tab | `CaseWorkspace` mounts `TkgEvaluationPanel`. It renders an independent verdict, graph attribution, counts and optional explicit sync actions. |
| API reads and writes | `caseTkgApi` calls authorized Case Evaluation health, latest, history and run status plus explicit evaluate and sync actions. All go through the SOC API. |
| Persistence | Case Evaluation persists its own score and attribution. Active progress is polled from the Evaluation run. Investigation results have separate Agents run state and a PostgreSQL ledger. |
| Delivery and receipt | Evaluation can show its own submission and materialization observations. The tab has no live read model for the transactional outbox. |
| Recon history | The historical bundle is present inside the Investigator and cached case result but does not have a dedicated bounded, durable analyst projection. |
| Tool executions | The existing Ledger shows general agent steps. Internal TKG calls and outcomes are absent from the Case TKG panel. |
| Historical graph | Case Graph and Attack Chain visualize current case data. Neither plots the structured historical Recon evidence. |
| Temporal provenance | Evaluation shows alert dates. Historical valid time and record/knowledge time are not presented together. |
| Evaluation and Investigation | The tab shows Evaluation alone. Opening the tab does not itself start an investigation. |
| Workspace behavior | Evaluation endpoints check explicit workspace and Case permissions. Older SWR keys lack a workspace dimension and the in-flight Evaluation loop does not stop on unmount. |

## Evidence and release gates

| Gate | Status | Evidence / remaining action |
|---|---|---|
| Organization main integration | Source reviewed | SOC merge d9e1781d includes e6bf4cf0. |
| Durable producer and receipt reconciler | Implemented; regression pending | Migration 094/095, frozen requests, fenced updates, separate status PAT and DB login. |
| Multi-root stateful Recon | Implemented; regression pending | Signed scope, bounded seeds, five read tools, working memory, protected planner and final assessment. |
| Search wire identity | Adapter correction included; regression pending | TKG ChunkView uses id; SOC normalizes the chunk identity and rejects contradictory aliases. Search does not confer graph authority. |
| Budgets and coverage | Implemented; qualification pending | Byte-based conservative packing and admission estimates are not provider token measurements. Record stop reason, omitted evidence and actual usage. |
| Privacy | Earlier baseline passed; new multi-turn run pending | Keep DLP mandatory. Confirm provider-bound redaction, successful decoding, isolation, failure handling and context lifetime for this revision. |
| Static Compose matrix | Passed as reported by Codex | Actual Server 55 overrides and credential mounts not checked by that run. |
| Full corpus materialization | OPEN | Earlier 64/640 admission tests materialized six samples each. Interrupted medium qualification has no completion record. |
| Real model evaluation / signed full pipeline | OPEN | Prove Connector to Kafka/Fusion, outbox, bound receipt, Recon tools and report with synthetic data. |
| Image and deployment qualification | OPEN | Verify migrations, image revision/digest, model caches, existing volume identity, role grants, TLS and resource headroom before cutover. |
| Final CI / merge | OPEN | Run targeted regression on the reviewed heads. Do not claim production readiness from the existence of tests. |

## Configuration and deployment notes

- Keep TKG and Recon flags disabled until their specific prerequisites pass.
- DeepSeek-V4-Flash is not in the current Recon model price table. Set both reviewed
  `AISOC_TKG_RECON_UNKNOWN_INPUT_USD_PER_1K` and
  `AISOC_TKG_RECON_UNKNOWN_OUTPUT_USD_PER_1K` values for the actual deployment
  tariff; do not use an invented price or zero. The unknown-price admission guard
  intentionally stops protected Historical Recon.
- Use the existing SOC security override as the final Compose input. Preserve DLP
  CA, credentials and privacy network. Use distinct reader, ingest and receipt
  credentials and separate database logins for submission and polling.
- The TKG hardened production interface validates immutable registry digests,
  existing volume identity and a unified CPU model service. A historical local
  build tag is not a registry digest. Do not substitute new empty volumes or
  recreate databases to satisfy a static preflight.
- The new TKG script is an inspection/preflight interface, not a build or rollout
  command. Follow the reviewed release procedure for image production and cutover.
- Metrics exported by the standalone workers are local text files; arrange
  approved collection before claiming dashboard coverage.
- Verify receipt authorization with Viewer membership and explicit KB scope,
  current RLS/GRANTs and credential revocation. Do not grant admin to Recon.
- Keep full materialization, production model evaluation and heavy image builds
  off the constrained developer machine. Use an approved CI or server window.

## Sequence

1. Lightweight targeted regression and source review on both feature branches.
2. Verify actual server inventory, approved immutable images, backups and recovery
   compatibility; validate Compose and migration prerequisites.
3. Qualify TKG first, then SOC with integration disabled, retaining previous images.
4. Enable synthetic-workspace submission and polling; prove bound and replay.
5. Enable preflight Recon, then bounded planner, then Deep Case by explicit approval.
6. Record evidence of full pipeline, privacy, model quality and resource behavior
   before marking the release accepted.

## Release changes

- The authenticated Case TKG tab now displays **Knowledge coverage**, **Historical investigation**, and the independent **Knowledge evaluation**. Coverage reads the workspace outbox without calling TKG and distinguishes an accepted receipt from bound graph materialization. It reports scheduled submission retry and recoverable receipt processing separately.
- The Investigator writes a bounded projection to its existing Recon ledger event, including the signed resource type and UUID. The API checks explicit workspace membership, resource read permission, the tenant-owned resource, the tenant-owned run, and the recorded scope. In-progress or older runs can have no historical projection. The legacy Case polling response omits the internal TKG bundle and checks that the run belongs to the requested Case.
- The Case tab, Ledger, Alert Detail, Investigation Rail and Report use the scoped read model. They show recorded tool outcomes, counts, final assessment and historical status separately, a bounded set of directed relationships with accessible fact details, valid and recorded time, chunk provenance, and analyst-review claims. Search hits remain in their own section. Polling for a selected running investigation has a five-minute client bound. Evaluation is explicit and its client polling stops on workspace or route change.
- SOC configuration validation rejects public binding of Ingest, Correlation, Fusion and Connectors and checks or preserves the existing DLP policy profile, TLS CA, signing and tracing defaults. TKG's production preflight checks both existing database and application data mounts. Neither canonical entry point deploys a server.
- `AISOC_TKG_AUTO_INGEST_ENABLED` controls submission. The database trigger enqueues new qualifying alerts while the workspace binding's `auto_ingest` remains enabled. No speculative revision synchronization was added.

## Release verification

Starting feature heads were SOC `b2266d61936670906d987f64d2ee899648301b6b` and TKG `50f323e7fd56091e20ac311ba017d662acb464d4`. Organization main was SOC `e6bf4cf0c3e1b257ab9dc6ffbb6d6d89a467511f` and TKG `75119697d7fdd9f877c481456ba6dffc375df52a`. Both were already ancestors of their feature branches. The read-only DLP checkout stayed at `226af03eda940a624b33e2ab722536fe9b90d9f5`.

The previous checkpoint reported 59 SOC passes across Recon, privacy and Compose. Earlier disposable runs recorded 634 Rust tests passed with two ignored and 56 of 56 eligible small-corpus records bound and resolved. Those are historical results on earlier code. There is no medium-corpus completion record and no complete service-level E2E result.

| Release selection | Result |
|---|---|
| API `pytest -q tests/api/v1/test_tkg_knowledge.py tests/api/v1/test_tkg_polishing.py tests/test_investigation_run_summary.py tests/test_cases_tenant_isolation.py` | 33 passed. Uses mocked SQL results and transport. The first run surfaced an outdated Case-list result fixture, which was corrected while preserving tenant assertions. |
| Agents `pytest -q tests/test_tkg_workspace_recon.py tests/test_alert_investigation_tenant_boundary.py tests/test_privacy_packaging_contract.py tests/test_fused_alert_worker.py::test_kafka_poison_commit_requires_durable_dlq tests/test_fused_alert_worker.py::test_kafka_supervisor_rejoins_after_commit_failure tests/test_llm_ops.py::test_committed_prompt_lock_matches_registry` | 30 passed. Synthetic and mocked. No live Kafka or LLM. |
| TKG `PYTHONPATH=. pytest -q soorin/tests/contracts/test_production_compose_preflight.py soorin/tests/contracts/test_native_profile.py` | 3 passed. Docker inventory is mocked. |
| SOC `SOORIN_TKG_CHECKOUT=<adjacent checkout> pytest -q tests/test_server55_production_arguments.py` | 2 passed. Static Compose and mocked deployment-argument checks. |
| API `pytest -q tests/api/v1/test_tkg_outbox.py::{test_quarantine_reasons,test_frozen_record_against_real_tkg_adapter,test_normalizer_overload_is_distinct_from_conflict}` | 5 passed, including the parameterized normalizer categories. The TKG Python adapter ran against synthetic frozen bytes. |
| SOC `vitest run TkgHistoryView.test.tsx --maxWorkers=1 --no-file-parallelism` | 3 passed in a temporary directory using the already installed adjacent Vitest and React packages. The SOC workspace's full dependencies were unavailable for local semantic type-check and Case/Rail browser integration. |
| Targeted Agents privacy regression | 4 passed. Synthetic remote multi-turn, failed encoding, expired context and unknown-alias fixtures. |

Python syntax, shell syntax, prompt registry, OpenAPI JSON and TypeScript transpile/syntax checks passed. The TypeScript check parsed 12 files. Full semantic checking is assigned to the SOC release workflow.

CI must qualify the final Rust build and receipt authorization, plus the SOC API and full workspace TypeScript checks. No new local Docker images, containers, database migrations, Rust builds, model calls or sizeable corpus jobs were run for this final release task. No screenshots or browser acceptance were performed.

The organization TKG candidate is under review. Its first CI run identified Rust formatting drift and a preflight test that imported pytest in a unittest-only job. The changes were revised without compiling Rust locally. Recheck the latest CI run and normal review requirements before merging. [TKG PR #1](https://github.com/SoorinSecurity/Soorin_Bidirectional_Temporal_Knowledge_Graph/pull/1)

## Traceability

| ID | Disposition |
|---|---|
| T01 | Source verified. Organization main is already included in both feature histories. |
| T02 | Lightweight verified. Mocked acknowledgment ordering and Kafka rejoin passed. Live pipeline pending. |
| T03 | Lightweight verified for tenant checks. Correlation case formation in the complete service pipeline is deferred. |
| T04 | Lightweight verified. Bounded single-pass receipt waves are covered by mocks. |
| T05 | Implemented. Dedicated DB role, status PAT and real scope/revocation qualification remain required. |
| T06 | Lightweight verified. Synthetic acknowledgment, overflow and overload cases passed. |
| T07 | Lightweight verified. Recoverable receipt state remains pending. |
| T08 | Implemented. Live database restart and lease recovery are deferred. |
| T09 | Lightweight verified. Signed case scopes and multiple roots covered. |
| T10 | Lightweight verified. Seed and candidate authority stay in the session. |
| T11 | Lightweight verified. Synthetic nonempty Search reaches the protected planner and raw text is excluded from the ledger projection. |
| T12 | Lightweight verified. Exact current chunk and fact linkage gates the pivot. |
| T13 | Lightweight verified. Objectives and observations remain within the run. |
| T14 | Lightweight verified. Deep Case can complete 12 mocked model turns including assessment. |
| T15 | Lightweight verified. Profile limits and independent MCP transport accounting preserved. |
| T16 | Lightweight verified. Separate planner output budget and final reservation. |
| T17 | Lightweight verified for configured limits. Real provider and gateway timeouts are deferred. |
| T18 | Lightweight verified. Essential metadata and serialized syntax retained within conservative packing. |
| T19 | Lightweight verified. Structured actions and schema checks remain in place. |
| T20 | Lightweight verified. Prompt registry lock is current. |
| T21 | Lightweight verified. Controlled canonical query repetitions and depth gates remain. |
| T22 | Lightweight verified. Bounded planner recovery and assessment failure handling. |
| T23 | Lightweight verified. Stop reason is captured before assessment. |
| T24 | Lightweight verified. Examined, resolved and pending roots are observable. |
| T25 | Lightweight verified for structural eligibility. Semantic claim accuracy requires model-backed review. |
| T26 | Lightweight verified by synthetic protected multi-turn paths. Existing DLP deployment remains unchanged. |
| T27 | Source and prior mocked regression reviewed. Server-specific context TTL and aliases are deferred. |
| T28 | Lightweight verified for the new ledger projection. Raw tool payloads, prompts and Search text are excluded from it. |
| T29 | Implemented. Production correlation of worker and Recon traces is deferred. |
| T30 | Implemented. Worker metrics exports exist; actual collection and sustained pending ages remain to be verified. |
| T31 | Deferred to Server 55. Neighbors and Timeline can read more storage facts than their output limits. |
| T32 | Deferred. Earlier small tier bound 56 records; the 632-record medium run has no completion record. |
| T33 | Deferred. No externally billed provider call occurred. |
| T34 | Deferred. No complete new local or server service pipeline was executed. |
| T35 | Lightweight verified. Static cross-stack matrix with synthetic values passed. |
| T36 | Lightweight verified for packaging source and prompt lock. Build and image inspection are pending. |
| T37 | Source reviewed. Native TKG revisions remain; SOC sends immutable first alert rows. |
| T38 | Implemented in both READMEs and linked integration, release and operator documents. |
| T39 | Partial. Targeted local suites passed. Final CI, semantic frontend type-check and Rust qualification remain separate gates. |
| T40 | Runbook prepared. No Server 55 operation was executed. |

| Deployment ID | Disposition |
|---|---|
| D01, D02 | Canonical SOC interface and ordered TKG overlays passed static configuration. |
| D03, D04 | Correlation is in the build and rollback inventory. Both TKG workers reuse the API image. Real build deferred. |
| D05, D06 | Hardened unified TKG interface verified statically. Experimental isolated topology remains outside it. |
| D07, D11 | Existing volume names and role/migration checks documented. Preflight refuses mismatched DB or app data. Live cutover and restoration are deferred. |
| D08, D09 | Configuration propagation, independent DLP networking, and separate SOC trust mounts passed static validation. |
| D10, D12 | Deployment arguments, static Compose and mocked volume checks passed. Canonical operator documents updated. |

## Deferred operator acceptance

Use the actual reviewed and merged revisions after release gates pass. First inventory existing projects, mounted database and app volumes, private networks, approved model instances, certificates, roles, image digests and system headroom. Verify tested backup and rollback. Qualify and cut over the new TKG app first, preserving the known model caches and roles. Build SOC API, Agents, Web, Fusion, Connectors, Realtime, Ingest and Correlation. Both TKG workers reuse the qualified API image. Use the existing DLP deployment and verify protected encoding/decoding and fail-closed behavior before enabling history. Verify a bounded synthetic connector delivery through Kafka and Fusion, bound receipt, authorized Alert and multi-root Case run, actual Case TKG tab behavior and workspace isolation. Then qualify Standard Recon, explicitly opt in to Deep Case and measure the protected live-model evidence path. Run complete corpus and high-degree graph benchmarks only after the small canary passes and the operator confirms resource headroom. [SOC operator procedure](SERVER55_TKG_QUALIFICATION.md#operator-preflight) · [SOC build interface](SERVER55_SOC_BUILD.md)
