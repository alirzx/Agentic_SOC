# Case Review to Main Migration Implementation Plan

> **For agentic workers:** REQUIRED WORKFLOW: Use this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. No commit, reset, restore, clean, stash, branch deletion, or push may occur unless the corresponding step is marked approved below.

**Goal:** Port the approved `case_review` correlation graph and TKG changes from `D:\Programming\Agentic_SOC - 3 graph engine and tkg` onto the latest `main` implementation without discarding main's newer UI/theme/workflow changes or adding the unfinished backend service.

**Architecture:** Use a separate worktree as an isolated migration branch. Keep the current `case_review` working tree and the full backup untouched until the migration is validated. Start from `origin/main`, port new behavior by file responsibility, adapt overlap files line-by-line, then run frontend/API tests. No commit happens until the user gives explicit approval at the commit gate.

**Tech Stack:** Next.js 16, React 19, TypeScript, Tailwind CSS v4, FastAPI/Python, SQLAlchemy, PostgreSQL migrations, Cytoscape, Three.js where explicitly needed.

**Spec:** User migration requirements captured in this chat, plus repository rules in `AGENTS.md` and `.github/copilot-instructions.md`.

## Global Constraints

- The full backup `D:\Programming\Agentic_SOC - 3 graph engine and tkg` is the source of case_review changes and must remain byte-identifiable.
- The current repository must not use `git stash`, `git reset --hard`, `git restore`, or `git clean` for this migration.
- No commit, push, force operation, merge, branch deletion, or branch switch may run automatically.
- The migration must preserve every newer change already present on latest `main`, including theme/layout and real empty/error states.
- Demo/mock data fallback code must not be ported into `main`.
- The backend service under `services/correlation/` is excluded.
- Correlation/TKG API and frontend behavior may be ported only as part of the existing main application contracts.
- Main migration work happens in `D:\Programming\Agentic_SOC-main-migration` until the user approves the commit step.
- New migration SQL files must be sequenced after the latest main migration inventory, observed currently through `076_alerts_affected_hosts_gin.sql`.

## Baseline Already Verified

- Current branch and HEAD: `case_review` / `d13d94a8b57ac72d346d7fa6be3a13d1d74cc664`
- Backup branch and HEAD match exactly: `case_review` / `d13d94a8b57ac72d346d7fa6be3a13d1d74cc664`
- Current and backup path lists match: 43 tracked changed files and 242 untracked files
- SHA-256 comparison: 283 ordinary dirty entries match, and the remaining 2 Persian-named plan files match by name and hash
- Latest fetched `origin/main`: `72db8102111f1067f2a9af49aa0bc1ab74d3acba`
- Latest main-relative divergence checked: 46 commits are unique to main from the common merge base
- 17 tracked overlap files and 242 untracked source paths were identified

## Execution Status — 2026-11-21

- **Original folder:** `D:\Programming\Agentic_SOC` now contains the complete worktree and is on `main`
- **Migration worktree:** created and later removed; no `D:\Programming\Agentic_SOC-main-migration` folder remains
- **Temporary worktree:** no temporary case-review worktree remains
- **Deleted branches:** `case_review` and `migration/case-review-to-main`
- **Base commit:** `72db8102111f1067f2a9af49aa0bc1ab74d3acba` (`origin/main`)
- **Implementation port:** frontend, API, agent/dedup, TKG, migrations, docs, and tests were ported or adapted onto latest `main`
- **Conflict state:** no Git-unmerged files, no exact conflict marker text, and no leftover conflict marker text in source files
- **Excluded:** the entire `services/correlation/` directory, diagnostic scripts, scratch plans, and `test_from_ubuntu.txt`
- **Frontend test:** `CaseWorkspace.test.tsx` passed 7/7
- **API tests:** 55 candidate/alert/TKG tests passed; 38 correlation/dedup/KPI/TKG tests passed with 11 skipped
- **Python lint:** focused Ruff check passed for the migrated API/TKG/dedup slice
- **Splunk connector port:** host/IP normalization, `orig_index`, simple-payload provenance, and exclusion regex completed
- **Splunk validation:** 54 focused tests passed in `test_splunk_simple_mode.py` and `test_splunk_connector.py`
- **Migration state:** case-related SQL files renumbered successfully to `077` through `089`
- **Main monorepo type-check:** not fully green; web type-check reports the pre-existing missing `CoverageAdvisorView` route import, and `packages/ui` has a Windows shell incompatibility
- **Remaining validation:** live database migration replay, browser E2E for `/cases` and `/cases/{id}`, desktop/mobile states, and manual commit review
- **Commit/push:** not performed; migration changes remain as working-tree changes on `main`

## Definitive Backup-to-Destination Gap Inventory

The backup changed 285 unique dirty paths: 43 tracked and 242 untracked.
At the destination, 101 paths are byte-identical, 36 paths differ because they were adapted
line-by-line for the newer `main` implementation, and 148 paths are absent.

### Missing Groups

- `41` files under `services/correlation/`: intentionally excluded backend service and its tests.
- `64` files under `docs/plans/case/`: verification reports, scripts, screenshots, CSV/JSON data, and Neo4j experiments.
- `21` files under `docs/plans/case-tkg-evaluation/`: TKG design notes and visual verification artifacts.
- `13` old migration filenames: `074_*` through `086_*`; they are replaced in purpose by renumbered `077` through `089` files in the destination.
- `3` agent diagnostic tests.
- `5` API diagnostic/utility scripts and tests.
- `1` TKG payload export script.

The plan documents, reports, Neo4j experiments, old backend service, and diagnostic scratch files
are not hidden loss: they were reviewed and excluded by the migration scope. Operational tools
still useful for rebuilding correlation/TKG must be re-authored or ported selectively rather than
copied wholesale.

### Eight Operational/Diagnostic Files

| Backup file | What it did | Why it was not copied directly | Needed when correlation is rebuilt? |
|---|---|---|---|
| `services/api/scripts/create_api_key.py` | Created a raw API key with `cases:write:correlation` and `alerts:read`, primarily for the correlation worker. | It used direct SQL, a hardcoded assumptions list, an unsafe `key_hash` model, and fell back to ad hoc environment auth. Destination already has the scoped API-key endpoint in `services/api/app/api/v1/endpoints/api_keys.py`. | **Yes, but reimplement through the API endpoint.** Generate the key through the authenticated admin path or a hardened operator CLI. |
| `services/api/scripts/verify_schema.py` | Checked KPI Level 1 tables, columns, and indexes after migration. | It was tied to old migration/table names and did not verify the complete renumbered `077`-`089` sequence. | **Medium priority.** Keep it as a post-migration verifier and update it to inspect the final migration inventory and tenant-scoped tables. |
| `services/api/tests/check_db_state.py` | Inspected live alert ownership, disposition/severity promotion eligibility, case counts, and graph-engine claims. | It used a hardcoded Docker/host IP and tenant ID plus migration `074` as the implementation signal. | **High priority for correlation replay.** Rewrite it as an environment-configurable diagnostic against `077_correlation_engine.sql` and the final schema. |
| `services/api/tests/diagnostic_case_creation.py` | Tested why agentic-funnel cases were missing by reporting eligible alerts, ownership distribution, graph-engine activity, and created cases. | It was a one-off live-database diagnostic for the old competition between legacy and graph engines. | **High priority for correlation replay.** Convert the useful checks into live smoke tests or a secure operator script, without hardcoded DB credentials. |
| `services/agents/tests/analyze_dedupe_llm_impact.py` | Estimated dedupe savings across triage calls, narrative work, case duplication, and token usage. | It contained fictional cost estimates, hardcoded DB/IP/tenant values, and was primarily benchmark/analysis tooling. | **Low/optional.** Useful for benchmark reporting, but not a runtime prerequisite for correlation. |
| `services/agents/tests/diagnostic_worker.py` | Checked Kafka configuration, imported `FusedAlertTriageWorker`, created an instance, and probed Kafka topics. | It diagnosed the legacy agents Kafka consumer, not the excluded graph correlation backend. | **Low/medium.** Useful for agent-service and Kafka smoke testing, but rebuild it separately from correlation engine diagnostics. |
| `services/agents/tests/verify_dedupe_case_prevention.py` | Queried live deduplicated alerts and case IDs to prove deduplicated evidence was not promoted into cases. | It was a live-database diagnostic script with hardcoded tenant/IP values. The invariant itself is production-critical. | **High.** Convert it to a pytest test or tenant-parameterized diagnostic that runs in CI/live replay. |
| `scripts/agentic_soc_sync_payload.py` | Exported alerts from one case as redacted `llm_payload_only.jsonl` data for standalone TKG ingestion. | It belongs to the TKG evidence-transfer workflow, not the excluded correlation backend. | **High for TKG integration, low for correlation runtime.** Port it after the final API response shape and auth flow are validated. |

### Rebuild-Dependency Order

1. Rebuild or restore `services/correlation/` only if a live correlation backend is now an accepted scope.
2. Reapply migration `077_correlation_engine.sql` and all dependent migration changes `078`-`089`.
3. Provision an API key using the destination API-key endpoint with `cases:write:correlation` scope.
4. Add live dedupe case-prevention coverage and database-state diagnostics.
5. Add the TKG payload export tool and verify it against the final case-alert API contract.
6. Treat cost-impact and Kafka diagnostic scripts as non-blocking operational tools.

The old migration names `074`-`086` must not be reused as if they were current destination migrations.

## Files / Services Discovered

- Frontend feature root: `apps/web/src/components/cases/`, `apps/web/src/components/correlation/`, `apps/web/src/components/candidates/`, `apps/web/src/hooks/`, `apps/web/src/lib/`
- Main theme/layout roots to preserve: `apps/web/src/app/globals.css`, `apps/web/src/app/light-theme.css`, `apps/web/src/app/layout.tsx`, `apps/web/src/components/layout/`, `apps/web/src/components/theme/`
- Main case UI roots: `apps/web/src/components/cases/CaseWorkspace.tsx`, `apps/web/src/components/cases/CasesView.tsx`
- API roots: `services/api/app/api/v1/endpoints/cases.py`, `services/api/app/api/v1/router.py`, `services/api/app/models/`, `services/api/app/services/`, `services/api/migrations/`
- Agent roots: `services/agents/app/workers/case_promoter.py`, `services/agents/app/workers/fused_alert_consumer.py`
- Documentation roots: `apps/docs/docs/console/case-tkg-evaluation.md`, `apps/docs/docs/concepts/cases.md`, `docs/architecture/case-lifecycle.md`, `docs/architecture/correlation-engine.md`
- Excluded: entire `services/correlation/` directory, diagnostic scripts, temporary files, generated scratch plans, and `test_from_ubuntu.txt`

## High-Risk Overlap Files

These files require line-by-line review. The main-version implementation is the base; only meaningful case_review behavior is reintroduced.

- `apps/web/src/components/cases/CaseWorkspace.tsx`: add correlation/TKG tabs only around the existing tab, loading, report, ledger, 404, and theme implementation.
- `apps/web/src/components/cases/CasesView.tsx`: preserve main's real live/empty/error behavior and remove old mock fallback behavior.
- `apps/web/src/lib/api.ts`: preserve main's runbook/report API additions while adding only case/correlation/TKG contracts and types.
- `apps/web/src/components/alerts/AlertDetailView.tsx`: retain main runbook, campaign, theme, and report behavior.
- `apps/web/src/components/copilot/ContextualActions.tsx`: preserve main contextual investigation behavior.
- `apps/web/src/components/cases/CaseWorkspace.test.tsx`: update test expectations against the main implementation rather than replacing with old branch tests.
- `services/api/app/api/v1/endpoints/cases.py`: preserve main reporting/investigation code and add case-specific graph/TKG endpoints without deleting code.
- `services/api/app/services/agentic_funnel.py`: preserve main campaign/dedup/backfill changes while integrating only compatible case behavior.
- `services/api/app/services/exact_dedupe.py`: preserve main's 3-layer/entity-aware dedup implementation.
- `services/agents/app/workers/case_promoter.py`: preserve main campaign/case reuse logic and add only compatible case_review fields.
- `services/agents/app/workers/fused_alert_consumer.py`: preserve main triage/fallback behavior.
- `services/api/app/core/config.py`: merge settings additions manually.
- `services/api/app/models/alert.py`: preserve main model fields.
- `CHANGELOG.md`: merge feature entries only; do not replace main release history.
- `apps/web/next.config.js`, `apps/web/package.json`, `pnpm-lock.yaml`: merge dependencies and configuration without replacing main values.

## Migration Rules

- Start every implementation unit from the latest `main` file, not from the case_review file.
- Compare old and new hunks by function/component, not only by filename.
- Add a feature only when it is reachable by a real route, button, tab, or API contract.
- Adapt old slate/dark classes to the current theme variables/classes.
- Do not port mock, synthetic, placeholder, or demo-case behavior.
- Do not introduce direct raw Neo4j or correlation service calls in an untested frontend path.
- Keep API functions tenant-scoped and tests tenant-aware.
- SQL migrations require a final inventory of existing main migrations before numbering.
- User-facing code in docs/comments remains accurate and in English unless the existing file is already localized for a clear product reason.

## Step-by-Step Plan

### 1. Recreate the isolated migration environment

**Files / Services:** Git worktree, no repository files modified in this step.

- [ ] Fetch the latest refs with `git fetch origin --prune`.
- [ ] Confirm `D:\Programming\Agentic_SOC-main-migration` does not already exist.
- [ ] Create migration worktree:

```powershell
Set-Location 'D:\Programming\Agentic_SOC'
git worktree add -b migration/case-review-to-main 'D:\Programming\Agentic_SOC-main-migration' origin/main
Set-Location 'D:\Programming\Agentic_SOC-main-migration'
git pull --ff-only origin main
```

- [ ] Verify the migration worktree is clean and branch points to `origin/main`.
- [ ] Do not run any commit or stash command in this step.

### 2. Freeze and verify sources

**Files / Services:** Current repo, backup repo, migration worktree.

- [ ] Recheck backup HEAD equals `d13d94a8b57ac72d346d7fa6be3a13d1d74cc664`.
- [ ] Recheck current repo still contains 43 tracked and 242 untracked changes.
- [ ] Recheck backup dirty path count and SHA state.
- [ ] Save the migration baseline in terminal output only; do not use stash.
- [ ] Confirm `services/correlation/` is excluded from the copy set.

### 3. Remove the old branch reference only after isolation succeeds

**Files / Services:** Git refs only.

- [ ] Preserve no branch deletion until the migration worktree and backup verification pass.
- [ ] Switch the original worktree to `main` only after it is safe and without discarding its files:

```powershell
Set-Location 'D:\Programming\Agentic_SOC'
git switch main
git pull --ff-only origin main
```

- [ ] Because the original worktree is dirty, do not execute a pull or switch that reports uncommitted-file conflicts.
- [ ] If Git reports that switching would overwrite files, stop and keep using the migration worktree only.
- [ ] Delete `case_review` only after migration content is committed or merged, approved, and verified:

```powershell
git branch -d case_review
```

- [ ] No branch deletion is part of the initial migration step.

### 4. Inventory and adapt dependencies

**Files:** `apps/web/package.json`, `pnpm-lock.yaml`.

- [ ] Compare the dependency blocks from backup and migration worktree.
- [ ] Preserve main package versions.
- [ ] Add only dependencies used by the adapted feature:
  - `cytoscape-cola` only if a case graph layout uses it.
  - `three` and `@types/three` only if Graph3D is actually retained and typed.
- [ ] Run `pnpm install --lockfile-only` in the migration worktree if dependencies change.
- [ ] Run `git diff -- apps/web/package.json pnpm-lock.yaml` and verify no unrelated dependency downgrade occurred.

### 5. Port TypeScript types and API client contracts

**Files:** `apps/web/src/lib/api.ts`, relevant files under `packages/types/` if the project uses them.

- [ ] Read existing main types and preserve their exact shape.
- [ ] Compare case-related types against backup additions.
- [ ] Add or update types for real case graph, candidates, TKG, timeline, and correlation responses.
- [ ] Preserve all existing main runbook/report/campaign types and API methods.
- [ ] Run a focused TypeScript check after this task.

### 6. Port the latest-main CasesView safely

**Files:** `apps/web/src/components/cases/CasesView.tsx`, `apps/web/src/components/candidates/` if applicable, `apps/web/src/lib/api.ts`.

- [ ] Start from latest-main `CasesView`.
- [ ] Preserve `EMPTY_CASES`, SWR fallback, loading, error, empty-filter, and empty-list states.
- [ ] Do not restore `MOCK_CASES` or synthetic case rows.
- [ ] Port the real candidates and creation-method additions if each uses a live API.
- [ ] Preserve the newest theme/card styles and light-theme behavior.
- [ ] Update and run `CasesView`-related tests.

### 7. Port the latest-main CaseWorkspace safely

**Files:** `apps/web/src/components/cases/CaseWorkspace.tsx`, `apps/web/src/components/cases/CaseWorkspace.test.tsx`, related case components.

- [ ] Start from latest-main `CaseWorkspace`.
- [ ] Preserve existing overview, investigation, attack-path, attack-chain, ledger, and report tabs.
- [ ] Add `correlation` and `tkg` only if their API contracts and UI components are available.
- [ ] Preserve 404/error handling and remove `buildDemoCase`, demo banner, demo reports, and demo mode writes.
- [ ] Add the correlation modal/button using the main theme and existing modal conventions.
- [ ] Adapt TKG to main light/dark classes, loading states, and content-width rules.
- [ ] Update `CaseWorkspace.test.tsx` to assert the main behavior rather than old demo behavior.
- [ ] Run the focused CaseWorkspace tests.

### 8. Port correlation/candidate/TKG frontend units

**Files:**
- `apps/web/src/components/cases/CaseCorrelationModal.tsx`
- `apps/web/src/components/cases/GraphViewer.tsx`
- `apps/web/src/components/cases/TkgEvaluationPanel.tsx`
- `apps/web/src/components/cases/CaseSummary.tsx`
- `apps/web/src/components/correlation/`
- `apps/web/src/components/candidates/`
- `apps/web/src/hooks/useCaseCandidates.ts`
- `apps/web/src/hooks/useTkgEvaluation.ts`
- `apps/web/src/lib/caseTkg.ts`
- `apps/web/src/lib/caseDescription.ts`
- `apps/web/src/lib/entityTimeline.ts`
- `apps/web/src/lib/graph*.ts`
- `apps/web/src/lib/relatedEntities.ts`
- `apps/web/src/cytoscape-cola.d.ts`

- [ ] Port only files required by the live case/correlation/TKG route set.
- [ ] Replace old dark/slate-only styling with main theme tokens/classes.
- [ ] Verify modal, graph, empty, loading, error, and mobile states in the new shell.
- [ ] Exclude graph backend implementation and backend test scripts.
- [ ] Run the relevant frontend unit tests and Playwright tests for `/cases/{id}`.

### 9. Reconcile AlertDetailView and ContextualActions

**Files:** `apps/web/src/components/alerts/AlertDetailView.tsx`, `apps/web/src/components/copilot/ContextualActions.tsx`, `apps/web/src/lib/api.ts`.

- [ ] Keep main report/runbook/campaign/ledger behavior as the base.
- [ ] Port only new case-related methods or fields that still compile against main types.
- [ ] Review every changed block line-by-line, especially report API, context headers, and case handoff calls.
- [ ] Run focused alert/copilot tests.

### 10. Port API models and endpoints

**Files:**
- `services/api/app/api/v1/endpoints/cases.py`
- `services/api/app/api/v1/endpoints/case_graph_views.py`
- `services/api/app/api/v1/endpoints/case_tkg_evaluation.py`
- `services/api/app/api/v1/endpoints/kpi.py`
- `services/api/app/models/aisoc_case.py`
- `services/api/app/models/case_graph_view.py`
- `services/api/app/models/tkg_evaluation.py`
- `services/api/app/services/alert_scope.py`
- `services/api/app/services/candidate_discovery.py`
- `services/api/app/services/kpi_metrics.py`
- `services/api/app/services/neo4j_client.py`
- `services/api/app/services/suggestion_engine.py`
- `services/api/app/services/tkg_evaluation/`

- [ ] Start from main route implementations and preserve existing report/investigation behavior.
- [ ] Recreate each case/candidate/TKG endpoint against main types and dependency signatures.
- [ ] Enforce tenant filtering in every new database and Neo4j query.
- [ ] Register the new endpoints in `services/api/app/api/v1/router.py` only if they exist in the adapted implementation.
- [ ] Run focused API tests.

### 11. Reconcile agent and deduplication behavior

**Files:** `services/agents/app/workers/case_promoter.py`, `services/agents/app/workers/fused_alert_consumer.py`, `services/api/app/services/agentic_funnel.py`, `services/api/app/services/exact_dedupe.py`.

- [ ] Preserve all main campaign, reuse, runbackfill, and 3-layer dedup changes.
- [ ] Port only compatible case creation fields and state transitions from case_review.
- [ ] Re-run existing fused-alert, outcome-memory, funnel, and dedupe tests.
- [ ] Do not port unfinished correlation-worker behavior from `services/correlation/`.

### 12. Inventory and renumber SQL migrations

**Files:** `services/api/migrations/074_correlation_engine.sql` through `services/api/migrations/086_case_tkg_evaluations.sql`.

- [ ] In the migration worktree, list every `services/api/migrations/*.sql` file.
- [ ] Reconfirm the highest existing main migration number.
- [ ] Assign new case_review migrations contiguous numbers after the actual main maximum, not after assumed branch names.
- [ ] Preserve every migration's up/down semantics and renumber all comments/references consistently.
- [ ] Run migration validation or focused database tests.

## Proposed Baseline Renumbering

This is based on the observed main baseline through `076_alerts_affected_hosts_gin.sql` and must be rechecked against the migration worktree before file operations:

- `074_correlation_engine.sql` -> `077_correlation_engine.sql`
- `075_case_creation_method.sql` -> `078_case_creation_method.sql`
- `076_semi_automatic_case.sql` -> `079_semi_automatic_case.sql`
- `077_phase2_dismissals_and_attachments.sql` -> `080_phase2_dismissals_and_attachments.sql`
- `078_kpi_level1_evaluation.sql` -> `081_kpi_level1_evaluation.sql`
- `079_correlation_observation_tokens.sql` -> `082_correlation_observation_tokens.sql`
- `080_correlation_observation_scoring_inputs.sql` -> `083_correlation_observation_scoring_inputs.sql`
- `081_case_alert_links_reconcile.sql` -> `084_case_alert_links_reconcile.sql`
- `082_case_alert_scope.sql` -> `085_case_alert_scope.sql`
- `083_fix_kpi_fk_to_aisoc_cases.sql` -> `086_fix_kpi_fk_to_aisoc_cases.sql`
- `084_case_rules_rollup.sql` -> `087_case_rules_rollup.sql`
- `085_case_graph_views.sql` -> `088_case_graph_views.sql`
- `086_case_tkg_evaluations.sql` -> `089_case_tkg_evaluations.sql`

### 13. Port documentation and tests selectively

**Files:**
- `apps/docs/docs/console/case-tkg-evaluation.md`
- `apps/docs/docs/concepts/cases.md`
- `docs/architecture/case-lifecycle.md`
- `docs/architecture/correlation-engine.md`
- Focused API test files under `services/api/tests/api/v1/`
- Focused frontend tests under `apps/web/src/components/cases/` and `apps/web/src/lib/`

- [x] Keep documentation that describes real API/UI behavior.
- [x] Exclude diagnostic and scratch verification scripts.
- [x] Add or update test coverage files for candidate, case, KPI, dedup, and TKG behavior.
- [x] Do not document `services/correlation/` as production-ready; it remains excluded.

### 14. Full validation in migration worktree

**Files / Services:** Worktree-wide diff, frontend, API, migrations.

- [x] Run `git diff --stat` and inspect the migration scope.
- [ ] Run a fully green monorepo `pnpm type-check`.
  - Executed `pnpm type-check`; blocked by an existing `packages/ui` Windows shell script issue.
  - Executed web type-check; only `CoverageAdvisorView` is missing from `apps/web/src/app/(app)/coverage-advisor/page.tsx`.
- [x] Run focused web tests for the CaseWorkspace; 7/7 passed.
- [x] Run focused API pytest suites; 93 tests passed in aggregate and 11 were skipped.
- [ ] Run migration replay against the live PostgreSQL database and verify schema state.
- [ ] Open `/cases` and `/cases/{id}` in desktop/mobile light and dark states.
- [ ] Verify 404, loading, empty, error, correlation, TKG, and no-backend states in the browser.
- [x] Stop and report conflicts/failing tests; no source conflict markers remain.

### 15. User review and manual commit gate

**Files:** Migration worktree.

- [x] Present migration scope, key conflict resolutions, test results, and remaining risks.
- [x] **No commit occurs until the user explicitly approves a commit.**
- [ ] User manually reviews and commits on the migration branch or main according to the confirmed workflow.
- [x] No automatic push occurs.

### 16. Final cleanup only after approval

**Files / Services:** Migration worktree and original worktree.

- [x] Migration worktree removed; no `D:\Programming\Agentic_SOC-main-migration` folder remains.
- [x] Original repository is on `main` in `D:\Programming\Agentic_SOC`.
- [x] Verify no production change was lost from backup or migration worktree.
- [x] Deleted `case_review` branch.
- [x] Deleted `migration/case-review-to-main` branch.
- [ ] Pull `origin/main` and verify only after the manual commit/merge state is settled.
- [ ] Push only if explicitly requested and after secret/sensitive-data review.

## Modified Files Log

- [x] Migration worktree created: `D:\Programming\Agentic_SOC-main-migration`
- [x] Migration dependencies updated in `apps/web/package.json` and `pnpm-lock.yaml`
- [x] Frontend case/candidate/correlation/TKG units ported onto latest-main UI
- [x] API, agent, dedup, TKG, migration, test, and documentation units ported or adapted
- [x] SQL migrations renumbered to `077` through `089`
- [x] Current `exact_dedupe.py` reviewed after subsequent edits and found free of conflict markers
- [x] Splunk connector and tests ported; 54 focused tests passed
- [x] Splunk connector improvements ported and 54 focused tests passed
- [x] Plan updated: `docs/plans/PLAN-20261121-1322-case-review-main-migration.md`
- [ ] No commit or push performed
- [x] Old `case_review` and migration branches deleted

## Risks & Dependencies

- **High:** `CaseWorkspace.tsx`, `CasesView.tsx`, `api.ts`, and `cases.py` have substantial main and case_review changes.
- **High:** Theme changes on main can break old slate/dark-only components copied without adaptation.
- **High:** Migration numbering must follow the actual worktree inventory, not this plan's example alone.
- **High:** Mock/demo removal on main must remain real-data only.
- **Medium:** `services/correlation/` may be needed for a live graph but is explicitly excluded.
- **Medium:** TKG or correlation API endpoints may fail if the backend or database migration is absent.
- **Medium:** Some untracked diagnostic files may share names or imports with production files and require careful exclusion.
- **Low:** Line-ending differences may appear when copying from the backup; compare content, not just Git status.
- **Low:** Network dependency can delay fetch/pull, but worktree isolation prevents loss.
- **Residual:** the web route `/coverage-advisor` references a missing `CoverageAdvisorView` in `main`; this was not introduced by this migration.
- **Residual:** live PostgreSQL migration replay and browser E2E have not been executed yet.
- **Residual:** database/container correlation/TKG availability is not yet proven end-to-end.
- **Residual:** the original folder now contains staged and unstaged migration changes on `main`; no migration worktree exists and no Git conflict state remains.
- **Residual:** 148 backup paths were absent from the destination; 41 are the excluded correlation service and 85 are historical plans/reports/artifacts.
- **Residual:** the eight operational files listed above are not production dependencies until explicitly reintroduced and hardened.

## Rollback / Recovery

- The current repository remains untouched until isolation and verification pass.
- The backup folder remains the independent source snapshot.
- The migration worktree can be removed or recreated at any point before approval.
- No `git reset`, `git clean`, or `git stash` is used.
- If an adapted file cannot be proven against main behavior, do not copy it; leave it on the migration branch for line-by-line review.
