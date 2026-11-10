# Runbook — progress log

Tracks implementation of the original `PLAN-20261027-1501-runbook-page.md` and its
successors (`PLAN-20261028-1200-runbook-professional.md`, `PLAN-20261028-1710-runbook-restructure.md`,
`PLAN-20261029-1026-runbook-alignment.md`). Those plan documents were consolidated as the
design settled and are no longer in the tree; this log is the durable record, kept so work
can resume after a crash. Plan documents are never edited in place (per repo preference).

---

## Phase 0 — Governance ✅ COMPLETE (2026-10-27)

| # | Task | Status | Evidence |
|---|---|---|---|
| 0.0 | `AISOC_RUNBOOK_ENABLED` flag + `require_runbook_enabled` dependency | ✅ | `app/core/config.py`, `app/api/v1/deps.py`; 4 tests |
| 0.1 | migration `062_runbook.sql` | ✅ | applied to dev DB (73 migrations); trigger/constraints verified live |
| 0.2 | Action catalog | ✅ | `app/services/runbook/action_catalog.py` — 19 actions |
| 0.3 | Four contracts | ✅ | `app/services/runbook/contracts.py` |
| 0.4 | Three-layer gate | ✅ | `app/services/runbook/gate.py` |
| 0.5 | Tests | ✅ | `tests/test_runbook_gate.py` — 34 tests, all passing |

### Design changes vs. the written plan (discovered during implementation)

1. **No new `action_definitions` / `tenant_action_overrides` tables.**
   `aisoc_autonomy_thresholds` (migrations 020 + 021) already *is* the tenant
   override layer, already served by `GET/PUT/DELETE /api/v1/autonomy-policy`
   and already surfaced in the admin UI. Migration 062 extends it with
   `enabled` (TenantActionOptIn) and `autonomy_level` (L0–L4 ceiling) instead of
   building a second place for operators to disagree with themselves. The four
   contracts are code-only in v1 — a contract is a property of the code that
   honours it.

2. **The catalog is now the single source for the API service.**
   `autonomy_policy.py` used to carry its own copy of the 19 defaults and blast
   radii (a third copy, next to `guardrails.py`). It now projects them from
   `action_catalog.py`, and `test_catalog_matches_the_agents_runtime_thresholds`
   parses `services/agents/app/policy/guardrails.py` with `ast` to catch drift —
   the drift test its docstring claimed existed but which did not.

3. **`runbook_events` does not duplicate `investigation_events`.**
   `investigation_events` (migration 008) is run-scoped (`run_id NOT NULL`, FK
   to `investigation_runs`) and cannot hold non-agent steps: connector query
   mode, analyst disposition, funnel transitions, ITSM pushes. `runbook_events`
   is subject-scoped and carries a nullable `run_id` so an "Investigation run"
   row points at the detailed ledger rather than copying its steps.

### Verified

- `pytest tests/test_runbook_gate.py` → **34 passed**
- `pytest tests/test_security_defaults.py tests/test_demo_mode.py tests/test_airgap.py tests/test_runbook_gate.py` → **102 passed**
- `ruff check` clean on every touched file
- `app.openapi()` builds; `/api/v1/autonomy-policy` live on :8888 returns the same
  19 actions with the same thresholds and blast radii as before the refactor
- Live DB probes on `runbook_events`: UPDATE blocked by trigger, DELETE blocked
  by trigger, duplicate `(tenant, subject, seq)` rejected, invalid
  `subject_type` rejected, RLS enabled + forced

### Known pre-existing failures (NOT from this work)

Full `services/api` suite: **79 failed, 2104 passed, 8 errors**. The same 14
files fail identically on a clean `HEAD` worktree (79 failed, 8 errors), so the
Runbook work introduced no regressions. Cause clusters: `test_lake_sql.py`
(sqlglot behaviour), `test_plugin_manager.py` (Windows symlink permissions),
`test_alerts_detail_envelope.py` (asserts the pre-061 field set — migration 061
added `llm_payload`), digest/PDF tests, and DB-dependent isolation tests.

---

## Phase 1 — Execution ledger ✅ COMPLETE (2026-10-28)

| # | Task | Status | Evidence |
|---|---|---|---|
| 1.1 | `record()` idempotent + `seq` allocation + sanitize | ✅ | `app/services/runbook/recorder.py` |
| 1.2 | Tests: append-only + seq + tenant isolation | ✅ | `tests/test_runbook_events.py` (integration-gated) |
| 1.3 | Splunk: `query_mode` / `pipeline_max_notables` / `enable_rule_enrichment` schema | ✅ | `connectors/splunk.py` |
| 1.4 | `_preflight_count()` + mode selection + fallback | ✅ | `connectors/splunk.py` |
| 1.5 | `_build_llm_payload()` + `_meta.caveats` | ✅ | `connectors/splunk.py` |
| 1.6 | `runbook_provenance` in `raw_event` | ✅ | `connectors/splunk.py::normalize` |
| 1.7 | Tests: threshold / fallback / payload fidelity | ✅ | `connectors/tests/test_splunk_simple_mode.py` |
| 1.8 | Provenance materialisation → `runbook_events` (lazy, narrative pattern) | ✅ | `app/services/runbook/materialize.py` |
| 1.9 | Emission at chokepoints (§3.9) | ✅ | `app/services/runbook/emitters.py`; wired in `alerts.py`, `inbox_itsm.py`, `agentic_funnel.py` |
| 1.10 | Tests: emission per chokepoint | ✅ | `tests/test_runbook_emission.py` |

---

## Phase 2 — API + page ✅ COMPLETE (2026-10-28)

| # | Task | Status | Evidence |
|---|---|---|---|
| 2.1 | `GET /runbook/{subject_type}/{subject_id}` endpoint | ✅ | `app/api/v1/endpoints/runbook.py` — uses `CurrentUser` auth (not X-Tenant-Id header) |
| 2.2 | Router mounted in `api.py` | ✅ | `app/api/v1/router.py` line 191 |
| 2.3 | `runbook.api.ts` + types | ✅ | `apps/web/src/lib/runbook.api.ts` — aligned to real backend shape; `RunbookEnvelope`/`RunbookStep` re-exported from `runbook.types.ts` |
| 2.4 | `RunbookPage` component + `internal.tsx` sub-components | ✅ | `apps/web/src/components/runbook/RunbookPage.tsx`, `internal.tsx` |
| 2.5 | Panel embedded in Alert detail (Summary view) | ✅ | `AlertDetailView.tsx` — `runbook` tab renders `RunbookPage` |
| 2.6 | Tab `timeline` → `runbook`; hardcoded records removed; ledger rendered | ✅ | `AlertDetailView.tsx` — tab array updated, section replaced with `<RunbookPage>` |
| 2.7 | `/runbook` listing page | ✅ | `apps/web/src/app/(app)/runbook/page.tsx` |
| 2.8 | Sidebar nav entry | ✅ | `Sidebar.tsx` — "Runbook" in Automation section |

### Design changes vs. plan

1. **`runbook.py` uses `CurrentUser` not `X-Tenant-Id` header.** The previous iteration used `X-Tenant-Id` header which was inconsistent with the rest of the API and required the frontend to know the tenant UUID. Switched to `require_permission("alerts:read")` + `CurrentUser` dependency (same as all other protected endpoints). Frontend calls are then plain session-cookie requests — no tenant header plumbing needed.

2. **`action_name` field stays snake_case.** `runbook.types.ts` previously had `actionName` (camelCase) but the Pydantic model serialises as `action_name`. Fixed to snake_case throughout frontend types and `internal.tsx`.

3. **`RunbookNav` in TopBar route labels instead of standalone header component.** The nav component is available in the runbook section via the `/runbook` page; the TopBar receives a route label so the title bar reads "Runbook" correctly.

---

## Phase 3 — Automation rules + Splunk enrichment ✅ COMPLETE (2026-10-28)

| # | Task | Status | Evidence |
|---|---|---|---|
| 3.1 | `automation_rules` + `runbook_templates` migrations | ✅ | `services/api/migrations/063_automation_rules.sql` |
| 3.2 | Safe condition evaluator (`evaluate_all` / allowlist / no `eval`) | ✅ | `services/api/app/services/runbook/condition_eval.py` |
| 3.3 | Rule executor + policy gate + ledger emission | ✅ | `services/api/app/services/runbook/rule_executor.py` |
| 3.4 | CRUD endpoints for automation rules + templates | ✅ | `services/api/app/api/v1/endpoints/runbook.py` |
| 3.5 | `alert.created` and `alert.updated` trigger wiring | ✅ | `services/api/app/api/v1/endpoints/alerts.py` |
| 3.6 | Runbook page tabs: Ledger / Automation Rules / Visual Editor | ✅ → **superseded** | `apps/web/src/app/(app)/runbook/page.tsx` — the Visual Editor tab was removed in Phase 5 (scope reset, PLAN-20261028-1710) |
| 3.7 | Automation Rules UI + condition builder | ✅ | `apps/web/src/components/runbook/AutomationRulesView.tsx` |
| 3.8 | Visual template editor with `@xyflow/react` canvas | ❌ **REMOVED** | `RunbookEditorView.tsx` deleted; `runbook_templates` dropped (migration 065). The editor was out of scope (PLAN-20261028-1710) and had no route, no API and no data. |
| 3.9 | Splunk simple-mode schema + default custom SPL | ✅ | `services/connectors/app/connectors/splunk.py` |
| 3.10 | REST rule lookup + macro enrichment | ✅ | `services/api/app/services/splunk_enrichment.py` |
| 3.11 | `llm_payload` builder fallback from alert fields | ✅ | `services/api/app/services/splunk_enrichment.py` |
| 3.12 | `POST /runbook/alerts/{alert_id}/enrich-payload` API | ✅ | `services/api/app/api/v1/endpoints/runbook.py` |
| 3.13 | Alert detail button to build missing payload | ✅ | `apps/web/src/components/alerts/AlertDetailView.tsx` |
| 3.14 | UI auto-fill for `query_mode=simple` and mode badge | ✅ | `apps/web/src/components/connectors/AddConnectorModal.tsx` |

### Scope changes vs. the original plan

1. **Automation rules are now part of the shipped v1 scope.** The repo already had a governed-action ledger and alert pipeline, so once the shared gate + recorder existed, the rule engine and UI were a direct extension rather than a future phase.
2. **Splunk enrichment is intentionally code-first fallback.** This matches the reality of high-volume notable indexes: when a simple query is used, the alert still receives a valid `llm_payload`, but it is built from the alert row when Splunk REST metadata is unavailable or the query is too cheap for the full pipeline.
3. **The Runbook page is no longer a read-only ledger only.** The UI now includes rule management and template editing, which is the operationally useful surface for SOC teams.

---

## Phase 4 — Docs + gates ⬜ PARTIAL

Runbook docs now exist (`apps/docs/docs/console/runbook.md`,
`docs/operations/runbook.md`). Release-readiness items in plan §4 remain open.

---

## Phase 5 — Alignment with the runbook definition ✅ COMPLETE (2026-10-29)

Plan: [PLAN-20261029-1026-runbook-alignment.md](PLAN-20261029-1026-runbook-alignment.md).

| # | Task | Status | Evidence |
|---|---|---|---|
| 5.1 | `runbook_tasks.signature` + model column | ✅ | `migrations/065_runbook_alignment.sql`, `models/runbook_task.py` |
| 5.2 | Triage worker carries the evidence fingerprint into the task | ✅ | `agents/.../ledger.py::create_task_for_needs_review(signature=…)`, `fused_alert_consumer.py::_record(signature=…)` |
| 5.3 | Internal feedback endpoint (HMAC tenant auth) | ✅ | `services/agents/app/api/outcomes.py` (`POST /api/v1/outcomes/feedback`) |
| 5.4 | API forwards feedback instead of logging a promise | ✅ | `services/api/app/services/agents_client.py`; `runbook.py::complete_runbook_task` |
| 5.5 | Action Plan scoped to the selected subject | ✅ | `runbook.py::list_runbook_tasks(alert_id, case_id)` |
| 5.6 | **Gate call repaired** — `evaluate()` + confidence normalisation | ✅ | `rule_executor.py`; regression test in `test_runbook_automation.py` |
| 5.7 | Approval-gate tasks created from blocked decisions (idempotent) | ✅ | `services/runbook/tasks.py`, partial unique index in 065 |
| 5.8 | Triage evidence visible in the ledger (read-only union) | ✅ | `read.py::_TRIAGE_READ` + `_triage_policy` |
| 5.9 | Procedure surface (static, code-defined) | ✅ | `services/runbook/procedure.py`, `ProcedureStepper` in `internal.tsx` |
| 5.10 | Per-task-type analyst actions | ✅ | `ActionPlanView.tsx` (manual_review / approval_gate / mssp read-only) |
| 5.11 | Action Plan dark theme + inline errors (no `alert()`) | ✅ | `ActionPlanView.tsx` |
| 5.12 | Automation Rules authoring + testing moved into dialogs | ✅ | `RunbookModal.tsx`; `AutomationRulesView.tsx` |
| 5.13 | Dead code removed | ✅ | `RunbookEditorView.tsx`, `RunbookNav.tsx`, `runbook.api.ts` deleted; `RunbookEnvelope` declared once |
| 5.14 | RLS parity for `runbook_tasks` | ✅ | migration 065 |
| 5.15 | Docs | ✅ | `apps/docs/docs/console/runbook.md`, `docs/operations/runbook.md` |

### Corrections to earlier plan documents (plan files are not edited)

`PLAN-20261028-1200-runbook-control-plane.md` names paths that do not exist in this
repo. The actual implementation used:

| Plan says | Reality |
|---|---|
| `services/api/alembic/versions/runbook_tasks_table.py` | `services/api/migrations/064_runbook_tasks.sql` (this repo uses numbered SQL migrations; there is no `alembic/versions`) |
| `services/api/app/services/fusion/consumer.py` | `services/agents/app/workers/fused_alert_consumer.py` |
| `services/agents/app/runtime/auto_triage.py` | `services/agents/app/agents/auto_triage_agent.py` |
| Hook in `services/api/app/services/llm_safety.py` | `services/agents/app/investigator/ledger.py` (writer) called from the worker |

### Defects found during this phase

1. **Rules never executed.** `rule_executor` called the pure `decide()` with an
   `AsyncSession` as the action name *and* `await`-ed a synchronous function. Every
   matching rule raised and was swallowed by the per-rule `except`, and the tests hid
   it by mocking `decide` with an `AsyncMock`. Now uses `evaluate()`; the regression
   test asserts the awaited call and the normalised confidence.
2. **Confidence scale.** Alert rows carry an int 0–100 while gate thresholds are
   0.0–1.0; `50` clamped to `1.0` and granted autonomy to everything.
   `normalize_confidence()` now converts, and the rule preview uses it too.
3. **Feedback was a log line.** `record_analyst_feedback()` had no callers; the UI
   claimed the model was being trained.

### Verified (2026-10-29)

- `pytest tests/test_runbook_alignment.py` → **11 passed**
- `pytest tests/test_runbook_automation.py tests/test_runbook_alignment.py tests/test_runbook_gate.py tests/test_runbook_events.py` → **139 passed, 8 skipped**
- `pytest tests/test_outcome_feedback.py tests/test_fused_alert_worker.py` (agents) → **22 passed**
- `pnpm --filter @aisoc/web type-check` → clean
- `pnpm --filter @aisoc/web vitest run src/components/runbook` → **6 passed**

### Known pre-existing failure (not from this work)

`tests/test_runbook_emission.py::test_escalate_alert_emits_the_previous_severity` and
`::test_emitters_never_break_the_action_when_the_ledger_is_off` fail on the current
working tree (`assert 'medium' == 'high'`), from earlier uncommitted escalation work —
untouched by Phase 5.

---

## Phase 6 — Feedback-loop measurement ✅ COMPLETE (2026-10-29)

The loop could be closed without anyone being able to tell. Phase 5 forwarded the
feedback, but the only record of whether a prior actually moved was a log line.

| # | Task | Status | Evidence |
|---|---|---|---|
| 6.1 | `runbook_tasks.feedback_applied` (TRUE / FALSE / NULL) | ✅ | `migrations/066_runbook_feedback_applied.sql`, `models/runbook_task.py` |
| 6.2 | Forward before the write so the row records the real result | ✅ | `runbook.py::complete_runbook_task` |
| 6.3 | `GET /api/v1/runbook/stats` tenant-scoped aggregate | ✅ | `runbook.py::runbook_feedback_stats` |
| 6.4 | Feedback-loop strip in the Action Plan | ✅ | `ActionPlanView.tsx::FeedbackLoopStrip` |
| 6.5 | Tests: applied / unapplied / no-feedback / aggregate scoping | ✅ | `test_runbook_alignment.py`, `ActionPlanView.test.tsx` |

Notes:

- `feedback_applied = NULL` is *unknown*, not false: every row written before 066 has
  no stored result and is counted as not applied. Do not backfill it as `TRUE`.
- The forward now runs before the completion write, so a completion can wait up to
  `AGENTS_TIMEOUT_SECONDS`. That ordering is what makes the flag truthful.

### Verified (2026-10-29, Phase 6)

- `pytest tests/test_runbook_alignment.py` → **14 passed**
- `ruff check` on touched files → clean
- `pnpm --filter @aisoc/web type-check` → clean
- `vitest run src/components/runbook/ActionPlanView.test.tsx` → **5 passed**

---

## Phase 7 — Workflow SOC ↔ Runbook linkage ✅ COMPLETE (2026-10-29)

The two surfaces had no connection: `/workflow-soc` was a purely presentational
diagram, and the Runbook had no way back to the lifecycle. Links were added only
where the destination is a real queue.

| # | Task | Status | Evidence |
|---|---|---|---|
| 7.1 | Stage 04 `Verdict & Copilot` → Action Plan filtered to `manual_review` | ✅ | `WorkflowSocView.tsx` (`STEPS[].link`) |
| 7.2 | Stage 05 `Approved Response` → Action Plan filtered to `approval_gate` | ✅ | same |
| 7.3 | `?stage=<id>` opens and pauses the lifecycle on that stage | ✅ | `workflow-soc/page.tsx`, `WorkflowSocView({ initialStage })` |
| 7.4 | Runbook header → lifecycle, mapped per tab | ✅ | `app/(app)/runbook/page.tsx` (`LIFECYCLE_STAGE`) |
| 7.5 | `/runbook?tab=…&task_type=…` deep link, with a visible cleared-on-demand filter | ✅ | `runbook/page.tsx`, `ActionPlanView({ task_type })` |

Deliberate omissions at the time: stages 01/02/03/06 got no link. Stage 02 gained a
real destination in Phase 8; 01, 03 and 06 still have none, because a link to an
unrelated screen would turn the diagram into a claim it cannot back.

### Verified (2026-10-29, Phase 7)

- `pnpm --filter @aisoc/web type-check` → clean
- `vitest run src/components/workflow src/components/runbook/ActionPlanView.test.tsx` → **10 passed** (4 new lifecycle tests, 1 new filter test)
- `eslint` on the four touched files → 0 errors, 2 pre-existing `set-state-in-effect` warnings

## Phase 8 — Workflow SOC stage 02 drill-down ✅ COMPLETE (2026-10-29)

Stage 02 ("rules and correlation promote noise into high-signal alerts") had no
surface to open. It now has one, built only from columns the fusion spine writes.

| # | Task | Status | Evidence |
|---|---|---|---|
| 8.1 | `GET /api/v1/runbook/detections` — tenant-scoped, recent-first | ✅ | `runbook.py::runbook_detection_activity` |
| 8.2 | Shaping + summary as pure functions | ✅ | `services/runbook/detections.py` |
| 8.3 | Detect & Fuse tab in the Runbook | ✅ | `DetectionFuseView.tsx`, `app/(app)/runbook/page.tsx` |
| 8.4 | Stage 02 link in Workflow SOC | ✅ | `WorkflowSocView.tsx` (`STEPS[detect].link`) |
| 8.5 | Tests | ✅ | `tests/test_runbook_detections.py`, `DetectionFuseView.test.tsx` |

Honesty constraints encoded:

- A missing rule is rendered as **No rule recorded**, never back-filled from the title
  (the connector path sets `rule_name = title`, so a title is not evidence of a rule).
- Summary counts cover the returned page, and the UI says "last N promotions".
- Fusion state is derived from persisted ids only: `fusion_incident_id` → incident,
  `is_merged` / `parent_alert_id` → merged, otherwise standalone.

### Verified (2026-10-29, Phase 8)

- `pytest tests/test_runbook_detections.py tests/test_runbook_alignment.py` → **24 passed**
- `ruff check` on touched files → clean
- `pnpm --filter @aisoc/web type-check` → clean
- `vitest run src/components/runbook/DetectionFuseView.test.tsx src/components/workflow` → **10 passed**
- `eslint` on touched files → 0 errors, 2 pre-existing `set-state-in-effect` warnings

---

## Phase 9 — Rule authoring audit + search ✅ COMPLETE (2026-10-29)

Asked for: search on Automation Rules and Governance, an audit of every rule field
(defaults, allowed values, tooltips), and match preview at authoring time instead of a
separate Test button.

| # | Task | Status | Evidence |
|---|---|---|---|
| 9.1 | Search on Automation Rules (name, action, trigger, owner, refs, conditions) | ✅ | `AutomationRulesView.tsx` (`filteredRules`) |
| 9.2 | Search on Governance (label, slug, category, blast radius) + filter composition | ✅ | `GovernanceView.tsx` |
| 9.3 | Per-field tooltips with defaults and allowed values | ✅ | `FieldLabel`, `FIELD_HELP`, `OP_HELP`, `TRIGGER_META` |
| 9.4 | Live draft preview endpoint | ✅ | `POST /runbook/automation-rules/preview` |
| 9.5 | Preview panel in the editor (debounced, abortable, error-reporting) | ✅ | `RuleForm` |
| 9.6 | Tests | ✅ | `test_runbook_rule_authoring.py`, `AutomationRulesView.test.tsx`, `GovernanceView.test.tsx` |

### Defects the audit found (all fixed)

1. **Autonomy ceiling was decorative.** `autonomy_level` was stored and selected but
   never read: a rule marked L0 could still execute on an L4 policy. Now
   `apply_rule_autonomy_ceiling()` caps the decision; a capped action becomes
   **approval-required**, not `denied` (refusing it would misreport "governance said
   no").
2. **`subject_type` was decorative.** The rule query ignored it, so a case-scoped
   rule fired on alert events. Now enforced in `_FETCH_RULES` (NULL/`all` stay
   catch-all).
3. **Preview and execution disagreed.** The test panel built its own smaller subject
   dict, so conditions on `disposition`, `rule_name`, or MITRE fields reported
   "not matched" while the executor would have matched them. Both sides now use
   `alert_subject_fields()`.
4. **Two field options could never match.** `disposition` was offered but missing
   from the preview dict; `risk_score` exists only in the API response schema, not on
   the `alerts` table. The editor now offers exactly the executor's keys.
5. **Two triggers never fire.** `case.created` and `manual` are accepted and stored
   but no code path emits them; the picker labels them **(inert)** instead of
   implying they work.
6. **Broken deep link.** The form linked to `/runbook?type=governance`; the tab is
   `?tab=governance`.

### Verified (2026-10-29, Phase 9)

- `pytest` runbook suites → **160 passed, 8 skipped** (8 new authoring tests)
- `ruff check` on touched files → clean
- `pnpm --filter @aisoc/web type-check` → clean
- `vitest run src/components/runbook` → **18 passed** (3 new Automation Rules tests, 2 new Governance tests)
- `eslint` on touched files → 0 errors, 2 pre-existing `set-state-in-effect` warnings

---

## Phase 10 — SOC Funnel ↔ Runbook linkage ✅ COMPLETE (2026-10-29)

The funnel board said how many alerts sit in each stage. It could not say why, and
nothing connected a stuck alert to the queue that would unstick it.

| # | Task | Status | Evidence |
|---|---|---|---|
| 10.1 | Open-task count per funnel stage | ✅ | `agentic_funnel._open_runbook_tasks`, `funnel_board` |
| 10.2 | `open_tasks` on each sample alert | ✅ | same |
| 10.3 | Task badges + **Runbook →** per card, **Open Runbook** in the header | ✅ | `SocFunnelBoardView.tsx` |
| 10.4 | Bulk funnel operations recorded in `audit_log` | ✅ | `soc_funnel._audit_bulk_operation` |
| 10.5 | Tests | ✅ | `test_soc_funnel_board_tasks.py`, `SocFunnelBoardView.test.tsx` |

Notes:

- The board reads `runbook_tasks`; the Runbook owns that table, so nothing is copied.
  If the table is absent the helper returns empty maps and the board still renders.
- Backfill / dedupe / re-enrich are **not** written to `runbook_events`: that ledger is
  per-subject (`subject_id` is one alert/case), while these are tenant-wide. They go to
  the append-only, hash-chained `audit_log` instead.

### Verified (2026-10-29, Phase 10)

- `pytest tests/test_agentic_funnel.py tests/test_funnel_and_pipeline.py tests/test_funnel_stages.py tests/test_soc_funnel_board_tasks.py` → **57 passed**
- `ruff check` on touched files → clean
- `pnpm --filter @aisoc/web type-check` → clean
- `vitest run src/components/funnel` → **3 passed**
- `eslint` on touched files → clean

---

## Phase 11 — Playbook ↔ Runbook safety boundary ✅ COMPLETE (2026-10-29)

The proposed Playbook↔Runbook features were checked against the code. Most of the
editor capabilities already existed (schema-driven step inspector, conditions, retry /
timeout, the `approval` step type in the model). Two things that did **not** exist were
defects that failed open.

| # | Task | Status | Evidence |
|---|---|---|---|
| 11.1 | `approval` step parks the run (`pending_approval`, step `blocked`) | ✅ | `playbook/engine.py` |
| 11.2 | Unimplemented step kind fails the run (no silent skip) | ✅ | same |
| 11.3 | `unsupported_step_types` exposed per playbook | ✅ | `api/playbooks.py::_serialize` |
| 11.4 | Gallery warns, run history renders the new statuses | ✅ | `PlaybooksGallery.tsx`, `PlaybooksView.tsx` |
| 11.5 | Tests | ✅ | `tests/test_playbook_approval_gate.py` |

### Defects found

1. **An approval step did nothing.** `StepType.APPROVAL` had no handler, so it hit the
   generic "no handler" branch, was recorded as `success` with `{"skipped": true}`, and
   the run continued — a playbook could isolate a host after an approval that nobody
   gave.
2. **Every unimplemented step type reported success.** `disable_user`, `revoke_session`,
   `kill_process`, `quarantine_file`, `block_ioc`, `run_script`, `search_siem`, … all
   fell into the same branch. Only the API/import path could produce them (the editor
   offers just the nine handled kinds, and shipped templates use none of the others),
   but the failure mode was a false "contained" in the run history.

### Deferred (needs design, not a patch)

Resuming a parked run after an analyst approves. Runs live in the agents process's
in-memory `_runs` map and there is no resume endpoint, so an approval can only stop a
playbook today. A real HITL loop needs: persisted run state (DB), a
`POST /playbooks/runs/{id}/resume` guarded by HMAC tenant auth, and the engine creating
an `approval_gate` task in `runbook_tasks` so the run and the task share one id. Until
then the Action Plan does **not** claim a paused run will continue.

### Verified (2026-10-29, Phase 11)

- `pytest tests/test_playbook_approval_gate.py` → **4 passed**
- `pytest` engine/models/drafter suites → **96 passed**
- `ruff check` on touched files → clean
- `pnpm --filter @aisoc/web type-check` → clean

---

## Phase 12 — Resumable playbook approvals ✅ COMPLETE (2026-10-29)

Phase 11 made the gate fail closed, which left a parked run as a dead end: the run
lived in the agents process's `_runs` dict, and nothing could release it. This phase
closes the loop, following [DESIGN-20261029-playbook-approval-resume.md](DESIGN-20261029-playbook-approval-resume.md).

| # | Task | Status | Evidence |
|---|---|---|---|
| 12.1 | `playbook_runs` table (+ RLS, indexes) | ✅ | `migrations/067_playbook_runs.sql` |
| 12.2 | `runbook_tasks.playbook_run_id` / `resume_applied` + one open task per run | ✅ | same migration |
| 12.3 | Engine persists run at start / gate / terminal; resume from `next_step_index` | ✅ | `playbook/engine.py`, `playbook/run_store.py` |
| 12.4 | Gate task created on park, naming the run | ✅ | `playbook/approvals.py` |
| 12.5 | `POST /api/v1/playbooks/runs/{id}/resume` (HMAC tenant auth, 404/409/503) | ✅ | `playbook/resume.py`, `api/playbooks.py` |
| 12.6 | API forwards the decision before writing the task | ✅ | `agents_client.resume_playbook_run`, `runbook.py::complete_runbook_task` |
| 12.7 | `playbooks:approve` permission (static map + DB catalogue) | ✅ | `core/security.py`, migration 067 |
| 12.8 | UI: explicit decision, resume label, resumed/not-resumed state | ✅ | `ActionPlanView.tsx`, `runbook.types.ts` |
| 12.9 | Run History reads the durable store and shows the parked step | ✅ | `PlaybooksView.tsx`, `playbooks/types.ts` |
| 12.10 | Retention: keep metadata, prune blobs after 90 days | ✅ | `scripts/prune_playbook_runs.py` |
| 12.11 | Docs | ✅ | `apps/docs/docs/console/runbook.md` § Resuming a parked run |

### Decisions (from the design's open questions)

1. **Retention** — keep the row forever (audit: who approved what, when, how it ended);
   prune only `playbook_snapshot` / `context` / `step_results` after 90 days, via
   `python -m app.scripts.prune_playbook_runs`. Parked runs are never pruned.
2. **Reject** — `cancelled` with `error = "rejected by <actor>"`. It reads as "a human
   ended this", not "the playbook broke".
3. **Who may approve** — new `playbooks:approve`, granted to `tenant_admin` and
   `soc_lead` only. `soc_analyst` keeps `playbooks:execute` but cannot clear a gate, so
   a tier-1 analyst cannot approve their own action. Scoped to playbook gates:
   autonomy-ceiling `approval_gate` tasks (no `playbook_run_id`) keep their existing
   `alerts:write` contract, since their rules live in the action catalog.

### Defects found while implementing

1. **The API's run id and the durable row id disagreed.** `_execute_and_update`
   assigned the caller's pre-allocated `run_id` *after* `engine.run()` returned, so a
   persisted row would have been keyed by a different id and the run the caller polls
   could never be loaded back or resumed. `engine.run(run_id=...)` now takes the id
   before the first persist.
2. **Run History read fields the engine never writes.** The UI consumed
   `run.steps[].step_name` while the API serialises `step_results[].name`, so progress
   dots and the step count were empty. The type now matches the payload, and the step
   status vocabulary is the engine's (`success`, not `completed`).
3. **Run History forgot parked runs on restart.** `GET /playbooks/runs` only read the
   process-local dict. It now merges the durable rows (tenant-scoped when a tenant
   header is present) — otherwise the Action Plan could hold a task for a run no one
   could see.

### Verified (2026-10-29, Phase 12)

- `pytest tests/test_playbook_resume.py tests/test_playbook_resume_api.py tests/test_playbook_approval_gate.py tests/test_playbook_engine_correctness.py` (agents) → **144 passed**
- `pytest tests/test_runbook_playbook_resume.py tests/test_runbook_alignment.py tests/test_runbook_automation.py tests/test_runbook_gate.py tests/test_runbook_events.py` (api) → **147 passed, 8 skipped**
- `pnpm --filter @aisoc/web type-check` → clean
- `vitest run src/components/runbook/ActionPlanView.test.tsx` → **8 passed** (2 new)

---

## Appendix — Verified (2026-10-28)

- `ruff check` → clean on all touched Python files
- `pytest tests/test_runbook_gate.py` → **34 passed**
- `pytest tests/test_security_defaults.py tests/test_demo_mode.py tests/test_airgap.py tests/test_runbook_gate.py` → **98 passed, 4 errors** (pre-existing `prometheus_client` import error on this machine, not from Runbook work)
- `tsc --noEmit` (apps/web) → **no errors**

---

## Phase 13 — Correctness review + documentation consolidation ✅ COMPLETE (2026-10-30)

Whole-branch review of the uncommitted Runbook work: what actually runs, what only
claims to run, and which documents are still true. Plan status for
[PLAN-20261029-1026-runbook-alignment.md](PLAN-20261029-1026-runbook-alignment.md) is
**implemented** (its header still says "implementation not started"; plan files are
not edited, so the status lives here).

### Defects found and fixed

1. **`test_runbook_automation.py` did not parse.** Two truncated docstrings
   (the `_claim_db` docstring, and the trailing `TestLinkApprovalGatesToRunbookTasks` block) left the
   module unimportable, so its 101 tests — including the whole linked-playbook start
   path — had never executed. Fixed; `PlaybookStart` import added; the trailing gate
   test now asserts the real call shape (`alert_id` / `action_name` /
   `autonomy_level`), which the previous version invented.
2. **The ledger catch-all shadowed two resource routes.** `GET
   /runbook/{subject_type}/{subject_id}` was declared first, so `GET
   /runbook/tasks/{id}` and `GET /runbook/automation-rules/{id}` answered 400
   ("subject_type must be one of …") instead of the resource. The catch-all is now
   registered last, with a comment and a route-resolution regression test
   (`tests/test_runbook_alignment.py`).
3. **Runtime DDL from a read endpoint.** `_ensure_rule_extra_columns()` ran
   `ALTER TABLE automation_rules …` on first call per process from
   `GET /runbook/automation-rules`. A read-only endpoint needed ALTER privileges, and
   `rule_executor._FETCH_RULES` (the alert write path) read the same columns without
   calling it — so on a freshly migrated database every rule silently evaluated
   nothing until somebody opened the Automation Rules page. Removed;
   `migrations/070_automation_rules_metadata.sql` now owns those columns.
4. **Three integration suites could destroy real data.** `test_calibration_monitor.py`,
   `test_operational_queries.py` and `test_runbook_integration.py` ran unscoped
   `DELETE FROM runbook_tasks / alerts / cases` against whatever `DATABASE_URL`
   pointed at, and errored (rather than skipped) without Postgres. Now gated behind
   `AISOC_RUN_INTEGRATION=1` like the rest of the integration suites, with every
   delete scoped to the fixture's own tenant. Also fixed: a bare-string
   `session.execute(...)` (SQLAlchemy 2.x rejects it), and `Alert(confidence=0.65)`
   against an integer column.
5. **The governance gate had no working test.** `test_phase3_governance.py` called
   `engine.execute(...)`, which the engine has never had, so the containment gate
   (`_check_governance` → park as `pending_approval`) was never covered. Rewritten to
   drive `_execute` with stubbed handlers and `_check_governance` directly: parks,
   approves, dry-run never asks, and both fail-closed paths.
6. **A malformed playbooks response blanked the rule editor.**
   `playbookOptions.find(...)` runs during render, so a non-array payload crashed the
   whole Automation Rules form. The response is now validated.
7. **Frontend tests asserted copy the shipped UI does not render** (Governance
   aria-label, count text, empty-state text, autonomy option role, `getByDisplayValue`).
   Fixed to the real markup; the `fetch` stub also stopped answering the playbooks
   request with the preview payload.

### Documentation

One doc per audience, no dead plans:

- kept — `apps/docs/docs/console/runbook.md` (console/user), `docs/operations/runbook.md`
  (operator: writers, gates, debugging), `PLAN-20261029-1026-runbook-alignment.md`,
  `DESIGN-20261029-playbook-approval-resume.md`, this log.
- deleted — seven superseded runbook plans (the original Persian plan page, the
  control-plane and "professional" plans whose paths never existed, the scope-reset
  plan, two completed micro-plans), three near-duplicate connector-availability docs,
  `docs/operations/automation-rules-debugging.md` (its unique checklist, with the wrong
  `/api/v1/automation-rules` path corrected, is now a section of the operator doc),
  `docs/phase-3-integration-complete.md` (stale status page claiming tests were "ready
  to run"), and the scratch scripts (`check_rules.py`, `debug_rules.py`,
  `run_runbook_tests.ps1`, `scripts/test_phase_2_e2e.py`, `services/api/_*.py`,
  `apps/web/__tmp_commit_body.js`, `services/api/generated/`).
- the connector-availability behaviour is documented in the console doc, so the three
  deleted feature writeups lose nothing.

### Verified (2026-10-30)

- `pytest` api runbook suites (gate, events, automation, alignment, detections,
  emission, rule authoring, actions endpoint, playbook resume, subject fields, funnel
  board tasks, alert tenant isolation) → **212 passed, 15 skipped**
- `pytest` the three Phase-13 integration suites → **45 skipped** without a database
  (they were 45 errors before)
- `pytest` agents playbook suites (approval gate, resume, resume API, outcome feedback,
  governance, engine correctness) → **94 passed**
- `pytest tests/test_splunk_simple_mode.py` (connectors) → **25 passed**
- `ruff check` → clean on every touched file except 8 `E501` inside
  `services/connectors/app/connectors/splunk.py`'s SPL pipeline string, where a newline
  is a command separator and wrapping would change the query
- `pnpm --filter @aisoc/web type-check` → clean
- `vitest run src/components/{runbook,funnel,workflow,playbooks,alerts}` → **153 passed**

### Known, pre-existing (verified identical on a clean `HEAD` worktree)

- `services/connectors`: 8 failures (`test_auditd_connector`, `test_conformance`,
  `test_hello_connector_example`, `test_kubernetes_audit`, 4 × `test_splunk_connector`).
- `services/api/tests/test_alerts_tenant_isolation.py` failed 12/20 on `HEAD`; 8 of those
  were test-harness gaps (missing `iocs`, unresolved `Query` sentinels) and are fixed
  here — the file is green now.

### Migration numbering fixed (2026-10-30)

The branch carried two colliding migration numbers — `068_runbook_confidence_and_defaults.sql`
next to `068_playbook_runs_dedupe.sql`, and `069_playbook_approvals.sql` next to
`069_autonomy_action_enabled.sql`. `run_migrations.py` sorts by filename, so the pair order was
decided by a lexicographic accident rather than intent. Renumbered to unique, intent-preserving
names and re-verified the ordering:

- `068_playbook_runs_dedupe.sql` → unchanged (still after `067_playbook_runs.sql`)
- `069_autonomy_action_enabled.sql` → unchanged
- `070_automation_rules_metadata.sql` → unchanged
- `068_runbook_confidence_and_defaults.sql` → `071_runbook_confidence_and_defaults.sql`
- `069_playbook_approvals.sql` → `072_playbook_approvals.sql`

Both renumbered files are idempotent (`ADD COLUMN IF NOT EXISTS`, `CREATE TABLE IF NOT EXISTS`)
and depend only on tables at or below `067`, so the move is order-safe for existing databases
whose `aisoc_schema_migrations` rows still carry the old names — those rows keep their schema
effect and the files simply re-apply as no-ops.

`services/api/tests/test_funnel_stages.py` also still asserted the old 80-character
`ai_summary` evidence bar; it now asserts the raised 100-character bar (and pins that a 90-char
summary no longer qualifies).

---

## Phase 14 — Splunk rule packs + review of the side-generated docs ✅ COMPLETE (2026-10-30)

Plan: [PLAN-20261030-1200-splunk-automation-rule-packs.md](PLAN-20261030-1200-splunk-automation-rule-packs.md).

### 14.1 Rule packs

| # | Task | Status | Evidence |
|---|---|---|---|
| 14.1 | `packs.py` registry + `windows-splunk` pack (31 rules, 93 ESCU names) | ✅ | `services/api/app/services/runbook/packs.py` |
| 14.2 | `GET /runbook/automation-rules/packs`, `POST …/packs/{id}/import` (404 / idempotent by name / validated conditions) | ✅ | `api/v1/endpoints/runbook.py` |
| 14.3 | **Packs** dialog in the rules page (counts + Import + result line) | ✅ | `AutomationRulesView.tsx` |
| 14.4 | Tests: validity, positive match, neutral-subject rejection, endpoint paths | ✅ | `tests/test_automation_rule_packs.py` |
| 14.5 | Docs | ✅ | console doc *Windows — Splunk rule pack*, operator doc *Rule packs* |
| 14.6 | UI test for the Packs dialog (list → import → result line) | ✅ | `AutomationRulesView.test.tsx` |

Defect found by 14.4 (fixed): `condition_eval._coerce()` stringified a list when the
subject field was a string, so `in` degenerated into a substring test and a 93-name
`rule_name in [...]` condition matched any alert with an empty `rule_name`. Containers are
no longer coerced; `_op_in` is membership-only and fails closed on a non-iterable right
side. Covered in `tests/test_automation_rule_packs.py` and
`tests/test_runbook_automation.py`.

### 14.2 Review of `docs/plans/runbook-docs/` (deleted)

Nineteen documents (~340 KB) produced while the design was still moving. Each was checked
against the working tree; the folder is now deleted because the kept set covers every
statement that is still true:

**Verified true, already documented elsewhere** (no loss):

- Calibration monitor (Task 1.2) — wired in `app/main.py` lifespan, gated by
  `CALIBRATION_MONITOR_ENABLED` and `not is_dev_env()`. Documented in
  `env-vars.md` § Runbook, with the ECE/interval/min-sample knobs.
- Investigation evidence bars (Task 1.3) — `ai_summary >= 100`, `narrative >= 200`, and
  the Runbook-task completion bar in `services/api/app/services/funnel_stages.py`.
- Phase 13 suites — `test_runbook_integration.py`, `test_calibration_monitor.py`,
  `test_operational_queries.py` exist and are `AISOC_RUN_INTEGRATION=1`-gated.
- Phase 3 governance — `migrations/072_playbook_approvals.sql` exists and the engine
  parks containment steps; covered in the operator doc *Playbook approval gates* and
  `services/agents/tests/test_phase3_governance.py`.

**Wrong or misleading** (why they had to go):

- `IMPLEMENTATION_SUMMARY_1_2_1_3.md` / `CODE_VERIFICATION_SUMMARY.md` place the monitor at
  `services/api/app/services/calibration_monitor.py` — it is
  `services/api/app/workers/calibration_monitor.py`.
- `RUNBOOK_E2E_TEST_GUIDE_FA.md` documents `./run_runbook_tests.ps1` flags and output that
  never existed (the script was a scratch file, deleted in Phase 13), and claims the
  three integration suites run by default — they skip unless `AISOC_RUN_INTEGRATION=1`.
- `COMPLETE_DATA_FLOW_ANALYSIS.md` and `FLOWCHARTS_AND_DIAGRAMS.md` narrate an
  eight-step `Splunk → auto-triage → Jira` pipeline with hand-maintained diagrams; the
  shipped spine is Connectors → ingest (OCSF) → Kafka → fusion → Postgres → realtime,
  with ITSM as an optional sink, so the step numbering and several component claims in
  them no longer describe the code.
- `IMPLEMENTATION_CHECKLIST.md` / `README_ANALYSIS_SUMMARY.md` score the platform
  ("70–75 % SOC-ready", "Priority-1 tasks, 4–5 days") against features that have since
  shipped (human gate, investigation gate, calibration), so the scores read as current
  gaps when they are already closed.
- `PHASE-2-E2E-TEST-GUIDE.md` / `PHASE-3-*.md` reference a `PlaybookApprovalQueue`
  component that does not exist (`apps/web/src/components/playbooks/` has no such file);
  the real surface is the Runbook Action Plan.
- `INDEX.md` / `COMPREHENSIVE_INDEX.md` / `*_COMPLETION*.md` index and "completion
  report" the documents above — dead links by construction, and their "COMPLETE" banners
  pre-date Phase 13's fixes (route-ordering, runtime DDL, destructive integration tests).

### Verified (2026-10-30)

- `pytest` api runbook suites (gate, events, automation, alignment, detections, emission,
  rule authoring, actions endpoint, playbook resume, rule packs, subject fields) →
  **420 passed, 15 skipped**
- `pytest tests/test_calibration_monitor.py` → **15 skipped** without `AISOC_RUN_INTEGRATION=1`
  (as designed)
- `ruff check` on the pack module, evaluator, endpoint and both touched test files → clean
- `tsc --noEmit` (apps/web) → clean
- `vitest run src/components/runbook` → **24 passed** (9 in `AutomationRulesView`, one new)

---

## Phase 15 — Rule/connector alignment: evaluator coverage, no auto-seed, connector-gated enabling ✅ COMPLETE (2026-10-30)

Two problems, one root cause: the rules page described automations the platform was not
actually running, and let operators switch on actions no connector could execute.

### 15.1 `alert.created` now covers every alert, not just the alert API

| # | Task | Status | Evidence |
|---|---|---|---|
| 15.1 | Migration `073` — `alerts.automation_rules_evaluated_at` (+ partial index, `NULLS FIRST`) | ✅ | `services/api/migrations/073_alerts_rule_evaluation.sql` |
| 15.2 | `RuleEvaluator` worker: claim-once pass, guarded by `AISOC_RULE_EVALUATOR_ENABLED`, interval, batch | ✅ | `services/api/app/workers/rule_evaluator.py`, `app/main.py` lifespan |
| 15.3 | `POST /alerts` no longer owns `alert.created`; `PATCH` runs on its own session | ✅ | `api/v1/endpoints/alerts.py` |
| 15.4 | Tests: claim → evaluate → mark, once-only, disabled flag, batch bound | ✅ | `tests/test_rule_evaluator_worker.py` |
| 15.5 | Docs | ✅ | console *When a rule fires*, operator *a rule that never fires*, `env-vars.md` § Runbook |

The previous path fired rules inline from `POST /api/v1/alerts` on the request session, so
a fusion-written alert — which never passes through an HTTP endpoint — never triggered a
rule. The worker claims rows with `automation_rules_evaluated_at IS NULL` (`FOR UPDATE SKIP
LOCKED`), runs `run_rules_for_trigger`, and stamps the row. One evaluation per alert by
design: a claim that dies with its process stays claimed, and the operator doc says how to
re-queue it.

### 15.2 The automation rules are a catalogue, not a default

| # | Task | Status | Evidence |
|---|---|---|---|
| 15.6 | `default_rules.py` — the 17 previously seeded rules, carried verbatim | ✅ | `services/api/app/services/runbook/default_rules.py` |
| 15.7 | `core-defaults` pack (`RawPackRule`) registered beside `windows-splunk` | ✅ | `services/api/app/services/runbook/packs.py` |
| 15.8 | `GET …/packs` lists **every** rule with `autonomy_level`, `dry_run`, `installed`; import accepts a subset and reports `unknown` | ✅ | `api/v1/endpoints/runbook.py` |
| 15.9 | `GET …/automation-rules` no longer seeds; `_seed_default_rules_for_tenant` deleted | ✅ | same |
| 15.10 | Packs dialog: per-rule checkboxes, *Add selected (n)* / *Add all missing*, **Added** badge; the dead **What these rules do** link removed | ✅ | `AutomationRulesView.tsx` |
| 15.11 | Empty state points at *Browse rule packs* / *New rule* instead of staying silent | ✅ | same |
| 15.12 | Tests: subset import, `unknown` names, `installed` flags, core posture parity, per-rule select | ✅ | `tests/test_automation_rule_packs.py`, `AutomationRulesView.test.tsx` |

The seeded set was wrong twice over: it appeared the first time a tenant opened the page
(so a tenant gained 17 automations nobody chose, four of them `dry_run=False`), and it
duplicated `core-defaults` in spirit while living as a literal in the endpoint module.
Both are gone. `RawPackRule` carries each row verbatim, and a test pins the four executing
rules by name so moving them into a pack cannot quietly change their posture.

The **What these rules do** link pointed at
`docs.tryaisoc.com/console/runbook#windows--splunk-rule-pack`, an anchor that never
existed. Packs now carry `docs_ref: None` and the UI renders no link; a test asserts it.

### 15.3 Enabling an action requires the connector that would run it

| # | Task | Status | Evidence |
|---|---|---|---|
| 15.13 | `GET /runbook/governance` returns `required_connectors`, `available`, `enabled` (per tenant) | ✅ | `api/v1/endpoints/runbook.py` |
| 15.14 | `PATCH /autonomy-policy/{action}/enabled` → **409** when enabling without the connector; disabling always allowed | ✅ | `api/v1/endpoints/autonomy_policy.py` |
| 15.15 | Console: toggle + **Edit Policy** disabled on unavailable rows, tooltip and notice name the connector(s), rejected toggle reverts with a message | ✅ | `GovernanceView.tsx`, `runbook.types.ts` |
| 15.16 | Tests | ✅ | `GovernanceView.test.tsx`, `tests/test_runbook_actions_endpoint.py` |

`available` was only computed by `GET /runbook/actions`; `/runbook/governance` — the
endpoint the page actually calls — never returned it, so the client's
`entry.available === false` guard could never fire and every action looked configurable.
That is the reported symptom: a workspace with no Splunk connector could enable
`lookup_ip` / `search_logs`. Availability is still display-and-enable-time only; the
executor does not re-check it, which the console doc now states.

### Verified (2026-10-30)

- `pytest tests/test_automation_rule_packs.py` → **281 passed** (ASCII-only run; the
  parametrised detection checks now apply to `PackRule` only, and the core pack has its
  own posture-parity test)
- `pytest tests/test_runbook_automation.py tests/test_runbook_actions_endpoint.py
  tests/test_automation_rule_subject_fields.py tests/test_rule_evaluator_worker.py` →
  **122 passed**
- `tsc --noEmit` (apps/web) → clean
- `vitest run src/components/runbook` → **25 passed** (10 in `AutomationRulesView`, 3 in
  `GovernanceView`)
- `python -m compileall` on both touched endpoint modules, the pack module and the worker
  → clean
