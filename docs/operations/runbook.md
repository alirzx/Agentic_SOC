# Runbook — operator notes

The Runbook is the platform's **control plane**: the procedure an operator follows,
the evidence of what actually ran, the queue of blocked decisions, and the feedback
that improves triage. It is deliberately not SOAR, not a visual workflow editor, and
not a second implementation of the auto-triage happy path.

## Scope boundaries

| Layer | Owns | Does not own |
| --- | --- | --- |
| `services/fusion` | dedup, correlation, confidence, narrative | human decisions |
| `services/agents` (`fused_alert_consumer`) | triage verdict, auto-close, case promotion | approval of blocked actions |
| `services/api` (`/runbook/*`) | ledger read, procedure derivation, task queue, rule engine | executing vendor actions |
| `apps/web` (`/runbook`) | presentation of all of the above | any decision logic |

## Writers (one per record type)

| Record | Sole writer | Read by |
| --- | --- | --- |
| `runbook_events` | `services/api` (`services/runbook/{emitters,materialize,recorder,rule_executor}.py`) | `read.py` |
| triage evidence | `services/agents` (`investigator/ledger.py` → `investigation_events`) | `read.py` (union, not copied) |
| `manual_review` tasks | `services/agents` (`ledger.create_task_for_needs_review`) | `/runbook/tasks` |
| `approval_gate` tasks | `services/api` (`services/runbook/tasks.ensure_approval_gate_task`) | `/runbook/tasks` |
| playbook gate tasks | `services/agents` (`playbook/approvals.create_gate_task`) | `/runbook/tasks` |
| `playbook_runs` | `services/agents` (`playbook/run_store.py`) | agents `GET /playbooks/runs`, `POST /playbooks/runs/{id}/resume` |

Nothing writes a record it does not own. The triage verdict lives in the agent
ledger; the Runbook page reads it and shows its real source.

## Feedback path

```
analyst completes a task
  → POST /api/v1/runbook/tasks/{id}/complete
      → if the task carries a signature and feedback was submitted:
          POST {agents}/api/v1/outcomes/feedback
            headers: X-Tenant-Id + X-AiSOC-Tenant-Signature (HMAC-SHA256)
            body:    {signature, feedback, alert_id}
          → agents: record_analyst_feedback(tenant, signature, feedback=…)
            returns {"updated": true|false}
      → row committed (status, resolution, feedback_to_llm, feedback_applied)
      → logs `forwarded=true|false`
```

The forward runs **before** the write so `runbook_tasks.feedback_applied` can hold
the real answer: `TRUE` (prior updated), `FALSE` (feedback sent, nothing moved), or
`NULL` (no feedback submitted). Price of that ordering: a completion waits up to
`AGENTS_TIMEOUT_SECONDS` for the agents service. Do not move the call back after the
commit without also recording the result another way — that is how the loop became
unmeasurable the first time.

`GET /api/v1/runbook/stats` aggregates that column per tenant and is what the
Action Plan's Feedback-loop strip renders. It is a measurement, not a promise: if
nobody submits feedback the strip stays empty, and the unapplied bucket absorbs both
"no prior existed" and every row written before migration 066.

Properties worth preserving:

- **Fail closed.** Without `AISOC_AGENTS_TENANT_SIGNING_KEY` the API does not send the
  call at all; the agents endpoint rejects an unsigned or badly-signed tenant header
  with 401.
- **Honest.** A task with no signature (an older row, or a path that could not compute
  one) does not call out, and the log records `forwarded=false`. The endpoint returns
  `{"updated": false}` when there is no prior to update.
- **Best-effort.** The task row is committed before the call; a transport error never
  rolls back the analyst's decision.

## Playbook approval gates

```
playbook reaches an `approval` step
  → engine parks: status=pending_approval, step=blocked, next_step_index=<gate+1>
  → run_store.persist_run()                       (playbook_runs row)
  → approvals.create_gate_task()                  (runbook_tasks row, playbook_run_id)
analyst clicks Approve & resume
  → POST /runbook/tasks/{id}/complete {decision: approve}
      → requires `playbooks:approve` (403 otherwise)
      → agents POST /api/v1/playbooks/runs/{id}/resume  (HMAC tenant auth)
          → engine resumes at next_step_index; earlier steps are not re-run
      → row committed with resume_applied = TRUE|FALSE
```

Properties worth preserving:

- **One open task per run.** `uq_runbook_tasks_playbook_run` (partial unique on
  `playbook_run_id` where `status <> 'completed'`) makes duplicate gate tasks
  impossible; the agents insert uses `ON CONFLICT DO NOTHING`.
- **Snapshot, not live document.** `playbook_runs.playbook_snapshot` is what resume
  executes. Editing the playbook between approval and resume must not change what was
  approved; a snapshot that lost the resume step fails the run instead of guessing.
- **Status transitions guard the release.** Anything that is not `pending_approval`
  gets 409, so a double click or two workers race into one winner. Cross-tenant and
  unknown runs are both 404 — the endpoint never confirms a foreign run exists.
- **`resume_applied` is the honest bit.** It is `TRUE` only when the agents service
  reports the gate was released. Approve with the flag off, a missing signing key, or
  a 5xx leaves `FALSE` and the UI says "Decision recorded · run not resumed". A reject
  also stores `FALSE`: the run did not resume, it was cancelled.
- **Retention.** Rows are kept; the bulk JSONB columns are cleared after 90 days by
  `python -m app.scripts.prune_playbook_runs --days 90`. `pending_approval` rows are
  never pruned.
- **Feature flag.** `AISOC_PLAYBOOK_RESUME` gates both halves (task creation and the
  resume endpoint). With it off, a run parks and no task is created — the pre-Phase-12
  behaviour, which is honest but useless. Turn both on together or neither.

## Rules engine correctness notes

Two defects were found and fixed while aligning the Runbook; keep them from returning:

1. **Gate call signature.** `rule_executor` must call `evaluate(db, action=…,
   confidence=…)` — the DB-aware entry point. Calling the pure `decide()` with a
   session, or awaiting it, raises inside the per-rule `except` block, so every rule
   silently recorded nothing. The regression test asserts `evaluate` is awaited.
2. **Confidence scale.** `alerts.confidence` is an int 0–100; gate thresholds are
   0.0–1.0. `normalize_confidence()` divides when the value exceeds 1. Passing 50
   straight through clamps to 1.0 and grants autonomy to everything.
3. **Containers are never coerced.** `_coerce()` stringified a list to compare it with a
   string field, which turned `in` into a substring test: `{"field": "rule_name", "op":
   "in", "value": [93 names]}` matched every alert whose `rule_name` was `""`. The
   operators now handle a mismatched type themselves, and `_op_in` is membership only
   (a scalar `value` becomes a one-item list, a non-iterable side fails closed).
   `contains` remains the substring operator; do not "fix" `in` back into it.

## Rule packs

`app/services/runbook/packs.py` holds checked-in rule bundles that are **imported per
tenant**, not seeded. Nothing is written to a tenant's `automation_rules` until an
operator adds it: not the vendor-neutral rules, not the detection-keyed ones. A rule an
operator did not choose has no owner, and there was no way to tell an intended
automation from an inherited one.

| Pack | Rules | Type |
| --- | --- | --- |
| `core-defaults` | 17 | `RawPackRule` — the previous seeded set, carried verbatim from `app/services/runbook/default_rules.py` |
| `windows-splunk` | 31 | `PackRule` — generated from ESCU detection names |

`RawPackRule` carries the row as-is, so moving a rule into a pack never changes what it
does — conditions, autonomy ceiling, `dry_run` and priority are identical to the seeded
values. Four core rules ship `dry_run=False` (`Auto-enrich network alerts`, `Auto-close
EICAR test files`, `Add TI context to case on indicator match`, `Tag noisy endpoint rules
for tuning`); the console shows that per rule before it is added.

- **Listing.** `GET /api/v1/runbook/automation-rules/packs` returns every rule of every
  pack with `autonomy_level`, `dry_run` and `installed` (computed from the tenant's rule
  names), so the UI can offer per-rule selection. Read-only.
- **Matching (detection rules).** One condition per rule: `rule_name in [<detection
  names>]`. `rule_name`
  is populated from the notable's `search_name`, which for Splunk Security Content
  (ESCU) equals the detection's `name:`. One `in` condition, never N `eq` conditions —
  conditions are ANDed, so N `eq`s could never match.
- **Shipped pack.** `windows-splunk`: 31 rules over 93 ESCU endpoint detections
  (`isolate_host` ×2, `create_case` ×18, `add_alert_tag` ×11; autonomy L1 ×11, L2 ×18,
  L3 ×2). Every rule is `dry_run=True`, so an import installs decisions, not execution.
- **Import.** `POST /api/v1/runbook/automation-rules/packs/{id}/import` (`alerts:write`)
  takes an optional `{"rule_names": [...]}` body to install a subset (empty installs the
  whole pack), skips rules whose name already exists for the tenant, and reports names
  that are not in the pack back under `unknown`. Conditions are validated before insert;
  a malformed condition fails the import (500) instead of installing an inert rule.
- **No docs link.** Packs carry `docs_ref: None`: the anchor the Splunk pack pointed at
  never existed on the docs site, and a dead link on a governed action is worse than no
  link. The console section is one click away in the app.
- **Drift.** Upstream renames a detection → the rule stops matching. That is visible by
  design: the pack reports `covered_detections` per pack.
- **Tests.** `pytest tests/test_automation_rule_packs.py` asserts every rule's condition
  validates, matches a subject built from its ESCU name, and — the regression that
  matters — is rejected by a subject whose `rule_name` is empty.

## Debugging: a rule that never fires

In order, because each step makes the next one meaningless:

1. **Does the tenant have any rules?** `GET /api/v1/runbook/automation-rules` lists the
   rules the tenant created or imported and returns an empty list otherwise — nothing is
   seeded on read. An empty list means the operator has not added anything yet: the
   `core-defaults` and `windows-splunk` packs are opt-in. (The path is under `/runbook`
   — `/api/v1/automation-rules` is not a route.)
2. **Is the trigger one that is emitted?** `alert.created` is evaluated by
   `app/workers/rule_evaluator.py` for every new alert (it claims rows whose
   `automation_rules_evaluated_at` is NULL — fusion-created alerts included), and
   `alert.updated` by the alert PATCH endpoint. Both call the same
   `run_rules_for_trigger`. `case.created` and `manual` are stored and listed as
   **(inert)**; nothing fires them.
   *Is this alert already marked?* If `automation_rules_evaluated_at` is set, creation
   evaluation was claimed. A claim whose evaluation died is not retried by design (a
   duplicated containment action is worse than a missed passive rule); re-queue it with
   `UPDATE alerts SET automation_rules_evaluated_at = NULL WHERE id = '<alert>';`.
   *Is the worker running?* It is inert when `AISOC_RUNBOOK_ENABLED` is off or
   `AISOC_RULE_EVALUATOR_ENABLED=false`, and it needs `DATABASE_URL`. Its log line is
   `rule_evaluator pass` with `claimed`/`evaluated`/`failed`.
3. **Is the rule enabled, and is its `subject_type` the one being triggered?** The
   executor's query filters on both; `NULL`/`all` stay catch-all.
4. **Do the conditions reference fields the executor actually puts in the subject?**
   `alert_subject_fields()` is the single source of truth for both the live path and
   the editor preview, so a field that is offered there is evaluated. A condition on a
   field the alert row does not carry (e.g. `risk_score`, which exists only in the API
   response) can never match.
5. **Did the gate stop it?** A matching rule whose action is blocked writes a `denied`
   or `recorded` ledger row and, for containment/case actions, one `approval_gate`
   task. Check `GET /api/v1/runbook/alert/{id}` for the row rather than assuming
   silence means no match.

Run the focused suites before changing any of this:

```bash
cd services/api && poetry run python -m pytest tests/test_automation_rule_subject_fields.py \
    tests/test_runbook_automation.py tests/test_runbook_rule_authoring.py -q
```

`test_automation_rule_subject_fields.py` is the guard that keeps `_ALLOWED_FIELDS`,
`alert_subject_fields()` and the default rules in agreement.

## Data model

`runbook_tasks` (migration 064 + 065):

- `signature` — evidence fingerprint from the triage run, keys the outcome prior.
- `uq_runbook_tasks_open_gate` — partial unique index on
  `(tenant_id, alert_id, title)` where `task_type='approval_gate' AND status<>'completed'`,
  so a blocked action queues once even though it is re-evaluated on every alert update.
- RLS enabled to match `runbook_events`; query-layer `tenant_id` filtering remains the
  primary gate.

`runbook_templates` was dropped in migration 065. It backed the retired visual editor
and had no API, no UI and no rows.

## Checklist for changes in this area

```bash
cd services/api && poetry run python -m pytest tests/test_runbook_alignment.py \
    tests/test_runbook_automation.py tests/test_runbook_gate.py \
    tests/test_automation_rule_packs.py -q
cd services/agents && poetry run python -m pytest tests/test_outcome_feedback.py \
    tests/test_fused_alert_worker.py -q
pnpm --filter @aisoc/web type-check
pnpm --filter @aisoc/web vitest run src/components/runbook
```
