# Design — Resumable Playbook Runs (approval that actually continues)

Status: **implemented** (Phase 12, 2026-10-29) — see `docs/plans/RUNBOOK-PROGRESS.md`
§ Phase 12 for the shipped tasks, the answers to § 12's open questions, and the three
defects found on the way (run-id mismatch, Run History field mismatch, parked runs lost
on restart). § 12 is kept as written for the record; its decisions live in Phase 12.

Date: 2026-10-29 · Owner: Runbook surface

Related: `docs/plans/RUNBOOK-PROGRESS.md` Phase 11 (the fail-closed engine change this
builds on), `apps/docs/docs/console/runbook.md` § "Relationship to Playbooks".

---

## 1. Problem

`services/agents/app/playbook/engine.py` now parks a run at an `approval` step
(`RunStatus.PENDING_APPROVAL`, step `StepStatus.BLOCKED`) instead of silently
continuing. That fix is complete and tested, but a parked run is a dead end:

| Fact | Consequence today |
| --- | --- |
| Runs live in the process-local `_runs` dict (`api/playbooks.py`) | A restart, deploy or scale-out loses every parked run |
| No resume endpoint exists | The gate can only *stop* a playbook, never release it |
| Agents already writes `runbook_tasks` (asyncpg, `investigator/ledger.py`) but nothing ties a task to a run | The analyst cannot see the gate in the Action Plan, and approving a task has nothing to approve |
| `playbook_ref` on an automation rule is reference-only | Nothing triggers a playbook from a rule, so the gap is currently latent rather than painful |

Closing this loop is a prerequisite for executing playbooks from automation rules: a
rule that starts a playbook with a gate would otherwise just fill memory.

## 2. Goals / non-goals

**Goals**

1. A run parked at an approval step survives a process restart and is visible to the
   analyst in the Action Plan.
2. Approving the task resumes the run **from the step after the gate**; rejecting it
   ends the run honestly (`cancelled`, with a reason).
3. Resume executes what the analyst approved, not a newer edit of the playbook.
4. No claim in the UI outlives the facts: if the resume call fails, the task says so.

**Non-goals (this design)**

- Executing a playbook from an automation rule (follow-on work, §9).
- Resume-after-failure, manual retry of arbitrary steps, or editing params mid-run.
- Multi-worker coordination for a run (one run is resumed by one caller, guarded by a
  status check; §7).
- Migrating in-flight in-memory runs: none of them are persisted, and on deploy they
  are lost. That is the status quo, not a regression.

## 3. Options considered

| Option | Why not |
| --- | --- |
| **A. Postgres `playbook_runs` (chosen)** | Matches every other store in the platform (per-tenant rows, RLS, SQL migrations). One row per run, JSONB blobs for context/results. Survives restarts without new infrastructure. |
| B. Redis key per run | Fast, but the platform treats Redis as ephemeral cache; an approval can wait hours and must not expire. Would also need a second tenancy story. |
| C. Keep runs in memory, resume by re-running the whole playbook | Re-executes the side effects already performed before the gate (`enrich`, `notify`, and any action the gate was meant to guard). Unacceptable. |
| D. Leave the gate as a stop-only signal | What ships today. Honest but useless: the analyst is told to approve something that cannot proceed. |

## 4. Data model

### 4.1 New table `playbook_runs` (migration `067_playbook_runs.sql`)

```sql
CREATE TABLE IF NOT EXISTS playbook_runs (
    id                UUID PRIMARY KEY,            -- == run_id
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    playbook_id       TEXT NOT NULL,
    playbook_name     TEXT NOT NULL,
    -- Frozen definition captured when the run parks. Resume must execute the
    -- version the analyst approved, not whatever the playbook looks like now.
    playbook_snapshot JSONB NOT NULL,
    status            TEXT NOT NULL,               -- pending|running|pending_approval|
                                                   -- completed|failed|cancelled
    trigger_context   JSONB NOT NULL DEFAULT '{}',
    context           JSONB NOT NULL DEFAULT '{}', -- accumulated run context
    step_results      JSONB NOT NULL DEFAULT '[]',
    next_step_index   INTEGER,                     -- step to resume at (after the gate)
    gate_step_id      TEXT,                        -- which approval step parked it
    gate_step_name    TEXT,
    decision_by       TEXT,                        -- actor email/id that decided
    decided_at        TIMESTAMPTZ,
    error             TEXT,
    started_at        TIMESTAMPTZ,
    finished_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_playbook_runs_tenant_created
    ON playbook_runs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_pending
    ON playbook_runs (tenant_id) WHERE status = 'pending_approval';

ALTER TABLE playbook_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY playbook_runs_tenant_isolation ON playbook_runs
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
```

Query-layer `tenant_id` filtering remains the primary isolation gate, as everywhere else;
RLS is defence-in-depth.

### 4.2 `runbook_tasks` additions (same migration)

```sql
ALTER TABLE runbook_tasks ADD COLUMN IF NOT EXISTS playbook_run_id UUID;
ALTER TABLE runbook_tasks ADD COLUMN IF NOT EXISTS resume_applied BOOLEAN;

-- One open gate per run: re-entering the same gate cannot create two tasks.
CREATE UNIQUE INDEX IF NOT EXISTS uq_runbook_tasks_playbook_run
    ON runbook_tasks (playbook_run_id)
    WHERE playbook_run_id IS NOT NULL AND status <> 'completed';
```

`resume_applied` mirrors the existing `feedback_applied` pattern (migration 066): `TRUE`
= the agents service confirmed the run continued, `FALSE` = approve was recorded but the
run did not move, `NULL` = not an approval task / no attempt. The UI must render all
three distinctly.

### 4.3 Why persist only at boundaries

The engine writes the row at three moments: run start, gate reached, terminal state. Not
per step. Per-step writes would add a round trip to every `enrich`/`notify` step for no
resumption value, since only a gate can park a run.

## 5. Engine changes (`services/agents/app/playbook/engine.py`)

1. Extract the step loop into `_execute(pr, *, start_index: int)` so it can be entered at
   an index. `run()` keeps its signature and calls `_execute(pr, start_index=0)`.
2. Add `PlaybookRun.from_state(...)` that rebuilds a run from a `playbook_runs` row
   (playbook from `playbook_snapshot`, `context`, `step_results`, `run_id`).
3. At the gate, before breaking: persist `status='pending_approval'`,
   `next_step_index=current_idx + 1`, `gate_step_id`, `gate_step_name`, `context`,
   `step_results`.
4. On `resume(decision)`:
   - `approve` → status `running`, clear `error`, `_execute(start_index=next_step_index)`.
   - `reject` → status `cancelled`, `error="rejected by <actor>"`, `finished_at=now()`.
   - Guard: the snapshot's step at `next_step_index` must exist; otherwise fail with
     `gate step no longer present in the playbook snapshot`.
5. Terminal states (`completed`/`failed`/`cancelled`) persist the final row.

## 6. Service wiring

### 6.1 Agents: create the task when parking

Where the run parks (§5.3), call a new
`services/agents/app/playbook/approvals.py::create_playbook_gate_task(...)` using the
existing asyncpg pool pattern from `investigator/ledger.py`:

```
runbook_tasks (
  id, tenant_id, alert_id (from trigger_context["alert_id"] if present),
  task_type='approval_gate',
  title='Approve Playbook: <playbook name> → <step name>',
  description='Run <run_id> is paused at <step name>. Approving continues from the next
               step; rejecting ends the run. Playbook: <playbook_id>',
  status='pending', created_by='system', signature=NULL, playbook_run_id=<run_id>
)
```

Best-effort like the existing writers: no DB → the row is not created, the run stays
parked, and the failure is logged. The park itself must never depend on the task write.

### 6.2 Agents: resume endpoint

`POST /api/v1/playbooks/runs/{run_id}/resume` in `services/agents/app/api/playbooks.py`,
authenticated exactly like `api/outcomes.py` (`resolve_request_tenant`, HMAC-signed
`X-Tenant-Id` + `X-AiSOC-Tenant-Signature`); 401 without a tenant.

Body: `{"decision": "approve" | "reject", "actor": "<email or id>"}`.

| Case | Response |
| --- | --- |
| run not found **or belongs to another tenant** | `404` (same answer — no existence leak) |
| status is not `pending_approval` | `409 {"detail": "run is <status>", "idempotent": true}` |
| approve, resumed | `200 {"status": "running"|"completed"|"failed", "resumed": true}` |
| reject | `200 {"status": "cancelled", "resumed": false}` |
| flag `AISOC_PLAYBOOK_RESUME` off | `503` (surface is not enabled) |

### 6.3 API: call it from the approval task

`services/api/app/services/agents_client.py::resume_playbook_run(run_id, decision, actor)`
— same signing helper and best-effort `bool` return as `post_outcome_feedback`.

In `runbook.py::complete_runbook_task`, when the row is an `approval_gate` task with a
`playbook_run_id`:

1. decide `approved`/`rejected` from the body (`resolution` starts with "Approved"/"Rejected"
   today; §8 changes the UI to send an explicit field),
2. call `resume_playbook_run(...)`,
3. store `resume_applied = <bool>` in the same UPDATE, and log it.

Ordering mirrors Phase 6: call first, then write, so the row records what happened.

### 6.4 Feature flag

`AISOC_PLAYBOOK_RESUME` (default **off**). Gates both task creation (§6.1) and the resume
endpoint (§6.2). With it off, behaviour is exactly what ships today: the run parks, no
task appears, nothing claims it can continue. This is why the flag must gate both halves —
a task without a working resume is the lie this design exists to prevent.

## 7. Concurrency and idempotency

- One `runbook_tasks` row per run via the partial unique index (§4.2).
- Resume is guarded by a status transition; two approvals race into one winner and one
  `409`. `resume_applied=false` on the loser, so the second click is visible, not silent.
- The engine keeps a process-local lock per `run_id` during `_execute` to stop two
  overlapping resumes in a single worker; cross-worker safety rests on the status check
  and is documented as "one in-flight resume per run".

## 8. UI changes (`apps/web`)

- `ActionPlanView` completion dialog for `approval_gate` tasks that carry a playbook run:
  shows the playbook name, gate step, and run id; buttons become **Approve & resume** /
  **Reject run** and send an explicit `decision` field rather than inferring it from
  `resolution` text.
- After completion, the task row shows `resumed` / `not resumed` from `resume_applied`,
  including the failure reason when it is `false`.
- `RunbookTask` type gains `playbook_run_id` and `resume_applied`.
- Playbooks → Run History: a parked run renders `pending_approval` (badge already added in
  Phase 11) and links to the Runbook task when one exists.

## 9. Follow-on (explicitly out of scope)

Automation rule → playbook execution: in `rule_executor`, a matching rule with
`playbook_ref` would start the linked playbook through the same gate. It is small once
§4–§6 exist, and unsafe before: the gate would have nothing to resume. Separate design.

## 10. Test plan

| Layer | Test |
| --- | --- |
| Engine | parked run persists `next_step_index` and does not execute the guarded step (already covered for the in-memory case; new: row written) |
| Engine | `resume(approve)` continues at `next_step_index` and never re-runs earlier steps |
| Engine | `resume(reject)` → `cancelled`, no step executed |
| Engine | snapshot mismatch (step edited away) → `failed` with a clear reason |
| Loader | `PlaybookRun.from_state()` round-trips a persisted row |
| Agents API | 401 without tenant header; 404 cross-tenant; 409 double approve; happy path |
| API | `complete_runbook_task` writes `resume_applied` from the client result (true/false), and skips the call when there is no `playbook_run_id` |
| API | flag off → no task created, endpoint 503 |
| Web | approve sends `decision=approve`; `resume_applied=false` renders as not resumed |

## 11. Rollout

1. Migration 067 (additive; no backfill).
2. Deploy with `AISOC_PLAYBOOK_RESUME` off — nothing changes for users.
3. Turn it on per environment; watch `playbook_runs` for parked rows that never decide.
4. Document in `apps/docs/docs/console/runbook.md` and record in `RUNBOOK-PROGRESS.md` as
   Phase 12.

## 12. Open questions (need a decision before implementation)

1. **Retention** — keep `playbook_runs` forever (audit value) or prune terminal rows after
   90 days? Recommendation: keep, and prune only `context`/`step_results` blobs.
2. **Reject semantics** — `cancelled` (recommended, "a human ended it") vs `failed`
   ("the playbook broke"). They read very differently in Run History.
3. **Who may approve** — any user with `alerts:write` (today's task permission), or a
   narrower `playbooks:approve` permission? Recommendation: reuse `alerts:write` for now
   and note it.
