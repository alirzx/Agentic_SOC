# Runbook Alignment Review & Corrected Requirements

**Date Created:** 2026-10-29 10:26
**Status:** IMPLEMENTED (2026-10-30) — every requirement below landed; the evidence,
including the seven defects the review surfaced and the suites that cover them, is in
`docs/plans/RUNBOOK-PROGRESS.md` § Phase 13
**Scope of review:** `apps/web` Runbook surfaces + the API/agents code they call (working tree, uncommitted)
**Reviewed inputs:** `PLAN-20261027-1501-runbook-page.md`, `PLAN-20261028-1200-runbook-control-plane.md`,
`PLAN-20261028-1200-runbook-professional.md`, `PLAN-20261028-1710-runbook-restructure.md`,
`docs/plans/RUNBOOK-PROGRESS.md`, `docs/ahmadi/docs/AUTO_TRIAGE_ARCHITECTURE.md`,
`docs/ahmadi/docs/AUTO_TRIAGE_CODE_MAPPING.md`

---

## Goal

Answer one question with evidence, then convert the answer into requirements:

> The Runbook page currently displays several things. How much of that *is* a runbook,
> and what is actually missing for it to be the control plane the platform needs?

Deliverable: this document — a verified gap list, corrected minimal requirements, and a
file-level task plan that closes the gap without re-opening the scope questions that
`PLAN-20261028-1710-runbook-restructure.md` already settled.

---

## 1. The definition used for this review

A **runbook** is the standardized operational procedure for a security workflow: *what should
happen, in what order, and under which decision points* — plus the evidence that it happened
and the human brake where the machine must stop.

From that, one subject (alert / case / incident) must answer four questions:

| # | Question | Name in this review |
|---|---|---|
| Q1 | What **should** happen, in order, with decision points? | **Procedure** |
| Q2 | What **did** happen, by whom, and why was it allowed? | **Evidence** |
| Q3 | What is **blocked right now** and needs a human? | **Control (HITL)** |
| Q4 | **Did the human agree** with the machine (so the next run improves)? | **Feedback** |

The auto-triage engine (`fused_alert_consumer.py` → `run_auto_triage` → `should_auto_close` →
`passes_investigation_gate` → `case_promoter`) owns the happy path. Per the control-plane
requirement, the Runbook must not re-implement that path; it must own Q1, Q3, Q4 and present Q2
honestly.

---

## 2. Verified current state (file:line, working tree)

| Surface | Implementation | What it actually is |
|---|---|---|
| `/runbook` — **Ledger** tab | `apps/web/src/app/(app)/runbook/page.tsx:138-260` → `RunbookPage.tsx` → `internal.tsx` | Historical log of `runbook_events` rows for one subject (`services/api/app/services/runbook/read.py:76-84`) |
| `/runbook` — **Action Plan** tab | `apps/web/src/components/runbook/ActionPlanView.tsx` | List of `runbook_tasks` from `GET /runbook/tasks` (`services/api/app/api/v1/endpoints/runbook.py:1145`) |
| `/runbook` — **Automation Rules** | `AutomationRulesView.tsx` (1038 lines) → `/runbook/automation-rules*` | Condition→action rules with a policy gate (`services/api/app/services/runbook/rule_executor.py`) |
| `/runbook` — **Governance** | `GovernanceView.tsx` → `GET /runbook/governance` (`runbook.py:765`) | Static action catalog with blast radius + 4 contracts (`action_catalog.py`, `contracts.py`, `gate.py`) |
| Alert detail "runbook" sub-tab | `AlertDetailView.tsx:991,1331` | Same `RunbookPage` embedded per alert |
| Deep link | `AlertsView.tsx:256` → `/runbook?type=alert&id=<uuid>` | Client-side subject resolution (`page.tsx:56-66`) |
| Realtime | `services/realtime/src/index.ts:188,295-297,569-621` | `/ws/runbook` channel consuming `aisoc.runbook.task_updates` |
| Task creation (only path) | `ledger.py::create_task_for_needs_review` ← `fused_alert_consumer.py:883` | Task is created **only** for `needs_review` verdicts |
| Table | `services/api/migrations/064_runbook_tasks.sql` | 15 columns, 6 indexes, **no RLS** |
| Feedback | `outcomes.py::record_analyst_feedback` (`:117`) | **Zero callers** |

The pipeline `Connectors → ingest → Kafka → fusion → fused_alert_consumer` is unchanged by the
Runbook work; the Runbook is a read/control layer on top of it. That part of the design is sound.

---

## 3. Alignment scorecard

| | Requirement | Verdict | Why |
|---|---|---|---|
| Q1 | Procedure (ordered expected steps + decision points) | **ABSENT** | Nothing renders "what should happen". `workflow_name`/`workflow_objective` are synthesized strings: `f"{subject_type.capitalize()} operational workflow"` (`read.py:93-100`). The only authoring surface (`RunbookEditorView.tsx`) is orphaned dead code. |
| Q2 | Evidence (what happened) | **PARTIAL** | Records API-side analyst actions, case creation, ITSM, rules, and connector provenance (`emitters.py`, `materialize.py`, `splunk_enrichment.py`). Does **not** record the auto-triage decision itself — see D4. |
| Q3 | Control / HITL | **PARTIAL** | `manual_review` tasks work end-to-end. `approval_gate` is dead code. `mssp_sla_check` is never created. The Action Plan ignores the selected subject. |
| Q4 | Feedback → learning | **ABSENT** | Completing a task writes `feedback_to_llm` to the row and a log line. `record_analyst_feedback()` is never invoked; the docstring in `emitters.py:22-25` claims triage steps are "shown by the Runbook view with their real source", which is not true either. |

**Verdict: the page is a well-built *governance ledger + rule cabinet*, and a *half-wired*
control plane. It is not yet a runbook, because Q1 is missing and Q4 is a stub.**

Worse, two comments promise behaviour the code does not have (`emitters.py:22-25`,
`runbook.py::complete_runbook_task` docstring). Those are the "stub presented as working"
pattern the repo forbids; they must be fixed or removed in the same pass.

---

## 4. Defects found (evidence-based)

### D1 — P0 — Analyst feedback never reaches the model
`runbook.py:1223-1290` updates the row, commits, then `logger.info(... "Analyst feedback recorded
for LLM model training")`. `grep record_analyst_feedback` returns the definition only. The UI
presents this as training the model (`ActionPlanView.tsx` "Feedback to AI Model"). Either wire it
or stop claiming it.

### D2 — P0 — `approval_gate` tasks are never created
`create_task_for_approval_gate()` exists at `runbook.py:1111` and has **no caller**. The gate
that would trigger it (`services/api/app/services/runbook/gate.py::decide`, used at
`rule_executor.py:128` and `runbook.py:676`) records a `deny`/`escalate` decision into the ledger
and stops there. So L2/L3 containment requests produce no approval queue item — the exact gap
the control-plane requirement names.

### D3 — P0 — Action Plan ignores the selected subject
`ActionPlanView.tsx:70-74` sends `?alert_id=<uuid>`; `list_runbook_tasks` (`runbook.py:1145-1160`)
accepts only `status`, `task_type`, `skip`, `limit`. FastAPI ignores the unknown query param, so
the tab silently shows **every tenant task** regardless of the subject chosen in the Ledger tab.

### D4 — P1 — The auto-triage decision is missing from the ledger
`read.py:76-84` reads `runbook_events` only. Nothing writes triage verdicts there: the agent side
persists them to `investigation_runs` / `investigation_events` (`ledger.py:412-444`, event kind
`triage_verdict`, run `case_id = str(alert_id)`). So the "Automated Trace" the control-plane spec
requires (Alert received → LLM triage → verdict/confidence) is invisible in the Runbook.

### D5 — P1 — No procedure definition at all (Q1)
See scorecard. Restructure declared the visual editor out of scope; no replacement defines the
expected sequence, so the page cannot tell an analyst what to do next.

### D6 — P1 — Action Plan is light-themed inside a dark console
`ActionPlanView.tsx` uses `bg-white`, `text-slate-900`, `bg-red-50`, `bg-emerald-50`,
`border-slate-200` (9 occurrences) while every sibling runbook surface is dark
(`bg-slate-950/30`, `text-slate-200`). It also uses raw `alert()` for errors
(`ActionPlanView.tsx:170,212`) instead of the inline error pattern in `internal.tsx` /
`GovernanceView.tsx`.

### D7 — P1 — Task semantics collapsed into one generic action
Every task type renders the same "Complete" → "Complete & Provide Feedback" flow, where feedback
is **mandatory** (`ActionPlanView.tsx:150-155`). An `approval_gate` needs Approve/Reject on the
*action*; an `mssp_sla_check` needs a checklist; only `manual_review` needs model feedback.

### D8 — P2 — Three dead artifacts on disk
- `apps/web/src/components/nav/RunbookNav.tsx` — never rendered; its links
  (`/runbook/alert`, `/runbook/case`, `/runbook/incident`) do not exist as routes.
- `apps/web/src/lib/runbook.api.ts` — `createRunbookApi` has no importer.
- `apps/web/src/components/runbook/RunbookEditorView.tsx` — no references; contradicts
  `RUNBOOK-PROGRESS.md` step 3.8 which marks it "shipped".

### D9 — P2 — `runbook_tasks` has no RLS
`064_runbook_tasks.sql` creates the table without `ENABLE/FORCE ROW LEVEL SECURITY`, while 062
does both for `runbook_events`. Query-layer `WHERE tenant_id` is present and correct in all four
endpoints, so this is defence-in-depth parity, not a live leak.

### D10 — P2 — No SLA path
`due_at` exists in the schema and is rendered (`ActionPlanView.tsx:380`), but no code path ever
sets it and `mssp_sla_check` is never created, so the SLA surface is empty by construction.

### D11 — P2 — Duplicated subject plumbing and types
`RunbookEnvelope` is declared three times (`runbook.types.ts`, re-exported in the dead
`runbook.api.ts`, and inline in `runbook/[subjectType]/[subjectId]/page.tsx:19-40`). Two entry
points (`?type=&id=` and `/runbook/{type}/{id}`) both exist.

### D12 — P2 — No test coverage for the Action Plan surface
`AutomationRulesView.test.tsx` exists (153 lines); there is no test for `ActionPlanView` and no
backend test asserting task tenant isolation or the feedback hand-off.

---

## 5. Corrected requirements (minimal, ordered)

- **R1 — Feedback closes the loop, or is removed.** Completing a `manual_review` task updates the
  tenant's outcome prior for that alert signature. If the prior does not exist, the call is a
  no-op, not a fake success. Acceptance: `feedback_to_llm='poor'` on a task with signature `S`
  lowers `aisoc_institutional_memory` confidence under key `outcome:S` by 0.10 (floored at 0.01)
  and sets `last_analyst_feedback`.
- **R2 — Every blocked action appears in the queue.** A gate decision of `REVIEW`/`ESCALATE`/
  `REJECT` on a containment or case action creates one `approval_gate` task, idempotently.
  Acceptance: two identical denied decisions produce one pending task, not two.
- **R3 — The Action Plan is per-subject when a subject is selected.** `GET /runbook/tasks` filters
  by `alert_id` / `case_id` when supplied. Acceptance: selecting alert A shows only A's tasks.
- **R4 — Triage evidence is visible for the alert.** The Ledger shows the auto-triage verdict and
  confidence with actor `agent` and stage `triage`, sourced from `investigation_events`
  (kind `triage_verdict`) — read, never copied.
- **R5 — A procedure exists.** For each subject type the page renders the expected ordered stages
  (ingest → enrich → triage → investigate → funnel → respond → close) with a per-stage status
  derived from evidence: `done`, `pending`, `skipped`, or `blocked`. No free-form authoring, no
  canvas. Acceptance: an alert with only a triage verdict shows `ingest: done`, `triage: done`,
  `investigate: pending`, and names the gate that will decide it.
- **R6 — Task actions match task type.** `manual_review` → Mark TP / Mark FP / Escalate +
  optional model feedback. `approval_gate` → Approve / Reject (action decision, feedback
  optional). `mssp_sla_check` → checklist completion. Acceptance: an analyst can approve an
  approval gate without being forced to grade the model.
- **R7 — Visual and interaction parity.** Dark theme, inline errors, no `alert()`.
- **R8 — No dead code ships.** Delete or wire the three artifacts in D8; reconcile
  `RUNBOOK-PROGRESS.md` so its ✅ marks match the tree.
- **R9 — Isolation and tests.** RLS parity for `runbook_tasks`; tests for tenant isolation on
  `/runbook/tasks*`, for feedback forwarding, and for `ActionPlanView` filtering.

### Explicitly out of scope (already decided, do not reopen)

SOAR execution, canvas/visual template authoring, a general workflow engine, MSSP billing/SLA
engine, and any change to the fusion/triage happy path. `mssp_sla_check` stays schema-only until a
tenant-facing SLA source exists (R5 does not depend on it).

---

## 6. Step-by-step plan

Each task is independently shippable and independently testable. Do them in order; T1–T4 are the
feedback chain, T5–T7 the control chain, T8–T9 the evidence/procedure surface, T10–T12 clean-up.

### Task 1 — Persist the evidence signature on a task

**Files:**
- Create: `services/api/migrations/065_runbook_task_signature.sql`
- Modify: `services/api/app/models/runbook_task.py` (after `feedback_to_llm`, ~line 40)

```sql
-- 065_runbook_task_signature.sql
-- The agents service computes an evidence fingerprint at triage time and keeps it
-- only in Redis. A task must carry it so analyst feedback can update the same prior.
ALTER TABLE runbook_tasks
    ADD COLUMN IF NOT EXISTS signature VARCHAR(200);

CREATE INDEX IF NOT EXISTS idx_runbook_tasks_signature
    ON runbook_tasks(signature) WHERE signature IS NOT NULL;
```

```python
# runbook_task.py
    signature: Mapped[str | None] = mapped_column(String(200), nullable=True)
```

- [ ] Step 1: add migration + model column
- [ ] Step 2: apply on a scratch DB, confirm `\d runbook_tasks` shows the column and index
- [ ] Step 3: `cd services/api && poetry run pytest tests/test_runbook_gate.py -q`
- [ ] Step 4: commit `feat(runbook): persist evidence signature on manual tasks`

### Task 2 — Populate the signature when the worker creates a task

**Files:**
- Modify: `services/agents/app/investigator/ledger.py:559-604` (`create_task_for_needs_review`)
- Modify: `services/agents/app/workers/fused_alert_consumer.py:883-895`

`fingerprint` is already in scope at the call site (`fused_alert_consumer.py:410`).

```python
# ledger.py — new keyword parameter
async def create_task_for_needs_review(
    *,
    alert_id: str | None,
    tenant_ref: str,
    confidence: float,
    rationale: str,
    signature: str | None = None,
) -> bool:
    ...
    INSERT INTO runbook_tasks
      (id, tenant_id, alert_id, task_type, title, description, status,
       created_by, created_at, signature)
    VALUES
      (uuid_generate_v4(), $1, $2, 'manual_review',
       'Verify Alert Triage (Low AI Confidence)', $3, 'pending', 'system', now(), $4)
    RETURNING id
    """, tenant_id, alert_uuid, description, signature)
```

```python
# fused_alert_consumer.py:883
task_created = await ledger_module.create_task_for_needs_review(
    alert_id=...,
    tenant_ref=...,
    confidence=...,
    rationale=...,
    signature=fingerprint,          # NEW
)
```

- [ ] Step 1: add parameter + SQL column, pass `fingerprint` at the call site
- [ ] Step 2: extend `services/agents/tests/test_fused_alert_worker.py` with a case asserting the
      inserted row carries the fingerprint the governor computed
- [ ] Step 3: `cd services/agents && poetry run pytest tests/test_fused_alert_worker.py -q`
- [ ] Step 4: commit `feat(runbook): carry evidence signature into manual tasks`

### Task 3 — Internal feedback endpoint on the agents service

**Files:**
- Create: `services/agents/app/api/outcomes.py`
- Modify: `services/agents/app/main.py` (import + `app.include_router(outcomes_router)`, no prefix)

Reuse the existing signed-tenant helper — do not invent a second auth scheme:
`services/agents/app/privacy/tenant.py::resolve_request_tenant(request)` returns a tenant only
for authenticated state or an HMAC-signed `X-Tenant-Id` header.

```python
# services/agents/app/api/outcomes.py
"""Internal outcome-feedback surface.

Called by services/api when an analyst completes a Runbook manual task. Authenticated
with the same HMAC-signed tenant header every tenant-scoped agent call uses; there is no
user session on this path.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.memory.outcomes import record_analyst_feedback
from app.privacy.tenant import resolve_request_tenant

# Every agents router declares its own /api/v1 prefix (see api/triage.py:47,
# api/alert_investigate.py:28) and is mounted without one in main.py:201-210.
router = APIRouter(prefix="/api/v1/outcomes", tags=["outcomes"])


class FeedbackIn(BaseModel):
    signature: str
    feedback: Literal["good", "poor"]
    alert_id: str | None = None


@router.post("/feedback")
async def post_feedback(body: FeedbackIn, request: Request) -> dict[str, bool]:
    tenant_id = resolve_request_tenant(request)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="tenant context required")
    prior = await record_analyst_feedback(
        tenant_id,
        body.signature.strip(),
        feedback=body.feedback,
        alert_id=body.alert_id,
    )
    # No prior => nothing to update. Report it honestly instead of faking success.
    return {"updated": bool(prior)}
```

- [ ] Step 1: add the router and mount it in `main.py`
- [ ] Step 2: test unsigned call → 401; signed call with unknown signature → `{"updated": false}`
- [ ] Step 3: signed call with a seeded prior → confidence moves exactly ±0.05/0.10
      (`services/agents/tests/test_outcome_feedback.py`, new)
- [ ] Step 4: `cd services/agents && poetry run pytest tests/test_outcome_feedback.py -q`
- [ ] Step 5: commit `feat(agents): internal analyst-feedback endpoint`

### Task 4 — Forward feedback from the API instead of logging it

**Files:**
- Create: `services/api/app/services/agents_client.py`
- Modify: `services/api/app/core/config.py` (new settings)
- Modify: `services/api/app/api/v1/endpoints/runbook.py:1270-1285` (replace the log block)

New settings: `AISOC_AGENTS_BASE_URL` (default `http://agents:8000` in compose,
`http://127.0.0.1:8001` locally) and `AISOC_AGENTS_TENANT_SIGNING_KEY` (must match the agents
service; already present in `infra/compose/docker-compose.demo.yml:230`).

The signature is HMAC-SHA256 over `b"aisoc-agents-tenant-v1" + b":" + tenant_id.encode()`,
identical to `tenant_signature()` in `services/agents/app/privacy/tenant.py:28`, sent as
`X-AiSOC-Tenant-Signature` with `X-Tenant-Id`.

```python
# agents_client.py
async def post_outcome_feedback(*, tenant_id: str, signature: str,
                                feedback: str, alert_id: str | None) -> bool:
    """Forward analyst feedback. Best-effort: the task is already committed."""
    ...
    resp = await client.post(f"{base_url}/api/v1/outcomes/feedback", json=payload, headers=headers)
    if resp.status_code != 200:
        logger.warning("agents_client.feedback_failed", status=resp.status_code)
        return False
    return bool(resp.json().get("updated"))
```

```python
# runbook.py — replaces the logger.info-only block
    if body.feedback_to_llm and row.signature:
        forwarded = await post_outcome_feedback(
            tenant_id=str(current_user.tenant_id),
            signature=row.signature,
            feedback=body.feedback_to_llm,
            alert_id=str(row.alert_id) if row.alert_id else None,
        )
        logger.info("runbook_task_feedback", task_id=str(tid),
                    forwarded=forwarded, feedback=body.feedback_to_llm)
```

Remove the misleading "recorded for LLM model training" wording; log `forwarded` truthfully.

- [ ] Step 1: client + settings + call site
- [ ] Step 2: test with a stub transport: 200 → `forwarded=true`; 500 → completion still 200 and
      the task row is committed (`services/api/tests/test_runbook_feedback.py`, new)
- [ ] Step 3: `cd services/api && poetry run pytest tests/test_runbook_feedback.py -q`
- [ ] Step 4: commit `feat(runbook): forward analyst feedback to outcome memory`

### Task 5 — Filter tasks by subject

**Files:**
- Modify: `services/api/app/api/v1/endpoints/runbook.py:1145-1160`
- Modify: `apps/web/src/components/runbook/ActionPlanView.tsx:66-76`

```python
async def list_runbook_tasks(
    db: DBSession,
    current_user: ...,
    status: str = Query(None),
    task_type: str = Query(None),
    alert_id: str = Query(None, description="Only tasks for this alert"),
    case_id: str = Query(None, description="Only tasks for this case"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> list[RunbookTaskOut]:
    q = select(RunbookTask).where(RunbookTask.tenant_id == current_user.tenant_id)
    if alert_id:
        q = q.where(RunbookTask.alert_id == _parse_uuid(alert_id, "alert_id"))
    if case_id:
        q = q.where(RunbookTask.case_id == _parse_uuid(case_id, "case_id"))
    ...
```

- [ ] Step 1: add both filters + client-side `subject_type === 'case'` branch
- [ ] Step 2: test that a task for alert B is absent when `alert_id=A`
      (`services/api/tests/test_runbook_tasks_isolation.py`, new — also asserts a second tenant's
      task never appears)
- [ ] Step 3: `cd services/api && poetry run pytest tests/test_runbook_tasks_isolation.py -q`
- [ ] Step 4: commit `fix(runbook): scope the action plan to the selected subject`

### Task 6 — Create approval-gate tasks from real gate decisions

**Files:**
- Modify: `services/api/app/services/runbook/rule_executor.py:120-160`
- Modify: `services/api/app/api/v1/endpoints/runbook.py:1111-1140` (add idempotency)

Rule: when `gate.decision` is not `AUTO` **and** the action's category is `containment` or `case`,
insert one `approval_gate` task keyed by `(tenant_id, alert_id, action)` — enforce with a partial
unique index rather than a read-then-write race:

```sql
-- append to 065_runbook_task_signature.sql
CREATE UNIQUE INDEX IF NOT EXISTS uq_runbook_tasks_open_gate
    ON runbook_tasks (tenant_id, alert_id, title)
    WHERE task_type = 'approval_gate' AND status <> 'completed';
```

Insert with `ON CONFLICT DO NOTHING` and log `created: true|false`.

- [ ] Step 1: unique index + `ON CONFLICT DO NOTHING` in `create_task_for_approval_gate`
- [ ] Step 2: call it from the `rule_executor` gate branch for containment/case actions
- [ ] Step 3: test: a `REVIEW` decision on `isolate_host` creates one task; re-running the same
      decision creates none (`services/api/tests/test_runbook_tasks_isolation.py`)
- [ ] Step 4: `cd services/api && poetry run pytest tests/test_runbook_tasks_isolation.py -q`
- [ ] Step 5: commit `feat(runbook): queue approval gates for blocked actions`

### Task 7 — Show triage evidence in the ledger (read-only union)

**Files:**
- Modify: `services/api/app/services/runbook/read.py:76-84` and the row loop at `:160-180`
- Modify: `services/api/app/services/runbook/emitters.py:22-25` (correct the false docstring)

`persist_auto_triage` writes `investigation_runs.case_id = str(alert_id)` and one
`investigation_events` row with `kind='triage_verdict'` (`ledger.py:412-444`). Read it, do not
copy it:

```sql
-- appended to _READ with UNION ALL, same column order
SELECT 1000 + e.seq                     AS seq,
       e.ts                             AS occurred_at,
       'triage'                         AS stage,
       'triage_verdict'                 AS kind,
       'auto_triage'                    AS action_name,
       'agent'                          AS actor_type,
       e.agent                          AS actor_label,
       e.summary                        AS summary,
       NULL                             AS detail,
       'recorded'                       AS status,
       NULL::jsonb                      AS policy
  FROM investigation_events e
  JOIN investigation_runs r ON r.id = e.run_id
 WHERE e.tenant_id = :tid
   AND e.kind = 'triage_verdict'
   AND :stype = 'alert'
   AND r.case_id = :sid::text
```

Keep the `1000 +` offset so agent rows never collide with `runbook_events.seq`, and sort by
`occurred_at` in Python before assigning the final `seq` the UI renders.

- [ ] Step 1: union + stable ordering; keep the empty-state behaviour unchanged
- [ ] Step 2: test: an alert with a persisted run shows one `triage` step citing the verdict and
      confidence; an alert without one still renders the honest empty state
- [ ] Step 3: `cd services/api && poetry run pytest tests/test_runbook_gate.py -q`
- [ ] Step 4: commit `feat(runbook): surface auto-triage evidence in the ledger`

### Task 8 — Add the procedure surface (Q1)

**Files:**
- Create: `services/api/app/services/runbook/procedure.py`
- Modify: `services/api/app/services/runbook/read.py` (extend the envelope)
- Modify: `apps/web/src/components/runbook/runbook.types.ts`
- Modify: `apps/web/src/components/runbook/RunbookPage.tsx` (new "Procedure" section above Actions)

Static, code-defined sequence per subject type — no authoring, no persistence:

```python
# procedure.py
PROCEDURES: dict[str, tuple[str, ...]] = {
    "alert": ("ingest", "enrich", "triage", "investigate", "funnel", "respond", "close"),
    "case":  ("funnel", "investigate", "respond", "itsm", "close"),
    "incident": ("triage", "investigate", "respond", "close"),
}

def derive_status(stages_done: set[str], stage: str) -> str:
    """done | skipped | pending — blocked is added when a task exists for the subject."""
    ...
```

`RunbookEnvelope` gains `procedure: list[{stage, stage_label, status, evidence_count,
blocked_by_task_id}]`. `blocked` is set when a pending `runbook_tasks` row exists for that subject.

- [ ] Step 1: procedure derivation + envelope field + tests for the three states
- [ ] Step 2: render the sequence as a compact stepper on the Runbook page, above Actions
- [ ] Step 3: `pnpm --filter @aisoc/web type-check` and `cd services/api && poetry run pytest tests/test_runbook_gate.py -q`
- [ ] Step 4: commit `feat(runbook): show the expected operational procedure`

### Task 9 — Task-type-specific actions in the Action Plan

**Files:**
- Modify: `apps/web/src/components/runbook/ActionPlanView.tsx`

- `manual_review`: Mark TP / Mark FP / Escalate (calls the existing alert disposition endpoint)
  plus optional model feedback.
- `approval_gate`: Approve / Reject → `POST /runbook/tasks/{id}/complete` with
  `resolution="approved"|"rejected: <reason>"`; feedback optional.
- `mssp_sla_check`: read-only checklist until a real SLA source exists; label it
  "awaiting SLA source" rather than pretending.
- Feedback becomes optional (`disabled={!completion.feedback}` → only required for
  `manual_review`).

- [ ] Step 1: per-type action rows; relax the feedback requirement
- [ ] Step 2: `apps/web/src/components/runbook/ActionPlanView.test.tsx` (new): filter by subject,
      approve without feedback, error renders inline
- [ ] Step 3: `pnpm --filter @aisoc/web test -- ActionPlanView`
- [ ] Step 4: commit `feat(runbook): task-type-specific analyst actions`

### Task 10 — Visual parity pass

**Files:**
- Modify: `apps/web/src/components/runbook/ActionPlanView.tsx` (all classes)

Replace `bg-white`/`text-slate-900`/`bg-*-50`/`border-slate-200` with the dark palette used in
`internal.tsx` and `GovernanceView.tsx`; replace `alert()` at lines 170 and 212 with an inline
`rounded border border-red-500/20 bg-red-500/10 text-red-400` banner.

- [ ] Step 1: class pass + inline errors
- [ ] Step 2: `pnpm --filter @aisoc/web type-check`
- [ ] Step 3: commit `style(runbook): align the action plan with the console theme`

### Task 11 — Delete dead artifacts, consolidate types

**Files:**
- Delete: `apps/web/src/components/nav/RunbookNav.tsx`, `apps/web/src/lib/runbook.api.ts`,
  `apps/web/src/components/runbook/RunbookEditorView.tsx`
- Modify: `apps/web/src/app/(app)/runbook/[subjectType]/[subjectId]/page.tsx` (import
  `RunbookEnvelope` from `runbook.types.ts` instead of redeclaring it)

- [ ] Step 1: delete + fix imports
- [ ] Step 2: `pnpm --filter @aisoc/web type-check` and `pnpm --filter @aisoc/web build`
- [ ] Step 3: commit `chore(runbook): remove dead runbook surfaces`

### Task 12 — Isolation parity, docs, and progress truth

**Files:**
- Modify: `services/api/migrations/065_runbook_task_signature.sql` (RLS block)
- Modify: `docs/plans/RUNBOOK-PROGRESS.md` (reconcile ✅ marks with the tree)
- Create: `docs/operations/runbook.md` (what Runbook is and is not; the four questions; task types)
- Create: `apps/docs/docs/console/runbook.md` (user-facing)

```sql
ALTER TABLE runbook_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE runbook_tasks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runbook_tasks_tenant ON runbook_tasks;
CREATE POLICY runbook_tasks_tenant ON runbook_tasks
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);
```

- [ ] Step 1: RLS block + docs
- [ ] Step 2: correct `RUNBOOK-PROGRESS.md` (mark 3.8 as removed, not shipped; record that
      `PLAN-20261028-1200-runbook-control-plane.md` names three files that do not exist)
- [ ] Step 3: full gate — `cd services/api && poetry run pytest -q`,
      `cd services/agents && poetry run pytest -q`, `pnpm type-check`
- [ ] Step 4: commit `docs(runbook): document scope and reconcile progress`

---

## 7. Modified Files Log

| Task | File | Change | Status |
|---|---|---|---|
| — | `docs/plans/PLAN-20261029-1026-runbook-alignment.md` | created (this review) | [x] |
| 1 | `services/api/migrations/065_runbook_task_signature.sql` | create | [ ] |
| 1 | `services/api/app/models/runbook_task.py` | signature column | [ ] |
| 2 | `services/agents/app/investigator/ledger.py` | accept + store signature | [ ] |
| 2 | `services/agents/app/workers/fused_alert_consumer.py` | pass `fingerprint` | [ ] |
| 3 | `services/agents/app/api/outcomes.py` | create | [ ] |
| 3 | `services/agents/app/main.py` | mount router | [ ] |
| 4 | `services/api/app/services/agents_client.py` | create | [ ] |
| 4 | `services/api/app/core/config.py` | agents base URL + signing key | [ ] |
| 4 | `services/api/app/api/v1/endpoints/runbook.py` | forward feedback | [ ] |
| 5 | `services/api/app/api/v1/endpoints/runbook.py` | `alert_id`/`case_id` filters | [ ] |
| 5 | `apps/web/src/components/runbook/ActionPlanView.tsx` | case branch | [ ] |
| 6 | `services/api/app/services/runbook/rule_executor.py` | create approval gate task | [ ] |
| 6 | `services/api/app/api/v1/endpoints/runbook.py` | idempotent insert | [ ] |
| 7 | `services/api/app/services/runbook/read.py` | triage union | [ ] |
| 7 | `services/api/app/services/runbook/emitters.py` | fix false docstring | [ ] |
| 8 | `services/api/app/services/runbook/procedure.py` | create | [ ] |
| 8 | `apps/web/src/components/runbook/RunbookPage.tsx` | procedure stepper | [ ] |
| 9 | `apps/web/src/components/runbook/ActionPlanView.tsx` | per-type actions | [ ] |
| 10 | `apps/web/src/components/runbook/ActionPlanView.tsx` | dark theme | [ ] |
| 11 | `RunbookNav.tsx`, `runbook.api.ts`, `RunbookEditorView.tsx` | delete | [ ] |
| 12 | `065_...sql`, `RUNBOOK-PROGRESS.md`, `docs/operations/runbook.md` | RLS + docs | [ ] |

---

## 8. Risks & dependencies

| Risk | Impact | Mitigation |
|---|---|---|
| `investigation_runs.case_id` doubles as the alert id for auto-triage runs | The union in T7 may match a real case id in future data | Guard with `model_used LIKE 'kafka:auto_triage:%'`; add a proper `alert_id` column in a later migration |
| Cross-service HTTP from API → agents adds a runtime dependency | Feedback silently lost when agents is down | Best-effort, already-committed task row; `forwarded=false` is logged and surfaced |
| Agents endpoint auth depends on a signing key that the API never sent before | Endpoint could start open in a deployment with the key unset | Fail closed: `resolve_request_tenant` returns `None` when unsigned headers are not explicitly allowed outside dev |
| Unique partial index on `(tenant_id, alert_id, title)` | A second genuinely different gate for the same action is suppressed | Include the action slug in `title` (already the pattern) and document it |
| `RUNBOOK-PROGRESS.md` currently overstates delivery (3.8) | Future work is planned against a false baseline | T12 corrects it in the same pass as the code |
| Plan documents name files that do not exist | Contributors follow broken paths | Do not edit plan files (repo rule); record the corrections in `RUNBOOK-PROGRESS.md` instead |

---

## 9. Definition of done

- Completing a manual task with feedback changes the tenant's outcome prior (verified by test,
  not by log line).
- A blocked containment action appears exactly once in the Action Plan and is per-subject.
- Opening an alert's Runbook shows: the expected procedure with statuses, the triage verdict as
  evidence, the analyst/agent action history, and any pending human task — in that order.
- No dead Runbook file remains, and `RUNBOOK-PROGRESS.md` matches the tree.
