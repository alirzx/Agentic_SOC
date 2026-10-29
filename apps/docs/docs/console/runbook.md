---
title: Runbook
sidebar_position: 8
---

# Runbook

The Runbook page answers four questions about one subject — an alert, a case, or an
incident:

| Question | Where it is answered |
| --- | --- |
| What **should** happen, in order? | **Expected procedure** stepper |
| What **did** happen, and why was it allowed? | **Ledger** tab |
| What is **blocked right now** and needs a human? | **Action Plan** tab |
| Did the human agree with the machine? | Task feedback (outcome memory) |

The Runbook is not a workflow engine and not a SOAR canvas. The platform's auto-triage
engine already handles the routine path; the Runbook is the control plane around it.

## Relationship to Workflow SOC

**Workflow SOC** (`/workflow-soc` in the app) is the executive diagram: six stages from connector
ingest to a Jira ticket, animated, no live data. The Runbook is where those stages
stop being automatic. The two are linked in both directions, and only where the
destination is real:

| Lifecycle stage | Runbook surface it opens |
| --- | --- |
| 02 · Detect & Fuse | Detect & Fuse tab — the alerts the spine produced, with rule, source and fusion state |
| 04 · Verdict & Copilot | Action Plan filtered to `manual_review` |
| 05 · Approved Response | Action Plan filtered to `approval_gate` |

Selecting one of those cards (or arriving with `?stage=detect` / `?stage=decide` /
`?stage=respond`) shows a link into that surface. Stages 01, 03 and 06 have no link on
purpose — they own no surface here, and pointing them at an unrelated screen would
make the diagram a lie.

In the other direction, **View lifecycle →** in the Runbook header opens Workflow SOC
on the stage the current tab enforces (Ledger → `investigate`, Detect & Fuse →
`detect`, Action Plan → `decide`, Automation Rules → `detect`, Governance → `respond`)
and pauses the animation there.

## Tabs

### Detect & Fuse

The evidence behind Workflow SOC stage 02: the most recent alerts the fusion spine
promoted, one row each, with the detection rule that fired (`rule_id` / `rule_name`),
the producing connector, how many duplicate events it absorbed, and how fusion treated
it — windowed **incident**, **merged** child, or **standalone**.

Every value is read from a persisted column on the alert. A row with no rule recorded
says so rather than borrowing the alert title, and the header counts describe the rows
on screen ("last 50 promotions"), not the whole history. Deeper lineage — contributing
events, historical false-positive rate, the correlation narrative — stays behind
**Explain** on the alert itself.

### Ledger

Every governed action taken against the selected subject: who acted (`connector`,
`system`, `agent`, `analyst`), which policy allowed it, and the outcome. Entries come
from two sources, both read-only here:

- `runbook_events` — analyst actions (status, tags, assignee, case link, escalation),
  automation-rule outcomes, connector ingest provenance, ITSM updates.
- the investigation ledger — the auto-triage verdict and confidence, shown as an
  `agent` step in the `triage` stage. It is read from the agent ledger rather than
  copied, so the two cannot disagree.

Pick a subject by UUID, or click **Runbook →** on an alert row. The `Policy` sub-tab
lists only the steps that carry a governance decision.

### Action Plan

Only what the engine could not, or must not, finish alone:

| Task type | Created when | What the analyst does |
| --- | --- | --- |
| `manual_review` | auto-triage returned `needs_review` | Mark true positive / false positive, or escalate. The verdict is recorded as an analyst override. |
| `approval_gate` | a governed action was blocked by the autonomy ceiling, **or** a playbook run parked at an `approval` step | Approve or reject the action. A gate that belongs to a playbook run also continues (or cancels) that run. |
| `mssp_sla_check` | reserved — no SLA source is wired yet, so none are created | — |

Model feedback ("AI was right / AI was wrong") is optional. It is a grade of the
model; approving a blocked action is a governance decision and does not require one.

When you do submit feedback, it is sent to the agents service, which updates the
outcome prior for that alert's evidence signature — so the next alert of the same
family starts from what you taught it. If no prior exists, nothing is invented and
the update is reported as not applied.

A **Feedback loop** strip above the task lists states what that path actually did:
`3/5 analyst completions updated an outcome prior`, plus a count of feedback that
was submitted but moved nothing. The numerator comes from the agents service
confirming the update (`updated: true`), not from the feedback being sent; rows
written before migration 066 have no recorded result and are counted as not
applied. An empty strip means no analyst has graded the model yet.

### Automation Rules

Simple condition → action rules that fire on alert events. Every action goes through
the governance gate, and every outcome is recorded in the ledger. Rules are dry-run by
default. Authoring opens in a dialog; **Search** filters the list across the name,
description, action slug, trigger, autonomy level, owner, refs, and the conditions
themselves (typing `confidence` finds the rule that filters on it).

**Live preview.** The editor evaluates the rule-as-typed against the tenant's most
recent alerts, using the same evaluator and gate the executor uses, and states its
scope: *“Matches 2 of the last 20 alerts”*. That is why the separate **Test** button is
no longer part of the authoring loop — it still exists on a saved row for per-alert
detail, but nothing has to be saved to find out what a rule would match. Operator
errors surface there too: an unknown operator is reported as an error instead of
silently matching nothing.

What each field actually does:

| Field | Default | Behaviour |
| --- | --- | --- |
| Trigger | `alert.created` | Only `alert.created` and `alert.updated` are emitted today. `case.created` and `manual` are stored but marked **(inert)** — a rule using them never fires. |
| Subject type | `alert` | Enforced in the executor's rule query, so a case-scoped rule cannot fire on an alert event. `all` is a catch-all. |
| Autonomy ceiling | `L2` | The **stricter** of this and the platform policy wins. A rule capped at L1 turns an L4 auto-approval into a queued approval — it never silently refuses an action the policy allows. |
| Priority | `100` (1–9999) | Rules are evaluated lowest first, up to 50 per event. |
| Dry run | on | Records the governed decision without calling the vendor. |
| Owner team / Playbook / Doc path | empty | Reference only: they are displayed on the rule and do not route or execute anything. |

Condition fields are exactly the keys the executor puts in the subject dict. A field
that is not there can never match, so it is not offered — this is why `risk_score`
(exists in the alert API response but not on the `alerts` table) is absent.

### Governance

The action catalog: blast radius, autonomy thresholds (`auto` / `review` /
`escalation`), and the audit, data-safety, failure and cost contracts for every action
the platform may take. Thresholds resolve as shipped defaults → site YAML → per-tenant
override.

**Search** filters the catalog by human label, action slug, category and blast radius,
and composes with the category buttons — searching `isolate` and filtering to
*Containment* narrows to the same row. The header reports `N of M actions` whenever a
search or filter is active.

## Relationship to Playbooks

A playbook is the *how*: an ordered list of governed steps. The Runbook is the *who
and whether*: which rule proposes it, who approved it, and what the ledger records
once it runs. Two hard boundaries are worth knowing:

- **An `approval` step parks the run.** The engine stops at that step, records it as
  `blocked`, and sets the run to `pending_approval`; nothing after the gate executes.
  A dry run reports the gate as skipped (`would_require_approval`) because a dry run
  executes nothing anyway.
- **A step kind with no handler fails the run.** It is not skipped silently. The run
  stops with `no handler implemented for step type '<kind>'` even when the step's
  `on_failure` is `continue` — a containment step that quietly did nothing is worse
  than a stopped playbook. The gallery flags any playbook containing such a kind
  (`N step types cannot run`), because the editor only offers kinds that have handlers.

Approving in the Action Plan **resumes** the run from the step after the gate; rejecting
ends it as `cancelled`. The mechanics are described under
[Resuming a parked run](#resuming-a-parked-run).

## Resuming a parked run

A gate is only useful if it can be cleared. Three pieces make that real:

- **The run is durable.** A parked run is written to `playbook_runs` (status,
  context, step results, the index of the step to resume at, and a frozen copy of the
  playbook definition). A restart, a deploy, or a different worker no longer loses it.
- **The gate appears in the Action Plan.** Parking creates one `approval_gate` task —
  *Approve Playbook: \<playbook\> → \<step\>* — with `playbook_run_id` pointing at the
  run. One open task per run, enforced by a partial unique index.
- **The decision is explicit.** The buttons send `decision: approve | reject`; nothing
  is inferred from the free-text notes.

What happens on each decision:

| Decision | Run | Steps executed |
| --- | --- | --- |
| **Approve & resume** | `running` → `completed` / `failed` | Only the steps *after* the gate. Steps before it are never re-run. |
| **Reject run** | `cancelled` | None. The reason records who rejected it. |

Resume executes the playbook **as it was when the gate was reached**, not the current
edit — an analyst approves a specific set of steps, and an edit made while the run
waited must not ride along. If the snapshot no longer contains the resume step, the run
fails with `gate step no longer present in the playbook snapshot` rather than guessing.

After completion the task row states what actually happened: **Playbook resumed** when
the agents service confirmed the run moved, or **Decision recorded · run not resumed**
when it did not — a 4xx/5xx, an unconfigured signing key, or a run that changed state
underneath the click. The second case is amber on purpose: a recorded decision that
released nothing is exactly the failure this surface exists to make visible.

Two boundaries worth knowing:

- **`playbooks:approve` is its own permission.** Clearing a gate releases the steps it
  guards (`isolate_host`, `disable_user`, …), so it is not implied by
  `playbooks:execute`: a tier-1 analyst may start a playbook without being able to
  rubber-stamp its own gate. SOC leads and tenant admins hold it; `soc_analyst` does
  not. Governance gates created by the autonomy ceiling (no playbook run behind them)
  keep their existing contract.
- **Retention.** `playbook_runs` rows are kept for audit. The bulky columns
  (`playbook_snapshot`, `context`, `step_results`) are cleared after 90 days by
  `python -m app.scripts.prune_playbook_runs --days 90`; parked runs are never pruned
  because they are still waiting on a human.

## Relationship to SOC Funnel

The funnel board (`/soc-funnel`) answers *what happened to all the alerts*; the Runbook
answers *why this one is stuck, and what to do next*. They are now connected in both
directions:

- Each stage column reports **N waiting on an analyst** — open `runbook_tasks` joined to
the alerts in that stage. A column of 50 alerts with none of these is a throughput
number; with 37, it is a diagnosis.
- Each funnel card shows the task types blocking that alert (`needs review`,
  `approval`) and carries a **Runbook →** link to `/runbook/alert/<id>`, where the
  procedure stepper shows the blocked stage and the Action Plan holds the action.
- **Open Runbook** in the header jumps to the analyst queue (`?tab=action-plan`).

The board degrades quietly if `runbook_tasks` does not exist yet: badges disappear and
the stage counts still render.

Bulk operations on this page (backfill, remove duplicates, Splunk re-enrich) are written
to the immutable `audit_log` as `soc_funnel:backfill` / `:dedupe_exact` /
`:reenrich_splunk`, with counts and the `dry_run` flag. They are tenant-wide actions, so
they do not belong in the per-subject `runbook_events` ledger.

## Reading the procedure stepper

| Status | Meaning |
| --- | --- |
| **done** | The ledger has evidence for this stage. |
| **skipped** | A later stage has evidence but this one does not — the procedure did not need it (e.g. an auto-closed alert never reaches `investigate`). |
| **blocked** | A task is waiting for a human at the first unreached stage. |
| **pending** | Not reached yet. |

## Configuration

| Variable | Purpose |
| --- | --- |
| `AISOC_RUNBOOK_ENABLED` | Turns the ledger and rule engine on. Unset means "on in development, off elsewhere". |
| `AISOC_AGENTS_TENANT_SIGNING_KEY` | Shared HMAC key the API uses to send analyst feedback to the agents service. When unset, feedback is not forwarded (it is never sent unsigned). |
| `AISOC_AGENTS_ALLOW_UNSIGNED_TENANT_HEADER` | Development escape hatch on the agents service. Leave `0` outside local dev. |
| `AISOC_PLAYBOOK_RESUME` | Turns on resumable playbook approvals (gate tasks + `POST /api/v1/playbooks/runs/{id}/resume`). Default **off**: with it off a parked run creates no task and the resume endpoint answers 503, so the UI never promises a continuation that is not wired. |
