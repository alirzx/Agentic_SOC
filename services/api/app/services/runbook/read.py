"""Runbook read service — what happened to this subject, and why.

Powers ``GET /api/v1/runbook/{subject_type}/{subject_id}`` so the Runbook page
can render the governed action ledger for an alert / case / incident.

It is deliberately a thin, honest read: it projects ``runbook_events`` rows
into a view-model with no fabrication, no inference of steps the ledger does
not contain, and an explicit empty state for subjects that have never had a
governed action recorded.

Naming
------
* **Runbook** (this module, the ledger, the page) — "what happened and why it
  was allowed". Operational record.
* **Investigation brief** (``case_investigation_brief``) — "what did the
  agent / analyst do inside this case". A different, narrower question.
* **Operational runbook** (``docs/operations/*.md``) — "what should be done".
  A document, not a record.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.runbook.procedure import build_procedure

# ── view models ──────────────────────────────────────────────────────────────

STAGE_LABELS: dict[str, str] = {
     "ingest": "Ingest",
     "enrich": "Enrichment",
     "triage": "Triage",
     "investigate": "Investigation",
     "funnel": "Funnel",
     "respond": "Response",
     "itsm": "ITSM",
     "close": "Close",
     "policy": "Policy",
 }


class RunbookStep(BaseModel):
    seq: int
    occurred_at: datetime
    stage: str
    stage_label: str
    kind: str
    action_name: str | None = None
    actor_type: str
    actor_label: str | None = None
    summary: str
    detail: str | None = None
    status: str
    policy: dict[str, Any] | None = None


class ProcedureStage(BaseModel):
    """One expected step of the operational procedure for this subject."""

    stage: str
    stage_label: str
    status: str  # done | skipped | pending | blocked


class RunbookEnvelope(BaseModel):
    subject_type: str
    subject_id: str
    total_steps: int
    workflow_name: str
    workflow_objective: str
    supporting_rule_count: int = 0
    procedure: list[ProcedureStage] = Field(default_factory=list)
    steps: list[RunbookStep] = Field(default_factory=list)
    empty: bool = False
    empty_reason: str | None = None


# ── query ────────────────────────────────────────────────────────────────────

_READ = text(
    """
    SELECT
        seq, occurred_at, stage, kind, action_name,
        actor_type, actor_label, summary, detail, status, policy
      FROM runbook_events
     WHERE tenant_id = :tid
       AND subject_type = :stype
       AND subject_id = :sid
     ORDER BY seq ASC
    """
)

# The auto-triage decision is persisted by the agents service to the
# investigation ledger (``persist_auto_triage`` writes one ``triage_verdict``
# event per run and stores the alert id in ``investigation_runs.case_id``). It is
# read here rather than copied into ``runbook_events`` so the two ledgers cannot
# disagree, and so a triage that never ran stays visibly absent.
_TRIAGE_READ = text(
    """
    SELECT
        e.ts          AS occurred_at,
        e.seq         AS source_seq,
        e.agent       AS actor_label,
        e.summary     AS summary,
        e.payload     AS payload
      FROM investigation_events e
      JOIN investigation_runs r ON r.id = e.run_id
     WHERE e.tenant_id = :tid
       AND e.kind = 'triage_verdict'
       AND r.model_used LIKE 'kafka:auto_triage:%'
       AND r.case_id = :sid_text
     ORDER BY e.ts ASC, e.seq ASC
    """
)

_PENDING_TASK = text(
    """
    SELECT COUNT(*)
      FROM runbook_tasks
     WHERE tenant_id = :tid
       AND status <> 'completed'
       AND ((:stype = 'alert' AND alert_id = :sid)
            OR (:stype = 'case' AND case_id = :sid))
    """
)


def _stage_label(stage: str | None) -> str:
    return STAGE_LABELS.get(stage or "").title() if (stage or "").strip() else (stage or "unknown").title()


def _workflow_name(subject_type: str) -> str:
    return f"{subject_type.capitalize()} operational workflow"


def _workflow_objective(subject_type: str) -> str:
    if subject_type == "alert":
        return "Record the operational steps, evidence, and policy decisions taken on this alert."
    if subject_type == "case":
        return "Track the workflow, reviews, and actions taken while this case is active."
    return "Capture the operational sequence and governance decisions for this incident."


def _policy_snapshot_row(row: Any) -> dict[str, Any] | None:
    """Extract the policy snapshot from a DB row when present."""
    value = row.policy if hasattr(row, "policy") else None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        import json

        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _triage_policy(row: Any) -> dict[str, Any] | None:
    """Render the triage event payload as a policy snapshot.

    The payload holds the model's verdict and confidence. It is labelled with
    ``layer='auto_triage'`` so the UI never mistakes a triage verdict for a
    governance gate decision — they are different questions.
    """
    import json

    payload = row.payload if hasattr(row, "payload") else None
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            payload = None
    if not isinstance(payload, dict):
        return {"layer": "auto_triage"}

    policy: dict[str, Any] = {"layer": "auto_triage"}
    verdict = payload.get("verdict")
    if isinstance(verdict, str) and verdict.strip():
        policy["decision"] = verdict.strip()
    confidence = payload.get("confidence")
    if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
        policy["confidence"] = float(confidence)
    return policy


async def load_runbook(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID,
) -> RunbookEnvelope:
    """Return the governed action ledger for one subject.

    * ``subject_type`` must be one of ``alert | case | incident``.
    * Returns an explicit empty envelope (not ``None``) when there are no rows,
      so the page can render the honest empty state rather than invent one.
    * Adds a workflow summary so the page describes the operation itself, not
      only the raw ledger entries.
    """
    if subject_type not in ("alert", "case", "incident"):
        raise ValueError(f"subject_type must be one of alert|case|incident, got {subject_type!r}")

    rows = (
        await db.execute(
            _READ.bindparams(
                tid=tenant_id,
                stype=subject_type,
                sid=subject_id,
            )
        )
    ).fetchall()

    supporting_rule_count = int(
        (
            await db.execute(
                text(
                    """
                    SELECT COUNT(*)
                      FROM automation_rules
                     WHERE tenant_id = :tid
                       AND enabled = TRUE
                    """
                ).bindparams(tid=tenant_id)
            )
        ).scalar_one() or 0
    )

    collected: list[RunbookStep] = []
    for row in rows:
        collected.append(
            RunbookStep(
                seq=int(row.seq),
                occurred_at=row.occurred_at,
                stage=row.stage,
                stage_label=_stage_label(row.stage),
                kind=row.kind,
                action_name=row.action_name,
                actor_type=row.actor_type,
                actor_label=row.actor_label,
                summary=row.summary,
                detail=row.detail,
                status=row.status,
                policy=_policy_snapshot_row(row),
            )
        )

    # Agent-side triage evidence (read-only, alert subjects only).
    if subject_type == "alert":
        triage_rows = (
            await db.execute(
                _TRIAGE_READ.bindparams(tid=tenant_id, sid_text=str(subject_id))
            )
        ).fetchall()
        for row in triage_rows:
            collected.append(
                RunbookStep(
                    seq=0,  # reassigned below, after chronological sort
                    occurred_at=row.occurred_at,
                    stage="triage",
                    stage_label=_stage_label("triage"),
                    kind="triage_verdict",
                    action_name="auto_triage",
                    actor_type="agent",
                    actor_label=row.actor_label,
                    summary=row.summary,
                    detail=None,
                    status="recorded",
                    policy=_triage_policy(row),
                )
            )

    # Chronological, then re-sequence so the UI's stable key matches reading
    # order. Rows from two ledgers can share a timestamp; the sort is stable, so
    # the ledger a row came from keeps its relative position.
    collected.sort(key=lambda step: step.occurred_at)
    steps = [step.model_copy(update={"seq": index + 1}) for index, step in enumerate(collected)]

    workflow_name = _workflow_name(subject_type)
    workflow_objective = _workflow_objective(subject_type)

    pending = int(
        (
            await db.execute(
                _PENDING_TASK.bindparams(
                    tid=tenant_id, stype=subject_type, sid=subject_id
                )
            )
        ).scalar_one()
        or 0
    )
    observed = {step.stage for step in steps}
    procedure = [
        ProcedureStage(
            stage=entry["stage"],
            stage_label=_stage_label(entry["stage"]),
            status=entry["status"],
        )
        for entry in build_procedure(
            subject_type,
            observed_stages=observed,
            has_pending_task=pending > 0,
        )
    ]

    if not steps:
        return RunbookEnvelope(
            subject_type=subject_type,
            subject_id=str(subject_id),
            total_steps=0,
            workflow_name=workflow_name,
            workflow_objective=workflow_objective,
            supporting_rule_count=supporting_rule_count,
            procedure=procedure,
            steps=[],
            empty=True,
            empty_reason="No governed actions recorded yet. The Runbook starts empty and fills as actions are taken against this subject.",
        )

    return RunbookEnvelope(
        subject_type=subject_type,
        subject_id=str(subject_id),
        total_steps=len(steps),
        workflow_name=workflow_name,
        workflow_objective=workflow_objective,
        supporting_rule_count=supporting_rule_count,
        procedure=procedure,
        steps=steps,
    )
