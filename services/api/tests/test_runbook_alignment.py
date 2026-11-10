"""Tests for the Runbook alignment work (PLAN-20261029-1026).

Covers the four things that were previously claimed but not true:

1. Analyst feedback on a completed task actually crosses to outcome memory.
2. The Action Plan is scoped to the subject that was selected.
3. A blocked action produces exactly one pending approval task.
4. The ledger shows the auto-triage decision, and the procedure reflects it.

Endpoint functions are called directly with a mocked session, matching the
convention in ``test_alerts_tenant_isolation.py``.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import runbook as runbook_module
from app.api.v1.endpoints.runbook import (
    RunbookTaskComplete,
    complete_runbook_task,
    list_runbook_tasks,
    runbook_feedback_stats,
)
from app.services.runbook.procedure import build_procedure
from app.services.runbook.read import load_runbook
from app.services.runbook.rule_executor import normalize_confidence
from app.services.runbook.tasks import ensure_approval_gate_task


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="soc_analyst",
        email="analyst@example.com",
    )


def _task(**overrides: Any) -> MagicMock:
    row = MagicMock()
    defaults = {
        "id": uuid.uuid4(),
        "task_type": "manual_review",
        "title": "Verify Alert Triage (Low AI Confidence)",
        "description": "confidence below threshold",
        "alert_id": uuid.uuid4(),
        "case_id": None,
        "assigned_to": None,
        "status": "pending",
        "due_at": None,
        "completed_at": None,
        "resolution": None,
        "feedback_to_llm": None,
        "created_by": "system",
        "created_at": datetime.now(UTC),
        "signature": "sig-abc",
        # Explicit Nones: a bare MagicMock would auto-create a truthy
        # playbook_run_id and send every completion down the gate-resume path.
        "playbook_run_id": None,
        "resume_applied": None,
    }
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(row, key, value)
    return row


# ── Action Plan scoping ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_tasks_filters_by_alert_and_tenant() -> None:
    """A subject-scoped Action Plan must bind alert_id *and* tenant_id."""
    user = _user()
    alert_id = uuid.uuid4()
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))))

    await list_runbook_tasks(
        db=db,
        current_user=user,
        status=None,
        task_type=None,
        alert_id=str(alert_id),
        case_id=None,
        skip=0,
        limit=50,
    )

    assert db.execute.await_count == 1
    compiled = db.execute.await_args.args[0]
    sql = re.sub(r"\s+", " ", str(compiled)).lower()
    assert "runbook_tasks" in sql
    params = dict(compiled.compile().params)
    values = {str(value) for value in params.values()}
    assert str(alert_id) in values, "alert_id filter was not bound"
    assert str(user.tenant_id) in values, "tenant_id filter was not bound"


@pytest.mark.asyncio
async def test_list_tasks_rejects_malformed_alert_id() -> None:
    """A bad UUID is a 422 from the shared parser, not a silent full-tenant read."""
    from fastapi import HTTPException

    db = MagicMock()
    db.execute = AsyncMock()
    with pytest.raises(HTTPException) as exc:
        await list_runbook_tasks(
            db=db,
            current_user=_user(),
            status=None,
            task_type=None,
            alert_id="not-a-uuid",
            case_id=None,
            skip=0,
            limit=50,
        )
    assert exc.value.status_code == 422
    db.execute.assert_not_called()


# ── Feedback forwarding ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_complete_task_forwards_feedback_with_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    """Completion forwards the stored signature; the model actually learns."""
    user = _user()
    row = _task(tenant_id=user.tenant_id, signature="fingerprint-1")
    pending = _task(tenant_id=user.tenant_id, signature="fingerprint-1")

    db = MagicMock()
    # 1) SELECT the task, 2) UPDATE it, 3) SELECT it again for the response.
    db.execute = AsyncMock(
        side_effect=[
            MagicMock(scalar_one_or_none=MagicMock(return_value=row)),
            MagicMock(rowcount=1),
            MagicMock(scalar_one=MagicMock(return_value=pending)),
        ]
    )
    db.commit = AsyncMock()

    calls: list[dict[str, Any]] = []

    async def _fake_post(**kwargs: Any) -> bool:
        calls.append(kwargs)
        return True

    monkeypatch.setattr(runbook_module, "post_outcome_feedback", _fake_post)

    await complete_runbook_task(
        task_id=str(row.id),
        body=RunbookTaskComplete(resolution="checked", feedback_to_llm="poor"),
        db=db,
        current_user=user,
    )

    assert len(calls) == 1
    assert calls[0]["signature"] == "fingerprint-1"
    assert calls[0]["feedback"] == "poor"
    assert calls[0]["tenant_id"] == str(user.tenant_id)

    # The row records what the forward actually did, not just that it was tried.
    update = db.execute.call_args_list[1].args[0]
    assert update.compile().params["applied"] is True


@pytest.mark.asyncio
async def test_complete_task_records_unapplied_feedback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Feedback that moved no prior is stored as False, never as a success."""
    user = _user()
    row = _task(tenant_id=user.tenant_id, signature="fingerprint-1")

    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[
            MagicMock(scalar_one_or_none=MagicMock(return_value=row)),
            MagicMock(rowcount=1),
            MagicMock(scalar_one=MagicMock(return_value=row)),
        ]
    )
    db.commit = AsyncMock()

    async def _no_prior(**kwargs: Any) -> bool:
        return False

    monkeypatch.setattr(runbook_module, "post_outcome_feedback", _no_prior)

    await complete_runbook_task(
        task_id=str(row.id),
        body=RunbookTaskComplete(resolution="checked", feedback_to_llm="good"),
        db=db,
        current_user=user,
    )

    update = db.execute.call_args_list[1].args[0]
    assert update.compile().params["applied"] is False


@pytest.mark.asyncio
async def test_complete_task_without_feedback_leaves_prior_flag_unset() -> None:
    """Approving an action is a governance decision; it must not claim learning."""
    user = _user()
    row = _task(tenant_id=user.tenant_id, task_type="approval_gate")

    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[
            MagicMock(scalar_one_or_none=MagicMock(return_value=row)),
            MagicMock(rowcount=1),
            MagicMock(scalar_one=MagicMock(return_value=row)),
        ]
    )
    db.commit = AsyncMock()

    await complete_runbook_task(
        task_id=str(row.id),
        body=RunbookTaskComplete(resolution="Approved by analyst", feedback_to_llm=None),
        db=db,
        current_user=user,
    )

    update = db.execute.call_args_list[1].args[0]
    assert update.compile().params["applied"] is None


@pytest.mark.asyncio
async def test_complete_task_skips_forward_without_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    """No signature => no cross-service call. A fake success would be worse."""
    user = _user()
    row = _task(tenant_id=user.tenant_id, signature=None)

    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[
            MagicMock(scalar_one_or_none=MagicMock(return_value=row)),
            MagicMock(rowcount=1),
            MagicMock(scalar_one=MagicMock(return_value=row)),
        ]
    )
    db.commit = AsyncMock()

    async def _fail(**kwargs: Any) -> bool:  # pragma: no cover - must not run
        raise AssertionError("feedback forwarded without a signature")

    monkeypatch.setattr(runbook_module, "post_outcome_feedback", _fail)

    await complete_runbook_task(
        task_id=str(row.id),
        body=RunbookTaskComplete(resolution="checked", feedback_to_llm="good"),
        db=db,
        current_user=user,
    )


# ── Feedback-loop metric ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_feedback_stats_are_tenant_scoped_and_report_unapplied() -> None:
    """The metric counts priors moved *and* the feedback that moved nothing."""
    user = _user()
    aggregate = {
        "tasks_total": 9,
        "tasks_pending": 4,
        "tasks_completed": 5,
        "completions_with_feedback": 5,
        "priors_updated": 3,
        "feedback_unapplied": 2,
    }
    db = MagicMock()
    db.execute = AsyncMock(
        return_value=MagicMock(
            mappings=MagicMock(return_value=MagicMock(one=MagicMock(return_value=aggregate)))
        )
    )

    stats = await runbook_feedback_stats(db=db, current_user=user)

    assert db.execute.call_args.args[0].compile().params["tenant_id"] == user.tenant_id
    assert stats.priors_updated == 3
    assert stats.completions_with_feedback == 5
    assert stats.feedback_unapplied == 2
    # Whatever did not move a prior stays visible instead of disappearing.
    assert stats.priors_updated + stats.feedback_unapplied == stats.completions_with_feedback


# ── Approval-gate task creation ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_approval_gate_task_is_idempotent_and_tenant_scoped() -> None:
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock(rowcount=1))

    created = await ensure_approval_gate_task(
        db,
        tenant_id=uuid.uuid4(),
        alert_id=uuid.uuid4(),
        action_name="isolate_host",
        autonomy_level="L2",
        reason="review required",
    )

    assert created is True
    statement = db.execute.await_args.args[0]
    sql = re.sub(r"\s+", " ", str(statement)).lower()
    assert "insert into runbook_tasks" in sql
    assert "approval_gate" in sql
    assert "on conflict do nothing" in sql, "duplicate approval tasks must collapse onto the open one"
    params = dict(statement.compile().params)
    assert "Approve Action: isolate_host" in params["title"]


@pytest.mark.asyncio
async def test_approval_gate_task_reports_not_created_on_conflict() -> None:
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock(rowcount=0))
    assert (
        await ensure_approval_gate_task(
            db,
            tenant_id=uuid.uuid4(),
            alert_id=None,
            action_name="isolate_host",
            autonomy_level="L2",
            reason="duplicate",
        )
        is False
    )


# ── Confidence normalisation ─────────────────────────────────────────────────


def test_normalize_confidence_accepts_both_scales() -> None:
    assert normalize_confidence(50) == 0.5
    assert normalize_confidence(85) == 0.85
    assert normalize_confidence(0.42) == 0.42
    assert normalize_confidence(None) == 0.5
    assert normalize_confidence("bad") == 0.5
    assert normalize_confidence(-5) == 0.0
    assert normalize_confidence(400) == 1.0


# ── Procedure derivation ─────────────────────────────────────────────────────


def test_procedure_marks_done_skipped_and_pending() -> None:
    stages = build_procedure(
        "alert",
        observed_stages={"ingest", "triage"},
        has_pending_task=False,
    )
    statuses = {entry["stage"]: entry["status"] for entry in stages}
    assert statuses["ingest"] == "done"
    assert statuses["triage"] == "done"
    assert statuses["enrich"] == "skipped", "no enrich evidence, but triage ran after it"
    assert statuses["investigate"] == "pending"


def test_procedure_marks_first_unreached_stage_blocked() -> None:
    stages = build_procedure(
        "alert",
        observed_stages={"ingest", "triage"},
        has_pending_task=True,
    )
    blocked = [entry["stage"] for entry in stages if entry["status"] == "blocked"]
    # "enrich" is skipped (triage ran without it), so the first *unreached*
    # stage is where the human queue actually sits.
    assert blocked == ["investigate"], "a pending task blocks exactly one stage"


def test_procedure_uses_the_subject_sequence() -> None:
    stages = build_procedure("case", observed_stages={"funnel"}, has_pending_task=False)
    assert [entry["stage"] for entry in stages][:2] == ["funnel", "investigate"]


# ── Ledger read: triage evidence + procedure ─────────────────────────────────


def _mk_read_db(payloads: list[Any]) -> MagicMock:
    """Session mock that serves queued results one execute() at a time."""
    db = MagicMock()
    iterator = iter(payloads)

    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        try:
            payload = next(iterator)
        except StopIteration:
            payload = []
        result = MagicMock()
        rows = payload if isinstance(payload, list) else []
        result.fetchall = MagicMock(return_value=rows)
        result.scalar_one = MagicMock(return_value=payload if isinstance(payload, int) else 0)
        return result

    db.execute = AsyncMock(side_effect=_execute)
    return db


@pytest.mark.asyncio
async def test_load_runbook_includes_triage_evidence_and_procedure() -> None:
    tenant_id = uuid.uuid4()
    subject_id = uuid.uuid4()
    ledger_row = MagicMock(
        seq=1,
        occurred_at=datetime(2026, 10, 29, 10, 0, tzinfo=UTC),
        stage="ingest",
        kind="ingest",
        action_name=None,
        actor_type="connector",
        actor_label="splunk",
        summary="3 events ingested",
        detail=None,
        status="recorded",
        policy=None,
    )
    triage_row = MagicMock(
        occurred_at=datetime(2026, 10, 29, 10, 5, tzinfo=UTC),
        source_seq=1,
        actor_label="auto_triage:llm",
        summary="verdict=needs_review confidence=0.72",
        payload={"verdict": "needs_review", "confidence": 0.72},
    )

    # order: runbook_events, automation_rules count, triage rows, pending tasks
    db = _mk_read_db([[ledger_row], 2, [triage_row], 0])

    envelope = await load_runbook(
        db, tenant_id=tenant_id, subject_type="alert", subject_id=subject_id
    )

    assert [step.stage for step in envelope.steps] == ["ingest", "triage"]
    triage_step = envelope.steps[1]
    assert triage_step.actor_type == "agent"
    assert triage_step.kind == "triage_verdict"
    assert triage_step.policy is not None
    assert triage_step.policy["decision"] == "needs_review"
    assert triage_step.policy["confidence"] == pytest.approx(0.72)

    statuses = {entry.stage: entry.status for entry in envelope.procedure}
    assert statuses["triage"] == "done"
    assert statuses["enrich"] == "skipped"
    assert statuses["investigate"] == "pending"
    assert "blocked" not in statuses.values()


# ── route resolution ─────────────────────────────────────────────────────────
#
# The ledger lives at ``/runbook/{subject_type}/{subject_id}``, a two-segment
# catch-all. Declared before the concrete routes it silently answered
# ``GET /runbook/tasks/{id}`` and ``GET /runbook/automation-rules/{id}`` with
# 400 "subject_type must be one of …", so the resource routes were dead.


def _resolve_endpoint(method: str, path: str) -> str | None:
    from starlette.routing import Match

    for route in runbook_module.router.routes:
        match, _ = route.matches(
            {"type": "http", "path": path, "method": method, "headers": []}
        )
        if match == Match.FULL:
            return getattr(route, "name", None)
    return None


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("GET", f"/runbook/tasks/{uuid.uuid4()}", "get_runbook_task"),
        ("GET", f"/runbook/automation-rules/{uuid.uuid4()}", "get_automation_rule"),
        ("PATCH", f"/runbook/automation-rules/{uuid.uuid4()}", "patch_automation_rule"),
        ("DELETE", f"/runbook/automation-rules/{uuid.uuid4()}", "delete_automation_rule"),
        ("GET", f"/runbook/alert/{uuid.uuid4()}", "get_runbook"),
        ("GET", f"/runbook/case/{uuid.uuid4()}", "get_runbook"),
        ("GET", "/runbook/tasks", "list_runbook_tasks"),
        ("GET", "/runbook/detections", "runbook_detection_activity"),
    ],
)
def test_ledger_catch_all_does_not_shadow_concrete_routes(method: str, path: str, expected: str) -> None:
    assert _resolve_endpoint(method, path) == expected
