"""Approval tasks that release a parked playbook run (Phase 12).

The engine can now park a run at an approval gate and resume it. This is the
control-plane half: an analyst completing that task must actually release the
run, must need ``playbooks:approve`` to do it, and the row must record whether
the release worked instead of assuming it did.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import runbook as runbook_module
from app.api.v1.endpoints.runbook import RunbookTaskComplete, complete_runbook_task
from fastapi import HTTPException

RUN_ID = "11111111-1111-4111-8111-111111111111"


def _user(role: str = "soc_lead") -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role=role,
        email="lead@example.com",
    )


def _gate_task(**overrides: Any) -> MagicMock:
    row = MagicMock()
    defaults = {
        "id": uuid.uuid4(),
        "task_type": "approval_gate",
        "title": "Approve Playbook: containment → Isolate host",
        "description": f"Run {RUN_ID} is paused at the approval step 'Isolate host'.",
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
        "signature": None,
        "playbook_run_id": uuid.UUID(RUN_ID),
        "resume_applied": None,
    }
    defaults.update(overrides)
    for key, value in defaults.items():
        setattr(row, key, value)
    return row


def _db(row: MagicMock) -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[
            MagicMock(scalar_one_or_none=MagicMock(return_value=row)),
            MagicMock(rowcount=1),
            MagicMock(scalar_one=MagicMock(return_value=row)),
        ]
    )
    db.commit = AsyncMock()
    return db


def _permit(monkeypatch: pytest.MonkeyPatch, *, allowed: bool) -> list[str]:
    """Replace the DB-backed permission check with a fixed answer."""
    asked: list[str] = []

    async def _require(self: CurrentUser, permission: str, db: Any) -> None:
        asked.append(permission)
        if not allowed:
            raise HTTPException(status_code=403, detail=f"Permission denied: {permission}")

    monkeypatch.setattr(CurrentUser, "require_permission_db", _require)
    return asked


@pytest.mark.asyncio
async def test_approving_a_gate_resumes_the_run_and_records_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _gate_task()
    db = _db(row)
    asked = _permit(monkeypatch, allowed=True)

    forwarded: list[dict[str, Any]] = []

    async def _resume(**kwargs: Any) -> bool:
        forwarded.append(kwargs)
        return True

    monkeypatch.setattr(runbook_module, "resume_playbook_run", _resume)

    await complete_runbook_task(
        task_id=str(row.id),
        body=RunbookTaskComplete(resolution="looks right", decision="approve"),
        db=db,
        current_user=_user(),
    )

    assert asked == ["playbooks:approve"]
    assert len(forwarded) == 1
    assert forwarded[0]["run_id"] == RUN_ID
    assert forwarded[0]["decision"] == "approve"
    # The audit trail names the human, not a synthetic id.
    assert forwarded[0]["actor"] == "lead@example.com"
    # The row records the outcome of the forward, not just the intent.
    update = db.execute.call_args_list[1].args[0]
    assert update.compile().params["resume_applied"] is True


@pytest.mark.asyncio
async def test_a_resume_that_did_not_move_the_run_is_stored_as_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _gate_task()
    db = _db(row)
    _permit(monkeypatch, allowed=True)

    async def _resume(**_: Any) -> bool:
        return False

    monkeypatch.setattr(runbook_module, "resume_playbook_run", _resume)

    await complete_runbook_task(
        task_id=str(row.id),
        body=RunbookTaskComplete(resolution="approved", decision="approve"),
        db=db,
        current_user=_user(),
    )

    update = db.execute.call_args_list[1].args[0]
    assert update.compile().params["resume_applied"] is False


@pytest.mark.asyncio
async def test_tier_one_analyst_cannot_clear_a_playbook_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _gate_task()
    db = _db(row)
    _permit(monkeypatch, allowed=False)

    called = False

    async def _resume(**_: Any) -> bool:
        nonlocal called
        called = True
        return True

    monkeypatch.setattr(runbook_module, "resume_playbook_run", _resume)

    with pytest.raises(HTTPException) as exc:
        await complete_runbook_task(
            task_id=str(row.id),
            body=RunbookTaskComplete(resolution="approved", decision="approve"),
            db=db,
            current_user=_user(role="soc_analyst"),
        )

    assert exc.value.status_code == 403
    # The run must not have been released by a denied caller.
    assert called is False


@pytest.mark.asyncio
async def test_decision_is_required_for_playbook_gate_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _gate_task()
    db = _db(row)
    _permit(monkeypatch, allowed=True)

    called = False

    async def _resume(**_: Any) -> bool:
        nonlocal called
        called = True
        return True

    monkeypatch.setattr(runbook_module, "resume_playbook_run", _resume)

    with pytest.raises(HTTPException) as exc:
        await complete_runbook_task(
            task_id=str(row.id),
            body=RunbookTaskComplete(resolution="approved", feedback_to_llm="good"),
            db=db,
            current_user=_user(),
        )

    assert exc.value.status_code == 422
    assert called is False


@pytest.mark.asyncio
async def test_governance_gate_without_a_run_is_unaffected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Autonomy-ceiling gates keep their existing contract: no run, no resume."""
    row = _gate_task(playbook_run_id=None)
    db = _db(row)
    _permit(monkeypatch, allowed=False)  # would 403 if it were consulted

    called = False

    async def _resume(**_: Any) -> bool:
        nonlocal called
        called = True
        return True

    monkeypatch.setattr(runbook_module, "resume_playbook_run", _resume)

    await complete_runbook_task(
        task_id=str(row.id),
        body=RunbookTaskComplete(resolution="Approved by analyst"),
        db=db,
        current_user=_user(role="soc_analyst"),
    )

    assert called is False
    update = db.execute.call_args_list[1].args[0]
    assert update.compile().params["resume_applied"] is None
