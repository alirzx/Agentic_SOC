"""Approval gates that can actually be released (Phase 12).

Before this, a parked run was a dead end: nothing recorded *where* to resume, so
the only possible answer to an approval was "the run stopped". These tests pin the
four things that make the gate real:

1. parking records the resume index and the gate identity,
2. approving continues *after* the gate instead of replaying earlier steps,
3. rejecting ends the run as ``cancelled`` without executing anything,
4. a snapshot that no longer has the gate fails closed instead of guessing.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from app.playbook import engine as engine_mod
from app.playbook import run_store
from app.playbook.engine import PlaybookEngine, PlaybookRun, RunStatus, StepStatus
from app.playbook.models import Playbook, PlaybookStep, StepType
from app.playbook.resume import resume_run

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def silence_side_effects(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Stub realtime, persistence and gate-task creation.

    Returns the dict the gate-task stub records into, so tests can assert the
    analyst surface was raised exactly when a run parked.
    """
    tasks: dict[str, Any] = {"calls": []}

    monkeypatch.setattr(engine_mod, "_emit", AsyncMock(return_value=None))
    monkeypatch.setattr(engine_mod, "_persist", AsyncMock(return_value=None))

    async def _raise_gate_task(pr: PlaybookRun) -> None:
        tasks["calls"].append(pr.run_id)

    monkeypatch.setattr(engine_mod, "_raise_gate_task", _raise_gate_task)
    return tasks


@pytest.fixture
def http_handler(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace the HTTP handler with a recorder; returns the visited step names."""
    visited: list[str] = []

    async def _handler(step: PlaybookStep, ctx: dict, http: Any) -> dict:
        visited.append(step.name)
        return {"ok": True, "step": step.name}

    monkeypatch.setitem(engine_mod._HANDLERS, StepType.HTTP, _handler)
    return visited


def _playbook(gate_after: bool = True) -> Playbook:
    steps = [PlaybookStep(id="s1", name="before", type=StepType.HTTP)]
    if gate_after:
        steps.append(PlaybookStep(id="gate", name="Isolate host", type=StepType.APPROVAL))
        steps.append(PlaybookStep(id="s3", name="after", type=StepType.HTTP))
    return Playbook(name="containment", steps=steps)


def _persisted_row(pr: PlaybookRun, playbook: Playbook) -> dict[str, Any]:
    """The shape ``run_store.load_run`` returns (JSON-ish, all strings/ints)."""
    return {
        "id": pr.run_id,
        "playbook_snapshot": playbook.model_dump(mode="json"),
        "trigger_context": {"alert_id": "11111111-1111-4111-8111-111111111111"},
        "context": pr.context,
        "step_results": pr.step_results,
        "status": pr.status.value,
        "next_step_index": pr.next_step_index,
        "gate_step_id": pr.gate_step_id,
        "gate_step_name": pr.gate_step_name,
        "started_at": pr.started_at,
        "error": pr.error,
    }


# ---------------------------------------------------------------------------
# Parking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_park_records_resume_point_and_does_not_run_guarded_step(
    http_handler: list[str], silence_side_effects: dict
) -> None:
    playbook = _playbook()

    run = await PlaybookEngine().run(playbook, {"alert_id": "a-1"})

    assert run.status == RunStatus.PENDING_APPROVAL
    # The step after the gate — this is what makes a resume possible at all.
    assert run.next_step_index == 2
    assert run.gate_step_id == "gate"
    assert run.gate_step_name == "Isolate host"
    assert [r["status"] for r in run.step_results] == [StepStatus.SUCCESS, StepStatus.BLOCKED]
    # The guarded step never executed.
    assert http_handler == ["before"]
    # Nothing after the gate ran while the run sat parked.
    assert run.finished_at == ""
    # And the analyst can now see it.
    assert silence_side_effects["calls"] == [run.run_id]


# ---------------------------------------------------------------------------
# Resume
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approve_continues_after_the_gate_without_replaying_steps(
    http_handler: list[str],
) -> None:
    playbook = _playbook()
    parked = await PlaybookEngine().run(playbook, {"alert_id": "a-1"})
    row = _persisted_row(parked, playbook)

    # Round-trip through the persisted shape: resume must work from the row, not
    # from the live in-memory object.
    resumed_run = PlaybookRun.from_state(
        Playbook.model_validate(row["playbook_snapshot"]),
        run_id=str(row["id"]),
        trigger_context=row["trigger_context"],
        context=row["context"],
        step_results=row["step_results"],
        status=RunStatus(row["status"]),
        next_step_index=row["next_step_index"],
        gate_step_id=row["gate_step_id"],
        gate_step_name=row["gate_step_name"],
        started_at=row["started_at"],
        error=row["error"],
    )

    result = await PlaybookEngine().resume(resumed_run, playbook, actor="analyst@example.com")

    assert result.status == RunStatus.COMPLETED
    assert result.gate_released is True
    # Only the step *after* the gate ran — the earlier side effect was not repeated.
    assert http_handler == ["before", "after"]
    # The cleared gate reads as approved, not blocked.
    gate_entry = next(r for r in result.step_results if r["step_id"] == "gate")
    assert gate_entry["status"] == StepStatus.SUCCESS
    assert gate_entry["result"]["approved_by"] == "analyst@example.com"
    assert result.next_step_index is None


@pytest.mark.asyncio
async def test_resume_fails_closed_when_the_snapshot_lost_the_gate(
    http_handler: list[str],
) -> None:
    playbook = _playbook()
    parked = await PlaybookEngine().run(playbook, {})
    row = _persisted_row(parked, playbook)

    # The playbook was edited/replaced: there is no step at the recorded index.
    trimmed = Playbook(name="containment", steps=[playbook.steps[0]])
    run = PlaybookRun.from_state(
        trimmed,
        run_id=str(row["id"]),
        context=row["context"],
        step_results=row["step_results"],
        status=RunStatus.PENDING_APPROVAL,
        next_step_index=row["next_step_index"],
        gate_step_id="gate",
        gate_step_name="Isolate host",
        started_at=row["started_at"],
    )

    result = await PlaybookEngine().resume(run, trimmed, actor="analyst")

    assert result.status == RunStatus.FAILED
    assert "no longer present" in (result.error or "")
    assert result.gate_released is False
    # Nothing extra executed — a failed gate must not quietly continue.
    assert http_handler == ["before"]


@pytest.mark.asyncio
async def test_resume_refuses_a_run_that_is_not_parked(http_handler: list[str]) -> None:
    playbook = _playbook()
    run = await PlaybookEngine().run(playbook, {})
    await PlaybookEngine().resume(run, playbook, actor="analyst")  # clears the gate
    http_handler.clear()

    with pytest.raises(ValueError):
        await PlaybookEngine().resume(run, playbook, actor="analyst")
    assert http_handler == []


# ---------------------------------------------------------------------------
# Reject
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reject_decision_cancels_the_run(
    monkeypatch: pytest.MonkeyPatch, http_handler: list[str]
) -> None:
    playbook = _playbook()
    parked = await PlaybookEngine().run(playbook, {})
    row = _persisted_row(parked, playbook)

    decided: list[dict[str, Any]] = []

    async def _mark_decided(run_id: str, tenant: str, *, actor: str, decision: str) -> bool:
        decided.append({"run_id": run_id, "actor": actor, "decision": decision})
        return True

    monkeypatch.setattr(run_store, "mark_decided", _mark_decided)

    result = await resume_run(row, decision="reject", actor="analyst@example.com", tenant_ref="default")

    assert result["status"] == "cancelled"
    assert result["resumed"] is False
    assert decided == [{"run_id": str(row["id"]), "actor": "analyst@example.com", "decision": "reject"}]


@pytest.mark.asyncio
async def test_resume_is_idempotent_for_an_already_finished_run(http_handler: list[str]) -> None:
    playbook = _playbook()
    parked = await PlaybookEngine().run(playbook, {})
    row = {**_persisted_row(parked, playbook), "status": "completed"}

    result = await resume_run(row, decision="approve", actor="analyst", tenant_ref="default")

    assert result["resumed"] is False
    assert result["status"] == "completed"
    assert "completed" in str(result.get("detail"))


@pytest.mark.asyncio
async def test_approve_reports_resumed_only_when_the_gate_was_released(
    monkeypatch: pytest.MonkeyPatch, http_handler: list[str]
) -> None:
    playbook = _playbook()
    parked = await PlaybookEngine().run(playbook, {})
    row = _persisted_row(parked, playbook)

    monkeypatch.setattr(run_store, "mark_decided", AsyncMock(return_value=True))

    result = await resume_run(row, decision="approve", actor="analyst", tenant_ref="default")

    assert result["resumed"] is True
    assert result["status"] == "completed"


@pytest.mark.asyncio
async def test_corrupt_snapshot_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_store, "mark_decided", AsyncMock(return_value=True))
    row = {
        "id": "11111111-1111-4111-8111-111111111111",
        "status": "pending_approval",
        "playbook_snapshot": {"steps": "not-a-list"},
        "subscriber": "analyst",
    }

    result = await resume_run(row, decision="approve", actor="analyst", tenant_ref="default")

    assert result["resumed"] is False
    assert "snapshot" in str(result.get("detail"))


# ---------------------------------------------------------------------------
# Gate task surface
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_task_is_not_created_when_the_surface_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.playbook import approvals

    monkeypatch.delenv("AISOC_PLAYBOOK_RESUME", raising=False)
    run = PlaybookRun(_playbook(), {})
    run.gate_step_name = "Isolate host"

    assert await approvals.create_gate_task(run) is None


def test_gate_task_title_names_the_playbook_and_step() -> None:
    from app.playbook import approvals

    run = PlaybookRun(_playbook(), {})
    run.gate_step_name = "Isolate host"

    title = approvals.title_for(run)
    assert "containment" in title
    assert "Isolate host" in title
    assert len(title) <= 255


def test_resume_flag_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    for value in ("1", "true", "Yes", "on"):
        monkeypatch.setenv("AISOC_PLAYBOOK_RESUME", value)
        assert run_store.resume_enabled() is True
    for value in ("", "0", "false", "off"):
        monkeypatch.setenv("AISOC_PLAYBOOK_RESUME", value)
        assert run_store.resume_enabled() is False
