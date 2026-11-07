"""The funnel board shows *why* a stage is stuck, by reading Runbook tasks.

A stage count alone says 50 alerts are in `triaged`. The Runbook tasks attached to
those alerts say 37 of them are waiting on an analyst — which is the diagnosis a
manager actually needs. These tests pin that link, and the graceful degradation
when `runbook_tasks` does not exist yet.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services.agentic_funnel import funnel_board


def _rows(rows: list[dict[str, Any]]) -> MagicMock:
    return MagicMock(mappings=MagicMock(return_value=MagicMock(all=MagicMock(return_value=rows))))


def _stage_counts() -> list[dict[str, Any]]:
    return [
        {"stage": "triaged", "n": 5},
        {"stage": "investigating", "n": 2},
    ]


def _samples() -> list[dict[str, Any]]:
    return [
        {
            "id": uuid.UUID("11111111-1111-4111-8111-111111111111"),
            "title": "Impossible travel",
            "severity": "medium",
            "status": "new",
            "disposition": None,
            "funnel_stage": "triaged",
            "confidence": 61,
            "case_id": None,
            "created_at": datetime.now(UTC),
            "same_title_count": 1,
        },
        {
            "id": uuid.UUID("22222222-2222-4222-8222-222222222222"),
            "title": "Contained host beaconing",
            "severity": "high",
            "status": "in_progress",
            "disposition": "true_positive",
            "funnel_stage": "investigating",
            "confidence": 88,
            "case_id": None,
            "created_at": datetime.now(UTC),
            "same_title_count": 2,
        },
    ]


@pytest.mark.asyncio
async def test_board_attaches_open_tasks_to_the_alert_that_is_stuck() -> None:
    tasks = [
        {
            "alert_id": "11111111-1111-4111-8111-111111111111",
            "task_type": "manual_review",
            "title": "Verify Alert Triage (Low AI Confidence)",
            "status": "pending",
            "stage": "triaged",
        },
        {
            "alert_id": "11111111-1111-4111-8111-111111111111",
            "task_type": "approval_gate",
            "title": "Approve Action: isolate_host",
            "status": "pending",
            "stage": "triaged",
        },
    ]
    db = MagicMock()
    db.execute = AsyncMock(side_effect=[_rows(tasks), _rows(_stage_counts()), _rows(_samples())])

    board = await funnel_board(db, tenant_id=uuid.uuid4(), hours=24)

    triaged = next(stage for stage in board["stages"] if stage["id"] == "triaged")
    assert triaged["count"] == 5
    assert triaged["open_tasks"] == 2

    investigating = next(stage for stage in board["stages"] if stage["id"] == "investigating")
    assert investigating["open_tasks"] == 0

    sample = board["samples_by_stage"]["triaged"][0]
    assert [task["task_type"] for task in sample["open_tasks"]] == [
        "manual_review",
        "approval_gate",
    ]

    # An alert with no task carries an empty list, never a missing key.
    other = board["samples_by_stage"]["investigating"][0]
    assert other["open_tasks"] == []


@pytest.mark.asyncio
async def test_board_still_renders_when_runbook_tasks_is_unavailable() -> None:
    """A deployment without migration 064 must not lose the whole board."""

    async def _execute(*args: Any, **kwargs: Any) -> Any:
        # 1st call is the open-task query; it fails. The rest are the board queries.
        if _execute.calls == 0:
            _execute.calls += 1
            raise RuntimeError('relation "runbook_tasks" does not exist')
        _execute.calls += 1
        return _rows(_stage_counts()) if _execute.calls == 2 else _rows(_samples())

    _execute.calls = 0  # type: ignore[attr-defined]

    db = MagicMock()
    db.execute = _execute

    board = await funnel_board(db, tenant_id=uuid.uuid4(), hours=24)

    assert board["alerts_total"] == 7
    assert all(stage["open_tasks"] == 0 for stage in board["stages"])
    assert board["samples_by_stage"]["triaged"][0]["open_tasks"] == []
