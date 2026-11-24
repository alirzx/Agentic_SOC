"""Regression: ledger RunSummary must accept UUID case_id from the ORM."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

from app.api.v1.endpoints.investigations import _run_to_summary


def test_run_to_summary_stringifies_uuid_case_id() -> None:
    case_id = uuid.UUID("dd766cc3-6513-4990-821b-20985715b34e")
    run_id = uuid.uuid4()
    started = datetime(2026, 11, 23, 13, 30, 25, tzinfo=UTC)
    input_run = SimpleNamespace(
        id=run_id,
        case_id=case_id,
        status="completed",
        model_used=None,
        iterations=4,
        total_tokens=9895,
        total_cost_usd=0.015547,
        started_at=started,
        completed_at=started,
        error=None,
    )

    actual = _run_to_summary(input_run)

    assert actual.id == run_id
    assert actual.case_id == str(case_id)
    assert isinstance(actual.case_id, str)
    assert actual.status == "completed"
