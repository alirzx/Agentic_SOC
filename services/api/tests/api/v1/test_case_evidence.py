"""Evidence-union tests for a case's correlation view.

A case's evidence is ``alert_ids`` ∪ ``alerts.case_id`` ∪ soft-dedup losers
whose ``deduplicated_into:<winner>`` tag points at a member. The third source is
what lets a campaign the engine collapsed (114 alerts → 9 canonical) be drawn
and scored at full size.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import UUID, uuid4

from app.api.v1.endpoints.cases import _case_evidence

CASE = uuid4()
OTHER = uuid4()


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _DB:
    """Serves the three sequential queries ``_case_evidence`` issues."""

    def __init__(self, case_row, owned, losers):
        self._queue = [_Result([case_row]), _Result(owned), _Result(losers)]
        self.statements: list[str] = []

    async def execute(self, statement, params=None):
        self.statements.append(str(statement))
        return self._queue.pop(0)


def _case(alert_ids):
    return SimpleNamespace(
        id=CASE,
        title="t",
        severity="medium",
        status="new",
        alert_ids=alert_ids,
        created_at=None,
    )


def _alert(alert_id, *, case_id=None):
    return SimpleNamespace(id=UUID(alert_id), case_id=case_id)


def test_union_covers_ownership_and_dedup_losers():
    a, b, c, loser = (str(uuid4()) for _ in range(4))
    # a is cached and owned, b is cached but unowned (writer has not stamped it),
    # c is cached but now belongs to another case.
    owned = [_alert(a, case_id=CASE), _alert(b), _alert(c, case_id=OTHER)]
    db = _DB(_case([UUID(a), UUID(b), UUID(c)]), owned, [_alert(loser)])

    _row, evidence = asyncio.run(_case_evidence(db, CASE, uuid4()))

    assert evidence == sorted([a, b, loser])
    assert any("deduplicated_into" in sql for sql in db.statements)


def test_foreign_case_alert_is_not_evidence():
    a, c = (str(uuid4()) for _ in range(2))
    owned = [_alert(a, case_id=CASE), _alert(c, case_id=OTHER)]
    db = _DB(_case([UUID(a)]), owned, [])

    _row, evidence = asyncio.run(_case_evidence(db, CASE, uuid4()))

    assert evidence == [a]
