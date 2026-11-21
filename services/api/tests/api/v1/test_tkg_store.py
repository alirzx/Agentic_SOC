"""Evidence-union tests for the shared store.

A case's evidence is ``aisoc_cases.alert_ids`` ∪ ``alerts.case_id`` — the cached
array is a fast path that drifts, and soft-dedup alerts live on ``case_id`` only.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.services.tkg_evaluation.store import load_alerts

CASE = uuid4()
OTHER = uuid4()


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _DB:
    """Rows for each of the three evidence queries a case answers.

    The union SQL is checked by the rules it encodes, so the fake only has to
    reproduce which rows each query would return: the ownership union, or the
    dedup-loser join.
    """

    def __init__(self, rows):
        self.rows = rows
        self.sql = ""
        self.statements: list[str] = []

    async def execute(self, statement, params=None):
        self.sql = str(statement)
        self.statements.append(self.sql)
        if "deduplicated_into" in self.sql:
            bound = getattr(statement, "_bindparams", {}).get("winners")
            winners = set(getattr(bound, "value", None) or [])
            return _Result(
                [
                    row
                    for row in self.rows
                    if row.funnel_stage == "deduplicated" and row.dedup_into in winners
                ]
            )
        return _Result(self.rows)


def _row(alert_id: str, *, case_id=None, stage="cased", dedup_into=None):
    """Stand-in for an asyncpg Record: attribute access plus ``_mapping``."""

    values = {
        "id": alert_id,
        "case_id": case_id,
        "funnel_stage": stage,
        "correlation_state": "claimed",
        "occurrence_count": 1,
        "title": "t",
        "severity": "high",
        "event_time": None,
        "rule_name": None,
        "mitre_techniques": [],
        "llm_payload": None,
        "dedup_into": dedup_into,
    }
    record = SimpleNamespace(**values)
    record._mapping = values
    return record


def test_union_keeps_owned_and_unowned_cached_alerts_only():
    owned = _row("a", case_id=CASE, stage="deduplicated")
    unowned_cached = _row("b", case_id=None)
    foreign = _row("c", case_id=OTHER)
    db = _DB([owned, unowned_cached, foreign])

    rows = asyncio.run(load_alerts(db, uuid4(), CASE, ["b", "c"], set()))

    assert [str(row["id"]) for row in rows] == ["a", "b"]
    # Soft-dedup evidence is included, not filtered out.
    assert rows[0]["funnel_stage"] == "deduplicated"
    assert any("case_id = :case_id" in sql for sql in db.statements)


def test_dedup_losers_of_a_case_winner_are_evidence():
    """The engine links only the winner; its losers are still campaign evidence."""

    db = _DB(
        [
            _row("a", case_id=CASE),
            _row("loser", case_id=None, stage="deduplicated", dedup_into="a"),
            _row("foreign-loser", case_id=None, stage="deduplicated", dedup_into="z"),
        ]
    )
    rows = asyncio.run(load_alerts(db, uuid4(), CASE, [], set()))
    assert [str(row["id"]) for row in rows] == ["a", "loser"]


def test_excluded_alerts_are_dropped():
    db = _DB([_row("a", case_id=CASE), _row("b", case_id=CASE)])
    rows = asyncio.run(load_alerts(db, uuid4(), CASE, [], {"a"}))
    assert [str(row["id"]) for row in rows] == ["b"]


def test_case_with_no_rows_returns_empty():
    db = _DB([])
    assert asyncio.run(load_alerts(db, uuid4(), CASE, [], set())) == []
