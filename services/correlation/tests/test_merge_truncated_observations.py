"""The 512-char Observation key migration: pure planning + a stubbed graph run."""

from __future__ import annotations

import re
from typing import Any

import pytest

from app.scripts.merge_truncated_observations import (
    _COUNT_TRUNCATED,
    _DELETE_OLD,
    _MATCH_TRUNCATED,
    _MERGE_TARGET,
    OBSERVATION_RELATIONSHIPS,
    bounded_key,
    merge_truncated_keys,
    move_statement,
    plan_merge,
)
from app.services import graph as graph_module
from app.services.observations import MAX_OBSERVATION_KEY_CHARS

LONG_KEY = "file|it000|" + "\n".join(
    f"sha1={i:040x},md5={i:032x},sha256={i:064x},imphash={i:032x}" for i in range(1, 4)
)
SHORT_KEY = "lsass|it000|{source}|{target}|T1003.001"


def test_plan_merge_bounds_only_over_long_keys():
    planned = plan_merge("tenant-1", LONG_KEY)

    assert planned is not None
    assert planned.tenant == "tenant-1"
    assert planned.old_key == LONG_KEY
    assert len(planned.new_key) <= MAX_OBSERVATION_KEY_CHARS
    assert re.search(r"\|#[0-9a-f]{16}$", planned.new_key)
    assert planned.new_key == bounded_key(LONG_KEY)

    assert plan_merge("tenant-1", SHORT_KEY) is None
    assert plan_merge("tenant-1", "") is None


def test_plan_merge_keeps_distinct_long_keys_apart():
    first = plan_merge("t", LONG_KEY)
    second = plan_merge("t", LONG_KEY + "\nextra=1")

    assert first is not None and second is not None
    assert first.new_key != second.new_key


def test_relationship_map_covers_every_edge_the_projector_writes():
    """The migration re-points :data:`OBSERVATION_RELATIONSHIPS`; a new edge the
    projector adds without registering it here would be silently dropped."""
    assert set(OBSERVATION_RELATIONSHIPS) == {"CONTAINS_ALERT"} | set(graph_module._ENTITY_MERGE)


def test_move_statement_refuses_unknown_relationship_types():
    for relationship in OBSERVATION_RELATIONSHIPS:
        assert f"[:{relationship}]" in move_statement(relationship)

    with pytest.raises(ValueError):
        move_statement("CONTAINS_ALERT]) DETACH DELETE n //")


class _Result:
    def __init__(self, rows: list[dict[str, Any]] | None = None, single: dict | None = None):
        self._rows = rows or []
        self._single = single

    async def data(self) -> list[dict[str, Any]]:
        return self._rows

    async def single(self) -> dict | None:
        return self._single


class _FakeSession:
    """Replays the migration's queries without a Neo4j instance."""

    def __init__(self, *, rows: list[dict], counts: list[int], incoming: list[dict]):
        self.rows = rows
        self.counts = list(counts)
        self.incoming = incoming
        self.seen: list[tuple[str, dict]] = []
        self.deleted: list[str] = []

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def run(self, query: str, **kwargs: Any) -> _Result:
        self.seen.append((query, kwargs))
        if query is _COUNT_TRUNCATED:
            return _Result(single={"nodes": self.counts.pop(0)})
        if query is _MATCH_TRUNCATED:
            gone = set(kwargs.get("skip") or []) | set(self.deleted)
            return _Result(rows=[r for r in self.rows if r["observation_id"] not in gone])
        if "RETURN type(r) AS rel" in query:
            return _Result(rows=self.incoming)
        if query is _MERGE_TARGET:
            return _Result(single={})
        if query is _DELETE_OLD:
            self.deleted.append(kwargs["old"])
            return _Result(single={})
        if "RETURN count(m) AS moved" in query:
            return _Result(single={"moved": 3})
        return _Result(single={})


class _FakeDriver:
    def __init__(self, session: _FakeSession):
        self._session = session

    def session(self, database: str | None = None) -> _FakeSession:  # noqa: ARG002
        return self._session


@pytest.mark.asyncio
async def test_merge_folds_a_truncated_node_and_repoints_every_edge():
    old_key = LONG_KEY
    session = _FakeSession(
        rows=[
            {
                "tenant": "tenant-1",
                "observation_id": old_key,
                "props": {
                    "role": "general:intrusion",
                    "time_quality": "first_event",
                    "normalizer_version": "2.1.0",
                    "first_seen": "2026-11-14T10:00:00Z",
                    "last_seen": "2026-11-14T10:05:00Z",
                    "techniques": ["T1003.006"],
                    "hosts": ["it000"],
                    "users": [],
                    "ips": [],
                    "domains": [],
                },
            }
        ],
        counts=[1, 0],
        incoming=[],
    )

    counters = await merge_truncated_keys(_FakeDriver(session), batch_size=10)

    assert counters == {
        "truncated_before": 1,
        "merged": 1,
        "skipped": 0,
        "relationships_moved": 3 * len(OBSERVATION_RELATIONSHIPS),
        "truncated_after": 0,
    }
    assert session.deleted == [old_key]
    merge_call = next(kwargs for query, kwargs in session.seen if query is _MERGE_TARGET)
    assert len(merge_call["new"]) <= MAX_OBSERVATION_KEY_CHARS
    assert merge_call["techniques"] == ["T1003.006"]
    assert merge_call["hosts"] == ["it000"]


@pytest.mark.asyncio
async def test_node_with_incoming_edges_is_skipped_not_detached():
    old_key = LONG_KEY
    session = _FakeSession(
        rows=[{"tenant": "tenant-1", "observation_id": old_key, "props": {"hosts": ["it000"]}}],
        counts=[1, 1],
        incoming=[{"rel": "SOMETHING_ELSE", "count": 2}],
    )

    counters = await merge_truncated_keys(_FakeDriver(session), batch_size=10)

    assert counters["merged"] == 0
    assert counters["skipped"] == 1
    assert counters["truncated_after"] == 1
    assert session.deleted == []
    # The skipped key is excluded from the next match, so the loop terminates.
    match_calls = [kwargs for query, kwargs in session.seen if query is _MATCH_TRUNCATED]
    assert match_calls[-1]["skip"] == [old_key]


@pytest.mark.asyncio
async def test_dry_run_plans_without_writing():
    old_key = LONG_KEY
    session = _FakeSession(
        rows=[{"tenant": "tenant-1", "observation_id": old_key, "props": {"hosts": ["it000"]}}],
        counts=[1, 1],
        incoming=[],
    )

    counters = await merge_truncated_keys(_FakeDriver(session), batch_size=10, dry_run=True)

    assert counters["merged"] == 1
    assert session.deleted == []
    assert not any(query is _MERGE_TARGET for query, _kwargs in session.seen)
