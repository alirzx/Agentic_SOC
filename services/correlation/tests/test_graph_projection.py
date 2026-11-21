"""Neo4j projection tests for ``GraphProjector``.

The projector is the only place the correlation engine writes to Neo4j, and it
is deliberately the least trusted part of a cycle: a graph outage must degrade
to Postgres and must never stop case creation. It also owns a subtle Cypher
shape — one statement per relationship, with an explicit ``WITH`` before each
``UNWIND`` — because a single query chaining several ``UNWIND`` clauses silently
drops the clauses after an empty list (a host-only observation would never
attach its alerts or users).

These tests drive the projector with a recording fake driver: no Bolt
connection, no Neo4j server, and every statement it would send is asserted.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services import graph as graph_module
from app.services.graph import (
    OBSERVATION_RELATIONSHIPS,
    GraphProjector,
)
from app.services.observations import Observation


class _Result:
    def __init__(self) -> None:
        self.consumed = 0

    async def consume(self) -> None:
        self.consumed += 1


class _Session:
    def __init__(self, driver: _Driver) -> None:
        self._driver = driver
        self.closed = False

    async def run(self, query: str, **params: Any) -> _Result:
        self._driver.calls.append((query, params))
        if self._driver.fail_on is not None and self._driver.fail_on in query:
            raise RuntimeError("graph is down")
        return _Result()

    async def close(self) -> None:
        self.closed = True


class _Driver:
    def __init__(self, *, fail_on: str | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail_on = fail_on
        self.sessions: list[_Session] = []

    def session(self, **_kwargs: Any) -> _Session:
        session = _Session(self)
        self.sessions.append(session)
        return session


def _projector(driver: _Driver | None = None) -> GraphProjector:
    projector = GraphProjector()
    projector._enabled = True
    projector._driver = driver or _Driver()
    return projector


def _observation(**overrides: Any) -> Observation:
    kwargs: dict[str, Any] = {
        "key": "lsass|win-dc-01|src-guid|tgt-guid|T1003.001",
        "alert_ids": ["alert-1", "alert-2"],
        "hosts": ["win-dc-01.attackrange.local"],
        "users": ["administrator"],
        "ips": ["10.0.2.107"],
        "domains": ["attackrange.local"],
        "techniques": ["T1003.001"],
        "role": "credential_access:lsass",
    }
    kwargs.update(overrides)
    return Observation(**kwargs)


def test_projection_is_disabled_when_the_setting_is_off(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(graph_module.settings, "graph_enabled", False)
    projector = GraphProjector()
    assert projector.enabled is False
    assert projector._driver is None


@pytest.mark.asyncio
async def test_upsert_merges_the_observation_node_and_every_relation():
    driver = _Driver()
    projector = _projector(driver)

    assert await projector.upsert_observation("tenant-1", _observation()) is True

    queries = [query for query, _params in driver.calls]
    assert len(driver.calls) == 5, "observation + four entity relations"
    assert "MERGE (o:Observation" in queries[0]
    assert "CONTAINS_ALERT" in queries[0]
    assert "MERGE (a:Alert" in queries[0]
    for relation in ("OBSERVED_ON", "INVOLVES_USER", "USES_IP", "QUERIED_DOMAIN"):
        assert any(relation in query for query in queries), relation

    params = driver.calls[0][1]
    assert params["tenant"] == "tenant-1"
    assert params["observation_id"] == _observation().key
    assert params["alerts"] == ["alert-1", "alert-2"]
    assert params["techniques"] == ["T1003.001"]
    assert params["role"] == "credential_access:lsass"

    # The entity statements carry only the values of their own relation.
    relation_params = dict(driver.calls[1:])
    assert any(p["values"] == ["win-dc-01.attackrange.local"] for p in relation_params.values())
    assert any(p["values"] == ["10.0.2.107"] for p in relation_params.values())
    assert all(session.closed for session in driver.sessions)


@pytest.mark.asyncio
async def test_empty_entity_lists_do_not_skip_the_alert_merge():
    """One statement per relation: an empty host list cannot swallow the rest."""

    driver = _Driver()
    projector = _projector(driver)

    await projector.upsert_observation(
        "tenant-1",
        _observation(hosts=[], users=[], ips=[], domains=[]),
    )

    assert len(driver.calls) == 1
    assert "CONTAINS_ALERT" in driver.calls[0][0]


@pytest.mark.asyncio
async def test_a_graph_failure_is_swallowed_and_counted_once_per_cycle():
    """A graph outage is logged and skipped; it never propagates to the caller."""

    driver = _Driver(fail_on="Observation")
    projector = _projector(driver)

    assert await projector.upsert_observation("tenant-1", _observation()) is False
    assert projector._fail_count == 1
    assert all(session.closed for session in driver.sessions), "the session is always closed"

    # A successful write resets the counter so the log stays a failure *streak*.
    driver.fail_on = None
    assert await projector.upsert_observation("tenant-1", _observation()) is True
    assert projector._fail_count == 0


@pytest.mark.asyncio
async def test_disabled_projector_reports_false_without_touching_the_driver():
    driver = _Driver()
    projector = GraphProjector()
    projector._driver = driver
    projector._enabled = False

    assert projector.enabled is False
    assert await projector.upsert_observation("tenant-1", _observation()) is False
    assert driver.calls == []


def test_relationship_map_covers_every_edge_the_layer_owns():
    """The 512-char key migration re-points exactly these edges."""

    assert OBSERVATION_RELATIONSHIPS == {
        "CONTAINS_ALERT": ("Alert", "alert_id"),
        "OBSERVED_ON": ("Host", "name"),
        "INVOLVES_USER": ("User", "name"),
        "USES_IP": ("IP", "address"),
        "QUERIED_DOMAIN": ("Domain", "name"),
    }
