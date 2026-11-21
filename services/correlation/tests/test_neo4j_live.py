"""Opt-in integration test against a real Neo4j.

The projector's unit tests use a fake driver; these exercise the actual Cypher
against a running server. They are skipped unless ``NEO4J_URI`` is reachable and
``AISOC_GRAPH_ENABLED`` is not false, so a unit-only run and CI stay green.

Every node the test creates carries a random ``tenant_id`` and is deleted in a
``finally`` block, including when an assertion fails. The shared dev graph is
never touched: the projector's MERGEs are tenant-scoped.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import pytest

from app.core.config import settings
from app.services.graph import GraphProjector
from app.services.observations import Observation

pytestmark = pytest.mark.asyncio


def _observation(key: str, host: str, alerts: list[str]) -> Observation:
    return Observation(
        key=key,
        alert_ids=alerts,
        hosts=[host],
        users=["administrator"],
        ips=["10.0.2.107"],
        domains=["attackrange.local"],
        techniques=["T1003.001"],
        role="credential_access:lsass",
    )


async def _driver() -> Any:
    pytest.importorskip("neo4j")
    from neo4j import AsyncGraphDatabase  # noqa: PLC0415 — optional dependency

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
        connection_timeout=5,
    )
    try:
        await driver.verify_connectivity()
    except Exception as exc:  # noqa: BLE001 — no server means skip, not fail
        await driver.close()
        pytest.skip(f"Neo4j at {settings.neo4j_uri} is unreachable ({type(exc).__name__})")
    return driver


async def _counts(driver, tenant: str) -> tuple[int, int]:
    async with driver.session(database=settings.neo4j_database) as session:
        nodes = (await (await session.run(
            "MATCH (n {tenant_id: $t}) RETURN count(n) AS c", t=tenant
        )).single())["c"]
        rels = (await (await session.run(
            "MATCH (:Observation {tenant_id: $t})-[r]->() RETURN count(r) AS c", t=tenant
        )).single())["c"]
    return nodes, rels


async def test_projection_is_idempotent_and_keeps_the_observation_edges():
    if os.environ.get("AISOC_GRAPH_ENABLED", "true").lower() in {"false", "0", "no"}:
        pytest.skip("AISOC_GRAPH_ENABLED is off")

    driver = await _driver()
    projector = GraphProjector()
    await projector.connect()
    if not projector.enabled:
        await driver.close()
        pytest.skip("projector could not connect to Neo4j")

    tenant = str(uuid.uuid4())
    batch = [
        _observation("entity|T1003.001|one", "win-dc-live.attackrange.local", ["a-1"]),
        _observation("entity|T1003.001|two", "win-dc-live.attackrange.local", ["a-2"]),
        _observation("entity|T1649|three", "win-dc-live.attackrange.local", ["a-3"]),
    ]

    try:
        for observation in batch:
            assert await projector.upsert_observation(tenant, observation) is True
        first = await _counts(driver, tenant)

        # The MERGEs are keyed, so re-projecting the same observations must not
        # duplicate a single node or relationship.
        for observation in batch:
            assert await projector.upsert_observation(tenant, observation) is True
        second = await _counts(driver, tenant)
        assert second == first

        async with driver.session(database=settings.neo4j_database) as session:
            observations = (await (await session.run(
                "MATCH (o:Observation {tenant_id: $t}) RETURN count(o) AS c", t=tenant
            )).single())["c"]
            assert observations == len(batch)

            # The three observations share a host, so they are one 2-hop hop
            # apart in the projection the graph query would walk.
            path = await (await session.run(
                """
                MATCH p = (a:Observation {tenant_id: $t})-[*2]-(b:Observation {tenant_id: $t})
                WHERE a.observation_id <> b.observation_id
                RETURN count(p) AS c
                """,
                t=tenant,
            )).single()
            assert path["c"] > 0
            assert first[1] > 0
    finally:
        async with driver.session(database=settings.neo4j_database) as session:
            await session.run("MATCH (n {tenant_id: $t}) DETACH DELETE n", t=tenant)
        await driver.close()
        await projector.close()
