"""Neo4j projection for observations (doc §6).

The Go ingest service owns the canonical ``(:Alert)``/``(:Host)``/``(:User)``
projection of the attack graph; Python has always been read-only there. This
projector therefore performs a *narrow, idempotent additive merge* — it never
updates or deletes existing nodes, and it only attaches the new
``(:Observation)`` layer that the correlation engine owns:

    (:Observation)-[:CONTAINS_ALERT]->(:Alert)
    (:Observation)-[:OBSERVED_ON]->(:Host)
    (:Observation)-[:INVOLVES_USER]->(:User)
    (:Observation)-[:USES_IP]->(:IP)
    (:Observation)-[:QUERIED_DOMAIN]->(:Domain)

Everything is best-effort. If the driver is unavailable or the graph is down,
the engine keeps working from Postgres — a graph outage must never stop case
creation, and must never be silently reported as "correlated in the graph".
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from app.core.config import settings
from app.services.observations import Observation

logger = structlog.get_logger()

_ALERT_MERGE = """
UNWIND $alerts AS aid
MERGE (a:Alert {tenant_id: $tenant, alert_id: aid})
  ON CREATE SET a.created_at = datetime()
MERGE (o:Observation {tenant_id: $tenant, observation_id: $observation_id})
  SET o.key = $key,
      o.role = $role,
      o.techniques = $techniques,
      o.hosts = $hosts,
      o.users = $users,
      o.ips = $ips,
      o.domains = $domains,
      o.first_seen = $first_seen,
      o.last_seen = $last_seen,
      o.time_quality = $time_quality,
      o.normalizer_version = $normalizer_version,
      o.updated_at = datetime()
MERGE (o)-[:CONTAINS_ALERT]->(a)
"""

# One statement per relation. A single query chaining several UNWINDs is a
# trap: an empty list consumes the rest of the clause, so a host-only
# observation would silently never attach its alerts or users. MERGE also needs
# an explicit WITH before UNWIND.
_ENTITY_MERGE = {
    "OBSERVED_ON": (
        "Host",
        "name",
        """
        MERGE (o:Observation {tenant_id: $tenant, observation_id: $observation_id})
        WITH o
        UNWIND $values AS value
          MERGE (n:Host {tenant_id: $tenant, name: value})
          MERGE (o)-[:OBSERVED_ON]->(n)
        """,
    ),
    "INVOLVES_USER": (
        "User",
        "name",
        """
        MERGE (o:Observation {tenant_id: $tenant, observation_id: $observation_id})
        WITH o
        UNWIND $values AS value
          MERGE (n:User {tenant_id: $tenant, name: value})
          MERGE (o)-[:INVOLVES_USER]->(n)
        """,
    ),
    "USES_IP": (
        "IP",
        "address",
        """
        MERGE (o:Observation {tenant_id: $tenant, observation_id: $observation_id})
        WITH o
        UNWIND $values AS value
          MERGE (n:IP {tenant_id: $tenant, address: value})
          MERGE (o)-[:USES_IP]->(n)
        """,
    ),
    "QUERIED_DOMAIN": (
        "Domain",
        "name",
        """
        MERGE (o:Observation {tenant_id: $tenant, observation_id: $observation_id})
        WITH o
        UNWIND $values AS value
          MERGE (n:Domain {tenant_id: $tenant, name: value})
          MERGE (o)-[:QUERIED_DOMAIN]->(n)
        """,
    ),
}


#: Every relationship type the ``(:Observation)`` layer owns, mapped to the
#: label + key property of the node on the other side. The 512-char key
#: migration (``app/scripts/merge_truncated_observations.py``) has to re-point
#: exactly these edges, so they live in one place instead of being restated.
OBSERVATION_RELATIONSHIPS: dict[str, tuple[str, str]] = {
    "CONTAINS_ALERT": ("Alert", "alert_id"),
    **{rel: (label, prop) for rel, (label, prop, _cypher) in _ENTITY_MERGE.items()},
}


class GraphProjector:
    """Optional Neo4j writer for observation nodes."""

    def __init__(self) -> None:
        self._driver: Any = None
        self._enabled = bool(settings.graph_enabled)
        self._fail_count = 0  # consecutive write failures; reset on success

    @property
    def enabled(self) -> bool:
        return self._enabled and self._driver is not None

    async def connect(self) -> None:
        if not self._enabled:
            logger.info("graph.disabled", reason="AISOC_GRAPH_ENABLED=false")
            return
        try:
            from neo4j import AsyncGraphDatabase  # noqa: PLC0415 — optional dependency
        except ImportError:
            self._enabled = False
            logger.warning("graph.disabled", reason="neo4j driver not installed")
            return
        try:
            self._driver = AsyncGraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
                # Connection pool settings to prevent buffer overflow issues
                max_connection_pool_size=50,
                connection_timeout=30.0,
                max_transaction_retry_time=30.0,
                encrypted=False,
            )
            try:
                await self._driver.verify_connectivity()
                logger.info("graph.connected", uri=settings.neo4j_uri)
            except Exception as verify_exc:
                logger.warning("graph.verify_connectivity_failed", error=str(verify_exc)[:200])
                # Don't disable, keep trying
        except Exception as exc:  # noqa: BLE001 — graph is optional
            self._enabled = False
            self._driver = None
            logger.warning("graph.unavailable", uri=settings.neo4j_uri, error=str(exc)[:200])

    async def close(self) -> None:
        if self._driver is not None:
            try:
                # Close with timeout to prevent hangs during shutdown
                await asyncio.wait_for(self._driver.close(), timeout=5.0)
                logger.info("graph.driver_closed")
            except asyncio.TimeoutError:
                logger.warning("graph.driver_close_timeout")
                # Don't raise - let shutdown continue
            except Exception as exc:  # noqa: BLE001
                logger.warning("graph.driver_close_error", error=str(exc)[:100])
            finally:
                self._driver = None

    async def upsert_observation(self, tenant_id: str, observation: Observation) -> bool:
        """Merge one observation + its alert links + entity edges."""
        if not self.enabled:
            return False
        params = {
            "tenant": str(tenant_id),
            "observation_id": observation.key,
            "key": observation.key,
            "role": observation.role,
            "techniques": observation.techniques,
            "hosts": observation.hosts,
            "users": observation.users,
            "ips": observation.ips,
            "domains": observation.domains,
            "alerts": observation.alert_ids,
            "first_seen": observation.first_seen.isoformat() if observation.first_seen else None,
            "last_seen": observation.last_seen.isoformat() if observation.last_seen else None,
            "time_quality": observation.time_quality,
            "normalizer_version": observation.normalizer_version,
        }
        try:
            session = None
            try:
                session = self._driver.session(database=settings.neo4j_database)
                # Execute the alert merge and consume the result
                result = await session.run(_ALERT_MERGE, **params)
                await result.consume()
                
                # Execute entity merges sequentially, consuming each result
                for relation, values in (
                    ("OBSERVED_ON", observation.hosts),
                    ("INVOLVES_USER", observation.users),
                    ("USES_IP", observation.ips),
                    ("QUERIED_DOMAIN", observation.domains),
                ):
                    if not values:
                        continue
                    result = await session.run(
                        _ENTITY_MERGE[relation][2],
                        tenant=str(tenant_id),
                        observation_id=observation.key,
                        values=list(values),
                    )
                    await result.consume()
                self._fail_count = 0
                return True
            finally:
                if session is not None:
                    try:
                        await session.close()
                    except Exception as close_exc:  # noqa: BLE001
                        logger.warning("graph.session_close_failed", error=str(close_exc)[:100])
        except Exception as exc:  # noqa: BLE001 — never block case creation
            self._fail_count += 1
            if self._fail_count == 1 or self._fail_count % 50 == 0:
                logger.warning(
                    "graph.write_failed",
                    observation=observation.key,
                    error=str(exc)[:200],
                    consecutive_failures=self._fail_count,
                )
            return False


__all__ = ["GraphProjector", "OBSERVATION_RELATIONSHIPS"]
