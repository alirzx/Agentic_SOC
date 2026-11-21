"""Merge ``(:Observation)`` nodes whose key predates the 512-char bound.

Why this exists
---------------
Graph dedup keys used to embed whatever ``process_hash`` carried. Splunk sometimes
puts **every hash of a file** in that field on separate lines, so
``file|<host>|sha1=…,md5=…,sha256=…,imphash=…`` produced keys well past the
512-character limit of the case API's ``observation_id``. Those keys also went
into Neo4j.

``observations.bounded_key()`` now bounds every key before it leaves the engine:
a long key keeps a readable prefix and gains ``|#<sha256 prefix>`` taken from the
full key. New cycles write the bounded id, so an old over-long node and its
bounded successor describe the same observation but are two nodes until this
script folds them together — otherwise the graph shows duplicate observations
and their alert/entity edges never join up.

What it does, per over-long node
--------------------------------
1. ``MERGE`` the bounded ``(:Observation)`` for the same tenant.
2. Union its scalar/list properties (``techniques``, ``hosts``, ``users``,
   ``ips``, ``domains``), take the earliest ``first_seen`` / latest
   ``last_seen``, keep ``role`` / ``time_quality`` / ``normalizer_version``.
3. Re-point every outgoing relationship the Observation layer owns
   (:data:`app.services.graph.OBSERVATION_RELATIONSHIPS`) at the bounded node.
4. Delete the old node.
5. Record the old key in ``merged_from`` so the merge is auditable.

The run is idempotent: processed nodes disappear, so a second pass finds
nothing. A node with **incoming** relationships (none are expected — the
Observation layer only owns outgoing edges) is skipped and reported, never
silently detached; pass ``--force-detach`` to drop those edges anyway.

Run it (inside the correlation service image, or from ``services/correlation``):

    python -m app.scripts.merge_truncated_observations --dry-run
    python -m app.scripts.merge_truncated_observations

No graph changes are made without ``--dry-run`` being absent; use the dry run
first to see the old → new mapping and the edge counts.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.core.config import settings
from app.services.graph import OBSERVATION_RELATIONSHIPS
from app.services.observations import MAX_OBSERVATION_KEY_CHARS, bounded_key

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

#: Fields the bounded node unions instead of overwriting.
_LIST_PROPERTIES = ("techniques", "hosts", "users", "ips", "domains")

_MATCH_TRUNCATED = """
MATCH (o:Observation)
WHERE o.observation_id IS NOT NULL
  AND size(o.observation_id) > $limit
  AND ($tenant IS NULL OR o.tenant_id = $tenant)
  AND NOT o.observation_id IN $skip
RETURN o.tenant_id AS tenant, o.observation_id AS observation_id, properties(o) AS props
ORDER BY o.observation_id
LIMIT $batch
"""

_COUNT_TRUNCATED = """
MATCH (o:Observation)
WHERE o.observation_id IS NOT NULL AND size(o.observation_id) > $limit
RETURN count(o) AS nodes
"""

# ``reduce`` keeps the list deduplicated without APOC, so the merge works on a
# bare Neo4j 5 install.
_MERGE_TARGET = """
MERGE (n:Observation {tenant_id: $tenant, observation_id: $new})
ON CREATE SET n.created_at = datetime()
SET n.key = $new,
    n.role = coalesce(n.role, $role),
    n.time_quality = coalesce(n.time_quality, $time_quality),
    n.normalizer_version = coalesce(n.normalizer_version, $normalizer_version),
    n.first_seen = CASE
        WHEN n.first_seen IS NULL THEN $first_seen
        WHEN $first_seen IS NULL THEN n.first_seen
        WHEN $first_seen < n.first_seen THEN $first_seen
        ELSE n.first_seen END,
    n.last_seen = CASE
        WHEN n.last_seen IS NULL THEN $last_seen
        WHEN $last_seen IS NULL THEN n.last_seen
        WHEN $last_seen > n.last_seen THEN $last_seen
        ELSE n.last_seen END,
    n.techniques = reduce(
        acc = [], x IN coalesce(n.techniques, []) + $techniques
        | CASE WHEN x IN acc THEN acc ELSE acc + [x] END),
    n.hosts = reduce(
        acc = [], x IN coalesce(n.hosts, []) + $hosts
        | CASE WHEN x IN acc THEN acc ELSE acc + [x] END),
    n.users = reduce(
        acc = [], x IN coalesce(n.users, []) + $users
        | CASE WHEN x IN acc THEN acc ELSE acc + [x] END),
    n.ips = reduce(
        acc = [], x IN coalesce(n.ips, []) + $ips
        | CASE WHEN x IN acc THEN acc ELSE acc + [x] END),
    n.domains = reduce(
        acc = [], x IN coalesce(n.domains, []) + $domains
        | CASE WHEN x IN acc THEN acc ELSE acc + [x] END),
    n.merged_from = reduce(
        acc = coalesce(n.merged_from, []), x IN [$old]
        | CASE WHEN x IN acc THEN acc ELSE acc + [x] END),
    n.updated_at = datetime()
"""

_INCOMING = """
MATCH (x)-[r]->(o:Observation {tenant_id: $tenant, observation_id: $old})
RETURN type(r) AS rel, count(*) AS count
"""

_DELETE_OLD = """
MATCH (o:Observation {tenant_id: $tenant, observation_id: $old})
DELETE o
"""

_DETACH_OLD = """
MATCH (o:Observation {tenant_id: $tenant, observation_id: $old})
DETACH DELETE o
"""


@dataclass(frozen=True)
class MergeCandidate:
    """One over-long key and the bounded key it now resolves to."""

    tenant: str
    old_key: str
    new_key: str


def plan_merge(tenant: Any, old_key: str) -> MergeCandidate | None:
    """Return the merge for one key, or ``None`` when it already fits the bound.

    Pure: no driver, no I/O, so the mapping the migration will apply is testable
    (and printable in ``--dry-run``) without a Neo4j instance.
    """
    if not old_key:
        return None
    new_key = bounded_key(old_key)
    if new_key == old_key:
        return None
    return MergeCandidate(tenant=str(tenant or ""), old_key=str(old_key), new_key=new_key)


def move_statement(relationship: str) -> str:
    """Cypher that re-points one relationship type at the bounded node.

    ``relationship`` is interpolated into the query (Cypher has no parameterised
    relationship types), so it is restricted to the declared Observation edges.
    """
    if relationship not in OBSERVATION_RELATIONSHIPS:
        raise ValueError(f"unsupported observation relationship: {relationship!r}")
    return f"""
MATCH (old:Observation {{tenant_id: $tenant, observation_id: $old}})
MATCH (new:Observation {{tenant_id: $tenant, observation_id: $new}})
MATCH (old)-[:{relationship}]->(m)
MERGE (new)-[:{relationship}]->(m)
RETURN count(m) AS moved
"""


async def _count_truncated(session: Any, *, limit: int) -> int:
    result = await session.run(_COUNT_TRUNCATED, limit=limit)
    row = await result.single()
    return int((row or {}).get("nodes") or 0)


async def merge_truncated_keys(
    driver: Any,
    *,
    limit: int = MAX_OBSERVATION_KEY_CHARS,
    batch_size: int = 500,
    tenant: str | None = None,
    dry_run: bool = False,
    force_detach: bool = False,
) -> dict[str, int]:
    """Fold every over-long Observation key into its bounded successor.

    Returns a counter dict so the caller (or an operator reading the log) can
    see that the pass was complete: ``truncated_before`` should equal
    ``merged + skipped`` when the run finishes, and ``truncated_after`` is 0
    unless a node was skipped for having incoming edges.
    """
    counters = {
        "truncated_before": 0,
        "merged": 0,
        "skipped": 0,
        "relationships_moved": 0,
        "truncated_after": 0,
    }
    skipped: list[str] = []

    async with driver.session(database=settings.neo4j_database) as session:
        counters["truncated_before"] = await _count_truncated(session, limit=limit)
        logger.info(
            "merge_truncated_observations.start",
            extra={"truncated": counters["truncated_before"], "dry_run": dry_run},
        )

        while True:
            result = await session.run(
                _MATCH_TRUNCATED,
                limit=limit,
                batch=batch_size,
                tenant=tenant,
                skip=skipped,
            )
            rows = await result.data()
            if not rows:
                break

            for row in rows:
                candidate = plan_merge(row.get("tenant"), str(row.get("observation_id") or ""))
                if candidate is None:  # pragma: no cover — MATCH already filtered these
                    continue

                if dry_run:
                    logger.info(
                        "merge_truncated_observations.plan",
                        extra={
                            "tenant": candidate.tenant,
                            "old_chars": len(candidate.old_key),
                            "new_chars": len(candidate.new_key),
                            "old": candidate.old_key[:120],
                            "new": candidate.new_key,
                        },
                    )
                    counters["merged"] += 1
                    continue

                incoming = await (
                    await session.run(
                        _INCOMING,
                        tenant=candidate.tenant,
                        old=candidate.old_key,
                    )
                ).data()
                if incoming and not force_detach:
                    skipped.append(candidate.old_key)
                    counters["skipped"] += 1
                    logger.error(
                        "merge_truncated_observations.incoming_relationships",
                        extra={
                            "tenant": candidate.tenant,
                            "old": candidate.old_key[:120],
                            "incoming": incoming,
                            "action": "skipped (re-run with --force-detach to drop them)",
                        },
                    )
                    continue

                props: Mapping[str, Any] = row.get("props") or {}
                await session.run(
                    _MERGE_TARGET,
                    tenant=candidate.tenant,
                    old=candidate.old_key,
                    new=candidate.new_key,
                    role=props.get("role"),
                    time_quality=props.get("time_quality"),
                    normalizer_version=props.get("normalizer_version"),
                    first_seen=props.get("first_seen"),
                    last_seen=props.get("last_seen"),
                    **{prop: list(props.get(prop) or []) for prop in _LIST_PROPERTIES},
                )

                for relationship in OBSERVATION_RELATIONSHIPS:
                    moved = await (
                        await session.run(
                            move_statement(relationship),
                            tenant=candidate.tenant,
                            old=candidate.old_key,
                            new=candidate.new_key,
                        )
                    ).single()
                    counters["relationships_moved"] += int((moved or {}).get("moved") or 0)

                await session.run(
                    _DETACH_OLD if force_detach else _DELETE_OLD,
                    tenant=candidate.tenant,
                    old=candidate.old_key,
                )
                counters["merged"] += 1

            if dry_run:
                # Nothing was deleted, so the same rows would come back forever.
                break

        counters["truncated_after"] = await _count_truncated(session, limit=limit)

    logger.info("merge_truncated_observations.done", extra=counters)
    return counters


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Merge Neo4j Observation nodes whose key exceeds the 512-char bound.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the old -> new key mapping for one batch without writing anything.",
    )
    parser.add_argument(
        "--tenant",
        default=None,
        help="Only migrate one tenant id (default: every tenant).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Nodes per match batch (default: 500).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=MAX_OBSERVATION_KEY_CHARS,
        help="Key length above which a node is migrated (default: 512).",
    )
    parser.add_argument(
        "--force-detach",
        action="store_true",
        help="Delete old nodes even if they have incoming relationships (drops those edges).",
    )
    args = parser.parse_args(argv)

    try:
        from neo4j import AsyncGraphDatabase  # noqa: PLC0415 — optional dependency
    except ImportError:
        logger.error(
            "merge_truncated_observations.driver_missing",
            extra={"hint": "install the neo4j package (see services/correlation requirements)"},
        )
        return 2

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )
    try:
        await driver.verify_connectivity()
        counters = await merge_truncated_keys(
            driver,
            limit=args.limit,
            batch_size=args.batch_size,
            tenant=args.tenant,
            dry_run=args.dry_run,
            force_detach=args.force_detach,
        )
    finally:
        await driver.close()

    if counters["skipped"]:
        logger.error(
            "merge_truncated_observations.incomplete",
            extra={"skipped": counters["skipped"], "remaining": counters["truncated_after"]},
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover — CLI entry point
    raise SystemExit(asyncio.run(main()))
