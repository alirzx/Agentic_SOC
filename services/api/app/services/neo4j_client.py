"""Neo4j graph client for entity correlation analysis.

This module provides async access to the Neo4j entity graph to calculate
graph distance scores (L3) for alert suggestions.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Async Neo4j client for graph queries."""

    def __init__(self, uri: str, username: str, password: str):
        """
        Initialize Neo4j client.

        **Args:**
        - uri: Neo4j connection URI (e.g., 'bolt://localhost:7687')
        - username: Neo4j username
        - password: Neo4j password
        """
        self.uri = uri
        self.username = username
        self.password = password
        self.driver = None

    async def connect(self):
        """Connect to Neo4j (lazy initialization)."""
        if self.driver is None:
            try:
                from neo4j import AsyncGraphDatabase
                self.driver = AsyncGraphDatabase.driver(
                    self.uri,
                    auth=(self.username, self.password),
                )
                # Test connection
                async with self.driver.session() as session:
                    await session.run("RETURN 1")
                logger.info("✅ Neo4j connected")
            except Exception as e:
                logger.warning(f"⚠️ Neo4j connection failed: {e}")
                self.driver = None
                return False
        return True

    async def close(self):
        """Close Neo4j connection."""
        if self.driver:
            await self.driver.close()
            self.driver = None

    async def get_shortest_path_distance(
        self,
        tenant_id: str,
        entity_a: str,
        entity_b: str,
        max_hops: int = 3,
    ) -> Optional[int]:
        """
        Calculate shortest path distance between two entities in the graph.

        **Args:**
        - tenant_id: Tenant UUID
        - entity_a: First entity (e.g., "192.168.1.100", "alice@example.com")
        - entity_b: Second entity
        - max_hops: Maximum path length to search (default 3)

        **Returns:**
        - Distance (0-max_hops) or None if no path found
        """
        if not await self.connect():
            return None

        if not entity_a or not entity_b or entity_a == entity_b:
            return None

        try:
            async with self.driver.session() as session:
                # Cypher query: find shortest path
                query = """
                    MATCH path = shortestPath(
                        (a {value: $entity_a, tenant_id: $tenant_id})-[*..{max_hops}]-(b {value: $entity_b, tenant_id: $tenant_id})
                    )
                    RETURN length(path) as distance
                    LIMIT 1
                """
                result = await session.run(
                    query,
                    entity_a=entity_a,
                    entity_b=entity_b,
                    tenant_id=tenant_id,
                    max_hops=max_hops,
                )
                record = await result.single()
                if record:
                    return record["distance"]
                return None
        except Exception as e:
            logger.warning(f"⚠️ Neo4j query failed: {e}")
            return None

    async def get_connected_entities(
        self,
        tenant_id: str,
        entity: str,
        max_hops: int = 2,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Get all entities connected to a given entity.

        **Args:**
        - tenant_id: Tenant UUID
        - entity: Starting entity
        - max_hops: Maximum hops to search
        - limit: Maximum results to return

        **Returns:**
        - List of connected entities with distance
        """
        if not await self.connect():
            return []

        if not entity:
            return []

        try:
            async with self.driver.session() as session:
                query = """
                    MATCH (a {value: $entity, tenant_id: $tenant_id})-[*1..{max_hops}]-(b {tenant_id: $tenant_id})
                    WHERE a <> b
                    RETURN 
                        DISTINCT b.value as entity,
                        b.entity_type as type,
                        min(length(shortestPath((a)-[*]->(b)))) as distance
                    LIMIT {limit}
                """
                result = await session.run(
                    query,
                    entity=entity,
                    tenant_id=tenant_id,
                    max_hops=max_hops,
                    limit=limit,
                )
                records = await result.fetch(limit)
                return [
                    {
                        "entity": record["entity"],
                        "type": record["type"],
                        "distance": record["distance"],
                    }
                    for record in records
                ]
        except Exception as e:
            logger.warning(f"⚠️ Neo4j query failed: {e}")
            return []


# Global Neo4j client instance
_neo4j_client: Optional[Neo4jClient] = None


def get_neo4j_client() -> Neo4jClient:
    """Get or create the global Neo4j client."""
    global _neo4j_client

    if _neo4j_client is None:
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        username = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "password")

        _neo4j_client = Neo4jClient(uri, username, password)

    return _neo4j_client


async def close_neo4j_client():
    """Close global Neo4j client on shutdown."""
    global _neo4j_client

    if _neo4j_client:
        await _neo4j_client.close()
        _neo4j_client = None
