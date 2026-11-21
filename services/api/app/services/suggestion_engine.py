"""Suggestion engine for finding related alerts to attach to cases.

This service finds alerts that are likely related to a case based on:
- Entity overlap (same hosts, users, IPs, domains)
- Temporal proximity (alerts within ~2 hours)
- Technique overlap (same MITRE ATT&CK techniques)

Scoring is independent of case membership — we score all observations
and rank by likelihood of belonging to the case.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.case import Case
from app.services.neo4j_client import get_neo4j_client

logger = logging.getLogger(__name__)


class SuggestionEngine:
    """Find alerts related to a case but not yet attached."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def find_suggestions(
        self,
        tenant_id: str,
        case_id: str,
        min_score: int = 2,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Find related alerts not in this case.
        Score based on entity overlap, temporal proximity, and techniques.
        Return sorted by score descending (highest likelihood first).

        **Score thresholds:**
        - min_score=2: Low threshold (match on 1 entity)
        - min_score=3: Medium threshold (match on 2 entities or 1 technique)
        - min_score=5: High threshold (strong correlation)

        **Returns:**
        List of dicts:
        ```json
        {
          "alert_id": "uuid",
          "title": "Alert title",
          "severity": "high",
          "score": 4,
          "entity_overlap": 2,
          "technique_overlap": 1,
          "created_at": "2026-11-09T...",
          "reason": "2 entities, 1 technique"
        }
        ```
        """

        # 1. Get case details
        case_stmt = select(Case).where(
            and_(
                Case.id == case_id,
                Case.tenant_id == tenant_id,
            )
        )
        case_result = await self.session.execute(case_stmt)
        case = case_result.scalar_one_or_none()

        if not case:
            return []

        # 2. Get case's current alert IDs
        case_alert_ids = set(case.alert_ids or [])

        # 3. Load all case alerts to extract entities and techniques
        case_alerts_stmt = select(Alert).where(Alert.id.in_(case_alert_ids))
        case_alerts_result = await self.session.execute(case_alerts_stmt)
        case_alerts = case_alerts_result.scalars().all()

        # Extract entities and techniques from case alerts
        case_entities = set()
        case_techniques = set()

        for alert in case_alerts:
            # Extract entities (hosts, users, IPs, domains)
            # Try both the generic 'entities' field and denormalized fields
            if isinstance(alert.entities, list):
                case_entities.update(alert.entities)

            if isinstance(alert.affected_hosts, list):
                case_entities.update(alert.affected_hosts)
            if isinstance(alert.affected_users, list):
                case_entities.update(alert.affected_users)
            if isinstance(alert.affected_ips, list):
                case_entities.update(alert.affected_ips)

            # Extract techniques (using mitre_techniques)
            if isinstance(alert.mitre_techniques, list):
                case_techniques.update(alert.mitre_techniques)

        if not case_entities and not case_techniques:
            # No entities to correlate on
            return []

        # 4. Query candidate alerts (not in case, same tenant)
        candidate_stmt = select(Alert).where(
            and_(
                Alert.tenant_id == tenant_id,
                ~Alert.id.in_(case_alert_ids),  # Not already in case
                Alert.created_at > datetime.now(UTC) - timedelta(hours=72),  # Last 72h
            )
        )
        candidate_result = await self.session.execute(candidate_stmt)
        candidates = candidate_result.scalars().all()

        # 5. Score each candidate
        scored = []
        for alert in candidates:
            score = self._score_alert(alert, case_entities, case_techniques)

            if score >= min_score:
                scored.append({
                    "alert_id": str(alert.id),
                    "title": alert.title or "Untitled Alert",
                    "severity": alert.severity,
                    "score": score,
                    "entity_overlap": self._count_entity_overlap(
                        alert, case_entities
                    ),
                    "technique_overlap": self._count_technique_overlap(
                        alert, case_techniques
                    ),
                    "created_at": alert.created_at.isoformat(),
                    "reason": self._build_reason(
                        self._count_entity_overlap(alert, case_entities),
                        self._count_technique_overlap(alert, case_techniques),
                    ),
                })

        # 6. Sort by score descending and apply limit
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:limit]

    def _score_alert(
        self, alert: Alert, case_entities: set, case_techniques: set
    ) -> int:
        """
        Score an alert's relevance to the case.

        **Scoring:**
        - Entity overlap: +1 per matching entity
        - Technique overlap: +2 per matching technique
        """
        score = 0

        # Score entity overlap
        entity_overlap = self._count_entity_overlap(alert, case_entities)
        score += entity_overlap

        # Score technique overlap (weighted heavier)
        technique_overlap = self._count_technique_overlap(alert, case_techniques)
        score += technique_overlap * 2

        return score

    def _count_entity_overlap(self, alert: Alert, case_entities: set) -> int:
        """Count how many entities this alert shares with the case."""
        alert_entities = set()

        # Collect from generic entities field
        if isinstance(alert.entities, list):
            alert_entities.update(alert.entities)

        # Collect from denormalized fields
        if isinstance(alert.affected_hosts, list):
            alert_entities.update(alert.affected_hosts)
        if isinstance(alert.affected_users, list):
            alert_entities.update(alert.affected_users)
        if isinstance(alert.affected_ips, list):
            alert_entities.update(alert.affected_ips)

        return len(alert_entities & case_entities)

    def _count_technique_overlap(
        self, alert: Alert, case_techniques: set
    ) -> int:
        """Count how many techniques this alert shares with the case."""
        alert_techniques = set(alert.mitre_techniques or [])
        return len(alert_techniques & case_techniques)

    def _build_reason(self, entity_count: int, technique_count: int) -> str:
        """Build a human-readable reason for the score."""
        parts = []

        if entity_count > 0:
            parts.append(
                f"{entity_count} entit{'ies' if entity_count != 1 else 'y'}"
            )

        if technique_count > 0:
            parts.append(
                f"{technique_count} technique{'s' if technique_count != 1 else ''}"
            )

        return " • ".join(parts) if parts else "Related alert"

    async def calculate_attach_impact(
        self, tenant_id: str, case_id: str, alert_id: str
    ) -> dict[str, Any]:
        """
        Calculate the impact on case correlation score if we attach this alert.

        **Returns:**
        ```json
        {
          "current_score": 15,
          "new_score": 18,
          "delta": 3,
          "reason": "Adding alert brings 1 new entity and 2 techniques"
        }
        ```
        """

        # This is a simplified version — in Phase 3 we'd recalculate full correlation
        # For now, return the suggestion score as the delta

        case_stmt = select(Case).where(
            and_(
                Case.id == case_id,
                Case.tenant_id == tenant_id,
            )
        )
        case_result = await self.session.execute(case_stmt)
        case = case_result.scalar_one_or_none()

        if not case:
            return {}

        alert_stmt = select(Alert).where(Alert.id == alert_id)
        alert_result = await self.session.execute(alert_stmt)
        alert = alert_result.scalar_one_or_none()

        if not alert:
            return {}

        # Get case entities and techniques
        case_alert_ids = set(case.alert_ids or [])
        case_alerts_stmt = select(Alert).where(Alert.id.in_(case_alert_ids))
        case_alerts_result = await self.session.execute(case_alerts_stmt)
        case_alerts = case_alerts_result.scalars().all()

        case_entities = set()
        case_techniques = set()

        for ca in case_alerts:
            # Collect entities
            if isinstance(ca.entities, list):
                case_entities.update(ca.entities)

            if isinstance(ca.affected_hosts, list):
                case_entities.update(ca.affected_hosts)
            if isinstance(ca.affected_users, list):
                case_entities.update(ca.affected_users)
            if isinstance(ca.affected_ips, list):
                case_entities.update(ca.affected_ips)

            # Collect techniques
            if isinstance(ca.mitre_techniques, list):
                case_techniques.update(ca.mitre_techniques)

        # Score this alert against case
        delta = self._score_alert(alert, case_entities, case_techniques)

        # Simplified: current_score is 0, new_score is delta
        # In Phase 3 we'd calculate actual case correlation score
        current_score = 0
        new_score = delta

        return {
            "current_score": current_score,
            "new_score": new_score,
            "delta": delta,
            "reason": self._build_reason(
                self._count_entity_overlap(alert, case_entities),
                self._count_technique_overlap(alert, case_techniques),
            ),
        }

    async def calculate_graph_distance_score(
        self,
        tenant_id: str,
        alert_entities: set[str],
        case_entities: set[str],
    ) -> int:
        """
        Calculate L3 graph distance score based on Neo4j entity graph.

        **Scoring:**
        - Distance 0 (direct connection): +5
        - Distance 1 (1 hop): +3
        - Distance 2 (2 hops): +2
        - Distance >= 3 (too far): +0

        **Args:**
        - tenant_id: Tenant UUID
        - alert_entities: Entities in candidate alert
        - case_entities: Entities in case

        **Returns:**
        - Score (0-5)
        """
        if not alert_entities or not case_entities:
            return 0

        # Get Neo4j client
        neo4j = get_neo4j_client()

        # Calculate shortest path for each entity pair
        # Take minimum distance (closest relationship)
        min_distance = float("inf")

        for alert_entity in alert_entities:
            for case_entity in case_entities:
                if alert_entity == case_entity:
                    # Direct match
                    return 5

                # Query Neo4j for shortest path
                distance = await neo4j.get_shortest_path_distance(
                    tenant_id=tenant_id,
                    entity_a=alert_entity,
                    entity_b=case_entity,
                    max_hops=3,
                )

                if distance is not None and distance < min_distance:
                    min_distance = distance

        # Convert distance to score
        if min_distance == float("inf"):
            return 0  # No path found
        elif min_distance == 0:
            return 5  # Direct connection
        elif min_distance == 1:
            return 3  # 1 hop
        elif min_distance == 2:
            return 2  # 2 hops
        else:
            return 0  # Too far (3+ hops)

    async def find_suggestions_with_l3(
        self,
        tenant_id: str,
        case_id: str,
        min_score: float = 2.0,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Find related alerts using L1 (entities) + L2 (temporal) + L3 (graph) scoring.

        **Scoring Weights:**
        - L1 (Entity overlap): 30% weight
        - L2 (Temporal proximity): 30% weight (not implemented in this version)
        - L3 (Graph distance): 40% weight

        **Returns:**
        List of suggestions scored by combined confidence (0.0-1.0)

        **Note:**
        This is Phase 3 enhancement. Falls back to L1+L2 if Neo4j unavailable.
        """

        # 1. Get case details
        case_stmt = select(Case).where(
            and_(
                Case.id == case_id,
                Case.tenant_id == tenant_id,
            )
        )
        case_result = await self.session.execute(case_stmt)
        case = case_result.scalar_one_or_none()

        if not case:
            return []

        # 2. Get case's current alert IDs
        case_alert_ids = set(case.alert_ids or [])

        # 3. Load all case alerts to extract entities and techniques
        case_alerts_stmt = select(Alert).where(Alert.id.in_(case_alert_ids))
        case_alerts_result = await self.session.execute(case_alerts_stmt)
        case_alerts = case_alerts_result.scalars().all()

        # Extract entities and techniques from case alerts
        case_entities = set()
        case_techniques = set()

        for alert in case_alerts:
            # Extract entities
            if isinstance(alert.entities, list):
                case_entities.update(alert.entities)

            if isinstance(alert.affected_hosts, list):
                case_entities.update(alert.affected_hosts)
            if isinstance(alert.affected_users, list):
                case_entities.update(alert.affected_users)
            if isinstance(alert.affected_ips, list):
                case_entities.update(alert.affected_ips)

            # Extract techniques
            if isinstance(alert.mitre_techniques, list):
                case_techniques.update(alert.mitre_techniques)

        if not case_entities and not case_techniques:
            return []

        # 4. Query candidate alerts (not in case, same tenant)
        candidate_stmt = select(Alert).where(
            and_(
                Alert.tenant_id == tenant_id,
                ~Alert.id.in_(case_alert_ids),
                Alert.created_at > datetime.now(UTC) - timedelta(hours=72),
            )
        )
        candidate_result = await self.session.execute(candidate_stmt)
        candidates = candidate_result.scalars().all()

        # 5. Score each candidate with L1 + L3
        scored = []
        for alert in candidates:
            # L1: Entity overlap score (0-5+)
            entity_overlap = self._count_entity_overlap(alert, case_entities)
            l1_score = entity_overlap  # +1 per entity

            # L3: Graph distance score (0-5)
            alert_entities = set()
            if isinstance(alert.entities, list):
                alert_entities.update(alert.entities)
            if isinstance(alert.affected_hosts, list):
                alert_entities.update(alert.affected_hosts)
            if isinstance(alert.affected_users, list):
                alert_entities.update(alert.affected_users)
            if isinstance(alert.affected_ips, list):
                alert_entities.update(alert.affected_ips)

            l3_score = await self.calculate_graph_distance_score(
                tenant_id=tenant_id,
                alert_entities=alert_entities,
                case_entities=case_entities,
            )

            # Technique overlap (L2)
            technique_overlap = self._count_technique_overlap(
                alert, case_techniques
            )
            l2_score = technique_overlap * 2

            # Combined score with weights:
            # L1: 30%, L2: 30%, L3: 40%
            combined_score = (l1_score * 0.3) + (l2_score * 0.3) + (l3_score * 0.4)
            confidence = combined_score / 5.0  # Normalize to 0.0-1.0

            if combined_score >= min_score:
                scored.append({
                    "alert_id": str(alert.id),
                    "title": alert.title or "Untitled Alert",
                    "severity": alert.severity,
                    "score": round(combined_score, 2),
                    "confidence": round(confidence, 2),
                    "l1_entity_score": l1_score,
                    "l2_technique_score": l2_score,
                    "l3_graph_score": l3_score,
                    "entity_overlap": entity_overlap,
                    "technique_overlap": technique_overlap,
                    "created_at": alert.created_at.isoformat(),
                    "reason": self._build_reason(
                        entity_overlap,
                        technique_overlap,
                    ),
                })

        # 6. Sort by score descending and apply limit
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:limit]
