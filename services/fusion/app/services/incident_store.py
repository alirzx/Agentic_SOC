"""Durable Postgres store for Fusion correlation incidents.

Redis remains the hot-path correlator cache. This store:
* upserts incident rows so restart / Redis TTL cannot erase membership;
* restores open incidents into Redis when the cache misses;
* records optional ``case_id`` updates from the agents Case promoter.

Fail-soft: DB outages never crash the fusion worker.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

import asyncpg
import structlog

from app.models.alert import AlertSeverity, IncidentSummary

logger = structlog.get_logger()


def _asyncpg_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


class IncidentStore:
    """asyncpg-backed writer/reader for ``fusion_incidents``."""

    def __init__(self, database_url: str, pool_size: int = 2) -> None:
        self._dsn = _asyncpg_dsn(database_url)
        self._pool_size = pool_size
        self._pool: asyncpg.Pool | None = None

    async def start(self) -> None:
        try:
            self._pool = await asyncpg.create_pool(
                self._dsn, min_size=1, max_size=self._pool_size, timeout=10
            )
            logger.info("incident_store.started")
        except Exception as exc:  # noqa: BLE001
            self._pool = None
            logger.error("incident_store.connect_failed", error=str(exc))

    async def stop(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def _ensure_pool(self) -> asyncpg.Pool | None:
        if self._pool is None:
            await self.start()
        return self._pool

    async def upsert(self, incident: IncidentSummary, *, status: str = "open") -> bool:
        pool = await self._ensure_pool()
        if pool is None:
            return False
        corr = incident.correlation_keys[0] if incident.correlation_keys else ""
        alert_uuids: list[UUID] = []
        for raw in incident.alert_ids:
            try:
                alert_uuids.append(UUID(str(raw)))
            except (ValueError, TypeError):
                continue
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO fusion_incidents (
                        id, tenant_id, correlation_key, status, title, severity,
                        alert_count, alert_ids, first_seen, last_seen,
                        mitre_techniques, created_at, updated_at
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6,
                        $7, $8::uuid[], $9, $10,
                        $11::jsonb, COALESCE($9, now()), now()
                    )
                    ON CONFLICT (id) DO UPDATE SET
                        status = EXCLUDED.status,
                        title = EXCLUDED.title,
                        severity = EXCLUDED.severity,
                        alert_count = EXCLUDED.alert_count,
                        alert_ids = EXCLUDED.alert_ids,
                        last_seen = GREATEST(
                            COALESCE(fusion_incidents.last_seen, EXCLUDED.last_seen),
                            COALESCE(EXCLUDED.last_seen, fusion_incidents.last_seen)
                        ),
                        mitre_techniques = EXCLUDED.mitre_techniques,
                        updated_at = now()
                    """,
                    incident.id,
                    incident.tenant_id,
                    corr,
                    status,
                    incident.title[:500],
                    incident.severity.value if isinstance(incident.severity, AlertSeverity) else str(incident.severity),
                    int(incident.alert_count),
                    alert_uuids,
                    incident.first_seen,
                    incident.last_seen,
                    json.dumps(list(incident.mitre_techniques or [])),
                )
            return True
        except Exception as exc:  # noqa: BLE001 — pre-migration / outage
            logger.debug("incident_store.upsert_failed", error=str(exc), incident_id=str(incident.id))
            return False

    async def find_open(self, tenant_id: UUID, correlation_key: str) -> IncidentSummary | None:
        pool = await self._ensure_pool()
        if pool is None or not correlation_key:
            return None
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT id, tenant_id, correlation_key, title, severity, alert_count,
                           alert_ids, first_seen, last_seen, mitre_techniques, case_id
                      FROM fusion_incidents
                     WHERE tenant_id = $1
                       AND correlation_key = $2
                       AND status = 'open'
                     ORDER BY last_seen DESC NULLS LAST
                     LIMIT 1
                    """,
                    tenant_id,
                    correlation_key,
                )
            if row is None:
                return None
            return self._row_to_summary(row)
        except Exception as exc:  # noqa: BLE001
            logger.debug("incident_store.find_open_failed", error=str(exc))
            return None

    async def get(self, incident_id: UUID) -> IncidentSummary | None:
        pool = await self._ensure_pool()
        if pool is None:
            return None
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT id, tenant_id, correlation_key, title, severity, alert_count,
                           alert_ids, first_seen, last_seen, mitre_techniques, case_id
                      FROM fusion_incidents
                     WHERE id = $1
                     LIMIT 1
                    """,
                    incident_id,
                )
            return self._row_to_summary(row) if row else None
        except Exception as exc:  # noqa: BLE001
            logger.debug("incident_store.get_failed", error=str(exc))
            return None

    async def link_alert(self, incident_id: UUID, alert_id: UUID, tenant_id: UUID) -> bool:
        pool = await self._ensure_pool()
        if pool is None:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE alerts
                       SET fusion_incident_id = $1, updated_at = now()
                     WHERE id = $2 AND tenant_id = $3
                    """,
                    incident_id,
                    alert_id,
                    tenant_id,
                )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug("incident_store.link_alert_failed", error=str(exc))
            return False

    async def set_case_id(self, incident_id: UUID, case_id: UUID, tenant_id: UUID) -> bool:
        pool = await self._ensure_pool()
        if pool is None:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE fusion_incidents
                       SET case_id = $1, updated_at = now()
                     WHERE id = $2 AND tenant_id = $3
                    """,
                    case_id,
                    incident_id,
                    tenant_id,
                )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug("incident_store.set_case_failed", error=str(exc))
            return False

    @staticmethod
    def _row_to_summary(row: Any) -> IncidentSummary:
        techniques = row["mitre_techniques"]
        if isinstance(techniques, str):
            techniques = json.loads(techniques)
        alert_ids = [str(a) for a in (row["alert_ids"] or [])]
        return IncidentSummary(
            id=row["id"],
            tenant_id=row["tenant_id"],
            title=row["title"] or "",
            severity=AlertSeverity(str(row["severity"] or "medium").lower()),
            alert_count=int(row["alert_count"] or 1),
            alert_ids=alert_ids,
            mitre_techniques=list(techniques or []),
            correlation_keys=[row["correlation_key"]] if row["correlation_key"] else [],
            first_seen=row["first_seen"] or datetime.utcnow(),
            last_seen=row["last_seen"] or datetime.utcnow(),
        )
