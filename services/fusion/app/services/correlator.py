"""
Alert correlation engine: groups related alerts into incidents using entity and
MITRE ATT&CK context stored in Redis, with optional durable Postgres restore.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import redis.asyncio as aioredis
import structlog

from app.core.config import settings
from app.models.alert import AlertSeverity, IncidentSummary, RawAlert

logger = structlog.get_logger()

_CORRELATION_PREFIX = "aisoc:fusion:correlation:"
_INCIDENT_PREFIX = "aisoc:fusion:incident:"

_SEVERITY_ORDER = {
    AlertSeverity.CRITICAL: 5,
    AlertSeverity.HIGH: 4,
    AlertSeverity.MEDIUM: 3,
    AlertSeverity.LOW: 2,
    AlertSeverity.INFO: 1,
}


def _max_severity(a: AlertSeverity, b: AlertSeverity) -> AlertSeverity:
    return a if _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b] else b


class Correlator:
    """Correlates alerts into incidents using entity-based grouping."""

    def __init__(self, redis_client: aioredis.Redis, store: Any = None) -> None:
        self._redis = redis_client
        self._window = settings.correlation_window_seconds
        self._max_alerts = settings.max_alerts_per_incident
        self._store = store

    def set_store(self, store: Any) -> None:
        self._store = store

    async def correlate(self, alert: RawAlert) -> tuple[bool, IncidentSummary]:
        """
        Attempt to correlate an alert to an existing incident.

        Returns:
            (is_correlated_to_existing, incident_summary)
        """
        corr_key = alert.correlation_key()
        index_key = f"{_CORRELATION_PREFIX}{corr_key}"

        incident_id_bytes = await self._redis.get(index_key)
        incident: IncidentSummary | None = None

        if incident_id_bytes:
            incident_id = incident_id_bytes.decode() if isinstance(incident_id_bytes, bytes) else str(incident_id_bytes)
            incident = await self._load_incident(incident_id)
            if incident is None and self._store is not None:
                try:
                    incident = await self._store.get(UUID(incident_id))
                except (ValueError, TypeError):
                    incident = None

        if incident is None and self._store is not None:
            # Redis TTL miss → restore open durable incident for this key.
            try:
                incident = await self._store.find_open(alert.tenant_id, corr_key)
            except Exception as exc:  # noqa: BLE001
                logger.debug("correlator.durable_restore_failed", error=str(exc))
                incident = None
            if incident is not None:
                await self._save_incident(incident)
                await self._redis.set(index_key, str(incident.id), ex=self._window)

        if incident is not None and incident.alert_count < self._max_alerts:
            incident = await self._merge_alert(incident, alert)
            await self._save_incident(incident)
            await self._persist_durable(incident, status="open")
            await self._link_alert(incident, alert)
            logger.info(
                "Alert correlated to existing incident",
                incident_id=str(incident.id),
                alert_id=str(alert.id),
                alert_count=incident.alert_count,
            )
            return True, incident

        if incident is not None and incident.alert_count >= self._max_alerts:
            await self._persist_durable(incident, status="capped")

        incident = self._create_incident(alert)
        await self._save_incident(incident)
        await self._redis.set(index_key, str(incident.id), ex=self._window)
        await self._persist_durable(incident, status="open")
        await self._link_alert(incident, alert)
        logger.info(
            "New incident created from alert",
            incident_id=str(incident.id),
            alert_id=str(alert.id),
            correlation_key=corr_key,
        )
        return False, incident

    def _create_incident(self, alert: RawAlert) -> IncidentSummary:
        seen_at = alert.event_time or alert.created_at
        return IncidentSummary(
            id=uuid4(),
            tenant_id=alert.tenant_id,
            title=f"Incident: {alert.title}",
            severity=alert.severity,
            alert_count=1,
            alert_ids=[str(alert.id)],
            src_ips=[alert.src_ip] if alert.src_ip else [],
            hostnames=[alert.hostname] if alert.hostname else [],
            usernames=[alert.username] if alert.username else [],
            mitre_tactics=list(set(alert.mitre_tactics)),
            mitre_techniques=list(set(alert.mitre_techniques)),
            correlation_keys=[alert.correlation_key()],
            first_seen=seen_at,
            last_seen=seen_at,
        )

    async def _merge_alert(self, incident: IncidentSummary, alert: RawAlert) -> IncidentSummary:
        incident.alert_count += 1
        aid = str(alert.id)
        if aid not in incident.alert_ids:
            incident.alert_ids.append(aid)
        incident.severity = _max_severity(incident.severity, alert.severity)
        observed = alert.event_time or alert.created_at or datetime.utcnow()
        if incident.last_seen is None or observed > incident.last_seen:
            incident.last_seen = observed

        if alert.src_ip and alert.src_ip not in incident.src_ips:
            incident.src_ips.append(alert.src_ip)
        if alert.hostname and alert.hostname not in incident.hostnames:
            incident.hostnames.append(alert.hostname)
        if alert.username and alert.username not in incident.usernames:
            incident.usernames.append(alert.username)

        for tactic in alert.mitre_tactics:
            if tactic not in incident.mitre_tactics:
                incident.mitre_tactics.append(tactic)
        for technique in alert.mitre_techniques:
            if technique not in incident.mitre_techniques:
                incident.mitre_techniques.append(technique)

        corr_key = alert.correlation_key()
        if corr_key not in incident.correlation_keys:
            incident.correlation_keys.append(corr_key)

        return incident

    async def _persist_durable(self, incident: IncidentSummary, *, status: str) -> None:
        if self._store is None:
            return
        try:
            await self._store.upsert(incident, status=status)
        except Exception as exc:  # noqa: BLE001
            logger.debug("correlator.durable_upsert_failed", error=str(exc))

    async def _link_alert(self, incident: IncidentSummary, alert: RawAlert) -> None:
        if self._store is None:
            return
        try:
            await self._store.link_alert(incident.id, alert.id, alert.tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("correlator.link_alert_failed", error=str(exc))

    async def _save_incident(self, incident: IncidentSummary) -> None:
        key = f"{_INCIDENT_PREFIX}{incident.id}"
        await self._redis.set(
            key,
            incident.model_dump_json(),
            ex=self._window,
        )

    async def _load_incident(self, incident_id: str) -> IncidentSummary | None:
        key = f"{_INCIDENT_PREFIX}{incident_id}"
        data = await self._redis.get(key)
        if not data:
            return None
        return IncidentSummary.model_validate_json(data)
