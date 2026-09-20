"""
Alert deduplication using fingerprinting and a Redis sliding-window cache.
"""

from typing import Any

import redis.asyncio as aioredis
import structlog

from app.core.config import settings
from app.models.alert import RawAlert

logger = structlog.get_logger()

_DEDUP_PREFIX = "aisoc:fusion:dedup:"


class Deduplicator:
    """Deduplicates incoming alerts using SHA-256 fingerprints stored in Redis."""

    def __init__(self, redis_client: aioredis.Redis, sink: Any = None) -> None:
        self._redis = redis_client
        self._window = settings.dedup_window_seconds
        self._sink = sink

    def set_sink(self, sink: Any) -> None:
        """Attach the Postgres alert sink for durable fingerprint lookup."""
        self._sink = sink

    async def is_duplicate(self, alert: RawAlert) -> tuple[bool, str | None]:
        """
        Check if an alert is a duplicate within the deduplication window.

        Returns:
            (is_duplicate, original_alert_id)
        """
        fingerprint = alert.fingerprint()
        key = f"{_DEDUP_PREFIX}{fingerprint}"

        existing = await self._redis.get(key)
        if existing:
            logger.debug(
                "Duplicate alert detected",
                fingerprint=fingerprint,
                original_id=existing.decode(),
                alert_id=str(alert.id),
            )
            return True, existing.decode()

        if self._sink is not None:
            try:
                found = await self._sink.lookup_dedup(alert.tenant_id, fingerprint)
            except Exception as exc:  # noqa: BLE001 — Redis path remains authoritative if PG is down
                logger.debug("dedup.postgres_lookup_failed", error=str(exc))
                found = None
            if found:
                await self._redis.set(key, found, ex=self._window)
                return True, found

        return False, None

    async def register(self, alert: RawAlert) -> None:
        """Register an alert fingerprint to suppress future duplicates."""
        fingerprint = alert.fingerprint()
        key = f"{_DEDUP_PREFIX}{fingerprint}"
        await self._redis.set(key, str(alert.id), ex=self._window)
        logger.debug(
            "Alert fingerprint registered",
            fingerprint=fingerprint,
            alert_id=str(alert.id),
            ttl_seconds=self._window,
        )
