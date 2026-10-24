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
            original_id = existing.decode() if isinstance(existing, bytes) else str(existing)
            logger.debug(
                "Duplicate alert detected",
                fingerprint=fingerprint,
                original_id=original_id,
                alert_id=str(alert.id),
            )
            if self._sink is not None:
                await self._safe_touch(alert, original_id)
            return True, original_id

        if self._sink is not None:
            try:
                found = await self._sink.lookup_dedup(alert.tenant_id, fingerprint)
            except Exception as exc:  # noqa: BLE001 — Redis path remains authoritative if PG is down
                logger.debug("dedup.postgres_lookup_failed", error=str(exc))
                found = None
            if found:
                await self._redis.set(key, found, ex=self._window)
                await self._safe_touch(alert, found)
                return True, found

        return False, None

    async def _safe_touch(self, alert: RawAlert, original_id: str) -> None:
        """Best-effort last_seen / occurrence bump on the canonical row."""
        if self._sink is None or not hasattr(self._sink, "touch_duplicate"):
            return
        try:
            await self._sink.touch_duplicate(
                alert.tenant_id,
                alert.fingerprint(),
                event_time=getattr(alert, "event_time", None),
                original_id=original_id,
            )
        except Exception as exc:  # noqa: BLE001 — never fail the fuse path on metrics
            logger.debug("dedup.touch_failed", error=str(exc), original_id=original_id)

    async def register(self, alert: RawAlert) -> bool:
        """Register an alert fingerprint. Returns True if this caller won the race.

        Uses Redis ``SET NX`` so concurrent workers cannot both believe they
        own a new fingerprint. The loser should treat the alert as a duplicate
        of the winner's id (caller re-checks via ``is_duplicate``).
        """
        fingerprint = alert.fingerprint()
        key = f"{_DEDUP_PREFIX}{fingerprint}"
        # aiokafka redis: set(..., nx=True) → True if set, None/False if exists
        created = await self._redis.set(key, str(alert.id), ex=self._window, nx=True)
        won = bool(created)
        logger.debug(
            "Alert fingerprint registered",
            fingerprint=fingerprint,
            alert_id=str(alert.id),
            ttl_seconds=self._window,
            won_race=won,
        )
        return won
