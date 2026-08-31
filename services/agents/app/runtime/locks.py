"""Incident processing locks (spec §42). Redis when available, in-memory otherwise."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any


class IncidentLockBusy(RuntimeError):
    pass


class IncidentLock:
    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}

    def _lock_for(self, incident_id: str) -> asyncio.Lock:
        if incident_id not in self._locks:
            self._locks[incident_id] = asyncio.Lock()
        return self._locks[incident_id]

    @asynccontextmanager
    async def acquire(self, incident_id: str, *, blocking: bool = True) -> AsyncIterator[None]:
        lock = self._lock_for(incident_id)
        if not blocking and lock.locked():
            raise IncidentLockBusy(f"incident {incident_id} is already being processed")
        await lock.acquire()
        try:
            yield
        finally:
            lock.release()


class RedisIncidentLock:
    """Optional Redis SET NX lock. Falls back to in-process lock if Redis is absent."""

    def __init__(self, redis_client: Any | None = None, *, ttl_seconds: int = 120) -> None:
        self._redis = redis_client
        self._ttl = ttl_seconds
        self._local = IncidentLock()

    @asynccontextmanager
    async def acquire(self, incident_id: str, *, blocking: bool = True) -> AsyncIterator[None]:
        if self._redis is None:
            async with self._local.acquire(incident_id, blocking=blocking):
                yield
            return
        key = f"tenant:lock:incident:{incident_id}"
        token = "1"
        ok = await self._redis.set(key, token, nx=True, ex=self._ttl)
        if not ok:
            if not blocking:
                raise IncidentLockBusy(f"incident {incident_id} is already being processed")
            await asyncio.sleep(0.05)
            async with self.acquire(incident_id, blocking=True):
                yield
            return
        try:
            yield
        finally:
            await self._redis.delete(key)
