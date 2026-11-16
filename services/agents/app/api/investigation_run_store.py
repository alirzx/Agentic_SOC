"""Durable investigation run poll-store (Redis + in-process fallback).

Alert Detail and Case Workspace poll investigation status by ``run_id``.
Those runs used to live only in a process-local dict, so any agents
restart (or a future multi-worker deploy) made ``GET …/investigations/{id}``
return 404 while the background task was still valid in the ledger.

This module mirrors every write to Redis when ``REDIS_URL`` is reachable,
and hydrates the in-process cache on miss so pollers survive restarts.
"""

from __future__ import annotations

import json
import os
from typing import Any

import structlog

logger = structlog.get_logger()

_TTL_SECONDS = int(os.environ.get("AISOC_INVESTIGATION_RUN_TTL_SECONDS", str(86_400)))
_KEY_PREFIX = "aisoc:agents:inv_run:"
_MEMORY: dict[str, dict[str, Any]] = {}

try:
    import redis.asyncio as aioredis  # type: ignore[import]

    _redis: aioredis.Redis | None = None

    async def _get_redis() -> aioredis.Redis | None:
        global _redis
        if _redis is not None:
            return _redis
        url = os.environ.get("REDIS_URL", "").strip()
        if not url:
            return None
        try:
            _redis = aioredis.from_url(url, decode_responses=True)
            await _redis.ping()
            return _redis
        except Exception as exc:  # noqa: BLE001 - fall back to memory
            logger.debug("investigation_run_store.redis_unavailable", error=str(exc))
            return None

except ImportError:

    async def _get_redis() -> Any:  # type: ignore[misc]
        return None


def _redis_key(run_id: str) -> str:
    return f"{_KEY_PREFIX}{run_id}"


def clear_memory_for_tests() -> None:
    """Drop the process cache (unit tests only)."""
    _MEMORY.clear()


async def put_run(run_id: str, data: dict[str, Any]) -> None:
    """Upsert a run document into memory and Redis."""
    payload = dict(data)
    _MEMORY[run_id] = payload
    client = await _get_redis()
    if client is None:
        return
    try:
        await client.setex(_redis_key(run_id), _TTL_SECONDS, json.dumps(payload, default=str))
    except Exception as exc:  # noqa: BLE001 - memory remains authoritative
        logger.warning("investigation_run_store.put_failed", run_id=run_id, error=str(exc))


async def get_run(run_id: str) -> dict[str, Any] | None:
    """Return a run document, hydrating from Redis on memory miss."""
    cached = _MEMORY.get(run_id)
    if cached is not None:
        return cached
    client = await _get_redis()
    if client is None:
        return None
    try:
        raw = await client.get(_redis_key(run_id))
    except Exception as exc:  # noqa: BLE001
        logger.warning("investigation_run_store.get_failed", run_id=run_id, error=str(exc))
        return None
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    _MEMORY[run_id] = data
    return data


async def update_run(run_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    """Merge ``patch`` into an existing run and persist. Returns None if missing."""
    current = await get_run(run_id)
    if current is None:
        return None
    merged = {**current, **patch}
    await put_run(run_id, merged)
    return merged


async def mutate_run(run_id: str, **fields: Any) -> dict[str, Any] | None:
    """Convenience wrapper for keyword field updates."""
    return await update_run(run_id, dict(fields))
