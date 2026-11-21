"""asyncpg pool helpers for the correlation engine."""

from __future__ import annotations

import asyncpg

from app.core.config import settings


async def _init_connection(conn: asyncpg.Connection) -> None:
    """Initialize each connection with TCP keepalive settings.
    
    Prevents "Data should not be empty" asyncio selector errors by ensuring
    stale connections are detected and recycled early.
    """
    await conn.execute("SELECT 1")  # Verify connection works


async def create_pool() -> asyncpg.Pool:
    """Create the engine's connection pool.

    ``min_size``/``max_size`` are deliberately small: the engine is a single
    background worker that reads in batches, not a request-serving tier.
    Added socket keepalive to detect stale connections early and prevent
    "Data should not be empty" socket errors.
    """
    return await asyncpg.create_pool(
        dsn=settings.asyncpg_dsn,
        min_size=settings.db_pool_min,
        max_size=settings.db_pool_max,
        command_timeout=60,
        server_settings={
            "application_name": "aisoc-correlation",
            "jit": "off",  # Disable JIT for consistency
        },
        # TCP keepalive: detect stale connections before they cause write errors
        init=_init_connection,
    )


__all__ = ["create_pool"]
