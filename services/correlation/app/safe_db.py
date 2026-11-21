"""Safe database operation wrappers with resilience and error recovery.

Wraps all asyncpg pool operations to handle connection pool exhaustion,
socket errors, and unexpected disconnections gracefully.
"""

from __future__ import annotations

import asyncio
from typing import Any, TypeVar, Callable, Awaitable

import asyncpg
import structlog

logger = structlog.get_logger()

T = TypeVar("T")

# Common socket/connection errors that may indicate pool exhaustion
_TRANSIENT_ERRORS = (
    asyncpg.PostgresError,
    ConnectionError,
    TimeoutError,
    asyncio.TimeoutError,
    OSError,
)


async def safe_acquire_and_run(
    pool: asyncpg.Pool | asyncpg.Connection,
    operation: Callable[[asyncpg.Connection], Awaitable[T]],
    operation_name: str,
    max_retries: int = 3,
    backoff_ms: int = 200,
) -> T | None:
    """Safely run an operation against an asyncpg pool or a direct connection.

    Direct connections cannot be retried — the same broken connection won't
    heal on a second attempt — so they execute once with no acquire/release.
    """
    is_pool = hasattr(pool, "acquire") and hasattr(pool, "release")

    if not is_pool:
        # Direct connection: one attempt only, no acquire/release cycle.
        try:
            return await operation(pool)
        except Exception as exc:
            logger.warning(
                "safe_db.operation_failed",
                operation=operation_name,
                error_type=type(exc).__name__,
                error=str(exc)[:200],
            )
            return None

    for attempt in range(1, max_retries + 1):
        conn = None
        try:
            conn = await asyncio.wait_for(pool.acquire(), timeout=30.0)
            return await operation(conn)
        except asyncio.TimeoutError:
            logger.warning(
                "safe_db.pool_acquire_timeout",
                operation=operation_name,
                attempt=attempt,
                max_retries=max_retries,
            )
            if attempt >= max_retries:
                logger.error(
                    "safe_db.pool_acquire_exhausted",
                    operation=operation_name,
                    after_attempts=attempt,
                )
                return None
            await asyncio.sleep(backoff_ms / 1000.0)
            backoff_ms = min(backoff_ms * 2, 2000)
        except Exception as exc:
            logger.warning(
                "safe_db.operation_failed",
                operation=operation_name,
                attempt=attempt,
                max_retries=max_retries,
                error_type=type(exc).__name__,
                error=str(exc)[:200],
            )
            if attempt >= max_retries:
                logger.error(
                    "safe_db.operation_exhausted",
                    operation=operation_name,
                    after_attempts=attempt,
                    final_error=str(exc)[:100],
                )
                return None
            if isinstance(exc, _TRANSIENT_ERRORS):
                await asyncio.sleep(backoff_ms / 1000.0)
                backoff_ms = min(backoff_ms * 2, 2000)
            else:
                logger.error(
                    "safe_db.operation_permanent_error",
                    operation=operation_name,
                    error_type=type(exc).__name__,
                )
                return None
        finally:
            if conn is not None:
                try:
                    await pool.release(conn)
                except Exception as rel_exc:
                    logger.warning(
                        "safe_db.connection_release_failed",
                        operation=operation_name,
                        error=str(rel_exc)[:100],
                    )


async def safe_fetch(
    pool: asyncpg.Pool,
    query: str,
    *args: Any,
    operation_name: str = "fetch",
) -> list[Any]:
    """Safely fetch rows from the database.
    
    Returns:
        List of rows, or empty list if operation fails
    """
    async def _fetch(conn: asyncpg.Connection) -> list[Any]:
        return await conn.fetch(query, *args)
    
    result = await safe_acquire_and_run(pool, _fetch, operation_name)
    return result or []


async def safe_execute(
    pool: asyncpg.Pool,
    query: str,
    *args: Any,
    operation_name: str = "execute",
) -> bool:
    """Safely execute a query (INSERT/UPDATE/DELETE).
    
    Returns:
        True if operation succeeded, False otherwise
    """
    async def _execute(conn: asyncpg.Connection) -> bool:
        await conn.execute(query, *args)
        return True
    
    result = await safe_acquire_and_run(pool, _execute, operation_name)
    return bool(result)


async def safe_executemany(
    pool: asyncpg.Pool,
    query: str,
    args_list: list[Any],
    operation_name: str = "executemany",
) -> bool:
    """Safely execute multiple queries in a batch.
    
    Returns:
        True if operation succeeded, False otherwise
    """
    async def _executemany(conn: asyncpg.Connection) -> bool:
        await conn.executemany(query, args_list)
        return True
    
    result = await safe_acquire_and_run(pool, _executemany, operation_name)
    return bool(result)


async def safe_transaction(
    pool: asyncpg.Pool,
    operation: Callable[[asyncpg.Connection], Awaitable[None]],
    operation_name: str = "transaction",
) -> bool:
    """Safely run an operation within a transaction.
    
    Returns:
        True if operation succeeded, False otherwise
    """
    async def _transaction(conn: asyncpg.Connection) -> bool:
        async with conn.transaction():
            await operation(conn)
        return True
    
    result = await safe_acquire_and_run(pool, _transaction, operation_name)
    return bool(result)


__all__ = [
    "safe_acquire_and_run",
    "safe_fetch",
    "safe_execute",
    "safe_executemany",
    "safe_transaction",
]
