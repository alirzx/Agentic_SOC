"""Background worker loop: run one correlation cycle per tenant, forever.

The engine is tenant-scoped by construction (every query carries
``tenant_id``), so the worker enumerates tenants from the alert table rather
than keeping a tenant list of its own. That keeps onboarding a tenant free of
scheduler bookkeeping: the first alert makes it eligible.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid

import structlog

from app.core.config import settings
from app.db import create_pool
from app.safe_db import safe_fetch
from app.services.case_client import CaseClient
from app.services.engine import CorrelationEngine
from app.services.graph import GraphProjector

logger = structlog.get_logger()


async def active_tenants(pool) -> list[uuid.UUID]:
    """Fetch all tenants with recent alerts, with error resilience."""
    rows = await safe_fetch(
        pool,
        """
        SELECT DISTINCT tenant_id
          FROM alerts
         WHERE created_at >= now() - make_interval(hours => $1)
        """,
        settings.lookback_hours,
        operation_name="active_tenants",
    )
    return [row["tenant_id"] for row in rows]


class CorrelationWorker:
    def __init__(self, pool, *, graph: GraphProjector | None = None) -> None:
        self._pool = pool
        self._graph = graph
        self._stop = asyncio.Event()

    def stop(self) -> None:
        """Signal the worker to stop gracefully.
        
        The worker will complete the current cycle before exiting.
        """
        self._stop.set()

    async def run_cycle(self) -> list[dict]:
        results: list[dict] = []
        tenants = await active_tenants(self._pool)
        for tenant_id in tenants:
            # Create a fresh client for each tenant to prevent connection pool exhaustion.
            # Reusing one client across many tenants can cause asyncio selector buffer errors
            # after the pool reaches capacity.
            async with CaseClient() as client:
                engine = CorrelationEngine(self._pool, graph=self._graph, case_client=client)
                try:
                    result = await engine.run_once(tenant_id)
                    results.append(result.as_dict())
                except Exception as exc:  # noqa: BLE001 — one tenant must not stall the rest
                    logger.warning(
                        "worker.tenant_failed",
                        tenant=str(tenant_id),
                        error=str(exc),
                    )
        return results

    async def run_forever(self) -> None:
        logger.info(
            "worker.started",
            poll_seconds=settings.poll_interval_seconds,
            theta=settings.theta,
        )
        while not self._stop.is_set():
            try:
                await self.run_cycle()
            except Exception as exc:  # noqa: BLE001
                logger.warning("worker.cycle_failed", error=str(exc))
            
            # Wait for stop signal or timeout
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=settings.poll_interval_seconds)
        
        logger.info("worker.stopped")


async def main() -> None:  # pragma: no cover — container entry point
    pool = await create_pool()
    graph = GraphProjector()
    await graph.connect()
    worker = CorrelationWorker(pool, graph=graph)
    try:
        await worker.run_forever()
    finally:
        await graph.close()
        await pool.close()


__all__ = ["CorrelationWorker", "active_tenants", "main"]
