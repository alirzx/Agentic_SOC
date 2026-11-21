"""Correlation engine service entry point.

Runs the background worker, exposes health/readiness probes, a Prometheus
endpoint, and an operator-triggered cycle (``POST /v1/run``) that is useful for
backfills and for verifying a deployment without waiting for the poll interval.
"""

from __future__ import annotations

import sys

# Python 3.13 on Windows: _SelectorSocketTransport._write_send has an assertion
# that fires when asyncpg socket callbacks run after buffer drain.  ProactorEventLoop
# uses IocpTransport instead and is unaffected.
if sys.platform == "win32":  # pragma: no cover
    import asyncio as _asyncio
    _asyncio.set_event_loop_policy(_asyncio.WindowsProactorEventLoopPolicy())

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Header, HTTPException, Response, status

from app.core.config import settings
from app.db import create_pool
from app.services.graph import GraphProjector
from app.worker import CorrelationWorker, active_tenants

try:  # prometheus_client is optional in tests
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
except Exception:  # pragma: no cover - pragma: no cover
    CONTENT_TYPE_LATEST = "text/plain"
    Counter = None  # type: ignore[assignment]
    generate_latest = None  # type: ignore[assignment]

logger = structlog.get_logger()

if Counter is not None:  # pragma: no branch
    CYCLES = Counter("aisoc_correlation_cycles_total", "Correlation cycles run", ["tenant"])
    CASES = Counter("aisoc_correlation_cases_total", "Cases created/reused", ["outcome"])
else:  # pragma: no cover
    CYCLES = CASES = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    pool = await create_pool()
    graph = GraphProjector()
    await graph.connect()
    worker = CorrelationWorker(pool, graph=graph)
    task: asyncio.Task | None = None
    if settings.worker_enabled:
        task = asyncio.create_task(worker.run_forever(), name="correlation-worker")

    app.state.pool = pool
    app.state.graph = graph
    app.state.worker = worker
    logger.info("service.started", owner=settings.owner, theta=settings.theta)
    try:
        yield
    finally:
        # Graceful shutdown sequence
        logger.info("service.shutdown_starting")
        
        # 1. Stop the worker first (unblock any in-flight operations)
        worker.stop()
        if task is not None:
            try:
                logger.info("service.waiting_for_worker")
                # Wait for worker to complete current cycle (max 90 seconds)
                await asyncio.wait_for(task, timeout=90.0)
            except asyncio.TimeoutError:
                logger.warning("service.worker_timeout", after_seconds=90)
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            except asyncio.CancelledError:
                pass
        
        # 2. Close Neo4j driver
        try:
            logger.info("service.closing_graph")
            await asyncio.wait_for(graph.close(), timeout=10.0)
        except asyncio.TimeoutError:
            logger.warning("service.graph_close_timeout")
        except Exception as exc:
            logger.warning("service.graph_close_error", error=str(exc)[:100])
        
        # 3. Close connection pool with timeout
        try:
            logger.info("service.closing_pool")
            # Release all idle connections first
            await asyncio.wait_for(pool.close(), timeout=15.0)
            logger.info("service.pool_closed")
        except asyncio.TimeoutError:
            logger.error("service.pool_close_timeout")
            # Force-close by clearing connections
            try:
                await pool.terminate()
            except Exception as term_exc:
                logger.warning("service.pool_terminate_failed", error=str(term_exc)[:100])
        except Exception as exc:
            logger.error("service.pool_close_error", error=str(exc)[:100])
        
        logger.info("service.stopped")


app = FastAPI(title="AiSOC Correlation Engine", version="2.0.0", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": settings.service_name}


@app.get("/readyz")
async def readyz() -> dict[str, object]:
    pool = getattr(app.state, "pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool not initialised")
    try:
        # Use a short timeout to fail fast
        async def check_db():
            async with pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
        
        await asyncio.wait_for(check_db(), timeout=5.0)
        tenants = len(await active_tenants(pool)) if pool else 0
    except asyncio.TimeoutError:
        raise HTTPException(status_code=503, detail="database query timeout") from None
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"database unavailable: {str(exc)[:100]}") from exc
    graph = getattr(app.state, "graph", None)
    return {
        "status": "ready",
        "tenants_in_window": tenants,
        "graph_enabled": bool(graph and graph.enabled),
        "owner": settings.owner,
        "theta": settings.theta,
    }


@app.get("/metrics")
async def metrics() -> Response:
    if generate_latest is None:  # pragma: no cover
        return Response("prometheus_client not installed\n", media_type="text/plain")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _authorise(token: str | None) -> None:
    expected = settings.internal_token or os.getenv("AISOC_INTERNAL_TOKEN", "")
    if not expected:
        if settings.environment.lower() in {"production", "prod"}:
            raise HTTPException(status_code=503, detail="AISOC_INTERNAL_TOKEN is not configured")
        return
    if token != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid internal token")


@app.get("/v1/diagnostics/{tenant_id}")
async def ambient_diagnostics(
    tenant_id: str,
    x_internal_token: str | None = Header(default=None),
) -> dict[str, object]:
    """The ambient decisions of this tenant's last cycle in this process.

    Answers the two questions the cycle counters cannot: which values the engine
    treated as wallpaper (hub hosts, high-frequency accounts, well-known or
    tenant-wide domains) and which pairs it refused to merge because they shared
    nothing but those values. Nothing is persisted, so a restart (or a tenant
    that has not cycled yet) gets an explicit 404 instead of an empty report.
    """
    _authorise(x_internal_token)
    import uuid as _uuid  # noqa: PLC0415

    from app.services import diagnostics  # noqa: PLC0415

    try:
        tid = str(_uuid.UUID(tenant_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="tenant_id must be a UUID") from exc

    report = diagnostics.last(tid)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "no cycle has run for this tenant in this process yet — "
                f"POST /v1/run/{tid} to produce one"
            ),
        )
    return report


@app.post("/v1/run")
async def run_cycle(x_internal_token: str | None = Header(default=None)) -> dict[str, object]:
    """Run one correlation cycle across every tenant in the window."""
    _authorise(x_internal_token)
    worker: CorrelationWorker = app.state.worker
    results = await worker.run_cycle()
    for result in results:
        if CYCLES is not None:
            CYCLES.labels(tenant=str(result.get("tenant_id"))).inc()
        if CASES is not None:
            CASES.labels(outcome="created").inc(int(result.get("cases_created") or 0))
            CASES.labels(outcome="reused").inc(int(result.get("cases_reused") or 0))
    return {"cycles": results}


@app.post("/v1/run/{tenant_id}")
async def run_cycle_for_tenant(
    tenant_id: str,
    x_internal_token: str | None = Header(default=None),
) -> dict[str, object]:
    _authorise(x_internal_token)
    import uuid as _uuid  # noqa: PLC0415

    from app.services.case_client import CaseClient  # noqa: PLC0415
    from app.services.engine import CorrelationEngine  # noqa: PLC0415

    try:
        tid = _uuid.UUID(tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="tenant_id must be a UUID") from exc

    async with CaseClient() as client:
        engine = CorrelationEngine(app.state.pool, graph=app.state.graph, case_client=client)
        result = await engine.run_once(tid)
    # API clients get full diagnostics; logs get summary only
    return result.as_dict(include_full_diagnostics=True)
