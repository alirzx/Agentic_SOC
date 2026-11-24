"""Second-opinion evaluation of a case against the Soorin TKG.

Endpoints
---------
* ``GET  /cases/tkg-evaluation/health``        Readiness of the configured TKG.
* ``POST /cases/{case_id}/tkg-evaluation``     Run (or reuse a cached) evaluation.
* ``GET  /cases/{case_id}/tkg-evaluation``     Latest stored evaluation.
* ``GET  /cases/{case_id}/tkg-evaluations``    Evaluation history for a case.

The evaluation is advisory: it never changes a case's status, verdict or
evidence, and an unreachable TKG returns ``status='unavailable'`` with a reason
code instead of failing the panel.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession
from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.models.tkg_evaluation import CaseTkgEvaluation
from app.services.tkg.evaluation import workspace_config
from app.services.tkg_evaluation import progress
from app.services.tkg_evaluation.client import TkgClient, TkgError
from app.services.tkg_evaluation.constants import PROFILE
from app.services.tkg_evaluation.runner import persist_provisional, run_evaluation
from app.services.tkg_evaluation.sync import sync_missing_alerts

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cases", tags=["case-tkg-evaluation"])


class TkgCheck(BaseModel):
    id: str
    ok: bool
    detail: str | None = None


class TkgHealthResponse(BaseModel):
    enabled: bool
    configured: bool
    ready: bool
    checks: list[TkgCheck] = Field(default_factory=list)
    counts: dict[str, Any] = Field(default_factory=dict)
    kb_id: str | None = None
    error: str | None = None
    #: True when the manual send path is enabled (AISOC_TKG_ALLOW_SEND).
    allow_send: bool = False


class TkgSyncRequest(BaseModel):
    """Manual push of the case's missing alerts. ``dry_run`` defaults to true."""

    dry_run: bool = True
    limit: int = Field(25, ge=1, le=100)
    delay_s: float | None = Field(None, ge=0, le=30)


class TkgSyncResponse(BaseModel):
    ok: bool
    dry_run: bool = True
    reason: str | None = None
    detail: str | None = None
    source_id: str | None = None
    would_send: list[dict[str, Any]] = Field(default_factory=list)
    sent: list[dict[str, Any]] = Field(default_factory=list)
    rejected: list[dict[str, Any]] = Field(default_factory=list)
    failed: list[dict[str, Any]] = Field(default_factory=list)
    already_in_graph: list[dict[str, Any]] = Field(default_factory=list)
    existing_deliveries: list[dict[str, Any]] = Field(default_factory=list)
    invalid: list[dict[str, Any]] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    allow_send: bool = False
    note: str | None = None
    started_at: str | None = None


class TkgEvaluationRequest(BaseModel):
    """Optional body: the engine verdict to compare against, and cache bypass."""

    engine_verdict: str | None = Field(None, max_length=32)
    refresh: bool = False
    #: The run pushes the alerts the graph does not know before attributing them.
    #: Only effective when `AISOC_TKG_ALLOW_SEND` is on; one click does everything.
    send_missing: bool = True


class TkgEvaluationResponse(BaseModel):
    evaluation_id: str | None = None
    status: str
    reason_codes: list[str] = Field(default_factory=list)
    verdict: str | None = None
    confidence: int | None = None
    passes: str | None = None
    agree: bool | None = None
    reasons: list[Any] = Field(default_factory=list)
    attribution: dict[str, Any] = Field(default_factory=dict)
    input_payload: dict[str, Any] | None = None
    kb_id: str | None = None
    profile: str | None = None
    created_at: str | None = None
    stats: dict[str, Any] = Field(default_factory=dict)
    detail: str | None = None


class TkgRunSnapshot(BaseModel):
    """Live state of one evaluation run, as the panel's stepper renders it."""

    run_id: str
    state: str
    stage: str
    total: int = 0
    probed: int = 0
    resolved: int = 0
    facts: int = 0
    pending: int = 0
    wave: int = 0
    max_waves: int = 0
    message: str | None = None
    error: str | None = None
    elapsed_ms: int = 0
    result: TkgEvaluationResponse | None = None
    #: The evaluation as it stands while the run is in flight: same shape as a
    #: stored row, rescored after every few resolved alerts. The panel renders
    #: these numbers instead of the last stored run, so confidence and the
    #: attribution rows move during the run.
    partial: TkgEvaluationResponse | None = None


#: Keeps the spawned task referenced so it is not garbage-collected mid-run.
_TASKS: dict[str, asyncio.Task[None]] = {}


def _ensure_enabled(user) -> None:
    if not user.explicit_workspace:
        raise HTTPException(403, "Select an authorized workspace")
    user.require_permission("cases:read")
    if not settings.AISOC_FEATURE_TKG_EVALUATION:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="TKG evaluation is disabled (AISOC_FEATURE_TKG_EVALUATION=false).",
        )


@router.get(
    "/tkg-evaluation/health",
    response_model=TkgHealthResponse,
    summary="Readiness of the configured Soorin TKG",
)
async def tkg_health(user: AuthUser, db: DBSession) -> TkgHealthResponse:
    """Cheap probe so the UI can show why the button is unavailable."""

    _ensure_enabled(user)
    cfg = await workspace_config(db, user.tenant_id, settings)
    if not cfg.configured:
        return TkgHealthResponse(
            enabled=True,
            configured=False,
            ready=False,
            checks=[TkgCheck(id="config", ok=False, detail="TKG credentials are not configured")],
            kb_id=None,
            error="tkg_not_configured",
            allow_send=False,
        )

    client = TkgClient(cfg)
    try:
        readiness = await client.readiness()
    except TkgError as exc:  # pragma: no cover - defensive
        return TkgHealthResponse(
            enabled=True,
            configured=True,
            ready=False,
            checks=[TkgCheck(id="graph", ok=False, detail=exc.detail or exc.code)],
            kb_id=cfg.kb_id,
            error=exc.code,
        )
    finally:
        await client.aclose()

    return TkgHealthResponse(
        enabled=True,
        configured=True,
        ready=bool(readiness.get("ready")),
        checks=[TkgCheck(**check) for check in readiness.get("checks", [])],
        counts=readiness.get("counts") or {},
        kb_id=readiness.get("kb_id"),
        error=readiness.get("error"),
        allow_send=bool(cfg.allow_send),
    )


def _row_to_payload(row: CaseTkgEvaluation) -> TkgEvaluationResponse:
    return TkgEvaluationResponse(
        evaluation_id=str(row.id),
        status=row.status,
        reason_codes=list(row.reason_codes or []),
        verdict=row.verdict,
        confidence=row.confidence,
        passes=row.passes,
        agree=row.agree,
        reasons=list(row.reasons or []),
        attribution=row.attribution or {},
        input_payload=row.input_payload,
        kb_id=row.kb_id,
        profile=row.profile,
        created_at=row.created_at.isoformat() if row.created_at else None,
        stats={
            "alerts": row.alert_count,
            "resolved": row.resolved_count,
            "duration_ms": row.duration_ms,
        },
        detail=row.detail,
    )


@router.post(
    "/{case_id}/tkg-evaluation",
    response_model=TkgEvaluationResponse,
    summary="Ask the Soorin TKG for a second opinion on this case",
)
async def evaluate_case_with_tkg(
    case_id: UUID,
    db: DBSession,
    user: AuthUser,
    payload: TkgEvaluationRequest | None = None,
) -> TkgEvaluationResponse:
    _ensure_enabled(user)
    body = payload or TkgEvaluationRequest()
    try:
        result = await run_evaluation(
            db,
            tenant_id=user.tenant_id,
            case_id=case_id,
            requested_by=getattr(user, "user_id", None),
            engine_verdict=body.engine_verdict,
            refresh=body.refresh,
            settings_obj=settings,
            send_missing=body.send_missing,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return TkgEvaluationResponse(**result)


@router.post(
    "/{case_id}/tkg-evaluation/run",
    response_model=TkgRunSnapshot,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a TKG evaluation and watch it run",
)
async def start_tkg_evaluation(
    case_id: UUID,
    user: AuthUser,
    payload: TkgEvaluationRequest | None = None,
) -> TkgRunSnapshot:
    """Start the evaluation as a job.

    The synchronous endpoint stayed for scripts; the panel needs a handle it can
    poll (98 alerts resolve in waves, and queued ones are re-probed), and a way
    to cancel a run that is taking too long.
    """

    _ensure_enabled(user)
    body = payload or TkgEvaluationRequest()
    job = progress.start(case_id=case_id, tenant_id=user.tenant_id)

    async def execute() -> None:
        # A request-scoped session dies with the response, so the job opens its own.
        try:
            async with AsyncSessionLocal() as session:
                result = await run_evaluation(
                    session,
                    tenant_id=user.tenant_id,
                    case_id=case_id,
                    requested_by=getattr(user, "user_id", None),
                    engine_verdict=body.engine_verdict,
                    refresh=body.refresh,
                    settings_obj=settings,
                    job=job,
                    send_missing=body.send_missing,
                )
            progress.finish(job, result=result)
        except progress.RunCancelled:
            # A cancelled run used to store nothing, throwing away every alert it
            # had already resolved and scored. Store what it had instead.
            await _store_provisional(job)
            progress.cancelled(job)
        except asyncio.CancelledError:  # pragma: no cover - worker shutdown
            await _store_provisional(job)
            progress.cancelled(job)
            raise
        except Exception as exc:  # noqa: BLE001 - reported, never a silent 500
            logger.exception("tkg evaluation run %s failed", job.id)
            await _store_provisional(job)
            progress.fail(job, str(exc) or exc.__class__.__name__)

    task = asyncio.create_task(execute())
    _TASKS[job.id] = task
    job.snapshot()
    return TkgRunSnapshot(**job.snapshot())


async def _store_provisional(job: progress.RunJob) -> None:
    """Persist the live partial result of a run that is being stopped.

    Best effort: a database failure here must not turn a cancel into a 500, and
    the panel already has the partial payload.
    """

    if not job.partial:
        return
    try:
        async with AsyncSessionLocal() as session:
            await persist_provisional(session, job)
    except Exception:  # noqa: BLE001 - the cancel itself must still succeed
        logger.exception("could not store the partial result of tkg run %s", job.id)


def _snapshot(job: progress.RunJob) -> TkgRunSnapshot:
    snapshot = job.snapshot()
    if isinstance(snapshot.get("result"), dict):
        snapshot["result"] = TkgEvaluationResponse(**snapshot["result"])
    if isinstance(snapshot.get("partial"), dict):
        snapshot["partial"] = TkgEvaluationResponse(**snapshot["partial"])
    return TkgRunSnapshot(**snapshot)


@router.get(
    "/{case_id}/tkg-evaluation/run/{run_id}",
    response_model=TkgRunSnapshot,
    summary="Live progress of a TKG evaluation run",
)
async def get_tkg_evaluation_run(
    case_id: UUID,
    run_id: str,
    user: AuthUser,
) -> TkgRunSnapshot:
    _ensure_enabled(user)
    job = progress.get(run_id, case_id=case_id, tenant_id=user.tenant_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown run id.")
    return _snapshot(job)


@router.delete(
    "/{case_id}/tkg-evaluation/run/{run_id}",
    response_model=TkgRunSnapshot,
    summary="Cancel a running TKG evaluation",
)
async def cancel_tkg_evaluation_run(
    case_id: UUID,
    run_id: str,
    user: AuthUser,
) -> TkgRunSnapshot:
    _ensure_enabled(user)
    job = progress.cancel(run_id, case_id=case_id, tenant_id=user.tenant_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown run id.")
    return _snapshot(job)


@router.post(
    "/{case_id}/tkg-evaluation/run/{run_id}/skip-wait",
    response_model=TkgRunSnapshot,
    summary="Stop waiting for the graph and score what is resolved",
)
async def skip_tkg_evaluation_wait(
    case_id: UUID,
    run_id: str,
    user: AuthUser,
) -> TkgRunSnapshot:
    """End the wait stage only — the run still judges and stores.

    The alerts already sent keep materialising inside the graph; the next run
    reads them. Cancelling the whole run (``DELETE .../run/{run_id}``) is the
    control that still stores nothing.
    """

    _ensure_enabled(user)
    job = progress.skip_waiting(run_id, case_id=case_id, tenant_id=user.tenant_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown run id.")
    return _snapshot(job)


@router.get(
    "/{case_id}/tkg-evaluation",
    response_model=TkgEvaluationResponse,
    summary="Latest TKG evaluation for this case",
)
async def latest_case_tkg_evaluation(
    case_id: UUID,
    db: DBSession,
    user: AuthUser,
) -> TkgEvaluationResponse:
    _ensure_enabled(user)
    row = (
        await db.execute(
            select(CaseTkgEvaluation)
            .where(
                CaseTkgEvaluation.case_id == case_id,
                CaseTkgEvaluation.tenant_id == user.tenant_id,
            )
            .order_by(CaseTkgEvaluation.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No TKG evaluation has been run for this case.",
        )
    return _row_to_payload(row)


@router.post(
    "/{case_id}/tkg-evaluation/sync",
    response_model=TkgSyncResponse,
    summary="Push this case's missing alerts into the TKG (opt-in, audited)",
)
async def sync_case_alerts_to_tkg(
    case_id: UUID,
    db: DBSession,
    user: AuthUser,
    payload: TkgSyncRequest | None = None,
) -> TkgSyncResponse:
    """Manual escape hatch for a case whose alerts were never ingested.

    The workspace outbox deduplicates eligible alerts. A write requires
    ``dry_run=false``, write permission and ``AISOC_TKG_ALLOW_SEND=true``.
    """

    _ensure_enabled(user)
    body = payload or TkgSyncRequest()
    if not body.dry_run:
        user.require_permission("cases:write")
    try:
        result = await sync_missing_alerts(
            db,
            tenant_id=user.tenant_id,
            case_id=case_id,
            dry_run=body.dry_run,
            limit=body.limit,
            delay=body.delay_s if body.delay_s is not None else settings.AISOC_TKG_SEND_DELAY_S,
            settings_obj=settings,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Case not found.") from exc
    return TkgSyncResponse(**result)


@router.get(
    "/{case_id}/tkg-evaluations",
    response_model=list[TkgEvaluationResponse],
    summary="TKG evaluation history for this case",
)
async def list_case_tkg_evaluations(
    case_id: UUID,
    db: DBSession,
    user: AuthUser,
    limit: int = 20,
) -> list[TkgEvaluationResponse]:
    _ensure_enabled(user)
    rows = (
        await db.execute(
            select(CaseTkgEvaluation)
            .where(
                CaseTkgEvaluation.case_id == case_id,
                CaseTkgEvaluation.tenant_id == user.tenant_id,
            )
            .order_by(CaseTkgEvaluation.created_at.desc())
            .limit(max(1, min(limit, 100)))
        )
    ).scalars().all()
    return [_row_to_payload(row) for row in rows]


__all__ = ["router", "PROFILE"]
