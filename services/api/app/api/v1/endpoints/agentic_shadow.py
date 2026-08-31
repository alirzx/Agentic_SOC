"""Read-only Agentic SOC shadow-run API (Phase 7). Never mutates Case/Alert."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.v1.deps import CurrentUser, require_permission
from app.db.rls import TenantDBSession
from app.models.agentic_shadow import AgenticShadowRun

router = APIRouter(prefix="/soc/agentic/shadow-runs", tags=["agentic-soc"])


class ShadowRunSummary(BaseModel):
    id: uuid.UUID
    alert_id: str
    case_id: str
    status: str
    duration_ms: int
    risk_score: float
    confidence: float
    agent_version: str
    tool_call_count: int
    input_tokens: int
    output_tokens: int
    estimated_cost: float
    decision: str
    recommended_actions: list[Any]
    created_at: datetime
    error: str | None = None


class ShadowRunDetail(ShadowRunSummary):
    tenant_id: uuid.UUID
    workflow_version: str
    prompt_version: str
    started_at: datetime | None
    completed_at: datetime | None
    result: dict[str, Any]
    comparison: dict[str, Any]


def _to_summary(row: AgenticShadowRun) -> ShadowRunSummary:
    return ShadowRunSummary(
        id=row.id,
        alert_id=row.alert_id,
        case_id=row.case_id,
        status=row.status,
        duration_ms=row.duration_ms,
        risk_score=float(row.risk_score or 0),
        confidence=float(row.confidence or 0),
        agent_version=row.agent_version,
        tool_call_count=row.tool_call_count,
        input_tokens=row.input_tokens,
        output_tokens=row.output_tokens,
        estimated_cost=float(row.estimated_cost or 0),
        decision=row.decision,
        recommended_actions=list(row.recommended_actions or []),
        created_at=row.created_at,
        error=row.error,
    )


@router.get("", response_model=list[ShadowRunSummary])
async def list_shadow_runs(
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:read"))],
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
) -> list[ShadowRunSummary]:
    stmt = (
        select(AgenticShadowRun)
        .where(AgenticShadowRun.tenant_id == current_user.tenant_id)
        .order_by(AgenticShadowRun.created_at.desc())
        .limit(limit)
    )
    if status_filter:
        stmt = stmt.where(AgenticShadowRun.status == status_filter)
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_summary(row) for row in rows]


async def _load_run(
    db: TenantDBSession,
    current_user: CurrentUser,
    run_id: uuid.UUID,
) -> AgenticShadowRun:
    stmt = select(AgenticShadowRun).where(
        AgenticShadowRun.id == run_id,
        AgenticShadowRun.tenant_id == current_user.tenant_id,
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="shadow run not found")
    return row


@router.get("/{run_id}", response_model=ShadowRunDetail)
async def get_shadow_run(
    run_id: uuid.UUID,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:read"))],
) -> ShadowRunDetail:
    row = await _load_run(db, current_user, run_id)
    return ShadowRunDetail(
        **_to_summary(row).model_dump(),
        tenant_id=row.tenant_id,
        workflow_version=row.workflow_version,
        prompt_version=row.prompt_version,
        started_at=row.started_at,
        completed_at=row.completed_at,
        result=dict(row.result or {}),
        comparison=dict(row.comparison or {}),
    )


@router.get("/{run_id}/evidence")
async def get_shadow_evidence(
    run_id: uuid.UUID,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:read"))],
) -> dict[str, Any]:
    row = await _load_run(db, current_user, run_id)
    return {"id": str(row.id), "evidence": list(row.evidence or [])}


@router.get("/{run_id}/comparison")
async def get_shadow_comparison(
    run_id: uuid.UUID,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:read"))],
) -> dict[str, Any]:
    row = await _load_run(db, current_user, run_id)
    return dict(row.comparison or {})
