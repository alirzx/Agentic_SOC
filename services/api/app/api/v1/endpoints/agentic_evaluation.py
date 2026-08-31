"""Read-only Agentic SOC evaluation API (Phase 8)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.v1.deps import CurrentUser, require_permission
from app.db.rls import TenantDBSession
from app.models.agentic_evaluation import AgenticCaseEvaluation as AgenticCaseEvaluationRow
from app.models.agentic_evaluation import AgenticEvaluationRun as AgenticEvaluationRunRow

router = APIRouter(prefix="/soc/agentic/evaluations", tags=["agentic-soc"])


class EvaluationRunSummary(BaseModel):
    id: uuid.UUID
    dataset_id: str
    dataset_version: str
    status: str
    total_cases: int
    completed_cases: int
    failed_cases: int
    total_duration_ms: int
    agent_version: str
    workflow_version: str
    comparison_summary: dict[str, Any]
    production_readiness: dict[str, Any]
    created_at: datetime


class EvaluationRunDetail(EvaluationRunSummary):
    tenant_id: uuid.UUID
    prompt_version: str
    tool_version: str
    model: str
    input_tokens: int
    output_tokens: int
    estimated_cost: float
    aggregate_metrics: dict[str, Any]
    quality_gates: dict[str, Any]
    pipeline_status: dict[str, Any]
    report: dict[str, Any]


def _summary(row: AgenticEvaluationRunRow) -> EvaluationRunSummary:
    return EvaluationRunSummary(
        id=row.id,
        dataset_id=row.dataset_id,
        dataset_version=row.dataset_version,
        status=row.status,
        total_cases=row.total_cases,
        completed_cases=row.completed_cases,
        failed_cases=row.failed_cases,
        total_duration_ms=row.total_duration_ms,
        agent_version=row.agent_version,
        workflow_version=row.workflow_version,
        comparison_summary=dict(row.comparison_summary or {}),
        production_readiness=dict(row.production_readiness or {}),
        created_at=row.created_at,
    )


@router.get("", response_model=list[EvaluationRunSummary])
async def list_evaluations(
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:read"))],
    limit: int = Query(50, ge=1, le=200),
) -> list[EvaluationRunSummary]:
    stmt = (
        select(AgenticEvaluationRunRow)
        .where(AgenticEvaluationRunRow.tenant_id == current_user.tenant_id)
        .order_by(AgenticEvaluationRunRow.created_at.desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [_summary(row) for row in rows]


async def _load_run(db: TenantDBSession, user: CurrentUser, run_id: uuid.UUID) -> AgenticEvaluationRunRow:
    stmt = select(AgenticEvaluationRunRow).where(
        AgenticEvaluationRunRow.id == run_id,
        AgenticEvaluationRunRow.tenant_id == user.tenant_id,
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evaluation run not found")
    return row


@router.get("/{run_id}", response_model=EvaluationRunDetail)
async def get_evaluation(
    run_id: uuid.UUID,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:read"))],
) -> EvaluationRunDetail:
    row = await _load_run(db, current_user, run_id)
    return EvaluationRunDetail(
        **_summary(row).model_dump(),
        tenant_id=row.tenant_id,
        prompt_version=row.prompt_version,
        tool_version=row.tool_version,
        model=row.model,
        input_tokens=row.input_tokens,
        output_tokens=row.output_tokens,
        estimated_cost=float(row.estimated_cost or 0),
        aggregate_metrics=dict(row.aggregate_metrics or {}),
        quality_gates=dict(row.quality_gates or {}),
        pipeline_status=dict(row.pipeline_status or {}),
        report=dict(row.report or {}),
    )


@router.get("/{run_id}/metrics")
async def get_evaluation_metrics(
    run_id: uuid.UUID,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:read"))],
) -> dict[str, Any]:
    row = await _load_run(db, current_user, run_id)
    return dict(row.aggregate_metrics or {})


@router.get("/{run_id}/cases")
async def list_case_evaluations(
    run_id: uuid.UUID,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:read"))],
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    await _load_run(db, current_user, run_id)
    stmt = (
        select(AgenticCaseEvaluationRow)
        .where(
            AgenticCaseEvaluationRow.evaluation_run_id == run_id,
            AgenticCaseEvaluationRow.tenant_id == current_user.tenant_id,
        )
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "case_id": r.case_id,
            "overall_score": r.overall_score,
            "classification_score": r.classification_score,
            "severity_score": r.severity_score,
            "mitre_score": r.mitre_score,
            "ioc_score": r.ioc_score,
            "evidence_score": r.evidence_score,
            "hallucination_score": r.hallucination_score,
            "analyst_review_required": r.analyst_review_required,
            "metric_details": dict(r.metric_details or {}),
        }
        for r in rows
    ]


@router.get("/{run_id}/comparison")
async def get_evaluation_comparison(
    run_id: uuid.UUID,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:read"))],
) -> dict[str, Any]:
    row = await _load_run(db, current_user, run_id)
    return dict(row.comparison_summary or {})
