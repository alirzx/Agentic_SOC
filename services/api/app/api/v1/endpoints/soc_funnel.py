"""Agentic funnel endpoints — reportable queue + 24h backfill."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, DBSession
from app.services import agentic_funnel

router = APIRouter(prefix="/soc", tags=["soc-funnel"])


class BackfillResponse(BaseModel):
    window_hours: int
    alerts_scanned: int
    false_positive_tagged: int
    cases_created: int
    alerts_linked: int
    skipped: int
    reportable: list[dict[str, Any]] = Field(default_factory=list)


class ReportableResponse(BaseModel):
    window_hours: int
    alerts_total: int
    false_positives: int
    reportable_count: int
    reportable_cases: list[dict[str, Any]] = Field(default_factory=list)


@router.get("/reportable", response_model=ReportableResponse, summary="SOC reportable case queue")
async def get_reportable(
    db: DBSession,
    user: AuthUser,
    hours: int = Query(24, ge=1, le=168),
) -> ReportableResponse:
    """What the SOC should escalate / report from the last N hours."""
    payload = await agentic_funnel.list_reportable(db, tenant_id=user.tenant_id, hours=hours)
    return ReportableResponse(**payload)


@router.post("/funnel/backfill", response_model=BackfillResponse, summary="Run 24h agentic funnel backfill")
async def post_funnel_backfill(
    db: DBSession,
    user: AuthUser,
    hours: int = Query(24, ge=1, le=168),
) -> BackfillResponse:
    """Classify existing alerts: FP-tag noise, promote importants into Cases + tasks."""
    payload = await agentic_funnel.run_backfill(db, tenant_id=user.tenant_id, hours=hours)
    return BackfillResponse(**payload)
