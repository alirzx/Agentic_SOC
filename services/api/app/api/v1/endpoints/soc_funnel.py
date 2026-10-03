"""Agentic funnel endpoints — reportable queue, backfill, board, Jira push."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession
from app.services import agentic_funnel
from app.services.case_fanout import fanout_create_case
from app.services.funnel_stages import READY_FOR_JIRA, passes_jira_gate
from app.services.incident_report import build_incident_report

router = APIRouter(prefix="/soc", tags=["soc-funnel"])


class BackfillResponse(BaseModel):
    window_hours: int
    alerts_scanned: int
    false_positive_tagged: int
    cases_created: int
    alerts_linked: int
    skipped: int
    reportable: list[dict[str, Any]] = Field(default_factory=list)
    stage_sync: dict[str, int] = Field(default_factory=dict)
    stages_updated: int = 0


class ReportableResponse(BaseModel):
    window_hours: int
    alerts_total: int
    false_positives: int
    reportable_count: int
    reportable_cases: list[dict[str, Any]] = Field(default_factory=list)


class FunnelBoardResponse(BaseModel):
    window_hours: int
    alerts_total: int
    stages: list[dict[str, Any]]
    samples_by_stage: dict[str, list[dict[str, Any]]]
    ratios: dict[str, float]


class PushItsmRequest(BaseModel):
    case_id: str
    connector_ids: list[UUID] = Field(min_length=1)
    analyst_approved: bool = True


class PushItsmResponse(BaseModel):
    case_id: str
    gated: bool = False
    gate_reason: str | None = None
    report_preview: str | None = None
    results: list[dict[str, Any]] = Field(default_factory=list)


@router.get("/reportable", response_model=ReportableResponse, summary="SOC reportable case queue")
async def get_reportable(
    db: DBSession,
    user: AuthUser,
    hours: int = Query(24, ge=1, le=168),
) -> ReportableResponse:
    """What the SOC should escalate / report from the last N hours."""
    payload = await agentic_funnel.list_reportable(db, tenant_id=user.tenant_id, hours=hours)
    return ReportableResponse(**payload)


@router.get("/funnel/board", response_model=FunnelBoardResponse, summary="SOC funnel stage board")
async def get_funnel_board(
    db: DBSession,
    user: AuthUser,
    hours: int = Query(24, ge=1, le=168),
) -> FunnelBoardResponse:
    """Live counts per funnel stage for UI tracking (ingested → jira_pushed)."""
    payload = await agentic_funnel.funnel_board(db, tenant_id=user.tenant_id, hours=hours)
    return FunnelBoardResponse(**payload)


@router.post("/funnel/backfill", response_model=BackfillResponse, summary="Run 24h agentic funnel backfill")
async def post_funnel_backfill(
    db: DBSession,
    user: AuthUser,
    hours: int = Query(24, ge=1, le=168),
) -> BackfillResponse:
    """Classify existing alerts: FP-tag noise, promote importants into Cases + tasks."""
    payload = await agentic_funnel.run_backfill(db, tenant_id=user.tenant_id, hours=hours)
    return BackfillResponse(**payload)


@router.post("/funnel/push-itsm", response_model=PushItsmResponse, summary="Push case to Jira (gated)")
async def post_push_itsm(
    body: PushItsmRequest,
    db: DBSession,
    user: AuthUser,
) -> PushItsmResponse:
    """Promote-to-incident + push Jira with standard report (product funnel P2/P3)."""
    try:
        case_uuid = UUID(body.case_id.strip())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="case_id must be a UUID") from exc

    row = (
        await db.execute(
            text(
                "SELECT * FROM aisoc_cases WHERE id = :id AND tenant_id = :tid"
            ).bindparams(id=case_uuid, tid=user.tenant_id)
        )
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Case not found")

    disp_row = (
        await db.execute(
            text(
                """
                SELECT disposition FROM alerts
                 WHERE tenant_id = :tid AND case_id = :cid
                   AND disposition IS NOT NULL
                 ORDER BY CASE disposition
                   WHEN 'true_positive' THEN 1 WHEN 'escalate' THEN 2 ELSE 3 END
                 LIMIT 1
                """
            ).bindparams(tid=user.tenant_id, cid=case_uuid)
        )
    ).fetchone()
    disposition = str(disp_row[0]) if disp_row and disp_row[0] else None
    if not passes_jira_gate(
        disposition=disposition,
        tags=dict(row._mapping).get("tags") if hasattr(row, "_mapping") else None,
        analyst_approved=body.analyst_approved,
    ):
        return PushItsmResponse(
            case_id=str(case_uuid),
            gated=True,
            gate_reason=(
                f"Blocked: disposition={disposition or 'unknown'} "
                "(need true_positive/escalate or analyst_approved for needs_review)"
            ),
            results=[],
        )

    # Mark ready before push so the board reflects analyst intent immediately.
    await db.execute(
        text(
            """
            UPDATE alerts
               SET funnel_stage = :stage, updated_at = now()
             WHERE tenant_id = :tid AND case_id = :cid
               AND funnel_stage NOT IN ('jira_pushed')
            """
        ).bindparams(stage=READY_FOR_JIRA, tid=user.tenant_id, cid=case_uuid)
    )
    await db.commit()

    mapping = dict(row._mapping)
    preview = build_incident_report(
        title=str(mapping.get("title") or "Incident"),
        severity=str(mapping.get("severity") or "medium"),
        disposition=disposition,
        summary=str(mapping.get("description") or "")[:2000],
        mitre_techniques=mapping.get("mitre_techniques") or [],
        case_id=str(case_uuid),
        alert_ids=[str(a) for a in (mapping.get("alert_ids") or [])],
    )
    results = await fanout_create_case(
        db,
        case_row=row,
        tenant_id=user.tenant_id,
        connector_ids=body.connector_ids,
        pushed_by=getattr(user, "email", None),
        analyst_approved=body.analyst_approved,
    )
    await db.commit()
    return PushItsmResponse(
        case_id=str(case_uuid),
        gated=False,
        report_preview=preview,
        results=[r.model_dump(mode="json") for r in results],
    )
