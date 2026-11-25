"""Read-only, workspace-scoped delivery and investigation history for analysts."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, StringConstraints, ValidationError
from sqlalchemy import select, text

from app.api.v1.deps import AuthUser
from app.db.rls import TenantDBSession
from app.models.investigation import InvestigationEvent

from .investigations import _fetch_run

router = APIRouter(tags=["tkg-knowledge"])
Resource = Literal["case", "alert"]
Short = Annotated[str, StringConstraints(max_length=90)]


class Coverage(BaseModel):
    alerts: int
    eligible_alerts: int
    configured_bindings: int
    enabled_bindings: int
    covered_bindings: int
    delivery_counts: dict[str, int]
    accepted_receipts: int
    recoverable_receipts: int
    last_updated: datetime | None


class BoundEntity(BaseModel):
    id: UUID
    kb_id: UUID


class Reference(BaseModel):
    document_id: UUID
    chunk_id: UUID


class Candidate(Reference):
    kb_id: UUID


class HistoricalFact(BoundEntity):
    root_id: UUID | None = None
    other_id: UUID | None = None
    direction: Literal["in", "out"] | None = None
    predicate_key: Short | None = None
    other_type: Short | None = None
    valid_from: Short | None = None
    valid_to: Short | None = None
    recorded_at: Short | None = None
    knowledge_time: Short | None = None
    contested: bool = False
    stale: bool = False
    inferred: bool = False
    sources: list[Reference] = Field(default_factory=list, max_length=5)


class ToolOutcome(BaseModel):
    tool: Short
    status: Short
    seed_id: Short | None = None
    duration_ms: int | None = None
    fact_count: int
    truncated: bool


class HistoricalClaim(BaseModel):
    claim: str = Field(max_length=420)
    citations: list[Short] = Field(min_length=1, max_length=5)
    status: Literal["requires_analyst_review"]


class History(BaseModel):
    profile: Literal["standard", "deep_case"] | None = None
    historical_status: Short | None = None
    stop_reason: Short | None = None
    coverage: dict[Short, int | bool | None] = Field(default_factory=dict, max_length=20)
    limits: dict[Short, int] = Field(default_factory=dict, max_length=8)
    tool_calls: int | None = None
    tool_requests: int | None = None
    llm_calls: int | None = None
    provider_calls: int | None = None
    planner_attempts: int | None = None
    preflight_tool_calls: int | None = None
    assessment_status: Short | None = None
    reserved_tokens_charged: int | None = None
    estimated_cost_usd: float | None = None
    tools: list[ToolOutcome] = Field(default_factory=list, max_length=25)
    facts: list[HistoricalFact] = Field(default_factory=list, max_length=30)
    entities: list[BoundEntity] = Field(default_factory=list, max_length=25)
    candidates: list[Candidate] = Field(default_factory=list, max_length=15)
    claims: list[HistoricalClaim] = Field(default_factory=list, max_length=8)
    truncated: bool = False


class RunHistory(BaseModel):
    run_id: UUID
    run_status: str
    started_at: datetime
    history: History | None = None


def _permit(user, kind: Resource):
    if not user.explicit_workspace:
        raise HTTPException(403, "Select an authorized workspace")
    user.require_permission("cases:read" if kind == "case" else "alerts:read")


async def _require_owner(db, tenant, kind: Resource, resource_id):
    query = {
        "case": "SELECT 1 FROM aisoc_cases WHERE id=:id AND tenant_id=:tenant",
        "alert": "SELECT 1 FROM alerts WHERE id=:id AND tenant_id=:tenant",
    }[kind]
    if not (await db.execute(text(query), {"id": resource_id, "tenant": tenant})).scalar_one_or_none():
        raise HTTPException(404, "Resource not found")


_MEMBERS = {
    "case": """SELECT a.id,a.connector_id,a.connector_type FROM alerts a
        JOIN aisoc_cases c ON c.id=:id AND c.tenant_id=a.tenant_id
        WHERE a.tenant_id=:tenant AND (a.case_id=c.id OR (a.case_id IS NULL AND a.id=ANY(c.alert_ids)))""",
    "alert": "SELECT id,connector_id,connector_type FROM alerts WHERE id=:id AND tenant_id=:tenant",
}


async def _coverage(db, user, kind: Resource, resource_id):
    _permit(user, kind)
    tenant = user.tenant_id
    await _require_owner(db, tenant, kind, resource_id)
    result = await db.execute(text(f"""
        WITH members AS ({_MEMBERS[kind]}),
        owned_bindings AS (
            SELECT id,connector_id FROM workspace_tkg_bindings
            WHERE tenant_id=:tenant AND enabled AND source_system='splunk'
        ), deliveries AS (
            SELECT d.state,d.updated_at,d.receipt_id,d.receipt_delivery_state
            FROM tkg_alert_deliveries d JOIN members m ON m.id=d.alert_row_id
            WHERE d.tenant_id=:tenant
        ), totals AS (SELECT state,count(*) AS n FROM deliveries GROUP BY state)
        SELECT (SELECT count(*) FROM members) AS alerts,
            (SELECT count(*) FROM members m WHERE m.connector_type='splunk' AND EXISTS (SELECT 1 FROM owned_bindings b
                                                          WHERE b.connector_id=m.connector_id)) AS eligible_alerts,
            (SELECT count(*) FROM workspace_tkg_bindings WHERE tenant_id=:tenant AND source_system='splunk') AS configured_bindings,
            (SELECT count(*) FROM owned_bindings) AS enabled_bindings,
            (SELECT count(*) FROM owned_bindings b WHERE EXISTS (SELECT 1 FROM members m
                                                                 WHERE m.connector_id=b.connector_id)) AS covered_bindings,
            coalesce((SELECT jsonb_object_agg(state,n) FROM totals),'{{}}'::jsonb) AS delivery_counts,
            (SELECT count(*) FROM deliveries WHERE receipt_id IS NOT NULL) AS accepted_receipts,
            (SELECT count(*) FROM deliveries WHERE state='pending_materialization'
              AND receipt_delivery_state IN ('failed_recoverable','retryable_failure')) AS recoverable_receipts,
            (SELECT max(updated_at) FROM deliveries) AS last_updated
    """), {"tenant": tenant, "id": resource_id})
    return Coverage.model_validate(dict(result.mappings().one()))


@router.get("/cases/{resource_id}/tkg-coverage", response_model=Coverage)
async def case_coverage(resource_id: UUID, db: TenantDBSession, user: AuthUser) -> Coverage:
    return await _coverage(db, user, "case", resource_id)


@router.get("/alerts/{resource_id}/tkg-coverage", response_model=Coverage)
async def alert_coverage(resource_id: UUID, db: TenantDBSession, user: AuthUser) -> Coverage:
    return await _coverage(db, user, "alert", resource_id)


@router.get("/investigations/{run_id}/tkg-history", response_model=RunHistory)
async def run_history(run_id: UUID, resource_id: UUID, kind: Resource, db: TenantDBSession, user: AuthUser) -> RunHistory:
    _permit(user, kind)
    tenant = user.tenant_id
    await _require_owner(db, tenant, kind, resource_id)
    run = await _fetch_run(db, run_id, tenant)
    if kind == "case" and run.case_id != resource_id:
        raise HTTPException(404, "Investigation run not found")
    result = await db.execute(select(InvestigationEvent.payload["tkg_history_v1"]).where(
        InvestigationEvent.run_id == run_id, InvestigationEvent.tenant_id == tenant,
        InvestigationEvent.kind == "recon", InvestigationEvent.agent == "ReconAgent",
    ).order_by(InvestigationEvent.seq.desc()).limit(1))
    entry = result.scalar_one_or_none()
    history = None
    if isinstance(entry, dict):
        if entry.get("resource_kind") != kind or entry.get("resource_id") != str(resource_id):
            raise HTTPException(404, "Investigation run not found")
        try:
            history = History.model_validate(entry.get("history"))
        except ValidationError:
            pass  # Unreadable historical projections are unavailable to the browser.
    elif kind == "alert" and run.case_id != resource_id:
        raise HTTPException(404, "Investigation run not found")
    return RunHistory(run_id=run.id, run_status=run.status, started_at=run.started_at, history=history)
