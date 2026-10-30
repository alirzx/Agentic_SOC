"""
Agent service REST API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel

from app.graph.runner import run_full_investigation
from app.models.state import AgentTask, InvestigationState
from app.privacy.tenant import require_run_owner, resolve_tenant_for_llm, trusted_workflow_tenant

router = APIRouter()

# In-memory run store for status polling. The durable record of every step is
# the Postgres Investigation Ledger (written by the shared graph runner) — this
# dict is only the fast local status cache for GET /investigations/{run_id}.
_runs: dict[str, dict] = {}


class InvestigationRequest(BaseModel):
    incident_id: UUID
    tenant_id: UUID
    alert_summary: str
    raw_alert: dict[str, Any] = {}
    task: AgentTask = AgentTask.INVESTIGATION


class InvestigationResponse(BaseModel):
    run_id: UUID
    status: str
    message: str


async def _run_investigation(run_id: str, state: InvestigationState) -> None:
    """Run investigation in background and store results.

    Uses the SAME durable graph runner as the Kafka auto-triage worker
    (issue #569), so manual and automated investigations share one
    orchestration implementation and both persist every step to the ledger.
    """
    try:
        result = await run_full_investigation(state)
        _runs[run_id].update(
            {
                "status": "completed",
                "result": result.to_dict(),
                "completed_at": datetime.utcnow().isoformat(),
            }
        )
    except Exception as exc:  # noqa: BLE001 — surface failure via the status cache
        _runs[run_id].update({"status": "failed", "error": type(exc).__name__})


@router.post("/investigations", response_model=InvestigationResponse)
async def start_investigation(
    body: InvestigationRequest,
    background_tasks: BackgroundTasks,
    request: Request,
):
    """Start a new automated investigation for an incident."""
    tenant_ref = trusted_workflow_tenant(request, str(body.tenant_id))
    tenant_id = await resolve_tenant_for_llm(tenant_ref)
    run_id = str(uuid4())
    state = InvestigationState(
        run_id=UUID(run_id),
        incident_id=body.incident_id,
        tenant_id=UUID(tenant_id),
        task=body.task,
        alert_summary=body.alert_summary,
        raw_alert=body.raw_alert,
    )
    _runs[run_id] = {
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "_tenant_owner": tenant_id,
    }
    background_tasks.add_task(_run_investigation, run_id, state)

    return InvestigationResponse(
        run_id=UUID(run_id),
        status="running",
        message="Investigation started",
    )


@router.get("/investigations/{run_id}")
async def get_investigation(run_id: str, request: Request):
    """Get the status and results of an investigation run."""
    run = _runs.get(run_id)
    if not run:
        # ``app.main`` historically registered this legacy route before the
        # newer investigator route at the same path. Serve the newer store as
        # a compatibility fallback so route ordering cannot bypass ownership
        # or make successfully launched investigator runs unpollable.
        from app.api.investigate import _runs as investigator_runs  # noqa: PLC0415

        run = investigator_runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")
    await require_run_owner(request, run.get("_tenant_owner"))
    return {key: value for key, value in run.items() if key != "_tenant_owner"}


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-agents"}
