"""Alert-scoped AI Investigation — powers Alert Detail "Start AI Investigation".

``POST /api/v1/agents/investigate`` starts the Pillar-1 InvestigatorOrchestrator
(recon → forensic → responder → report) in the background and returns
``status=running`` immediately. Poll ``GET /api/v1/agents/investigations/{id}``
for the finished report. This keeps Next.js / browser proxies from timing out
on cold LLM runs (~60s+) and surfacing a false 500 while the agent is still
working.

Live LLM calls go through :func:`app.llm.factory.make_chat_model` (roles
``recon`` / ``investigation`` / ``report``), so pointing ``OPENAI_BASE_URL`` at
an OpenAI-compatible gateway (e.g. Arvan Cloud AI / DeepSeek-V4-Flash) is enough
to drive this path — no code change per provider.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.investigator import InvestigatorOrchestrator
from app.privacy.context import PrivacyConfigurationError
from app.llm.gateway_config import validate_gateway_config
from app.privacy.tenant import require_run_owner, resolve_tenant_for_llm, trusted_workflow_tenant

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/agents", tags=["agents-investigate"])

_runs: dict[str, dict[str, Any]] = {}
_background_tasks: set[asyncio.Task[None]] = set()


class AlertInvestigateRequest(BaseModel):
    """Body from the web console (camelCase) or internal callers (snake_case)."""

    alertId: str | None = None
    alert_id: str | None = None
    alert_summary: str = ""
    raw_alert: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = "default"


class AgentActionOut(BaseModel):
    type: str
    target: str
    status: str = "proposed"


class AgentInvestigationOut(BaseModel):
    id: str
    alertId: str
    status: str
    findings: str | None = None
    recommendations: list[str] | None = None
    actions: list[AgentActionOut] | None = None
    startedAt: str
    completedAt: str | None = None
    model: str | None = None
    error: str | None = None


def _resolve_alert_id(req: AlertInvestigateRequest) -> str:
    alert_id = (req.alertId or req.alert_id or "").strip()
    if not alert_id:
        raise HTTPException(status_code=422, detail="alertId is required")
    return alert_id


def _build_summary(req: AlertInvestigateRequest, alert_id: str) -> str:
    if req.alert_summary.strip():
        return req.alert_summary.strip()
    raw = req.raw_alert or {}
    title = str(raw.get("title") or raw.get("name") or "").strip()
    description = str(raw.get("description") or raw.get("narrative") or "").strip()
    severity = str(raw.get("severity") or "").strip()
    parts = [p for p in (title, description) if p]
    if not parts:
        return f"Investigate alert {alert_id}"
    head = " — ".join(parts[:2])
    if severity:
        return f"[{severity}] {head}"
    return head


def _map_recommendations(responder: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for item in responder.get("recommended_actions") or []:
        if isinstance(item, dict):
            action = str(item.get("action") or item.get("description") or "").strip()
            if action:
                out.append(action)
        elif isinstance(item, str) and item.strip():
            out.append(item.strip())
    for step in responder.get("containment_steps") or []:
        text = str(step).strip()
        if text and text not in out:
            out.append(text)
    return out[:20]


def _map_actions(responder: dict[str, Any]) -> list[AgentActionOut]:
    actions: list[AgentActionOut] = []
    for item in responder.get("recommended_actions") or []:
        if not isinstance(item, dict):
            continue
        action_type = str(item.get("action") or item.get("type") or "investigate").strip()
        target = str(item.get("target") or item.get("rationale") or "alert").strip()
        actions.append(
            AgentActionOut(
                type=action_type[:120],
                target=target[:200],
                status="proposed",
            )
        )
    return actions[:15]


def _findings_markdown(state: Any) -> str:
    report = getattr(state, "report_md", None) or ""
    if isinstance(report, str) and report.strip():
        return report.strip()
    bits: list[str] = []
    recon = getattr(state, "recon", None)
    forensic = getattr(state, "forensic", None)
    if recon is not None and getattr(recon, "summary", None):
        bits.append(f"## Recon\n{recon.summary}")
    if forensic is not None and getattr(forensic, "summary", None):
        bits.append(f"## Forensic\n{forensic.summary}")
    mitre = getattr(recon, "mitre_techniques", None) if recon is not None else None
    if mitre:
        bits.append("## MITRE\n" + ", ".join(str(t) for t in mitre[:25]))
    return "\n\n".join(bits) if bits else "Investigation completed with no narrative report."


async def _run_investigation(
    *,
    run_id: str,
    alert_id: str,
    summary: str,
    raw_alert: dict[str, Any],
    tenant_id: str,
    model_name: str | None,
    started_at: str,
) -> None:
    """Persist background investigation output for the authenticated tenant."""
    try:
        state = await InvestigatorOrchestrator().run(
            case_id=alert_id,
            alert_summary=summary,
            raw_alert=raw_alert or {"alert_id": alert_id},
            tenant_id=tenant_id,
        )
        completed_at = datetime.now(UTC).isoformat()
        status = state.status if state.status in ("completed", "failed", "running") else "completed"
        if state.error and status != "failed":
            status = "failed"
        responder = state.responder.model_dump(mode="json") if state.responder else {}
        result = AgentInvestigationOut(
            id=run_id,
            alertId=alert_id,
            status=status,
            findings=_findings_markdown(state) if status != "failed" else "Investigation failed",
            recommendations=_map_recommendations(responder) if status != "failed" else [],
            actions=_map_actions(responder) if status != "failed" else [],
            startedAt=started_at,
            completedAt=completed_at,
            model=model_name,
            error="Investigation failed" if status == "failed" else None,
        )
        _runs[run_id] = {**result.model_dump(), "_tenant_owner": tenant_id}
        logger.info(
            "alert_investigate.done",
            run_id=run_id,
            alert_id=alert_id,
            status=status,
            findings_len=len(result.findings or ""),
            recommendations=len(result.recommendations or []),
        )
    except Exception as exc:  # noqa: BLE001 - persist a sanitized failure for polling
        completed_at = datetime.now(UTC).isoformat()
        logger.error(
            "alert_investigate.failed",
            run_id=run_id,
            alert_id=alert_id,
            error_category=type(exc).__name__,
        )
        failed = AgentInvestigationOut(
            id=run_id,
            alertId=alert_id,
            status="failed",
            findings=None,
            recommendations=[],
            actions=[],
            startedAt=started_at,
            completedAt=completed_at,
            model=model_name,
            error="Investigation failed",
        )
        _runs[run_id] = {**failed.model_dump(), "_tenant_owner": tenant_id}


@router.post("/investigate", response_model=AgentInvestigationOut)
async def investigate_alert(req: AlertInvestigateRequest, request: Request) -> AgentInvestigationOut:
    """Start a tenant-bound background investigation; poll for its result."""
    alert_id = _resolve_alert_id(req)
    summary = _build_summary(req, alert_id)

    # Body tenant_id is never proof of identity when privacy protection is enabled.
    try:
        trusted_ref = trusted_workflow_tenant(request, req.tenant_id)
    except PrivacyConfigurationError as exc:
        raise HTTPException(status_code=403, detail="Trusted tenant required") from exc
    try:
        tenant_id = await resolve_tenant_for_llm(trusted_ref, allow_default=True)
    except PrivacyConfigurationError as exc:
        raise HTTPException(status_code=503, detail="Tenant resolution unavailable") from exc

    gateway = validate_gateway_config()
    model_name = gateway.get("model_investigation")
    run_id = str(uuid4())
    started_at = datetime.now(UTC).isoformat()
    pending = AgentInvestigationOut(
        id=run_id,
        alertId=alert_id,
        status="running",
        findings=None,
        recommendations=[],
        actions=[],
        startedAt=started_at,
        completedAt=None,
        model=model_name,
        error=None,
    )
    _runs[run_id] = {**pending.model_dump(), "_tenant_owner": tenant_id}
    logger.info(
        "alert_investigate.start",
        run_id=run_id,
        alert_id=alert_id,
        llm_configured=gateway.get("llm_configured"),
        model=model_name,
        base_url=gateway.get("base_url_normalized_sanitized"),
    )
    task = asyncio.create_task(
        _run_investigation(
            run_id=run_id,
            alert_id=alert_id,
            summary=summary,
            raw_alert=req.raw_alert or {"alert_id": alert_id},
            tenant_id=tenant_id,
            model_name=model_name,
            started_at=started_at,
        )
    )
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return pending


@router.get("/investigations/{run_id}", response_model=AgentInvestigationOut)
async def get_alert_investigation(run_id: str, request: Request) -> AgentInvestigationOut:
    """Poll run status only for the authenticated tenant owner."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")
    await require_run_owner(request, run.get("_tenant_owner"))
    if "id" not in run:
        return AgentInvestigationOut(
            id=run_id,
            alertId=str(run.get("alertId") or ""),
            status=str(run.get("status") or "running"),
            startedAt=str(run.get("startedAt") or datetime.now(UTC).isoformat()),
            model=run.get("model"),
        )
    return AgentInvestigationOut.model_validate(run)


@router.get("/llm-status")
async def llm_status() -> dict[str, Any]:
    """Safe diagnostics for the OpenAI-compatible gateway (no secrets)."""
    return validate_gateway_config()
