"""Alert-scoped AI Investigation — powers Alert Detail "Start AI Investigation".

``POST /api/v1/agents/investigate`` runs the Pillar-1 InvestigatorOrchestrator
(recon → forensic → responder → report) synchronously and returns the shape the
web console expects. Every step is recorded in the case ledger.

Live LLM calls go through :func:`app.llm.factory.make_chat_model` (roles
``recon`` / ``investigation`` / ``report``), so pointing ``OPENAI_BASE_URL`` at
an OpenAI-compatible gateway (e.g. Arvan Cloud AI / DeepSeek-V4-Flash) is enough
to drive this path — no code change per provider.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.investigator import InvestigatorOrchestrator
from app.llm.gateway_config import validate_gateway_config

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/agents", tags=["agents-investigate"])

_runs: dict[str, dict[str, Any]] = {}


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


@router.post("/investigate", response_model=AgentInvestigationOut)
async def investigate_alert(req: AlertInvestigateRequest) -> AgentInvestigationOut:
    """Run a full agent investigation for one alert and return the report."""
    alert_id = _resolve_alert_id(req)
    summary = _build_summary(req, alert_id)
    run_id = str(uuid4())
    started_at = datetime.now(UTC).isoformat()
    gateway = validate_gateway_config()
    model_name = gateway.get("model_investigation")
    _runs[run_id] = {
        "status": "running",
        "alertId": alert_id,
        "startedAt": started_at,
        "model": model_name,
    }
    logger.info(
        "alert_investigate.start",
        run_id=run_id,
        alert_id=alert_id,
        llm_configured=gateway.get("llm_configured"),
        model=model_name,
        base_url=gateway.get("base_url_normalized_sanitized"),
    )
    try:
        state = await InvestigatorOrchestrator().run(
            case_id=alert_id,
            alert_summary=summary,
            raw_alert=req.raw_alert or {"alert_id": alert_id},
            tenant_id=req.tenant_id or "default",
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
            findings=_findings_markdown(state) if status != "failed" else state.error,
            recommendations=_map_recommendations(responder) if status != "failed" else [],
            actions=_map_actions(responder) if status != "failed" else [],
            startedAt=started_at,
            completedAt=completed_at,
            model=model_name,
            error=state.error,
        )
        _runs[run_id] = result.model_dump()
        logger.info(
            "alert_investigate.done",
            run_id=run_id,
            alert_id=alert_id,
            status=status,
            findings_len=len(result.findings or ""),
            recommendations=len(result.recommendations or []),
        )
        return result
    except Exception as exc:  # noqa: BLE001 — surface failure to the console
        completed_at = datetime.now(UTC).isoformat()
        logger.error("alert_investigate.failed", run_id=run_id, alert_id=alert_id, error=str(exc))
        result = AgentInvestigationOut(
            id=run_id,
            alertId=alert_id,
            status="failed",
            findings=None,
            recommendations=[],
            actions=[],
            startedAt=started_at,
            completedAt=completed_at,
            model=model_name,
            error=str(exc),
        )
        _runs[run_id] = result.model_dump()
        raise HTTPException(status_code=502, detail=f"Investigation failed: {exc}") from exc


@router.get("/investigations/{run_id}", response_model=AgentInvestigationOut)
async def get_alert_investigation(run_id: str) -> AgentInvestigationOut:
    """Poll a previously started alert investigation (in-memory status cache)."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")
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
