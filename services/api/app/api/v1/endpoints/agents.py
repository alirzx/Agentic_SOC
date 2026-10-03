"""Agent-facing endpoints — capability tools + AI Investigation proxy.

Workstream 4 covers ``GET /agents/tools`` (connector capability catalogue).
This module also hosts ``POST /agents/investigate`` — the Alert Detail
"Start AI Investigation" button. That path loads the tenant-scoped alert
here, then proxies a synchronous investigation to the agents service
(DeepSeek / OpenAI-compatible via ``OPENAI_BASE_URL``).
"""

from __future__ import annotations

import logging
import os
import re
from typing import Annotated, Any
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.connectors import _fetch_catalog, _safe_log_val
from app.models.alert import Alert
from app.models.connector import Connector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agents", tags=["agents"])

_AGENTS_URL = (os.getenv("AGENTS_SERVICE_URL") or os.getenv("AGENTS_API_URL") or "http://agents:8084").rstrip("/")
_SAFE_PROXY_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./%]*$")
_INVESTIGATE_TIMEOUT_SECONDS = float(os.getenv("AISOC_ALERT_INVESTIGATE_TIMEOUT", "180"))


# --------------------------------------------------------------- Pydantic schemas


class AgentToolDescriptor(BaseModel):
    """One callable verb on one connector instance, as the agent sees it."""

    name: str = Field(
        description=(
            "Stable unique identifier for this tool, formatted as "
            "'<connector_instance_id>.<capability>'."
        ),
    )
    connector_id: str = Field(description="Connector instance UUID.")
    connector_type: str = Field(description="Catalog connector type, e.g. 'crowdstrike'.")
    connector_name: str = Field(
        description="Operator-chosen instance display name (e.g. 'CrowdStrike — prod').",
    )
    category: str = Field(description="Catalog category, e.g. 'edr', 'siem', 'iam'.")
    capability: str = Field(description="The capability verb.")
    capability_group: str = Field(description="Coarse grouping (read/query/pivot/…).")
    description: str = Field(description="Human-readable summary of the verb.")
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}},
        description="JSON-Schema for the verb's arguments.",
    )


class AgentToolsResponse(BaseModel):
    """Tenant-wide tool catalogue surfaced to the agent layer."""

    tools: list[AgentToolDescriptor]
    tool_count: int
    connector_count: int


class AlertInvestigateRequest(BaseModel):
    """Body from Alert Detail — camelCase ``alertId`` matches the web console."""

    alertId: str = Field(..., min_length=1, description="Alert UUID to investigate.")


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


# ---------------------------------------------------------------------- helpers


_CAPABILITY_GROUP_LOOKUP: dict[str, str] = {
    "pull_alerts": "read",
    "pull_logs": "read",
    "pull_audit": "read",
    "pull_pcap": "read",
    "pull_file": "read",
    "query_logs": "query",
    "query_processes": "query",
    "pivot_user": "pivot",
    "pivot_host": "pivot",
    "pivot_ip": "pivot",
    "pivot_hash": "pivot",
    "pivot_domain": "pivot",
    "enrich_user": "enrich",
    "enrich_host": "enrich",
    "enrich_ioc": "enrich",
    "enrich_domain": "enrich",
    "enrich_vuln": "enrich",
    "enrich_asset": "enrich",
    "isolate_host": "contain",
    "unisolate_host": "contain",
    "kill_process": "contain",
    "quarantine_file": "contain",
    "block_hash": "contain",
    "block_domain": "contain",
    "block_user_signin": "remediate",
    "disable_user": "remediate",
    "revoke_session": "remediate",
    "reset_password": "remediate",
    "revoke_token": "remediate",
    "push_case": "ticket",
    "push_status": "ticket",
    "read_audit_trail": "audit",
}


def _capability_group_of(capability: str) -> str:
    return _CAPABILITY_GROUP_LOOKUP.get(capability, "unknown")


def _capability_descriptions(catalog_entry: dict[str, Any]) -> dict[str, str]:
    raw = catalog_entry.get("capabilities") or []
    out: dict[str, str] = {}
    for item in raw:
        if isinstance(item, dict):
            name = item.get("value") or item.get("name")
            if isinstance(name, str):
                desc = item.get("description")
                out[name] = desc if isinstance(desc, str) and desc else _default_description(name)
        elif isinstance(item, str):
            out[item] = _default_description(item)
    return out


def _default_description(capability: str) -> str:
    pretty = capability.replace("_", " ")
    return f"Invoke '{pretty}' on this connector instance."


def _validate_agents_path(path: str) -> str:
    if not isinstance(path, str) or not _SAFE_PROXY_PATH_RE.match(path) or ".." in path or path.startswith("//"):
        raise HTTPException(status_code=400, detail="invalid_request_path")
    return path


def _build_alert_summary(alert: Alert) -> str:
    parts = [alert.title]
    if alert.description:
        parts.append(alert.description)
    elif alert.narrative:
        parts.append(alert.narrative)
    head = " — ".join(parts[:2])
    return f"[{alert.severity}] {head}"


def _build_raw_alert(alert: Alert) -> dict[str, Any]:
    return {
        "id": str(alert.id),
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "category": alert.category,
        "mitre_tactics": alert.mitre_tactics or [],
        "mitre_techniques": alert.mitre_techniques or [],
        "connector_type": alert.connector_type,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "narrative": alert.narrative,
        "affected_ips": alert.affected_ips or [],
        "affected_hosts": alert.affected_hosts or [],
        "affected_users": alert.affected_users or [],
        "raw_event": alert.raw_event or {},
    }


# -------------------------------------------------------------------- endpoints


@router.get("/tools", response_model=AgentToolsResponse)
async def list_agent_tools(
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> AgentToolsResponse:
    """Return the agent's allowed tool surface for this tenant."""
    result = await db.execute(
        select(Connector).where(
            Connector.tenant_id == current_user.tenant_id,
            Connector.is_enabled.is_(True),
        )
    )
    instances = list(result.scalars().all())
    if not instances:
        return AgentToolsResponse(tools=[], tool_count=0, connector_count=0)

    catalog = await _fetch_catalog()
    catalog_by_type: dict[str, dict[str, Any]] = {
        entry["connector_id"]: entry for entry in catalog if isinstance(entry, dict) and isinstance(entry.get("connector_id"), str)
    }

    tools: list[AgentToolDescriptor] = []
    contributing_instances = 0

    for inst in instances:
        catalog_entry = catalog_by_type.get(inst.connector_type)
        if catalog_entry is None:
            logger.info(
                "agents.tools.skip_orphan tenant_id=%s connector_id=%s connector_type=%s",
                current_user.tenant_id,
                inst.id,
                _safe_log_val(inst.connector_type),
            )
            continue

        declared_descriptions = _capability_descriptions(catalog_entry)
        declared_set = set(declared_descriptions.keys())

        if inst.allowed_capabilities is None:
            effective: list[str] = sorted(declared_set)
        else:
            allowed_set = {str(c) for c in inst.allowed_capabilities}
            effective = sorted(allowed_set & declared_set)

        if not effective:
            continue
        contributing_instances += 1

        category = catalog_entry.get("category") or getattr(inst, "category", None) or "uncategorized"
        connector_id_str = str(inst.id)

        for cap in effective:
            tools.append(
                AgentToolDescriptor(
                    name=f"{connector_id_str}.{cap}",
                    connector_id=connector_id_str,
                    connector_type=inst.connector_type,
                    connector_name=inst.name,
                    category=category,
                    capability=cap,
                    capability_group=_capability_group_of(cap),
                    description=declared_descriptions[cap],
                ),
            )

    tools.sort(key=lambda t: (t.connector_name.lower(), t.capability))
    logger.info(
        "agents.tools.served tenant_id=%s instances=%d tools=%d",
        current_user.tenant_id,
        contributing_instances,
        len(tools),
    )
    return AgentToolsResponse(
        tools=tools,
        tool_count=len(tools),
        connector_count=contributing_instances,
    )


@router.post("/investigate", response_model=AgentInvestigationOut)
async def investigate_alert(
    body: AlertInvestigateRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
) -> AgentInvestigationOut:
    """Run AI Investigation on an alert (Alert Detail → Start AI Investigation)."""
    try:
        alert_uuid = UUID(body.alertId.strip())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="alertId must be a UUID") from exc

    from sqlalchemy import update

    from app.services.funnel_stages import INVESTIGATING, READY_FOR_JIRA, TRIAGED

    result = await db.execute(
        select(Alert).where(Alert.id == alert_uuid, Alert.tenant_id == current_user.tenant_id)
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    await db.execute(
        update(Alert)
        .where(Alert.id == alert.id, Alert.tenant_id == current_user.tenant_id)
        .values(funnel_stage=INVESTIGATING)
    )
    await db.commit()

    path = _validate_agents_path("/api/v1/agents/investigate")
    payload = {
        "alertId": str(alert.id),
        "alert_summary": _build_alert_summary(alert),
        "raw_alert": _build_raw_alert(alert),
        "tenant_id": str(current_user.tenant_id),
    }
    url = f"{_AGENTS_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=_INVESTIGATE_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json=payload)
    except httpx.HTTPError as exc:
        logger.exception("agents.investigate.proxy_failed alert_id=%s", alert.id)
        raise HTTPException(status_code=503, detail=f"Agents service unavailable: {exc}") from exc

    if resp.status_code >= 400:
        detail = resp.text[:500] if resp.text else f"agents returned {resp.status_code}"
        raise HTTPException(status_code=resp.status_code, detail=detail)

    out = AgentInvestigationOut.model_validate(resp.json())
    # After a successful investigation, park at ready_for_jira when already
    # cased/TP; otherwise leave at investigating so the board reflects work.
    next_stage = READY_FOR_JIRA if alert.case_id or (alert.disposition or "") in {
        "true_positive",
        "escalate",
        "likely_tp",
    } else INVESTIGATING
    if out.status == "failed":
        next_stage = TRIAGED
    await db.execute(
        update(Alert)
        .where(Alert.id == alert.id, Alert.tenant_id == current_user.tenant_id)
        .values(funnel_stage=next_stage)
    )
    await db.commit()
    return out


@router.get("/investigations/{run_id}", response_model=AgentInvestigationOut)
async def get_alert_investigation(
    run_id: str,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
) -> AgentInvestigationOut:
    """Poll a previously started alert investigation via the agents service."""
    safe_run_id = re.sub(r"[^A-Za-z0-9_\-]", "", run_id)
    if not safe_run_id:
        raise HTTPException(status_code=422, detail="invalid run_id")
    path = _validate_agents_path(f"/api/v1/agents/investigations/{safe_run_id}")
    url = f"{_AGENTS_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail=f"Agents service unavailable: {exc}") from exc
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text[:500])
    return AgentInvestigationOut.model_validate(resp.json())
