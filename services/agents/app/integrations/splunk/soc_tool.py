"""SocToolRegistry adapter for splunk_search (Phase 8.7)."""

from __future__ import annotations

from typing import Any

from app.runtime.contracts import AgentContext
from app.runtime.tools import SOCTool, ToolContext

from .tool import run_splunk_search


class SplunkSearchSocTool(SOCTool[dict[str, Any], Any]):
    name = "splunk_search"
    description = (
        "Search the organization's Splunk SIEM for security-relevant events (read-only). "
        "Use when validating an alert, investigating authentication activity, network connections, "
        "suspicious hosts/IPs/users, or correlating activity in a time window. "
        "Returns normalized Splunk evidence events with evidence_id splunk:<sid>:<index>. "
        "Prefer this over siem.get_related_events when raw SIEM telemetry is needed."
    )
    risk_level = "read"
    requires_approval = False
    allowed_agents = frozenset({"investigation", "correlation", "validation"})
    allowed_roles = frozenset({"analyst", "admin", "system"})
    input_schema = {
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {"type": "string", "description": "SPL search (read-only)"},
            "earliest": {"type": "string", "description": "e.g. -15m"},
            "latest": {"type": "string", "description": "default now"},
            "max_events": {"type": "integer", "minimum": 1, "maximum": 100},
        },
    }
    output_schema = {"type": "object"}
    permission = "READ_SECURITY_DATA"
    timeout_seconds = 45.0
    audit_required = True

    async def execute(self, input: dict[str, Any], context: ToolContext) -> Any:
        agent_ctx = AgentContext(
            tenant_id=context.tenant_id,
            incident_id=context.incident_id,
            objective=str(context.metadata.get("objective") or ""),
            metadata=context.metadata,
        )
        result = await run_splunk_search(
            str(input.get("query") or ""),
            earliest=input.get("earliest"),
            latest=input.get("latest", "now"),
            max_events=int(input.get("max_events") or 100),
            context=agent_ctx,
            agent_name=context.agent_name,
        )
        context.metadata.update(agent_ctx.metadata)
        return result.model_dump(mode="json")
