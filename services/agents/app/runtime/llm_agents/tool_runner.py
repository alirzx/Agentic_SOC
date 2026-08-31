"""Tool execution through SocToolRegistry with policy validation (Phase 8.6)."""

from __future__ import annotations

import time
from typing import Any

import structlog

from app.runtime.contracts import AgentContext
from app.runtime.tools import SocToolRegistry, ToolCallBudgetExceeded, ToolContext, ToolPermissionDenied, UnknownToolError

from .evidence_bridge import evidence_from_tool_result
from .limits import max_tool_calls

logger = structlog.get_logger()


def _tool_context(context: AgentContext, agent_name: str, tool_call_count: int) -> ToolContext:
    return ToolContext(
        tenant_id=context.tenant_id,
        incident_id=context.incident_id,
        agent_name=agent_name,
        approval_granted=bool(context.metadata.get("approval_granted")),
        shadow_mode=bool(context.metadata.get("shadow_mode")),
        tool_call_count=tool_call_count,
        max_tool_calls=min(context.constraints.max_tool_calls, max_tool_calls()),
        metadata=dict(context.metadata),
    )


def list_tools_for_agent(registry: SocToolRegistry, agent_name: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in registry.names():
        tool = registry.get(name)
        if agent_name in tool.allowed_agents or not tool.allowed_agents:
            schema = getattr(tool, "to_schema", lambda: {})()
            rows.append(
                {
                    "name": name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                    "risk_level": tool.risk_level,
                    **schema,
                }
            )
    return rows


async def execute_registry_tool(
    registry: SocToolRegistry,
    context: AgentContext,
    *,
    agent_name: str,
    agent_version: str,
    tool_name: str,
    arguments: dict[str, Any],
    tool_call_count: int,
    reason: str = "",
) -> tuple[Any, Any]:
    """Execute tool via registry; returns (result, Evidence)."""
    tool_ctx = _tool_context(context, agent_name, tool_call_count)
    try:
        result = await registry.execute(tool_name, arguments or {}, tool_ctx)
    except UnknownToolError as exc:
        return {"error": "tool_not_found", "detail": str(exc)}, None
    except ToolPermissionDenied as exc:
        return {"error": "permission_denied", "detail": str(exc)}, None
    except ToolCallBudgetExceeded as exc:
        return {"error": "tool_budget_exceeded", "detail": str(exc)}, None
    except Exception as exc:  # noqa: BLE001
        logger.warning("tool_execution_failed", tool=tool_name, error=str(exc))
        return {"error": "tool_execution_failed", "detail": str(exc)}, None
    evidence = evidence_from_tool_result(
        context,
        tool_name=tool_name,
        arguments=arguments,
        result=result,
        agent_name=agent_name,
        agent_version=agent_version,
        relevance=reason,
    )
    return result, evidence


def parse_json_response(text: str) -> dict[str, Any]:
    """Parse JSON from LLM text using the shared structured-output extractor."""
    from app.llm.structured_output import parse_structured

    result = parse_structured(text)
    if not result.ok:
        raise ValueError(result.error or "invalid JSON")
    if not isinstance(result.value, dict):
        raise ValueError("expected JSON object")
    return result.value
