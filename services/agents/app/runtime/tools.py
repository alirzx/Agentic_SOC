"""SOC tool contracts + permission engine (spec §24–27).

Wraps, does not replace, ``app.tools.registry.ToolRegistry`` used by the LLM tool loop.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

from .contracts import ToolRiskLevel

DESTRUCTIVE_TOOL_NAMES = frozenset(
    {
        "response.block_ip",
        "response.isolate_asset",
        "response.disable_user",
        "response.kill_process",
        "response.create_firewall_rule",
        "block_ip",
        "isolate_asset",
        "disable_user",
        "kill_process",
        "firewall_change",
    }
)
DESTRUCTIVE_TOKENS = ("block_ip", "isolate_asset", "disable_user", "kill_process", "firewall")

TInput = TypeVar("TInput")
TOutput = TypeVar("TOutput")


class ToolContext(BaseModel):
    tenant_id: str
    incident_id: str
    agent_name: str
    role: str = "analyst"
    approval_granted: bool = False
    shadow_mode: bool = False
    tool_call_count: int = 0
    max_tool_calls: int = 16
    result_limit: int = Field(default=50, ge=1, le=500)
    metadata: dict[str, Any] = Field(default_factory=dict)


def is_destructive_tool(name: str, risk_level: ToolRiskLevel) -> bool:
    lowered = name.lower()
    if name in DESTRUCTIVE_TOOL_NAMES or lowered in DESTRUCTIVE_TOOL_NAMES:
        return True
    if any(token in lowered for token in DESTRUCTIVE_TOKENS):
        return True
    return risk_level in {"high", "critical"} and lowered.startswith("response.")


class ToolPermissionDenied(PermissionError):
    pass


class UnknownToolError(KeyError):
    pass


class ToolCallBudgetExceeded(RuntimeError):
    pass


class SOCTool(ABC, Generic[TInput, TOutput]):
    name: str
    description: str
    risk_level: ToolRiskLevel
    requires_approval: bool
    allowed_agents: frozenset[str]
    allowed_roles: frozenset[str]
    input_schema: dict[str, Any]

    @abstractmethod
    async def execute(self, input: TInput, context: ToolContext) -> TOutput:
        raise NotImplementedError


class CallableSOCTool(SOCTool[dict[str, Any], Any]):
    """Adapter around an existing async callable (enrich_ioc, map_to_mitre, …)."""

    def __init__(
        self,
        *,
        name: str,
        description: str,
        fn: Any,
        risk_level: ToolRiskLevel = "read",
        requires_approval: bool = False,
        allowed_agents: frozenset[str] | None = None,
        allowed_roles: frozenset[str] | None = None,
        input_schema: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self._fn = fn
        self.risk_level = risk_level
        self.requires_approval = requires_approval
        self.allowed_agents = allowed_agents or frozenset()
        self.allowed_roles = allowed_roles or frozenset({"analyst", "admin", "system"})
        self.input_schema = input_schema or {"type": "object"}

    async def execute(self, input: dict[str, Any], context: ToolContext) -> Any:
        result = self._fn(**(input or {}))
        if hasattr(result, "__await__"):
            return await result
        return result


class ToolPermissionEngine:
    def authorize(self, tool: SOCTool[Any, Any], context: ToolContext) -> None:
        if context.tool_call_count >= context.max_tool_calls:
            raise ToolCallBudgetExceeded(
                f"tool call budget {context.max_tool_calls} exhausted"
            )
        if tool.allowed_agents and context.agent_name not in tool.allowed_agents:
            raise ToolPermissionDenied(
                f"agent {context.agent_name} cannot use {tool.name}"
            )
        if tool.allowed_roles and context.role not in tool.allowed_roles:
            raise ToolPermissionDenied(
                f"role {context.role} cannot use {tool.name}"
            )
        if tool.requires_approval and not context.approval_granted:
            raise ToolPermissionDenied(
                f"{tool.name} requires human approval"
            )
        if tool.risk_level in {"high", "critical"} and not context.approval_granted:
            raise ToolPermissionDenied(
                f"{tool.name} risk {tool.risk_level} requires approval"
            )


class SocToolRegistry:
    def __init__(self, permission: ToolPermissionEngine | None = None) -> None:
        self._tools: dict[str, SOCTool[Any, Any]] = {}
        self._permission = permission or ToolPermissionEngine()

    def register(self, tool: SOCTool[Any, Any]) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> SOCTool[Any, Any]:
        tool = self._tools.get(name)
        if tool is None:
            raise UnknownToolError(f"Unknown tool: {name}")
        return tool

    def names(self) -> list[str]:
        return sorted(self._tools)

    async def execute(
        self,
        name: str,
        input: dict[str, Any],
        context: ToolContext,
    ) -> Any:
        from .flags import enabled, shadow_mode

        tool = self.get(name)
        shadow = bool(
            context.shadow_mode
            or context.metadata.get("shadow_mode")
            or (enabled() and shadow_mode())
        )
        if shadow and is_destructive_tool(name, tool.risk_level):
            return {
                "simulated": True,
                "dry_run": True,
                "action": name,
                "target": input.get("target") or input.get("ip") or input.get("asset_id") or input,
                "reason": "shadow_mode",
            }
        self._permission.authorize(tool, context)
        return await tool.execute(input, context)
