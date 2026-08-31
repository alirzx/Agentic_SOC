"""Agentic SOC runtime contracts layered on the existing Python stack.

This package implements Soorin spec §§8–28, 31–34, 17–22 as Pydantic
contracts. It does not replace LangGraph, the four-agent façade, fusion,
or connectors.
"""

from .catalog import build_agent_registry, build_tool_registry
from .contracts import Agent, AgentContext, AgentResult, Evidence, Finding
from .incident import IncidentState, IncidentStateMachine
from .orchestrator import SocOrchestrator
from .registry import AgentRegistry
from .risk import score_risk
from .runtime import AgentRuntime

__all__ = [
    "Agent",
    "AgentContext",
    "AgentRegistry",
    "AgentResult",
    "AgentRuntime",
    "Evidence",
    "Finding",
    "IncidentState",
    "IncidentStateMachine",
    "SocOrchestrator",
    "build_agent_registry",
    "build_tool_registry",
    "score_risk",
]
