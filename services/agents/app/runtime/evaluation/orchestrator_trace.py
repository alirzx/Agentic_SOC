"""Trace agent execution order during evaluation (Phase 8.5)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.runtime.contracts import AgentContext, AgentResult

if TYPE_CHECKING:
    from app.runtime.orchestrator import SocOrchestrator


async def run_with_trace(
    orchestrator: SocOrchestrator,
    context: AgentContext,
) -> tuple[list[AgentResult], list[str]]:
    """Run the orchestrator and record each agent name in execution order."""
    agent_order: list[str] = []
    original = orchestrator._run_agent

    async def traced(machine, ctx: AgentContext, agent_name: str) -> AgentResult:
        agent_order.append(agent_name)
        return await original(machine, ctx, agent_name)

    orchestrator._run_agent = traced
    try:
        results = await orchestrator.run(context)
    finally:
        orchestrator._run_agent = original
    return results, agent_order
