"""Dry-run response agent (spec §19). Never executes containment itself."""

from __future__ import annotations

from .contracts import Agent, AgentAction, AgentContext, AgentResult, Finding, NextTask


class ResponseAgent(Agent):
    name = "response"
    version = "1.0"

    async def execute(self, context: AgentContext) -> AgentResult:
        planned = [action for action in context.previous_actions if action.tool.startswith("response.")]
        if not planned:
            planned = [
                AgentAction(name="plan_only", tool="response.noop", risk_level="read", output={"dry_run": True})
            ]
        blocked = any(action.risk_level in {"high", "critical"} for action in planned)
        if blocked and not context.metadata.get("approval_granted"):
            return AgentResult(
                status="blocked",
                findings=[Finding(statement="response_requires_approval", confidence=1.0)],
                actions=planned,
                next_tasks=[NextTask(agent="validation", objective="await_approval", priority=1)],
                confidence=1.0,
                reasoning="high/critical response cannot execute without approval",
                uncertainty=["live SOAR not invoked; dry-run default"],
            )
        simulated = [
            action.model_copy(update={"output": {"status": "simulated", "dry_run": True}})
            for action in planned
        ]
        return AgentResult(
            status="success",
            findings=[Finding(statement="response_simulated", confidence=1.0)],
            actions=simulated,
            next_tasks=[NextTask(agent="validation", objective="validate_containment", priority=1)],
            confidence=1.0,
            reasoning="response planned only; live execution stays in services/actions",
            uncertainty=["results are simulated unless actions service credentials are wired"],
        )
