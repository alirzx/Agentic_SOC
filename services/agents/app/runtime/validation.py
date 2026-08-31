"""Validation agent — post-response effectiveness checks (spec §21). No LLM."""

from __future__ import annotations

from .contracts import Agent, AgentContext, AgentResult, Finding, NextTask


class ValidationAgent(Agent):
    name = "validation"
    version = "1.0"

    async def execute(self, context: AgentContext) -> AgentResult:
        raw = context.state.raw_alert
        ioc_still_seen = bool(raw.get("ioc_still_seen"))
        auth_continues = bool(raw.get("auth_continues"))
        new_alerts = bool(raw.get("new_alerts"))
        containment_effective = bool(raw.get("containment_effective", not (ioc_still_seen or auth_continues or new_alerts)))
        success = containment_effective and not ioc_still_seen and not auth_continues and not new_alerts
        uncertainty: list[str] = []
        if "containment_effective" not in raw and not context.evidence:
            uncertainty.append("no post-response telemetry provided")
        if ioc_still_seen:
            uncertainty.append("IOC still observed after response")
        if auth_continues:
            uncertainty.append("authentication activity continues")
        if new_alerts:
            uncertainty.append("new related alerts after response")
        next_agent = "report" if success else "investigation"
        return AgentResult(
            status="success" if success else "blocked",
            findings=[
                Finding(
                    statement="containment_effective" if success else "containment_failed",
                    evidence_ids=[item.id for item in context.evidence],
                    confidence=0.8 if success else 0.4,
                )
            ],
            evidence=list(context.evidence),
            next_tasks=[NextTask(agent=next_agent, objective="post_validation", priority=1)],
            confidence=0.8 if success else 0.4,
            reasoning="deterministic validation over post-response signals",
            uncertainty=uncertainty,
        )
