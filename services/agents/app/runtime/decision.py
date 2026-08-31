"""Decision agent — interprets deterministic risk, never assigns it (spec §18)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .contracts import Agent, AgentAction, AgentContext, AgentResult, Finding, NextTask
from .policy import ApprovalPolicy, approval_tier, requires_human_approval
from .risk import RiskAssessment, RiskFactors, score_risk

DecisionLabel = Literal[
    "benign",
    "false_positive",
    "needs_review",
    "likely_compromise",
    "confirmed_compromise",
]


class DecisionPackage(BaseModel):
    decision: DecisionLabel
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_actions: list[str] = Field(default_factory=list)
    requires_human_approval: bool
    approval_tier: str
    risk: RiskAssessment
    uncertainty: list[str] = Field(default_factory=list)


def interpret_decision(risk: RiskAssessment, *, confidence: float) -> DecisionLabel:
    if risk.band == "EMERGENCY":
        return "confirmed_compromise"
    if risk.band == "CRITICAL":
        return "likely_compromise"
    if risk.band == "HIGH":
        return "likely_compromise" if confidence >= 0.6 else "needs_review"
    if risk.band == "MEDIUM":
        return "needs_review"
    if confidence < 0.4:
        return "false_positive"
    return "benign"


def recommend_actions(label: DecisionLabel, risk: RiskAssessment) -> list[str]:
    if label in {"likely_compromise", "confirmed_compromise"}:
        actions = ["block_ioc"]
        if risk.factors.asset_criticality >= 10:
            actions.append("isolate_asset")
        if risk.factors.user_privilege >= 8:
            actions.append("disable_account")
        return actions
    if label == "needs_review":
        return ["request_analyst_review"]
    return []


class DecisionAgent(Agent):
    name = "decision"
    version = "1.0"

    def __init__(self, policy: ApprovalPolicy | None = None) -> None:
        self._policy = policy or ApprovalPolicy()

    async def execute(self, context: AgentContext) -> AgentResult:
        raw = context.state.raw_alert
        factors = RiskFactors(
            alert_severity=str(context.state.severity or raw.get("severity") or "medium"),
            asset_criticality=int(raw.get("asset_criticality", 0) or 0),
            user_privilege=int(raw.get("user_privilege", 0) or 0),
            threat_intel=int(raw.get("threat_intel", 0) or 0),
            behavioral_anomaly=int(raw.get("behavioral_anomaly", 0) or 0),
            correlation=int(raw.get("correlation", 0) or 0),
            attack_chain=int(raw.get("attack_chain", 0) or 0),
        )
        risk = score_risk(factors)
        confidence = min(1.0, max(context.state.confidence, context.metadata.get("confidence", 0.0) or 0.0))
        label = interpret_decision(risk, confidence=confidence)
        actions = recommend_actions(label, risk)
        needs_approval = requires_human_approval(risk.score, self._policy)
        tier = approval_tier(risk.score, self._policy)
        uncertainty: list[str] = []
        if not context.evidence:
            uncertainty.append("no evidence attached to decision context")
        if factors.threat_intel == 0:
            uncertainty.append("no threat-intel contribution")
        next_tasks: list[NextTask] = []
        if needs_approval:
            next_tasks.append(NextTask(agent="response", objective="await_approval", priority=1))
        elif actions:
            next_tasks.append(NextTask(agent="response", objective="execute_plan", priority=1))
        else:
            next_tasks.append(NextTask(agent="report", objective="write_report", priority=1))
        result = AgentResult(
            status="success",
            findings=[
                Finding(
                    statement=f"decision={label} risk={risk.score}/{risk.band} tier={tier}",
                    confidence=confidence,
                    evidence_ids=[item.id for item in context.evidence],
                )
            ],
            evidence=list(context.evidence),
            actions=[
                AgentAction(name=name, tool=f"response.{name}", risk_level="high" if needs_approval else "medium")
                for name in actions
            ],
            next_tasks=next_tasks,
            confidence=confidence,
            reasoning="; ".join(risk.reasons),
            uncertainty=uncertainty,
        )
        return result
