"""Incident report package (spec §22 / §51). Uncertainties are required."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .contracts import Agent, AgentContext, AgentResult, Evidence, Finding, NextTask
from .risk import RiskAssessment


class TimelineEvent(BaseModel):
    timestamp: str
    event: str
    source: str = ""


class IncidentReportPackage(BaseModel):
    incident_id: str
    title: str
    executive_summary: str
    classification: str = ""
    severity: str = ""
    risk: RiskAssessment | None = None
    timeline: list[TimelineEvent] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    attack_story: dict[str, Any] = Field(default_factory=dict)
    attack_graph: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    response_actions: list[str] = Field(default_factory=list)
    analyst_decisions: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    uncertainties: list[str]
    root_cause: str = ""
    validation: str = ""


class ReportAgent(Agent):
    name = "report"
    version = "1.0"

    async def execute(self, context: AgentContext) -> AgentResult:
        uncertainties = list(getattr(context, "uncertainty", []) or [])
        if not context.evidence:
            uncertainties.append("evidence coverage unknown")
        if context.state.risk_score == 0:
            uncertainties.append("risk not scored in this run")
        if not uncertainties:
            uncertainties = ["no residual uncertainties recorded"]
        package = IncidentReportPackage(
            incident_id=context.incident_id,
            title=context.objective or context.incident_id,
            executive_summary=context.objective,
            severity=context.state.severity or "",
            evidence=list(context.evidence),
            uncertainties=uncertainties,
            attack_story=dict(context.state.summary),
        )
        return AgentResult(
            status="success",
            findings=[
                Finding(
                    statement="report_package_ready",
                    evidence_ids=[item.id for item in context.evidence],
                )
            ],
            evidence=list(context.evidence),
            next_tasks=[NextTask(agent="runtime", objective="close", priority=0)],
            confidence=0.5,
            reasoning=package.executive_summary,
            uncertainty=package.uncertainties,
        )
