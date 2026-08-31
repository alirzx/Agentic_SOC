"""Structured models for LLM-backed runtime agents (Phase 8.6)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class HypothesisItem(BaseModel):
    id: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)


class InvestigationPlanStep(BaseModel):
    step: int = Field(ge=1)
    goal: str
    tool_candidates: list[str] = Field(default_factory=list)


class TriageResult(BaseModel):
    classification: str
    hypotheses: list[HypothesisItem] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    priority: str = "medium"
    investigation_plan: list[InvestigationPlanStep] = Field(default_factory=list)
    required_evidence: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)


class Claim(BaseModel):
    claim: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    rationale: str | None = None
    status: Literal["supported", "unsupported", "insufficient_evidence", "contradicted"] = "supported"


class RiskSignals(BaseModel):
    credential_access_confirmed: bool = False
    privileged_account: bool = False
    lateral_movement_suspected: bool = False
    c2_detected: bool = False
    data_exfiltration_suspected: bool = False


class InvestigationOutput(BaseModel):
    status: Literal["completed", "INSUFFICIENT_EVIDENCE", "FAILED"] = "completed"
    claims: list[Claim] = Field(default_factory=list)
    attack_chain: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    risk_signals: RiskSignals = Field(default_factory=RiskSignals)


class ToolRequest(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class LlmStepResponse(BaseModel):
    action: Literal["tool", "conclude", "ti_lookup"]
    tool: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    output: InvestigationOutput | None = None


class StructuredInvestigationState(BaseModel):
    """Audit-safe investigation state — no chain-of-thought."""

    incident_id: str
    hypotheses: list[HypothesisItem] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    investigation_plan: list[InvestigationPlanStep] = Field(default_factory=list)
    completed_steps: list[int] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    risk_signals: RiskSignals = Field(default_factory=RiskSignals)
    decision: str = ""
    uncertainties: list[str] = Field(default_factory=list)
    llm_calls: int = 0
    execution_mode: str = "LLM"
