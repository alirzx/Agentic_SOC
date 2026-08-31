"""Phase 8 evaluation contracts — deterministic scoring inputs/outputs."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.runtime.contracts import utcnow

GroundTruthSource = Literal[
    "human_verified",
    "existing_soc_verified",
    "incident_response_verified",
    "SYNTHETIC",
    "existing_soc_substrate",
]
EvaluationRunStatus = Literal["created", "running", "completed", "failed", "cancelled"]
SeverityBand = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "EMERGENCY"]
RiskBand = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "EMERGENCY"]


class GroundTruth(BaseModel):
    classification: str = ""
    severity: str = ""
    risk_band: RiskBand | str = "MEDIUM"
    risk_score: float | None = None
    compromised: bool = False
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    attack_stage: str = ""
    expected_correlation_group: list[str] = Field(default_factory=list)
    expected_actions: list[str] = Field(default_factory=list)
    source: GroundTruthSource = "SYNTHETIC"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    labels: dict[str, Any] = Field(default_factory=dict)


class SocResultSnapshot(BaseModel):
    """Normalized existing or agentic SOC output for comparison."""

    classification: str = ""
    severity: str = ""
    risk_score: float = 0.0
    risk_band: str = ""
    confidence: float = 0.0
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    correlation_groups: list[list[str]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    claims: list[dict[str, Any]] = Field(default_factory=list)
    investigation_stages: dict[str, bool] = Field(default_factory=dict)
    duration_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost: float = 0.0
    tool_call_count: int = 0
    pipeline_degraded: bool = False
    degraded_agents: list[str] = Field(default_factory=list)


class EvaluationDataset(BaseModel):
    dataset_id: str
    tenant_id: str = ""
    name: str
    description: str = ""
    source: str = "SYNTHETIC"
    version: str = "1.0"
    created_at: datetime = Field(default_factory=utcnow)
    cases: list[dict[str, Any]] = Field(default_factory=list)


class AgenticEvaluationRun(BaseModel):
    id: str
    dataset_id: str
    tenant_id: str
    agent_version: str = "runtime/v1.0"
    workflow_version: str = "agentic-eval-v1"
    prompt_version: str = "agentic-soc-runtime/v1"
    tool_version: str = "soc-tools/v1"
    model: str = "deterministic"
    dataset_version: str = "1.0"
    status: EvaluationRunStatus = "created"
    total_cases: int = 0
    completed_cases: int = 0
    failed_cases: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    total_duration_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost: float = 0.0
    aggregate_metrics: dict[str, Any] = Field(default_factory=dict)
    comparison_summary: dict[str, Any] = Field(default_factory=dict)
    quality_gates: dict[str, Any] = Field(default_factory=dict)
    production_readiness: dict[str, Any] = Field(default_factory=dict)
    pipeline_status: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class AgenticCaseEvaluation(BaseModel):
    evaluation_run_id: str
    case_id: str
    tenant_id: str = ""
    existing_result: SocResultSnapshot = Field(default_factory=SocResultSnapshot)
    agentic_result: SocResultSnapshot = Field(default_factory=SocResultSnapshot)
    ground_truth: GroundTruth = Field(default_factory=GroundTruth)
    classification_score: float = 0.0
    severity_score: float = 0.0
    risk_score_metric: float = 0.0
    mitre_score: float = 0.0
    ioc_score: float = 0.0
    correlation_score: float = 0.0
    evidence_score: float = 0.0
    investigation_score: float = 0.0
    hallucination_score: float = 0.0
    action_score: float = 0.0
    overall_score: float = 0.0
    analyst_review_required: bool = False
    metric_details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class AgenticEvaluationReport(BaseModel):
    evaluation_run_id: str
    dataset_id: str
    dataset_version: str
    agent_version: str
    workflow_version: str
    prompt_version: str
    executive_summary: str
    sections: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utcnow)
