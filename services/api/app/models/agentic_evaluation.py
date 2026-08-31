"""ORM for Phase 8 Agentic SOC evaluation."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, Numeric, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class AgenticEvaluationRun(Base):
    __tablename__ = "agentic_evaluation_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    dataset_id: Mapped[str] = mapped_column(String(120), nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(40), nullable=False, default="1.0")
    agent_version: Mapped[str] = mapped_column(String(80), nullable=False, default="runtime/v1.0")
    workflow_version: Mapped[str] = mapped_column(String(80), nullable=False, default="agentic-eval-v1")
    prompt_version: Mapped[str] = mapped_column(String(80), nullable=False, default="agentic-soc-runtime/v1")
    tool_version: Mapped[str] = mapped_column(String(80), nullable=False, default="soc-tools/v1")
    model: Mapped[str] = mapped_column(String(120), nullable=False, default="deterministic")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="created")
    total_cases: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed_cases: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_cases: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    total_duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    estimated_cost: Mapped[float] = mapped_column(Numeric(12, 6), nullable=False, default=0)
    aggregate_metrics: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    comparison_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    quality_gates: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    production_readiness: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    pipeline_status: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    report: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AgenticCaseEvaluation(Base):
    __tablename__ = "agentic_case_evaluations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evaluation_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(200), nullable=False)
    existing_result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    agentic_result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    ground_truth: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    classification_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    severity_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    risk_score_metric: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    mitre_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    ioc_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    correlation_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    evidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    investigation_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    hallucination_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    action_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    overall_score: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    analyst_review_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metric_details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
