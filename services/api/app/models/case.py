"""Case management ORM models."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)

    # Core
    case_number: Mapped[str] = mapped_column(String(30), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    priority: Mapped[str] = mapped_column(String(20), default="medium", index=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    case_type: Mapped[str] = mapped_column(String(50), default="security_incident")

    # MITRE
    mitre_tactics: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)

    # Assignment
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    # SLA
    sla_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_breached: Mapped[bool] = mapped_column(default=False)

    # Linked data
    alert_ids: Mapped[list] = mapped_column(JSONB, default=list)
    ioc_ids: Mapped[list] = mapped_column(JSONB, default=list)
    artifact_ids: Mapped[list] = mapped_column(JSONB, default=list)
    tags: Mapped[list] = mapped_column(JSONB, default=list)

    # External tickets
    ticket_refs: Mapped[list] = mapped_column(JSONB, default=list)

    # Rule roll-up for this case: rule_name → how many member alerts it fired on.
    # A map, not a list, because the API and console both need the counts (the
    # response model is ``dict[str, int]`` and the case header renders "N rules").
    rules: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Metadata
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[str | None] = mapped_column(Text, nullable=True)

    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    tasks: Mapped[list["CaseTask"]] = relationship("CaseTask", back_populates="case", lazy="noload")
    timeline: Mapped[list["CaseTimeline"]] = relationship("CaseTimeline", back_populates="case", lazy="noload")


class CaseTask(Base):
    __tablename__ = "case_tasks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    case: Mapped["Case"] = relationship("Case", back_populates="tasks")


class CaseTimeline(Base):
    __tablename__ = "case_timeline"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id"), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)  # comment/status_change/assignment/etc
    content: Mapped[str] = mapped_column(Text, nullable=False)
    event_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    is_automated: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)

    case: Mapped["Case"] = relationship("Case", back_populates="timeline")


class CaseCandidateDismissal(Base):
    """Record when analyst dismisses a candidate (snooze for 24h)."""

    __tablename__ = "case_candidate_dismissals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    candidate_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    dismissed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)


class CaseEvaluation(Base):
    """Record ground-truth evaluation of a case (correct/incorrect)."""

    __tablename__ = "case_evaluations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    evaluator_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    is_correct: Mapped[bool] = mapped_column(nullable=False, comment="TRUE=valid case, FALSE=false correlation")
    confidence_score: Mapped[int] = mapped_column(nullable=False, comment="0-100, evaluator confidence level")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class FalseAlertRecord(Base):
    """Track which specific alerts are irrelevant in a case."""

    __tablename__ = "false_alert_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id"), nullable=False, index=True)
    evaluator_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True, comment="Why alert does not belong in case")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class KPIMetrics(Base):
    """Store calculated KPI snapshots (daily/weekly/monthly)."""

    __tablename__ = "kpi_metrics"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    metric_date: Mapped[str] = mapped_column(String(10), nullable=False, comment="Date of metric calculation (YYYY-MM-DD)")
    metric_period: Mapped[str] = mapped_column(String(20), nullable=False, comment="daily/weekly/monthly")

    # KPI Values (0-1 scale)
    alert_reduction_rate: Mapped[float] = mapped_column(nullable=False, comment="0-1, target > 0.90")
    precision: Mapped[float] = mapped_column(nullable=False, comment="0-1, target > 0.75")
    cluster_purity: Mapped[float] = mapped_column(nullable=False, comment="0-1, target > 0.85")
    false_correlation_rate: Mapped[float] = mapped_column(nullable=False, comment="0-1, target < 0.05")

    # Calculation Details
    sample_size: Mapped[int] = mapped_column(nullable=False, comment="Number of evaluated cases")
    raw_alerts_count: Mapped[int] = mapped_column(nullable=False)
    created_cases_count: Mapped[int] = mapped_column(nullable=False)
    evaluated_cases_count: Mapped[int] = mapped_column(nullable=False)
    correct_cases_count: Mapped[int] = mapped_column(nullable=False)
    cases_with_false_alerts_count: Mapped[int] = mapped_column(nullable=False)

    # Timestamps
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
