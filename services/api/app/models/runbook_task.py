"""SQLAlchemy model for runbook_tasks table."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class RunbookTaskStatus(str, Enum):
    """Status values for RunbookTask."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class RunbookTask(Base):
    """Manual task created when auto-triage needs human intervention.

    Task types:
      - manual_review: LLM confidence too low, needs human verification
      - approval_gate: Awaiting approval for L2/L3 actions (isolate, disable user, etc)
      - mssp_sla_check: Customer SLA obligation (e.g., call contact, open Jira ticket)
    """
    __tablename__ = "runbook_tasks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    # Type of task
    task_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False)  # 'manual_review', 'approval_gate', 'mssp_sla_check'

    # Task metadata
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # Assignment
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    # Status tracking
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True, default="pending")  # pending, in_progress, completed
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    # Analyst findings and feedback
    resolution: Mapped[str | None] = mapped_column(Text)  # What did the analyst find/decide?
    feedback_to_llm: Mapped[str | None] = mapped_column(String(20))  # 'good', 'poor', or None

    # Evidence fingerprint this task was raised for. Analyst feedback updates the
    # outcome prior under this key, so the loop closes on the alert family the
    # machine actually misjudged — not just on one alert id.
    signature: Mapped[str | None] = mapped_column(String(200))

    # What the feedback actually did. TRUE = the agents service confirmed a prior
    # was updated, FALSE = feedback sent but no prior changed, NULL = no feedback
    # submitted (or the row predates migration 066). This is what makes the loop
    # measurable instead of assumed.
    feedback_applied: Mapped[bool | None] = mapped_column(Boolean)

    # Confidence captured at the moment the task was raised. This keeps the
    # calibration monitor independent of the live alert state and supports the
    # historical runbook calibration queries used in tests and dashboards.
    confidence_at_submission: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)

    # Playbook gate tasks only: the durable run this task releases
    # (``playbook_runs.id``). NULL for every other task type.
    playbook_run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    # Did approving this task actually continue the run? TRUE = the agents
    # service confirmed it moved past the gate, FALSE = decision recorded but
    # the run did not move, NULL = not a gate task / no resume attempted.
    resume_applied: Mapped[bool | None] = mapped_column(Boolean)

    # Audit
    created_by: Mapped[str] = mapped_column(String(50), nullable=False, default="system", server_default="system")  # 'system' or user_id
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    def __repr__(self) -> str:
        return f"<RunbookTask(id={self.id}, type={self.task_type}, status={self.status})>"
