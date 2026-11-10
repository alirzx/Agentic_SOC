"""
SQLAlchemy ORM model for playbook_approvals table.

Phase 3: Governance Hardening

Tracks analyst decisions on playbook steps that require governance approval.
When a playbook step needs L2/L3/L4 approval, a record is created here
and the run is parked (pending_approval status).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import UUID as SQLAlchemyUUID
from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import declarative_base

if TYPE_CHECKING:
    pass

Base = declarative_base()


class PlaybookApproval(Base):
    """Governance approval record for a playbook step.

    When a playbook step requires L2/L3/L4 approval, a row is created here
    and the run is parked in pending_approval status. The analyst reviews
    the step (action_slug, governance_level) and decides to approve or reject.

    Relationship:
        - playbook_run_id → playbook_runs(id)
        - alert_id → alerts(id)

    Tenant Isolation:
        - RLS policy: WHERE tenant_id = current_setting('app.current_tenant_id')
    """

    __tablename__ = "playbook_approvals"
    __table_args__ = (
        # Foreign keys are defined in the column specifications
    )

    # Primary key
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True)

    # Tenant isolation
    tenant_id = Column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Foreign keys
    playbook_run_id = Column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("playbook_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id = Column(
        SQLAlchemyUUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Step identification
    step_id = Column(String(255), nullable=False)
    step_name = Column(String(255), nullable=True)

    # Governance context
    action_slug = Column(String(255), nullable=False)
    governance_level = Column(String(16), nullable=False)  # L2, L3, L4

    # Analyst decision
    status = Column(
        String(32),
        nullable=False,
        default="pending_approval",
        index=True,
    )  # pending_approval, approved, rejected
    analyst_email = Column(String(255), nullable=True)
    decision_at = Column(DateTime(timezone=True), nullable=True)
    decision_reason = Column(Text, nullable=True)

    # Audit trail
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationships (optional, for lazy loading)
    # playbook_run = relationship("PlaybookRun", back_populates="approvals")
    # alert = relationship("Alert", back_populates="playbook_approvals")

    def __repr__(self) -> str:
        return (
            f"PlaybookApproval(id={self.id!r}, run={self.playbook_run_id!r}, "
            f"action={self.action_slug!r}, status={self.status!r})"
        )

    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization."""
        return {
            "id": str(self.id),
            "playbook_run_id": str(self.playbook_run_id),
            "alert_id": str(self.alert_id),
            "step_id": self.step_id,
            "step_name": self.step_name,
            "action_slug": self.action_slug,
            "governance_level": self.governance_level,
            "status": self.status,
            "analyst_email": self.analyst_email,
            "decision_at": self.decision_at.isoformat() if self.decision_at else None,
            "decision_reason": self.decision_reason,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
