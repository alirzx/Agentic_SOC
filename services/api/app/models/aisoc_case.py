"""AiSOC case management ORM model - maps to aisoc_cases table (Migration 012)."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, String, Text, ARRAY
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class AiSOCCase(Base):
    """ORM model for the canonical aisoc_cases table created by Migration 012.
    
    This table holds the case management state and is the source of truth for
    all case-related operations. All endpoints use this table (not the legacy
    ORM `cases` table from Migration 001).
    """

    __tablename__ = "aisoc_cases"

    # Primary identifiers
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )

    # Core metadata
    case_number: Mapped[str | None] = mapped_column(
        String(30), unique=True, nullable=True
    )  # Added Migration 028
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Status lifecycle
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="new",
        index=True,
        comment="new|triaged|investigating|contained|resolved|closed",
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="medium",
        index=True,
        comment="info|low|medium|high|critical",
    )
    assignee: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # ATT&CK coverage
    mitre_techniques: Mapped[list] = mapped_column(JSONB, default=list)

    # Case membership (alerts, IOCs, etc.)
    alert_ids: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    observable_graph: Mapped[dict] = mapped_column(JSONB, default=dict)
    evidence_chain: Mapped[list] = mapped_column(JSONB, default=list)
    compliance_frameworks: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)

    # Timeline
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    triaged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    created_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[dict] = mapped_column(JSONB, default=dict)
    sla_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Case creation origin (Migration 075)
    creation_method: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        comment="graph_correlation|agentic_funnel|manual|system",
    )
