"""ORM model for case_tkg_evaluations — TKG second-opinion runs on a case."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class CaseTkgEvaluation(Base):
    """One immutable second-opinion run against the Soorin TKG."""

    __tablename__ = "case_tkg_evaluations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("aisoc_cases.id", ondelete="CASCADE"), nullable=False
    )
    requested_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[str] = mapped_column(String(16), nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    engine_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    passes: Mapped[str | None] = mapped_column(String(16), nullable=True)
    agree: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    payload_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    attribution: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    reasons: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)

    kb_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    profile: Mapped[str | None] = mapped_column(String(64), nullable=True)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resolved_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_out: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(nullable=False, default=datetime.utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)

    __table_args__ = (
        Index("ix_case_tkg_evaluations_case", "case_id", "created_at"),
        Index("ix_case_tkg_evaluations_tenant", "tenant_id", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<CaseTkgEvaluation {self.id} case={self.case_id} "
            f"status={self.status!r} verdict={self.verdict!r}>"
        )
