"""ORM model for case_graph_views — correlation graph view state snapshots."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class CaseGraphView(Base):
    """Named snapshot of a correlation graph's view state (camera, focus, hidden nodes, etc.)."""

    __tablename__ = "case_graph_views"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=lambda: __import__("uuid").uuid4())
    case_id: Mapped[UUID] = mapped_column(ForeignKey("aisoc_cases.id", ondelete="CASCADE"), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(nullable=False)
    view_state: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("case_id", "user_id", "name", name="case_graph_views_name_unique"),
        Index("ix_case_graph_views_case", "case_id"),
        Index("ix_case_graph_views_user", "user_id"),
        Index("ix_case_graph_views_tenant", "tenant_id"),
    )

    def __repr__(self) -> str:
        return f"<CaseGraphView {self.id} case={self.case_id} user={self.user_id} name={self.name!r}>"
