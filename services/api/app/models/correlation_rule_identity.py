"""Correlation rule identity registry and resolution audit ORM models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class CorrelationRuleIdentityMap(Base):
    __tablename__ = "correlation_rule_identity_maps"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    rule_name: Mapped[str] = mapped_column(String(500), nullable=False)
    rule_name_pattern: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    host_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    user_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    ip_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    domain_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    hash_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    process_guid_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    excluded_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    field_kind_overrides: Mapped[dict[str, str]] = mapped_column(JSONB, nullable=False, default=dict)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="operator")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


class CorrelationRuleResolutionAudit(Base):
    __tablename__ = "correlation_rule_resolution_audits"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(500), nullable=False)
    map_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("correlation_rule_identity_maps.id", ondelete="SET NULL"),
        nullable=True,
    )
    matched_source: Mapped[str] = mapped_column(String(16), nullable=False)
    resolved_host_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    resolved_user_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    resolved_ip_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    missing_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    filtered_values: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    normalizer_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=lambda: datetime.now(UTC),
    )


__all__ = ["CorrelationRuleIdentityMap", "CorrelationRuleResolutionAudit"]
