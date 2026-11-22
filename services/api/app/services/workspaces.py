"""Workspace (= tenant) membership helpers."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant import Tenant, WorkspaceMembership

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify_workspace_name(name: str) -> str:
    base = _SLUG_RE.sub("-", (name or "").strip().lower()).strip("-") or "workspace"
    base = base[:72]
    suffix = uuid.uuid4().hex[:8]
    return f"{base}-{suffix}"


async def user_has_membership(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> bool:
    result = await db.execute(
        select(WorkspaceMembership.id).where(
            WorkspaceMembership.user_id == user_id,
            WorkspaceMembership.tenant_id == tenant_id,
        )
    )
    return result.scalar_one_or_none() is not None


async def ensure_home_membership(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    home_tenant_id: uuid.UUID,
    role: str = "owner",
) -> None:
    """Idempotently ensure the user has a membership on their home tenant."""
    if await user_has_membership(db, user_id=user_id, tenant_id=home_tenant_id):
        return
    db.add(
        WorkspaceMembership(
            id=uuid.uuid4(),
            user_id=user_id,
            tenant_id=home_tenant_id,
            role=role,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
    )
    await db.flush()


async def list_memberships_with_tenants(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
) -> list[tuple[WorkspaceMembership, Tenant]]:
    result = await db.execute(
        select(WorkspaceMembership, Tenant)
        .join(Tenant, Tenant.id == WorkspaceMembership.tenant_id)
        .where(
            WorkspaceMembership.user_id == user_id,
            Tenant.is_active.is_(True),
        )
        .order_by(Tenant.name.asc())
    )
    return list(result.all())
