"""Workspace (= tenant) list/create for the authenticated user."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession
from app.models.tenant import Tenant, WorkspaceMembership
from app.services.workspaces import (
    list_memberships_with_tenants,
    slugify_workspace_name,
)

router = APIRouter(prefix="/workspaces", tags=["workspaces"])


class WorkspaceOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    membership_role: str
    is_home: bool
    is_active: bool


class WorkspaceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class WorkspaceMeOut(BaseModel):
    id: uuid.UUID | None
    name: str | None = None
    slug: str | None = None
    workspace_selected: bool
    home_tenant_id: uuid.UUID


@router.get("", response_model=list[WorkspaceOut])
async def list_workspaces(current_user: AuthUser, db: DBSession) -> list[WorkspaceOut]:
    rows = await list_memberships_with_tenants(db, user_id=current_user.user_id)
    return [
        WorkspaceOut(
            id=tenant.id,
            name=tenant.name,
            slug=tenant.slug,
            membership_role=membership.role,
            is_home=tenant.id == current_user.home_tenant_id,
            is_active=bool(tenant.is_active),
        )
        for membership, tenant in rows
    ]


@router.get("/me", response_model=WorkspaceMeOut)
async def workspace_me(current_user: AuthUser, db: DBSession) -> WorkspaceMeOut:
    if not current_user.workspace_selected:
        return WorkspaceMeOut(
            id=None,
            workspace_selected=False,
            home_tenant_id=current_user.home_tenant_id,
        )
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        return WorkspaceMeOut(
            id=None,
            workspace_selected=False,
            home_tenant_id=current_user.home_tenant_id,
        )
    return WorkspaceMeOut(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        workspace_selected=True,
        home_tenant_id=current_user.home_tenant_id,
    )


@router.post("", response_model=WorkspaceOut, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    body: WorkspaceCreate,
    current_user: AuthUser,
    db: DBSession,
) -> WorkspaceOut:
    name = body.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Name too short")

    slug = slugify_workspace_name(name)
    # Extremely unlikely collision; retry once.
    existing = await db.execute(select(Tenant.id).where(Tenant.slug == slug))
    if existing.scalar_one_or_none() is not None:
        slug = slugify_workspace_name(name)

    now = datetime.now(UTC)
    tenant = Tenant(
        id=uuid.uuid4(),
        name=name,
        slug=slug,
        plan="starter",
        is_active=True,
        settings={},
        limits={},
        mssp_role="standalone",
        created_at=now,
        updated_at=now,
    )
    membership = WorkspaceMembership(
        id=uuid.uuid4(),
        user_id=current_user.user_id,
        tenant_id=tenant.id,
        role="owner",
        created_at=now,
        updated_at=now,
    )
    db.add(tenant)
    db.add(membership)
    await db.commit()
    await db.refresh(tenant)

    return WorkspaceOut(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        membership_role="owner",
        is_home=False,
        is_active=True,
    )
