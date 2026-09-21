"""Tenant and user management endpoints."""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.security import ASSIGNABLE_ROLES, get_password_hash, is_privileged_role
from app.models.tenant import Tenant, User

router = APIRouter(prefix="/tenants", tags=["tenants"])


class TenantHeaderResponse(BaseModel):
    """Minimal tenant identity payload — safe for *any* authenticated user.

    Used by the SOC console TopBar to render the tenant switcher and role
    badge (Workstream 5). Intentionally excludes `plan`, `settings`, and
    `limits` so it does not leak privileged config to viewer/analyst roles.
    """

    id: uuid.UUID
    name: str
    mssp_role: str | None
    parent_tenant_id: uuid.UUID | None

    model_config = {"from_attributes": True}


class TenantResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    plan: str
    is_active: bool
    settings: dict
    limits: dict
    mssp_role: str | None = None
    parent_tenant_id: uuid.UUID | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class UserResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    last_login: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    role: str = "soc_analyst"


class UpdateUserRequest(BaseModel):
    email: EmailStr | None = None
    username: str | None = Field(default=None, min_length=1, max_length=100)
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=128)


def _normalize_role(role: str) -> str:
    return (role or "").strip().lower()


def _assert_assignable_role(actor_role: str, target_role: str) -> str:
    role = _normalize_role(target_role)
    if role not in ASSIGNABLE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown role '{target_role}'",
        )
    if is_privileged_role(role) and not is_privileged_role(actor_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only a super admin can assign admin roles",
        )
    return role


def _assert_can_deactivate(actor_id: uuid.UUID, target_id: uuid.UUID, is_active: bool | None) -> None:
    if is_active is False and target_id == actor_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot disable your own account",
        )


class UpdateTenantSettingsRequest(BaseModel):
    settings: dict = {}


@router.get("/me/identity", response_model=TenantHeaderResponse)
async def get_my_tenant_identity(
    current_user: AuthUser,
    db: DBSession,
) -> TenantHeaderResponse:
    """Get minimal tenant identity for the current user.

    Returns only `id`, `name`, `mssp_role`, and `parent_tenant_id`. This is
    safe for **any** authenticated user (analyst, viewer, responder, etc.)
    because it does not expose plan, settings, or limits. Used by the SOC
    console TopBar to render the tenant switcher pill and role badge.
    """
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantHeaderResponse.model_validate(tenant)


@router.get("/me", response_model=TenantResponse)
async def get_my_tenant(
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
    db: DBSession,
) -> TenantResponse:
    """Get the current user's tenant details (full config — requires settings:read)."""
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantResponse.model_validate(tenant)


@router.patch("/me/settings", response_model=TenantResponse)
async def update_tenant_settings(
    request: UpdateTenantSettingsRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> TenantResponse:
    """Update tenant settings."""
    await db.execute(
        update(Tenant)
        .where(Tenant.id == current_user.tenant_id)
        .values(
            settings=request.settings,
            updated_at=datetime.now(UTC),
        )
    )
    await db.commit()

    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    return TenantResponse.model_validate(result.scalar_one())


@router.get("/me/users", response_model=list[UserResponse])
async def list_users(
    current_user: Annotated[AuthUser, Depends(require_permission("users:read"))],
    db: DBSession,
) -> list[UserResponse]:
    """List all users in the current tenant."""
    result = await db.execute(select(User).where(User.tenant_id == current_user.tenant_id).order_by(User.created_at))
    users = result.scalars().all()
    return [UserResponse.model_validate(u) for u in users]


@router.post("/me/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: CreateUserRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> UserResponse:
    """Create a new user in the current tenant."""
    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == request.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists",
        )

    role = _assert_assignable_role(current_user.role, request.role)
    user = User(
        tenant_id=current_user.tenant_id,
        email=request.email,
        username=request.username.strip(),
        hashed_password=get_password_hash(request.password),
        role=role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.patch("/me/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    request: UpdateUserRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> UserResponse:
    """Update a user."""
    result = await db.execute(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    _assert_can_deactivate(current_user.user_id, user.id, request.is_active)

    updates: dict = {}
    if request.email is not None:
        email = str(request.email).strip().lower()
        clash = await db.execute(select(User).where(User.email == email, User.id != user_id))
        if clash.scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists",
            )
        updates["email"] = email
    if request.username is not None:
        updates["username"] = request.username.strip()
    if request.role is not None:
        updates["role"] = _assert_assignable_role(current_user.role, request.role)
    if request.is_active is not None:
        updates["is_active"] = request.is_active
    if request.password is not None:
        updates["hashed_password"] = get_password_hash(request.password)

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        await db.execute(update(User).where(User.id == user_id).values(**updates))
        await db.commit()
        await db.refresh(user)

    return UserResponse.model_validate(user)
