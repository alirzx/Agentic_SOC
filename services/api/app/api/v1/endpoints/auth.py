"""Authentication endpoints: login, refresh, logout, workspace select, preferences."""

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, update

from app.api.v1.deps import AuthUser, DBSession, get_current_user

__all__ = ["router", "get_current_user"]
from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    session_is_expired,
    verify_password,
)
from app.models.tenant import User
from app.services.workspaces import ensure_home_membership, user_has_membership

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    workspace_selected: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str


class SelectWorkspaceRequest(BaseModel):
    tenant_id: uuid.UUID


class UserMeResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    home_tenant_id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    preferences: dict[str, Any] = {}
    workspace_selected: bool = False

    model_config = {"from_attributes": True}


class PreferencesPatch(BaseModel):
    """Partial update payload for user preferences (merged server-side)."""

    preferences: dict[str, Any]


def _login_identifier(value: str) -> str:
    return (value or "").strip().lower()


def _token_payload(
    user: User,
    *,
    active_tenant_id: uuid.UUID,
    workspace_selected: bool,
) -> dict[str, Any]:
    return {
        "sub": str(user.id),
        "tenant_id": str(active_tenant_id),
        "home_tenant_id": str(user.tenant_id),
        "role": user.role,
        "email": user.email,
        "workspace_selected": workspace_selected,
    }


async def _user_for_login(db: DBSession, identifier: str) -> User | None:
    """Match email or username, ignoring case."""
    ident = _login_identifier(identifier)
    if not ident:
        return None
    result = await db.execute(
        select(User).where(
            or_(
                func.lower(User.email) == ident,
                func.lower(User.username) == ident,
            )
        )
    )
    return result.scalars().first()


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: DBSession) -> TokenResponse:
    """Authenticate with email or username + password, return JWT tokens.

    Tokens are issued with ``workspace_selected=false`` so the console must
    call ``POST /auth/select-workspace`` before data routes are fully bound.
    """
    user = await _user_for_login(db, request.email)
    password = (request.password or "").strip()
    if user is None or user.is_active is not True or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await ensure_home_membership(db, user_id=user.id, home_tenant_id=user.tenant_id)
    await db.execute(update(User).where(User.id == user.id).values(last_login=datetime.now(UTC)))
    await db.commit()
    await db.refresh(user)

    token_data = _token_payload(user, active_tenant_id=user.tenant_id, workspace_selected=False)
    auth_time = int(datetime.now(UTC).timestamp())
    access_token = create_access_token(token_data, auth_time=auth_time)
    refresh_token = create_refresh_token(token_data, auth_time=auth_time)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        workspace_selected=False,
    )


@router.post("/select-workspace", response_model=TokenResponse)
async def select_workspace(
    body: SelectWorkspaceRequest,
    current_user: AuthUser,
    db: DBSession,
) -> TokenResponse:
    """Re-issue JWTs bound to a workspace the user belongs to."""
    result = await db.execute(
        select(User).where(User.id == current_user.user_id, User.is_active.is_(True))
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    await ensure_home_membership(db, user_id=user.id, home_tenant_id=user.tenant_id)
    if not await user_has_membership(db, user_id=user.id, tenant_id=body.tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this workspace",
        )
    await db.commit()

    token_data = _token_payload(user, active_tenant_id=body.tenant_id, workspace_selected=True)
    auth_time = int(datetime.now(UTC).timestamp())
    return TokenResponse(
        access_token=create_access_token(token_data, auth_time=auth_time),
        refresh_token=create_refresh_token(token_data, auth_time=auth_time),
        workspace_selected=True,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest, db: DBSession) -> TokenResponse:
    """Refresh access token using a valid refresh token."""
    try:
        payload = decode_token(request.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        if session_is_expired(payload):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired. Sign in again.",
            )
        user_id = payload.get("sub")
        auth_time = payload.get("auth_time")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from e

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id), User.is_active.is_(True)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    await ensure_home_membership(db, user_id=user.id, home_tenant_id=user.tenant_id)

    workspace_selected = bool(payload.get("workspace_selected"))
    active_tenant = user.tenant_id
    claim_tenant = payload.get("tenant_id")
    if workspace_selected and claim_tenant:
        try:
            claimed = uuid.UUID(str(claim_tenant))
        except (TypeError, ValueError):
            claimed = None
        if claimed is not None and await user_has_membership(
            db, user_id=user.id, tenant_id=claimed
        ):
            active_tenant = claimed
        else:
            workspace_selected = False
            active_tenant = user.tenant_id
    await db.commit()

    token_data = _token_payload(
        user, active_tenant_id=active_tenant, workspace_selected=workspace_selected
    )
    bound_auth_time = int(auth_time) if isinstance(auth_time, (int, float)) else None
    return TokenResponse(
        access_token=create_access_token(token_data, auth_time=bound_auth_time),
        refresh_token=create_refresh_token(token_data, auth_time=bound_auth_time),
        workspace_selected=workspace_selected,
    )


@router.get("/me", response_model=UserMeResponse)
async def get_me(current_user: AuthUser, db: DBSession) -> UserMeResponse:
    """Get current authenticated user info (active workspace in tenant_id)."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserMeResponse(
        id=user.id,
        tenant_id=current_user.tenant_id,
        home_tenant_id=current_user.home_tenant_id,
        email=user.email,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
        preferences=user.preferences or {},
        workspace_selected=current_user.workspace_selected,
    )


@router.patch("/me/preferences", response_model=UserMeResponse)
async def patch_me_preferences(
    body: PreferencesPatch,
    current_user: AuthUser,
    db: DBSession,
) -> UserMeResponse:
    """Merge user preferences (e.g. theme) into the stored JSONB column.

    Only the keys supplied in the request body are updated; all other
    existing keys are preserved.  This lets the frontend evolve independent
    preference namespaces without overwriting each other.
    """
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    merged = {**(user.preferences or {}), **body.preferences}
    await db.execute(update(User).where(User.id == current_user.user_id).values(preferences=merged))
    await db.commit()

    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    assert user is not None
    return UserMeResponse(
        id=user.id,
        tenant_id=current_user.tenant_id,
        home_tenant_id=current_user.home_tenant_id,
        email=user.email,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
        preferences=user.preferences or {},
        workspace_selected=current_user.workspace_selected,
    )
