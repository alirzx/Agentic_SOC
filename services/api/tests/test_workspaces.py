"""Workspace membership + JWT rebinding + cross-workspace isolation."""

from __future__ import annotations

import re
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.api.v1 import deps as deps_module
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import auth as auth_module
from app.api.v1.endpoints import workspaces as workspaces_module
from app.api.v1.endpoints.connectors import get_connector, list_connectors
from app.core.security import create_access_token, decode_token
from app.services.workspaces import slugify_workspace_name
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials


def test_slugify_workspace_name_is_stable_and_unique_suffix() -> None:
    a = slugify_workspace_name("  My Production SOC!!! ")
    b = slugify_workspace_name("  My Production SOC!!! ")
    assert a.startswith("my-production-soc-")
    assert b.startswith("my-production-soc-")
    assert a != b


def test_access_token_carries_workspace_selected_claim() -> None:
    tenant = uuid.uuid4()
    token = create_access_token(
        {
            "sub": str(uuid.uuid4()),
            "tenant_id": str(tenant),
            "workspace_selected": True,
        }
    )
    payload = decode_token(token)
    assert payload["workspace_selected"] is True
    assert payload["tenant_id"] == str(tenant)


def test_current_user_tracks_home_and_selection() -> None:
    home = uuid.uuid4()
    active = uuid.uuid4()
    user = CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=active,
        role="admin",
        email="a@example.com",
        home_tenant_id=home,
        workspace_selected=True,
    )
    assert user.home_tenant_id == home
    assert user.tenant_id == active
    assert user.workspace_selected is True


@pytest.mark.asyncio
async def test_select_workspace_rejects_non_member() -> None:
    user_id = uuid.uuid4()
    home = uuid.uuid4()
    foreign = uuid.uuid4()
    current = CurrentUser(
        user_id=user_id,
        tenant_id=home,
        role="admin",
        email="a@example.com",
        home_tenant_id=home,
        workspace_selected=False,
    )
    db_user = MagicMock()
    db_user.id = user_id
    db_user.tenant_id = home
    db_user.role = "admin"
    db_user.email = "a@example.com"
    db_user.is_active = True

    result = MagicMock()
    result.scalar_one_or_none.return_value = db_user
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()

    with (
        patch.object(auth_module, "ensure_home_membership", new=AsyncMock()),
        patch.object(auth_module, "user_has_membership", new=AsyncMock(return_value=False)),
    ):
        with pytest.raises(HTTPException) as exc:
            await auth_module.select_workspace(
                auth_module.SelectWorkspaceRequest(tenant_id=foreign),
                current,
                db,
            )
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_select_workspace_issues_bound_token() -> None:
    user_id = uuid.uuid4()
    home = uuid.uuid4()
    ws = uuid.uuid4()
    current = CurrentUser(
        user_id=user_id,
        tenant_id=home,
        role="admin",
        email="a@example.com",
        home_tenant_id=home,
        workspace_selected=False,
    )
    db_user = MagicMock()
    db_user.id = user_id
    db_user.tenant_id = home
    db_user.role = "admin"
    db_user.email = "a@example.com"
    db_user.is_active = True

    result = MagicMock()
    result.scalar_one_or_none.return_value = db_user
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()

    with (
        patch.object(auth_module, "ensure_home_membership", new=AsyncMock()),
        patch.object(auth_module, "user_has_membership", new=AsyncMock(return_value=True)),
    ):
        tokens = await auth_module.select_workspace(
            auth_module.SelectWorkspaceRequest(tenant_id=ws),
            current,
            db,
        )
    assert tokens.workspace_selected is True
    payload = decode_token(tokens.access_token)
    assert payload["workspace_selected"] is True
    assert payload["tenant_id"] == str(ws)


@pytest.mark.asyncio
async def test_create_workspace_adds_owner_membership() -> None:
    user_id = uuid.uuid4()
    home = uuid.uuid4()
    current = CurrentUser(
        user_id=user_id,
        tenant_id=home,
        role="admin",
        email="a@example.com",
        home_tenant_id=home,
        workspace_selected=True,
    )

    empty = MagicMock()
    empty.scalar_one_or_none.return_value = None
    db = AsyncMock()
    db.execute = AsyncMock(return_value=empty)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    out = await workspaces_module.create_workspace(
        workspaces_module.WorkspaceCreate(name="Eng SOC"),
        current,
        db,
    )
    assert out.name == "Eng SOC"
    assert out.membership_role == "owner"
    assert out.is_home is False
    assert db.add.call_count == 2
    db.commit.assert_awaited()


def _capture_db() -> MagicMock:
    """AsyncSession mock that records compiled SQL + bind params."""
    db = MagicMock()
    db.executed: list[tuple[str, dict[str, Any]]] = []

    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        sql = str(clause)
        try:
            params = dict(clause.compile().params) if hasattr(clause, "compile") else {}
        except Exception:
            params = {}
        db.executed.append((sql, params))
        result = MagicMock()
        scalars = MagicMock()
        scalars.all = MagicMock(return_value=[])
        result.scalars = MagicMock(return_value=scalars)
        result.scalar_one_or_none = MagicMock(return_value=None)
        return result

    db.execute = AsyncMock(side_effect=_execute)
    return db


def _assert_bound_tenant(executed: list[tuple[str, dict[str, Any]]], tenant_id: uuid.UUID) -> None:
    assert executed, "expected at least one DB call"
    matched = False
    for sql, params in executed:
        normalized = re.sub(r"\s+", " ", sql).lower()
        if "tenant_id" not in normalized:
            continue
        for name, value in params.items():
            if (name == "tenant_id" or name.startswith("tenant_id_")) and value == tenant_id:
                matched = True
    assert matched, f"no statement bound caller's tenant_id={tenant_id}; executed={executed}"


@pytest.mark.asyncio
async def test_list_connectors_scopes_to_active_workspace() -> None:
    """WS1 session must not query connectors for WS2."""
    ws1 = uuid.uuid4()
    user = CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=ws1,
        role="admin",
        email="a@example.com",
        home_tenant_id=ws1,
        workspace_selected=True,
    )
    db = _capture_db()
    out = await list_connectors(current_user=user, db=db)
    assert out == []
    _assert_bound_tenant(db.executed, ws1)
    for sql, params in db.executed:
        for name, value in params.items():
            if name == "tenant_id" or name.startswith("tenant_id_"):
                assert value == ws1


@pytest.mark.asyncio
async def test_get_connector_cross_workspace_returns_404() -> None:
    ws1 = uuid.uuid4()
    user = CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=ws1,
        role="admin",
        email="a@example.com",
        home_tenant_id=ws1,
        workspace_selected=True,
    )
    db = _capture_db()
    with pytest.raises(HTTPException) as exc:
        await get_connector(connector_id=uuid.uuid4(), current_user=user, db=db)
    assert exc.value.status_code == 404
    _assert_bound_tenant(db.executed, ws1)


@pytest.mark.asyncio
async def test_get_current_user_falls_back_without_membership() -> None:
    """JWT claiming a foreign tenant without membership must not rebind."""
    user_id = uuid.uuid4()
    home = uuid.uuid4()
    foreign = uuid.uuid4()
    db_user = MagicMock()
    db_user.id = user_id
    db_user.tenant_id = home
    db_user.role = "admin"
    db_user.email = "a@example.com"

    result = MagicMock()
    result.scalar_one_or_none.return_value = db_user
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)

    token = create_access_token(
        {
            "sub": str(user_id),
            "tenant_id": str(foreign),
            "workspace_selected": True,
            "role": "admin",
            "email": "a@example.com",
        }
    )
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with patch.object(deps_module, "user_has_membership", new=AsyncMock(return_value=False)):
        current = await deps_module.get_current_user(credentials=creds, db=db)

    assert current.tenant_id == home
    assert current.workspace_selected is False
    assert current.home_tenant_id == home


@pytest.mark.asyncio
async def test_list_alerts_scopes_to_active_workspace_not_home() -> None:
    """After select-workspace, alert queries bind active tenant_id, not home."""
    from app.api.v1.endpoints.alerts import list_alerts

    home = uuid.uuid4()
    ws2 = uuid.uuid4()
    user = CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=ws2,
        role="admin",
        email="a@example.com",
        home_tenant_id=home,
        workspace_selected=True,
    )
    db = _capture_db()
    # list_alerts does count then select; mock scalar_one for count.
    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        sql = str(clause)
        try:
            params = dict(clause.compile().params) if hasattr(clause, "compile") else {}
        except Exception:
            params = {}
        db.executed.append((sql, params))
        result = MagicMock()
        scalars = MagicMock()
        scalars.all = MagicMock(return_value=[])
        result.scalars = MagicMock(return_value=scalars)
        result.scalar_one = MagicMock(return_value=0)
        result.scalar_one_or_none = MagicMock(return_value=None)
        return result

    db.execute = AsyncMock(side_effect=_execute)
    defaults = {
        "page": 1,
        "page_size": 25,
        "severity": None,
        "status": None,
        "category": None,
        "assigned_to_me": False,
        "search": None,
        "min_confidence": None,
        "confidence_label": None,
        "funnel_stage": None,
        "disposition": None,
    }
    resp = await list_alerts(current_user=user, db=db, **defaults)
    assert resp.total == 0
    _assert_bound_tenant(db.executed, ws2)
    for _sql, params in db.executed:
        for name, value in params.items():
            if name == "tenant_id" or name.startswith("tenant_id_"):
                assert value != home
                assert value == ws2


@pytest.mark.asyncio
async def test_get_current_user_binds_membership_workspace() -> None:
    user_id = uuid.uuid4()
    home = uuid.uuid4()
    ws2 = uuid.uuid4()
    db_user = MagicMock()
    db_user.id = user_id
    db_user.tenant_id = home
    db_user.role = "admin"
    db_user.email = "a@example.com"

    result = MagicMock()
    result.scalar_one_or_none.return_value = db_user
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)

    token = create_access_token(
        {
            "sub": str(user_id),
            "tenant_id": str(ws2),
            "workspace_selected": True,
            "role": "admin",
            "email": "a@example.com",
        }
    )
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with patch.object(deps_module, "user_has_membership", new=AsyncMock(return_value=True)):
        current = await deps_module.get_current_user(credentials=creds, db=db)

    assert current.tenant_id == ws2
    assert current.workspace_selected is True
    assert current.home_tenant_id == home
