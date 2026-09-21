"""Tenant user admin: role assignment is gated to super admins."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.tenants import _assert_assignable_role


def test_analyst_cannot_mint_super_admin() -> None:
    with pytest.raises(HTTPException) as exc:
        _assert_assignable_role("soc_analyst", "super_admin")
    assert exc.value.status_code == 403


def test_tenant_admin_can_create_analyst() -> None:
    assert _assert_assignable_role("tenant_admin", "soc_analyst") == "soc_analyst"


def test_super_admin_can_assign_admin() -> None:
    assert _assert_assignable_role("super_admin", "admin") == "admin"


def test_unknown_role_is_rejected() -> None:
    with pytest.raises(HTTPException) as exc:
        _assert_assignable_role("admin", "root")
    assert exc.value.status_code == 400


def test_cannot_disable_own_account() -> None:
    from uuid import uuid4

    from app.api.v1.endpoints.tenants import _assert_can_deactivate

    actor = uuid4()
    with pytest.raises(HTTPException) as exc:
        _assert_can_deactivate(actor, actor, False)
    assert exc.value.status_code == 400
    _assert_can_deactivate(actor, uuid4(), False)
    _assert_can_deactivate(actor, actor, True)
