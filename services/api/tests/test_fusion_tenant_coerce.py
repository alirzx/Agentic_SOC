"""Gateway must accept the console's historical `default` tenant slug."""

from __future__ import annotations

from uuid import UUID

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.fusion import _coerce_tenant_id

_DEMO = UUID("00000000-0000-0000-0000-000000000001")


def test_coerce_default_slug() -> None:
    assert _coerce_tenant_id("default") == _DEMO


def test_coerce_demo_slug() -> None:
    assert _coerce_tenant_id("DEMO") == _DEMO


def test_coerce_rejects_garbage() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _coerce_tenant_id("not-a-uuid")
    assert exc_info.value.status_code == 422
