"""Tenant query-param aliases must not 422 fusion entity-risk endpoints."""

from __future__ import annotations

from uuid import UUID

import pytest

from app.api.tenant import DEMO_TENANT_ID, TenantIdError, coerce_tenant_id


def test_coerce_default_slug() -> None:
    assert coerce_tenant_id("default") == DEMO_TENANT_ID


def test_coerce_demo_slug_case_insensitive() -> None:
    assert coerce_tenant_id("Demo") == DEMO_TENANT_ID


def test_coerce_canonical_uuid() -> None:
    raw = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert coerce_tenant_id(raw) == UUID(raw)


def test_coerce_rejects_garbage() -> None:
    with pytest.raises(TenantIdError):
        coerce_tenant_id("not-a-uuid")
