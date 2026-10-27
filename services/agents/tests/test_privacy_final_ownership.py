"""Focused tenant-auth regression checks for manual investigation output."""
from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException, Request

from app.privacy.context import PrivacyConfigurationError
from app.privacy.tenant import require_run_owner, tenant_signature, resolve_request_tenant


def signed_request(tenant: str, *, key: str) -> Request:
    signature = tenant_signature(tenant, key)
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/api/v1/investigations/test",
        "headers": [
            (b"x-tenant-id", tenant.encode()),
            (b"x-aisoc-tenant-signature", signature.encode()),
        ],
    })


@pytest.mark.asyncio
async def test_owner_can_read_and_other_tenant_cannot(monkeypatch):
    key = "k" * 32
    owner = str(uuid.uuid4())
    other = str(uuid.uuid4())
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", key)
    monkeypatch.delenv("AISOC_AGENTS_ALLOW_UNSIGNED_TENANT_HEADER", raising=False)
    await require_run_owner(signed_request(owner, key=key), owner)
    with pytest.raises(HTTPException) as err:
        await require_run_owner(signed_request(other, key=key), owner)
    assert err.value.status_code == 404


@pytest.mark.asyncio
async def test_missing_trusted_tenant_rejected():
    req = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    with pytest.raises(HTTPException) as err:
        await require_run_owner(req, str(uuid.uuid4()))
    assert err.value.status_code == 404


def test_app_env_production_rejects_unsigned_tenant(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("AISOC_ENV", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.setenv("AISOC_AGENTS_ALLOW_UNSIGNED_TENANT_HEADER", "1")
    monkeypatch.delenv("AISOC_AGENTS_TENANT_SIGNING_KEY", raising=False)
    req = Request({"type": "http", "method": "GET", "path": "/", "headers": [(b"x-tenant-id", b"synthetic")]})
    with pytest.raises(PrivacyConfigurationError):
        resolve_request_tenant(req)
