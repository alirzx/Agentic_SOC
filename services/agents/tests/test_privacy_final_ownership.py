"""Focused tenant-auth regression checks for manual investigation output."""
from __future__ import annotations

import uuid

import pytest
from fastapi import BackgroundTasks, HTTPException, Request

from app.api import investigate as investigator_api
from app.api import router as legacy_router
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


@pytest.mark.asyncio
async def test_legacy_investigation_uses_signed_tenant_not_body_tenant(monkeypatch):
    key = "k" * 32
    owner = str(uuid.uuid4())
    body_tenant = uuid.uuid4()
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "local")
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", "p" * 32)
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", key)
    legacy_router._runs.clear()

    response = await legacy_router.start_investigation(
        legacy_router.InvestigationRequest(
            incident_id=uuid.uuid4(),
            tenant_id=body_tenant,
            alert_summary="Synthetic alert",
        ),
        BackgroundTasks(),
        signed_request(owner, key=key),
    )

    stored = legacy_router._runs[str(response.run_id)]
    assert stored["_tenant_owner"] == owner
    assert stored["_tenant_owner"] != str(body_tenant)


@pytest.mark.asyncio
async def test_legacy_investigation_polling_enforces_run_owner(monkeypatch):
    key = "k" * 32
    owner = str(uuid.uuid4())
    other = str(uuid.uuid4())
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", key)
    legacy_router._runs.clear()
    legacy_router._runs["synthetic-run"] = {
        "status": "completed",
        "_tenant_owner": owner,
        "result": {"verdict": "needs_review"},
    }

    result = await legacy_router.get_investigation("synthetic-run", signed_request(owner, key=key))
    assert result["status"] == "completed"
    assert "_tenant_owner" not in result

    with pytest.raises(HTTPException) as denied:
        await legacy_router.get_investigation("synthetic-run", signed_request(other, key=key))
    assert denied.value.status_code == 404


@pytest.mark.asyncio
async def test_legacy_route_order_falls_through_to_owned_investigator_run(monkeypatch):
    key = "k" * 32
    owner = str(uuid.uuid4())
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", key)
    legacy_router._runs.clear()
    investigator_api._runs.clear()
    investigator_api._runs["investigator-run"] = {
        "status": "completed",
        "_tenant_owner": owner,
        "report_md": "Synthetic report",
    }

    result = await legacy_router.get_investigation(
        "investigator-run",
        signed_request(owner, key=key),
    )
    assert result == {"status": "completed", "report_md": "Synthetic report"}
