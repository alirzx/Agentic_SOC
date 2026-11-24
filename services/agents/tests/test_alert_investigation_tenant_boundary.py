"""Regression tests for tenant-bound alert investigation background runs."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.api import alert_investigate as api
from app.api import investigation_run_store as run_store
from app.privacy.tenant import tenant_signature

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"
SIGNING_KEY = "synthetic-investigation-signing-key-0123456789abcdef"


def _request(tenant: str, *, signed: bool = True) -> Request:
    headers = [(b"x-tenant-id", tenant.encode())]
    if signed:
        headers.append((b"x-aisoc-tenant-signature", tenant_signature(tenant, SIGNING_KEY).encode()))
    return Request({"type": "http", "method": "POST", "path": "/api/v1/agents/investigate", "headers": headers})


@pytest.fixture(autouse=True)
def _privacy_config(monkeypatch):
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.delenv("AISOC_AGENTS_ALLOW_UNSIGNED_TENANT_HEADER", raising=False)
    monkeypatch.setattr(api, "validate_gateway_config", lambda: {
        "model_investigation": "synthetic",
        "llm_configured": True,
        "base_url_normalized_sanitized": "synthetic",
    })
    monkeypatch.setattr(api, "resolve_tenant_for_llm", AsyncMock(side_effect=lambda tenant, **_: str(UUID(tenant))))
    run_store.clear_memory_for_tests()


@pytest.mark.asyncio
async def test_signed_tenant_controls_background_run_and_poll(monkeypatch):
    state = SimpleNamespace(
        status="completed", error=None, responder=None, recon=None,
        forensic=None, report_md="Synthetic investigation report",
    )
    orchestrator = SimpleNamespace(run=AsyncMock(return_value=state))
    monkeypatch.setattr(api, "InvestigatorOrchestrator", lambda: orchestrator)

    pending = await api.investigate_alert(
        api.AlertInvestigateRequest(
            alertId="synthetic-alert", tenant_id=TENANT_B,
            raw_alert={"title": "Synthetic alert"},
        ),
        _request(TENANT_A),
    )
    assert pending.status == "running"
    stored = await run_store.get_run(pending.id)
    assert stored is not None
    assert stored["_tenant_owner"] == TENANT_A
    tasks = list(api._background_tasks)
    assert len(tasks) == 1
    await asyncio.gather(*tasks)
    orchestrator.run.assert_awaited_once()
    assert orchestrator.run.await_args.kwargs["tenant_id"] == TENANT_A
    assert orchestrator.run.await_args.kwargs["run_id"] == UUID(pending.id)

    owned = await api.get_alert_investigation(pending.id, _request(TENANT_A))
    assert owned.status == "completed"
    assert owned.findings == "Synthetic investigation report"

    with pytest.raises(HTTPException) as denied:
        await api.get_alert_investigation(pending.id, _request(TENANT_B))
    assert denied.value.status_code == 404


@pytest.mark.asyncio
async def test_unsigned_body_tenant_cannot_start_background_investigation(monkeypatch):
    runner = AsyncMock()
    monkeypatch.setattr(api, "InvestigatorOrchestrator", lambda: SimpleNamespace(run=runner))
    with pytest.raises(HTTPException) as rejected:
        await api.investigate_alert(
            api.AlertInvestigateRequest(alertId="synthetic-alert", tenant_id=TENANT_A),
            _request(TENANT_A, signed=False),
        )
    assert rejected.value.status_code == 403
    runner.assert_not_awaited()
    assert await run_store.get_run("unused") is None


@pytest.mark.asyncio
async def test_background_error_is_sanitized_and_tenant_scoped(monkeypatch):
    runner = AsyncMock(side_effect=RuntimeError("private-provider-key-should-never-leak"))
    monkeypatch.setattr(api, "InvestigatorOrchestrator", lambda: SimpleNamespace(run=runner))
    pending = await api.investigate_alert(
        api.AlertInvestigateRequest(alertId="synthetic-alert"),
        _request(TENANT_A),
    )
    await asyncio.gather(*list(api._background_tasks))
    result = await api.get_alert_investigation(pending.id, _request(TENANT_A))
    assert result.status == "failed"
    assert result.error == "Investigation failed"
    failed = await run_store.get_run(pending.id)
    assert failed is not None
    assert "private-provider-key" not in str(failed)
    with pytest.raises(HTTPException) as denied:
        await api.get_alert_investigation(pending.id, _request(TENANT_B))
    assert denied.value.status_code == 404


def test_only_one_alert_investigation_post_route():
    routes = [r for r in api.router.routes if getattr(r, "path", "") == "/api/v1/agents/investigate"
              and "POST" in (getattr(r, "methods", None) or set())]
    assert len(routes) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("signed_alert_matches", [True, False])
async def test_alert_route_tkg_grant_reaches_only_matching_background_task(monkeypatch, signed_alert_matches):
    import hmac

    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from app.integrations.tkg.tools import grant

    alert = UUID(int=61)
    signature_alert = alert if signed_alert_matches else UUID(int=62)
    signature = hmac.digest(SIGNING_KEY.encode(), f"tkg-read-v1/{TENANT_A}/{signature_alert}".encode(), "sha256").hex()
    received = []

    async def run(**_):
        received.append(grant.get())
        return SimpleNamespace(status="completed", error=None, responder=None, report_md="# Fixture")

    monkeypatch.setattr(api, "InvestigatorOrchestrator", lambda: SimpleNamespace(run=run))
    application = FastAPI()
    application.include_router(api.router)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        response = await client.post("/api/v1/agents/investigate",
            headers={"X-Tenant-Id":TENANT_A,"X-AiSOC-Tenant-Signature":tenant_signature(TENANT_A,SIGNING_KEY),
                     "X-AiSOC-TKG-Grant":signature},
            json={"alertId":str(alert),"tenant_id":TENANT_B})
    assert response.status_code == 200
    await asyncio.gather(*list(api._background_tasks))
    assert received == [(UUID(TENANT_A),alert) if signed_alert_matches else None]
    assert grant.get() is None


@pytest.mark.asyncio
async def test_case_route_derives_alert_scope_in_background(monkeypatch):
    import hmac
    from contextlib import asynccontextmanager

    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from app.api import investigate
    from app.integrations.tkg.tools import grant
    from app.investigator import ledger

    case, alert = UUID(int=71), UUID(int=72)
    signature = hmac.digest(SIGNING_KEY.encode(), f"tkg-case-v1/{TENANT_A}/{case}".encode(), "sha256").hex()
    received = []

    class Database:
        @asynccontextmanager
        async def acquire(self):
            yield self

        transaction = acquire

        async def execute(self, _, tenant):
            assert tenant == TENANT_A

        async def fetchval(self, sql, tenant, case_id):
            assert "a.tenant_id=$1" in sql and "c.id=$2" in sql
            assert (tenant, case_id) == (UUID(TENANT_A), case)
            return alert

    async def run(*_):
        received.append(grant.get())

    monkeypatch.setattr(ledger, "get_pool", AsyncMock(return_value=Database()))
    monkeypatch.setattr(investigate, "_run_and_store", run)
    monkeypatch.setenv("AISOC_TKG_RECON_ENABLED", "true")
    monkeypatch.delenv("AISOC_INVESTIGATE_USE_ROUTER", raising=False)
    app = FastAPI()
    app.include_router(investigate.router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(f"/api/v1/cases/{case}/investigate",
            headers={"X-Tenant-Id":TENANT_A,"X-AiSOC-Tenant-Signature":tenant_signature(TENANT_A,SIGNING_KEY),
                     "X-AiSOC-TKG-Grant":signature}, json={"tenant_id":TENANT_B,"alert_summary":"Synthetic case"})
    assert response.status_code == 200
    assert received == [(UUID(TENANT_A),alert)]
    assert grant.get() is None
