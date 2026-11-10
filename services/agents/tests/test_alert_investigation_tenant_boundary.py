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
    api._runs.clear()


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
    assert api._runs[pending.id]["_tenant_owner"] == TENANT_A
    tasks = list(api._background_tasks)
    assert len(tasks) == 1
    await asyncio.gather(*tasks)
    orchestrator.run.assert_awaited_once()
    assert orchestrator.run.await_args.kwargs["tenant_id"] == TENANT_A

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
    assert api._runs == {}


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
    assert "private-provider-key" not in str(api._runs[pending.id])
    with pytest.raises(HTTPException) as denied:
        await api.get_alert_investigation(pending.id, _request(TENANT_B))
    assert denied.value.status_code == 404


def test_only_one_alert_investigation_post_route():
    routes = [r for r in api.router.routes if getattr(r, "path", "") == "/api/v1/agents/investigate"
              and "POST" in (getattr(r, "methods", None) or set())]
    assert len(routes) == 1
