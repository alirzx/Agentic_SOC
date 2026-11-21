"""``GET /v1/diagnostics/{tenant_id}`` — serving the last cycle's ambient report.

Runs the real ASGI app through httpx (no server, no lifespan: the endpoint only
reads the in-process cache, so a database is irrelevant to it).
"""

from __future__ import annotations

import uuid

import pytest
from app.main import app
from app.services.diagnostics import forget_all, remember
from httpx import ASGITransport, AsyncClient


def client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://correlation")


@pytest.mark.asyncio
async def test_reports_the_cached_cycle_for_that_tenant():
    forget_all()
    tenant = str(uuid.uuid4())
    remember(
        {
            "tenant_id": tenant,
            "ambient_key_count": 1,
            "ambient_keys": [{"token": "domain:attackrange.local"}],
            "vetoed_pair_count": 12,
            "vetoed_pairs": [],
        }
    )

    async with client() as http:
        response = await http.get(f"/v1/diagnostics/{tenant}")

    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == tenant
    assert body["ambient_keys"][0]["token"] == "domain:attackrange.local"
    assert body["vetoed_pair_count"] == 12


@pytest.mark.asyncio
async def test_unknown_tenant_is_a_404_that_says_what_to_do():
    forget_all()
    tenant = str(uuid.uuid4())

    async with client() as http:
        response = await http.get(f"/v1/diagnostics/{tenant}")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "no cycle has run" in detail
    # An operator should not have to read the source to learn the next step.
    assert f"/v1/run/{tenant}" in detail


@pytest.mark.asyncio
async def test_tenant_id_must_be_a_uuid():
    async with client() as http:
        response = await http.get("/v1/diagnostics/not-a-uuid")

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_internal_token_is_enforced_when_configured(monkeypatch):
    forget_all()
    tenant = str(uuid.uuid4())
    remember({"tenant_id": tenant})
    monkeypatch.setenv("AISOC_INTERNAL_TOKEN", "s3cret")

    async with client() as http:
        denied = await http.get(f"/v1/diagnostics/{tenant}")
        allowed = await http.get(
            f"/v1/diagnostics/{tenant}", headers={"X-Internal-Token": "s3cret"}
        )

    assert denied.status_code == 401
    assert allowed.status_code == 200
