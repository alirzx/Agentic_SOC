"""Client + attribution tests against a mocked TKG transport."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from app.services.tkg_evaluation.attribution import attribute_alerts, is_synthetic_fact
from app.services.tkg_evaluation.client import TkgClient, TkgConfig, TkgError

CFG = TkgConfig(
    base_url="http://tkg.test",
    email="analyst@example.test",
    password="secret",
    kb_id="kb-1",
)


def _client(handler) -> TkgClient:
    return TkgClient(CFG, transport=httpx.MockTransport(handler))


def test_readiness_reports_counts_and_ready(monkeypatch):
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(200, json={"token": "t"})
        if request.url.path == "/api/v1/kbs/kb-1/graph/overview":
            return httpx.Response(200, json={"total_nodes": 1890, "total_edges": 6886})
        return httpx.Response(404)

    async def run():
        client = _client(handler)
        try:
            return await client.readiness()
        finally:
            await client.aclose()

    readiness = asyncio.run(run())
    assert readiness["ready"] is True
    assert readiness["counts"] == {"nodes": 1890, "edges": 6886}
    assert calls[0] == "/api/v1/auth/login"


def test_expired_token_is_refreshed_once():
    logins = {"count": 0}
    seen = {"protected": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/login":
            logins["count"] += 1
            return httpx.Response(200, json={"token": f"t{logins['count']}"})
        seen["protected"] += 1
        if seen["protected"] == 1:
            return httpx.Response(401, json={"detail": "expired"})
        return httpx.Response(200, json={"total_nodes": 1, "total_edges": 0})

    async def run():
        client = _client(handler)
        try:
            return await client.graph_overview()
        finally:
            await client.aclose()

    assert asyncio.run(run())["total_nodes"] == 1
    assert logins["count"] == 2


def test_bad_credentials_raise_auth_reason_code():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "bad password"})

    async def run():
        client = _client(handler)
        try:
            await client.graph_overview()
        finally:
            await client.aclose()

    with pytest.raises(TkgError) as excinfo:
        asyncio.run(run())
    assert excinfo.value.code == "tkg_auth_failed"


def test_context_sends_the_mandatory_tenant_id():
    """The live route rejects a context call without ``tenant_id`` (HTTP 422)."""

    seen: dict[str, bytes] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(200, json={"token": "t"})
        seen["body"] = request.content
        return httpx.Response(200, json={"facts": []})

    async def run():
        client = _client(handler)
        try:
            await client.context("e1", limit=5)
        finally:
            await client.aclose()

    asyncio.run(run())
    body = seen["body"].decode()
    assert '"tenant_id":"tenant-blue"' in body.replace(" ", "")
    assert '"entity":"e1"' in body.replace(" ", "")


def test_synthetic_marker_detection():
    assert is_synthetic_fact({"synthetic": True})
    assert is_synthetic_fact({"evidence": {"source_kind": "synthetic"}})
    assert is_synthetic_fact({"document_id": "d1"}, {"d1"})
    assert not is_synthetic_fact({"source_kind": "ingested", "document_id": "d2"}, {"d1"})


def test_attribution_separates_synthetic_from_real_facts():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(200, json={"token": "t"})
        if request.url.path.endswith("/knowledge/resolve"):
            return httpx.Response(200, json={
                "status": "resolved",
                "candidates": [{"entity_id": "e1", "canonical_key": "soorin:splunknotable:aa"}],
            })
        if request.url.path.endswith("/knowledge/context"):
            return httpx.Response(200, json={"facts": [
                {"subject": "s", "predicate": "p", "object": "o"},
                {"subject": "s", "predicate": "p", "object": "o2", "synthetic": True},
            ]})
        return httpx.Response(404)

    async def run():
        client = _client(handler)
        try:
            return await attribute_alerts(client, ["a1"], budget_s=5)
        finally:
            await client.aclose()

    result = asyncio.run(run())
    assert result["resolved"] == 1
    assert result["synthetic_facts"] == 1
    assert result["real_facts"] == 1
    assert result["synthetic_only"] is False
    assert result["alerts"][0]["pass"] == "corroborated"


def _readiness_for(handler, cfg: TkgConfig = CFG) -> dict:
    async def run():
        client = TkgClient(cfg, transport=httpx.MockTransport(handler))
        try:
            return await client.readiness()
        finally:
            await client.aclose()

    return asyncio.run(run())


def test_wrong_kb_id_404_is_kb_missing_not_unreachable():
    """A 404 on a KB path is a configuration answer, not an outage."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(404, json={"detail": "kb not found"})

    readiness = _readiness_for(handler)
    assert readiness["ready"] is False
    assert readiness["error"] == "tkg_kb_missing"
    assert readiness["checks"][0]["detail"] == "knowledge base kb-1 was not found on the TKG"


def test_malformed_kb_id_rejected_with_422_is_kb_missing():
    """A kb id that is not a UUID fails path validation before the handler runs."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(400, json={"detail": "invalid path parameter"})

    readiness = _readiness_for(handler)
    assert readiness["error"] == "tkg_kb_missing"


def test_server_error_and_timeout_stay_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(200, json={"token": "t"})
        raise httpx.ConnectTimeout("slow graph", request=request)

    assert _readiness_for(handler)["error"] == "tkg_unreachable"

    def erroring(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(503, json={"detail": "busy"})

    assert _readiness_for(erroring)["error"] == "tkg_unreachable"


def test_source_token_404_is_not_a_missing_kb():
    """The source-token route 404s when a token is absent — that is not the KB."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(404, json={"detail": "no token"})

    async def run():
        client = _client(handler)
        try:
            await client._request("GET", "/api/v1/kbs/kb-1/sources/s1/token")
        finally:
            await client.aclose()

    with pytest.raises(TkgError) as excinfo:
        asyncio.run(run())
    assert excinfo.value.code == "tkg_unreachable"
