"""No-network regression tests for independent Gateway protection in API service."""
from __future__ import annotations

import copy
import uuid

import httpx
import pytest

from app.services import privacy_llm as privacy


TENANT = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"
ALIAS = "USER_" + "A" * 18
URL = "https://provider.example/v1/chat/completions"
BODY = {
    "model": "synthetic-model",
    "messages": [
        {"role": "system", "content": "Analyze login anomalies."},
        {"role": "user", "content": "CORP\\alice from 10.20.3.7"},
    ],
}


def _response(url: str, data: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(status_code=status, json=data, request=httpx.Request("POST", url))


class GatewayStub:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.failure: str | None = None
        self.return_tenant = TENANT
        self.unknown_aliases = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def post(self, path: str, *, json: dict):
        self.calls.append(path)
        if self.failure == path:
            raise httpx.ConnectError("synthetic gateway unavailable")
        if path == "/v1/contexts":
            return _response("https://gateway.example" + path, {
                "context_id": "ctx_synthetic",
                "tenant_id": self.return_tenant,
                "profile": json["profile"],
                "policy_version": "1.0.0",
                "expires_at": "2099-01-01T00:00:00Z",
            })
        if path == "/v1/encode":
            protected = copy.deepcopy(json["payload"])
            protected["messages"][1]["content"] = "Protected " + ALIAS
            return _response("https://gateway.example" + path, {"payload": protected})
        if path == "/v1/decode":
            restored = copy.deepcopy(json["payload"])
            restored["choices"][0]["message"]["content"] = "CORP\\alice"
            return _response("https://gateway.example" + path, {
                "payload": restored,
                "stats": {"unknown_aliases": self.unknown_aliases},
            })
        raise AssertionError(path)

    async def delete(self, path: str):
        self.calls.append("DELETE " + path)
        return httpx.Response(status_code=204, request=httpx.Request("DELETE", "https://gateway.example" + path))


class ProviderStub:
    def __init__(self):
        self.posts: list[dict] = []

    async def post(self, url: str, *, headers: dict, json: dict):
        self.posts.append(copy.deepcopy(json))
        return _response(url, {"choices": [{"message": {"role": "assistant", "content": ALIAS}}]})


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    monkeypatch.setenv("AISOC_PRIVACY_REMOTE_URL", "https://gateway.example")
    monkeypatch.setenv("AISOC_PRIVACY_REMOTE_PROFILE", "agentic-soc-v1")
    monkeypatch.setenv("AISOC_PRIVACY_REMOTE_API_KEY", "synthetic-test-key")
    monkeypatch.setenv("AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS", "3")
    monkeypatch.setenv("AISOC_PRIVACY_CONTEXT_TTL_SECONDS", "300")
    monkeypatch.setenv("ENV", "test")
    monkeypatch.delenv("AISOC_ENV", raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.setattr(privacy, "enforce_airgap_for_url", lambda _url: None)
    gateway = GatewayStub()
    monkeypatch.setattr(privacy.httpx, "AsyncClient", lambda **_kw: gateway)
    return gateway


@pytest.mark.asyncio
async def test_encode_provider_decode_and_cleanup(enabled):
    provider = ProviderStub()
    result = await privacy.safe_chat_post(
        provider, URL, headers={"Authorization": "Bearer synthetic"}, body=BODY, tenant_id=uuid.UUID(TENANT)
    )
    assert len(provider.posts) == 1
    assert "CORP\\alice" not in str(provider.posts[0])
    assert ALIAS in str(provider.posts[0])
    assert result.json()["choices"][0]["message"]["content"] == "CORP\\alice"
    assert enabled.calls == [
        "/v1/contexts", "/v1/encode", "/v1/decode", "DELETE /v1/contexts/ctx_synthetic"
    ]


@pytest.mark.asyncio
async def test_gateway_encode_failure_blocks_provider(enabled):
    enabled.failure = "/v1/encode"
    provider = ProviderStub()
    with pytest.raises(privacy.PrivacyEgressError):
        await privacy.safe_chat_post(provider, URL, headers={}, body=BODY, tenant_id=TENANT)
    assert provider.posts == []
    assert "DELETE /v1/contexts/ctx_synthetic" in enabled.calls


@pytest.mark.asyncio
async def test_context_tenant_mismatch_blocks_provider(enabled):
    enabled.return_tenant = OTHER
    provider = ProviderStub()
    with pytest.raises(privacy.PrivacyEgressError, match="gateway_context_binding_mismatch"):
        await privacy.safe_chat_post(provider, URL, headers={}, body=BODY, tenant_id=TENANT)
    assert provider.posts == []


@pytest.mark.asyncio
async def test_unknown_aliases_never_return(enabled):
    enabled.unknown_aliases = 1
    provider = ProviderStub()
    with pytest.raises(privacy.PrivacyEgressError, match="unknown_provider_alias"):
        await privacy.safe_chat_post(provider, URL, headers={}, body=BODY, tenant_id=TENANT)
    assert len(provider.posts) == 1


@pytest.mark.asyncio
async def test_missing_tenant_blocks_provider(enabled):
    provider = ProviderStub()
    with pytest.raises(privacy.PrivacyEgressError, match="missing_authorized_tenant"):
        await privacy.safe_chat_post(provider, URL, headers={}, body=BODY, tenant_id=None)
    assert provider.posts == []


@pytest.mark.asyncio
async def test_production_privacy_disabled_blocks_provider(enabled, monkeypatch):
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "0")
    monkeypatch.setenv("APP_ENV", "production")
    provider = ProviderStub()
    with pytest.raises(privacy.PrivacyEgressError, match="production_provider_privacy_disabled"):
        await privacy.safe_chat_post(provider, URL, headers={}, body=BODY, tenant_id=TENANT)
    assert provider.posts == []


@pytest.mark.asyncio
async def test_production_requires_https_gateway(enabled, monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("AISOC_PRIVACY_REMOTE_URL", "http://gateway.example")
    provider = ProviderStub()
    with pytest.raises(privacy.PrivacyEgressError, match="production_gateway_requires_https"):
        await privacy.safe_chat_post(provider, URL, headers={}, body=BODY, tenant_id=TENANT)
    assert provider.posts == []


@pytest.mark.asyncio
async def test_explicit_privacy_required_flag_blocks_raw_egress(enabled, monkeypatch):
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "0")
    monkeypatch.setenv("AISOC_LLM_PRIVACY_REQUIRED", "1")
    provider = ProviderStub()
    with pytest.raises(privacy.PrivacyEgressError):
        await privacy.safe_chat_post(provider, URL, headers={}, body=BODY, tenant_id=TENANT)
    assert provider.posts == []
