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
        self.overrides: dict[str, dict] = {}
        self.statuses: dict[str, int] = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def post(self, path: str, *, json: dict):
        self.calls.append(path)
        if self.failure == path:
            raise httpx.ConnectError("synthetic gateway unavailable")
        if path == "/v1/contexts":
            data = {
                "context_id": "ctx_synthetic",
                "tenant_id": self.return_tenant,
                "profile": json["profile"],
                "policy_version": "1.0.0",
                "expires_at": "2099-01-01T00:00:00Z",
            }
            data.update(self.overrides.get(path, {}))
            return _response("https://gateway.example" + path, data, self.statuses.get(path, 201))
        if path == "/v1/encode":
            protected = copy.deepcopy(json["payload"])
            protected["messages"][2]["content"] = "Protected " + ALIAS
            data = {
                "context_id": "ctx_synthetic",
                "policy_version": "1.0.0",
                "format": "json",
                "payload": protected,
                "expires_at": "2099-01-01T00:00:00Z",
                "stats": {"tokenized_unique": 2},
            }
            data.update(self.overrides.get(path, {}))
            return _response("https://gateway.example" + path, data, self.statuses.get(path, 200))
        if path == "/v1/decode":
            restored = copy.deepcopy(json["payload"])
            restored["choices"][0]["message"]["content"] = "CORP\\alice"
            data = {
                "context_id": "ctx_synthetic",
                "format": "json",
                "payload": restored,
                "stats": {"unknown_aliases": self.unknown_aliases},
            }
            data.update(self.overrides.get(path, {}))
            return _response("https://gateway.example" + path, data, self.statuses.get(path, 200))
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
    original = copy.deepcopy(BODY)
    result = await privacy.safe_chat_post(
        provider, URL, headers={"Authorization": "Bearer synthetic"}, body=BODY, tenant_id=uuid.UUID(TENANT)
    )
    assert len(provider.posts) == 1
    assert "CORP\\alice" not in str(provider.posts[0])
    assert ALIAS in str(provider.posts[0])
    assert provider.posts[0]["messages"][0]["role"] == "system"
    assert "opaque but stable identity" in provider.posts[0]["messages"][0]["content"]
    assert BODY == original
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

@pytest.mark.asyncio
async def test_explicit_required_privacy_enforces_https(enabled, monkeypatch):
    monkeypatch.setenv("AISOC_LLM_PRIVACY_REQUIRED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_REMOTE_URL", "http://gateway.example")
    provider = ProviderStub()
    with pytest.raises(privacy.PrivacyEgressError, match="required_gateway_requires_https"):
        await privacy.safe_chat_post(provider, URL, headers={}, body=BODY, tenant_id=TENANT)
    assert provider.posts == []


@pytest.mark.asyncio
async def test_decode_failure_does_not_release_response(enabled):
    enabled.failure = "/v1/decode"
    provider = ProviderStub()
    with pytest.raises(privacy.PrivacyEgressError):
        await privacy.safe_chat_post(provider, URL, headers={}, body=BODY, tenant_id=TENANT)
    assert len(provider.posts) == 1
    assert "DELETE /v1/contexts/ctx_synthetic" in enabled.calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "override", "error", "provider_calls"),
    [
        ("/v1/encode", {"context_id": "ctx_other"}, "gateway_encode_binding_mismatch", 0),
        ("/v1/encode", {"format": "messages"}, "gateway_encode_binding_mismatch", 0),
        ("/v1/encode", {"stats": []}, "invalid_gateway_encode_response", 0),
        ("/v1/decode", {"context_id": "ctx_other"}, "gateway_decode_binding_mismatch", 1),
        ("/v1/decode", {"format": "messages"}, "gateway_decode_binding_mismatch", 1),
        ("/v1/decode", {"stats": {"unknown_aliases": False}}, "invalid_gateway_decode_response", 1),
    ],
)
async def test_gateway_operation_responses_are_bound_to_context_and_schema(
    enabled,
    path,
    override,
    error,
    provider_calls,
):
    enabled.overrides[path] = override
    provider = ProviderStub()
    with pytest.raises(privacy.PrivacyEgressError, match=error):
        await privacy.safe_chat_post(provider, URL, headers={}, body=BODY, tenant_id=TENANT)
    assert len(provider.posts) == provider_calls


@pytest.mark.asyncio
async def test_gateway_rejects_unexpected_success_status(enabled):
    enabled.statuses["/v1/contexts"] = 200
    provider = ProviderStub()
    with pytest.raises(privacy.PrivacyEgressError, match="gateway_request_failed"):
        await privacy.safe_chat_post(provider, URL, headers={}, body=BODY, tenant_id=TENANT)
    assert provider.posts == []
