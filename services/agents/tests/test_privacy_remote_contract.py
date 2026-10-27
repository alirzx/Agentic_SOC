"""Every centralized provider boundary is fail-closed in remote mode."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.llm import safe_ainvoke, safe_astream
from app.llm import contract as contract_module
from app.llm.contract import LLMContractViolation, safe_chat_completions_request
from app.privacy.context import async_privacy_context
from app.privacy.remote import RemotePrivacyBackend, RemotePrivacyError
from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage
from tests.remote_privacy_fakes import FakePrivacyClient

TENANT = "11111111-1111-1111-1111-111111111111"


def _backend(client: FakePrivacyClient) -> RemotePrivacyBackend:
    return RemotePrivacyBackend(
        tenant_id=TENANT,
        base_url="https://privacy.synthetic.test",
        api_key="synthetic-service-credential",
        client=client,
    )


class ProviderSpy:
    model = "synthetic-provider"

    def __init__(self, client: FakePrivacyClient) -> None:
        self.client = client
        self.calls: list[list] = []

    async def ainvoke(self, messages, **_kwargs):
        self.calls.append(list(messages))
        protected = messages[-1].content
        assert "dc01.corp.example" not in protected
        return AIMessage(content=f"Observed {protected}")

    async def astream(self, messages, **_kwargs):
        self.calls.append(list(messages))
        protected = messages[-1].content
        midpoint = len(protected) // 2
        yield AIMessageChunk(content=protected[:midpoint])
        yield AIMessageChunk(content=protected[midpoint:])


@pytest.mark.asyncio
async def test_remote_ainvoke_and_cache_disabled(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    client = FakePrivacyClient()
    backend = _backend(client)
    llm = ProviderSpy(client)
    async with async_privacy_context(TENANT, remote_backend=backend):
        first = await safe_ainvoke(llm, [HumanMessage(content="Investigate dc01.corp.example")])
        second = await safe_ainvoke(llm, [HumanMessage(content="Investigate dc01.corp.example")])

    assert len(llm.calls) == 2
    assert "dc01.corp.example" in first.content
    assert "dc01.corp.example" in second.content


@pytest.mark.asyncio
async def test_remote_stream_buffers_then_decodes_once(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    client = FakePrivacyClient()
    backend = _backend(client)
    async with async_privacy_context(TENANT, remote_backend=backend):
        chunks = [
            chunk
            async for chunk in safe_astream(
                ProviderSpy(client),
                [HumanMessage(content="Investigate dc01.corp.example")],
            )
        ]

    assert len(chunks) == 1
    assert "dc01.corp.example" in chunks[0].content
    assert [name for name, _ in client.calls].count("decode") == 1


@pytest.mark.asyncio
async def test_encode_failure_prevents_langchain_provider_egress(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    client = FakePrivacyClient(fail="encode", fail_status=413)
    backend = _backend(client)
    llm = ProviderSpy(client)
    async with async_privacy_context(TENANT, remote_backend=backend):
        with pytest.raises(RemotePrivacyError, match="payload_too_large"):
            await safe_ainvoke(llm, [HumanMessage(content="Investigate dc01.corp.example")])
    assert llm.calls == []


@pytest.mark.asyncio
async def test_unsupported_serialization_prevents_provider_egress(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    client = FakePrivacyClient()
    backend = _backend(client)
    llm = ProviderSpy(client)
    async with async_privacy_context(TENANT, remote_backend=backend):
        with pytest.raises(RemotePrivacyError, match="unsupported_message_type"):
            await safe_ainvoke(llm, [object()])
    assert llm.calls == []


@pytest.mark.asyncio
async def test_raw_http_protects_complete_body_and_decodes(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    client = FakePrivacyClient()
    backend = _backend(client)
    response = MagicMock(spec=httpx.Response)
    response.raise_for_status.return_value = None
    http_client = MagicMock()
    http_client.__aenter__ = AsyncMock(return_value=http_client)
    http_client.__aexit__ = AsyncMock(return_value=None)

    async def post(_url, **kwargs):
        body = kwargs["json"]
        rendered = str(body)
        assert "dc01.corp.example" not in rendered
        assert "CORP\\alice" not in rendered
        assert "HOST_" in rendered and "USER_" in rendered
        response.json.return_value = {"choices": [{"message": {"content": body["messages"][-1]["content"]}}]}
        return response

    http_client.post = AsyncMock(side_effect=post)
    with patch("httpx.AsyncClient", return_value=http_client):
        async with async_privacy_context(TENANT, remote_backend=backend):
            result = await safe_chat_completions_request(
                api_key="synthetic-provider-key",
                model="synthetic-model",
                messages=[{"role": "user", "content": "Investigate dc01.corp.example"}],
                tools=[
                    {
                        "type": "function",
                        "function": {
                            "name": "lookup_user",
                            "description": "Look up CORP\\alice",
                            "parameters": {"type": "object", "properties": {}},
                        },
                    }
                ],
            )
    assert "dc01.corp.example" in result["choices"][0]["message"]["content"]


@pytest.mark.asyncio
async def test_raw_http_rejects_message_override_unknown_fields_and_auth_override() -> None:
    common = {
        "api_key": "synthetic-provider-key",
        "model": "synthetic-model",
        "messages": [{"role": "user", "content": "hello"}],
    }
    with pytest.raises(LLMContractViolation, match="unsupported"):
        await safe_chat_completions_request(**common, diagnostics={"messages": "unprotected"})
    with pytest.raises(LLMContractViolation, match="authorization"):
        await safe_chat_completions_request(**common, extra_headers={"Authorization": "Bearer override"})


@pytest.mark.asyncio
async def test_decode_failure_never_releases_protected_response(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    client = FakePrivacyClient(fail="decode", fail_status=503)
    backend = _backend(client)
    llm = ProviderSpy(client)
    async with async_privacy_context(TENANT, remote_backend=backend):
        with pytest.raises(RemotePrivacyError, match="storage_unavailable"):
            await safe_ainvoke(llm, [HumanMessage(content="Investigate dc01.corp.example")])
    assert len(llm.calls) == 1


@pytest.mark.asyncio
async def test_remote_call_records_cost_once(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    client = FakePrivacyClient()
    backend = _backend(client)
    recorded = []
    monkeypatch.setattr(contract_module, "record_llm_call", lambda *args, **kwargs: recorded.append((args, kwargs)))
    async with async_privacy_context(TENANT, remote_backend=backend):
        await safe_ainvoke(ProviderSpy(client), [HumanMessage(content="Investigate dc01.corp.example")])
    assert len(recorded) == 1
