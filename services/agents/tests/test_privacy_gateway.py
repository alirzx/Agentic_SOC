"""Central LLM privacy gateway request/response/cache/streaming coverage."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.llm.contract import make_safe_chat_model, safe_ainvoke, safe_astream, safe_chat_completions_request
from app.privacy.context import PrivacyConfigurationError, privacy_context
from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage

KEY = "abcdef0123456789abcdef0123456789"


@pytest.fixture
def privacy(monkeypatch):
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", KEY)


class SpyLLM:
    model = "privacy-spy-model"

    def __init__(self) -> None:
        self.calls: list[list] = []

    async def ainvoke(self, messages, **_kwargs):
        self.calls.append(list(messages))
        content = messages[-1].content
        return AIMessage(content=f"Observed {content}")

    async def astream(self, messages, **_kwargs):
        self.calls.append(list(messages))
        content = messages[-1].content
        midpoint = content.find("_") + 5
        yield AIMessageChunk(content=content[:midpoint])
        yield AIMessageChunk(content=content[midpoint:])


async def test_safe_ainvoke_projects_provider_and_rehydrates_caller(privacy) -> None:
    llm = SpyLLM()
    with privacy_context("tenant-a"):
        result = await safe_ainvoke(llm, [HumanMessage(content="Investigate 10.20.3.7 on dc01.example.local user=alice")])
    sent = llm.calls[0][0].content
    assert "10.20.3.7" not in sent and "dc01.example.local" not in sent and "alice" not in sent
    assert "IP_V4_PRIVATE_" in sent and "HOST_" in sent and "USER_" in sent
    assert "10.20.3.7" in result.content and "dc01.example.local" in result.content and "alice" in result.content


async def test_make_safe_chat_model_inherits_privacy_boundary(privacy) -> None:
    llm = SpyLLM()
    guarded = make_safe_chat_model(llm)
    with privacy_context("tenant-a"):
        await guarded.ainvoke([HumanMessage(content="host dc01.example.local")])
    assert "dc01.example.local" not in llm.calls[0][0].content


async def test_safe_stream_buffers_split_alias_then_rehydrates_once(privacy) -> None:
    llm = SpyLLM()
    with privacy_context("tenant-a"):
        chunks = [chunk async for chunk in safe_astream(llm, [HumanMessage(content="host dc01.example.local")])]
    assert len(chunks) == 1
    assert "dc01.example.local" in chunks[0].content


async def test_raw_http_projects_and_rehydrates(privacy) -> None:
    response = MagicMock(spec=httpx.Response)
    response.raise_for_status.return_value = None
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    async def post(_url, **kwargs):
        sent = kwargs["json"]["messages"][0]["content"]
        assert "10.20.3.7" not in sent
        response.json.return_value = {"choices": [{"message": {"content": sent}}]}
        return response

    client.post = AsyncMock(side_effect=post)
    with patch("httpx.AsyncClient", return_value=client):
        with privacy_context("tenant-a"):
            body = await safe_chat_completions_request(
                api_key="synthetic-test-key",
                model="test-model",
                messages=[{"role": "user", "content": "Investigate 10.20.3.7"}],
            )
    assert "10.20.3.7" in body["choices"][0]["message"]["content"]


async def test_missing_key_or_tenant_context_fails_before_network(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.delenv("AISOC_PRIVACY_TOKEN_KEY", raising=False)
    llm = SpyLLM()
    with pytest.raises(PrivacyConfigurationError):
        await safe_ainvoke(llm, [HumanMessage(content="host dc01.example.local")])
    assert llm.calls == []
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", KEY)
    with pytest.raises(PrivacyConfigurationError, match="tenant privacy context"):
        await safe_ainvoke(llm, [HumanMessage(content="host dc01.example.local")])
    assert llm.calls == []


async def test_cache_is_tenant_isolated_and_provider_safe(privacy) -> None:
    llm = SpyLLM()
    message = HumanMessage(content="unique-cache-private host dc01.example.local")
    with privacy_context("tenant-a"):
        first = await safe_ainvoke(llm, [message])
        second = await safe_ainvoke(llm, [message])
    with privacy_context("tenant-b"):
        third = await safe_ainvoke(llm, [message])
    assert len(llm.calls) == 2
    assert "dc01.example.local" in first.content == second.content
    assert "dc01.example.local" in third.content
