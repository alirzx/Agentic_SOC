"""Central LLM privacy gateway request/response/cache/streaming coverage."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.llm.contract import LLMContractViolation, make_safe_chat_model, safe_ainvoke, safe_astream, safe_chat_completions_request
from app.privacy.context import PrivacyConfigurationError, privacy_context
from app.privacy.gateway import PRIVACY_SYSTEM_GUIDANCE, PrivacyGateway
from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage

KEY = "abcdef0123456789abcdef0123456789"
TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"


@pytest.fixture
def privacy(privacy_enabled):
    return privacy_enabled


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
    with privacy_context(TENANT_A):
        result = await safe_ainvoke(llm, [HumanMessage(content="Investigate 10.20.3.7 on dc01.example.local user=alice")])
    assert llm.calls[0][0].content == PRIVACY_SYSTEM_GUIDANCE
    assert "Do not decode" in llm.calls[0][0].content
    assert "abbreviate, truncate" in llm.calls[0][0].content
    sent = llm.calls[0][-1].content
    assert "10.20.3.7" not in sent and "dc01.example.local" not in sent and "alice" not in sent
    assert "IP_V4_PRIVATE_" in sent and "HOST_" in sent and "USER_" in sent
    assert "10.20.3.7" in result.content and "dc01.example.local" in result.content and "alice" in result.content


async def test_make_safe_chat_model_inherits_privacy_boundary(privacy) -> None:
    llm = SpyLLM()
    guarded = make_safe_chat_model(llm)
    with privacy_context(TENANT_A):
        await guarded.ainvoke([HumanMessage(content="host dc01.example.local")])
    assert "dc01.example.local" not in llm.calls[0][-1].content


async def test_privacy_guidance_is_not_added_when_privacy_is_disabled(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "0")
    llm = SpyLLM()
    await safe_ainvoke(llm, [HumanMessage(content="plain request")])
    assert len(llm.calls[0]) == 1
    assert llm.calls[0][0].content == "plain request"


async def test_privacy_guidance_is_injected_exactly_once_per_provider_call(privacy) -> None:
    llm = SpyLLM()
    original = [HumanMessage(content="Investigate host=dc01.example.local")]
    with privacy_context(TENANT_A):
        await safe_ainvoke(llm, original, temperature=0)
        await safe_ainvoke(llm, original, temperature=0)

    assert len(llm.calls) == 2
    for call in llm.calls:
        assert [message.content for message in call].count(PRIVACY_SYSTEM_GUIDANCE) == 1
        assert call[0].content == PRIVACY_SYSTEM_GUIDANCE
    assert len(original) == 1
    assert original[0].content == "Investigate host=dc01.example.local"


def test_whole_turn_identity_discovery_is_message_order_independent() -> None:
    host = "endpoint01.corp.synthetic.test"
    first = PrivacyGateway(tenant_id="tenant-a", token_key=KEY)
    first_projected = first.project_messages(
        [
            HumanMessage(content=f"Registry modification on {host}"),
            HumanMessage(content=f"hostname={host}"),
        ]
    )
    second = PrivacyGateway(tenant_id="tenant-a", token_key=KEY)
    second_projected = second.project_messages(
        [
            HumanMessage(content=f"hostname={host}"),
            HumanMessage(content=f"Registry modification on {host}"),
        ]
    )

    first_text = "\n".join(message.content for message in first_projected)
    second_text = "\n".join(message.content for message in second_projected)
    assert host not in first_text and host not in second_text
    first_alias = next(iter(first.codec.mapping))
    second_alias = next(iter(second.codec.mapping))
    assert first_alias == second_alias
    assert first_text.count(first_alias) == 2
    assert second_text.count(second_alias) == 2


async def test_safe_stream_buffers_split_alias_then_rehydrates_once(privacy) -> None:
    llm = SpyLLM()
    with privacy_context(TENANT_A):
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
        assert kwargs["json"]["messages"][0] == {"role": "system", "content": PRIVACY_SYSTEM_GUIDANCE}
        sent = kwargs["json"]["messages"][-1]["content"]
        assert "10.20.3.7" not in sent
        response.json.return_value = {"choices": [{"message": {"content": sent}}]}
        return response

    client.post = AsyncMock(side_effect=post)
    with patch("httpx.AsyncClient", return_value=client):
        with privacy_context(TENANT_A):
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


@pytest.mark.parametrize("enabled", [False, True])
async def test_privacy_projection_does_not_weaken_raw_ocsf_contract(
    enabled: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1" if enabled else "0")
    if enabled:
        monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", KEY)
    else:
        monkeypatch.delenv("AISOC_PRIVACY_TOKEN_KEY", raising=False)
    llm = SpyLLM()
    if enabled:
        with privacy_context(TENANT_A):
            with pytest.raises(LLMContractViolation, match="raw-log signature|OCSF"):
                await safe_ainvoke(
                    llm,
                    [HumanMessage(content='{"class_uid": 2001, "activity_id": 1, "raw_data": "vendor payload"}')],
                )
    else:
        with pytest.raises(LLMContractViolation, match="raw-log signature|OCSF"):
            await safe_ainvoke(
                llm,
                [HumanMessage(content='{"class_uid": 2001, "activity_id": 1, "raw_data": "vendor payload"}')],
            )
    assert llm.calls == []


async def test_cache_is_tenant_isolated_and_provider_safe(privacy) -> None:
    llm = SpyLLM()
    message = HumanMessage(content="unique-cache-private host dc01.example.local")
    with privacy_context(TENANT_A):
        first = await safe_ainvoke(llm, [message])
        second = await safe_ainvoke(llm, [message])
    with privacy_context(TENANT_B):
        third = await safe_ainvoke(llm, [message])
    assert len(llm.calls) == 2
    assert "dc01.example.local" in first.content == second.content
    assert "dc01.example.local" in third.content
    assert all("dc01.example.local" not in str(call) for call in llm.calls)


def test_cache_namespace_includes_policy_version_and_tenant_scope() -> None:
    tenant_a = PrivacyGateway(tenant_id="tenant-a", token_key=KEY)
    tenant_b = PrivacyGateway(tenant_id="tenant-b", token_key=KEY)
    assert tenant_a.cache_namespace.startswith("privacy:v1.1:")
    assert tenant_a.policy_version == "v1.1"
    assert tenant_a.cache_namespace != tenant_b.cache_namespace
