"""Focused coverage for explicit Human Trace logging at the LLM boundary."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.llm import contract
from app.llm.contract import safe_ainvoke, safe_astream, safe_chat_completions_request
from app.llm.human_trace import (
    INTERNAL_INPUT,
    LOCAL_RESPONSE,
    PROVIDER_INPUT,
    PROVIDER_RESPONSE,
    TRACE_EVENT_NAMES,
    emit_human_trace,
)
from app.privacy.context import privacy_context
from langchain_core.messages import AIMessage, AIMessageChunk, HumanMessage

HOST = "endpoint01.corp.synthetic.test"
TRACE_TENANT = "77777777-7777-7777-7777-777777777777"
STREAM_TENANT = "88888888-8888-8888-8888-888888888888"
CACHE_TENANT = "99999999-9999-9999-9999-999999999999"


@pytest.fixture
def trace_events(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setenv("AISOC_LLM_HUMAN_TRACE_ENABLED", "1")
    monkeypatch.setenv("AISOC_LLM_HUMAN_TRACE_MAX_CHARS", "50000")
    monkeypatch.setattr(
        "app.llm.human_trace.logger",
        MagicMock(info=lambda event, **fields: events.append((event, fields))),
    )
    return events


def _event(events: list[tuple[str, dict[str, Any]]], stage: str, *, path: str | None = None) -> dict[str, Any]:
    matches = [fields for _name, fields in events if fields["stage"] == stage and (path is None or fields["path"] == path)]
    assert matches, (stage, path, events)
    return matches[-1]


class _InvokeLLM:
    model = "human-trace-model"

    def __init__(self) -> None:
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any], **_kwargs: Any) -> AIMessage:
        self.calls.append(list(messages))
        return AIMessage(
            content=f"Reviewed {messages[-1].content}",
            additional_kwargs={"tool_calls": [{"name": "lookup_host", "arguments": {"host": messages[-1].content}}]},
        )


class _StreamLLM:
    model = "human-trace-stream-model"

    async def astream(self, messages: list[Any], **_kwargs: Any):
        content = messages[-1].content
        midpoint = max(1, len(content) // 2)
        yield AIMessageChunk(content=content[:midpoint])
        yield AIMessageChunk(content=content[midpoint:])


@pytest.mark.asyncio
async def test_trace_flag_off_emits_no_payload_events(
    privacy_disabled,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logger = MagicMock()
    monkeypatch.setenv("AISOC_LLM_HUMAN_TRACE_ENABLED", "0")
    monkeypatch.setattr("app.llm.human_trace.logger", logger)

    result = await safe_ainvoke(_InvokeLLM(), [HumanMessage(content="plain request")], temperature=0)

    assert result.content == "Reviewed plain request"
    logger.info.assert_not_called()


@pytest.mark.asyncio
async def test_privacy_trace_shows_projection_provider_response_and_exact_local_rehydration(
    privacy_enabled,
    trace_events: list[tuple[str, dict[str, Any]]],
) -> None:
    messages = [
        HumanMessage(
            content=f"Investigate host={HOST}",
            additional_kwargs={"debug_context": {"hostname": HOST}},
        )
    ]
    llm = _InvokeLLM()

    with privacy_context(TRACE_TENANT):
        result = await safe_ainvoke(llm, messages, temperature=0)

    internal = _event(trace_events, INTERNAL_INPUT)
    provider_input = _event(trace_events, PROVIDER_INPUT)
    provider_response = _event(trace_events, PROVIDER_RESPONSE)
    local_response = _event(trace_events, LOCAL_RESPONSE)

    assert HOST in internal["payload"]
    assert HOST not in provider_input["payload"]
    assert "HOST_" in provider_input["payload"]
    assert "HOST_" in provider_response["payload"] and HOST not in provider_response["payload"]
    assert "additional_kwargs" in provider_input["payload"]
    assert "tool_calls" in provider_response["payload"]
    assert HOST in local_response["payload"]
    assert result.content == f"Reviewed Investigate host={HOST}"
    assert internal["tenant_id"] == TRACE_TENANT
    assert internal["privacy_enabled"] is True
    assert internal["projection_applied"] is False
    assert provider_input["projection_applied"] is True
    assert provider_response["projection_applied"] is True
    assert local_response["projection_applied"] is False
    assert {name for name, _fields in trace_events} == set(TRACE_EVENT_NAMES.values())


@pytest.mark.asyncio
async def test_privacy_off_trace_does_not_claim_projection(
    privacy_disabled,
    trace_events: list[tuple[str, dict[str, Any]]],
) -> None:
    await safe_ainvoke(_InvokeLLM(), [HumanMessage(content="plain request")], temperature=0)

    internal = _event(trace_events, INTERNAL_INPUT)
    provider = _event(trace_events, PROVIDER_INPUT)
    assert json.loads(internal["payload"])[0]["content"] == "plain request"
    assert json.loads(provider["payload"])[0]["content"] == "plain request"
    assert provider["privacy_enabled"] is False
    assert provider["projection_applied"] is False
    assert provider["tenant_id"] is None


@pytest.mark.asyncio
async def test_privacy_stream_trace_captures_raw_then_rehydrated_response(
    privacy_enabled,
    trace_events: list[tuple[str, dict[str, Any]]],
) -> None:
    with privacy_context(STREAM_TENANT):
        chunks = [chunk async for chunk in safe_astream(_StreamLLM(), [HumanMessage(content=f"host={HOST}")])]

    assert len(chunks) == 1
    assert HOST in chunks[0].content
    provider = _event(trace_events, PROVIDER_RESPONSE, path="astream")
    local = _event(trace_events, LOCAL_RESPONSE, path="astream")
    assert "HOST_" in provider["payload"] and HOST not in provider["payload"]
    assert HOST in local["payload"]


@pytest.mark.asyncio
async def test_privacy_off_stream_traces_each_unchanged_chunk(
    privacy_disabled,
    trace_events: list[tuple[str, dict[str, Any]]],
) -> None:
    chunks = [chunk async for chunk in safe_astream(_StreamLLM(), [HumanMessage(content="plain stream")])]

    provider = [fields for _name, fields in trace_events if fields["stage"] == PROVIDER_RESPONSE]
    local = [fields for _name, fields in trace_events if fields["stage"] == LOCAL_RESPONSE]
    assert len(chunks) == len(provider) == len(local) == 2
    assert [fields["chunk_index"] for fields in provider] == [0, 1]
    assert all(fields["projection_applied"] is False for fields in provider + local)


@pytest.mark.asyncio
async def test_raw_http_trace_scrubs_credentials_and_preserves_four_stages(
    privacy_disabled,
    trace_events: list[tuple[str, dict[str, Any]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_key = "provider-key-human-trace-123456"
    privacy_key = "privacy-key-human-trace-1234567890"
    signing_key = "signing-key-human-trace-1234567890"
    path_token = "path-token-human-trace-1234567890"
    monkeypatch.setenv("OPENAI_API_KEY", provider_key)
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", privacy_key)
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", signing_key)

    response_payload = {
        "choices": [{"message": {"content": "synthetic response"}}],
        "authorization": f"Bearer {provider_key}",
    }
    response = MagicMock(spec=httpx.Response)
    response.raise_for_status.return_value = None
    response.json.return_value = response_payload
    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=client):
        result = await safe_chat_completions_request(
            api_key=provider_key,
            model="synthetic-http-model",
            messages=[{"role": "user", "content": f"Summarize credential echo {provider_key}"}],
            url=f"https://user:{provider_key}@provider.synthetic.test/v1/chat/completions?token={signing_key}",
            extra_headers={"Authorization": f"Bearer {provider_key}"},
            diagnostics={
                "api_key": provider_key,
                "authorization": f"Bearer {provider_key}",
                "privacy": privacy_key,
                "signing": signing_key,
                "url": f"https://user:{provider_key}@provider.synthetic.test/{path_token}/v1?token={signing_key}",
            },
        )

    rendered_events = json.dumps(trace_events)
    assert result == response_payload
    assert {fields["stage"] for _name, fields in trace_events} == {
        INTERNAL_INPUT,
        PROVIDER_INPUT,
        PROVIDER_RESPONSE,
        LOCAL_RESPONSE,
    }
    assert provider_key not in rendered_events
    assert privacy_key not in rendered_events
    assert signing_key not in rendered_events
    assert path_token not in rendered_events
    assert "Authorization" not in rendered_events
    assert "[REDACTED_CREDENTIAL]" in rendered_events


@pytest.mark.asyncio
async def test_cache_trace_marks_provider_not_called(
    privacy_enabled,
    trace_events: list[tuple[str, dict[str, Any]]],
) -> None:
    contract._RESPONSE_CACHE.clear()
    llm = _InvokeLLM()
    message = HumanMessage(content=f"unique human trace cache host={HOST}")
    with privacy_context(CACHE_TENANT):
        first = await safe_ainvoke(llm, [message])
        second = await safe_ainvoke(llm, [message])

    assert first.content == second.content
    assert len(llm.calls) == 1
    cached_provider = _event(trace_events, PROVIDER_RESPONSE, path="cache")
    cached_local = _event(trace_events, LOCAL_RESPONSE, path="cache")
    assert cached_provider["cache_hit"] is True
    assert cached_provider["provider_called"] is False
    assert cached_local["provider_called"] is False
    assert HOST in cached_local["payload"]
    rendered_events = json.dumps(trace_events)
    assert "privacy:v1.1" not in rendered_events
    assert "cache_namespace" not in rendered_events


@pytest.mark.asyncio
async def test_trace_serialization_failure_never_breaks_llm_call(
    privacy_disabled,
    trace_events: list[tuple[str, dict[str, Any]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_render(_payload: Any) -> tuple[str, bool, int]:
        raise RuntimeError("synthetic trace failure")

    monkeypatch.setattr("app.llm.human_trace._render_payload", fail_render)
    result = await safe_ainvoke(_InvokeLLM(), [HumanMessage(content="still runs")], temperature=0)

    assert result.content == "Reviewed still runs"
    assert trace_events == []


@pytest.mark.asyncio
async def test_trace_logger_failure_never_breaks_llm_call(
    privacy_disabled,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AISOC_LLM_HUMAN_TRACE_ENABLED", "1")
    monkeypatch.setattr(
        "app.llm.human_trace.logger",
        MagicMock(info=MagicMock(side_effect=RuntimeError("synthetic logger failure"))),
    )

    result = await safe_ainvoke(_InvokeLLM(), [HumanMessage(content="still runs")], temperature=0)

    assert result.content == "Reviewed still runs"


def test_trace_payload_limit_is_logging_only(
    privacy_disabled,
    trace_events: list[tuple[str, dict[str, Any]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AISOC_LLM_HUMAN_TRACE_MAX_CHARS", "80")
    original = "x" * 500

    emit_human_trace(
        INTERNAL_INPUT,
        original,
        model="synthetic-model",
        privacy_enabled=False,
        tenant_id=None,
        path="ainvoke",
        projection_applied=False,
    )

    event = _event(trace_events, INTERNAL_INPUT)
    assert len(event["payload"]) == 80
    assert event["payload_truncated"] is True
    assert event["payload_original_chars"] > 80
    assert original == "x" * 500
