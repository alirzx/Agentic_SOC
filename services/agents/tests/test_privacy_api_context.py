"""Trusted tenant binding for direct Copilot and contextual LLM APIs."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.api import contextual, copilot, explain, playbooks
from app.privacy.context import PrivacyConfigurationError, current_privacy_gateway
from app.privacy.gateway import PRIVACY_SYSTEM_GUIDANCE
from app.privacy.tenant import resolve_request_tenant, tenant_signature
from langchain_core.messages import AIMessage, AIMessageChunk
from starlette.requests import Request

PRIVACY_KEY = "privacy-key-0123456789abcdef012345"
SIGNING_KEY = "tenant-signing-0123456789abcdef01234"
TENANT = "tenant-synthetic-a"
HOST = "endpoint01.corp.synthetic.test"


def _request(*, signed: bool = True) -> Request:
    headers = [(b"x-tenant-id", TENANT.encode())]
    if signed:
        headers.append((b"x-aisoc-tenant-signature", tenant_signature(TENANT, SIGNING_KEY).encode()))
    return Request({"type": "http", "method": "POST", "path": "/", "headers": headers})


@pytest.fixture
def privacy_api(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", PRIVACY_KEY)
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-provider-key")
    monkeypatch.delenv("AISOC_AGENTS_ALLOW_UNSIGNED_TENANT_HEADER", raising=False)


class _SpyLLM:
    model = "synthetic-copilot-model"

    def __init__(self) -> None:
        self.calls: list[list] = []

    async def ainvoke(self, messages, **_kwargs):
        self.calls.append(list(messages))
        assert current_privacy_gateway() is not None
        return AIMessage(content=messages[-1].content)

    async def astream(self, messages, **_kwargs):
        self.calls.append(list(messages))
        assert current_privacy_gateway() is not None
        content = messages[-1].content
        split = max(1, len(content) // 2)
        yield AIMessageChunk(content=content[:split])
        yield AIMessageChunk(content=content[split:])


def test_request_tenant_requires_authenticated_state_or_valid_signature(privacy_api, monkeypatch) -> None:
    assert resolve_request_tenant(_request(signed=True)) == TENANT
    assert resolve_request_tenant(_request(signed=False)) is None

    request = _request(signed=False)
    request.state.authenticated_tenant_id = "tenant-from-auth-middleware"
    assert resolve_request_tenant(request) == "tenant-from-auth-middleware"

    monkeypatch.setenv("AISOC_AGENTS_ALLOW_UNSIGNED_TENANT_HEADER", "1")
    monkeypatch.setenv("AISOC_ENV", "development")
    assert resolve_request_tenant(_request(signed=False)) == TENANT
    monkeypatch.setenv("AISOC_ENV", "production")
    with pytest.raises(PrivacyConfigurationError, match="cannot be enabled in production"):
        resolve_request_tenant(_request(signed=False))


async def test_generic_copilot_binds_signed_tenant_and_projects_provider_view(privacy_api) -> None:
    copilot._CONVERSATIONS.clear()
    response = MagicMock(spec=httpx.Response)
    response.raise_for_status.return_value = None
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    captured: dict = {}

    async def post(_url, **kwargs):
        captured.update(kwargs["json"])
        sent = kwargs["json"]["messages"][-1]["content"]
        response.json.return_value = {"choices": [{"message": {"content": sent}}]}
        return response

    client.post = AsyncMock(side_effect=post)
    with patch("httpx.AsyncClient", return_value=client):
        result = await copilot.chat(
            copilot.CopilotChatRequest(message=f"Investigate hostname={HOST} user=alice"),
            _request(),
        )

    provider_text = json.dumps(captured)
    assert captured["messages"][0]["content"] == PRIVACY_SYSTEM_GUIDANCE
    assert HOST not in provider_text and "alice" not in provider_text
    assert "HOST_" in provider_text and "USER_" in provider_text
    assert HOST in result.reply.content and "alice" in result.reply.content


async def test_generic_copilot_missing_trusted_tenant_has_zero_network_egress(privacy_api) -> None:
    copilot._CONVERSATIONS.clear()
    with patch("httpx.AsyncClient", side_effect=AssertionError("network must not be constructed")) as client:
        result = await copilot.chat(
            copilot.CopilotChatRequest(message=f"Investigate hostname={HOST}"),
            _request(signed=False),
        )
    client.assert_not_called()
    assert result.reply.content in copilot._SYNTHETIC_REPLIES


async def test_contextual_one_shot_uses_factory_and_signed_privacy_context(privacy_api, monkeypatch) -> None:
    llm = _SpyLLM()
    monkeypatch.setattr(contextual, "make_chat_model", lambda role, **_kwargs: llm if role == "copilot" else None)
    result = await contextual.run_action(
        contextual.ContextualActionRequest(
            page="alerts",
            action="explain",
            entity_id="alert-synthetic",
            entity={"device": {"name": HOST}, "user": "alice"},
        ),
        _request(),
    )
    sent = "\n".join(str(message.content) for message in llm.calls[0])
    assert PRIVACY_SYSTEM_GUIDANCE in sent
    assert HOST not in sent and "alice" not in sent
    assert HOST in result.content and "alice" in result.content
    assert result.fallback is False


async def test_contextual_stream_keeps_privacy_bound_across_iteration(privacy_api, monkeypatch) -> None:
    llm = _SpyLLM()
    monkeypatch.setattr(contextual, "make_chat_model", lambda role, **_kwargs: llm if role == "copilot" else None)
    response = await contextual.run_action_stream(
        contextual.ContextualActionRequest(
            page="alerts",
            action="explain",
            entity_id="alert-synthetic",
            entity={"hostname": HOST},
        ),
        _request(),
    )
    rendered = b"".join([chunk async for chunk in response.body_iterator]).decode()
    sent = "\n".join(str(message.content) for message in llm.calls[0])
    assert HOST not in sent
    assert HOST in rendered
    assert '"done": true' in rendered


async def test_contextual_missing_trusted_tenant_falls_back_before_factory(privacy_api, monkeypatch) -> None:
    calls = 0

    def factory(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("model factory must not be reached")

    monkeypatch.setattr(contextual, "make_chat_model", factory)
    result = await contextual.run_action(
        contextual.ContextualActionRequest(page="alerts", action="explain", entity_id="alert-synthetic"),
        _request(signed=False),
    )
    assert calls == 0
    assert result.fallback is True


async def test_nl_playbook_api_forwards_only_resolved_tenant(privacy_api, monkeypatch) -> None:
    captured: dict = {}

    class _Draft:
        def to_dict(self) -> dict:
            return {"ok": True}

    async def _draft(prompt: str, *, allow_llm: bool, tenant_id: str | None):
        captured.update(prompt=prompt, allow_llm=allow_llm, tenant_id=tenant_id)
        return _Draft()

    monkeypatch.setattr(playbooks, "draft_from_nl", _draft)
    result = await playbooks.draft_playbook_from_nl(
        playbooks.DraftFromNLRequest(prompt="Notify the SOC", allow_llm=True),
        _request(),
    )
    assert result == {"ok": True}
    assert captured == {"prompt": "Notify the SOC", "allow_llm": True, "tenant_id": TENANT}


async def test_explain_uses_resolved_tenant_for_config_and_stream(privacy_api, monkeypatch) -> None:
    captured: dict = {}
    config = MagicMock(source="environment", allowed=True)

    async def _resolve(tenant_id):
        captured["resolver_tenant"] = tenant_id
        return config

    async def _stream(req, llm_config, privacy_tenant_id=None):
        captured["privacy_tenant"] = privacy_tenant_id
        assert llm_config is config
        yield b'{"kind":"done"}\n'

    monkeypatch.setattr(explain, "resolve_llm_config", _resolve)
    monkeypatch.setattr(explain, "_stream_explanation", _stream)
    monkeypatch.setenv("AISOC_EXPLAIN_RPM", "0")
    explain._reset_explain_limiter()
    response = await explain.explain(
        explain.ExplainRequest(alert={"title": "Synthetic"}, tenant_id="client-controlled-tenant"),
        _request(),
    )
    body = b"".join([chunk async for chunk in response.body_iterator])
    assert body == b'{"kind":"done"}\n'
    assert captured == {"resolver_tenant": TENANT, "privacy_tenant": TENANT}
