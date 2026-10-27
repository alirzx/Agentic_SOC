"""SOC adapter exercised through the real Gateway Python SDK transport."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from app.privacy.remote import RemotePrivacyBackend
from langchain_core.messages import AIMessage, HumanMessage

soorin_privacy = pytest.importorskip("soorin_privacy")

TENANT = "11111111-1111-1111-1111-111111111111"
HOST = "dc01.corp.example"
ALIAS = "HOST_" + "A" * 32


@pytest.mark.asyncio
async def test_real_async_sdk_request_contract_and_round_trip() -> None:
    calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = None
        if request.content:
            body = __import__("json").loads(request.content)
        calls.append((request.method, request.url.path, body))
        assert request.headers["Authorization"] == "Bearer synthetic-service-credential"
        expires_at = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        if request.url.path == "/v1/contexts":
            assert body == {"tenant_id": TENANT, "profile": "agentic-soc-v1", "ttl_seconds": 3600}
            return httpx.Response(
                201,
                json={
                    "context_id": "ctx_sdk_contract",
                    "tenant_id": TENANT,
                    "profile": "agentic-soc-v1",
                    "policy_version": "1.0.0",
                    "expires_at": expires_at,
                },
            )
        if request.url.path == "/v1/encode":
            assert body["format"] == "messages"
            assert body["context_id"] == "ctx_sdk_contract"
            assert body["profile"] == "agentic-soc-v1"
            assert body["tenant_id"] == TENANT
            protected = body["payload"]
            protected[0]["content"] = protected[0]["content"].replace(HOST, ALIAS)
            return httpx.Response(
                200,
                json={
                    "context_id": "ctx_sdk_contract",
                    "policy_version": "1.0.0",
                    "format": "messages",
                    "payload": protected,
                    "expires_at": expires_at,
                    "stats": {"tokenized_unique": 1, "mapping_entries": 1, "credential_aliases": 0},
                },
            )
        if request.url.path == "/v1/decode":
            assert body == {
                "payload": {"content": f"Observed {ALIAS}", "additional_kwargs": {}, "response_metadata": {}, "type": "ai", "name": None, "id": None, "example": False, "tool_calls": [], "invalid_tool_calls": [], "usage_metadata": None},
                "format": "json",
                "context_id": "ctx_sdk_contract",
                "purpose": "llm-response",
                "reveal_credentials": False,
            }
            payload = dict(body["payload"])
            payload["content"] = payload["content"].replace(ALIAS, HOST)
            return httpx.Response(
                200,
                json={
                    "context_id": "ctx_sdk_contract",
                    "format": "json",
                    "payload": payload,
                    "stats": {"rehydrated": 1, "restricted_credentials": 0, "unknown_aliases": 0},
                },
            )
        if request.method == "DELETE" and request.url.path == "/v1/contexts/ctx_sdk_contract":
            return httpx.Response(204)
        return httpx.Response(404, json={"code": "not_found"})

    transport = httpx.MockTransport(handler)
    backend = RemotePrivacyBackend(
        tenant_id=TENANT,
        base_url="https://privacy.synthetic.test",
        api_key="synthetic-service-credential",
        client_factory=soorin_privacy.AsyncPrivacyClient,
        transport=transport,
    )
    await backend.start()
    protected = await backend.encode_messages([HumanMessage(content=f"Investigate {HOST}")])
    assert HOST not in protected[-1].content
    restored = await backend.decode_response(AIMessage(content=f"Observed {ALIAS}"))
    assert restored.content == f"Observed {HOST}"
    await backend.aclose()

    assert [(method, path) for method, path, _ in calls] == [
        ("POST", "/v1/contexts"),
        ("POST", "/v1/encode"),
        ("POST", "/v1/decode"),
        ("DELETE", "/v1/contexts/ctx_sdk_contract"),
    ]
