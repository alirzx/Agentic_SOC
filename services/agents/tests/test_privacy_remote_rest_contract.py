"""Direct HTTPX contract tests for the independent Privacy Gateway."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from app.privacy.remote import RemotePrivacyBackend, RemotePrivacyError
from app.privacy.rest_client import PrivacyGatewayRESTClient, PrivacyGatewayRESTError
from langchain_core.messages import AIMessage, HumanMessage

TENANT = "11111111-1111-1111-1111-111111111111"
HOST = "dc01.corp.example"
ALIAS = "HOST_" + "A" * 32
CONTEXT_ID = "ctx_" + "b" * 32


def _expires_at() -> str:
    return (datetime.now(UTC) + timedelta(hours=1)).isoformat()


def _backend(handler: Any, **kwargs: Any) -> RemotePrivacyBackend:
    return RemotePrivacyBackend(
        tenant_id=TENANT,
        base_url="https://privacy.synthetic.test",
        api_key="synthetic-service-credential",
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_direct_rest_request_contract_and_round_trip() -> None:
    calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        calls.append((request.method, request.url.path, copy.deepcopy(body)))
        assert request.headers["Authorization"] == "Bearer synthetic-service-credential"
        assert request.headers["Accept"] == "application/json"

        if request.method == "POST" and request.url.path == "/v1/contexts":
            assert body == {
                "tenant_id": TENANT,
                "profile": "agentic-soc-v1",
                "ttl_seconds": 3600,
            }
            return httpx.Response(
                201,
                json={
                    "context_id": CONTEXT_ID,
                    "tenant_id": TENANT,
                    "profile": "agentic-soc-v1",
                    "policy_version": "1.0.0",
                    "expires_at": _expires_at(),
                },
            )
        if request.method == "POST" and request.url.path == "/v1/encode":
            assert body["context_id"] == CONTEXT_ID
            assert body["tenant_id"] == TENANT
            assert body["profile"] == "agentic-soc-v1"
            assert body["purpose"] == "llm-egress"
            assert body["format"] == "messages"
            assert body["registrations"] == [
                {
                    "kind": "HOST",
                    "value": HOST,
                    "source": "soc.structured_message",
                    "role": "hostname",
                }
            ]
            protected = copy.deepcopy(body["payload"])
            protected[0]["content"] = protected[0]["content"].replace(HOST, ALIAS)
            protected[0]["additional_kwargs"]["hostname"] = ALIAS
            return httpx.Response(
                200,
                json={
                    "context_id": CONTEXT_ID,
                    "policy_version": "1.0.0",
                    "format": "messages",
                    "payload": protected,
                    "expires_at": _expires_at(),
                    "stats": {"tokenized_unique": 1, "mapping_entries": 1, "credential_aliases": 0},
                },
            )
        if request.method == "POST" and request.url.path == "/v1/decode":
            assert body["context_id"] == CONTEXT_ID
            assert body["format"] == "json"
            assert body["purpose"] == "llm-response"
            assert body["reveal_credentials"] is False
            assert body["payload"]["content"] == f"Observed {ALIAS}"
            restored = copy.deepcopy(body["payload"])
            restored["content"] = restored["content"].replace(ALIAS, HOST)
            return httpx.Response(
                200,
                json={
                    "context_id": CONTEXT_ID,
                    "format": "json",
                    "payload": restored,
                    "stats": {"rehydrated": 1, "restricted_credentials": 0, "unknown_aliases": 0},
                },
            )
        if request.method == "DELETE" and request.url.path == f"/v1/contexts/{CONTEXT_ID}":
            return httpx.Response(204)
        raise AssertionError(f"unexpected request: {request.method} {request.url.path}")

    backend = _backend(handler)
    await backend.start()
    protected = await backend.encode_messages(
        [HumanMessage(content=f"Investigate {HOST}", additional_kwargs={"hostname": HOST})]
    )
    assert HOST not in str(protected)
    assert ALIAS in str(protected)
    restored = await backend.decode_response(AIMessage(content=f"Observed {ALIAS}"))
    assert restored.content == f"Observed {HOST}"
    await backend.aclose()

    assert [(method, path) for method, path, _body in calls] == [
        ("POST", "/v1/contexts"),
        ("POST", "/v1/encode"),
        ("POST", "/v1/decode"),
        ("DELETE", f"/v1/contexts/{CONTEXT_ID}"),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "category"),
    [
        (400, "invalid_context_or_policy"),
        (401, "invalid_service_credential"),
        (403, "unauthorized_tenant_or_context"),
        (413, "payload_too_large"),
        (422, "invalid_request_schema"),
        (503, "storage_unavailable"),
    ],
)
async def test_direct_rest_http_errors_map_to_safe_categories(status: int, category: str) -> None:
    backend = _backend(lambda _request: httpx.Response(status, json={"detail": "sensitive upstream text"}))
    with pytest.raises(RemotePrivacyError) as raised:
        await backend.start()
    assert raised.value.category == category
    assert "sensitive upstream text" not in str(raised.value)


@pytest.mark.asyncio
async def test_direct_rest_invalid_json_is_rejected() -> None:
    backend = _backend(
        lambda _request: httpx.Response(201, content=b"not-json", headers={"content-type": "application/json"})
    )
    with pytest.raises(RemotePrivacyError, match="invalid_gateway_response"):
        await backend.start()


@pytest.mark.asyncio
async def test_direct_rest_malformed_success_is_rejected() -> None:
    backend = _backend(lambda _request: httpx.Response(201, json={"tenant_id": TENANT}))
    with pytest.raises(RemotePrivacyError, match="invalid_gateway_response"):
        await backend.start()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "response"),
    [
        (
            "encode",
            {
                "context_id": CONTEXT_ID,
                "policy_version": "1.0.0",
                "format": "json",
                "payload": {},
                "expires_at": "2030-01-01T00:00:00+00:00",
                "stats": {"tokenized_unique": False},
            },
        ),
        (
            "decode",
            {
                "context_id": CONTEXT_ID,
                "format": "json",
                "payload": {},
            },
        ),
    ],
)
async def test_direct_rest_operation_malformed_success_is_rejected(
    operation: str,
    response: dict[str, Any],
) -> None:
    client = PrivacyGatewayRESTClient(
        base_url="https://privacy.synthetic.test",
        api_key="synthetic-service-credential",
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=response)),
    )
    with pytest.raises(PrivacyGatewayRESTError, match="invalid_gateway_response"):
        if operation == "encode":
            await client.encode(
                {},
                format="json",
                context_id=CONTEXT_ID,
                profile="agentic-soc-v1",
                tenant_id=TENANT,
                registrations=[],
            )
        else:
            await client.decode({}, context_id=CONTEXT_ID)
    await client.aclose()


@pytest.mark.asyncio
async def test_direct_rest_timeout_is_sanitized() -> None:
    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("synthetic timeout containing no credential")

    backend = _backend(timeout)
    with pytest.raises(RemotePrivacyError) as raised:
        await backend.start()
    assert raised.value.category == "gateway_timeout"
    assert "synthetic timeout" not in str(raised.value)


@pytest.mark.asyncio
async def test_direct_rest_connection_failure_is_sanitized() -> None:
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("synthetic unavailable upstream", request=request)

    backend = _backend(unavailable)
    with pytest.raises(RemotePrivacyError) as raised:
        await backend.start()
    assert raised.value.category == "gateway_unavailable"
    assert "synthetic unavailable upstream" not in str(raised.value)


@pytest.mark.asyncio
async def test_direct_rest_cleanup_failure_does_not_replace_completed_workflow() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.method == "POST":
            return httpx.Response(
                201,
                json={
                    "context_id": CONTEXT_ID,
                    "tenant_id": TENANT,
                    "profile": "agentic-soc-v1",
                    "policy_version": "1.0.0",
                    "expires_at": _expires_at(),
                },
            )
        return httpx.Response(503, json={"detail": "storage unavailable"})

    backend = _backend(handler, max_attempts=1)
    await backend.start()
    await backend.aclose()
    assert calls == ["POST /v1/contexts", f"DELETE /v1/contexts/{CONTEXT_ID}"]
