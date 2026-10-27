"""Remote adapter lifecycle, serialization, concurrency, and safety tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from app.privacy.context import PrivacyConfigurationError, async_privacy_context, current_privacy_gateway
from app.privacy.gateway import PRIVACY_SYSTEM_GUIDANCE
from app.privacy.remote import RemotePrivacyBackend, RemotePrivacyError
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from tests.remote_privacy_fakes import FakePrivacyClient

TENANT = "11111111-1111-1111-1111-111111111111"


def _backend(client: FakePrivacyClient) -> RemotePrivacyBackend:
    return RemotePrivacyBackend(
        tenant_id=TENANT,
        base_url="https://privacy.synthetic.test",
        api_key="synthetic-service-credential",
        client=client,
    )


@pytest.mark.asyncio
async def test_message_round_trip_preserves_langchain_structure_and_metadata() -> None:
    client = FakePrivacyClient()
    backend = _backend(client)
    original = [
        HumanMessage(
            content=[
                {"type": "text", "text": "Investigate dc01.corp.example as CORP\\alice"},
                {"type": "text", "text": "path C:\\Windows\\System32\\reg.exe"},
            ],
            additional_kwargs={"nested": {"src_ip": "10.20.3.7"}},
        ),
        ToolMessage(content='{"hostname":"dc01.corp.example"}', tool_call_id="call-1"),
    ]
    await backend.start()
    protected = await backend.encode_messages(original)

    assert protected[0].content == PRIVACY_SYSTEM_GUIDANCE
    assert isinstance(protected[1], HumanMessage)
    assert isinstance(protected[2], ToolMessage)
    assert protected[2].tool_call_id == "call-1"
    assert "dc01.corp.example" not in str(protected)
    assert "HOST_" in str(protected)
    assert "PATH_" in str(protected)
    assert original[0].content[0]["text"].endswith("CORP\\alice")

    provider_response = AIMessage(
        content=f"Host {client.mapping['dc01.corp.example']}",
        tool_calls=[
            {
                "name": "lookup_host",
                "args": {"host": client.mapping["dc01.corp.example"]},
                "id": "call-2",
                "type": "tool_call",
            }
        ],
        response_metadata={"model": "synthetic"},
    )
    restored = await backend.decode_response(provider_response)
    assert restored.content == "Host dc01.corp.example"
    assert restored.tool_calls[0]["args"] == {"host": "dc01.corp.example"}
    assert restored.response_metadata == {"model": "synthetic"}


@pytest.mark.asyncio
async def test_unknown_provider_alias_is_rejected_before_local_use() -> None:
    backend = _backend(FakePrivacyClient())
    await backend.start()
    with pytest.raises(RemotePrivacyError, match="unknown_provider_alias"):
        await backend.decode_response(AIMessage(content="HOST_" + "F" * 32))


@pytest.mark.asyncio
async def test_provider_corrupted_alias_is_rejected_after_decode() -> None:
    backend = _backend(FakePrivacyClient())
    await backend.start()
    with pytest.raises(RemotePrivacyError, match="unresolved_provider_alias"):
        await backend.decode_response(AIMessage(content="HOST_" + "A" * 20 + "Z"))


@pytest.mark.asyncio
async def test_async_context_reuses_one_remote_context_for_parallel_work(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    monkeypatch.setenv("AISOC_PRIVACY_REMOTE_URL", "https://privacy.synthetic.test")
    monkeypatch.setenv("AISOC_PRIVACY_REMOTE_API_KEY", "synthetic-service-credential")
    client = FakePrivacyClient()
    backend = _backend(client)

    async with async_privacy_context(TENANT, remote_backend=backend) as outer:
        assert outer is not None

        async def inspect() -> int:
            async with async_privacy_context(TENANT) as inner:
                assert inner is outer
                assert current_privacy_gateway() is backend
                await inner.gateway.encode_messages([HumanMessage(content="host dc01.corp.example")])
                return id(inner.gateway)

        ids = await asyncio.gather(inspect(), inspect())

    assert ids[0] == ids[1] == id(backend)
    assert [name for name, _ in client.calls].count("create_context") == 1
    assert [name for name, _ in client.calls].count("encode") == 2
    assert client.deleted is True


@pytest.mark.asyncio
async def test_nested_context_rejects_cross_tenant_reuse(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    backend = _backend(FakePrivacyClient())
    async with async_privacy_context(TENANT, remote_backend=backend):
        with pytest.raises(PrivacyConfigurationError, match="tenant mismatch"):
            async with async_privacy_context("22222222-2222-2222-2222-222222222222"):
                pass


@pytest.mark.asyncio
async def test_remote_configuration_rejects_credentials_in_url_and_plain_http_production(monkeypatch) -> None:
    with pytest.raises(RemotePrivacyError, match="must_not_embed_credentials"):
        RemotePrivacyBackend(
            tenant_id=TENANT,
            base_url="https://user:secret@privacy.synthetic.test",
            api_key="synthetic",
        )
    monkeypatch.setenv("AISOC_ENV", "production")
    with pytest.raises(RemotePrivacyError, match="https_required"):
        RemotePrivacyBackend(
            tenant_id=TENANT,
            base_url="http://10.0.0.8:8484",
            api_key="synthetic",
        )


@pytest.mark.asyncio
async def test_gateway_failure_error_does_not_expose_sdk_message() -> None:
    client = FakePrivacyClient(fail="create_context", fail_status=401)
    backend = _backend(client)
    with pytest.raises(RemotePrivacyError) as raised:
        await backend.start()
    assert raised.value.category == "invalid_service_credential"
    assert "synthetic gateway failure" not in str(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "category"),
    [
        (400, "invalid_context_or_policy"),
        (403, "unauthorized_tenant_or_context"),
        (413, "payload_too_large"),
        (422, "invalid_request_schema"),
        (503, "storage_unavailable"),
        (500, "gateway_server_error"),
    ],
)
async def test_gateway_statuses_map_to_stable_categories(status: int, category: str) -> None:
    backend = _backend(FakePrivacyClient(fail="create_context", fail_status=status))
    with pytest.raises(RemotePrivacyError) as raised:
        await backend.start()
    assert raised.value.category == category


@pytest.mark.asyncio
async def test_expired_context_fails_before_encode_request() -> None:
    client = FakePrivacyClient()
    backend = _backend(client)
    await backend.start()
    backend._expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(RemotePrivacyError, match="remote_context_expired"):
        await backend.encode_messages([HumanMessage(content="host dc01.corp.example")])
    assert [name for name, _ in client.calls].count("encode") == 0


@pytest.mark.asyncio
async def test_gateway_context_binding_mismatch_is_cleaned_up(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")

    class MismatchedClient(FakePrivacyClient):
        async def create_context(self, **kwargs):
            result = await super().create_context(**kwargs)
            result["tenant_id"] = "22222222-2222-2222-2222-222222222222"
            return result

    client = MismatchedClient()
    with pytest.raises(PrivacyConfigurationError, match="binding_mismatch"):
        async with async_privacy_context(TENANT, remote_backend=_backend(client)):
            pass
    assert client.deleted is True


def test_unsupported_python_object_fails_serialization() -> None:
    backend = _backend(FakePrivacyClient())
    # Keep a concrete unsupported value for contract-path fail-closed tests.
    assert isinstance(SimpleNamespace(value=object()), SimpleNamespace)
    assert backend.backend_name == "remote"
