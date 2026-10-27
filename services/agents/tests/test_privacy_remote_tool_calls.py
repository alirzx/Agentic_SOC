"""Provider aliases are decoded before any internal tool executes."""

from __future__ import annotations

import pytest
from app.agents.tool_loop import run_with_tools
from app.privacy.context import async_privacy_context
from app.privacy.remote import RemotePrivacyBackend, RemotePrivacyError
from app.tools.registry import Tool, ToolRegistry
from langchain_core.messages import AIMessage

from tests.remote_privacy_fakes import FakePrivacyClient

TENANT = "11111111-1111-1111-1111-111111111111"


class RemoteToolLLM:
    model = "synthetic-tool-model"

    def __init__(self, client: FakePrivacyClient, *, unknown: bool = False) -> None:
        self.client = client
        self.unknown = unknown
        self.calls = 0
        self.provider_tools: list[list[dict]] = []

    def bind_tools(self, schemas):
        parent = self

        class BoundToolModel:
            model = "synthetic-bound-tool-model"

            async def ainvoke(self, messages, **kwargs):
                return await parent.ainvoke(messages, tools=schemas, **kwargs)

        return BoundToolModel()

    async def ainvoke(self, messages, **kwargs):
        self.calls += 1
        self.provider_tools.append(kwargs.get("tools", []))
        assert "dc01.corp.example" not in str(kwargs.get("tools", []))
        if self.calls == 1:
            alias = "HOST_" + "F" * 32 if self.unknown else self.client.mapping["dc01.corp.example"]
            return AIMessage(
                content="",
                tool_calls=[{"name": "lookup_host", "args": {"host": alias}, "id": "call-1", "type": "tool_call"}],
            )
        return AIMessage(content=f"Completed for {self.client.mapping['dc01.corp.example']}")


def _backend(client: FakePrivacyClient) -> RemotePrivacyBackend:
    return RemotePrivacyBackend(
        tenant_id=TENANT,
        base_url="https://privacy.synthetic.test",
        api_key="synthetic-service-credential",
        client=client,
    )


@pytest.mark.asyncio
async def test_remote_tool_argument_decodes_before_schema_validated_execution(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    client = FakePrivacyClient()
    executed: list[str] = []
    registry = ToolRegistry(
        [
            Tool(
                name="lookup_host",
                description="Look up the synthetic host dc01.corp.example",
                parameters={
                    "type": "object",
                    "properties": {"host": {"type": "string", "minLength": 3}},
                    "required": ["host"],
                    "additionalProperties": False,
                },
                fn=lambda host: executed.append(host) or {"hostname": host},
            )
        ]
    )
    llm = RemoteToolLLM(client)
    async with async_privacy_context(TENANT, remote_backend=_backend(client)):
        result = await run_with_tools(
            llm,
            system="You are an analyst",
            user="Investigate dc01.corp.example",
            registry=registry,
        )

    assert executed == ["dc01.corp.example"]
    assert result["content"] == "Completed for dc01.corp.example"
    assert "dc01.corp.example" not in str(llm.provider_tools)
    assert "HOST_" in str(llm.provider_tools)


@pytest.mark.asyncio
async def test_unknown_alias_blocks_tool_execution(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_BACKEND", "remote")
    client = FakePrivacyClient()
    executed: list[str] = []
    registry = ToolRegistry(
        [
            Tool(
                name="lookup_host",
                description="Look up a host",
                parameters={"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
                fn=lambda host: executed.append(host),
            )
        ]
    )
    async with async_privacy_context(TENANT, remote_backend=_backend(client)):
        with pytest.raises(RemotePrivacyError, match="unknown_provider_alias"):
            await run_with_tools(
                RemoteToolLLM(client, unknown=True),
                system="You are an analyst",
                user="Investigate dc01.corp.example",
                registry=registry,
            )
    assert executed == []


def test_malformed_registered_schema_is_rejected_before_tool_execution() -> None:
    with pytest.raises(ValueError, match="invalid JSON Schema"):
        ToolRegistry(
            [
                Tool(
                    name="broken",
                    description="Broken synthetic schema",
                    parameters={"type": "definitely-not-a-json-schema-type"},
                    fn=lambda: None,
                )
            ]
        )
