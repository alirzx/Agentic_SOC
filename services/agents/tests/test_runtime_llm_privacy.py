"""Privacy coverage for the newer structured agent runtime."""

from __future__ import annotations

import json
import re
from typing import Any

import pytest
from app.privacy.context import PrivacyConfigurationError, current_privacy_gateway, privacy_context
from app.privacy.gateway import PRIVACY_SYSTEM_GUIDANCE
from app.runtime.audit import InMemoryAuditSink
from app.runtime.contracts import Agent, AgentContext, AgentResult, IncidentStateSnapshot
from app.runtime.llm_agents.execution_errors import InvestigationExecutionMeta
from app.runtime.llm_agents.investigation import run_llm_investigation
from app.runtime.llm_agents.structured_step import invoke_investigation_step
from app.runtime.llm_agents.tool_runner import execute_registry_tool
from app.runtime.orchestrator import SocOrchestrator
from app.runtime.registry import AgentRegistry
from app.runtime.runtime import AgentRuntime
from app.runtime.tools import CallableSOCTool, SocToolRegistry
from langchain_core.messages import AIMessage

TENANT = "44444444-4444-4444-4444-444444444444"
HOST = "endpoint01.corp.synthetic.test"
_HOST_TOKEN = re.compile(r"HOST_[A-F0-9]{24}")


def _context(*, skip_investigation: bool = False) -> AgentContext:
    return AgentContext(
        incident_id="incident-runtime-privacy",
        tenant_id=TENANT,
        objective=f"Investigate host={HOST}",
        state=IncidentStateSnapshot(state="NEW", severity="high", raw_alert={"title": "Synthetic alert"}),
        metadata={"skip_investigation": skip_investigation},
    )


def _contents(messages: list[Any]) -> list[str]:
    return [str(getattr(message, "content", message.get("content", "") if isinstance(message, dict) else "")) for message in messages]


def _assert_one_guidance(messages: list[Any]) -> None:
    assert _contents(messages).count(PRIVACY_SYSTEM_GUIDANCE) == 1


@pytest.mark.asyncio
async def test_runtime_orchestrator_binds_tenant_privacy_context(privacy_enabled) -> None:
    seen: list[str] = []

    class PrivacyCheckingAgent(Agent):
        version = "test"

        def __init__(self, name: str) -> None:
            self.name = name

        async def execute(self, context: AgentContext) -> AgentResult:
            gateway = current_privacy_gateway()
            assert gateway is not None
            assert gateway.tenant_id == context.tenant_id
            seen.append(self.name)
            return AgentResult(status="success", reasoning=self.name)

    registry = AgentRegistry()
    for name in ("triage", "correlation", "decision", "report"):
        registry.register(PrivacyCheckingAgent(name))
    orchestrator = SocOrchestrator(AgentRuntime(registry, audit=InMemoryAuditSink()), registry)

    await orchestrator.run(_context(skip_investigation=True))

    assert seen == ["triage", "correlation", "decision", "report"]
    with pytest.raises(PrivacyConfigurationError, match="tenant privacy context"):
        current_privacy_gateway()


@pytest.mark.asyncio
async def test_runtime_unresolved_tenant_keeps_deterministic_pipeline_offline(
    privacy_enabled,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _unresolved(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.privacy.tenant.resolve_canonical_tenant", _unresolved)
    seen: list[str] = []

    class DeterministicAgent(Agent):
        version = "test"

        def __init__(self, name: str) -> None:
            self.name = name

        async def execute(self, context: AgentContext) -> AgentResult:
            with pytest.raises(PrivacyConfigurationError, match="tenant privacy context"):
                current_privacy_gateway()
            seen.append(self.name)
            return AgentResult(status="success", reasoning=self.name)

    registry = AgentRegistry()
    for name in ("triage", "correlation", "decision", "report"):
        registry.register(DeterministicAgent(name))
    orchestrator = SocOrchestrator(AgentRuntime(registry, audit=InMemoryAuditSink()), registry)
    context = _context(skip_investigation=True)
    context.tenant_id = "unknown-tenant"

    await orchestrator.run(context)

    assert seen == ["triage", "correlation", "decision", "report"]
    assert context.tenant_id == "unknown-tenant"


class _ToolCallingLLM:
    model = "runtime-privacy-test"

    def __init__(self) -> None:
        self.calls: list[list[Any]] = []
        self.alias = ""

    async def ainvoke(self, messages: list[Any], **_kwargs: Any) -> AIMessage:
        self.calls.append(list(messages))
        rendered = "\n".join(_contents(messages))
        assert HOST not in rendered
        match = _HOST_TOKEN.search(rendered)
        assert match is not None
        self.alias = match.group(0)
        if len(self.calls) == 1:
            return AIMessage(
                content=json.dumps(
                    {
                        "action": "tool",
                        "tool": "lookup_host",
                        "arguments": {"host": self.alias},
                        "reason": f"Inspect {self.alias}",
                    }
                )
            )
        return AIMessage(
            content=json.dumps(
                {
                    "action": "conclude",
                    "output": {
                        "status": "completed",
                        "claims": [],
                        "attack_chain": [],
                        "open_questions": [],
                        "uncertainties": [],
                        "risk_signals": {},
                    },
                }
            )
        )


@pytest.mark.asyncio
async def test_runtime_tool_alias_is_restored_locally_and_reprojected(
    privacy_enabled,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executed: list[str] = []

    def lookup_host(host: str) -> dict[str, str]:
        executed.append(host)
        return {"hostname": host, "status": "known"}

    registry = SocToolRegistry()
    registry.register(
        CallableSOCTool(
            name="lookup_host",
            description="Look up an internal host.",
            fn=lookup_host,
            allowed_agents=frozenset({"investigation"}),
            input_schema={"type": "object", "properties": {"host": {"type": "string"}}},
        )
    )
    llm = _ToolCallingLLM()
    monkeypatch.setattr("app.runtime.llm_agents.investigation.make_chat_model", lambda *_a, **_k: llm)

    with privacy_context(TENANT):
        result = await run_llm_investigation(_context(), registry)

    assert result.status == "success"
    assert executed == [HOST]
    assert len(llm.calls) == 2
    for messages in llm.calls:
        _assert_one_guidance(messages)
        assert HOST not in "\n".join(_contents(messages))
        assert llm.alias in "\n".join(_contents(messages))


class _RepairLLM:
    model = "runtime-repair-privacy-test"

    def __init__(self) -> None:
        self.calls: list[list[Any]] = []
        self.alias = ""

    async def ainvoke(self, messages: list[Any], **_kwargs: Any) -> AIMessage:
        self.calls.append(list(messages))
        rendered = "\n".join(_contents(messages))
        assert HOST not in rendered
        match = _HOST_TOKEN.search(rendered)
        assert match is not None
        self.alias = match.group(0)
        if len(self.calls) == 1:
            return AIMessage(content=f"invalid response for {self.alias}")
        return AIMessage(
            content=json.dumps(
                {
                    "action": "conclude",
                    "output": {
                        "status": "completed",
                        "claims": [],
                        "attack_chain": [],
                        "open_questions": [],
                        "uncertainties": [],
                        "risk_signals": {},
                    },
                }
            )
        )


@pytest.mark.asyncio
async def test_runtime_repair_reprojects_rehydrated_invalid_response(privacy_enabled) -> None:
    llm = _RepairLLM()
    meta = InvestigationExecutionMeta()

    with privacy_context(TENANT):
        step = await invoke_investigation_step(
            llm,
            nonce="synthetic-nonce",
            user_content=f"Investigate host={HOST}",
            attempt_index=1,
            exec_meta=meta,
        )

    assert step.action == "conclude"
    assert meta.repair_attempted is True
    assert meta.llm_calls == 2
    assert len(llm.calls) == 2
    for messages in llm.calls:
        _assert_one_guidance(messages)
        rendered = "\n".join(_contents(messages))
        assert HOST not in rendered
        assert llm.alias in rendered


@pytest.mark.asyncio
async def test_execute_registry_tool_receives_canonical_arguments() -> None:
    """Keep the execution boundary explicit even when invoked independently."""
    executed: list[str] = []
    registry = SocToolRegistry()
    registry.register(
        CallableSOCTool(
            name="lookup_host",
            description="Look up host.",
            fn=lambda host: executed.append(host) or {"host": host},
            allowed_agents=frozenset({"investigation"}),
        )
    )
    await execute_registry_tool(
        registry,
        _context(),
        agent_name="investigation",
        agent_version="test",
        tool_name="lookup_host",
        arguments={"host": HOST},
        tool_call_count=0,
    )
    assert executed == [HOST]
