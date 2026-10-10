"""Wave 4a — LLM tool-calling: the registry exposes real tools and the loop
executes the model's selected calls, feeds results back, and terminates."""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest
from app.agents.tool_loop import run_with_tools
from app.privacy.context import privacy_context
from app.privacy.gateway import PRIVACY_SYSTEM_GUIDANCE
from app.tools.registry import Tool, ToolRegistry, default_registry

pytestmark = pytest.mark.usefixtures("privacy_disabled")


class _FakeLLM:
    """Scripted chat model exposing bind_tools + ainvoke."""

    def __init__(self, script: list) -> None:
        self._script = script
        self.calls = 0
        self.bound_tools = None

    def bind_tools(self, tools):
        self.bound_tools = tools
        return self

    async def ainvoke(self, _messages):
        resp = self._script[min(self.calls, len(self._script) - 1)]
        self.calls += 1
        return resp


def _tool_call(name, args, cid="c1"):
    return SimpleNamespace(content="", tool_calls=[{"name": name, "args": args, "id": cid}])


def _final(text):
    return SimpleNamespace(content=text, tool_calls=[])


def test_registry_exposes_openai_schemas():
    reg = default_registry()
    schemas = reg.openai_schemas()
    names = {s["function"]["name"] for s in schemas}
    assert {"extract_iocs", "map_to_mitre", "lookup_technique", "enrich_ioc"} <= names
    assert all(s["type"] == "function" for s in schemas)


@pytest.mark.asyncio
async def test_registry_execute_runs_real_tool_and_handles_unknown():
    reg = default_registry()
    iocs = await reg.execute("extract_iocs", {"text": "beacon to evil.example and 45.9.148.99"})
    assert isinstance(iocs, list)
    # Unknown tool fails soft.
    err = await reg.execute("nope", {})
    assert "error" in err


@pytest.mark.asyncio
async def test_tool_loop_executes_selected_tool_then_answers():
    reg = default_registry()
    llm = _FakeLLM([_tool_call("extract_iocs", {"text": "45.9.148.99 and evil.example"}), _final("Two IOCs found.")])
    out = await run_with_tools(llm, system="You are an analyst.", user="Find IOCs.", registry=reg)
    assert out["truncated"] is False
    assert out["content"] == "Two IOCs found."
    assert out["iterations"] == 2
    assert any(t["tool"] == "extract_iocs" for t in out["tool_trace"])
    assert llm.bound_tools is not None  # tools were bound to the model


@pytest.mark.asyncio
async def test_tool_loop_is_bounded_by_max_iters():
    # A model that always asks for a tool must not loop forever.
    reg = ToolRegistry([Tool(name="noop", description="noop", parameters={"type": "object", "properties": {}}, fn=lambda: {"ok": True})])
    llm = _FakeLLM([_tool_call("noop", {})])  # always returns a tool call
    out = await run_with_tools(llm, system="s", user="u", registry=reg, max_iters=3)
    assert out["truncated"] is True
    assert out["iterations"] == 3
    assert len(out["tool_trace"]) == 3


class _PrivacyToolLLM:
    model = "privacy-tool-loop-test"

    def __init__(self) -> None:
        self.calls = []
        self.alias = ""

    def bind_tools(self, _tools):
        return self

    async def ainvoke(self, messages):
        self.calls.append(list(messages))
        assert [getattr(message, "content", "") for message in messages].count(PRIVACY_SYSTEM_GUIDANCE) == 1
        if len(self.calls) == 1:
            rendered = " ".join(str(getattr(message, "content", "")) for message in messages)
            self.alias = re.search(r"HOST_[A-F0-9]{24}", rendered).group(0)
            return _tool_call("lookup_host", {"host": self.alias})
        tool_content = str(getattr(messages[-1], "content", ""))
        assert "dc01.example.local" not in tool_content
        assert self.alias in tool_content
        return _final(f"Investigated {self.alias}")


@pytest.mark.asyncio
async def test_tool_loop_decodes_arguments_and_reprojects_results(monkeypatch):
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", "abcdef0123456789abcdef0123456789")
    executed = []

    def lookup_host(host):
        executed.append(host)
        return {"hostname": host, "status": "contained"}

    registry = ToolRegistry(
        [
            Tool(
                name="lookup_host",
                description="Look up an internal host.",
                parameters={"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
                fn=lookup_host,
            )
        ]
    )
    llm = _PrivacyToolLLM()
    with privacy_context("55555555-5555-5555-5555-555555555555"):
        result = await run_with_tools(
            llm,
            system="You are an analyst.",
            user="Investigate dc01.example.local",
            registry=registry,
        )

    assert executed == ["dc01.example.local"]
    assert result["content"] == "Investigated dc01.example.local"
    assert "dc01.example.local" not in str(llm.calls)
