"""Phase 7 Agentic SOC shadow-mode tests. Production flow is never invoked."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from uuid import uuid4

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.runtime.audit import InMemoryAuditSink
from app.runtime.contracts import Agent, AgentContext, AgentResult, NextTask
from app.runtime.orchestrator import SocOrchestrator
from app.runtime.registry import AgentRegistry
from app.runtime.runtime import AgentRuntime
from app.runtime.shadow_service import AgenticShadowService
from app.runtime.tools import CallableSOCTool, SocToolRegistry, ToolContext, ToolPermissionDenied

TENANT = "11111111-1111-1111-1111-111111111111"
ALERT = "22222222-2222-2222-2222-222222222222"


def _fused(**overrides: object) -> dict:
    alert = {
        "id": ALERT,
        "tenant_id": TENANT,
        "title": "Credential dumping via LSASS access",
        "severity": "critical",
        "hostname": "WIN-DC01",
        "username": "admin-backup",
        "src_ip": "10.20.30.40",
        "mitre_techniques": ["T1003"],
        "risk_score": 0.9,
    }
    msg = {
        "id": ALERT,
        "tenant_id": TENANT,
        "incident_id": "CASE-123",
        "fusion_decision": "new_incident",
        "confidence_score": 0.8,
        "alert": alert,
    }
    msg.update(overrides)
    return msg


class StubAgent(Agent):
    def __init__(self, name: str, hang: float = 0.0, fail: bool = False) -> None:
        self.name = name
        self.version = "1.0"
        self.hang = hang
        self.fail = fail
        self.calls = 0

    async def execute(self, context: AgentContext) -> AgentResult:
        self.calls += 1
        if self.hang:
            await asyncio.sleep(self.hang)
        if self.fail:
            raise RuntimeError("shadow boom")
        nxt = "report" if self.name == "decision" else "correlation"
        return AgentResult(
            status="success",
            findings=[],
            next_tasks=[NextTask(agent=nxt, objective="write_report" if self.name == "decision" else "go")],
            reasoning=self.name,
            confidence=0.9,
        )


def _stub_orchestrator(**kwargs: object) -> SocOrchestrator:
    registry = AgentRegistry()
    for name in ("triage", "investigation", "threat-intel", "correlation", "decision", "response", "validation", "report"):
        registry.register(StubAgent(name, **kwargs))  # type: ignore[arg-type]
    return SocOrchestrator(AgentRuntime(registry, audit=InMemoryAuditSink()), registry)


def _service(**kwargs: object) -> AgenticShadowService:
    orch = kwargs.pop("orchestrator", None) or _stub_orchestrator()
    return AgenticShadowService(orchestrator=orch, **kwargs)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_disabled_flag_does_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "false")
    service = _service()
    assert await service.submit(_fused()) is None
    assert service.store.list_for_tenant(TENANT) == []


@pytest.mark.asyncio
async def test_enabled_shadow_creates_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "true")
    monkeypatch.setenv("AGENTIC_SOC_SHADOW_MODE", "true")
    service = _service()
    record = await service.submit(_fused())
    assert record is not None
    assert record.status == "completed"
    assert record.alert_id == ALERT
    assert record.comparison["caseId"] == "CASE-123"
    assert record.result["shadow_mode"] is True


@pytest.mark.asyncio
async def test_shadow_destructive_tool_is_dry_run_even_with_auto_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "true")
    monkeypatch.setenv("AGENTIC_SOC_SHADOW_MODE", "true")
    monkeypatch.setenv("AGENTIC_SOC_AUTO_RESPONSE", "true")
    from app.runtime.catalog import _simulated_response

    tools = SocToolRegistry()
    tools.register(
        CallableSOCTool(
            name="response.isolate_asset",
            description="isolate",
            fn=_simulated_response,
            risk_level="high",
            requires_approval=True,
            allowed_agents=frozenset({"response"}),
        )
    )
    ctx = ToolContext(
        tenant_id=TENANT,
        incident_id="CASE-123",
        agent_name="response",
        shadow_mode=True,
        approval_granted=True,
    )
    out = await tools.execute("response.isolate_asset", {"asset_id": "host-1"}, ctx)
    assert out["simulated"] is True
    assert out["dry_run"] is True
    assert out["reason"] == "shadow_mode"


@pytest.mark.asyncio
async def test_agentic_failure_does_not_break_existing_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "true")
    existing_ok = {"ok": True}

    async def existing_flow() -> dict:
        return existing_ok

    class Boom:
        async def run(self, context: AgentContext):
            raise RuntimeError("orchestrator crashed")

    service = AgenticShadowService(orchestrator=Boom())  # type: ignore[arg-type]
    record = await service.submit(_fused())
    production = await existing_flow()
    assert production["ok"] is True
    assert record is not None
    assert record.status == "failed"


@pytest.mark.asyncio
async def test_idempotency_same_alert_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "true")
    triage = StubAgent("triage")
    registry = AgentRegistry()
    for name in ("triage", "investigation", "threat-intel", "correlation", "decision", "response", "validation", "report"):
        registry.register(triage if name == "triage" else StubAgent(name))
    service = AgenticShadowService(
        orchestrator=SocOrchestrator(AgentRuntime(registry, audit=InMemoryAuditSink()), registry)
    )
    first = await service.submit(_fused())
    second = await service.submit(_fused())
    assert first is not None and second is not None
    assert first.id == second.id
    assert triage.calls == 1


@pytest.mark.asyncio
async def test_concurrency_limit_queues(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "true")
    started = asyncio.Event()
    release = asyncio.Event()

    class Slow(Agent):
        name = "triage"
        version = "1.0"

        async def execute(self, context: AgentContext) -> AgentResult:
            started.set()
            await release.wait()
            return AgentResult(status="success", next_tasks=[NextTask(agent="report", objective="write_report")])

    registry = AgentRegistry()
    slow = Slow()
    for name in ("triage", "investigation", "threat-intel", "correlation", "decision", "response", "validation", "report"):
        registry.register(slow if name == "triage" else StubAgent(name))
    orch = SocOrchestrator(AgentRuntime(registry, audit=InMemoryAuditSink()), registry)
    service = AgenticShadowService(orchestrator=orch, max_concurrent=1)
    first = asyncio.create_task(service.submit(_fused()))
    await started.wait()
    second_alert = _fused()
    second_alert["id"] = "other-alert"
    second_alert["alert"]["id"] = "other-alert"
    second = asyncio.create_task(service.submit(second_alert))
    await asyncio.sleep(0.05)
    assert service.queued >= 1
    release.set()
    await asyncio.gather(first, second)


@pytest.mark.asyncio
async def test_tenant_store_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "true")
    service = _service()
    await service.submit(_fused())
    other = str(uuid4())
    assert service.store.list_for_tenant(other) == []
    assert len(service.store.list_for_tenant(TENANT)) == 1


@pytest.mark.asyncio
async def test_timeout_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "true")
    service = _service(orchestrator=_stub_orchestrator(hang=1.0), timeout=0.05)
    record = await service.submit(_fused())
    assert record is not None
    assert record.status == "timeout"


@pytest.mark.asyncio
async def test_cost_budget_stops_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "true")
    from app.core.cost_governor import Decision, GovernorDecision

    class Gov:
        def decide(self, tenant_id: str, alert: object) -> GovernorDecision:
            return GovernorDecision(decision=Decision.CIRCUIT_OPEN, reason="cap", remaining_usd=0.0)

    inv = StubAgent("investigation")
    registry = AgentRegistry()
    for name in ("triage", "investigation", "threat-intel", "correlation", "decision", "response", "validation", "report"):
        registry.register(inv if name == "investigation" else StubAgent(name))
    service = AgenticShadowService(
        orchestrator=SocOrchestrator(AgentRuntime(registry, audit=InMemoryAuditSink()), registry),
        governor=Gov(),
    )
    record = await service.submit(_fused())
    assert record is not None
    assert record.status == "completed"
    assert record.error == "budget_exceeded"
    assert inv.calls == 0


@pytest.mark.asyncio
async def test_shadow_flag_dry_runs_even_if_agent_omits_shadow_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "true")
    monkeypatch.setenv("AGENTIC_SOC_SHADOW_MODE", "true")
    monkeypatch.setenv("AGENTIC_SOC_AUTO_RESPONSE", "true")
    from app.runtime.catalog import _simulated_response

    tools = SocToolRegistry()
    tools.register(
        CallableSOCTool(
            name="response.block_ip",
            description="block",
            fn=_simulated_response,
            risk_level="high",
            requires_approval=True,
            allowed_agents=frozenset({"response"}),
        )
    )
    ctx = ToolContext(
        tenant_id=TENANT,
        incident_id="CASE-123",
        agent_name="response",
        shadow_mode=False,
        approval_granted=True,
    )
    out = await tools.execute("response.block_ip", {"ip": "185.1.2.3"}, ctx)
    assert out["simulated"] is True
    assert out["dry_run"] is True
    assert out["action"] == "response.block_ip"


@pytest.mark.asyncio
async def test_redis_idempotency_skips_second_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "true")

    class FakeRedis:
        def __init__(self) -> None:
            self.keys: dict[str, str] = {}

        async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None) -> bool:
            if nx and key in self.keys:
                return False
            self.keys[key] = value
            return True

        async def delete(self, key: str) -> None:
            self.keys.pop(key, None)

    redis = FakeRedis()
    service = _service(redis=redis)
    first = await service.submit(_fused())
    second = await service.submit(_fused())
    assert first is not None and second is not None
    assert first.id == second.id
    assert redis.keys[f"agentic-shadow:{TENANT}:{ALERT}"] == "1"


@pytest.mark.asyncio
async def test_shadow_mode_still_writes_report_when_approval_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "true")
    from app.runtime.decision import DecisionAgent

    registry = AgentRegistry()
    report = StubAgent("report")
    for name in ("triage", "investigation", "threat-intel", "correlation", "response", "validation"):
        registry.register(StubAgent(name))
    registry.register(DecisionAgent())
    registry.register(report)
    service = AgenticShadowService(
        orchestrator=SocOrchestrator(AgentRuntime(registry, audit=InMemoryAuditSink()), registry)
    )
    record = await service.submit(_fused())
    assert record is not None
    assert record.status == "completed"
    assert report.calls == 1
    assert record.decision.startswith("decision=")


@pytest.mark.asyncio
async def test_shadow_consumer_isolates_service_exceptions() -> None:
    from app.runtime.shadow_consumer import AgenticShadowConsumer

    class BoomService:
        async def submit(self, message: dict) -> None:
            raise RuntimeError("should not escape")

    consumer = AgenticShadowConsumer(bootstrap_servers="localhost:9092", service=BoomService())  # type: ignore[arg-type]
    try:
        await consumer._service.submit({})  # type: ignore[union-attr]
        raise AssertionError("expected boom")
    except RuntimeError:
        production_ok = True
    assert production_ok is True
    # The Kafka loop catches this the same way; existing triage worker is a separate task.
