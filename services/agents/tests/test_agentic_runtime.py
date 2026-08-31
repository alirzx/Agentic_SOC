"""Unit tests for the Soorin runtime contracts layered on AiSOC.

Offline and deterministic. Existing LangGraph / four-agent façade behaviour
is not exercised except for the heuristic triage adapter.
"""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.runtime.adapters import CorrelationRuntimeAgent, TriageRuntimeAgent
from app.runtime.audit import InMemoryAuditSink
from app.runtime.catalog import build_agent_registry
from app.runtime.contracts import (
    AgentContext,
    AgentConstraints,
    Evidence,
    EvidenceProvenance,
    Finding,
    IncidentStateSnapshot,
    hash_payload,
)
from app.runtime.decision import DecisionAgent
from app.runtime.evidence import build_evidence_graph
from app.runtime.hypothesis import Hypothesis, reject_hypothesis
from app.runtime.idempotency import IdempotencyStore
from app.runtime.incident import IllegalTransitionError, IncidentState, IncidentStateMachine
from app.runtime.locks import IncidentLock, IncidentLockBusy
from app.runtime.policy import approval_tier, requires_human_approval
from app.runtime.registry import UnknownAgentError
from app.runtime.reports import IncidentReportPackage, ReportAgent
from app.runtime.response import ResponseAgent
from app.runtime.risk import RiskFactors, band_for, score_risk
from app.runtime.runtime import AgentLoopLimitError, AgentRuntime
from app.runtime.tools import ToolContext, ToolPermissionDenied, UnknownToolError
from app.runtime.validation import ValidationAgent


def _context(**kwargs: object) -> AgentContext:
    base = dict(
        incident_id=str(uuid4()),
        tenant_id=str(uuid4()),
        objective="brute force against vpn.corp.example",
        state=IncidentStateSnapshot(
            state="NEW",
            severity="high",
            raw_alert={"severity": "high", "src_ip": "185.1.2.3"},
        ),
    )
    base.update(kwargs)
    return AgentContext(**base)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_evidence_hash_is_stable() -> None:
    first = Evidence(incident_id="inc-1", type="auth", source="siem", data={"count": 127})
    second = Evidence(incident_id="inc-1", type="auth", source="siem", data={"count": 127})
    assert first.hash == second.hash
    assert first.hash == hash_payload({"count": 127})
    assert len(first.hash) == 64


@pytest.mark.asyncio
async def test_registry_rejects_unknown_agent() -> None:
    registry = build_agent_registry()
    with pytest.raises(UnknownAgentError):
        registry.get("swarm")
    assert "triage:v1.0" in registry.names()
    assert "decision:v1.0" in registry.names()


@pytest.mark.asyncio
async def test_runtime_audits_success_and_enforces_loop_limit() -> None:
    registry = build_agent_registry()
    sink = InMemoryAuditSink()
    runtime = AgentRuntime(registry, audit=sink)
    result = await runtime.run("correlation", _context())
    assert result.status == "success"
    types = [event["type"] for event in sink.events]
    assert types == ["AGENT_STARTED", "AGENT_COMPLETED"]
    limited = _context(constraints=AgentConstraints(max_iterations=1), iteration=1)
    with pytest.raises(AgentLoopLimitError):
        await runtime.run("correlation", limited)


@pytest.mark.asyncio
async def test_tool_permission_engine_blocks_response_without_approval() -> None:
    from app.runtime.catalog import _simulated_response
    from app.runtime.tools import CallableSOCTool, SocToolRegistry

    tools = SocToolRegistry()
    tools.register(
        CallableSOCTool(
            name="response.isolate_asset",
            description="Isolate an asset (simulated).",
            fn=_simulated_response,
            risk_level="high",
            requires_approval=True,
            allowed_agents=frozenset({"decision", "response"}),
        )
    )
    ctx = ToolContext(
        tenant_id="t1",
        incident_id="i1",
        agent_name="response",
        role="analyst",
        approval_granted=False,
    )
    with pytest.raises(ToolPermissionDenied):
        await tools.execute("response.isolate_asset", {"asset_id": "host-1"}, ctx)
    ctx.approval_granted = True
    out = await tools.execute("response.isolate_asset", {"asset_id": "host-1"}, ctx)
    assert out["dry_run"] is True
    with pytest.raises(UnknownToolError):
        await tools.execute("shell.exec", {}, ctx)


@pytest.mark.asyncio
async def test_incident_state_machine_allows_spec_path_and_rejects_skip() -> None:
    machine = IncidentStateMachine()
    machine.transition(IncidentState.TRIAGING)
    machine.transition(IncidentState.INVESTIGATING)
    machine.transition(IncidentState.CORRELATING)
    machine.transition(IncidentState.RISK_ASSESSMENT)
    machine.transition(IncidentState.DECISION)
    machine.transition(IncidentState.REPORTING)
    machine.transition(IncidentState.RESOLVED)
    machine.transition(IncidentState.CLOSED)
    with pytest.raises(IllegalTransitionError):
        machine.transition(IncidentState.NEW)


def test_risk_engine_is_deterministic_and_not_llm() -> None:
    low = score_risk(RiskFactors(alert_severity="info"))
    high = score_risk(
        RiskFactors(
            alert_severity="critical",
            asset_criticality=20,
            user_privilege=15,
            threat_intel=15,
            behavioral_anomaly=10,
            correlation=10,
            attack_chain=15,
        )
    )
    assert low.score == 0
    assert low.band == "LOW"
    assert high.score == 100
    assert high.band == "EMERGENCY"
    assert band_for(70) == "CRITICAL"
    assert band_for(85) == "EMERGENCY"
    assert score_risk(RiskFactors(alert_severity="high")).score == 25


@pytest.mark.asyncio
async def test_decision_agent_requires_approval_above_policy() -> None:
    agent = DecisionAgent()
    ctx = _context(
        state=IncidentStateSnapshot(
            state="DECISION",
            severity="critical",
            confidence=0.9,
            raw_alert={
                "severity": "critical",
                "asset_criticality": 20,
                "user_privilege": 15,
                "threat_intel": 15,
                "attack_chain": 15,
            },
        )
    )
    result = await agent.execute(ctx)
    assert result.status == "success"
    assert "EMERGENCY" in result.findings[0].statement or "CRITICAL" in result.findings[0].statement
    assert any(task.agent == "response" for task in result.next_tasks)
    assert requires_human_approval(94) is True
    assert approval_tier(20) == "none"
    assert approval_tier(55) == "recommend"
    assert approval_tier(80) == "mandatory"
    assert approval_tier(95) == "critical"


@pytest.mark.asyncio
async def test_validation_agent_escalates_on_failed_containment() -> None:
    agent = ValidationAgent()
    failed = await agent.execute(
        _context(state=IncidentStateSnapshot(raw_alert={"ioc_still_seen": True}))
    )
    assert failed.status == "blocked"
    assert failed.next_tasks[0].agent == "investigation"
    ok = await agent.execute(
        _context(state=IncidentStateSnapshot(raw_alert={"containment_effective": True}))
    )
    assert ok.status == "success"
    assert ok.next_tasks[0].agent == "report"


@pytest.mark.asyncio
async def test_report_package_requires_uncertainties() -> None:
    with pytest.raises(ValidationError):
        IncidentReportPackage(
            incident_id="i",
            title="t",
            executive_summary="s",
        )
    agent = ReportAgent()
    result = await agent.execute(_context())
    assert result.uncertainty
    assert "report_package_ready" in result.findings[0].statement


@pytest.mark.asyncio
async def test_hypothesis_can_be_rejected() -> None:
    hypothesis = Hypothesis(name="brute_force", statement="credential stuffing", confidence=0.8)
    rejected = reject_hypothesis(hypothesis, evidence_ids=["ev-1"], reason="successful MFA")
    assert rejected.status == "rejected"
    assert rejected.confidence <= 0.2


@pytest.mark.asyncio
async def test_triage_adapter_wraps_existing_heuristic() -> None:
    pytest.importorskip("langchain_core")
    agent = TriageRuntimeAgent()
    result = await agent.execute(_context())
    assert result.status == "success"
    assert result.next_tasks[0].agent == "investigation"
    assert result.evidence[0].provenance is not None
    assert result.evidence[0].provenance.agent == "triage"


@pytest.mark.asyncio
async def test_correlation_and_response_dry_run() -> None:
    corr = await CorrelationRuntimeAgent().execute(_context())
    assert corr.status == "success"
    blocked = await ResponseAgent().execute(
        _context(
            previous_actions=[],
            metadata={},
        )
    )
    # plan_only is read risk so it simulates
    assert blocked.status in {"success", "blocked"}
    from app.runtime.contracts import AgentAction

    high = await ResponseAgent().execute(
        _context(
            previous_actions=[
                AgentAction(name="isolate_asset", tool="response.isolate_asset", risk_level="high")
            ]
        )
    )
    assert high.status == "blocked"


@pytest.mark.asyncio
async def test_idempotency_and_nonblocking_lock() -> None:
    store = IdempotencyStore()
    key = store.key(tenant_id="t", incident_id="i", agent="triage", objective="same")
    assert store.seen(key) is False
    store.remember(key, "abc")
    assert store.seen(key) is True
    lock = IncidentLock()
    async with lock.acquire("inc-1"):
        with pytest.raises(IncidentLockBusy):
            async with lock.acquire("inc-1", blocking=False):
                pass


@pytest.mark.asyncio
async def test_evidence_graph_walks_finding_to_source() -> None:
    evidence = Evidence(
        incident_id="i",
        type="auth_failures",
        source="elasticsearch",
        data={"count": 127},
        provenance=EvidenceProvenance(
            agent="investigation",
            agent_version="1.0",
            tool="siem.search_authentication",
            query_id="Q-1",
            source="elasticsearch",
        ),
    )
    finding = Finding(statement="Likely credential attack", evidence_ids=[evidence.id], confidence=0.9)
    graph = build_evidence_graph(findings=[finding], evidence=[evidence])
    chain = graph.cite_chain(finding.id)
    assert chain[0] == finding.id
    assert evidence.id in chain
    assert chain[-1] == "source:elasticsearch"


@pytest.mark.asyncio
async def test_orchestrator_advances_state_machine_with_stub_agents() -> None:
    from app.runtime.contracts import Agent, AgentResult, NextTask
    from app.runtime.orchestrator import SocOrchestrator
    from app.runtime.registry import AgentRegistry

    class StubAgent(Agent):
        def __init__(self, name: str, next_agent: str, objective: str = "continue") -> None:
            self.name = name
            self.version = "1.0"
            self._next_agent = next_agent
            self._objective = objective

        async def execute(self, context: AgentContext) -> AgentResult:
            return AgentResult(
                status="success",
                next_tasks=[NextTask(agent=self._next_agent, objective=self._objective)],
                reasoning=self.name,
            )

    registry = AgentRegistry()
    for name, nxt in (
        ("triage", "investigation"),
        ("investigation", "correlation"),
        ("correlation", "decision"),
        ("decision", "report"),
        ("response", "validation"),
        ("validation", "report"),
        ("report", "runtime"),
    ):
        registry.register(StubAgent(name, nxt, "write_report" if name == "decision" else "continue"))
    runtime = AgentRuntime(registry, audit=InMemoryAuditSink())
    orch = SocOrchestrator(runtime, registry)
    ctx = _context(metadata={"skip_investigation": True})
    results = await orch.run(ctx)
    names = [item.reasoning for item in results]
    assert "triage" in names
    assert "correlation" in names
    assert "decision" in names
    assert "report" in names
    assert ctx.state.state == "RESOLVED"
