"""Router topology keeps tenant privacy bound for run and stream lifetimes."""

from __future__ import annotations

import uuid

import pytest
from app.models.state import AgentStatus, InvestigationState
from app.orchestrator import router as router_module
from app.orchestrator.router import RouterOrchestrator
from app.privacy.context import current_privacy_gateway

KEY = "router-privacy-0123456789abcdef012345"


@pytest.fixture
def privacy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", KEY)


def _state() -> InvestigationState:
    return InvestigationState(
        incident_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        alert_summary="Synthetic router privacy alert",
        raw_alert={"hostname": "endpoint01.corp.synthetic.test"},
    )


async def test_router_run_binds_privacy_for_auto_triage_and_early_exit(privacy, monkeypatch) -> None:
    state = _state()

    async def _auto_triage(current: InvestigationState) -> InvestigationState:
        gateway = current_privacy_gateway()
        assert gateway is not None
        assert gateway.tenant_id == str(state.tenant_id)
        current.status = AgentStatus.COMPLETED
        return current

    monkeypatch.setattr(router_module, "_run_auto_triage_step", _auto_triage)
    final, info = await RouterOrchestrator().run(state, topology="sequential")
    assert final.status == AgentStatus.COMPLETED
    assert info["auto_closed"] is True


async def test_router_stream_keeps_privacy_bound_across_yields(privacy, monkeypatch) -> None:
    state = _state()
    observations: list[str] = []

    async def _bound(self, current: InvestigationState, *, topology=None):
        gateway = current_privacy_gateway()
        assert gateway is not None
        observations.append(gateway.tenant_id)
        yield {"type": "step", "agent": "synthetic"}
        gateway = current_privacy_gateway()
        assert gateway is not None
        observations.append(gateway.tenant_id)
        yield {"type": "done"}

    monkeypatch.setattr(RouterOrchestrator, "_stream_bound", _bound)
    events = [event async for event in RouterOrchestrator().stream(state, topology="parallel")]
    assert [event["type"] for event in events] == ["step", "done"]
    assert observations == [str(state.tenant_id), str(state.tenant_id)]
