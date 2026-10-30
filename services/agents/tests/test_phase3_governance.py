"""Governance gate for containment steps in the playbook engine.

Before the engine executes a containment action (``isolate_host``, ``block_ip``,
…, see ``_GOVERNED_STEP_TYPES``) it asks the API service's autonomy policy
(``POST /api/v1/governance/check``). If the policy wants a human, the run parks
as ``pending_approval`` on that step and nothing behind it executes — approving
releases the steps, it never replays the one that was gated.

The earlier version of this file called ``engine.execute(...)``, which the engine
has never had, so it failed at collection with ``AttributeError`` and the gate had
no executed coverage. These tests drive the real entry points: ``_check_governance``
directly (fail-closed paths) and ``PlaybookEngine._execute`` with its handlers and
policy check stubbed, which is exactly the seam ``run()`` uses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest
from app.playbook import engine as engine_module
from app.playbook.engine import (
    PlaybookEngine,
    PlaybookRun,
    RunStatus,
    StepStatus,
    StepType,
    _check_governance,
)
from app.playbook.models import Playbook, PlaybookStep


def _playbook(*steps: PlaybookStep) -> Playbook:
    return Playbook(
        id="test-playbook-isolation",
        name="Test: Host Isolation",
        description="Governance gating on containment",
        enabled=True,
        steps=list(steps),
    )


def _isolate_step() -> PlaybookStep:
    return PlaybookStep(
        id="step-isolate",
        name="Isolate Compromised Host",
        type=StepType.ISOLATE_HOST,
        params={"host": "prod-db-01", "reason": "Suspected compromise"},
    )


def _close_step() -> PlaybookStep:
    return PlaybookStep(
        id="step-close",
        name="Close Case",
        type=StepType.CLOSE_CASE,
        params={"disposition": "true_positive"},
    )


def _context(**overrides) -> dict:
    context = {
        "alert_id": "12345678-1234-5678-1234-567812345678",
        "id": "12345678-1234-5678-1234-567812345678",
        "severity": "critical",
        "confidence": 85,
        "affected_hosts": ["prod-db-01"],
        "tenant_id": "87654321-4321-8765-4321-876543218765",
    }
    context.update(overrides)
    return context


@pytest.fixture
def stub_handlers(monkeypatch):
    """Replace the containment handlers so no vendor is contacted.

    The gate runs *before* the handler, so a test about the gate must be able to
    say whether the handler ran at all — that is what these stubs record.
    """
    executed: list[str] = []

    async def _record(step, context, http):
        executed.append(step.type.value)
        return {"stub": True}

    handlers = dict(engine_module._HANDLERS)
    for step_type in (StepType.ISOLATE_HOST, StepType.CLOSE_CASE, StepType.BLOCK_IP):
        handlers[step_type] = _record
    monkeypatch.setattr(engine_module, "_HANDLERS", handlers)
    return executed


@pytest.mark.asyncio
async def test_containment_step_parks_the_run_when_policy_wants_a_human(
    monkeypatch, stub_handlers
) -> None:
    """A ``requires_approval`` answer parks the run on that step."""
    monkeypatch.setattr(
        engine_module,
        "_check_governance",
        AsyncMock(
            return_value={
                "decision": "requires_approval",
                "governance_level": "L2",
                "requires_approval": True,
                "approved": False,
                "reason": "critical severity requires analyst sign-off",
            }
        ),
    )

    playbook = _playbook(_isolate_step(), _close_step())
    pr = PlaybookRun(playbook, _context())
    await PlaybookEngine()._execute(pr, playbook, start_index=0, dry_run=False, http=AsyncMock())

    assert pr.status == RunStatus.PENDING_APPROVAL
    assert pr.gate_step_id == "step-isolate"
    # The gate is the step that was *not* run, so resuming starts at it.
    assert pr.next_step_index == 0
    assert "requires governance approval" in (pr.error or "")

    assert [r["step_id"] for r in pr.step_results] == ["step-isolate"]
    blocked = pr.step_results[0]
    assert blocked["status"] == StepStatus.BLOCKED
    assert blocked["result"]["governance_level"] == "L2"
    # Nothing behind the gate ran, and the gated handler did not run either.
    assert stub_handlers == []


@pytest.mark.asyncio
async def test_approved_step_executes_and_the_run_continues(monkeypatch, stub_handlers) -> None:
    """An ``approved`` answer lets the step run; the run reaches the next step."""
    monkeypatch.setattr(
        engine_module,
        "_check_governance",
        AsyncMock(
            return_value={
                "decision": "approved",
                "governance_level": "L1",
                "requires_approval": False,
                "approved": True,
                "reason": "low severity auto-approved",
            }
        ),
    )

    playbook = _playbook(_isolate_step(), _close_step())
    pr = PlaybookRun(playbook, _context(severity="low", confidence=30))
    await PlaybookEngine()._execute(pr, playbook, start_index=0, dry_run=False, http=AsyncMock())

    assert pr.status != RunStatus.PENDING_APPROVAL
    assert pr.gate_step_id is None
    assert stub_handlers == ["isolate_host", "close_case"]
    statuses = [r["status"] for r in pr.step_results]
    assert StepStatus.BLOCKED not in statuses


@pytest.mark.asyncio
async def test_dry_run_never_queries_governance(monkeypatch, stub_handlers) -> None:
    """A dry run touches no vendor and no policy check — it only simulates."""
    check = AsyncMock()
    monkeypatch.setattr(engine_module, "_check_governance", check)

    playbook = _playbook(_isolate_step())
    pr = PlaybookRun(playbook, _context())
    await PlaybookEngine()._execute(pr, playbook, start_index=0, dry_run=True, http=AsyncMock())

    check.assert_not_awaited()
    assert pr.status != RunStatus.PENDING_APPROVAL
    assert stub_handlers == []


# ── _check_governance: the fail-closed contract ───────────────────────────────


@pytest.mark.asyncio
async def test_governance_network_error_fails_closed() -> None:
    """An unreachable policy service must block the action, not allow it."""
    http = AsyncMock()
    http.post = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

    result = await _check_governance(_isolate_step(), _context(), "tenant-1", http)

    assert result["requires_approval"] is True
    assert result["approved"] is False


@pytest.mark.asyncio
async def test_governance_api_error_fails_closed() -> None:
    """A non-200 from the policy endpoint also blocks the action."""
    http = AsyncMock()
    response = httpx.Response(status_code=503, request=httpx.Request("POST", "http://api"))
    http.post = AsyncMock(return_value=response)

    result = await _check_governance(_isolate_step(), _context(), "tenant-1", http)

    assert result["requires_approval"] is True
    assert result["approved"] is False


@pytest.mark.asyncio
async def test_governance_sends_the_step_action_and_alert_facts() -> None:
    """The policy service decides on the step's action, not on the playbook."""
    http = AsyncMock()
    http.post = AsyncMock(
        return_value=httpx.Response(
            status_code=200,
            json={"requires_approval": False, "approved": True, "governance_level": "L1"},
            request=httpx.Request("POST", "http://api"),
        )
    )

    await _check_governance(_isolate_step(), _context(), "tenant-1", http)

    kwargs = http.post.await_args.kwargs
    assert kwargs["json"]["action_slug"] == StepType.ISOLATE_HOST.value
    assert kwargs["json"]["severity"] == "critical"
    assert kwargs["json"]["confidence"] == 85
    assert kwargs["headers"]["X-Tenant-Id"] == "tenant-1"
