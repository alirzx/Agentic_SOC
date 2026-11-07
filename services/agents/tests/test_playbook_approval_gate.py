"""An approval step must stop a playbook; an unsupported step must fail it.

Both behaviours were missing and both failed *open*:

* ``StepType.APPROVAL`` had no handler, so it fell through to the generic
  "no handler" branch, was recorded as SUCCESS with ``{"skipped": True}``, and the
  run continued — a playbook could isolate a host after an approval nobody gave.
* Every other handler-less step kind (``disable_user``, ``revoke_session``,
  ``kill_process``, ``block_ioc``, ...) did the same and reported success.

These tests pin the fail-closed behaviour so it cannot regress.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from app.playbook import engine as engine_mod
from app.playbook.engine import PlaybookEngine, RunStatus, StepStatus
from app.playbook.models import Playbook, PlaybookStep, StepType


def _make_playbook(steps: list[PlaybookStep]) -> Playbook:
    return Playbook(name="approval-test", steps=steps)


@pytest.fixture(autouse=True)
def _silence_realtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine_mod, "_emit", AsyncMock(return_value=None))


@pytest.fixture
def patch_handlers():
    saved: dict = {}

    def _install(mapping: dict) -> None:
        for key, value in mapping.items():
            saved[key] = engine_mod._HANDLERS.get(key)
            engine_mod._HANDLERS[key] = value

    yield _install

    for key, value in saved.items():
        if value is None:
            engine_mod._HANDLERS.pop(key, None)
        else:
            engine_mod._HANDLERS[key] = value


@pytest.mark.asyncio
async def test_approval_step_parks_the_run_before_the_next_step(patch_handlers) -> None:
    ran: list[str] = []

    async def isolate(step: PlaybookStep, ctx: dict, http: Any) -> dict:
        ran.append(step.name)
        return {"isolated": True}

    patch_handlers({StepType.ISOLATE_HOST: isolate})

    pb = _make_playbook(
        [
            PlaybookStep(id="s1", name="ask-analyst", type=StepType.APPROVAL),
            PlaybookStep(id="s2", name="isolate-host", type=StepType.ISOLATE_HOST),
        ]
    )

    run = await PlaybookEngine().run(pb, trigger_context={})

    assert run.status == RunStatus.PENDING_APPROVAL
    # The dangerous step never executed — that is the whole point of the gate.
    assert ran == []
    assert len(run.step_results) == 1
    assert run.step_results[0]["status"] == StepStatus.BLOCKED
    assert run.step_results[0]["result"]["requires_approval"] is True
    assert "requires analyst approval" in (run.error or "")


@pytest.mark.asyncio
async def test_approval_step_is_skipped_only_in_a_dry_run(patch_handlers) -> None:
    """A dry run executes nothing, so it reports the gate without parking the run."""
    ran: list[str] = []

    async def isolate(step: PlaybookStep, ctx: dict, http: Any) -> dict:  # pragma: no cover
        ran.append(step.name)
        return {"isolated": True}

    patch_handlers({StepType.ISOLATE_HOST: isolate})

    pb = _make_playbook(
        [
            PlaybookStep(id="s1", name="ask-analyst", type=StepType.APPROVAL),
            PlaybookStep(id="s2", name="isolate-host", type=StepType.ISOLATE_HOST),
        ]
    )

    run = await PlaybookEngine().run(pb, trigger_context={}, dry_run=True)

    assert run.status == RunStatus.COMPLETED
    assert run.step_results[0]["status"] == StepStatus.SKIPPED
    assert run.step_results[0]["result"]["would_require_approval"] is True
    # Nothing ran, not even under dry_run.
    assert ran == []


@pytest.mark.asyncio
async def test_unimplemented_step_type_fails_the_run_even_when_on_failure_is_continue() -> None:
    """Silently skipping a containment step is worse than stopping."""
    pb = _make_playbook(
        [
            PlaybookStep(
                id="s1",
                name="disable-account",
                type=StepType.DISABLE_USER,
                on_failure="continue",
            ),
            PlaybookStep(id="s2", name="close-case", type=StepType.CLOSE_CASE),
        ]
    )

    run = await PlaybookEngine().run(pb, trigger_context={})

    assert RunStatus.FAILED == run.status
    assert "no handler implemented" in (run.error or "")
    assert run.step_results[0]["status"] == StepStatus.FAILED
    assert run.step_results[0]["result"]["unsupported_step_type"] == "disable_user"
    # The run stopped there: no later step was recorded as executed.
    assert len(run.step_results) == 1


@pytest.mark.asyncio
async def test_dry_run_tolerates_an_unsupported_step() -> None:
    """Dry run never calls a handler, so an unimplemented kind is not a failure."""
    pb = _make_playbook(
        [PlaybookStep(id="s1", name="disable-account", type=StepType.DISABLE_USER)]
    )

    run = await PlaybookEngine().run(pb, trigger_context={}, dry_run=True)

    assert run.status == RunStatus.COMPLETED
    assert run.step_results[0]["result"].get("dry_run") is True
