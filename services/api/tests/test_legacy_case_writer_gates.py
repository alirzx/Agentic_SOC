"""Retired automatic case writers must stay off unless a rollback is explicit.

`services/correlation` owns automatic case creation. Every legacy producer keeps
its code for rollback/reference but is gated; these tests pin the gate defaults
so a future edit cannot silently re-enable a second writer.
"""

from __future__ import annotations

import uuid

import pytest
from app.services import agentic_funnel, exact_dedupe, tier2_ip_pivot
from app.services.tier2_adaptive import case_policy

_GATES = (
    agentic_funnel.legacy_case_writes_enabled,
    exact_dedupe.legacy_case_mutations_enabled,
    tier2_ip_pivot.legacy_case_writes_enabled,
    case_policy.legacy_case_writes_enabled,
)


@pytest.fixture(autouse=True)
def _clear_gate_env(monkeypatch):
    monkeypatch.delenv("AISOC_CORRELATION_CASE_WRITER_ONLY", raising=False)
    monkeypatch.delenv("AISOC_AGENT_AUTO_CASE", raising=False)


def test_every_legacy_writer_defaults_off():
    assert [gate() for gate in _GATES] == [False] * len(_GATES)


def test_explicit_rollback_enables_every_legacy_writer(monkeypatch):
    monkeypatch.setenv("AISOC_CORRELATION_CASE_WRITER_ONLY", "0")
    monkeypatch.setenv("AISOC_AGENT_AUTO_CASE", "1")
    assert [gate() for gate in _GATES] == [True] * len(_GATES)


def test_writer_only_flag_wins_over_rollback_opt_in(monkeypatch):
    monkeypatch.setenv("AISOC_CORRELATION_CASE_WRITER_ONLY", "1")
    monkeypatch.setenv("AISOC_AGENT_AUTO_CASE", "1")
    assert [gate() for gate in _GATES] == [False] * len(_GATES)


class _ExplodingSession:
    """Any DB use means a gated writer ran when it should not have."""

    async def execute(self, *args, **kwargs):
        raise AssertionError("legacy writer touched the database while disabled")

    async def commit(self):
        raise AssertionError("legacy writer committed while disabled")


@pytest.mark.asyncio
async def test_exact_case_merge_is_a_noop_while_writer_only():
    result = await exact_dedupe.dedupe_exact_cases(_ExplodingSession(), tenant_id=uuid.uuid4())
    assert result["ok"] is False
    assert result["error"] == "legacy_writer_disabled"
    assert result["cases_deleted"] == 0


@pytest.mark.asyncio
async def test_tier2_pivot_returns_no_case_while_writer_only():
    class _NoIps:
        src_ips: list[str] = []
        dest_ips: list[str] = []

    case_id, created, extended = await tier2_ip_pivot.aggregate_into_case(
        _ExplodingSession(),
        tenant_id=uuid.uuid4(),
        seed=None,
        alert_ids=[],
        ips=_NoIps(),
    )
    assert case_id is None
    assert (created, extended) == (False, False)
