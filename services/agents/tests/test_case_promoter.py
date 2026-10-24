"""Acceptance tests for agentic case promotion policy (mission Feature 8)."""

from __future__ import annotations

import uuid

import pytest
from app.models.state import AgentStatus, InvestigationState
from app.workers import case_promoter
from app.workers.case_promoter import auto_case_enabled, should_promote


def test_true_positive_always_promotes():
    assert should_promote(verdict="true_positive", severity="low", confidence=0.4) is True
    assert should_promote(verdict="true_positive", severity="critical", confidence=0.9) is True


def test_escalate_and_likely_tp_promote():
    assert should_promote(verdict="escalate", severity="low", confidence=0.1) is True
    assert should_promote(verdict="likely_tp", severity="medium", confidence=0.5) is True
    assert should_promote(verdict="likely_true_positive", severity="info", confidence=0.2) is True


def test_false_positive_never_promotes():
    assert should_promote(verdict="false_positive", severity="critical", confidence=0.99) is False
    assert should_promote(verdict="benign_true_positive", severity="high", confidence=0.9) is False
    assert should_promote(verdict="benign", severity="critical", confidence=0.99) is False


def test_needs_review_promotes_high_or_confident_medium():
    assert should_promote(verdict="needs_review", severity="high", confidence=0.2) is True
    assert should_promote(verdict="needs_review", severity="critical", confidence=0.1) is True
    assert should_promote(verdict="needs_review", severity="medium", confidence=0.7) is True
    assert should_promote(verdict="needs_review", severity="medium", confidence=0.69) is False
    assert should_promote(verdict="needs_review", severity="low", confidence=0.9) is False


def test_auto_case_flag_defaults_on_and_can_disable(monkeypatch):
    monkeypatch.delenv("AISOC_AGENT_AUTO_CASE", raising=False)
    assert auto_case_enabled() is True
    monkeypatch.setenv("AISOC_AGENT_AUTO_CASE", "0")
    assert auto_case_enabled() is False
    monkeypatch.setenv("AISOC_AGENT_AUTO_CASE", "false")
    assert auto_case_enabled() is False
    monkeypatch.setenv("AISOC_AGENT_AUTO_CASE", "1")
    assert auto_case_enabled() is True


@pytest.mark.asyncio
async def test_promote_to_case_respects_disabled_flag(monkeypatch):
    monkeypatch.setenv("AISOC_AGENT_AUTO_CASE", "0")
    state = InvestigationState(
        run_id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        alert_summary="TP spray",
        raw_alert={"id": str(uuid.uuid4()), "severity": "high"},
        status=AgentStatus.RUNNING,
        verdict="true_positive",
        confidence=0.95,
    )
    assert await case_promoter.promote_to_case(state, message={"alert": state.raw_alert}) is None
