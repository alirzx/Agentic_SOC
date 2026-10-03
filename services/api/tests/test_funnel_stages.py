"""Unit tests for product funnel stages + investigation / Jira gates."""

from __future__ import annotations

from app.services.funnel_stages import (
    READY_FOR_JIRA,
    SUPPRESSED,
    TRIAGED,
    passes_investigation_gate,
    passes_jira_gate,
    stage_after_triage,
)
from app.services.incident_report import build_incident_report


def test_stage_after_triage_suppresses_fp():
    assert stage_after_triage(disposition="false_positive", auto_closed=True) == SUPPRESSED
    assert stage_after_triage(disposition="benign", auto_closed=False) == SUPPRESSED
    assert stage_after_triage(disposition="true_positive", auto_closed=False) == TRIAGED


def test_investigation_gate_blocks_noise():
    assert not passes_investigation_gate(
        disposition="false_positive", severity="critical", confidence=0.99
    )
    assert not passes_investigation_gate(
        disposition="needs_review", severity="low", confidence=0.9
    )


def test_investigation_gate_allows_tp_and_high_needs_review():
    assert passes_investigation_gate(
        disposition="true_positive", severity="low", confidence=0.4
    )
    assert passes_investigation_gate(
        disposition="needs_review", severity="high", confidence=0.3
    )
    assert passes_investigation_gate(
        disposition="needs_review", severity="medium", confidence=0.75
    )
    assert not passes_investigation_gate(
        disposition="needs_review", severity="medium", confidence=0.5
    )


def test_jira_gate_blocks_fp_and_unapproved_needs_review():
    assert not passes_jira_gate(disposition="false_positive")
    assert not passes_jira_gate(disposition="needs_review", analyst_approved=False)
    assert passes_jira_gate(disposition="needs_review", analyst_approved=True)
    assert passes_jira_gate(disposition="true_positive")
    assert passes_jira_gate(disposition="escalate")
    # Legacy unknown disposition still allowed (operator-selected ITSM).
    assert passes_jira_gate(disposition=None)


def test_incident_report_has_required_sections():
    md = build_incident_report(
        title="Password spray on VPN",
        severity="high",
        disposition="true_positive",
        confidence=0.88,
        summary="Multiple failed logins from one source IP.",
        mitre_techniques=["T1110"],
        hosts=["vpn-gw-1"],
        ips=["203.0.113.9"],
        evidence=["Ledger: recon confirmed spray pattern"],
        recommended_actions=["Reset targeted accounts", "Block source IP"],
        case_id="11111111-1111-1111-1111-111111111111",
    )
    assert "## Executive summary" in md
    assert "## MITRE ATT&CK" in md
    assert "T1110" in md
    assert "## Recommended actions" in md
    assert READY_FOR_JIRA  # sanity: constant imported / stage vocabulary stable
    assert "88%" in md
