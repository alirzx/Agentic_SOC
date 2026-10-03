"""Unit tests for agentic funnel backfill classification + stage derive."""

from __future__ import annotations

from uuid import uuid4

from app.services.agentic_funnel import classify_backfill, derive_funnel_stage
from app.services.funnel_stages import passes_jira_gate


def test_existing_disposition_wins():
    assert classify_backfill({"disposition": "false_positive", "title": "Password Spray", "severity": "high"}) == "false_positive"


def test_attack_title_is_true_positive():
    assert classify_backfill({"title": "Detect Password Spray Attempts", "severity": "medium"}) == "true_positive"
    assert classify_backfill({"title": "Credential dumping", "severity": "low"}) == "true_positive"


def test_noisy_low_is_fp():
    assert classify_backfill({"title": "Network - Unapproved Port Activity Detected - Rule", "severity": "low"}) == "false_positive"


def test_high_severity_promotes():
    assert classify_backfill({"title": "Something odd", "severity": "critical"}) == "true_positive"


def test_backfill_tp_is_jira_eligible():
    disp = classify_backfill({"title": "Detect Password Spray Attempts", "severity": "medium"})
    assert passes_jira_gate(disposition=disp)


def test_backfill_fp_is_not_jira_eligible():
    disp = classify_backfill(
        {"title": "Network - Unapproved Port Activity Detected - Rule", "severity": "low"}
    )
    assert not passes_jira_gate(disposition=disp)


def test_derive_funnel_stage_legacy_paths():
    assert derive_funnel_stage({"disposition": "false_positive"}) == "suppressed"
    assert derive_funnel_stage({"disposition": "true_positive"}) == "triaged"
    assert derive_funnel_stage({"disposition": None, "status": "investigating"}) == "investigating"
    case_id = uuid4()
    assert derive_funnel_stage({"case_id": case_id, "disposition": "needs_review"}) == "cased"
    assert (
        derive_funnel_stage(
            {"case_id": case_id, "disposition": "true_positive"},
            has_external_ref=False,
        )
        == "ready_for_jira"
    )
    assert (
        derive_funnel_stage(
            {"case_id": case_id, "disposition": "true_positive"},
            has_external_ref=True,
        )
        == "jira_pushed"
    )
    assert derive_funnel_stage({}) == "ingested"
