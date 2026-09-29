"""Unit tests for agentic funnel backfill classification."""

from __future__ import annotations

from app.services.agentic_funnel import classify_backfill


def test_existing_disposition_wins():
    assert classify_backfill({"disposition": "false_positive", "title": "Password Spray", "severity": "high"}) == "false_positive"


def test_attack_title_is_true_positive():
    assert classify_backfill({"title": "Detect Password Spray Attempts", "severity": "medium"}) == "true_positive"
    assert classify_backfill({"title": "Credential dumping", "severity": "low"}) == "true_positive"


def test_noisy_low_is_fp():
    assert classify_backfill({"title": "Network - Unapproved Port Activity Detected - Rule", "severity": "low"}) == "false_positive"


def test_high_severity_promotes():
    assert classify_backfill({"title": "Something odd", "severity": "critical"}) == "true_positive"
