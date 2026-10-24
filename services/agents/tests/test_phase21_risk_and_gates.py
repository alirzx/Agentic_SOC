"""Phase 2.1 — unified risk must not bypass Case gates or invent probability."""

from __future__ import annotations

from app.risk.unified import assess_unified_risk
from app.workers.case_promoter import should_promote


def test_risk_score_does_not_authorize_case_for_benign():
    risk = assess_unified_risk(
        alert_severity="critical",
        detection_confidence=0.99,
        asset_criticality_points=20,
        correlated_alert_count=5,
    )
    # Elevated prioritization score (exact band is provisional).
    assert risk.risk_score >= 50
    assert risk.investigation_priority in {"P0", "P1", "P2"}
    # Disposition still wins — high risk alone cannot promote FP/benign.
    assert should_promote(verdict="false_positive", severity="critical", confidence=0.99) is False
    assert should_promote(verdict="benign", severity="critical", confidence=0.99) is False


def test_needs_review_gate_unchanged_by_risk():
    assert should_promote(verdict="needs_review", severity="medium", confidence=0.69) is False
    assert should_promote(verdict="needs_review", severity="medium", confidence=0.70) is True
    assert should_promote(verdict="needs_review", severity="high", confidence=0.1) is True


def test_likely_tp_and_escalate_still_promote():
    assert should_promote(verdict="likely_tp", severity="low", confidence=0.1) is True
    assert should_promote(verdict="escalate", severity="info", confidence=0.0) is True
    assert should_promote(verdict="true_positive", severity="low", confidence=0.0) is True


def test_unified_risk_declares_provisional_not_probability():
    out = assess_unified_risk(alert_severity="high", detection_confidence=0.8)
    assert out.provisional is True
    assert 0 <= out.risk_score <= 100
    assert 0.0 <= out.detection_confidence <= 1.0
    assert 0.0 <= out.incident_confidence <= 1.0
    blob = " ".join(out.reasons).lower()
    assert "provisional" in blob
    assert "probability" in blob or "not a calibrated" in blob
