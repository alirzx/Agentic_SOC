"""Unified risk engine — provisional, explainable, deterministic."""

from __future__ import annotations

from app.risk.unified import assess_unified_risk


def test_deterministic_for_same_inputs():
    a = assess_unified_risk(alert_severity="high", detection_confidence=0.8, asset_criticality_points=15)
    b = assess_unified_risk(alert_severity="high", detection_confidence=0.8, asset_criticality_points=15)
    assert a.risk_score == b.risk_score
    assert a.investigation_priority == b.investigation_priority
    assert a.provisional is True


def test_missing_inputs_do_not_invent_impact():
    out = assess_unified_risk(alert_severity="low", detection_confidence=0.1)
    assert out.business_impact == 0
    assert out.risk_score < 50


def test_asset_criticality_raises_priority_not_proof():
    base = assess_unified_risk(alert_severity="medium", detection_confidence=0.5)
    hot = assess_unified_risk(
        alert_severity="medium",
        detection_confidence=0.5,
        asset_criticality_points=20,
    )
    assert hot.risk_score > base.risk_score
    assert "provisional" in " ".join(hot.reasons).lower()


def test_correlation_increases_incident_confidence():
    one = assess_unified_risk(alert_severity="medium", detection_confidence=0.6, correlated_alert_count=1)
    many = assess_unified_risk(alert_severity="medium", detection_confidence=0.6, correlated_alert_count=4)
    assert many.incident_confidence > one.incident_confidence
