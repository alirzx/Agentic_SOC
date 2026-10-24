"""Unified, explainable risk assessment (Phase 2) — provisional weights.

Separates concepts that must not be conflated:
* alert_severity — vendor / rule severity
* detection_confidence — triage confidence (0–1)
* incident_confidence — correlation / multi-evidence strength (0–1)
* business_impact — asset criticality contribution (0–20)
* risk_score — bounded 0–100 prioritization score (NOT a probability)
* investigation_priority / response_urgency — derived bands

Delegates numeric scoring to ``app.runtime.risk.score_risk`` so the shadow
orchestrator and triage path share one function. Does **not** authorize Case
creation or response actions by itself.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.runtime.risk import RiskAssessment, RiskFactors, score_risk

Priority = Literal["P4", "P3", "P2", "P1", "P0"]
Urgency = Literal["routine", "elevated", "urgent", "immediate"]


class UnifiedRiskResult(BaseModel):
    """Contract for triage / UI — provisional calibration."""

    alert_severity: str
    detection_confidence: float = Field(ge=0.0, le=1.0)
    incident_confidence: float = Field(ge=0.0, le=1.0)
    business_impact: int = Field(ge=0, le=20)
    risk_score: int = Field(ge=0, le=100)
    risk_band: str
    investigation_priority: Priority
    response_urgency: Urgency
    reasons: list[str]
    provisional: bool = True
    factors: dict[str, Any] = Field(default_factory=dict)


def _as_unit(value: float | int | None) -> float:
    if value is None:
        return 0.0
    v = float(value)
    if v > 1.0:
        v = v / 100.0
    return max(0.0, min(1.0, v))


def _priority(score: int) -> Priority:
    if score >= 85:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 50:
        return "P2"
    if score >= 30:
        return "P3"
    return "P4"


def _urgency(score: int, *, detection_confidence: float) -> Urgency:
    if score >= 85 and detection_confidence >= 0.7:
        return "immediate"
    if score >= 70:
        return "urgent"
    if score >= 50:
        return "elevated"
    return "routine"


def assess_unified_risk(
    *,
    alert_severity: str = "medium",
    detection_confidence: float | int | None = 0.0,
    correlated_alert_count: int = 1,
    asset_criticality_points: int = 0,
    threat_intel_points: int = 0,
    behavioral_points: int = 0,
    attack_chain_points: int = 0,
    user_privilege_points: int = 0,
) -> UnifiedRiskResult:
    """Deterministic unified risk. Missing inputs contribute 0 — never guessed."""
    det_conf = _as_unit(detection_confidence)
    # Incident confidence rises with independent correlated members (capped).
    incident_conf = min(1.0, 0.35 + 0.15 * max(0, correlated_alert_count - 1) + 0.25 * det_conf)
    business = max(0, min(20, int(asset_criticality_points)))
    corr_pts = max(0, min(10, (correlated_alert_count - 1) * 3))
    factors = RiskFactors(
        alert_severity=(alert_severity or "medium").lower(),
        asset_criticality=business,
        user_privilege=max(0, min(15, int(user_privilege_points))),
        threat_intel=max(0, min(15, int(threat_intel_points))),
        behavioral_anomaly=max(0, min(10, int(behavioral_points))),
        correlation=corr_pts,
        attack_chain=max(0, min(15, int(attack_chain_points))),
    )
    assessment: RiskAssessment = score_risk(factors)
    reasons = list(assessment.reasons)
    reasons.append("provisional weights — not a calibrated probability")
    if correlated_alert_count > 1:
        reasons.append(f"{correlated_alert_count} correlated alerts in fusion incident")
    return UnifiedRiskResult(
        alert_severity=factors.alert_severity,
        detection_confidence=det_conf,
        incident_confidence=round(incident_conf, 3),
        business_impact=business,
        risk_score=assessment.score,
        risk_band=assessment.band,
        investigation_priority=_priority(assessment.score),
        response_urgency=_urgency(assessment.score, detection_confidence=det_conf),
        reasons=reasons,
        provisional=True,
        factors=factors.model_dump(),
    )
