"""Deterministic risk engine (spec §17). LLM must never set the final score."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

RiskBand = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "EMERGENCY"]

SEVERITY_POINTS: dict[str, int] = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 25,
    "critical": 35,
}


class RiskFactors(BaseModel):
    """All inputs are numeric contributions. Missing evidence → 0, never guessed."""

    alert_severity: str = "medium"
    asset_criticality: int = Field(default=0, ge=0, le=20)
    user_privilege: int = Field(default=0, ge=0, le=15)
    threat_intel: int = Field(default=0, ge=0, le=15)
    behavioral_anomaly: int = Field(default=0, ge=0, le=10)
    correlation: int = Field(default=0, ge=0, le=10)
    attack_chain: int = Field(default=0, ge=0, le=15)


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    band: RiskBand
    factors: RiskFactors
    reasons: list[str]


def band_for(score: int) -> RiskBand:
    if score >= 85:
        return "EMERGENCY"
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def score_risk(factors: RiskFactors) -> RiskAssessment:
    severity = SEVERITY_POINTS.get(factors.alert_severity.lower(), 15)
    total = (
        severity
        + factors.asset_criticality
        + factors.user_privilege
        + factors.threat_intel
        + factors.behavioral_anomaly
        + factors.correlation
        + factors.attack_chain
    )
    score = max(0, min(100, total))
    reasons: list[str] = []
    if severity >= 25:
        reasons.append(f"alert severity {factors.alert_severity}")
    if factors.asset_criticality >= 10:
        reasons.append("critical or high-value asset")
    if factors.user_privilege >= 8:
        reasons.append("privileged account")
    if factors.threat_intel >= 8:
        reasons.append("malicious IOC / campaign match")
    if factors.behavioral_anomaly >= 5:
        reasons.append("behavioral anomaly")
    if factors.correlation >= 5:
        reasons.append("correlated related alerts")
    if factors.attack_chain >= 8:
        reasons.append("multi-stage attack chain")
    if not reasons:
        reasons.append("insufficient amplifying factors")
    return RiskAssessment(score=score, band=band_for(score), factors=factors, reasons=reasons)
