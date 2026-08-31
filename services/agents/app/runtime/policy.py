"""Configurable HITL policy (spec §20). Thresholds are data, not prompt text."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ApprovalTier = Literal["none", "recommend", "mandatory", "critical"]


class ApprovalPolicy(BaseModel):
    auto_below: int = Field(default=40, ge=0, le=100)
    recommend_below: int = Field(default=70, ge=0, le=100)
    mandatory_below: int = Field(default=90, ge=0, le=100)


def approval_tier(risk_score: int, policy: ApprovalPolicy | None = None) -> ApprovalTier:
    cfg = policy or ApprovalPolicy()
    if risk_score < cfg.auto_below:
        return "none"
    if risk_score < cfg.recommend_below:
        return "recommend"
    if risk_score < cfg.mandatory_below:
        return "mandatory"
    return "critical"


def requires_human_approval(risk_score: int, policy: ApprovalPolicy | None = None) -> bool:
    return approval_tier(risk_score, policy) in {"mandatory", "critical"}
