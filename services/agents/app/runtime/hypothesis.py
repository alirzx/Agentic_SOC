"""Hypothesis create / test / reject (spec §63–64)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

HypothesisStatus = Literal["open", "supported", "rejected", "inconclusive"]


class Hypothesis(BaseModel):
    name: str
    statement: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: HypothesisStatus = "open"
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    reason: str = ""


def reject_hypothesis(hypothesis: Hypothesis, *, evidence_ids: list[str], reason: str) -> Hypothesis:
    return hypothesis.model_copy(
        update={
            "status": "rejected",
            "contradicting_evidence_ids": list(evidence_ids),
            "reason": reason,
            "confidence": min(hypothesis.confidence, 0.2),
        }
    )


def support_hypothesis(hypothesis: Hypothesis, *, evidence_ids: list[str], reason: str) -> Hypothesis:
    return hypothesis.model_copy(
        update={
            "status": "supported",
            "supporting_evidence_ids": list(evidence_ids),
            "reason": reason,
        }
    )
