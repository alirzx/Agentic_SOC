"""Three-tier confidence thresholds for governed actions (Runbook Phase 0).

The tiers are cutoffs on the *confidence* the deciding agent reports for a
proposed action:

* ``auto``       — at or above this, act without a human
* ``review``     — at or above this (but below ``auto``) → queue for an analyst
* ``escalation`` — at or above this (but below ``review``) → page the on-call
* below ``escalation`` → reject outright

Invariant: ``escalation <= review <= auto``, all inside ``[0.0, 1.0]``.

Why this module exists separately from the agents service
--------------------------------------------------------
The authoritative runtime copy is ``services/agents/app/policy/guardrails.py``.
The API service ships as its own container, so it cannot import that package —
the values are mirrored here and kept identical by
``tests/test_runbook_thresholds.py::test_catalog_matches_guardrails``, which
parses the agents module with ``ast`` and fails on any drift.

Semantics here are intentionally byte-for-byte the same as guardrails':
``review`` defaults to ``auto - 0.1`` and ``escalation`` to ``review - 0.2``
so a definition that only supplies ``auto`` behaves identically on both sides.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "AutonomyDecision",
    "ActionThresholds",
    "DEFAULT_REQUIRE_ANALYST",
    "make_thresholds",
]


class AutonomyDecision(str, Enum):
    """What the policy says to do with a proposed action."""

    AUTO = "auto"
    REVIEW = "review"
    ESCALATE = "escalate"
    REJECT = "reject"


@dataclass(frozen=True)
class ActionThresholds:
    """Three confidence cutoffs for a single action.

    Invariant: ``escalation <= review <= auto`` and all are in ``[0.0, 1.0]``.
    """

    auto: float
    review: float
    escalation: float

    def decide(self, confidence: float) -> AutonomyDecision:
        """Classify a confidence value into one autonomy decision."""
        if confidence >= self.auto:
            return AutonomyDecision.AUTO
        if confidence >= self.review:
            return AutonomyDecision.REVIEW
        if confidence >= self.escalation:
            return AutonomyDecision.ESCALATE
        return AutonomyDecision.REJECT

    def to_dict(self) -> dict[str, float]:
        return {"auto": self.auto, "review": self.review, "escalation": self.escalation}


# An action the catalog does not know about is treated as "always ask a human".
DEFAULT_REQUIRE_ANALYST = ActionThresholds(auto=1.0, review=1.0, escalation=1.0)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def make_thresholds(
    auto: float,
    review: float | None = None,
    escalation: float | None = None,
) -> ActionThresholds:
    """Build normalised, monotonically ordered thresholds.

    When only ``auto`` is supplied the other tiers are derived exactly as
    ``guardrails._make_thresholds`` derives them (``review = auto - 0.1``,
    ``escalation = review - 0.2``), then clamped so ordering can never invert.
    """
    a = _clamp(auto)
    r = _clamp(review) if review is not None else max(0.0, a - 0.1)
    e = _clamp(escalation) if escalation is not None else max(0.0, r - 0.2)
    r = min(a, r)
    e = min(r, e)
    return ActionThresholds(auto=a, review=r, escalation=e)
