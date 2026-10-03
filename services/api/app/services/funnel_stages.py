"""Agentic SOC product funnel — stages + promotion / Jira gates.

Tracks where each alert sits on the path:

    ingested → triaged | suppressed → investigating → cased
             → ready_for_jira → jira_pushed

Gates keep Jira free of noise: only real incidents with evidence
(and not FP/benign / unapproved needs_review) may push to ITSM.
"""

from __future__ import annotations

from typing import Any, Iterable

# Canonical stage labels (persist on ``alerts.funnel_stage``).
INGESTED = "ingested"
TRIAGED = "triaged"
SUPPRESSED = "suppressed"
INVESTIGATING = "investigating"
CASED = "cased"
READY_FOR_JIRA = "ready_for_jira"
JIRA_PUSHED = "jira_pushed"

FUNNEL_STAGES: tuple[str, ...] = (
    INGESTED,
    TRIAGED,
    SUPPRESSED,
    INVESTIGATING,
    CASED,
    READY_FOR_JIRA,
    JIRA_PUSHED,
)

STAGE_LABELS: dict[str, str] = {
    INGESTED: "Ingested",
    TRIAGED: "Triaged",
    SUPPRESSED: "Suppressed",
    INVESTIGATING: "Investigating",
    CASED: "Cased",
    READY_FOR_JIRA: "Ready for Jira",
    JIRA_PUSHED: "Jira pushed",
}

# Ordered for board left→right (suppressed is a side exit after triage).
BOARD_ORDER: tuple[str, ...] = (
    INGESTED,
    TRIAGED,
    SUPPRESSED,
    INVESTIGATING,
    CASED,
    READY_FOR_JIRA,
    JIRA_PUSHED,
)

_AUTO_CLOSEABLE = frozenset({"false_positive", "benign", "benign_true_positive"})
_ESCALATE_VERDICTS = frozenset({"true_positive", "likely_tp", "escalate", "needs_review"})
_JIRA_VERDICTS = frozenset({"true_positive", "escalate", "likely_tp"})
_HIGH_SEV = frozenset({"high", "critical"})


def normalize_stage(value: str | None, *, default: str = INGESTED) -> str:
    """Return a known stage or ``default``."""
    stage = (value or "").strip().lower()
    return stage if stage in FUNNEL_STAGES else default


def stage_after_triage(*, disposition: str, auto_closed: bool) -> str:
    """Map an auto-triage outcome onto the next funnel stage."""
    d = (disposition or "").strip().lower()
    if auto_closed or d in _AUTO_CLOSEABLE:
        return SUPPRESSED
    return TRIAGED


def _as_unit_confidence(confidence: float | int | None) -> float:
    """Accept 0–1 float or 0–100 int; clamp to [0, 1]."""
    if confidence is None:
        return 0.0
    value = float(confidence)
    if value > 1.0:
        value = value / 100.0
    return max(0.0, min(1.0, value))


def passes_investigation_gate(
    *,
    disposition: str | None,
    severity: str | None,
    confidence: float | int | None,
) -> bool:
    """True when an alert may enter deep investigation / Case promotion.

    Policy (product funnel P1):
    * Never for FP / benign auto-closeables.
    * Always for ``true_positive`` / ``likely_tp`` / ``escalate``.
    * For ``needs_review``: severity high/critical, OR medium with
      confidence ≥ 0.70 (70).
    """
    d = (disposition or "").strip().lower()
    if not d or d in _AUTO_CLOSEABLE:
        return False
    sev = (severity or "medium").strip().lower()
    conf = _as_unit_confidence(confidence)
    if d in {"true_positive", "likely_tp", "escalate"}:
        return True
    if d == "needs_review":
        if sev in _HIGH_SEV:
            return True
        if sev == "medium" and conf >= 0.70:
            return True
        return False
    return d in _ESCALATE_VERDICTS and sev in _HIGH_SEV


def passes_jira_gate(
    *,
    disposition: str | None,
    severity: str | None = None,
    confidence: float | int | None = None,
    tags: Any = None,
    analyst_approved: bool = False,
) -> bool:
    """True when a case/alert may be pushed to Jira / ITSM.

    Policy (product funnel P3):
    * Never for FP / benign.
    * ``needs_review`` stays internal unless ``analyst_approved``.
    * ``true_positive`` / ``escalate`` / ``likely_tp`` may push.
    * ``reportable`` tag alone is not enough without a non-FP disposition
      (defense against noisy auto-promotion).
    """
    d = (disposition or "").strip().lower()
    tag_set = _tag_set(tags)
    if d in _AUTO_CLOSEABLE or "false_positive" in tag_set or "benign" in tag_set:
        return False
    if d == "needs_review" and not analyst_approved:
        return False
    # Explicit analyst/operator approval unlocks any non-FP disposition.
    if analyst_approved and d not in _AUTO_CLOSEABLE:
        return True
    if d in _JIRA_VERDICTS:
        return True
    if "reportable" in tag_set and d in _JIRA_VERDICTS:
        return True
    # Legacy cases with no disposition yet: allow (caller selected ITSM
    # targets). Noise must be explicitly dispositioned/tagged to block.
    if not d:
        return True
    # Severity/confidence are advisory for logging; disposition is the gate.
    _ = severity, confidence
    return False


def _tag_set(tags: Any) -> set[str]:
    if tags is None:
        return set()
    if isinstance(tags, dict):
        labels = tags.get("labels")
        if isinstance(labels, list):
            return {str(t).lower() for t in labels}
        return {str(k).lower() for k in tags.keys()}
    if isinstance(tags, Iterable) and not isinstance(tags, (str, bytes)):
        return {str(t).lower() for t in tags}
    return set()


def disposition_from_case_tags(tags: Any) -> str | None:
    """Best-effort disposition hint from case tags when alerts are absent."""
    tag_set = _tag_set(tags)
    if "false_positive" in tag_set or "benign" in tag_set:
        return "false_positive"
    if "true_positive" in tag_set:
        return "true_positive"
    if "reportable" in tag_set:
        return "true_positive"
    return None
