"""Agent-side funnel stage + gate helpers (mirrors API ``funnel_stages``).

Kept byte-small and dependency-free so the Kafka auto-triage worker can
advance ``alerts.funnel_stage`` without importing the API package.

Ready-for-Jira evidence bar matches the triage input-requirements doc:
high/critical, or medium@≥0.70 with MITRE/rule signal, or findings prose.
"""

from __future__ import annotations

from typing import Any

INGESTED = "ingested"
TRIAGED = "triaged"
SUPPRESSED = "suppressed"
INVESTIGATING = "investigating"
CASED = "cased"
READY_FOR_JIRA = "ready_for_jira"
JIRA_PUSHED = "jira_pushed"

_AUTO_CLOSEABLE = frozenset({"false_positive", "benign", "benign_true_positive"})
_HIGH_SEV = frozenset({"high", "critical"})


def stage_after_triage(*, disposition: str, auto_closed: bool) -> str:
    d = (disposition or "").strip().lower()
    if auto_closed or d in _AUTO_CLOSEABLE:
        return SUPPRESSED
    return TRIAGED


def _as_unit_confidence(confidence: float | int | None) -> float:
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
    """Same policy as ``services/api/app/services/funnel_stages.py``."""
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
    return False


def passes_ready_for_jira_stage(
    *,
    disposition: str | None,
    severity: str | None,
    confidence: float | int | None,
    mitre_techniques: list[Any] | None = None,
    findings: list[Any] | None = None,
) -> bool:
    """Mirror of API Ready-for-Jira evidence bar (no case_id check here)."""
    d = (disposition or "").strip().lower()
    if d not in {"true_positive", "escalate", "likely_tp"}:
        return False
    sev = (severity or "medium").strip().lower()
    conf = _as_unit_confidence(confidence)
    if sev in _HIGH_SEV:
        return True
    if any(len(str(f).strip()) >= 80 for f in (findings or [])[:5]):
        return True
    if sev == "medium" and conf >= 0.70 and mitre_techniques:
        return True
    return False
