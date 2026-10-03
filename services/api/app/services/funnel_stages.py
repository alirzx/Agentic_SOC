"""Agentic SOC product funnel — stages + triage / investigation / Jira gates.

Tracks where each alert sits on the path:

    ingested → triaged | suppressed → investigating → cased
             → ready_for_jira → jira_pushed

Aligned with the Triage data-requirements doc:

* Triage decides whether investigation is worth it (classification,
  severity, FP likelihood, light entity context).
* Investigation solves the case (cmdline, network, baselines, …).
* Ready for Jira is only for real incidents with evidence — not every
  heuristic true_positive that got a Case during backfill.
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


def has_triage_meaningful_metadata(
    *,
    rule_id: str | None = None,
    rule_name: str | None = None,
    mitre_techniques: list[Any] | None = None,
    analytic_story: str | None = None,
    security_domain: str | None = None,
) -> bool:
    """Triage doc §4 — meaningful minimum beyond signature/src/severity.

    At least one of: rule id/name, MITRE technique, analytic story, security domain.
    """
    if (rule_id or "").strip():
        return True
    if (rule_name or "").strip():
        return True
    if (analytic_story or "").strip():
        return True
    if (security_domain or "").strip():
        return True
    if mitre_techniques and any(str(t).strip() for t in mitre_techniques):
        return True
    return False


def has_investigation_evidence(
    *,
    ai_summary: str | None = None,
    narrative: str | None = None,
) -> bool:
    """Light evidence signal that Investigation produced usable output."""
    summary = (ai_summary or "").strip()
    narr = (narrative or "").strip()
    return len(summary) >= 80 or len(narr) >= 80


def passes_investigation_gate(
    *,
    disposition: str | None,
    severity: str | None,
    confidence: float | int | None,
) -> bool:
    """True when an alert may enter deep investigation / Case promotion.

    Triage → Investigation handoff (doc §2):
    * Never for FP / benign.
    * ``true_positive`` / ``likely_tp`` / ``escalate`` → investigate.
    * ``needs_review``: high/critical, OR medium with confidence ≥ 0.70.
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


def passes_ready_for_jira_stage(
    *,
    disposition: str | None,
    severity: str | None = None,
    confidence: float | int | None = None,
    case_id: Any = None,
    tags: Any = None,
    rule_id: str | None = None,
    rule_name: str | None = None,
    mitre_techniques: list[Any] | None = None,
    analytic_story: str | None = None,
    security_domain: str | None = None,
    ai_summary: str | None = None,
    narrative: str | None = None,
    analyst_approved: bool = False,
) -> bool:
    """Stage gate for ``ready_for_jira`` (stricter than bare TP+case).

    Simple policy (triage doc + product funnel):

    1. Must have a Case.
    2. Disposition must be TP / escalate / likely_tp (needs_review only with
       analyst approval). Never FP/benign.
    3. PLUS at least one evidence bar:
       * severity high/critical, OR
       * medium + confidence ≥ 70% + triage-meaningful metadata, OR
       * investigation evidence (ai_summary / narrative), OR
       * explicit analyst approval.
    """
    if not case_id:
        return False
    if not passes_jira_gate(
        disposition=disposition,
        severity=severity,
        confidence=confidence,
        tags=tags,
        analyst_approved=analyst_approved,
        require_evidence_bar=False,
    ):
        return False
    if analyst_approved:
        return True
    sev = (severity or "medium").strip().lower()
    conf = _as_unit_confidence(confidence)
    if sev in _HIGH_SEV:
        return True
    if has_investigation_evidence(ai_summary=ai_summary, narrative=narrative):
        return True
    if (
        sev == "medium"
        and conf >= 0.70
        and has_triage_meaningful_metadata(
            rule_id=rule_id,
            rule_name=rule_name,
            mitre_techniques=mitre_techniques,
            analytic_story=analytic_story,
            security_domain=security_domain,
        )
    ):
        return True
    return False


def passes_jira_gate(
    *,
    disposition: str | None,
    severity: str | None = None,
    confidence: float | int | None = None,
    tags: Any = None,
    analyst_approved: bool = False,
    require_evidence_bar: bool = True,
    rule_id: str | None = None,
    rule_name: str | None = None,
    mitre_techniques: list[Any] | None = None,
    analytic_story: str | None = None,
    security_domain: str | None = None,
    ai_summary: str | None = None,
    narrative: str | None = None,
    case_id: Any = None,
) -> bool:
    """True when a case/alert may be pushed to Jira / ITSM.

    Disposition filter always applies. When ``require_evidence_bar`` is True
    (default for real pushes), also require the Ready-for-Jira evidence bar
    so medium heuristic TPs without investigation do not flood Jira.
    """
    d = (disposition or "").strip().lower()
    tag_set = _tag_set(tags)
    if d in _AUTO_CLOSEABLE or "false_positive" in tag_set or "benign" in tag_set:
        return False
    if d == "needs_review" and not analyst_approved:
        return False
    if analyst_approved and d not in _AUTO_CLOSEABLE:
        return True
    if d not in _JIRA_VERDICTS and d:
        return False
    # Unknown disposition: only with explicit analyst approval (operator push).
    if not d:
        return analyst_approved
    if not require_evidence_bar:
        return True
    # Evidence bar (same as ready_for_jira stage, case optional for push API).
    sev = (severity or "medium").strip().lower()
    conf = _as_unit_confidence(confidence)
    if sev in _HIGH_SEV:
        return True
    if has_investigation_evidence(ai_summary=ai_summary, narrative=narrative):
        return True
    if (
        sev == "medium"
        and conf >= 0.70
        and has_triage_meaningful_metadata(
            rule_id=rule_id,
            rule_name=rule_name,
            mitre_techniques=mitre_techniques,
            analytic_story=analytic_story,
            security_domain=security_domain,
        )
    ):
        return True
    _ = case_id
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
