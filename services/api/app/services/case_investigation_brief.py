"""Case investigation brief — what we did, evidence, and outcome.

Powers ``GET /cases/{id}/brief`` so the Case workspace can show a short,
analyst-facing summary:

* linked alert reports (disposition + AI summary)
* evidence highlights
* investigation / triage actions taken
* resulting outcome (incident / false_positive / needs_review / …)
"""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_OUTCOME_LABELS: dict[str, str] = {
    "incident": "Likely incident",
    "false_positive": "False positive / noise",
    "benign": "Benign / expected activity",
    "needs_review": "Needs analyst review",
    "escalated": "Escalated",
    "unknown": "Outcome not yet determined",
}


class AlertBriefItem(BaseModel):
    id: str
    title: str
    severity: str
    disposition: str | None = None
    funnel_stage: str | None = None
    summary: str | None = None
    confidence: int | None = None


class EvidenceHighlight(BaseModel):
    kind: str
    text: str
    source: str | None = None


class ActionItem(BaseModel):
    kind: str  # triage | investigate | case | task | itsm
    label: str
    detail: str | None = None


class CaseInvestigationBrief(BaseModel):
    case_id: str
    case_number: str | None = None
    title: str
    severity: str
    status: str
    generated_at: datetime
    outcome: str
    outcome_label: str
    outcome_rationale: str
    disposition_counts: dict[str, int] = Field(default_factory=dict)
    ready_for_jira: bool = False
    jira_pushed: bool = False
    what_we_did: list[ActionItem] = Field(default_factory=list)
    evidence: list[EvidenceHighlight] = Field(default_factory=list)
    alerts: list[AlertBriefItem] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    next_step: str | None = None


@dataclass
class BriefAlertRow:
    id: uuid.UUID
    title: str
    severity: str
    disposition: str | None
    funnel_stage: str | None
    ai_summary: str | None
    narrative: str | None
    confidence: int | None
    mitre_techniques: list[str] = field(default_factory=list)


@dataclass
class BriefCaseRow:
    id: uuid.UUID
    case_number: str | None
    title: str
    description: str | None
    severity: str
    status: str
    tags: dict[str, Any]
    mitre_techniques: list[str]
    evidence_chain: list[Any]
    alert_ids: list[str]


@dataclass
class BriefInputs:
    case: BriefCaseRow
    alerts: list[BriefAlertRow] = field(default_factory=list)
    task_titles: list[str] = field(default_factory=list)
    investigation_notes: list[str] = field(default_factory=list)
    has_external_ref: bool = False


def derive_case_outcome(
    *,
    dispositions: list[str],
    case_status: str,
    tags: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Return ``(outcome_key, rationale)`` from linked alert dispositions."""
    counts = Counter((d or "").strip().lower() for d in dispositions if d)
    tag_set = set()
    if isinstance(tags, dict):
        if tags.get("false_positive"):
            tag_set.add("false_positive")
        if tags.get("reportable"):
            tag_set.add("reportable")
        labels = tags.get("labels")
        if isinstance(labels, list):
            tag_set.update(str(x).lower() for x in labels)

    fp = counts.get("false_positive", 0) + counts.get("benign", 0) + counts.get("benign_true_positive", 0)
    tp = counts.get("true_positive", 0) + counts.get("likely_tp", 0)
    escalate = counts.get("escalate", 0)
    needs = counts.get("needs_review", 0)

    if "false_positive" in tag_set and tp == 0 and escalate == 0:
        return "false_positive", "Case tagged false_positive and no true-positive alerts remain."
    if tp > 0 or escalate > 0 or "reportable" in tag_set:
        return (
            "incident",
            f"Linked alerts include true_positive/escalate (tp={tp}, escalate={escalate}).",
        )
    if fp > 0 and tp == 0 and escalate == 0 and needs == 0:
        return "false_positive", f"All dispositioned alerts are FP/benign ({fp})."
    if counts.get("benign", 0) > 0 and tp == 0:
        return "benign", "Alerts dispositioned as benign/expected activity."
    if escalate > 0:
        return "escalated", "At least one alert was escalated."
    if needs > 0:
        return "needs_review", f"{needs} alert(s) still need analyst review."
    status = (case_status or "").lower()
    if status in {"resolved", "closed"} and fp == 0 and tp == 0:
        return "unknown", "Case closed without a clear alert disposition."
    return "unknown", "No firm disposition yet — triage/investigation still open."


def build_brief_from_rows(inputs: BriefInputs, *, now: datetime | None = None) -> CaseInvestigationBrief:
    """Pure builder — unit-tested without DB."""
    moment = now or datetime.now(UTC)
    case = inputs.case
    dispositions = [a.disposition or "" for a in inputs.alerts]
    outcome, rationale = derive_case_outcome(
        dispositions=dispositions,
        case_status=case.status,
        tags=case.tags,
    )
    disp_counts = dict(Counter((d or "unset").strip().lower() or "unset" for d in dispositions))

    stages = {(a.funnel_stage or "").lower() for a in inputs.alerts}
    ready = "ready_for_jira" in stages
    pushed = inputs.has_external_ref or "jira_pushed" in stages

    actions: list[ActionItem] = []
    actions.append(
        ActionItem(
            kind="case",
            label="Case opened",
            detail=f"Severity {case.severity}; {len(inputs.alerts)} linked alert(s).",
        )
    )
    triaged = [a for a in inputs.alerts if a.disposition]
    if triaged:
        actions.append(
            ActionItem(
                kind="triage",
                label="Auto / analyst triage applied",
                detail=", ".join(
                    f"{d}×{n}" for d, n in Counter((a.disposition or '?').lower() for a in triaged).items()
                ),
            )
        )
    investigating = [a for a in inputs.alerts if (a.funnel_stage or "") == "investigating"]
    if investigating or inputs.investigation_notes:
        actions.append(
            ActionItem(
                kind="investigate",
                label="Investigation run",
                detail=(
                    inputs.investigation_notes[0][:200]
                    if inputs.investigation_notes
                    else f"{len(investigating)} alert(s) marked investigating."
                ),
            )
        )
    for note in inputs.investigation_notes[:4]:
        text = note.strip()
        if text:
            actions.append(ActionItem(kind="investigate", label="Finding / report note", detail=text[:240]))
    for title in inputs.task_titles[:8]:
        actions.append(ActionItem(kind="task", label="Investigation task", detail=title[:200]))
    if ready:
        actions.append(
            ActionItem(
                kind="itsm",
                label="Marked ready for Jira",
                detail="Evidence bar met (high/critical or medium@≥70% with metadata / investigation prose).",
            )
        )
    if pushed:
        actions.append(ActionItem(kind="itsm", label="Pushed to ITSM / Jira", detail="External ticket reference exists."))

    evidence: list[EvidenceHighlight] = []
    for item in case.evidence_chain or []:
        if isinstance(item, dict):
            kind = str(item.get("kind") or item.get("type") or "evidence")
            body = str(item.get("summary") or item.get("description") or item.get("text") or item.get("title") or "")
            if body.strip():
                evidence.append(EvidenceHighlight(kind=kind, text=body.strip()[:280], source="evidence_chain"))
    for alert in inputs.alerts:
        blob = (alert.ai_summary or alert.narrative or "").strip()
        if blob:
            evidence.append(
                EvidenceHighlight(
                    kind="alert_report",
                    text=blob[:280],
                    source=alert.title[:80],
                )
            )
    evidence = evidence[:12]

    mitre: list[str] = []
    seen: set[str] = set()
    for tech in list(case.mitre_techniques or []):
        t = str(tech).strip()
        if t and t not in seen:
            seen.add(t)
            mitre.append(t)
    for alert in inputs.alerts:
        for tech in alert.mitre_techniques:
            t = str(tech).strip()
            if t and t not in seen:
                seen.add(t)
                mitre.append(t)

    alert_items = [
        AlertBriefItem(
            id=str(a.id),
            title=a.title,
            severity=a.severity,
            disposition=a.disposition,
            funnel_stage=a.funnel_stage,
            summary=((a.ai_summary or a.narrative or "")[:220] or None),
            confidence=a.confidence,
        )
        for a in inputs.alerts[:20]
    ]

    next_step: str | None
    if outcome == "incident" and not pushed:
        next_step = "Review evidence, confirm incident, then Promote → Jira if ITSM handoff is required."
    elif outcome == "false_positive":
        next_step = "Close/resolve the case and feed the FP into detection tuning / override memory."
    elif outcome == "needs_review":
        next_step = "Run investigation or set an analyst disposition (TP / FP) before Jira."
    elif outcome == "unknown":
        next_step = "Start triage on linked alerts or run Investigate with agent."
    else:
        next_step = "Archive or continue remediation tasks as needed."

    return CaseInvestigationBrief(
        case_id=str(case.id),
        case_number=case.case_number,
        title=case.title,
        severity=case.severity,
        status=case.status,
        generated_at=moment,
        outcome=outcome,
        outcome_label=_OUTCOME_LABELS.get(outcome, outcome),
        outcome_rationale=rationale,
        disposition_counts=disp_counts,
        ready_for_jira=ready,
        jira_pushed=pushed,
        what_we_did=actions,
        evidence=evidence,
        alerts=alert_items,
        mitre_techniques=mitre[:25],
        next_step=next_step,
    )


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif isinstance(item, dict):
            tid = item.get("id") or item.get("technique_id") or item.get("name")
            if tid:
                out.append(str(tid))
    return out


def render_case_report_markdown(brief: CaseInvestigationBrief) -> str:
    """Deterministic analyst-facing incident report (Markdown).

    Used by ``GET /cases/{id}/report.md`` so the Case Report tab always has
    content — even when no agent investigation run has produced a report yet.
    """
    case_label = brief.case_number or brief.case_id[:8]
    lines: list[str] = [
        f"# Case Report — {brief.title}",
        "",
        f"**Case:** `{case_label}`  ",
        f"**Severity:** {brief.severity}  ",
        f"**Status:** {brief.status}  ",
        f"**Generated:** {brief.generated_at.isoformat()}  ",
        "",
        "## Outcome",
        "",
        f"**{brief.outcome_label}** (`{brief.outcome}`)",
        "",
        brief.outcome_rationale,
        "",
    ]
    if brief.disposition_counts:
        disp = ", ".join(f"{k}: {n}" for k, n in sorted(brief.disposition_counts.items()))
        lines.extend([f"**Disposition counts:** {disp}", ""])
    flags: list[str] = []
    if brief.ready_for_jira:
        flags.append("Ready for Jira")
    if brief.jira_pushed:
        flags.append("Jira pushed")
    if flags:
        lines.extend([f"**ITSM:** {', '.join(flags)}", ""])
    lines.extend(["## What we did", ""])
    if brief.what_we_did:
        for action in brief.what_we_did:
            detail = f" — {action.detail}" if action.detail else ""
            lines.append(f"- **{action.label}**{detail}")
    else:
        lines.append("_No investigation actions recorded yet._")
    lines.extend(["", "## Evidence & alert reports", ""])
    if brief.evidence:
        for item in brief.evidence:
            src = f" ({item.source})" if item.source else ""
            lines.append(f"- **{item.kind}**{src}: {item.text}")
    else:
        lines.append("_No evidence snippets yet._")
    lines.extend(["", "## Linked alerts", ""])
    if brief.alerts:
        for alert in brief.alerts:
            disp = alert.disposition or "unset"
            stage = alert.funnel_stage or "—"
            conf = f", confidence {alert.confidence}" if alert.confidence is not None else ""
            lines.append(
                f"- **{alert.title}** — severity `{alert.severity}`, "
                f"disposition `{disp}`, stage `{stage}`{conf}"
            )
            if alert.summary:
                lines.append(f"  - Report: {alert.summary}")
    else:
        lines.append("_No linked alerts._")
    if brief.mitre_techniques:
        lines.extend(["", "## MITRE ATT&CK", ""])
        lines.append(", ".join(f"`{t}`" for t in brief.mitre_techniques))
    if brief.next_step:
        lines.extend(["", "## Next step", "", brief.next_step])
    lines.extend(
        [
            "",
            "---",
            "_Auto-generated by AiSOC from case triage, linked alert reports, "
            "and investigation state. Re-run Investigate with agent for a "
            "deeper agent-authored report._",
            "",
        ]
    )
    return "\n".join(lines)


async def build_case_investigation_brief(
    db: AsyncSession,
    case_id: uuid.UUID,
    *,
    tenant_id: uuid.UUID | None = None,
) -> CaseInvestigationBrief | None:
    """Load case + linked alerts + tasks and build the brief."""
    case_q = text(
        """
        SELECT id, case_number, title, description, severity, status, tags,
               mitre_techniques, evidence_chain, alert_ids, tenant_id
          FROM aisoc_cases
         WHERE id = :id
        """
        + (" AND tenant_id = :tid" if tenant_id is not None else "")
    )
    params: dict[str, Any] = {"id": case_id}
    if tenant_id is not None:
        params["tid"] = tenant_id
    row = (await db.execute(case_q.bindparams(**params))).fetchone()
    if row is None:
        return None

    tags = dict(row.tags) if isinstance(row.tags, dict) else {}
    case = BriefCaseRow(
        id=row.id,
        case_number=getattr(row, "case_number", None),
        title=row.title,
        description=row.description,
        severity=row.severity,
        status=row.status,
        tags=tags,
        mitre_techniques=_as_str_list(row.mitre_techniques),
        evidence_chain=list(row.evidence_chain or []) if isinstance(row.evidence_chain, list) else [],
        alert_ids=[str(a) for a in (row.alert_ids or [])],
    )

    alert_rows = (
        await db.execute(
            text(
                """
                SELECT id, title, severity, disposition, funnel_stage,
                       ai_summary, narrative, confidence, mitre_techniques
                  FROM alerts
                 WHERE case_id = :cid
                 ORDER BY created_at DESC
                 LIMIT 40
                """
            ).bindparams(cid=case_id)
        )
    ).mappings().all()

    alerts = [
        BriefAlertRow(
            id=r["id"],
            title=str(r["title"] or ""),
            severity=str(r["severity"] or "medium"),
            disposition=r.get("disposition"),
            funnel_stage=r.get("funnel_stage"),
            ai_summary=r.get("ai_summary"),
            narrative=r.get("narrative"),
            confidence=r.get("confidence"),
            mitre_techniques=_as_str_list(r.get("mitre_techniques")),
        )
        for r in alert_rows
    ]

    task_rows = (
        await db.execute(
            text(
                """
                SELECT title FROM aisoc_case_tasks
                 WHERE case_id = :cid
                 ORDER BY created_at DESC
                 LIMIT 12
                """
            ).bindparams(cid=case_id)
        )
    ).fetchall()
    task_titles = [str(r[0]) for r in task_rows if r and r[0]]

    note_rows = (
        await db.execute(
            text(
                """
                SELECT body FROM aisoc_case_comments
                 WHERE case_id = :cid AND is_system = TRUE
                 ORDER BY created_at DESC
                 LIMIT 8
                """
            ).bindparams(cid=case_id)
        )
    ).fetchall()
    investigation_notes = [str(r[0]) for r in note_rows if r and r[0]]

    has_ext = False
    if (await db.execute(text("SELECT to_regclass('public.case_external_refs') IS NOT NULL"))).scalar():
        has_ext = bool(
            (
                await db.execute(
                    text("SELECT 1 FROM case_external_refs WHERE case_id = :cid LIMIT 1").bindparams(cid=case_id)
                )
            ).fetchone()
        )

    return build_brief_from_rows(
        BriefInputs(
            case=case,
            alerts=alerts,
            task_titles=task_titles,
            investigation_notes=investigation_notes,
            has_external_ref=has_ext,
        )
    )
