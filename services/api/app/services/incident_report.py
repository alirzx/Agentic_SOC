"""Standard incident report for Case → management / Jira.

Produces a deterministic Markdown body so every Jira ticket carries the
same structure: executive summary, MITRE, timeline, entities, evidence,
recommended actions, verdict + confidence.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def build_incident_report(
    *,
    title: str,
    severity: str | None = None,
    disposition: str | None = None,
    confidence: float | int | None = None,
    summary: str | None = None,
    narrative: str | None = None,
    mitre_techniques: list[Any] | None = None,
    mitre_tactics: list[Any] | None = None,
    hosts: list[Any] | None = None,
    ips: list[Any] | None = None,
    users: list[Any] | None = None,
    iocs: list[Any] | None = None,
    timeline: list[dict[str, Any]] | None = None,
    evidence: list[str] | None = None,
    recommended_actions: list[Any] | None = None,
    case_id: str | None = None,
    alert_ids: list[str] | None = None,
    aisoc_url: str | None = None,
) -> str:
    """Return a Markdown incident report suitable for Jira description."""
    conf_txt = _format_confidence(confidence)
    lines: list[str] = [
        f"# Incident Report — {title.strip() or 'Untitled'}",
        "",
        f"**Severity:** {(severity or 'medium').upper()}  ",
        f"**Disposition:** {(disposition or 'needs_review')}  ",
        f"**Confidence:** {conf_txt}  ",
        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Executive summary",
        (summary or narrative or "No summary available.").strip(),
        "",
    ]
    if narrative and summary and narrative.strip() != summary.strip():
        lines.extend(["## Narrative", narrative.strip(), ""])

    techs = [str(t) for t in (mitre_techniques or []) if t]
    tactics = [str(t) for t in (mitre_tactics or []) if t]
    lines.append("## MITRE ATT&CK")
    if techs or tactics:
        if tactics:
            lines.append("- **Tactics:** " + ", ".join(tactics[:20]))
        if techs:
            lines.append("- **Techniques:** " + ", ".join(techs[:20]))
    else:
        lines.append("_No MITRE mapping recorded._")
    lines.append("")

    lines.append("## Affected entities")
    lines.append(_bullet_block("Hosts", hosts))
    lines.append(_bullet_block("IPs", ips))
    lines.append(_bullet_block("Users", users))
    lines.append(_bullet_block("IOCs", _flatten_iocs(iocs)))
    lines.append("")

    lines.append("## Timeline")
    if timeline:
        for event in timeline[:30]:
            ts = str(event.get("timestamp") or event.get("ts") or "")
            title_e = str(event.get("title") or event.get("summary") or "event")
            lines.append(f"- `{ts}` {title_e}")
    else:
        lines.append("_No timeline events attached._")
    lines.append("")

    lines.append("## Evidence")
    if evidence:
        for item in evidence[:40]:
            text = str(item).strip()
            if text:
                lines.append(f"- {text}")
    else:
        lines.append("_See AiSOC case ledger for full evidence chain._")
    lines.append("")

    lines.append("## Recommended actions")
    actions = _flatten_actions(recommended_actions)
    if actions:
        for action in actions[:20]:
            lines.append(f"- {action}")
    else:
        lines.append("_No recommended actions yet._")
    lines.append("")

    lines.append("## References")
    if case_id:
        link = f"{aisoc_url.rstrip('/')}/cases/{case_id}" if aisoc_url else f"case:{case_id}"
        lines.append(f"- AiSOC case: {link}")
    if alert_ids:
        lines.append("- Source alerts: " + ", ".join(str(a) for a in alert_ids[:25]))
    lines.append("")
    return "\n".join(lines).strip() + "\n"


def _format_confidence(confidence: float | int | None) -> str:
    if confidence is None:
        return "n/a"
    value = float(confidence)
    if value <= 1.0:
        return f"{int(round(value * 100))}%"
    return f"{int(round(value))}%"


def _bullet_block(label: str, values: list[Any] | None) -> str:
    items = [str(v).strip() for v in (values or []) if str(v).strip()]
    if not items:
        return f"- **{label}:** _(none)_"
    return f"- **{label}:** " + ", ".join(items[:25])


def _flatten_iocs(iocs: list[Any] | None) -> list[str]:
    out: list[str] = []
    for item in iocs or []:
        if isinstance(item, dict):
            kind = str(item.get("type") or item.get("kind") or "ioc")
            value = str(item.get("value") or item.get("ioc") or "")
            if value:
                out.append(f"{kind}:{value}")
        elif item:
            out.append(str(item))
    return out


def _flatten_actions(actions: list[Any] | None) -> list[str]:
    out: list[str] = []
    for item in actions or []:
        if isinstance(item, dict):
            text = str(
                item.get("description")
                or item.get("action")
                or item.get("action_type")
                or ""
            ).strip()
            if text:
                out.append(text)
        elif item:
            out.append(str(item).strip())
    return out
