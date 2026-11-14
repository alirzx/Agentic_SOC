"""Bilingual (EN + FA) incident reports for true-positive alerts/cases.

English section follows the AI Investigation narrative shape (executive
summary, timeline, IOCs, MITRE, recommendations). Persian section follows
the Soorin SOC handoff template used in production tickets:

* گزارش رخداد سایبری
* عنوان / شدت / وضعیت رویداد
* شرح رویداد / جزئیات رویداد / اقدامات پیشنهادی

Reports are gated on analyst ``true_positive`` (or case outcome ``incident``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

_SEVERITY_FA: dict[str, str] = {
    "critical": "بحرانی",
    "high": "بالا",
    "medium": "متوسط",
    "low": "پایین",
    "info": "اطلاعاتی",
}

_STATUS_FA: dict[str, str] = {
    "true_positive": "به وقوع پیوسته",
    "incident": "به وقوع پیوسته",
    "false_positive": "مثبت کاذب / نویز",
    "benign": "فعالیت مجاز / مورد انتظار",
    "investigating": "در حال وقوع",
    "new": "جدید",
    "resolved": "بسته شده",
    "closed": "بسته شده",
}


def _clean(value: Any, *, limit: int = 4_000) -> str:
    text = " ".join(str(value or "").split()).strip()
    return text[:limit] if text else ""


def _bullets(items: list[str], *, limit: int = 12) -> list[str]:
    out: list[str] = []
    for item in items:
        cleaned = _clean(item, limit=400)
        if cleaned and cleaned not in out:
            out.append(cleaned)
        if len(out) >= limit:
            break
    return out


def _severity_fa(severity: str) -> str:
    return _SEVERITY_FA.get((severity or "").lower(), severity or "نامشخص")


def _status_fa(status: str) -> str:
    return _STATUS_FA.get((status or "").lower(), status or "نامشخص")


def _extract_explanation(alert_like: dict[str, Any]) -> dict[str, Any]:
    extra = alert_like.get("enrichment_data")
    if isinstance(extra, dict):
        stored = extra.get("contextual_explanation")
        if isinstance(stored, dict):
            return stored
    direct = alert_like.get("contextual_explanation")
    return direct if isinstance(direct, dict) else {}


def build_alert_report_inputs(alert: Any, *, investigation_markdown: str | None = None) -> dict[str, Any]:
    """Normalize an Alert ORM / dict into report inputs."""
    if hasattr(alert, "title"):
        enrichment = getattr(alert, "enrichment_data", None) or {}
        expl = enrichment.get("contextual_explanation") if isinstance(enrichment, dict) else None
        mitre = list(getattr(alert, "mitre_techniques", None) or [])
        iocs = []
        if isinstance(enrichment, dict) and isinstance(enrichment.get("iocs"), list):
            iocs = enrichment["iocs"]
        return {
            "id": str(getattr(alert, "id", "")),
            "title": str(getattr(alert, "title", "") or ""),
            "description": str(getattr(alert, "description", "") or getattr(alert, "narrative", "") or ""),
            "severity": str(getattr(alert, "severity", "") or "medium"),
            "status": str(getattr(alert, "status", "") or ""),
            "disposition": str(getattr(alert, "disposition", "") or ""),
            "source": str(getattr(alert, "connector_type", "") or getattr(alert, "source", "") or ""),
            "rule_name": str(getattr(alert, "rule_name", "") or ""),
            "created_at": getattr(alert, "created_at", None),
            "ai_summary": str(getattr(alert, "ai_summary", "") or ""),
            "narrative": str(getattr(alert, "narrative", "") or ""),
            "affected_hosts": list(getattr(alert, "affected_hosts", None) or []),
            "affected_ips": list(getattr(alert, "affected_ips", None) or []),
            "affected_users": list(getattr(alert, "affected_users", None) or []),
            "mitre_techniques": [str(t) for t in mitre if t],
            "iocs": iocs,
            "contextual_explanation": expl if isinstance(expl, dict) else {},
            "investigation_markdown": investigation_markdown or "",
            "project_name": "آستان قدس",
            "prepared_by": "تیم مرکز عملیات امنیت سورین",
            "audience": "مرکز فناوری اطلاعات آستان قدس رضوی",
        }
    data = dict(alert)
    data["contextual_explanation"] = _extract_explanation(data)
    data.setdefault("investigation_markdown", investigation_markdown or "")
    data.setdefault("project_name", "آستان قدس")
    data.setdefault("prepared_by", "تیم مرکز عملیات امنیت سورین")
    data.setdefault("audience", "مرکز فناوری اطلاعات آستان قدس رضوی")
    return data


def _english_section(inp: dict[str, Any], *, generated_at: datetime) -> str:
    title = _clean(inp.get("title"), limit=300) or "Untitled alert"
    severity = _clean(inp.get("severity"), limit=40) or "medium"
    disposition = _clean(inp.get("disposition"), limit=40) or "true_positive"
    description = _clean(inp.get("description") or inp.get("narrative") or inp.get("ai_summary"), limit=2_500)
    expl = inp.get("contextual_explanation") if isinstance(inp.get("contextual_explanation"), dict) else {}
    meaning = _clean(expl.get("meaning") or "", limit=2_000)
    steps = _bullets([str(s) for s in (expl.get("suggested_next_steps") or []) if s])
    inv = _clean(inp.get("investigation_markdown") or "", limit=20_000)
    hosts = _bullets([str(h) for h in (inp.get("affected_hosts") or [])])
    ips = _bullets([str(i) for i in (inp.get("affected_ips") or [])])
    users = _bullets([str(u) for u in (inp.get("affected_users") or [])])
    mitre = _bullets([str(t) for t in (inp.get("mitre_techniques") or [])])

    lines: list[str] = [
        "# Cyber Incident Report",
        "",
        f"**Alert ID:** `{_clean(inp.get('id'), limit=80)}`  ",
        f"**Title:** {title}  ",
        f"**Severity:** {severity}  ",
        f"**Disposition:** {disposition}  ",
        f"**Source:** {_clean(inp.get('source') or inp.get('rule_name'), limit=120) or '—'}  ",
        f"**Generated:** {generated_at.isoformat()}  ",
        "",
        "## Executive Summary",
        "",
    ]
    if meaning:
        lines.append(meaning)
    elif description:
        lines.append(description)
    else:
        lines.append(
            "Analyst marked this alert as a true positive. Supporting investigation "
            "narrative should be completed with raw telemetry and host evidence."
        )
    lines.extend(["", "## Event narrative", ""])
    if description and description != meaning:
        lines.append(description)
    elif inv:
        lines.append("_See attached AI Investigation report below._")
    else:
        lines.append("_Narrative pending enrichment from raw events._")

    lines.extend(["", "## Scope", ""])
    if hosts or ips or users:
        if hosts:
            lines.append("- **Hosts:** " + ", ".join(f"`{h}`" for h in hosts))
        if ips:
            lines.append("- **IPs:** " + ", ".join(f"`{i}`" for i in ips))
        if users:
            lines.append("- **Users:** " + ", ".join(f"`{u}`" for u in users))
    else:
        lines.append("_No affected hosts/IPs/users were attached to the alert snapshot._")

    lines.extend(["", "## Indicators", ""])
    iocs = inp.get("iocs") if isinstance(inp.get("iocs"), list) else []
    if iocs:
        for ioc in iocs[:20]:
            if isinstance(ioc, dict):
                lines.append(
                    f"- `{_clean(ioc.get('type'), limit=40)}`: `{_clean(ioc.get('value'), limit=200)}`"
                )
            else:
                lines.append(f"- `{_clean(ioc, limit=200)}`")
    else:
        lines.append("_No IOCs recorded on the alert._")

    if mitre:
        lines.extend(["", "## MITRE ATT&CK", "", ", ".join(f"`{t}`" for t in mitre)])

    lines.extend(["", "## Recommended actions", ""])
    if steps:
        for step in steps:
            lines.append(f"- {step}")
    else:
        lines.extend(
            [
                "- Preserve raw SIEM / EDR / web logs for the alert window before any change.",
                "- Corroborate with host evidence (process tree, file writes, auth anomalies).",
                "- Document containment and recovery steps; feed detection tuning if needed.",
            ]
        )

    if inv:
        lines.extend(["", "## AI Investigation (attached)", "", inv, ""])

    return "\n".join(lines).strip()


def _persian_section(inp: dict[str, Any], *, generated_at: datetime) -> str:
    title = _clean(inp.get("title"), limit=300) or "رویداد امنیتی بدون عنوان"
    severity = _severity_fa(str(inp.get("severity") or "medium"))
    disposition = _status_fa(str(inp.get("disposition") or "true_positive"))
    expl = inp.get("contextual_explanation") if isinstance(inp.get("contextual_explanation"), dict) else {}
    meaning = _clean(expl.get("meaning") or inp.get("ai_summary") or inp.get("description") or "", limit=2_500)
    details = _clean(inp.get("description") or inp.get("narrative") or "", limit=3_000)
    steps = _bullets([str(s) for s in (expl.get("suggested_next_steps") or []) if s], limit=10)
    hosts = _bullets([str(h) for h in (inp.get("affected_hosts") or [])])
    ips = _bullets([str(i) for i in (inp.get("affected_ips") or [])])
    created = inp.get("created_at")
    if isinstance(created, datetime):
        event_date = created.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    else:
        event_date = _clean(created, limit=64) or generated_at.strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        "# گزارش رخداد سایبری",
        "",
        f"جهت ارائه به  ",
        f"**{_clean(inp.get('audience'), limit=120)}**",
        "",
        f"تهیه شده توسط  ",
        f"**{_clean(inp.get('prepared_by'), limit=120)}**",
        "",
        f"**پروژه:** {_clean(inp.get('project_name'), limit=80)}  ",
        f"**تاریخ رخداد:** {event_date}  ",
        f"**تاریخ گزارش:** {generated_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**شناسه هشدار:** `{_clean(inp.get('id'), limit=80)}`  ",
        "",
        f"**عنوان رویداد:** {title}  ",
        f"**شدت رویداد:** {severity}  ",
        f"**وضعیت رویداد:** {disposition}  ",
        "",
        "## شرح رویداد",
        "",
    ]
    if meaning:
        lines.append(meaning)
    else:
        lines.append(
            "این هشدار توسط تحلیل‌گر به‌عنوان true positive ثبت شده است. "
            "شرح تکمیلی باید بر اساس رویدادهای خام و شواهد میزبان تکمیل شود."
        )

    lines.extend(["", "## جزئیات رویداد", ""])
    if details and details != meaning:
        lines.append(details)
    detail_bits: list[str] = []
    source = _clean(inp.get("source") or inp.get("rule_name"), limit=160)
    if source:
        detail_bits.append(f"منبع تشخیص: `{source}`")
    if hosts:
        detail_bits.append("میزبان‌های درگیر: " + "، ".join(f"`{h}`" for h in hosts))
    if ips:
        detail_bits.append("آدرس‌های IP: " + "، ".join(f"`{i}`" for i in ips))
    mitre = _bullets([str(t) for t in (inp.get("mitre_techniques") or [])])
    if mitre:
        detail_bits.append("تکنیک‌های MITRE: " + "، ".join(f"`{t}`" for t in mitre))
    if detail_bits:
        for bit in detail_bits:
            lines.append(f"- {bit}")
    elif not (details and details != meaning):
        lines.append(
            "در اسنپ‌شات فعلی هشدار، فیلدهای میزبان/IP/کاربر یا IOC کامل نشده است؛ "
            "برای تکمیل جزئیات باید رویدادهای خام SIEM و لاگ‌های مرتبط استخراج شود."
        )

    lines.extend(["", "## اقدامات پیشنهادی", ""])
    if steps:
        for step in steps:
            lines.append(f"- {step}")
    else:
        lines.extend(
            [
                "- قبل از هر تغییر، رویدادهای خام مرتبط در SIEM/EDR/وب‌سرور حفظ و استخراج شود.",
                "- همبستگی با هشدارهای مرتبط و شواهد سطح میزبان برای تأیید بهره‌برداری انجام شود.",
                "- در صورت تأیید نفوذ، اقدامات مهار و پاک‌سازی با مستندسازی کامل اجرا شود؛ "
                "در غیر این صورت علت و تنظیم تشخیص مستند گردد.",
            ]
        )
    lines.extend(["", "با تشکر.", ""])
    return "\n".join(lines).strip()


def render_bilingual_incident_report(
    inp: dict[str, Any],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Return Markdown with English then Persian sections."""
    moment = generated_at or datetime.now(UTC)
    en = _english_section(inp, generated_at=moment)
    fa = _persian_section(inp, generated_at=moment)
    return "\n\n---\n\n".join(
        [
            en,
            fa,
            "_Bilingual incident report · English + فارسی · AiSOC_",
        ]
    )


def is_true_positive_disposition(disposition: str | None) -> bool:
    return (disposition or "").strip().lower() in {"true_positive", "likely_tp", "escalate"}


def render_persian_handoff(
    inp: dict[str, Any],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Public wrapper for the Persian customer-handoff section."""
    return _persian_section(inp, generated_at=generated_at or datetime.now(UTC))


def severity_label_fa(severity: str) -> str:
    return _severity_fa(severity)


def status_label_fa(status: str) -> str:
    return _status_fa(status)
