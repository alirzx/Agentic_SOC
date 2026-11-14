"""Persian incident handoff report for true-positive alerts.

Matches the Soorin SOC customer-handoff shape (Report_sample):

* گزارش رخداد سایبری
* Analyst-filled header (audience / project / analyst / approval)
* Title / severity / status
* شرح رویداد · جزئیات رویداد · اقدامات انجام‌شده · اقدامات پیشنهادی

Content is distilled from Explain + AI Investigation + llm_payload + Runbook
+ Tier-2 snapshot. Empty/noise sections are omitted; narrative is richer than
a one-liner but still avoids dumping the full English investigation.
"""

from __future__ import annotations

import re
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
    "in_progress": "در حال وقوع",
    "new": "جدید",
    "resolved": "بسته شده",
    "closed": "بسته شده",
}

_PLACEHOLDER_FA = "[پر شود توسط تحلیل‌گر]"
_HANDOFF_KEYS = (
    "audience",
    "prepared_by",
    "project_name",
    "analyst",
    "approved_by",
)

_LLM_EVIDENCE_KEYS: tuple[str, ...] = (
    "url",
    "uri",
    "src_ip",
    "dest_ip",
    "src",
    "dest",
    "host",
    "hostname",
    "machine",
    "computer",
    "dvc",
    "user",
    "username",
    "http_method",
    "status",
    "user_agent",
    "process",
    "cmdline",
    "file_name",
    "file_path",
    "path",
    "sha256",
    "sha1",
    "md5",
    "hash",
    "infection",
    "verdict",
    "action",
    "orig_rule_description",
    "orig_rule_title",
    "search_name",
    "alert_time",
    "event_time",
)

_NONE_VALUES = {"", "none", "null", "n/a", "-", "—"}


def _clean(value: Any, *, limit: int = 4_000) -> str:
    text = " ".join(str(value or "").split()).strip()
    return text[:limit] if text else ""


def _is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    text = _clean(value, limit=80).lower()
    return text in _NONE_VALUES


def _bullets(items: list[str], *, limit: int = 10) -> list[str]:
    out: list[str] = []
    for item in items:
        cleaned = _clean(item, limit=450)
        if cleaned and cleaned not in out:
            out.append(cleaned)
        if len(out) >= limit:
            break
    return out


def _severity_fa(severity: str) -> str:
    return _SEVERITY_FA.get((severity or "").lower(), severity or "نامشخص")


def _status_fa(status: str) -> str:
    return _STATUS_FA.get((status or "").lower(), status or "نامشخص")


def _handoff_value(value: Any) -> str:
    cleaned = _clean(value, limit=160)
    return cleaned if cleaned else _PLACEHOLDER_FA


def _dedupe_source(connector: str, rule: str) -> str:
    c = _clean(connector, limit=80)
    r = _clean(rule, limit=160)
    if not c and not r:
        return ""
    if not c:
        return r
    if not r:
        return c

    def _collapse_dup_tokens(text: str) -> str:
        parts = [p for p in re.split(r"[\s/|_-]+", text) if p]
        out: list[str] = []
        seen: set[str] = set()
        for part in parts:
            key = part.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(part)
        return " ".join(out)

    c = _collapse_dup_tokens(c)
    r = _collapse_dup_tokens(r)
    c_tokens = {t.lower() for t in re.split(r"[\s/|_-]+", c) if t}
    r_tokens = {t.lower() for t in re.split(r"[\s/|_-]+", r) if t}
    if c.lower() == r.lower() or r_tokens <= c_tokens:
        return c
    if c_tokens <= r_tokens:
        return r
    # Prefer rule title when connector is a short product name already inside rule.
    if len(c_tokens) <= 2 and any(tok in r.lower() for tok in c_tokens):
        return r
    return f"{c} / {r}"


def _first_paragraph(text: str, *, limit: int = 1_200) -> str:
    for block in re.split(r"\n\s*\n", text or ""):
        para = _clean(block, limit=limit)
        if not para or para.startswith("#"):
            continue
        if para.lower().startswith("| field"):
            continue
        return para
    return _clean(text, limit=limit)


def _extract_section(inv: str, heading: str, *, limit: int = 2_400) -> str:
    pattern = rf"##\s*{re.escape(heading)}\s*(.+?)(?=\n##\s|\Z)"
    match = re.search(pattern, inv or "", flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    body = match.group(1).strip()
    # Keep up to two prose paragraphs; drop tables.
    paras: list[str] = []
    for block in re.split(r"\n\s*\n", body):
        para = _clean(block, limit=limit)
        if not para or para.startswith("|") or para.startswith("#"):
            continue
        paras.append(para)
        if len(paras) >= 2:
            break
    return "\n\n".join(paras)


def _extract_investigation_summary(inv: str) -> str:
    """Prefer Executive Summary body from AI Investigation markdown."""
    section = _extract_section(inv, "Executive Summary", limit=2_200)
    if section:
        return section
    return _first_paragraph(inv, limit=1_400)


def _extract_explanation(alert_like: dict[str, Any]) -> dict[str, Any]:
    extra = alert_like.get("enrichment_data")
    if isinstance(extra, dict):
        stored = extra.get("contextual_explanation")
        if isinstance(stored, dict):
            return stored
    direct = alert_like.get("contextual_explanation")
    return direct if isinstance(direct, dict) else {}


def _extract_handoff_meta(enrichment: dict[str, Any] | None) -> dict[str, str]:
    meta: dict[str, str] = {k: "" for k in _HANDOFF_KEYS}
    if not isinstance(enrichment, dict):
        return meta
    stored = enrichment.get("report_handoff")
    if not isinstance(stored, dict):
        return meta
    for key in _HANDOFF_KEYS:
        raw = stored.get(key)
        if isinstance(raw, str):
            meta[key] = raw.strip()[:160]
    return meta


def summarize_llm_payload(payload: Any, *, max_items: int = 14) -> list[str]:
    """Keep only useful evidence fields; drop None/empty noise."""
    if not isinstance(payload, dict) or not payload:
        return []
    lines: list[str] = []
    for key in _LLM_EVIDENCE_KEYS:
        if key not in payload:
            continue
        value = payload.get(key)
        if _is_blank(value):
            continue
        rendered = _clean(value, limit=260)
        if not rendered:
            continue
        lines.append(f"{key}: `{rendered}`")
        if len(lines) >= max_items:
            break
    return lines


def format_runbook_steps(steps: list[dict[str, Any]], *, limit: int = 12) -> list[str]:
    """Only real recorded steps — skip empty/pending noise."""
    out: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        status = _clean(step.get("status"), limit=40).lower()
        if status in {"pending", ""}:
            if not _clean(step.get("summary"), limit=20):
                continue
        summary = _clean(step.get("summary"), limit=280)
        if not summary:
            continue
        # Skip "empty / not run yet" Tier-2 placeholders in customer report.
        if "not run yet" in summary.lower() or "هنوز اجرا نشده" in summary:
            continue
        stage = _clean(step.get("stage_label") or step.get("stage") or step.get("action_name"), limit=60) or "گام"
        label = _clean(step.get("action_name"), limit=60)
        prefix = stage if not label or label == stage else f"{stage} · {label}"
        out.append(f"{prefix}: {summary}")
        if len(out) >= limit:
            break
    return out


def build_alert_report_inputs(
    alert: Any,
    *,
    investigation_markdown: str | None = None,
    runbook_steps: list[dict[str, Any]] | None = None,
    runbook_procedure: list[dict[str, Any]] | None = None,
    handoff_meta: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Normalize an Alert ORM / dict into report inputs."""
    del runbook_procedure  # not rendered as empty pending checklist
    if hasattr(alert, "title"):
        enrichment = getattr(alert, "enrichment_data", None) or {}
        if not isinstance(enrichment, dict):
            enrichment = {}
        expl = enrichment.get("contextual_explanation")
        if not isinstance(expl, dict):
            expl = {}
        mitre = [str(t) for t in (getattr(alert, "mitre_techniques", None) or []) if t]
        iocs: list[Any] = []
        if isinstance(enrichment.get("iocs"), list):
            iocs = enrichment["iocs"]
        tier2 = enrichment.get("tier2_runbook") if isinstance(enrichment.get("tier2_runbook"), dict) else {}
        stored_meta = _extract_handoff_meta(enrichment)
        if handoff_meta:
            for key in _HANDOFF_KEYS:
                val = handoff_meta.get(key)
                if isinstance(val, str) and val.strip():
                    stored_meta[key] = val.strip()[:160]
        inv = investigation_markdown or ""
        if not inv.strip():
            stored_inv = enrichment.get("investigation_report")
            if isinstance(stored_inv, str):
                inv = stored_inv
            elif isinstance(stored_inv, dict):
                inv = str(stored_inv.get("markdown") or "")
        return {
            "id": str(getattr(alert, "id", "")),
            "title": str(getattr(alert, "title", "") or ""),
            "description": str(
                getattr(alert, "description", "") or getattr(alert, "narrative", "") or ""
            ),
            "severity": str(getattr(alert, "severity", "") or "medium"),
            "status": str(getattr(alert, "status", "") or ""),
            "disposition": str(getattr(alert, "disposition", "") or ""),
            "source": _dedupe_source(
                str(getattr(alert, "connector_type", "") or ""),
                str(getattr(alert, "rule_name", "") or ""),
            ),
            "rule_name": _clean(getattr(alert, "rule_name", None), limit=160),
            "created_at": getattr(alert, "created_at", None),
            "ai_summary": str(getattr(alert, "ai_summary", "") or ""),
            "narrative": str(getattr(alert, "narrative", "") or ""),
            "affected_hosts": list(getattr(alert, "affected_hosts", None) or []),
            "affected_ips": list(getattr(alert, "affected_ips", None) or []),
            "affected_users": list(getattr(alert, "affected_users", None) or []),
            "mitre_techniques": mitre,
            "iocs": iocs,
            "contextual_explanation": expl,
            "investigation_markdown": inv,
            "llm_payload": getattr(alert, "llm_payload", None) or None,
            "runbook_steps": list(runbook_steps or []),
            "tier2_runbook": tier2,
            "enrichment_data": enrichment,
            **stored_meta,
        }
    data = dict(alert)
    data["contextual_explanation"] = _extract_explanation(data)
    data.setdefault("investigation_markdown", investigation_markdown or "")
    data.setdefault("runbook_steps", list(runbook_steps or []))
    for key in _HANDOFF_KEYS:
        data.setdefault(key, (handoff_meta or {}).get(key, ""))
    return data


def _compose_sharh(inp: dict[str, Any]) -> str:
    """Richer Persian narrative: greeting + explain + investigation assessment."""
    expl = inp.get("contextual_explanation") if isinstance(inp.get("contextual_explanation"), dict) else {}
    meaning = _clean(expl.get("meaning") or "", limit=2_000)
    inv = str(inp.get("investigation_markdown") or "")
    inv_summary = _extract_investigation_summary(inv) if inv.strip() else ""
    forensic = _extract_section(inv, "Forensic Findings", limit=1_600) if inv.strip() else ""
    title = _clean(inp.get("title"), limit=200)
    parts: list[str] = ["با سلام و احترام"]
    if title:
        parts.append(f"پس از بررسی هشدار «{title}»، خلاصه وضعیت به شرح زیر است.")
    # Prefer investigation executive summary when substantive; else explain meaning.
    core = ""
    if inv_summary and len(inv_summary) >= 40:
        core = inv_summary
    elif meaning:
        core = meaning
    elif inv_summary:
        core = inv_summary
    else:
        core = _clean(inp.get("description") or inp.get("ai_summary") or "", limit=1_400)
    if core:
        parts.append(core)
    if meaning and inv_summary and meaning not in inv_summary and len(meaning) >= 40:
        parts.append(f"توضیح تشخیص (Explain): {meaning}")
    if forensic and forensic not in "\n".join(parts):
        parts.append(f"جمع‌بندی بررسی فنی: {forensic}")
    if len(parts) <= 1:
        parts.append(
            "این هشدار به‌عنوان true positive ثبت شده است. "
            "برای تکمیل شرح، Explain و Investigate را اجرا کنید."
        )
    return "\n\n".join(parts)


def _compose_details(inp: dict[str, Any]) -> list[str]:
    """Detail bullets + short prose context (not a wall of English dump)."""
    lines: list[str] = []
    source = _clean(inp.get("source"), limit=160)
    if source:
        lines.append(f"منبع تشخیص: `{source}`")
    rule = _clean(inp.get("rule_name"), limit=160)
    if rule and rule.lower() not in source.lower():
        lines.append(f"نام قاعده: `{rule}`")

    hosts = _bullets([str(h) for h in (inp.get("affected_hosts") or [])], limit=8)
    ips = _bullets([str(i) for i in (inp.get("affected_ips") or [])], limit=8)
    users = _bullets([str(u) for u in (inp.get("affected_users") or [])], limit=8)
    if hosts:
        lines.append("میزبان‌ها: " + "، ".join(f"`{h}`" for h in hosts))
    if ips:
        lines.append("IPها: " + "، ".join(f"`{i}`" for i in ips))
    if users:
        lines.append("کاربران: " + "، ".join(f"`{u}`" for u in users))
    mitre = _bullets([str(t) for t in (inp.get("mitre_techniques") or [])], limit=8)
    if mitre:
        lines.append("MITRE ATT&CK: " + "، ".join(f"`{t}`" for t in mitre))

    evidence = summarize_llm_payload(inp.get("llm_payload"), max_items=12)
    if evidence:
        lines.append("شواهد استخراج‌شده از LLM Payload:")
        lines.extend(f"  - {item}" for item in evidence)

    iocs = inp.get("iocs") if isinstance(inp.get("iocs"), list) else []
    for ioc in iocs[:8]:
        if isinstance(ioc, dict):
            kind = _clean(ioc.get("type"), limit=40)
            value = _clean(ioc.get("value"), limit=160)
            if kind and value:
                lines.append(f"IOC ({kind}): `{value}`")
        else:
            value = _clean(ioc, limit=160)
            if value:
                lines.append(f"IOC: `{value}`")

    tier2 = inp.get("tier2_runbook") if isinstance(inp.get("tier2_runbook"), dict) else {}
    if tier2:
        pivot = tier2.get("pivot") if isinstance(tier2.get("pivot"), dict) else {}
        src = pivot.get("src_ips") if isinstance(pivot.get("src_ips"), list) else []
        dest = pivot.get("dest_ips") if isinstance(pivot.get("dest_ips"), list) else []
        related = pivot.get("related_alert_ids") if isinstance(pivot.get("related_alert_ids"), list) else []
        case_id = pivot.get("case_id")
        bits: list[str] = []
        if src:
            bits.append("src=" + ", ".join(f"`{x}`" for x in src[:4]))
        if dest:
            bits.append("dest=" + ", ".join(f"`{x}`" for x in dest[:4]))
        if related:
            bits.append(f"related_alerts={max(0, len(related) - 1)}")
        if case_id:
            bits.append(f"case=`{case_id}`")
        if bits:
            lines.append("Tier-2 IP pivot: " + " · ".join(bits))
        for step in (tier2.get("steps") or [])[:5]:
            if not isinstance(step, dict):
                continue
            summary = _clean(step.get("summary"), limit=220)
            status = _clean(step.get("status"), limit=40)
            if summary and status not in {"pending", ""}:
                label = _clean(step.get("label") or step.get("action_name"), limit=80) or "Tier-2"
                lines.append(f"{label}: {summary}")

    # Short analyst guidance paragraph when evidence is thin.
    if len(lines) <= 2:
        lines.append(
            "جزئیات موجودیتی در اسنپ‌شات هشدار محدود است؛ "
            "رویدادهای خام SIEM و خروجی Explain/Investigate برای تکمیل لازم است."
        )
    return lines


def _compose_actions(inp: dict[str, Any]) -> list[str]:
    """Recommended actions — from Explain; guidance to execute/track in Runbook."""
    expl = inp.get("contextual_explanation") if isinstance(inp.get("contextual_explanation"), dict) else {}
    steps = _bullets([str(s) for s in (expl.get("suggested_next_steps") or []) if s], limit=8)
    if steps:
        return steps
    # Prefer concrete Tier-2 follow-ups when explain is empty.
    tier2 = inp.get("tier2_runbook") if isinstance(inp.get("tier2_runbook"), dict) else {}
    pivot = tier2.get("pivot") if isinstance(tier2.get("pivot"), dict) else {}
    related = pivot.get("related_alert_ids") if isinstance(pivot.get("related_alert_ids"), list) else []
    if len(related) > 1:
        return [
            "هشدارهای مرتبط ۲۴ساعته (Tier-2) داخل Case تجمیع‌شده را در Runbook بررسی و triage کنید.",
            "Investigate را روی Case اجرا کنید تا گزارش همه هشدارهای لینک‌شده را پوشش دهد.",
            "شواهد میزبان/فایل (hash، مسیر، action) را از SIEM استخراج و در Runbook ثبت کنید.",
        ]
    return [
        "رویدادهای خام مرتبط را در SIEM حفظ و در Runbook (مرحله Investigate) ثبت کنید.",
        "شواهد سطح میزبان برای تأیید یا رد بهره‌برداری را بررسی و نتیجه را در Runbook بنویسید.",
        "نتیجه triage / containment را در Runbook ببندید و گزارش را به‌روز کنید.",
    ]


def render_persian_incident_report(
    inp: dict[str, Any],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Persian customer handoff report with richer narrative + Runbook section."""
    moment = generated_at or datetime.now(UTC)
    title = _clean(inp.get("title"), limit=300) or "رویداد امنیتی بدون عنوان"
    severity = _severity_fa(str(inp.get("severity") or "medium"))
    disposition = _status_fa(str(inp.get("disposition") or "true_positive"))
    created = inp.get("created_at")
    if isinstance(created, datetime):
        event_date = created.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    else:
        event_date = _clean(created, limit=64) or moment.strftime("%Y-%m-%d %H:%M UTC")

    sharh = _compose_sharh(inp)
    details = _compose_details(inp)
    actions = _compose_actions(inp)
    runbook = format_runbook_steps(
        inp.get("runbook_steps") if isinstance(inp.get("runbook_steps"), list) else [],
        limit=10,
    )

    lines: list[str] = [
        "# گزارش رخداد سایبری",
        "",
        "جهت ارائه به",
        _handoff_value(inp.get("audience")),
        "",
        "تهیه شده توسط",
        _handoff_value(inp.get("prepared_by")),
        "",
        f"پروژه: {_handoff_value(inp.get('project_name'))}",
        f"تاریخ رخداد: {event_date}",
        f"تاریخ گزارش: {moment.strftime('%Y-%m-%d %H:%M UTC')}",
        f"کارشناس شیفت: {_handoff_value(inp.get('analyst'))}",
        f"تایید توسط: {_handoff_value(inp.get('approved_by'))}",
        "",
        f"عنوان رویداد: {title}",
        f"شدت رویداد: {severity}",
        f"وضعیت رویداد: {disposition}",
        "",
        "شرح رویداد:",
        sharh,
        "",
        "جزئیات رویداد:",
    ]
    if details:
        for item in details:
            lines.append(f"- {item}" if not item.startswith("  - ") else item)
    else:
        lines.append(
            "- جزئیات موجودیتی در اسنپ‌شات هشدار ثبت نشده؛ "
            "رویدادهای خام SIEM برای تکمیل لازم است."
        )

    lines.extend(
        [
            "",
            "اقدامات انجام‌شده (Runbook):",
        ]
    )
    if runbook:
        for item in runbook:
            lines.append(f"- {item}")
    else:
        lines.append(
            "- هنوز اقدام اجراشده‌ای در Runbook ثبت نشده است. "
            "اقدامات پیشنهادی زیر را در تب Runbook انجام و ثبت کنید."
        )

    lines.extend(
        [
            "",
            "اقدامات پیشنهادی:",
            "(این موارد راهنمای تحلیل‌گر است و باید در تب Runbook اجرا/ثبت شوند.)",
        ]
    )
    for item in actions:
        lines.append(f"- {item}")
    lines.extend(["", "با تشکر.", ""])
    return "\n".join(lines).strip() + "\n"


def render_bilingual_incident_report(
    inp: dict[str, Any],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Back-compat entrypoint — returns the Persian handoff."""
    return render_persian_incident_report(inp, generated_at=generated_at)


def is_true_positive_disposition(disposition: str | None) -> bool:
    return (disposition or "").strip().lower() in {"true_positive", "likely_tp", "escalate"}


def render_persian_handoff(
    inp: dict[str, Any],
    *,
    generated_at: datetime | None = None,
) -> str:
    return render_persian_incident_report(inp, generated_at=generated_at)


def severity_label_fa(severity: str) -> str:
    return _severity_fa(severity)


def status_label_fa(status: str) -> str:
    return _status_fa(status)


def normalize_handoff_meta(payload: dict[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {k: "" for k in _HANDOFF_KEYS}
    if not isinstance(payload, dict):
        return out
    for key in _HANDOFF_KEYS:
        raw = payload.get(key)
        if isinstance(raw, str):
            out[key] = raw.strip()[:160]
    return out
