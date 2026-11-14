"""Bilingual (EN + FA) incident reports for true-positive alerts/cases.

Content priority (richest first):
1. AI Investigation Markdown (full agent report)
2. Ambient Copilot Explain Markdown (full sections + next steps)
3. Curated ``llm_payload`` evidence fields
4. Runbook procedure / ledger steps (human-readable)
5. Alert snapshot fields (hosts, IOCs, MITRE)

Persian handoff header fields (audience / project / prepared_by / analyst /
approved_by) are **operator-filled** — never hardcoded to a customer name.
Empty fields render as ``[پر شود توسط تحلیل‌گر]``.
"""

from __future__ import annotations

import json
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

_PLACEHOLDER_FA = "[پر شود توسط تحلیل‌گر]"
_HANDOFF_KEYS = (
    "audience",
    "prepared_by",
    "project_name",
    "analyst",
    "approved_by",
)

# Prefer these llm_payload keys when summarizing evidence for the report.
_LLM_PAYLOAD_PREFERRED_KEYS: tuple[str, ...] = (
    "summary",
    "title",
    "description",
    "rule_name",
    "rule_id",
    "detection",
    "severity",
    "risk_score",
    "confidence",
    "src_ip",
    "dest_ip",
    "src",
    "dest",
    "host",
    "hostname",
    "user",
    "username",
    "url",
    "uri",
    "http_method",
    "status",
    "user_agent",
    "process",
    "cmdline",
    "file_path",
    "hash",
    "sha256",
    "mitre",
    "techniques",
    "iocs",
    "evidence",
    "raw_fields",
    "notable",
    "search_name",
    "orig_rule_description",
    "orig_rule_title",
)


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


def _handoff_value(value: Any) -> str:
    cleaned = _clean(value, limit=160)
    return cleaned if cleaned else _PLACEHOLDER_FA


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


def summarize_llm_payload(payload: Any, *, max_items: int = 24) -> list[str]:
    """Flatten curated LLM evidence into short report lines (no raw dump)."""
    if not isinstance(payload, dict) or not payload:
        return []
    lines: list[str] = []
    seen: set[str] = set()

    def _add(label: str, value: Any) -> None:
        if len(lines) >= max_items:
            return
        if isinstance(value, (dict, list)):
            try:
                rendered = json.dumps(value, ensure_ascii=False, default=str)
            except TypeError:
                rendered = str(value)
        else:
            rendered = str(value)
        rendered = _clean(rendered, limit=320)
        if not rendered:
            return
        key = f"{label}:{rendered}"
        if key in seen:
            return
        seen.add(key)
        lines.append(f"**{label}:** {rendered}")

    for key in _LLM_PAYLOAD_PREFERRED_KEYS:
        if key in payload:
            _add(key, payload.get(key))
    # Catch remaining top-level scalars / short lists.
    for key, value in payload.items():
        if key in _LLM_PAYLOAD_PREFERRED_KEYS:
            continue
        if key.startswith("_"):
            continue
        if isinstance(value, (str, int, float, bool)) or (
            isinstance(value, list) and len(value) <= 8
        ):
            _add(str(key), value)
        if len(lines) >= max_items:
            break
    return lines


def format_runbook_steps(steps: list[dict[str, Any]], *, limit: int = 40) -> list[str]:
    """Human-readable runbook timeline lines."""
    out: list[str] = []
    for step in steps[:limit]:
        if not isinstance(step, dict):
            continue
        stage = _clean(step.get("stage_label") or step.get("stage"), limit=40) or "Step"
        summary = _clean(step.get("summary"), limit=280)
        status = _clean(step.get("status"), limit=40)
        actor = _clean(step.get("actor_label") or step.get("actor_type"), limit=80)
        when = step.get("occurred_at")
        when_s = ""
        if isinstance(when, datetime):
            when_s = when.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
        elif when:
            when_s = _clean(when, limit=40)
        bits = [f"**{stage}**"]
        if status:
            bits.append(f"`{status}`")
        if when_s:
            bits.append(when_s)
        if actor:
            bits.append(f"by {actor}")
        head = " · ".join(bits)
        if summary:
            out.append(f"- {head}: {summary}")
        else:
            out.append(f"- {head}")
    return out


def format_runbook_procedure(procedure: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for item in procedure[:20]:
        if not isinstance(item, dict):
            continue
        label = _clean(item.get("stage_label") or item.get("stage"), limit=60)
        status = _clean(item.get("status"), limit=40)
        if label:
            out.append(f"- {label}: `{status or 'pending'}`")
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
    if hasattr(alert, "title"):
        enrichment = getattr(alert, "enrichment_data", None) or {}
        if not isinstance(enrichment, dict):
            enrichment = {}
        expl = enrichment.get("contextual_explanation")
        if not isinstance(expl, dict):
            expl = {}
        mitre = list(getattr(alert, "mitre_techniques", None) or [])
        iocs: list[Any] = []
        if isinstance(enrichment.get("iocs"), list):
            iocs = enrichment["iocs"]
        stored_meta = _extract_handoff_meta(enrichment)
        if handoff_meta:
            for key in _HANDOFF_KEYS:
                val = handoff_meta.get(key)
                if isinstance(val, str) and val.strip():
                    stored_meta[key] = val.strip()[:160]
        connector = _clean(getattr(alert, "connector_type", None), limit=80)
        rule = _clean(getattr(alert, "rule_name", None), limit=160)
        source = connector or rule
        if connector and rule and rule.lower() != connector.lower():
            source = f"{connector} / {rule}"
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
            "source": source,
            "rule_name": rule,
            "created_at": getattr(alert, "created_at", None),
            "ai_summary": str(getattr(alert, "ai_summary", "") or ""),
            "narrative": str(getattr(alert, "narrative", "") or ""),
            "affected_hosts": list(getattr(alert, "affected_hosts", None) or []),
            "affected_ips": list(getattr(alert, "affected_ips", None) or []),
            "affected_users": list(getattr(alert, "affected_users", None) or []),
            "mitre_techniques": [str(t) for t in mitre if t],
            "iocs": iocs,
            "contextual_explanation": expl,
            "investigation_markdown": inv,
            "llm_payload": getattr(alert, "llm_payload", None) or None,
            "runbook_steps": list(runbook_steps or []),
            "runbook_procedure": list(runbook_procedure or []),
            **stored_meta,
        }
    data = dict(alert)
    data["contextual_explanation"] = _extract_explanation(data)
    data.setdefault("investigation_markdown", investigation_markdown or "")
    data.setdefault("runbook_steps", list(runbook_steps or []))
    data.setdefault("runbook_procedure", list(runbook_procedure or []))
    for key in _HANDOFF_KEYS:
        data.setdefault(key, (handoff_meta or {}).get(key, ""))
    return data


def _english_section(inp: dict[str, Any], *, generated_at: datetime) -> str:
    title = _clean(inp.get("title"), limit=300) or "Untitled alert"
    severity = _clean(inp.get("severity"), limit=40) or "medium"
    disposition = _clean(inp.get("disposition"), limit=40) or "true_positive"
    expl = inp.get("contextual_explanation") if isinstance(inp.get("contextual_explanation"), dict) else {}
    meaning = _clean(expl.get("meaning") or "", limit=2_500)
    expl_md = _clean(expl.get("markdown") or "", limit=12_000)
    steps = _bullets([str(s) for s in (expl.get("suggested_next_steps") or []) if s], limit=12)
    inv = str(inp.get("investigation_markdown") or "").strip()
    if len(inv) > 40_000:
        inv = inv[:40_000]
    hosts = _bullets([str(h) for h in (inp.get("affected_hosts") or [])])
    ips = _bullets([str(i) for i in (inp.get("affected_ips") or [])])
    users = _bullets([str(u) for u in (inp.get("affected_users") or [])])
    mitre = _bullets([str(t) for t in (inp.get("mitre_techniques") or [])])
    llm_lines = summarize_llm_payload(inp.get("llm_payload"))
    runbook_lines = format_runbook_steps(
        inp.get("runbook_steps") if isinstance(inp.get("runbook_steps"), list) else []
    )
    procedure_lines = format_runbook_procedure(
        inp.get("runbook_procedure") if isinstance(inp.get("runbook_procedure"), list) else []
    )

    lines: list[str] = [
        "# Cyber Incident Report",
        "",
        f"**Alert ID:** `{_clean(inp.get('id'), limit=80)}`  ",
        f"**Title:** {title}  ",
        f"**Severity:** {severity}  ",
        f"**Disposition:** {disposition}  ",
        f"**Source:** {_clean(inp.get('source'), limit=160) or '—'}  ",
        f"**Generated:** {generated_at.isoformat()}  ",
        "",
        "## Executive Summary",
        "",
    ]
    if meaning:
        lines.append(meaning)
    elif inv:
        # First meaningful paragraph from investigation
        para = next((p.strip() for p in inv.split("\n\n") if p.strip() and not p.strip().startswith("#")), "")
        lines.append(para[:2_000] if para else "_See AI Investigation section._")
    else:
        lines.append(
            "Analyst marked this alert as a true positive. Supporting investigation "
            "narrative should be completed with raw telemetry and host evidence."
        )

    if expl_md:
        lines.extend(["", "## Alert explanation (Ambient Copilot)", "", expl_md, ""])

    if llm_lines:
        lines.extend(["", "## LLM evidence payload (curated)", ""])
        for item in llm_lines:
            lines.append(f"- {item}")

    lines.extend(["", "## Scope", ""])
    if hosts or ips or users:
        if hosts:
            lines.append("- **Hosts:** " + ", ".join(f"`{h}`" for h in hosts))
        if ips:
            lines.append("- **IPs:** " + ", ".join(f"`{i}`" for i in ips))
        if users:
            lines.append("- **Users:** " + ", ".join(f"`{u}`" for u in users))
    else:
        lines.append(
            "_No affected hosts/IPs/users on the alert snapshot — use LLM payload / "
            "raw Splunk events to recover entities._"
        )

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

    if procedure_lines or runbook_lines:
        lines.extend(["", "## Runbook / response workflow", ""])
        if procedure_lines:
            lines.append("### Procedure status")
            lines.extend(procedure_lines)
            lines.append("")
        if runbook_lines:
            lines.append("### Governed steps")
            lines.extend(runbook_lines)

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
        lines.extend(["", "## AI Investigation (full)", "", inv, ""])

    return "\n".join(lines).strip()


def _persian_section(inp: dict[str, Any], *, generated_at: datetime) -> str:
    title = _clean(inp.get("title"), limit=300) or "رویداد امنیتی بدون عنوان"
    severity = _severity_fa(str(inp.get("severity") or "medium"))
    disposition = _status_fa(str(inp.get("disposition") or "true_positive"))
    expl = inp.get("contextual_explanation") if isinstance(inp.get("contextual_explanation"), dict) else {}
    meaning = _clean(expl.get("meaning") or "", limit=2_500)
    expl_md = _clean(expl.get("markdown") or "", limit=8_000)
    inv = str(inp.get("investigation_markdown") or "").strip()
    steps = _bullets([str(s) for s in (expl.get("suggested_next_steps") or []) if s], limit=12)
    hosts = _bullets([str(h) for h in (inp.get("affected_hosts") or [])])
    ips = _bullets([str(i) for i in (inp.get("affected_ips") or [])])
    llm_lines = summarize_llm_payload(inp.get("llm_payload"), max_items=16)
    runbook_lines = format_runbook_steps(
        inp.get("runbook_steps") if isinstance(inp.get("runbook_steps"), list) else [],
        limit=25,
    )
    procedure_lines = format_runbook_procedure(
        inp.get("runbook_procedure") if isinstance(inp.get("runbook_procedure"), list) else []
    )
    created = inp.get("created_at")
    if isinstance(created, datetime):
        event_date = created.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    else:
        event_date = _clean(created, limit=64) or generated_at.strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        "# گزارش رخداد سایبری",
        "",
        "جهت ارائه به  ",
        f"**{_handoff_value(inp.get('audience'))}**",
        "",
        "تهیه شده توسط  ",
        f"**{_handoff_value(inp.get('prepared_by'))}**",
        "",
        f"**پروژه:** {_handoff_value(inp.get('project_name'))}  ",
        f"**کارشناس شیفت:** {_handoff_value(inp.get('analyst'))}  ",
        f"**تایید توسط:** {_handoff_value(inp.get('approved_by'))}  ",
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
    elif inv:
        para = next(
            (p.strip() for p in inv.split("\n\n") if p.strip() and not p.strip().startswith("#")),
            "",
        )
        lines.append(para[:2_500] if para else "شرح تفصیلی در بخش یافته‌های بررسی هوش مصنوعی آمده است.")
    else:
        lines.append(
            "این هشدار توسط تحلیل‌گر به‌عنوان true positive ثبت شده است. "
            "برای تکمیل شرح، Explain و Investigate را اجرا کنید تا شواهد LLM Payload "
            "و مراحل Runbook وارد گزارش شود."
        )

    lines.extend(["", "## جزئیات رویداد", ""])
    if expl_md and expl_md != meaning:
        # Keep FA details readable: prefer meaning + structured evidence over raw EN markdown dump
        lines.append(
            "توضیح کامل تشخیص (از Ambient Copilot) در بخش انگلیسی گزارش آمده است؛ "
            "خلاصه‌ای از شواهد curated در ادامه آمده است."
        )
    if llm_lines:
        lines.append("### شواهد LLM Payload")
        for item in llm_lines:
            lines.append(f"- {item}")
    detail_bits: list[str] = []
    source = _clean(inp.get("source"), limit=160)
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
    elif not llm_lines:
        lines.append(
            "در اسنپ‌شات هشدار، موجودیت/IOC کامل نیست؛ از LLM Payload و رویدادهای خام "
            "برای تکمیل جزئیات استفاده کنید."
        )

    if procedure_lines or runbook_lines:
        lines.extend(["", "## مراحل Runbook / گردش پاسخ", ""])
        if procedure_lines:
            lines.append("### وضعیت رویه")
            lines.extend(procedure_lines)
            lines.append("")
        if runbook_lines:
            lines.append("### گام‌های ثبت‌شده")
            lines.extend(runbook_lines)

    if inv:
        lines.extend(
            [
                "",
                "## یافته‌های بررسی هوش مصنوعی",
                "",
                "متن کامل بررسی در بخش انگلیسی (AI Investigation) آمده است. "
                "خلاصه اجرایی همان بخش مبنای تصمیم‌گیری این گزارش است.",
                "",
            ]
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


def normalize_handoff_meta(payload: dict[str, Any] | None) -> dict[str, str]:
    """Sanitize operator-supplied handoff header fields."""
    out: dict[str, str] = {k: "" for k in _HANDOFF_KEYS}
    if not isinstance(payload, dict):
        return out
    for key in _HANDOFF_KEYS:
        raw = payload.get(key)
        if isinstance(raw, str):
            out[key] = raw.strip()[:160]
    return out
