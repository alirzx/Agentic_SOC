"""Unit tests for concise Persian incident handoff reports."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from app.services.bilingual_incident_report import (
    build_alert_report_inputs,
    is_true_positive_disposition,
    normalize_handoff_meta,
    render_bilingual_incident_report,
    summarize_llm_payload,
)
from app.services.case_investigation_brief import (
    BriefAlertRow,
    BriefCaseRow,
    BriefInputs,
    build_brief_from_rows,
    render_case_report_markdown,
)


def test_is_true_positive_disposition():
    assert is_true_positive_disposition("true_positive")
    assert not is_true_positive_disposition("false_positive")


def test_concise_persian_report_omits_noise_and_english_dump():
    md = render_bilingual_incident_report(
        {
            "id": str(uuid4()),
            "title": "Soorin-Web-Command Injection Attempts",
            "severity": "high",
            "disposition": "true_positive",
            "description": "short",
            "contextual_explanation": {
                "meaning": "این یک تطبیق الگو روی URL است، نه نفوذ تأییدشده.",
                "suggested_next_steps": [
                    "رویدادهای خام Splunk را استخراج کنید",
                    "شواهد اجرا روی میزبان را بررسی کنید",
                ],
            },
            "llm_payload": {
                "url": "/admin?cmd=whoami",
                "src_ip": "203.0.113.9",
                "risk_score": None,
                "severity": "high",
            },
            "runbook_steps": [
                {
                    "stage_label": "Triage",
                    "status": "pending",
                    "summary": "",
                },
                {
                    "stage_label": "Triage",
                    "status": "recorded",
                    "summary": "تحلیل‌گر true_positive ثبت کرد",
                },
            ],
            "investigation_markdown": (
                "# Incident Report\n\n## Executive Summary\n\n"
                "شواهد با تطبیق الگوی URL و احتمال مثبت کاذب سازگار است؛ "
                "نفوذ تأیید نشده و باید رویداد خام بررسی شود.\n\n"
                "## Timeline\n\nlong english dump should not appear\n"
            ),
            "audience": "",
            "source": "splunk",
            "created_at": datetime(2026, 11, 14, 6, 39, 50, tzinfo=UTC),
        }
    )
    assert md.startswith("# گزارش رخداد سایبری")
    assert "Cyber Incident Report" not in md
    assert "آستان قدس" not in md
    assert "[پر شود توسط تحلیل‌گر]" in md
    assert "شرح رویداد:" in md
    assert "جزئیات رویداد:" in md
    assert "اقدامات پیشنهادی:" in md
    assert "اقدامات انجام‌شده (Runbook):" in md
    assert "تب Runbook" in md
    assert "با سلام و احترام" in md
    assert "203.0.113.9" in md
    assert "risk_score" not in md
    assert "long english dump" not in md
    assert "تحلیل‌گر true_positive ثبت کرد" in md
    assert "شواهد با تطبیق الگوی URL" in md
    assert md.count("pending") == 0


def test_normalize_handoff_meta():
    meta = normalize_handoff_meta({"audience": "  تیم امنیت  ", "project_name": "P1"})
    assert meta["audience"] == "تیم امنیت"
    assert meta["project_name"] == "P1"


def test_summarize_llm_payload_skips_none():
    lines = summarize_llm_payload({"url": "/x", "risk_score": None, "src_ip": "1.2.3.4"})
    assert any("url" in line for line in lines)
    assert any("src_ip" in line for line in lines)
    assert not any("risk_score" in line for line in lines)


def test_case_report_persian_appendix_has_placeholders():
    brief = build_brief_from_rows(
        BriefInputs(
            case=BriefCaseRow(
                id=uuid4(),
                case_number="INC-7",
                title="Command injection",
                description=None,
                severity="high",
                status="investigating",
                tags={"reportable": True},
                mitre_techniques=["T1190"],
                evidence_chain=[],
                alert_ids=[str(uuid4())],
            ),
            alerts=[
                BriefAlertRow(
                    id=uuid4(),
                    title="ESCU rule",
                    severity="high",
                    disposition="true_positive",
                    funnel_stage="ready_for_jira",
                    ai_summary="Pattern match",
                    narrative=None,
                    confidence=70,
                    mitre_techniques=["T1190"],
                    explanation_meaning="تطبیق الگو",
                    suggested_next_steps=["حفظ لاگ"],
                )
            ],
        )
    )
    md = render_case_report_markdown(brief)
    assert "آستان قدس" not in md
    assert "[پر شود توسط تحلیل‌گر]" in md


def test_build_alert_report_inputs_dedupes_source():
    alert = SimpleNamespace(
        id=uuid4(),
        title="t",
        description="d",
        severity="high",
        status="new",
        disposition="true_positive",
        connector_type="splunk",
        rule_name="splunk",
        created_at=datetime.now(UTC),
        ai_summary=None,
        narrative=None,
        affected_hosts=[],
        affected_ips=[],
        affected_users=[],
        mitre_techniques=[],
        llm_payload=None,
        enrichment_data={},
    )
    inp = build_alert_report_inputs(alert)
    assert inp["source"] == "splunk"
