"""Unit tests for bilingual true-positive incident reports."""

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
    assert is_true_positive_disposition("escalate")
    assert not is_true_positive_disposition("false_positive")
    assert not is_true_positive_disposition(None)


def test_handoff_fields_are_placeholders_not_hardcoded_customer():
    md = render_bilingual_incident_report(
        {
            "id": str(uuid4()),
            "title": "Soorin-Web-Command Injection Attempts",
            "severity": "high",
            "disposition": "true_positive",
            "description": "short desc",
            "contextual_explanation": {
                "meaning": "Signature/pattern match on URL content.",
                "markdown": (
                    "## What this alert means\n\n"
                    "Signature/pattern match on URL content.\n\n"
                    "## Suggested next steps\n\n"
                    "- Pull raw Splunk events\n"
                ),
                "suggested_next_steps": ["Pull raw Splunk events"],
            },
            "llm_payload": {
                "url": "/admin?cmd=whoami",
                "src_ip": "203.0.113.9",
                "orig_rule_description": "Web datamodel proxyshell macro",
            },
            "runbook_steps": [
                {
                    "stage_label": "Triage",
                    "status": "recorded",
                    "summary": "Analyst set true_positive",
                    "actor_label": "analyst",
                    "occurred_at": "2026-11-14T07:00:00Z",
                }
            ],
            "runbook_procedure": [
                {"stage_label": "Investigation", "status": "done"},
                {"stage_label": "Response", "status": "pending"},
            ],
            "investigation_markdown": (
                "# Incident Report\n\n## Executive Summary\n\n"
                "Full investigation found probing against Soorin-Web.\n"
            ),
            "audience": "",
            "prepared_by": "",
            "project_name": "",
            "source": "splunk",
            "created_at": datetime(2026, 11, 14, 6, 39, 50, tzinfo=UTC),
        }
    )
    assert "آستان قدس" not in md
    assert "[پر شود توسط تحلیل‌گر]" in md
    assert "# Cyber Incident Report" in md
    assert "# گزارش رخداد سایبری" in md
    assert "Alert explanation (Ambient Copilot)" in md
    assert "LLM evidence payload" in md
    assert "203.0.113.9" in md
    assert "Runbook / response workflow" in md
    assert "Analyst set true_positive" in md
    assert "AI Investigation (full)" in md
    assert "Full investigation found probing" in md
    assert "مراحل Runbook" in md


def test_normalize_handoff_meta():
    meta = normalize_handoff_meta(
        {"audience": "  تیم امنیت  ", "project_name": "پروژه الف", "extra": "x"}
    )
    assert meta["audience"] == "تیم امنیت"
    assert meta["project_name"] == "پروژه الف"
    assert meta["prepared_by"] == ""


def test_summarize_llm_payload_prefers_useful_keys():
    lines = summarize_llm_payload(
        {"url": "/x", "src_ip": "1.2.3.4", "_internal": "skip", "noise": {"a": 1}}
    )
    assert any("url" in line for line in lines)
    assert any("src_ip" in line for line in lines)


def test_case_report_has_no_hardcoded_aqr():
    case_id = uuid4()
    alert_id = uuid4()
    brief = build_brief_from_rows(
        BriefInputs(
            case=BriefCaseRow(
                id=case_id,
                case_number="INC-7",
                title="Command injection cluster",
                description=None,
                severity="high",
                status="investigating",
                tags={"reportable": True},
                mitre_techniques=["T1190"],
                evidence_chain=[],
                alert_ids=[str(alert_id)],
            ),
            alerts=[
                BriefAlertRow(
                    id=alert_id,
                    title="Soorin-Web-Command Injection Attempts",
                    severity="high",
                    disposition="true_positive",
                    funnel_stage="ready_for_jira",
                    ai_summary="Pattern match on URL content.",
                    narrative=None,
                    confidence=70,
                    mitre_techniques=["T1190"],
                    explanation_markdown="## What this alert means\n\nSignature hit.",
                    explanation_meaning="Signature hit on URL content.",
                    suggested_next_steps=["Preserve raw logs"],
                )
            ],
        )
    )
    md = render_case_report_markdown(brief)
    assert "آستان قدس" not in md
    assert "[پر شود توسط تحلیل‌گر]" in md


def test_build_alert_report_inputs_uses_handoff_and_llm_payload():
    alert = SimpleNamespace(
        id=uuid4(),
        title="t",
        description="d",
        severity="medium",
        status="new",
        disposition="true_positive",
        connector_type="splunk",
        rule_name="web_attack_detection",
        created_at=datetime.now(UTC),
        ai_summary=None,
        narrative=None,
        affected_hosts=[],
        affected_ips=[],
        affected_users=[],
        mitre_techniques=[],
        llm_payload={"src_ip": "10.0.0.1"},
        enrichment_data={
            "contextual_explanation": {
                "markdown": "## What\n\nx",
                "meaning": "meaning",
                "suggested_next_steps": ["a"],
            },
            "report_handoff": {"audience": "مرکز X", "project_name": "P1"},
        },
    )
    inp = build_alert_report_inputs(alert)
    assert inp["audience"] == "مرکز X"
    assert inp["project_name"] == "P1"
    assert inp["source"] == "splunk / web_attack_detection"
    assert inp["llm_payload"]["src_ip"] == "10.0.0.1"
