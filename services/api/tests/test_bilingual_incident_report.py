"""Unit tests for bilingual true-positive incident reports."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.services.bilingual_incident_report import (
    build_alert_report_inputs,
    is_true_positive_disposition,
    render_bilingual_incident_report,
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


def test_render_bilingual_includes_en_and_fa_sections():
    md = render_bilingual_incident_report(
        {
            "id": str(uuid4()),
            "title": "Soorin-Web-Command Injection Attempts",
            "severity": "high",
            "disposition": "true_positive",
            "description": "URL pattern match against command-injection macro.",
            "ai_summary": "Signature hit, not confirmed compromise.",
            "contextual_explanation": {
                "meaning": "This is a signature/pattern match on URL content.",
                "suggested_next_steps": [
                    "Pull raw Splunk events for the source_ref",
                    "Hunt host for w3wp.exe child processes",
                ],
            },
            "affected_hosts": ["soorin-web-01"],
            "mitre_techniques": ["T1190"],
            "source": "splunk",
            "created_at": datetime(2026, 11, 14, 6, 39, 50, tzinfo=UTC),
        }
    )
    assert "# Cyber Incident Report" in md
    assert "# گزارش رخداد سایبری" in md
    assert "شرح رویداد" in md
    assert "اقدامات پیشنهادی" in md
    assert "Soorin-Web-Command Injection Attempts" in md
    assert "Pull raw Splunk events" in md
    assert "**شدت رویداد:** بالا" in md


def test_case_report_appends_persian_handoff():
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
    assert "# Case Report" in md
    assert "گزارش رخداد سایبری" in md
    assert "Preserve raw logs" in md


def test_build_alert_report_inputs_from_namespace():
    from types import SimpleNamespace

    alert = SimpleNamespace(
        id=uuid4(),
        title="t",
        description="d",
        severity="medium",
        status="new",
        disposition="true_positive",
        connector_type="splunk",
        rule_name="r",
        created_at=datetime.now(UTC),
        ai_summary=None,
        narrative=None,
        affected_hosts=[],
        affected_ips=[],
        affected_users=[],
        mitre_techniques=[],
        enrichment_data={
            "contextual_explanation": {
                "markdown": "## What\n\nx",
                "meaning": "meaning",
                "suggested_next_steps": ["a"],
            }
        },
    )
    inp = build_alert_report_inputs(alert)
    assert inp["contextual_explanation"]["meaning"] == "meaning"
