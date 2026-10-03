"""Unit tests for case investigation brief outcome + builder."""

from __future__ import annotations

from uuid import uuid4

from app.services.case_investigation_brief import (
    BriefAlertRow,
    BriefCaseRow,
    BriefInputs,
    build_brief_from_rows,
    derive_case_outcome,
)


def test_derive_outcome_incident_from_tp():
    outcome, rationale = derive_case_outcome(
        dispositions=["true_positive", "needs_review"],
        case_status="investigating",
    )
    assert outcome == "incident"
    assert "true_positive" in rationale


def test_derive_outcome_false_positive():
    outcome, _ = derive_case_outcome(
        dispositions=["false_positive", "benign"],
        case_status="resolved",
    )
    assert outcome == "false_positive"


def test_derive_outcome_needs_review():
    outcome, _ = derive_case_outcome(
        dispositions=["needs_review", "needs_review"],
        case_status="new",
    )
    assert outcome == "needs_review"


def test_build_brief_includes_alerts_evidence_and_actions():
    case_id = uuid4()
    alert_id = uuid4()
    inputs = BriefInputs(
        case=BriefCaseRow(
            id=case_id,
            case_number="INC-42",
            title="Password spray cluster",
            description="Auto-promoted",
            severity="high",
            status="investigating",
            tags={"reportable": True},
            mitre_techniques=["T1110"],
            evidence_chain=[{"kind": "ioc", "summary": "Source IP 203.0.113.9 sprayed accounts"}],
            alert_ids=[str(alert_id)],
        ),
        alerts=[
            BriefAlertRow(
                id=alert_id,
                title="ESCU - Detect Password Spray",
                severity="high",
                disposition="true_positive",
                funnel_stage="ready_for_jira",
                ai_summary="Multiple failed logins from one source — likely spray.",
                narrative=None,
                confidence=88,
                mitre_techniques=["T1110"],
            )
        ],
        task_titles=["SPL: pivot src ↔ dest"],
        investigation_notes=["Auto-created by Agentic SOC funnel."],
        has_external_ref=False,
    )
    brief = build_brief_from_rows(inputs)
    assert brief.outcome == "incident"
    assert brief.outcome_label == "Likely incident"
    assert brief.ready_for_jira is True
    assert len(brief.alerts) == 1
    assert brief.alerts[0].disposition == "true_positive"
    assert any(e.kind == "ioc" for e in brief.evidence)
    assert any(a.kind == "triage" for a in brief.what_we_did)
    assert any(a.kind == "task" for a in brief.what_we_did)
    assert "Jira" in (brief.next_step or "")
