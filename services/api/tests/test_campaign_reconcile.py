"""Unit tests for megacase reconcile helpers (no DB)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.services.campaign_correlation import score_campaign_link, select_campaign_siblings
from app.services.case_investigation_brief import (
    BriefAlertRow,
    BriefCaseRow,
    BriefInputs,
    build_brief_from_rows,
)


def _alert(**overrides):
    row = {
        "id": str(uuid4()),
        "title": "Alert",
        "severity": "high",
        "disposition": "true_positive",
        "rule_id": "r1",
        "rule_name": "r1",
        "affected_hosts": [],
        "affected_ips": [],
        "affected_users": [],
        "mitre_techniques": [],
        "created_at": datetime(2026, 11, 14, 12, 0, tzinfo=UTC),
        "event_time": datetime(2026, 11, 14, 12, 0, tzinfo=UTC),
        "raw_event": {},
        "llm_payload": {},
    }
    row.update(overrides)
    return row


def test_megacase_style_mix_rejects_cross_domain():
    t0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
    seed = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_ips=["1.2.3.4"],
        event_time=t0,
    )
    candidates = [
        _alert(
            title="Soorin-Web-Path Traversal Attempts",
            affected_ips=["1.2.3.4"],
            event_time=t0 + timedelta(minutes=2),
        ),
        _alert(
            title="Soorin-Endpoint-Powershell Invoke Command",
            affected_hosts=["cao01vw065.cao.ir"],
            event_time=t0 + timedelta(minutes=3),
        ),
        _alert(
            title="ESCU - Access LSASS Memory for Dump Creation",
            affected_hosts=["other-host"],
            event_time=t0 + timedelta(minutes=4),
        ),
        _alert(
            title="Risk - 24 Hour Risk Threshold Exceeded",
            affected_ips=["1.2.3.4"],
            event_time=t0 + timedelta(minutes=5),
        ),
        _alert(
            title="Access - Short-lived Account Detected",
            event_time=t0 + timedelta(minutes=6),
        ),
    ]
    accepted, decisions = select_campaign_siblings(seed, candidates)
    titles = {str(a.get("title")) for a in accepted}
    assert "Soorin-Web-Path Traversal Attempts" in titles
    assert "Soorin-Endpoint-Powershell Invoke Command" not in titles
    assert "ESCU - Access LSASS Memory for Dump Creation" not in titles
    assert "Access - Short-lived Account Detected" not in titles
    # Risk may attach as supporting if IP overlaps — role must be supporting.
    for d in decisions:
        if "Risk" in str(d.get("title") or "") or (
            d.get("alert_id")
            and any(
                str(c["id"]) == str(d["alert_id"]) and "Risk" in str(c["title"])
                for c in candidates
            )
        ):
            if d.get("linked"):
                assert d.get("role") == "supporting"


def test_brief_flags_legacy_megacase_as_needs_review():
    case = BriefCaseRow(
        id=uuid4(),
        case_number="INC-1",
        title="Suspected intrusion campaign",
        description=(
            "Auto-created by Agentic SOC funnel backfill as an attack-campaign case.\n"
            "Theme: general-intrusion\nEntities: (no strong entity)\n"
            "Disposition: true_positive\nLinked alerts: 1\n"
        ),
        severity="high",
        status="open",
        tags={"source": "backfill"},
        mitre_techniques=[],
        evidence_chain=[],
        alert_ids=[str(uuid4()) for _ in range(12)],
    )
    alerts = [
        BriefAlertRow(
            id=uuid4(),
            title=f"Alert {i}",
            severity="high",
            disposition="true_positive",
            funnel_stage="ready_for_jira",
            ai_summary=None,
            narrative=None,
            confidence=44,
            mitre_techniques=[],
        )
        for i in range(12)
    ]
    brief = build_brief_from_rows(
        BriefInputs(case=case, alerts=alerts, task_titles=[], investigation_notes=[])
    )
    assert brief.outcome == "needs_review"
    assert "correlation" in brief.outcome_rationale.lower() or "weak" in brief.outcome_rationale.lower()


def test_reconcile_dry_run_idempotent_membership_selection():
    """Repeated select_campaign_siblings on the same megacase pool is stable."""
    t0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
    seed = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_ips=["10.1.1.1"],
        event_time=t0,
    )
    path = _alert(
        title="Soorin-Web-Path Traversal Attempts",
        affected_ips=["10.1.1.1"],
        event_time=t0 + timedelta(minutes=1),
    )
    noise = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["other"],
        event_time=t0 + timedelta(minutes=2),
    )
    a1, d1 = select_campaign_siblings(seed, [path, noise], ignore_case_membership=True)
    a2, d2 = select_campaign_siblings(seed, [path, noise], ignore_case_membership=True)
    assert {str(x["id"]) for x in a1} == {str(x["id"]) for x in a2}
    assert [d.get("alert_id") for d in d1] == [d.get("alert_id") for d in d2]
    assert all(d1[i].get("linked") == d2[i].get("linked") for i in range(len(d1)))


def test_stale_uac_task_filtered_from_brief():
    case = BriefCaseRow(
        id=uuid4(),
        case_number=None,
        title="Campaign",
        description="Entities: host:web01",
        severity="high",
        status="open",
        tags={},
        mitre_techniques=[],
        evidence_chain=[],
        alert_ids=[],
    )
    alerts = [
        BriefAlertRow(
            id=uuid4(),
            title="Soorin-Web-SQL Injection Attempts",
            severity="high",
            disposition="true_positive",
            funnel_stage="cased",
            ai_summary=None,
            narrative=None,
            confidence=80,
            mitre_techniques=[],
        )
    ]
    brief = build_brief_from_rows(
        BriefInputs(
            case=case,
            alerts=alerts,
            task_titles=[
                "Confirm whether «ESCU - Windows UAC Bypass Suspicious Escalation Behavior - Rule» must be reported to stakeholders.",
                "Review host web01",
            ],
            investigation_notes=[],
        )
    )
    task_details = [a.detail for a in brief.what_we_did if a.kind == "task"]
    assert not any("UAC Bypass" in (t or "") for t in task_details)
    assert any("web01" in (t or "") for t in task_details)
