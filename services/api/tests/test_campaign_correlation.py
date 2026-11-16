"""Campaign correlation — prevent false megacases (audit case 065bd5b9)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.services.campaign_correlation import (
    alert_family,
    is_risk_supporting_alert,
    score_campaign_link,
    select_campaign_siblings,
)
from app.services.agentic_funnel import classify_backfill


def _alert(**overrides):
    row = {
        "id": str(uuid4()),
        "title": "Alert",
        "severity": "high",
        "disposition": "needs_review",
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


def test_web_vs_powershell_without_shared_host_rejected():
    web = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_ips=["1.2.3.4"],
        llm_payload={"alert_fields": {}},
    )
    ps = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["cao01vw065.cao.ir"],
        llm_payload={"alert_fields": {"Computer": "cao01vw065.cao.ir"}},
    )
    decision = score_campaign_link(web, ps)
    assert decision.linked is False
    assert decision.role == "rejected"


def test_lsass_same_host_links():
    t0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
        event_time=t0,
        created_at=t0,
        mitre_techniques=["T1003.001"],
    )
    b = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["HOST-A"],
        event_time=t0 + timedelta(minutes=8),
        created_at=t0 + timedelta(minutes=8),
        mitre_techniques=["T1003.001"],
    )
    decision = score_campaign_link(a, b)
    assert decision.linked is True
    assert decision.matched_entities.get("host") == "host-a"
    assert any(e.type == "shared_host" for e in decision.evidence_refs)


def test_same_severity_alone_does_not_link():
    a = _alert(title="Soorin-Web-SQL Injection Attempts", severity="high")
    b = _alert(title="Access - Short-lived Account Detected", severity="high")
    decision = score_campaign_link(a, b)
    assert decision.linked is False


def test_risk_alert_is_supporting_only():
    seed = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
    )
    risk = _alert(
        title="Risk - 24 Hour Risk Threshold Exceeded",
        affected_hosts=["HOST-A"],
    )
    assert is_risk_supporting_alert(risk) is True
    decision = score_campaign_link(seed, risk)
    assert decision.role in {"supporting", "rejected"}
    if decision.linked:
        assert decision.role == "supporting"


def test_risk_seed_does_not_pull_siblings():
    risk = _alert(title="Risk - 7 Day ATT&CK Tactic Threshold Exceeded")
    other = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
    )
    accepted, _ = select_campaign_siblings(risk, [other])
    assert accepted == []


def test_select_siblings_keeps_web_family_on_shared_ip():
    t0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
    seed = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_ips=["10.0.0.9"],
        event_time=t0,
    )
    path = _alert(
        title="Soorin-Web-Path Traversal Attempts",
        affected_ips=["10.0.0.9"],
        event_time=t0 + timedelta(minutes=3),
    )
    ps = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["other-host"],
        event_time=t0 + timedelta(minutes=4),
    )
    accepted, decisions = select_campaign_siblings(seed, [path, ps])
    ids = {str(a["id"]) for a in accepted}
    assert str(path["id"]) in ids
    assert str(ps["id"]) not in ids
    # Host-centric discovery only evaluates entity-overlapping candidates;
    # PowerShell (no shared IP/host with web seed) may be omitted entirely
    # or present as rejected — either way it must not be linked.
    ps_decisions = [d for d in decisions if str(d.get("alert_id")) == str(ps["id"])]
    assert not ps_decisions or all(not d.get("linked") for d in ps_decisions)


def test_families():
    assert alert_family(_alert(title="Soorin-Web-Command Injection")) == "web"
    assert alert_family(_alert(title="ESCU - Access LSASS Memory")) == "credential"
    assert alert_family(_alert(title="Risk - 24 Hour Risk Threshold Exceeded")) == "risk"


def test_classify_does_not_auto_tp_powershell_high():
    assert (
        classify_backfill(
            {"title": "Soorin-Endpoint-Powershell Invoke Command", "severity": "high"}
        )
        == "needs_review"
    )
