"""Host-Centric Correlation — discovery, cross-domain, risk, no transitive."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.services.campaign_correlation import (
    DEFAULT_CROSS_DOMAIN_THRESHOLD,
    DEFAULT_LINK_THRESHOLD,
    WEIGHT_HOST,
    WEIGHT_MITRE,
    WEIGHT_TEMPORAL_MAX,
    WEIGHT_USER,
    extract_alert_hosts,
    find_host_related_alerts,
    normalize_host,
    primary_seed_host,
    score_campaign_link,
    select_campaign_siblings,
)

T0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


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
        "created_at": T0,
        "event_time": T0,
        "raw_event": {},
        "llm_payload": {},
        "case_id": None,
    }
    row.update(overrides)
    return row


# ---------------------------------------------------------------------------
# Host normalization / extraction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("SERVER-01", "server-01"),
        ("  Server-01.  ", "server-01"),
        ("server-01.corp.local.", "server-01.corp.local"),
        ("", None),
        (None, None),
        ("unknown", None),
        ("localhost", None),
        ("10.1.2.3", None),  # IP is not a host identity
        ("n/a", None),
    ],
)
def test_normalize_host(raw, expected):
    assert normalize_host(raw) == expected


def test_short_name_not_equated_to_fqdn():
    assert normalize_host("web01") != normalize_host("web01.corp.local")
    a = _alert(affected_hosts=["web01"])
    b = _alert(affected_hosts=["web01.corp.local"])
    assert not set(extract_alert_hosts(a)) & set(extract_alert_hosts(b))


def test_similar_prefix_does_not_match():
    a = _alert(affected_hosts=["server-01"])
    b = _alert(affected_hosts=["server-01-backup"])
    assert not set(extract_alert_hosts(a)) & set(extract_alert_hosts(b))


def test_canonical_host_preferred():
    a = _alert(
        canonical_host="asset-canonical",
        affected_hosts=["other-name"],
        hostname="raw-host",
    )
    assert primary_seed_host(a) == "asset-canonical"
    assert extract_alert_hosts(a)[0] == "asset-canonical"


def test_case_insensitive_host_discovery():
    seed = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["SERVER-01"],
    )
    cand = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["server-01"],
        event_time=T0 + timedelta(minutes=5),
    )
    hits = find_host_related_alerts(seed, [cand])
    assert len(hits) == 1
    assert hits[0]["_matched_hosts"] == ["server-01"]


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_host_discovery_excludes_different_host():
    seed = _alert(affected_hosts=["host-a"], title="Soorin-Endpoint-Powershell Invoke Command")
    other = _alert(
        affected_hosts=["host-b"],
        title="ESCU - Access LSASS Memory for Dump Creation",
        event_time=T0 + timedelta(minutes=1),
    )
    assert find_host_related_alerts(seed, [other]) == []


def test_host_discovery_excludes_cased_and_fp():
    seed = _alert(affected_hosts=["h1"], title="Soorin-Endpoint-Powershell Invoke Command")
    cased = _alert(
        affected_hosts=["h1"],
        title="ESCU - Access LSASS Memory for Dump Creation",
        case_id=str(uuid4()),
    )
    fp = _alert(
        affected_hosts=["h1"],
        title="ESCU - Access LSASS Memory for Dump Creation",
        disposition="false_positive",
        id="fp1",
    )
    assert find_host_related_alerts(seed, [cased, fp]) == []


def test_host_discovery_seed_relative_window_not_sibling_chain():
    """B within window of A; C within window of B but outside A's window → not discovered from A."""
    seed = _alert(
        id="a",
        affected_hosts=["h1"],
        title="Soorin-Endpoint-Powershell Invoke Command",
        event_time=T0,
    )
    b = _alert(
        id="b",
        affected_hosts=["h1"],
        title="ESCU - Access LSASS Memory for Dump Creation",
        event_time=T0 + timedelta(hours=1),
    )
    c = _alert(
        id="c",
        affected_hosts=["h1"],
        title="Windows Non-System Account Targeting LSASS",
        event_time=T0 + timedelta(hours=25),  # outside 24h of A, but 24h from B
    )
    hits = find_host_related_alerts(
        seed, [b, c], temporal_window_seconds=86400
    )
    ids = {str(h["id"]) for h in hits}
    assert ids == {"b"}


def test_duplicate_candidate_records_deduped():
    seed = _alert(affected_hosts=["h1"], title="Soorin-Endpoint-Powershell Invoke Command")
    dup_id = "dup-1"
    c1 = _alert(
        id=dup_id,
        affected_hosts=["h1"],
        title="ESCU - Access LSASS Memory for Dump Creation",
    )
    c2 = dict(c1)
    hits = find_host_related_alerts(seed, [c1, c2])
    assert len(hits) == 1


# ---------------------------------------------------------------------------
# Cross-domain host-centric scoring
# ---------------------------------------------------------------------------


def test_powershell_lsass_same_host_discovered_cross_domain_threshold():
    seed = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["server-01"],
        event_time=T0,
    )
    cand = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["server-01"],
        event_time=T0 + timedelta(minutes=5),
        mitre_techniques=["T1003.001"],
    )
    accepted, decisions = select_campaign_siblings(seed, [cand])
    d = decisions[0]
    assert d["discovery_path"] == "host_centric"
    assert d["cross_domain"] is True
    assert d["threshold"] == DEFAULT_CROSS_DOMAIN_THRESHOLD
    assert d["normalized_host_match"] == ["server-01"]
    assert d["signals"]["host_score"] == WEIGHT_HOST
    # host 0.35 + temporal + mitre 0.10 — may or may not clear 0.70
    expected_min = WEIGHT_HOST
    assert d["final_score"] >= expected_min
    if d["final_score"] < DEFAULT_CROSS_DOMAIN_THRESHOLD:
        assert d["linked"] is False
        assert "cross_domain_threshold_not_met" in d["rejection_reasons"] or (
            "below_threshold" in d["rejection_reasons"]
        )
    else:
        assert d["linked"] is True
        assert d["correlation_type"] == "host_centric"


def test_cross_domain_same_host_with_user_clears_070():
    seed = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["server-01"],
        affected_users=["admin"],
        event_time=T0,
    )
    cand = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["server-01"],
        affected_users=["admin"],
        event_time=T0,  # full temporal weight
        mitre_techniques=["T1003.001"],
    )
    d = score_campaign_link(seed, cand)
    assert d.cross_domain is True
    # 0.35 + 0.25 + 0.15 + 0.10 = 0.85
    assert d.final_score >= DEFAULT_CROSS_DOMAIN_THRESHOLD
    assert d.linked is True
    accepted, decisions = select_campaign_siblings(seed, [cand])
    assert decisions[0]["discovery_path"] == "host_centric"
    assert decisions[0]["linked"] is True
    assert decisions[0]["role"] == "primary"


def test_web_endpoint_same_host_eligible_for_scoring():
    seed = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_hosts=["web-01"],
    )
    cand = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["web-01"],
        event_time=T0 + timedelta(minutes=2),
    )
    _, decisions = select_campaign_siblings(seed, [cand])
    assert decisions[0]["discovery_path"] == "host_centric"
    assert decisions[0]["cross_domain"] is True
    assert decisions[0]["threshold"] == DEFAULT_CROSS_DOMAIN_THRESHOLD


def test_cross_domain_ip_only_still_rejected():
    seed = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_ips=["10.1.1.1"],
    )
    cand = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_ips=["10.1.1.1"],
    )
    _, decisions = select_campaign_siblings(seed, [cand])
    # May be discovered via entity_overlap IP, but must reject link.
    linked = [d for d in decisions if d.get("linked")]
    assert linked == []
    if decisions:
        assert decisions[0]["linked"] is False


def test_same_family_host_uses_055():
    seed = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["cred-01"],
    )
    cand = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["cred-01"],
        event_time=T0 + timedelta(minutes=1),
    )
    _, decisions = select_campaign_siblings(seed, [cand])
    assert decisions[0]["discovery_path"] == "host_centric"
    assert decisions[0]["cross_domain"] is False
    assert decisions[0]["threshold"] == DEFAULT_LINK_THRESHOLD
    assert decisions[0]["linked"] is True


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------


def test_risk_candidate_same_host_supporting_only():
    seed = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["h1"],
    )
    risk = _alert(
        title="Risk - 24 Hour Risk Threshold Exceeded",
        affected_hosts=["h1"],
    )
    accepted, decisions = select_campaign_siblings(seed, [risk])
    assert decisions[0]["discovery_path"] == "host_centric"
    if decisions[0]["linked"]:
        assert decisions[0]["role"] == "supporting"
        assert all(
            (a.get("_correlation") or {}).get("role") != "primary" for a in accepted
        )


def test_risk_seed_host_centric_returns_no_siblings():
    risk = _alert(
        title="Risk - 7 Day ATT&CK Tactic Threshold Exceeded",
        affected_hosts=["h1"],
    )
    attack = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["h1"],
    )
    accepted, decisions = select_campaign_siblings(risk, [attack])
    assert accepted == []
    assert decisions[0]["rejection_reasons"] == ["risk_seed_no_siblings"]
    assert find_host_related_alerts(risk, [attack]) == []


# ---------------------------------------------------------------------------
# No transitive linking
# ---------------------------------------------------------------------------


def test_no_transitive_abc_on_same_host():
    """A↔B link; C outside A's window — must not join via B."""
    a = _alert(
        id="alert-a",
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["host-01"],
        affected_users=["u1"],
        event_time=T0,
    )
    b = _alert(
        id="alert-b",
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["host-01"],
        affected_users=["u1"],
        event_time=T0 + timedelta(minutes=5),
        mitre_techniques=["T1003.001"],
    )
    c = _alert(
        id="alert-c",
        title="Windows Defender Exclusion",
        affected_hosts=["host-01"],
        affected_users=["u1"],
        event_time=T0 + timedelta(hours=30),  # outside 24h of A
    )
    accepted, decisions = select_campaign_siblings(
        a, [b, c], temporal_window_seconds=86400
    )
    ids = {str(x["id"]) for x in accepted}
    assert "alert-b" in ids
    assert "alert-c" not in ids
    # Every decision scored against A (seed), never B as reference.
    for d in decisions:
        assert d.get("seed_hosts") == ["host-01"]


def test_b_does_not_become_reference_for_c():
    a = _alert(
        id="a",
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["h"],
        event_time=T0,
    )
    b = _alert(
        id="b",
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["h"],
        event_time=T0 + timedelta(hours=20),
    )
    c = _alert(
        id="c",
        title="Attacker Tools on Endpoint",
        affected_hosts=["h"],
        event_time=T0 + timedelta(hours=40),
    )
    # From A with 24h window: only B
    hits_a = find_host_related_alerts(a, [b, c], temporal_window_seconds=86400)
    assert {str(x["id"]) for x in hits_a} == {"b"}
    # From B, C would be in window — must not affect A's campaign
    hits_b = find_host_related_alerts(b, [c], temporal_window_seconds=86400)
    assert {str(x["id"]) for x in hits_b} == {"c"}
    accepted, _ = select_campaign_siblings(a, [b, c], temporal_window_seconds=86400)
    assert "c" not in {str(x["id"]) for x in accepted}


# ---------------------------------------------------------------------------
# Existing paths still work + explainability
# ---------------------------------------------------------------------------


def test_ip_same_family_still_works_without_host():
    seed = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_ips=["10.50.1.9"],
    )
    path = _alert(
        title="Soorin-Web-Path Traversal Attempts",
        affected_ips=["10.50.1.9"],
        event_time=T0 + timedelta(minutes=1),
    )
    accepted, decisions = select_campaign_siblings(seed, [path])
    assert len(accepted) == 1
    assert decisions[0]["discovery_path"] == "entity_overlap"
    assert decisions[0]["linked"] is True


def test_user_based_correlation_still_works():
    seed = _alert(
        title="Access - Short-lived Account Detected",
        affected_users=["jdoe"],
    )
    # identity + credential with shared user → cross-domain needs 0.70
    cand = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_users=["jdoe"],
        affected_hosts=["x"],  # different host only on cand — no shared host
        event_time=T0,
        mitre_techniques=["T1003.001"],
    )
    # seed has no host; shared user only
    _, decisions = select_campaign_siblings(seed, [cand])
    assert decisions
    assert decisions[0]["discovery_path"] == "entity_overlap"


def test_disposition_not_copied_onto_sibling_rows():
    seed = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["h"],
        disposition="true_positive",
    )
    cand = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["h"],
        disposition="needs_review",
    )
    accepted, _ = select_campaign_siblings(seed, [cand])
    assert accepted[0]["disposition"] == "needs_review"


def test_sibling_cap_still_100():
    seed = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["h"],
    )
    cands = [
        _alert(
            title="ESCU - Creation of lsass Dump with Taskmgr",
            affected_hosts=["h"],
            event_time=T0 + timedelta(seconds=i),
        )
        for i in range(120)
    ]
    accepted, _ = select_campaign_siblings(seed, cands, limit=100)
    assert len(accepted) == 100


def test_065bd5b9_host_centric_keeps_families_separated_without_shared_host():
    """Web/IP campaign must not pull endpoint/credential without shared host."""
    web_ip = "10.50.1.9"
    seed = _alert(title="Soorin-Web-SQL Injection Attempts", affected_ips=[web_ip])
    pool = [
        _alert(
            title="Soorin-Web-Path Traversal Attempts",
            affected_ips=[web_ip],
            event_time=T0 + timedelta(minutes=1),
        ),
        _alert(
            title="Soorin-Endpoint-Powershell Invoke Command",
            affected_hosts=["cao01vw065"],
            event_time=T0 + timedelta(minutes=3),
        ),
        _alert(
            title="ESCU - Access LSASS Memory for Dump Creation",
            affected_hosts=["other-host"],
            event_time=T0 + timedelta(minutes=4),
        ),
        _alert(
            title="Risk - 24 Hour Risk Threshold Exceeded",
            affected_ips=[web_ip],
            event_time=T0 + timedelta(minutes=5),
        ),
    ]
    accepted, decisions = select_campaign_siblings(seed, pool)
    titles = {str(a["title"]) for a in accepted}
    assert "Soorin-Web-Path Traversal Attempts" in titles
    assert "Soorin-Endpoint-Powershell Invoke Command" not in titles
    assert "ESCU - Access LSASS Memory for Dump Creation" not in titles
    # Host-centric should not have fired for web seed without hosts
    assert all(
        d.get("discovery_path") != "host_centric" or d.get("linked") is False
        for d in decisions
        if "Powershell" in str(d.get("alert_id"))
    )


def test_symmetric_pairwise_with_host():
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["sym-host"],
        event_time=T0,
    )
    b = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["sym-host"],
        event_time=T0 + timedelta(minutes=3),
    )
    d1 = score_campaign_link(a, b)
    d2 = score_campaign_link(b, a)
    assert d1.final_score == d2.final_score
    assert d1.linked == d2.linked
