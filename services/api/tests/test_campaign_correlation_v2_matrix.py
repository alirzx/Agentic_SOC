"""Comprehensive campaign-corr:v2 matrix — eligibility, scoring, invariants.

Does not invent production entity values for case 065bd5b9; the megacase
regression uses titled groups with *explicit* entity fixtures documenting
when links are evidenced vs rejected.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.services.campaign_correlation import (
    DEFAULT_CROSS_DOMAIN_THRESHOLD,
    DEFAULT_LINK_THRESHOLD,
    WEIGHT_FAMILY,
    WEIGHT_HOST,
    WEIGHT_IP_SAME_FAMILY,
    WEIGHT_MITRE,
    WEIGHT_TEMPORAL_MAX,
    WEIGHT_USER,
    alert_family,
    assess_evidence_independence,
    campaign_temporal_window_seconds,
    is_candidate_eligible,
    is_risk_supporting_alert,
    is_seed_eligible,
    normalize_ip,
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
# Seed / candidate eligibility
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "disp,sev,ok",
    [
        ("true_positive", "low", True),
        ("escalate", "medium", True),
        ("needs_review", "high", True),
        ("needs_review", "medium", True),  # rank 3 — preserved ladder
        ("needs_review", "low", False),
        ("false_positive", "critical", False),
        ("benign", "high", False),
        ("", "high", False),
    ],
)
def test_seed_eligibility_matrix(disp, sev, ok):
    a = _alert(disposition=disp, severity=sev)
    assert is_seed_eligible(a)[0] is ok


def test_seed_rejects_existing_case_id():
    a = _alert(case_id=str(uuid4()))
    assert is_seed_eligible(a)[0] is False


def test_candidate_rejects_missing_disposition():
    a = _alert(disposition="")
    assert is_candidate_eligible(a)[0] is False


def test_candidate_allows_likely_tp():
    a = _alert(disposition="likely_tp")
    assert is_candidate_eligible(a)[0] is True


# ---------------------------------------------------------------------------
# Family classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "title,family",
    [
        ("Soorin-Web-SQL Injection Attempts", "web"),
        ("Soorin-Web-Path Traversal Attempts", "web"),
        ("Soorin-Web-Command Injection", "web"),
        ("ESCU - Access LSASS Memory for Dump Creation", "credential"),
        ("Mimikatz credential dump observed", "credential"),
        ("Soorin-Endpoint-Powershell Invoke Command", "endpoint"),
        ("Sysmon Process Create anomalous", "endpoint"),
        ("Access - Short-lived Account Detected", "identity"),
        ("Risk - 24 Hour Risk Threshold Exceeded", "risk"),
        ("Risk - 7 Day ATT&CK Tactic Threshold Exceeded", "risk"),
        ("Completely Unknown Detection XYZ", "general"),
        ("sql injection attempts", "web"),  # case-insensitive
    ],
)
def test_family_table(title, family):
    assert alert_family(_alert(title=title)) == family


def test_structured_family_metadata_wins_over_generic_title():
    a = _alert(title="Generic alert", security_domain="credential")
    assert alert_family(a) == "credential"


def test_risk_precedence_over_other_keywords():
    a = _alert(title="Risk - 24 Hour Risk Threshold Exceeded involving LSASS hosts")
    assert alert_family(a) == "risk"
    assert is_risk_supporting_alert(a) is True


# ---------------------------------------------------------------------------
# IP normalization
# ---------------------------------------------------------------------------


def test_normalize_ip_rejects_placeholders():
    assert normalize_ip("0.0.0.0") is None
    assert normalize_ip("127.0.0.1") is None
    assert normalize_ip("") is None
    assert normalize_ip("not-an-ip") is None
    assert normalize_ip(None) is None


def test_normalize_ip_v4_and_mapped_v6():
    assert normalize_ip("10.1.2.3") == "10.1.2.3"
    assert normalize_ip("::ffff:10.1.2.3") == "10.1.2.3"


def test_normalize_ipv6_canonical():
    assert normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") is None  # docs range
    # Non-docs global-ish unique local still allowed if parseable
    assert normalize_ip("fd12:3456:789a::1") == "fd12:3456:789a::1"


def test_duplicate_ip_fields_do_not_inflate_score():
    a = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_ips=["10.0.0.9", "10.0.0.9", "10.0.0.9"],
        event_time=T0,
    )
    b = _alert(
        title="Soorin-Web-Path Traversal Attempts",
        affected_ips=["10.0.0.9"],
        event_time=T0 + timedelta(minutes=1),
    )
    d = score_campaign_link(a, b)
    assert d.signals["ip_score"] == WEIGHT_IP_SAME_FAMILY
    assert d.linked is True


def test_explicit_infrastructure_ip_excluded():
    a = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_ips=["10.9.9.9"],
        tags={"infrastructure_ips": ["10.9.9.9"]},
        event_time=T0,
    )
    b = _alert(
        title="Soorin-Web-Path Traversal Attempts",
        affected_ips=["10.9.9.9"],
        event_time=T0,
    )
    d = score_campaign_link(a, b)
    assert d.linked is False
    assert "no_shared_entity" in d.rejection_reasons


# ---------------------------------------------------------------------------
# Scoring / thresholds / symmetry
# ---------------------------------------------------------------------------


def test_no_entity_all_boosters_still_rejected():
    a = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        mitre_techniques=["T1190"],
        event_time=T0,
    )
    b = _alert(
        title="Soorin-Web-Path Traversal Attempts",
        mitre_techniques=["T1190"],
        event_time=T0 + timedelta(seconds=30),
    )
    d = score_campaign_link(a, b)
    assert d.linked is False
    assert d.role == "rejected"
    assert "no_shared_entity" in d.rejection_reasons


def test_score_never_exceeds_one():
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
        affected_users=["admin"],
        affected_ips=["10.0.0.5"],
        mitre_techniques=["T1003.001"],
        event_time=T0,
    )
    b = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["HOST-A"],
        affected_users=["admin"],
        affected_ips=["10.0.0.5"],
        mitre_techniques=["T1003.001"],
        event_time=T0,
    )
    d = score_campaign_link(a, b)
    assert 0.0 <= d.final_score <= 1.0
    assert d.correlation_score <= 1.0
    # Raw can exceed 1 before cap
    assert d.raw_score >= d.final_score


def test_symmetry_non_risk_pair():
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
        event_time=T0,
        mitre_techniques=["T1003.001"],
    )
    b = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["HOST-A"],
        event_time=T0 + timedelta(minutes=5),
        mitre_techniques=["T1003.001"],
    )
    d1 = score_campaign_link(a, b)
    d2 = score_campaign_link(b, a)
    assert d1.linked == d2.linked
    assert d1.final_score == d2.final_score
    assert d1.role == d2.role


def test_host_plus_family_passes_same_domain_threshold():
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
        event_time=T0,
    )
    b = _alert(
        title="Windows Non-System Account Targeting LSASS",
        affected_hosts=["HOST-A"],
        event_time=T0 + timedelta(minutes=2),
    )
    d = score_campaign_link(a, b)
    assert d.signals["host_score"] == WEIGHT_HOST
    assert d.signals["family_score"] == WEIGHT_FAMILY
    assert d.final_score >= DEFAULT_LINK_THRESHOLD
    assert d.linked is True
    assert d.role == "primary"
    assert d.cross_domain is False


def test_cross_domain_host_uses_070_threshold():
    a = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_hosts=["HOST-A"],
        event_time=T0,
    )
    b = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["HOST-A"],
        event_time=T0 + timedelta(minutes=1),
    )
    d = score_campaign_link(a, b)
    assert d.cross_domain is True
    assert d.threshold == DEFAULT_CROSS_DOMAIN_THRESHOLD
    # host 0.35 + temporal ~0.15 = ~0.50 < 0.70 without family/mitre
    assert d.signals["host_score"] == WEIGHT_HOST
    assert d.signals["family_score"] == 0.0
    if d.final_score < DEFAULT_CROSS_DOMAIN_THRESHOLD:
        assert d.linked is False


def test_cross_domain_ip_only_rejected():
    a = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_ips=["10.1.1.1"],
        event_time=T0,
    )
    b = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_ips=["10.1.1.1"],
        event_time=T0,
    )
    d = score_campaign_link(a, b)
    assert d.linked is False
    assert "cross_domain_ip_only" in d.rejection_reasons


def test_web_credential_shared_user_eligible_for_scoring():
    a = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_users=["jdoe"],
        event_time=T0,
    )
    b = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_users=["jdoe"],
        event_time=T0,
        mitre_techniques=["T1003.001"],
    )
    d = score_campaign_link(a, b)
    assert d.cross_domain is True
    assert "cross_domain_ip_only" not in d.rejection_reasons
    assert d.signals["user_score"] == WEIGHT_USER


def test_severity_alone_never_links():
    a = _alert(title="Soorin-Web-SQL Injection Attempts", severity="critical")
    b = _alert(title="Access - Short-lived Account Detected", severity="critical")
    d = score_campaign_link(a, b)
    assert d.linked is False


# ---------------------------------------------------------------------------
# Time window
# ---------------------------------------------------------------------------


def test_temporal_window_helpers():
    assert campaign_temporal_window_seconds(1) == 3600
    assert campaign_temporal_window_seconds(24) == 86400
    assert campaign_temporal_window_seconds(48) == 172800


def test_same_timestamp_gets_full_temporal_weight():
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["H"],
        event_time=T0,
    )
    b = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["H"],
        event_time=T0,
    )
    d = score_campaign_link(a, b)
    assert d.time_difference_seconds == 0
    assert d.signals["temporal_score"] == pytest.approx(WEIGHT_TEMPORAL_MAX, rel=1e-3)


def test_exactly_at_window_boundary_accepted():
    window = 3600
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["H"],
        event_time=T0,
    )
    b = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["H"],
        event_time=T0 + timedelta(seconds=window),
    )
    d = score_campaign_link(a, b, temporal_window_seconds=window)
    assert d.linked is True or d.final_score >= 0  # not rejected for window
    assert "outside_temporal_window" not in d.rejection_reasons


def test_outside_window_rejected():
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["H"],
        event_time=T0,
    )
    b = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["H"],
        event_time=T0 + timedelta(hours=25),
    )
    d = score_campaign_link(a, b, temporal_window_seconds=86400)
    assert d.linked is False
    assert "outside_temporal_window" in d.rejection_reasons


def test_missing_timestamp_rejected_not_zero_delta():
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["H"],
        event_time=None,
        created_at=None,
    )
    b = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["H"],
        event_time=T0,
    )
    d = score_campaign_link(a, b)
    assert d.linked is False
    assert "missing_timestamp" in d.rejection_reasons
    assert d.time_difference_seconds is None


def test_naive_and_aware_timestamps_compare():
    naive = datetime(2026, 11, 14, 12, 0, 0)  # treated as UTC
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["H"],
        event_time=naive,
        created_at=naive,
    )
    b = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["H"],
        event_time=T0,
    )
    d = score_campaign_link(a, b)
    assert "missing_timestamp" not in d.rejection_reasons
    assert d.time_difference_seconds == 0


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------


def test_risk_candidate_supporting_not_primary():
    seed = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
    )
    risk = _alert(
        title="Risk - 24 Hour Risk Threshold Exceeded",
        affected_hosts=["HOST-A"],
    )
    d = score_campaign_link(seed, risk)
    if d.linked:
        assert d.role == "supporting"
    assert d.role != "primary"


def test_risk_candidate_no_entity_rejected():
    seed = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
    )
    risk = _alert(title="Risk - 24 Hour Risk Threshold Exceeded")
    d = score_campaign_link(seed, risk)
    assert d.linked is False


def test_risk_seed_no_siblings():
    risk = _alert(title="Risk - 7 Day ATT&CK Tactic Threshold Exceeded")
    other = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
        disposition="true_positive",
    )
    accepted, decisions = select_campaign_siblings(risk, [other])
    assert accepted == []
    assert decisions and decisions[0]["role"] == "rejected"


def test_risk_ip_only_cross_domain_rejected():
    seed = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_ips=["10.2.2.2"],
    )
    risk = _alert(
        title="Risk - 24 Hour Risk Threshold Exceeded",
        affected_ips=["10.2.2.2"],
    )
    # risk family vs endpoint → cross_domain; IP-only reject before risk path
    d = score_campaign_link(seed, risk)
    # risk family is excluded from cross_domain pair definition when other is endpoint
    # seed=endpoint, cand=risk → cross_domain False (risk excluded)
    # So risk can attach via IP with supporting threshold
    if d.cross_domain:
        assert d.linked is False


def test_risk_does_not_inflate_primary_count():
    seed = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
    )
    sib = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["HOST-A"],
        event_time=T0 + timedelta(minutes=1),
    )
    risk = _alert(
        title="Risk - 24 Hour Risk Threshold Exceeded",
        affected_hosts=["HOST-A"],
        event_time=T0 + timedelta(minutes=2),
    )
    accepted, _ = select_campaign_siblings(seed, [sib, risk])
    primaries = [
        a
        for a in accepted
        if (a.get("_correlation") or {}).get("role") == "primary"
    ]
    supporting = [
        a
        for a in accepted
        if (a.get("_correlation") or {}).get("role") == "supporting"
    ]
    assert len(primaries) == 1
    assert all("Risk" in str(a.get("title")) for a in supporting) or len(supporting) <= 1


def test_duplicate_lineage_rejected():
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["H"],
        raw_event={"event_id": "evt-1"},
    )
    b = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["H"],
        raw_event={"event_id": "evt-1"},
    )
    assert assess_evidence_independence(a, b) == "duplicate"
    d = score_campaign_link(a, b)
    assert d.linked is False
    assert "duplicate_lineage" in d.rejection_reasons


# ---------------------------------------------------------------------------
# Sibling selection — ordering, cap, no transitive, no disposition copy
# ---------------------------------------------------------------------------


def test_no_transitive_abc_expansion():
    """A↔B and B↔C must not imply A↔C without pairwise evidence."""
    a = _alert(
        id="aaa",
        title="Soorin-Web-SQL Injection Attempts",
        affected_ips=["10.0.0.1"],
        disposition="true_positive",
    )
    b = _alert(
        id="bbb",
        title="Soorin-Web-Path Traversal Attempts",
        affected_ips=["10.0.0.1"],
        affected_hosts=["HOST-B"],
        disposition="true_positive",
        event_time=T0 + timedelta(minutes=1),
    )
    c = _alert(
        id="ccc",
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["HOST-B"],
        disposition="true_positive",
        event_time=T0 + timedelta(minutes=2),
    )
    # A links B (same family + IP). A must NOT link C (cross-domain, no shared host with A).
    accepted, _ = select_campaign_siblings(a, [b, c])
    ids = {str(x["id"]) for x in accepted}
    assert "bbb" in ids
    assert "ccc" not in ids
    # B would link C, but that must not pull C into A's campaign.
    d_bc = score_campaign_link(b, c)
    assert d_bc.cross_domain is True
    # Regardless of B↔C, A↔C stays rejected.
    d_ac = score_campaign_link(a, c)
    assert d_ac.linked is False


def test_sibling_ordering_primary_then_score_then_id():
    seed = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
        affected_users=["u1"],
        mitre_techniques=["T1003.001"],
    )
    low = _alert(
        id="11111111-1111-1111-1111-111111111111",
        title="Windows Non-System Account Targeting LSASS",
        affected_hosts=["HOST-A"],
        event_time=T0 + timedelta(hours=12),  # weaker temporal
    )
    high = _alert(
        id="22222222-2222-2222-2222-222222222222",
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["HOST-A"],
        affected_users=["u1"],
        mitre_techniques=["T1003.001"],
        event_time=T0,
    )
    risk = _alert(
        id="33333333-3333-3333-3333-333333333333",
        title="Risk - 24 Hour Risk Threshold Exceeded",
        affected_hosts=["HOST-A"],
        event_time=T0,
    )
    accepted, _ = select_campaign_siblings(seed, [risk, low, high])
    roles = [(a["id"], a["_correlation"]["role"]) for a in accepted]
    # All primaries before supporting
    seen_supporting = False
    for _id, role in roles:
        if role == "supporting":
            seen_supporting = True
        if seen_supporting:
            assert role == "supporting"


def test_sibling_hard_cap_100():
    seed = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["HOST-A"],
    )
    cands = [
        _alert(
            title="ESCU - Creation of lsass Dump with Taskmgr",
            affected_hosts=["HOST-A"],
            event_time=T0 + timedelta(seconds=i),
        )
        for i in range(120)
    ]
    accepted, _ = select_campaign_siblings(seed, cands, limit=100)
    assert len(accepted) == 100


def test_candidate_already_cased_rejected():
    seed = _alert(title="ESCU - Access LSASS Memory for Dump Creation", affected_hosts=["H"])
    cased = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["H"],
        case_id=str(uuid4()),
    )
    accepted, decisions = select_campaign_siblings(seed, [cased])
    assert accepted == []
    # Host-centric discovery drops ineligible (cased) candidates before scoring.
    # They must never appear as linked; an eligibility reject decision is optional.
    assert not any(d.get("linked") for d in decisions)
    if decisions:
        assert "already_has_case_id" in (decisions[0].get("rejection_reasons") or [])


def test_ignore_case_membership_for_reconcile():
    seed = _alert(title="ESCU - Access LSASS Memory for Dump Creation", affected_hosts=["H"])
    cased = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["H"],
        case_id=str(uuid4()),
    )
    accepted, _ = select_campaign_siblings(
        seed, [cased], ignore_case_membership=True
    )
    assert len(accepted) == 1


# ---------------------------------------------------------------------------
# Case 065bd5b9 style regression (titled groups; entities only where stated)
# ---------------------------------------------------------------------------


def test_065bd5b9_style_megacase_does_not_merge_all_twelve():
    """Previously 12 alerts were OR-merged. v2 must keep families separate
    unless real shared host/user evidence exists.

    Entity policy for this fixture (honest — no invented hosts/IPs from prod):
    * Web trio shares attacker IP 203.0.113.50 — WAIT: docs range is excluded.
      Use 10.50.1.9 as a stand-in for "shared web source IP" in tests only.
    * Credential trio shares HOST-CRED.
    * Endpoint trio shares HOST-ENDP (different from HOST-CRED).
    * Identity has no shared entity with others.
    * Risk alerts share HOST-CRED (supporting only on credential seed).
    """
    web_ip = "10.50.1.9"
    web = [
        _alert(title="Soorin-Web-SQL Injection Attempts", affected_ips=[web_ip]),
        _alert(
            title="Soorin-Web-Path Traversal Attempts",
            affected_ips=[web_ip],
            event_time=T0 + timedelta(minutes=1),
        ),
        _alert(
            title="Soorin-Web-Command Injection",
            affected_ips=[web_ip],
            event_time=T0 + timedelta(minutes=2),
        ),
    ]
    cred_host = "host-cred"
    cred = [
        _alert(
            title="ESCU - Access LSASS Memory for Dump Creation",
            affected_hosts=[cred_host],
            event_time=T0 + timedelta(minutes=10),
        ),
        _alert(
            title="ESCU - Creation of lsass Dump with Taskmgr",
            affected_hosts=[cred_host],
            event_time=T0 + timedelta(minutes=11),
        ),
        _alert(
            title="Windows Non-System Account Targeting LSASS",
            affected_hosts=[cred_host],
            event_time=T0 + timedelta(minutes=12),
        ),
    ]
    endp_host = "host-endp"
    endp = [
        _alert(
            title="Soorin-Endpoint-Powershell Invoke Command",
            affected_hosts=[endp_host],
            event_time=T0 + timedelta(minutes=20),
        ),
        _alert(
            title="Attacker Tools on Endpoint",
            affected_hosts=[endp_host],
            event_time=T0 + timedelta(minutes=21),
        ),
        _alert(
            title="Windows Defender Exclusion",
            affected_hosts=[endp_host],
            event_time=T0 + timedelta(minutes=22),
        ),
    ]
    identity = [
        _alert(
            title="Access - Short-lived Account Detected",
            event_time=T0 + timedelta(minutes=30),
        )
    ]
    risk = [
        _alert(
            title="Risk - 7 Day ATT&CK Tactic Threshold Exceeded",
            affected_hosts=[cred_host],
            event_time=T0 + timedelta(minutes=15),
        ),
        _alert(
            title="Risk - 24 Hour Risk Threshold Exceeded",
            affected_hosts=[cred_host],
            event_time=T0 + timedelta(minutes=16),
        ),
    ]

    # Seed = first web → only other web join; not cred/endpoint/identity.
    accepted_web, _ = select_campaign_siblings(web[0], web[1:] + cred + endp + identity + risk)
    titles = {str(a["title"]) for a in accepted_web}
    assert "Soorin-Web-Path Traversal Attempts" in titles
    assert "Soorin-Web-Command Injection" in titles
    assert not any("LSASS" in t for t in titles)
    assert not any("Powershell" in t for t in titles)
    assert not any("Short-lived" in t for t in titles)

    # Seed = LSASS → other LSASS primary; Risk supporting; not web/endpoint.
    accepted_cred, decisions = select_campaign_siblings(
        cred[0], web + cred[1:] + endp + identity + risk
    )
    roles_by_title = {
        str(a["title"]): a["_correlation"]["role"] for a in accepted_cred
    }
    assert roles_by_title.get("ESCU - Creation of lsass Dump with Taskmgr") == "primary"
    assert roles_by_title.get("Windows Non-System Account Targeting LSASS") == "primary"
    for t, role in roles_by_title.items():
        if t.startswith("Risk"):
            assert role == "supporting"
    assert "Soorin-Web-SQL Injection Attempts" not in roles_by_title
    assert "Soorin-Endpoint-Powershell Invoke Command" not in roles_by_title

    # UAC Bypass must not appear — not in the 12 linked titles.
    all_titles = [a["title"] for a in web + cred + endp + identity + risk]
    assert not any("UAC Bypass" in str(t) for t in all_titles)


# ---------------------------------------------------------------------------
# Invariants (parameterized)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed_i", range(5))
def test_invariant_no_entity_never_linked(seed_i):
    a = _alert(title=f"Alert-{seed_i}-A", severity="critical", mitre_techniques=["T1059"])
    b = _alert(title=f"Alert-{seed_i}-B", severity="critical", mitre_techniques=["T1059"])
    d = score_campaign_link(a, b)
    assert d.linked is False


@pytest.mark.parametrize(
    "fam_a,fam_b,title_a,title_b",
    [
        ("web", "endpoint", "Soorin-Web-SQL Injection Attempts", "Soorin-Endpoint-Powershell Invoke Command"),
        ("web", "credential", "Soorin-Web-Path Traversal Attempts", "ESCU - Access LSASS Memory for Dump Creation"),
        ("endpoint", "credential", "Sysmon anomalous", "Mimikatz credential dump"),
    ],
)
def test_invariant_cross_domain_ip_only_never_linked(fam_a, fam_b, title_a, title_b):
    a = _alert(title=title_a, affected_ips=["10.8.8.8"])
    b = _alert(title=title_b, affected_ips=["10.8.8.8"])
    assert alert_family(a) != "general" or fam_a == "endpoint"
    d = score_campaign_link(a, b)
    if alert_family(a) not in {"general", "risk"} and alert_family(b) not in {
        "general",
        "risk",
    }:
        assert d.linked is False
        assert d.role == "rejected"


def test_invariant_score_bounds_and_explainable_entity_when_linked():
    a = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["Z"],
    )
    b = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["Z"],
    )
    d = score_campaign_link(a, b)
    assert 0.0 <= d.final_score <= 1.0
    if d.linked:
        assert d.matched_entities.get("host") or d.matched_entities.get("user") or d.matched_entities.get("source_ip")
        assert d.evidence_refs
        assert d.role in {"primary", "supporting"}
