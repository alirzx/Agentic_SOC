"""Mandatory scenarios for three-layer dedup + categorization + correlation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.services.dedup.alert_identity import (
    alert_logical_key,
    extract_identity_entities,
    within_dedup_window,
)
from app.services.dedup.categories import (
    AlertCategory,
    IncidentCategory,
    classify_alert_category,
    classify_incident_category,
)
from app.services.dedup.correlation import score_alert_pair
from app.services.dedup.event_fingerprint import (
    event_dedup_fields,
    event_fingerprint_hash,
)
from app.services.dedup.shadow import compare_grouping
from app.services.exact_dedupe import (
    _group_alerts_for_dedupe,
    alert_display_key,
)


def _base(**overrides):
    row = {
        "id": str(uuid4()),
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "title": "Soorin-Endpoint-Powershell Invoke Command",
        "severity": "high",
        "disposition": None,
        "rule_id": "soorin-endpoint-powershell-invoke",
        "rule_name": "Soorin-Endpoint-Powershell Invoke Command",
        "connector_type": "splunk",
        "affected_hosts": [],
        "affected_ips": [],
        "affected_users": [],
        "source_event_ids": [],
        "created_at": datetime(2026, 11, 14, 12, 0, tzinfo=UTC),
        "event_time": datetime(2026, 11, 14, 12, 0, tzinfo=UTC),
        "llm_payload": {
            "security_domain": "endpoint",
            "detection_type": "ebd",
            "alert_fields": {
                "Computer": "cao01vw013.cao.ir",
                "user_id": "'S-1-5-21-1793179736-1175893981-2474273398-13753'",
                "Path": r"C:\Windows\TEMP\SDIAG\CL_Utility.ps1",
                "ScriptBlockText": "function Get-FreeSpace { }",
                "extracted_host": "SH2",
            },
        },
    }
    row.update(overrides)
    return row


# --- Layer 1: event fingerprint ---


def test_event_replay_same_source_event_id():
    a = event_dedup_fields(
        tenant_id="t1", source="splunk", source_event_ids=["evt-1"]
    )
    b = event_dedup_fields(
        tenant_id="t1", source="splunk", source_event_ids=["evt-1"]
    )
    assert event_fingerprint_hash(a) == event_fingerprint_hash(b)


def test_event_different_source_event_ids_identical_content():
    a = event_dedup_fields(
        tenant_id="t1", source="splunk", source_event_ids=["evt-1"], title="x"
    )
    b = event_dedup_fields(
        tenant_id="t1", source="splunk", source_event_ids=["evt-2"], title="x"
    )
    assert event_fingerprint_hash(a) != event_fingerprint_hash(b)


def test_event_different_source_systems():
    a = event_dedup_fields(
        tenant_id="t1", source="splunk", source_event_ids=["evt-1"]
    )
    b = event_dedup_fields(
        tenant_id="t1", source="crowdstrike", source_event_ids=["evt-1"]
    )
    assert event_fingerprint_hash(a) != event_fingerprint_hash(b)


def test_event_different_tenants():
    a = event_dedup_fields(
        tenant_id="t1", source="splunk", source_event_ids=["evt-1"]
    )
    b = event_dedup_fields(
        tenant_id="t2", source="splunk", source_event_ids=["evt-1"]
    )
    assert event_fingerprint_hash(a) != event_fingerprint_hash(b)


def test_event_missing_source_event_id_fallback_marked():
    fields = event_dedup_fields(
        tenant_id="t1",
        source="splunk",
        source_event_ids=[],
        title="rule",
        hostname="host-a",
        rule_id="r1",
    )
    assert fields.get("fallback") is True
    assert "hostname" in fields


# --- Layer 2: alert identity ---


def test_powershell_alert_extracts_host_sid_not_ip():
    ents = extract_identity_entities(_base())
    assert "cao01vw013.cao.ir" in ents["hosts"]
    assert any(u.startswith("S-1-5-21") for u in ents["users"])
    assert ents["src_ips"] == []
    assert ents["dst_ips"] == []
    # SH2 must not replace / equal Computer
    assert "sh2" not in ents["hosts"] or ents["hosts"][0] == "cao01vw013.cao.ir"
    assert "sh2" in ents.get("alias_hosts", []) or "SH2".lower() in [
        h.lower() for h in ents.get("alias_hosts", [])
    ]


def test_same_rule_different_hosts_separate_keys():
    a = _base(affected_hosts=["host-a"], llm_payload={"security_domain": "endpoint"})
    b = _base(affected_hosts=["host-b"], llm_payload={"security_domain": "endpoint"})
    # Clear Computer so affected_hosts drive identity
    a["llm_payload"] = {"security_domain": "endpoint", "alert_fields": {}}
    b["llm_payload"] = {"security_domain": "endpoint", "alert_fields": {}}
    assert alert_logical_key(a) != alert_logical_key(b)
    # Legacy display key incorrectly merges them
    assert alert_display_key(a) == alert_display_key(b)


def test_same_rule_different_users_separate_keys():
    a = _base()
    b = _base()
    a["llm_payload"] = {
        "alert_fields": {"Computer": "same-host", "user_id": "alice"}
    }
    b["llm_payload"] = {
        "alert_fields": {"Computer": "same-host", "user_id": "bob"}
    }
    # Same host → same primary entity; users are secondary — they still share
    # primary host token. Require users in parts to differ when hosts equal.
    from app.services.dedup.alert_identity import alert_logical_key_parts

    pa, pb = alert_logical_key_parts(a), alert_logical_key_parts(b)
    assert pa["users"] != pb["users"]
    # Full key includes users list → distinct
    assert alert_logical_key(a) != alert_logical_key(b)


def test_severity_and_disposition_excluded_from_identity():
    a = _base(severity="high", disposition="true_positive")
    b = _base(severity="critical", disposition="false_positive")
    assert alert_logical_key(a) == alert_logical_key(b)
    assert alert_display_key(a) != alert_display_key(b)


def test_same_title_different_rule_ids():
    a = _base(rule_id="rule-a", title="Same Title")
    b = _base(rule_id="rule-b", title="Same Title")
    assert alert_logical_key(a) != alert_logical_key(b)


def test_outside_time_window_not_grouped():
    early = _base(created_at=datetime(2026, 11, 14, 12, 0, tzinfo=UTC))
    late = _base(
        id=str(uuid4()),
        created_at=datetime(2026, 11, 14, 13, 0, tzinfo=UTC),
        event_time=datetime(2026, 11, 14, 13, 0, tzinfo=UTC),
    )
    assert within_dedup_window(early, late, window_seconds=900) is False
    groups = _group_alerts_for_dedupe([early, late], v2=True, window_seconds=900)
    # Two window clusters despite same logical key
    multi = [g for g in groups.values() if len(g) >= 1]
    assert sum(1 for g in groups.values() if len(g) >= 2) == 0
    assert len(groups) >= 2


def test_inside_time_window_same_entity_groups():
    t0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
    a = _base(id=str(uuid4()), created_at=t0, event_time=t0)
    b = _base(
        id=str(uuid4()),
        created_at=t0 + timedelta(minutes=5),
        event_time=t0 + timedelta(minutes=5),
    )
    groups = _group_alerts_for_dedupe([a, b], v2=True, window_seconds=900)
    assert any(len(g) >= 2 for g in groups.values())


def test_missing_ip_endpoint_identity_works():
    key = alert_logical_key(_base())
    assert key.startswith("alert:v1:")


def test_shadow_detects_legacy_false_merges():
    a = _base(affected_hosts=["host-a"], llm_payload={"alert_fields": {}})
    b = _base(
        id=str(uuid4()),
        affected_hosts=["host-b"],
        llm_payload={"alert_fields": {}},
    )
    report = compare_grouping([a, b], window_seconds=900)
    assert report["false_merges_prevented_by_v2"] >= 1


# --- Layer 3: correlation ---


def test_same_rule_different_hosts_not_forced_incident():
    a = _base(llm_payload={"alert_fields": {"Computer": "host-a"}})
    b = _base(
        id=str(uuid4()),
        llm_payload={"alert_fields": {"Computer": "host-b"}},
    )
    match = score_alert_pair(a, b)
    assert match.relationship == "unrelated"


def test_shared_host_and_temporal_correlates():
    t0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
    a = _base(
        rule_id="r1",
        event_time=t0,
        created_at=t0,
        llm_payload={"alert_fields": {"Computer": "host-a"}},
        mitre_tactics=["execution"],
    )
    b = _base(
        id=str(uuid4()),
        rule_id="r2",
        event_time=t0 + timedelta(minutes=10),
        created_at=t0 + timedelta(minutes=10),
        llm_payload={"alert_fields": {"Computer": "host-a"}},
        mitre_tactics=["execution"],
    )
    match = score_alert_pair(a, b)
    assert match.correlation_score >= 0.55
    assert match.relationship in {"potentially_related", "weakly_related"}
    assert any(r.type == "shared_host" for r in match.correlation_reasons)


def test_shared_ip_alone_insufficient():
    t0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
    a = {
        "id": str(uuid4()),
        "rule_id": "r1",
        "event_time": t0,
        "affected_ips": ["1.2.3.4"],
        "llm_payload": {},
    }
    b = {
        "id": str(uuid4()),
        "rule_id": "r2",
        "event_time": t0 + timedelta(minutes=5),
        "affected_ips": ["1.2.3.4"],
        "llm_payload": {},
    }
    match = score_alert_pair(a, b)
    assert match.relationship in {"unrelated", "weakly_related"}
    if match.relationship == "weakly_related":
        assert not any(
            r.type in {"shared_host", "shared_user", "shared_hash"}
            for r in match.correlation_reasons
        )


# --- Categorization ---


def test_endpoint_category_from_security_domain():
    result = classify_alert_category(_base())
    assert result.category_id == AlertCategory.ENDPOINT.value
    assert result.confidence >= 0.8


def test_unknown_when_no_evidence():
    result = classify_alert_category(
        {"title": "xyz", "rule_name": "abc", "llm_payload": {}}
    )
    assert result.category_id == AlertCategory.UNKNOWN.value


def test_incident_category_from_tactic_not_title_alone():
    with_tactic = classify_incident_category(mitre_tactics=["lateral movement"])
    assert with_tactic.category_id == IncidentCategory.LATERAL_MOVEMENT.value
    title_only = classify_incident_category(title="Lateral Movement Detected")
    # Must not invent ATT&CK from title — suspicious or unknown, not lateral_movement
    assert title_only.category_id != IncidentCategory.LATERAL_MOVEMENT.value


def test_manual_category_preserved():
    result = classify_alert_category(
        {"category": "malware", "title": "something", "llm_payload": {}}
    )
    assert result.category_id == AlertCategory.MALWARE.value
    assert result.analyst_confirmed is True


def test_multi_stage_incident():
    result = classify_incident_category(
        mitre_tactics=["initial access", "lateral movement"]
    )
    assert result.category_id == IncidentCategory.MULTI_STAGE.value


# --- Funnel / Tier-2 compatibility helpers ---


def test_v2_group_preserves_independent_hosts():
    rows = [
        _base(id=str(uuid4()), llm_payload={"alert_fields": {"Computer": "h1"}}),
        _base(id=str(uuid4()), llm_payload={"alert_fields": {"Computer": "h2"}}),
    ]
    groups = _group_alerts_for_dedupe(rows, v2=True, window_seconds=900)
    assert sum(1 for g in groups.values() if len(g) >= 2) == 0


@pytest.mark.parametrize(
    "domain,expected",
    [
        ("network", AlertCategory.NETWORK),
        ("identity", AlertCategory.IDENTITY),
        ("email", AlertCategory.EMAIL),
        ("cloud", AlertCategory.CLOUD),
    ],
)
def test_domain_categories(domain, expected):
    result = classify_alert_category(
        {"llm_payload": {"security_domain": domain}, "title": "t"}
    )
    assert result.category_id == expected.value
