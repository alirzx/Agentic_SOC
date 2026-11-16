"""Multi-host seed/candidate discovery + SQL param + audit summarize."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.services.campaign_correlation import (
    HOST_CENTRIC_DISCOVERY_SQL,
    extract_alert_hosts,
    find_host_related_alerts,
    host_centric_discovery_params,
    host_centric_sql_filter_clause,
    normalize_host,
    primary_seed_host,
    score_campaign_link,
    select_campaign_siblings,
    summarize_correlation_decisions,
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


def test_multi_host_seed_discovers_via_any_host():
    seed = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["host-a", "host-b"],
    )
    on_a = _alert(
        id="on-a",
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["host-a"],
        affected_users=["u1"],
        event_time=T0 + timedelta(minutes=2),
        mitre_techniques=["T1003.001"],
    )
    on_b = _alert(
        id="on-b",
        title="Windows Non-System Account Targeting LSASS",
        affected_hosts=["HOST-B."],  # trailing dot + case
        affected_users=["u1"],
        event_time=T0 + timedelta(minutes=3),
        mitre_techniques=["T1003.001"],
    )
    hits = find_host_related_alerts(seed, [on_a, on_b])
    assert {str(h["id"]) for h in hits} == {"on-a", "on-b"}
    accepted, decisions = select_campaign_siblings(seed, [on_a, on_b])
    assert len(decisions) == 2
    for d in decisions:
        assert d["discovery_path"] == "host_centric"
        assert "host_centric" in d["discovery_paths"]
        assert d["seed_hosts"] == ["host-a", "host-b"]
        assert d["matched_hosts"]


def test_candidate_matching_two_seed_hosts_deduped_once():
    seed = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["h1", "h2"],
        affected_users=["admin"],
    )
    both = _alert(
        id="both",
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["h1", "h2"],
        affected_users=["admin"],
        mitre_techniques=["T1003.001"],
    )
    accepted, decisions = select_campaign_siblings(seed, [both, both])
    assert len(decisions) == 1
    assert decisions[0]["alert_id"] == "both"
    assert set(decisions[0]["matched_hosts"]) == {"h1", "h2"}
    # Scored once — host weight not doubled
    d = score_campaign_link(seed, both)
    assert d.signals["host_score"] == 0.35


def test_invalid_host_alongside_valid_ignored():
    seed = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["localhost", "10.1.1.1", "", "real-host", "unknown"],
    )
    hosts = extract_alert_hosts(seed)
    assert hosts == ["real-host"]
    assert primary_seed_host(seed) == "real-host"
    cand = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["real-host"],
        affected_users=["u"],
        mitre_techniques=["T1003.001"],
    )
    hits = find_host_related_alerts(seed, [cand])
    assert len(hits) == 1


def test_seed_without_valid_host_falls_back_to_entity_overlap():
    seed = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_hosts=["localhost"],
        affected_ips=["10.9.9.9"],
    )
    assert extract_alert_hosts(seed) == []
    path = _alert(
        title="Soorin-Web-Path Traversal Attempts",
        affected_ips=["10.9.9.9"],
        event_time=T0 + timedelta(minutes=1),
    )
    accepted, decisions = select_campaign_siblings(seed, [path])
    assert len(accepted) == 1
    assert decisions[0]["discovery_path"] == "entity_overlap"


def test_candidate_without_host_not_host_centric():
    seed = _alert(
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["server-01"],
    )
    no_host = _alert(
        title="Soorin-Web-SQL Injection Attempts",
        affected_ips=["10.1.1.1"],
    )
    assert find_host_related_alerts(seed, [no_host]) == []


def test_underscore_and_fqdn_labels():
    assert normalize_host("WEB_01") == "web_01"
    assert normalize_host("a.b.c.d.corp") == "a.b.c.d.corp"
    assert normalize_host("bad host") is None
    assert normalize_host("!!!") is None


def test_host_and_entity_overlap_paths_merged_without_double_score():
    seed = _alert(
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["h1"],
        affected_ips=["10.0.0.5"],
        affected_users=["u1"],
    )
    cand = _alert(
        title="ESCU - Creation of lsass Dump with Taskmgr",
        affected_hosts=["h1"],
        affected_ips=["10.0.0.5"],
        affected_users=["u1"],
        mitre_techniques=["T1003.001"],
    )
    _, decisions = select_campaign_siblings(seed, [cand])
    assert len(decisions) == 1
    paths = decisions[0]["discovery_paths"]
    assert "host_centric" in paths
    # entity_overlap may also be recorded when IP/user shared
    assert decisions[0]["signals"]["host_score"] == 0.35
    assert decisions[0]["final_score"] <= 1.0


def test_sql_filter_parameterized_no_injection():
    clause = host_centric_sql_filter_clause(multi_host=True)
    assert ":norm_hosts" in clause
    assert "ANY" in clause
    assert "';" not in clause.lower() or "SELECT 1" in clause
    # Malicious host string must only appear as bind value, never interpolated
    evil = "'); DROP TABLE alerts;--"
    params = host_centric_discovery_params(
        tenant_id=uuid4(),
        seed_id=uuid4(),
        seed_hosts=["safe-host", evil],
        seed_ts=T0.timestamp(),
        temporal_window_seconds=86400,
    )
    assert params is not None
    # evil fails normalize_host → not in norm_hosts
    assert params["norm_hosts"] == ["safe-host"]
    assert "DROP" not in HOST_CENTRIC_DISCOVERY_SQL
    assert ":norm_hosts" in HOST_CENTRIC_DISCOVERY_SQL
    assert ":window_start" in HOST_CENTRIC_DISCOVERY_SQL
    assert params["window_end"] > params["window_start"]


def test_sql_params_none_without_hosts_or_timestamp():
    assert (
        host_centric_discovery_params(
            tenant_id=uuid4(),
            seed_id=uuid4(),
            seed_hosts=[],
            seed_ts=T0.timestamp(),
            temporal_window_seconds=3600,
        )
        is None
    )
    assert (
        host_centric_discovery_params(
            tenant_id=uuid4(),
            seed_id=uuid4(),
            seed_hosts=["h1"],
            seed_ts=None,
            temporal_window_seconds=3600,
        )
        is None
    )


def test_summarize_counts_unique_candidates():
    decisions = [
        {
            "alert_id": "1",
            "role": "primary",
            "linked": True,
            "discovery_paths": ["host_centric", "entity_overlap"],
        },
        {
            "alert_id": "2",
            "role": "supporting",
            "linked": True,
            "discovery_path": "host_centric",
            "discovery_paths": ["host_centric"],
        },
        {
            "alert_id": "3",
            "role": "rejected",
            "linked": False,
            "discovery_paths": ["entity_overlap"],
        },
    ]
    counts = summarize_correlation_decisions(decisions)
    assert counts["unique_candidates"] == 3
    assert counts["host_centric"] == 2
    assert counts["entity_overlap"] == 2
    assert counts["primary"] == 1
    assert counts["supporting"] == 1
    assert counts["rejected"] == 1


def test_no_transitive_multi_host_abc():
    a = _alert(
        id="a",
        title="Soorin-Endpoint-Powershell Invoke Command",
        affected_hosts=["h1", "h2"],
        affected_users=["u"],
        event_time=T0,
    )
    b = _alert(
        id="b",
        title="ESCU - Access LSASS Memory for Dump Creation",
        affected_hosts=["h1"],
        affected_users=["u"],
        event_time=T0 + timedelta(minutes=5),
        mitre_techniques=["T1003.001"],
    )
    c = _alert(
        id="c",
        title="Windows Defender Exclusion",
        affected_hosts=["h2"],
        affected_users=["u"],
        event_time=T0 + timedelta(hours=30),
    )
    accepted, _ = select_campaign_siblings(a, [b, c], temporal_window_seconds=86400)
    ids = {str(x["id"]) for x in accepted}
    assert "b" in ids
    assert "c" not in ids


def test_case_insensitive_duplicate_hosts_deduped_in_extract():
    a = _alert(affected_hosts=["Server-01.", "server-01", "SERVER-01"])
    assert extract_alert_hosts(a) == ["server-01"]
