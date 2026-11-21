"""Unit tests for the pure candidate filter helper (no database required).

The endpoint runs discovery (which needs Postgres) and then applies these rules.
Keeping the rules pure is what makes the filter contract testable: a regression
here silently shows the wrong candidates to an analyst.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.services.candidate_discovery import (
    Observation,
    TokenIndex,
    entity_tokens,
    filter_candidates,
    observation_tokens,
    payload_rule_title,
)


def _candidate(
    key: str,
    *,
    score: int = 6,
    evidence: int = 12,
    alerts: int = 5,
    hosts: list[str] | None = None,
    users: list[str] | None = None,
    ips: list[str] | None = None,
    domains: list[str] | None = None,
    techniques: list[str] | None = None,
    severity: str = "high",
    first: datetime | None = None,
    last: datetime | None = None,
) -> dict:
    base = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
    return {
        "candidate_key": key,
        "campaign_theme": "MULTI_HOST_CORRELATION",
        "score": score,
        "evidence_score": evidence,
        "pair_count": 3,
        "alert_count": alerts,
        "entities": {
            "hosts": hosts or [],
            "users": users or [],
            "ips": ips or [],
            "domains": domains or [],
        },
        "techniques": techniques or [],
        "alert_ids": [f"{key}-alert-1"],
        "severity": severity,
        "time_first": first or base,
        "time_last": last or base + timedelta(hours=2),
    }


def test_min_score_filters_on_peak_not_evidence_total():
    tight = _candidate("tight", score=9, evidence=900, alerts=200)
    loose = _candidate("loose", score=3, evidence=5000, alerts=300)

    result = filter_candidates([tight, loose], min_score=6)

    assert [c["candidate_key"] for c in result] == ["tight"]


def test_search_matches_entity_values_techniques_and_ids():
    candidate = _candidate(
        "abc123",
        hosts=["win-dc-8537412.attackrange.local"],
        techniques=["T1003.001"],
    )
    other = _candidate("def456", hosts=["web-01"], techniques=["T1021"])

    assert filter_candidates([candidate, other], q="8537412") == [candidate]
    assert filter_candidates([candidate, other], q="t1003") == [candidate]
    assert filter_candidates([candidate, other], q="abc123") == [candidate]
    assert filter_candidates([candidate, other], q="no-such-value") == []


def test_search_is_case_insensitive_and_ignores_surrounding_space():
    candidate = _candidate("abc", users=["Administrator"])
    assert filter_candidates([candidate], q="  ADMINISTRATOR ")


def test_entity_kinds_require_every_selected_bucket():
    both = _candidate("both", users=["alice"], ips=["10.0.1.15"])
    host_only = _candidate("host-only", hosts=["dc-01"])
    with_technique = _candidate("tech", hosts=["dc-01"], techniques=["T1003"])

    result = filter_candidates([both, host_only, with_technique], entity_kinds=["users", "ips"])
    assert [c["candidate_key"] for c in result] == ["both"]

    techniques = filter_candidates([both, host_only, with_technique], entity_kinds=["techniques"])
    assert [c["candidate_key"] for c in techniques] == ["tech"]


def test_unknown_entity_kind_is_ignored_rather_than_matching_everything():
    candidate = _candidate("abc", hosts=["dc-01"])
    assert filter_candidates([candidate], entity_kinds=["bogus"]) == [candidate]


def test_time_filter_uses_span_overlap_not_start_only():
    now = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    still_active = _candidate(
        "active",
        first=now - timedelta(days=2),
        last=now - timedelta(minutes=10),
    )
    finished = _candidate(
        "finished",
        first=now - timedelta(days=5),
        last=now - timedelta(days=3),
    )

    result = filter_candidates([still_active, finished], since=now - timedelta(hours=24))
    assert [c["candidate_key"] for c in result] == ["active"]


def test_time_filter_honours_an_upper_bound():
    now = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    old = _candidate("old", first=now - timedelta(days=10), last=now - timedelta(days=9))
    new = _candidate("new", first=now - timedelta(hours=2), last=now - timedelta(hours=1))

    result = filter_candidates([old, new], until=now - timedelta(days=1))
    assert [c["candidate_key"] for c in result] == ["old"]


def test_time_filter_accepts_iso_strings():
    candidate = _candidate("abc", first=datetime(2026, 11, 8, 15, 0, tzinfo=UTC))
    assert filter_candidates([candidate], since="2026-11-08T00:00:00Z")
    assert filter_candidates([candidate], since="2026-11-09T00:00:00Z") == []


def test_alert_count_bounds():
    small = _candidate("small", alerts=2)
    big = _candidate("big", alerts=101)

    assert [c["candidate_key"] for c in filter_candidates([small, big], min_alerts=5)] == ["big"]
    assert [c["candidate_key"] for c in filter_candidates([small, big], max_alerts=5)] == ["small"]


def test_severity_is_case_insensitive():
    candidate = _candidate("abc", severity="Critical")
    assert filter_candidates([candidate], severity="critical")
    assert filter_candidates([candidate], severity="low") == []


def test_sort_orders():
    a = _candidate("a", score=3, alerts=100, last=datetime(2026, 11, 8, 17, 0, tzinfo=UTC))
    b = _candidate("b", score=11, alerts=5, last=datetime(2026, 11, 8, 13, 0, tzinfo=UTC))
    c = _candidate("c", score=6, alerts=50, last=datetime(2026, 11, 8, 15, 0, tzinfo=UTC))

    candidates = [a, b, c]
    assert [x["candidate_key"] for x in filter_candidates(candidates, sort="score")] == ["b", "c", "a"]
    assert [x["candidate_key"] for x in filter_candidates(candidates, sort="alerts")] == ["a", "c", "b"]
    assert [x["candidate_key"] for x in filter_candidates(candidates, sort="recent")] == ["a", "c", "b"]


# ── llm_payload rule title ────────────────────────────────────────────────────


def test_payload_rule_title_reads_the_analytic_name():
    payload = {
        "rule_name": "ESCU - Windows Possible Credential Dumping - Rule",
        "rule": {
            "title": "Windows Possible Credential Dumping",
            "title_template": "Windows Possible Credential Dumping",
        },
    }
    assert (
        payload_rule_title(payload, "ESCU - Windows Possible Credential Dumping - Rule")
        == "Windows Possible Credential Dumping"
    )


def test_payload_rule_title_falls_back_to_title_template():
    payload = {"rule_name": "ESCU - Rule", "rule": {"title": "", "title_template": "Human Title"}}
    assert payload_rule_title(payload, "ESCU - Rule") == "Human Title"


def test_payload_rule_title_is_none_without_new_information():
    # Missing / malformed payloads and payloads that merely echo the search name
    # must not produce a duplicate line in the UI.
    assert payload_rule_title(None) is None
    assert payload_rule_title("not-a-dict") is None
    assert payload_rule_title({"rule_name": "ESCU - Rule", "rule": {"title": "ESCU - Rule"}}, "ESCU - Rule") is None


# ── L3: 3-hop graph proximity ─────────────────────────────────────────────────


def _observation(key: str, *, hosts=(), users=(), ips=(), domains=()) -> Observation:
    return Observation(
        signature=key,
        alert_ids=[key],
        role=None,
        techniques=[],
        hosts=list(hosts),
        users=list(users),
        ips=list(ips),
        domains=list(domains),
    )


def test_entity_tokens_are_kind_scoped_and_case_insensitive():
    obs = _observation("a", hosts=["WIN-DC01"], users=["Administrator"], ips=["10.0.0.5"])
    assert entity_tokens(obs) == {"host:win-dc01", "user:administrator", "ip:10.0.0.5"}


def test_l3_fires_on_a_path_through_a_third_observation():
    # A shares host1 with C, C shares user:bob with B → A and B are joined
    # through C by two distinct keys, which is genuine graph evidence.
    observations = {
        "a": _observation("a", hosts=["host1"]),
        "c": _observation("c", hosts=["host1"], users=["bob"]),
        "b": _observation("b", users=["bob"]),
    }
    index = TokenIndex(observations)
    assert index.has_three_hop_path("a", "b") is True


def test_l3_ignores_a_direct_shared_key():
    observations = {
        "a": _observation("a", hosts=["host1"]),
        "b": _observation("b", hosts=["host1"]),
    }
    assert TokenIndex(observations).has_three_hop_path("a", "b") is False


def test_l3_ignores_a_third_observation_that_adds_nothing():
    # C shares the same single token with both sides: that is just another
    # direct overlap, not a multi-hop path.
    observations = {
        "a": _observation("a", hosts=["host1"]),
        "b": _observation("b", hosts=["host1"]),
        "c": _observation("c", hosts=["host1"]),
    }
    assert TokenIndex(observations).has_three_hop_path("a", "b") is False


def test_persisted_tokens_win_over_entity_rebuild():
    # The ledger stores the engine's own weighted keys; a hash key is not
    # recoverable from the entity buckets, so it must come from the ledger.
    obs = _observation("a", hosts=["host1"])
    obs.tokens = {"host:host1", "hash:deadbeef"}
    assert observation_tokens(obs) == {"host:host1", "hash:deadbeef"}


def test_persisted_hash_token_can_complete_a_three_hop_path():
    # A and B share nothing; C meets each of them on a different key. Without
    # persisted tokens this pair could never earn L3.
    a = _observation("a", hosts=["host1"])
    a.tokens = {"host:host1", "hash:deadbeef"}
    b = _observation("b", users=["bob"])
    b.tokens = {"user:bob", "hash:deadbeef"}
    c = _observation("c")
    c.tokens = {"host:host1", "user:bob"}
    index = TokenIndex({"a": a, "b": b, "c": c})
    assert index.has_three_hop_path("a", "b") is True


def test_observations_without_persisted_tokens_still_use_entities():
    observations = {
        "a": _observation("a", hosts=["host1"]),
        "c": _observation("c", hosts=["host1"], users=["bob"]),
        "b": _observation("b", users=["bob"]),
    }
    assert TokenIndex(observations).has_three_hop_path("a", "b") is True


def test_three_hop_path_returns_the_middle_observation_and_keys():
    observations = {
        "a": _observation("a", hosts=["host1"]),
        "c": _observation("c", hosts=["host1"], users=["bob"]),
        "b": _observation("b", users=["bob"]),
    }
    path = TokenIndex(observations).three_hop_path("a", "b")
    assert path == {"via": "c", "left_token": "host:host1", "right_token": "user:bob"}


def test_three_hop_path_is_deterministic_across_equivalent_middles():
    # Two middles are equally valid; sorted traversal must pick the same one
    # every run, otherwise the inspector's explanation flickers.
    observations = {
        "a": _observation("a", hosts=["host1"]),
        "b": _observation("b", users=["bob"]),
        "c2": _observation("c2", hosts=["host1"], users=["bob"]),
        "c1": _observation("c1", hosts=["host1"], users=["bob"]),
    }
    index = TokenIndex(observations)
    assert index.three_hop_path("a", "b") == index.three_hop_path("a", "b")
    assert index.three_hop_path("a", "b")["via"] == "c1"


def test_three_hop_path_returns_none_without_a_path():
    observations = {
        "a": _observation("a", hosts=["host1"]),
        "b": _observation("b", users=["bob"]),
    }
    assert TokenIndex(observations).three_hop_path("a", "b") is None
