"""Unit tests for the analyst alert scope (exclusions + llm_payload filters)."""

from __future__ import annotations

import pytest
from app.services.alert_scope import (
    ScopeError,
    apply_scope,
    filter_matches,
    parse_filter,
    parse_filters,
    resolve_path,
)
from app.services.candidate_discovery import Observation, keep_alert_ids


def _alert(alert_id: str, payload: dict, title: str = "Alert") -> dict:
    return {"id": alert_id, "title": title, "llm_payload": payload}


PAYLOAD_A = {
    "rule": {"name": "Credential dumping", "title": "LSASS access"},
    "alert_fields": {"src": "10.0.0.5", "dest": "win-dc-01", "index": "wineventlog"},
}
PAYLOAD_B = {
    "rule": {"name": "Scheduled scan"},
    "alert_fields": {"src": "10.0.0.9", "dest": "win-dc-01", "index": "vulnscan"},
}


def test_parse_filter_rejects_fields_outside_llm_payload() -> None:
    with pytest.raises(ScopeError):
        parse_filter("affected_hosts|eq|win-dc-01|exclude")


def test_parse_filter_accepts_alert_fields_alias() -> None:
    parsed = parse_filter("alert_fields.dest|eq|win-dc-01|exclude")
    assert parsed.field == "llm_payload.alert_fields.dest"
    assert parsed.op == "eq"
    assert parsed.mode == "exclude"


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        ("llm_payload.alert_fields.index|eq|vulnscan|exclude", True),
        ("llm_payload.alert_fields.index|eq|wineventlog|exclude", False),
        ("llm_payload.alert_fields.index|contains|vuln|exclude", True),
        ("llm_payload.alert_fields.index|in|vulnscan,syslog|exclude", True),
        ("llm_payload.rule.missing|exists|exclude", False),
        ("llm_payload.rule.missing|not_exists||exclude", True),
        ("llm_payload.alert_fields.dest|neq|win-dc-01|exclude", False),
    ],
)
def test_filter_matching_ops(raw: str, match: bool) -> None:
    assert filter_matches(_alert("a", PAYLOAD_B), parse_filter(raw)) is match


def test_resolve_path_reads_list_indices() -> None:
    payload = {"alert_fields": {"hosts": [{"name": "win-dc-01"}]}}
    assert resolve_path(payload, "llm_payload.alert_fields.hosts.0.name") == "win-dc-01"
    assert resolve_path(payload, "llm_payload.alert_fields.hosts.4.name") is None


def test_exclude_filter_drops_any_match() -> None:
    alerts = [_alert("a", PAYLOAD_A), _alert("b", PAYLOAD_B)]
    result = apply_scope(
        alerts,
        filters=parse_filters(["llm_payload.alert_fields.index|eq|vulnscan|exclude"]),
    )
    assert result.kept_ids == ["a"]
    assert result.dropped[0]["alert_id"] == "b"
    assert "exclude filter" in result.dropped[0]["reason"]


def test_include_filters_are_conjunctive() -> None:
    alerts = [_alert("a", PAYLOAD_A), _alert("b", PAYLOAD_B)]
    result = apply_scope(
        alerts,
        filters=parse_filters(
            [
                "llm_payload.alert_fields.dest|eq|win-dc-01|include",
                "llm_payload.rule.name|contains|credential|include",
            ]
        ),
    )
    assert result.kept_ids == ["a"]
    assert [item["alert_id"] for item in result.dropped] == ["b"]


def test_explicit_exclusion_wins_over_matching_filters() -> None:
    alerts = [_alert("a", PAYLOAD_A), _alert("b", PAYLOAD_B)]
    result = apply_scope(
        alerts,
        excluded_ids=["a"],
        filters=parse_filters(["llm_payload.alert_fields.dest|eq|win-dc-01|include"]),
    )
    assert result.kept_ids == ["b"]
    assert result.dropped[0]["reason"] == "excluded by the analyst"


def test_scope_with_no_rules_keeps_everything() -> None:
    alerts = [_alert("a", PAYLOAD_A), _alert("b", PAYLOAD_B)]
    result = apply_scope(alerts)
    assert result.kept_ids == ["a", "b"]
    assert result.dropped == []


def _observation(key: str, alert_ids: list[str]) -> Observation:
    return Observation(
        signature=key,
        alert_ids=list(alert_ids),
        role=None,
        techniques=[],
        hosts=[],
        users=[],
        ips=[],
        domains=[],
    )


def test_keep_alert_ids_trims_and_drops_empty_observations() -> None:
    observations = {
        "obs-1": _observation("obs-1", ["a1", "a2"]),
        "obs-2": _observation("obs-2", ["a3"]),
    }
    kept = keep_alert_ids(observations, ["a1"])
    assert list(kept) == ["obs-1"]
    assert kept["obs-1"].alert_ids == ["a1"]
