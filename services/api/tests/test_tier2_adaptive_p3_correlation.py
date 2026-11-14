"""P3 mandatory gate — Entity-aware Correlation Engine."""

from __future__ import annotations

from app.services.tier2_adaptive.correlation import (
    SCORE_CANDIDATE,
    SCORE_UNRELATED,
    correlate_candidates,
    score_alert_correlation,
)
from app.services.tier2_adaptive.entities import powershell_regression_alert


def _alert(**kwargs):
    base = {
        "id": kwargs.get("id", "a1"),
        "tenant_id": kwargs.get("tenant_id", "t1"),
        "severity": kwargs.get("severity", "high"),
        "rule_name": kwargs.get("rule_name", "Rule-A"),
        "event_time": kwargs.get("event_time", "2026-11-14T12:00:00+00:00"),
        "llm_payload": {"alert_fields": kwargs.get("fields", {})},
    }
    base.update({k: v for k, v in kwargs.items() if k not in {"fields"}})
    if "fields" in kwargs:
        base["llm_payload"] = {"alert_fields": kwargs["fields"]}
    return base


def test_host_based_correlation():
    seed = _alert(id="s1", fields={"Computer": "cao01vw013.cao.ir"})
    cand = _alert(id="c1", fields={"Computer": "cao01vw013.cao.ir", "Image": "cmd.exe"})
    result = score_alert_correlation(seed, cand)
    assert result.total_score >= SCORE_UNRELATED
    assert any(r.type in {"exact_hostname", "exact_endpoint"} for r in result.correlation_reasons)
    assert result.decision in {"candidate", "eligible"}


def test_user_based_correlation():
    seed = _alert(id="s1", fields={"username": "jdoe"})
    cand = _alert(id="c1", fields={"username": "jdoe", "Computer": "h1"})
    result = score_alert_correlation(seed, cand)
    assert any(r.type == "exact_user" for r in result.correlation_reasons)
    assert result.total_score > 0


def test_sid_based_correlation():
    sid = "S-1-5-21-1793179736-1175893981-2474273398-13753"
    seed = _alert(id="s1", fields={"user_id": sid})
    cand = _alert(id="c1", fields={"user_id": sid})
    result = score_alert_correlation(seed, cand)
    assert any(r.type == "exact_user_sid" for r in result.correlation_reasons)
    assert result.decision in {"candidate", "eligible"}


def test_hash_based_correlation():
    h = "a" * 64
    seed = _alert(id="s1", fields={"sha256": h})
    cand = _alert(id="c1", fields={"sha256": h, "Computer": "other"})
    result = score_alert_correlation(seed, cand)
    assert any(r.type == "exact_file_hash" for r in result.correlation_reasons)
    assert result.total_score >= SCORE_UNRELATED


def test_ip_based_correlation():
    seed = _alert(id="s1", fields={"src_ip": "10.20.30.40"})
    cand = _alert(id="c1", fields={"dest_ip": "10.20.30.40"})
    result = score_alert_correlation(seed, cand)
    assert any(r.type == "exact_ip" for r in result.correlation_reasons)


def test_behavioral_correlation():
    fields = {
        "Computer": "h1.local",
        "Image": "powershell.exe",
        "Path": r"C:\Temp\CL_Utility.ps1",
        "ScriptBlockText": "function Get-FreeSpace { ... }",
    }
    seed = _alert(id="s1", security_domain="endpoint", fields=fields)
    cand = _alert(id="c1", security_domain="endpoint", fields=dict(fields))
    result = score_alert_correlation(seed, cand)
    assert any(r.type == "behavioral_similarity" for r in result.correlation_reasons)


def test_time_based_correlation():
    seed = _alert(
        id="s1",
        event_time="2026-11-14T12:00:00+00:00",
        fields={"Computer": "h1.local"},
    )
    cand = _alert(
        id="c1",
        event_time="2026-11-14T12:30:00+00:00",
        fields={"Computer": "h1.local"},
    )
    result = score_alert_correlation(seed, cand, temporal_window_seconds=3600)
    assert any(r.type == "temporal_proximity" for r in result.correlation_reasons)
    assert "within_" in result.time_relationship


def test_same_rule_without_sufficient_evidence():
    seed = _alert(id="s1", rule_name="Same Rule", fields={})
    cand = _alert(id="c1", rule_name="Same Rule", fields={})
    result = score_alert_correlation(seed, cand)
    assert result.decision == "unrelated"
    assert result.total_score == 0.0
    assert "same_rule_insufficient" in result.supporting_evidence or any(
        r.type == "same_rule_without_evidence" for r in result.correlation_reasons
    )


def test_common_ip_false_positive_prevention():
    seed = _alert(id="s1", fields={"dest_ip": "8.8.8.8"})
    cand = _alert(id="c1", fields={"dest_ip": "8.8.8.8"})
    result = score_alert_correlation(seed, cand)
    assert result.decision == "unrelated"
    assert any(r.type == "common_infra_ip" for r in result.correlation_reasons)


def test_cross_tenant_isolation():
    seed = _alert(id="s1", tenant_id="tenant-a", fields={"Computer": "h1"})
    cand = _alert(id="c1", tenant_id="tenant-b", fields={"Computer": "h1"})
    result = score_alert_correlation(seed, cand)
    assert result.decision == "unrelated"
    assert result.match_type == "cross_tenant_blocked"
    assert result.total_score == 0.0


def test_multiple_correlated_alerts():
    seed = _alert(
        id="s1",
        fields={
            "Computer": "cao01vw013.cao.ir",
            "user_id": "S-1-5-21-1793179736-1175893981-2474273398-13753",
        },
    )
    cands = [
        _alert(id="c1", fields={"Computer": "cao01vw013.cao.ir"}),
        _alert(
            id="c2",
            fields={"user_id": "S-1-5-21-1793179736-1175893981-2474273398-13753"},
        ),
        _alert(id="c3", fields={"Computer": "other.local"}),
    ]
    history = correlate_candidates(seed, cands, min_decision="candidate")
    ids = {r.candidate_alert_id for r in history.results}
    assert "c1" in ids
    assert "c2" in ids
    assert "c3" not in ids


def test_correlation_explanation():
    seed = _alert(id="s1", fields={"Computer": "h1", "src_ip": "10.1.1.1"})
    cand = _alert(id="c1", fields={"Computer": "h1", "src_ip": "10.1.1.1"})
    result = score_alert_correlation(seed, cand)
    assert result.correlation_reasons
    assert result.supporting_evidence
    assert result.matched_entities
    payload = result.to_dict()
    assert payload["algorithm_version"].startswith("tier2-corr:")
    assert payload["total_score"] >= SCORE_CANDIDATE or payload["decision"] in {
        "candidate",
        "eligible",
    }


def test_correlation_history():
    seed = powershell_regression_alert()
    seed["tenant_id"] = "t1"
    seed["id"] = seed["alert_id"]
    sibling = _alert(
        id="sib-1",
        tenant_id="t1",
        fields={
            "Computer": "cao01vw013.cao.ir",
            "user_id": "S-1-5-21-1793179736-1175893981-2474273398-13753",
        },
    )
    history = correlate_candidates(seed, [sibling], min_decision="unrelated")
    assert history.seed_alert_id == seed["alert_id"]
    assert history.results
    assert history.recorded_at
    assert history.to_dict()["results"]


def test_severity_alone_does_not_correlate():
    seed = _alert(id="s1", severity="critical", fields={})
    cand = _alert(id="c1", severity="critical", fields={})
    result = score_alert_correlation(seed, cand)
    assert result.decision == "unrelated"


def test_powershell_host_user_correlation_without_ip():
    seed = powershell_regression_alert()
    seed["tenant_id"] = "t1"
    seed["id"] = seed["alert_id"]
    sibling = {
        "id": "sib-ps",
        "tenant_id": "t1",
        "rule_name": "Other endpoint rule",
        "event_time": "2026-11-14T15:20:00+0330",
        "llm_payload": {
            "alert_fields": {
                "Computer": "cao01vw013.cao.ir",
                "user_id": "S-1-5-21-1793179736-1175893981-2474273398-13753",
            }
        },
    }
    result = score_alert_correlation(seed, sibling)
    assert result.decision in {"candidate", "eligible"}
    assert result.total_score >= SCORE_UNRELATED
    types = {r.type for r in result.correlation_reasons}
    assert "exact_hostname" in types or "exact_endpoint" in types
    assert "exact_user_sid" in types
