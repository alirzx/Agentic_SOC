"""P7 mandatory gate — 18-group test matrix + feature-flag behavior.

Groups map 1:1 to the delivery specification. Existing Tier-2 IP-pivot
regression tests remain in ``test_tier2_ip_pivot.py`` and are executed in the
P7 regression command.
"""

from __future__ import annotations

from app.services.tier2_adaptive.case_policy import decide_case_action
from app.services.tier2_adaptive.correlation import (
    SCORE_CANDIDATE,
    SCORE_UNRELATED,
    score_alert_correlation,
)
from app.services.tier2_adaptive.engine import run_adaptive_pipeline_sync
from app.services.tier2_adaptive.entities import (
    extract_alert_entities,
    powershell_regression_alert,
)
from app.services.tier2_adaptive.feature_flags import selected_tier2_path
from app.services.tier2_adaptive.profiles import select_investigation_profiles


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


# --- Group 1 ---
def test_g01_powershell_endpoint_alert_without_ip():
    result = run_adaptive_pipeline_sync(powershell_regression_alert())
    assert result.entities.values("ip") == []
    assert "endpoint" in result.profiles.names
    assert result.report.final_assessment


# --- Group 2 ---
def test_g02_host_extraction_from_alert_fields():
    ents = extract_alert_entities(powershell_regression_alert())
    assert "cao01vw013.cao.ir" in ents.values("hostname")


# --- Group 3 ---
def test_g03_user_sid_extraction():
    ents = extract_alert_entities(powershell_regression_alert())
    assert "S-1-5-21-1793179736-1175893981-2474273398-13753" in ents.values("user_sid")


# --- Group 4 ---
def test_g04_multiple_and_conflicting_hosts():
    ents = extract_alert_entities(powershell_regression_alert())
    hosts = {e.normalized_value: e.source_field for e in ents.by_type("hostname")}
    assert hosts.get("cao01vw013.cao.ir") == "Computer"
    assert hosts.get("sh2") == "extracted_host"


# --- Group 5 ---
def test_g05_endpoint_profile_selection():
    sel = select_investigation_profiles(powershell_regression_alert())
    assert sel.names[0] == "endpoint"


# --- Group 6 ---
def test_g06_network_profile_selection():
    sel = select_investigation_profiles(
        {
            "security_domain": "network",
            "llm_payload": {"src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"},
        }
    )
    assert "network" in sel.names


# --- Group 7 ---
def test_g07_identity_profile_selection():
    sel = select_investigation_profiles(
        {
            "security_domain": "identity",
            "llm_payload": {"alert_fields": {"user_id": "S-1-5-21-1-2-3-4"}},
        }
    )
    assert "identity" in sel.names


# --- Group 8 ---
def test_g08_multi_profile_selection():
    alert = {
        "security_domain": "endpoint",
        "raw_event": {"orig_security_domain": "identity"},
        "llm_payload": {
            "alert_fields": {
                "Computer": "h1",
                "user_id": "S-1-5-21-1-2-3-9",
            }
        },
    }
    sel = select_investigation_profiles(alert)
    assert "endpoint" in sel.names and "identity" in sel.names


# --- Group 9 ---
def test_g09_host_based_sibling_correlation():
    seed = _alert(id="s1", fields={"Computer": "h1.local"})
    cand = _alert(id="c1", fields={"Computer": "h1.local"})
    result = score_alert_correlation(seed, cand)
    assert result.total_score >= SCORE_UNRELATED


# --- Group 10 ---
def test_g10_user_sid_based_correlation():
    sid = "S-1-5-21-1793179736-1175893981-2474273398-13753"
    seed = _alert(id="s1", fields={"user_id": sid})
    cand = _alert(id="c1", fields={"user_id": sid})
    result = score_alert_correlation(seed, cand)
    assert any(r.type == "exact_user_sid" for r in result.correlation_reasons)


# --- Group 11 ---
def test_g11_hash_based_correlation():
    h = "d" * 64
    seed = _alert(id="s1", fields={"sha256": h})
    cand = _alert(id="c1", fields={"sha256": h})
    result = score_alert_correlation(seed, cand)
    assert any(r.type == "exact_file_hash" for r in result.correlation_reasons)


# --- Group 12 ---
def test_g12_correlation_score_and_explanation():
    seed = powershell_regression_alert()
    seed["id"] = seed["alert_id"]
    seed["tenant_id"] = "t1"
    sibling = _alert(
        id="sib",
        tenant_id="t1",
        fields={
            "Computer": "cao01vw013.cao.ir",
            "user_id": "S-1-5-21-1793179736-1175893981-2474273398-13753",
        },
    )
    result = score_alert_correlation(seed, sibling)
    assert result.correlation_reasons
    assert result.to_dict()["total_score"] >= SCORE_UNRELATED
    assert result.decision in {"candidate", "eligible"}


# --- Group 13 ---
def test_g13_high_severity_standalone_case_creation():
    decision = decide_case_action(powershell_regression_alert())
    assert decision.action == "create"


# --- Group 14 ---
def test_g14_existing_case_extension():
    from app.services.tier2_adaptive.correlation import CorrelationHistoryEntry, CorrelationResult

    decision = decide_case_action(
        {"id": "a1", "severity": "medium", "llm_payload": {"alert_fields": {"Computer": "h1"}}},
        correlation=CorrelationHistoryEntry(
            seed_alert_id="a1",
            results=[
                CorrelationResult(
                    candidate_alert_id="a2",
                    total_score=80.0,
                    decision="eligible",
                )
            ],
            window_hours=24,
            recorded_at="2026-11-14T00:00:00Z",
        ),
    )
    assert decision.action == "extend"
    assert decision.correlation_score >= SCORE_CANDIDATE


# --- Group 15 ---
def test_g15_no_false_case_extension_below_threshold():
    from app.services.tier2_adaptive.correlation import CorrelationHistoryEntry, CorrelationResult

    decision = decide_case_action(
        {"id": "a1", "severity": "low", "llm_payload": {"alert_fields": {"Computer": "h1"}}},
        correlation=CorrelationHistoryEntry(
            seed_alert_id="a1",
            results=[
                CorrelationResult(
                    candidate_alert_id="a2",
                    total_score=45.0,
                    decision="candidate",
                )
            ],
            window_hours=24,
            recorded_at="2026-11-14T00:00:00Z",
        ),
    )
    assert decision.action == "review"


# --- Group 16 ---
def test_g16_investigation_with_unavailable_data_sources():
    from app.services.tier2_adaptive.investigation import execute_adaptive_investigation
    from app.services.tier2_adaptive.profiles import select_investigation_profiles

    alert = powershell_regression_alert()
    ents = extract_alert_entities(alert)
    profiles = select_investigation_profiles(alert, entities=ents)
    steps, report = execute_adaptive_investigation(
        alert=alert,
        entities=ents,
        profiles=profiles,
        unavailable_tools={"query_edr_telemetry", "inspect_host"},
    )
    assert any(s.status == "not_available" for s in steps)
    assert report.limitations


# --- Group 17 ---
def test_g17_single_and_multi_alert_reports():
    seed = powershell_regression_alert()
    seed["id"] = seed["alert_id"]
    seed["tenant_id"] = "t1"
    single = run_adaptive_pipeline_sync(seed)
    sibling = _alert(
        id="sib",
        tenant_id="t1",
        fields={
            "Computer": "cao01vw013.cao.ir",
            "user_id": "S-1-5-21-1793179736-1175893981-2474273398-13753",
        },
    )
    multi = run_adaptive_pipeline_sync(seed, related_candidates=[sibling])
    assert single.report.report_kind == "standalone"
    assert multi.report.to_dict()["findings"]


# --- Group 18 ---
def test_g18_feature_flag_behavior_and_backward_compatibility(monkeypatch):
    monkeypatch.delenv("AISOC_TIER2_ADAPTIVE", raising=False)
    monkeypatch.delenv("AISOC_TIER2_ADAPTIVE_SHADOW", raising=False)
    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
    except Exception:
        pass

    monkeypatch.setattr(
        "app.services.tier2_adaptive.feature_flags.tier2_adaptive_enabled",
        lambda: False,
    )
    monkeypatch.setattr(
        "app.services.tier2_adaptive.feature_flags.tier2_adaptive_shadow",
        lambda: False,
    )
    assert selected_tier2_path() == "legacy"

    monkeypatch.setattr(
        "app.services.tier2_adaptive.feature_flags.tier2_adaptive_enabled",
        lambda: False,
    )
    monkeypatch.setattr(
        "app.services.tier2_adaptive.feature_flags.tier2_adaptive_shadow",
        lambda: True,
    )
    assert selected_tier2_path() == "legacy+shadow_adaptive"

    monkeypatch.setattr(
        "app.services.tier2_adaptive.feature_flags.tier2_adaptive_enabled",
        lambda: True,
    )
    assert selected_tier2_path() == "adaptive"

    # Shadow pipeline must not claim case creation
    shadowed = run_adaptive_pipeline_sync(powershell_regression_alert(), shadow=True)
    assert shadowed.case_decision.action in {"review", "standalone"}
    assert shadowed.case_decision.idempotency_key.startswith("shadow:")

    # Legacy extract_alert_ips still works (backward compatibility)
    from app.services.tier2_ip_pivot import extract_alert_ips, tier2_step_catalog

    ips = extract_alert_ips(powershell_regression_alert())
    assert ips.all_ips == []
    monkeypatch.setattr(
        "app.services.tier2_adaptive.feature_flags.tier2_adaptive_enabled",
        lambda: False,
    )
    assert len(tier2_step_catalog()) == 5
