"""P6 mandatory gate — Tier-2 UI contract / eight-stage API compatibility."""

from __future__ import annotations

from app.services.tier2_adaptive.engine import (
    LEGACY_STEP_ALIASES,
    TIER2_ADAPTIVE_STEPS,
    adaptive_step_catalog,
    run_adaptive_pipeline_sync,
)
from app.services.tier2_adaptive.entities import powershell_regression_alert
from app.services.tier2_ip_pivot import TIER2_RUNBOOK_STEPS, tier2_step_catalog


def test_eight_adaptive_stages():
    catalog = adaptive_step_catalog()
    assert len(catalog) == 8
    assert catalog[0]["action_name"] == "tier2_alert_context"
    assert catalog[-1]["action_name"] == "tier2_final_report"
    assert len(TIER2_ADAPTIVE_STEPS) == 8


def test_legacy_catalog_still_five_when_flag_off(monkeypatch):
    monkeypatch.delenv("AISOC_TIER2_ADAPTIVE", raising=False)
    monkeypatch.setattr(
        "app.services.tier2_adaptive.feature_flags.tier2_adaptive_enabled",
        lambda: False,
    )
    catalog = tier2_step_catalog()
    assert len(catalog) == 5
    assert catalog[0]["action_name"] == "tier2_extract_ips"
    assert len(TIER2_RUNBOOK_STEPS) == 5


def test_adaptive_catalog_when_flag_on(monkeypatch):
    monkeypatch.setattr(
        "app.services.tier2_adaptive.feature_flags.tier2_adaptive_enabled",
        lambda: True,
    )
    # Clear settings cache if present
    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
    except Exception:
        pass
    monkeypatch.setenv("AISOC_TIER2_ADAPTIVE", "1")
    try:
        from app.core.config import get_settings

        get_settings.cache_clear()
    except Exception:
        pass
    catalog = tier2_step_catalog()
    assert len(catalog) == 8


def test_legacy_aliases_cover_old_action_names():
    assert LEGACY_STEP_ALIASES["tier2_extract_ips"] == "tier2_entity_extraction"
    assert LEGACY_STEP_ALIASES["tier2_case_report"] == "tier2_final_report"


def test_pipeline_emits_eight_runbook_steps_shape():
    from app.services.tier2_adaptive.engine import _build_runbook_steps

    result = run_adaptive_pipeline_sync(powershell_regression_alert())
    steps = _build_runbook_steps(
        result=result,
        investigate_queued=False,
        steps_detail=[],
    )
    assert len(steps) == 8
    assert steps[1]["action_name"] == "tier2_entity_extraction"
    assert "no IP" in steps[1]["summary"] or "entities" in steps[1]["summary"].lower()
    # Missing IP must not mark entity extraction as failed
    assert steps[1]["status"] == "executed"


def test_entity_profile_correlation_case_in_result_payload():
    result = run_adaptive_pipeline_sync(powershell_regression_alert())
    payload = result.to_dict()
    assert payload["entities"]["counts_by_type"]["hostname"] >= 2
    assert "endpoint" in payload["profiles"]["profile_names"]
    assert payload["case_decision"]["action"] == "create"
    assert payload["report"]["investigation_steps"]
    assert payload["report"]["final_assessment"]


def test_single_and_multi_alert_view_contract():
    seed = powershell_regression_alert()
    seed["id"] = seed["alert_id"]
    seed["tenant_id"] = "t1"
    single = run_adaptive_pipeline_sync(seed)
    assert single.report.report_kind == "standalone"
    sibling = {
        "id": "sib",
        "tenant_id": "t1",
        "llm_payload": {
            "alert_fields": {
                "Computer": "cao01vw013.cao.ir",
                "user_id": "S-1-5-21-1793179736-1175893981-2474273398-13753",
            }
        },
    }
    multi = run_adaptive_pipeline_sync(seed, related_candidates=[sibling])
    assert multi.report.to_dict()["related_alerts"] is not None


def test_empty_evidence_statuses_are_explicit():
    alert = {"id": "empty", "severity": "low", "title": "empty", "llm_payload": {}}
    result = run_adaptive_pipeline_sync(alert)
    statuses = {s["status"] for s in result.report.investigation_steps}
    # Empty evidence yields not_available / skipped-like statuses, not fabricated completed findings for host ops
    assert "not_available" in statuses or result.report.limitations
