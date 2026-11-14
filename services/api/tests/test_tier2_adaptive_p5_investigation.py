"""P5 mandatory gate — Adaptive Investigation and Reporting."""

from __future__ import annotations

from app.services.tier2_adaptive.engine import run_adaptive_pipeline_sync
from app.services.tier2_adaptive.entities import (
    extract_alert_entities,
    powershell_regression_alert,
)
from app.services.tier2_adaptive.investigation import execute_adaptive_investigation
from app.services.tier2_adaptive.profiles import select_investigation_profiles


def test_endpoint_investigation_without_ip():
    alert = powershell_regression_alert()
    result = run_adaptive_pipeline_sync(alert)
    assert result.entities.values("ip") == []
    assert "endpoint" in result.profiles.names
    assert result.report.final_assessment
    assert any(
        s["status"] in {"completed", "partial", "not_available", "no_results"}
        for s in result.report.investigation_steps
    )
    # Must not treat missing IP as failure
    assert not any(
        "ip" in (s.get("summary") or "").lower() and s.get("status") == "failed"
        for s in result.report.investigation_steps
    )


def test_network_investigation_without_hostname():
    alert = {
        "id": "net-1",
        "severity": "high",
        "security_domain": "network",
        "llm_payload": {"src_ip": "10.1.1.1", "dest_ip": "10.2.2.2"},
    }
    result = run_adaptive_pipeline_sync(alert)
    assert "network" in result.profiles.names
    assert result.entities.values("hostname") == []
    assert result.report.report_kind in {"standalone", "multi_alert"}


def test_identity_investigation_without_ip():
    alert = {
        "id": "id-1",
        "severity": "high",
        "security_domain": "identity",
        "llm_payload": {
            "alert_fields": {
                "user_id": "S-1-5-21-1-2-3-4",
                "username": "bob",
            }
        },
    }
    result = run_adaptive_pipeline_sync(alert)
    assert "identity" in result.profiles.names
    assert result.entities.values("ip") == []
    assert result.case_decision.action in {"create", "standalone", "review"}


def test_no_sibling_alert_still_reports():
    alert = powershell_regression_alert()
    result = run_adaptive_pipeline_sync(alert, related_candidates=[])
    assert result.related_alert_ids
    assert len(result.related_alert_ids) == 1  # seed only
    assert result.report.findings
    assert result.report.limitations


def test_unavailable_tools():
    alert = powershell_regression_alert()
    ents = extract_alert_entities(alert)
    profiles = select_investigation_profiles(alert, entities=ents)
    steps, report = execute_adaptive_investigation(
        alert=alert,
        entities=ents,
        profiles=profiles,
        unavailable_tools={"inspect_host", "query_edr_telemetry"},
    )
    host_steps = [s for s in steps if s.step_name == "inspect_host"]
    assert host_steps
    assert host_steps[0].status == "not_available"
    assert report.limitations


def test_partial_evidence():
    alert = {
        "id": "p1",
        "severity": "high",
        "security_domain": "endpoint",
        "llm_payload": {"alert_fields": {"Computer": "only-host.local"}},
    }
    result = run_adaptive_pipeline_sync(alert)
    statuses = {s["status"] for s in result.report.investigation_steps}
    assert "not_available" in statuses or "partial" in statuses or "completed" in statuses


def test_failed_steps_do_not_fabricate_findings():
    alert = powershell_regression_alert()
    result = run_adaptive_pipeline_sync(alert)
    for finding in result.report.findings:
        assert finding["assessment"] != "malicious"
        # Must not auto-conclude malice from rule alone
        if "Detection rule fired" in finding["title"]:
            assert finding["assessment"] == "informational"


def test_report_generation_structure():
    alert = powershell_regression_alert()
    result = run_adaptive_pipeline_sync(alert)
    report = result.report.to_dict()
    for key in (
        "alert_summary",
        "security_domain",
        "selected_profiles",
        "extracted_entities",
        "entity_provenance",
        "related_alerts",
        "correlation_results",
        "case_decision",
        "investigation_steps",
        "evidence",
        "findings",
        "confidence",
        "limitations",
        "recommendations",
        "timeline",
        "final_assessment",
    ):
        assert key in report


def test_powershell_regression_investigation():
    alert = powershell_regression_alert()
    result = run_adaptive_pipeline_sync(alert)
    assert "endpoint" in result.profiles.names
    hosts = result.entities.values("hostname")
    assert "cao01vw013.cao.ir" in hosts
    assert "sh2" in hosts
    assert "S-1-5-21-1793179736-1175893981-2474273398-13753" in result.entities.values(
        "user_sid"
    )
    assert result.entities.by_type("script_block")
    assert any("CL_Utility.ps1" in p for p in result.entities.values("file_path"))
    assert result.case_decision.action == "create"
    assert result.report.final_assessment in {
        "likely_benign_administrative",
        "insufficient_evidence",
        "informational_detection",
        "suspicious_activity_suspected",
    }
    # SH2 preserved separately in provenance
    fields = {e.source_field for e in result.entities.by_type("hostname")}
    assert "Computer" in fields
    assert "extracted_host" in fields


def test_retry_behavior_idempotent_decision():
    alert = powershell_regression_alert()
    r1 = run_adaptive_pipeline_sync(alert)
    r2 = run_adaptive_pipeline_sync(alert)
    assert r1.case_decision.idempotency_key == r2.case_decision.idempotency_key
    assert r1.case_decision.action == r2.case_decision.action


def test_single_and_multi_alert_reports():
    seed = powershell_regression_alert()
    sibling = {
        "id": "sib-1",
        "tenant_id": "t1",
        "rule_name": "Other",
        "event_time": "2026-11-14T15:20:00+0330",
        "llm_payload": {
            "alert_fields": {
                "Computer": "cao01vw013.cao.ir",
                "user_id": "S-1-5-21-1793179736-1175893981-2474273398-13753",
            }
        },
    }
    seed["tenant_id"] = "t1"
    seed["id"] = seed["alert_id"]
    single = run_adaptive_pipeline_sync(seed)
    multi = run_adaptive_pipeline_sync(seed, related_candidates=[sibling])
    assert single.report.report_kind == "standalone"
    assert multi.report.report_kind in {"standalone", "multi_alert"}
    # With strong host+SID, multi should see related
    if multi.correlation.results:
        assert any(r.decision in {"candidate", "eligible"} for r in multi.correlation.results)
