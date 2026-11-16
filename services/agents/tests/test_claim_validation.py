"""Evidence-to-Claim validation for investigator reports."""

from __future__ import annotations

from types import SimpleNamespace

from app.investigator.claim_validation import (
    EvidenceInventory,
    build_evidence_inventory,
    evaluate_claims,
    normalize_mitre_techniques,
    validate_and_repair_report,
)


def test_normalize_mitre_rewrites_uac_setuid_to_bypass():
    actual = normalize_mitre_techniques(["T1548.001", "T1068"], uac_context=True)
    assert actual == ["T1548.002"]


def test_normalize_mitre_preserves_setuid_outside_uac():
    actual = normalize_mitre_techniques(["T1548.001"], uac_context=False)
    assert actual == ["T1548.001"]


def test_evaluate_claims_marks_execution_missing_without_process():
    inventory = EvidenceInventory(
        linked_alert_count=1,
        has_registry_artefact=True,
        uac_context=True,
        has_process_evidence=False,
        has_integrity_evidence=False,
        has_host=False,
        similar_top_score=0.0,
        retrieved_history_candidates=4,
    )
    checks = {c.claim: c for c in evaluate_claims(inventory)}
    assert checks["Elevated process executed (UAC bypass succeeded)"].status == "missing"
    assert checks["Privilege escalation confirmed"].status == "missing"
    assert checks["All Windows endpoints affected (blast radius)"].status == "unsupported"
    assert checks["Attack campaign (multi-alert)"].status == "unsupported"
    assert checks["Meaningful historical case similarity"].status == "unsupported"


def test_validate_and_repair_softens_overclaims_and_fixes_mitre():
    state = SimpleNamespace(
        alert_summary="ESCU - Windows UAC Bypass Suspicious Escalation Behavior",
        raw_alert={"title": "UAC Bypass", "linked_alert_count": 1},
        context_bundle={
            "historical_similar_cases": [
                {"similarity_score": 0.0, "case_id": "a"},
                {"similarity_score": 0.0, "case_id": "b"},
                {"similarity_score": 0.0, "case_id": "c"},
                {"similarity_score": 0.0, "case_id": "d"},
            ],
            "case_model": "incident",
        },
        recon=SimpleNamespace(
            summary="Registry HKCU\\Software\\Classes\\ms-settings DelegateExecute",
            iocs=[],
            mitre_techniques=["T1548.001"],
            threat_actors=[],
        ),
        forensic=SimpleNamespace(
            summary="Registry artefacts under HKCU Software Classes",
            artefacts=["HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command"],
            timeline=[],
        ),
    )
    report = """# Incident Report

An attacker successfully exploited a UAC bypass for full system compromise.
Blast radius: All Windows endpoints in the environment are potentially affected.
MITRE: T1548.001 Abuse Elevation Control Mechanism: Setuid and Setgid
Total similar historical cases: 4 (top similarity = 0.00).
This intrusion campaign spans multiple stages.
"""
    result = validate_and_repair_report(report, state)
    body, _, appendix = result.report_md.partition("## Evidence-to-Claim Validation")
    assert "T1548.002" in body
    assert "T1548.001" not in body
    assert "Bypass User Account Control" in body
    assert "full system compromise" not in body.lower()
    assert "All Windows endpoints" not in body
    assert "scope of impact remains pending validation" in body.lower() or "Blast radius: Unknown" in body
    assert "No meaningful historical similarity" in body
    assert "security incident" in body.lower() or "intrusion incident" in body.lower()
    assert appendix
    assert "unsupported" in appendix
    assert result.mitre_rewrites == [("T1548.001", "T1548.002")]


def test_build_inventory_filters_similarity_floor():
    state = SimpleNamespace(
        alert_summary="UAC Bypass fodhelper",
        raw_alert={"affected_hosts": [], "linked_alert_count": 1},
        context_bundle={
            "historical_similar_cases": [
                {"similarity_score": 0.0},
                {"similarity_score": 0.4},
            ]
        },
        recon=SimpleNamespace(summary="DelegateExecute", iocs=[], mitre_techniques=[]),
        forensic=SimpleNamespace(summary="HKCU registry", artefacts=[], timeline=[]),
    )
    inventory = build_evidence_inventory(state)
    assert inventory.retrieved_history_candidates == 2
    assert inventory.similar_case_count == 1
    assert inventory.similar_top_score == 0.4
    assert inventory.uac_context is True
    assert inventory.case_model == "incident"
