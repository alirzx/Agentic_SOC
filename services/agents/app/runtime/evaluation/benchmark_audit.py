"""Benchmark leakage audit — Existing SOC proxy vs ground truth (Phase 8.6).

The synthetic eval substrate (`synthetic_incidents.json`) was built for playbook /
completeness self-consistency gates, not as an independent Existing SOC baseline.
`existing_snapshot_from_case` copies label fields that `ground_truth_from_case`
also uses, producing tautological Existing scores (~1.0) that must NOT drive
agent optimization or production-readiness decisions.
"""

from __future__ import annotations

from typing import Any

# Fields used to build GroundTruth from a case row (see dataset.ground_truth_from_case).
_GROUND_TRUTH_FIELD_SOURCES: dict[str, list[str]] = {
    "classification": ["classification", "response_class"],
    "severity": ["severity"],
    "mitre_techniques": ["expected_techniques", "mitre_techniques"],
    "expected_actions": ["expected_actions", "response_class"],
    "risk_score": ["risk_score"],
    "iocs": ["iocs"],
}

# Fields copied into existing_snapshot_from_case.
_EXISTING_PROXY_FIELDS: dict[str, list[str]] = {
    "classification": ["response_class", "fusion_decision"],
    "severity": ["severity"],
    "mitre_techniques": ["expected_techniques"],
    "recommended_actions": ["response_class"],
    "risk_score": ["risk_score"],
    "iocs": ["src_ip", "domain", "file_hash", "telemetry"],
}


def shared_label_fields() -> list[str]:
    """Ground-truth axes that Existing proxy reads from the same case labels."""
    shared: list[str] = []
    if set(_GROUND_TRUTH_FIELD_SOURCES["classification"]) & set(_EXISTING_PROXY_FIELDS["classification"]):
        shared.append("classification←response_class")
    if "severity" in _GROUND_TRUTH_FIELD_SOURCES["severity"]:
        shared.append("severity←severity")
    if set(_GROUND_TRUTH_FIELD_SOURCES["mitre_techniques"]) & set(_EXISTING_PROXY_FIELDS["mitre_techniques"]):
        shared.append("mitre←expected_techniques")
    if "response_class" in _GROUND_TRUTH_FIELD_SOURCES["expected_actions"]:
        shared.append("actions←response_class")
    return shared


def audit_case_leakage(case: dict[str, Any]) -> dict[str, Any]:
    """Per-case audit: is Existing score tautological vs ground truth?"""
    gt_classification = case.get("classification") or case.get("response_class") or ""
    existing_classification = case.get("response_class") or case.get("fusion_decision") or ""
    gt_mitre = set(case.get("expected_techniques") or case.get("mitre_techniques") or [])
    existing_mitre = set(case.get("expected_techniques") or [])
    classification_tautology = (
        str(gt_classification).strip().lower() == str(existing_classification).strip().lower()
        and bool(gt_classification)
    )
    severity_tautology = bool(case.get("severity"))
    mitre_tautology = gt_mitre == existing_mitre and bool(gt_mitre)
    actions_tautology = bool(case.get("response_class"))
    tautological_axes = []
    if classification_tautology:
        tautological_axes.append("classification")
    if severity_tautology:
        tautological_axes.append("severity")
    if mitre_tautology:
        tautological_axes.append("mitre")
    if actions_tautology:
        tautological_axes.append("actions")
    leakage = len(tautological_axes) >= 3
    return {
        "leakage_detected": leakage,
        "tautological_axes": tautological_axes,
        "shared_fields": shared_label_fields(),
        "interpretation": (
            "SUBSTRATE_SELF_CONSISTENCY_NOT_EXISTING_SOC"
            if leakage
            else "PARTIAL_LABEL_OVERLAP"
        ),
    }


def audit_dataset(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Dataset-level leakage summary."""
    if not cases:
        return {"leakage_rate": 0.0, "existing_score_valid": False, "cases": 0}
    leaked = sum(1 for c in cases if audit_case_leakage(c)["leakage_detected"])
    rate = leaked / len(cases)
    return {
        "cases": len(cases),
        "leakage_cases": leaked,
        "leakage_rate": rate,
        "existing_score_valid": rate < 0.05,
        "shared_fields": shared_label_fields(),
        "interpretation": (
            "SUBSTRATE_SELF_CONSISTENCY_NOT_EXISTING_SOC"
            if rate >= 0.95
            else "MIXED_VALIDITY"
        ),
        "valid_comparison_baselines": ["heuristic_agentic", "llm_agentic"],
        "invalid_comparison_baselines": ["existing_substrate_proxy"] if rate >= 0.95 else [],
        "recommendation": (
            "Do not use existing_score or delta_vs_existing for agent optimization. "
            "Compare heuristic_agentic and llm_agentic against ground truth only."
            if rate >= 0.95
            else "Review per-case audit before using existing_score."
        ),
    }
