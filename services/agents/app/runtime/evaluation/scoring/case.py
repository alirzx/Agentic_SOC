"""Score a single case evaluation (Phase 8)."""

from __future__ import annotations

from typing import Any

from ..contracts import AgenticCaseEvaluation, GroundTruth, SocResultSnapshot
from .actions import score_actions
from .classification import score_classification
from .correlation import score_correlation
from .evidence import score_evidence, score_hallucination
from .investigation import score_investigation
from .ioc import score_iocs
from .mitre import score_mitre
from .risk import score_risk_distance
from .severity import score_severity


def score_case(
    *,
    evaluation_run_id: str,
    case_id: str,
    tenant_id: str,
    ground_truth: GroundTruth,
    existing: SocResultSnapshot,
    agentic: SocResultSnapshot,
    case_payload: dict[str, Any],
) -> AgenticCaseEvaluation:
    cls_existing = score_classification(ground_truth.classification, existing.classification)
    cls_agentic = score_classification(ground_truth.classification, agentic.classification)
    sev_existing = score_severity(ground_truth.severity, existing.severity)
    sev_agentic = score_severity(ground_truth.severity, agentic.severity)
    mitre = score_mitre(ground_truth.mitre_techniques, agentic.mitre_techniques, existing.mitre_techniques)
    ioc = score_iocs(ground_truth.iocs, agentic.iocs, existing.iocs)
    corr = score_correlation(ground_truth.expected_correlation_group, agentic.correlation_groups)
    evidence_metrics = score_evidence(agentic.claims, agentic.evidence, case_payload.get("telemetry"))
    hallucination = score_hallucination(agentic.claims, agentic.evidence)
    investigation = score_investigation(case_payload, agentic.investigation_stages)
    actions = score_actions(ground_truth.expected_actions, agentic.recommended_actions, shadow_mode=True)
    risk_metric = score_risk_distance(ground_truth.risk_score, agentic.risk_score)
    existing_overall = (cls_existing + sev_existing + mitre["existing_f1"]) / 3
    agentic_overall = (
        cls_agentic
        + sev_agentic
        + mitre["agentic_f1"]
        + ioc["agentic_f1"]
        + corr["f1"]
        + evidence_metrics["evidence_support_rate"]
        + hallucination
        + investigation
        + float(actions["action_score"])
        + risk_metric
    ) / 9
    analyst_review = (
        agentic.pipeline_degraded
        or evidence_metrics["unsupported_claim_rate"] > 0.05
        or float(actions["dangerous_action_rate"]) > 0
        or cls_agentic < 0.5
    )
    return AgenticCaseEvaluation(
        evaluation_run_id=evaluation_run_id,
        case_id=case_id,
        tenant_id=tenant_id,
        existing_result=existing,
        agentic_result=agentic,
        ground_truth=ground_truth,
        classification_score=cls_agentic,
        severity_score=sev_agentic,
        risk_score_metric=risk_metric,
        mitre_score=mitre["agentic_f1"],
        ioc_score=ioc["agentic_f1"],
        correlation_score=corr["f1"],
        evidence_score=evidence_metrics["evidence_support_rate"],
        investigation_score=investigation,
        hallucination_score=hallucination,
        action_score=float(actions["action_score"]),
        overall_score=agentic_overall,
        analyst_review_required=analyst_review,
        metric_details={
            "classification": {"agentic": cls_agentic, "existing": cls_existing},
            "severity": {"agentic": sev_agentic, "existing": sev_existing},
            "mitre": mitre,
            "ioc": ioc,
            "correlation": corr,
            "evidence_support_rate": evidence_metrics["evidence_support_rate"],
            "unsupported_claim_rate": evidence_metrics["unsupported_claim_rate"],
            "dangerous_action_rate": actions["dangerous_action_rate"],
            "production_action_leakage": actions["production_action_leakage"],
            "existing_scores": {"overall": existing_overall},
            "delta_vs_existing": agentic_overall - existing_overall,
        },
    )
