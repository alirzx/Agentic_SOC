"""Existing SOC vs Agentic SOC comparison (Phase 7). Never mutates Case."""

from __future__ import annotations

from typing import Any


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]


def build_comparison(
    *,
    case_id: str,
    existing: dict[str, Any],
    agentic: dict[str, Any],
) -> dict[str, Any]:
    """Compare production vs shadow decisions. Never mutates Cases/alerts."""
    differences: list[str] = []
    categories: dict[str, list[str]] = {
        "disposition": [],
        "suppression": [],
        "correlation": [],
        "risk": [],
        "case_recommendation": [],
        "other": [],
    }
    ex_sev = str(existing.get("severity") or "")
    ag_sev = str(agentic.get("severity") or "")
    if ex_sev and ag_sev and ex_sev.lower() != ag_sev.lower():
        msg = f"severity {ex_sev} vs {ag_sev}"
        differences.append(msg)
        categories["other"].append(msg)
    ex_risk = existing.get("risk")
    ag_risk = agentic.get("riskScore")
    if ex_risk is not None and ag_risk is not None and float(ex_risk) != float(ag_risk):
        msg = f"risk {ex_risk} vs {ag_risk}"
        differences.append(msg)
        categories["risk"].append(msg)
    ex_disp = str(existing.get("disposition") or existing.get("classification") or "").lower()
    ag_disp = str(agentic.get("disposition") or agentic.get("classification") or "").lower()
    if ex_disp and ag_disp and ex_disp != ag_disp:
        msg = f"disposition {ex_disp} vs {ag_disp}"
        differences.append(msg)
        categories["disposition"].append(msg)
        if ex_disp in {"benign", "false_positive", "benign_true_positive"} and ag_disp in {
            "true_positive",
            "escalate",
            "likely_tp",
            "needs_review",
        }:
            categories["case_recommendation"].append("production_benign_shadow_candidate")
        if ex_disp in {"true_positive", "escalate", "likely_tp"} and ag_disp in {
            "benign",
            "false_positive",
            "benign_true_positive",
        }:
            categories["case_recommendation"].append("production_candidate_shadow_benign")
    ex_sup = bool(existing.get("suppressed"))
    ag_sup = bool(agentic.get("suppressed"))
    if ex_sup != ag_sup:
        msg = f"suppression {ex_sup} vs {ag_sup}"
        differences.append(msg)
        categories["suppression"].append(msg)
    if bool(existing.get("correlated")) != bool(agentic.get("correlated")):
        msg = "correlation membership diverged"
        differences.append(msg)
        categories["correlation"].append(msg)
    if agentic.get("privileged_account"):
        differences.append("Agentic SOC identified privileged account usage")
    if agentic.get("correlated"):
        differences.append("Agentic SOC correlated related activity")
    blob = " ".join(
        str(item)
        for item in (
            agentic.get("classification"),
            existing.get("classification"),
            *(_as_list(agentic.get("iocs"))),
            *(_as_list(existing.get("iocs"))),
        )
    ).lower()
    if "ldap" in blob:
        differences.append("Agentic SOC correlated LDAP activity")
    for field in ("classification", "confidence", "affectedAssets", "affectedUsers", "iocs", "mitreTechniques"):
        left = existing.get(field)
        right = agentic.get(field)
        if left and right and str(left) != str(right):
            differences.append(f"{field} diverged")
            categories["other"].append(f"{field} diverged")
    return {
        "caseId": case_id,
        "existing": existing,
        "agentic": agentic,
        "differences": differences,
        "differenceCategories": {k: v for k, v in categories.items() if v},
        "shadowSideEffects": {
            "createsCase": False,
            "appliesSuppression": False,
            "executesPlaybook": False,
        },
    }


def existing_from_fused(message: dict[str, Any]) -> dict[str, Any]:
    alert = message.get("alert") if isinstance(message.get("alert"), dict) else {}
    return {
        "severity": alert.get("severity"),
        "classification": message.get("fusion_decision"),
        "disposition": alert.get("disposition") or message.get("disposition"),
        "suppressed": bool(alert.get("__suppressed__") or message.get("suppressed")),
        "correlated": str(message.get("fusion_decision") or "").lower() == "correlated",
        "risk": alert.get("risk_score"),
        "confidence": message.get("confidence_score"),
        "affectedAssets": _as_list(alert.get("hostname")),
        "affectedUsers": _as_list(alert.get("username")),
        "iocs": [v for v in (alert.get("src_ip"), alert.get("domain"), alert.get("file_hash")) if v],
        "mitreTechniques": _as_list(alert.get("mitre_techniques")),
        "recommendedActions": [],
        "incidentId": message.get("incident_id"),
    }
