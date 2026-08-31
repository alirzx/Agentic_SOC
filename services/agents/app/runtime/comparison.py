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
    differences: list[str] = []
    ex_sev = str(existing.get("severity") or "")
    ag_sev = str(agentic.get("severity") or "")
    if ex_sev and ag_sev and ex_sev.lower() != ag_sev.lower():
        differences.append(f"severity {ex_sev} vs {ag_sev}")
    ex_risk = existing.get("risk")
    ag_risk = agentic.get("riskScore")
    if ex_risk is not None and ag_risk is not None and float(ex_risk) != float(ag_risk):
        differences.append(f"risk {ex_risk} vs {ag_risk}")
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
    return {
        "caseId": case_id,
        "existing": existing,
        "agentic": agentic,
        "differences": differences,
    }


def existing_from_fused(message: dict[str, Any]) -> dict[str, Any]:
    alert = message.get("alert") if isinstance(message.get("alert"), dict) else {}
    return {
        "severity": alert.get("severity"),
        "classification": message.get("fusion_decision"),
        "risk": alert.get("risk_score"),
        "confidence": message.get("confidence_score"),
        "affectedAssets": _as_list(alert.get("hostname")),
        "affectedUsers": _as_list(alert.get("username")),
        "iocs": [v for v in (alert.get("src_ip"), alert.get("domain"), alert.get("file_hash")) if v],
        "mitreTechniques": _as_list(alert.get("mitre_techniques")),
        "recommendedActions": [],
    }
