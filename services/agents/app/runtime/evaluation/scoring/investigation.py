"""Investigation stage rubric (Phase 8). Only score stages with telemetry hints."""

from __future__ import annotations

from typing import Any

INVESTIGATION_STAGES = [
    "asset_identification",
    "user_identification",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "credential_access",
    "lateral_movement",
    "c2",
    "impact",
]

STAGE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "asset_identification": ("hostname", "host", "asset", "computer"),
    "user_identification": ("user", "account", "username", "userid"),
    "initial_access": ("phishing", "exploit", "initial", "t1566", "t1190"),
    "execution": ("cmd.exe", "powershell", "execution", "t1059"),
    "persistence": ("persist", "registry", "scheduled", "t1547"),
    "privilege_escalation": ("privilege", "sudo", "uac", "t1068"),
    "credential_access": ("credential", "lsass", "t1003", "dump"),
    "lateral_movement": ("lateral", "rdp", "smb", "t1021"),
    "c2": ("c2", "beacon", "command and control", "t1071"),
    "impact": ("ransom", "encrypt", "exfil", "impact", "t1486"),
}


def stages_available(case_payload: dict[str, Any]) -> set[str]:
    blob = " ".join(
        str(case_payload.get("description", ""))
        + str(case_payload.get("title", ""))
        + str(case_payload.get("telemetry", ""))
    ).lower()
    available: set[str] = set()
    for stage, keywords in STAGE_KEYWORDS.items():
        if any(kw in blob for kw in keywords):
            available.add(stage)
    return available


def score_investigation(
    case_payload: dict[str, Any],
    agentic_stages: dict[str, bool],
) -> float:
    available = stages_available(case_payload)
    if not available:
        return 1.0
    scored = 0.0
    for stage in available:
        if agentic_stages.get(stage):
            scored += 1.0
    return scored / len(available)
