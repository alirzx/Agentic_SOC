"""Evidence-to-Claim validation for investigator reports.

Keeps ReportWriter from elevating registry/UAC *indicators* into confirmed
privilege escalation, persistence, lateral movement, or environment-wide
blast radius when the case evidence does not support those claims.

Also normalises known MITRE mis-maps (e.g. T1548.001 setuid/setgid used for
Windows UAC bypass — must be T1548.002).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

ClaimStatus = Literal["supported", "partial", "missing", "unsupported"]

_SIMILARITY_FLOOR = 0.25

_UAC_MARKERS = (
    "uac bypass",
    "user account control",
    "fodhelper",
    "computerdefaults",
    "sdclt",
    "eventvwr",
    "delegateexecute",
    "ms-settings",
    "hkcu\\software\\classes",
)

_PROCESS_EVIDENCE_MARKERS = (
    "process creation",
    "parent-child",
    "integrity level",
    "elevated process",
    "event id 4688",
    "sysmon 1",
)

_HOST_ENTITY_MARKERS = (
    "hostname",
    "host:",
    "affected host",
    "endpoint:",
    "dst_host",
    "src_host",
)


@dataclass(frozen=True)
class EvidenceInventory:
    """What the case actually has — not what the model knows about a technique."""

    linked_alert_count: int = 1
    has_host: bool = False
    has_user: bool = False
    has_ip: bool = False
    has_registry_artefact: bool = False
    has_process_evidence: bool = False
    has_integrity_evidence: bool = False
    has_confirmed_ioc: bool = False
    ioc_count: int = 0
    mitre_techniques: tuple[str, ...] = ()
    similar_case_count: int = 0
    similar_top_score: float = 0.0
    retrieved_history_candidates: int = 0
    uac_context: bool = False
    case_model: str = "incident"


@dataclass
class ClaimCheck:
    claim: str
    evidence: str
    status: ClaimStatus
    note: str = ""


@dataclass
class ValidationResult:
    inventory: EvidenceInventory
    checks: list[ClaimCheck] = field(default_factory=list)
    mitre_rewrites: list[tuple[str, str]] = field(default_factory=list)
    report_md: str = ""


def _blob(*parts: Any) -> str:
    return " ".join(str(p or "") for p in parts).lower()


def _has_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(m in text for m in markers)


def build_evidence_inventory(state: Any) -> EvidenceInventory:
    """Derive an evidence inventory from InvestigatorState (duck-typed)."""
    alert = getattr(state, "alert_summary", "") or ""
    recon = getattr(state, "recon", None)
    forensic = getattr(state, "forensic", None)
    raw = getattr(state, "raw_alert", None) or {}
    bundle = getattr(state, "context_bundle", None) or {}

    recon_summary = getattr(recon, "summary", "") if recon is not None else ""
    forensic_summary = getattr(forensic, "summary", "") if forensic is not None else ""
    artefacts = list(getattr(forensic, "artefacts", []) or []) if forensic is not None else []
    timeline = list(getattr(forensic, "timeline", []) or []) if forensic is not None else []
    iocs = list(getattr(recon, "iocs", []) or []) if recon is not None else []
    mitre = list(getattr(recon, "mitre_techniques", []) or []) if recon is not None else []

    text = _blob(
        alert,
        recon_summary,
        forensic_summary,
        " ".join(str(a) for a in artefacts),
        " ".join(str(t) for t in timeline),
        raw.get("title"),
        raw.get("search_name"),
    )

    hosts = raw.get("affected_hosts") or raw.get("hosts") or []
    users = raw.get("affected_users") or raw.get("users") or []
    ips = raw.get("affected_ips") or raw.get("ips") or []
    if isinstance(hosts, str):
        hosts = [hosts]
    if isinstance(users, str):
        users = [users]
    if isinstance(ips, str):
        ips = [ips]

    has_host = bool(hosts) or _has_any(text, _HOST_ENTITY_MARKERS)
    has_user = bool(users) or ("user" in text and "username" in text)
    has_ip = bool(ips)

    hist = []
    if isinstance(bundle, dict):
        hist = list(bundle.get("historical_similar_cases") or [])
    similar = [h for h in hist if float((h or {}).get("similarity_score") or 0.0) >= _SIMILARITY_FLOOR]
    top = max((float((h or {}).get("similarity_score") or 0.0) for h in hist), default=0.0)

    linked = 1
    if isinstance(raw, dict):
        for key in ("linked_alert_count", "alert_count"):
            try:
                linked = max(1, int(raw.get(key) or linked))
            except (TypeError, ValueError):
                pass
        alert_ids = raw.get("alert_ids") or raw.get("case_alert_ids")
        if isinstance(alert_ids, list) and alert_ids:
            linked = max(linked, len(alert_ids))

    case_model = "attack_campaign" if linked > 1 else "incident"
    if isinstance(bundle, dict) and bundle.get("case_model"):
        case_model = str(bundle.get("case_model"))

    confirmed_iocs = [
        i
        for i in iocs
        if isinstance(i, dict)
        and str(i.get("type") or "").lower() in {"hash", "ip", "domain", "url"}
        and str(i.get("value") or "").strip()
    ]

    return EvidenceInventory(
        linked_alert_count=linked,
        has_host=has_host,
        has_user=bool(users) or has_user,
        has_ip=has_ip,
        has_registry_artefact=_has_any(text, ("hkcu", "hklm", "registry", "delegateexecute")),
        has_process_evidence=_has_any(text, _PROCESS_EVIDENCE_MARKERS),
        has_integrity_evidence="integrity level" in text or "high integrity" in text,
        has_confirmed_ioc=bool(confirmed_iocs),
        ioc_count=len(confirmed_iocs),
        mitre_techniques=tuple(str(t) for t in mitre),
        similar_case_count=len(similar),
        similar_top_score=float(top),
        retrieved_history_candidates=len(hist),
        uac_context=_has_any(text, _UAC_MARKERS),
        case_model=case_model,
    )


def normalize_mitre_techniques(techniques: list[str], *, uac_context: bool) -> list[str]:
    """Rewrite known Windows/UAC mis-maps; de-dupe preserving order."""
    out: list[str] = []
    for raw in techniques:
        tech = str(raw or "").strip().upper()
        if not tech:
            continue
        if tech == "T1548.001" and uac_context:
            tech = "T1548.002"
        if tech == "T1068" and uac_context:
            # Prefer UAC-specific technique; do not keep T1068 for registry UAC
            # indicators without separate exploit evidence.
            tech = "T1548.002"
        if tech not in out:
            out.append(tech)
    if uac_context and "T1548.002" not in out and any("UAC" in t or "1548" in t for t in techniques):
        out.append("T1548.002")
    return out


def evaluate_claims(inventory: EvidenceInventory) -> list[ClaimCheck]:
    """Core Evidence-to-Claim matrix for SOC report honesty."""
    checks: list[ClaimCheck] = []

    if inventory.uac_context and inventory.has_registry_artefact:
        checks.append(
            ClaimCheck(
                claim="UAC bypass *behavior indicator* detected",
                evidence="Registry artefacts / ESCU UAC rule",
                status="supported",
            )
        )
    elif inventory.uac_context:
        checks.append(
            ClaimCheck(
                claim="UAC bypass *behavior indicator* detected",
                evidence="Rule title / narrative only",
                status="partial",
                note="Registry value data not present in case payload",
            )
        )

    checks.append(
        ClaimCheck(
            claim="Elevated process executed (UAC bypass succeeded)",
            evidence="Process creation + integrity level",
            status="supported" if inventory.has_process_evidence and inventory.has_integrity_evidence else "missing",
        )
    )
    checks.append(
        ClaimCheck(
            claim="Privilege escalation confirmed",
            evidence="Elevated execution evidence",
            status="supported" if inventory.has_process_evidence and inventory.has_integrity_evidence else "missing",
        )
    )
    checks.append(
        ClaimCheck(
            claim="Persistence established",
            evidence="Verified persistence mechanism + recurrence",
            status="missing",
            note="HKCU Classes paths are indicators, not confirmed persistence",
        )
    )
    checks.append(
        ClaimCheck(
            claim="Lateral movement / data exfiltration occurred",
            evidence="Network or multi-host process evidence",
            status="missing",
        )
    )
    checks.append(
        ClaimCheck(
            claim="All Windows endpoints affected (blast radius)",
            evidence="Asset-level host inventory",
            status="unsupported" if not inventory.has_host else "partial",
            note="Scope unknown until host/user identified" if not inventory.has_host else "",
        )
    )
    checks.append(
        ClaimCheck(
            claim="Attack campaign (multi-alert)",
            evidence=f"Linked alerts={inventory.linked_alert_count}; strong entities",
            status="supported"
            if inventory.linked_alert_count > 1 and (inventory.has_host or inventory.has_ip or inventory.has_user)
            else "unsupported",
            note="Single alert without entities → incident case, not campaign",
        )
    )
    if inventory.retrieved_history_candidates and inventory.similar_top_score < _SIMILARITY_FLOOR:
        checks.append(
            ClaimCheck(
                claim="Meaningful historical case similarity",
                evidence=f"Retrieved {inventory.retrieved_history_candidates}; top={inventory.similar_top_score:.2f}",
                status="unsupported",
                note="Candidates with similarity 0.00 are not similar cases",
            )
        )
    elif inventory.similar_case_count:
        checks.append(
            ClaimCheck(
                claim="Meaningful historical case similarity",
                evidence=f"{inventory.similar_case_count} above floor {_SIMILARITY_FLOOR}",
                status="supported",
            )
        )
    return checks


def _rewrite_mitre_in_markdown(md: str, *, uac_context: bool) -> tuple[str, list[tuple[str, str]]]:
    rewrites: list[tuple[str, str]] = []
    out = md
    if uac_context and "T1548.001" in out:
        out = out.replace("T1548.001", "T1548.002")
        # Fix the common wrong technique name if present.
        out = out.replace(
            "Abuse Elevation Control Mechanism: Setuid and Setgid",
            "Abuse Elevation Control Mechanism: Bypass User Account Control",
        )
        out = out.replace("Setuid and Setgid", "Bypass User Account Control")
        rewrites.append(("T1548.001", "T1548.002"))
    return out, rewrites


def _soften_overclaims(md: str, inventory: EvidenceInventory) -> str:
    out = md
    if not inventory.has_host:
        out = re.sub(
            r"(?i)all windows endpoints[^.]*\.",
            "The affected host has not been identified from available evidence; "
            "scope of impact remains pending validation. ",
            out,
        )
        out = re.sub(
            r"(?i)blast radius:\s*[^\n]+",
            "Blast radius: Unknown — no host/user entity in case evidence.",
            out,
        )
    if not inventory.has_process_evidence:
        out = re.sub(
            r"(?i)successful(ly)? (exploitation|privilege escalation|uac bypass)",
            "suspected UAC bypass indicator (execution unconfirmed)",
            out,
        )
        out = re.sub(
            r"(?i)full system compromise",
            "potential system compromise (unconfirmed)",
            out,
        )
    if inventory.linked_alert_count <= 1:
        out = re.sub(
            r"(?i)attack campaign",
            "security incident",
            out,
        )
        out = re.sub(
            r"(?i)intrusion campaign",
            "intrusion incident",
            out,
        )
    if inventory.similar_top_score < _SIMILARITY_FLOOR:
        out = re.sub(
            r"(?i)total similar historical cases:\s*\d+[^.]*\.",
            "No meaningful historical similarity found (retrieved candidates scored below threshold). ",
            out,
        )
        out = re.sub(
            r"(?i)\d+\s+similar cases",
            "0 similar cases (above threshold)",
            out,
        )
    return out


def _appendix(checks: list[ClaimCheck], inventory: EvidenceInventory) -> str:
    rows = [
        "| Claim | Evidence | Status | Note |",
        "|-------|----------|--------|------|",
    ]
    for c in checks:
        note = (c.note or "").replace("|", "/")
        rows.append(f"| {c.claim} | {c.evidence} | {c.status} | {note} |")
    stages = [
        "",
        "### Investigation stage gates",
        "",
        "| Stage | Status |",
        "|-------|--------|",
        f"| UAC_BYPASS_INDICATOR_DETECTED | "
        f"{'yes' if inventory.uac_context else 'n/a'} |",
        f"| UAC_BYPASS_EXECUTION_CONFIRMED | "
        f"{'yes' if inventory.has_process_evidence else 'no'} |",
        f"| PRIVILEGE_ESCALATION_CONFIRMED | "
        f"{'yes' if inventory.has_process_evidence and inventory.has_integrity_evidence else 'no'} |",
        "",
        "### Confidence breakdown (qualitative)",
        "",
        "| Axis | Assessment |",
        "|------|------------|",
        f"| Detection confidence | "
        f"{'high' if inventory.uac_context or inventory.has_registry_artefact else 'medium'} |",
        f"| Technique confidence | "
        f"{'high' if inventory.uac_context and inventory.has_registry_artefact else 'medium'} |",
        f"| Execution confidence | "
        f"{'high' if inventory.has_process_evidence else 'low'} |",
        f"| Compromise confidence | "
        f"{'high' if inventory.has_process_evidence and inventory.has_integrity_evidence else 'low'} |",
        "",
        f"Case model: **{inventory.case_model}** · linked alerts: **{inventory.linked_alert_count}** · "
        f"historical similar (≥{_SIMILARITY_FLOOR:.2f}): **{inventory.similar_case_count}** "
        f"(retrieved candidates: {inventory.retrieved_history_candidates}, "
        f"top={inventory.similar_top_score:.2f}).",
    ]
    return (
        "\n\n## Evidence-to-Claim Validation\n\n"
        + "\n".join(rows)
        + "\n"
        + "\n".join(stages)
        + "\n"
    )


def validate_and_repair_report(report_md: str, state: Any) -> ValidationResult:
    """Post-process LLM report: MITRE fixups, soften overclaims, append matrix."""
    inventory = build_evidence_inventory(state)
    checks = evaluate_claims(inventory)
    md, rewrites = _rewrite_mitre_in_markdown(report_md or "", uac_context=inventory.uac_context)
    md = _soften_overclaims(md, inventory)
    if "## Evidence-to-Claim Validation" not in md:
        md = md.rstrip() + _appendix(checks, inventory)
    return ValidationResult(
        inventory=inventory,
        checks=checks,
        mitre_rewrites=rewrites,
        report_md=md,
    )


def report_writer_guardrails(inventory: EvidenceInventory) -> str:
    """Extra system/human instructions injected into ReportWriter."""
    lines = [
        "EVIDENCE GUARDRAILS (mandatory):",
        "1. Separate Facts (from case data) vs Assessment (inference) vs Recommendations.",
        "2. Never claim successful privilege escalation, persistence, lateral movement,",
        "   or data exfiltration without process/network evidence in the case payload.",
        "3. Registry Open\\command / DelegateExecute artefacts are UAC-bypass INDICATORS,",
        "   not proof of elevated execution.",
        "4. Windows binaries fodhelper.exe / computerdefaults.exe / sdclt.exe are LOLbins,",
        "   not confirmed IOCs by path alone — label as observables unless hashed/malicious.",
        "5. If no hostname/user/IP is present, blast radius = Unknown (not all Windows endpoints).",
        "6. MITRE: Windows UAC bypass maps to T1548.002 — NEVER T1548.001 (setuid/setgid).",
        "7. Do not call a single-alert case an attack campaign without multi-alert evidence.",
        "8. Historical similarity: only cite cases with similarity ≥ 0.25; if top=0.00 write",
        "   'No meaningful historical similarity found.'",
        "9. Response plan actions are Recommended (not activated/executed) unless evidence says so.",
        "10. Include confidence breakdown: Detection / Technique / Execution / Compromise.",
        f"Case model hint: {inventory.case_model}; linked_alerts={inventory.linked_alert_count}; "
        f"has_host={inventory.has_host}; process_evidence={inventory.has_process_evidence}; "
        f"similar_above_floor={inventory.similar_case_count}; top_sim={inventory.similar_top_score:.2f}.",
    ]
    return "\n".join(lines)
