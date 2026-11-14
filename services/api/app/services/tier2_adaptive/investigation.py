"""P5 — Adaptive investigation execution and structured report generation.

Missing data is statused as skipped / not_available / no_results — never treated
as execution failure or as evidence of benign activity. Findings are never fabricated.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.services.tier2_adaptive.case_policy import CaseDecision
from app.services.tier2_adaptive.correlation import CorrelationHistoryEntry
from app.services.tier2_adaptive.entities import EntityExtractionResult
from app.services.tier2_adaptive.profiles import ProfileSelection

INVESTIGATION_VERSION = "invest:v1"

StepStatus = str  # completed | partial | skipped | failed | not_available | no_results


@dataclass
class InvestigationStepResult:
    step_name: str
    profile: str
    status: StepStatus
    summary: str
    evidence: list[str] = field(default_factory=list)
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationFinding:
    title: str
    assessment: str  # suspicious | benign_admin | insufficient_evidence | informational
    confidence: float
    evidence_refs: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationReport:
    alert_summary: dict[str, Any]
    security_domain: list[str]
    selected_profiles: list[str]
    extracted_entities: list[dict[str, Any]]
    entity_provenance: list[dict[str, Any]]
    related_alerts: list[dict[str, Any]]
    correlation_results: list[dict[str, Any]]
    case_decision: dict[str, Any]
    investigation_steps: list[dict[str, Any]]
    evidence: list[str]
    findings: list[dict[str, Any]]
    confidence: float
    limitations: list[str]
    recommendations: list[str]
    timeline: list[dict[str, Any]]
    final_assessment: str
    report_kind: str  # standalone | multi_alert
    algorithm_version: str = INVESTIGATION_VERSION
    generated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if not payload.get("generated_at"):
            payload["generated_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        return payload


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _run_step(
    *,
    step_name: str,
    profile: str,
    required_types: tuple[str, ...],
    entities: EntityExtractionResult,
    builder: Any = None,
) -> InvestigationStepResult:
    """Execute one investigation step against available local evidence only."""
    present = [t for t in required_types if entities.has_type(t)]
    missing = [t for t in required_types if not entities.has_type(t)]
    if not required_types:
        return InvestigationStepResult(
            step_name=step_name,
            profile=profile,
            status="not_available",
            summary="No local evidence contract for this step",
            detail="External tool not invoked in preflight scope",
        )
    if not present:
        return InvestigationStepResult(
            step_name=step_name,
            profile=profile,
            status="not_available",
            summary=f"Required entities missing: {', '.join(missing)}",
            detail="Unavailable data source — not treated as benign",
        )
    evidence: list[str] = []
    for t in present:
        for val in entities.values(t)[:5]:
            evidence.append(f"{t}={val}")
    status: StepStatus = "completed" if not missing else "partial"
    summary = f"Observed {', '.join(present)}"
    if missing:
        summary += f"; unavailable: {', '.join(missing)}"
    if builder:
        try:
            extra = builder(entities)
            if extra is None:
                status = "no_results"
                summary = "No results from local evidence scan"
            elif isinstance(extra, dict):
                evidence.extend(str(x) for x in extra.get("evidence", [])[:8])
                if extra.get("status"):
                    status = str(extra["status"])
                if extra.get("summary"):
                    summary = str(extra["summary"])
        except Exception as exc:  # noqa: BLE001
            return InvestigationStepResult(
                step_name=step_name,
                profile=profile,
                status="failed",
                summary=f"Step failed: {type(exc).__name__}",
                evidence=evidence,
            )
    return InvestigationStepResult(
        step_name=step_name,
        profile=profile,
        status=status,
        summary=summary,
        evidence=evidence,
    )


# Map profile operations → required entity types for local evidence steps.
_OP_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "inspect_host": ("hostname", "endpoint"),
    "inspect_user_account": ("username", "user_sid"),
    "inspect_process_tree": ("process_name", "process_id", "parent_process"),
    "inspect_command_line": ("script_block",),
    "inspect_script_block": ("script_block",),
    "inspect_file_path_hash": ("file_path", "file_hash"),
    "inspect_parent_child": ("process_name", "parent_process"),
    "build_endpoint_timeline": ("hostname", "source_event_id"),
    "find_related_endpoint_alerts": ("hostname", "username", "user_sid"),
    "query_edr_telemetry": (),  # external — not_available unless wired
    "inspect_src_dest_ip": ("ip",),
    "inspect_ports_protocols": ("network_service",),
    "inspect_dns": ("domain",),
    "inspect_connection_history": ("ip",),
    "find_related_network_alerts": ("ip",),
    "analyze_traffic_patterns": ("ip",),
    "analyze_network_behavior": ("ip",),
    "inspect_user_sid": ("user_sid", "username"),
    "inspect_authentication": ("username", "user_sid"),
    "inspect_login_patterns": ("username",),
    "inspect_privilege_changes": ("username", "user_sid"),
    "inspect_failed_auth": ("username",),
    "inspect_account_anomalies": ("username", "user_sid"),
    "find_related_identity_alerts": ("username", "user_sid"),
    "inspect_firewall_device": ("hostname", "ip"),
    "inspect_src_dest": ("ip",),
    "inspect_rule_policy": (),
    "inspect_allow_deny": (),
    "find_related_network_events": ("ip",),
    "analyze_traffic_anomalies": ("ip",),
    "inspect_url_domain": ("url", "domain"),
    "inspect_http_requests": ("url",),
    "inspect_web_server": ("hostname",),
    "inspect_request_patterns": ("url",),
    "inspect_status_codes": (),
    "find_related_web_alerts": ("url", "domain"),
    "inspect_sender_recipient": ("email_sender", "email_recipient", "email"),
    "inspect_message_ids": (),
    "inspect_subject": (),
    "inspect_attachments": ("file_hash", "file_path"),
    "inspect_urls": ("url",),
    "inspect_file_hashes": ("file_hash",),
    "find_related_email_activity": ("email_sender", "email_recipient"),
    "inspect_cloud_account": ("account_id",),
    "inspect_cloud_resource": ("cloud_resource",),
    "inspect_cloud_identity": ("username", "account_id"),
    "inspect_api_activity": (),
    "inspect_permission_changes": ("account_id",),
    "inspect_audit_events": (),
    "inspect_hash": ("file_hash",),
    "inspect_file_metadata": ("file_path", "file_hash"),
    "inspect_behavioral_indicators": ("script_block", "process_name"),
    "inspect_related_hosts": ("hostname",),
    "inspect_detection_history": (),
    "query_sandbox_results": (),
}


def execute_adaptive_investigation(
    *,
    alert: dict[str, Any],
    entities: EntityExtractionResult,
    profiles: ProfileSelection,
    correlation: CorrelationHistoryEntry | None = None,
    case_decision: CaseDecision | None = None,
    related_alerts: list[dict[str, Any]] | None = None,
    unavailable_tools: set[str] | None = None,
) -> tuple[list[InvestigationStepResult], InvestigationReport]:
    """Run profile-scoped investigation steps and build a structured report."""
    unavailable = unavailable_tools or set()
    steps: list[InvestigationStepResult] = []
    for profile in profiles.profiles:
        for op in profile.operations:
            if op in unavailable or op in {
                "query_edr_telemetry",
                "query_sandbox_results",
                "inspect_api_activity",
                "inspect_detection_history",
                "inspect_message_ids",
                "inspect_subject",
                "inspect_status_codes",
                "inspect_rule_policy",
                "inspect_allow_deny",
                "inspect_audit_events",
            }:
                steps.append(
                    InvestigationStepResult(
                        step_name=op,
                        profile=profile.name,
                        status="not_available",
                        summary="External/tool data source not available in this run",
                        detail="Not treated as benign absence",
                    )
                )
                continue
            req = _OP_REQUIREMENTS.get(op, ())
            steps.append(
                _run_step(
                    step_name=op,
                    profile=profile.name,
                    required_types=req,
                    entities=entities,
                )
            )

    findings = _derive_findings(alert, entities, steps)
    limitations = _derive_limitations(steps, entities)
    recommendations = _derive_recommendations(findings, case_decision)
    timeline = _build_timeline(alert, entities, related_alerts or [])
    evidence = []
    for step in steps:
        evidence.extend(step.evidence[:3])
    # Dedup evidence
    evidence = list(dict.fromkeys(evidence))[:40]

    related = related_alerts or []
    report_kind = "multi_alert" if len(related) > 1 else "standalone"
    conf = _overall_confidence(steps, findings)
    final = _final_assessment(findings)

    report = InvestigationReport(
        alert_summary={
            "id": str(alert.get("id") or alert.get("alert_id") or ""),
            "title": alert.get("title") or alert.get("rule_name"),
            "severity": alert.get("severity"),
            "rule_name": alert.get("rule_name"),
            "detection_type": alert.get("detection_type"),
        },
        security_domain=list(profiles.security_domains),
        selected_profiles=list(profiles.names),
        extracted_entities=[
            {"entity_type": e.entity_type, "normalized_value": e.normalized_value}
            for e in entities.entities
        ],
        entity_provenance=[e.to_dict() for e in entities.entities],
        related_alerts=[
            {
                "id": str(a.get("id") or ""),
                "title": a.get("title"),
                "severity": a.get("severity"),
            }
            for a in related
        ],
        correlation_results=[r.to_dict() for r in (correlation.results if correlation else [])],
        case_decision=case_decision.to_dict() if case_decision else {},
        investigation_steps=[s.to_dict() for s in steps],
        evidence=evidence,
        findings=[f.to_dict() for f in findings],
        confidence=conf,
        limitations=limitations,
        recommendations=recommendations,
        timeline=timeline,
        final_assessment=final,
        report_kind=report_kind,
        generated_at=_now(),
    )
    return steps, report


def _derive_findings(
    alert: dict[str, Any],
    entities: EntityExtractionResult,
    steps: list[InvestigationStepResult],
) -> list[InvestigationFinding]:
    findings: list[InvestigationFinding] = []
    # Never conclude malicious solely because a detection rule fired.
    findings.append(
        InvestigationFinding(
            title="Detection rule fired",
            assessment="informational",
            confidence=0.9,
            evidence_refs=[str(alert.get("rule_name") or alert.get("title") or "")],
            notes="Rule match is a starting point, not proof of malicious activity",
        )
    )
    if entities.has_type("script_block"):
        script = entities.values("script_block")[0]
        # Heuristic: Get-FreeSpace / SDIAG paths often indicate Windows troubleshooting.
        lower = script.lower()
        path_vals = " ".join(entities.values("file_path")).lower()
        if "get-freespace" in lower or "sdiag_" in path_vals or "cl_utility.ps1" in path_vals:
            findings.append(
                InvestigationFinding(
                    title="PowerShell ScriptBlock resembles diagnostic utility",
                    assessment="benign_admin",
                    confidence=0.55,
                    evidence_refs=entities.values("script_block")[:1]
                    + entities.values("file_path")[:1],
                    notes="Insufficient to prove malice; may be administrative troubleshooting",
                )
            )
        else:
            findings.append(
                InvestigationFinding(
                    title="PowerShell ScriptBlock present",
                    assessment="insufficient_evidence",
                    confidence=0.4,
                    evidence_refs=entities.values("script_block")[:1],
                    notes="Script content requires analyst review; not auto-classified malicious",
                )
            )
    if entities.has_type("hostname") and entities.has_type("user_sid"):
        findings.append(
            InvestigationFinding(
                title="Host and user identity available for correlation",
                assessment="informational",
                confidence=0.8,
                evidence_refs=entities.values("hostname")[:1] + entities.values("user_sid")[:1],
            )
        )
    completed = [s for s in steps if s.status in {"completed", "partial"}]
    if not completed:
        findings.append(
            InvestigationFinding(
                title="Limited local evidence",
                assessment="insufficient_evidence",
                confidence=0.3,
                notes="Many investigation steps unavailable; do not treat as benign",
            )
        )
    return findings


def _derive_limitations(
    steps: list[InvestigationStepResult],
    entities: EntityExtractionResult,
) -> list[str]:
    limits: list[str] = []
    if not entities.values("ip"):
        limits.append("No IP addresses observed — network pivots not applicable")
    na = [s.step_name for s in steps if s.status == "not_available"]
    if na:
        limits.append(f"Unavailable tools/steps: {', '.join(na[:8])}")
    skipped = [s.step_name for s in steps if s.status == "skipped"]
    if skipped:
        limits.append(f"Skipped: {', '.join(skipped[:8])}")
    failed = [s.step_name for s in steps if s.status == "failed"]
    if failed:
        limits.append(f"Failed steps: {', '.join(failed[:8])}")
    if len(entities.values("hostname")) > 1:
        limits.append(
            "Multiple host values observed (e.g. Computer vs extracted_host) — "
            "kept separate without verified mapping"
        )
    return limits


def _derive_recommendations(
    findings: list[InvestigationFinding],
    case_decision: CaseDecision | None,
) -> list[str]:
    recs = [
        "Review ScriptBlock/process evidence before containment",
        "Correlate by host and user identity when IP is absent",
    ]
    if case_decision and case_decision.action == "review":
        recs.append("Analyst review required before Case merge")
    if any(f.assessment == "benign_admin" for f in findings):
        recs.append("Validate with asset owner whether diagnostic activity was expected")
    if any(f.assessment == "insufficient_evidence" for f in findings):
        recs.append("Collect additional endpoint telemetry before final disposition")
    return recs


def _build_timeline(
    alert: dict[str, Any],
    entities: EntityExtractionResult,
    related: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    ts = alert.get("event_time") or alert.get("alert_time") or alert.get("created_at")
    events.append(
        {
            "ts": str(ts) if ts else None,
            "kind": "seed_alert",
            "label": alert.get("title") or alert.get("rule_name"),
            "alert_id": str(alert.get("id") or alert.get("alert_id") or ""),
        }
    )
    for ent in entities.by_type("source_event_id")[:1]:
        events.append(
            {
                "ts": str(ts) if ts else None,
                "kind": "source_event",
                "label": ent.normalized_value,
                "alert_id": str(alert.get("id") or ""),
            }
        )
    for rel in related[:12]:
        if str(rel.get("id") or "") == str(alert.get("id") or alert.get("alert_id") or ""):
            continue
        events.append(
            {
                "ts": str(rel.get("event_time") or rel.get("created_at") or ""),
                "kind": "related_alert",
                "label": rel.get("title"),
                "alert_id": str(rel.get("id") or ""),
            }
        )
    return events


def _overall_confidence(
    steps: list[InvestigationStepResult],
    findings: list[InvestigationFinding],
) -> float:
    if not findings:
        return 0.2
    avg = sum(f.confidence for f in findings) / len(findings)
    completed = sum(1 for s in steps if s.status in {"completed", "partial"})
    factor = min(1.0, 0.4 + 0.05 * completed)
    return round(min(1.0, avg * factor), 3)


def _final_assessment(findings: list[InvestigationFinding]) -> str:
    assessments = {f.assessment for f in findings}
    if "suspicious" in assessments:
        return "suspicious_activity_suspected"
    if "benign_admin" in assessments and "insufficient_evidence" not in assessments:
        return "likely_benign_administrative"
    if "insufficient_evidence" in assessments:
        return "insufficient_evidence"
    return "informational_detection"
