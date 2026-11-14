"""Alert and Incident categorization (separate taxonomies)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class AlertCategory(StrEnum):
    ENDPOINT = "endpoint_security"
    NETWORK = "network_security"
    IDENTITY = "identity_access"
    FIREWALL = "firewall_perimeter"
    WEB = "web_security"
    EMAIL = "email_security"
    CLOUD = "cloud_security"
    MALWARE = "malware"
    DATABASE = "database_security"
    APPLICATION = "application_security"
    DATA = "data_security"
    THREAT_INTEL = "threat_intelligence"
    UNKNOWN = "unknown"


class IncidentCategory(StrEnum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"
    MULTI_STAGE = "multi_stage_attack"
    POLICY_VIOLATION = "policy_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    UNKNOWN = "unknown"


_DOMAIN_TO_ALERT: dict[str, AlertCategory] = {
    "endpoint": AlertCategory.ENDPOINT,
    "endpoint_security": AlertCategory.ENDPOINT,
    "network": AlertCategory.NETWORK,
    "network_security": AlertCategory.NETWORK,
    "identity": AlertCategory.IDENTITY,
    "iam": AlertCategory.IDENTITY,
    "identity_access": AlertCategory.IDENTITY,
    "firewall": AlertCategory.FIREWALL,
    "web": AlertCategory.WEB,
    "waf": AlertCategory.WEB,
    "email": AlertCategory.EMAIL,
    "cloud": AlertCategory.CLOUD,
    "malware": AlertCategory.MALWARE,
    "database": AlertCategory.DATABASE,
    "application": AlertCategory.APPLICATION,
    "data": AlertCategory.DATA,
    "threat_intel": AlertCategory.THREAT_INTEL,
    "ti": AlertCategory.THREAT_INTEL,
}

_TACTIC_TO_INCIDENT: dict[str, IncidentCategory] = {
    "initial access": IncidentCategory.INITIAL_ACCESS,
    "initial-access": IncidentCategory.INITIAL_ACCESS,
    "execution": IncidentCategory.EXECUTION,
    "persistence": IncidentCategory.PERSISTENCE,
    "privilege escalation": IncidentCategory.PRIVILEGE_ESCALATION,
    "privilege-escalation": IncidentCategory.PRIVILEGE_ESCALATION,
    "defense evasion": IncidentCategory.DEFENSE_EVASION,
    "defense-evasion": IncidentCategory.DEFENSE_EVASION,
    "credential access": IncidentCategory.CREDENTIAL_ACCESS,
    "credential-access": IncidentCategory.CREDENTIAL_ACCESS,
    "discovery": IncidentCategory.DISCOVERY,
    "lateral movement": IncidentCategory.LATERAL_MOVEMENT,
    "lateral-movement": IncidentCategory.LATERAL_MOVEMENT,
    "collection": IncidentCategory.COLLECTION,
    "exfiltration": IncidentCategory.EXFILTRATION,
    "command and control": IncidentCategory.COMMAND_AND_CONTROL,
    "command-and-control": IncidentCategory.COMMAND_AND_CONTROL,
    "impact": IncidentCategory.IMPACT,
}

_ALERT_KEYWORD_HINTS: list[tuple[AlertCategory, tuple[str, ...]]] = [
    (AlertCategory.MALWARE, ("malware", "ransomware", "trojan", "virus", "hash reputation")),
    (AlertCategory.EMAIL, ("phish", "email", "mailbox", "sender", "attachment")),
    (AlertCategory.CLOUD, ("aws", "azure", "gcp", "cloudtrail", "iam policy")),
    (AlertCategory.IDENTITY, ("login", "authentication", "okta", "entra", "privilege")),
    (AlertCategory.FIREWALL, ("firewall", "deny", "acl", "packet filter")),
    (AlertCategory.WEB, ("waf", "http", "xss", "sqli", "url path")),
    (AlertCategory.ENDPOINT, ("powershell", "process", "endpoint", "sysmon", "scriptblock")),
    (AlertCategory.NETWORK, ("dns", "zeek", "connection", "port scan", "lateral")),
    (AlertCategory.DATABASE, ("sql", "database", "db user", "query")),
]


@dataclass(frozen=True)
class CategoryResult:
    category_id: str
    category_name: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    source: str = "heuristic"
    classification_method: str = "rule"
    classification_timestamp: str = ""
    model_version: str = "cat:v1"
    inferred: bool = True
    analyst_confirmed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def classify_alert_category(row: dict[str, Any]) -> CategoryResult:
    """Classify an alert; Unknown when evidence is insufficient (never guess ATT&CK)."""
    payload = row.get("llm_payload") if isinstance(row.get("llm_payload"), dict) else {}
    domain = str(
        row.get("security_domain") or payload.get("security_domain") or ""
    ).strip().lower()
    if domain in _DOMAIN_TO_ALERT:
        cat = _DOMAIN_TO_ALERT[domain]
        return CategoryResult(
            category_id=cat.value,
            category_name=cat.name.replace("_", " ").title(),
            confidence=0.9,
            evidence=[f"security_domain={domain}"],
            source="security_domain",
            classification_method="explicit_field",
            classification_timestamp=_now_iso(),
            inferred=False,
        )
    manual = row.get("category")
    if manual and str(manual).strip().lower() not in {"", "unknown", "uncategorized"}:
        raw = str(manual).strip().lower().replace(" ", "_")
        for cat in AlertCategory:
            if cat.value == raw or cat.name.lower() == raw:
                return CategoryResult(
                    category_id=cat.value,
                    category_name=cat.name.replace("_", " ").title(),
                    confidence=1.0,
                    evidence=[f"manual_or_stored_category={manual}"],
                    source="stored",
                    classification_method="analyst_or_prior",
                    classification_timestamp=_now_iso(),
                    inferred=False,
                    analyst_confirmed=True,
                )
    blob = " ".join(
        str(x or "")
        for x in (
            row.get("title"),
            row.get("rule_name"),
            row.get("rule_id"),
            payload.get("rule_name"),
        )
    ).lower()
    for cat, keys in _ALERT_KEYWORD_HINTS:
        hits = [k for k in keys if k in blob]
        if hits:
            return CategoryResult(
                category_id=cat.value,
                category_name=cat.name.replace("_", " ").title(),
                confidence=0.55,
                evidence=[f"keyword:{h}" for h in hits[:3]],
                source="title_rule_heuristic",
                classification_method="keyword",
                classification_timestamp=_now_iso(),
                inferred=True,
            )
    return CategoryResult(
        category_id=AlertCategory.UNKNOWN.value,
        category_name="Unknown",
        confidence=0.0,
        evidence=["insufficient_evidence"],
        source="default",
        classification_method="none",
        classification_timestamp=_now_iso(),
        inferred=True,
    )


def classify_incident_category(
    *,
    mitre_tactics: list[Any] | None = None,
    alert_categories: list[str] | None = None,
    title: str | None = None,
) -> CategoryResult:
    """Incident category from tactics when present; else multi-stage/suspicious/unknown."""
    tactics = [str(t).strip().lower() for t in (mitre_tactics or []) if str(t).strip()]
    mapped: list[IncidentCategory] = []
    evidence: list[str] = []
    for tactic in tactics:
        cat = _TACTIC_TO_INCIDENT.get(tactic)
        if cat:
            mapped.append(cat)
            evidence.append(f"mitre_tactic={tactic}")
    if len(set(mapped)) >= 2:
        return CategoryResult(
            category_id=IncidentCategory.MULTI_STAGE.value,
            category_name="Multi Stage Attack",
            confidence=0.8,
            evidence=evidence,
            source="mitre_tactics",
            classification_method="multi_tactic",
            classification_timestamp=_now_iso(),
            inferred=True,
        )
    if len(mapped) == 1:
        cat = mapped[0]
        return CategoryResult(
            category_id=cat.value,
            category_name=cat.name.replace("_", " ").title(),
            confidence=0.85,
            evidence=evidence,
            source="mitre_tactics",
            classification_method="tactic_map",
            classification_timestamp=_now_iso(),
            inferred=True,
        )
    # Do NOT invent ATT&CK from title alone.
    cats = {str(c).lower() for c in (alert_categories or [])}
    if len(cats) >= 2:
        return CategoryResult(
            category_id=IncidentCategory.MULTI_STAGE.value,
            category_name="Multi Stage Attack",
            confidence=0.5,
            evidence=[f"alert_categories={sorted(cats)}"],
            source="alert_category_mix",
            classification_method="heuristic",
            classification_timestamp=_now_iso(),
            inferred=True,
        )
    if title and "policy" in title.lower():
        return CategoryResult(
            category_id=IncidentCategory.POLICY_VIOLATION.value,
            category_name="Policy Violation",
            confidence=0.4,
            evidence=["title_keyword=policy"],
            source="title",
            classification_method="keyword",
            classification_timestamp=_now_iso(),
            inferred=True,
        )
    if title:
        return CategoryResult(
            category_id=IncidentCategory.SUSPICIOUS_ACTIVITY.value,
            category_name="Suspicious Activity",
            confidence=0.3,
            evidence=["title_present_no_tactic"],
            source="default",
            classification_method="fallback",
            classification_timestamp=_now_iso(),
            inferred=True,
        )
    return CategoryResult(
        category_id=IncidentCategory.UNKNOWN.value,
        category_name="Unknown",
        confidence=0.0,
        evidence=["insufficient_evidence"],
        source="default",
        classification_method="none",
        classification_timestamp=_now_iso(),
        inferred=True,
    )
