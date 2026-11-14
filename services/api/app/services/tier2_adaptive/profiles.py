"""P2 — Adaptive security-domain investigation profiles.

Profiles declare which investigation operations are relevant given entities,
``security_domain``, detection type, and rule metadata. Multiple profiles may
be selected for a single alert (e.g. Endpoint + Identity).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from app.services.tier2_adaptive.entities import (
    EntityExtractionResult,
    extract_alert_entities,
)

PROFILE_VERSION = "profile:v1"

# Operations each profile can request during investigation execution (P5).
ENDPOINT_OPS: tuple[str, ...] = (
    "inspect_host",
    "inspect_user_account",
    "inspect_process_tree",
    "inspect_command_line",
    "inspect_script_block",
    "inspect_file_path_hash",
    "inspect_parent_child",
    "build_endpoint_timeline",
    "find_related_endpoint_alerts",
    "query_edr_telemetry",
)
NETWORK_OPS: tuple[str, ...] = (
    "inspect_src_dest_ip",
    "inspect_ports_protocols",
    "inspect_dns",
    "inspect_connection_history",
    "find_related_network_alerts",
    "analyze_traffic_patterns",
    "analyze_network_behavior",
)
IDENTITY_OPS: tuple[str, ...] = (
    "inspect_user_sid",
    "inspect_authentication",
    "inspect_login_patterns",
    "inspect_privilege_changes",
    "inspect_failed_auth",
    "inspect_account_anomalies",
    "find_related_identity_alerts",
)
FIREWALL_OPS: tuple[str, ...] = (
    "inspect_firewall_device",
    "inspect_src_dest",
    "inspect_rule_policy",
    "inspect_allow_deny",
    "find_related_network_events",
    "analyze_traffic_anomalies",
)
WEB_OPS: tuple[str, ...] = (
    "inspect_url_domain",
    "inspect_http_requests",
    "inspect_web_server",
    "inspect_request_patterns",
    "inspect_status_codes",
    "find_related_web_alerts",
)
EMAIL_OPS: tuple[str, ...] = (
    "inspect_sender_recipient",
    "inspect_message_ids",
    "inspect_subject",
    "inspect_attachments",
    "inspect_urls",
    "inspect_file_hashes",
    "find_related_email_activity",
)
CLOUD_OPS: tuple[str, ...] = (
    "inspect_cloud_account",
    "inspect_cloud_resource",
    "inspect_cloud_identity",
    "inspect_api_activity",
    "inspect_permission_changes",
    "inspect_audit_events",
)
MALWARE_OPS: tuple[str, ...] = (
    "inspect_hash",
    "inspect_file_metadata",
    "inspect_behavioral_indicators",
    "inspect_related_hosts",
    "inspect_detection_history",
    "query_sandbox_results",
)


@dataclass(frozen=True)
class InvestigationProfile:
    """Declarative investigation profile for one security domain."""

    name: str
    label: str
    operations: tuple[str, ...]
    entity_signals: tuple[str, ...]
    domain_aliases: tuple[str, ...]
    rule_keywords: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProfileSelection:
    """Result of adaptive profile selection."""

    profiles: list[InvestigationProfile] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    security_domains: list[str] = field(default_factory=list)
    fallback_used: bool = False
    algorithm_version: str = PROFILE_VERSION

    @property
    def names(self) -> list[str]:
        return [p.name for p in self.profiles]

    def to_dict(self) -> dict[str, Any]:
        return {
            "profiles": [p.to_dict() for p in self.profiles],
            "profile_names": self.names,
            "reasons": self.reasons,
            "security_domains": self.security_domains,
            "fallback_used": self.fallback_used,
            "algorithm_version": self.algorithm_version,
        }


# Registry — extensible; add profiles without changing selection core.
PROFILE_REGISTRY: dict[str, InvestigationProfile] = {
    "endpoint": InvestigationProfile(
        name="endpoint",
        label="Endpoint",
        operations=ENDPOINT_OPS,
        entity_signals=(
            "hostname",
            "endpoint",
            "process_name",
            "process_id",
            "parent_process",
            "file_path",
            "script_block",
        ),
        domain_aliases=("endpoint", "endpoint_security", "edr", "host", "device"),
        rule_keywords=(
            "powershell",
            "scriptblock",
            "sysmon",
            "process",
            "endpoint",
            "malware scan",
            "edr",
        ),
    ),
    "network": InvestigationProfile(
        name="network",
        label="Network",
        operations=NETWORK_OPS,
        entity_signals=("ip", "domain", "url", "network_service"),
        domain_aliases=("network", "netflow", "dns", "proxy"),
        rule_keywords=("dns", "network", "c2", "beacon", "connection", "traffic"),
    ),
    "identity": InvestigationProfile(
        name="identity",
        label="Identity",
        operations=IDENTITY_OPS,
        entity_signals=("username", "user_sid", "account_id"),
        domain_aliases=("identity", "access", "authentication", "iam", "ad"),
        rule_keywords=(
            "login",
            "auth",
            "kerberos",
            "password",
            "privilege",
            "account",
            "identity",
        ),
    ),
    "firewall": InvestigationProfile(
        name="firewall",
        label="Firewall",
        operations=FIREWALL_OPS,
        entity_signals=("ip", "network_service"),
        domain_aliases=("firewall", "fw", "ngfw", "ids", "ips"),
        rule_keywords=("firewall", "allow", "deny", "blocked", "acl", "policy"),
    ),
    "web": InvestigationProfile(
        name="web",
        label="Web",
        operations=WEB_OPS,
        entity_signals=("url", "domain"),
        domain_aliases=("web", "http", "https", "waf", "application"),
        rule_keywords=("http", "web", "url", "waf", "xss", "sqli"),
    ),
    "email": InvestigationProfile(
        name="email",
        label="Email",
        operations=EMAIL_OPS,
        entity_signals=("email", "email_sender", "email_recipient"),
        domain_aliases=("email", "mail", "phishing"),
        rule_keywords=("email", "phish", "mail", "attachment", "sender"),
    ),
    "cloud": InvestigationProfile(
        name="cloud",
        label="Cloud",
        operations=CLOUD_OPS,
        entity_signals=("cloud_resource", "account_id", "kubernetes_workload", "container"),
        domain_aliases=("cloud", "aws", "azure", "gcp", "saas"),
        rule_keywords=("cloud", "aws", "azure", "gcp", "iam policy", "api call"),
    ),
    "malware": InvestigationProfile(
        name="malware",
        label="Malware",
        operations=MALWARE_OPS,
        entity_signals=("file_hash", "file_path"),
        domain_aliases=("malware", "antivirus", "av", "threat"),
        rule_keywords=("malware", "trojan", "virus", "ransomware", "hash", "sandbox"),
    ),
}


def register_profile(profile: InvestigationProfile) -> None:
    """Extend the registry with a custom profile (tests / plugins)."""
    PROFILE_REGISTRY[profile.name] = profile


def _alert_text_blob(alert: dict[str, Any]) -> str:
    parts = [
        str(alert.get("title") or ""),
        str(alert.get("rule_name") or ""),
        str(alert.get("detection_type") or ""),
        str(alert.get("security_domain") or ""),
    ]
    payload = alert.get("llm_payload") if isinstance(alert.get("llm_payload"), dict) else {}
    parts.append(str(payload.get("security_domain") or ""))
    parts.append(str(payload.get("detection_type") or ""))
    parts.append(str(payload.get("rule_name") or ""))
    return " ".join(parts).lower()


def _declared_domains(alert: dict[str, Any]) -> list[str]:
    domains: list[str] = []
    for source in (
        alert.get("security_domain"),
        (alert.get("llm_payload") or {}).get("security_domain")
        if isinstance(alert.get("llm_payload"), dict)
        else None,
        (alert.get("raw_event") or {}).get("security_domain")
        if isinstance(alert.get("raw_event"), dict)
        else None,
        (alert.get("raw_event") or {}).get("orig_security_domain")
        if isinstance(alert.get("raw_event"), dict)
        else None,
    ):
        text = str(source or "").strip().lower()
        if text and text not in domains:
            domains.append(text)
    return domains


def _score_profile(
    profile: InvestigationProfile,
    *,
    domains: list[str],
    entities: EntityExtractionResult,
    blob: str,
) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []

    for domain in domains:
        if domain in profile.domain_aliases or any(
            domain.startswith(alias) or alias in domain for alias in profile.domain_aliases
        ):
            score += 50.0
            reasons.append(f"security_domain={domain}")
            break

    matched_entities = [t for t in profile.entity_signals if entities.has_type(t)]
    if matched_entities:
        # Cap entity contribution so titles alone cannot dominate via keywords.
        contrib = min(35.0, 8.0 * len(matched_entities))
        score += contrib
        reasons.append(f"entities={','.join(matched_entities[:6])}")

    keyword_hits = [kw for kw in profile.rule_keywords if kw in blob]
    if keyword_hits:
        # Keywords alone are weak — never enough to select without domain/entity.
        score += min(15.0, 5.0 * len(keyword_hits))
        reasons.append(f"keywords={','.join(keyword_hits[:4])}")

    return score, reasons


def select_investigation_profiles(
    alert: Any,
    *,
    entities: EntityExtractionResult | None = None,
    min_score: float = 20.0,
    max_profiles: int = 4,
) -> ProfileSelection:
    """Select one or more investigation profiles for the alert.

    Selection uses security_domain, extracted entities, detection type, and
    rule metadata. Title keywords alone never select a profile.
    Missing IP does not block Endpoint or Identity selection.
    """
    row = alert if isinstance(alert, dict) else {
        k: getattr(alert, k, None)
        for k in (
            "title",
            "rule_name",
            "security_domain",
            "detection_type",
            "llm_payload",
            "raw_event",
            "enrichment_data",
        )
    }
    ents = entities if entities is not None else extract_alert_entities(row)
    domains = _declared_domains(row)
    blob = _alert_text_blob(row)

    scored: list[tuple[float, InvestigationProfile, list[str]]] = []
    for profile in PROFILE_REGISTRY.values():
        score, reasons = _score_profile(
            profile, domains=domains, entities=ents, blob=blob
        )
        # Reject keyword-only selections (no domain match and no entity signal).
        has_domain = any("security_domain=" in r for r in reasons)
        has_entity = any(r.startswith("entities=") for r in reasons)
        if not has_domain and not has_entity:
            continue
        if score >= min_score:
            scored.append((score, profile, reasons))

    scored.sort(key=lambda item: (-item[0], item[1].name))
    selected = scored[:max_profiles]

    if selected:
        reasons_out: list[str] = []
        profiles_out: list[InvestigationProfile] = []
        for score, profile, reasons in selected:
            profiles_out.append(profile)
            reasons_out.append(f"{profile.name}:{score:.0f}:{';'.join(reasons)}")
        return ProfileSelection(
            profiles=profiles_out,
            reasons=reasons_out,
            security_domains=domains,
            fallback_used=False,
        )

    # Unknown / empty domain fallback: evidence-only generic endpoint if host-like
    # evidence exists, else a soft network fallback when IPs exist, else endpoint
    # as the safest default for investigation continuity (never IP-gated).
    fallback = PROFILE_REGISTRY["endpoint"]
    fallback_reason = "fallback:endpoint_default"
    if ents.has_type("ip") and not ents.has_type("hostname"):
        fallback = PROFILE_REGISTRY["network"]
        fallback_reason = "fallback:network_from_ip"
    elif ents.has_type("username") or ents.has_type("user_sid"):
        # Prefer identity when only identity entities exist.
        if not ents.has_type("hostname") and not ents.has_type("process_name"):
            fallback = PROFILE_REGISTRY["identity"]
            fallback_reason = "fallback:identity_from_user"
    return ProfileSelection(
        profiles=[fallback],
        reasons=[fallback_reason],
        security_domains=domains,
        fallback_used=True,
    )
