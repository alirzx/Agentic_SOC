"""Campaign-centric case identity for the agentic funnel.

A Case should represent an *attack campaign* (e.g. C2, lateral movement),
bundling many related alerts that share entities across the kill chain —
not a bucket of identical rule titles.
"""

from __future__ import annotations

import re
from typing import Any

# Primary MITRE tactic → campaign theme (stable product vocabulary).
_TACTIC_THEME: dict[str, str] = {
    "command-and-control": "command-and-control",
    "command_and_control": "command-and-control",
    "c2": "command-and-control",
    "lateral-movement": "lateral-movement",
    "lateral_movement": "lateral-movement",
    "credential-access": "credential-access",
    "credential_access": "credential-access",
    "initial-access": "initial-access",
    "initial_access": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege-escalation",
    "defense-evasion": "defense-evasion",
    "discovery": "discovery",
    "collection": "collection",
    "exfiltration": "exfiltration",
    "impact": "impact",
    "reconnaissance": "reconnaissance",
}

_THEME_TITLE: dict[str, str] = {
    "command-and-control": "Suspected C2 / command-and-control campaign",
    "lateral-movement": "Suspected lateral movement campaign",
    "credential-access": "Suspected credential-access campaign",
    "initial-access": "Suspected initial-access campaign",
    "execution": "Suspected malware execution campaign",
    "persistence": "Suspected persistence campaign",
    "privilege-escalation": "Suspected privilege-escalation campaign",
    "defense-evasion": "Suspected defense-evasion campaign",
    "discovery": "Suspected discovery / recon campaign",
    "collection": "Suspected collection campaign",
    "exfiltration": "Suspected data-exfiltration campaign",
    "impact": "Suspected impact / ransomware campaign",
    "reconnaissance": "Suspected reconnaissance campaign",
    "general-intrusion": "Suspected intrusion campaign",
}

# Title keyword hints when MITRE tactics are missing (Splunk ES notables).
_KEYWORD_THEMES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "command-and-control",
        ("c2", "command and control", "command-and-control", "beacon", "callback", "cobalt strike", "empire"),
    ),
    (
        "lateral-movement",
        ("lateral", "pass the hash", "psexec", "wmi", "smb admin", "remote service"),
    ),
    (
        "credential-access",
        ("password spray", "brute force", "credential", "mimikatz", "ntlm", "kerberoast", "as-rep"),
    ),
    ("exfiltration", ("exfil", "data staging", "unusual upload", "large outbound")),
    ("impact", ("ransomware", "encrypt", "ransom", "wiper", "destructive")),
    ("initial-access", ("phishing", "spearphish", "exploit kit", "drive-by")),
    ("execution", ("malicious file", "dropper", "powershell encoded", "lolbin")),
)


def _norm_tactic(raw: Any) -> str:
    return str(raw or "").strip().lower().replace(" ", "-").replace("_", "-")


def infer_attack_theme(
    *,
    title: str | None = None,
    mitre_tactics: list[Any] | None = None,
    mitre_techniques: list[Any] | None = None,
    raw_alert: dict[str, Any] | None = None,
) -> str:
    """Classify the campaign theme for case grouping + display title."""
    raw = raw_alert or {}
    tactics = list(mitre_tactics or []) + list(raw.get("mitre_tactics") or [])
    for tactic in tactics:
        theme = _TACTIC_THEME.get(_norm_tactic(tactic))
        if theme:
            return theme
    # Technique IDs sometimes carry tactic-ish labels in free text.
    techniques = list(mitre_techniques or []) + list(raw.get("mitre_techniques") or [])
    blob = " ".join(str(t) for t in techniques).lower()
    for theme, keys in _KEYWORD_THEMES:
        if any(k in blob for k in keys):
            return theme
    text = f"{title or ''} {raw.get('title') or ''} {raw.get('search_name') or ''}".lower()
    for theme, keys in _KEYWORD_THEMES:
        if any(k in text for k in keys):
            return theme
    return "general-intrusion"


def campaign_entities(alert: dict[str, Any], raw: dict[str, Any] | None = None) -> list[tuple[str, str]]:
    """Stable (kind, value) entities used to attach alerts to one campaign case."""
    src = {**(raw or {}), **(alert or {})}
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(kind: str, value: Any) -> None:
        text = str(value or "").strip()
        if not text or text.lower() in {"none", "null", "-", "unknown"}:
            return
        key = (kind, text.lower())
        if key in seen:
            return
        seen.add(key)
        out.append((kind, text))

    _add("host", src.get("hostname") or src.get("host") or src.get("dvc") or src.get("dest"))
    _add("ip", src.get("src_ip") or src.get("src"))
    _add("ip", src.get("dst_ip") or src.get("dest_ip"))
    _add("user", src.get("username") or src.get("user") or src.get("src_user"))
    # Nested arrays from fusion / Postgres JSONB.
    for host in src.get("affected_hosts") or []:
        if isinstance(host, str):
            _add("host", host)
        elif isinstance(host, dict):
            _add("host", host.get("value") or host.get("host"))
    for ip in src.get("affected_ips") or []:
        if isinstance(ip, str):
            _add("ip", ip)
        elif isinstance(ip, dict):
            _add("ip", ip.get("value") or ip.get("ip"))
    for user in src.get("affected_users") or []:
        if isinstance(user, str):
            _add("user", user)
        elif isinstance(user, dict):
            _add("user", user.get("value") or user.get("user"))
    return out


def primary_campaign_key(theme: str, entities: list[tuple[str, str]]) -> str | None:
    """Single reopen key: theme + strongest entity (host > ip > user)."""
    if not entities:
        return None
    priority = {"host": 0, "ip": 1, "user": 2}
    kind, value = sorted(entities, key=lambda e: priority.get(e[0], 9))[0]
    safe = re.sub(r"\s+", "_", value.strip())[:120]
    return f"{theme}|{kind}:{safe}"


def campaign_case_title(theme: str, entities: list[tuple[str, str]]) -> str:
    """Human case title — attack narrative, not the first rule name."""
    base = _THEME_TITLE.get(theme, _THEME_TITLE["general-intrusion"])
    bits = [value for _, value in entities[:3]]
    if bits:
        return f"{base} involving {', '.join(bits)}"[:500]
    return base[:500]


def campaign_tags(
    *,
    theme: str,
    campaign_key: str | None,
    source: str,
) -> dict[str, Any]:
    tags: dict[str, Any] = {
        "agentic-promoted": True,
        "reportable": True,
        "source": source,
        "campaign_theme": theme,
        "case_model": "attack_campaign",
    }
    if campaign_key:
        tags["campaign_key"] = campaign_key
    return tags
