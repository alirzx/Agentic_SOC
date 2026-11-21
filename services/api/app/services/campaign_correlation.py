"""LEGACY RETIREMENT: campaign key and case recommendation logic only.

Automatic case creation belongs to `services/correlation`; this module is kept
for compatibility and scoring. It must not become an independent case writer.

CASE KINDS (retired): the scoring/selection half of the funnel's
"attack-campaign" case (plus its risk "supporting context" attachment). It never
wrote a case row itself. Campaign membership now comes from
`services/correlation` (weighted entity keys + L1/L2/L3); single-alert incidents
and risk-supporter attachment are not produced any more.

Explainable campaign-case correlation for funnel backfill (campaign-corr:v2).

Rejects false campaigns that previously linked alerts merely because they were
high-severity / same Splunk source / same loose OR(host|ip|user) window.

Business rules (source of truth)
--------------------------------
* Shared host / user / IP is required for a primary link (Level 1).
* Temporal proximity is **mandatory**: missing or out-of-window timestamps reject.
* Technical/MITRE family affinity strengthens but never alone (Level 3).
* Severity / ML priority / identical source MUST NOT create links (Level 4).
* Risk-engine / RBA threshold alerts are supporting context only.
* Cross-domain links (web ↔ credential ↔ endpoint …) require shared host or
  user — IP-only is insufficient across domains.
* Pairwise only — no transitive A→B→C expansion.
* Scoring is additive then capped to [0, 1]; thresholds are absolute on the
  capped score (same-domain 0.55, cross-domain 0.70).

Infrastructure-IP limitation
----------------------------
We exclude loopback / unspecified / link-local / multicast / documentation
ranges as identity evidence. We do **not** invent NAT/proxy/LB classification
without explicit metadata (``infrastructure_ip`` tag or field).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.services.campaign_case import campaign_entities, infer_attack_theme
from app.services.dedup.alert_identity import extract_identity_entities

CORRELATION_VERSION = "campaign-corr:v2"

# --- Thresholds & weights (centralized) -------------------------------------
DEFAULT_LINK_THRESHOLD = 0.55
DEFAULT_CROSS_DOMAIN_THRESHOLD = 0.70
WEIGHT_HOST = 0.35
WEIGHT_USER = 0.25
WEIGHT_IP_SAME_FAMILY = 0.28
WEIGHT_IP_WITH_HOST_OR_USER = 0.20
WEIGHT_IP_ONLY_CROSS_FAMILY = 0.12
WEIGHT_TEMPORAL_MAX = 0.15
WEIGHT_MITRE = 0.10
WEIGHT_FAMILY = 0.15
SUPPORTING_FLOOR = 0.40
SUPPORTING_THRESHOLD_OFFSET = 0.10
DEFAULT_TEMPORAL_WINDOW_SECONDS = 86_400
SIBLING_HARD_CAP = 100

# Seed may open/join a campaign case.
SEED_ELIGIBLE_DISPOSITIONS = frozenset({"true_positive", "needs_review", "escalate"})
# Candidate may be admitted as a sibling (never missing/unknown alone).
CANDIDATE_ELIGIBLE_DISPOSITIONS = frozenset(
    {"true_positive", "needs_review", "escalate", "likely_tp"}
)
BLOCKED_DISPOSITIONS = frozenset(
    {"false_positive", "benign", "benign_true_positive"}
)
# needs_review seed requires severity rank >= this (medium=3 in ladder).
NEEDS_REVIEW_MIN_SEVERITY_RANK = 3

_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

_RISK_TITLE_RE = re.compile(
    r"(?i)\brisk\s*-|\bATT&CK\s+Tactic\s+Threshold\b|\bRisk\s+Threshold\s+Exceeded\b|"
    r"\b7\s*Day\s+ATT&CK\b|\b24\s*Hour\s+Risk\b|\bRBA\b.*\bthreshold\b"
)

# Order matters: risk first, then more specific families before general.
_FAMILY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("risk", _RISK_TITLE_RE),
    (
        "web",
        re.compile(
            r"(?i)\bsql\s*injection\b|\bpath\s*traversal\b|\bcommand\s*injection\b|"
            r"\bxss\b|\bwaf\b|\bweb[-_]?(sqli|attack|exploit)"
        ),
    ),
    (
        "credential",
        re.compile(
            r"(?i)\blsass\b|\bmimikatz\b|\bcredential\s*(dump|access|theft)\b|"
            r"\bdump\s*creation\b|\bntds\b|\bkerberoast\b|\bdcsync\b|\bsam\s*database\b"
        ),
    ),
    (
        "endpoint",
        re.compile(
            r"(?i)\bpowershell\b|\bscriptblock\b|\binvoke[- ]?command\b|"
            r"\battacker\s*tools\b|\bdefender\s*exclusion\b|\bsysmon\b|"
            r"\bprocess\s*injection\b|\buac\s*bypass\b"
        ),
    ),
    (
        "identity",
        re.compile(
            r"(?i)\bshort[- ]?lived\s*account\b|\baccount\s*created\b|"
            r"\bimpossible\s*travel\b|\bokta\b.*\b(login|auth)"
        ),
    ),
    (
        "malware",
        re.compile(
            r"(?i)\bmalware\b|\bransomware\b|\btrojan\b|\bcobalt\s*strike\b|\bbeacon\b"
        ),
    ),
]

_NONE_TOKENS = frozenset({"", "none", "null", "n/a", "-", "—", "unknown", "nil"})


@dataclass
class LinkEvidence:
    type: str
    value: str
    weight: float


@dataclass
class CampaignLinkDecision:
    linked: bool
    correlation_type: str
    matched_entities: dict[str, Any]
    time_difference_seconds: int | None
    shared_techniques: list[str]
    correlation_score: float
    evidence_refs: list[LinkEvidence] = field(default_factory=list)
    decision_reason: str = ""
    confidence: float = 0.0
    role: str = "primary"  # primary | supporting | rejected
    algorithm_version: str = CORRELATION_VERSION
    # Extended audit fields (backward-compatible extras)
    seed_family: str = ""
    candidate_family: str = ""
    cross_domain: bool = False
    signals: dict[str, float] = field(default_factory=dict)
    raw_score: float = 0.0
    final_score: float = 0.0
    threshold: float = DEFAULT_LINK_THRESHOLD
    rejection_reasons: list[str] = field(default_factory=list)
    evidence_independence: str = "unknown"  # independent | duplicate | derived | unknown
    discovery_path: str = ""  # primary path label (first / preferred)
    discovery_paths: list[str] = field(default_factory=list)  # all paths (deduped)
    time_window_seconds: int | None = None
    seed_hosts: list[str] = field(default_factory=list)
    candidate_hosts: list[str] = field(default_factory=list)
    matched_hosts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence_refs"] = [asdict(e) for e in self.evidence_refs]
        return payload


# ---------------------------------------------------------------------------
# Eligibility
# ---------------------------------------------------------------------------


def severity_rank(sev: Any) -> int:
    return _SEVERITY_RANK.get(str(sev or "").strip().lower(), 0)


def is_seed_eligible(alert: dict[str, Any]) -> tuple[bool, str]:
    """Return (ok, reason) for campaign seed eligibility."""
    if alert.get("case_id"):
        return False, "already_has_case_id"
    disp = str(alert.get("disposition") or "").strip().lower()
    if not disp:
        return False, "missing_disposition"
    if disp in BLOCKED_DISPOSITIONS:
        return False, f"blocked_disposition:{disp}"
    if disp not in SEED_ELIGIBLE_DISPOSITIONS:
        return False, f"ineligible_disposition:{disp}"
    if disp == "needs_review" and severity_rank(alert.get("severity")) < NEEDS_REVIEW_MIN_SEVERITY_RANK:
        return False, "needs_review_severity_below_medium"
    return True, "ok"


def is_candidate_eligible(
    alert: dict[str, Any],
    *,
    ignore_case_membership: bool = False,
) -> tuple[bool, str]:
    """Return (ok, reason) for sibling candidate eligibility.

    ``ignore_case_membership`` is used by reconcile paths that re-score alerts
    already attached to the case under audit.
    """
    if not ignore_case_membership and alert.get("case_id"):
        return False, "already_has_case_id"
    disp = str(alert.get("disposition") or "").strip().lower()
    if not disp:
        return False, "missing_disposition"
    if disp in BLOCKED_DISPOSITIONS:
        return False, f"blocked_disposition:{disp}"
    if disp not in CANDIDATE_ELIGIBLE_DISPOSITIONS:
        return False, f"ineligible_disposition:{disp}"
    return True, "ok"


# ---------------------------------------------------------------------------
# Family / risk / lineage
# ---------------------------------------------------------------------------


def is_risk_supporting_alert(alert: dict[str, Any]) -> bool:
    """True for Risk Engine / threshold rollups — not independent attack evidence."""
    title = str(alert.get("title") or alert.get("rule_name") or "")
    rule = str(alert.get("rule_id") or alert.get("rule_name") or "")
    if _RISK_TITLE_RE.search(title) or _RISK_TITLE_RE.search(rule):
        return True
    payload = alert.get("llm_payload") if isinstance(alert.get("llm_payload"), dict) else {}
    domain = str(
        alert.get("security_domain") or payload.get("security_domain") or ""
    ).lower()
    if domain in {"risk", "rba", "ueba"} and "threshold" in title.lower():
        return True
    structured = _structured_family(alert)
    return structured == "risk"


def _structured_family(alert: dict[str, Any]) -> str | None:
    for key in ("security_domain", "detection_family", "alert_family", "family"):
        raw = alert.get(key)
        if isinstance(raw, str) and raw.strip():
            val = raw.strip().lower()
            if val in {"web", "credential", "endpoint", "identity", "malware", "risk", "general"}:
                return val
    payload = alert.get("llm_payload") if isinstance(alert.get("llm_payload"), dict) else {}
    for key in ("security_domain", "detection_family", "family"):
        raw = payload.get(key)
        if isinstance(raw, str) and raw.strip():
            val = raw.strip().lower()
            if val in {"web", "credential", "endpoint", "identity", "malware", "risk", "general"}:
                return val
    return None


def alert_family(alert: dict[str, Any]) -> str:
    structured = _structured_family(alert)
    if structured == "risk" or is_risk_supporting_alert(alert):
        # Risk takes precedence for genuine threshold/RBA detections.
        if structured == "risk" or _RISK_TITLE_RE.search(
            str(alert.get("title") or "")
        ) or _RISK_TITLE_RE.search(str(alert.get("rule_name") or "")):
            return "risk"
    if structured and structured != "general":
        return structured

    blob = " ".join(
        str(x or "")
        for x in (
            alert.get("title"),
            alert.get("rule_name"),
            alert.get("rule_id"),
        )
    )
    for name, pattern in _FAMILY_PATTERNS:
        if pattern.search(blob):
            return name
    theme = infer_attack_theme(
        title=str(alert.get("title") or ""),
        mitre_tactics=alert.get("mitre_tactics")
        if isinstance(alert.get("mitre_tactics"), list)
        else None,
        mitre_techniques=alert.get("mitre_techniques")
        if isinstance(alert.get("mitre_techniques"), list)
        else None,
        raw_alert=alert.get("raw_event")
        if isinstance(alert.get("raw_event"), dict)
        else {},
    )
    if theme in {"credential-access"}:
        return "credential"
    if theme in {"execution", "defense-evasion", "persistence", "privilege-escalation"}:
        return "endpoint"
    if theme in {"initial-access"}:
        return "web"
    return "general"


def evidence_lineage_key(alert: dict[str, Any]) -> str | None:
    """Best-effort lineage key; None when independence cannot be established."""
    raw = alert.get("raw_event") if isinstance(alert.get("raw_event"), dict) else {}
    payload = alert.get("llm_payload") if isinstance(alert.get("llm_payload"), dict) else {}
    for blob in (alert, raw, payload):
        if not isinstance(blob, dict):
            continue
        for key in (
            "event_id",
            "eventId",
            "notable_id",
            "orig_sid",
            "sid",
            "search_id",
            "source_event_id",
            "dedupe_key",
            "fingerprint",
        ):
            val = blob.get(key)
            if val is not None and str(val).strip() and str(val).strip().lower() not in _NONE_TOKENS:
                return f"{key}:{str(val).strip().lower()}"
    return None


def assess_evidence_independence(
    seed: dict[str, Any], candidate: dict[str, Any]
) -> str:
    sk = evidence_lineage_key(seed)
    ck = evidence_lineage_key(candidate)
    if sk and ck and sk == ck:
        return "duplicate"
    if is_risk_supporting_alert(candidate) and not is_risk_supporting_alert(seed):
        return "derived"
    if sk is None or ck is None:
        return "unknown"
    return "independent"


# ---------------------------------------------------------------------------
# Host identity (Host-Centric Correlation)
# ---------------------------------------------------------------------------

_HOST_PLACEHOLDERS = frozenset(
    {
        *_NONE_TOKENS,
        "localhost",
        "local",
        "n/a",
        "na",
        "unknown-host",
        "unknown_host",
        "host",
        "none",
        "-",
    }
)
# Hostname labels: letters/digits/hyphen/underscore/dot; reject pure IPs as hosts.
_HOST_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,252}[a-z0-9])?$", re.I)


def normalize_host(value: Any) -> str | None:
    """Normalize a hostname for exact host-centric matching.

    Rules:
    * trim whitespace, lowercase, strip trailing dots
    * reject null / empty / placeholders
    * reject values that parse as IP addresses (IP ≠ host identity)
    * do **not** equate short name with FQDN (no guessing)
    * do **not** substring / prefix match
    """
    text = str(value or "").strip().strip("'\"")
    if not text:
        return None
    text = text.lower().rstrip(".")
    if not text or text in _HOST_PLACEHOLDERS:
        return None
    # Never treat IPs as host identity.
    if normalize_ip(text) is not None:
        return None
    try:
        ipaddress.ip_address(text.strip("[]"))
        return None
    except ValueError:
        pass
    if not _HOST_LABEL_RE.match(text):
        return None
    if len(text) > 253:
        return None
    return text


def extract_alert_hosts(alert: dict[str, Any]) -> list[str]:
    """Return deduped normalized host identities for an alert (deterministic order).

    Preference order for canonical identity when present:
    ``canonical_host`` / ``asset_hostname`` / ``asset_id`` (as host-like) then
    structured fields and ``affected_hosts``.
    """
    found: list[str] = []
    seen: set[str] = set()

    def _add(raw: Any) -> None:
        norm = normalize_host(raw)
        if norm and norm not in seen:
            seen.add(norm)
            found.append(norm)

    # Authoritative / canonical first — do not invent aliases.
    for key in ("canonical_host", "asset_hostname", "primary_host"):
        if alert.get(key):
            _add(alert.get(key))
    payload = alert.get("llm_payload") if isinstance(alert.get("llm_payload"), dict) else {}
    af = payload.get("alert_fields") if isinstance(payload.get("alert_fields"), dict) else {}
    raw = alert.get("raw_event") if isinstance(alert.get("raw_event"), dict) else {}
    for blob in (alert, af, raw, payload):
        if not isinstance(blob, dict):
            continue
        for key in (
            "hostname",
            "host",
            "Computer",
            "computer",
            "dvc",
            "dest",
            "dest_host",
            "destination_host",
            "src_host",
            "device_name",
            "endpoint",
        ):
            if blob.get(key):
                _add(blob.get(key))
        device = blob.get("device")
        if isinstance(device, dict) and device.get("name"):
            _add(device.get("name"))

    for item in alert.get("affected_hosts") or []:
        if isinstance(item, dict):
            _add(item.get("value") or item.get("host") or item.get("hostname"))
        else:
            _add(item)

    # Also fold identity extractor hosts (already lowercased).
    for h in extract_identity_entities(alert).get("hosts") or []:
        _add(h)
    return found


def primary_seed_host(alert: dict[str, Any]) -> str | None:
    """Strongest single host identity for Host-Centric discovery."""
    hosts = extract_alert_hosts(alert)
    return hosts[0] if hosts else None


def hosts_exact_match(seed_hosts: set[str] | list[str], cand_hosts: set[str] | list[str]) -> list[str]:
    """Exact normalized host intersection (no prefix / substring)."""
    return sorted(set(seed_hosts) & set(cand_hosts))


def find_host_related_alerts(
    seed: dict[str, Any],
    candidates: list[dict[str, Any]],
    *,
    temporal_window_seconds: int = DEFAULT_TEMPORAL_WINDOW_SECONDS,
    enforce_candidate_eligibility: bool = True,
    ignore_case_membership: bool = False,
) -> list[dict[str, Any]]:
    """Discover eligible same-host candidates relative to the **seed** timestamp.

    Discovery ≠ linking. Callers must still run ``score_campaign_link(seed, cand)``.
    Time filtering uses the seed clock only (never a sibling's timestamp).
    """
    seed_hosts = set(extract_alert_hosts(seed))
    if not seed_hosts:
        return []
    if is_risk_supporting_alert(seed):
        return []

    seed_ts = _ts(seed)
    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seed_id = str(seed.get("id") or "")

    for cand in candidates:
        cid = str(cand.get("id") or "")
        if not cid or cid == seed_id or cid in seen_ids:
            continue
        if enforce_candidate_eligibility:
            ok, _why = is_candidate_eligible(
                cand, ignore_case_membership=ignore_case_membership
            )
            if not ok:
                continue
        cand_hosts = set(extract_alert_hosts(cand))
        matched = hosts_exact_match(seed_hosts, cand_hosts)
        if not matched:
            continue
        # Seed-relative window (mandatory when seed has a timestamp).
        if seed_ts is not None:
            cand_ts = _ts(cand)
            if cand_ts is None:
                continue
            if int(abs(seed_ts - cand_ts)) > temporal_window_seconds:
                continue
        row = dict(cand)
        row["_discovery_path"] = "host_centric"
        row["_discovery_paths"] = ["host_centric"]
        row["_matched_hosts"] = matched
        out.append(row)
        seen_ids.add(cid)

    out.sort(key=lambda r: str(r.get("id") or ""))
    return out


def find_entity_overlap_alerts(
    seed: dict[str, Any],
    candidates: list[dict[str, Any]],
    *,
    temporal_window_seconds: int = DEFAULT_TEMPORAL_WINDOW_SECONDS,
    enforce_candidate_eligibility: bool = True,
    ignore_case_membership: bool = False,
    exclude_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Complementary discovery: shared user or IP (and host if not excluded)."""
    seed_e = _entity_sets(seed)
    seed_ts = _ts(seed)
    seed_id = str(seed.get("id") or "")
    skip = set(exclude_ids or ())
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    for cand in candidates:
        cid = str(cand.get("id") or "")
        if not cid or cid == seed_id or cid in skip or cid in seen:
            continue
        if enforce_candidate_eligibility:
            ok, _why = is_candidate_eligible(
                cand, ignore_case_membership=ignore_case_membership
            )
            if not ok:
                continue
        cand_e = _entity_sets(cand)
        shared_user = bool(seed_e["users"] & cand_e["users"])
        shared_ip = bool(seed_e["ips"] & cand_e["ips"])
        shared_host = bool(seed_e["hosts"] & cand_e["hosts"])
        if not (shared_user or shared_ip or shared_host):
            continue
        if seed_ts is not None:
            cand_ts = _ts(cand)
            if cand_ts is None:
                continue
            if int(abs(seed_ts - cand_ts)) > temporal_window_seconds:
                continue
        path = "host_centric" if shared_host else "entity_overlap"
        row = dict(cand)
        row["_discovery_path"] = path
        row["_discovery_paths"] = [path]
        if shared_host:
            row["_matched_hosts"] = sorted(seed_e["hosts"] & cand_e["hosts"])
        if shared_user and path == "entity_overlap":
            row["_discovery_paths"] = ["entity_overlap"]
        if shared_ip and "entity_overlap" not in row["_discovery_paths"] and not shared_host:
            row["_discovery_paths"] = ["entity_overlap"]
        out.append(row)
        seen.add(cid)
    out.sort(key=lambda r: str(r.get("id") or ""))
    return out


def host_centric_sql_filter_clause(*, multi_host: bool = False) -> str:
    """SQL fragment for exact normalized host match on ``affected_hosts`` JSONB.

    Single-host bind ``:norm_host`` or multi-host ``:norm_hosts`` (text[]).
    Prefer tenant + time predicates first so planners can use
    ``idx_alerts_event_t`` / tenant indexes before the EXISTS. Optional GIN
    on ``affected_hosts`` (migration 076) helps containment prefilters only —
    exact lower(rtrim) still needs the EXISTS. Never run migrations on Production.
    """
    if multi_host:
        return """
      EXISTS (
        SELECT 1
          FROM jsonb_array_elements_text(COALESCE(alerts.affected_hosts, '[]'::jsonb)) AS elem(h)
         WHERE lower(rtrim(elem.h, '.')) = ANY(CAST(:norm_hosts AS text[]))
      )
    """
    return """
      EXISTS (
        SELECT 1
          FROM jsonb_array_elements_text(COALESCE(alerts.affected_hosts, '[]'::jsonb)) AS elem(h)
         WHERE lower(rtrim(elem.h, '.')) = :norm_host
      )
    """


HOST_CENTRIC_DISCOVERY_SQL = """
SELECT
    id, title, severity, status, disposition, case_id, tags,
    affected_hosts, affected_ips, affected_users, raw_event,
    created_at, event_time, llm_payload, iocs,
    rule_id, rule_name, mitre_techniques, mitre_tactics,
    confidence, ai_score
  FROM alerts
 WHERE tenant_id = :tid
   AND id <> CAST(:seed_id AS uuid)
   AND case_id IS NULL
   AND COALESCE(event_time, created_at) >= :window_start
   AND COALESCE(event_time, created_at) <= :window_end
   AND lower(COALESCE(NULLIF(disposition, ''), '')) = ANY(CAST(:eligible_disps AS text[]))
   AND EXISTS (
         SELECT 1
           FROM jsonb_array_elements_text(COALESCE(affected_hosts, '[]'::jsonb)) AS elem(h)
          WHERE lower(rtrim(elem.h, '.')) = ANY(CAST(:norm_hosts AS text[]))
       )
 ORDER BY id
 LIMIT :lim
"""


def host_centric_discovery_params(
    *,
    tenant_id: Any,
    seed_id: Any,
    seed_hosts: list[str],
    seed_ts: float | None,
    temporal_window_seconds: int,
    limit: int = SIBLING_HARD_CAP,
) -> dict[str, Any] | None:
    """Bind params for ``HOST_CENTRIC_DISCOVERY_SQL`` (seed-relative window).

    Returns ``None`` when discovery cannot run (no hosts / no seed timestamp).
    """
    # Always bind *normalized* host identities (lowercase, no trailing dot).
    # Passing raw casing/trailing-dot values would miss exact SQL matches.
    seen: set[str] = set()
    norm_hosts: list[str] = []
    for h in seed_hosts:
        norm = normalize_host(h)
        if norm and norm not in seen:
            seen.add(norm)
            norm_hosts.append(norm)
    if not norm_hosts or seed_ts is None:
        return None
    from datetime import datetime, timedelta, timezone

    center = datetime.fromtimestamp(seed_ts, tz=timezone.utc)
    window = timedelta(seconds=int(temporal_window_seconds))
    return {
        "tid": tenant_id,
        "seed_id": str(seed_id),
        "norm_hosts": norm_hosts,
        "window_start": center - window,
        "window_end": center + window,
        "eligible_disps": sorted(CANDIDATE_ELIGIBLE_DISPOSITIONS),
        "lim": max(1, min(int(limit), SIBLING_HARD_CAP * 2)),
    }


def summarize_correlation_decisions(decisions: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate discovery/role counts without double-counting unique candidates."""
    unique_ids: set[str] = set()
    path_hits = {"host_centric": 0, "entity_overlap": 0, "provided": 0}
    roles = {"primary": 0, "supporting": 0, "rejected": 0}
    for d in decisions:
        aid = str(d.get("alert_id") or "")
        if aid:
            unique_ids.add(aid)
        paths = d.get("discovery_paths") or (
            [d["discovery_path"]] if d.get("discovery_path") else []
        )
        for p in paths:
            key = str(p)
            if key in path_hits:
                path_hits[key] += 1
            elif key == "host_centric" or key.startswith("host_centric"):
                path_hits["host_centric"] += 1
        role = str(d.get("role") or "rejected")
        if role in roles:
            roles[role] += 1
        elif d.get("linked"):
            roles["primary"] += 1
        else:
            roles["rejected"] += 1
    return {
        "host_centric": path_hits["host_centric"],
        "entity_overlap": path_hits["entity_overlap"],
        "provided": path_hits["provided"],
        "unique_candidates": len(unique_ids),
        "primary": roles["primary"],
        "supporting": roles["supporting"],
        "rejected": roles["rejected"],
    }


# ---------------------------------------------------------------------------
# Entity extraction & IP hygiene
# ---------------------------------------------------------------------------


def _is_non_identity_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Reject IPs that must never count as endpoint identity evidence.

    Private RFC1918 addresses are intentionally allowed — SOC hosts are often
    internal. NAT/proxy/LB classification requires explicit metadata
    (see ``_explicit_infrastructure_ips``); we do not invent it here.
    """
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        return True
    if ip.is_reserved:
        return True
    # Documentation / example nets (RFC 5737 / 3849)
    for net in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
    ):
        if ip in ipaddress.ip_network(net):
            return True
    return False


def normalize_ip(value: Any) -> str | None:
    text = str(value or "").strip().strip("[]").lower()
    if not text or text in _NONE_TOKENS:
        return None
    if "/" in text:
        text = text.split("/", 1)[0]
    # Collapse IPv4-mapped IPv6
    if text.startswith("::ffff:"):
        text = text[7:]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if _is_non_identity_ip(ip):
        return None
    # Canonical form (IPv6 compressed lower-case; IPv4 dotted)
    return str(ip)


def _explicit_infrastructure_ips(alert: dict[str, Any]) -> set[str]:
    """Only trust explicit metadata — never invent proxy/NAT classification."""
    out: set[str] = set()
    tags = alert.get("tags")
    infra_list: list[Any] = []
    if isinstance(tags, dict):
        raw = tags.get("infrastructure_ips") or tags.get("infra_ips")
        if isinstance(raw, list):
            infra_list.extend(raw)
        labels = tags.get("labels")
        if isinstance(labels, list) and "infrastructure_ip" in {str(x).lower() for x in labels}:
            # All IPs on this alert treated as infra when labeled.
            for ip in alert.get("affected_ips") or []:
                infra_list.append(ip)
    elif isinstance(tags, list) and "infrastructure_ip" in {str(x).lower() for x in tags}:
        for ip in alert.get("affected_ips") or []:
            infra_list.append(ip)
    for key in ("infrastructure_ips", "proxy_ips", "gateway_ips"):
        raw = alert.get(key)
        if isinstance(raw, list):
            infra_list.extend(raw)
    for item in infra_list:
        if isinstance(item, dict):
            norm = normalize_ip(item.get("value") or item.get("ip"))
        else:
            norm = normalize_ip(item)
        if norm:
            out.add(norm)
    return out


def _entity_sets(alert: dict[str, Any]) -> dict[str, set[str]]:
    """Entity sets for scoring — hosts always via ``normalize_host`` (same as discovery)."""
    extracted = extract_identity_entities(alert)
    legacy = campaign_entities(
        alert,
        alert.get("raw_event") if isinstance(alert.get("raw_event"), dict) else {},
    )
    # Single normalization contract with Host-Centric discovery.
    hosts = set(extract_alert_hosts(alert))
    users = {u.lower() for u in (extracted.get("users") or []) if u}
    raw_ips = {
        *(extracted.get("src_ips") or []),
        *(extracted.get("dst_ips") or []),
    }
    ips: set[str] = set()
    for raw in raw_ips:
        norm = normalize_ip(raw)
        if norm:
            ips.add(norm)
    for kind, value in legacy:
        if kind == "host":
            # Already covered by extract_alert_hosts; keep for safety if legacy-only.
            nh = normalize_host(value)
            if nh:
                hosts.add(nh)
            continue
        v = str(value).strip().lower()
        if not v or v in _NONE_TOKENS:
            continue
        if kind == "user":
            users.add(v)
        elif kind == "ip":
            norm = normalize_ip(v)
            if norm:
                ips.add(norm)
    infra = _explicit_infrastructure_ips(alert)
    if infra:
        ips -= infra
    return {"hosts": hosts, "users": users, "ips": ips}


def _ts(alert: dict[str, Any]) -> float | None:
    """Return Unix epoch seconds (UTC) or None — never treat missing as zero delta."""
    for key in ("event_time", "created_at"):
        val = alert.get(key)
        if val is None:
            continue
        if hasattr(val, "timestamp"):
            dt = val
            if getattr(dt, "tzinfo", None) is None:
                try:
                    dt = dt.replace(tzinfo=timezone.utc)
                except Exception:  # noqa: BLE001
                    pass
            try:
                return float(dt.timestamp())
            except Exception:  # noqa: BLE001
                continue
        if isinstance(val, (int, float)):
            # Heuristic: ms vs s
            num = float(val)
            if num > 1e12:
                num = num / 1000.0
            return num
        if isinstance(val, str):
            text = val.strip()
            if not text:
                continue
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return float(parsed.timestamp())
            except ValueError:
                continue
    return None


def campaign_temporal_window_seconds(hours: int) -> int:
    """Backfill window: ``max(3600, hours * 3600)``."""
    return max(3600, int(hours) * 3600)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _reject(
    *,
    correlation_type: str,
    matched: dict[str, Any],
    delta: int | None,
    shared_tech: list[str],
    score: float,
    evidence: list[LinkEvidence],
    reason: str,
    rejection_reasons: list[str],
    seed_fam: str,
    cand_fam: str,
    cross_domain: bool,
    threshold: float,
    signals: dict[str, float],
    independence: str,
) -> CampaignLinkDecision:
    capped = round(min(1.0, max(0.0, score)), 4)
    return CampaignLinkDecision(
        linked=False,
        correlation_type=correlation_type,
        matched_entities=matched,
        time_difference_seconds=delta,
        shared_techniques=shared_tech,
        correlation_score=capped,
        evidence_refs=evidence,
        decision_reason=reason,
        confidence=capped if evidence else 0.0,
        role="rejected",
        seed_family=seed_fam,
        candidate_family=cand_fam,
        cross_domain=cross_domain,
        signals=signals,
        raw_score=round(score, 4),
        final_score=capped,
        threshold=threshold,
        rejection_reasons=rejection_reasons,
        evidence_independence=independence,
    )


def score_campaign_link(
    seed: dict[str, Any],
    candidate: dict[str, Any],
    *,
    temporal_window_seconds: int = DEFAULT_TEMPORAL_WINDOW_SECONDS,
    threshold: float = DEFAULT_LINK_THRESHOLD,
) -> CampaignLinkDecision:
    """Decide whether candidate belongs in the same campaign case as seed.

    Score model
    -----------
    Additive contributions from distinct evidence classes, then
    ``final_score = min(1.0, raw_score)``. Thresholds apply to ``final_score``.
    Entity evidence is mandatory; boosters never create a link alone.
    Temporal window is mandatory (missing / out-of-window → reject).
    """
    seed_e = _entity_sets(seed)
    cand_e = _entity_sets(candidate)
    shared_hosts = sorted(seed_e["hosts"] & cand_e["hosts"])
    shared_users = sorted(seed_e["users"] & cand_e["users"])
    shared_ips = sorted(seed_e["ips"] & cand_e["ips"])

    matched: dict[str, Any] = {
        "host": shared_hosts[0] if shared_hosts else None,
        "user": shared_users[0] if shared_users else None,
        "source_ip": shared_ips[0] if shared_ips else None,
        "destination_ip": None,
        "hosts": shared_hosts,
        "users": shared_users,
        "ips": shared_ips,
    }

    evidence: list[LinkEvidence] = []
    signals = {
        "host_score": 0.0,
        "user_score": 0.0,
        "ip_score": 0.0,
        "temporal_score": 0.0,
        "mitre_score": 0.0,
        "family_score": 0.0,
    }
    score = 0.0
    rejection_reasons: list[str] = []

    seed_fam = alert_family(seed)
    cand_fam = alert_family(candidate)
    same_family = seed_fam == cand_fam and seed_fam not in {"general", "risk"}
    cross_domain = (
        seed_fam != cand_fam
        and seed_fam not in {"general", "risk"}
        and cand_fam not in {"general", "risk"}
    )
    required = DEFAULT_CROSS_DOMAIN_THRESHOLD if cross_domain else threshold
    independence = assess_evidence_independence(seed, candidate)

    # --- Level 1 entities -------------------------------------------------
    if shared_hosts:
        signals["host_score"] = WEIGHT_HOST
        score += WEIGHT_HOST
        evidence.append(LinkEvidence("shared_host", shared_hosts[0], WEIGHT_HOST))
    if shared_users:
        signals["user_score"] = WEIGHT_USER
        score += WEIGHT_USER
        evidence.append(LinkEvidence("shared_user", shared_users[0], WEIGHT_USER))
    if shared_ips:
        if same_family:
            w = WEIGHT_IP_SAME_FAMILY
        elif shared_hosts or shared_users:
            w = WEIGHT_IP_WITH_HOST_OR_USER
        else:
            w = WEIGHT_IP_ONLY_CROSS_FAMILY
        signals["ip_score"] = w
        score += w
        evidence.append(LinkEvidence("shared_ip", shared_ips[0], w))

    # No Level-1 entity overlap → never link.
    if not (shared_hosts or shared_users or shared_ips):
        rejection_reasons.append("no_shared_entity")
        return _reject(
            correlation_type="rejected_no_shared_entity",
            matched=matched,
            delta=None,
            shared_tech=[],
            score=0.0,
            evidence=evidence,
            reason="No shared host, user, or IP — cannot correlate.",
            rejection_reasons=rejection_reasons,
            seed_fam=seed_fam,
            cand_fam=cand_fam,
            cross_domain=cross_domain,
            threshold=required,
            signals=signals,
            independence=independence,
        )

    # Cross-domain: require host or user — IP-only insufficient.
    if cross_domain and not (shared_hosts or shared_users):
        rejection_reasons.append("cross_domain_ip_only")
        return _reject(
            correlation_type="rejected_cross_domain_without_host_user",
            matched=matched,
            delta=None,
            shared_tech=[],
            score=score,
            evidence=evidence,
            reason=(
                f"Cross-domain ({seed_fam}↔{cand_fam}) requires shared host or user; "
                f"IP/severity alone is insufficient."
            ),
            rejection_reasons=rejection_reasons,
            seed_fam=seed_fam,
            cand_fam=cand_fam,
            cross_domain=True,
            threshold=required,
            signals=signals,
            independence=independence,
        )

    # --- Mandatory temporal window ----------------------------------------
    ta, tb = _ts(seed), _ts(candidate)
    delta: int | None = None
    if ta is None or tb is None:
        rejection_reasons.append("missing_timestamp")
        return _reject(
            correlation_type="rejected_missing_timestamp",
            matched=matched,
            delta=None,
            shared_tech=[],
            score=score,
            evidence=evidence,
            reason="Missing event_time/created_at — timestamps required for campaign link.",
            rejection_reasons=rejection_reasons,
            seed_fam=seed_fam,
            cand_fam=cand_fam,
            cross_domain=cross_domain,
            threshold=required,
            signals=signals,
            independence=independence,
        )
    delta = int(abs(ta - tb))
    # Inclusive boundary: delta <= window is inside.
    if delta > temporal_window_seconds:
        rejection_reasons.append("outside_temporal_window")
        return _reject(
            correlation_type="rejected_outside_temporal_window",
            matched=matched,
            delta=delta,
            shared_tech=[],
            score=score,
            evidence=evidence,
            reason=(
                f"Time delta {delta}s exceeds window {temporal_window_seconds}s."
            ),
            rejection_reasons=rejection_reasons,
            seed_fam=seed_fam,
            cand_fam=cand_fam,
            cross_domain=cross_domain,
            threshold=required,
            signals=signals,
            independence=independence,
        )
    proximity = max(0.0, 1.0 - (delta / max(temporal_window_seconds, 1)))
    # Closer events score higher; identical timestamps get full temporal weight.
    tw = WEIGHT_TEMPORAL_MAX * (0.4 + 0.6 * proximity)
    signals["temporal_score"] = round(tw, 4)
    score += tw
    evidence.append(LinkEvidence("temporal_proximity", f"delta_s={delta}", round(tw, 4)))

    # --- Boosters (only with entity evidence already present) -------------
    seed_tech = {
        str(t).strip().lower()
        for t in (seed.get("mitre_techniques") or [])
        if str(t).strip()
    }
    cand_tech = {
        str(t).strip().lower()
        for t in (candidate.get("mitre_techniques") or [])
        if str(t).strip()
    }
    shared_tech = sorted(seed_tech & cand_tech)
    if shared_tech:
        signals["mitre_score"] = WEIGHT_MITRE
        score += WEIGHT_MITRE
        evidence.append(LinkEvidence("shared_technique", shared_tech[0], WEIGHT_MITRE))

    if same_family:
        signals["family_score"] = WEIGHT_FAMILY
        score += WEIGHT_FAMILY
        evidence.append(LinkEvidence("same_detection_family", seed_fam, WEIGHT_FAMILY))

    # Duplicate lineage: do not treat as independent corroboration.
    if independence == "duplicate":
        rejection_reasons.append("duplicate_lineage")
        return _reject(
            correlation_type="rejected_duplicate_lineage",
            matched=matched,
            delta=delta,
            shared_tech=shared_tech,
            score=score,
            evidence=evidence,
            reason="Same raw-event lineage — not independent corroboration.",
            rejection_reasons=rejection_reasons,
            seed_fam=seed_fam,
            cand_fam=cand_fam,
            cross_domain=cross_domain,
            threshold=required,
            signals=signals,
            independence=independence,
        )

    raw_score = score
    final_score = round(min(1.0, max(0.0, score)), 4)
    risk_cand = is_risk_supporting_alert(candidate)
    risk_seed = is_risk_supporting_alert(seed)

    # --- Risk candidate → supporting only ---------------------------------
    if risk_cand and not risk_seed:
        supporting_threshold = max(SUPPORTING_FLOOR, required - SUPPORTING_THRESHOLD_OFFSET)
        linked = final_score >= supporting_threshold and bool(evidence)
        if not linked:
            rejection_reasons.append("risk_below_supporting_threshold")
        return CampaignLinkDecision(
            linked=linked,
            correlation_type="supporting_risk_context" if linked else "below_threshold",
            matched_entities=matched,
            time_difference_seconds=delta,
            shared_techniques=shared_tech,
            correlation_score=final_score,
            evidence_refs=evidence,
            decision_reason=(
                "Risk/threshold alert attached as supporting context only "
                "(not independent attack evidence)."
                if linked
                else (
                    f"Risk alert score {final_score} below supporting "
                    f"threshold {supporting_threshold}."
                )
            ),
            confidence=final_score,
            role="supporting" if linked else "rejected",
            seed_family=seed_fam,
            candidate_family=cand_fam,
            cross_domain=cross_domain,
            signals=signals,
            raw_score=round(raw_score, 4),
            final_score=final_score,
            threshold=supporting_threshold,
            rejection_reasons=rejection_reasons,
            evidence_independence=independence,
        )

    if risk_seed and not risk_cand:
        if not (shared_hosts or shared_users):
            rejection_reasons.append("risk_seed_weak_attach")
            return _reject(
                correlation_type="rejected_risk_seed",
                matched=matched,
                delta=delta,
                shared_tech=shared_tech,
                score=raw_score,
                evidence=evidence,
                reason="Campaign seed is a Risk rollup; refusing weak attach.",
                rejection_reasons=rejection_reasons,
                seed_fam=seed_fam,
                cand_fam=cand_fam,
                cross_domain=cross_domain,
                threshold=required,
                signals=signals,
                independence=independence,
            )

    linked = final_score >= required and bool(evidence)
    if not linked:
        rejection_reasons.append("below_threshold")
    reason = (
        f"Linked via {[e.type for e in evidence]} score={final_score} "
        f"(threshold={required}, families={seed_fam}/{cand_fam})."
        if linked
        else f"Score {final_score} below threshold {required} or insufficient evidence."
    )
    return CampaignLinkDecision(
        linked=linked,
        correlation_type="entity_and_temporal" if linked else "below_threshold",
        matched_entities=matched,
        time_difference_seconds=delta,
        shared_techniques=shared_tech,
        correlation_score=final_score,
        evidence_refs=evidence,
        decision_reason=reason,
        confidence=final_score,
        role="primary" if linked else "rejected",
        seed_family=seed_fam,
        candidate_family=cand_fam,
        cross_domain=cross_domain,
        signals=signals,
        raw_score=round(raw_score, 4),
        final_score=final_score,
        threshold=required,
        rejection_reasons=rejection_reasons,
        evidence_independence=independence,
    )


def select_campaign_siblings(
    seed: dict[str, Any],
    candidates: list[dict[str, Any]],
    *,
    temporal_window_seconds: int = DEFAULT_TEMPORAL_WINDOW_SECONDS,
    threshold: float = DEFAULT_LINK_THRESHOLD,
    limit: int = SIBLING_HARD_CAP,
    enforce_candidate_eligibility: bool = True,
    ignore_case_membership: bool = False,
    use_host_centric_discovery: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (accepted_rows_with_decision, all_decisions).

    Flow:
    1. Reject Risk seeds (no attack sibling expansion).
    2. Host-Centric discovery on the seed host (exact normalized match).
    3. Merge with entity-overlap (user/IP/host) discovery — complementary.
    4. Deduplicate by alert id.
    5. Score every candidate **pairwise against the seed only** (no transitive).
    6. Keep linked=True; sort primary→supporting→score→id; cap at ``limit``.

    Discovery ≠ linking: same-host candidates still must pass
    ``score_campaign_link`` (incl. cross-domain 0.70).
    """
    decisions: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    seed_hosts = extract_alert_hosts(seed)
    if is_risk_supporting_alert(seed):
        return [], [
            {
                "alert_id": str(seed.get("id")),
                "linked": False,
                "decision_reason": "Seed is Risk/threshold rollup — solo or supporting only.",
                "role": "rejected",
                "algorithm_version": CORRELATION_VERSION,
                "rejection_reasons": ["risk_seed_no_siblings"],
                "discovery_path": "host_centric_blocked_risk_seed",
                "seed_hosts": seed_hosts,
                "time_window_seconds": temporal_window_seconds,
            }
        ]

    # --- Candidate discovery (all seed hosts + entity overlap; score once) -
    # meta[id] = {row, paths: list[str], matched_hosts: set[str]}
    meta: dict[str, dict[str, Any]] = {}

    def _merge_discovery(
        row: dict[str, Any],
        *,
        paths: list[str],
        matched_hosts: list[str] | None = None,
    ) -> None:
        cid = str(row.get("id") or "")
        if not cid:
            return
        entry = meta.get(cid)
        if entry is None:
            entry = {
                "row": dict(row),
                "paths": [],
                "matched_hosts": set(),
            }
            meta[cid] = entry
        for p in paths:
            if p and p not in entry["paths"]:
                entry["paths"].append(p)
        for h in matched_hosts or row.get("_matched_hosts") or []:
            if h:
                entry["matched_hosts"].add(str(h))

    if use_host_centric_discovery:
        # Cover **all** valid seed hosts (not only primary_seed_host).
        if seed_hosts:
            host_hits = find_host_related_alerts(
                seed,
                candidates,
                temporal_window_seconds=temporal_window_seconds,
                enforce_candidate_eligibility=enforce_candidate_eligibility,
                ignore_case_membership=ignore_case_membership,
            )
            for row in host_hits:
                _merge_discovery(
                    row,
                    paths=["host_centric"],
                    matched_hosts=list(row.get("_matched_hosts") or []),
                )
        # Do NOT exclude host hits — merge entity_overlap path when also shared IP/user.
        overlap = find_entity_overlap_alerts(
            seed,
            candidates,
            temporal_window_seconds=temporal_window_seconds,
            enforce_candidate_eligibility=enforce_candidate_eligibility,
            ignore_case_membership=ignore_case_membership,
            exclude_ids=None,
        )
        for row in overlap:
            paths = list(row.get("_discovery_paths") or [row.get("_discovery_path") or "entity_overlap"])
            # If already host-discovered, keep host_centric and add entity_overlap
            # only when there is non-host entity evidence (user/IP).
            cid = str(row.get("id") or "")
            seed_e = _entity_sets(seed)
            cand_e = _entity_sets(row)
            extra: list[str] = []
            if seed_e["users"] & cand_e["users"] or seed_e["ips"] & cand_e["ips"]:
                if "entity_overlap" not in paths and "host_centric" in (
                    meta.get(cid, {}).get("paths") or paths
                ):
                    extra.append("entity_overlap")
            _merge_discovery(
                row,
                paths=paths + extra,
                matched_hosts=list(row.get("_matched_hosts") or []),
            )
    else:
        for cand in candidates:
            cid = str(cand.get("id") or "")
            if not cid or cid == str(seed.get("id")):
                continue
            _merge_discovery(dict(cand), paths=["provided"])

    # Deterministic order by alert id; score each unique candidate once.
    for cid in sorted(meta.keys()):
        entry = meta[cid]
        cand = entry["row"]
        paths = list(entry["paths"]) or ["provided"]
        path = (
            "host_centric"
            if "host_centric" in paths
            else (paths[0] if paths else "provided")
        )
        matched_hosts = sorted(entry["matched_hosts"])
        if enforce_candidate_eligibility:
            ok, why = is_candidate_eligible(
                cand, ignore_case_membership=ignore_case_membership
            )
            if not ok:
                decisions.append(
                    {
                        "alert_id": cid,
                        "linked": False,
                        "role": "rejected",
                        "correlation_type": "rejected_candidate_eligibility",
                        "decision_reason": why,
                        "rejection_reasons": [why],
                        "correlation_score": 0.0,
                        "algorithm_version": CORRELATION_VERSION,
                        "discovery_path": path,
                        "discovery_paths": paths,
                        "seed_hosts": seed_hosts,
                        "candidate_hosts": extract_alert_hosts(cand),
                        "matched_hosts": matched_hosts,
                        "time_window_seconds": temporal_window_seconds,
                    }
                )
                continue
        decision = score_campaign_link(
            seed,
            cand,
            temporal_window_seconds=temporal_window_seconds,
            threshold=threshold,
        )
        # Annotate discovery without altering score math (no double-count).
        decision.discovery_path = path
        decision.discovery_paths = paths
        decision.time_window_seconds = temporal_window_seconds
        decision.seed_hosts = list(seed_hosts)
        decision.candidate_hosts = extract_alert_hosts(cand)
        decision.matched_hosts = matched_hosts or hosts_exact_match(
            seed_hosts, decision.candidate_hosts
        )
        if path == "host_centric" and decision.linked:
            decision.correlation_type = "host_centric"
        elif path == "host_centric" and not decision.linked:
            if decision.correlation_type.startswith("rejected") or decision.correlation_type == "below_threshold":
                decision.correlation_type = f"host_centric_{decision.correlation_type}"
        if (
            path == "host_centric"
            and decision.cross_domain
            and not decision.linked
            and "below_threshold" in (decision.rejection_reasons or [])
        ):
            if "cross_domain_threshold_not_met" not in decision.rejection_reasons:
                decision.rejection_reasons.append("cross_domain_threshold_not_met")
        payload = decision.to_dict()
        payload["alert_id"] = cid
        payload["normalized_host_match"] = list(decision.matched_hosts)
        decisions.append(payload)
        if decision.linked:
            row = dict(cand)
            row["_correlation"] = payload
            accepted.append(row)

    accepted.sort(
        key=lambda r: (
            0 if (r.get("_correlation") or {}).get("role") == "primary" else 1,
            -float((r.get("_correlation") or {}).get("correlation_score") or 0),
            str(r.get("id") or ""),
        )
    )
    return accepted[: max(0, int(limit))], decisions
