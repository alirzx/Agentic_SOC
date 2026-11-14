"""Layer 2 — Entity-aware logical alert identity.

Excludes mutable fields (severity, disposition). Different hosts/users stay
separate. Missing entities use typed sentinels so unknowns do not collapse
across unrelated alerts of the same rule.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

ALERT_IDENTITY_VERSION = "alert:v1"

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_SID_RE = re.compile(r"^S-1-\d+(-\d+)+$", re.IGNORECASE)
_NONE = {"", "none", "null", "n/a", "-", "—", "unknown"}


def _norm_text(value: Any) -> str:
    text = str(value or "").strip().strip("'\"")
    if not text or text.lower() in _NONE:
        return ""
    return text


def _norm_ip(value: Any) -> str:
    text = _norm_text(value)
    if not text:
        return ""
    text = text.strip("[]")
    if "/" in text:
        text = text.split("/", 1)[0]
    if not _IPV4_RE.match(text) and ":" not in text:
        return ""
    return text.lower()


def _norm_host(value: Any) -> str:
    text = _norm_text(value)
    if not text:
        return ""
    # Do not treat IPs as hosts here — callers split roles.
    if _IPV4_RE.match(text) or (":" in text and text.count(":") >= 2):
        return ""
    return text.lower().rstrip(".")


def _norm_user(value: Any) -> str:
    text = _norm_text(value)
    if not text:
        return ""
    if _SID_RE.match(text):
        return text.upper()
    return text.lower()


def _norm_hash(value: Any) -> str:
    text = _norm_text(value)
    if text and _HASH_RE.match(text):
        return text.lower()
    return ""


def _first_list(values: Any) -> list[Any]:
    if values is None:
        return []
    if isinstance(values, list):
        return values
    return [values]


def _from_alert_fields(row: dict[str, Any]) -> dict[str, Any]:
    payload = row.get("llm_payload") if isinstance(row.get("llm_payload"), dict) else {}
    fields = payload.get("alert_fields") if isinstance(payload.get("alert_fields"), dict) else {}
    raw = row.get("raw_event") if isinstance(row.get("raw_event"), dict) else {}
    nested = {}
    for blob in (payload, raw, row.get("enrichment_data")):
        if isinstance(blob, dict):
            af = blob.get("alert_fields")
            if isinstance(af, dict):
                nested.update(af)
    nested.update(fields)
    return nested


def extract_identity_entities(row: dict[str, Any]) -> dict[str, list[str]]:
    """Extract typed entities used for Layer-2 identity (multi-value, deduped)."""
    af = _from_alert_fields(row)
    hosts: list[str] = []
    users: list[str] = []
    src_ips: list[str] = []
    dst_ips: list[str] = []
    hashes: list[str] = []
    processes: list[str] = []
    domains: list[str] = []

    def add(bucket: list[str], value: str) -> None:
        if value and value not in bucket:
            bucket.append(value)

    for key in ("hostname", "host", "dvc", "Computer", "computer", "dest_host", "endpoint"):
        add(hosts, _norm_host(row.get(key) or af.get(key)))
    # extracted_host is a separate alias — keep out of primary host identity unless alone
    for item in _first_list(row.get("affected_hosts")):
        if isinstance(item, dict):
            add(hosts, _norm_host(item.get("value") or item.get("host")))
        else:
            add(hosts, _norm_host(item))

    for key in ("username", "user", "src_user", "user_id", "User", "account"):
        add(users, _norm_user(row.get(key) or af.get(key)))
    for item in _first_list(row.get("affected_users")):
        if isinstance(item, dict):
            add(users, _norm_user(item.get("value") or item.get("user")))
        else:
            add(users, _norm_user(item))

    for key in ("src_ip", "src", "source_ip", "client_ip"):
        add(src_ips, _norm_ip(row.get(key) or af.get(key)))
    for key in ("dest_ip", "dst_ip", "destination_ip", "dst"):
        add(dst_ips, _norm_ip(row.get(key) or af.get(key)))
    for item in _first_list(row.get("affected_ips")):
        if isinstance(item, dict):
            add(src_ips, _norm_ip(item.get("value") or item.get("ip")))
        else:
            add(src_ips, _norm_ip(item))

    for key in ("file_hash", "sha256", "sha1", "md5", "hash"):
        add(hashes, _norm_hash(row.get(key) or af.get(key)))
    for ioc in _first_list(row.get("iocs")):
        if not isinstance(ioc, dict):
            continue
        kind = str(ioc.get("type") or ioc.get("kind") or "").lower()
        val = ioc.get("value") or ioc.get("ip") or ioc.get("hash")
        if kind in {"ip", "ipv4", "ipv6", "address"}:
            add(dst_ips, _norm_ip(val))
        elif kind in {"hash", "sha256", "sha1", "md5", "filehash"}:
            add(hashes, _norm_hash(val))
        elif kind in {"domain", "dns"}:
            add(domains, _norm_host(val))

    for key in ("process_name", "process", "Image", "ParentImage"):
        p = _norm_text(row.get(key) or af.get(key))
        if p:
            add(processes, p.lower())

    for key in ("domain", "query", "url_domain"):
        add(domains, _norm_host(row.get(key) or af.get(key)))

    alias_host = _norm_host(af.get("extracted_host") or row.get("extracted_host"))
    alias_hosts: list[str] = []
    if alias_host:
        if not hosts:
            # Only promote alias into primary hosts when no verified host exists.
            add(hosts, alias_host)
        elif alias_host not in hosts:
            # Preserve SH2 vs FQDN Computer as distinct — never equate silently.
            alias_hosts.append(alias_host)

    return {
        "hosts": hosts,
        "users": users,
        "src_ips": src_ips,
        "dst_ips": dst_ips,
        "hashes": hashes,
        "processes": processes,
        "domains": domains,
        "alias_hosts": alias_hosts,
    }


def _rule_identity(row: dict[str, Any]) -> str:
    rule_id = _norm_text(row.get("rule_id")).lower()
    if rule_id:
        return f"id:{rule_id}"
    rule_name = _norm_text(row.get("rule_name") or row.get("title")).lower()
    return f"name:{rule_name}" if rule_name else "name:"


def _primary_entity_token(entities: dict[str, list[str]]) -> str:
    """Stable primary entity for identity — prefer host, then user, then IPs, then hash."""
    if entities["hosts"]:
        return f"host:{entities['hosts'][0]}"
    if entities["users"]:
        return f"user:{entities['users'][0]}"
    if entities["dst_ips"]:
        return f"dst:{entities['dst_ips'][0]}"
    if entities["src_ips"]:
        return f"src:{entities['src_ips'][0]}"
    if entities["hashes"]:
        return f"hash:{entities['hashes'][0]}"
    if entities["domains"]:
        return f"domain:{entities['domains'][0]}"
    if entities["processes"]:
        return f"proc:{entities['processes'][0]}"
    # Typed unknown — includes rule in outer key so different rules stay apart,
    # but same-rule unknowns without entities still share a bucket (rare).
    return "entity:unknown"


def alert_logical_key_parts(row: dict[str, Any]) -> dict[str, Any]:
    """Structured parts for hashing / explainability (no severity/disposition)."""
    entities = extract_identity_entities(row)
    tenant = str(row.get("tenant_id") or "").strip().lower()
    source = _norm_text(row.get("connector_type") or row.get("source") or "").lower()
    payload = row.get("llm_payload") if isinstance(row.get("llm_payload"), dict) else {}
    detection_type = _norm_text(
        row.get("detection_type") or payload.get("detection_type")
    ).lower()
    security_domain = _norm_text(
        row.get("security_domain") or payload.get("security_domain")
    ).lower()
    return {
        "v": ALERT_IDENTITY_VERSION,
        "tenant_id": tenant,
        "source": source,
        "rule": _rule_identity(row),
        "detection_type": detection_type,
        "security_domain": security_domain,
        "primary_entity": _primary_entity_token(entities),
        # Secondary anchors reduce false merges when primary is sparse.
        "hosts": entities["hosts"][:5],
        "users": entities["users"][:5],
        "src_ips": entities["src_ips"][:5],
        "dst_ips": entities["dst_ips"][:5],
        "hashes": entities["hashes"][:3],
    }


def alert_logical_key(row: dict[str, Any]) -> str:
    """Versioned SHA-256 logical alert identity (Layer 2)."""
    parts = alert_logical_key_parts(row)
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{ALERT_IDENTITY_VERSION}:{digest}"


def within_dedup_window(
    a: dict[str, Any],
    b: dict[str, Any],
    *,
    window_seconds: int,
) -> bool:
    """True when event/created times of a and b fall within the window."""
    def _ts(row: dict[str, Any]) -> float | None:
        for key in ("event_time", "created_at", "first_seen_at"):
            val = row.get(key)
            if val is None:
                continue
            if hasattr(val, "timestamp"):
                return float(val.timestamp())
            try:
                from datetime import datetime

                if isinstance(val, str):
                    return datetime.fromisoformat(val.replace("Z", "+00:00")).timestamp()
            except (TypeError, ValueError):
                continue
        return None

    ta = _ts(a)
    tb = _ts(b)
    if ta is None or tb is None:
        # Without reliable times, do not expand the window arbitrarily —
        # treat as in-window only when both missing (same batch collapse).
        return ta is None and tb is None
    return abs(ta - tb) <= max(1, window_seconds)
