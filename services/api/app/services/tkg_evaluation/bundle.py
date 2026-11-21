"""Build the frozen payload a TKG evaluation is judged on.

The payload is deliberately the *alerts only*: no case narrative, no analyst
notes, no previous verdict. If the model saw the analyst's conclusion it would
agree with it, and the second opinion would be worthless. What a reviewer later
needs is exactly what the model saw — hence the fingerprint stored on the row.

Input shape
-----------
AiSOC stores the Splunk ESCU payload as JSON. Current payloads look like::

    {"llm_payload": "{\\"alert_fields\\": {\\"dest\\": \\"win-dc-01.corp.local\\",
                       \\"user\\": \\"administrator\\", ...},
                     \\"annotations\\": {\\"mitre_attack\\": \\"T1649\\"},
                     \\"entity\\": \\"administrator\\", \\"entity_type\\": \\"user\\",
                     \\"rule_name\\": \\"ESCU - ...\\", \\"event_time\\": \\"...\\"}"}

so the extraction keys live in ``alert_fields`` (a flat dict — the older
``alert_fields.raw`` k=v blob is deprecated and deliberately not parsed) plus
``entity``/``risk_object`` and their ``*_type``. Older/other producers emit the
fields at the top level, which is why both shapes are accepted.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from app.services.tkg_evaluation.constants import (
    MAX_ALERT_CHARS,
    MAX_ALERTS,
    MAX_PAYLOAD_CHARS,
    R_NO_ALERTS,
    R_NO_PAYLOAD,
    R_PAYLOAD_TOO_LARGE,
    R_TOO_MANY_ALERTS,
    RUBRIC_VERSION,
)

#: Containers that may hold the alert's fields, most specific first.
_FIELD_CONTAINERS = ("alert_fields", "fields", "payload", "event")

#: Direct lowercased-key → identity-bucket mapping.
_FIELD_MAP: dict[str, str] = {
    **dict.fromkeys(("host", "src_host", "dest_host", "hostname", "computername", "computer_name"), "hosts"),
    **dict.fromkeys(("user", "src_user", "dest_user", "user_name", "username", "account_name"), "users"),
    **dict.fromkeys(("src_ip", "dest_ip", "dst_ip", "ip", "ip_address", "src_ipv4", "dest_ipv4"), "ips"),
    **dict.fromkeys(("dest_nt_domain", "domain", "domain_name", "dns_query", "query"), "domains"),
    **dict.fromkeys(("url", "uri", "http_url", "request_url"), "urls"),
    **dict.fromkeys(("file_hash", "md5", "sha1", "sha256", "process_hash", "hash"), "hashes"),
    **dict.fromkeys(("process_name", "parent_process_name", "image", "parent_process"), "processes"),
    **dict.fromkeys(("command_line", "process", "parent_process_exec", "process_exec"), "commands"),
}

#: ``entity_type`` / ``risk_object_type`` → bucket.
_ENTITY_TYPES: dict[str, str] = {
    "user": "users",
    "users": "users",
    "identity": "users",
    "host": "hosts",
    "hosts": "hosts",
    "hostname": "hosts",
    "asset": "hosts",
    "ip": "ips",
    "ip_address": "ips",
    "ipv4": "ips",
    "domain": "domains",
    "domain_name": "domains",
    "url": "urls",
    "process": "processes",
    "file": "hashes",
}

#: Technique keys, checked at every level of the payload.
_TECHNIQUE_KEYS = ("mitre_attack", "mitre_technique_id", "technique_id", "techniqueid", "techniques", "mitre")

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_FQDN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{1,252}[A-Za-z0-9])?$")
_BINARY_SUFFIX = re.compile(r"\.(exe|dll|sys|tmp|ps1|bat|zip|log|dat|bin|txt)$", re.IGNORECASE)
_TOKENISH = re.compile(r"^[A-Za-z0-9@._:/\\-]{2,300}$")
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

#: Keys never copied, even if the payload carries them.
_SECRET_HINTS = ("password", "passwd", "secret", "token", "api_key", "apikey", "credential")


# --------------------------------------------------------------------------- #
# Low-level scraping
# --------------------------------------------------------------------------- #
def _loads(value: Any) -> Any:
    """Parse a JSON string if that is what the column holds; else pass through."""

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        if text[0] in "{[":
            try:
                return json.loads(text)
            except ValueError:
                return {}
        return {}
    return value


def _inner_payload(raw: Any) -> Mapping[str, Any]:
    """Accept ``{llm_payload: "<json>"}``, a bare JSON string, or a plain dict."""

    value = _loads(raw)
    for _ in range(2):  # payload → llm_payload → payload, bounded on purpose
        if not isinstance(value, Mapping):
            return {}
        nested = value.get("llm_payload")
        if isinstance(nested, (str, Mapping)) and _loads(nested):
            value = _loads(nested)
            continue
        break
    return value if isinstance(value, Mapping) else {}


def _scalar(value: Any) -> str | None:
    """A single copyable token, or ``None`` for nulls/placeholders/containers."""

    if value is None or isinstance(value, (bool, dict, list)):
        return None
    text = str(value).strip().strip('"').strip("'").strip()
    if not text or text.lower() in {"null", "none", "n/a", "na", "-", "0", "0x0", "unknown"}:
        return None
    if len(text) > 300 or not _TOKENISH.match(text):
        return None
    return text


def _command(value: Any) -> str | None:
    """Command lines legitimately contain spaces; everything else is a token."""

    if value is None or isinstance(value, (bool, dict, list)):
        return None
    text = str(value).strip()
    if not text or text.lower() in {"null", "none"}:
        return None
    return text[:300]


def _classify_ambiguous(value: str) -> str:
    """``dest``/``src`` carry an IP, an FQDN or a hostname — decide by shape."""

    if _IPV4.fullmatch(value):
        return "ips"
    if _FQDN.match(value) and "." in value and not _BINARY_SUFFIX.search(value):
        return "domains"
    return "hosts"


def _candidate_sources(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    sources: list[Mapping[str, Any]] = []
    for key in _FIELD_CONTAINERS:
        container = payload.get(key)
        if isinstance(container, Mapping) and container:
            sources.append(container)
    if not sources:
        sources.append(payload)
    return sources


def _add(bucket: dict[str, list[str]], kind: str, value: str | None) -> None:
    if not value:
        return
    values = bucket.setdefault(kind, [])
    if value not in values and len(values) < 24:
        values.append(value)


def _techniques(payload: Mapping[str, Any]) -> list[str]:
    found: list[str] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 3:
            return
        if isinstance(node, Mapping):
            for key, value in node.items():
                lowered = str(key).lower()
                if lowered in _TECHNIQUE_KEYS:
                    found.extend(_collect_technique_values(value))
                elif isinstance(value, (Mapping, list)):
                    walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:20]:
                walk(item, depth + 1)

    walk(payload)
    ordered: dict[str, None] = {}
    for technique in found:
        ordered.setdefault(technique, None)
    return list(ordered)[:12]


def _collect_technique_values(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, (list, tuple, set)):
        for item in value:
            found.extend(_collect_technique_values(item))
        return found
    if isinstance(value, Mapping):
        return found
    text = str(value or "")
    return _TECHNIQUE.findall(text.upper())


def _payload_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Identity + technique keys, in the compact shape the DTO uses."""

    bucket: dict[str, list[str]] = {}

    for source in _candidate_sources(payload):
        lowered = {str(key).lower(): value for key, value in source.items()}

        for key, kind in _FIELD_MAP.items():
            value = lowered.get(key)
            if value is None:
                continue
            if kind == "commands":
                _add(bucket, "commands", _command(value))
                continue
            if isinstance(value, (list, tuple, set)):
                for item in list(value)[:8]:
                    _add(bucket, kind, _scalar(item))
                continue
            _add(bucket, kind, _scalar(value))

        # ``dest``/``src`` are untyped: classify by shape instead of guessing.
        # An FQDN endpoint counts as both the host and the domain it resolves to,
        # which is how the correlation engine tokenises ``host:``/``domain:``.
        for key in ("dest", "src", "destination", "source"):
            candidate = _scalar(lowered.get(key))
            if not candidate:
                continue
            kind = _classify_ambiguous(candidate)
            _add(bucket, kind, candidate)
            if kind == "domains":
                _add(bucket, "hosts", candidate)

        # The notable's own entity (newer payloads carry it explicitly).
        for value_key, type_key in (("entity", "entity_type"), ("risk_object", "risk_object_type")):
            candidate = _scalar(lowered.get(value_key))
            if not candidate:
                continue
            declared = _scalar(lowered.get(type_key))
            kind = _ENTITY_TYPES.get((declared or "").lower())
            resolved = kind or _classify_ambiguous(candidate)
            _add(bucket, resolved, candidate)
            if resolved == "domains":
                _add(bucket, "hosts", candidate)

    fields: dict[str, Any] = {kind: values for kind, values in bucket.items() if values}

    techniques = _techniques(payload)
    if techniques:
        fields["techniques"] = techniques
    return fields


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def normalize_alert(row: Mapping[str, Any]) -> dict[str, Any]:
    """One alert → the compact item the TKG (and the judge) sees."""

    payload = _inner_payload(row.get("llm_payload") or {})
    rule = payload.get("rule") if isinstance(payload.get("rule"), Mapping) else {}

    fields = _payload_fields(payload)
    event_time = row.get("event_time") or payload.get("event_time") or payload.get("alert_time")
    if isinstance(event_time, datetime):
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=UTC)
        event_time = event_time.isoformat()
    elif event_time is not None:
        event_time = str(event_time)

    row_id = str(row.get("id") or "")
    notable_id = str(payload.get("alert_id") or row_id or "")
    stage = str(row.get("funnel_stage") or "").strip()

    item: dict[str, Any] = {
        "alert_id": row_id or notable_id,
        # The identity the graph was fed with: ingestion used the Splunk notable
        # id carried inside the payload, which can differ from the stored row id.
        "notable_id": notable_id,
        "time": event_time,
        "title": str(row.get("title") or rule.get("title") or "")[:300],
        "severity": row.get("severity") or payload.get("severity"),
        "rule": str(rule.get("name") or rule.get("title") or payload.get("rule_name") or row.get("rule_name") or "")[:200] or None,
        "techniques": _merge_techniques(fields.pop("techniques", []), row.get("mitre_techniques")),
    }
    if stage:
        item["funnel_stage"] = stage
    if stage == "deduplicated":
        # Soft-dedup witness: still evidence the engine scores, but a reviewer
        # (and the model) must see that it is not an independent observation.
        item["deduplicated"] = True
        occurrences = row.get("occurrence_count")
        if isinstance(occurrences, int) and occurrences > 1:
            item["occurrence_count"] = occurrences
    item.update({key: value for key, value in fields.items() if value})

    encoded = json.dumps(item, default=str, ensure_ascii=False)
    if len(encoded) > MAX_ALERT_CHARS:
        # Trim the widest lists first; the time/title/rule stay intact.
        for key in ("urls", "commands", "hashes", "processes", "domains", "ips", "hosts", "users"):
            values = item.get(key) or []
            if isinstance(values, list) and len(values) > 4:
                item[key] = values[:4]
        item["truncated"] = True
    return item


def _merge_techniques(from_payload: Iterable[str], from_row: Any) -> list[str]:
    merged: dict[str, None] = {}
    for technique in list(from_payload) + list(from_row or []):
        value = str(technique).strip().upper()
        if value:
            merged.setdefault(value, None)
    return list(merged)[:12]


def _compact(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Authority-only view of one alert, for oversized cases.

    Keeps identity, time, rule, techniques and the dedup marker; caps every
    entity list to three values. The TKG resolves by ``notable_id``, so this is
    enough to attribute the alert — the verdict does not depend on the tail of
    a host list.
    """

    compact: dict[str, Any] = {
        "alert_id": alert.get("alert_id"),
        "notable_id": alert.get("notable_id"),
        "time": alert.get("time"),
        "title": str(alert.get("title") or "")[:160],
        "severity": alert.get("severity"),
        "rule": str(alert.get("rule") or "")[:120] or None,
        "techniques": list(alert.get("techniques") or [])[:6],
        "truncated": True,
    }
    for kind in ("hosts", "users", "ips", "domains", "urls", "hashes", "processes"):
        values = alert.get(kind)
        if isinstance(values, list) and values:
            compact[kind] = values[:3]
    if alert.get("deduplicated"):
        compact["deduplicated"] = True
        if alert.get("occurrence_count"):
            compact["occurrence_count"] = alert["occurrence_count"]
    return compact


def fingerprint(alerts: Iterable[Mapping[str, Any]]) -> str:
    """Stable hash of the alert set — the cache key for repeated evaluations."""

    canonical = json.dumps(sorted(alerts, key=lambda a: str(a.get("alert_id"))), sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_bundle(
    *,
    case: Mapping[str, Any],
    alerts: Iterable[Mapping[str, Any]],
    scope: Mapping[str, Any] | None = None,
    max_alerts: int = MAX_ALERTS,
    max_chars: int = MAX_PAYLOAD_CHARS,
) -> dict[str, Any]:
    """Assemble the input payload, or explain why it cannot be sent.

    Returns ``{"ok": bool, "payload": {...} | None, "reason": code | None,
    "stats": {...}}``. Nothing raises: a case with unusable evidence is a
    *reported* ineligibility, not a 500.
    """

    rows = list(alerts)
    if not rows:
        return {"ok": False, "payload": None, "reason": R_NO_ALERTS, "stats": {"alerts": 0}}

    normalized = [normalize_alert(row) for row in rows]
    normalized.sort(key=lambda a: (a.get("time") or "", a["alert_id"]))

    without_payload = [
        alert["alert_id"]
        for alert in normalized
        if not any(key in alert for key in ("hosts", "users", "ips", "domains", "urls", "hashes", "processes", "commands"))
    ]
    if len(without_payload) == len(normalized):
        return {
            "ok": False,
            "payload": None,
            "reason": R_NO_PAYLOAD,
            "stats": {"alerts": len(normalized), "without_payload": len(without_payload)},
        }

    # The cap protects the graph from a genuinely wide case, so it counts the
    # *distinct* observations only. Soft-dedup witnesses are repeats of an alert
    # already in the set: a campaign with three real alerts and several hundred
    # repeats is still a three-alert case, and refusing it would throw away the
    # verdict the three canonical alerts can earn.
    canonical = [alert for alert in normalized if not alert.get("deduplicated")]
    deduplicated = len(normalized) - len(canonical)
    if len(canonical) > max_alerts:
        return {
            "ok": False,
            "payload": None,
            "reason": R_TOO_MANY_ALERTS,
            "stats": {
                "alerts": len(normalized),
                "canonical": len(canonical),
                "deduplicated": deduplicated,
                "max_alerts": max_alerts,
            },
            "detail": (
                f"{len(canonical)} distinct alert(s) exceed AISOC_TKG_MAX_ALERTS={max_alerts} "
                f"({deduplicated} duplicate witness(es) do not count toward the cap)"
            ),
        }

    times = [alert["time"] for alert in normalized if alert.get("time")]
    payload = {
        "schema_version": RUBRIC_VERSION,
        "case": {
            "id": str(case.get("id")),
            "title": str(case.get("title") or "")[:300],
            "severity": case.get("severity"),
            "alert_count": len(normalized),
            "time_first": times[0] if times else None,
            "time_last": times[-1] if times else None,
        },
        "scope": dict(scope or {}),
        "alerts": normalized,
    }

    size = len(json.dumps(payload, default=str, ensure_ascii=False))
    if size > max_chars:
        # A campaign with hundreds of dedup witnesses is still one case: shrink
        # each alert to its authority fields before giving up on the payload.
        # Dropping the case would replace a real verdict with "too big".
        payload["alerts"] = [_compact(alert) for alert in normalized]
        payload["trimmed"] = True
        size = len(json.dumps(payload, default=str, ensure_ascii=False))
    if size > max_chars:
        return {
            "ok": False,
            "payload": None,
            "reason": R_PAYLOAD_TOO_LARGE,
            "stats": {"alerts": len(normalized), "chars": size, "max_chars": max_chars},
        }

    return {
        "ok": True,
        "payload": payload,
        "reason": None,
        "stats": {
            "alerts": len(normalized),
            "chars": size,
            "without_payload": len(without_payload),
            "canonical": len(canonical),
            "deduplicated": deduplicated,
            "fingerprint": fingerprint(normalized),
        },
    }
