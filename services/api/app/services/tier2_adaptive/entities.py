"""P1 — Universal entity extraction for Tier-2 Adaptive Investigation.

Walks every common alert surface (columns, llm_payload, alert_fields, raw_event,
enrichment, IOCs, annotations, nested JSON) and emits typed entities with full
provenance. Never silently merges conflicting observed values (e.g. Computer
FQDN vs extracted_host alias).
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable
from urllib.parse import urlparse

EXTRACTOR_NAME = "tier2_adaptive.entities"
EXTRACTOR_VERSION = "entity:v1"

# Canonical entity types required by the adaptive engine.
ENTITY_TYPES: frozenset[str] = frozenset(
    {
        "ip",
        "hostname",
        "endpoint",
        "username",
        "user_sid",
        "domain",
        "process_name",
        "process_id",
        "parent_process",
        "file_path",
        "file_hash",
        "url",
        "email",
        "email_sender",
        "email_recipient",
        "network_service",
        "cloud_resource",
        "account_id",
        "database",
        "container",
        "kubernetes_workload",
        "certificate_fingerprint",
        "script_block",
        "source_event_id",
        "event_id",
    }
)

_NONE = frozenset(
    {"", "none", "null", "n/a", "-", "—", "unknown", "0.0.0.0", "::", "n/a"}
)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_SID_RE = re.compile(r"^S-1-\d+(-\d+)+$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_WIN_PATH_RE = re.compile(r"^[A-Za-z]:\\|^\\\\[^\\]+\\")
_POSIX_PATH_RE = re.compile(r"^/(?:[^/\0]+/)*[^/\0]*$")
_CERT_FP_RE = re.compile(r"^(?:[a-fA-F0-9]{2}:){19}[a-fA-F0-9]{2}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_EVENT_ID_RE = re.compile(r"^\d{1,6}$")

# Field-name → entity_type maps (case-insensitive key match).
_FIELD_MAP: dict[str, str] = {
    # Host / endpoint
    "computer": "hostname",
    "hostname": "hostname",
    "host": "hostname",
    "dvc": "hostname",
    "dest_host": "hostname",
    "endpoint": "endpoint",
    "device_name": "endpoint",
    "extracted_host": "hostname",
    # User / SID
    "username": "username",
    "user": "username",
    "src_user": "username",
    "account": "username",
    "user_name": "username",
    "user_id": "user_sid",  # often a SID in Splunk notable fields
    "sid": "user_sid",
    "usersid": "user_sid",
    "user_sid": "user_sid",
    # Domain
    "domain": "domain",
    "user_domain": "domain",
    "dns_domain": "domain",
    "query": "domain",
    "url_domain": "domain",
    # Process
    "process_name": "process_name",
    "process": "process_name",
    "image": "process_name",
    "processid": "process_id",
    "process_id": "process_id",
    "pid": "process_id",
    "parentimage": "parent_process",
    "parent_process": "parent_process",
    "parent_process_name": "parent_process",
    # File
    "path": "file_path",
    "file_path": "file_path",
    "filepath": "file_path",
    "targetfilename": "file_path",
    "filename": "file_path",
    "script_path": "file_path",
    "sha256": "file_hash",
    "sha1": "file_hash",
    "md5": "file_hash",
    "file_hash": "file_hash",
    "hash": "file_hash",
    # Network
    "src_ip": "ip",
    "source_ip": "ip",
    "client_ip": "ip",
    "attacker_ip": "ip",
    "srcip": "ip",
    "dest_ip": "ip",
    "dst_ip": "ip",
    "destination_ip": "ip",
    "server_ip": "ip",
    "destip": "ip",
    "dstip": "ip",
    "url": "url",
    "request_url": "url",
    "http_url": "url",
    "service": "network_service",
    "network_service": "network_service",
    # Email
    "email": "email",
    "sender": "email_sender",
    "email_sender": "email_sender",
    "from": "email_sender",
    "mail_from": "email_sender",
    "recipient": "email_recipient",
    "email_recipient": "email_recipient",
    "to": "email_recipient",
    "mail_to": "email_recipient",
    # Cloud / infra
    "cloud_resource": "cloud_resource",
    "resource_id": "cloud_resource",
    "arn": "cloud_resource",
    "account_id": "account_id",
    "aws_account": "account_id",
    "azure_subscription": "account_id",
    "database": "database",
    "db_name": "database",
    "container": "container",
    "container_id": "container",
    "container_name": "container",
    "kubernetes_workload": "kubernetes_workload",
    "k8s_workload": "kubernetes_workload",
    "pod_name": "kubernetes_workload",
    "deployment": "kubernetes_workload",
    "certificate_fingerprint": "certificate_fingerprint",
    "cert_fingerprint": "certificate_fingerprint",
    "tls_fingerprint": "certificate_fingerprint",
    # Evidence-style entities
    "scriptblocktext": "script_block",
    "script_block": "script_block",
    "script_block_text": "script_block",
    "source_event_id": "source_event_id",
    "event_id": "event_id",
    "eventid": "event_id",
    "eventcode": "event_id",
    "event_code": "event_id",
}

# Keys that must NEVER be treated as free-form entity values when walking blindly.
_SKIP_KEYS = frozenset(
    {
        "title",
        "description",
        "rule_description",
        "orig_rule_description",
        "search_name",
        "rule_name",
        "severity",
        "urgency",
        "status",
        "disposition",
        "summary",
        "narrative",
        "annotations",
        "mitre_tactics",
        "mitre_techniques",
        "count",
        "info",
        "message",
        "raw",
    }
)

# Keys whose values are JSON strings that may contain nested entities.
_JSON_STRING_KEYS = frozenset({"rule_specific_json", "annotations", "entity"})


@dataclass(frozen=True)
class ExtractedEntity:
    """One typed entity observation with provenance."""

    entity_type: str
    normalized_value: str
    original_value: str
    source_field: str
    source_location: str
    confidence: float
    is_observed: bool
    is_inferred: bool
    extractor_name: str
    extraction_timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EntityExtractionResult:
    """Bundle of extracted entities plus lightweight indexes."""

    entities: list[ExtractedEntity] = field(default_factory=list)
    extractor_version: str = EXTRACTOR_VERSION

    def by_type(self, entity_type: str) -> list[ExtractedEntity]:
        return [e for e in self.entities if e.entity_type == entity_type]

    def values(self, entity_type: str) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for ent in self.by_type(entity_type):
            key = ent.normalized_value.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(ent.normalized_value)
        return out

    def has_type(self, entity_type: str) -> bool:
        return any(e.entity_type == entity_type for e in self.entities)

    def to_dict(self) -> dict[str, Any]:
        return {
            "extractor_version": self.extractor_version,
            "entities": [e.to_dict() for e in self.entities],
            "counts_by_type": self.counts_by_type(),
        }

    def counts_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for ent in self.entities:
            counts[ent.entity_type] = counts.get(ent.entity_type, 0) + 1
        return counts


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return ""
    text = str(value).strip().strip("'\"")
    if not text or text.lower() in _NONE:
        return ""
    return text


def _is_valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]").split("/", 1)[0])
        return True
    except ValueError:
        return False


def _normalize_ip(text: str) -> str | None:
    raw = text.strip().strip("[]")
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if not _is_valid_ip(raw):
        return None
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def _looks_like_hostname(text: str) -> bool:
    if not text or len(text) > 253:
        return False
    candidate = text.rstrip(".")
    if not candidate:
        return False
    if _is_valid_ip(candidate):
        return False
    if " " in candidate or "/" in candidate or "\\" in candidate:
        return False
    # Require either a dotted name or a short NetBIOS-like token.
    if "." in candidate:
        return bool(_HOSTNAME_RE.match(candidate))
    # Short host aliases (SH2) — alphanumeric + hyphen, 2–63 chars.
    return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$", candidate))


def _looks_like_path(text: str) -> bool:
    if not text or len(text) < 3:
        return False
    return bool(_WIN_PATH_RE.match(text) or (_POSIX_PATH_RE.match(text) and text.count("/") >= 1))


def _looks_like_url(text: str) -> bool:
    if not text or " " in text:
        return False
    lower = text.lower()
    if not (lower.startswith("http://") or lower.startswith("https://")):
        return False
    parsed = urlparse(text)
    return bool(parsed.scheme and parsed.netloc)


def _normalize_for_type(entity_type: str, original: str) -> str | None:
    text = _clean_text(original)
    if not text:
        return None

    if entity_type == "ip":
        return _normalize_ip(text)

    if entity_type in {"hostname", "endpoint", "domain"}:
        if not _looks_like_hostname(text):
            return None
        return text.lower().rstrip(".")

    if entity_type == "user_sid":
        # Strip wrapping quotes already handled; validate SID shape.
        if _SID_RE.match(text):
            return text.upper()
        # user_id sometimes holds a username — demote caller handles remap.
        return None

    if entity_type == "username":
        if _SID_RE.match(text):
            return None  # SIDs belong in user_sid
        if len(text) > 256 or "\n" in text:
            return None
        return text.lower()

    if entity_type == "file_hash":
        if _HASH_RE.match(text):
            return text.lower()
        return None

    if entity_type == "file_path":
        if _looks_like_path(text):
            return text
        # Allow bare script names with extension when sourced from Path-like fields.
        if re.search(r"\.(ps1|bat|cmd|vbs|js|exe|dll|sh)$", text, re.I) and len(text) < 512:
            return text
        return None

    if entity_type in {"process_name", "parent_process"}:
        if len(text) > 512 or "\n" in text:
            return None
        # Prefer basename for Image paths.
        if "\\" in text or "/" in text:
            base = text.replace("\\", "/").rstrip("/").split("/")[-1]
            return base.lower() if base else None
        return text.lower()

    if entity_type == "process_id":
        if text.isdigit() and 0 < int(text) < 10_000_000:
            return text
        return None

    if entity_type == "url":
        return text if _looks_like_url(text) else None

    if entity_type in {"email", "email_sender", "email_recipient"}:
        return text.lower() if _EMAIL_RE.match(text) else None

    if entity_type == "certificate_fingerprint":
        cleaned = text.replace(" ", "")
        return cleaned.lower() if _CERT_FP_RE.match(cleaned) else None

    if entity_type == "event_id":
        if _EVENT_ID_RE.match(text):
            return text
        return None

    if entity_type == "script_block":
        # Keep meaningful script bodies; avoid single-token junk.
        if len(text) < 8:
            return None
        return text

    if entity_type == "source_event_id":
        if len(text) < 4 or len(text) > 512:
            return None
        return text

    if entity_type in {
        "network_service",
        "cloud_resource",
        "account_id",
        "database",
        "container",
        "kubernetes_workload",
    }:
        if len(text) < 2 or len(text) > 512 or "\n" in text:
            return None
        return text

    return None


def _resolve_type_for_field(field_name: str, value: str) -> str | None:
    key = field_name.lower().strip()
    # dest/src alone are ambiguous — accept IP or hostname only.
    if key in {"src", "dest", "dst"}:
        if _normalize_ip(value):
            return "ip"
        if _looks_like_hostname(value):
            return "hostname"
        return None
    # user_id may be SID or username.
    if key == "user_id":
        if _SID_RE.match(value.strip().strip("'\"")):
            return "user_sid"
        return "username"
    return _FIELD_MAP.get(key)


@dataclass
class _Collector:
    entities: list[ExtractedEntity] = field(default_factory=list)
    # Dedup key → index; same type+normalized keeps first but appends provenance twin
    # only when source_field/location differs (conflicting originals preserved).
    _index: dict[tuple[str, str, str, str], int] = field(default_factory=dict)

    def add(
        self,
        *,
        entity_type: str,
        original: Any,
        source_field: str,
        source_location: str,
        confidence: float = 0.9,
        is_observed: bool = True,
        is_inferred: bool = False,
    ) -> None:
        if entity_type not in ENTITY_TYPES:
            return
        original_text = _clean_text(original)
        if not original_text:
            return
        normalized = _normalize_for_type(entity_type, original_text)
        if normalized is None:
            return
        if is_inferred and not is_observed:
            pass  # allowed
        elif is_inferred:
            is_observed = False
        key = (entity_type, normalized.lower(), source_field.lower(), source_location)
        if key in self._index:
            return
        # Preserve conflicting originals for same type+normalized from other sources —
        # already covered by distinct source_field/location keys.
        # Also preserve same type with DIFFERENT normalized values (conflicts).
        self._index[key] = len(self.entities)
        self.entities.append(
            ExtractedEntity(
                entity_type=entity_type,
                normalized_value=normalized,
                original_value=original_text,
                source_field=source_field,
                source_location=source_location,
                confidence=max(0.0, min(1.0, confidence)),
                is_observed=bool(is_observed) and not is_inferred,
                is_inferred=bool(is_inferred),
                extractor_name=EXTRACTOR_NAME,
                extraction_timestamp=_now_iso(),
            )
        )


def _alert_as_dict(alert: Any) -> dict[str, Any]:
    if isinstance(alert, dict):
        return alert
    out: dict[str, Any] = {}
    for name in (
        "id",
        "title",
        "severity",
        "rule_name",
        "rule_id",
        "security_domain",
        "detection_type",
        "hostname",
        "host",
        "username",
        "src_ip",
        "dest_ip",
        "affected_hosts",
        "affected_ips",
        "affected_users",
        "llm_payload",
        "raw_event",
        "enrichment_data",
        "iocs",
        "annotations",
        "entity",
        "alert_fields",
    ):
        if hasattr(alert, name):
            out[name] = getattr(alert, name)
    return out


def _iter_alert_fields_blobs(row: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield (source_location, alert_fields dict) from all known nests."""
    direct = row.get("alert_fields")
    if isinstance(direct, dict):
        yield ("alert.alert_fields", direct)

    for loc, blob in (
        ("alert.llm_payload", row.get("llm_payload")),
        ("alert.raw_event", row.get("raw_event")),
        ("alert.enrichment_data", row.get("enrichment_data")),
    ):
        if not isinstance(blob, dict):
            continue
        af = blob.get("alert_fields")
        if isinstance(af, dict):
            yield (f"{loc}.alert_fields", af)
        # Some connectors nest under raw_event / raw_data / event.
        for nested_key in ("raw_event", "raw_data", "event", "notable"):
            nested = blob.get(nested_key)
            if isinstance(nested, dict):
                nested_af = nested.get("alert_fields")
                if isinstance(nested_af, dict):
                    yield (f"{loc}.{nested_key}.alert_fields", nested_af)


def _safe_json_loads(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


def _walk_mapped_fields(
    collector: _Collector,
    payload: dict[str, Any],
    *,
    source_location: str,
    depth: int = 0,
) -> None:
    if depth > 6 or not isinstance(payload, dict):
        return
    for raw_key, raw_val in payload.items():
        key = str(raw_key)
        lk = key.lower()
        if lk in _SKIP_KEYS:
            continue
        if isinstance(raw_val, dict):
            _walk_mapped_fields(
                collector, raw_val, source_location=f"{source_location}.{key}", depth=depth + 1
            )
            continue
        if isinstance(raw_val, list):
            for idx, item in enumerate(raw_val[:32]):
                if isinstance(item, dict):
                    _walk_mapped_fields(
                        collector,
                        item,
                        source_location=f"{source_location}.{key}[{idx}]",
                        depth=depth + 1,
                    )
                else:
                    text = _clean_text(item)
                    if not text:
                        continue
                    et = _resolve_type_for_field(key, text)
                    if et:
                        collector.add(
                            entity_type=et,
                            original=text,
                            source_field=key,
                            source_location=f"{source_location}.{key}[{idx}]",
                        )
            continue
        if lk in _JSON_STRING_KEYS:
            parsed = _safe_json_loads(raw_val)
            if isinstance(parsed, dict):
                _walk_mapped_fields(
                    collector,
                    parsed,
                    source_location=f"{source_location}.{key}",
                    depth=depth + 1,
                )
                continue
        text = _clean_text(raw_val)
        if not text:
            continue
        et = _resolve_type_for_field(key, text)
        if et is None:
            continue
        # Event ID: only from explicit event id fields — never from title.
        if et == "event_id" and lk not in {"event_id", "eventid", "eventcode", "event_code"}:
            continue
        collector.add(
            entity_type=et,
            original=text,
            source_field=key,
            source_location=source_location,
            confidence=0.95 if source_location.endswith("alert_fields") else 0.85,
        )


def _extract_from_affected(
    collector: _Collector,
    row: dict[str, Any],
) -> None:
    for item in row.get("affected_hosts") or []:
        if isinstance(item, dict):
            collector.add(
                entity_type="hostname",
                original=item.get("value") or item.get("host"),
                source_field="affected_hosts",
                source_location="alert.affected_hosts",
            )
        else:
            collector.add(
                entity_type="hostname",
                original=item,
                source_field="affected_hosts",
                source_location="alert.affected_hosts",
            )
    for item in row.get("affected_ips") or []:
        if isinstance(item, dict):
            collector.add(
                entity_type="ip",
                original=item.get("value") or item.get("ip"),
                source_field="affected_ips",
                source_location="alert.affected_ips",
            )
        else:
            collector.add(
                entity_type="ip",
                original=item,
                source_field="affected_ips",
                source_location="alert.affected_ips",
            )
    for item in row.get("affected_users") or []:
        if isinstance(item, dict):
            val = item.get("value") or item.get("user")
            text = _clean_text(val)
            et = "user_sid" if text and _SID_RE.match(text) else "username"
            collector.add(
                entity_type=et,
                original=val,
                source_field="affected_users",
                source_location="alert.affected_users",
            )
        else:
            text = _clean_text(item)
            et = "user_sid" if text and _SID_RE.match(text) else "username"
            collector.add(
                entity_type=et,
                original=item,
                source_field="affected_users",
                source_location="alert.affected_users",
            )


def _extract_from_iocs(collector: _Collector, row: dict[str, Any]) -> None:
    for ioc in row.get("iocs") or []:
        if not isinstance(ioc, dict):
            continue
        kind = str(ioc.get("type") or ioc.get("kind") or "").lower()
        val = ioc.get("value") or ioc.get("ip") or ioc.get("hash") or ioc.get("url")
        mapping = {
            "ip": "ip",
            "ipv4": "ip",
            "ipv6": "ip",
            "address": "ip",
            "hash": "file_hash",
            "sha256": "file_hash",
            "sha1": "file_hash",
            "md5": "file_hash",
            "filehash": "file_hash",
            "domain": "domain",
            "dns": "domain",
            "url": "url",
            "email": "email",
            "host": "hostname",
            "hostname": "hostname",
        }
        et = mapping.get(kind)
        if et and val is not None:
            collector.add(
                entity_type=et,
                original=val,
                source_field=f"iocs.{kind or 'value'}",
                source_location="alert.iocs",
                confidence=0.9,
            )


def _extract_column_fields(collector: _Collector, row: dict[str, Any]) -> None:
    for key in (
        "hostname",
        "host",
        "username",
        "src_ip",
        "dest_ip",
        "security_domain",
    ):
        if key == "security_domain":
            continue
        if key in row and row[key] is not None:
            text = _clean_text(row[key])
            if not text:
                continue
            et = _resolve_type_for_field(key, text)
            if et:
                collector.add(
                    entity_type=et,
                    original=text,
                    source_field=key,
                    source_location="alert.column",
                    confidence=0.9,
                )


def _maybe_endpoint_from_hostname(collector: _Collector) -> None:
    """Mark observed hostnames as endpoints when Computer/endpoint-like fields exist."""
    extras: list[ExtractedEntity] = []
    for ent in collector.entities:
        if ent.entity_type != "hostname":
            continue
        if ent.source_field.lower() in {"computer", "endpoint", "device_name", "dvc"}:
            extras.append(
                ExtractedEntity(
                    entity_type="endpoint",
                    normalized_value=ent.normalized_value,
                    original_value=ent.original_value,
                    source_field=ent.source_field,
                    source_location=ent.source_location,
                    confidence=ent.confidence,
                    is_observed=ent.is_observed,
                    is_inferred=True,  # endpoint role inferred from hostname observation
                    extractor_name=EXTRACTOR_NAME,
                    extraction_timestamp=ent.extraction_timestamp,
                )
            )
    for ent in extras:
        key = (
            ent.entity_type,
            ent.normalized_value.lower(),
            ent.source_field.lower(),
            ent.source_location,
        )
        if key in collector._index:
            continue
        collector._index[key] = len(collector.entities)
        collector.entities.append(ent)


def extract_alert_entities(alert: Any) -> EntityExtractionResult:
    """Extract typed entities with provenance from all available alert surfaces."""
    row = _alert_as_dict(alert)
    collector = _Collector()

    _extract_column_fields(collector, row)
    _extract_from_affected(collector, row)
    _extract_from_iocs(collector, row)

    for location, af in _iter_alert_fields_blobs(row):
        _walk_mapped_fields(collector, af, source_location=location)

    for loc_name, blob in (
        ("alert.llm_payload", row.get("llm_payload")),
        ("alert.raw_event", row.get("raw_event")),
        ("alert.enrichment_data", row.get("enrichment_data")),
    ):
        if isinstance(blob, dict):
            # Walk top-level mapped keys; nested alert_fields already handled.
            flat = {k: v for k, v in blob.items() if k != "alert_fields"}
            _walk_mapped_fields(collector, flat, source_location=loc_name)

    # entity / annotations columns
    for loc_name, blob in (
        ("alert.entity", row.get("entity")),
        ("alert.annotations", row.get("annotations")),
    ):
        parsed = blob if isinstance(blob, dict) else _safe_json_loads(blob)
        if isinstance(parsed, dict):
            _walk_mapped_fields(collector, parsed, source_location=loc_name)
        elif isinstance(parsed, list):
            for idx, item in enumerate(parsed[:32]):
                if isinstance(item, dict):
                    _walk_mapped_fields(
                        collector, item, source_location=f"{loc_name}[{idx}]"
                    )

    _maybe_endpoint_from_hostname(collector)
    return EntityExtractionResult(entities=list(collector.entities))


def powershell_regression_alert() -> dict[str, Any]:
    """Canonical PowerShell Invoke Command alert used by P1+ regression gates."""
    return {
        "id": "1b48d719-b603-4e91-abaa-c8306ad6cda6",
        "alert_id": "1b48d719-b603-4e91-abaa-c8306ad6cda6",
        "severity": "high",
        "title": "Soorin-Endpoint-Powershell Invoke Command",
        "rule_name": "Soorin-Endpoint-Powershell Invoke Command",
        "security_domain": "endpoint",
        "detection_type": "ebd",
        "alert_time": "2026-11-14T15:24:29+0330",
        "event_time": "2026-11-14T15:24:29+0330",
        "affected_ips": [],
        "affected_hosts": [],
        "affected_users": [],
        "iocs": [],
        "raw_event": {},
        "enrichment_data": {},
        "llm_payload": {
            "security_domain": "endpoint",
            "detection_type": "ebd",
            "alert_fields": {
                "Computer": "cao01vw013.cao.ir",
                "user_id": "'S-1-5-21-1793179736-1175893981-2474273398-13753'",
                "Path": r"C:\Windows\TEMP\SDIAG_a982bdc8-63b3-40e9-b454-8def2c201900\CL_Utility.ps1",
                "ScriptBlockText": "function Get-FreeSpace { ... }",
                "count": 1,
                "extracted_host": "SH2",
                "source_event_id": (
                    "1b48d719-b603-4e91-abaa-c8306ad6cda6@@notable@@time1794656314"
                ),
            },
        },
    }
