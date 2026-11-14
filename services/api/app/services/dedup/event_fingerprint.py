"""Layer 1 — Event deduplication identity helpers.

Canonical runtime fingerprint remains Fusion ``RawAlert.fingerprint()`` /
``alerts.dedup_hash``. This module documents and mirrors the field contract so
API-side shadow/validation and migrations stay aligned.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

EVENT_FINGERPRINT_VERSION = "evt:v1"


def event_dedup_fields(
    *,
    tenant_id: str,
    source: str,
    source_event_ids: list[str] | None,
    source_instance: str | None = None,
    title: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    file_hash: str | None = None,
    rule_id: str | None = None,
    event_timestamp: str | None = None,
) -> dict[str, Any]:
    """Build canonical fields for event-level dedupe (aligned with Fusion).

    Prefer stable vendor event ids. Fallback includes entities + optional
    bounded timestamp only when no source_event_id exists.
    """
    event_ids = sorted(
        {str(x).strip() for x in (source_event_ids or []) if str(x).strip()}
    )
    base: dict[str, Any] = {
        "tenant_id": str(tenant_id),
        "source": (source or "").strip().lower(),
    }
    if source_instance:
        base["source_instance"] = str(source_instance).strip().lower()
    if event_ids:
        base["source_event_ids"] = event_ids
        return base
    # Bounded fallback — explicit low-confidence path (no vendor id).
    base.update(
        {
            "title": (title or "").strip().lower(),
            "src_ip": (src_ip or "").strip().lower(),
            "dst_ip": (dst_ip or "").strip().lower(),
            "hostname": (hostname or "").strip().lower(),
            "username": (username or "").strip().lower(),
            "file_hash": (file_hash or "").strip().lower(),
            "rule_id": (rule_id or "").strip().lower(),
            "fallback": True,
        }
    )
    if event_timestamp:
        # Truncate to minute to absorb sub-second redelivery noise.
        base["event_timestamp_minute"] = str(event_timestamp).strip()[:16]
    return base


def event_fingerprint_hash(fields: dict[str, Any]) -> str:
    """SHA-256 hex digest; same algorithm as Fusion RawAlert.fingerprint."""
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest
