"""Three-layer alert deduplication & incident correlation (v2).

Layer 1 — Event deduplication (Fusion ``dedup_hash`` / ``source_event_ids``)
Layer 2 — Alert logical identity (entity-aware, time-windowed)
Layer 3 — Incident correlation (scored, non-destructive)

Feature flags (API ``Settings`` / env):

* ``AISOC_ALERT_DEDUP_V2`` — use entity-aware soft-dedupe (default True)
* ``AISOC_DEDUP_SHADOW`` — compare legacy display key vs v2 without writing
* ``AISOC_ALERT_DEDUP_WINDOW_SECONDS`` — Layer-2 window (default 900 = 15m)
"""

from app.services.dedup.alert_identity import (
    ALERT_IDENTITY_VERSION,
    alert_logical_key,
    alert_logical_key_parts,
    extract_identity_entities,
)
from app.services.dedup.categories import (
    AlertCategory,
    IncidentCategory,
    classify_alert_category,
    classify_incident_category,
)
from app.services.dedup.correlation import (
    CORRELATION_VERSION,
    CorrelationMatch,
    score_alert_pair,
)
from app.services.dedup.event_fingerprint import (
    EVENT_FINGERPRINT_VERSION,
    event_dedup_fields,
)

__all__ = [
    "ALERT_IDENTITY_VERSION",
    "CORRELATION_VERSION",
    "EVENT_FINGERPRINT_VERSION",
    "AlertCategory",
    "CorrelationMatch",
    "IncidentCategory",
    "alert_logical_key",
    "alert_logical_key_parts",
    "classify_alert_category",
    "classify_incident_category",
    "event_dedup_fields",
    "extract_identity_entities",
    "score_alert_pair",
]
