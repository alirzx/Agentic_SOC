"""Project source fields from a durable alert. Store the exact bytes before first I/O."""
import json
from datetime import datetime
from uuid import UUID

from app.services.tkg_evaluation.constants import PROFILE
from app.services.tkg_evaluation.sender import MAX_BODY_BYTES, RecordError


def obj(value):
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise RecordError("malformed_json") from None
    if not isinstance(value, dict):
        raise RecordError("invalid_object")
    return value


def freeze(snapshot, binding):
    if snapshot.get("connector_type") != "splunk" or binding.source_system != "splunk":
        raise RecordError("unsupported_profile")
    if str(binding.connector_id) != str(snapshot.get("connector_id")) or not binding.connector_id:
        raise RecordError("source_scope_mismatch")
    try:
        row_id = str(UUID(str(snapshot["id"])))
    except (KeyError, ValueError):
        raise RecordError("invalid_alert_row_id") from None
    raw = obj(snapshot.get("raw_event"))
    envelope = obj(raw.get("raw_data"))
    original = obj(envelope.get("raw_event")) or envelope
    payload = obj(snapshot.get("llm_payload"))
    if "llm_payload" in payload:
        payload = obj(payload["llm_payload"])
    api = obj(payload.get("_meta")).get("mode") == "enriched_from_api"
    if api and payload.get("alert_id") not in (None, row_id):
        raise RecordError("conflicting_soc_alert_identity")
    finding = obj(raw.get("finding"))
    notable = original.get("notable_id") or original.get("source_guid") or (None if api else payload.get("alert_id"))
    event_ids = original.get("source_event_ids") or []
    if not isinstance(event_ids, list):
        raise RecordError("invalid_source_event_ids")
    event_ids = [*event_ids, original.get("source_event_id"), original.get("event_id")]
    # Older Fusion rows copied the OCSF finding UID to source_event_ids.
    stored_ids = snapshot.get("source_event_ids") or []
    if not isinstance(stored_ids, list):
        raise RecordError("invalid_source_event_ids")
    event_ids.extend(v for v in stored_ids if v != finding.get("uid"))
    ids = [v for v in event_ids if isinstance(v, str) and v.strip()]
    if not any(isinstance(v, str) and v.strip() for v in [notable, finding.get("uid"), *ids]):
        raise RecordError("missing_source_identity")
    occurrence = payload.get("event_time") or payload.get("alert_time") or original.get("_time")
    version = original.get("source_updated_at") or original.get("updated_at") or payload.get("source_updated_at")
    for ts in (occurrence, version or occurrence):
        try:
            if datetime.fromisoformat(ts).utcoffset() is None:
                raise ValueError
        except (TypeError, ValueError):
            raise RecordError("missing_or_invalid_source_time") from None
    rule = snapshot.get("rule_id") or original.get("detection_id")
    if not any((rule, snapshot.get("rule_name"), payload.get("rule_name"), payload.get("entity"),
                payload.get("alert_fields"), original.get("search_name"), original.get("src_ip"))):
        raise RecordError("no_event_information")
    record = {
        "alert_row_id": row_id, "event_time": occurrence, "source_updated_at": version,
        "tenant_id": binding.tkg_tenant, "source_system": binding.source_system,
        "source_instance": binding.source_instance, "connector_id": str(binding.connector_id),
        "notable_id": notable, "finding": {"uid": finding["uid"]} if finding.get("uid") else None,
        "source_event_ids": list(dict.fromkeys(ids)), "rule_id": rule,
        "rule_name": snapshot.get("rule_name"), "ocsf_class_uid": snapshot.get("ocsf_class_uid"),
        "llm_payload": payload, "src_ip": original.get("src_ip"),
    }
    record = {k: v for k, v in record.items() if v is not None}
    data = json.dumps({"profile": PROFILE, "record": record}, sort_keys=True,
                      ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    if len(data) > MAX_BODY_BYTES:
        raise RecordError("record_too_large")
    return data
