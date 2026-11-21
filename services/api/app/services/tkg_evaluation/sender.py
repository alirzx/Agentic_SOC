"""Build the curated Splunk record for the manual "send to TKG" escape hatch.

The evaluation itself is read-only. This module exists for one narrow operator
action the UI exposes behind an explicit confirmation: when a case's alerts are
simply not in the graph yet (the usual reason for a 0% coverage verdict), push
*those* alerts once so the panel can be exercised end to end.

The mapping is the same one the standalone backfill script uses, because the
server-side normalizer only accepts that shape:

* ``notable_id`` — the alert's payload ``alert_id`` (the ``splunk_notable_id``
  authority; AiSOC's row UUID is a different thing and will not resolve).
* ``event_time`` — timezone-aware; the profile refuses a bare local timestamp.
* ``llm_payload`` — the original payload, nested so the server applies its
  documented mapping.
* ``rule.title`` — dropped. It normalizes onto the same ``DetectionRule`` as
  ``rule_name``, which the contract rejects as ``duplicate_entity``.

Nothing here writes to AiSOC's database; the receipt on the TKG side is the
audit record, and the caller returns it to the operator.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from app.services.tkg_evaluation.constants import PROFILE

#: The TKG rejects bodies over 1 MiB; leave headroom for the envelope.
MAX_BODY_BYTES = 1_000_000


class RecordError(ValueError):
    """A payload cannot be turned into a record. ``code`` is shown to the operator."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _payload_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except ValueError:
            return {}
        return dict(value) if isinstance(value, Mapping) else {}
    return {}


def _payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """Accept ``{llm_payload: "<json>"}`` or the payload directly."""

    inner = _payload_dict(row.get("llm_payload"))
    nested = inner.get("llm_payload")
    if isinstance(nested, (str, Mapping)):
        unwrapped = _payload_dict(nested)
        if unwrapped:
            return unwrapped
    return inner


def _alert_fields(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    fields = payload.get("alert_fields")
    return fields if isinstance(fields, Mapping) else {}


def build_curated_record(row: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """One AiSOC alert → ``(record, warnings)`` for ``soc/ingest``.

    Raises :class:`RecordError` with a stable code when the alert cannot be sent
    (missing notable id, missing timezone-aware time, oversized body).
    """

    warnings: list[str] = []
    payload = _payload(row)

    notable_id = str(payload.get("alert_id") or "").strip()
    if not notable_id:
        raise RecordError("missing_alert_id", "payload has no alert_id to use as notable_id")

    event_time = payload.get("event_time") or payload.get("alert_time") or row.get("event_time")
    if not isinstance(event_time, str) or "T" not in event_time:
        raise RecordError("event_time_not_iso", "payload needs an ISO-8601 event_time")

    payload = dict(payload)
    record: dict[str, Any] = {
        "notable_id": notable_id,
        "event_time": event_time,
        "llm_payload": payload,
    }
    alert_time = payload.get("alert_time")
    if isinstance(alert_time, str) and alert_time:
        record["alert_time"] = alert_time

    # ``network_scope`` is part of the resolve authority key: without it
    # ``knowledge/resolve`` answers not_found even for an ingested record.
    fields = _alert_fields(payload)
    scope = fields.get("network_scope") or payload.get("network_scope")
    if isinstance(scope, str) and scope:
        record["network_scope"] = scope

    host = fields.get("hostname") or fields.get("dest") or fields.get("host")
    if isinstance(host, str) and host:
        record["host"] = host
    src_ip = fields.get("src_ip")
    if isinstance(src_ip, str) and src_ip:
        record["src_ip"] = src_ip
    user = fields.get("user") or fields.get("username")
    if isinstance(user, str) and user:
        record["user"] = user

    rule = payload.get("rule")
    if isinstance(rule, Mapping):
        if "title" in rule:
            rule = {key: value for key, value in rule.items() if key != "title"}
            payload = {**payload, "rule": rule}
            record["llm_payload"] = payload
            warnings.append("rule_title_omitted_duplicate")

    body = json.dumps({"profile": PROFILE, "record": record}, ensure_ascii=False)
    if len(body.encode()) > MAX_BODY_BYTES and isinstance(rule, Mapping) and "spl" in rule:
        # The SPL query is the only routinely large field that carries no
        # authority; dropping it keeps the record inside the 1 MiB body limit.
        rule = {key: value for key, value in rule.items() if key != "spl"}
        payload = {**payload, "rule": rule}
        record["llm_payload"] = payload
        warnings.append("rule_spl_dropped_for_size")
        body = json.dumps({"profile": PROFILE, "record": record}, ensure_ascii=False)
    if len(body.encode()) > MAX_BODY_BYTES:
        raise RecordError("record_too_large", f"{len(body.encode())} bytes > {MAX_BODY_BYTES}")

    return record, warnings
