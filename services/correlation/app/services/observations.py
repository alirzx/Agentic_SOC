"""Graph-based deduplication: many raw alerts collapse into few observations.

Doc §4.2 is explicit that dedup must not rely on ``alerts.dedup_hash`` (content
identity) because the same attacker action surfaces as several *different*
notables. Instead we group alerts by the topology of the action they describe:

===============  ======================================================
Action           Observation key
===============  ======================================================
LSASS access     ``host | SourceProcessGUID | TargetProcessGUID | technique``
SMB admin write  ``host | src_user | firstTime-to-the-minute | RelativeTargetName``
3CX desktop app  ``host | process_hash``
anything else    ``technique | strongest non-guid keys``
===============  ======================================================

The key is a *string*, so it is trivially testable and stable across restarts.
Observations are what scoring compares; raw alerts remain the evidence.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.normalizer.extract_keys import PLACEHOLDERS, ExtractedKeys, Key


@dataclass
class Observation:
    """One atomic attacker action, backed by one or more raw alerts."""

    key: str
    alert_ids: list[str] = field(default_factory=list)
    keys: list[Key] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    process_guids: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    stories: list[str] = field(default_factory=list)
    kill_chain: list[str] = field(default_factory=list)
    role: str = "general:intrusion"
    rule_names: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    time_quality: str = "alert_time_fallback"
    normalizer_version: str = ""

    @property
    def tokens(self) -> set[str]:
        return {k.token for k in self.keys if k.weight > 0}

    def merge(self, other: Observation) -> Observation:
        """Fold another observation with the same key into this one."""
        for alert_id in other.alert_ids:
            if alert_id not in self.alert_ids:
                self.alert_ids.append(alert_id)
        seen_tokens = {k.token for k in self.keys}
        for key in other.keys:
            if key.token not in seen_tokens:
                seen_tokens.add(key.token)
                self.keys.append(key)
            else:  # keep the strongest weight for the shared token
                for existing in self.keys:
                    if existing.token == key.token and key.weight > existing.weight:
                        self.keys[self.keys.index(existing)] = Key(
                            kind=key.kind,
                            value=key.value,
                            weight=key.weight,
                            origins=tuple(sorted(set(existing.origins) | set(key.origins))),
                            alias=existing.alias or key.alias,
                        )
                        break
        for attr in (
            "hosts",
            "users",
            "ips",
            "domains",
            "hashes",
            "process_guids",
            "techniques",
            "stories",
            "kill_chain",
            "rule_names",
        ):
            bucket: list[str] = getattr(self, attr)
            for value in getattr(other, attr):
                if value not in bucket:
                    bucket.append(value)
        if other.first_seen and (self.first_seen is None or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen
        if other.last_seen and (self.last_seen is None or other.last_seen > self.last_seen):
            self.last_seen = other.last_seen
        # A confirmed event time outranks an alert-time fallback.
        if other.time_quality == "first_event":
            self.time_quality = "first_event"
        return self

    @property
    def time_quality_ok(self) -> bool:
        return self.time_quality == "first_event"


def parse_time(value: Any) -> datetime | None:
    """Parse the payload's ISO-ish timestamps (``…T19:53:51+0330``)."""
    if value in (None, "", "null"):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    if not text:
        return None
    # Normalise ``+0330`` → ``+03:30`` and a space separator to ``T``.
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text.replace(" ", "T", 1))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _minute(dt: datetime | None) -> str:
    return dt.astimezone(UTC).strftime("%Y%m%dT%H%M") if dt else ""


def _field(lp: Mapping[str, Any], name: str) -> Any:
    fields = lp.get("alert_fields")
    return fields.get(name) if isinstance(fields, Mapping) else None


def _target_is_lsass(lp: Mapping[str, Any]) -> bool:
    target = str(_field(lp, "TargetImage") or "").lower()
    return target.endswith("\\lsass.exe") or target.endswith("/lsass.exe") or target == "lsass.exe"


#: Hard ceiling on a graph dedup key. The API's correlation contract caps
#: ``observation_id`` at 512 characters (``CorrelationObservation`` in
#: ``services/api/app/api/v1/endpoints/cases.py``); exceeding it rejects the
#: *whole* bundle with a 422, so no case is created for any alert in it.
MAX_OBSERVATION_KEY_CHARS = 512

#: Hex characters of the sha256 suffix that replaces the truncated key tail.
_KEY_HASH_CHARS = 16


def bounded_key(key: str, *, limit: int = MAX_OBSERVATION_KEY_CHARS) -> str:
    """Bound a dedup key to the API contract without losing its identity.

    A file identity is not always one digest: ``process_hash`` can carry every
    hash of the file on separate lines (``sha1=…,md5=…,sha256=…,imphash=…``).
    Concatenated into ``file|<host>|<that blob>`` the key ran past the 512-char
    contract and the case bundle was rejected.

    The truncated form keeps a readable prefix and appends a stable
    ``|#<sha256 prefix>`` taken from the *full* key, so two alerts still share an
    observation exactly when they did before — distinct keys never collapse
    into one just because they share a prefix.
    """
    if len(key) <= limit:
        return key
    digest = hashlib.sha256(key.encode()).hexdigest()[:_KEY_HASH_CHARS]
    tail = f"|#{digest}"
    # Collapse the multi-line digest blob: the bounded key is printed on one
    # timeline line, so a newline in it would break the case comment.
    head = " ".join(key[: limit - len(tail)].split()).rstrip("|,;").rstrip()
    return f"{head}{tail}"


def observation_signature(
    llm_payload: Mapping[str, Any],
    extracted: ExtractedKeys,
    *,
    alert_id: str,
) -> str:
    """Graph-dedup key for one alert (doc §4.2), bounded for the case contract."""
    return bounded_key(_unbounded_signature(llm_payload, extracted, alert_id=alert_id))


def _unbounded_signature(
    llm_payload: Mapping[str, Any],
    extracted: ExtractedKeys,
    *,
    alert_id: str,
) -> str:
    """Derive the raw graph-dedup key for one alert (doc §4.2).

    The host in the key is the machine the event happened on
    (``extracted.primary_host``), never the Splunk indexer — see
    ``extract_keys._is_splunk_payload`` for why that distinction matters.
    """
    host = extracted.primary_host
    technique = extracted.techniques[0] if extracted.techniques else ""

    # 1. LSASS: identity is the process pair, not the count of rules that fired.
    if _target_is_lsass(llm_payload) or (
        extracted.process_guids and "T1003.001" in extracted.techniques
    ):
        source_guid = str(_field(llm_payload, "SourceProcessGUID") or "").strip("{}").lower()
        target_guid = str(_field(llm_payload, "TargetProcessGUID") or "").strip("{}").lower()
        if not source_guid and not target_guid:
            # Older LSASS rules only carry process_guid / parent_process_guid.
            guids = sorted(extracted.process_guids)
            source_guid = guids[0] if guids else ""
            target_guid = guids[-1] if len(guids) > 1 else ""
        return f"lsass|{host}|{source_guid}|{target_guid}|{technique}"

    # 2. SMB administrative write: same user writing the same file to the same
    #    share inside one minute is one observation.
    relative = _field(llm_payload, "RelativeTargetName")
    share = _field(llm_payload, "ShareName")
    if relative and share and str(relative).strip().lower() not in PLACEHOLDERS:
        user = extracted.users[0] if extracted.users else ""
        first = parse_time(llm_payload.get("event_time")) or parse_time(_field(llm_payload, "firstTime"))
        return f"smb|{host}|{user}|{_minute(first)}|{str(relative).lower()}|{str(share).lower()}"

    # 3. 3CX / signed-app hash: the binary hash is the identity.
    process_hash = _field(llm_payload, "process_hash")
    if process_hash:
        digest = str(process_hash).strip().lower()
        if digest not in PLACEHOLDERS:
            return f"file|{host}|{digest}"

    # 4. Fallback: technique + the strongest non-guid entity keys. GUIDs are
    #    excluded here because they are already covered by case 1 and would
    #    make every single alert its own observation.
    strong = sorted(
        k.token
        for k in extracted.keys
        if k.kind != "process_guid" and k.weight >= 2 and not k.alias
    )
    if strong:
        digest = hashlib.sha1("|".join(strong).encode()).hexdigest()[:16]
        return f"entity|{technique}|{digest}"

    # 5. No entities at all (RBA threshold notables): never merge with anything.
    return f"alert|{alert_id}"


def build_observation(
    llm_payload: Mapping[str, Any],
    extracted: ExtractedKeys,
    *,
    alert_id: str,
    role: str = "general:intrusion",
) -> Observation:
    """Build a single-alert observation."""
    event_dt = parse_time(extracted.event_time)
    alert_dt = parse_time(extracted.alert_time)
    observed = event_dt or alert_dt
    return Observation(
        key=observation_signature(llm_payload, extracted, alert_id=alert_id),
        alert_ids=[alert_id],
        keys=list(extracted.keys),
        hosts=list(extracted.hosts),
        users=list(extracted.users),
        ips=list(extracted.ips),
        domains=list(extracted.domains),
        hashes=list(extracted.hashes),
        process_guids=list(extracted.process_guids),
        techniques=list(extracted.techniques),
        stories=list(extracted.stories),
        kill_chain=list(extracted.kill_chain),
        role=role,
        rule_names=[extracted.rule_name] if extracted.rule_name else [],
        first_seen=observed,
        last_seen=observed,
        time_quality=extracted.time_quality,
        normalizer_version=extracted.normalizer_version,
    )


def group_observations(observations: Iterable[Observation]) -> list[Observation]:
    """Merge observations that share a signature; return a stable ordering."""
    merged: dict[str, Observation] = {}
    for observation in observations:
        current = merged.get(observation.key)
        if current is None:
            merged[observation.key] = observation
        else:
            merged[observation.key] = current.merge(observation)
    return sorted(merged.values(), key=lambda o: (o.first_seen or datetime.min.replace(tzinfo=UTC), o.key))


__all__ = [
    "MAX_OBSERVATION_KEY_CHARS",
    "Observation",
    "bounded_key",
    "build_observation",
    "group_observations",
    "observation_signature",
    "parse_time",
]
