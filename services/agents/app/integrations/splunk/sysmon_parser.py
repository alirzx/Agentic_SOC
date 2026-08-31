"""Extract Sysmon fields from Splunk _raw XML (Phase 8.7.4)."""

from __future__ import annotations

import re
from typing import Any

_SIMPLE_TAG_RE = re.compile(r"<(EventID|Computer|Channel|Provider|UtcTime)>([^<]*)</\1>")
_DATA_NAME_RE = re.compile(r"<Data Name='([^']+)'>([^<]*)</Data>")

_SYSMON_FIELDS = (
    "EventID",
    "Computer",
    "Provider",
    "Channel",
    "UtcTime",
    "ProcessGuid",
    "ProcessId",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "Hashes",
    "ParentProcessGuid",
    "ParentProcessId",
    "ParentImage",
    "ParentCommandLine",
    "ParentUser",
    "CurrentDirectory",
    "LogonGuid",
    "LogonId",
    "TerminalSessionId",
)


def parse_sysmon_raw(raw: str | None) -> dict[str, Any]:
    """Best-effort Sysmon XML extraction. Never invents values on parse failure."""
    if not raw or not str(raw).strip():
        return {"parse_status": "empty_raw"}
    text = str(raw)
    if "Sysmon" not in text and "EventID" not in text:
        return {"parse_status": "not_sysmon_xml"}
    parsed: dict[str, str] = {}
    for tag, value in _SIMPLE_TAG_RE.findall(text):
        if value.strip():
            parsed[tag] = value.strip()
    for name, value in _DATA_NAME_RE.findall(text):
        if name in _SYSMON_FIELDS and value.strip():
            parsed[name] = value.strip()
    if not parsed:
        return {"parse_status": "xml_parse_failed", "_raw_length": len(text)}
    parsed["parse_status"] = "ok"
    return parsed


def merge_sysmon_into_row(row: dict[str, Any]) -> dict[str, Any]:
    """Augment Splunk row dict with sysmon extraction and preserved _raw."""
    merged = dict(row)
    raw = row.get("_raw")
    if raw is not None:
        merged["_raw"] = str(raw)
        sysmon = parse_sysmon_raw(str(raw))
        merged["sysmon"] = sysmon
        if sysmon.get("parse_status") == "ok":
            for key in _SYSMON_FIELDS:
                if key in sysmon and key not in merged:
                    merged[key] = sysmon[key]
    return merged
