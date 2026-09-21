"""Splunk notable → Alert field mapping (no live Splunk)."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from app.services.splunk_notable import (
    apply_notable,
    extract_mitre_ids,
    iocs_from_raw,
    mitre_attack_rows,
    needs_hydrate,
)


def _alert(**overrides):
    now = datetime.now(UTC)
    base = {
        "title": "Network - Unapproved Port Activity Detected - Rule",
        "description": "Splunk notable on WIN-017UMT7DCGT.soorinsec.local",
        "severity": "medium",
        "priority": 50,
        "connector_type": "splunk",
        "rule_name": None,
        "rule_id": None,
        "raw_event": {
            "source": "splunk",
            "search_name": "Network - Unapproved Port Activity Detected - Rule",
            "host": "WIN-017",
        },
        "affected_hosts": ["WIN-017UMT7DCGT.soorinsec.local"],
        "affected_ips": [],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "source_event_ids": [],
        "tags": ["splunk", "notable"],
        "enrichment_data": {},
        "event_time": now,
        "first_seen": now,
        "last_seen": now,
        "updated_at": now,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_extract_mitre_from_es_rule_catalog_when_stash_has_none():
    ids = extract_mitre_ids({}, "Network - Unapproved Port Activity Detected - Rule")
    assert "T1046" in ids
    assert "T1571" in ids


def test_needs_hydrate_when_mission_control_fields_missing():
    assert needs_hydrate(_alert()) is True
    assert needs_hydrate(_alert(raw_event={"dest_port": "3389"})) is True


def test_needs_hydrate_false_when_extract_fields_present():
    alert = _alert(
        raw_event={
            "orig_rule_description": "The device connected to a prohibited port.",
            "detection_id": "6dd9e9ab-1111-2222-3333-444444444444",
            "dest_port": "3389",
        }
    )
    assert needs_hydrate(alert) is False


def test_apply_notable_uses_orig_rule_description_and_ids():
    alert = _alert()
    apply_notable(
        alert,
        {
            "title": "Network - Unapproved Port Activity Detected - Rule",
            "severity": "low",
            "hostname": "WIN-017UMT7DCGT.soorinsec.local",
            "src_ip": "10.1.2.3",
            "external_id": "af145ac9-6b34-49b9-af4a-afe5e342e47c",
            "created_at": "2026-07-01T12:48:35.000+03:30",
            "raw_event": {
                "search_name": "Network - Unapproved Port Activity Detected - Rule",
                "orig_rule_title": "Prohibited Port Activity Detected",
                "orig_rule_description": "The device connected to a prohibited port.",
                "detection_id": "6dd9e9ab-1111-2222-3333-444444444444",
                "notable_id": "af145ac9-6b34-49b9-af4a-afe5e342e47c",
                "dest_port": "3389",
                "transport": "tcp",
                "dvc": "WIN-017UMT7DCGT.soorinsec.local",
                "src": "10.1.2.3",
                "is_prohibited": "true",
            },
        },
    )
    assert alert.description.startswith("The device connected")
    assert alert.rule_name == "Prohibited Port Activity Detected"
    assert alert.rule_id == "6dd9e9ab-1111-2222-3333-444444444444"
    assert alert.severity == "low"
    assert "T1046" in alert.mitre_techniques
    iocs = iocs_from_raw(alert.raw_event)
    assert {"type": "port", "value": "tcp/3389"} in iocs
    assert any(row["technique_id"] == "T1046" for row in mitre_attack_rows(alert.mitre_techniques))
