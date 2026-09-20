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
        "raw_event": {"source": "splunk", "search_name": "Network - Unapproved Port Activity Detected - Rule", "host": "WIN-017"},
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


def test_extract_mitre_from_annotations_json():
    ids = extract_mitre_ids({"annotations": {"mitre_attack": ["T1046", "T1571"]}})
    assert ids == ["T1046", "T1571"]


def test_extract_mitre_from_es_rule_catalog_when_stash_has_none():
    ids = extract_mitre_ids(
        {},
        "Network - Unapproved Port Activity Detected - Rule",
    )
    assert "T1046" in ids
    assert "T1571" in ids


def test_needs_hydrate_for_title_only_stub():
    assert needs_hydrate(_alert()) is True


def test_needs_hydrate_false_after_stash_fields():
    alert = _alert(raw_event={"dest_port": "3389", "dvc": "WIN-017"})
    assert needs_hydrate(alert) is False


def test_apply_notable_fills_port_host_mitre_and_description():
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
                "dest_port": "3389",
                "transport": "tcp",
                "dvc": "WIN-017UMT7DCGT.soorinsec.local",
                "src": "10.1.2.3",
                "source_guid": "af145ac9-6b34-49b9-af4a-afe5e342e47c",
                "_raw": 'dest_port="3389", dvc="WIN-017UMT7DCGT.soorinsec.local"',
            },
        },
    )
    assert alert.severity == "low"
    assert "3389" in alert.description
    assert "10.1.2.3" in alert.description
    assert alert.affected_hosts[-1] == "WIN-017UMT7DCGT.soorinsec.local"
    assert "10.1.2.3" in alert.affected_ips
    assert "T1046" in alert.mitre_techniques
    assert alert.enrichment_data["splunk_source_ref"] == "af145ac9-6b34-49b9-af4a-afe5e342e47c"
    iocs = iocs_from_raw(alert.raw_event)
    assert {"type": "port", "value": "tcp/3389"} in iocs
    rows = mitre_attack_rows(alert.mitre_techniques)
    assert any(row["technique_id"] == "T1046" for row in rows)
