"""Splunk notable → Alert field mapping (no live Splunk)."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from app.services.splunk_notable import (
    _has_wide_annotation_fields,
    _merge_stash_into_raw_event,
    _unwrap_splunk_stash,
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


def test_needs_hydrate_when_orig_rule_present_but_mitre_annotations_missing():
    """Older polls had MC extract fields but dropped annotations_mitre_attack."""
    alert = _alert(
        raw_event={
            "orig_rule_description": "The device connected to a prohibited port.",
            "detection_id": "6dd9e9ab-1111-2222-3333-444444444444",
            "dest_port": "3389",
        }
    )
    assert needs_hydrate(alert) is True


def test_needs_hydrate_false_when_wide_annotations_present():
    alert = _alert(
        raw_event={
            "orig_rule_description": "The device connected to a prohibited port.",
            "detection_id": "6dd9e9ab-1111-2222-3333-444444444444",
            "annotations_mitre_attack": "T1046",
            "dest_port": "3389",
        }
    )
    assert needs_hydrate(alert) is False


def test_extract_mitre_from_annotations_mitre_attack_field():
    ids = extract_mitre_ids({"annotations_mitre_attack": "T1110.003"})
    assert ids == ["T1110.003"]


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


def test_apply_notable_sets_mitre_from_annotations_mitre_attack():
    alert = _alert(mitre_techniques=[])
    apply_notable(
        alert,
        {
            "title": "ESCU - Detect Password Spray Attack Behavior From Source - Rule",
            "severity": "medium",
            "raw_event": {
                "search_name": "ESCU - Detect Password Spray Attack Behavior From Source - Rule",
                "annotations_mitre_attack": "T1110.003",
                "annotations": '{"mitre_attack":["T1110.003"],"analytic_story":["Compromised User Account"]}',
                "orig_rule_description": "Password spray analytic.",
                "detection_id": "abc",
                "notable_id": "nid-1",
            },
        },
    )
    assert alert.mitre_techniques == ["T1110.003"]
    assert alert.raw_event["annotations_mitre_attack"] == "T1110.003"
    assert alert.enrichment_data.get("splunk_wide_reenrich_attempted") is True


def test_unwrap_ocsf_nested_raw_data():
    ocsf = {
        "class_uid": 2001,
        "message": "ESCU - Detect Password Spray Attack Behavior From Source - Rule",
        "finding": {"uid": "e0158673-3e13-41a4-951e-1f0633f881e6@@notable@@time1790668163"},
        "raw_data": (
            '{"source":"splunk","raw_event":{"search_name":"ESCU - Detect Password Spray '
            'Attack Behavior From Source - Rule","src":"B_309",'
            '"source_event_id":"e0158673-3e13-41a4-951e-1f0633f881e6@@notable@@time1790668163",'
            '"orig_rule_description":"Password spray"}}'
        ),
    }
    stash = _unwrap_splunk_stash(ocsf)
    assert stash["src"] == "B_309"
    assert "Password spray" in stash["orig_rule_description"]
    assert not _has_wide_annotation_fields(ocsf)


def test_merge_wide_fields_into_ocsf_raw_for_raw_tab():
    ocsf = {
        "class_uid": 2001,
        "message": "ESCU - Detect Password Spray Attack Behavior From Source - Rule",
        "raw_data": '{"source":"splunk","raw_event":{"src":"B_309"}}',
        "metadata": {"product": {"name": "splunk"}},
    }
    stash = {
        "search_name": "ESCU - Detect Password Spray Attack Behavior From Source - Rule",
        "annotations_mitre_attack": "T1110.003",
        "annotations_analytic_story": "Compromised User Account",
        "src": "B_309",
        "orig_rule_description": "Password spray analytic.",
    }
    merged = _merge_stash_into_raw_event(ocsf, stash)
    assert merged["annotations_mitre_attack"] == "T1110.003"
    assert merged["splunk_notable"]["annotations_mitre_attack"] == "T1110.003"
    assert merged["class_uid"] == 2001
    assert _has_wide_annotation_fields(merged)


def test_apply_notable_merges_into_existing_ocsf_raw_event():
    alert = _alert(
        mitre_techniques=[],
        affected_users=[],
        raw_event={
            "class_uid": 2001,
            "message": "ESCU - Detect Password Spray Attack Behavior From Source - Rule",
            "finding": {"uid": "nid@@notable@@1"},
            "raw_data": '{"source":"splunk","raw_event":{"src":"B_309"}}',
            "metadata": {"product": {"name": "splunk"}},
            "src_endpoint": {"ip": "B_309"},
        },
    )
    apply_notable(
        alert,
        {
            "title": "ESCU - Detect Password Spray Attack Behavior From Source - Rule",
            "severity": "medium",
            "raw_event": {
                "search_name": "ESCU - Detect Password Spray Attack Behavior From Source - Rule",
                "annotations_mitre_attack": "T1110.003",
                "src": "B_309",
                "orig_rule_description": "Password spray analytic.",
                "notable_id": "nid@@notable@@1",
            },
        },
    )
    assert alert.raw_event["class_uid"] == 2001
    assert alert.raw_event["annotations_mitre_attack"] == "T1110.003"
    assert alert.mitre_techniques == ["T1110.003"]
