"""P1 mandatory gate — Universal Entity Extraction."""

from __future__ import annotations

import json

from app.services.tier2_adaptive.entities import (
    extract_alert_entities,
    powershell_regression_alert,
)


def test_host_extraction_from_alert_fields():
    alert = {
        "llm_payload": {"alert_fields": {"Computer": "host01.example.local"}},
        "raw_event": {},
    }
    result = extract_alert_entities(alert)
    hosts = result.values("hostname")
    assert "host01.example.local" in hosts
    assert any(e.source_field == "Computer" for e in result.by_type("hostname"))


def test_user_sid_extraction():
    sid = "S-1-5-21-1793179736-1175893981-2474273398-13753"
    alert = {"llm_payload": {"alert_fields": {"user_id": f"'{sid}'"}}}
    result = extract_alert_entities(alert)
    assert result.values("user_sid") == [sid]
    assert result.by_type("user_sid")[0].original_value == sid


def test_process_extraction():
    alert = {
        "llm_payload": {
            "alert_fields": {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ParentImage": r"C:\Windows\explorer.exe",
                "ProcessId": "4242",
            }
        }
    }
    result = extract_alert_entities(alert)
    assert "powershell.exe" in result.values("process_name")
    assert "explorer.exe" in result.values("parent_process")
    assert "4242" in result.values("process_id")


def test_file_path_extraction():
    path = r"C:\Windows\TEMP\SDIAG_a982bdc8-63b3-40e9-b454-8def2c201900\CL_Utility.ps1"
    alert = {"llm_payload": {"alert_fields": {"Path": path}}}
    result = extract_alert_entities(alert)
    assert path in result.values("file_path")


def test_hash_extraction():
    sha = "a" * 64
    alert = {
        "iocs": [{"type": "sha256", "value": sha}],
        "llm_payload": {"alert_fields": {"md5": "b" * 32}},
    }
    result = extract_alert_entities(alert)
    hashes = result.values("file_hash")
    assert sha in hashes
    assert "b" * 32 in hashes


def test_ip_extraction():
    alert = {
        "affected_ips": ["10.1.2.3"],
        "llm_payload": {"src_ip": "203.0.113.10", "dest_ip": "10.0.0.5"},
        "raw_event": {"src": "198.51.100.7"},
    }
    result = extract_alert_entities(alert)
    ips = set(result.values("ip"))
    assert {"10.1.2.3", "203.0.113.10", "10.0.0.5", "198.51.100.7"} <= ips


def test_multiple_entities_same_type_preserved():
    alert = {
        "llm_payload": {
            "alert_fields": {
                "Computer": "cao01vw013.cao.ir",
                "extracted_host": "SH2",
            }
        }
    }
    result = extract_alert_entities(alert)
    hosts = result.by_type("hostname")
    norms = {e.normalized_value for e in hosts}
    assert "cao01vw013.cao.ir" in norms
    assert "sh2" in norms
    assert len(norms) == 2


def test_nested_json_extraction():
    alert = {
        "raw_event": {
            "event": {
                "alert_fields": {
                    "Computer": "nested-host.corp",
                    "user_id": "S-1-5-21-1-2-3-4",
                }
            }
        }
    }
    result = extract_alert_entities(alert)
    assert "nested-host.corp" in result.values("hostname")
    assert "S-1-5-21-1-2-3-4" in result.values("user_sid")


def test_conflicting_sources_not_overwritten():
    alert = {
        "hostname": "column-host.local",
        "llm_payload": {"alert_fields": {"Computer": "fields-host.local"}},
        "raw_event": {"hostname": "raw-host.local"},
    }
    result = extract_alert_entities(alert)
    hosts = result.values("hostname")
    assert "column-host.local" in hosts
    assert "fields-host.local" in hosts
    assert "raw-host.local" in hosts
    # Provenance retained for each
    fields = {e.source_field for e in result.by_type("hostname")}
    assert "hostname" in fields or "Computer" in fields


def test_malformed_payloads_safe():
    alert = {
        "llm_payload": "not-a-dict",
        "raw_event": {"alert_fields": "also-bad"},
        "enrichment_data": {"rule_specific_json": "{not json"},
        "annotations": "{",
        "iocs": "oops",
        "affected_hosts": None,
    }
    result = extract_alert_entities(alert)
    assert result.entities == []


def test_missing_entities_returns_empty_not_error():
    result = extract_alert_entities({"title": "no entities here", "severity": "high"})
    assert result.entities == []
    assert result.counts_by_type() == {}


def test_entity_normalization():
    alert = {
        "llm_payload": {
            "alert_fields": {
                "Computer": "HOST.Example.COM.",
                "user_id": "'S-1-5-21-1-2-3-99'",
                "sha256": "AA" + ("b" * 62),
                "src_ip": "192.168.1.1",
            }
        }
    }
    result = extract_alert_entities(alert)
    assert "host.example.com" in result.values("hostname")
    assert result.values("user_sid") == ["S-1-5-21-1-2-3-99"]
    assert result.values("file_hash") == ["aa" + ("b" * 62)]
    assert "192.168.1.1" in result.values("ip")


def test_provenance_preservation():
    alert = powershell_regression_alert()
    result = extract_alert_entities(alert)
    computer = next(
        e for e in result.by_type("hostname") if e.original_value == "cao01vw013.cao.ir"
    )
    assert computer.source_field == "Computer"
    assert "alert_fields" in computer.source_location
    assert computer.is_observed is True
    assert computer.is_inferred is False
    assert computer.extractor_name == "tier2_adaptive.entities"
    assert computer.extraction_timestamp
    assert 0.0 < computer.confidence <= 1.0


def test_powershell_regression_case():
    alert = powershell_regression_alert()
    result = extract_alert_entities(alert)

    host_vals = {e.normalized_value for e in result.by_type("hostname")}
    assert "cao01vw013.cao.ir" in host_vals
    assert "sh2" in host_vals
    # Must remain separate observed values
    computer = next(e for e in result.by_type("hostname") if "cao01" in e.normalized_value)
    alias = next(e for e in result.by_type("hostname") if e.normalized_value == "sh2")
    assert computer.source_field == "Computer"
    assert alias.source_field == "extracted_host"
    assert computer.normalized_value != alias.normalized_value

    assert "S-1-5-21-1793179736-1175893981-2474273398-13753" in result.values("user_sid")
    paths = result.values("file_path")
    assert any("CL_Utility.ps1" in p for p in paths)
    assert any("SDIAG_" in p for p in paths)

    scripts = result.values("script_block")
    assert scripts
    assert "Get-FreeSpace" in scripts[0]

    assert result.values("source_event_id")
    assert "@@notable@@" in result.values("source_event_id")[0]

    # Event ID 4104 must NOT be inferred from title alone
    assert "4104" not in result.values("event_id")
    assert result.values("ip") == []


def test_event_id_only_from_evidence_not_title():
    alert = {
        "title": "PowerShell Script Block Logging Event ID 4104 detected",
        "rule_name": "ESCU - Powershell 4104",
        "llm_payload": {"alert_fields": {"Computer": "x.local"}},
    }
    result = extract_alert_entities(alert)
    assert result.values("event_id") == []

    alert2 = {
        "llm_payload": {"alert_fields": {"EventCode": "4104", "Computer": "x.local"}},
    }
    result2 = extract_alert_entities(alert2)
    assert "4104" in result2.values("event_id")


def test_avoid_false_positive_from_unrelated_fields():
    alert = {
        "llm_payload": {
            "alert_fields": {
                "count": 1,
                "description": "talked about 8.8.8.8 and host evil.com in prose",
                "severity": "high",
            }
        },
        "title": "Something about 1.2.3.4",
    }
    result = extract_alert_entities(alert)
    assert result.values("ip") == []
    assert result.values("hostname") == []
    assert result.values("domain") == []


def test_to_dict_roundtrip_shape():
    result = extract_alert_entities(powershell_regression_alert())
    payload = result.to_dict()
    assert payload["extractor_version"].startswith("entity:")
    assert isinstance(payload["entities"], list)
    assert payload["counts_by_type"]["hostname"] >= 2
    # JSON-serializable
    json.dumps(payload)


def test_inferred_endpoint_flagged():
    alert = {"llm_payload": {"alert_fields": {"Computer": "ep01.corp.local"}}}
    result = extract_alert_entities(alert)
    endpoints = result.by_type("endpoint")
    assert endpoints
    assert endpoints[0].is_inferred is True
    assert endpoints[0].normalized_value == "ep01.corp.local"
