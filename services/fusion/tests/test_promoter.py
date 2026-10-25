"""Unit tests for the Phase 3.1 raw-event → RawAlert promotion bridge.

These cover the deterministic mapping logic. The gate that proves the bridge
works against real containers is `.github/workflows/integration.yml`
(scripts/integration/spine_test.py) — these tests never mock Kafka/Postgres
and never claim to.
"""

from __future__ import annotations

import json
import uuid

from app.models.alert import AlertSeverity
from app.services.promoter import promote_normalized_event, should_promote

TENANT = "00000000-0000-0000-0000-000000000001"
CONNECTOR = "00000000-0000-0000-0000-0000000000c1"


def _message(ocsf_overrides: dict | None = None) -> dict:
    ocsf = {
        "class_uid": 2001,
        "class_name": "Security Finding",
        "category_uid": 2,
        "severity_id": 5,
        "severity": "Critical",
        "message": "Credential dumping via LSASS access",
        "time": "2026-07-12T08:00:00Z",
        "tenant_uid": TENANT,
        "metadata": {"product": {"name": "Falcon", "vendor_name": "CrowdStrike"}},
        "device": {"name": "WIN-DC01"},
        "actor": {"user": {"name": "svc-backup"}},
        "src_endpoint": {"ip": "10.20.30.40"},
        "file": {"fingerprints": [{"value": "a" * 64}]},
        "mitre_attck": [
            {
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "tactic_names": ["Credential Access"],
            }
        ],
        "raw_data": '{"event_simpleName":"CredentialDump"}',
    }
    if ocsf_overrides:
        ocsf.update(ocsf_overrides)
    return {
        "id": str(uuid.uuid4()),
        "connector_id": CONNECTOR,
        "connector_type": "crowdstrike_falcon",
        "tenant_id": TENANT,
        "ocsf_event": ocsf,
        "normalization_version": "1.1.0",
    }


class TestShouldPromote:
    def test_findings_category_always_promotes(self):
        assert should_promote({"class_uid": 2004, "severity_id": 1})

    def test_findings_category_promotes_when_class_uid_is_float(self):
        assert should_promote({"class_uid": 2001.0, "severity_id": 1.0})

    def test_high_severity_non_finding_promotes(self):
        assert should_promote({"class_uid": 3002, "severity_id": 4})

    def test_critical_non_finding_promotes(self):
        assert should_promote({"class_uid": 4001, "severity_id": 5})

    def test_medium_non_finding_does_not_promote(self):
        assert not should_promote({"class_uid": 4001, "severity_id": 3})

    def test_unknown_severity_non_finding_does_not_promote(self):
        assert not should_promote({"class_uid": 6003, "severity_id": 0})

    def test_missing_fields_do_not_promote(self):
        assert not should_promote({})


class TestPromoteNormalizedEvent:
    def test_full_mapping(self):
        alert = promote_normalized_event(_message())
        assert alert is not None
        assert str(alert.tenant_id) == TENANT
        assert alert.title == "Credential dumping via LSASS access"
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.source == "CrowdStrike Falcon"
        assert alert.hostname == "WIN-DC01"
        assert alert.username == "svc-backup"
        assert alert.src_ip == "10.20.30.40"
        assert alert.file_hash == "a" * 64
        assert alert.mitre_techniques == ["T1003"]
        assert alert.mitre_tactics == ["Credential Access"]
        assert alert.event_time is not None
        assert alert.raw_event["class_uid"] == 2001
        # Provenance carried first-class (issue #568)
        assert str(alert.connector_id) == CONNECTOR
        assert alert.connector_type == "crowdstrike_falcon"
        assert alert.ocsf_class_uid == 2001

    def test_provenance_falls_back_to_ocsf_when_envelope_sparse(self):
        # No top-level connector_id/type — recover from the OCSF payload.
        msg = _message()
        del msg["connector_id"]
        del msg["connector_type"]
        msg["ocsf_event"]["source_connector_id"] = CONNECTOR
        alert = promote_normalized_event(msg)
        assert alert is not None
        assert str(alert.connector_id) == CONNECTOR
        # connector_type falls back to the OCSF product vendor+name label.
        assert alert.connector_type == "CrowdStrike Falcon"

    def test_canonical_id_is_deterministic_across_promotions(self):
        # The stamped id happens in the worker, but the derivation is on the
        # model and must be stable for identical content (issue #568).
        a = promote_normalized_event(_message())
        b = promote_normalized_event(_message())
        assert a is not None and b is not None
        assert a.deterministic_id() == b.deterministic_id()

    def test_severity_ladder(self):
        for sev_id, expected in [
            (5, AlertSeverity.CRITICAL),
            (4, AlertSeverity.HIGH),
            (3, AlertSeverity.MEDIUM),
            (2, AlertSeverity.LOW),
            (1, AlertSeverity.INFO),
        ]:
            alert = promote_normalized_event(_message({"severity_id": sev_id}))
            assert alert is not None, f"severity_id={sev_id} (finding) must promote"
            assert alert.severity == expected

    def test_below_threshold_non_finding_returns_none(self):
        msg = _message({"class_uid": 4001, "category_uid": 4, "severity_id": 2})
        assert promote_normalized_event(msg) is None

    def test_title_falls_back_to_class_and_product(self):
        msg = _message()
        del msg["ocsf_event"]["message"]
        alert = promote_normalized_event(msg)
        assert alert is not None
        assert alert.title == "Security Finding from Falcon"

    def test_non_uuid_tenant_returns_none(self):
        msg = _message()
        msg["tenant_id"] = "acme-corp"
        msg["ocsf_event"]["tenant_uid"] = "acme-corp"
        assert promote_normalized_event(msg) is None

    def test_malformed_message_returns_none(self):
        assert promote_normalized_event({"nope": True}) is None
        assert promote_normalized_event({"ocsf_event": "not-a-dict"}) is None

    def test_fingerprint_stable_across_promotions(self):
        # The same source event promoted twice must dedup downstream.
        a = promote_normalized_event(_message())
        b = promote_normalized_event(_message())
        assert a is not None and b is not None
        assert a.fingerprint() == b.fingerprint()

    def test_finding_uid_is_not_used_as_rule_id(self):
        msg = _message()
        msg["ocsf_event"]["finding"] = {"uid": "UNIQUE-EVENT-1"}
        alert = promote_normalized_event(msg)
        assert alert is not None
        assert alert.source_event_ids == ["UNIQUE-EVENT-1"]
        assert alert.rule_id != "UNIQUE-EVENT-1"

    def test_prefers_finding_title_over_message(self):
        msg = _message(
            {
                "message": "verbose ocsf body",
                "finding": {
                    "title": "Network - Unapproved Port Activity Detected - Rule",
                },
            }
        )
        alert = promote_normalized_event(msg)
        assert alert is not None
        assert alert.title == "Network - Unapproved Port Activity Detected - Rule"
        assert alert.rule_name == alert.title

    def test_envelope_title_beats_generic_message(self):
        msg = _message({"message": "Security Finding"})
        msg["title"] = "Network - Unapproved Port Activity Detected - Rule"
        alert = promote_normalized_event(msg)
        assert alert is not None
        assert alert.title == "Network - Unapproved Port Activity Detected - Rule"

    def test_multivalue_hostname_from_splunk_dest_is_coerced(self):
        # Splunk often returns dest/dvc as a multivalue list; Pydantic rejects
        # list→str and used to drop the whole message in fusion.
        alert = promote_normalized_event(
            _message(
                {
                    "device": {"name": ["win-dc-137.attackrange.local", "win-dc-137"]},
                    "src_endpoint": {"ip": ["10.0.0.8"]},
                }
            )
        )
        assert alert is not None
        assert alert.hostname == "win-dc-137.attackrange.local"
        assert alert.src_ip == "10.0.0.8"

    def test_description_prefers_finding_desc_over_raw_data(self):
        # ingest maps the canonical connector ``description`` to finding.desc;
        # the alert description must be that text, not the truncated envelope.
        msg = _message(
            {
                "finding": {
                    "desc": "The following analytic identifies DNS queries to 3CX IOC domains."
                },
                "raw_data": '{"description":"The following analytic identifies DNS queries to 3CX IOC domains.","raw_event":{}}',
            }
        )
        alert = promote_normalized_event(msg)
        assert alert is not None
        assert alert.description == (
            "The following analytic identifies DNS queries to 3CX IOC domains."
        )

    def test_description_falls_back_to_raw_data_when_finding_desc_missing(self):
        alert = promote_normalized_event(_message())
        assert alert is not None
        assert alert.description == '{"event_simpleName":"CredentialDump"}'

    def test_llm_payload_is_lifted_from_the_connector_envelope(self):
        # The Splunk notable carries llm_payload on the vendor row, which ingest
        # tucks into raw_data (canonical envelope JSON) and OCSF keeps as
        # raw_data. Promotion lifts it to a first-class RawAlert field so agents
        # never unwrap three levels at prompt time.
        payload = {
            "alert_id": "d1ef60ed-07e8-4581-ba9f-2b5de38a9daa",
            "rule_name": "ESCU - 3CX Supply Chain Attack Network Indicators - Rule",
            "event_time_source": "first_event",
            "alert_fields": {"query": "www.3cx.com", "isIOC": "TRUE"},
        }
        envelope = {
            "source": "splunk",
            "external_id": "d1ef60ed-07e8-4581-ba9f-2b5de38a9daa",
            "title": "ESCU - 3CX Supply Chain Attack Network Indicators - Rule",
            "severity": "medium",
            "raw_event": {
                "_time": "2026-10-24T14:33:41Z",
                "llm_payload": json.dumps(payload),
            },
        }
        alert = promote_normalized_event(_message({"raw_data": json.dumps(envelope)}))
        assert alert is not None
        assert alert.llm_payload == payload

    def test_llm_payload_is_none_without_one(self):
        alert = promote_normalized_event(_message())
        assert alert is not None
        assert alert.llm_payload is None

    def test_llm_payload_does_not_disturb_the_fingerprint(self):
        # The payload is evidence, not identity: adding it must not mint a new
        # alert on the next poll of the same notable.
        envelope = {
            "source": "splunk",
            "raw_event": {"llm_payload": json.dumps({"alert_id": "x", "rule": {"spl": "| tstats count"}})},
        }
        without = promote_normalized_event(_message())
        with_payload = promote_normalized_event(_message({"raw_data": json.dumps(envelope)}))
        assert without is not None and with_payload is not None
        assert without.fingerprint() == with_payload.fingerprint()

    def test_empty_or_missing_llm_payload_is_none(self):
        # A saved search / operator SPL that predates the payload must promote to
        # NULL, never to an empty object that claims evidence exists.
        for raw_payload in (None, "", "   ", "{}", "null", "[]"):
            envelope = {"source": "splunk", "raw_event": {"llm_payload": raw_payload}}
            alert = promote_normalized_event(_message({"raw_data": json.dumps(envelope)}))
            assert alert is not None
            assert alert.llm_payload is None, raw_payload

    def test_llm_payload_stripped_from_raw_event(self):
        # llm_payload must NOT appear inside raw_event — it lives in its own
        # first-class column (migration 061) and must not duplicate there.
        # raw_data arrives from ingest as a JSON-encoded string (not a dict).
        payload = {"alert_id": "abc", "severity": "high"}
        inner_raw_event = {
            "_time": "2026-10-25T10:00:00Z",
            "llm_payload": json.dumps(payload),
            "entity": "WIN-01",
        }
        connector_envelope = {
            "source": "splunk",
            "raw_event": inner_raw_event,
        }
        alert = promote_normalized_event(
            _message({"raw_data": json.dumps(connector_envelope)})
        )
        assert alert is not None
        assert alert.llm_payload == payload
        # llm_payload must be absent from every layer of raw_event
        assert "llm_payload" not in alert.raw_event
        raw_data_str = alert.raw_event.get("raw_data")
        if raw_data_str:
            raw_data_obj = json.loads(raw_data_str) if isinstance(raw_data_str, str) else raw_data_str
            assert "llm_payload" not in raw_data_obj
            inner = raw_data_obj.get("raw_event") if isinstance(raw_data_obj, dict) else None
            if isinstance(inner, dict):
                assert "llm_payload" not in inner
