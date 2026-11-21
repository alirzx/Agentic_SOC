"""Bundle tests: what the TKG (and the judge) are allowed to see."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from app.services.tkg_evaluation.bundle import build_bundle, fingerprint, normalize_alert


def _alert(**overrides):
    row = {
        "id": "0b6c2f3a-0000-4000-8000-000000000001",
        "title": "Suspicious PowerShell",
        "severity": "high",
        "event_time": datetime(2026, 11, 16, 12, 0, tzinfo=UTC),
        "rule_name": "Credential Access - LSASS",
        "mitre_techniques": ["T1003.001"],
        "llm_payload": {
            "rule": {"name": "Credential Access - LSASS"},
            "src_host": "win-dc-01",
            "dest_ip": "10.0.0.9",
            "user": "svc_backup",
            "command_line": "powershell -enc AAAA",
            "password": "should-never-leave",
        },
    }
    row.update(overrides)
    return row


def test_normalize_extracts_identity_keys_only():
    item = normalize_alert(_alert())
    assert item["hosts"] == ["win-dc-01"]
    assert item["users"] == ["svc_backup"]
    assert "10.0.0.9" in item["ips"]
    assert item["rule"] == "Credential Access - LSASS"
    assert item["techniques"] == ["T1003.001"]
    # The payload's own scalar fields are not dumped wholesale.
    assert "password" not in item
    assert set(item) <= {
        "alert_id", "notable_id", "time", "title", "severity", "rule", "techniques", "hosts",
        "users", "ips", "domains", "urls", "hashes", "processes", "commands", "truncated",
        "funnel_stage", "deduplicated", "occurrence_count",
    }


def test_normalize_reads_the_current_escu_payload_shape():
    """New payloads wrap a JSON string and keep identity in ``alert_fields``.

    ``alert_fields.raw`` (the deprecated k=v blob) must not be needed: the flat
    dict is authoritative and the notable's own ``entity``/``risk_object`` adds
    the actor the rule fired on.
    """

    inner = {
        "alert_id": "005cb761-8591-4280-a8e2-c6fea4e85953",
        "rule_name": "ESCU - Windows Steal Authentication Certificates CertUtil Backup - Rule",
        "severity": "high",
        "event_time": "2026-11-16T14:53:52+0330",
        "entity": "administrator",
        "entity_type": "user",
        "risk_object": "win-dc-01.attackrange.local",
        "risk_object_type": "system",
        "annotations": {"mitre_attack": "T1649", "kill_chain_phases": "Exploitation"},
        "rule": {"title": "Windows Steal Authentication Certificates CertUtil Backup"},
        "alert_fields": {
            "dest": "win-dc-01.attackrange.local",
            "user": "administrator",
            "src": "10.10.4.12",
            "process": '"C:\\Windows\\system32\\certutil.exe" -backupdb c:\\temp',
            "process_name": "certutil.exe",
            "action": "allowed",
            "count": 3,
            "process_guid": None,
            "raw": "dest=ignored-by-design, user=ignored",
        },
    }
    row = {
        "id": "005cb761-8591-4280-a8e2-c6fea4e85953",
        "title": "Windows Steal Authentication Certificates CertUtil Backup",
        "severity": "high",
        "event_time": None,
        "rule_name": None,
        "mitre_techniques": [],
        "llm_payload": json.dumps({"llm_payload": json.dumps(inner)}),
    }

    item = normalize_alert(row)
    assert item["alert_id"] == "005cb761-8591-4280-a8e2-c6fea4e85953"
    # The graph is keyed on the payload's notable id, which is what was ingested.
    assert item["notable_id"] == "005cb761-8591-4280-a8e2-c6fea4e85953"
    assert item["users"] == ["administrator"]
    assert "win-dc-01.attackrange.local" in item["hosts"]
    assert item["ips"] == ["10.10.4.12"]
    assert "certutil.exe" in item["processes"]
    assert item["commands"] == ['"C:\\Windows\\system32\\certutil.exe" -backupdb c:\\temp']
    assert item["techniques"] == ["T1649"]
    assert item["time"] == "2026-11-16T14:53:52+0330"
    # The deprecated raw blob is not parsed, so its values never appear.
    assert "ignored-by-design" not in json.dumps(item)


def test_build_bundle_orders_by_time_and_is_deterministic():
    later = _alert(id="b", event_time=datetime(2026, 11, 16, 13, 0, tzinfo=UTC))
    earlier = _alert(id="a", event_time=datetime(2026, 11, 16, 11, 0, tzinfo=UTC))
    bundle = build_bundle(case={"id": "c1", "title": "Case"}, alerts=[later, earlier])
    assert bundle["ok"] is True
    assert [a["alert_id"] for a in bundle["payload"]["alerts"]] == ["a", "b"]
    assert bundle["stats"]["fingerprint"] == fingerprint(bundle["payload"]["alerts"])


def test_build_bundle_refuses_empty_and_unusable_cases():
    assert build_bundle(case={"id": "c"}, alerts=[])["reason"] == "no_alerts"
    no_payload = build_bundle(
        case={"id": "c"},
        alerts=[{"id": "a", "title": "x", "llm_payload": {"note": "nothing correlatable"}}],
    )
    assert no_payload["ok"] is False
    assert no_payload["reason"] == "no_llm_payload"


def test_soft_deduplicated_alerts_are_sent_and_labelled():
    """Dedup losers are case witnesses: they go to the graph, flagged as such."""

    alert = _alert(funnel_stage="deduplicated", occurrence_count=7)
    item = normalize_alert(alert)
    assert item["deduplicated"] is True
    assert item["funnel_stage"] == "deduplicated"
    assert item["occurrence_count"] == 7

    bundle = build_bundle(case={"id": "c"}, alerts=[alert])
    assert bundle["ok"] is True
    assert bundle["stats"]["deduplicated"] == 1
    assert bundle["payload"]["alerts"][0]["deduplicated"] is True


def test_oversized_case_is_compacted_before_refusing():
    """A 500-alert campaign must still get a verdict, not a 'too big' error."""

    alerts = [_alert(id=f"a{i:03d}") for i in range(30)]
    # 30 fixture alerts cost ~9.5k raw and ~8.7k compacted; the cap sits between.
    bundle = build_bundle(case={"id": "c"}, alerts=alerts, max_chars=9_000)

    assert bundle["ok"] is True
    assert bundle["payload"].get("trimmed") is True
    first = bundle["payload"]["alerts"][0]
    assert first["notable_id"]
    assert set(first) <= {
        "alert_id", "notable_id", "time", "title", "severity", "rule", "techniques",
        "hosts", "users", "ips", "domains", "urls", "hashes", "processes",
        "deduplicated", "occurrence_count", "truncated",
    }
    assert all(len(v) <= 3 for k, v in first.items() if isinstance(v, list))


def test_build_bundle_refuses_oversized_case():
    bundle = build_bundle(
        case={"id": "c"}, alerts=[_alert(), _alert(id="z")], max_alerts=1
    )
    assert bundle["reason"] == "too_many_alerts"
    assert bundle["stats"]["canonical"] == 2


def test_dedup_witnesses_do_not_count_toward_the_alert_cap():
    """A campaign is as wide as its distinct alerts, not its repeats."""

    canonical = _alert()
    witnesses = [
        _alert(id=f"w{i:03d}", funnel_stage="deduplicated", occurrence_count=5)
        for i in range(20)
    ]
    bundle = build_bundle(case={"id": "c"}, alerts=[canonical, *witnesses], max_alerts=1)

    assert bundle["ok"] is True
    assert bundle["stats"]["canonical"] == 1
    assert bundle["stats"]["deduplicated"] == 20
    # Every witness still rides along: the second pass is what sends them.
    assert len(bundle["payload"]["alerts"]) == 21


def test_canonical_alerts_over_the_cap_are_still_refused():
    alerts = [_alert(id=f"a{i}") for i in range(3)] + [
        _alert(id=f"w{i}", funnel_stage="deduplicated") for i in range(5)
    ]
    bundle = build_bundle(case={"id": "c"}, alerts=alerts, max_alerts=2)

    assert bundle["reason"] == "too_many_alerts"
    assert "max_alerts" in bundle["stats"]
    assert bundle["detail"].startswith("3 distinct alert(s)")
