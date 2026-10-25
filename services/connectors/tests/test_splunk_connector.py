"""Splunk connector: saved-search dispatch (#525), normalize-once (#528), and
checkpointed pagination + deterministic identity (#529)."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from app.connectors.splunk import (
    SplunkConnector,
    _DEFAULT_NOTABLE_SPL,
    _is_replaceable_notable_search,
    _should_oneshot,
    mission_control_spl,
)

BASE = "https://splunk.test:8089"


def _conn(**kw) -> SplunkConnector:
    return SplunkConnector(base_url=BASE, token="tok", **kw)


def test_mission_control_spl_tables_extracted_fields():
    spl = mission_control_spl()
    assert spl.startswith("search index=notable")
    assert "eval rule_specific_json=json_object()" in spl
    assert "orig_rule_description" in spl
    assert "notable_id=coalesce" in spl
    assert "llm_payload=json_object" in spl
    assert "analyst_labels=json_object" in spl
    assert "annotations_mitre_attack" in spl
    assert "annotations_analytic_story" in spl
    assert "earliest=" not in spl
    lookup = mission_control_spl('(search_name="Network - Unapproved Port Activity Detected - Rule")', limit=5)
    assert "search_name=" in lookup
    assert "| head 5" in lookup


def test_custom_search_is_never_silently_replaced():
    """Operator Custom SPL (including index=notable) must not be treated as blank."""
    notable = (
        "search index=notable "
        "| table _time source search_name severity urgency host dvc dest "
        "dest_port transport src src_ip source_guid source_event_id event_id _cd _raw"
    )
    assert _is_replaceable_notable_search("")
    assert _is_replaceable_notable_search("   ")
    assert not _is_replaceable_notable_search(notable)
    assert not _is_replaceable_notable_search(
        "search index=notable | extract | eval notable_id=coalesce(source_event_id, source_guid, detection_id) | table _time"
    )
    assert not _is_replaceable_notable_search(
        "search index=agentic* | extract "
        "| eval notable_id=coalesce(source_event_id, source_guid, detection_id) "
        "| table _time notable_id search_name | sort 0 - _time"
    )
    assert not _is_replaceable_notable_search("| rest /services/saved/searches | table title")
    assert not _is_replaceable_notable_search(_DEFAULT_NOTABLE_SPL)
    assert not _should_oneshot(_DEFAULT_NOTABLE_SPL)
    assert not _should_oneshot(mission_control_spl())
    assert not _should_oneshot("| rest /services/saved/searches | table title")


def test_poll_earliest_uses_checkpoint_time_when_present():
    c = _conn(earliest_time="-90d@d")
    assert c._poll_earliest(1800) == "-90d@d"
    # Recent checkpoint → exact resume time.
    from datetime import datetime, timedelta, timezone

    recent = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime(
        "%Y-%m-%dT%H:%M:%S.000+00:00"
    )
    c.set_checkpoint({"time": recent, "id": "abc"})
    assert c._poll_earliest(1800) == recent
    c.set_checkpoint({"time": "", "id": "abc"})
    assert c._poll_earliest(1800) == "-1920s"


def test_poll_earliest_caps_stale_checkpoint_catchup():
    """Ancient checkpoint must not open a multi-day Splunk window (timeout → Error)."""
    from datetime import datetime, timedelta, timezone

    c = _conn(earliest_time="-90d@d")
    ancient = (datetime.now(timezone.utc) - timedelta(days=3)).strftime(
        "%Y-%m-%dT%H:%M:%S.000+00:00"
    )
    c.set_checkpoint({"time": ancient, "id": "old"})
    earliest = c._poll_earliest(1800)
    assert earliest != ancient
    # Relative form is not used — absolute floor near "now - max catchup".
    assert earliest.endswith("+00:00") or earliest.endswith("Z")


# --------------------------------------------------------------------------
# normalize: idempotent + deterministic identity (#528 / #529)
# --------------------------------------------------------------------------


def test_normalize_is_idempotent():
    c = _conn()
    row = {
        "event_id": "E1",
        "search_name": "Brute Force Detected",
        "urgency": "high",
        "_time": "2026-08-01T00:00:00Z",
        "src": "1.2.3.4",
        "host": "h1",
    }
    once = c.normalize(row)
    twice = c.normalize(once)
    # Re-normalizing a canonical envelope must be a no-op (no blanked
    # external_id, no title -> "splunk", no severity reset, no double nesting).
    assert twice == once
    assert once["external_id"] == "E1"
    assert once["title"] == "Brute Force Detected"
    assert once["severity"] == "high"
    assert once["hostname"] == "h1"
    assert once["raw_event"] == row


def test_normalize_unwraps_multivalue_search_name():
    """Splunk often returns search_name as a duplicated list; keep a scalar title."""
    c = _conn()
    row = {
        "event_id": "E-mv",
        "search_name": [
            "ESCU - Windows UAC Bypass Suspicious Child Process - Rule",
            "ESCU - Windows UAC Bypass Suspicious Child Process - Rule",
        ],
        "urgency": "medium",
        "_time": "2026-10-14T17:23:00Z",
        "host": ["host-a", "host-a"],
        "src": ["10.0.0.1", "10.0.0.1"],
    }
    out = c.normalize(row)
    assert out["title"] == "ESCU - Windows UAC Bypass Suspicious Child Process - Rule"
    assert out["hostname"] == "host-a"
    assert out["src_ip"] == "10.0.0.1"


def test_normalize_stable_when_vendor_ids_missing():
    c = _conn()
    row = {
        "search_name": "Network - Unapproved Port Activity Detected - Rule",
        "_time": "2026-06-01T00:00:00Z",
        "host": "WIN-017UMT7DCGT.soorinsec.local",
        "src": "10.0.0.8",
        "dest_port": "445",
    }
    once = c.normalize(row)
    twice = c.normalize(dict(row))
    assert once["external_id"]
    assert once["external_id"] == twice["external_id"]
    assert once["external_id"] != c.normalize({**row, "dest_port": "3389"})["external_id"]


def test_normalize_deterministic_external_id():
    c = _conn()
    assert c.normalize({"_cd": "1:99", "urgency": "low"})["external_id"] == "1:99"
    assert c.normalize({"event_id": "E7"})["external_id"] == c.normalize({"event_id": "E7"})["external_id"]


# --------------------------------------------------------------------------
# ordering + checkpoint (#529)
# --------------------------------------------------------------------------


def test_order_and_checkpoint_filters_seen_and_advances():
    c = _conn()
    c.set_checkpoint({"time": "2026-08-01T00:00:10Z", "id": "E10", "seen": ["E10"]})
    rows = [
        {"event_id": "E09", "_time": "2026-08-01T00:00:09Z"},  # before checkpoint -> dropped
        {"event_id": "E10", "_time": "2026-08-01T00:00:10Z"},  # == checkpoint -> dropped
        {"event_id": "E12", "_time": "2026-08-01T00:00:12Z"},
        {"event_id": "E11", "_time": "2026-08-01T00:00:11Z"},
    ]
    fresh = c._order_and_checkpoint(rows)
    assert [r["event_id"] for r in fresh] == ["E11", "E12"]  # stable order restored
    cp = c.get_checkpoint()
    assert cp is not None
    assert cp["time"] == "2026-08-01T00:00:12Z"
    assert cp["id"] == "E12"
    assert "E11" in cp["seen"] and "E12" in cp["seen"] and "E10" in cp["seen"]


def test_checkpoint_not_advanced_when_nothing_new():
    c = _conn()
    c.set_checkpoint({"time": "2026-08-01T00:00:99Z", "id": "Z", "seen": ["Z"]})
    assert c._order_and_checkpoint([{"event_id": "E1", "_time": "2026-08-01T00:00:01Z"}]) == []
    assert c.get_checkpoint() is None


def test_same_timestamp_distinct_ids_both_kept():
    c = _conn()
    rows = [
        {"event_id": "A", "_time": "2026-08-01T00:00:10Z"},
        {"event_id": "B", "_time": "2026-08-01T00:00:10Z"},
    ]
    assert {r["event_id"] for r in c._order_and_checkpoint(rows)} == {"A", "B"}


def test_overlap_poll_skips_ids_already_in_seen_ring():
    """Inclusive earliest_time re-reads watermark rows — seen ids must suppress them."""
    c = _conn()
    c.set_checkpoint(
        {
            "time": "2026-08-01T00:00:10.000+00:00",
            "id": "E10",
            "seen": ["E09", "E10"],
        }
    )
    # Same events again, plus one new — Z vs +00:00 must not defeat the watermark.
    rows = [
        {"event_id": "E09", "_time": "2026-08-01T00:00:09Z"},
        {"event_id": "E10", "_time": "2026-08-01T00:00:10Z"},
        {"event_id": "E11", "_time": "2026-08-01T00:00:11Z"},
    ]
    fresh = c._order_and_checkpoint(rows)
    assert [r["event_id"] for r in fresh] == ["E11"]


# --------------------------------------------------------------------------
# saved-search dispatch vs notable fallback (#525) + pagination (#529)
# --------------------------------------------------------------------------


def _done_status() -> httpx.Response:
    return httpx.Response(200, json={"entry": [{"content": {"dispatchState": "DONE"}}]})


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_dispatches_configured_saved_search():
    c = _conn(saved_search="My Search")
    # Name is URL-encoded into the dispatch path, never injected into SPL.
    dispatch = respx.post(url__regex=r".+/services/saved/searches/My%20Search/dispatch").mock(
        return_value=httpx.Response(201, json={"sid": "SID1"})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID1/results").mock(
        return_value=httpx.Response(200, json={"results": [{"event_id": "E1", "urgency": "high", "_time": "2026-08-01T00:00:00Z"}]})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID1(\?.*)?$").mock(return_value=_done_status())

    out = await c.fetch_alerts(since_seconds=300)
    assert dispatch.called, "configured saved_search was not dispatched (#525)"
    assert len(out) == 1
    assert out[0]["external_id"] == "E1"
    assert out[0]["severity"] == "high"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_falls_back_to_notable_index_when_unset():
    c = _conn(saved_search="")
    jobs = respx.post(url__regex=r".+/services/search/jobs$").mock(
        return_value=httpx.Response(201, json={"sid": "SID-NOTABLE"})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID-NOTABLE/results").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "_time": "2026-07-01T12:48:35.000+03:30",
                        "notable_id": "af145ac9-6b34-49b9-af4a-afe5e342e47c",
                        "search_name": "Network - Unapproved Port Activity Detected - Rule",
                        "dvc": "WIN-017UMT7DCGT.soorinsec.local",
                        "dest_port": "3389",
                        "severity": "low",
                        "orig_rule_title": "Prohibited Port Activity Detected",
                        "orig_rule_description": "The device connected to a prohibited port.",
                        "llm_payload": '{"alert_id": "af145ac9-6b34-49b9-af4a-afe5e342e47c", "severity": "low"}',
                        "analyst_labels": '{"status": "open", "owner": null}',
                    }
                ],
            },
        )
    )
    respx.get(url__regex=r".+/services/search/jobs/SID-NOTABLE(\?.*)?$").mock(
        return_value=_done_status()
    )
    out = await c.fetch_alerts()
    body = jobs.calls[0].request.content.decode()
    assert "notable" in body
    assert "eval rule_specific_json" in body
    assert "llm_payload" in body
    assert "orig_rule_description" in body
    assert "exec_mode=oneshot" not in body
    assert len(out) == 1
    assert out[0]["hostname"] == "WIN-017UMT7DCGT.soorinsec.local"
    assert out[0]["description"].startswith("The device connected")
    assert out[0]["raw_event"]["dest_port"] == "3389"
    assert "llm_payload" in out[0]["raw_event"]


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_with_checkpoint_resumes_from_checkpoint_time():
    from datetime import datetime, timedelta, timezone
    from urllib.parse import unquote_plus

    c = _conn(saved_search="")
    # Within catch-up cap so earliest_time stays the checkpoint (not floor).
    cp_time = (datetime.now(timezone.utc) - timedelta(minutes=15)).strftime(
        "%Y-%m-%dT%H:%M:%S.000+00:00"
    )
    c.set_checkpoint({"time": cp_time, "id": "old"})
    jobs = respx.post(url__regex=r".+/services/search/jobs$").mock(
        return_value=httpx.Response(201, json={"sid": "SID-CP"})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID-CP/results").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "_time": (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime(
                            "%Y-%m-%dT%H:%M:%S.000+00:00"
                        ),
                        "notable_id": "new-1",
                        "search_name": "Fresh Notable",
                        "severity": "high",
                        "llm_payload": '{"alert_id": "new-1", "severity": "high"}',
                        "analyst_labels": '{}',
                    }
                ]
            },
        )
    )
    respx.get(url__regex=r".+/services/search/jobs/SID-CP(\?.*)?$").mock(
        return_value=_done_status()
    )
    out = await c.fetch_alerts(since_seconds=1800)
    body = unquote_plus(jobs.calls[0].request.content.decode())
    assert cp_time in body
    assert "-1920s" not in body
    assert "exec_mode=oneshot" not in body
    assert len(out) == 1
    assert out[0]["title"] == "Fresh Notable"
    assert "llm_payload" in out[0]["raw_event"]


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_custom_search_uses_basic_auth_and_earliest():
    c = SplunkConnector(
        base_url=BASE,
        username="admin",
        password="secret",
        custom_search='search rest splunk_server=local count=0 /services/saved/searches | table title',
        earliest_time="-90d@d",
        ssl_verify=False,
    )
    jobs = respx.post(url__regex=r".+/services/search/jobs$").mock(
        return_value=httpx.Response(201, json={"sid": "SID3"})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID3/results").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "Notable Name": "Brute Force Detected",
                        "Description": "Too many failures",
                        "Severity": "4",
                    }
                ]
            },
        )
    )
    respx.get(url__regex=r".+/services/search/jobs/SID3(\?.*)?$").mock(return_value=_done_status())

    out = await c.fetch_alerts()
    assert jobs.called
    body = jobs.calls[0].request.content.decode()
    assert "earliest_time" in body and "-90d" in body
    auth_header = jobs.calls[0].request.headers.get("authorization", "")
    assert auth_header.lower().startswith("basic ")
    assert len(out) == 1
    assert out[0]["title"] == "Brute Force Detected"
    assert out[0]["severity"] == "high"
    assert out[0]["external_id"]


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_honors_index_notable_custom_search():
    """Custom SPL starting with index=notable must run as saved — not agentic* default."""
    custom = (
        "search index=notable | table _time source search_name severity host "
        "dvc dest_port source_guid source_event_id _cd _raw"
    )
    c = SplunkConnector(
        base_url=BASE,
        username="admin",
        password="secret",
        custom_search=custom,
        earliest_time="-90d@d",
        ssl_verify=False,
    )
    jobs = respx.post(url__regex=r".+/services/search/jobs$").mock(
        return_value=httpx.Response(201, json={"sid": "SID-NOTABLE"})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID-NOTABLE/results").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID-NOTABLE(\?.*)?$").mock(
        return_value=_done_status()
    )

    await c.fetch_alerts()
    assert jobs.called
    body = jobs.calls[0].request.content.decode()
    assert "index%3Dnotable" in body or "index=notable" in body
    assert "index%3Dagentic" not in body and "index=agentic" not in body


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_pipe_rest_is_not_prefixed_with_search():
    c = SplunkConnector(
        base_url=BASE,
        username="admin",
        password="secret",
        custom_search="| rest splunk_server=local count=0 /services/saved/searches | head 1",
        ssl_verify=False,
    )
    jobs = respx.post(url__regex=r".+/services/search/jobs$").mock(
        return_value=httpx.Response(201, json={"sid": "SID4"})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID4/results").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    respx.get(url__regex=r".+/services/search/jobs/SID4(\?.*)?$").mock(return_value=_done_status())

    await c.fetch_alerts()
    body = jobs.calls[0].request.content.decode()
    assert "search=%7C+rest" in body or "search=| rest" in body or "%7C%20rest" in body
    assert "search+search" not in body
    assert "search%20search" not in body


def test_ssl_verify_string_false_is_disabled():
    c = SplunkConnector(base_url=BASE, username="a", password="b", ssl_verify="false")
    assert c._ssl_verify is False


def test_normalize_parses_notable_stash_raw():
    c = _conn()
    raw = {
        "_time": "2026-07-01T12:48:35.000+03:30",
        "host": "SH",
        "index": "notable",
        "source": "Network - Unapproved Port Activity Detected - Rule",
        "_cd": "37:42",
        "_raw": (
            '1782897512, search_name="Network - Unapproved Port Activity Detected - Rule", '
            'dest_port="3389", dvc="WIN-017UMT7DCGT.soorinsec.local", severity="low", '
            'source_guid="af145ac9-6b34-49b9-af4a-afe5e342e47c", transport="tcp"'
        ),
    }
    out = c.normalize(raw)
    assert out["title"] == "Network - Unapproved Port Activity Detected - Rule"
    assert out["severity"] == "low"
    assert out["hostname"] == "WIN-017UMT7DCGT.soorinsec.local"
    assert out["external_id"] == "af145ac9-6b34-49b9-af4a-afe5e342e47c"
    assert out["raw_event"]["dest_port"] == "3389"


def test_normalize_mission_control_extract_row():
    c = _conn()
    row = {
        "_time": "2026-07-01T12:48:35.000+03:30",
        "notable_id": "af145ac9-6b34-49b9-af4a-afe5e342e47c",
        "search_name": "Network - Unapproved Port Activity Detected - Rule",
        "detection_id": "6dd9e9ab-1111-2222-3333-444444444444",
        "dvc": "WIN-017UMT7DCGT.soorinsec.local",
        "dest_port": "3389",
        "src": "10.1.2.3",
        "severity": "low",
        "orig_rule_title": "Prohibited Port Activity Detected",
        "orig_rule_description": "The device connected to a prohibited port.",
        "transport": "tcp",
        "is_prohibited": "true",
        "llm_payload": '{"alert_id": "af145ac9-6b34-49b9-af4a-afe5e342e47c"}',
        "analyst_labels": '{"status": "open", "severity": "low"}',
    }
    out = c.normalize(row)
    assert out["title"] == "Network - Unapproved Port Activity Detected - Rule"
    assert out["description"].startswith("The device connected")
    assert out["hostname"] == "WIN-017UMT7DCGT.soorinsec.local"
    assert out["external_id"] == "af145ac9-6b34-49b9-af4a-afe5e342e47c"
    assert out["raw_event"]["detection_id"] == "6dd9e9ab-1111-2222-3333-444444444444"
    assert "llm_payload" in out["raw_event"]
    assert "analyst_labels" in out["raw_event"]


def test_normalize_extracts_mitre_from_annotations():
    c = _conn()
    row = {
        "_time": "2026-09-29T11:19:26.000+03:30",
        "search_name": "ESCU - Detect Password Spray Attack Behavior From Source - Rule",
        "source_event_id": "e0158673-3e13-41a4-951e-1f0633f881e6@@notable@@time1790668163",
        "severity": "medium",
        "annotations_mitre_attack": "T1110.003",
        "annotations": (
            '{"analytic_story":["Compromised User Account"],'
            '"mitre_attack":["T1110.003"],"type":"TTP"}'
        ),
        "src": "B_309",
    }
    out = c.normalize(row)
    assert out["mitre_techniques"] == ["T1110.003"]
    assert out["raw_event"]["annotations_mitre_attack"] == "T1110.003"


@respx.mock
@pytest.mark.asyncio
async def test_lookup_notable_filters_search_name_and_host():
    c = _conn()
    # Lookups use oneshot + return results in the POST body (fast path).
    jobs = respx.post(url__regex=r".+/services/search/jobs$").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "_time": "2026-07-01T12:48:35.000+03:30",
                        "search_name": "Network - Unapproved Port Activity Detected - Rule",
                        "dest_port": "3389",
                        "dvc": "WIN-017UMT7DCGT.soorinsec.local",
                        "src": "10.1.2.3",
                        "transport": "tcp",
                        "severity": "low",
                        "orig_rule_description": "The device connected to a prohibited port.",
                        "llm_payload": '{"alert_id": "lookup-1", "severity": "low"}',
                        "analyst_labels": '{"status": "open"}',
                    }
                ],
            },
        )
    )
    out = await c.lookup_notable(
        "Network - Unapproved Port Activity Detected - Rule",
        "WIN-017UMT7DCGT.soorinsec.local",
    )
    assert out is not None
    assert out["hostname"] == "WIN-017UMT7DCGT.soorinsec.local"
    assert out["raw_event"]["dest_port"] == "3389"
    assert "llm_payload" in out["raw_event"]
    body = jobs.calls[0].request.content.decode()
    assert "Unapproved" in body
    assert "eval rule_specific_json" in body
    assert "llm_payload" in body
    assert "orig_rule_description" in body
    assert "exec_mode=oneshot" in body
    assert "earliest_time=-30d" in body


def test_timeless_catalog_dedupes_via_seen_ids():
    """Catalog SPL rows have no _time — still must not re-emit on every Sync."""
    c = _conn()
    rows = [
        {"Notable Name": "AAA Rule", "Severity": "3"},
        {"Notable Name": "MMM Rule", "Severity": "4"},
    ]
    first = c._order_and_checkpoint(rows)
    assert len(first) == 2
    cp = c.get_checkpoint()
    assert cp is not None
    assert "AAA Rule" in cp["seen"] and "MMM Rule" in cp["seen"]

    c2 = _conn()
    c2.set_checkpoint(cp)
    second = c2._order_and_checkpoint(rows)
    assert second == []
    assert c2.get_checkpoint() is None


def test_normalize_es_catalog_row():
    c = _conn()
    row = {
        "Notable Name": "Access - Excessive Failed Logins",
        "Description": "ES correlation",
        "Severity": "5",
        "Notable SPL": "| tstats ...",
    }
    out = c.normalize(row)
    assert out["title"] == "Access - Excessive Failed Logins"
    assert out["severity"] == "critical"
    assert out["description"] == "ES correlation"


def test_normalize_preserves_llm_payload_and_analyst_labels():
    """Verify that llm_payload and analyst_labels are properly preserved in raw_event."""
    c = _conn()
    llm_payload = {
        "alert_id": "test-alert-1",
        "severity": "high",
        "rule_name": "Suspicious Login",
        "annotations": {"mitre_attack": ["T1110.003"]},
    }
    analyst_labels = {
        "status": "investigating",
        "owner": "SOC-Team",
        "urgency": "high",
        "disposition": "true_positive",
    }
    row = {
        "_time": "2026-10-01T15:30:00Z",
        "notable_id": "test-alert-1",
        "search_name": "Suspicious Login",
        "severity": "high",
        "src": "192.168.1.100",
        "host": "target-host",
        "llm_payload": json.dumps(llm_payload),
        "analyst_labels": json.dumps(analyst_labels),
    }
    out = c.normalize(row)
    assert out["external_id"] == "test-alert-1"
    assert out["title"] == "Suspicious Login"
    assert out["severity"] == "high"
    # Verify both fields are preserved in raw_event
    assert "llm_payload" in out["raw_event"]
    assert "analyst_labels" in out["raw_event"]
    assert out["raw_event"]["llm_payload"] == json.dumps(llm_payload)
    assert out["raw_event"]["analyst_labels"] == json.dumps(analyst_labels)


@respx.mock
@pytest.mark.asyncio
async def test_pagination_collects_all_results_no_head_cap():
    c = _conn(saved_search="", page_size=100)
    total = 250
    respx.post(url__regex=r".+/services/search/jobs$").mock(return_value=httpx.Response(201, json={"sid": "S"}))
    respx.get(url__regex=r".+/services/search/jobs/S(\?.*)?$").mock(return_value=_done_status())

    def _results(request: httpx.Request) -> httpx.Response:
        qs = parse_qs(urlparse(str(request.url)).query)
        offset = int(qs.get("offset", ["0"])[0])
        count = int(qs.get("count", ["100"])[0])
        page = [
            {
                "event_id": f"E{i}",
                "_time": f"2026-08-01T00:{(i // 60) % 60:02d}:{i % 60:02d}Z",
                "llm_payload": f'{{"alert_id": "E{i}", "severity": "medium"}}',
                "analyst_labels": '{}',
            }
            for i in range(offset, min(offset + count, total))
        ]
        return httpx.Response(200, json={"results": page})

    respx.get(url__regex=r".+/services/search/jobs/S/results").mock(side_effect=_results)

    out = await c.fetch_alerts()
    # All 250 survive — the old `head 100` / count=100 cap silently dropped 150.
    assert len(out) == total
    assert len({e["external_id"] for e in out}) == total
    # Verify llm_payload is preserved in raw_event
    assert all("llm_payload" in e["raw_event"] for e in out)
