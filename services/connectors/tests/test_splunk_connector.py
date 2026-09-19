"""Splunk connector: saved-search dispatch (#525), normalize-once (#528), and
checkpointed pagination + deterministic identity (#529)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from app.connectors.splunk import SplunkConnector

BASE = "https://splunk.test:8089"


def _conn(**kw) -> SplunkConnector:
    return SplunkConnector(base_url=BASE, token="tok", **kw)


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


def test_normalize_deterministic_external_id():
    c = _conn()
    assert c.normalize({"_cd": "1:99", "urgency": "low"})["external_id"] == "1:99"
    assert c.normalize({"event_id": "E7"})["external_id"] == c.normalize({"event_id": "E7"})["external_id"]


# --------------------------------------------------------------------------
# ordering + checkpoint (#529)
# --------------------------------------------------------------------------


def test_order_and_checkpoint_filters_seen_and_advances():
    c = _conn()
    c.set_checkpoint({"time": "2026-08-01T00:00:10Z", "id": "E10"})
    rows = [
        {"event_id": "E09", "_time": "2026-08-01T00:00:09Z"},  # before checkpoint -> dropped
        {"event_id": "E10", "_time": "2026-08-01T00:00:10Z"},  # == checkpoint -> dropped
        {"event_id": "E12", "_time": "2026-08-01T00:00:12Z"},
        {"event_id": "E11", "_time": "2026-08-01T00:00:11Z"},
    ]
    fresh = c._order_and_checkpoint(rows)
    assert [r["event_id"] for r in fresh] == ["E11", "E12"]  # stable order restored
    assert c.get_checkpoint() == {"time": "2026-08-01T00:00:12Z", "id": "E12"}


def test_checkpoint_not_advanced_when_nothing_new():
    c = _conn()
    c.set_checkpoint({"time": "2026-08-01T00:00:99Z", "id": "Z"})
    assert c._order_and_checkpoint([{"event_id": "E1", "_time": "2026-08-01T00:00:01Z"}]) == []
    assert c.get_checkpoint() is None


def test_same_timestamp_distinct_ids_both_kept():
    c = _conn()
    rows = [
        {"event_id": "A", "_time": "2026-08-01T00:00:10Z"},
        {"event_id": "B", "_time": "2026-08-01T00:00:10Z"},
    ]
    assert {r["event_id"] for r in c._order_and_checkpoint(rows)} == {"A", "B"}


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
    jobs = respx.post(url__regex=r".+/services/search/jobs$").mock(return_value=httpx.Response(201, json={"sid": "SID2"}))
    respx.get(url__regex=r".+/services/search/jobs/SID2/results").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.get(url__regex=r".+/services/search/jobs/SID2(\?.*)?$").mock(return_value=_done_status())

    await c.fetch_alerts()
    assert jobs.called
    assert "notable" in jobs.calls[0].request.content.decode()


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


def test_timeless_catalog_skips_checkpoint_filter():
    c = _conn()
    c.set_checkpoint({"time": "", "id": "Zzz"})
    rows = [
        {"Notable Name": "AAA Rule", "Severity": "3"},
        {"Notable Name": "MMM Rule", "Severity": "4"},
    ]
    fresh = c._order_and_checkpoint(rows)
    assert len(fresh) == 2
    assert c.get_checkpoint() is None


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
            {"event_id": f"E{i}", "_time": f"2026-08-01T00:{(i // 60) % 60:02d}:{i % 60:02d}Z"}
            for i in range(offset, min(offset + count, total))
        ]
        return httpx.Response(200, json={"results": page})

    respx.get(url__regex=r".+/services/search/jobs/S/results").mock(side_effect=_results)

    out = await c.fetch_alerts()
    # All 250 survive — the old `head 100` / count=100 cap silently dropped 150.
    assert len(out) == total
    assert len({e["external_id"] for e in out}) == total
