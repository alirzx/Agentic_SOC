"""Splunk query modes: simple projection, auto threshold, fallback, payload.

The Mission Control pipeline needs memory proportional to the notable window;
instances holding tens of thousands of notables get a memory error and ingest
nothing at all. These tests pin the behaviour of the alternatives:

* ``pipeline`` (default) — unchanged for every existing connector instance.
* ``simple`` — the low-memory projection, with the LLM payload built in Python.
* ``auto`` — a cheap count decides, and a failed count never downgrades.
* ``fallback_to_simple_on_failure`` — opt-in, and the reason is recorded.

The connector's HTTP layer is stubbed rather than mocked at the httpx level:
what needs pinning is the mode decision and the provenance it produces, not the
shape of Splunk's REST responses (covered by ``test_splunk_connector.py``).
"""

from __future__ import annotations

import pytest
from app.connectors.splunk import (
    _ALERT_FIELD_EXCLUDE_RE,
    _DEFAULT_NOTABLE_SPL,
    _SIMPLE_NOTABLE_SPL,
    SplunkConnector,
    _is_platform_default_spl,
)

BASE = "https://splunk.test:8089"

_SIMPLE_ROW = {
    "_time": "1793091032",
    "source": "ESCU - Access LSASS Memory for Dump Creation - Rule",
    "search_name": "ESCU - Access LSASS Memory for Dump Creation - Rule",
    "severity": "medium",
    "host": "win-dc-807",
    "dvc": "win-dc-807.attackrange.local",
    "dest_port": "445",
    "source_guid": "5bca1049-61ea-4e08-b0e1-321eb738d6f9",
    "source_event_id": "5bca1049-61ea-4e08-b0e1-321eb738d6f9@@notable@@time1793091032",
    "_cd": "123:456",
    "_raw": 'firstTime="2026-10-27T12:20:21", process_name="lsass.exe",',
    "firstTime": "2026-10-27T12:20:21",
    "annotations_mitre_attack": ["T1003.001"],
}


class _Stub(SplunkConnector):
    """Connector with the transport replaced by a scriptable recorder."""

    def __init__(self, **kw) -> None:
        super().__init__(base_url=BASE, token="tok", **kw)
        self.searches: list[str] = []
        self.pipeline_calls = 0
        self.pipeline_error: Exception | None = None
        self.count: int | None = 0
        self.count_error: Exception | None = None
        self.rule_context: dict | None = None
        self.enrichment_calls = 0

    async def _run_adhoc(self, client, search, earliest, *, oneshot):  # noqa: ANN001
        normalised = " ".join(search.split())
        self.searches.append(normalised)
        if "| stats count" in normalised:
            if self.count_error is not None:
                raise self.count_error
            return [{"count": str(self.count)}]
        return [dict(_SIMPLE_ROW)]

    async def _fetch_pipeline(self, client, earliest):  # noqa: ANN001
        self.pipeline_calls += 1
        if self.pipeline_error is not None:
            raise self.pipeline_error
        return [
            {
                "_time": "1793091032",
                "search_name": "Rule A",
                "severity": "high",
                "llm_payload": '{"rule": {"title": "Rule A"}, "_meta": {"mode": "pipeline"}}',
            }
        ]

    async def _attach_rule_context(self, client, rows):  # noqa: ANN001
        self.enrichment_calls += 1
        if self.rule_context:
            for row in rows:
                row["_rule_context"] = dict(self.rule_context)


def _conn(**kw) -> _Stub:
    return _Stub(**kw)


# ─── Mode defaults ───────────────────────────────────────────────────────────


def test_default_mode_is_pipeline_and_does_not_touch_the_simple_query():
    conn = _conn()
    assert conn._query_mode == "pipeline"
    assert conn._fallback_to_simple is False


def test_unknown_mode_falls_back_to_pipeline():
    conn = _conn(query_mode="turbo")
    assert conn._query_mode == "pipeline"


def test_bad_threshold_falls_back_to_the_shipped_default():
    conn = _conn(pipeline_max_notables="not-a-number")
    assert conn._pipeline_max_notables == 20_000


# ─── Mode selection ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pipeline_mode_runs_the_mission_control_pipeline():
    conn = _conn()
    rows = await conn._fetch_rows(None, "-1h")
    assert conn.pipeline_calls == 1
    assert len(rows) == 1
    assert conn._poll_provenance["query_mode"] == "pipeline"
    assert conn._poll_provenance["llm_payload_source"] == "query"
    assert conn.searches == []


@pytest.mark.asyncio
async def test_simple_mode_issues_the_projection_and_records_provenance():
    conn = _conn(query_mode="simple")
    rows = await conn._fetch_rows(None, "-1h")

    assert conn.pipeline_calls == 0
    assert conn.searches == [" ".join(_SIMPLE_NOTABLE_SPL.split())]
    assert rows, "simple mode must still return rows"
    assert conn.enrichment_calls == 1

    provenance = conn._poll_provenance
    assert provenance["query_mode"] == "simple"
    assert provenance["reason"] == "operator_configured"
    assert provenance["llm_payload_source"] == "code"
    assert "simple_query_projection" in provenance["caveats"]


@pytest.mark.asyncio
async def test_auto_mode_above_threshold_switches_to_simple():
    conn = _conn(query_mode="auto", pipeline_max_notables=20_000)
    conn.count = 24_310
    await conn._fetch_rows(None, "-1h")

    assert conn.pipeline_calls == 0
    assert any("stats count" in search for search in conn.searches)
    assert conn._poll_provenance["query_mode"] == "simple"
    assert conn._poll_provenance["reason"] == "volume_above_threshold"
    assert conn._poll_provenance["notable_volume"] == 24_310
    assert conn._poll_provenance["threshold"] == 20_000


@pytest.mark.asyncio
async def test_auto_mode_below_threshold_keeps_the_pipeline():
    conn = _conn(query_mode="auto", pipeline_max_notables=20_000)
    conn.count = 42
    await conn._fetch_rows(None, "-1h")

    assert conn.pipeline_calls == 1
    assert conn._poll_provenance["query_mode"] == "pipeline"
    assert conn._poll_provenance["reason"] == "auto_below_threshold"


@pytest.mark.asyncio
async def test_auto_mode_keeps_the_pipeline_when_the_count_is_unavailable():
    """A restricted count search must not silently downgrade ingestion."""
    conn = _conn(query_mode="auto")
    conn.count_error = RuntimeError("403 Forbidden")
    await conn._fetch_rows(None, "-1h")

    assert conn.pipeline_calls == 1
    assert conn._poll_provenance["query_mode"] == "pipeline"


# ─── Failure fallback ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pipeline_failure_raises_by_default():
    conn = _conn()
    conn.pipeline_error = RuntimeError("Failed to execute search: out of memory")
    with pytest.raises(RuntimeError, match="out of memory"):
        await conn._fetch_rows(None, "-1h")


@pytest.mark.asyncio
async def test_fallback_records_why_it_used_the_simple_query():
    conn = _conn(fallback_to_simple_on_failure=True)
    conn.pipeline_error = RuntimeError("Failed to execute search: out of memory")
    rows = await conn._fetch_rows(None, "-1h")

    assert rows
    provenance = conn._poll_provenance
    assert provenance["query_mode"] == "simple"
    assert provenance["reason"] == "pipeline_failed"
    assert provenance["fallback_from"] == "pipeline"
    assert "out of memory" in provenance["fallback_error"]


# ─── Custom SPL is sacred ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_operator_custom_spl_is_never_replaced_by_simple_mode():
    conn = _conn(query_mode="simple", custom_search="search index=main | head 5")
    await conn._fetch_rows(None, "-1h")

    assert conn.searches == ["search index=main | head 5"]
    assert conn._poll_provenance["query_mode"] == "custom"


def test_platform_default_spl_counts_as_replaceable():
    """The schema pre-fills ``custom_search`` with the pipeline — that is not
    operator work, so ``query_mode`` must still be able to take effect."""
    assert _is_platform_default_spl(_DEFAULT_NOTABLE_SPL)
    assert _is_platform_default_spl("  " + _DEFAULT_NOTABLE_SPL.replace("\n", " ") + "  ")
    assert not _is_platform_default_spl("search index=main | head 5")


@pytest.mark.asyncio
async def test_simple_mode_applies_even_when_custom_search_holds_the_default():
    conn = _conn(query_mode="simple", custom_search=_DEFAULT_NOTABLE_SPL)
    await conn._fetch_rows(None, "-1h")
    assert conn.pipeline_calls == 0
    assert conn.searches == [" ".join(_SIMPLE_NOTABLE_SPL.split())]


# ─── Python payload builder ──────────────────────────────────────────────────


def test_payload_builder_marks_what_it_could_not_recover():
    conn = _conn(query_mode="simple")
    payload = conn._build_llm_payload(dict(_SIMPLE_ROW))

    assert payload["rule"]["title"] == _SIMPLE_ROW["search_name"]
    assert payload["rule"]["spl"] is None
    assert payload["annotations"]["mitre_attack"] == ["T1003.001"]
    assert payload["event_time_source"] == "first_event"
    assert payload["_meta"]["mode"] == "simple"

    caveats = payload["_meta"]["caveats"]
    assert "rule_spl_unavailable" in caveats
    assert "time_window_unavailable" in caveats
    assert "simple_query_projection" in caveats


def test_payload_builder_recovers_rule_spl_and_macros_when_available():
    conn = _conn(query_mode="simple")
    row = dict(_SIMPLE_ROW)
    row["_rule_context"] = {
        "spl": "`sysmon` EventCode=10 TargetImage=*lsass.exe",
        "title_template": "process $SourceImage$ dumped LSASS on $dest$",
        "macros": [{"name": "sysmon", "definition": "index=* source=XmlWinEventLog"}],
        "earliest": "-4m",
        "latest": "now",
    }
    payload = conn._build_llm_payload(row)

    assert payload["rule"]["spl"].startswith("`sysmon`")
    assert payload["rule"]["macro_definitions"][0]["name"] == "sysmon"
    assert payload["rule"]["title_template"].startswith("process $SourceImage$")
    assert "rule_spl_unavailable" not in payload["_meta"]["caveats"]


def test_payload_builder_records_a_skipped_enrichment():
    conn = _conn(query_mode="simple")
    row = dict(_SIMPLE_ROW)
    row["_rule_context"] = {"skipped": "too_many_rules"}
    payload = conn._build_llm_payload(row)
    assert "rule_enrichment_skipped" in payload["_meta"]["caveats"]


def test_payload_alert_fields_exclude_metadata_columns():
    conn = _conn(query_mode="simple")
    row = dict(_SIMPLE_ROW)
    row["process_name"] = "lsass.exe"
    row["llm_payload"] = {"ignored": True}
    payload = conn._build_llm_payload(row)

    assert payload["alert_fields"]["process_name"] == "lsass.exe"
    assert "search_name" not in payload["alert_fields"]
    assert "llm_payload" not in payload["alert_fields"]
    assert not _ALERT_FIELD_EXCLUDE_RE.match("process_name")


def test_time_window_uses_notable_info_when_present():
    conn = _conn()
    window = conn._time_window(
        {"info_min_time": "1793090430.0", "info_max_time": "1793090430.9", "info_search_time": "1793091030.98"}
    )
    assert window["source"] == "notable_info"
    assert window["earliest"].startswith("2026-10-27T")


def test_time_window_is_unknown_rather_than_invented():
    conn = _conn()
    window = conn._time_window({})
    assert window == {"earliest": None, "latest": None, "search_time": None, "source": "unknown"}


def test_macro_refs_are_deduplicated_and_capped():
    conn = _conn()
    spl = "`sysmon` `sysmon` `a_filter` `b` `c` `d` `e` `f` `g` `h` `i` `j`"
    refs = conn._macro_refs(spl)
    assert refs[0] == "sysmon"
    assert len(refs) == len(set(refs))
    assert len(refs) <= 8


def test_annotations_fall_back_to_the_json_blob():
    conn = _conn()
    row = {"annotations": '{"mitre_attack": ["T1059"], "kill_chain_phases": ["Execution"]}'}
    annotations = conn._annotations_from_row(row)
    assert annotations["mitre_attack"] == ["T1059"]
    assert annotations["kill_chain_phases"] == ["Execution"]
    assert annotations["cve"] is None


# ─── normalize wiring ────────────────────────────────────────────────────────


def test_normalize_attaches_the_built_payload_and_provenance():
    conn = _conn(query_mode="simple")
    conn._poll_provenance = {
        "source": "splunk",
        "query_mode": "simple",
        "reason": "volume_above_threshold",
        "notable_volume": 24_310,
        "threshold": 20_000,
        "llm_payload_source": "code",
        "caveats": ["simple_query_projection"],
    }
    event = conn.normalize(dict(_SIMPLE_ROW))

    raw = event["raw_event"]
    assert raw["llm_payload"]["_meta"]["mode"] == "simple"
    assert raw["runbook_provenance"]["query_mode"] == "simple"
    assert raw["runbook_provenance"]["notable_volume"] == 24_310


def test_normalize_keeps_the_query_payload_when_the_pipeline_provided_one():
    conn = _conn()
    conn._poll_provenance = {"source": "splunk", "query_mode": "pipeline", "llm_payload_source": "query"}
    row = dict(_SIMPLE_ROW)
    row["llm_payload"] = '{"rule": {"title": "from the query"}}'
    event = conn.normalize(row)

    # Verbatim: the query's own payload keeps its wire form; fusion parses it.
    assert event["raw_event"]["llm_payload"] == '{"rule": {"title": "from the query"}}'
    assert event["raw_event"]["runbook_provenance"]["query_mode"] == "pipeline"


def test_normalize_does_not_fabricate_a_payload_for_pipeline_rows():
    conn = _conn()
    conn._poll_provenance = {"source": "splunk", "query_mode": "pipeline", "llm_payload_source": "query"}
    event = conn.normalize(dict(_SIMPLE_ROW))
    assert "llm_payload" not in event["raw_event"]


def test_normalize_does_not_dress_up_operator_spl():
    conn = _conn()
    conn._poll_provenance = {"source": "splunk", "query_mode": "custom", "llm_payload_source": None}
    event = conn.normalize(dict(_SIMPLE_ROW))
    assert "llm_payload" not in event["raw_event"]
    assert event["raw_event"]["runbook_provenance"]["query_mode"] == "custom"
