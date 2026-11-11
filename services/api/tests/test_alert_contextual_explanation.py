"""Unit tests for Ambient Copilot explanation parse + merge helpers."""

from __future__ import annotations

from types import SimpleNamespace

from app.services.alert_contextual_explanation import (
    build_explanation_record,
    explanation_for_agents,
    get_stored_explanation,
    merge_explanation_into_enrichment,
    parse_explanation_markdown,
)


SAMPLE_MD = """## What this alert means

This is a Splunk ESCU detection-rule hit, not a confirmed compromise.

## Likely attacker behavior

DNS queries to a sinkhole domain can indicate malware C2.

## Suggested next steps

- Pivot on the querying host in the last 24 hours
- Check EDR for the same process tree
- Confirm whether the domain is still on the blocklist
"""


def test_parse_explanation_markdown_extracts_sections_and_steps():
    parsed = parse_explanation_markdown(SAMPLE_MD)
    assert "splunk escu" in (parsed["meaning"] or "").lower()
    assert len(parsed["suggested_next_steps"]) == 3
    assert "Pivot on the querying host" in parsed["suggested_next_steps"][0]
    assert parsed["markdown"].startswith("## What this alert means")


def test_build_and_merge_explanation_record():
    record = build_explanation_record(SAMPLE_MD, model="DeepSeek-V4-Flash")
    assert record["model"] == "DeepSeek-V4-Flash"
    assert record["source"] == "contextual_explain"
    assert len(record["suggested_next_steps"]) == 3
    merged = merge_explanation_into_enrichment({"foo": 1}, record)
    assert merged["foo"] == 1
    assert merged["contextual_explanation"]["markdown"].startswith("## What")


def test_explanation_for_agents_reads_enrichment():
    record = build_explanation_record(SAMPLE_MD, model="test-model")
    alert = SimpleNamespace(
        enrichment_data=merge_explanation_into_enrichment({}, record)
    )
    stored = get_stored_explanation(alert)
    assert stored is not None
    shaped = explanation_for_agents(alert)
    assert shaped is not None
    assert shaped["suggested_next_steps"][0].startswith("Pivot")
    assert shaped["model"] == "test-model"
