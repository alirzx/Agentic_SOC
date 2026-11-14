"""Unit tests for Tier-2 Investigate IP pivot helpers."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from app.services.tier2_ip_pivot import extract_alert_ips


def test_extract_prefers_llm_payload_dest_and_src():
    alert = SimpleNamespace(
        affected_ips=[],
        llm_payload={"src_ip": "203.0.113.10", "dest_ip": "10.0.0.5"},
        raw_event={},
        enrichment_data={},
        iocs=[],
    )
    ips = extract_alert_ips(alert)
    assert ips.src_ips == ["203.0.113.10"]
    assert ips.dest_ips == ["10.0.0.5"]


def test_extract_from_raw_event_aliases():
    alert = {
        "affected_ips": [],
        "llm_payload": None,
        "raw_event": {"src": "198.51.100.7", "dst_ip": "192.168.1.20"},
        "enrichment_data": {},
        "iocs": [{"type": "ip", "value": "192.168.1.20"}],
    }
    ips = extract_alert_ips(alert)
    assert "198.51.100.7" in ips.src_ips
    assert "192.168.1.20" in ips.dest_ips


def test_extract_skips_garbage():
    alert = SimpleNamespace(
        affected_ips=["none", "0.0.0.0", "not-an-ip"],
        llm_payload={"dest_ip": "-"},
        raw_event={},
        enrichment_data={},
        iocs=[],
    )
    ips = extract_alert_ips(alert)
    assert ips.src_ips == []
    assert ips.dest_ips == []


def test_extract_affected_ips_as_fallback_src():
    alert = SimpleNamespace(
        id=uuid4(),
        affected_ips=["10.1.2.3"],
        llm_payload={},
        raw_event={},
        enrichment_data={},
        iocs=[],
    )
    ips = extract_alert_ips(alert)
    assert ips.src_ips == ["10.1.2.3"]
