"""Attack-campaign case identity (not same-title buckets)."""

from __future__ import annotations

from app.workers.campaign_case import (
    campaign_case_title,
    campaign_entities,
    infer_attack_theme,
    primary_campaign_key,
)


def test_infer_theme_from_mitre_tactic():
    assert (
        infer_attack_theme(mitre_tactics=["command-and-control"], title="noise")
        == "command-and-control"
    )
    assert infer_attack_theme(mitre_tactics=["lateral-movement"]) == "lateral-movement"


def test_infer_theme_from_title_keywords():
    assert (
        infer_attack_theme(title="Possible C2 beacon to 1.2.3.4") == "command-and-control"
    )
    assert (
        infer_attack_theme(title="Password spray against VPN") == "credential-access"
    )


def test_campaign_title_is_narrative_not_rule_name():
    entities = [("host", "WIN-DC01"), ("ip", "10.1.2.3")]
    title = campaign_case_title("command-and-control", entities)
    assert "C2" in title or "command-and-control" in title
    assert "WIN-DC01" in title
    assert "Risk - 24 Hour" not in title


def test_campaign_key_prefers_host():
    key = primary_campaign_key(
        "command-and-control",
        [("ip", "10.0.0.1"), ("host", "SRV-01"), ("user", "alice")],
    )
    assert key == "command-and-control|host:SRV-01"


def test_entities_from_alert_and_raw():
    ents = campaign_entities(
        {"hostname": "HOST-A", "affected_ips": ["9.9.9.9"]},
        {"src_ip": "1.1.1.1", "username": "bob"},
    )
    kinds = {k for k, _ in ents}
    values = {v for _, v in ents}
    assert "host" in kinds and "ip" in kinds and "user" in kinds
    assert "HOST-A" in values and "bob" in values
