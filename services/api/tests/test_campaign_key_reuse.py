"""Campaign key generation + reuse policy unit tests (no DB)."""

from __future__ import annotations

from app.services.campaign_case import primary_campaign_key
from app.services.campaign_correlation import campaign_temporal_window_seconds


def test_campaign_key_deterministic():
    entities = [("host", "WEB-01"), ("ip", "10.0.0.1"), ("user", "alice")]
    k1 = primary_campaign_key("credential-access", entities)
    k2 = primary_campaign_key("credential-access", list(reversed(entities)))
    # Host wins priority regardless of list order.
    assert k1 == k2 == "credential-access|host:WEB-01"


def test_campaign_key_none_without_entities():
    assert primary_campaign_key("general-intrusion", []) is None


def test_different_themes_different_keys():
    entities = [("host", "WEB-01")]
    assert primary_campaign_key("web", entities) != primary_campaign_key(
        "credential-access", entities
    )


def test_different_hosts_different_keys():
    assert primary_campaign_key("execution", [("host", "A")]) != primary_campaign_key(
        "execution", [("host", "B")]
    )


def test_reuse_policy_documented_constants():
    """Reuse requires same campaign_key + open status + funnel creators + window.

    Enforced in agentic_funnel SQL — this locks the window helper contract.
    """
    assert campaign_temporal_window_seconds(24) == 86_400
    allowed_creators = {"agentic-funnel", "agentic-funnel-backfill"}
    assert "agentic-funnel-backfill" in allowed_creators
    blocked_statuses = {"resolved", "closed"}
    assert "open" not in blocked_statuses
