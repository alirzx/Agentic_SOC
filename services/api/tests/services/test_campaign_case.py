"""API-side campaign case helpers (funnel backfill)."""

from __future__ import annotations

from app.services.campaign_case import (
    campaign_case_title,
    infer_attack_theme,
    primary_campaign_key,
)


def test_infer_c2_theme():
    assert infer_attack_theme(title="Cobalt Strike C2 callback") == "command-and-control"


def test_title_is_campaign_narrative():
    title = campaign_case_title("lateral-movement", [("host", "WKSTN-22")])
    assert "lateral" in title.lower()
    assert "WKSTN-22" in title


def test_primary_key_stable():
    assert primary_campaign_key("impact", [("host", "FILE-01")]) == "impact|host:FILE-01"
