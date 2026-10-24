"""Near-duplicate similarity must stay shadow-only and never replace fingerprints."""

from __future__ import annotations

import inspect

import app.services.fusion_engine as fusion_engine
import app.services.near_duplicate as near_dup
from app.services.near_duplicate import assess_near_duplicate, near_dup_shadow_enabled


def test_fusion_engine_does_not_call_near_duplicate():
    src = inspect.getsource(fusion_engine)
    assert "near_duplicate" not in src
    assert "assess_near_duplicate" not in src
    assert "DEDUP_SIMILARITY" not in src


def test_deceptively_similar_titles_with_different_users_not_merged():
    left = {
        "title": "ESCU - Detect Password Spray Attack Behavior On User - Rule",
        "username": "alice",
        "src_ip": "10.0.0.1",
        "rule_id": "spray-1",
    }
    right = {
        "title": "ESCU - Detect Password Spray Attack Behavior On User - Rule",
        "username": "bob",
        "src_ip": "10.0.0.2",
        "rule_id": "spray-1",
    }
    out = assess_near_duplicate(left, right)
    assert out.entity_conflict is True
    assert out.above_threshold is False
    assert out.shadow_only is True


def test_near_dup_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AISOC_NEAR_DUP_SHADOW", raising=False)
    assert near_dup_shadow_enabled() is False
