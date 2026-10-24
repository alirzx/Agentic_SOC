"""Shadow-only near-duplicate similarity."""

from __future__ import annotations

from app.services.near_duplicate import assess_near_duplicate, near_dup_shadow_enabled


def test_similar_titles_score_high_without_entity_conflict():
    left = {"title": "Detect Password Spray Attack Behavior On User", "username": "alice"}
    right = {"title": "Detect Password Spray Attack Behavior On User", "username": "alice"}
    out = assess_near_duplicate(left, right)
    assert out.score >= 0.85
    assert out.above_threshold is True
    assert out.shadow_only is True


def test_entity_conflict_blocks_merge_recommendation():
    left = {"title": "Password Spray On User", "username": "alice", "src_ip": "1.1.1.1"}
    right = {"title": "Password Spray On User", "username": "bob", "src_ip": "2.2.2.2"}
    out = assess_near_duplicate(left, right)
    assert out.entity_conflict is True
    assert out.above_threshold is False


def test_shadow_flag_defaults_off(monkeypatch):
    monkeypatch.delenv("AISOC_NEAR_DUP_SHADOW", raising=False)
    assert near_dup_shadow_enabled() is False
