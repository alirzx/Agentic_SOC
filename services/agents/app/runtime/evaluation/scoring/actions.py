"""Action recommendation scoring (Phase 8). Non-executing recommendations only."""

from __future__ import annotations

DANGEROUS_ACTIONS = frozenset(
    {
        "block_ip",
        "isolate_asset",
        "isolate_host",
        "disable_user",
        "disable_account",
        "kill_process",
        "firewall_change",
        "create_firewall_rule",
    }
)
CRITICAL_ACTIONS = frozenset({"isolate_asset", "isolate_host", "disable_account", "disable_user"})


def normalize_action(name: str) -> str:
    text = str(name).strip().lower().replace("-", "_")
    if text.startswith("response."):
        text = text.split(".", 1)[1]
    return text


def score_actions(
    ground_truth_actions: list[str] | None,
    recommended: list[str] | None,
    shadow_mode: bool = True,
) -> dict[str, float | bool]:
    gt = {normalize_action(a) for a in (ground_truth_actions or []) if a}
    rec = {normalize_action(a) for a in (recommended or []) if a}
    dangerous = [a for a in rec if a in DANGEROUS_ACTIONS]
    dangerous_rate = len(dangerous) / max(1, len(rec)) if rec else 0.0
    if not gt:
        correct = 1.0 if not rec else 0.5
        missing_critical = 0.0
    else:
        correct_hits = len(gt & rec)
        correct = correct_hits / len(gt)
        missing = gt - rec
        missing_critical = len([a for a in missing if a in CRITICAL_ACTIONS]) / len(gt)
    unnecessary = len(rec - gt) / max(1, len(rec)) if rec else 0.0
    # shadow mode: dangerous actions in recommendations are scored but never executed
    action_score = max(0.0, correct - 0.25 * unnecessary - 0.5 * missing_critical)
    if shadow_mode and dangerous:
        action_score = max(0.0, action_score - 0.1 * len(dangerous))
    return {
        "action_score": action_score,
        "correct_rate": correct,
        "dangerous_action_rate": dangerous_rate,
        "missing_critical_rate": missing_critical,
        "unnecessary_rate": unnecessary,
        "production_action_leakage": 0.0 if shadow_mode else dangerous_rate,
    }
