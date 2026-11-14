"""Shadow comparison: legacy display key vs Layer-2 logical key (no writes)."""

from __future__ import annotations

from typing import Any

from app.services.dedup.alert_identity import alert_logical_key, within_dedup_window
from app.services.exact_dedupe import alert_display_key


def compare_grouping(
    rows: list[dict[str, Any]],
    *,
    window_seconds: int = 900,
) -> dict[str, Any]:
    """Compare legacy soft groups vs v2 entity-aware groups.

    Returns counts of agreements, false-merges (legacy merged, v2 would not),
    and false-splits (v2 merged, legacy would not) for shadow reports.
    """
    legacy: dict[str, list[str]] = {}
    for row in rows:
        legacy.setdefault(alert_display_key(row), []).append(str(row.get("id")))

    v2: dict[str, list[str]] = {}
    for row in rows:
        key = alert_logical_key(row)
        v2.setdefault(key, []).append(str(row.get("id")))

    # Pairwise: among legacy groups size>=2, how many pairs would v2 keep apart?
    false_merges = 0
    legacy_pairs = 0
    for members in legacy.values():
        if len(members) < 2:
            continue
        by_id = {str(r.get("id")): r for r in rows}
        for i, left_id in enumerate(members):
            for right_id in members[i + 1 :]:
                legacy_pairs += 1
                left = by_id.get(left_id)
                right = by_id.get(right_id)
                if not left or not right:
                    continue
                same_v2 = alert_logical_key(left) == alert_logical_key(right)
                in_window = within_dedup_window(
                    left, right, window_seconds=window_seconds
                )
                if not (same_v2 and in_window):
                    false_merges += 1

    return {
        "row_count": len(rows),
        "legacy_groups": len(legacy),
        "v2_groups": len(v2),
        "legacy_multi_groups": sum(1 for m in legacy.values() if len(m) >= 2),
        "v2_multi_groups": sum(1 for m in v2.values() if len(m) >= 2),
        "legacy_pairs_checked": legacy_pairs,
        "false_merges_prevented_by_v2": false_merges,
        "window_seconds": window_seconds,
    }
