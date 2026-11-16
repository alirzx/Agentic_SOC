"""Monthly day/night shift roster generator.

Rules (product):
* One day analyst + one night analyst per calendar day (distinct people).
* No person may work two consecutive night shifts.
* Per person, day vs night load stays roughly balanced (~50/50, e.g. 10/6 or 8/8).
* Total shifts are spread as evenly as possible across the roster.
"""

from __future__ import annotations

import calendar
import random
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import date
from typing import Any


@dataclass(frozen=True)
class ShiftPerson:
    id: str
    name: str
    role: str = "soc_analyst"


@dataclass
class DayAssignment:
    date: str  # YYYY-MM-DD
    day_analyst_id: str
    day_analyst_name: str
    night_analyst_id: str
    night_analyst_name: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _pick(
    candidates: list[ShiftPerson],
    *,
    day_counts: dict[str, int],
    night_counts: dict[str, int],
    prefer: str,
    rng: random.Random,
) -> ShiftPerson:
    """Weighted pick: prefer people behind on ``prefer`` ('day'|'night') and total."""

    def score(p: ShiftPerson) -> float:
        d, n = day_counts[p.id], night_counts[p.id]
        total = d + n
        preferred = n if prefer == "night" else d
        other = d if prefer == "night" else n
        # Lower is better: fewer preferred slots, then fewer totals, then balance.
        balance_penalty = abs((d + 1 if prefer == "day" else d) - (n + 1 if prefer == "night" else n))
        return preferred * 100 + total * 10 + balance_penalty + rng.random()

    ordered = sorted(candidates, key=score)
    # Soft randomness among the best few.
    top = ordered[: max(1, min(3, len(ordered)))]
    return rng.choice(top)


def generate_month_roster(
    *,
    year: int,
    month: int,
    analysts: list[ShiftPerson],
    seed: int | None = None,
    max_attempts: int = 80,
) -> tuple[list[DayAssignment], dict[str, Any]]:
    """Return (assignments, stats). Raises ValueError if roster too small."""
    if len(analysts) < 2:
        raise ValueError("Need at least 2 analysts to staff day and night shifts.")
    days_in_month = calendar.monthrange(year, month)[1]
    rng = random.Random(seed)

    best: list[DayAssignment] | None = None
    best_stats: dict[str, Any] | None = None
    best_score = float("inf")

    for _ in range(max_attempts):
        day_counts: dict[str, int] = defaultdict(int)
        night_counts: dict[str, int] = defaultdict(int)
        last_night_id: str | None = None
        rows: list[DayAssignment] = []
        failed = False

        for day_num in range(1, days_in_month + 1):
            night_pool = [p for p in analysts if p.id != last_night_id]
            if not night_pool:
                failed = True
                break
            night = _pick(
                night_pool,
                day_counts=day_counts,
                night_counts=night_counts,
                prefer="night",
                rng=rng,
            )
            day_pool = [p for p in analysts if p.id != night.id]
            if not day_pool:
                failed = True
                break
            day = _pick(
                day_pool,
                day_counts=day_counts,
                night_counts=night_counts,
                prefer="day",
                rng=rng,
            )
            day_counts[day.id] += 1
            night_counts[night.id] += 1
            last_night_id = night.id
            rows.append(
                DayAssignment(
                    date=date(year, month, day_num).isoformat(),
                    day_analyst_id=day.id,
                    day_analyst_name=day.name,
                    night_analyst_id=night.id,
                    night_analyst_name=night.name,
                )
            )

        if failed or len(rows) != days_in_month:
            continue

        stats = compute_roster_stats(rows, analysts)
        if not stats["ok_no_consecutive_nights"]:
            continue
        # Prefer even totals + day/night ratio close to 0.5.
        imbalance = stats["max_total"] - stats["min_total"]
        ratio_penalty = sum(
            abs(0.5 - (s["day"] / s["total"] if s["total"] else 0.5))
            for s in stats["per_analyst"].values()
            if s["total"] > 0
        )
        score = imbalance * 10 + ratio_penalty
        if score < best_score:
            best_score = score
            best = rows
            best_stats = stats

    if best is None or best_stats is None:
        raise ValueError("Could not generate a valid roster; try again or add analysts.")
    best_stats["seed"] = seed
    best_stats["attempts_used"] = max_attempts
    return best, best_stats


def compute_roster_stats(
    assignments: list[DayAssignment] | list[dict[str, Any]],
    analysts: list[ShiftPerson],
) -> dict[str, Any]:
    """Validate consecutive nights + per-person day/night counts."""
    day_counts: dict[str, int] = {a.id: 0 for a in analysts}
    night_counts: dict[str, int] = {a.id: 0 for a in analysts}
    names = {a.id: a.name for a in analysts}
    consecutive_violations: list[str] = []
    prev_night: str | None = None

    normalized: list[dict[str, Any]] = []
    for row in assignments:
        if isinstance(row, DayAssignment):
            d = row.to_dict()
        else:
            d = dict(row)
        normalized.append(d)
        day_id = str(d.get("day_analyst_id") or "")
        night_id = str(d.get("night_analyst_id") or "")
        if day_id in day_counts:
            day_counts[day_id] += 1
        else:
            day_counts[day_id] = day_counts.get(day_id, 0) + 1
            names.setdefault(day_id, str(d.get("day_analyst_name") or day_id))
        if night_id in night_counts:
            night_counts[night_id] += 1
        else:
            night_counts[night_id] = night_counts.get(night_id, 0) + 1
            names.setdefault(night_id, str(d.get("night_analyst_name") or night_id))
        if prev_night and night_id == prev_night:
            consecutive_violations.append(str(d.get("date")))
        prev_night = night_id or None

    per: dict[str, Any] = {}
    totals: list[int] = []
    for aid in sorted(set(day_counts) | set(night_counts)):
        d, n = day_counts.get(aid, 0), night_counts.get(aid, 0)
        total = d + n
        totals.append(total)
        ratio = (d / total) if total else 0.5
        per[aid] = {
            "id": aid,
            "name": names.get(aid, aid),
            "day": d,
            "night": n,
            "total": total,
            "day_ratio": round(ratio, 3),
            "balanced": total == 0 or 0.35 <= ratio <= 0.65 or abs(d - n) <= 4,
        }

    return {
        "ok_no_consecutive_nights": len(consecutive_violations) == 0,
        "consecutive_night_violations": consecutive_violations,
        "per_analyst": per,
        "max_total": max(totals) if totals else 0,
        "min_total": min(totals) if totals else 0,
        "days": len(normalized),
    }


def apply_cell_edit(
    assignments: list[dict[str, Any]],
    *,
    day_iso: str,
    slot: str,
    analyst_id: str,
    analyst_name: str,
    analysts: list[ShiftPerson],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Update one day/night cell and return (assignments, stats)."""
    if slot not in {"day", "night"}:
        raise ValueError("slot must be 'day' or 'night'")
    out = [dict(a) for a in assignments]
    found = False
    for row in out:
        if row.get("date") != day_iso:
            continue
        found = True
        other = "night" if slot == "day" else "day"
        other_id = str(row.get(f"{other}_analyst_id") or "")
        if other_id == analyst_id:
            raise ValueError("Same person cannot cover both day and night on one date.")
        row[f"{slot}_analyst_id"] = analyst_id
        row[f"{slot}_analyst_name"] = analyst_name
        break
    if not found:
        raise ValueError(f"No assignment for date {day_iso}")
    # Rebuild DayAssignment-compatible list for stats
    typed = [
        DayAssignment(
            date=str(r["date"]),
            day_analyst_id=str(r["day_analyst_id"]),
            day_analyst_name=str(r["day_analyst_name"]),
            night_analyst_id=str(r["night_analyst_id"]),
            night_analyst_name=str(r["night_analyst_name"]),
        )
        for r in out
    ]
    return out, compute_roster_stats(typed, analysts)
