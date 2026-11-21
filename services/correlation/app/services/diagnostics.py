"""Per-tenant ambient-key diagnostics for the last correlation cycle.

The ambient rules (see ``extract_keys._weight`` and ``scoring.score_pair``) make
two things invisible in the cycle counters: *which* values the engine decided
were wallpaper, and *which* pairs it refused to merge because they shared
nothing else. Without that, "why did these two alerts not become a case?" has no
answer short of re-running the engine by hand.

This module keeps the answer. ``build_ambient_report`` is a pure function over
the same inputs the cycle already has (frequency baseline, ambient set,
observations, scored pairs), so it costs nothing to produce; ``remember`` /
``last`` hold the most recent report per tenant in the process, which is what
``GET /v1/diagnostics/{tenant_id}`` serves. Nothing is persisted: this reports on
the last cycle *this process* ran, and says so, rather than pretending to be a
history table.
"""

from __future__ import annotations

import copy
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from app.normalizer.extract_keys import (
    COMMON_DOMAINS,
    DOMAIN_UBIQUITY_RATIO,
    H_HUB,
    MIN_RATIO_SAMPLE,
    T_COMMON_DOMAIN,
    T_USER_COMMON,
)
from app.services.observations import Observation
from app.services.scoring import PairScore

#: Prefix of the veto reason ``score_pair`` sets when every shared key is ambient.
AMBIENT_VETO_PREFIX = "ambient_keys_only"

#: How many vetoed pairs a report lists. A tenant-wide domain vetoes thousands;
#: the count is always complete, the listing is the head of it.
PAIR_SAMPLE_LIMIT = 50

#: Tenants kept in the in-process cache. A diagnostics cache must never grow with
#: the tenant table.
MAX_CACHED_TENANTS = 64

_last_reports: OrderedDict[str, dict[str, Any]] = OrderedDict()


def _reason(kind: str, value: str, count: int, *, total_alerts: int) -> str:
    """Why the engine treated this value as ambient — the rule that fired.

    Order matters for honesty: the ratio rule is evaluated before the absolute
    one, because in a large window a tenant-wide zone trivially clears the
    absolute count too, and calling it "well known" would misdescribe it. The
    absolute thresholds are 30-day constants compared against *this window's*
    counts, so they are reported as "frequent in this window", not as a
    well-known-ness claim.
    """

    if kind == "domain" and value in COMMON_DOMAINS:
        return "well-known public domain (static allow-list)"
    if kind == "domain" and total_alerts >= MIN_RATIO_SAMPLE and total_alerts:
        share = count / total_alerts
        if share >= DOMAIN_UBIQUITY_RATIO:
            return (
                f"tenant-wide domain: on {share:.0%} of the window's {total_alerts} alerts "
                f"(>={DOMAIN_UBIQUITY_RATIO:.0%} is ambient)"
            )
    if kind == "host" and count > H_HUB:
        return f"hub host: seen {count}x in this window (above the {H_HUB} threshold)"
    if kind == "user" and count > T_USER_COMMON:
        return (
            f"high-frequency account: seen {count}x in this window "
            f"(above the {T_USER_COMMON} threshold)"
        )
    if kind == "domain" and count > T_COMMON_DOMAIN:
        return (
            f"frequent domain: seen {count}x in this window "
            f"(above the {T_COMMON_DOMAIN} threshold)"
        )
    # Only reachable when the caller was handed an ambient value that this
    # window's own counts do not explain (a durable rollup, or an explicit set).
    return "listed in the tenant's ambient set"


def _ambient_keys(
    freq: Mapping[tuple[str, str], int] | None,
    ambient: Iterable[str],
    *,
    total_alerts: int,
) -> list[dict[str, Any]]:
    """The ambient set with the frequency and the reason behind each value.

    ``ambient`` is a flat set of *values* (``common_values`` deliberately ignores
    the kind), so the kind and the count come from ``freq``. A value with no
    entry in the window's counts can still be ambient — that is a value flagged
    by the durable rollup or the static list — and is reported with ``frequency``
    0 rather than dropped.
    """

    wanted = {str(value).lower() for value in ambient}
    if not wanted:
        return []

    by_value: dict[str, list[tuple[str, int]]] = {}
    for (kind, value), count in (freq or {}).items():
        if value.lower() in wanted:
            by_value.setdefault(value.lower(), []).append((kind, int(count)))

    keys: list[dict[str, Any]] = []
    for value in sorted(wanted):
        entries = by_value.get(value) or [("domain", 0)]
        for kind, count in sorted(entries):
            keys.append(
                {
                    "token": f"{kind}:{value}",
                    "kind": kind,
                    "value": value,
                    "frequency": count,
                    "share": round(count / total_alerts, 3) if total_alerts else 0.0,
                    "reason": _reason(kind, value, count, total_alerts=total_alerts),
                }
            )
    # Strongest evidence of ambience first: most frequent, then alphabetical.
    keys.sort(key=lambda item: (-int(item["frequency"]), item["token"]))
    return keys


def _vetoed_pairs(
    pairs: Sequence[PairScore],
    observations: Mapping[str, Observation],
    *,
    limit: int = PAIR_SAMPLE_LIMIT,
) -> tuple[list[dict[str, Any]], int]:
    """Pairs the ambient rule refused to merge, plus the total count."""

    vetoed = [p for p in pairs if p.veto and p.veto.startswith(AMBIENT_VETO_PREFIX)]
    # Most shared ambient evidence first: those are the pairs an analyst would
    # have expected to merge, so they are the ones worth showing.
    vetoed.sort(key=lambda p: (-len(p.vetoed_by), p.left, p.right))

    out: list[dict[str, Any]] = []
    for pair in vetoed[:limit]:
        left = observations.get(pair.left)
        right = observations.get(pair.right)
        out.append(
            {
                "left": pair.left,
                "right": pair.right,
                "left_role": left.role if left else None,
                "right_role": right.role if right else None,
                # The alias-group tokens the pair shares, e.g. ``domain:corp.local``.
                "ambient_keys": list(pair.vetoed_by),
                "alerts": (len(left.alert_ids) if left else 0)
                + (len(right.alert_ids) if right else 0),
            }
        )
    return out, len(vetoed)


def build_ambient_report(
    *,
    tenant_id: str,
    freq: Mapping[tuple[str, str], int] | None,
    ambient: Iterable[str],
    observations: Sequence[Observation],
    pairs: Sequence[PairScore],
    total_alerts: int,
    theta: int,
    generated_at: datetime | None = None,
    pair_limit: int = PAIR_SAMPLE_LIMIT,
) -> dict[str, Any]:
    """The last cycle's ambient decisions, as a JSON-ready report."""

    ambient_keys = _ambient_keys(freq, ambient, total_alerts=total_alerts)
    by_key = {observation.key: observation for observation in observations}
    vetoed_pairs, vetoed_count = _vetoed_pairs(pairs, by_key, limit=pair_limit)

    return {
        "tenant_id": str(tenant_id),
        "generated_at": (generated_at or datetime.now(UTC)).isoformat(),
        "window_alerts": int(total_alerts),
        "frequency_values": len(freq or {}),
        "observation_count": len(observations),
        "pair_count": len(pairs),
        "theta": int(theta),
        "ambient_key_count": len(ambient_keys),
        "ambient_keys": ambient_keys,
        "vetoed_pair_count": vetoed_count,
        # Only the head is listed; the count above is complete.
        "vetoed_pairs_truncated": vetoed_count > len(vetoed_pairs),
        "vetoed_pairs": vetoed_pairs,
        "note": (
            "Ambient values (hub hosts, high-frequency accounts, well-known or "
            "tenant-wide domains) add nothing to L1, and a pair whose shared keys "
            "are all ambient is never merged. This report covers the last cycle "
            "this process ran — it is not persisted history."
        ),
    }


def remember(report: Mapping[str, Any]) -> dict[str, Any]:
    """Cache a report as the tenant's latest, evicting the oldest tenant."""

    tenant = str(report.get("tenant_id") or "")
    if not tenant:
        return copy.deepcopy(dict(report))
    # Deep copy: a caller (or an API serializer) mutating the nested key/pair
    # lists must not rewrite what other requests read back.
    _last_reports[tenant] = copy.deepcopy(dict(report))
    _last_reports.move_to_end(tenant)
    while len(_last_reports) > MAX_CACHED_TENANTS:
        _last_reports.popitem(last=False)
    return copy.deepcopy(_last_reports[tenant])


def last(tenant_id: str) -> dict[str, Any] | None:
    """The most recent report for a tenant in this process, or ``None``."""

    report = _last_reports.get(str(tenant_id))
    return copy.deepcopy(report) if report is not None else None


def forget_all() -> None:
    """Drop the cache (tests, and a deliberate reset of the diagnostics view)."""

    _last_reports.clear()


__all__ = [
    "AMBIENT_VETO_PREFIX",
    "MAX_CACHED_TENANTS",
    "PAIR_SAMPLE_LIMIT",
    "build_ambient_report",
    "forget_all",
    "last",
    "remember",
]
