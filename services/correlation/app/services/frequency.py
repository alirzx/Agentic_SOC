"""Frequency service (doc §5.1).

Weights are only meaningful relative to a tenant's own baseline: ``Administrator``
is a high-frequency account *here* because it appears 35+ times in 30 days, not
because it is special. This module provides that baseline two ways:

* ``count_keys`` — exact counts from the alerts already loaded for the current
  window (deterministic, no extra query, used on every cycle).
* ``value_frequency`` table — the durable 30-day rollup, used as a fallback when
  a window scan is capped, and as the source for ``common_values`` (domains and
  hosts seen so often they carry little signal).

Counts are per ``(tenant_id, kind, value)``; the table has no cross-tenant
aggregate, which keeps the "is this rare?" question tenant-local and avoids
leaking one customer's asset names into another's scoring.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

import structlog

from app.safe_db import safe_executemany, safe_fetch
from app.normalizer.extract_keys import (
    DOMAIN_UBIQUITY_RATIO,
    H_HUB,
    MIN_RATIO_SAMPLE,
    T_COMMON_DOMAIN,
    T_USER_COMMON,
    ExtractedKeys,
    Key,
)

logger = structlog.get_logger()


def count_keys(extracted: Iterable[ExtractedKeys]) -> dict[tuple[str, str], int]:
    """Count how many alerts mention each ``(kind, value)`` pair."""
    counter: Counter[tuple[str, str]] = Counter()
    for item in extracted:
        # Count each distinct value once per alert, not once per provenance.
        for key in {k.token: k for k in item.keys}.values():
            counter[(key.kind, _unscoped(key))] += 1
    return dict(counter)


def _unscoped(key: Key) -> str:
    """Frequency is about the value itself, not its host scope."""
    if key.kind == "process_guid" and key.scope and key.value.startswith(f"{key.scope}|"):
        return key.value.split("|", 1)[1]
    return key.value


def common_values(
    freq: Mapping[tuple[str, str], int],
    *,
    total_alerts: int | None = None,
) -> frozenset[str]:
    """Values frequent enough to be considered ambient (weak evidence).

    Two tests, because an absolute threshold alone cannot see a tenant-wide
    value. The counts in ``freq`` are per *window*, and the engine's window is
    capped (``max_alerts_per_cycle``), so a domain that appears on every single
    alert of the tenant — the Active Directory domain in a lab, a corporate
    parent zone in production — can sit far below ``T_COMMON_DOMAIN`` while
    being the least discriminating value in the payload. Linking two unrelated
    observations through it is exactly the "self-correlating tenant domain"
    failure, so a value on a large share of the window's alerts is treated as
    ambient too:

    * absolute: ``host > H_HUB``, ``user > T_USER_COMMON``,
      ``domain > T_COMMON_DOMAIN``;
    * relative: a *domain* on at least ``DOMAIN_UBIQUITY_RATIO`` of the window's
      alerts, once the window is big enough to make a ratio meaningful
      (``MIN_RATIO_SAMPLE``). Hosts keep their absolute bar: one compromised
      server legitimately appears on every alert of a single-host campaign, and
      demoting it would dissolve real cases rather than noise.
    """
    out: set[str] = set()
    window = int(total_alerts or 0)
    ratio_floor = DOMAIN_UBIQUITY_RATIO * window if window >= MIN_RATIO_SAMPLE else None
    for (kind, value), count in freq.items():
        if kind == "host" and count > H_HUB:
            out.add(value)
        elif kind == "user" and count > T_USER_COMMON:
            out.add(value)
        elif kind == "domain" and count > T_COMMON_DOMAIN:
            out.add(value)
        elif kind == "domain" and ratio_floor is not None and count >= ratio_floor:
            out.add(value)
    return frozenset(out)


async def load_frequency(db, tenant_id) -> dict[tuple[str, str], int]:
    """Read the durable 30-day rollup for one tenant."""
    rows = await safe_fetch(
        db,
        """
        SELECT kind, value, freq_30d
          FROM value_frequency
         WHERE tenant_id = $1
        """,
        tenant_id,
        operation_name="load_frequency",
    )
    return {(row["kind"], row["value"]): int(row["freq_30d"] or 0) for row in rows}


async def store_frequency(db, tenant_id, freq: Mapping[tuple[str, str], int]) -> int:
    """Upsert a rollup. Returns the number of rows written.

    ``window_start`` is the eval point of this count so a stale rollup can be
    recognised and ignored by future readers.
    """
    if not freq:
        return 0
    rows = [
        (tenant_id, kind, value, int(count), json.dumps({"source": "correlation_engine"}))
        for (kind, value), count in freq.items()
        if value
    ]
    success = await safe_executemany(
        db,
        """
        INSERT INTO value_frequency (tenant_id, kind, value, freq_30d, metadata, window_start, updated_at)
        VALUES ($1, $2, $3, $4, $5::jsonb, now(), now())
        ON CONFLICT (tenant_id, kind, value)
        DO UPDATE SET freq_30d = EXCLUDED.freq_30d,
                      metadata = EXCLUDED.metadata,
                      window_start = EXCLUDED.window_start,
                      updated_at = now()
        """,
        rows,
        operation_name="store_frequency",
    )
    return len(rows) if success else 0


async def refresh_from_alerts(db, tenant_id, alerts: Iterable[Mapping]) -> dict[tuple[str, str], int]:
    """Best-effort rollup write; never blocks a correlation cycle."""
    from app.normalizer.extract_keys import extract_keys  # local import: keeps module acyclic

    def _payload(alert: Mapping) -> Any:
        raw = alert.get("llm_payload")
        if isinstance(raw, (str, bytes, bytearray)):
            try:
                raw = json.loads(raw)
            except (TypeError, ValueError):
                return {}
        return raw if isinstance(raw, Mapping) else {}

    try:
        extracted = [extract_keys(_payload(alert)) for alert in alerts]
        freq = count_keys(extracted)
        await store_frequency(db, tenant_id, freq)
        return freq
    except Exception as exc:  # noqa: BLE001 — frequencies are an optimisation
        logger.warning("frequency.refresh_failed", tenant_id=str(tenant_id), error=str(exc))
        return {}


__all__ = [
    "common_values",
    "count_keys",
    "load_frequency",
    "refresh_from_alerts",
    "store_frequency",
]
