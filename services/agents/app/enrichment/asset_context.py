"""Fail-soft Asset/CMDB enrichment for the auto-triage hot path (Phase 2).

Looks up ``assets`` by hostname / IP within the same tenant. Never fabricates
records, never overwrites raw alert evidence, and never blocks triage beyond
``AISOC_ASSET_ENRICH_TIMEOUT_SECONDS`` (default 1.5s).

Criticality influences prioritization via Unified Risk — it does **not** prove
an incident by itself. Missing asset ≠ malicious.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog

from app.investigator import ledger as ledger_module

logger = structlog.get_logger()

_CRITICALITY_POINTS = {
    "critical": 20,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

# Process-local TTL cache: (tenant_id, key) → (expires_monotonic, payload|None)
_CACHE: dict[tuple[str, str], tuple[float, dict[str, Any] | None]] = {}
_CACHE_TTL = float(os.getenv("AISOC_ASSET_ENRICH_CACHE_TTL_SECONDS", "300"))
_TIMEOUT = float(os.getenv("AISOC_ASSET_ENRICH_TIMEOUT_SECONDS", "1.5"))
_CIRCUIT_OPEN_UNTIL = 0.0
_CIRCUIT_FAILURES = 0
_CIRCUIT_THRESHOLD = int(os.getenv("AISOC_ASSET_ENRICH_CIRCUIT_FAILURES", "5"))
_CIRCUIT_COOLDOWN = float(os.getenv("AISOC_ASSET_ENRICH_CIRCUIT_COOLDOWN_SECONDS", "60"))


@dataclass(frozen=True)
class AssetEnrichmentResult:
    found: bool
    stale: bool
    unavailable: bool
    context: dict[str, Any]
    reason: str


def asset_enrichment_enabled() -> bool:
    raw = os.getenv("AISOC_ASSET_ENRICH_ENABLED", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def criticality_points(criticality: str | None) -> int:
    return _CRITICALITY_POINTS.get((criticality or "").strip().lower(), 0)


def _cache_get(tenant_id: str, key: str) -> dict[str, Any] | None | object:
    hit = _CACHE.get((tenant_id, key))
    if hit is None:
        return _MISS
    expires, payload = hit
    if time.monotonic() > expires:
        _CACHE.pop((tenant_id, key), None)
        return _MISS
    return payload


_MISS = object()


def _cache_set(tenant_id: str, key: str, payload: dict[str, Any] | None) -> None:
    _CACHE[(tenant_id, key)] = (time.monotonic() + _CACHE_TTL, payload)


def _circuit_open() -> bool:
    return time.monotonic() < _CIRCUIT_OPEN_UNTIL


def _record_failure() -> None:
    global _CIRCUIT_FAILURES, _CIRCUIT_OPEN_UNTIL
    _CIRCUIT_FAILURES += 1
    if _CIRCUIT_FAILURES >= _CIRCUIT_THRESHOLD:
        _CIRCUIT_OPEN_UNTIL = time.monotonic() + _CIRCUIT_COOLDOWN
        _CIRCUIT_FAILURES = 0
        logger.warning("asset_enrich.circuit_open", cooldown_s=_CIRCUIT_COOLDOWN)


def _record_success() -> None:
    global _CIRCUIT_FAILURES
    _CIRCUIT_FAILURES = 0


def _is_stale(last_seen: datetime | None, *, max_age_hours: float = 168.0) -> bool:
    if last_seen is None:
        return True
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    age_h = (datetime.now(UTC) - last_seen).total_seconds() / 3600.0
    return age_h > max_age_hours


async def enrich_alert_assets(
    *,
    tenant_id: UUID | str,
    hostname: str | None = None,
    ip: str | None = None,
) -> AssetEnrichmentResult:
    """Return asset context for triage. Fail-soft on every error path."""
    empty = AssetEnrichmentResult(False, False, False, {}, "no_lookup_keys")
    if not asset_enrichment_enabled():
        return AssetEnrichmentResult(False, False, False, {}, "disabled")
    if _circuit_open():
        return AssetEnrichmentResult(False, False, True, {}, "circuit_open")

    tid = str(tenant_id)
    keys: list[tuple[str, str]] = []
    if hostname:
        keys.append(("hostname", hostname.strip().lower()))
    if ip:
        keys.append(("ip", ip.strip()))
    if not keys:
        return empty

    for kind, value in keys:
        cached = _cache_get(tid, f"{kind}:{value}")
        if cached is not _MISS:
            if cached is None:
                continue
            assert isinstance(cached, dict)
            return AssetEnrichmentResult(
                True,
                bool(cached.get("stale")),
                False,
                cached,
                "cache_hit",
            )

    try:
        ctx = await asyncio.wait_for(
            _lookup(tid, hostname=hostname, ip=ip),
            timeout=_TIMEOUT,
        )
    except TimeoutError:
        _record_failure()
        return AssetEnrichmentResult(False, False, True, {}, "timeout")
    except Exception as exc:  # noqa: BLE001
        _record_failure()
        logger.debug("asset_enrich.failed", error=str(exc))
        return AssetEnrichmentResult(False, False, True, {}, "error")

    _record_success()
    for kind, value in keys:
        _cache_set(tid, f"{kind}:{value}", ctx)
    if ctx is None:
        return AssetEnrichmentResult(False, False, False, {}, "not_found")
    return AssetEnrichmentResult(
        True,
        bool(ctx.get("stale")),
        False,
        ctx,
        "db_hit",
    )


async def _lookup(
    tenant_id: str,
    *,
    hostname: str | None,
    ip: str | None,
) -> dict[str, Any] | None:
    pool = await ledger_module.get_pool()
    if pool is None:
        raise RuntimeError("asset_enrich: no database pool")
    tid = UUID(tenant_id)
    async with pool.acquire() as conn:
        row = None
        if hostname:
            row = await conn.fetchrow(
                """
                SELECT id, name, fqdn, ip_addresses, os, os_version, criticality,
                       owner_email, last_seen, asset_type
                  FROM assets
                 WHERE tenant_id = $1
                   AND (
                        lower(name) = lower($2)
                     OR lower(COALESCE(fqdn, '')) = lower($2)
                   )
                 ORDER BY last_seen DESC NULLS LAST
                 LIMIT 1
                """,
                tid,
                hostname,
            )
        if row is None and ip:
            row = await conn.fetchrow(
                """
                SELECT id, name, fqdn, ip_addresses, os, os_version, criticality,
                       owner_email, last_seen, asset_type
                  FROM assets
                 WHERE tenant_id = $1
                   AND $2 = ANY(COALESCE(ip_addresses, ARRAY[]::text[]))
                 ORDER BY last_seen DESC NULLS LAST
                 LIMIT 1
                """,
                tid,
                ip,
            )
    if row is None:
        return None
    last_seen = row["last_seen"]
    stale = _is_stale(last_seen)
    return {
        "asset_id": str(row["id"]),
        "name": row["name"],
        "fqdn": row["fqdn"],
        "ip_addresses": list(row["ip_addresses"] or []),
        "os": row["os"],
        "os_version": row["os_version"],
        "criticality": row["criticality"],
        "criticality_points": criticality_points(row["criticality"]),
        "owner_email": row["owner_email"],
        "asset_type": row["asset_type"],
        "last_seen": last_seen.isoformat() if last_seen else None,
        "stale": stale,
        "source": "assets_table",
        "observed": True,
        "inferred": False,
    }
