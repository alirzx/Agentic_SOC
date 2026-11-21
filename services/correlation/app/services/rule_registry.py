"""Tenant-aware correlation rule identity registry.

Resolution precedence:
1. exact tenant rule
2. exact global rule
3. tenant wildcard pattern
4. global wildcard pattern
5. generic shape-aware fallback
6. missing rule name

Registry lookup is fail-soft: database or migration absence never blocks a
correlation cycle. Audit writes are best-effort and never alter llm_payload.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import uuid
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import asyncpg

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RuleIdentityMap:
    rule_name: str
    tenant_id: str | uuid.UUID | None = None
    rule_name_pattern: str | None = None
    id: str | uuid.UUID | None = None
    is_active: bool = True
    host_fields: tuple[str, ...] = field(default_factory=tuple)
    user_fields: tuple[str, ...] = field(default_factory=tuple)
    ip_fields: tuple[str, ...] = field(default_factory=tuple)
    domain_fields: tuple[str, ...] = field(default_factory=tuple)
    hash_fields: tuple[str, ...] = field(default_factory=tuple)
    process_guid_fields: tuple[str, ...] = field(default_factory=tuple)
    excluded_fields: tuple[str, ...] = field(default_factory=tuple)
    field_kind_overrides: Mapping[str, str] = field(default_factory=dict)
    notes: str | None = None
    source: str = "operator"

    def __post_init__(self) -> None:
        object.__setattr__(self, "host_fields", tuple(str(v).strip() for v in (self.host_fields or ()) if str(v).strip()))
        object.__setattr__(self, "user_fields", tuple(str(v).strip() for v in (self.user_fields or ()) if str(v).strip()))
        object.__setattr__(self, "ip_fields", tuple(str(v).strip() for v in (self.ip_fields or ()) if str(v).strip()))
        object.__setattr__(self, "domain_fields", tuple(str(v).strip() for v in (self.domain_fields or ()) if str(v).strip()))
        object.__setattr__(self, "hash_fields", tuple(str(v).strip() for v in (self.hash_fields or ()) if str(v).strip()))
        object.__setattr__(self, "process_guid_fields", tuple(str(v).strip() for v in (self.process_guid_fields or ()) if str(v).strip()))
        object.__setattr__(self, "excluded_fields", tuple(str(v).strip() for v in (self.excluded_fields or ()) if str(v).strip()))
        overrides = {str(k).strip(): str(v).strip().lower() for k, v in (self.field_kind_overrides or {}).items()}
        object.__setattr__(self, "field_kind_overrides", overrides)


@dataclass(frozen=True)
class RuleResolution:
    matched_source: str
    map: RuleIdentityMap | None = None


def _tenant_key(value: str | uuid.UUID | None) -> str:
    return "" if value is None else str(value)


@asynccontextmanager
async def tenant_connection(
    pool: asyncpg.Pool,
    tenant_id: uuid.UUID,
) -> AsyncIterator[asyncpg.Connection]:
    """Yield a pooled connection with the RLS tenant GUC set for the transaction.

    Both registry tables carry ``FORCE ROW LEVEL SECURITY``. Without
    ``app.current_tenant_id`` the audit ``WITH CHECK`` rejects the row and the
    tenant-owned registry rows become invisible, so reads and writes must run in
    a transaction that sets the GUC. ``set_config(..., true)`` is
    transaction-local, so the value cannot leak to the next borrower of the
    connection.
    """
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "SELECT set_config('app.current_tenant_id', $1, true)",
                str(tenant_id),
            )
            yield conn


def resolve_rule_identity_map(
    tenant_id: str | uuid.UUID,
    rule_name: str,
    maps: Sequence[RuleIdentityMap],
) -> RuleResolution:
    """Resolve a rule name without database or side effects."""
    tid = _tenant_key(tenant_id)
    name = str(rule_name or "").strip()
    if not name:
        return RuleResolution("missing", None)

    active = [item for item in maps if item.is_active]

    tenant_exact = next(
        (
            item
            for item in active
            if _tenant_key(item.tenant_id) == tid
            and item.rule_name_pattern is None
            and str(item.rule_name).strip().lower() == name.lower()
        ),
        None,
    )
    if tenant_exact is not None:
        return RuleResolution("exact", tenant_exact)

    global_exact = next(
        (
            item
            for item in active
            if item.tenant_id is None
            and item.rule_name_pattern is None
            and str(item.rule_name).strip().lower() == name.lower()
        ),
        None,
    )
    if global_exact is not None:
        return RuleResolution("exact", global_exact)

    tenant_pattern = next(
        (
            item
            for item in active
            if _tenant_key(item.tenant_id) == tid
            and item.rule_name_pattern
            and fnmatch.fnmatchcase(name.lower(), str(item.rule_name_pattern).strip().lower())
        ),
        None,
    )
    if tenant_pattern is not None:
        return RuleResolution("tenant_pattern", tenant_pattern)

    global_pattern = next(
        (
            item
            for item in active
            if item.tenant_id is None
            and item.rule_name_pattern
            and fnmatch.fnmatchcase(name.lower(), str(item.rule_name_pattern).strip().lower())
        ),
        None,
    )
    if global_pattern is not None:
        return RuleResolution("global_pattern", global_pattern)

    return RuleResolution("generic_fallback", None)


def _json_list(value: Any) -> list[Any]:
    """Decode a ``jsonb`` array column.

    asyncpg returns ``json``/``jsonb`` as ``str`` unless a type codec is
    registered on the connection, and this pool registers none. Iterating the
    raw string would yield single characters, so every registry read decodes
    explicitly and tolerates a value that is already a Python list.
    """
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray)):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return []
    return list(value) if isinstance(value, (list, tuple)) else []


def _json_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, (str, bytes, bytearray)):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _row_to_map(row: Mapping[str, Any] | asyncpg.Record) -> RuleIdentityMap:
    return RuleIdentityMap(
        id=row["id"],
        tenant_id=row["tenant_id"],
        rule_name=str(row["rule_name"]),
        rule_name_pattern=row["rule_name_pattern"],
        is_active=bool(row["is_active"]),
        host_fields=_json_list(row["host_fields"]),
        user_fields=_json_list(row["user_fields"]),
        ip_fields=_json_list(row["ip_fields"]),
        domain_fields=_json_list(row["domain_fields"]),
        hash_fields=_json_list(row["hash_fields"]),
        process_guid_fields=_json_list(row["process_guid_fields"]),
        excluded_fields=_json_list(row["excluded_fields"]),
        field_kind_overrides=_json_mapping(row["field_kind_overrides"]),
        notes=row["notes"],
        source=str(row["source"] or "operator"),
    )


async def load_rule_identity_maps(pool: asyncpg.Pool, tenant_id: str | uuid.UUID) -> list[RuleIdentityMap]:
    """Load active tenant and global maps. Migration absence is fail-soft."""
    tid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(str(tenant_id))
    try:
        async with tenant_connection(pool, tid) as conn:
            rows = await conn.fetch(
                """
                SELECT id, tenant_id, rule_name, rule_name_pattern, is_active,
                       host_fields, user_fields, ip_fields, domain_fields,
                       hash_fields, process_guid_fields, excluded_fields,
                       field_kind_overrides, notes, source
                  FROM correlation_rule_identity_maps
                 WHERE is_active = TRUE
                   AND (tenant_id = $1 OR tenant_id IS NULL)
                 ORDER BY tenant_id NULLS LAST, rule_name ASC
                """,
                tid,
            )
    except asyncpg.PostgresError as exc:
        logger.warning("rule_identity_registry_unavailable", error=str(exc)[:200])
        return []
    return [_row_to_map(row) for row in rows]


async def resolve_rule_identity_map_db(
    pool: asyncpg.Pool,
    tenant_id: str | uuid.UUID,
    rule_name: str,
) -> RuleResolution:
    maps = await load_rule_identity_maps(pool, tenant_id)
    return resolve_rule_identity_map(tenant_id, rule_name, maps)


async def audit_rule_resolution(
    pool: asyncpg.Pool,
    *,
    tenant_id: str | uuid.UUID,
    alert_id: str | uuid.UUID,
    rule_name: str,
    resolution: RuleResolution,
    normalizer_version: str,
    resolved_host_fields: Sequence[str] = (),
    resolved_user_fields: Sequence[str] = (),
    resolved_ip_fields: Sequence[str] = (),
    missing_fields: Sequence[str] = (),
    filtered_values: Mapping[str, Any] | None = None,
) -> bool:
    """Persist one resolution audit row; migration/insert failure is fail-soft."""
    tid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(str(tenant_id))
    aid = alert_id if isinstance(alert_id, uuid.UUID) else uuid.UUID(str(alert_id))
    map_id = resolution.map.id if resolution.map is not None else None
    map_uuid = map_id if isinstance(map_id, uuid.UUID) else (uuid.UUID(str(map_id)) if map_id else None)

    try:
        async with tenant_connection(pool, tid) as conn:
            await conn.execute(
                """
                INSERT INTO correlation_rule_resolution_audits
                  (id, tenant_id, alert_id, rule_name, map_id, matched_source,
                   resolved_host_fields, resolved_user_fields, resolved_ip_fields,
                   missing_fields, filtered_values, normalizer_version)
                VALUES
                  ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb,
                   $10::jsonb, $11::jsonb, $12)
                """,
                uuid.uuid4(),
                tid,
                aid,
                str(rule_name or "").strip()[:500],
                map_uuid,
                resolution.matched_source,
                json.dumps(list(resolved_host_fields)),
                json.dumps(list(resolved_user_fields)),
                json.dumps(list(resolved_ip_fields)),
                json.dumps(list(missing_fields)),
                json.dumps(dict(filtered_values or {})),
                str(normalizer_version)[:32],
            )
        return True
    except asyncpg.PostgresError as exc:
        logger.warning("rule_identity_resolution_audit_failed", error=str(exc)[:200])
        return False


__all__ = [
    "RuleIdentityMap",
    "RuleResolution",
    "tenant_connection",
    "resolve_rule_identity_map",
    "resolve_rule_identity_map_db",
    "load_rule_identity_maps",
    "audit_rule_resolution",
]
