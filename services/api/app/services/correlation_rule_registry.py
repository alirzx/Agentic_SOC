"""Tenant-aware correlation rule identity registry helpers."""

from __future__ import annotations

import fnmatch
import uuid
from collections.abc import Sequence
from typing import Literal

from app.models.correlation_rule_identity import CorrelationRuleIdentityMap

MatchedSource = Literal[
    "exact",
    "tenant_pattern",
    "global_pattern",
    "generic_fallback",
    "missing",
]


def normalize_field_names(values: Sequence[str] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values or ():
        name = str(value).strip()
        key = name.lower()
        if name and key not in seen:
            seen.add(key)
            out.append(name)
    return out


def normalize_field_kind_overrides(overrides: dict[str, str] | None) -> dict[str, str]:
    allowed = {"host", "user", "ip", "domain", "hash", "process_guid"}
    out: dict[str, str] = {}
    for field_name, kind in (overrides or {}).items():
        name = str(field_name).strip()
        normal_kind = str(kind).strip().lower()
        if name and normal_kind in allowed:
            out[name] = normal_kind
    return out


def resolve_rule_identity_map(
    tenant_id: uuid.UUID,
    rule_name: str,
    rows: Sequence[CorrelationRuleIdentityMap],
) -> tuple[MatchedSource, CorrelationRuleIdentityMap | None]:
    name = str(rule_name or "").strip()
    if not name:
        return "missing", None

    tenant_exact = next(
        (
            row
            for row in rows
            if row.is_active
            and row.tenant_id == tenant_id
            and row.rule_name_pattern is None
            and str(row.rule_name).strip().lower() == name.lower()
        ),
        None,
    )
    if tenant_exact is not None:
        return "exact", tenant_exact

    global_exact = next(
        (
            row
            for row in rows
            if row.is_active
            and row.tenant_id is None
            and row.rule_name_pattern is None
            and str(row.rule_name).strip().lower() == name.lower()
        ),
        None,
    )
    if global_exact is not None:
        return "exact", global_exact

    tenant_pattern = next(
        (
            row
            for row in rows
            if row.is_active
            and row.tenant_id == tenant_id
            and row.rule_name_pattern
            and fnmatch.fnmatchcase(name.lower(), str(row.rule_name_pattern).strip().lower())
        ),
        None,
    )
    if tenant_pattern is not None:
        return "tenant_pattern", tenant_pattern

    global_pattern = next(
        (
            row
            for row in rows
            if row.is_active
            and row.tenant_id is None
            and row.rule_name_pattern
            and fnmatch.fnmatchcase(name.lower(), str(row.rule_name_pattern).strip().lower())
        ),
        None,
    )
    if global_pattern is not None:
        return "global_pattern", global_pattern

    return "generic_fallback", None


__all__ = [
    "normalize_field_names",
    "normalize_field_kind_overrides",
    "resolve_rule_identity_map",
]
