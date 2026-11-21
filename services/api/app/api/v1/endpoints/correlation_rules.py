"""Tenant-scoped correlation rule identity registry API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.correlation_rule_identity import (
    CorrelationRuleIdentityMap,
    CorrelationRuleResolutionAudit,
)
from app.services.correlation_rule_registry import (
    normalize_field_kind_overrides,
    normalize_field_names,
    resolve_rule_identity_map,
)

router = APIRouter(prefix="/correlation/rules", tags=["correlation"])

_FIELD_KINDS = {
    "host",
    "user",
    "ip",
    "domain",
    "hash",
    "process_guid",
}


def _field_names(values: list[str]) -> list[str]:
    return normalize_field_names(values)


class IdentityMapPayload(BaseModel):
    rule_name: str = Field(min_length=1, max_length=500)
    rule_name_pattern: str | None = Field(default=None, max_length=500)
    is_active: bool = True
    host_fields: list[str] = Field(default_factory=list)
    user_fields: list[str] = Field(default_factory=list)
    ip_fields: list[str] = Field(default_factory=list)
    domain_fields: list[str] = Field(default_factory=list)
    hash_fields: list[str] = Field(default_factory=list)
    process_guid_fields: list[str] = Field(default_factory=list)
    excluded_fields: list[str] = Field(default_factory=list)
    field_kind_overrides: dict[str, str] = Field(default_factory=dict)
    notes: str | None = Field(default=None, max_length=5000)


class IdentityMapUpdate(BaseModel):
    rule_name: str | None = Field(default=None, min_length=1, max_length=500)
    rule_name_pattern: str | None = Field(default=None, max_length=500)
    is_active: bool | None = None
    host_fields: list[str] | None = None
    user_fields: list[str] | None = None
    ip_fields: list[str] | None = None
    domain_fields: list[str] | None = None
    hash_fields: list[str] | None = None
    process_guid_fields: list[str] | None = None
    excluded_fields: list[str] | None = None
    field_kind_overrides: dict[str, str] | None = None
    notes: str | None = None


class IdentityMapResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    rule_name: str
    rule_name_pattern: str | None
    is_active: bool
    host_fields: list[str]
    user_fields: list[str]
    ip_fields: list[str]
    domain_fields: list[str]
    hash_fields: list[str]
    process_guid_fields: list[str]
    excluded_fields: list[str]
    field_kind_overrides: dict[str, str]
    notes: str | None
    source: str
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class IdentityResolutionResponse(BaseModel):
    rule_name: str
    matched_source: Literal[
        "exact",
        "tenant_pattern",
        "global_pattern",
        "generic_fallback",
        "missing",
    ]
    map: IdentityMapResponse | None


class ResolutionAuditResponse(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    rule_name: str
    map_id: uuid.UUID | None
    matched_source: str
    resolved_host_fields: list[str]
    resolved_user_fields: list[str]
    resolved_ip_fields: list[str]
    missing_fields: list[str]
    filtered_values: dict
    normalizer_version: str
    created_at: datetime


def _normalise_payload(payload: IdentityMapPayload) -> IdentityMapPayload:
    payload.rule_name = payload.rule_name.strip()
    payload.rule_name_pattern = payload.rule_name_pattern.strip() if payload.rule_name_pattern else None
    payload.notes = payload.notes.strip() if payload.notes else None

    payload.host_fields = _field_names(payload.host_fields)
    payload.user_fields = _field_names(payload.user_fields)
    payload.ip_fields = _field_names(payload.ip_fields)
    payload.domain_fields = _field_names(payload.domain_fields)
    payload.hash_fields = _field_names(payload.hash_fields)
    payload.process_guid_fields = _field_names(payload.process_guid_fields)
    payload.excluded_fields = _field_names(payload.excluded_fields)

    payload.field_kind_overrides = normalize_field_kind_overrides(payload.field_kind_overrides)
    return payload


def _map_response(row: CorrelationRuleIdentityMap) -> IdentityMapResponse:
    return IdentityMapResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        rule_name=row.rule_name,
        rule_name_pattern=row.rule_name_pattern,
        is_active=row.is_active,
        host_fields=row.host_fields or [],
        user_fields=row.user_fields or [],
        ip_fields=row.ip_fields or [],
        domain_fields=row.domain_fields or [],
        hash_fields=row.hash_fields or [],
        process_guid_fields=row.process_guid_fields or [],
        excluded_fields=row.excluded_fields or [],
        field_kind_overrides=row.field_kind_overrides or {},
        notes=row.notes,
        source=row.source,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("", response_model=list[IdentityMapResponse])
async def list_rule_identity_maps(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: TenantDBSession,
) -> list[IdentityMapResponse]:
    result = await db.execute(
        select(CorrelationRuleIdentityMap)
        .where(
            or_(
                CorrelationRuleIdentityMap.tenant_id == current_user.tenant_id,
                CorrelationRuleIdentityMap.tenant_id.is_(None),
            )
        )
        .order_by(CorrelationRuleIdentityMap.rule_name.asc())
    )
    rows = result.scalars().all()
    return [_map_response(row) for row in rows]


@router.post("", response_model=IdentityMapResponse, status_code=status.HTTP_201_CREATED)
async def create_rule_identity_map(
    payload: IdentityMapPayload,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: TenantDBSession,
) -> IdentityMapResponse:
    payload = _normalise_payload(payload)
    row = CorrelationRuleIdentityMap(
        tenant_id=current_user.tenant_id,
        rule_name=payload.rule_name,
        rule_name_pattern=payload.rule_name_pattern,
        is_active=payload.is_active,
        host_fields=payload.host_fields,
        user_fields=payload.user_fields,
        ip_fields=payload.ip_fields,
        domain_fields=payload.domain_fields,
        hash_fields=payload.hash_fields,
        process_guid_fields=payload.process_guid_fields,
        excluded_fields=payload.excluded_fields,
        field_kind_overrides=payload.field_kind_overrides,
        notes=payload.notes,
        source="operator",
        created_by=current_user.user_id,
    )
    db.add(row)
    try:
        await db.commit()
        await db.refresh(row)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="An exact tenant rule map already exists") from exc
    return _map_response(row)


@router.patch("/{map_id}", response_model=IdentityMapResponse)
async def update_rule_identity_map(
    map_id: uuid.UUID,
    payload: IdentityMapUpdate,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: TenantDBSession,
) -> IdentityMapResponse:
    result = await db.execute(
        select(CorrelationRuleIdentityMap).where(
            CorrelationRuleIdentityMap.id == map_id,
            CorrelationRuleIdentityMap.tenant_id == current_user.tenant_id,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Tenant rule identity map not found")

    changes = payload.model_dump(exclude_unset=True)
    for field_name in (
        "host_fields",
        "user_fields",
        "ip_fields",
        "domain_fields",
        "hash_fields",
        "process_guid_fields",
        "excluded_fields",
    ):
        if field_name in changes:
            changes[field_name] = _field_names(changes[field_name])
    if "rule_name" in changes and changes["rule_name"] is not None:
        changes["rule_name"] = str(changes["rule_name"]).strip()
    if "rule_name_pattern" in changes:
        changes["rule_name_pattern"] = (
            str(changes["rule_name_pattern"]).strip()
            if changes["rule_name_pattern"]
            else None
        )
    if "notes" in changes:
        changes["notes"] = str(changes["notes"]).strip() if changes["notes"] else None
    if "field_kind_overrides" in changes:
        changes["field_kind_overrides"] = normalize_field_kind_overrides(
            changes["field_kind_overrides"]
        )

    for field_name, value in changes.items():
        setattr(row, field_name, value)

    try:
        await db.commit()
        await db.refresh(row)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="An exact tenant rule map already exists") from exc
    return _map_response(row)


@router.delete("/{map_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule_identity_map(
    map_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: TenantDBSession,
) -> None:
    result = await db.execute(
        select(CorrelationRuleIdentityMap).where(
            CorrelationRuleIdentityMap.id == map_id,
            CorrelationRuleIdentityMap.tenant_id == current_user.tenant_id,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Tenant rule identity map not found")
    await db.delete(row)
    await db.commit()


@router.get("/resolve", response_model=IdentityResolutionResponse)
async def resolve_rule_identity_map_preview(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: TenantDBSession,
    rule_name: str = Query(min_length=1, max_length=500),
) -> IdentityResolutionResponse:
    name = rule_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="rule_name is required")

    result = await db.execute(
        select(CorrelationRuleIdentityMap)
        .where(
            CorrelationRuleIdentityMap.is_active.is_(True),
            or_(
                CorrelationRuleIdentityMap.tenant_id == current_user.tenant_id,
                CorrelationRuleIdentityMap.tenant_id.is_(None),
            ),
        )
    )
    rows = result.scalars().all()

    matched_source, mapped_row = resolve_rule_identity_map(
        current_user.tenant_id,
        name,
        rows,
    )
    return IdentityResolutionResponse(
        rule_name=name,
        matched_source=matched_source,
        map=_map_response(mapped_row) if mapped_row is not None else None,
    )


@router.get("/audits", response_model=list[ResolutionAuditResponse])
async def list_resolution_audits(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: TenantDBSession,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ResolutionAuditResponse]:
    result = await db.execute(
        select(CorrelationRuleResolutionAudit)
        .where(CorrelationRuleResolutionAudit.tenant_id == current_user.tenant_id)
        .order_by(CorrelationRuleResolutionAudit.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return [
        ResolutionAuditResponse(
            id=row.id,
            alert_id=row.alert_id,
            rule_name=row.rule_name,
            map_id=row.map_id,
            matched_source=row.matched_source,
            resolved_host_fields=row.resolved_host_fields or [],
            resolved_user_fields=row.resolved_user_fields or [],
            resolved_ip_fields=row.resolved_ip_fields or [],
            missing_fields=row.missing_fields or [],
            filtered_values=row.filtered_values or {},
            normalizer_version=row.normalizer_version,
            created_at=row.created_at,
        )
        for row in rows
    ]


__all__ = ["router"]
