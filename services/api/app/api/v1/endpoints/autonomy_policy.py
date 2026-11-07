"""Autonomy policy admin endpoints — Tier 1 capability 1.3.

Surfaces the three-tier per-action confidence thresholds (auto / review /
escalation) the agent uses when deciding whether to execute, queue for
review, escalate, or reject a proposed action.

Threshold resolution (low → high precedence) when the agent loads a policy:

    hard-coded defaults  →  YAML site policy  →  DB tenant overrides

This module manages the **DB tenant overrides** layer. Reads return the
*effective* policy after merging defaults + DB so the admin UI can show a
single coherent view; writes only persist to the DB layer.

All endpoints are tenant-scoped and require ``settings:read`` /
``settings:write`` permissions (typically held only by the ``tenant_admin``
role — see ``services/api/app/core/security.py``).
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession
from app.services.runbook.action_catalog import ACTIONS, required_connectors

logger = structlog.get_logger()

router = APIRouter(prefix="/autonomy-policy", tags=["autonomy-policy"])


# ---------------------------------------------------------------------------
# Reference policy — sourced from the Runbook action catalog.
#
# These views used to be literal dicts duplicated in this module, on top of a
# third copy inside ``services/agents/app/policy/guardrails.py``. Since the
# Runbook gate needs the same values, they now live in exactly one place for
# the API service — ``app/services/runbook/action_catalog.py`` — and are
# projected back into the dict shapes the rest of this module already reads.
#
# The agents service still ships its own copy (separate container, no shared
# package); ``tests/test_runbook_thresholds.py`` parses that module with ``ast``
# and fails if the values ever diverge.
# ---------------------------------------------------------------------------
_DEFAULTS: dict[str, tuple[float, float, float]] = {
    name: (definition.thresholds.auto, definition.thresholds.review, definition.thresholds.escalation)
    for name, definition in ACTIONS.items()
}

_BLAST_RADIUS: dict[str, str] = {name: definition.blast_radius.value for name, definition in ACTIONS.items()}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ThresholdTriple(BaseModel):
    """Three confidence cutoffs for one action.

    Invariant: ``escalation <= review <= auto`` and all are in ``[0.0, 1.0]``.
    """

    auto: float = Field(..., ge=0.0, le=1.0)
    review: float = Field(..., ge=0.0, le=1.0)
    escalation: float = Field(..., ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _enforce_ordering(self) -> ThresholdTriple:
        if self.review > self.auto:
            raise ValueError("review threshold must be <= auto threshold")
        if self.escalation > self.review:
            raise ValueError("escalation threshold must be <= review threshold")
        return self


class ActionPolicy(BaseModel):
    action: str
    blast_radius: str
    thresholds: ThresholdTriple
    default_thresholds: ThresholdTriple
    overridden: bool
    override_source: str | None = None
    last_updated_at: str | None = None
    last_updated_by: str | None = None
    last_reason: str | None = None
    # Manager-facing governance features
    enabled: bool = True
    is_system_core: bool = True
    # Connector availability — False if required connectors are missing
    available: bool = True


class AutonomyPolicyResponse(BaseModel):
    tenant_id: str
    actions: list[ActionPolicy]


class ThresholdUpdateRequest(BaseModel):
    auto: float = Field(..., ge=0.0, le=1.0)
    review: float = Field(..., ge=0.0, le=1.0)
    escalation: float = Field(..., ge=0.0, le=1.0)
    reason: str | None = Field(
        None,
        max_length=500,
        description="Free-text justification — surfaced in the audit log.",
    )

    @model_validator(mode="after")
    def _enforce_ordering(self) -> ThresholdUpdateRequest:
        if self.review > self.auto:
            raise ValueError("review threshold must be <= auto threshold")
        if self.escalation > self.review:
            raise ValueError("escalation threshold must be <= review threshold")
        return self


class ThresholdUpdateResponse(BaseModel):
    action: str
    thresholds: ThresholdTriple
    updated_at: str
    updated_by: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _default_triple(action: str) -> ThresholdTriple:
    a, r, e = _DEFAULTS.get(action, (1.0, 1.0, 1.0))
    return ThresholdTriple(auto=a, review=r, escalation=e)


async def _fetch_overrides(db, tenant_id: str) -> dict[str, dict]:
    """Return ``{action_name: row_dict}`` from the DB, or ``{}`` if the table
    is missing or unreachable. Falls back to the legacy single-column shape
    if the migration 021 columns aren't present yet."""
    try:
        result = await db.execute(
            text(
                """
                SELECT action_name,
                       min_confidence,
                       review_confidence,
                       escalation_confidence,
                       updated_by,
                       updated_at,
                       source,
                       reason,
                       COALESCE(enabled, true) AS enabled
                FROM aisoc_autonomy_thresholds
                WHERE tenant_id = :tenant_id
                """
            ),
            {"tenant_id": str(tenant_id)},
        )
        rows = result.mappings().all()
    except Exception:
        # Pre-021 schema or table missing — try the minimal legacy shape.
        try:
            result = await db.execute(
                text(
                    """
                    SELECT action_name,
                           min_confidence,
                           updated_by,
                           updated_at,
                           COALESCE(enabled, true) AS enabled
                    FROM aisoc_autonomy_thresholds
                    WHERE tenant_id = :tenant_id
                    """
                ),
                {"tenant_id": str(tenant_id)},
            )
            rows = result.mappings().all()
        except Exception as exc:
            logger.warning(
                "autonomy_policy.fetch_overrides_unavailable",
                tenant_id=str(tenant_id),
                error=str(exc),
            )
            return {}
    return {r["action_name"]: dict(r) for r in rows}


def _row_to_triple(row: dict) -> ThresholdTriple:
    auto = float(row["min_confidence"])
    review = row.get("review_confidence")
    escalation = row.get("escalation_confidence")
    review_v = float(review) if review is not None else max(0.0, auto - 0.1)
    escalation_v = float(escalation) if escalation is not None else max(0.0, review_v - 0.2)
    # Clamp into a valid ordering — older legacy rows may not satisfy it.
    review_v = min(review_v, auto)
    escalation_v = min(escalation_v, review_v)
    return ThresholdTriple(auto=auto, review=review_v, escalation=escalation_v)


async def _fetch_active_connectors(db, tenant_id: str) -> set[str]:
    """Return a set of active/enabled connector types for the tenant."""
    try:
        result = await db.execute(
            text(
                """
                SELECT DISTINCT connector_type
                FROM connectors
                WHERE tenant_id = :tenant_id AND is_enabled = true
                """
            ),
            {"tenant_id": str(tenant_id)},
        )
        rows = result.scalars().all()
        return set(rows) if rows else set()
    except Exception as exc:
        logger.warning(
            "autonomy_policy.fetch_active_connectors_unavailable",
            tenant_id=str(tenant_id),
            error=str(exc),
        )
        return set()


def _is_action_available(action: str, active_connectors: set[str]) -> bool:
    """Check if all required connectors for an action are active.

    Returns True if the action has no connector requirements or all required
    connectors are present in the active set.
    """
    req = required_connectors(action)
    if not req:
        return True
    # Action is available if ANY of the required connectors is active
    # (e.g. firewall_rule_add needs "firewall", isolate_host needs "firewall" or "edr")
    return any(ct in active_connectors for ct in req)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=AutonomyPolicyResponse)
async def get_autonomy_policy(
    user: AuthUser,
    db: DBSession,
) -> AutonomyPolicyResponse:
    """Return the effective autonomy policy for the calling tenant.

    For each known action we surface the merged thresholds (defaults + DB
    overrides), the hard-coded defaults, and an ``overridden`` flag the UI
    uses to render a "modified from default" badge. The ``available`` field
    indicates whether required connectors are active for the action.
    """
    await user.require_permission_db("settings:read", db)

    overrides = await _fetch_overrides(db, str(user.tenant_id))
    active_connectors = await _fetch_active_connectors(db, str(user.tenant_id))

    actions: list[ActionPolicy] = []
    seen: set[str] = set()
    for action in _DEFAULTS:
        seen.add(action)
        defaults = _default_triple(action)
        row = overrides.get(action)
        available = _is_action_available(action, active_connectors)
        if row is not None:
            thresholds = _row_to_triple(row)
            actions.append(
                ActionPolicy(
                    action=action,
                    blast_radius=_BLAST_RADIUS.get(action, "unknown"),
                    thresholds=thresholds,
                    default_thresholds=defaults,
                    overridden=True,
                    override_source=row.get("source") or "admin_ui",
                    last_updated_at=row["updated_at"].isoformat() if row.get("updated_at") else None,
                    last_updated_by=row.get("updated_by"),
                    last_reason=row.get("reason"),
                    enabled=row.get("enabled", True),
                    is_system_core=True,
                    available=available,
                )
            )
        else:
            actions.append(
                ActionPolicy(
                    action=action,
                    blast_radius=_BLAST_RADIUS.get(action, "unknown"),
                    thresholds=defaults,
                    default_thresholds=defaults,
                    overridden=False,
                    enabled=True,
                    is_system_core=True,
                    available=available,
                )
            )

    # Surface any DB rows for actions we don't recognise (custom tenant
    # actions) so the admin can still see and clear them.
    for action, row in overrides.items():
        if action in seen:
            continue
        thresholds = _row_to_triple(row)
        available = _is_action_available(action, active_connectors)
        actions.append(
            ActionPolicy(
                action=action,
                blast_radius="custom",
                thresholds=thresholds,
                default_thresholds=ThresholdTriple(auto=1.0, review=1.0, escalation=1.0),
                overridden=True,
                override_source=row.get("source") or "admin_ui",
                last_updated_at=row["updated_at"].isoformat() if row.get("updated_at") else None,
                last_updated_by=row.get("updated_by"),
                last_reason=row.get("reason"),
                enabled=row.get("enabled", True),
                is_system_core=False,
                available=available,
            )
        )

    actions.sort(key=lambda a: (a.blast_radius, a.action))
    return AutonomyPolicyResponse(tenant_id=str(user.tenant_id), actions=actions)


@router.put("/{action}", response_model=ThresholdUpdateResponse)
async def upsert_action_threshold(
    action: str,
    payload: ThresholdUpdateRequest,
    user: AuthUser,
    db: DBSession,
) -> ThresholdUpdateResponse:
    """Set (or update) the three-tier thresholds for one action.

    The new policy takes effect after the agent's tenant-cache TTL expires
    or the cache is reset (``services/agents/app/policy/__init__.py``
    ``reset_tenant_cache``).
    """
    await user.require_permission_db("settings:write", db)

    if not action or len(action) > 100 or not action.replace("_", "").isalnum():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="action name must be alphanumeric/underscore, ≤ 100 chars",
        )

    now = datetime.now(UTC)
    try:
        # We always SET min_confidence; the new columns are silently ignored
        # if they don't exist yet because the migration adds them as NULLable.
        await db.execute(
            text(
                """
                INSERT INTO aisoc_autonomy_thresholds (
                    tenant_id, action_name, min_confidence,
                    review_confidence, escalation_confidence,
                    updated_by, updated_at, source, reason
                )
                VALUES (
                    :tenant_id, :action, :auto,
                    :review, :escalation,
                    :updated_by, :updated_at, 'admin_ui', :reason
                )
                ON CONFLICT (tenant_id, action_name) DO UPDATE SET
                    min_confidence = EXCLUDED.min_confidence,
                    review_confidence = EXCLUDED.review_confidence,
                    escalation_confidence = EXCLUDED.escalation_confidence,
                    updated_by = EXCLUDED.updated_by,
                    updated_at = EXCLUDED.updated_at,
                    source = EXCLUDED.source,
                    reason = EXCLUDED.reason
                """
            ),
            {
                "tenant_id": str(user.tenant_id),
                "action": action,
                "auto": payload.auto,
                "review": payload.review,
                "escalation": payload.escalation,
                "updated_by": user.email,
                "updated_at": now,
                "reason": payload.reason,
            },
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        # Retry against the legacy schema if the new columns aren't there.
        try:
            await db.execute(
                text(
                    """
                    INSERT INTO aisoc_autonomy_thresholds (
                        tenant_id, action_name, min_confidence,
                        updated_by, updated_at
                    )
                    VALUES (:tenant_id, :action, :auto, :updated_by, :updated_at)
                    ON CONFLICT (tenant_id, action_name) DO UPDATE SET
                        min_confidence = EXCLUDED.min_confidence,
                        updated_by = EXCLUDED.updated_by,
                        updated_at = EXCLUDED.updated_at
                    """
                ),
                {
                    "tenant_id": str(user.tenant_id),
                    "action": action,
                    "auto": payload.auto,
                    "updated_by": user.email,
                    "updated_at": now,
                },
            )
            await db.commit()
            logger.warning(
                "autonomy_policy.legacy_schema_used",
                tenant_id=str(user.tenant_id),
                action=action,
                reason="pre-021 schema; review/escalation tiers will be derived",
            )
        except Exception as final_exc:
            await db.rollback()
            logger.error(
                "autonomy_policy.upsert_failed",
                tenant_id=str(user.tenant_id),
                action=action,
                error=str(final_exc),
                first_error=str(exc),
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to persist autonomy threshold",
            ) from final_exc

    logger.info(
        "autonomy_policy.threshold_updated",
        tenant_id=str(user.tenant_id),
        action=action,
        auto=payload.auto,
        review=payload.review,
        escalation=payload.escalation,
        updated_by=user.email,
        reason_set=payload.reason is not None,
    )

    return ThresholdUpdateResponse(
        action=action,
        thresholds=ThresholdTriple(auto=payload.auto, review=payload.review, escalation=payload.escalation),
        updated_at=now.isoformat(),
        updated_by=user.email,
    )


@router.delete("/{action}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def reset_action_threshold(
    action: str,
    user: AuthUser,
    db: DBSession,
) -> None:
    """Reset a single action back to the hard-coded / YAML default."""
    await user.require_permission_db("settings:write", db)

    try:
        await db.execute(
            text(
                """
                DELETE FROM aisoc_autonomy_thresholds
                WHERE tenant_id = :tenant_id AND action_name = :action
                """
            ),
            {"tenant_id": str(user.tenant_id), "action": action},
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.error(
            "autonomy_policy.reset_failed",
            tenant_id=str(user.tenant_id),
            action=action,
            error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset autonomy threshold",
        ) from exc

    logger.info(
        "autonomy_policy.threshold_reset",
        tenant_id=str(user.tenant_id),
        action=action,
        reset_by=user.email,
    )


# ── New endpoint for toggle enable/disable ────────────────────────────────────


class ActionToggleRequest(BaseModel):
    enabled: bool


class ActionToggleResponse(BaseModel):
    action: str
    enabled: bool
    updated_at: str
    updated_by: str


@router.patch("/{action}/enabled", response_model=ActionToggleResponse)
async def toggle_action_enabled(
    action: str,
    payload: ActionToggleRequest,
    user: AuthUser,
    db: DBSession,
) -> ActionToggleResponse:
    """Enable or disable an action for the tenant.

    When an action is disabled (enabled=false), it will not execute even if
    the confidence threshold is met. This is useful for temporarily disabling
    a capability without deleting the policy configuration.
    """
    await user.require_permission_db("settings:write", db)

    if not action or len(action) > 100 or not action.replace("_", "").isalnum():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="action name must be alphanumeric/underscore, ≤ 100 chars",
        )

    # An action cannot be switched on in a workspace that has no connector able
    # to execute it: enabling it would advertise a capability the platform cannot
    # deliver. Disabling is always allowed, so an existing row can be cleared.
    if payload.enabled:
        active_connectors = await _fetch_active_connectors(db, str(user.tenant_id))
        if not _is_action_available(action, active_connectors):
            needed = ", ".join(required_connectors(action))
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"action {action!r} requires an enabled connector of type "
                    f"{needed}; none is configured for this workspace"
                ),
            )

    now = datetime.now(UTC)
    try:
        # Use UPSERT to ensure the row exists if this is the first time the action
        # is being disabled. If the row doesn't exist, we create it with defaults.
        await db.execute(
            text(
                """
                INSERT INTO aisoc_autonomy_thresholds (
                    tenant_id, action_name, min_confidence, enabled,
                    updated_by, updated_at, source
                )
                VALUES (
                    :tenant_id, :action, 1.0, :enabled,
                    :updated_by, :updated_at, 'admin_ui'
                )
                ON CONFLICT (tenant_id, action_name) DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    updated_by = EXCLUDED.updated_by,
                    updated_at = EXCLUDED.updated_at
                """
            ),
            {
                "tenant_id": str(user.tenant_id),
                "action": action,
                "enabled": payload.enabled,
                "updated_by": user.email,
                "updated_at": now,
            },
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.error(
            "autonomy_policy.toggle_failed",
            tenant_id=str(user.tenant_id),
            action=action,
            enabled=payload.enabled,
            error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to toggle action enabled status",
        ) from exc

    logger.info(
        "autonomy_policy.action_toggled",
        tenant_id=str(user.tenant_id),
        action=action,
        enabled=payload.enabled,
        updated_by=user.email,
    )

    return ActionToggleResponse(
        action=action,
        enabled=payload.enabled,
        updated_at=now.isoformat(),
        updated_by=user.email,
    )
