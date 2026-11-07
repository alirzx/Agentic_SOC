"""The Runbook gate — may this action run, right now, for this tenant?

Every governed step asks this module before it touches a subject. The answer is
a :class:`GateDecision`, and the decision is stored verbatim on the resulting
``runbook_events`` row (``policy`` column) so "why was this allowed?" stays
answerable years later without replaying historical policy.

Threshold resolution (low → high precedence)
-------------------------------------------
1. The action's shipped defaults — :mod:`app.services.runbook.action_catalog`.
2. Site-wide YAML at ``$AISOC_AUTONOMY_POLICY`` (or the agents service's
   ``config/autonomy_policy.yaml`` when this checkout has it), using the exact
   schema ``services/agents/app/policy/guardrails.py`` already accepts.
3. Per-tenant rows in ``aisoc_autonomy_thresholds`` plus the migration-062
   ``enabled`` / ``autonomy_level`` columns.

This is the same three-layer model the agents runtime uses, deliberately: an
operator who tunes autonomy in the admin UI must not discover a second,
differently-tuned policy on the API side.

Failure behaviour
-----------------
A missing table, a legacy schema (pre-062), an unreadable YAML file, or a
malformed entry all degrade to the *stricter* layer, never to "allow". An
unreadable site policy falls back to catalog defaults; an unreadable tenant row
falls back to defaults rather than granting an override we could not verify.

Schema shape is discovered once per process (``information_schema``) instead of
by catching statement errors: a failed statement inside a request transaction
aborts the whole transaction in Postgres, which would break unrelated work the
caller had already staged.
"""

from __future__ import annotations

import math
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
import yaml
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.runbook.action_catalog import ActionDefinition, BlastRadius, get_action
from app.services.runbook.thresholds import (
    DEFAULT_REQUIRE_ANALYST,
    ActionThresholds,
    AutonomyDecision,
    make_thresholds,
)

logger = structlog.get_logger()

__all__ = [
    "GateDecision",
    "TenantOverride",
    "autonomy_level_for",
    "cap_autonomy_level",
    "decide",
    "evaluate",
    "fetch_tenant_override",
    "load_site_policy",
    "reset_gate_caches",
]

_LEVEL_ORDER = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4}

# Actions whose blast radius stays inside the platform's own records may reach
# L4; anything that can change a customer system caps at L3 no matter how
# confident the agent is.
_SAFE_BLAST_RADII = (BlastRadius.READ, BlastRadius.LOW)

_THRESHOLDS_TABLE = "aisoc_autonomy_thresholds"
_MIGRATION_062_COLUMN = "enabled"

# Site policy is read once per process (same as the agents runtime).
_SITE_POLICY: dict[str, ActionThresholds] | None = None
# (table_present, has_migration_062_columns) — ``None`` means "not probed yet".
_SCHEMA_SHAPE: tuple[bool, bool] | None = None


@dataclass(frozen=True)
class TenantOverride:
    """One tenant's row from ``aisoc_autonomy_thresholds``."""

    enabled: bool = True
    autonomy_level: str | None = None
    thresholds: ActionThresholds | None = None
    source: str | None = None
    updated_by: str | None = None


@dataclass(frozen=True)
class GateDecision:
    """The gate's answer, plus everything needed to justify it later."""

    action: str
    decision: AutonomyDecision
    allowed: bool
    approval_required: bool
    autonomy_level: str
    layer: str
    thresholds: ActionThresholds
    reason: str
    definition: ActionDefinition | None = None

    def policy_snapshot(self) -> dict[str, Any]:
        """JSON-safe record stored in ``runbook_events.policy``.

        Kept flat and small on purpose: the ledger must stay queryable, and the
        full definition is recoverable from the catalog by ``action`` name plus
        the release that wrote the row.
        """
        return {
            "decision": self.decision.value,
            "allowed": self.allowed,
            "approval_required": self.approval_required,
            "autonomy_level": self.autonomy_level,
            "layer": self.layer,
            "thresholds": self.thresholds.to_dict(),
            "blast_radius": self.definition.blast_radius.value if self.definition else None,
            "reason": self.reason,
        }


# ─── Site YAML ───────────────────────────────────────────────────────────────


def _site_policy_path() -> Path:
    """Where to look for the operator-managed YAML.

    ``$AISOC_AUTONOMY_POLICY`` wins so a deployment can mount the file
    anywhere. Otherwise we look for the agents service's copy in a monorepo
    checkout — inside the API container that path does not exist, the file is
    simply absent, and catalog defaults apply.
    """
    override = os.environ.get("AISOC_AUTONOMY_POLICY", "").strip()
    if override:
        return Path(override).expanduser()
    # services/api/app/services/runbook/gate.py → parents[4] == services/
    return Path(__file__).resolve().parents[4] / "agents" / "config" / "autonomy_policy.yaml"


def _coerce_thresholds(action: str, value: Any) -> ActionThresholds | None:
    """Accept the agents runtime's scalar or ``{auto, review, escalation}`` form."""
    safe_action = str(action).replace("\r", "").replace("\n", " ")[:200]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return make_thresholds(float(value))
    if isinstance(value, Mapping):
        raw_auto = value.get("auto", value.get("auto_threshold"))
        if raw_auto is None:
            logger.warning("runbook.gate.yaml_missing_auto", action=safe_action)
            return None
        try:
            review = value.get("review", value.get("analyst_review_threshold"))
            escalation = value.get("escalation", value.get("escalation_threshold"))
            return make_thresholds(
                float(raw_auto),
                float(review) if review is not None else None,
                float(escalation) if escalation is not None else None,
            )
        except (TypeError, ValueError):
            logger.warning("runbook.gate.yaml_bad_value", action=safe_action)
            return None
    logger.warning("runbook.gate.yaml_bad_value", action=safe_action)
    return None


def load_site_policy(path: Path | None = None) -> dict[str, ActionThresholds]:
    """Parsed site-wide thresholds; empty when the file is absent or unusable.

    Never raises: a broken policy file must not take the API down, and falling
    back to catalog defaults is the strict answer, not a permissive one.
    """
    target = path or _site_policy_path()
    safe_path = str(target).replace("\r", "").replace("\n", " ")[:200]
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning(
            "runbook.gate.site_policy_unreadable",
            path=safe_path,
            error=str(f"{type(exc).__name__}: {exc}").replace("\r", "").replace("\n", " ")[:200],
        )
        return {}

    if not isinstance(raw, Mapping):
        logger.warning("runbook.gate.site_policy_not_a_mapping", path=safe_path)
        return {}

    section = raw.get("thresholds", raw)
    if not isinstance(section, Mapping):
        logger.warning("runbook.gate.site_policy_bad_thresholds", path=safe_path)
        return {}

    parsed: dict[str, ActionThresholds] = {}
    for name, value in section.items():
        action = str(name).strip()
        if not action or action in {"version", "thresholds"}:
            continue
        thresholds = _coerce_thresholds(action, value)
        if thresholds is not None:
            parsed[action] = thresholds
    return parsed


def reset_gate_caches() -> None:
    """Drop process-level caches (site policy + schema shape). Used by tests."""
    global _SITE_POLICY, _SCHEMA_SHAPE
    _SITE_POLICY = None
    _SCHEMA_SHAPE = None


def _cached_site_policy() -> dict[str, ActionThresholds]:
    global _SITE_POLICY
    if _SITE_POLICY is None:
        _SITE_POLICY = load_site_policy()
    return _SITE_POLICY


# ─── Tenant overrides ────────────────────────────────────────────────────────


async def _schema_shape(db: AsyncSession) -> tuple[bool, bool]:
    """Probe ``(table_present, has_migration_062_columns)`` once per process."""
    global _SCHEMA_SHAPE
    if _SCHEMA_SHAPE is not None:
        return _SCHEMA_SHAPE

    probe = text(
        """
        SELECT column_name
          FROM information_schema.columns
         WHERE table_name = :table_name
        """
    ).bindparams(table_name=_THRESHOLDS_TABLE)
    try:
        columns = {str(name) for name in (await db.execute(probe)).scalars().all()}
    except Exception as exc:  # noqa: BLE001 — unreachable database is a valid state
        logger.warning(
            "runbook.gate.schema_probe_failed",
            error=str(f"{type(exc).__name__}: {exc}").replace("\r", "").replace("\n", " ")[:200],
        )
        # Do not cache a probe failure: the next caller (or the next request on
        # a recovered connection) must be allowed to succeed.
        return False, False

    _SCHEMA_SHAPE = (bool(columns), _MIGRATION_062_COLUMN in columns)
    return _SCHEMA_SHAPE


def _row_thresholds(row: Mapping[str, Any]) -> ActionThresholds | None:
    """Build thresholds from a DB row, tolerating the pre-021 single-column shape."""
    raw_auto = row.get("min_confidence")
    if raw_auto is None:
        return None
    try:
        review = row.get("review_confidence")
        escalation = row.get("escalation_confidence")
        return make_thresholds(
            float(raw_auto),
            float(review) if review is not None else None,
            float(escalation) if escalation is not None else None,
        )
    except (TypeError, ValueError):
        logger.warning("runbook.gate.tenant_override_bad_value")
        return None


async def fetch_tenant_override(
    db: AsyncSession | None,
    tenant_id: uuid.UUID | str | None,
    action: str,
) -> TenantOverride | None:
    """Load one tenant's override row, or ``None``.

    The migration-062 columns are always the source of truth when the table has
    them; on a pre-062 database (rolling deploy) ``enabled`` is treated as true
    and no autonomy cap applies, which is exactly the behaviour before 062.
    """
    if db is None or tenant_id is None:
        return None

    table_present, has_062_columns = await _schema_shape(db)
    if not table_present:
        return None

    params = {"tenant_id": str(tenant_id), "action_name": action}
    if has_062_columns:
        statement = text(
            """
            SELECT action_name, min_confidence, review_confidence, escalation_confidence,
                   enabled, autonomy_level, source, updated_by
              FROM aisoc_autonomy_thresholds
             WHERE tenant_id = :tenant_id AND action_name = :action_name
             LIMIT 1
            """
        ).bindparams(**params)
    else:
        statement = text(
            """
            SELECT action_name, min_confidence, review_confidence, escalation_confidence
              FROM aisoc_autonomy_thresholds
             WHERE tenant_id = :tenant_id AND action_name = :action_name
             LIMIT 1
            """
        ).bindparams(**params)

    try:
        row = (await db.execute(statement)).mappings().first()
    except Exception as exc:  # noqa: BLE001 — e.g. pre-021 shape without the tier columns
        logger.warning(
            "runbook.gate.override_query_failed",
            action=str(action).replace("\r", "").replace("\n", " ")[:200],
            error=str(f"{type(exc).__name__}: {exc}").replace("\r", "").replace("\n", " ")[:200],
        )
        return None

    if row is None:
        return None

    raw_level = row.get("autonomy_level")
    level = str(raw_level).strip().upper() if raw_level else None
    if level not in _LEVEL_ORDER:
        level = None

    return TenantOverride(
        enabled=bool(row.get("enabled", True)),
        autonomy_level=level,
        thresholds=_row_thresholds(row),
        source=row.get("source"),
        updated_by=row.get("updated_by"),
    )


# ─── Decision ────────────────────────────────────────────────────────────────


def autonomy_level_for(definition: ActionDefinition | None, decision: AutonomyDecision) -> str:
    """Map a decision to the L0–L4 ladder the console displays.

    L4 fully autonomous · L3 autonomy with HITL · L2 supervised ·
    L1 assisted · L0 manual.
    """
    if definition is None or definition.always_requires_approval:
        return "L0"
    if decision is AutonomyDecision.AUTO:
        return "L4" if definition.blast_radius in _SAFE_BLAST_RADII else "L3"
    if decision is AutonomyDecision.REVIEW:
        return "L2"
    if decision is AutonomyDecision.ESCALATE:
        return "L1"
    return "L0"


def cap_autonomy_level(level: str, cap: str | None) -> str:
    """Return the stricter of ``level`` and ``cap`` (a tenant ceiling)."""
    if cap is None or cap not in _LEVEL_ORDER:
        return level
    if level not in _LEVEL_ORDER:
        return cap
    return level if _LEVEL_ORDER[level] <= _LEVEL_ORDER[cap] else cap


def decide(
    action: str,
    confidence: float,
    *,
    override: TenantOverride | None = None,
    site_policy: Mapping[str, ActionThresholds] | None = None,
) -> GateDecision:
    """Pure decision — no database, no I/O. This is the unit-tested core."""
    definition = get_action(action)
    if definition is None:
        return GateDecision(
            action=action,
            decision=AutonomyDecision.REJECT,
            allowed=False,
            approval_required=True,
            autonomy_level="L0",
            layer="unknown_action",
            thresholds=DEFAULT_REQUIRE_ANALYST,
            reason=(
                f"{action!r} is not in the action catalog — ungoverned actions "
                "always require an analyst"
            ),
            definition=None,
        )

    thresholds = definition.thresholds
    layer = "defaults"

    site = _cached_site_policy() if site_policy is None else site_policy
    if action in site:
        thresholds = site[action]
        layer = "site_yaml"

    if override is not None and override.thresholds is not None:
        thresholds = override.thresholds
        layer = "tenant"

    # Tenant opt-out beats every threshold: disabling an action means it does
    # not run at all, not that it needs more confidence.
    if override is not None and not override.enabled:
        return GateDecision(
            action=action,
            decision=AutonomyDecision.REJECT,
            allowed=False,
            approval_required=True,
            autonomy_level="L0",
            layer="tenant_opt_out",
            thresholds=thresholds,
            reason="action is disabled for this tenant (TenantActionOptIn.enabled = false)",
            definition=definition,
        )

    # A NaN/inf confidence is a broken caller, not a confident one. Clamping
    # NaN naively is unsafe (``min(1.0, nan)`` returns 1.0), which would grant
    # autonomy to an action whose confidence could not be computed.
    raw_confidence = float(confidence)
    if not math.isfinite(raw_confidence):
        raw_confidence = 0.0
    confidence_value = max(0.0, min(1.0, raw_confidence))
    decision = thresholds.decide(confidence_value)

    approval_required = decision is not AutonomyDecision.AUTO
    if definition.always_requires_approval:
        # Critical blast radius: an autonomous verdict is demoted to review,
        # because no confidence score buys an unreviewed irreversible action.
        approval_required = True
        if decision is AutonomyDecision.AUTO:
            decision = AutonomyDecision.REVIEW

    level = autonomy_level_for(definition, decision)
    if override is not None:
        level = cap_autonomy_level(level, override.autonomy_level)

    return GateDecision(
        action=action,
        decision=decision,
        allowed=decision is AutonomyDecision.AUTO,
        approval_required=approval_required,
        autonomy_level=level,
        layer=layer,
        thresholds=thresholds,
        reason=_reason_for(definition, decision, confidence_value, layer),
        definition=definition,
    )


def _reason_for(
    definition: ActionDefinition,
    decision: AutonomyDecision,
    confidence: float,
    layer: str,
) -> str:
    """One-line, human-readable justification stored with the ledger row."""
    if definition.always_requires_approval:
        return (
            f"{definition.name} has {definition.blast_radius.value} blast radius "
            "and always requires approval"
        )
    return (
        f"confidence {confidence:.2f} → {decision.value} "
        f"(auto≥{definition.thresholds.auto:.2f}); policy layer: {layer}"
    )


async def evaluate(
    db: AsyncSession | None,
    *,
    action: str,
    tenant_id: uuid.UUID | str | None = None,
    confidence: float,
    site_policy: Mapping[str, ActionThresholds] | None = None,
) -> GateDecision:
    """Resolve the effective policy for ``action`` and decide.

    ``db``/``tenant_id`` are optional so call sites with no tenant session (and
    unit tests) still get a correct answer from the defaults + site layers.
    """
    override = await fetch_tenant_override(db, tenant_id, action)
    return decide(action, confidence, override=override, site_policy=site_policy)
