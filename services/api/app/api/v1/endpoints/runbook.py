"""Runbook governed action ledger and lightweight automation rules.

Routes
------
GET  /runbook/{subject_type}/{subject_id}      — ledger for one subject
POST /runbook/alerts/{alert_id}/enrich-payload — build/refresh llm_payload
GET  /runbook/automation-rules                 — list rules for tenant
POST /runbook/automation-rules                 — create a rule
GET  /runbook/automation-rules/{id}            — get one rule
PATCH /runbook/automation-rules/{id}           — update a rule
DELETE /runbook/automation-rules/{id}          — delete a rule
POST /runbook/automation-rules/preview         — preview an unsaved rule on recent alerts
POST /runbook/automation-rules/{id}/test       — preview a saved rule on alerts
GET  /runbook/tasks                            — list pending/completed manual tasks
GET  /runbook/tasks/{id}                       — get one task
POST /runbook/tasks/{id}/complete              — mark task completed and save analyst's findings
GET  /runbook/stats                            — analyst-feedback funnel for the tenant
GET  /runbook/detections                       — how recent alerts were produced (Detect & Fuse)

All endpoints use standard session-cookie auth via CurrentUser.
Tenant isolation: WHERE tenant_id = :tid on every query.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.logging import safe_log_value
from app.models.alert import Alert
from app.models.runbook_task import RunbookTask
from app.services.agents_client import list_playbooks, post_outcome_feedback, resume_playbook_run
from app.services.runbook.action_catalog import ACTIONS, required_connectors
from app.services.runbook.condition_eval import evaluate_all, validate_conditions
from app.services.runbook.detections import (
    DetectionActivityOut,
    item_from_alert,
    summarize,
)
from app.services.runbook.gate import decide
from app.services.runbook.packs import get_pack, list_packs, pack_rule_payloads
from app.services.runbook.read import load_runbook
from app.services.runbook.rule_executor import (
    _gate_to_status,
    alert_subject_fields,
    apply_rule_autonomy_ceiling,
    normalize_confidence,
)
from app.services.splunk_enrichment import enrich_alert_llm_payload

try:
    from sqlalchemy import select, text
except ImportError:  # pragma: no cover
    pass

_MAX_TAG = 60

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/runbook", tags=["runbook"])

VALID_SUBJECT_TYPES = ("alert", "case", "incident")
VALID_TRIGGER_TYPES = ("alert.created", "alert.updated", "case.created", "manual")
VALID_AUTONOMY_LEVELS = ("L0", "L1", "L2", "L3", "L4")

_ACTION_SLUG_ALIASES: dict[str, str] = {
    "alert.close": "close_alert",
    "alert.tag": "add_alert_tag",
    "alert.assign": "assign_case",
    "alert.create": "create_case",
    "case.create": "create_case",
    "case.assign": "assign_case",
    "tag.alert": "add_alert_tag",
    "close.alert": "close_alert",
    "create.case": "create_case",
    "assign.case": "assign_case",
    "close_alert": "close_alert",
    "add_alert_tag": "add_alert_tag",
    "create_case": "create_case",
    "assign_case": "assign_case",
    "add_case_comment": "add_case_comment",
}


def _normalize_action_slug(action_slug: str | None) -> str | None:
    if action_slug is None:
        return None
    key = (action_slug or "").strip()
    if not key:
        return key
    return _ACTION_SLUG_ALIASES.get(key, key)


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ConditionIn(BaseModel):
    field: str
    op: str
    value: Any = None


VALID_SUBJECT_TYPES_RULE = ("alert", "case", "incident", "all")


class AutomationRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    description: str | None = None
    trigger_type: str
    conditions: list[ConditionIn] = Field(default_factory=list)
    action_slug: str
    action_params: dict[str, Any] = Field(default_factory=dict)
    autonomy_level: str = "L2"
    dry_run: bool = True
    enabled: bool = True
    priority: int = Field(default=100, ge=1, le=9999)
    subject_type: str = "alert"
    playbook_ref: str | None = None
    docs_ref: str | None = None
    owner_team: str | None = None


class AutomationRulePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=256)
    description: str | None = None
    trigger_type: str | None = None
    conditions: list[ConditionIn] | None = None
    action_slug: str | None = None
    action_params: dict[str, Any] | None = None
    autonomy_level: str | None = None
    dry_run: bool | None = None
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=1, le=9999)
    subject_type: str | None = None
    playbook_ref: str | None = None
    docs_ref: str | None = None
    owner_team: str | None = None


class AutomationRuleOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    trigger_type: str
    conditions: list[dict]
    action_slug: str
    action_params: dict
    autonomy_level: str
    dry_run: bool
    enabled: bool
    priority: int
    trigger_count: int
    last_triggered_at: datetime | None
    created_at: datetime
    updated_at: datetime
    subject_type: str = "alert"
    playbook_ref: str | None = None
    docs_ref: str | None = None
    owner_team: str | None = None
    success_count: int = 0
    failed_count: int = 0
    denied_count: int = 0


class RulePreviewRequest(BaseModel):
    alert_ids: list[str] = Field(default_factory=list)


class RulePreviewResult(BaseModel):
    alert_id: str
    matched: bool
    status: str
    action_slug: str
    reason: str | None = None


class RulePreviewResponse(BaseModel):
    rule_id: uuid.UUID
    results: list[RulePreviewResult]


class RulePackRuleOut(BaseModel):
    """One rule inside a pack, with whether this tenant already has it.

    The whole list is returned (not just the count) so an operator can add rules
    one at a time instead of importing a pack wholesale, and can see the posture
    each rule will be installed with.
    """

    name: str
    trigger_type: str
    action_slug: str

    autonomy_level: str
    dry_run: bool

    priority: int

    installed: bool


class RulePackOut(BaseModel):
    """A pack of rules that can be imported into this tenant.

    ``rule_count`` is how many rules the import would try to create;
    ``covered_detections`` is how many upstream detection names they target.
    Neither is a coverage claim for the whole corpus.
    """

    id: str
    label: str
    description: str
    source: str
    rule_count: int
    covered_detections: int
    docs_ref: str | None = None

    #: Every rule in the pack, with whether this tenant already has it.
    rules: list[RulePackRuleOut] = Field(default_factory=list)


class RulePackImportRequest(BaseModel):
    """Which rules of the pack to install.

    ``rule_names`` empty (the default) means the whole pack. The UI sends an
    explicit list so an operator adds the rules they want instead of gaining a
    bundle they never read.
    """

    rule_names: list[str] = Field(default_factory=list)


class RulePackImportResult(BaseModel):
    """Outcome of an import. ``skipped`` already existed under the same name."""

    pack_id: str
    created: list[str] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
    #: Names sent by the caller that are not rules of this pack.
    unknown: list[str] = Field(default_factory=list)


class RuleDraftPreviewRequest(BaseModel):
    """An unsaved rule, as the editor currently holds it."""

    subject_type: str = "alert"
    conditions: list[ConditionIn] = Field(default_factory=list)
    action_slug: str
    autonomy_level: str = "L2"
    dry_run: bool = True
    limit: int = Field(default=20, ge=1, le=100)


class RuleDraftMatch(BaseModel):
    alert_id: str
    title: str
    severity: str
    confidence: int | None = None
    status: str
    action_slug: str
    reason: str | None = None
    condition_values: dict[str, Any] = Field(default_factory=dict)


class RuleDraftPreviewOut(BaseModel):
    """What this draft would do right now, before it is saved.

    ``evaluated_against`` is always ``alert``: the preview runs over recent alert
    rows. A draft scoped to cases has nothing to evaluate until cases are
    triggered, and the UI says so instead of showing a misleading zero.
    """

    evaluated: int = 0
    matched: int = 0
    action_slug: str
    evaluated_against: str = "alert"
    matches: list[RuleDraftMatch] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ── Runbook Task Schemas ──────────────────────────────────────────────────────

class RunbookTaskCreate(BaseModel):
    """Schema for creating a runbook task (internal only — not exposed to frontend create)."""
    task_type: str  # 'manual_review', 'approval_gate', 'mssp_sla_check'
    title: str
    description: str | None = None
    alert_id: uuid.UUID | None = None
    case_id: uuid.UUID | None = None
    assigned_to: uuid.UUID | None = None
    due_at: datetime | None = None
    feedback_to_llm: str | None = None
    created_by: str = "system"


class RunbookTaskOut(BaseModel):
    """Schema for returning a runbook task to the frontend."""
    id: uuid.UUID
    task_type: str
    title: str
    description: str | None
    alert_id: uuid.UUID | None
    case_id: uuid.UUID | None
    assigned_to: uuid.UUID | None
    status: str
    due_at: datetime | None
    completed_at: datetime | None
    resolution: str | None
    feedback_to_llm: str | None
    created_by: str
    created_at: datetime
    # Playbook gate fields (NULL/absent on every other task type).
    playbook_run_id: uuid.UUID | None = None
    resume_applied: bool | None = None


class RunbookTaskComplete(BaseModel):
    """Schema for completing a task."""
    resolution: str | None = None
    feedback_to_llm: str | None = None  # 'good' or 'poor'
    # Required for playbook gate tasks: the explicit decision, rather than
    # inferring it from the free-text resolution. Approving releases the steps
    # behind the gate; rejecting ends the run as cancelled.
    decision: Literal["approve", "reject"] | None = None


class RunbookFeedbackStats(BaseModel):
    """Analyst-feedback funnel for the tenant.

    ``priors_updated`` is the only field that proves the loop closed: it counts
    completions where outcome memory confirmed a prior change. Every completion
    that carried feedback but did not move a prior lands in
    ``feedback_unapplied`` — which also absorbs rows written before migration
    066, where the forward result was logged but never stored.
    """
    tasks_total: int = 0
    tasks_pending: int = 0
    tasks_completed: int = 0
    completions_with_feedback: int = 0
    priors_updated: int = 0
    feedback_unapplied: int = 0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_rule_input(data: AutomationRuleCreate | AutomationRulePatch) -> None:
    if data.trigger_type is not None and data.trigger_type not in VALID_TRIGGER_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"trigger_type must be one of {VALID_TRIGGER_TYPES}",
        )
    if data.autonomy_level is not None and data.autonomy_level not in VALID_AUTONOMY_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"autonomy_level must be one of {VALID_AUTONOMY_LEVELS}",
        )
    if hasattr(data, "subject_type") and data.subject_type is not None and data.subject_type not in VALID_SUBJECT_TYPES_RULE:
        raise HTTPException(
            status_code=400,
            detail=f"subject_type must be one of {VALID_SUBJECT_TYPES_RULE}",
        )
    if data.action_slug is not None:
        normalized = _normalize_action_slug(data.action_slug)
        if normalized not in ACTIONS:
            raise HTTPException(
                status_code=400,
                detail=f"action_slug {data.action_slug!r} is not in the action catalog",
            )
        data.action_slug = normalized
    if data.conditions is not None:
        cond_dicts = [c.model_dump() for c in data.conditions]
        errors = validate_conditions(cond_dicts)
        if errors:
            raise HTTPException(status_code=400, detail={"conditions_errors": errors})


# ── LLM Payload enrichment ────────────────────────────────────────────────────

@router.post(
    "/alerts/{alert_id}/enrich-payload",
    summary="Build or refresh the LLM payload for an alert",
)
async def enrich_alert_payload(
    alert_id: str,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    connector_id: str | None = Query(default=None, description="Specific Splunk connector UUID"),
    force: bool = Query(default=False, description="Re-build even if llm_payload already exists"),
) -> dict:
    """Fetch rule details from Splunk REST and build ``llm_payload``.

    Falls back to building the payload from the alert's stored fields when
    Splunk is unreachable or the alert is not from a Splunk connector.
    Records the enrichment in the Runbook ledger.
    """
    aid = _parse_uuid(alert_id, "alert_id")
    cid: uuid.UUID | None = None
    if connector_id:
        cid = _parse_uuid(connector_id, "connector_id")

    logger.info(
        "RUNBOOK-ENRICH alert=%s tenant=%s force=%s",
        safe_log_value(alert_id)[:_MAX_TAG],
        safe_log_value(str(current_user.tenant_id)),
        force,
    )

    result = await enrich_alert_llm_payload(
        db,
        alert_id=aid,
        tenant_id=current_user.tenant_id,
        connector_id=cid,
        force=force,
    )
    if result.get("status") == "error" and "alert_not_found" in (result.get("caveats") or []):
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


# ── Automation Rules CRUD ─────────────────────────────────────────────────────

_LIST_RULES = text(
    """
    SELECT id, name, description, trigger_type, conditions, action_slug,
           action_params, autonomy_level, dry_run, enabled, priority,
           trigger_count, last_triggered_at, created_at, updated_at,
           COALESCE(subject_type, 'alert') AS subject_type,
           playbook_ref, docs_ref, owner_team,
           COALESCE(success_count, 0) AS success_count,
           COALESCE(failed_count, 0) AS failed_count,
           COALESCE(denied_count, 0) AS denied_count
      FROM automation_rules
     WHERE tenant_id = :tid
     ORDER BY priority ASC, created_at DESC
     LIMIT 200
    """
)

_RULE_NAMES = text(
    """
    SELECT name FROM automation_rules WHERE tenant_id = :tid
    """
)

_GET_RULE = text(
    """
    SELECT id, name, description, trigger_type, conditions, action_slug,
           action_params, autonomy_level, dry_run, enabled, priority,
           trigger_count, last_triggered_at, created_at, updated_at,
           COALESCE(subject_type, 'alert') AS subject_type,
           playbook_ref, docs_ref, owner_team,
           COALESCE(success_count, 0) AS success_count,
           COALESCE(failed_count, 0) AS failed_count,
           COALESCE(denied_count, 0) AS denied_count
      FROM automation_rules
     WHERE tenant_id = :tid AND id = :rid
    """
)


def _row_to_rule(row: Any) -> AutomationRuleOut:
    return AutomationRuleOut(
        id=row.id,
        name=row.name,
        description=row.description,
        trigger_type=row.trigger_type,
        conditions=row.conditions or [],
        action_slug=row.action_slug,
        action_params=row.action_params or {},
        autonomy_level=row.autonomy_level,
        dry_run=row.dry_run,
        enabled=row.enabled,
        priority=row.priority,
        trigger_count=row.trigger_count,
        last_triggered_at=row.last_triggered_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        subject_type=getattr(row, "subject_type", None) or "alert",
        playbook_ref=getattr(row, "playbook_ref", None),
        docs_ref=getattr(row, "docs_ref", None),
        owner_team=getattr(row, "owner_team", None),
        success_count=int(getattr(row, "success_count", 0) or 0),
        failed_count=int(getattr(row, "failed_count", 0) or 0),
        denied_count=int(getattr(row, "denied_count", 0) or 0),
    )


def _build_alert_subject(alert: Alert) -> dict[str, Any]:
    """Preview subject — the *same* dict the live trigger path evaluates.

    Both now come from ``alert_subject_fields``; the preview previously built its
    own smaller dict, so a condition on ``disposition`` (or any MITRE field) read
    "not matched" in the test panel while the executor would have matched it.
    """
    subject = alert_subject_fields(alert)
    if subject.get("confidence") is None:
        subject["confidence"] = 50
    subject["id"] = str(alert.id)
    return subject


def _preview_rule_for_subjects(rule: dict[str, Any], subjects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    action_slug = _normalize_action_slug(rule.get("action_slug") or "") or (rule.get("action_slug") or "")
    results: list[dict[str, Any]] = []

    for subject in subjects:
        matched = evaluate_all(rule.get("conditions") or [], subject)
        status = "not_matched"
        reason = None
        if matched:
            # Alert confidence is an int 0–100; the gate's thresholds are
            # 0.0–1.0. Normalise before deciding or the preview promises an
            # autonomy the live executor will never grant.
            gate = decide(action_slug, normalize_confidence(subject.get("confidence")))
            # The rule's own ceiling is part of the live decision, so it is part
            # of the preview too.
            gate = apply_rule_autonomy_ceiling(gate, rule.get("autonomy_level"))
            status = _gate_to_status(gate, bool(rule.get("dry_run", True)))
            reason = gate.reason

        results.append(
            {
                "alert_id": str(subject.get("id") or ""),
                "matched": matched,
                "status": status,
                "action_slug": action_slug,
                "reason": reason,
            }
        )

    return results


def _action_available(action_name: str, active_connectors: set[str]) -> bool:
    """Whether an action's connector dependency is satisfied.

    An action is available when it needs no connector, or when *any* of its
    required connector types is enabled for the tenant (``("firewall", "edr")``
    means either one can execute the action).
    """
    req = required_connectors(action_name)
    if not req:
        return True
    return any(ct in active_connectors for ct in req)


async def _disabled_actions(db: DBSession, tenant_id: uuid.UUID) -> set[str]:
    """Action names the tenant has switched off.

    Read here as well as in ``/autonomy-policy`` so the governance page renders
    the stored state instead of assuming everything is on. A missing table (an
    install that predates the toggle) means nothing is disabled.
    """
    try:
        result = await db.execute(
            text(
                """
                SELECT action_name
                FROM aisoc_autonomy_thresholds
                WHERE tenant_id = :tenant_id AND enabled = false
                """
            ),
            {"tenant_id": str(tenant_id)},
        )
        return set(result.scalars().all() or [])
    except Exception as exc:  # noqa: BLE001 - render the catalog even without the table
        logger.warning(
            "runbook.disabled_actions_lookup_failed tenant=%s error=%s",
            safe_log_value(str(tenant_id)).replace("\r", "").replace("\n", " ")[:120],
            safe_log_value(str(exc)).replace("\r", "").replace("\n", " ")[:300],
        )
        return set()


async def _enabled_connector_types(db: DBSession, tenant_id: uuid.UUID) -> set[str]:
    """Connector types enabled for the tenant, for action-availability checks.

    A failed lookup is treated as "no connectors": an action is never advertised
    as executable on the strength of a query that did not run.
    """
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
        return set(result.scalars().all() or [])
    except Exception as exc:  # noqa: BLE001 - availability must never 500 the page
        logger.warning(
            "runbook.connector_lookup_failed tenant=%s error=%s",
            safe_log_value(str(tenant_id)).replace("\r", "").replace("\n", " ")[:120],
            safe_log_value(str(exc)).replace("\r", "").replace("\n", " ")[:300],
        )
        return set()


@router.get("/actions", summary="Actions available in automation rules")
async def list_automation_actions(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
) -> list[dict[str, Any]]:
    """Return the action list for automation rule dropdowns.

    Each action includes: name, label, category, and available flag.
    available=false means required connectors are not configured.
    For the full governance details (blast radius, contracts, thresholds),
    use GET /governance instead.
    """
    active_connectors = await _enabled_connector_types(db, current_user.tenant_id)

    return [
        {
            "name": defn.name,
            "label": defn.label,
            "category": defn.category.value,
            "available": _action_available(defn.name, active_connectors),
        }
        for defn in ACTIONS.values()
    ]


@router.get("/playbooks", summary="Playbooks available for rule linking")
async def list_available_playbooks(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
) -> list[dict[str, Any]]:
    """Return the list of available playbooks for the automation rules dropdown.

    Each playbook includes: id, name, and description.
    Returns an empty list if the agents service is unreachable.
    """
    playbooks = await list_playbooks(tenant_id=str(current_user.tenant_id))
    return playbooks


@router.get("/governance", summary="Governed action catalog")
async def get_governance_catalog(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
) -> list[dict]:
    """Return the full governed action catalog — labels, blast radii, and all four contracts.

    ``available`` and ``required_connectors`` are computed per tenant from the
    enabled connectors. The console needs them: without a server-side answer an
    action that depends on Splunk looked configurable (and was toggleable) in a
    workspace that had never connected Splunk.
    """
    active_connectors = await _enabled_connector_types(db, current_user.tenant_id)
    disabled_actions = await _disabled_actions(db, current_user.tenant_id)

    return [
        {
            "name": defn.name,
            "label": defn.label,
            "category": defn.category.value,
            "blast_radius": defn.blast_radius.value,
            "always_requires_approval": defn.always_requires_approval,
            "dry_run_default": defn.dry_run_default,
            "required_connectors": list(required_connectors(defn.name)),
            "available": _action_available(defn.name, active_connectors),
            "enabled": defn.name not in disabled_actions,
            "is_system_core": True,
            "thresholds": defn.thresholds.to_dict(),
            "audit": {
                "record_ledger": defn.audit.record_ledger,
                "audit_log": defn.audit.audit_log,
                "include_input": defn.audit.include_input,
                "include_output": defn.audit.include_output,
            },
            "data_safety": {
                "allowed_fields": list(defn.data_safety.allowed_fields),
                "max_payload_bytes": defn.data_safety.max_payload_bytes,
                "allow_pii": defn.data_safety.allow_pii,
            },
            "failure": {
                "max_attempts": defn.failure.max_attempts,
                "backoff_seconds": defn.failure.backoff_seconds,
                "timeout_seconds": defn.failure.timeout_seconds,
                "on_failure": defn.failure.on_failure,
            },
            "cost": {
                "max_usd_per_run": defn.cost.max_usd_per_run,
                "max_tokens": defn.cost.max_tokens,
                "max_wall_ms": defn.cost.max_wall_ms,
            },
        }
        for defn in ACTIONS.values()
    ]


@router.get("/automation-rules", summary="List automation rules")
async def list_automation_rules(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
) -> list[AutomationRuleOut]:
    """Rules this tenant has created or imported. Nothing is seeded here.

    This endpoint used to insert a default rule set the first time it was
    called, which meant a tenant gained automations (some of them executing)
    just by opening the page. The defaults now live in the ``core-defaults``
    pack and are imported rule by rule via
    ``POST /runbook/automation-rules/packs/core-defaults/import``.
    """
    rows = (await db.execute(_LIST_RULES.bindparams(tid=current_user.tenant_id))).fetchall()
    return [_row_to_rule(r) for r in rows]


@router.post("/automation-rules", status_code=201, summary="Create automation rule")
async def create_automation_rule(
    body: AutomationRuleCreate,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
) -> AutomationRuleOut:
    body.action_slug = _normalize_action_slug(body.action_slug) or body.action_slug
    _validate_rule_input(body)
    cond_dicts = [c.model_dump() for c in body.conditions]
    row = (
        await db.execute(
            text(
                """
                INSERT INTO automation_rules
                  (tenant_id, name, description, trigger_type, conditions, action_slug,
                   action_params, autonomy_level, dry_run, enabled, priority, created_by,
                   subject_type, playbook_ref, docs_ref, owner_team)
                VALUES
                  (:tid, :name, :desc, :trigger, CAST(:conds AS jsonb), :slug,
                   CAST(:params AS jsonb), :level, :dry, :enabled, :prio, :creator,
                   :subject_type, :playbook_ref, :docs_ref, :owner_team)
                RETURNING id, name, description, trigger_type, conditions, action_slug,
                          action_params, autonomy_level, dry_run, enabled, priority,
                          trigger_count, last_triggered_at, created_at, updated_at,
                          COALESCE(subject_type, 'alert') AS subject_type,
                          playbook_ref, docs_ref, owner_team,
                          COALESCE(success_count, 0) AS success_count,
                          COALESCE(failed_count, 0) AS failed_count,
                          COALESCE(denied_count, 0) AS denied_count
                """
            ).bindparams(
                tid=current_user.tenant_id,
                name=body.name,
                desc=body.description,
                trigger=body.trigger_type,
                conds=_json_param(cond_dicts),
                slug=body.action_slug,
                params=_json_param(body.action_params),
                level=body.autonomy_level,
                dry=body.dry_run,
                enabled=body.enabled,
                prio=body.priority,
                creator=current_user.user_id,
                subject_type=body.subject_type or "alert",
                playbook_ref=body.playbook_ref,
                docs_ref=body.docs_ref,
                owner_team=body.owner_team,
            )
        )
    ).fetchone()
    await db.commit()
    return _row_to_rule(row)


@router.get("/automation-rules/packs", summary="List importable rule packs")
async def list_rule_packs(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
) -> list[RulePackOut]:
    """Packs shipped with the platform, every rule listed individually.

    Each rule carries the posture it would be installed with and whether this
    tenant already has it, so the console can offer per-rule selection instead of
    an all-or-nothing import. This is a read: nothing is written for a tenant
    that has never opened the dialog.

    Declared before ``/automation-rules/{rule_id}`` on purpose: FastAPI matches
    routes in registration order, so a later declaration would make "packs" be
    parsed as a rule id.
    """
    installed = {
        row[0]
        for row in (
            await db.execute(_RULE_NAMES.bindparams(tid=current_user.tenant_id))
        ).fetchall()
    }

    out: list[RulePackOut] = []
    for pack in list_packs():
        out.append(
            RulePackOut(
                id=pack.id,
                label=pack.label,
                description=pack.description,
                source=pack.source,
                rule_count=len(pack.rules),
                covered_detections=len(pack.covered_detections),
                # No docs link: the console page is one click away in the app and
                # the anchor these rules pointed at never existed.
                docs_ref=None,
                rules=[
                    RulePackRuleOut(
                        name=payload["name"],
                        trigger_type=payload.get("trigger_type") or "alert.created",
                        action_slug=_normalize_action_slug(payload.get("action_slug") or "")
                        or (payload.get("action_slug") or ""),
                        autonomy_level=payload.get("autonomy_level") or "L2",
                        dry_run=bool(payload.get("dry_run", True)),
                        priority=int(payload.get("priority") or 200),
                        installed=payload["name"] in installed,
                    )
                    for payload in pack_rule_payloads(pack)
                ],
            )
        )
    return out


@router.post(
    "/automation-rules/packs/{pack_id}/import",
    status_code=201,
    summary="Import a rule pack",
)
async def import_rule_pack(
    pack_id: str,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    body: RulePackImportRequest | None = None,
) -> RulePackImportResult:
    """Install some or all of a pack's rules, skipping names that already exist.

    Import is explicit rather than seeded for everyone: the vendor-neutral rules
    apply to any telemetry but should still be chosen, and the Windows rules
    match named Splunk detections, so a tenant without that telemetry would only
    gain rules that can never fire. Idempotent by rule name, so re-running after
    a pack update adds only the rules that are missing.

    ``body.rule_names`` selects a subset; empty installs the whole pack.
    """
    pack = get_pack(pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail=f"Unknown rule pack {pack_id!r}")

    existing = {
        row[0]
        for row in (
            await db.execute(_RULE_NAMES.bindparams(tid=current_user.tenant_id))
        ).fetchall()
    }

    result = RulePackImportResult(pack_id=pack.id)

    payloads = pack_rule_payloads(pack)
    selected = {n.strip() for n in (body.rule_names if body else []) if n and n.strip()}
    if selected:
        known = {payload["name"] for payload in payloads}
        result.unknown = sorted(selected - known)
        payloads = [payload for payload in payloads if payload["name"] in selected]

    for payload in payloads:
        if payload["name"] in existing:
            result.skipped.append(payload["name"])
            continue

        # A malformed condition would silently never match, so refuse the
        # import loudly instead of installing an inert rule.
        errors = validate_conditions(payload["conditions"])
        if errors:
            raise HTTPException(
                status_code=500,
                detail=f"rule pack {pack.id!r} rule {payload['name']!r} is invalid: {errors}",
            )

        await db.execute(
            text(
                """
                INSERT INTO automation_rules
                  (tenant_id, name, description, trigger_type, conditions, action_slug,
                   action_params, autonomy_level, dry_run, enabled, priority, created_by,
                   subject_type, playbook_ref, docs_ref, owner_team)
                VALUES
                  (:tid, :name, :desc, :trigger, CAST(:conds AS jsonb), :slug,
                   CAST(:params AS jsonb), :level, :dry, :enabled, :prio, :creator,
                   :subject_type, NULL, :docs_ref, :owner_team)
                """
            ).bindparams(
                tid=current_user.tenant_id,
                name=payload["name"],
                desc=payload["description"],
                trigger=payload["trigger_type"],
                conds=_json_param(payload["conditions"]),
                slug=_normalize_action_slug(payload["action_slug"]) or payload["action_slug"],
                params=_json_param(payload["action_params"]),
                level=payload["autonomy_level"],
                dry=bool(payload["dry_run"]),
                enabled=bool(payload["enabled"]),
                prio=int(payload["priority"]),
                creator=current_user.user_id,
                subject_type=payload.get("subject_type") or "alert",
                docs_ref=payload.get("docs_ref"),
                owner_team=payload.get("owner_team"),
            )
        )
        result.created.append(payload["name"])

    await db.commit()
    return result


@router.get("/automation-rules/{rule_id}", summary="Get one automation rule")
async def get_automation_rule(
    rule_id: str,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
) -> AutomationRuleOut:
    rid = _parse_uuid(rule_id, "rule_id")
    row = (await db.execute(_GET_RULE.bindparams(tid=current_user.tenant_id, rid=rid))).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return _row_to_rule(row)


@router.patch("/automation-rules/{rule_id}", summary="Update automation rule")
async def patch_automation_rule(
    rule_id: str,
    body: AutomationRulePatch,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
) -> AutomationRuleOut:
    rid = _parse_uuid(rule_id, "rule_id")
    if body.action_slug is not None:
        body.action_slug = _normalize_action_slug(body.action_slug) or body.action_slug
    _validate_rule_input(body)

    existing = (await db.execute(_GET_RULE.bindparams(tid=current_user.tenant_id, rid=rid))).fetchone()
    if existing is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    sets: list[str] = ["updated_at = now()"]
    params: dict[str, Any] = {"tid": current_user.tenant_id, "rid": rid}

    for field, col in [
        ("name", "name"),
        ("description", "description"),
        ("trigger_type", "trigger_type"),
        ("action_slug", "action_slug"),
        ("autonomy_level", "autonomy_level"),
        ("dry_run", "dry_run"),
        ("enabled", "enabled"),
        ("priority", "priority"),
        ("subject_type", "subject_type"),
        ("playbook_ref", "playbook_ref"),
        ("docs_ref", "docs_ref"),
        ("owner_team", "owner_team"),
    ]:
        val = getattr(body, field, None)
        if val is not None:
            sets.append(f"{col} = :{field}")
            params[field] = val

    if body.conditions is not None:
        sets.append("conditions = CAST(:conditions AS jsonb)")
        params["conditions"] = _json_param([c.model_dump() for c in body.conditions])
    if body.action_params is not None:
        sets.append("action_params = CAST(:action_params AS jsonb)")
        params["action_params"] = _json_param(body.action_params)

    row = (
        await db.execute(
            text(
                f"""
                UPDATE automation_rules SET {", ".join(sets)}
                 WHERE tenant_id = :tid AND id = :rid
                RETURNING id, name, description, trigger_type, conditions, action_slug,
                          action_params, autonomy_level, dry_run, enabled, priority,
                          trigger_count, last_triggered_at, created_at, updated_at,
                          COALESCE(subject_type, 'alert') AS subject_type,
                          playbook_ref, docs_ref, owner_team,
                          COALESCE(success_count, 0) AS success_count,
                          COALESCE(failed_count, 0) AS failed_count,
                          COALESCE(denied_count, 0) AS denied_count
                """
            ).bindparams(**params)
        )
    ).fetchone()
    await db.commit()
    return _row_to_rule(row)


@router.delete("/automation-rules/{rule_id}", status_code=204, summary="Delete automation rule")
async def delete_automation_rule(
    rule_id: str,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
) -> None:
    rid = _parse_uuid(rule_id, "rule_id")
    result = await db.execute(
        text("DELETE FROM automation_rules WHERE tenant_id = :tid AND id = :rid").bindparams(
            tid=current_user.tenant_id, rid=rid
        )
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Rule not found")


@router.post(
    "/automation-rules/preview",
    response_model=RuleDraftPreviewOut,
    summary="Preview an unsaved rule against recent alerts",
)
async def preview_automation_rule_draft(
    body: RuleDraftPreviewRequest,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
) -> RuleDraftPreviewOut:
    """Evaluate a draft rule against the tenant's most recent alerts.

    Authoring used to require saving the rule and then pressing Test in the list
    to find out what it matched. This answers the same question before the rule
    exists, using the same evaluator and the same gate the executor uses —
    including the draft's autonomy ceiling.
    """
    action_slug = _normalize_action_slug(body.action_slug) or body.action_slug
    conditions = [condition.model_dump() for condition in body.conditions]
    errors = validate_conditions(conditions)
    if errors:
        return RuleDraftPreviewOut(
            action_slug=action_slug,
            evaluated=0,
            matched=0,
            errors=errors,
        )

    alert_rows = (
        await db.execute(
            select(Alert)
            .where(Alert.tenant_id == current_user.tenant_id)
            .order_by(Alert.created_at.desc())
            .limit(body.limit)
        )
    ).scalars().all()

    subjects = [_build_alert_subject(alert) for alert in alert_rows]
    rule_dict = {
        "conditions": conditions,
        "action_slug": action_slug,
        "autonomy_level": body.autonomy_level,
        "dry_run": body.dry_run,
    }
    results = _preview_rule_for_subjects(rule_dict, subjects)

    matched_results = [result for result in results if result["matched"]]
    by_id = {str(alert.id): alert for alert in alert_rows}
    subject_by_id = {str(alert.id): _build_alert_subject(alert) for alert in alert_rows}
    matches: list[RuleDraftMatch] = []
    for result in matched_results[:10]:
        alert = by_id.get(result["alert_id"])
        subject = subject_by_id.get(result["alert_id"], {})
        condition_values: dict[str, Any] = {}
        for condition in conditions:
            field = condition.get("field")
            if not field:
                continue
            value = subject.get(field)
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value if v is not None)
            elif isinstance(value, dict):
                value = json.dumps(value, sort_keys=True)
            elif value is None:
                value = "—"
            condition_values[field] = value
        matches.append(
            RuleDraftMatch(
                alert_id=result["alert_id"],
                title=str(getattr(alert, "title", "") or ""),
                severity=str(getattr(alert, "severity", "") or ""),
                confidence=getattr(alert, "confidence", None),
                status=result["status"],
                action_slug=result["action_slug"],
                reason=result.get("reason"),
                condition_values=condition_values,
            )
        )

    return RuleDraftPreviewOut(
        evaluated=len(results),
        matched=len(matched_results),
        action_slug=action_slug,
        matches=matches,
    )


@router.post(
    "/automation-rules/{rule_id}/test",
    response_model=RulePreviewResponse,
    summary="Preview a rule against selected existing alerts",
)
async def preview_automation_rule_on_alerts(
    rule_id: str,
    body: RulePreviewRequest,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
) -> RulePreviewResponse:
    rid = _parse_uuid(rule_id, "rule_id")
    row = (await db.execute(_GET_RULE.bindparams(tid=current_user.tenant_id, rid=rid))).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    if body.alert_ids:
        parsed_ids = []
        for alert_id in body.alert_ids:
            try:
                parsed_ids.append(uuid.UUID(alert_id))
            except ValueError:
                raise HTTPException(status_code=422, detail="Each alert_id must be a valid UUID") from None
        alert_rows = (
            await db.execute(
                select(Alert)
                .where(Alert.tenant_id == current_user.tenant_id, Alert.id.in_(parsed_ids))
                .order_by(Alert.created_at.desc())
            )
        ).scalars().all()
    else:
        alert_rows = (
            await db.execute(
                select(Alert)
                .where(Alert.tenant_id == current_user.tenant_id)
                .order_by(Alert.created_at.desc())
                .limit(20)
            )
        ).scalars().all()

    rule_dict = {
        "name": row.name,
        "description": row.description,
        "trigger_type": row.trigger_type,
        "conditions": row.conditions or [],
        "action_slug": row.action_slug,
        "action_params": row.action_params or {},
        "autonomy_level": row.autonomy_level,
        "dry_run": row.dry_run,
        "enabled": row.enabled,
        "priority": row.priority,
    }

    results = _preview_rule_for_subjects(
        rule_dict,
        [_build_alert_subject(alert) for alert in alert_rows],
    )
    return RulePreviewResponse(
        rule_id=rid,
        results=[RulePreviewResult(**result) for result in results],
    )


# ── Utilities ─────────────────────────────────────────────────────────────────

def _parse_uuid(value: str, param: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"{param} must be a valid UUID") from None


def _json_param(value: Any) -> str:
    """Serialize JSON values to text before casting to PostgreSQL jsonb."""
    import json
    return json.dumps(value)


# ── Runbook Tasks (Exception Handling & Manual Workflow) ──────────────────────
#
# Task *creation* lives in the writer that owns each path:
#   * ``manual_review`` — services/agents ``ledger.create_task_for_needs_review``
#     (the triage worker is the only thing that knows the verdict + confidence).
#   * ``approval_gate``  — services/runbook/tasks.ensure_approval_gate_task,
#     called from the rule executor when the gate blocks an action.
# This module only reads and completes them, so there is exactly one writer per
# task type.

@router.get(
    "/detections",
    summary="Detect & Fuse activity: how the recent alerts were actually produced",
)
async def runbook_detection_activity(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    limit: int = Query(50, ge=1, le=200),
) -> DetectionActivityOut:
    """Return the most recent alerts with the evidence of how they were produced.

    Workflow SOC stage 02 is the only lifecycle stage whose claim ("rules promote
    noise into high-signal alerts") had no live surface to open. This reads the
    `alerts` rows the fusion spine already wrote — rule lineage, connector, dedup
    count, and fusion state — so the stage can link somewhere real.
    """
    rows = (
        await db.execute(
            select(Alert)
            .where(Alert.tenant_id == current_user.tenant_id)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()

    items = [item_from_alert(row) for row in rows]
    return DetectionActivityOut(summary=summarize(items), items=items)


@router.get("/stats", summary="Analyst feedback funnel: how many completions actually moved a prior")
async def runbook_feedback_stats(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
) -> RunbookFeedbackStats:
    """Count what analyst feedback actually did.

    Submitting feedback and updating a prior are different events: the forward to
    outcome memory can find no prior for the evidence signature, or the agents
    service may not be wired up at all. Without this the loop's effect is an
    assumption; with it the Runbook can state the ratio out loud.
    """
    result = await db.execute(
        text(
            """
            SELECT
                COUNT(*)                                                          AS tasks_total,
                COUNT(*) FILTER (WHERE status <> 'completed')                      AS tasks_pending,
                COUNT(*) FILTER (WHERE status = 'completed')                       AS tasks_completed,
                COUNT(*) FILTER (WHERE feedback_to_llm IS NOT NULL)                AS completions_with_feedback,
                COUNT(*) FILTER (WHERE feedback_applied IS TRUE)                   AS priors_updated,
                COUNT(*) FILTER (WHERE feedback_to_llm IS NOT NULL
                                   AND feedback_applied IS NOT TRUE)               AS feedback_unapplied
            FROM runbook_tasks
            WHERE tenant_id = :tenant_id
            """
        ).bindparams(tenant_id=current_user.tenant_id)
    )
    row = result.mappings().one()

    return RunbookFeedbackStats(
        tasks_total=int(row["tasks_total"] or 0),
        tasks_pending=int(row["tasks_pending"] or 0),
        tasks_completed=int(row["tasks_completed"] or 0),
        completions_with_feedback=int(row["completions_with_feedback"] or 0),
        priors_updated=int(row["priors_updated"] or 0),
        feedback_unapplied=int(row["feedback_unapplied"] or 0),
    )


@router.get("/tasks", summary="List pending/completed manual tasks")
async def list_runbook_tasks(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    status: str = Query(None, description="Filter by status: pending, in_progress, completed"),
    task_type: str = Query(None, description="Filter by task type"),
    alert_id: str = Query(None, description="Only tasks raised for this alert"),
    case_id: str = Query(None, description="Only tasks raised for this case"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> list[RunbookTaskOut]:
    """List manual runbook tasks for the tenant, optionally scoped to a subject.

    The Action Plan tab sits inside a per-subject Runbook, so it must be able to
    ask for that subject's tasks. Without these filters the tab silently showed
    every task in the tenant.
    """
    q = select(RunbookTask).where(RunbookTask.tenant_id == current_user.tenant_id)

    if status:
        q = q.where(RunbookTask.status == status)
    if task_type:
        q = q.where(RunbookTask.task_type == task_type)
    if alert_id:
        q = q.where(RunbookTask.alert_id == _parse_uuid(alert_id, "alert_id"))
    if case_id:
        q = q.where(RunbookTask.case_id == _parse_uuid(case_id, "case_id"))

    rows = (await db.execute(
        q.order_by(RunbookTask.created_at.desc()).offset(skip).limit(limit)
    )).scalars().all()

    return [
        RunbookTaskOut(
            id=r.id,
            task_type=r.task_type,
            title=r.title,
            description=r.description,
            alert_id=r.alert_id,
            case_id=r.case_id,
            assigned_to=r.assigned_to,
            status=r.status,
            due_at=r.due_at,
            completed_at=r.completed_at,
            resolution=r.resolution,
            feedback_to_llm=r.feedback_to_llm,
            created_by=r.created_by,
            created_at=r.created_at,
            playbook_run_id=r.playbook_run_id,
            resume_applied=r.resume_applied,
        )
        for r in rows
    ]


@router.get("/tasks/{task_id}", summary="Get one runbook task")
async def get_runbook_task(
    task_id: str,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
) -> RunbookTaskOut:
    """Retrieve details of a single runbook task."""
    tid = _parse_uuid(task_id, "task_id")
    row = (await db.execute(
        select(RunbookTask).where(
            RunbookTask.id == tid,
            RunbookTask.tenant_id == current_user.tenant_id,
        )
    )).scalar_one_or_none()

    if not row:
        raise HTTPException(status_code=404, detail="Task not found")

    return RunbookTaskOut(
        id=row.id,
        task_type=row.task_type,
        title=row.title,
        description=row.description,
        alert_id=row.alert_id,
        case_id=row.case_id,
        assigned_to=row.assigned_to,
        status=row.status,
        due_at=row.due_at,
        completed_at=row.completed_at,
        resolution=row.resolution,
        feedback_to_llm=row.feedback_to_llm,
        created_by=row.created_by,
        created_at=row.created_at,
        playbook_run_id=row.playbook_run_id,
        resume_applied=row.resume_applied,
    )


@router.post("/tasks/{task_id}/complete", summary="Mark task completed and save analyst findings")
async def complete_runbook_task(
    task_id: str,
    body: RunbookTaskComplete,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
) -> RunbookTaskOut:
    """Complete a manual task and capture analyst findings/feedback.

    This is where the analyst records:
      - resolution: What they found or decided (for audit trail)
      - feedback_to_llm: Was the AI's recommendation good or poor? ('good' or 'poor')

    The feedback is logged for the agents service to consume and update outcome priors.
    """
    tid = _parse_uuid(task_id, "task_id")
    row = (await db.execute(
        select(RunbookTask).where(
            RunbookTask.id == tid,
            RunbookTask.tenant_id == current_user.tenant_id,
        )
    )).scalar_one_or_none()

    if not row:
        raise HTTPException(status_code=404, detail="Task not found")

    if row.status == "completed":
        raise HTTPException(status_code=400, detail="Task is already completed")

    # Playbook gate task: approving releases the steps the gate guards, so it
    # needs its own permission — a tier-1 analyst who may execute playbooks must
    # not be able to clear the very gate that asks for a second pair of eyes.
    # Governance approval gates (no playbook run behind them) keep their existing
    # rules; their contract lives in the action catalog, not here.
    resume_applied: bool | None = None
    if row.playbook_run_id is not None:
        await current_user.require_permission_db("playbooks:approve", db)
        if body.decision is None:
            raise HTTPException(
                status_code=422,
                detail="decision is required for playbook approval-gate tasks (approve|reject)",
            )
        resume_applied = await resume_playbook_run(
            tenant_id=str(current_user.tenant_id),
            run_id=str(row.playbook_run_id),
            decision=body.decision,
            actor=str(current_user.email or current_user.user_id),
        )
        logger.info(
            "runbook_task_playbook_resume",
            task_id=str(tid),
            playbook_run_id=str(row.playbook_run_id),
            decision=body.decision,
            tenant_id=str(current_user.tenant_id),
            analyst_id=str(current_user.user_id),
            resumed=resume_applied,
        )

    # Forward the feedback to the service that owns outcome memory *before* the
    # completion is written, so the row can record what the forward actually did.
    # `applied` is what makes the feedback loop measurable rather than assumed:
    # True only when the agents service confirmed a prior was updated.
    applied: bool | None = None
    if body.feedback_to_llm:
        applied = False
        if row.signature:
            applied = await post_outcome_feedback(
                tenant_id=str(current_user.tenant_id),
                signature=row.signature,
                feedback=body.feedback_to_llm,
                alert_id=str(row.alert_id) if row.alert_id else None,
            )
        logger.info(
            "runbook_task_feedback",
            task_id=str(tid),
            alert_id=str(row.alert_id) if row.alert_id else None,
            task_type=row.task_type,
            feedback=body.feedback_to_llm,
            tenant_id=str(current_user.tenant_id),
            analyst_id=str(current_user.user_id),
            has_signature=bool(row.signature),
            forwarded=applied,
        )

    # Update task
    await db.execute(
        text(
            """
            UPDATE runbook_tasks
            SET status = 'completed', completed_at = NOW(), completed_by = :user_id,
                resolution = :resolution, feedback_to_llm = :feedback,
                feedback_applied = :applied, resume_applied = :resume_applied
            WHERE id = :task_id AND tenant_id = :tenant_id
            """
        ).bindparams(
            task_id=tid,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            resolution=body.resolution,
            feedback=body.feedback_to_llm,
            applied=applied,
            resume_applied=resume_applied,
        )
    )
    await db.commit()

    # Return updated row
    row = (await db.execute(
        select(RunbookTask).where(RunbookTask.id == tid)
    )).scalar_one()

    return RunbookTaskOut(
        id=row.id,
        task_type=row.task_type,
        title=row.title,
        description=row.description,
        alert_id=row.alert_id,
        case_id=row.case_id,
        assigned_to=row.assigned_to,
        status=row.status,
        due_at=row.due_at,
        completed_at=row.completed_at,
        resolution=row.resolution,
        feedback_to_llm=row.feedback_to_llm,
        created_by=row.created_by,
        created_at=row.created_at,
        playbook_run_id=row.playbook_run_id,
        resume_applied=row.resume_applied,
    )


# ── Ledger read ───────────────────────────────────────────────────────────────
#
# Registered LAST on purpose. This is a two-segment catch-all, and FastAPI
# matches routes in declaration order: declared earlier it swallowed
# ``GET /runbook/tasks/{id}`` and ``GET /runbook/automation-rules/{id}``, which
# then answered 400 ("subject_type must be one of …") instead of the resource.
# Any new two-segment GET route must be declared above this one.

@router.get(
    "/{subject_type}/{subject_id}",
    summary="Runbook ledger for a subject",
)
async def get_runbook(
    subject_type: str,
    subject_id: str,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
) -> dict:
    if subject_type not in VALID_SUBJECT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"subject_type must be one of {VALID_SUBJECT_TYPES}",
        )
    try:
        sid = uuid.UUID(subject_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="subject_id must be a valid UUID") from None

    logger.debug(
        "RUNBOOK-READ tenant=%s type=%s id=%s",
        safe_log_value(str(current_user.tenant_id)),
        subject_type,
        safe_log_value(subject_id)[:_MAX_TAG],
    )
    try:
        envelope = await load_runbook(
            db, tenant_id=current_user.tenant_id, subject_type=subject_type, subject_id=sid
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return envelope.model_dump(mode="json")
