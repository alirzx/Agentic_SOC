"""Apply automation rules to a subject.

When an alert is created or updated, callers pass the subject's field dict to
:func:`run_rules_for_trigger`. This module:

1. Fetches enabled rules for the tenant that match the trigger type.
2. Evaluates each rule's conditions against the subject dict.
3. Passes matching rules through the governance gate.
4. Starts the rule's linked playbook when governance allows the action
   (``playbook_ref``), recording the run id in the ledger.
5. Records the outcome (allowed / denied / simulated) in ``runbook_events``.

Execution posture
-----------------
Default ``dry_run=true`` on every rule. A rule's outcome is ``"simulated"``
unless the tenant has explicitly set ``dry_run=false`` on that rule **and**
real vendor credentials exist. This mirrors the platform-wide copilot posture.

Error handling
--------------
Every error is swallowed. Rule execution is bookkeeping; a DB error or a
misconfigured rule must never prevent the underlying alert from being saved.

Linked playbooks
----------------
A rule may name a playbook (``playbook_ref``). The playbook runs only when the
gate has allowed the rule's own action — starting it while the policy waits for
an analyst would execute the very thing the gate stopped. Starts are at-most-once
per (rule, playbook, subject): the ledger's ``idempotency_key`` is the
authoritative claim and the same key is handed to the agents service as a
``dedupe_key``, which closes the window between the two.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import runbook_enabled
from app.services.agents_client import start_playbook_run
from app.services.runbook.condition_eval import evaluate_all
from app.services.runbook.gate import GateDecision, cap_autonomy_level, evaluate
from app.services.runbook.recorder import record_event
from app.services.runbook.tasks import ensure_approval_gate_task
from app.services.runbook.thresholds import AutonomyDecision

logger = structlog.get_logger()

_FETCH_RULES = text(
    """
    SELECT id, name, action_slug, action_params, conditions,
           autonomy_level, dry_run, priority, playbook_ref
      FROM automation_rules
     WHERE tenant_id = :tid
       AND enabled = true
       AND trigger_type = :trigger
       -- subject_type is enforced here, not just displayed in the editor: a
       -- case-scoped rule must not fire on alert events. NULL/'all' predate the
       -- column and stay catch-all.
       AND (subject_type IS NULL OR subject_type = 'all' OR subject_type = :subject_type)
     ORDER BY priority ASC, created_at ASC
     LIMIT 50
    """
)


def alert_subject_fields(alert: Any) -> dict[str, Any]:
    """The exact field dict automation rules evaluate against for an alert.

    Single source of truth: the live trigger path and the rule-test/preview
    endpoints must agree, or a preview promises a match the executor will never
    make. Fields that the ``Alert`` model does not carry are ``None`` (and so
    fail closed) rather than absent — a condition on a missing key and a
    condition on a null value read the same to the evaluator, but only the
    second one can be explained in the UI.
    """
    return {
        "severity": getattr(alert, "severity", None),
        "status": getattr(alert, "status", None),
        "priority": getattr(alert, "priority", None),
        "confidence": getattr(alert, "confidence", None),
        "confidence_label": getattr(alert, "confidence_label", None),
        "funnel_stage": getattr(alert, "funnel_stage", None),
        "disposition": getattr(alert, "disposition", None),
        "source": getattr(alert, "source", None) or getattr(alert, "connector_type", None) or "manual",
        "connector_type": getattr(alert, "connector_type", None),
        "category": getattr(alert, "category", None),
        "title": getattr(alert, "title", None),
        "description": getattr(alert, "description", None),
        "tags": getattr(alert, "tags", None) or [],
        "affected_ips": getattr(alert, "affected_ips", None) or [],
        "affected_hosts": getattr(alert, "affected_hosts", None) or [],
        "affected_users": getattr(alert, "affected_users", None) or [],
        "risk_score": getattr(alert, "risk_score", None),
        "mitre_tactics": getattr(alert, "mitre_tactics", None) or [],
        "mitre_techniques": getattr(alert, "mitre_techniques", None) or [],
        "rule_name": getattr(alert, "rule_name", None),
    }

_BUMP_TRIGGER = text(
    """
    UPDATE automation_rules
       SET trigger_count    = trigger_count + 1,
           last_triggered_at = now()
     WHERE id = :rid
    """
)


async def run_rules_for_trigger(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    trigger_type: str,
    subject_type: str,
    subject_id: uuid.UUID,
    subject_fields: dict[str, Any],
) -> None:
    """Evaluate all matching automation rules and record outcomes in the ledger.

    Never raises — every exception is logged and swallowed so the caller
    (alert create/update path) is unaffected.
    """
    if not runbook_enabled():
        return

    try:
        rows = (
            await db.execute(
                _FETCH_RULES.bindparams(
                    tid=tenant_id,
                    trigger=trigger_type,
                    subject_type=subject_type,
                )
            )
        ).fetchall()
    except Exception:  # noqa: BLE001
        logger.warning("automation.rule_fetch_failed", exc_info=True)
        return

    for row in rows:
        try:
            await _apply_rule(
                db,
                tenant_id=tenant_id,
                subject_type=subject_type,
                subject_id=subject_id,
                subject_fields=subject_fields,
                rule_id=row.id,
                rule_name=row.name,
                action_slug=row.action_slug,
                action_params=row.action_params or {},
                conditions=row.conditions or [],
                dry_run=bool(row.dry_run),
                rule_autonomy_level=getattr(row, "autonomy_level", None),
                playbook_ref=getattr(row, "playbook_ref", None),
                trigger_type=trigger_type,
            )
        except Exception:  # noqa: BLE001
            logger.warning(
                "automation.rule_apply_failed",
                rule_id=str(row.id).replace("\r", "").replace("\n", " "),
                exc_info=True,
            )


async def _apply_rule(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID,
    subject_fields: dict[str, Any],
    rule_id: uuid.UUID,
    rule_name: str,
    action_slug: str,
    action_params: dict[str, Any],
    conditions: list[dict[str, Any]],
    dry_run: bool,
    rule_autonomy_level: str | None = None,
    playbook_ref: str | None = None,
    trigger_type: str | None = None,
) -> None:
    if not evaluate_all(conditions, subject_fields):
        return  # conditions not met — no ledger row (not noteworthy)

    # Resolve the effective policy for this action + tenant.
    #
    # ``evaluate`` is the DB-aware entry point (tenant override → site YAML →
    # catalog defaults). ``decide`` is the pure core and takes no session; calling
    # it here previously passed an AsyncSession as the action name and awaited a
    # synchronous function, so every matching rule raised and was swallowed.
    gate: GateDecision = await evaluate(
        db,
        action=action_slug,
        tenant_id=tenant_id,
        confidence=normalize_confidence(subject_fields.get("confidence")),
    )

    gate = apply_rule_autonomy_ceiling(gate, rule_autonomy_level)

    # The playbook runs before the action row is written so the ledger line can
    # name the run it started — an audit entry that says "started a playbook"
    # without saying which run is not worth writing.
    playbook_outcome = (
        await _start_linked_playbook(
            db,
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
            trigger_type=trigger_type,
            subject_fields=subject_fields,
            rule_id=rule_id,
            rule_name=rule_name,
            playbook_ref=playbook_ref,
            dry_run=dry_run,
            gate=gate,
        )
        if playbook_ref
        else None
    )

    status = _gate_to_status(gate, dry_run)
    summary = (
        f"Automation rule '{rule_name}' "
        + (
            f"→ {action_slug} ({gate.decision.value}, {gate.autonomy_level})"
            if gate.allowed
            else f"denied: {gate.reason}"
        )
    )
    if playbook_outcome is not None:
        summary += _playbook_summary(playbook_outcome)

    await record_event(
        db,
        tenant_id=tenant_id,
        subject_type=subject_type,
        subject_id=subject_id,
        stage="respond",
        kind="action",
        action_name=action_slug,
        actor_type="system",
        actor_label=f"automation-rule:{rule_name}".replace("\r", "").replace("\n", " ")[:120],
        summary=summary[:1000],
        status=status,
        policy=gate.policy_snapshot(),
        input_payload={
            "action_params": action_params,
            "rule_id": str(rule_id),
            "playbook": playbook_outcome,
        },
    )

    if playbook_outcome is not None:
        await _record_playbook_start(
            db,
            outcome=playbook_outcome,
            gate=gate,
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
            rule_id=rule_id,
            rule_name=rule_name,
            playbook_ref=playbook_ref,
            trigger_type=trigger_type,
            dry_run=dry_run,
        )

    # A blocked governed action is exactly the exception a human has to clear.
    # Only containment/case actions belong in the approval queue: read-only
    # enrichment never needs a decision, and an unknown slug was already rejected
    # by the catalog (`definition is None`).
    #
    # Scoped to alert subjects: the idempotency index keys on alert_id, and a
    # NULL alert_id would let the same blocked action queue up on every update.
    # Case-scoped approvals need their own index before they can be queued.
    if subject_type == "alert" and (_needs_human_approval(gate)) and (
        not gate.allowed or gate.approval_required
    ):
        created = await ensure_approval_gate_task(
            db,
            tenant_id=tenant_id,
            alert_id=subject_id,
            action_name=action_slug,
            autonomy_level=gate.autonomy_level,
            reason=gate.reason,
        )
        if created:
            await db.commit()

    # Bump the rule's counters only when it actually matched.
    try:
        await db.execute(_BUMP_TRIGGER.bindparams(rid=rule_id))
    except Exception:  # noqa: BLE001
        logger.warning("automation.bump_failed rule_id=%s", str(rule_id)[:36], exc_info=True)


def _playbook_dedupe_key(*, rule_id: uuid.UUID, playbook_ref: str, subject_id: uuid.UUID) -> str:
    """At-most-once claim for one (rule, playbook, subject) combination.

    Keyed on the rule and the subject — not on the alert's state — because the
    same rule is re-evaluated on every update and must fire the playbook once.
    The playbook id is truncated rather than hashed so the key stays readable in
    the ledger; a rule has exactly one ``playbook_ref`` at a time, so a prefix is
    enough to tell two of its playbooks apart. Capped at the column's 128 chars.
    """
    return f"automation:{rule_id}:{playbook_ref.strip()[:24]}:{subject_id}"[:128]


_STARTED_RUN_ID = text(
    """
    SELECT output->>'playbook_run_id' AS run_id
      FROM runbook_events
     WHERE tenant_id = :tid
       AND idempotency_key = :key
       AND output IS NOT NULL
     LIMIT 1
    """
)


async def _started_run_id(
    db: AsyncSession, *, tenant_id: uuid.UUID, key: str
) -> tuple[bool, str | None]:
    """``(claim readable, run id already recorded under ``key``)``.

    A read failure answers ``False``: the caller then declines to start rather
    than risking a second run of a playbook that may isolate a host. Failing
    open here would trade a silent double-execution for a missed one.
    """
    try:
        row = (await db.execute(_STARTED_RUN_ID.bindparams(tid=tenant_id, key=key))).first()
    except Exception:  # noqa: BLE001
        logger.warning("automation.playbook_claim_unreadable", exc_info=True)
        return False, None
    if row is None:
        return True, None
    run_id = row[0]
    return True, str(run_id) if run_id else None


def _playbook_context(
    *,
    tenant_id: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID,
    trigger_type: str | None,
    rule_id: uuid.UUID,
    rule_name: str,
    subject_fields: dict[str, Any],
) -> dict[str, Any]:
    """Run context handed to the playbook.

    ``alert_id`` is what lets the agents service attach a parked run's approval
    task to this alert, so the gate lands in *this* alert's Action Plan instead
    of an orphaned queue. Subject fields follow so a step can read ``severity``
    or ``affected_ips`` without a second lookup; explicit ids win over them.
    """
    context: dict[str, Any] = {
        "tenant_id": str(tenant_id),
        "subject_type": subject_type,
        "subject_id": str(subject_id),
        "trigger": trigger_type or "manual",
        "rule_id": str(rule_id),
        "rule_name": str(rule_name)[:256],
    }
    if subject_type == "alert":
        context["alert_id"] = str(subject_id)
    for field, value in subject_fields.items():
        context.setdefault(field, value)
    return context


def _playbook_summary(outcome: dict[str, Any]) -> str:
    """Clause appended to the rule's own ledger line."""
    ref = outcome.get("ref")
    if outcome.get("started"):
        run_id = outcome.get("run_id")
        if outcome.get("reason") == "already started by an earlier evaluation":
            return f" · playbook {ref} already started (run {run_id})"
        verb = "simulated" if outcome.get("dry_run") else "started"
        return f" · playbook {ref} {verb} (run {run_id})"
    reason = outcome.get("reason") or "not started"
    return f" · playbook {ref} not started — {reason}"


async def _start_linked_playbook(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID,
    trigger_type: str | None,
    subject_fields: dict[str, Any],
    rule_id: uuid.UUID,
    rule_name: str,
    playbook_ref: str,
    dry_run: bool,
    gate: GateDecision,
) -> dict[str, Any]:
    """Start the rule's linked playbook, or say why it did not start.

    Always returns a ledger-shaped dict: silence would leave ``playbook_ref``
    looking effective when nothing ran. Never raises — this sits on the alert
    write path, so a broken agents call must not cost the alert its ledger row.

    The gate is the arbiter. A rule whose action is waiting for an analyst must
    not start a playbook that performs that action, or the approval queue would
    be advisory rather than binding.
    """
    outcome: dict[str, Any] = {
        "ref": playbook_ref,
        "started": False,
        "run_id": None,
        "dry_run": bool(dry_run),
    }
    try:
        if not gate.allowed:
            outcome["reason"] = f"governance denied {gate.action}: {gate.reason}"
            return outcome
        if gate.approval_required:
            outcome["reason"] = (
                f"awaiting analyst approval of {gate.action}; "
                "the playbook would act ahead of it"
            )
            return outcome

        key = _playbook_dedupe_key(rule_id=rule_id, playbook_ref=playbook_ref, subject_id=subject_id)
        claimable, existing_run = await _started_run_id(db, tenant_id=tenant_id, key=key)
        if not claimable:
            outcome["reason"] = (
                "could not verify whether an earlier run exists, so no new run was started"
            )
            return outcome
        if existing_run:
            outcome.update(
                started=True,
                run_id=existing_run,
                reason="already started by an earlier evaluation",
            )
            return outcome

        start = await start_playbook_run(
            tenant_id=str(tenant_id),
            playbook_id=playbook_ref,
            context=_playbook_context(
                tenant_id=tenant_id,
                subject_type=subject_type,
                subject_id=subject_id,
                trigger_type=trigger_type,
                rule_id=rule_id,
                rule_name=rule_name,
                subject_fields=subject_fields,
            ),
            dry_run=dry_run,
            dedupe_key=key,
        )
        if not start.run_id:
            outcome["reason"] = start.reason or "the agents service did not start the playbook"
            return outcome

        outcome.update(started=True, run_id=str(start.run_id), reason=None)
    except Exception:  # noqa: BLE001 — bookkeeping must not break the alert path
        logger.warning(
            "automation.playbook_start_failed",
            rule_id=str(rule_id).replace("\r", "").replace("\n", " ")[:64],
            playbook=str(playbook_ref).replace("\r", "").replace("\n", " ")[:64],
            exc_info=True,
        )
        outcome.setdefault("reason", "playbook start failed")
    return outcome


async def _record_playbook_start(
    db: AsyncSession,
    *,
    outcome: dict[str, Any],
    gate: GateDecision,
    tenant_id: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID,
    rule_id: uuid.UUID,
    rule_name: str,
    playbook_ref: str,
    trigger_type: str | None,
    dry_run: bool,
) -> None:
    """Ledger line for a run this evaluation actually started.

    Written after the rule's own row so the timeline reads cause → effect, and
    keyed on (rule, playbook, subject) so the next evaluation of the same rule
    cannot add a second one. A run that was already started — or never started —
    is already explained by the rule's row and needs no line of its own.
    """
    run_id = outcome.get("run_id")
    if not run_id or outcome.get("reason") is not None:
        return

    await record_event(
        db,
        tenant_id=tenant_id,
        subject_type=subject_type,
        subject_id=subject_id,
        stage="respond",
        kind="action",
        action_name="playbook.run",
        actor_type="system",
        actor_label=f"automation-rule:{rule_name}".replace("\r", "").replace("\n", " ")[:120],
        summary=(
            f"Automation rule '{rule_name}' "
            f"{'simulated' if dry_run else 'started'} playbook '{playbook_ref}' "
            f"(run {run_id})"
        ),
        # A dry run never reaches a gate and never calls a vendor, so it is
        # recorded as simulated — the same posture as the rule's own action.
        status="simulated" if dry_run else "executed",
        policy=gate.policy_snapshot(),
        input_payload={
            "rule_id": str(rule_id),
            "playbook_ref": playbook_ref,
            "alert_id": str(subject_id) if subject_type == "alert" else None,
            "trigger": trigger_type or "manual",
            "dry_run": bool(dry_run),
        },
        output_payload={"playbook_run_id": str(run_id)},
        idempotency_key=_playbook_dedupe_key(
            rule_id=rule_id, playbook_ref=playbook_ref, subject_id=subject_id
        ),
    )


def apply_rule_autonomy_ceiling(
    gate: GateDecision,
    rule_autonomy_level: str | None,
) -> GateDecision:
    """Cap the policy decision at the rule's own autonomy ceiling.

    The editor has always offered an "autonomy ceiling" per rule, and the column
    was stored — but nothing read it, so a rule marked L0 (always require an
    analyst) could still execute on a policy that allows L4. The stricter of the
    two wins, and the reason is recorded so the ledger explains the block.
    """
    if not rule_autonomy_level:
        return gate

    capped = cap_autonomy_level(gate.autonomy_level, rule_autonomy_level)
    if capped == gate.autonomy_level:
        return gate

    # The policy still permits the action; the rule asked for a stricter posture,
    # so it waits for a human instead of being refused. Recording it as `denied`
    # would read as "governance said no" when it means "queued for sign-off".
    return replace(
        gate,
        decision=AutonomyDecision.REVIEW,
        approval_required=True,
        autonomy_level=capped,
        layer=f"{gate.layer}+rule_ceiling",
        reason=(
            f"rule autonomy ceiling {rule_autonomy_level} is stricter than the "
            f"policy level {gate.autonomy_level}"
        ),
    )


def _needs_human_approval(gate: GateDecision) -> bool:
    """Whether this blocked decision should land in the analyst queue."""
    definition = gate.definition
    if definition is None:
        # Unknown action: the catalog already forces analyst involvement, and
        # queuing it gives the operator something concrete to fix.
        return True
    return definition.category.value in {"containment", "case"}


def normalize_confidence(value: Any, *, default: float = 0.5) -> float:
    """Return a 0.0–1.0 confidence.

    Alert rows store confidence as an int 0–100, while the gate's thresholds are
    0.0–1.0. Passing 50 straight through used to clamp to 1.0 inside the gate,
    which granted autonomy to every rule that matched.
    """
    try:
        raw = float(value)
    except (TypeError, ValueError):
        return default
    if raw > 1.0:
        raw = raw / 100.0
    return max(0.0, min(1.0, raw))


def _gate_to_status(gate: GateDecision, dry_run: bool) -> str:
    if not gate.allowed:
        return "denied"
    if gate.approval_required:
        return "recorded"
    return "simulated" if dry_run else "executed"
