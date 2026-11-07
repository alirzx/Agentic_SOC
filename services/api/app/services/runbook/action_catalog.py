"""Action catalog — the single source of truth for governed actions.

Every action the platform may take on a subject (alert / case / incident) is
declared exactly once here: its identity, blast radius, default autonomy
thresholds, and the four execution contracts that constrain it.

Who reads this module
---------------------
* :mod:`app.services.runbook.gate` — resolves the effective policy per tenant.
* :mod:`app.api.v1.endpoints.autonomy_policy` — serves the admin UI. It used to
  carry its own copy of the defaults and blast radii; both moved here so there
  is one place to edit and no chance of the API and the gate disagreeing.
* ``tests/test_runbook_thresholds.py`` — asserts the values still match the
  agents runtime copy (``services/agents/app/policy/guardrails.py``).

Scope note (Phase 0)
--------------------
The catalog lists exactly the actions the platform can already take — the same
19 the autonomy admin UI has been showing. New catalog entries for the Runbook
itself (``splunk.simple_query``, ``alert.disposition``, …) are added in Phase 1
together with the code that emits them; listing them earlier would advertise
actions that nothing can execute yet.

Blast radius vocabulary is fixed by the existing consumers and must not be
renamed: ``read | low | medium | high | critical``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from app.services.runbook.contracts import (
    AuditContract,
    CostBudget,
    DataSafetyContract,
    FailureContract,
)
from app.services.runbook.thresholds import (
    DEFAULT_REQUIRE_ANALYST,
    ActionThresholds,
    make_thresholds,
)

__all__ = [
    "ActionCategory",
    "ActionDefinition",
    "BlastRadius",
    "ACTIONS",
    "get_action",
    "action_names",
    "default_thresholds",
    "blast_radius",
    "required_connectors",
]


class BlastRadius(str, Enum):
    """How far a mistake with this action can reach."""

    READ = "read"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionCategory(str, Enum):
    """Grouping used by the console to organise the policy list."""

    READ = "read"
    CASE = "case"
    CONTAINMENT = "containment"


@dataclass(frozen=True)
class ActionDefinition:
    """One governed action.

    ``thresholds`` are the shipped defaults. ``always_requires_approval`` is the
    escape hatch for actions where no confidence value should ever buy
    unattended execution — a critical-blast-radius action such as
    ``delete_object``. It is intentionally a separate flag instead of
    ``auto=2.0`` so the reason is readable in an audit.

    ``required_connectors`` is a tuple of connector types (e.g. ``("splunk",)``
    or ``("firewall", "edr")``) that must be active and enabled for this action
    to be available to the agent. An empty tuple means the action has no
    connector dependency (e.g. read-only enrichment actions).
    """

    name: str
    label: str
    category: ActionCategory
    blast_radius: BlastRadius
    thresholds: ActionThresholds
    audit: AuditContract
    data_safety: DataSafetyContract
    failure: FailureContract
    cost: CostBudget
    required_connectors: tuple[str, ...] = ()
    always_requires_approval: bool = False
    dry_run_default: bool = False

    @property
    def requires_audit_log(self) -> bool:
        """Whether the definition demands a legal audit row.

        Every ``high``/``critical`` blast radius action must trip this: the
        ledger explains the operation, the audit log is what compliance reads.
        """
        return self.audit.audit_log


# ─── Contract presets ────────────────────────────────────────────────────────
# One preset per category keeps the 19 definitions below readable. Per-action
# overrides are applied at the definition site, so a deviation is visible where
# it happens instead of hidden in a conditional.

_READ_CONTRACTS = {
    "audit_log": False,
    "data_safety": DataSafetyContract(allowed_fields=("*",), max_payload_bytes=4096),
    "failure": FailureContract(max_attempts=2, backoff_seconds=0.5, timeout_seconds=15.0, on_failure="continue"),
    "cost": CostBudget(),
}

_CASE_CONTRACTS = {
    "audit_log": False,
    "data_safety": DataSafetyContract(allowed_fields=("*",), max_payload_bytes=8192),
    "failure": FailureContract(max_attempts=2, backoff_seconds=1.0, timeout_seconds=30.0, on_failure="continue"),
    "cost": CostBudget(),
}

# Containment: dry-run by default (project-wide copilot posture), always audited
# to the legal store, and explicitly barred from spending LLM budget.
_CONTAINMENT_CONTRACTS = {
    "audit_log": True,
    "data_safety": DataSafetyContract(
        allowed_fields=("target", "target_type", "reason", "alert_id", "case_id", "confidence", "action"),
        max_payload_bytes=4096,
    ),
    "failure": FailureContract(max_attempts=1, timeout_seconds=60.0, on_failure="escalate"),
    "cost": CostBudget(max_usd_per_run=0.0),
}


def _definition(
    name: str,
    label: str,
    category: ActionCategory,
    blast_radius: BlastRadius,
    thresholds: tuple[float, float, float],
    *,
    required_connectors: tuple[str, ...] = (),
    always_requires_approval: bool = False,
    dry_run_default: bool = False,
) -> ActionDefinition:
    """Assemble a definition from a category preset plus explicit overrides."""
    preset = {
        ActionCategory.READ: _READ_CONTRACTS,
        ActionCategory.CASE: _CASE_CONTRACTS,
        ActionCategory.CONTAINMENT: _CONTAINMENT_CONTRACTS,
    }[category]

    # A critical action must reach the legal audit store even when its category
    # preset says otherwise. The audit action name is derived, never hand-typed,
    # so every entry is unique and greppable back to this catalog.
    wants_audit_log = bool(preset["audit_log"]) or always_requires_approval
    audit = AuditContract(
        record_ledger=True,
        audit_log=wants_audit_log,
        audit_action=f"{category.value}.{name}" if wants_audit_log else None,
    )

    auto, review, escalation = thresholds
    return ActionDefinition(
        name=name,
        label=label,
        category=category,
        blast_radius=blast_radius,
        thresholds=make_thresholds(auto, review, escalation),
        audit=audit,
        data_safety=preset["data_safety"],
        failure=preset["failure"],
        cost=preset["cost"],
        required_connectors=required_connectors,
        always_requires_approval=always_requires_approval,
        dry_run_default=dry_run_default,
    )


_READ = ActionCategory.READ
_CASE = ActionCategory.CASE
_CONTAIN = ActionCategory.CONTAINMENT

_DEFINITIONS: tuple[ActionDefinition, ...] = (
    # ── Read / enrichment — autonomous by default, never audited to the legal store
    # No connector required for most read actions (internal enrichment)
    _definition("lookup_ip", "Look up IP reputation", _READ, BlastRadius.READ, (0.0, 0.0, 0.0), required_connectors=("splunk",)),
    _definition("lookup_domain", "Look up domain reputation", _READ, BlastRadius.READ, (0.0, 0.0, 0.0)),
    _definition("search_logs", "Search log telemetry", _READ, BlastRadius.READ, (0.0, 0.0, 0.0), required_connectors=("splunk",)),
    _definition("enrich_alert", "Enrich alert with context", _READ, BlastRadius.READ, (0.0, 0.0, 0.0)),
    _definition("mitre_lookup", "Resolve MITRE ATT&CK technique", _READ, BlastRadius.READ, (0.0, 0.0, 0.0)),
    _definition("get_alert_context", "Load alert context bundle", _READ, BlastRadius.READ, (0.0, 0.0, 0.0)),
    # ── Case workflow — moderate autonomy, easy to roll back
    _definition("add_alert_tag", "Tag an alert", _CASE, BlastRadius.LOW, (0.50, 0.30, 0.10)),
    _definition("close_alert", "Close an alert", _CASE, BlastRadius.LOW, (0.60, 0.40, 0.20)),
    _definition("create_case", "Open a case", _CASE, BlastRadius.LOW, (0.50, 0.30, 0.10), required_connectors=("jira",)),
    _definition("add_case_comment", "Comment on a case", _CASE, BlastRadius.LOW, (0.40, 0.20, 0.05)),
    _definition("assign_case", "Assign a case", _CASE, BlastRadius.LOW, (0.60, 0.40, 0.20)),
    # ── Containment — high blast radius, dry-run by default, always audited
    _definition(
        "quarantine_file",
        "Quarantine a file",
        _CONTAIN,
        BlastRadius.HIGH,
        (0.85, 0.65, 0.40),
        required_connectors=("firewall", "edr"),
        dry_run_default=True,
    ),
    _definition(
        "block_ip",
        "Block an IP address",
        _CONTAIN,
        BlastRadius.HIGH,
        (0.90, 0.70, 0.40),
        required_connectors=("firewall", "edr"),
        dry_run_default=True,
    ),
    _definition(
        "isolate_host",
        "Isolate a host from the network",
        _CONTAIN,
        BlastRadius.HIGH,
        (0.92, 0.72, 0.45),
        required_connectors=("firewall", "edr"),
        dry_run_default=True,
    ),
    _definition(
        "disable_user_account",
        "Disable a user account",
        _CONTAIN,
        BlastRadius.HIGH,
        (0.90, 0.70, 0.40),
        required_connectors=("firewall", "edr"),
        dry_run_default=True,
    ),
    _definition(
        "revoke_session",
        "Revoke an active session",
        _CONTAIN,
        BlastRadius.MEDIUM,
        (0.80, 0.60, 0.30),
        required_connectors=("firewall", "edr"),
        dry_run_default=True,
    ),
    _definition(
        "delete_object",
        "Delete an object",
        _CONTAIN,
        BlastRadius.CRITICAL,
        (0.95, 0.80, 0.50),
        required_connectors=("firewall", "edr"),
        always_requires_approval=True,
        dry_run_default=True,
    ),
    _definition(
        "firewall_rule_add",
        "Add a firewall rule",
        _CONTAIN,
        BlastRadius.HIGH,
        (0.88, 0.68, 0.40),
        required_connectors=("firewall",),
        dry_run_default=True,
    ),
    _definition(
        "firewall_rule_remove",
        "Remove a firewall rule",
        _CONTAIN,
        BlastRadius.HIGH,
        (0.90, 0.70, 0.40),
        required_connectors=("firewall",),
        dry_run_default=True,
    ),
)

#: Read-only catalog keyed by action name.
ACTIONS: Mapping[str, ActionDefinition] = MappingProxyType(
    {definition.name: definition for definition in _DEFINITIONS}
)


def get_action(name: str) -> ActionDefinition | None:
    """Return the definition for ``name``, or ``None`` when it is not governed.

    Unknown actions are not a crash: a caller that asks the gate about an
    action nobody has governed yet gets a "require an analyst" answer from
    :func:`app.services.runbook.gate.evaluate`, which is the safe default.
    """
    return ACTIONS.get((name or "").strip())


def action_names() -> tuple[str, ...]:
    """All governed action names, in declaration order."""
    return tuple(ACTIONS)


def default_thresholds(name: str) -> ActionThresholds:
    """Shipped default thresholds, falling back to "always ask a human"."""
    definition = get_action(name)
    return definition.thresholds if definition is not None else DEFAULT_REQUIRE_ANALYST


def blast_radius(name: str) -> BlastRadius | None:
    """Blast radius for ``name``; ``None`` for an unknown action."""
    definition = get_action(name)
    return definition.blast_radius if definition is not None else None


def required_connectors(name: str) -> tuple[str, ...]:
    """Connector types required for ``name`` to be available; empty tuple if none."""
    definition = get_action(name)
    return definition.required_connectors if definition is not None else ()
