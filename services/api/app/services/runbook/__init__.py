"""Runbook — governed action ledger (Phase 0: governance).

The Runbook answers, for any subject (alert / case / incident): *what was done,
by whom, under which policy, and with what result*. This package is the
governance half of that promise; the ledger table and its writer arrive in
Phase 1, the console surface in Phase 2.

Naming: an **operational runbook** (``docs/operations/*.md``) is a document
describing what *should* be done. A **playbook** is an executable SOAR
workflow. A **runbook event** is the record of what *actually happened* — and
that is what this package governs and what the Runbook page renders.

Modules
-------
* :mod:`app.services.runbook.thresholds` — three-tier confidence cutoffs,
  value-identical to the agents runtime (``guardrails.py``).
* :mod:`app.services.runbook.contracts` — audit / data-safety / failure / cost
  contracts that constrain execution.
* :mod:`app.services.runbook.action_catalog` — the single source of truth for
  the actions the platform may take.
* :mod:`app.services.runbook.gate` — resolves the effective policy per tenant
  and answers allow / review / escalate / reject.
"""

from __future__ import annotations

from app.services.runbook.action_catalog import (
    ACTIONS,
    ActionCategory,
    ActionDefinition,
    BlastRadius,
    action_names,
    blast_radius,
    default_thresholds,
    get_action,
)
from app.services.runbook.contracts import (
    AuditContract,
    CostBudget,
    DataSafetyContract,
    FailureContract,
)
from app.services.runbook.gate import (
    GateDecision,
    TenantOverride,
    autonomy_level_for,
    cap_autonomy_level,
    decide,
    evaluate,
    fetch_tenant_override,
    load_site_policy,
    reset_gate_caches,
)
from app.services.runbook.thresholds import (
    DEFAULT_REQUIRE_ANALYST,
    ActionThresholds,
    AutonomyDecision,
    make_thresholds,
)

__all__ = [
    "ACTIONS",
    "ActionCategory",
    "ActionDefinition",
    "ActionThresholds",
    "AuditContract",
    "AutonomyDecision",
    "BlastRadius",
    "CostBudget",
    "DEFAULT_REQUIRE_ANALYST",
    "DataSafetyContract",
    "FailureContract",
    "GateDecision",
    "TenantOverride",
    "action_names",
    "autonomy_level_for",
    "blast_radius",
    "cap_autonomy_level",
    "decide",
    "default_thresholds",
    "evaluate",
    "fetch_tenant_override",
    "get_action",
    "load_site_policy",
    "make_thresholds",
    "reset_gate_caches",
]
