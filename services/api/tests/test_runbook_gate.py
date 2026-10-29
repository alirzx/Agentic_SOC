"""Unit tests for the Runbook governance layer (Phase 0).

Everything here is pure — no database, no HTTP, no clock. The gate's DB layer
(``fetch_tenant_override``) is exercised through the integration marker suite
once Phase 1 needs it; what must never regress silently is the decision logic,
because every governed action in the platform will answer to it.

Coverage map
------------
* catalog invariants (unique names, audit for high/critical blast radius)
* thresholds semantics (ordering, defaults, band boundaries)
* contracts (self-validation, redaction, budget)
* gate layering (defaults → site YAML → tenant), opt-out, autonomy caps
* drift against the agents runtime copy (``guardrails.py``)
* the ``AISOC_RUNBOOK_ENABLED`` feature flag
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from app.core import config as app_config
from app.api.v1.deps import require_runbook_enabled
from app.services.runbook.action_catalog import (
    ACTIONS,
    ActionCategory,
    BlastRadius,
    action_names,
    get_action,
)
from app.services.runbook.contracts import (
    REDACTED,
    AuditContract,
    CostBudget,
    DataSafetyContract,
    FailureContract,
)
from app.models.runbook_task import RunbookTask
from app.services.runbook.gate import (
    TenantOverride,
    autonomy_level_for,
    cap_autonomy_level,
    decide,
)
from app.services.runbook.thresholds import (
    DEFAULT_REQUIRE_ANALYST,
    AutonomyDecision,
    make_thresholds,
)

_SERVICES_ROOT = Path(__file__).resolve().parents[2]
_GUARDRAILS_MODULE = _SERVICES_ROOT / "agents" / "app" / "policy" / "guardrails.py"


# ─── Catalog invariants ──────────────────────────────────────────────────────


def test_runbook_task_uses_the_tenants_table_for_fk():
    fk = next(iter(RunbookTask.__table__.c.tenant_id.foreign_keys)).target_fullname
    assert fk == "tenants.id"


def test_catalog_has_no_duplicate_names():
    names = [definition.name for definition in ACTIONS.values()]
    assert len(names) == len(set(names))
    assert action_names() == tuple(ACTIONS)


def test_every_high_or_critical_action_is_audited():
    """Blast radius high/critical must reach the legal audit store.

    The ledger explains the operation; ``audit_log`` is what compliance
    exports. A containment action that only lands in the ledger would be
    invisible to an audit sweep, so this is a hard invariant.
    """
    for definition in ACTIONS.values():
        if definition.blast_radius in (BlastRadius.HIGH, BlastRadius.CRITICAL):
            assert definition.audit.audit_log, f"{definition.name} must write audit_log"
            assert definition.audit.audit_action, f"{definition.name} must name its audit action"


def test_containment_actions_are_dry_run_and_unbudgeted_for_llm():
    """Default posture is copilot/dry-run, and containment never spends tokens."""
    for definition in ACTIONS.values():
        if definition.category is ActionCategory.CONTAINMENT:
            assert definition.dry_run_default, f"{definition.name} must default to dry-run"
            assert definition.cost.max_usd_per_run == 0.0, f"{definition.name} must not call a paid model"


def test_read_actions_require_no_confidence():
    """Read-only actions stay autonomous at confidence 0 — otherwise triage stalls."""
    for definition in ACTIONS.values():
        if definition.blast_radius is BlastRadius.READ:
            assert definition.thresholds.auto == 0.0


def test_get_action_is_trimmed_and_case_sensitive():
    assert get_action("  isolate_host  ") is not None
    assert get_action("Isolate_Host") is None
    assert get_action("") is None
    assert get_action("nope") is None


# ─── Thresholds ──────────────────────────────────────────────────────────────


def test_make_thresholds_derives_missing_tiers_like_the_agents_runtime():
    thresholds = make_thresholds(0.80)
    assert thresholds.auto == 0.80
    assert thresholds.review == pytest.approx(0.70)
    assert thresholds.escalation == pytest.approx(0.50)


def test_make_thresholds_clamps_and_never_inverts_ordering():
    thresholds = make_thresholds(0.40, review=0.90, escalation=0.95)
    assert thresholds.auto == 0.40
    assert thresholds.review <= thresholds.auto
    assert thresholds.escalation <= thresholds.review

    clamped = make_thresholds(1.5, review=-1.0, escalation=-2.0)
    assert clamped.auto == 1.0
    assert clamped.review == 0.0
    assert clamped.escalation == 0.0


def test_decide_bands_are_inclusive_at_the_lower_bound():
    thresholds = make_thresholds(0.90, 0.70, 0.40)
    assert thresholds.decide(0.90) is AutonomyDecision.AUTO
    assert thresholds.decide(0.8999) is AutonomyDecision.REVIEW
    assert thresholds.decide(0.70) is AutonomyDecision.REVIEW
    assert thresholds.decide(0.6999) is AutonomyDecision.ESCALATE
    assert thresholds.decide(0.40) is AutonomyDecision.ESCALATE
    assert thresholds.decide(0.3999) is AutonomyDecision.REJECT


# ─── Contracts ───────────────────────────────────────────────────────────────


def test_audit_contract_requires_an_action_name_when_auditing():
    with pytest.raises(ValueError, match="audit_action is required"):
        AuditContract(audit_log=True)


def test_failure_contract_rejects_unknown_mode_and_bad_retry_count():
    with pytest.raises(ValueError, match="on_failure"):
        FailureContract(on_failure="retry-forever")
    with pytest.raises(ValueError, match="max_attempts"):
        FailureContract(max_attempts=0)


def test_failure_contract_backoff_is_linear():
    contract = FailureContract(max_attempts=3, backoff_seconds=1.5)
    assert contract.retry_delay(1) == pytest.approx(1.5)
    assert contract.retry_delay(3) == pytest.approx(4.5)


def test_cost_budget_zero_is_a_real_budget_not_unlimited():
    """``0.0`` means "no LLM spend", which is why containment gets it."""
    budget = CostBudget(max_usd_per_run=0.0)
    assert budget.exceeded(usd=0.0) is None
    assert budget.exceeded(usd=0.01) == "cost_budget_exceeded:usd"
    assert CostBudget().exceeded(usd=99.0) is None


def test_data_safety_redacts_credentials_even_when_passthrough():
    contract = DataSafetyContract(allowed_fields=("*",))
    clean = contract.sanitize({"target": "host1", "token": "abc", "nested": {"k": 1}})
    assert clean["target"] == "host1"
    assert clean["token"] == REDACTED
    assert clean["nested"] == {"k": 1}


def test_data_safety_allow_list_drops_everything_else():
    contract = DataSafetyContract(allowed_fields=("target", "reason"), redact=("reason",))
    clean = contract.sanitize({"target": "host1", "reason": "contain it", "raw_event": {"x": 1}})
    assert clean == {"target": "host1", "reason": REDACTED}


def test_data_safety_truncates_instead_of_shipping_half_a_payload():
    contract = DataSafetyContract(allowed_fields=("*",), max_payload_bytes=128)
    truncated = contract.sanitize({"blob": "x" * 500})
    assert truncated["_truncated"] is True
    assert truncated["_budget"] == 128


def test_data_safety_empty_payload_is_empty_not_missing():
    assert DataSafetyContract().sanitize(None) == {}
    assert DataSafetyContract().sanitize({}) == {}


# ─── Gate: layering ──────────────────────────────────────────────────────────


def test_unknown_action_is_rejected_with_analyst_required():
    decision = decide("do_something_unlisted", 1.0)
    assert decision.decision is AutonomyDecision.REJECT
    assert decision.allowed is False
    assert decision.approval_required is True
    assert decision.autonomy_level == "L0"
    assert decision.layer == "unknown_action"
    assert decision.thresholds is DEFAULT_REQUIRE_ANALYST


def test_defaults_layer_allows_at_or_above_auto():
    # ``site_policy={}`` pins the test to the catalog layer — the repo ships a
    # populated autonomy_policy.yaml, so relying on the ambient file would make
    # this test assert the file's contents rather than the gate's layering.
    decision = decide("isolate_host", 0.95, site_policy={})
    assert decision.decision is AutonomyDecision.AUTO
    assert decision.allowed is True
    assert decision.approval_required is False
    assert decision.layer == "defaults"


def test_shipped_site_policy_parses_and_covers_only_known_actions():
    """The repo's baseline YAML must stay loadable and in step with the catalog.

    A typo in that file is invisible at runtime (the loader degrades to
    defaults), so nothing else would catch it before an operator discovers
    their tuning never applied.
    """
    from app.services.runbook.gate import _site_policy_path, load_site_policy

    path = _site_policy_path()
    if not path.exists():  # service container / partial checkout
        pytest.skip(f"site policy not present at {path}")

    parsed = load_site_policy(path)
    assert parsed, "site policy parsed to nothing — the file is malformed"

    unknown = sorted(set(parsed) - set(ACTIONS))
    assert not unknown, f"site policy sets thresholds for unknown actions: {unknown}"

    for name, thresholds in parsed.items():
        expected = ACTIONS[name].thresholds
        assert thresholds == expected, (
            f"{name}: shipped YAML {thresholds.to_dict()} != catalog {expected.to_dict()}. "
            "If this change is intentional, update the catalog too — the two must tell one story."
        )


def test_below_review_never_allows():
    decision = decide("isolate_host", 0.10, site_policy={})
    assert decision.decision is AutonomyDecision.REJECT
    assert decision.allowed is False
    assert decision.approval_required is True


def test_site_yaml_layer_overrides_defaults():
    decision = decide(
        "isolate_host",
        0.80,
        site_policy={"isolate_host": make_thresholds(0.80)},
    )
    assert decision.layer == "site_yaml"
    assert decision.decision is AutonomyDecision.AUTO


def test_tenant_layer_overrides_site_yaml():
    override = TenantOverride(thresholds=make_thresholds(0.99))
    decision = decide(
        "isolate_host",
        0.80,
        override=override,
        site_policy={"isolate_host": make_thresholds(0.50)},
    )
    assert decision.layer == "tenant"
    assert decision.decision is not AutonomyDecision.AUTO


def test_tenant_opt_out_beats_any_confidence():
    override = TenantOverride(enabled=False)
    decision = decide("lookup_ip", 1.0, override=override)
    assert decision.decision is AutonomyDecision.REJECT
    assert decision.allowed is False
    assert decision.layer == "tenant_opt_out"


def test_critical_action_demotes_auto_to_review():
    """``delete_object`` must never run unattended, even at confidence 1.0."""
    definition = ACTIONS["delete_object"]
    assert definition.always_requires_approval is True

    decision = decide("delete_object", 1.0)
    assert decision.decision is AutonomyDecision.REVIEW
    assert decision.allowed is False
    assert decision.approval_required is True
    assert decision.autonomy_level == "L0"


def test_confidence_input_is_clamped_not_trusted():
    assert decide("lookup_ip", 5.0).decision is AutonomyDecision.AUTO
    assert decide("lookup_ip", -3.0).decision is AutonomyDecision.AUTO  # auto floor is 0.0
    assert decide("isolate_host", 1.7).decision is AutonomyDecision.AUTO


def test_non_finite_confidence_is_treated_as_zero():
    """A NaN confidence must never buy autonomy.

    ``min(1.0, float('nan'))`` returns ``1.0`` in Python, so a naive clamp would
    grant an isolation action to a caller that could not compute confidence.
    """
    for broken in (float("nan"), float("inf"), float("-inf")):
        decision = decide("isolate_host", broken)
        assert decision.allowed is False, broken
        assert decision.decision is AutonomyDecision.REJECT, broken
        assert decision.approval_required is True, broken


# ─── Gate: autonomy ladder ───────────────────────────────────────────────────


def test_autonomy_ladder_maps_decisions_to_levels():
    read_auto = autonomy_level_for(ACTIONS["lookup_ip"], AutonomyDecision.AUTO)
    containment_auto = autonomy_level_for(ACTIONS["block_ip"], AutonomyDecision.AUTO)
    assert read_auto == "L4"
    assert containment_auto == "L3"
    assert autonomy_level_for(ACTIONS["block_ip"], AutonomyDecision.REVIEW) == "L2"
    assert autonomy_level_for(ACTIONS["block_ip"], AutonomyDecision.ESCALATE) == "L1"
    assert autonomy_level_for(ACTIONS["block_ip"], AutonomyDecision.REJECT) == "L0"


def test_tenant_can_lower_the_autonomy_ceiling_but_not_raise_it():
    assert cap_autonomy_level("L4", "L2") == "L2"
    assert cap_autonomy_level("L2", "L4") == "L2"
    assert cap_autonomy_level("L3", None) == "L3"
    assert cap_autonomy_level("L3", "nonsense") == "L3"

    decision = decide("lookup_ip", 1.0, override=TenantOverride(autonomy_level="L1"))
    assert decision.autonomy_level == "L1"
    # The confidence decision itself is unchanged — only the displayed ceiling.
    assert decision.decision is AutonomyDecision.AUTO


def test_policy_snapshot_is_flat_and_json_safe():
    decision = decide("isolate_host", 0.95, site_policy={})
    snapshot = decision.policy_snapshot()
    assert json.loads(json.dumps(snapshot)) == snapshot
    assert snapshot["decision"] == "auto"
    assert snapshot["blast_radius"] == "high"
    assert snapshot["thresholds"] == {"auto": 0.92, "review": 0.72, "escalation": 0.45}


# ─── Drift guard against the agents runtime copy ─────────────────────────────


def _guardrails_defaults() -> dict[str, tuple[float, float, float]]:
    """Read ``_DEFAULT_THRESHOLDS`` out of the agents module without importing it.

    Parsed with ``ast`` instead of imported because the two services ship as
    separate containers and the API's test environment has no ``app`` package
    from the agents service on its path.
    """
    assert _GUARDRAILS_MODULE.exists(), f"guardrails module missing at {_GUARDRAILS_MODULE}"
    tree = ast.parse(_GUARDRAILS_MODULE.read_text(encoding="utf-8"))

    node: ast.Assign | ast.AnnAssign | None = None
    for candidate in tree.body:
        target = None
        if isinstance(candidate, ast.AnnAssign) and isinstance(candidate.target, ast.Name):
            target = candidate.target.id
        elif isinstance(candidate, ast.Assign):
            for assign_target in candidate.targets:
                if isinstance(assign_target, ast.Name):
                    target = assign_target.id
        if target == "_DEFAULT_THRESHOLDS":
            node = candidate
            break

    assert node is not None, "_DEFAULT_THRESHOLDS not found in guardrails.py"
    value = node.value
    assert isinstance(value, ast.Dict), "_DEFAULT_THRESHOLDS is no longer a dict literal"

    parsed: dict[str, tuple[float, float, float]] = {}
    for key, item in zip(value.keys, value.values, strict=True):
        name = ast.literal_eval(key)
        assert isinstance(item, ast.Call), f"{name}: expected a _make_thresholds(...) call"

        args = [ast.literal_eval(arg) for arg in item.args]
        kwargs = {kw.arg: ast.literal_eval(kw.value) for kw in item.keywords if kw.arg}
        auto = kwargs.get("auto", args[0] if args else 1.0)
        review = kwargs.get("review", args[1] if len(args) > 1 else None)
        escalation = kwargs.get("escalation", args[2] if len(args) > 2 else None)

        derived_review = float(review) if review is not None else max(0.0, float(auto) - 0.1)
        derived_escalation = (
            float(escalation) if escalation is not None else max(0.0, derived_review - 0.2)
        )
        parsed[name] = (float(auto), derived_review, derived_escalation)

    return parsed


def test_catalog_matches_the_agents_runtime_thresholds():
    """Drift guard: the API catalog and ``guardrails.py`` must not diverge.

    ``autonomy_policy.py`` used to promise this test in a comment without one
    existing; the catalog refactor moved the values, so the promise is now real.
    """
    from_agents = _guardrails_defaults()
    from_catalog = {
        name: (definition.thresholds.auto, definition.thresholds.review, definition.thresholds.escalation)
        for name, definition in ACTIONS.items()
    }

    missing = sorted(set(from_agents) - set(from_catalog))
    extra = sorted(set(from_catalog) - set(from_agents))
    assert not missing, f"actions in agents runtime but not in the Runbook catalog: {missing}"
    assert not extra, f"actions in the Runbook catalog but not in the agents runtime: {extra}"

    for name, expected in from_agents.items():
        actual = from_catalog[name]
        assert actual == pytest.approx(expected), (
            f"{name}: catalog {actual} != agents runtime {expected}"
        )


# ─── Feature flag ────────────────────────────────────────────────────────────


def test_runbook_flag_defaults_on_in_development(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(app_config.settings, "RUNBOOK_ENABLED", None)
    monkeypatch.setattr(app_config.settings, "ENVIRONMENT", "development")
    assert app_config.runbook_enabled() is True


def test_runbook_flag_defaults_off_in_production(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(app_config.settings, "RUNBOOK_ENABLED", None)
    monkeypatch.setattr(app_config.settings, "ENVIRONMENT", "production")
    assert app_config.runbook_enabled() is False


def test_runbook_flag_explicit_value_wins_both_ways(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(app_config.settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(app_config.settings, "RUNBOOK_ENABLED", True)
    assert app_config.runbook_enabled() is True

    monkeypatch.setattr(app_config.settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(app_config.settings, "RUNBOOK_ENABLED", False)
    assert app_config.runbook_enabled() is False


def test_disabled_runbook_routes_answer_404(monkeypatch: pytest.MonkeyPatch):
    from fastapi import HTTPException

    monkeypatch.setattr(app_config.settings, "RUNBOOK_ENABLED", False)
    with pytest.raises(HTTPException) as excinfo:
        require_runbook_enabled()
    assert excinfo.value.status_code == 404

    monkeypatch.setattr(app_config.settings, "RUNBOOK_ENABLED", True)
    require_runbook_enabled()  # must not raise
