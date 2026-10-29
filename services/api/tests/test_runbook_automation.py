"""Unit tests for the Runbook automation layer (Phase v2).

Tests the condition evaluator (pure logic, no DB) and the rule executor
(mocked DB). The automation_rules table tests go in test_runbook_events.py
with the rest of the DB-gated integration suite.
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.runbook.condition_eval import (
    ConditionError,
    _validate_field,
    evaluate_all,
    evaluate_condition,
    validate_conditions,
)
from app.services.runbook.gate import GateDecision
from app.services.runbook.thresholds import AutonomyDecision, make_thresholds


# ── condition_eval unit tests ─────────────────────────────────────────────────


class TestEvaluateCondition:
    def _cond(self, field: str, op: str, value=None) -> dict:
        return {"field": field, "op": op, "value": value}

    def test_eq_match(self):
        assert evaluate_condition(self._cond("severity", "eq", "critical"), {"severity": "critical"})

    def test_eq_no_match(self):
        assert not evaluate_condition(self._cond("severity", "eq", "critical"), {"severity": "high"})

    def test_ne(self):
        assert evaluate_condition(self._cond("status", "ne", "resolved"), {"status": "new"})

    def test_gt_numeric(self):
        assert evaluate_condition(self._cond("confidence", "gt", 80), {"confidence": 90})

    def test_lt_numeric(self):
        assert evaluate_condition(self._cond("confidence", "lt", 50), {"confidence": 30})

    def test_in_operator(self):
        assert evaluate_condition(self._cond("severity", "in", ["critical", "high"]), {"severity": "critical"})

    def test_not_in_operator(self):
        assert evaluate_condition(self._cond("severity", "not_in", ["critical", "high"]), {"severity": "medium"})

    def test_contains_string(self):
        assert evaluate_condition(self._cond("title", "contains", "phishing"), {"title": "Credential phishing detected"})

    def test_startswith(self):
        assert evaluate_condition(self._cond("title", "startswith", "Brute"), {"title": "Brute force login"})

    def test_endswith(self):
        assert evaluate_condition(self._cond("title", "endswith", "failed"), {"title": "Login failed"})

    def test_exists(self):
        assert evaluate_condition(self._cond("category", "exists"), {"category": "edr"})

    def test_not_exists(self):
        assert evaluate_condition(self._cond("category", "not_exists"), {"category": None})

    def test_array_contains(self):
        assert evaluate_condition(
            self._cond("tags", "array_contains", "critical-asset"),
            {"tags": ["critical-asset", "edr"]},
        )

    def test_array_not_contains(self):
        assert evaluate_condition(
            self._cond("tags", "array_not_contains", "suppressed"),
            {"tags": ["edr"]},
        )

    def test_missing_field_returns_false(self):
        assert not evaluate_condition(self._cond("severity", "eq", "critical"), {})

    def test_unknown_op_returns_false(self):
        assert not evaluate_condition(self._cond("severity", "EVILTHING", "critical"), {"severity": "critical"})

    def test_disallowed_field_returns_false(self):
        assert not evaluate_condition(self._cond("__class__", "eq", "evil"), {"__class__": "evil"})

    def test_path_too_deep_returns_false(self):
        assert not evaluate_condition(
            self._cond("a.b.c.d", "eq", "x"),
            {"a": {"b": {"c": {"d": "x"}}}},
        )

    def test_numeric_coercion(self):
        # Confidence stored as int, rule written as string "80"
        assert evaluate_condition(self._cond("confidence", "gt", "80"), {"confidence": 90})

    def test_bad_shape_returns_false(self):
        assert not evaluate_condition({"field": 123, "op": "eq", "value": "x"}, {"field": "x"})


class TestEvaluateAll:
    def test_empty_conditions_always_matches(self):
        assert evaluate_all([], {})
        assert evaluate_all([], {"severity": "critical"})

    def test_all_must_pass(self):
        conditions = [
            {"field": "severity", "op": "eq", "value": "critical"},
            {"field": "confidence", "op": "gt", "value": 80},
        ]
        assert evaluate_all(conditions, {"severity": "critical", "confidence": 90})
        assert not evaluate_all(conditions, {"severity": "critical", "confidence": 70})

    def test_one_fail_stops_evaluation(self):
        conditions = [
            {"field": "severity", "op": "eq", "value": "high"},
            {"field": "severity", "op": "eq", "value": "critical"},  # contradicts first
        ]
        assert not evaluate_all(conditions, {"severity": "high"})


class TestValidateConditions:
    def test_valid_conditions_return_no_errors(self):
        conds = [{"field": "severity", "op": "eq", "value": "critical"}]
        assert validate_conditions(conds) == []

    def test_invalid_field_returns_error(self):
        conds = [{"field": "password", "op": "eq", "value": "x"}]
        errors = validate_conditions(conds)
        assert len(errors) == 1
        assert "password" in errors[0]

    def test_invalid_op_returns_error(self):
        conds = [{"field": "severity", "op": "INJECT", "value": "x"}]
        errors = validate_conditions(conds)
        assert len(errors) == 1
        assert "INJECT" in errors[0]

    def test_multiple_errors_collected(self):
        conds = [
            {"field": "password", "op": "eq", "value": "x"},
            {"field": "severity", "op": "EVIL", "value": "x"},
        ]
        assert len(validate_conditions(conds)) == 2

    def test_empty_field_returns_error(self):
        conds = [{"field": "", "op": "eq", "value": "x"}]
        errors = validate_conditions(conds)
        assert len(errors) == 1


class TestValidateField:
    def test_allowed_fields_pass(self):
        for field in ("severity", "status", "confidence", "tags", "title"):
            _validate_field(field)  # must not raise

    def test_disallowed_field_raises(self):
        with pytest.raises(ConditionError):
            _validate_field("password")

    def test_too_deep_raises(self):
        with pytest.raises(ConditionError):
            _validate_field("a.b.c.d.e")


# ── rule_executor integration tests (mocked DB) ───────────────────────────────


def test_normalize_action_slug_accepts_ui_aliases() -> None:
    from app.api.v1.endpoints.runbook import _normalize_action_slug

    assert _normalize_action_slug("alert.close") == "close_alert"
    assert _normalize_action_slug("alert.tag") == "add_alert_tag"
    assert _normalize_action_slug("close_alert") == "close_alert"


def test_default_automation_rule_seed_is_defined() -> None:
    from app.api.v1.endpoints.runbook import DEFAULT_AUTOMATION_RULES

    assert len(DEFAULT_AUTOMATION_RULES) >= 2
    assert any(rule["action_slug"] == "add_alert_tag" for rule in DEFAULT_AUTOMATION_RULES)
    assert any(rule["action_slug"] == "create_case" for rule in DEFAULT_AUTOMATION_RULES)


def test_default_automation_rule_seed_contains_realistic_demo_rules() -> None:
    from app.api.v1.endpoints.runbook import DEFAULT_AUTOMATION_RULES

    assert len(DEFAULT_AUTOMATION_RULES) >= 10
    action_slugs = {rule["action_slug"] for rule in DEFAULT_AUTOMATION_RULES}
    assert {"add_alert_tag", "create_case", "close_alert", "block_ip", "isolate_host", "quarantine_file"} <= action_slugs


def _build_matching_subject_for_rule(rule: dict) -> dict:
    subject: dict = {
        "severity": "critical",
        "confidence": 90,
        "confidence_label": "high",
        "title": "Credential theft detected",
        "source": "identity",
        "category": "endpoint",
        "status": "new",
        "tags": [],
        "priority": 90,
    }

    for condition in rule["conditions"]:
        field = condition["field"]
        op = condition["op"]
        value = condition["value"]

        if field == "severity":
            if isinstance(value, list):
                subject["severity"] = value[0]
            elif op in {"not_in", "ne"}:
                subject["severity"] = "low"
            else:
                subject["severity"] = value
        elif field == "confidence":
            if op in {"lt", "le"}:
                threshold = float(value)
                subject["confidence"] = max(0, int(threshold) - 1)
            elif op in {"gt", "ge"}:
                threshold = float(value)
                subject["confidence"] = max(0, int(threshold) + 1)
            else:
                subject["confidence"] = int(value) if isinstance(value, str) else (value if isinstance(value, (int, float)) else 90)
        elif field == "confidence_label":
            # confidence_label is derived from confidence, but we can set it directly
            if isinstance(value, list):
                subject["confidence_label"] = value[0]
            elif op in {"not_in", "ne"}:
                subject["confidence_label"] = "low" if value != "low" else "high"
            else:
                subject["confidence_label"] = value
        elif field == "title":
            needle = str(value).lower()
            if "credential" in needle:
                subject["title"] = "Credential theft detected"
            elif "phishing" in needle:
                subject["title"] = "Phishing lure detected"
            elif "privileged" in needle:
                subject["title"] = "Privileged account suspicious activity"
            elif "ransomware" in needle:
                subject["title"] = "Ransomware execution detected"
            elif "risk" in needle:
                subject["title"] = "Risk review required"
            else:
                subject["title"] = str(value)
        elif field == "source":
            subject["source"] = value
        elif field == "category":
            subject["category"] = value
        elif field == "status":
            subject["status"] = value
        elif field == "tags":
            if isinstance(value, list):
                subject["tags"] = value
            else:
                subject["tags"] = [value]
        elif field == "priority":
            if op in {"lt", "le"}:
                subject["priority"] = max(1, int(value) - 1)
            elif op in {"gt", "ge"}:
                subject["priority"] = int(value) + 1
            else:
                subject["priority"] = int(value) if isinstance(value, str) else (value if isinstance(value, int) else 90)

    return subject


@pytest.mark.parametrize("rule", __import__("app.api.v1.endpoints.runbook", fromlist=["DEFAULT_AUTOMATION_RULES"]).DEFAULT_AUTOMATION_RULES, ids=lambda rule: rule["name"])
def test_each_default_rule_matches_a_realistic_subject(rule: dict) -> None:
    subject = _build_matching_subject_for_rule(rule)
    assert evaluate_all(rule["conditions"], subject) is True


@pytest.mark.parametrize("rule", __import__("app.api.v1.endpoints.runbook", fromlist=["DEFAULT_AUTOMATION_RULES"]).DEFAULT_AUTOMATION_RULES, ids=lambda rule: rule["name"])
def test_each_default_rule_rejects_a_non_matching_subject(rule: dict) -> None:
    subject = _build_matching_subject_for_rule(rule)

    if "severity" in subject:
        subject["severity"] = "critical" if subject["severity"] != "critical" else "low"
    if "confidence" in subject:
        subject["confidence"] = 0 if subject["confidence"] > 0 else 100
    if "confidence_label" in subject:
        subject["confidence_label"] = "low" if subject["confidence_label"] != "low" else "high"
    if "category" in subject:
        subject["category"] = "endpoint" if subject["category"] != "endpoint" else "network"
    if "title" in subject:
        subject["title"] = "Routine login activity"
    if "status" in subject:
        subject["status"] = "closed"
    if "tags" in subject:
        subject["tags"] = []
    if "priority" in subject:
        subject["priority"] = 1

    assert evaluate_all(rule["conditions"], subject) is False


@pytest.mark.parametrize("rule", __import__("app.api.v1.endpoints.runbook", fromlist=["DEFAULT_AUTOMATION_RULES"]).DEFAULT_AUTOMATION_RULES, ids=lambda rule: rule["name"])
def test_each_default_rule_executes_through_rule_executor(rule: dict) -> None:
    import asyncio

    from app.services.runbook.rule_executor import _apply_rule

    db = AsyncMock()
    db.execute = AsyncMock(return_value=MagicMock())

    mock_gate = GateDecision(
        action=rule["action_slug"],
        decision=AutonomyDecision.AUTO,
        allowed=True,
        autonomy_level=rule["autonomy_level"],
        layer="defaults",
        thresholds=make_thresholds(0.5, 0.7, 0.9),
        reason="test-pass",
        approval_required=False,
    )

    with (
        patch("app.services.runbook.rule_executor.evaluate", new_callable=AsyncMock, return_value=mock_gate),
        patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as mock_record,
    ):
        asyncio.run(
            _apply_rule(
                db,
                tenant_id=uuid.uuid4(),
                subject_type="alert",
                subject_id=uuid.uuid4(),
                subject_fields=_build_matching_subject_for_rule(rule),
                rule_id=uuid.uuid4(),
                rule_name=rule["name"],
                action_slug=rule["action_slug"],
                action_params=rule["action_params"],
                conditions=rule["conditions"],
                dry_run=bool(rule["dry_run"]),
            )
        )

    mock_record.assert_called_once()
    assert mock_record.call_args.kwargs["action_name"] == rule["action_slug"]
    assert mock_record.call_args.kwargs["status"] in {"simulated", "recorded", "executed"}


def test_preview_rule_for_alerts_reports_match_and_status() -> None:
    from app.api.v1.endpoints.runbook import _preview_rule_for_subjects

    rule = {
        "name": "Critical alerts -> case",
        "trigger_type": "alert.created",
        "conditions": [{"field": "severity", "op": "eq", "value": "critical"}],
        "action_slug": "create_case",
        "autonomy_level": "L2",
        "dry_run": True,
    }

    results = _preview_rule_for_subjects(
        rule,
        [
            {
                "id": "11111111-1111-4111-8111-111111111111",
                "severity": "critical",
                "confidence": 90,
                "title": "Credential theft detected",
                "source": "identity",
                "tags": [],
                "status": "new",
                "priority": 90,
                "category": "endpoint",
            }
        ],
    )

    assert len(results) == 1
    assert results[0]["matched"] is True
    assert results[0]["status"] in {"simulated", "recorded", "executed"}
    assert results[0]["action_slug"] == "create_case"


def test_json_param_serializes_jsonb_values() -> None:
    import json

    from app.api.v1.endpoints.runbook import _json_param

    payload = {"tag": "high-risk"}
    conds = [{"field": "severity", "op": "in", "value": ["high", "critical"]}]
    assert json.loads(_json_param(payload)) == payload
    assert json.loads(_json_param(conds)) == conds


def test_runbook_envelope_exposes_operational_workflow_summary() -> None:
    from app.services.runbook.read import RunbookEnvelope

    envelope = RunbookEnvelope(
        subject_type="alert",
        subject_id="11111111-1111-4111-8111-111111111111",
        total_steps=0,
        workflow_name="Alert operational workflow",
        workflow_objective="Record the operational steps, evidence, and policy decisions taken on this alert.",
        supporting_rule_count=3,
        steps=[],
        empty=True,
        empty_reason="No governed actions recorded yet.",
    )

    assert envelope.workflow_name == "Alert operational workflow"
    assert "operational steps" in envelope.workflow_objective
    assert envelope.supporting_rule_count == 3


class TestRunRulesForTrigger:
    """Test that the executor applies rules and writes ledger rows correctly."""

    def _make_db(self, rules=None):
        db = AsyncMock()
        result = MagicMock()
        result.fetchall = MagicMock(return_value=rules or [])
        db.execute = AsyncMock(return_value=result)
        return db

    def test_no_rules_does_nothing(self):
        import asyncio
        from app.services.runbook.rule_executor import run_rules_for_trigger

        db = self._make_db(rules=[])
        asyncio.run(
            run_rules_for_trigger(
                db,
                tenant_id=uuid.uuid4(),
                trigger_type="alert.created",
                subject_type="alert",
                subject_id=uuid.uuid4(),
                subject_fields={"severity": "critical"},
            )
        )
        # Only the fetch query ran; no record_event call
        db.execute.assert_called_once()

    def test_conditions_not_met_no_ledger_row(self):
        """A rule whose conditions fail must not write a ledger row."""
        import asyncio
        from app.services.runbook.rule_executor import _apply_rule

        db = self._make_db()
        with patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as mock_record:
            asyncio.run(
                _apply_rule(
                    db,
                    tenant_id=uuid.uuid4(),
                    subject_type="alert",
                    subject_id=uuid.uuid4(),
                    subject_fields={"severity": "medium"},
                    rule_id=uuid.uuid4(),
                    rule_name="test-rule",
                    action_slug="alert.close",
                    action_params={},
                    conditions=[{"field": "severity", "op": "eq", "value": "critical"}],
                    dry_run=True,
                )
            )
        mock_record.assert_not_called()

    def test_conditions_met_writes_simulated_when_dry_run(self):
        import asyncio
        from app.services.runbook.rule_executor import _apply_rule

        db = self._make_db()
        mock_gate = GateDecision(
            action="alert.close",
            decision=AutonomyDecision.AUTO,
            allowed=True,
            autonomy_level="L2",
            layer="defaults",
            thresholds=make_thresholds(0.5, 0.7, 0.9),
            reason="auto",
            approval_required=False,
        )

        with (
            patch("app.services.runbook.rule_executor.evaluate", new_callable=AsyncMock, return_value=mock_gate),
            patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as mock_record,
        ):
            asyncio.run(
                _apply_rule(
                    db,
                    tenant_id=uuid.uuid4(),
                    subject_type="alert",
                    subject_id=uuid.uuid4(),
                    subject_fields={"severity": "critical", "confidence": 90},
                    rule_id=uuid.uuid4(),
                    rule_name="close-critical",
                    action_slug="alert.close",
                    action_params={},
                    conditions=[{"field": "severity", "op": "eq", "value": "critical"}],
                    dry_run=True,
                )
            )

        mock_record.assert_called_once()
        call_kwargs = mock_record.call_args.kwargs
        assert call_kwargs["status"] == "simulated"
        assert call_kwargs["action_name"] == "alert.close"

    def test_deny_decision_writes_denied_status(self):
        import asyncio
        from app.services.runbook.rule_executor import _apply_rule

        db = self._make_db()
        mock_gate = GateDecision(
            action="containment.isolate_host",
            decision=AutonomyDecision.REJECT,
            allowed=False,
            autonomy_level="L0",
            layer="defaults",
            thresholds=make_thresholds(0.5, 0.7, 0.9),
            reason="blast_radius_too_high",
            approval_required=False,
        )

        with (
            patch("app.services.runbook.rule_executor.evaluate", new_callable=AsyncMock, return_value=mock_gate),
            patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as mock_record,
        ):
            asyncio.run(
                _apply_rule(
                    db,
                    tenant_id=uuid.uuid4(),
                    subject_type="alert",
                    subject_id=uuid.uuid4(),
                    subject_fields={"severity": "critical", "confidence": 90},
                    rule_id=uuid.uuid4(),
                    rule_name="isolate-on-critical",
                    action_slug="containment.isolate_host",
                    action_params={},
                    conditions=[{"field": "severity", "op": "eq", "value": "critical"}],
                    dry_run=False,
                )
            )

        call_kwargs = mock_record.call_args.kwargs
        assert call_kwargs["status"] == "denied"

    def test_executor_uses_db_aware_gate_with_normalized_confidence(self):
        """Regression: the executor must resolve policy through ``evaluate``.

        It previously called the pure ``decide`` with a session as the action
        name and ``await``-ed a synchronous function, so every matching rule
        raised and was swallowed — rules never recorded anything. The gate call
        is asserted directly here instead of being mocked away.
        """
        import asyncio
        from app.services.runbook.rule_executor import _apply_rule

        db = self._make_db()
        mock_gate = GateDecision(
            action="close_alert",
            decision=AutonomyDecision.AUTO,
            allowed=True,
            autonomy_level="L3",
            layer="defaults",
            thresholds=make_thresholds(0.5, 0.7, 0.9),
            reason="ok",
            approval_required=False,
        )

        with (
            patch(
                "app.services.runbook.rule_executor.evaluate",
                new_callable=AsyncMock,
                return_value=mock_gate,
            ) as mock_evaluate,
            patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock),
        ):
            asyncio.run(
                _apply_rule(
                    db,
                    tenant_id=uuid.uuid4(),
                    subject_type="alert",
                    subject_id=uuid.uuid4(),
                    # Alert rows carry confidence as an int 0–100.
                    subject_fields={"severity": "critical", "confidence": 90},
                    rule_id=uuid.uuid4(),
                    rule_name="close-critical",
                    action_slug="close_alert",
                    action_params={},
                    conditions=[{"field": "severity", "op": "eq", "value": "critical"}],
                    dry_run=True,
                )
            )

        mock_evaluate.assert_awaited_once()
        kwargs = mock_evaluate.await_args.kwargs
        assert kwargs["action"] == "close_alert"
        assert kwargs["confidence"] == 0.9, "0–100 confidence must be normalised for the gate"


# ── linked playbook execution (rule.playbook_ref) ────────────────────────────


_RUN_ID = "22222222-2222-4222-8222-222222222222"


def _already_started_playbook_id() -> str:
    return "22222222-2222-4222-8222-222222222222"


def _claim_db(existing_run_id: str | None = None, *, claim_broken: bool = False) -> AsyncMock:
    """Session whose only interesting query is the at-most-once claim lookup."

    def _execute(statement, *args, **kwargs):
        sql = str(statement)
        if "playbook_run_id' AS run_id" in sql:
            if claim_broken:
                raise RuntimeError("ledger is unreachable")
            result = MagicMock()
            result.first = MagicMock(return_value=(existing_run_id,) if existing_run_id else None)
            return result
        result = MagicMock()
        result.rowcount = 1
        result.fetchall = MagicMock(return_value=[])
        return result

    db = AsyncMock()
    db.execute = AsyncMock(side_effect=_execute)
    return db


def _allowed_gate(*, approval_required: bool = False) -> GateDecision:
    return GateDecision(
        action="isolate_host",
        decision=AutonomyDecision.AUTO,
        allowed=True,
        autonomy_level="L3",
        layer="defaults",
        thresholds=make_thresholds(0.5, 0.7, 0.9),
        reason="test-pass",
        approval_required=approval_required,
    )


async def _apply_with_playbook(
    db: AsyncMock,
    *,
    playbook_ref: str | None,
    dry_run: bool,
    rule_id: uuid.UUID,
    subject_id: uuid.UUID,
) -> None:
    from app.services.runbook.rule_executor import _apply_rule

    await _apply_rule(
        db,
        tenant_id=uuid.uuid4(),
        subject_type="alert",
        subject_id=subject_id,
        subject_fields={"severity": "critical", "confidence": 90, "title": "Credential theft"},
        rule_id=rule_id,
        rule_name="isolate-on-critical",
        action_slug="isolate_host",
        action_params={},
        conditions=[{"field": "severity", "op": "eq", "value": "critical"}],
        dry_run=dry_run,
        playbook_ref=playbook_ref,
        trigger_type="alert.created",
    )


class TestLinkedPlaybookStart:
    "A rule that names a playbook starts it -- once, and only when allowed."

    def test_allowed_rule_starts_the_playbook_with_alert_context(self):
        db = _claim_db()
        rule_id, subject_id = uuid.uuid4(), uuid.uuid4()

        with (
            patch(
                "app.services.runbook.rule_executor.evaluate",
                new_callable=AsyncMock,
                return_value=_allowed_gate(),
            ),
            patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as record,
            patch(
                "app.services.runbook.rule_executor.start_playbook_run",
                new_callable=AsyncMock,
                return_value=PlaybookStart(run_id=_RUN_ID),
            ) as start,
        ):
            asyncio.run(
                _apply_with_playbook(
                    db,
                    playbook_ref="pb-isolate-host",
                    dry_run=False,
                    rule_id=rule_id,
                    subject_id=subject_id,
                )
            )

        start.assert_awaited_once()
        kwargs = start.await_args.kwargs
        assert kwargs["playbook_id"] == "pb-isolate-host"
        assert kwargs["dry_run"] is False
        # The context is what lets the agents service attach a parked run's gate
        # task to this alert, so the approval lands in this alert's Action Plan.
        assert kwargs["context"]["alert_id"] == str(subject_id)
        assert kwargs["context"]["rule_id"] == str(rule_id)
        assert kwargs["context"]["severity"] == "critical"
        assert kwargs["dedupe_key"].startswith(f"automation:{rule_id}:")
        assert len(kwargs["dedupe_key"]) <= 128

        # Cause first, effect second: the rule's row, then the run it started.
        assert record.await_count == 2
        action_row = record.await_args_list[0].kwargs
        run_row = record.await_args_list[1].kwargs

        assert action_row["action_name"] == "isolate_host"
        assert action_row["input_payload"]["playbook"]["run_id"] == _RUN_ID
        assert action_row["input_payload"]["playbook"]["started"] is True
        assert "started" in action_row["summary"]

        assert run_row["action_name"] == "playbook.run"
        assert run_row["status"] == "executed"
        assert run_row["output_payload"]["playbook_run_id"] == _RUN_ID
        assert run_row["idempotency_key"] == kwargs["dedupe_key"]

    def test_dry_run_rule_simulates_instead_of_executing(self):
        db = _claim_db()

        with (
            patch(
                "app.services.runbook.rule_executor.evaluate",
                new_callable=AsyncMock,
                return_value=_allowed_gate(),
            ),
            patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as record,
            patch(
                "app.services.runbook.rule_executor.start_playbook_run",
                new_callable=AsyncMock,
                return_value=PlaybookStart(run_id=_RUN_ID),
            ) as start,
        ):
            asyncio.run(
                _apply_with_playbook(
                    db,
                    playbook_ref="pb-isolate-host",
                    dry_run=True,
                    rule_id=uuid.uuid4(),
                    subject_id=uuid.uuid4(),
                )
            )

        assert start.await_args.kwargs["dry_run"] is True
        run_row = record.await_args_list[1].kwargs
        assert run_row["status"] == "simulated", "a dry run must never read as executed"

    def test_already_claimed_run_is_not_started_twice(self):
        db = _claim_db(existing_run_id=_RUN_ID)

        with (
            patch(
                "app.services.runbook.rule_executor.evaluate",
                new_callable=AsyncMock,
                return_value=_allowed_gate(),
            ),
            patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as record,
            patch(
                "app.services.runbook.rule_executor.start_playbook_run",
                new_callable=AsyncMock,
                return_value=PlaybookStart(run_id=_RUN_ID),
            ) as start,
        ):
            asyncio.run(
                _apply_with_playbook(
                    db,
                    playbook_ref="pb-isolate-host",
                    dry_run=False,
                    rule_id=uuid.uuid4(),
                    subject_id=uuid.uuid4(),
                )
            )

        start.assert_not_awaited()
        # One row: the rule's own line, which points at the run that exists.
        assert record.await_count == 1
        action_row = record.await_args_list[0].kwargs
        assert action_row["input_payload"]["playbook"]["run_id"] == _RUN_ID
        assert "already started" in action_row["summary"]

    def test_unreadable_claim_fails_closed(self):
        """No proof that it is not already running means no second run."""
        db = _claim_db(claim_broken=True)

        with (
            patch(
                "app.services.runbook.rule_executor.evaluate",
                new_callable=AsyncMock,
                return_value=_allowed_gate(),
            ),
            patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as record,
            patch(
                "app.services.runbook.rule_executor.start_playbook_run",
                new_callable=AsyncMock,
                return_value=PlaybookStart(run_id=_RUN_ID),
            ) as start,
        ):
            asyncio.run(
                _apply_with_playbook(
                    db,
                    playbook_ref="pb-isolate-host",
                    dry_run=False,
                    rule_id=uuid.uuid4(),
                    subject_id=uuid.uuid4(),
                )
            )

        start.assert_not_awaited()
        assert record.await_count == 1
        reason = record.await_args_list[0].kwargs["input_payload"]["playbook"]["reason"]
        assert "could not verify" in reason

    def test_gate_requiring_approval_does_not_start_the_playbook(self):
        """The playbook must not act ahead of the approval the policy demands."""
        db = _claim_db()

        with (
            patch(
                "app.services.runbook.rule_executor.evaluate",
                new_callable=AsyncMock,
                return_value=_allowed_gate(approval_required=True),
            ),
            patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as record,
            patch(
                "app.services.runbook.rule_executor.ensure_approval_gate_task",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "app.services.runbook.rule_executor.start_playbook_run",
                new_callable=AsyncMock,
                return_value=PlaybookStart(run_id=_RUN_ID),
            ) as start,
        ):
            asyncio.run(
                _apply_with_playbook(
                    db,
                    playbook_ref="pb-isolate-host",
                    dry_run=False,
                    rule_id=uuid.uuid4(),
                    subject_id=uuid.uuid4(),
                )
            )

        start.assert_not_awaited()
        assert record.await_count == 1
        outcome = record.await_args_list[0].kwargs["input_payload"]["playbook"]
        assert outcome["started"] is False
        assert "awaiting analyst approval" in outcome["reason"]

    def test_refusal_from_the_agents_service_is_recorded(self):
        db = _claim_db()

        with (
            patch(
                "app.services.runbook.rule_executor.evaluate",
                new_callable=AsyncMock,
                return_value=_allowed_gate(),
            ),
            patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as record,
            patch(
                "app.services.runbook.rule_executor.start_playbook_run",
                new_callable=AsyncMock,
                return_value=PlaybookStart(
                    reason="playbook has an approval step and AISOC_PLAYBOOK_RESUME is off"
                ),
            ),
        ):
            asyncio.run(
                _apply_with_playbook(
                    db,
                    playbook_ref="pb-isolate-host",
                    dry_run=False,
                    rule_id=uuid.uuid4(),
                    subject_id=uuid.uuid4(),
                )
            )

        # Nothing ran, so nothing claims the at-most-once key: switching the
        # flag on lets the next evaluation start it.
        assert record.await_count == 1
        outcome = record.await_args_list[0].kwargs["input_payload"]["playbook"]
        assert outcome["started"] is False
        assert "AISOC_PLAYBOOK_RESUME" in outcome["reason"]

    def test_rule_without_a_playbook_never_calls_the_agents_service(self):
        db = _claim_db()

        with (
            patch(
                "app.services.runbook.rule_executor.evaluate",
                new_callable=AsyncMock,
                return_value=_allowed_gate(),
            ),
            patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as record,
            patch(
                "app.services.runbook.rule_executor.start_playbook_run",
                new_callable=AsyncMock,
            ) as start,
        ):
            asyncio.run(
                _apply_with_playbook(
                    db,
                    playbook_ref=None,
                    dry_run=True,
                    rule_id=uuid.uuid4(),
                    subject_id=uuid.uuid4(),
                )
            )

        start.assert_not_awaited()
        assert record.await_count == 1
        assert record.await_args_list[0].kwargs["input_payload"]["playbook"] is None


class TestLinkApprovalGatesToRunbookTasks:
    "When a Rules DB succeeds for a playbook-ref rule whose gate needs approval,
    the executor opens a Runbook task instead of starting the run."

    def test_gate_requiring_approval_opens_a_runbook_task(self):
        "An analyst-facing task is the only artifact on a policy-gated start."
        db = AsyncMock()

        async def _execute(sql, *args, **kwargs):
            result = MagicMock()
            result.rowcount = 1
            result.fetchall = MagicMock(return_value=[])
            return result

        db.execute = AsyncMock(side_effect=_execute)

        rule_id, subject_id = uuid.uuid4(), uuid.uuid4()

        with (
            patch(
                "app.services.runbook.rule_executor.evaluate",
                new_callable=AsyncMock,
                return_value=_allowed_gate(approval_required=True),
            ),
            patch("app.services.runbook.rule_executor.record_event", new_callable=AsyncMock) as record,
            patch(
                "app.services.runbook.rule_executor.start_playbook_run",
                new_callable=AsyncMock,
            ) as start,
            patch(
                "app.services.runbook.rule_executor.ensure_approval_gate_task",
                new_callable=AsyncMock,
                return_value=True,
            ) as ensure,
        ):
            asyncio.run(
                _apply_with_playbook(
                    db,
                    playbook_ref="pb-isolate-host",
                    dry_run=False,
                    rule_id=rule_id,
                    subject_id=subject_id,
                )
            )

        start.assert_not_awaited()
        ensure.assert_awaited_once()
        ensure_kwargs = ensure.await_args.kwargs
        assert ensure_kwargs["rule_id"] == rule_id
        assert ensure_kwargs["playbook_ref"] == "pb-isolate-host"
        assert ensure_kwargs["subject_id"] == subject_id
        assert ensure_kwargs["tenant_id"] == ensure_kwargs["assigned_tenant_id"]
        assert record.await_count == 1
        outcome = record.await_args_list[0].kwargs["input_payload"]["playbook"]
        assert outcome["started"] is False
        assert "awaiting analyst approval" in outcome["reason"]
