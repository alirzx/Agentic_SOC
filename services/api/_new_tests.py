@pytest.mark.parametrize("rule", __import__("app.api.v1.endpoints.runbook",
                                   fromlist=["DEFAULT_AUTOMATION_RULES"]).DEFAULT_AUTOMATION_RULES,
                         ids=lambda rule: rule["name"])
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


def _claim_db(existing_run_id: str | None = None, *, claim_broken: bool = False) -> AsyncMock:
    """Session whose only interesting query is the at-most-once claim lookup."""

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
    """A rule that names a playbook starts it — once, and only when allowed."""

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
    """When a Rules DB succeeds for a playbook-ref rule whose gate needs approval,
    the executor opens a Runbook task instead of starting the run."""

    def test_gate_requiring_approval_opens_a_runbook_task(self):
        """An analyst-facing task is the only artifact on a policy-gated start."""
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
