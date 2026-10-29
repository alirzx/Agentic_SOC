
# ── linked playbook execution (rule.playbook_ref) ────────────────────────────

import asyncio  # noqa: E402

from app.services.agents_client import PlaybookStart  # noqa: E402

_RUN_ID = "22222222-2222-4222-8222-222222222222"


def _claim_db(existing_run_id: str | None = None, *, claim_broken: bool = False) -> AsyncMock:
    """Session whose only interesting query is the at-most-once claim lookup."""
    db = AsyncMock()

    async def _execute(statement, *args, **kwargs):
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

    db.execute = AsyncMock(side_effect=_execute)
    return db


def _allowing_gate(*, approval_required: bool = False, allowed: bool = True) -> GateDecision:
    return GateDecision(
        action="isolate_host",
        decision=AutonomyDecision.AUTO if allowed else AutonomyDecision.REJECT,
        allowed=allowed,
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
                return_value=_allowing_gate(),
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
                return_value=_allowing_gate(),
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
                return_value=_allowing_gate(),
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
                return_value=_allowing_gate(),
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
                return_value=_allowing_gate(approval_required=True),
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
                return_value=_allowing_gate(),
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
                return_value=_allowing_gate(),
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
