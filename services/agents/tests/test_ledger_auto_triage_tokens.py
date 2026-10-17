"""Regression: auto-triage INSERT must set total_tokens (NOT NULL).

Live failure mode (demo stack): investigation_runs.total_tokens is NOT NULL
without a reliable Postgres DEFAULT when the table was created via ORM
create_all. Omitting the column on INSERT then violates the constraint and
dead-letters every Kafka auto-triage message at stage=persist.
"""

from __future__ import annotations

import inspect

from app.investigator import ledger as ledger_module


def test_persist_auto_triage_insert_sql_sets_token_columns() -> None:
    """Source-level guard so the INSERT cannot regress to omitting totals."""
    source = inspect.getsource(ledger_module.persist_auto_triage)
    assert "total_tokens" in source
    assert "total_cost_usd" in source
    assert "iterations" in source
    compact = source.replace(" ", "").replace("\n", "")
    assert "'running',0,0,0" in compact


def test_start_run_insert_sql_sets_token_columns() -> None:
    source = inspect.getsource(ledger_module.start_run)
    assert "total_tokens" in source
    compact = source.replace(" ", "").replace("\n", "")
    assert "'running',0,0,0" in compact
