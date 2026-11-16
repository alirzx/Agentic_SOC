"""Operational readiness gates for campaign-corr:v2 (no Production I/O)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.services.campaign_correlation import (
    CORRELATION_VERSION,
    DEFAULT_CROSS_DOMAIN_THRESHOLD,
    DEFAULT_LINK_THRESHOLD,
    HOST_CENTRIC_DISCOVERY_SQL,
    WEIGHT_FAMILY,
    WEIGHT_HOST,
    WEIGHT_MITRE,
    WEIGHT_TEMPORAL_MAX,
    WEIGHT_USER,
    host_centric_discovery_params,
    host_centric_sql_filter_clause,
)
from app.services.campaign_reconcile import reconcile_campaign_case


T0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


def test_correlation_version_stable():
    assert CORRELATION_VERSION == "campaign-corr:v2"


def test_thresholds_not_weakened():
    assert DEFAULT_LINK_THRESHOLD == 0.55
    assert DEFAULT_CROSS_DOMAIN_THRESHOLD == 0.70
    assert WEIGHT_HOST == 0.35
    assert WEIGHT_USER == 0.25
    assert WEIGHT_TEMPORAL_MAX == 0.15
    assert WEIGHT_MITRE == 0.10
    assert WEIGHT_FAMILY == 0.15


def test_host_centric_sql_has_safety_predicates():
    sql = HOST_CENTRIC_DISCOVERY_SQL
    for token in (
        "tenant_id = :tid",
        "case_id IS NULL",
        "window_start",
        "window_end",
        "norm_hosts",
        "eligible_disps",
        "LIMIT :lim",
    ):
        assert token in sql
    # No string concatenation of host values into SQL text
    assert '"+' not in sql
    assert "f\"" not in sql


def test_sql_filter_clause_parameterized():
    single = host_centric_sql_filter_clause(multi_host=False)
    multi = host_centric_sql_filter_clause(multi_host=True)
    assert ":norm_host" in single
    assert ":norm_hosts" in multi
    assert "ANY" in multi


def test_discovery_params_seed_relative_window():
    params = host_centric_discovery_params(
        tenant_id=uuid4(),
        seed_id=uuid4(),
        seed_hosts=["Server-01.", "server-01", "bad host"],
        seed_ts=T0.timestamp(),
        temporal_window_seconds=86400,
    )
    assert params is not None
    assert params["norm_hosts"] == ["server-01"]
    assert params["window_end"] - params["window_start"] == timedelta(seconds=172800)


@pytest.mark.asyncio
async def test_reconcile_dry_run_default_and_no_writes():
    """dry_run defaults True; dry-run path must not UPDATE or commit."""
    case_id = uuid4()
    tenant_id = uuid4()
    seed = {
        "id": uuid4(),
        "title": "Soorin-Web-SQL Injection Attempts",
        "severity": "high",
        "disposition": "true_positive",
        "affected_hosts": [],
        "affected_ips": ["10.1.1.1"],
        "affected_users": [],
        "mitre_techniques": [],
        "created_at": T0,
        "event_time": T0,
        "raw_event": {},
        "llm_payload": {},
        "case_id": case_id,
        "tags": [],
        "funnel_stage": "cased",
        "confidence": 80,
        "ai_score": None,
        "rule_id": "r1",
        "rule_name": "r1",
    }
    noise = {
        **seed,
        "id": uuid4(),
        "title": "Soorin-Endpoint-Powershell Invoke Command",
        "affected_ips": [],
        "affected_hosts": ["other-host"],
        "event_time": T0 + timedelta(minutes=2),
        "created_at": T0 + timedelta(minutes=2),
    }

    case_row = {
        "id": case_id,
        "title": "Suspected intrusion campaign",
        "description": "Entities: (no strong entity)",
        "severity": "high",
        "status": "open",
        "alert_ids": [seed["id"], noise["id"]],
        "tags": {},
        "created_by": "agentic-funnel-backfill",
        "opened_at": T0,
    }

    execute = AsyncMock()
    # First call: load case; second: load alerts
    case_result = MagicMock()
    case_result.mappings.return_value.first.return_value = case_row
    alerts_result = MagicMock()
    alerts_result.mappings.return_value.all.return_value = [seed, noise]
    execute.side_effect = [case_result, alerts_result]

    db = MagicMock()
    db.execute = execute
    db.commit = AsyncMock()

    # Explicitly omit dry_run — must default to True (safe).
    result = await reconcile_campaign_case(db, tenant_id=tenant_id, case_id=case_id)
    assert result["dry_run"] is True
    assert result["action"] == "dry_run"
    # Only SELECTs for load — no UPDATE/commit
    assert db.commit.await_count == 0
    for call in execute.await_args_list:
        sql = str(call.args[0]) if call.args else ""
        assert "UPDATE" not in sql.upper()


@pytest.mark.asyncio
async def test_reconcile_apply_requires_explicit_false():
    """Applying mutations requires dry_run=False explicitly."""
    case_id = uuid4()
    tenant_id = uuid4()
    only = {
        "id": uuid4(),
        "title": "solo",
        "severity": "high",
        "disposition": "true_positive",
        "affected_hosts": ["h"],
        "affected_ips": [],
        "affected_users": [],
        "mitre_techniques": [],
        "created_at": T0,
        "event_time": T0,
        "raw_event": {},
        "llm_payload": {},
        "case_id": case_id,
        "tags": [],
        "funnel_stage": "cased",
        "confidence": 90,
        "ai_score": None,
        "rule_id": "r",
        "rule_name": "r",
    }
    case_row = {
        "id": case_id,
        "title": "solo",
        "description": "",
        "severity": "high",
        "status": "open",
        "alert_ids": [only["id"]],
        "tags": {},
        "created_by": "agentic-funnel-backfill",
        "opened_at": T0,
    }
    execute = AsyncMock()
    case_result = MagicMock()
    case_result.mappings.return_value.first.return_value = case_row
    alerts_result = MagicMock()
    alerts_result.mappings.return_value.all.return_value = [only]
    execute.side_effect = [case_result, alerts_result]
    db = MagicMock()
    db.execute = execute
    db.commit = AsyncMock()

    result = await reconcile_campaign_case(
        db, tenant_id=tenant_id, case_id=case_id
    )  # default dry_run
    assert result["action"] == "noop" or result["dry_run"] is True
    assert db.commit.await_count == 0
