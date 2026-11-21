"""
Integration tests for deduplication and graph engine alert discovery.

Tests verify that:
1. Deduplication preserves alert visibility for graph engine
2. Deduplicated alerts with case_id remain in their cases
3. Graph engine can still create new cases from available alerts
4. Alert counts are consistent across all endpoints

Requires: AISOC_RUN_INTEGRATION=1 pytest -m integration
    to run against a live, migrated PostgreSQL database.
"""

from __future__ import annotations

import os
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.getenv("AISOC_RUN_INTEGRATION"),
        reason="set AISOC_RUN_INTEGRATION=1 to run graph engine integration tests against Postgres",
    ),
]


# ════════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ════════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="function")
async def integration_db():
    """Create test database session with isolated tenant."""
    from app.db.database import AsyncSessionLocal, Base, engine
    from app.models.tenant import Tenant

    # Create all tables if they don't exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create session with a dedicated test tenant
    async with AsyncSessionLocal() as session:
        tenant_id = uuid4()
        session.add(
            Tenant(
                id=tenant_id,
                name="Graph Engine Test Tenant",
                slug=f"graph-test-{uuid4().hex[:8]}",
                mssp_role="standalone",
            )
        )
        await session.commit()
        session.tenant_id = tenant_id

        yield session

    # Cleanup
    try:
        async with AsyncSessionLocal() as session:
            # Clear observations, cases, and alerts for this tenant
            for table in ("correlation_observations", "aisoc_cases", "alerts"):
                await session.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :tid"),
                    {"tid": str(tenant_id)},
                )
            await session.execute(
                text("DELETE FROM tenants WHERE id = :tid"), {"tid": str(tenant_id)}
            )
            await session.commit()
    except Exception:
        pass  # Ignore cleanup errors


@pytest.mark.asyncio
async def test_graph_engine_alert_coverage(integration_db: AsyncSession):
    """
    Verify graph engine has access to most alerts (99%+ coverage).
    Ensures deduplication didn't hide alerts from correlation engine.
    """
    tenant_id = integration_db.tenant_id
    async with integration_db.begin():
        # Count total alerts
        total_result = await integration_db.execute(text('''
            SELECT COUNT(*) as total
            FROM alerts
            WHERE tenant_id = :tid
        ''').bindparams(tid=tenant_id))
        total_alerts = total_result.scalar()
        
        if total_alerts == 0:
            pytest.skip("No alerts in database")
        
        # Count alerts in correlation_observations
        obs_result = await integration_db.execute(text('''
            SELECT COUNT(DISTINCT alert_id) as unique_alerts
            FROM (
                SELECT DISTINCT unnest(alert_ids) as alert_id
                FROM correlation_observations
                WHERE tenant_id = :tid
            ) t
        ''').bindparams(tid=tenant_id))
        
        obs_alert_count = obs_result.scalar() or 0
        
        # Verify coverage >= 99%
        coverage = (obs_alert_count / total_alerts) * 100 if total_alerts > 0 else 0
        
        assert coverage >= 99.0, (
            f"Graph engine alert coverage too low: {obs_alert_count}/{total_alerts} "
            f"({coverage:.1f}%). Expected >= 99%"
        )


@pytest.mark.asyncio
async def test_deduplicated_alerts_in_observations(integration_db: AsyncSession):
    """
    Verify that deduplicated alerts are still included in correlation_observations.
    Critical for graph engine to correlate deduplicated events.
    """
    tenant_id = integration_db.tenant_id
    async with integration_db.begin():
        # Get total deduplicated alerts
        total_dedup_result = await integration_db.execute(text('''
            SELECT COUNT(*) as total_dedup
            FROM alerts
            WHERE funnel_stage = 'deduplicated'
            AND tenant_id = :tid
        ''').bindparams(tid=tenant_id))
        
        total_dedup = total_dedup_result.scalar() or 0
        
        if total_dedup == 0:
            pytest.skip("No deduplicated alerts in database")
        
        # Count deduplicated alerts in observations
        dedup_in_obs_result = await integration_db.execute(text('''
            SELECT COUNT(DISTINCT a.id) as dedup_alerts_in_obs
            FROM alerts a
            WHERE a.funnel_stage = 'deduplicated'
            AND a.tenant_id = :tid
            AND EXISTS (
                SELECT 1 
                FROM correlation_observations co
                WHERE co.tenant_id = a.tenant_id
                AND a.id = ANY(co.alert_ids)
            )
        ''').bindparams(tid=tenant_id))
        
        dedup_in_obs = dedup_in_obs_result.scalar() or 0
        coverage = (dedup_in_obs / total_dedup) * 100 if total_dedup > 0 else 0
        
        assert coverage >= 99.0, (
            f"Deduplicated alert observation coverage too low: {dedup_in_obs}/{total_dedup} "
            f"({coverage:.1f}%). Expected >= 99%"
        )


@pytest.mark.asyncio
async def test_case_membership_preserved_after_dedup(integration_db: AsyncSession):
    """
    Verify that alerts with case_id maintain their case membership after deduplication.
    Tests the two-path logic in exact_dedupe.py.
    """
    tenant_id = integration_db.tenant_id
    async with integration_db.begin():
        # Get a case with alerts
        case_result = await integration_db.execute(text('''
            SELECT id, alert_ids
            FROM aisoc_cases
            WHERE creation_method = 'graph_correlation'
            AND tenant_id = :tid
            AND array_length(alert_ids, 1) > 0
            LIMIT 1
        ''').bindparams(tid=tenant_id))
        
        case_row = case_result.fetchone()
        if not case_row:
            pytest.skip("No graph_correlation cases in database")
        
        case_id = case_row[0]
        alert_ids_in_case = case_row[1] or []
        case_alert_count = len(alert_ids_in_case)
        
        # Verify all alerts in case exist in DB
        existing_result = await integration_db.execute(text(f'''
            SELECT COUNT(*) as cnt
            FROM alerts
            WHERE id = ANY(ARRAY{alert_ids_in_case!r}::uuid[])
            AND tenant_id = :tid
        ''').bindparams(tid=tenant_id))
        
        existing_count = existing_result.scalar() or 0
        
        assert existing_count == case_alert_count, (
            f"Case {case_id} has {case_alert_count} alert_ids but only "
            f"{existing_count} exist in alerts table"
        )
        
        # Verify all case alerts still have correct case_id or are deduplicated
        # (deduplicated alerts with case_id should preserve the case_id)
        invalid_result = await integration_db.execute(text(f'''
            SELECT COUNT(*) as cnt
            FROM alerts
            WHERE id = ANY(ARRAY{alert_ids_in_case!r}::uuid[])
            AND tenant_id = :tid
            AND case_id IS NOT NULL
            AND case_id != :case_id
        ''').bindparams(tid=tenant_id, case_id=case_id))
        
        invalid_count = invalid_result.scalar() or 0
        
        assert invalid_count == 0, (
            f"Case {case_id} has {invalid_count} alerts pointing to different cases"
        )


@pytest.mark.asyncio
async def test_alert_counts_consistency_across_endpoints(integration_db: AsyncSession):
    """
    Verify alert counts are consistent between:
    - aisoc_cases.alert_ids (list endpoint)
    - correlation_observations (modal endpoint)
    """
    tenant_id = integration_db.tenant_id
    async with integration_db.begin():
        # Get a case
        case_result = await integration_db.execute(text('''
            SELECT id, alert_ids
            FROM aisoc_cases
            WHERE creation_method = 'graph_correlation'
            AND tenant_id = :tid
            AND array_length(alert_ids, 1) > 0
            ORDER BY array_length(alert_ids, 1) DESC
            LIMIT 1
        ''').bindparams(tid=tenant_id))
        
        case_row = case_result.fetchone()
        if not case_row:
            pytest.skip("No graph_correlation cases in database")
        
        case_id = case_row[0]
        alert_ids_from_case = set(str(aid) for aid in (case_row[1] or []))
        case_alert_count = len(alert_ids_from_case)
        
        # Count unique alerts in observations that overlap with case alerts
        obs_result = await integration_db.execute(text(f'''
            SELECT COUNT(DISTINCT alert_id) as unique_alerts
            FROM (
                SELECT DISTINCT unnest(alert_ids) as alert_id
                FROM correlation_observations
                WHERE tenant_id = :tid
                AND alert_ids && ARRAY{case_row[1]!r}::uuid[]
            ) t
        ''').bindparams(tid=tenant_id))
        
        obs_alert_count = obs_result.scalar() or 0
        
        # Both should be very close (allowing for slight edge cases)
        # At minimum, all case alerts should be found in observations
        assert obs_alert_count >= case_alert_count * 0.95, (
            f"Case {case_id}: Found only {obs_alert_count} alerts in observations "
            f"but case has {case_alert_count} alerts. Coverage: "
            f"{(obs_alert_count/case_alert_count)*100:.1f}%"
        )


@pytest.mark.asyncio
async def test_no_case_observations_are_expected(integration_db: AsyncSession):
    """
    Verify that observations without any cased alerts are normal and expected.
    These represent correlations of purely deduplicated alerts (not case-forming).
    """
    tenant_id = integration_db.tenant_id
    async with integration_db.begin():
        # Count observations with no cased alerts
        no_case_obs_result = await integration_db.execute(text('''
            SELECT COUNT(DISTINCT co.observation_key) as obs_count
            FROM correlation_observations co
            WHERE co.tenant_id = :tid
            AND NOT EXISTS (
                SELECT 1 FROM alerts a
                WHERE a.tenant_id = co.tenant_id
                AND a.id = ANY(co.alert_ids)
                AND a.case_id IS NOT NULL
            )
        ''').bindparams(tid=tenant_id))
        
        no_case_obs = no_case_obs_result.scalar() or 0
        
        # Count observations containing only deduplicated alerts
        all_dedup_obs_result = await integration_db.execute(text('''
            SELECT COUNT(DISTINCT co.observation_key) as obs_count
            FROM correlation_observations co
            WHERE co.tenant_id = :tid
            AND NOT EXISTS (
                SELECT 1 FROM alerts a
                WHERE a.tenant_id = co.tenant_id
                AND a.id = ANY(co.alert_ids)
                AND a.funnel_stage != 'deduplicated'
            )
        ''').bindparams(tid=tenant_id))
        
        all_dedup_obs = all_dedup_obs_result.scalar() or 0
        
        # Verify that at least most of the no-case observations contain only dedup alerts
        if no_case_obs > 0:
            pct_dedup_only = (all_dedup_obs / no_case_obs) * 100 if no_case_obs > 0 else 0
            
            assert pct_dedup_only >= 90.0, (
                f"Expected most no-case observations to be all-deduplicated, "
                f"but only {pct_dedup_only:.1f}% are"
            )


@pytest.mark.asyncio
async def test_dedup_status_breakdown(integration_db: AsyncSession):
    """
    Verify deduplication status breakdown makes sense.
    Should have mix of cased, deduplicated, and other stages.
    """
    tenant_id = integration_db.tenant_id
    async with integration_db.begin():
        status_result = await integration_db.execute(text('''
            SELECT funnel_stage, COUNT(*) as cnt
            FROM alerts
            WHERE tenant_id = :tid
            GROUP BY funnel_stage
            ORDER BY cnt DESC
        ''').bindparams(tid=tenant_id))
        
        status_counts = {}
        total = 0
        for row in status_result:
            status_counts[row[0]] = row[1]
            total += row[1]
        
        if total == 0:
            pytest.skip("No alerts in database")
        
        # Verify we have at least some deduplicated alerts
        dedup_count = status_counts.get('deduplicated', 0)
        dedup_pct = (dedup_count / total) * 100 if total > 0 else 0
        
        # This is informational; dedup % can vary based on data
        # Just verify deduplicated alerts exist if there's enough data
        if total > 100:
            assert dedup_count > 0, "Expected some deduplicated alerts in larger dataset"
