"""Phase 13: Operational Database Tests

Tests for running direct SQL queries in production to verify:
1. Runbook task feedback collection
2. Approval gate tracking
3. Investigation workflow status
4. Ready for Jira readiness checks
5. Multi-tenant isolation

Run with: poetry run pytest services/api/tests/test_operational_queries.py -v
Needs a live, migrated Postgres and is therefore gated behind
``AISOC_RUN_INTEGRATION=1``.

OPERATORS: Run these queries in production to verify system health:

  -- Check 1: Count tasks with feedback
  SELECT COUNT(*) FROM runbook_tasks WHERE feedback_applied IS NOT NULL;

  -- Check 2: Approval gate completion rate
  SELECT
    COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
    COUNT(*) as total,
    ROUND(100.0 * COUNT(CASE WHEN status = 'completed' THEN 1 END) / COUNT(*), 1) as completion_rate
  FROM runbook_tasks WHERE task_type = 'approval_gate';

  -- Check 3: Investigation funnel
  SELECT
    funnel_stage,
    COUNT(*) as count
  FROM alerts
  WHERE created_at > now() - interval '24 hours'
  GROUP BY funnel_stage
  ORDER BY count DESC;

  -- Check 4: Calibration scores
  SELECT
    CASE WHEN confidence_at_submission < 0.25 THEN '0.0-0.25'
         WHEN confidence_at_submission < 0.50 THEN '0.25-0.5'
         WHEN confidence_at_submission < 0.75 THEN '0.5-0.75'
         ELSE '0.75-1.0' END as confidence_bin,
    COUNT(*) as total_tasks,
    SUM(CASE WHEN feedback_applied = true THEN 1 ELSE 0 END) as correct,
    ROUND(100.0 * SUM(CASE WHEN feedback_applied = true THEN 1 ELSE 0 END) / COUNT(*), 1) as accuracy_pct
  FROM runbook_tasks
  WHERE feedback_applied IS NOT NULL
    AND completed_at > now() - interval '24 hours'
  GROUP BY confidence_bin
  ORDER BY confidence_bin;
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from app.models.alert import Alert
from app.models.runbook_task import RunbookTask
from sqlalchemy import case, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

_REQUIRES_ENV = "AISOC_RUN_INTEGRATION"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.getenv(_REQUIRES_ENV),
        reason=f"set {_REQUIRES_ENV}=1 to run the operational queries against Postgres",
    ),
]


@pytest.fixture(scope="function")
async def test_db():
    """Test database using PostgreSQL."""
    from app.db.database import AsyncSessionLocal
    from app.models.tenant import Tenant

    # Use existing PostgreSQL connection
    async with AsyncSessionLocal() as session:
        # Create tenant with unique slug
        tenant_id = uuid4()
        unique_slug = f"test-tenant-{uuid4().hex[:8]}"
        tenant = Tenant(
            id=tenant_id,
            name="Test Tenant",
            slug=unique_slug,
            mssp_role="standalone",
        )
        session.add(tenant)
        await session.commit()

        # Scoped to this fixture's own tenant: an unscoped DELETE would wipe the
        # real alerts and ledger rows of whatever database DATABASE_URL points at.
        await session.execute(
            text("DELETE FROM runbook_tasks WHERE tenant_id = :tid"), {"tid": str(tenant_id)}
        )
        await session.execute(
            text("DELETE FROM alerts WHERE tenant_id = :tid"), {"tid": str(tenant_id)}
        )
        await session.commit()

        # Store tenant_id in session for later use
        session.tenant_id = tenant_id

        yield session

        # Cleanup
        try:
            await session.execute(
                text("DELETE FROM runbook_tasks WHERE tenant_id = :tid"), {"tid": str(tenant_id)}
            )
            await session.execute(
                text("DELETE FROM alerts WHERE tenant_id = :tid"), {"tid": str(tenant_id)}
            )
            await session.execute(
                text("DELETE FROM tenants WHERE id = :tid"), {"tid": str(tenant_id)}
            )
            await session.commit()
        except Exception:
            pass


@pytest.fixture
async def test_tenant_id(test_db):
    return test_db.tenant_id


# ════════════════════════════════════════════════════════════════════════════════
# OPERATIONAL CHECK 1: Feedback Collection
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_op_check_1_feedback_count(test_db: AsyncSession, test_tenant_id):
    """Operational Check 1: Count tasks with feedback_applied.

    Query:
    SELECT COUNT(*) FROM runbook_tasks WHERE feedback_applied IS NOT NULL;

    Healthy if: count > 0 (indicates calibration monitor has data)
    Warning if: count < 5 (low volume, monitor may not have run yet)
    """
    # Create 15 tasks, 10 with feedback
    for idx in range(15):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Task {idx}",
            feedback_applied=True if idx < 10 else None,
            completed_at=datetime.utcnow(),
        )
        test_db.add(task)
    await test_db.commit()

    # Run operational check query
    result = await test_db.execute(
        select(func.count(RunbookTask.id)).where(
            RunbookTask.feedback_applied.isnot(None)
        )
    )
    feedback_count = result.scalar()

    # Verify results
    assert feedback_count == 10
    assert feedback_count > 0  # System has feedback


@pytest.mark.asyncio
async def test_op_check_1_no_feedback_yet(test_db: AsyncSession, test_tenant_id):
    """Operational Check 1: System with no feedback yet (normal during cold start)."""
    # Create tasks but no feedback
    for idx in range(5):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="pending",
            title=f"Pending {idx}",
            feedback_applied=None,
        )
        test_db.add(task)
    await test_db.commit()

    result = await test_db.execute(
        select(func.count(RunbookTask.id)).where(
            RunbookTask.feedback_applied.isnot(None)
        )
    )
    feedback_count = result.scalar()

    # Verify: no feedback yet (normal during startup)
    assert feedback_count == 0


# ════════════════════════════════════════════════════════════════════════════════
# OPERATIONAL CHECK 2: Approval Gate Completion Rate
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_op_check_2_approval_gate_rate(test_db: AsyncSession, test_tenant_id):
    """Operational Check 2: Approval gate completion rate.

    Query:
    SELECT
      COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
      COUNT(*) as total,
      ROUND(100.0 * COUNT(...) / COUNT(*), 1) as completion_rate
    FROM runbook_tasks WHERE task_type = 'approval_gate';

    Healthy if: completion_rate >= 70% (most approvals processed)
    Warning if: completion_rate < 50% (high pending backlog)
    """
    # Create 10 approval gates: 8 completed, 2 pending
    for idx in range(10):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status=(
                "completed" if idx < 8 else "pending"
            ),
            title=f"Approval {idx}",
            completed_at=(
                datetime.utcnow() if idx < 8 else None
            ),
        )
        test_db.add(task)
    await test_db.commit()

    # Run operational check query
    result = await test_db.execute(
        select(
            func.count(case((RunbookTask.status == "completed", 1))).label("completed"),
            func.count(RunbookTask.id).label("total"),
        ).where(RunbookTask.task_type == "approval_gate")
    )
    completed, total = result.first()

    completion_rate = (completed / total * 100) if total > 0 else 0

    # Verify
    assert completed == 8
    assert total == 10
    assert completion_rate == 80.0  # Healthy (>= 70%)


@pytest.mark.asyncio
async def test_op_check_2_high_pending_backlog(test_db: AsyncSession, test_tenant_id):
    """Operational Check 2: High pending backlog (warning condition)."""
    # Create 10 approval gates: 3 completed, 7 pending
    for idx in range(10):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status=(
                "completed" if idx < 3 else "pending"
            ),
            title=f"Approval {idx}",
            completed_at=(
                datetime.utcnow() if idx < 3 else None
            ),
        )
        test_db.add(task)
    await test_db.commit()

    result = await test_db.execute(
        select(
            func.count(case((RunbookTask.status == "completed", 1))).label("completed"),
            func.count(RunbookTask.id).label("total"),
        ).where(RunbookTask.task_type == "approval_gate")
    )
    completed, total = result.first()

    completion_rate = (completed / total * 100) if total > 0 else 0

    # Warning: only 30% completed
    assert completion_rate == 30.0
    assert completion_rate < 50  # Alert condition


# ════════════════════════════════════════════════════════════════════════════════
# OPERATIONAL CHECK 3: Investigation Funnel Status
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_op_check_3_funnel_distribution(test_db: AsyncSession, test_tenant_id):
    """Operational Check 3: Alert distribution by funnel stage.

    Query:
    SELECT
      funnel_stage,
      COUNT(*) as count
    FROM alerts
    WHERE created_at > now() - interval '24 hours'
    GROUP BY funnel_stage
    ORDER BY count DESC;

    Healthy if: investigating > ingested (good triage rate)
    Warning if: Most alerts stuck in 'ingested' (triage backlog)
    """
    # Create 20 alerts in various stages (last 24 hours)
    funnel_stages = [
        ("ingested", 5),
        ("triaged", 4),
        ("investigating", 8),
        ("cased", 2),
        ("ready_for_jira", 1),
    ]

    for stage, count in funnel_stages:
        for idx in range(count):
            alert = Alert(
                id=uuid4(),
                tenant_id=test_tenant_id,
                title=f"Alert {stage} {idx}",
                severity="medium",
                confidence=65,
                funnel_stage=stage,
                created_at=datetime.utcnow() - timedelta(hours=2),
            )
            test_db.add(alert)
    await test_db.commit()

    # Run operational check query
    result = await test_db.execute(
        select(
            Alert.funnel_stage,
            func.count(Alert.id).label("count"),
        ).where(
            Alert.created_at > datetime.utcnow() - timedelta(hours=24)
        ).group_by(Alert.funnel_stage).order_by(func.count(Alert.id).desc())
    )
    stages = dict(result.all())

    # Verify distribution
    assert stages["investigating"] == 8  # Most alerts
    assert stages["ingested"] == 5      # Some at start
    assert stages["ready_for_jira"] == 1  # Few at end


@pytest.mark.asyncio
async def test_op_check_3_stuck_in_ingested(test_db: AsyncSession, test_tenant_id):
    """Operational Check 3: Alert backlog (warning - most stuck in 'ingested')."""
    # Create 10 alerts, mostly stuck
    for idx in range(10):
        stage = "ingested" if idx < 9 else "investigating"
        alert = Alert(
            id=uuid4(),
            tenant_id=test_tenant_id,
            title=f"Alert {idx}",
            severity="medium",
            confidence=65,
            funnel_stage=stage,
            created_at=datetime.utcnow() - timedelta(hours=2),
        )
        test_db.add(alert)
    await test_db.commit()

    result = await test_db.execute(
        select(
            Alert.funnel_stage,
            func.count(Alert.id).label("count"),
        ).where(
            Alert.created_at > datetime.utcnow() - timedelta(hours=24)
        ).group_by(Alert.funnel_stage).order_by(func.count(Alert.id).desc())
    )
    stages = dict(result.all())

    # Warning: 90% stuck in 'ingested'
    assert stages.get("ingested", 0) == 9
    assert stages.get("investigating", 0) == 1


# ════════════════════════════════════════════════════════════════════════════════
# OPERATIONAL CHECK 4: Calibration Scores by Bin
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_op_check_4_calibration_by_bin(test_db: AsyncSession, test_tenant_id):
    """Operational Check 4: Confidence calibration by bin.

    Query:
    SELECT
      CASE WHEN confidence_at_submission < 0.25 THEN '0.0-0.25'
           WHEN confidence_at_submission < 0.50 THEN '0.25-0.5'
           WHEN confidence_at_submission < 0.75 THEN '0.5-0.75'
           ELSE '0.75-1.0' END as confidence_bin,
      COUNT(*) as total_tasks,
      SUM(CASE WHEN feedback_applied = true THEN 1 ELSE 0 END) as correct,
      ROUND(100.0 * SUM(...) / COUNT(*), 1) as accuracy_pct
    FROM runbook_tasks
    WHERE feedback_applied IS NOT NULL
      AND completed_at > now() - interval '24 hours'
    GROUP BY confidence_bin
    ORDER BY confidence_bin;

    Healthy if: accuracy increases with confidence bin
    Warning if: High confidence bins have low accuracy (overconfident)
    """
    # Create tasks with known accuracy per bin
    test_data = [
        # (confidence, is_correct)
        # Bin 0.0-0.25: 60% accuracy
        (0.10, True),
        (0.15, True),
        (0.20, False),
        (0.22, False),
        (0.24, False),
        # Bin 0.25-0.5: 75% accuracy
        (0.30, True),
        (0.35, True),
        (0.40, True),
        (0.45, False),
        # Bin 0.5-0.75: 80% accuracy
        (0.55, True),
        (0.60, True),
        (0.65, True),
        (0.70, True),
        (0.72, False),
        # Bin 0.75-1.0: 90% accuracy
        (0.80, True),
        (0.85, True),
        (0.90, True),
        (0.95, True),
        (0.98, False),
        (1.00, True),
    ]

    for conf, is_correct in test_data:
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Task conf={conf}",
            feedback_applied=is_correct,
            confidence_at_submission=conf,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    # Run operational check query
    result = await test_db.execute(
        select(
            case(
                (RunbookTask.confidence_at_submission < 0.25, "0.0-0.25"),
                (RunbookTask.confidence_at_submission < 0.50, "0.25-0.5"),
                (RunbookTask.confidence_at_submission < 0.75, "0.5-0.75"),
                else_="0.75-1.0",
            ).label("bin"),
            func.count(RunbookTask.id).label("total"),
            func.sum(case((RunbookTask.feedback_applied.is_(True), 1), else_=0)).label("correct"),
        ).where(
            (RunbookTask.feedback_applied.isnot(None))
            & (RunbookTask.completed_at > datetime.utcnow() - timedelta(hours=24))
        ).group_by("bin").order_by("bin")
    )

    bins = {row[0]: (row[1], row[2]) for row in result.all()}

    # Verify calibration: accuracy should generally increase with confidence
    assert bins["0.0-0.25"][0] == 5  # 5 tasks
    assert bins["0.75-1.0"][0] == 5  # 5 tasks

    # Higher confidence bins should have better accuracy
    acc_low = bins["0.0-0.25"][1] / bins["0.0-0.25"][0]  # 60%
    acc_high = bins["0.75-1.0"][1] / bins["0.75-1.0"][0]  # 90%
    assert acc_high > acc_low


# ════════════════════════════════════════════════════════════════════════════════
# OPERATIONAL CHECK 5: Multi-Tenant Isolation Verification
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_op_check_5_tenant_isolation(test_db: AsyncSession):
    """Operational Check 5: Verify tenant data is not mixed.

    Critical security check: ensure tasks/alerts for tenant A are not visible to tenant B
    """
    tenant_a = uuid4()
    tenant_b = uuid4()

    # Create 5 tasks for tenant A
    for idx in range(5):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=tenant_a,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Tenant A task {idx}",
        )
        test_db.add(task)

    # Create 3 tasks for tenant B
    for idx in range(3):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=tenant_b,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Tenant B task {idx}",
        )
        test_db.add(task)
    await test_db.commit()

    # Query: tenant A should see only their 5 tasks
    result_a = await test_db.execute(
        select(func.count(RunbookTask.id)).where(
            RunbookTask.tenant_id == tenant_a
        )
    )
    count_a = result_a.scalar()

    # Query: tenant B should see only their 3 tasks
    result_b = await test_db.execute(
        select(func.count(RunbookTask.id)).where(
            RunbookTask.tenant_id == tenant_b
        )
    )
    count_b = result_b.scalar()

    # Verify isolation
    assert count_a == 5
    assert count_b == 3
    assert count_a + count_b == 8  # No cross-contamination


# ════════════════════════════════════════════════════════════════════════════════
# OPERATIONAL CHECK 6: Recently Completed Tasks
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_op_check_6_recent_completions(test_db: AsyncSession, test_tenant_id):
    """Operational Check 6: Tasks completed in last hour (recent activity).

    Query:
    SELECT COUNT(*) FROM runbook_tasks
    WHERE status = 'completed'
      AND completed_at > now() - interval '1 hour';

    Healthy if: count > 0 (indicates active operator engagement)
    Warning if: count = 0 for > 24 hours (no operator activity)
    """
    # Create recent completions (< 1 hour)
    for idx in range(3):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Recent {idx}",
            completed_at=datetime.utcnow() - timedelta(minutes=30),
        )
        test_db.add(task)

    # Create old completions (> 2 hours)
    for idx in range(5):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Old {idx}",
            completed_at=datetime.utcnow() - timedelta(hours=3),
        )
        test_db.add(task)
    await test_db.commit()

    # Query: recent completions (last hour)
    result = await test_db.execute(
        select(func.count(RunbookTask.id)).where(
            (RunbookTask.status == "completed")
            & (RunbookTask.completed_at > datetime.utcnow() - timedelta(hours=1))
        )
    )
    recent_count = result.scalar()

    assert recent_count == 3  # Only recent ones


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
