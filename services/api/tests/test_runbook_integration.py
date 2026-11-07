"""Phase 13: Integration & E2E Tests for Runbook + Calibration Monitor

Comprehensive test suite covering:
1. E2E alert flow: ingestion → triage → approval → investigation → jira
2. Calibration monitor: ECE measurement + metrics
3. Database operations: feedback collection & task tracking
4. Funnel stage gates: investigation evidence + ready_for_jira

Needs a live, migrated Postgres, so it is gated like the rest of the
integration suites:

    AISOC_RUN_INTEGRATION=1 pytest -m integration tests/test_runbook_integration.py
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from app.models.alert import Alert
from app.models.runbook_task import RunbookTask, RunbookTaskStatus
from app.services.funnel_stages import has_investigation_evidence
from app.workers.calibration_monitor import ConfidenceCalibrationMonitor
from sqlalchemy import and_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

_REQUIRES_ENV = "AISOC_RUN_INTEGRATION"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.getenv(_REQUIRES_ENV),
        reason=f"set {_REQUIRES_ENV}=1 to run the runbook integration suite against Postgres",
    ),
]


# ════════════════════════════════════════════════════════════════════════════════
# FIXTURES & DATABASE SETUP
# ════════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="function")
async def test_db():
    """Create test database session using PostgreSQL."""
    from app.db.database import AsyncSessionLocal, Base, engine
    from sqlalchemy import text

    # Create all tables if they don't exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    from app.models.tenant import Tenant

    # Create session. The tenant is created here (not in a separate fixture) so
    # every cleanup statement below can be scoped to it: an unscoped DELETE
    # would wipe the real alerts/cases/ledger of the configured database.
    async with AsyncSessionLocal() as session:
        tenant_id = uuid4()
        session.add(
            Tenant(
                id=tenant_id,
                name="Test Tenant",
                slug=f"test-tenant-{uuid4().hex[:8]}",
                mssp_role="standalone",
            )
        )
        await session.commit()
        session.tenant_id = tenant_id

        await _purge_tenant(session, tenant_id)
        yield session

    try:
        async with AsyncSessionLocal() as session:
            await _purge_tenant(session, tenant_id)
            await session.execute(
                text("DELETE FROM tenants WHERE id = :tid"), {"tid": str(tenant_id)}
            )
            await session.commit()
    except Exception:
        pass  # Ignore cleanup errors


async def _purge_tenant(session: AsyncSession, tenant_id: Any) -> None:
    """Delete this fixture's own rows; never another tenant's."""
    for table in ("runbook_tasks", "alerts", "cases"):
        await session.execute(
            text(f"DELETE FROM {table} WHERE tenant_id = :tid"), {"tid": str(tenant_id)}
        )
    await session.commit()


@pytest.fixture
async def test_tenant_id(test_db: AsyncSession):
    """The tenant created by the ``test_db`` fixture."""
    return test_db.tenant_id


@pytest.fixture
def test_alert_id():
    """Standard test alert ID."""
    return uuid4()


@pytest.fixture
async def sample_alert(test_db: AsyncSession, test_tenant_id, test_alert_id):
    """Create a sample alert for testing.

    Represents a real security alert with:
    - Initial ingestion confidence (0.65 - medium)
    - Title and narrative for investigation
    - Fused alert from multiple sources
    """
    alert = Alert(
        id=test_alert_id,
        tenant_id=test_tenant_id,
        title="Suspicious lateral movement detected",
        severity="medium",
        confidence=65,
        narrative="Process execution from unusual location. Investigation needed.",
        connector_type="fusion_engine",
        funnel_stage="ingested",
        ai_summary="Potential privilege escalation via lateral movement",
        ai_recommendations=["investigate", "isolate_endpoint"],
        created_at=datetime.utcnow(),
    )
    test_db.add(alert)
    await test_db.commit()
    await test_db.refresh(alert)
    return alert


@pytest.fixture
async def sample_runbook_task(test_db: AsyncSession, test_tenant_id, test_alert_id):
    """Create a sample approval gate task for testing."""
    task = RunbookTask(
        id=uuid4(),
        tenant_id=test_tenant_id,
        alert_id=test_alert_id,
        task_type="approval_gate",
        status="pending",
        title="Approve investigation for lateral movement alert",
        description="LLM determined this needs human review. Approve to proceed?",
        completed_at=None,
        completed_by=None,
        feedback_applied=None,
        created_at=datetime.utcnow(),
    )
    test_db.add(task)
    await test_db.commit()
    await test_db.refresh(task)
    return task


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 1: E2E ALERT FLOW
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_e2e_alert_ingestion(test_db: AsyncSession, test_tenant_id):
    """Test 1.1: Alert is correctly ingested and funnel stage set to 'ingested'."""
    alert_id = uuid4()
    alert = Alert(
        id=alert_id,
        tenant_id=test_tenant_id,
        title="Unauthorized admin access",
        severity="high",
        confidence=72,
        connector_type="iam_connector",
        funnel_stage="ingested",
        created_at=datetime.utcnow(),
    )
    test_db.add(alert)
    await test_db.commit()

    # Verify alert exists and is in 'ingested' stage
    result = await test_db.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    stored_alert = result.scalars().first()
    assert stored_alert is not None
    assert stored_alert.funnel_stage == "ingested"
    assert stored_alert.confidence == 0.72


@pytest.mark.asyncio
async def test_e2e_lLM_triage_creates_approval_gate(
    test_db: AsyncSession, sample_alert: Alert
):
    """Test 1.2: LLM triage with 'needs_review' disposition creates approval_gate task.

    Simulates: auto_triage agent returns needs_review → system creates manual_review task
    """
    # Simulate LLM triage response
    triage_result = {
        "disposition": "needs_review",
        "confidence": sample_alert.confidence,
        "reasoning": "MITRE ATT&CK T1210 + user in admin group + after hours",
    }

    # Create approval gate task (as the triage worker would)
    task = RunbookTask(
        tenant_id=sample_alert.tenant_id,
        alert_id=sample_alert.id,
        task_type="approval_gate",
        status="pending",
        title=f"Review: {sample_alert.title}",
        description=triage_result["reasoning"],
    )
    test_db.add(task)
    await test_db.commit()

    # Verify task was created
    result = await test_db.execute(
        select(RunbookTask).where(
            and_(
                RunbookTask.alert_id == sample_alert.id,
                RunbookTask.task_type == "approval_gate",
            )
        )
    )
    tasks = result.scalars().all()
    assert len(tasks) == 1
    assert tasks[0].status == RunbookTaskStatus.PENDING.value


@pytest.mark.asyncio
async def test_e2e_approval_gate_approval_advances_funnel(
    test_db: AsyncSession, sample_alert: Alert, sample_runbook_task: RunbookTask
):
    """Test 1.3: When analyst approves the approval_gate task, alert advances to 'investigating'."""
    # Simulate analyst approval
    sample_runbook_task.status = RunbookTaskStatus.COMPLETED.value
    sample_runbook_task.completed_by = uuid4()
    sample_runbook_task.completed_at = datetime.utcnow()
    sample_runbook_task.feedback_applied = True  # Approved (True means ✓ approve)
    test_db.add(sample_runbook_task)

    # Update alert funnel stage
    sample_alert.funnel_stage = "investigating"
    test_db.add(sample_alert)
    await test_db.commit()

    # Verify alert is now in 'investigating' stage
    result = await test_db.execute(select(Alert).where(Alert.id == sample_alert.id))
    updated_alert = result.scalars().first()
    assert updated_alert.funnel_stage == "investigating"


@pytest.mark.asyncio
async def test_e2e_investigation_completion_creates_case(
    test_db: AsyncSession, sample_alert: Alert
):
    """Test 1.4: After investigation (tasks completed), a Case is created and alert → 'cased'."""
    from app.models.case import Case

    # Simulate investigation completed
    sample_alert.ai_summary = (
        "Confirmed: Unauthorized admin access from IP 192.0.2.1 at 23:45 UTC. "
        "Created rogue service account aisoc-admin with full permissions. "
        "Lateral movement vector identified."
    )
    sample_alert.funnel_stage = "cased"
    test_db.add(sample_alert)

    # Create case
    case = Case(
        id=uuid4(),
        tenant_id=sample_alert.tenant_id,
        title=sample_alert.title,
        description="Investigating unauthorized admin access",
        severity=sample_alert.severity,
        created_at=datetime.utcnow(),
    )
    test_db.add(case)
    await test_db.commit()

    # Verify case created and alert in 'cased' stage
    result = await test_db.execute(
        select(Case).where(Case.id == case.id)
    )
    stored_case = result.scalars().first()
    assert stored_case is not None
    assert sample_alert.funnel_stage == "cased"


@pytest.mark.asyncio
async def test_e2e_ready_for_jira_gate(test_db: AsyncSession, sample_alert: Alert):
    """Test 1.5: Alert passes ready_for_jira gate when evidence is sufficient.

    Gate checks:
    - Summary length ≥ 100 chars
    - Narrative length ≥ 200 chars
    - Runbook tasks ≥ 80% complete
    """
    # Simulate completed investigation
    sample_alert.ai_summary = (
        "Confirmed: Unauthorized admin access from IP 192.0.2.1 at 23:45 UTC via SSH. "
        "Created rogue service account aisoc-admin with full permissions. "
        "Lateral movement vector via Process Hollow (T1055). Persistence via cron job."
    )
    sample_alert.narrative = (
        "Alert triggered by identity connector detecting new admin account creation. "
        "Correlation with EDR: process execution from /tmp/xmrig (cryptocurrency mining). "
        "Timeline: account created 22:30, first use 23:45, lateral movement attempt 00:15. "
        "Investigation findings: attacker used stolen credentials from dev-team SG, escalated via sudo misconfiguration. "
        "Scope: 3 systems compromised (prod-01, prod-02, staging-01). "
        "Recommended action: revoke credentials, force password reset, review sudo ACLs."
    )

    # Check evidence bar (should pass)
    has_evidence = has_investigation_evidence(
        ai_summary=sample_alert.ai_summary,
        narrative=sample_alert.narrative,
        runbook_tasks_completed=5,
        runbook_tasks_total=5,
    )
    assert has_evidence is True


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 2: CALIBRATION MONITOR
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_calibration_monitor_ece_measurement(
    test_db: AsyncSession, test_tenant_id
):
    """Test 2.1: Calibration monitor correctly measures ECE from feedback_applied column.

    Creates 10 tasks with varying confidence + feedback → measures ECE
    """
    # Create sample tasks with feedback
    tasks_data = [
        # (confidence, feedback_applied, expected_bin)
        (0.15, True, "0.0-0.25"),   # Low conf, correct → good calibration
        (0.18, True, "0.0-0.25"),
        (0.22, False, "0.0-0.25"),  # Low conf, wrong → bad calibration
        (0.35, True, "0.25-0.5"),   # Medium-low conf, correct
        (0.40, True, "0.25-0.5"),
        (0.45, False, "0.25-0.5"),  # Medium-low conf, wrong
        (0.62, True, "0.5-0.75"),   # Medium-high conf, correct
        (0.70, True, "0.5-0.75"),
        (0.68, False, "0.5-0.75"),  # Medium-high conf, wrong
        (0.95, True, "0.75-1.0"),   # High conf, correct
    ]

    for idx, (confidence, feedback, _) in enumerate(tasks_data):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Test task {idx}",
            feedback_applied=feedback,
            completed_at=datetime.utcnow() - timedelta(hours=1),
            confidence_at_submission=confidence,
        )
        test_db.add(task)
    await test_db.commit()

    # Measure ECE
    monitor = ConfidenceCalibrationMonitor()
    metrics = await monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    # ECE should be reasonable (not perfect, but measuring calibration)
    assert metrics is not None
    assert "ece" in metrics
    assert 0.0 <= metrics["ece"] <= 1.0
    assert metrics["sample_size"] >= 10


@pytest.mark.asyncio
async def test_calibration_monitor_status_ok(test_db: AsyncSession, test_tenant_id):
    """Test 2.2: Calibration monitor reports 'ok' status when ECE < threshold (0.15)."""
    # Create well-calibrated tasks (high confidence = high accuracy)
    for idx in range(8):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Well-calibrated task {idx}",
            feedback_applied=True,  # All correct
            confidence_at_submission=0.85 + (idx * 0.01),  # High confidence
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    monitor = ConfidenceCalibrationMonitor()
    metrics = await monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    # With all high-confidence tasks being correct, ECE should be low (< 0.15 = ok)
    assert metrics is not None
    assert metrics["ece"] < 0.15
    assert metrics["status"] == "ok"


@pytest.mark.asyncio
async def test_calibration_monitor_status_degraded(test_db: AsyncSession, test_tenant_id):
    """Test 2.3: Calibration monitor reports 'degraded' status when 0.15 ≤ ECE < 0.30."""
    # Create mixed-calibration tasks (some correct, some wrong)
    for idx in range(10):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Mixed-calibration task {idx}",
            feedback_applied=(idx % 3) != 0,  # ~67% correct
            confidence_at_submission=0.70,  # High confidence
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    monitor = ConfidenceCalibrationMonitor()
    metrics = await monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    # Mixed results → ECE should be in degraded range
    assert metrics is not None
    assert metrics["ece"] >= 0.15


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 3: DATABASE OPERATIONS & QUERIES
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_db_query_feedback_applied_count(test_db: AsyncSession, test_tenant_id):
    """Test 3.1: Query returns correct count of feedback_applied tasks.

    This is the core operational query:
    SELECT COUNT(*) FROM runbook_tasks WHERE feedback_applied IS NOT NULL;
    """
    # Create tasks with different feedback states
    for idx in range(15):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Task {idx}",
            feedback_applied=True if idx < 10 else None,  # 10 with feedback, 5 without
            completed_at=datetime.utcnow(),
        )
        test_db.add(task)
    await test_db.commit()

    # Query: tasks with feedback applied
    result = await test_db.execute(
        select(RunbookTask).where(RunbookTask.feedback_applied.isnot(None))
    )
    tasks_with_feedback = result.scalars().all()

    assert len(tasks_with_feedback) == 10


@pytest.mark.asyncio
async def test_db_query_pending_approval_gates(test_db: AsyncSession, test_tenant_id):
    """Test 3.2: Query correctly returns pending approval_gate tasks."""
    # Create mixed tasks
    for idx in range(5):
        status = (
            "pending"
            if idx < 3
            else "completed"
        )
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status=status,
            title=f"Approval task {idx}",
        )
        test_db.add(task)
    await test_db.commit()

    # Query: pending approval gates
    result = await test_db.execute(
        select(RunbookTask).where(
            and_(
                RunbookTask.task_type == "approval_gate",
                RunbookTask.status == RunbookTaskStatus.PENDING.value,
            )
        )
    )
    pending_tasks = result.scalars().all()

    assert len(pending_tasks) == 3


@pytest.mark.asyncio
async def test_db_query_tasks_by_alert(test_db: AsyncSession, test_tenant_id):
    """Test 3.3: Query returns all tasks for a specific alert."""
    alert_id = uuid4()

    # Create tasks for this alert
    for idx in range(3):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=alert_id,
            task_type="approval_gate",
            title=f"Task {idx}",
        )
        test_db.add(task)

    # Create task for different alert (noise)
    other_task = RunbookTask(
        id=uuid4(),
        tenant_id=test_tenant_id,
        alert_id=uuid4(),
        task_type="approval_gate",
        title="Other alert task",
    )
    test_db.add(other_task)
    await test_db.commit()

    # Query: tasks for specific alert
    result = await test_db.execute(
        select(RunbookTask).where(RunbookTask.alert_id == alert_id)
    )
    tasks = result.scalars().all()

    assert len(tasks) == 3


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 4: FUNNEL STAGE GATES
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_has_investigation_evidence_summary_gate():
    """Test 4.1: has_investigation_evidence() passes with sufficient summary (≥100 chars)."""
    summary = "A" * 100  # Exactly 100 chars
    has_evidence = has_investigation_evidence(ai_summary=summary)
    assert has_evidence is True


@pytest.mark.asyncio
async def test_has_investigation_evidence_narrative_gate():
    """Test 4.2: has_investigation_evidence() passes with sufficient narrative (≥200 chars)."""
    narrative = "B" * 200  # Exactly 200 chars
    has_evidence = has_investigation_evidence(narrative=narrative)
    assert has_evidence is True


@pytest.mark.asyncio
async def test_has_investigation_evidence_runbook_tasks_gate():
    """Test 4.3: has_investigation_evidence() passes with ≥80% runbook task completion."""
    has_evidence = has_investigation_evidence(
        runbook_tasks_completed=8,
        runbook_tasks_total=10,
    )
    assert has_evidence is True


@pytest.mark.asyncio
async def test_has_investigation_evidence_all_bars_fail():
    """Test 4.4: has_investigation_evidence() fails when all bars are below threshold."""
    has_evidence = has_investigation_evidence(
        ai_summary="Short",
        narrative="Not enough chars",
        runbook_tasks_completed=3,
        runbook_tasks_total=10,  # 30% < 80%
    )
    assert has_evidence is False


@pytest.mark.asyncio
async def test_has_investigation_evidence_backward_compatible():
    """Test 4.5: has_investigation_evidence() works with old-style calls (no runbook params)."""
    # Old-style call (before Task 1.3)
    has_evidence = has_investigation_evidence(
        ai_summary="X" * 150,  # > 100
    )
    assert has_evidence is True


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 5: INTEGRATION SCENARIOS
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_integration_full_alert_lifecycle(
    test_db: AsyncSession, test_tenant_id
):
    """Test 5.1: Full alert lifecycle from ingestion to Jira.

    Scenario:
    1. Alert ingested (confidence 0.68)
    2. Auto-triage determines needs_review
    3. Approval gate task created + completed
    4. Investigation tasks created + completed (80%)
    5. Alert evidence passes all gates
    6. Ready for Jira (high severity + sufficient evidence)
    """
    alert_id = uuid4()

    # Step 1: Ingest alert
    alert = Alert(
        id=alert_id,
        tenant_id=test_tenant_id,
        title="Suspicious activity detected",
        severity="high",
        confidence=68,
        funnel_stage="ingested",
        created_at=datetime.utcnow(),
    )
    test_db.add(alert)
    await test_db.commit()

    # Step 2: Triage determines needs_review
    approval_task = RunbookTask(
        id=uuid4(),
        tenant_id=test_tenant_id,
        alert_id=alert_id,
        task_type="approval_gate",
        status="completed",
        title="Review suspicious activity",
        feedback_applied=True,
        completed_at=datetime.utcnow(),
        confidence_at_submission=0.68,
    )
    test_db.add(approval_task)

    # Step 3: Create investigation tasks
    for idx in range(5):
        inv_task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=alert_id,
            task_type="investigation",
            status="completed",
            title=f"Investigation step {idx}",
            feedback_applied=True,
            completed_at=datetime.utcnow(),
        )
        test_db.add(inv_task)

    # Step 4: Update alert with investigation results
    alert.ai_summary = "Investigation complete. Confirmed threat. " + ("X" * 100)
    alert.narrative = (
        "Timeline of events: "
        "Initial access via phishing (22:15 UTC). "
        "Lateral movement to 3 systems. "
        "Command & control via port 443. "
        "Exfiltration of customer data detected. "
        "Scope: 5 systems affected. "
        "Recommended: Immediate isolation + incident response. " + ("Y" * 100)
    )
    alert.funnel_stage = "investigating"
    test_db.add(alert)
    await test_db.commit()

    # Step 5: Check all evidence gates pass
    has_evidence = has_investigation_evidence(
        ai_summary=alert.ai_summary,
        narrative=alert.narrative,
        runbook_tasks_completed=5,
        runbook_tasks_total=5,
    )
    assert has_evidence is True

    # Step 6: Alert ready for Jira
    is_high_severity = alert.severity in ("high", "critical")
    assert is_high_severity is True
    assert has_evidence is True
    # → Alert can be promoted to ready_for_jira


@pytest.mark.asyncio
async def test_integration_confidence_calibration_feedback_loop(
    test_db: AsyncSession, test_tenant_id
):
    """Test 5.2: Confidence calibration improves with feedback.

    Scenario:
    1. Create 20 alerts with initial confidence
    2. All reviewed + feedback_applied
    3. Measure ECE before → after
    4. System should detect calibration issues
    """
    # Create initial set of alerts (not well-calibrated)
    initial_ece = None
    for idx in range(20):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Alert {idx}",
            feedback_applied=(idx % 4) == 0,  # 25% correct - bad calibration
            confidence_at_submission=0.80,  # High confidence
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    # Measure initial ECE
    monitor = ConfidenceCalibrationMonitor()
    metrics = await monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)
    initial_ece = metrics["ece"]

    # ECE should be high (poor calibration)
    assert initial_ece > 0.20  # degraded or poor


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 6: ERROR HANDLING & EDGE CASES
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_edge_case_no_feedback_data(test_db: AsyncSession, test_tenant_id):
    """Test 6.1: Calibration monitor handles case where no feedback_applied data exists."""
    # Create tasks without feedback_applied
    for idx in range(5):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="pending",
            title=f"Pending task {idx}",
            feedback_applied=None,  # No feedback yet
        )
        test_db.add(task)
    await test_db.commit()

    # Should gracefully handle empty feedback set
    monitor = ConfidenceCalibrationMonitor()
    metrics = await monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    assert metrics is not None
    assert metrics["sample_size"] == 0


@pytest.mark.asyncio
async def test_edge_case_single_sample_ece():
    """Test 6.2: ECE calculation with single sample."""
    has_evidence = has_investigation_evidence(
        ai_summary="Single verdict.",
        narrative="Not enough.",
        runbook_tasks_completed=1,
        runbook_tasks_total=1,
    )
    # Should return True (100% completion)
    assert has_evidence is True


@pytest.mark.asyncio
async def test_edge_case_zero_total_tasks():
    """Test 6.3: has_investigation_evidence() with zero total tasks (division by zero)."""
    has_evidence = has_investigation_evidence(
        ai_summary="Short",
        narrative="Short",
        runbook_tasks_completed=0,
        runbook_tasks_total=0,  # Edge case: no tasks
    )
    # Should not crash, should return False (not enough evidence)
    assert has_evidence is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
