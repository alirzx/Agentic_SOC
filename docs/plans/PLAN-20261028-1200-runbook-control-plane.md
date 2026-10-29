# PLAN: Runbook Control Plane (Exception Handling & HITL Workflow)

**Date Created:** 2026-10-28  
**Status:** PHASE 1 (Backend DB & APIs) — IN PROGRESS  
**Author:** GitHub Copilot  
**User Intent:** Transform Runbook from "automation ledger viewer" to **"Control Plane for exception handling and HITL"**

---

## Executive Summary

The Agentic SOC platform has a powerful auto-triage LLM engine that handles **80% of work** (fusion, normalization, triage, auto-close). However, Runbook currently only logs what the engine did — it's a **read-only dashboard** with no operational value.

**This plan transforms Runbook into a Control Plane that manages the 20% that auto-triage CANNOT or SHOULD NOT do:**
- Exception handling (needs_review verdicts, LLM failures)
- Approval gates for L2/L3 containment actions
- Custom MSSP SLA procedures
- Human feedback loop for model training
- Cross-system orchestration (manual tasks)

---

## Architecture Overview

### Data Flow

```
Auto-Triage Engine
    ↓
┌─ Verdict == 'needs_review' (Confidence < 0.85)
│    → Create RunbookTask: type='manual_review'
│
├─ Verdict == 'escalate' + L2/L3 action blocked by Governance
│    → Create RunbookTask: type='approval_gate'
│
├─ LLM Failure / Circuit Breaker Trip
│    → Create RunbookTask: type='manual_review'
│
└─ MSSP Tenant + SLA Obligation
     → Create RunbookTask: type='mssp_sla_check'
    ↓
Runbook Console (Control Plane)
    ↓
Analyst Reviews Tasks + Submits Findings
    ↓
Feedback Loop → outcomes.py (Model Training)
```

### New UI: Ledger Tab Split into Two Sections

1. **Automated Actions (Read-Only)**
   - Timeline of what auto-triage engine did
   - Example: "12:20:21 Alert Received", "12:20:28 LLM Verdict: needs_review"

2. **Manual Action Plan (Interactive)**
   - List of pending tasks awaiting analyst action
   - Example: "Task: Review LLM Verdict", "Task: Approve Host Isolation"
   - Analyst clicks task, reviews context, submits findings

---

## Phase 1: Database & Backend APIs ✅ COMPLETED

### Status: DONE

**Files Created/Modified:**
- ✅ `services/api/alembic/versions/runbook_tasks_table.py` — Migration for `runbook_tasks` table
- ✅ `services/api/app/models/runbook_task.py` — SQLAlchemy ORM model
- ✅ `services/api/app/models/__init__.py` — Added RunbookTask import & __all__
- ✅ `services/api/app/api/v1/endpoints/runbook.py`:
  - Added Pydantic schemas: `RunbookTaskCreate`, `RunbookTaskOut`, `RunbookTaskComplete`
  - Added utility functions: `create_task_for_needs_review()`, `create_task_for_approval_gate()`
  - Added endpoints:
    - `GET /api/v1/runbook/tasks` — List all tasks for tenant
    - `GET /api/v1/runbook/tasks/{id}` — Get one task
    - `POST /api/v1/runbook/tasks/{id}/complete` — Mark task completed + save findings

**Database Schema:**
```sql
CREATE TABLE runbook_tasks (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL (indexed),
    alert_id UUID (indexed),
    case_id UUID,
    task_type VARCHAR(50) (indexed),  -- 'manual_review', 'approval_gate', 'mssp_sla_check'
    title VARCHAR(255),
    description TEXT,
    assigned_to UUID,
    status VARCHAR(20) (indexed),     -- 'pending', 'in_progress', 'completed'
    due_at TIMESTAMP,
    completed_at TIMESTAMP,
    completed_by UUID,
    resolution TEXT,                  -- Analyst's findings
    feedback_to_llm VARCHAR(20),      -- 'good' or 'poor'
    created_by VARCHAR(50),           -- 'system' or user_id
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
);
```

**API Contracts:**

1. **GET /api/v1/runbook/tasks**
   ```json
   {
     "status": "pending",
     "task_type": "manual_review",
     "skip": 0,
     "limit": 50
   }
   
   Response:
   [
     {
       "id": "uuid",
       "task_type": "manual_review",
       "title": "Verify Alert Triage (Low AI Confidence)",
       "description": "LLM confidence (0.72) below threshold...",
       "alert_id": "uuid",
       "status": "pending",
       "due_at": null,
       "created_at": "2026-10-28T12:20:00Z",
       "feedback_to_llm": null
     }
   ]
   ```

2. **POST /api/v1/runbook/tasks/{id}/complete**
   ```json
   {
     "resolution": "Verified: true positive. Process tree shows LSASS dump via injection.",
     "feedback_to_llm": "good"
   }
   
   Response: (updated RunbookTaskOut)
   ```

**Validation:**
- ✅ Python syntax verified (`python -m py_compile`)
- ⏳ Database migration NOT YET RUN (requires `alembic upgrade head`)
- ⏳ APIs NOT YET TESTED (requires running services/api)

**Next Step:** Phase 2 (Backend Hooks)

---

## Phase 2: Backend Hooks — Wire Auto-Triage to Task Creation

### Status: NOT STARTED

**Goal:** When auto-triage engine reaches certain verdicts, automatically create RunbookTasks.

**Files to Modify:**
1. `services/api/app/services/fusion/consumer.py` (or equivalent `fused_alert_consumer.py`)
   - Hook: After LLM verdict is determined, check verdict type
   - If `verdict == 'needs_review'`: Call `create_task_for_needs_review()`
   - If `verdict == 'escalate'` AND action is L2/L3: Call `create_task_for_approval_gate()`

2. `services/agents/app/runtime/auto_triage.py` (or `TriageAgent`)
   - Hook: When LLM returns low confidence result
   - Create task with reasoning

3. `services/api/app/services/llm_safety.py` (LLM Failure Handler)
   - Hook: When LLM circuit breaker trips or API fails
   - Create task with fallback deterministic triage steps

**Pseudocode Example:**

```python
# In fused_alert_consumer.py

async def process_fused_alert(alert, db, tenant_id):
    # ... existing fusion logic ...
    
    # Call auto-triage
    triage_result = await auto_triage(alert, db, tenant_id)
    
    # === NEW: Create Task if needed ===
    if triage_result.verdict == "needs_review":
        task = await create_task_for_needs_review(
            db=db,
            tenant_id=tenant_id,
            alert_id=alert.id,
            confidence=triage_result.confidence,
            reasoning=triage_result.reasoning,
        )
        logger.info(f"Created manual_review task {task.id} for alert {alert.id}")
    
    elif triage_result.verdict == "escalate" and governance_blocks_action:
        task = await create_task_for_approval_gate(
            db=db,
            tenant_id=tenant_id,
            alert_id=alert.id,
            action_name="isolate_host",
            autonomy_level="L2",
        )
        logger.info(f"Created approval_gate task {task.id} for alert {alert.id}")
    
    # ... save alert to DB ...
```

**Scope:**
- Identify exact points where verdicts are set (need to find AUTO_TRIAGE_CODE_MAPPING.md references)
- Add task creation calls at those points
- Add logging for audit trail
- Ensure tasks are only created once (idempotency check)

**Estimated Effort:** 2-3 hours (need to trace auto-triage flow in codebase)

---

## Phase 3: Frontend UI — Action Plan Tab + Task Completion Flow

### Status: NOT STARTED

**Goal:** Display tasks to analyst and let them complete them with findings.

**Files to Create/Modify:**

1. **New Component: `apps/web/src/components/runbook/ActionPlanView.tsx`**
   - Renders list of pending RunbookTasks
   - Two sections:
     - **Pending Tasks** (status='pending' or 'in_progress')
     - **Completed Tasks** (status='completed', collapsed by default)
   - For each task:
     - Task title + description
     - Related alert link
     - If type='manual_review': Show context query + "Mark as TP" / "Mark as FP" buttons
     - If type='approval_gate': Show "Approve" / "Reject" buttons
     - If type='mssp_sla_check': Show checklist with sub-tasks
     - Modal for task completion: textarea for "Resolution" + radio for "Feedback to LLM"

2. **Modify: `apps/web/src/app/(app)/runbook/page.tsx`**
   - Add new tab: "Action Plan" (alongside existing Ledger, Automation Rules, Governance)
   - Load tasks from `GET /api/v1/runbook/tasks?status=pending`

3. **New Hook: `apps/web/src/lib/hooks/useRunbookTasks.ts`**
   - SWR hook: `const { tasks, error, mutate } = useRunbookTasks()`
   - Polls `/api/v1/runbook/tasks` with status filter
   - Auto-refresh on task completion

**UI Mockup:**

```
┌─ Action Plan ──────────────────────────────────────────────┐
│                                                             │
│ ⚠ 3 Pending Tasks                                           │
│                                                             │
│ ┌─ TASK 1 ──────────────────────────────────────────────┐  │
│ │ [manual_review]                                       │  │
│ │ Verify Alert Triage (Low AI Confidence)              │  │
│ │ Alert: win-dc-807 LSASS Dump                         │  │
│ │                                                       │  │
│ │ Description:                                          │  │
│ │   LLM confidence (0.72 < 0.85). Please verify        │  │
│ │   process tree manually.                             │  │
│ │                                                       │  │
│ │ [View Alert Context] [Open Splunk Query]            │  │
│ │                                                       │  │
│ │ [ ✓ True Positive ] [ ✗ False Positive ] [ ? Need Help ] │
│ └───────────────────────────────────────────────────────┘  │
│                                                             │
│ ┌─ TASK 2 ──────────────────────────────────────────────┐  │
│ │ [approval_gate]                                       │  │
│ │ Approve Action: Isolate Host                         │  │
│ │                                                       │  │
│ │ Description:                                          │  │
│ │   AI recommends isolating win-dc-807 due to C2       │  │
│ │   communication. Autonomy level is L2 (needs approval)│  │
│ │                                                       │  │
│ │ [ Approve ] [ Reject ] [ Escalate to Manager ]      │  │
│ └───────────────────────────────────────────────────────┘  │
│                                                             │
│ ───── Completed Tasks (3) ─────                            │
│ [+] Show (3)                                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Estimated Effort:** 4-6 hours

---

## Phase 4: Feedback Loop Integration — Connect to outcomes.py

### Status: NOT STARTED

**Goal:** Send analyst feedback back to LLM model training pipeline.

**Files to Modify:**

1. **`services/agents/app/memory/outcomes.py`**
   - Add function: `record_analyst_feedback(alert_id, task_id, feedback, resolution)`
   - Store in `override:v2:*` memory for model retraining
   - Example: If analyst marked a manual_review task as "good", increment model confidence score for that pattern

2. **`services/api/app/api/v1/endpoints/runbook.py`**
   - Modify `complete_runbook_task()` to call `record_analyst_feedback()` after task completion
   - Log to audit trail

**Integration Points:**

- When analyst completes a `manual_review` task with `feedback_to_llm='good'`:
  - Record in outcomes.py: "LLM correctly identified this as needs_review"
  - Increment pattern confidence for this alert signature
  - Next time similar alert arrives, model starts with higher confidence

- When analyst completes a task with `feedback_to_llm='poor'`:
  - Record: "LLM incorrectly classified this"
  - Decrement confidence for this pattern
  - Flag for review in model evaluation

**Estimated Effort:** 2-3 hours (depends on outcomes.py API complexity)

---

## Files Modified / Created Summary

### PHASE 1 (COMPLETED)

| File | Action | Status |
|------|--------|--------|
| `services/api/alembic/versions/runbook_tasks_table.py` | CREATE | ✅ |
| `services/api/app/models/runbook_task.py` | CREATE | ✅ |
| `services/api/app/models/__init__.py` | MODIFY | ✅ |
| `services/api/app/api/v1/endpoints/runbook.py` | MODIFY | ✅ |

### PHASE 2 (PENDING)

| File | Action | Scope |
|------|--------|-------|
| `services/api/app/services/fusion/consumer.py` | MODIFY | Wire task creation on verdict='needs_review' |
| `services/agents/app/runtime/auto_triage.py` | MODIFY | Hook on LLM failure |
| `services/api/app/services/llm_safety.py` | MODIFY | Hook on circuit breaker |

### PHASE 3 (PENDING)

| File | Action | Scope |
|------|--------|-------|
| `apps/web/src/components/runbook/ActionPlanView.tsx` | CREATE | Render task list & completion UI |
| `apps/web/src/app/(app)/runbook/page.tsx` | MODIFY | Add "Action Plan" tab |
| `apps/web/src/lib/hooks/useRunbookTasks.ts` | CREATE | SWR hook for task fetching |

### PHASE 4 (PENDING)

| File | Action | Scope |
|------|--------|-------|
| `services/agents/app/memory/outcomes.py` | MODIFY | Record analyst feedback for model training |
| `services/api/app/api/v1/endpoints/runbook.py` | MODIFY | Call feedback recorder on task completion |

---

## Testing Strategy

### Phase 1 Validation
- ✅ Python syntax check (`python -m py_compile`)
- ⏳ Run migration: `cd services/api && alembic upgrade head`
- ⏳ Test endpoints manually: `curl http://localhost:8000/api/v1/runbook/tasks`

### Phase 2 Validation
- Integration test: Simulate alert with `confidence=0.72`, verify task is created
- Unit test: Mock fused_alert_consumer, check `create_task_for_needs_review()` is called

### Phase 3 Validation
- Component test: Render ActionPlanView with mock tasks
- E2E test: Complete alert-to-task flow in browser

### Phase 4 Validation
- Mock outcomes.py, verify feedback is recorded
- Re-run eval harness, check model improves on feedback

---

## Risk & Dependencies

### Dependencies
1. ✅ Phase 1 must complete before Phase 2
2. ⏳ Phase 2 must complete before Phase 3
3. ⏳ Phase 3 can run in parallel with Phase 4

### Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Auto-triage code is scattered; hard to find verdict points | Medium | Read AUTO_TRIAGE_CODE_MAPPING.md + trace ledger.py |
| outcomes.py API unknown | Medium | Check services/agents/app/memory/ files |
| DB migration breaks on existing tenants | High | Test migration idempotency; use `IF NOT EXISTS` |
| Task creation race condition (duplicate tasks) | Medium | Add UUID check before insert; use unique constraint |

---

## User Acceptance Criteria

### Phase 1 ✅
- [ ] Database migration runs without error
- [ ] All four API endpoints respond (GET tasks, GET task/{id}, POST task/{id}/complete)
- [ ] Tenant isolation enforced (cannot see other tenant's tasks)

### Phase 2 ✅
- [ ] When auto-triage verdict == 'needs_review', a task is automatically created
- [ ] When action is L2/L3 and blocked by governance, an approval_gate task is created
- [ ] Tasks appear in GET /api/v1/runbook/tasks response

### Phase 3 ✅
- [ ] New "Action Plan" tab appears in Runbook Console
- [ ] Tasks render with title, description, alert link
- [ ] Analyst can click "Complete Task" and submit resolution + feedback
- [ ] Task status updates to 'completed' in database

### Phase 4 ✅
- [ ] Analyst feedback is recorded in outcomes.py
- [ ] If feedback='good', model confidence increases for similar patterns (next alert)
- [ ] Weekly eval harness shows improvement in MITRE accuracy

---

## Next Immediate Action

**Confirm and proceed with Phase 2:**
- [ ] Locate exact auto-triage verdict-setting code in codebase
- [ ] Add task creation hooks
- [ ] Test end-to-end: Alert → Fusion → Task Created → Analyst Completes

**Expected timeline:**
- Phase 2: 2-3 hours
- Phase 3: 4-6 hours
- Phase 4: 2-3 hours
- **Total: 8-12 hours**
