# Phase 3: Governance Hardening — Playbook Steps Respect Approval Gates

## Problem Statement

**Current Gap:** Playbook steps that perform containment actions (e.g., `isolate_host`, `block_ip`, `create_ticket`) execute immediately without consulting governance gates. This bypasses the autonomy policy designed to prevent unauthorized containment.

**Attack Surface:**
- Analyst links a playbook containing `isolate_host` to an L1-level automation rule
- Alert matches → rule executes → playbook starts immediately
- Playbook's `isolate_host` step runs without checking L2/L3 approval gates
- **Result:** Containment action executes with lower governance oversight than if it had been a direct action

**Desired State (Phase 3 Goal):**
- Playbook steps that map to governing actions consult the same L0–L4 autonomy policy
- L2/L3 steps pause the playbook at an `approval_gate` step
- Analyst can approve/reject the paused playbook in the UI
- Resumption triggers the remaining steps

---

## Architecture: Playbook Governance Integration

### New Components

#### 1. Playbook-to-Action Mapping

Add a mapping in `services/agents/app/playbook/engine.py`:

```python
# Playbook step types that perform actions governed by autonomy policy
STEP_TYPE_TO_ACTION: dict[str, str] = {
    "block_ip": "block_ip",
    "isolate_host": "isolate_host",
    "create_ticket": "create_ticket",
    "close_case": "close_case",
    "osquery_live_query": "osquery_live_query",
}

# Step types that do NOT consume governance budget (read-only)
UNGOVERNED_STEPS = {"investigate", "enrich", "notify"}
```

#### 2. Inline Governance Check Step Handler

Add to `services/agents/app/playbook/handlers.py`:

```python
async def handle_approval_gate(
    step: PlaybookStep,
    context: PlaybookExecutionContext,
    db: AsyncSession,
) -> StepResult:
    """
    Pause the playbook at an approval gate.
    
    This step is injected by the engine when a downstream step
    requires governance approval (L2/L3/L4).
    
    Params:
      downstream_step_id: the step that required approval
      downstream_action: the action slug it maps to
      governance_level: L2 | L3 | L4
      alert_id: the alert driving the playbook
    
    Returns:
      Status: "pending_approval" → engine saves state and suspends
              "approved" → engine resumes playbook
              "rejected" → engine terminates playbook
    """
    downstream_step_id = step.params.get("downstream_step_id")
    downstream_action = step.params.get("downstream_action")
    governance_level = step.params.get("governance_level", "L2")
    alert_id = step.params.get("alert_id")
    
    # Query governance policy for this alert + action
    from app.services.autonomy_policy import get_autonomy_policy
    policy = await get_autonomy_policy(alert_id, downstream_action)
    
    # Create approval record in Postgres
    from app.models.playbook_approval import PlaybookApproval
    approval = PlaybookApproval(
        run_id=context.run_id,
        step_id=downstream_step_id,
        action_slug=downstream_action,
        governance_level=governance_level,
        alert_id=alert_id,
        status="pending_approval",
    )
    db.add(approval)
    await db.commit()
    
    return StepResult(
        status="pending_approval",
        output={"approval_record_id": approval.id},
        error=None,
    )
```

#### 3. Governance Check in Engine

Modify `services/agents/app/playbook/engine.py::execute_step()`:

```python
async def execute_step(
    self,
    playbook: Playbook,
    step: PlaybookStep,
    run_id: str,
    context: PlaybookExecutionContext,
    db: AsyncSession,
) -> StepResult:
    """
    Execute a playbook step with governance pre-check.
    """
    # Check if this step type requires governance
    action_slug = STEP_TYPE_TO_ACTION.get(step.type)
    
    if action_slug and context.alert_id:
        # Query autonomy policy for this alert + action
        from app.services.autonomy_policy import query_governance
        governance_result = await query_governance(
            alert_id=context.alert_id,
            action_slug=action_slug,
            severity=context.alert_severity,
            confidence=context.alert_confidence,
        )
        
        # If governance requires approval, inject an approval gate step
        if governance_result.decision in ("requires_l2_approval", "requires_l3_escalation"):
            approval_step = PlaybookStep(
                id=f"gate-before-{step.id}",
                name=f"Approval Gate: {step.name}",
                type="approval_gate",
                params={
                    "downstream_step_id": step.id,
                    "downstream_action": action_slug,
                    "governance_level": governance_result.required_level,
                    "alert_id": context.alert_id,
                },
            )
            result = await handle_approval_gate(approval_step, context, db)
            
            # If approval is pending, suspend playbook
            if result.status == "pending_approval":
                return result  # Engine will save state and pause
    
    # Normal execution path (no governance or pre-approved)
    handler = self.handlers.get(step.type)
    if not handler:
        return StepResult(
            status="failed",
            output=None,
            error=f"No handler for step type: {step.type}",
        )
    
    return await handler(step, context, db)
```

#### 4. Playbook Resumption API

Add to `services/agents/app/api/playbooks.py`:

```python
@router.post("/{playbook_id}/runs/{run_id}/resume")
async def resume_playbook_run(
    playbook_id: str,
    run_id: str,
    action: Literal["approve", "reject"],
    db: AsyncSession = Depends(get_db),
    current_user: AuthUser = Depends(require_permission("alerts:write")),
) -> dict:
    """
    Resume a paused playbook run.
    
    Args:
      action: "approve" to continue, "reject" to terminate
    
    Returns:
      {status, run_id, next_step_id, outcome}
    """
    # Load playbook run from store
    run = await PlaybookStore().get_run(run_id)
    if not run or run["playbook_id"] != playbook_id:
        raise HTTPException(status_code=404, detail="Run not found")
    
    if run["status"] != "pending_approval":
        raise HTTPException(
            status_code=400,
            detail=f"Run is {run['status']}, not pending_approval"
        )
    
    # Load approval record
    approval = await db.execute(
        select(PlaybookApproval)
        .where(PlaybookApproval.run_id == run_id)
        .where(PlaybookApproval.status == "pending_approval")
    )
    approval_rec = approval.scalars().first()
    if not approval_rec:
        raise HTTPException(status_code=404, detail="Approval record not found")
    
    # Record analyst decision in ledger
    await db.execute(
        insert(AlertLedgerEntry).values(
            alert_id=approval_rec.alert_id,
            kind="governance",
            summary=f"Analyst {current_user.email} {action} playbook step: {approval_rec.action_slug}",
            metadata={"run_id": run_id, "approval_id": approval_rec.id},
        )
    )
    
    if action == "reject":
        # Terminate playbook
        run["status"] = "rejected"
        await PlaybookStore().save_run(run)
        return {"status": "rejected", "run_id": run_id}
    
    elif action == "approve":
        # Update approval record
        approval_rec.status = "approved"
        await db.commit()
        
        # Resume playbook execution
        playbook = await PlaybookStore().get(playbook_id)
        engine = PlaybookEngine(handlers=STEP_HANDLERS, db=db)
        
        # Find the next step after the approval gate
        execution_context = PlaybookExecutionContext(
            run_id=run_id,
            alert_id=approval_rec.alert_id,
            alert_severity=run.get("alert_severity"),
            alert_confidence=run.get("alert_confidence"),
        )
        
        outcome = await engine.resume_from_pause(
            playbook=playbook,
            run=run,
            approved_step_id=approval_rec.step_id,
            context=execution_context,
            db=db,
        )
        
        return {
            "status": "resumed",
            "run_id": run_id,
            "outcome": outcome.model_dump(),
        }
```

---

## Database Schema Changes

### New Table: `playbook_approvals`

```sql
CREATE TABLE playbook_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    run_id VARCHAR NOT NULL,
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    step_id VARCHAR NOT NULL,
    action_slug VARCHAR NOT NULL,
    governance_level VARCHAR NOT NULL CHECK (governance_level IN ('L2', 'L3', 'L4')),
    status VARCHAR NOT NULL CHECK (status IN ('pending_approval', 'approved', 'rejected')),
    analyst_email VARCHAR,
    analyst_decision_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    UNIQUE (run_id, step_id)
);

CREATE INDEX idx_playbook_approvals_run_id ON playbook_approvals(run_id);
CREATE INDEX idx_playbook_approvals_status ON playbook_approvals(status);
CREATE INDEX idx_playbook_approvals_alert_id ON playbook_approvals(alert_id);
```

### Extend: `playbook_runs` table

Add optional fields for tracking pause state:

```sql
ALTER TABLE playbook_runs ADD COLUMN (
    paused_at TIMESTAMP WITH TIME ZONE,
    paused_step_id VARCHAR,
    pause_reason VARCHAR
);
```

---

## Frontend Changes

### New Component: `PlaybookApprovalQueue`

Location: `apps/web/src/components/runbook/PlaybookApprovalQueue.tsx`

```typescript
/**
 * Shows pending playbook approval gates in the UI.
 * Analyst can approve/reject each waiting step.
 */
export const PlaybookApprovalQueue: FC = () => {
  const [approvals, setApprovals] = useState<PlaybookApproval[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const resp = await fetch('/api/v1/playbooks/approvals/pending');
      const data = await resp.json();
      setApprovals(data);
      setLoading(false);
    })();
  }, []);

  const handleApprove = async (approvalId: string) => {
    await fetch(`/api/v1/playbooks/approvals/${approvalId}`, {
      method: "POST",
      body: JSON.stringify({ action: "approve" }),
    });
    setApprovals(approvals.filter(a => a.id !== approvalId));
  };

  const handleReject = async (approvalId: string) => {
    await fetch(`/api/v1/playbooks/approvals/${approvalId}`, {
      method: "POST",
      body: JSON.stringify({ action: "reject" }),
    });
    setApprovals(approvals.filter(a => a.id !== approvalId));
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-2">
      {approvals.length === 0 ? (
        <p className="text-sm text-slate-500">No pending playbook approvals</p>
      ) : (
        approvals.map(approval => (
          <div key={approval.id} className="border border-amber-500/40 rounded p-3 bg-amber-900/10">
            <div className="font-medium mb-2">
              Playbook Awaiting Approval: <code>{approval.action_slug}</code>
            </div>
            <div className="text-xs text-slate-400 mb-3">
              Step: {approval.step_id} | Governance Level: {approval.governance_level}
            </div>
            <div className="flex gap-2">
              <button onClick={() => handleApprove(approval.id)} className="...">
                Approve
              </button>
              <button onClick={() => handleReject(approval.id)} className="...">
                Reject
              </button>
            </div>
          </div>
        ))
      )}
    </div>
  );
};
```

---

## Testing Phase 3

### Test Case 3.1: L2 Gate Blocks Containment Step

**Setup:**
- Playbook with `isolate_host` step
- Rule with autonomy level L1
- Alert matching rule

**Expected:**
1. Rule executes → playbook starts
2. Engine checks `isolate_host` step → consults governance → requires L2 approval
3. Engine injects `approval_gate` step before `isolate_host`
4. Playbook status: `pending_approval`
5. Analyst sees approval in UI
6. Analyst clicks "Approve" → playbook resumes
7. `isolate_host` step executes
8. Ledger shows: "Analyst alice approved playbook step: isolate_host"

**API Test:**
```bash
# After approvals endpoint is live
curl -X POST http://localhost:8084/api/v1/playbooks/runs/{run_id}/resume \
  -H "Content-Type: application/json" \
  -H "Cookie: aisoc.session=<jwt>" \
  -d '{"action": "approve"}'
```

### Test Case 3.2: L3 Escalation Creates Incident

**Setup:**
- Same as 3.1, but alert severity `critical` + governance escalation threshold L3

**Expected:**
1. Playbook pauses at `approval_gate` with `governance_level: "L3"`
2. Escalation rule: Create incident ticket in JIRA
3. Analyst notified via Slack
4. Incident ticket shows link to approval in ledger

---

## Implementation Checklist

- [ ] Add playbook-to-action mapping constant to `engine.py`
- [ ] Implement `handle_approval_gate()` step handler
- [ ] Modify `execute_step()` to consult governance policy
- [ ] Create `PlaybookApproval` SQLAlchemy model
- [ ] Create database migration: `playbook_approvals` table
- [ ] Implement `resume_playbook_run()` endpoint
- [ ] Create `PlaybookApprovalQueue` frontend component
- [ ] Integrate queue into `/runbook?tab=tasks` (or new tab)
- [ ] Add tests: Phase 3 test cases in `test_phase_3_governance.py`
- [ ] Verify ledger entries for analyst decisions
- [ ] Document operator runbook: "Approving Paused Playbooks"

---

## Success Criteria

✅ All of the following must pass:

1. **L2 Gate:** Containment step pauses; playbook not resumed until approval
2. **Ledger Trail:** All analyst approvals/rejections recorded in alert ledger
3. **Escalation:** L3 alerts create incident + notify on-call
4. **Resumption:** `POST /api/v1/playbooks/runs/{run_id}/resume` works and continues execution
5. **Rejection:** Reject action terminates playbook gracefully
6. **UI:** Approval queue visible; approve/reject buttons functional

---

## Links & References

- Autonomy Policy: `services/api/app/services/autonomy_policy.py`
- Playbook Engine: `services/agents/app/playbook/engine.py`
- Alert Ledger: `services/api/app/models/alert_ledger.py`
- Governance Docs: `apps/docs/docs/concepts/automation-maturity.md`
