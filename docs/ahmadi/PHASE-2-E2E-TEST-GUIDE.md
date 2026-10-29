# Phase 2: End-to-End Test Guide — Rule → Playbook Execution

## Overview

This document provides a step-by-step guide to test that:
1. ✅ Frontend dropdown loads playbooks correctly from `GET /runbook/playbooks`
2. ✅ Automation rules can be created and linked to playbooks
3. ✅ When a rule matches an alert, the linked playbook is actually executed on the agents service

## Prerequisites

- Agents service (`services/agents`) is running at `http://agents:8084` (or configured via `AGENTS_SERVICE_URL`)
- API service (`services/api`) is running at `http://localhost:8000`
- PostgreSQL is accessible with a seeded tenant
- At least one playbook exists in the agents service (or use the bundled default template)

## Test Scenario: DDoS Response Playbook + Rule

### Step 1: Verify Playbooks Load in Frontend

**Objective:** Confirm the dropdown shows available playbooks.

**Action:**
```bash
# In your browser, navigate to the Automation Rules editor
# URL: http://localhost:3000/runbook?tab=rules → Click "Create new rule" or edit existing rule
```

**Expected Result:**
- Scroll down to the "Linked Playbook" field (now a dropdown instead of text input)
- The dropdown should populate with a list like:
  ```
  None
  DDoS: SYN Flood
  Ransomware Response
  Phishing Triage
  ```
- If the dropdown shows "No playbooks found": Check agents service logs for errors, verify `AGENTS_SERVICE_URL` is configured

---

### Step 2: Create a Test Playbook (if needed)

**Objective:** Ensure there's at least one playbook to link.

**Action — via API:**
```bash
# Create a simple test playbook on agents service
curl -X POST http://localhost:8084/api/v1/playbooks \
  -H "Content-Type: application/json" \
  -d '{
    "id": "test-ddos-response",
    "name": "Test: DDoS Response",
    "description": "Automated DDoS containment playbook",
    "enabled": true,
    "steps": [
      {
        "id": "step-1",
        "name": "Investigate Attack",
        "type": "investigate",
        "params": {}
      },
      {
        "id": "step-2",
        "name": "Block IP",
        "type": "block_ip",
        "params": {"ip": "{{src_ip}}"}
      }
    ]
  }'
```

**Expected Response:**
```json
{
  "id": "test-ddos-response",
  "name": "Test: DDoS Response",
  "status": 201
}
```

---

### Step 3: Create an Automation Rule Linked to Playbook

**Objective:** Wire a rule to the playbook.

**Action — via UI:**
1. Navigate to `/runbook?tab=rules`
2. Click **Create new rule**
3. Fill in:
   - **Name:** `Test DDoS Rule`
   - **Trigger:** `Alert created`
   - **Conditions:**
     - Field: `severity`
     - Op: `in`
     - Value: `["high","critical"]`
   - **Action:** `block_ip` (or any action)
   - **Autonomy Level:** `L1` (Assisted)
   - **Dry Run:** `true`
   - **Linked Playbook:** Select `Test: DDoS Response` from dropdown ← **KEY STEP**
4. Click **Save**

**Alternative — via API:**
```bash
curl -X POST http://localhost:8000/api/v1/runbook/automation-rules \
  -H "Content-Type: application/json" \
  -H "Cookie: aisoc.session=<your-jwt-here>" \
  -d '{
    "name": "Test DDoS Rule",
    "description": "Rule linked to playbook",
    "trigger_type": "alert.created",
    "conditions": [
      {"field": "severity", "op": "in", "value": ["high", "critical"]}
    ],
    "action_slug": "block_ip",
    "autonomy_level": "L1",
    "dry_run": true,
    "enabled": true,
    "priority": 50,
    "subject_type": "alert",
    "playbook_ref": "test-ddos-response"
  }'
```

**Expected Result:**
- Rule saved with `playbook_ref: "test-ddos-response"`
- In the rule list, you see the rule row with the playbook name displayed

---

### Step 4: Create or Ingest a Test Alert

**Objective:** Trigger the rule by creating an alert that matches the condition.

**Action — via API (create alert):**
```bash
curl -X POST http://localhost:8000/api/v1/alerts \
  -H "Content-Type: application/json" \
  -H "Cookie: aisoc.session=<your-jwt-here>" \
  -d '{
    "title": "Potential DDoS Attack",
    "description": "Unusual traffic spike detected",
    "severity": "critical",
    "status": "new",
    "source": "splunk",
    "affected_ips": ["10.0.1.100"],
    "tags": ["network", "external"]
  }'
```

**OR — via Connector (if you have one configured):**
- Ingest a real or synthetic event from Splunk / another connector with `severity: critical`

**Expected Result:**
- Alert created with ID (e.g., `alert-uuid-here`)
- Alert appears in `/alerts` dashboard

---

### Step 5: Verify Playbook Execution

**Objective:** Confirm the playbook actually started when the rule matched.

**Action — Check Playbook Runs:**

1. **Via API:**
   ```bash
   # Get the playbook run details
   curl http://localhost:8084/api/v1/playbooks/runs \
     -H "X-Tenant-Id: default"
   ```

   **Expected Response:**
   ```json
   [
     {
       "run_id": "run-uuid-here",
       "playbook_id": "test-ddos-response",
       "status": "completed",
       "step_results": [
         {"step_id": "step-1", "name": "Investigate Attack", "status": "success"},
         {"step_id": "step-2", "name": "Block IP", "status": "success"}
       ]
     }
   ]
   ```

2. **Via Frontend:**
   - Navigate to `/alerts` → click the alert → Expand "Investigation Rail"
   - Look for "Linked Playbook" section or check the alert's ledger
   - You should see: `Playbook "Test: DDoS Response" started with run ID: run-uuid-here`

3. **Via Runbook Ledger:**
   - Navigate to `/runbook?tab=ledger` (if available)
   - Filter by rule name "Test DDoS Rule"
   - You should see a ledger entry:
     ```
     Stage: respond
     Kind: action
     Action: block_ip
     Summary: "Automation rule 'Test DDoS Rule' → block_ip (allowed, L1) → started playbook test-ddos-response"
     ```

---

### Step 6: Verify Governance Interaction (Critical)

**Objective:** Confirm that governance gates are respected before playbook starts.

**Action:**

Update the rule to use autonomy level **L2** (which requires approval):
```bash
curl -X PATCH http://localhost:8000/api/v1/runbook/automation-rules/<rule-id> \
  -H "Content-Type: application/json" \
  -H "Cookie: aisoc.session=<your-jwt-here>" \
  -d '{"autonomy_level": "L2"}'
```

Ingest another alert matching the rule's conditions.

**Expected Behavior:**
- Rule evaluation: `denied: awaiting analyst approval of block_ip; the playbook would act ahead of it`
- Playbook: **NOT started** (because approval is still pending)
- Ledger entry: `Automation rule 'Test DDoS Rule' denied: awaiting analyst approval...`

Once analyst approves the rule in the UI (`/runbook?tab=tasks`):
- Playbook **SHOULD start** on approval release
- Status changes: `allowed: L2 (governance approved)`

---

## Troubleshooting

### Playbook not appearing in dropdown
- ✅ Verify agents service is reachable: `curl http://agents:8084/api/v1/playbooks`
- ✅ Check `AGENTS_SERVICE_URL` env var in API service
- ✅ Check browser network tab for 404/500 on `/api/v1/runbook/playbooks`
- ✅ Check API logs: `docker logs <api-container> | grep list_playbooks`

### Playbook linked but not executed
- ✅ Check rule matched: See ledger entry "Automation rule 'Test DDoS Rule' matched"
- ✅ Check governance gate: If rule outcome is "denied", playbook won't start
- ✅ Check `_AGENTS_TENANT_SIGNING_KEY` is configured on both services (if HMAC is required)
- ✅ Check agents service logs for `playbook_start_transport_failed` or `playbook_start_rejected`

### Playbook runs but steps fail
- ✅ Check playbook's step types (e.g., `investigate`, `block_ip`) are supported by engine
- ✅ Check step params are valid (e.g., `case_id` must exist for `investigate` step)
- ✅ Review playbook run result in agents service logs

---

## Success Criteria

✅ All of the following must pass:

1. **Dropdown loads:** Playbook list appears without errors
2. **Rule created:** Rule saved with `playbook_ref` set
3. **Rule matches:** Alert triggers rule, ledger shows "matched"
4. **Playbook starts:** Ledger shows "started playbook", playbook run exists on agents
5. **Governance respected:** L2 rules block playbook start until approval
6. **Steps execute:** Playbook steps run to completion (or fail gracefully)

---

## Next Steps (Phase 3)

Once Phase 2 passes, Phase 3 hardens governance:

- [ ] Playbook steps that map to actions (e.g., `isolate_host`) consult governance gates
- [ ] L2/L3 containment steps pause the playbook at an `approval` gate
- [ ] Analyst can resume or reject the playbook in the UI

See `PHASE-3-GOVERNANCE-HARDENING.md` for implementation details.
