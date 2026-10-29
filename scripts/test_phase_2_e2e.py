#!/usr/bin/env python3
"""
Phase 2 Automated E2E Test: Rule → Playbook Execution

This script tests the complete flow:
1. Create a test playbook on agents service
2. Fetch playbooks via GET /runbook/playbooks
3. Create an automation rule linked to the playbook
4. Create an alert matching the rule
5. Verify playbook execution on agents service
6. Verify ledger entries
"""

import asyncio
import json
import httpx
import uuid
from typing import Any

# Configuration
API_BASE_URL = "http://localhost:8000"
AGENTS_BASE_URL = "http://localhost:8084"
TENANT_ID = "default"
SESSION_COOKIE = None  # Will be set by login or pass manually

# Colors for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


async def log_step(message: str, color=YELLOW):
    print(f"{color}→ {message}{RESET}")


async def log_success(message: str):
    print(f"{GREEN}✓ {message}{RESET}")


async def log_error(message: str):
    print(f"{RED}✗ {message}{RESET}")


async def fetch_with_headers(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    json_data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
):
    """Helper to make requests with session cookie."""
    if headers is None:
        headers = {}
    if SESSION_COOKIE:
        headers["Cookie"] = f"aisoc.session={SESSION_COOKIE}"
    
    if json_data:
        response = await client.request(method, url, json=json_data, headers=headers)
    else:
        response = await client.request(method, url, headers=headers)
    
    return response


async def test_phase_2():
    """Run the complete Phase 2 E2E test."""
    
    await log_step("Phase 2: Rule → Playbook Execution Flow")
    
    async with httpx.AsyncClient() as client:
        # Step 1: Create a test playbook on agents service
        await log_step("Step 1: Creating test playbook on agents service")
        playbook_id = f"test-ddos-{uuid.uuid4().hex[:8]}"
        playbook_payload = {
            "id": playbook_id,
            "name": "Test: DDoS Response",
            "description": "Automated DDoS containment playbook",
            "enabled": True,
            "tags": ["test", "ddos"],
            "author": "e2e-test",
            "version": "1.0.0",
            "steps": [
                {
                    "id": "step-investigate",
                    "name": "Investigate Attack",
                    "type": "investigate",
                    "params": {"context": "Check for ongoing DDoS patterns"},
                },
                {
                    "id": "step-block",
                    "name": "Block Source IP",
                    "type": "block_ip",
                    "params": {"ip": "{{src_ip}}", "reason": "DDoS source"},
                },
            ],
        }
        
        try:
            resp = await fetch_with_headers(
                client,
                "POST",
                f"{AGENTS_BASE_URL}/api/v1/playbooks",
                json_data=playbook_payload,
                headers={"X-Tenant-Id": TENANT_ID},
            )
            if resp.status_code not in (200, 201):
                await log_error(f"Failed to create playbook: {resp.status_code} {resp.text}")
                return False
            created_pb = resp.json()
            await log_success(f"Playbook created: {playbook_id}")
        except Exception as e:
            await log_error(f"Exception creating playbook: {e}")
            return False

        # Step 2: Fetch playbooks via the API /runbook/playbooks endpoint
        await log_step("Step 2: Fetching playbooks via GET /api/v1/runbook/playbooks")
        try:
            resp = await fetch_with_headers(
                client,
                "GET",
                f"{API_BASE_URL}/api/v1/runbook/playbooks",
            )
            if resp.status_code != 200:
                await log_error(f"Failed to fetch playbooks: {resp.status_code}")
                return False
            
            playbooks_list = resp.json()
            await log_success(f"Fetched {len(playbooks_list)} playbooks")
            
            # Verify our newly created playbook is in the list
            found = any(pb["id"] == playbook_id for pb in playbooks_list)
            if not found:
                await log_error(f"Created playbook {playbook_id} not found in list")
                return False
            await log_success(f"Created playbook {playbook_id} found in dropdown list")
        except Exception as e:
            await log_error(f"Exception fetching playbooks: {e}")
            return False

        # Step 3: Create an automation rule linked to the playbook
        await log_step("Step 3: Creating automation rule linked to playbook")
        rule_id = f"test-rule-{uuid.uuid4().hex[:8]}"
        rule_payload = {
            "name": f"Test DDoS Rule {rule_id}",
            "description": "E2E test: rule linked to DDoS response playbook",
            "trigger_type": "alert.created",
            "conditions": [
                {"field": "severity", "op": "in", "value": ["high", "critical"]}
            ],
            "action_slug": "comment_case",  # Use non-containment action for L1
            "autonomy_level": "L1",
            "dry_run": False,  # Execute the action
            "enabled": True,
            "priority": 50,
            "subject_type": "alert",
            "playbook_ref": playbook_id,  # KEY: Link to the playbook
        }
        
        try:
            resp = await fetch_with_headers(
                client,
                "POST",
                f"{API_BASE_URL}/api/v1/runbook/automation-rules",
                json_data=rule_payload,
            )
            if resp.status_code not in (200, 201):
                await log_error(f"Failed to create rule: {resp.status_code} {resp.text}")
                return False
            created_rule = resp.json()
            rule_id_db = created_rule.get("id", rule_id)
            await log_success(f"Rule created: {rule_id_db} → playbook {playbook_id}")
        except Exception as e:
            await log_error(f"Exception creating rule: {e}")
            return False

        # Step 4: Create or ingest a test alert matching the rule condition
        await log_step("Step 4: Creating test alert (severity: critical) to match rule")
        alert_payload = {
            "title": "Potential DDoS Attack",
            "description": "Unusual traffic spike detected from external source",
            "severity": "critical",
            "status": "new",
            "source": "splunk",
            "affected_ips": ["192.0.2.100"],
            "tags": ["network", "external"],
            "confidence": 85,
        }
        
        try:
            resp = await fetch_with_headers(
                client,
                "POST",
                f"{API_BASE_URL}/api/v1/alerts",
                json_data=alert_payload,
            )
            if resp.status_code not in (200, 201):
                await log_error(f"Failed to create alert: {resp.status_code} {resp.text}")
                return False
            created_alert = resp.json()
            alert_id = created_alert.get("id")
            await log_success(f"Alert created: {alert_id} (severity: critical)")
        except Exception as e:
            await log_error(f"Exception creating alert: {e}")
            return False

        # Step 5: Give the system a moment to process the rule
        await log_step("Step 5: Waiting for rule executor to process alert...")
        await asyncio.sleep(3)

        # Step 6: Verify playbook execution on agents service
        await log_step("Step 6: Verifying playbook was started")
        try:
            resp = await fetch_with_headers(
                client,
                "GET",
                f"{AGENTS_BASE_URL}/api/v1/playbooks/runs",
                headers={"X-Tenant-Id": TENANT_ID},
            )
            if resp.status_code != 200:
                await log_error(f"Failed to fetch playbook runs: {resp.status_code}")
                return False
            
            runs = resp.json()
            matching_run = next(
                (r for r in runs if r.get("playbook_id") == playbook_id),
                None,
            )
            
            if not matching_run:
                await log_error(f"No playbook runs found for {playbook_id}")
                return False
            
            await log_success(f"Playbook run found: {matching_run.get('run_id')}")
            print(f"  Status: {matching_run.get('status')}")
            print(f"  Steps executed: {len(matching_run.get('step_results', []))}")
            for step in matching_run.get("step_results", []):
                print(f"    - {step.get('name')}: {step.get('status')}")
        except Exception as e:
            await log_error(f"Exception verifying playbook run: {e}")
            return False

        # Step 7: Verify ledger entries
        await log_step("Step 7: Verifying ledger entries in alert")
        try:
            resp = await fetch_with_headers(
                client,
                "GET",
                f"{API_BASE_URL}/api/v1/alerts/{alert_id}",
            )
            if resp.status_code != 200:
                await log_error(f"Failed to fetch alert: {resp.status_code}")
                return False
            
            alert_data = resp.json()
            ledger_entries = alert_data.get("ledger", [])
            
            # Look for entries indicating rule match and playbook start
            rule_matched = any(
                "Automation rule" in str(entry.get("summary", ""))
                for entry in ledger_entries
            )
            
            if rule_matched:
                await log_success("Ledger shows rule matched and executed")
                matching_entries = [
                    e for e in ledger_entries
                    if "Automation rule" in str(e.get("summary", ""))
                ]
                for entry in matching_entries:
                    print(f"  {entry.get('summary')}")
            else:
                await log_error("No rule execution entry found in ledger")
                return False
        except Exception as e:
            await log_error(f"Exception fetching alert ledger: {e}")
            return False

        # All tests passed
        await log_step("✅ Phase 2 E2E Test Complete!")
        print(f"""
{GREEN}Test Results:{RESET}
  ✓ Playbook created and fetched
  ✓ Rule linked to playbook successfully
  ✓ Alert created and matched rule
  ✓ Playbook execution confirmed
  ✓ Ledger entries recorded

{YELLOW}Next Steps:{RESET}
  1. Manually verify playbook in UI at /runbook?tab=rules
  2. Test with L2 governance level to verify approval gates
  3. Proceed to Phase 3: Governance hardening
""")
        return True


async def main():
    """Entry point."""
    try:
        success = await test_phase_2()
        exit(0 if success else 1)
    except Exception as e:
        await log_error(f"Unexpected error: {e}")
        exit(1)


if __name__ == "__main__":
    asyncio.run(main())
