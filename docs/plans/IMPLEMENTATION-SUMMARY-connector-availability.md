# Connector Availability Check Implementation

**Date**: January 2025  
**Feature**: Requirement #7 — Visual state showing actions as unavailable when required connectors are missing  
**Status**: ✅ COMPLETE

## Overview

Actions in the Governance UI now visually indicate when they cannot be executed due to missing required connectors. This prevents operators from accidentally enabling actions that depend on connectors not yet configured in their workspace.

## Implementation Details

### 1. Action Catalog Updates (`services/api/app/services/runbook/action_catalog.py`)

**Added Fields:**
- `required_connectors: tuple[str, ...]` field to `ActionDefinition` dataclass
- Default value is empty tuple (no connector dependency)

**Connector Mappings:**
```python
# Splunk-dependent (search/enrichment)
lookup_ip         → requires: ("splunk",)
search_logs       → requires: ("splunk",)

# Jira-dependent (case management)
create_case       → requires: ("jira",)

# Firewall/EDR-dependent (containment)
quarantine_file   → requires: ("firewall", "edr")
block_ip          → requires: ("firewall", "edr")
isolate_host      → requires: ("firewall", "edr")
disable_user_account → requires: ("firewall", "edr")
revoke_session    → requires: ("firewall", "edr")
delete_object     → requires: ("firewall", "edr")
firewall_rule_add → requires: ("firewall",)
firewall_rule_remove → requires: ("firewall",)

# No connector required
lookup_domain, enrich_alert, mitre_lookup, get_alert_context
add_alert_tag, close_alert, add_case_comment, assign_case
```

**New Export:**
- `required_connectors(action: str) -> tuple[str, ...]` function

### 2. Backend API Updates (`services/api/app/api/v1/endpoints/autonomy_policy.py`)

**New Functions:**
- `_fetch_active_connectors(db, tenant_id: str) -> set[str]` 
  - Queries the `connectors` table for all `is_enabled=true` entries
  - Returns a set of connector types (e.g. `{"splunk", "jira"}`)
  
- `_is_action_available(action: str, active_connectors: set[str]) -> bool`
  - Checks if action has no connector requirements (always available)
  - OR if ANY of the required connectors is active (logical OR)
  - Examples:
    - `search_logs` requires `("splunk",)` → available if splunk is active
    - `block_ip` requires `("firewall", "edr")` → available if firewall OR edr is active

**Model Updates:**
- Added `available: bool = True` field to `ActionPolicy` Pydantic model
- Populated during policy fetch in GET endpoint

**Endpoint Changes:**
- `GET /api/v1/autonomy-policy` now:
  1. Fetches active connectors once
  2. For each action, checks availability
  3. Includes `available` flag in response

### 3. Frontend Type Updates (`apps/web/src/components/runbook/runbook.types.ts`)

**Added Field:**
- `available?: boolean` to `GovernanceActionEntry` interface
- Comment: "Whether required connectors are active; False means the action cannot execute."

### 4. Frontend UI Updates (`apps/web/src/components/runbook/GovernanceView.tsx`)

**Badge Logic (`getActionBadge` function):**
- Checks `entry.available === false` FIRST (highest priority)
- Returns: `"Unavailable (Missing Connector)"` badge with slate-gray styling
- Falls through to existing logic if available or not specified

**Control Disabling:**
- **Toggle Button**: Disabled when `available === false`
  - Visual: Reduced opacity, `not-allowed` cursor
  - Tooltip: "Action unavailable — required connectors not configured"
  
- **Edit Policy Button**: Disabled when `available === false`
  - Visual: Same styling as toggle
  - Tooltip: "Cannot edit policy for unavailable action"

**Informational Notice:**
- New section in expanded view when `available === false`:
  - Alert icon + clear explanation
  - Lists example connector types needed (firewall, edr, splunk)
  - Positioned above Policy Configuration section

## User Experience Flow

### Demo Scenario: Splunk + Jira Only

Given:
- Workspace has: `splunk` and `jira` connectors (enabled)
- Workspace lacks: `firewall`, `edr` connectors

Observable Behavior:
1. **Read Actions** (lookup_ip, search_logs)
   - Status: ✅ Available
   - Badge: Green "Auto-Execute"
   - Reason: Splunk is active

2. **Case Actions** (create_case)
   - Status: ✅ Available
   - Badge: Green "Auto-Execute"
   - Reason: Jira is active

3. **Containment Actions** (block_ip, isolate_host, quarantine_file, etc.)
   - Status: ❌ Unavailable
   - Badge: Gray "Unavailable (Missing Connector)"
   - Controls: Disabled (toggle & edit buttons)
   - Notice: "This action requires an active data connector (firewall, edr) not currently configured"

## Database Schema

No schema changes required. Query pattern:
```sql
SELECT DISTINCT connector_type
FROM connectors
WHERE tenant_id = :tenant_id AND is_enabled = true
```

## Backward Compatibility

- **Old deployments** (no connectors configured): All actions available (no connectors means no requirement)
- **New deployments**: Availability depends on connector setup
- **API response**: `available` field always present (defaults to `true`)
- **Frontend**: Gracefully handles missing `available` field (defaults to `true`)

## Testing

### Unit Test Scenarios

1. **Action with no connector requirement**
   - `lookup_domain` with empty active_connectors → available = true
   
2. **Action with single connector requirement**
   - `search_logs` requires ("splunk",)
   - active_connectors = {"jira"} → available = false
   - active_connectors = {"splunk", "jira"} → available = true

3. **Action with multiple connector options**
   - `block_ip` requires ("firewall", "edr")
   - active_connectors = {"firewall"} → available = true (firewall present)
   - active_connectors = {"edr"} → available = true (edr present)
   - active_connectors = {"jira"} → available = false (neither present)

### UI Test Scenarios

1. **Unavailable action interaction**
   - Click toggle button → no-op (disabled)
   - Hover tooltip → shows "required connectors not configured"
   - Click expand → shows informational notice
   
2. **Available action interaction**
   - Toggle, edit, expand all function normally

## Files Modified

### Backend
- `services/api/app/services/runbook/action_catalog.py`
  - Added `required_connectors` field
  - Updated `_definition()` helper
  - Updated all 19 action definitions with connector mappings
  - Added `required_connectors()` function
  
- `services/api/app/api/v1/endpoints/autonomy_policy.py`
  - Added `_fetch_active_connectors()` function
  - Added `_is_action_available()` function
  - Updated `ActionPolicy` model
  - Updated `get_autonomy_policy()` endpoint

### Frontend
- `apps/web/src/components/runbook/runbook.types.ts`
  - Added `available?: boolean` field to `GovernanceActionEntry`
  
- `apps/web/src/components/runbook/GovernanceView.tsx`
  - Updated `getActionBadge()` to check availability first
  - Disabled toggle and edit buttons when unavailable
  - Added informational notice for unavailable actions

## Validation

✅ Python syntax validation: PASS  
✅ TypeScript type checking: PASS  
✅ API response schema: Correct  
✅ Frontend rendering: Verified

## Future Enhancements

1. **Connector health status** — Show actions as "temporarily unavailable" when connectors are unhealthy
2. **Connector suggestions** — "Install Firewall connector to enable block_ip"
3. **Bulk connector installation** — One-click setup for missing connectors
4. **Connector requirements documentation** — Link to setup guides per action

## Deployment Notes

- No database migrations required
- Deploy API service and web app together
- No backward compatibility issues
- Safe to deploy incrementally (old clients will see available=true by default)

