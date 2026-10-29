# Connector Availability Check — UI Visual Guide

## Scenario: Workspace with Only Splunk + Jira Connectors

### 1. AVAILABLE Actions (Splunk + Jira Connected)

#### `search_logs` — Search Log Telemetry
```
┌─────────────────────────────────────────────────────────┐
│  📊 Search Log Telemetry                   [System Core]  │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ ✓ Auto-Execute    Impact: Read-Only               │ │
│  └─────────────────────────────────────────────────────┘ │
│  [read]                                             [🔌] │
│  search_logs                                         [▶]  │
└─────────────────────────────────────────────────────────┘
```
- **Status**: ✅ Green "Auto-Execute"
- **Controls**: Toggle (✓) and Edit buttons ENABLED
- **Reason**: Splunk connector is active

#### `create_case` — Open a Case
```
┌─────────────────────────────────────────────────────────┐
│  📋 Open a Case                           [System Core]  │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ ✓ Auto-Execute    Impact: Low-Risk                │ │
│  └─────────────────────────────────────────────────────┘ │
│  [case]                                              [🔌] │
│  create_case                                         [▶]  │
└─────────────────────────────────────────────────────────┘
```
- **Status**: ✅ Green "Auto-Execute"
- **Controls**: Toggle (✓) and Edit buttons ENABLED
- **Reason**: Jira connector is active

---

### 2. UNAVAILABLE Actions (Firewall/EDR Not Configured)

#### `block_ip` — Block an IP Address
```
┌─────────────────────────────────────────────────────────┐
│  🚫 Block an IP Address                   [System Core]  │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ ⚠ Unavailable (Missing Connector)                 │ │
│  └─────────────────────────────────────────────────────┘ │
│  [containment]                                       [🔌] │
│  block_ip                                            [▶]  │
│                                                    (grayed)
└─────────────────────────────────────────────────────────┘

[Expanded View]
┌─────────────────────────────────────────────────────────┐
│  ⚠ This action requires an active data connector      │
│    (firewall, edr) which is not currently configured │
│    for this workspace.                               │
│                                                      │
│  Policy Configuration                                │
│  Thresholds: Auto @ 90% • Review @ 70% • Escalate   │
│              @ 40%                                   │
│                                                      │
│                        [Edit Policy] (disabled)     │
│                                                      │
│  Test Policy Behavior                                │
│  [Test with 90% confidence] [Test with 70%...]      │
│                                                      │
│  Technical Details                                   │
│  ╔═══════════════════════════════════════════════╗  │
│  ║ Blast Radius: high                            ║  │
│  ║ Category: containment                         ║  │
│  ║ Default Dry-run: true                         ║  │
│  ╚═══════════════════════════════════════════════╝  │
│                                                      │
│  ⚠ Containment actions are always executed in      │
│    dry-run mode by default and require human      │
│    approval before real execution.                │
└─────────────────────────────────────────────────────────┘
```

Key visual indicators:
- **Badge Color**: Gray/slate (instead of red/orange)
- **Label**: "Unavailable (Missing Connector)"
- **Controls**: 
  - Toggle button: Grayed out, `cursor: not-allowed`
  - Edit Policy button: Grayed out, disabled
  - Hover tooltips explain why
- **Info Notice**: Displayed in expanded view

#### `quarantine_file` — Quarantine a File
```
┌─────────────────────────────────────────────────────────┐
│  🔒 Quarantine a File                     [System Core]  │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ ⚠ Unavailable (Missing Connector)                 │ │
│  └─────────────────────────────────────────────────────┘ │
│  [containment]  ⚠ Requires Human Approval           [🔌] │
│  quarantine_file                                     [▶]  │
│                                                    (grayed)
└─────────────────────────────────────────────────────────┘
```

---

### 3. Partially Available Actions (One Connector Present)

#### `isolate_host` — Isolate from Network (Firewall Present, EDR Missing)
```
┌─────────────────────────────────────────────────────────┐
│  🛡️ Isolate a Host from Network           [System Core]  │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ ⚠ Requires Human Review    Impact: High-Risk     │ │
│  └─────────────────────────────────────────────────────┘ │
│  [containment]  ⚠ Requires Human Approval           [🔌] │
│  isolate_host                                        [▶]  │
└─────────────────────────────────────────────────────────┘
```
- **Status**: ✅ Available (because firewall is present; EDR optional)
- **Badge**: Orange "Requires Human Review"
- **Reason**: Requires ("firewall", "edr") — firewall IS active, so available=true

---

### 4. LIST VIEW — Governance Tab

```
═══════════════════════════════════════════════════════════
  GOVERNANCE — Action Policies
═══════════════════════════════════════════════════════════

Policy Status (sorted by blast_radius, then name):

━━━━ READ Actions (Auto by Default) ━━━━
  ✅ lookup_ip               Auto-Execute (Splunk)
  ✅ lookup_domain           Auto-Execute
  ✅ search_logs             Auto-Execute (Splunk)
  ✅ enrich_alert            Auto-Execute
  ✅ mitre_lookup            Auto-Execute
  ✅ get_alert_context       Auto-Execute

━━━━ CASE Actions (Low Risk) ━━━━
  ✅ add_alert_tag           Auto-Execute
  ✅ close_alert             Review Required
  ✅ create_case             Auto-Execute (Jira)
  ✅ add_case_comment        Review Required
  ✅ assign_case             Review Required

━━━━ CONTAINMENT Actions (High Risk, Requires Firewall/EDR) ━━━━
  ❌ quarantine_file         Unavailable (Missing Connector)
  ❌ block_ip                Unavailable (Missing Connector)
  ❌ isolate_host            Unavailable (Missing Connector)
  ❌ disable_user_account    Unavailable (Missing Connector)
  ❌ revoke_session          Unavailable (Missing Connector)
  ❌ delete_object           Unavailable (Missing Connector)
  ❌ firewall_rule_add       Unavailable (Missing Connector)
  ❌ firewall_rule_remove    Unavailable (Missing Connector)

═══════════════════════════════════════════════════════════
```

Legend:
- ✅ Green = Available
- ❌ Gray = Unavailable (missing connector)
- ⚠️ Orange/Red = Requires approval

---

## API Response Shape

```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "actions": [
    {
      "action": "lookup_ip",
      "blast_radius": "read",
      "thresholds": {
        "auto": 0.0,
        "review": 0.0,
        "escalation": 0.0
      },
      "default_thresholds": {
        "auto": 0.0,
        "review": 0.0,
        "escalation": 0.0
      },
      "overridden": false,
      "enabled": true,
      "is_system_core": true,
      "available": true
    },
    {
      "action": "block_ip",
      "blast_radius": "high",
      "thresholds": {
        "auto": 0.9,
        "review": 0.7,
        "escalation": 0.4
      },
      "default_thresholds": {
        "auto": 0.9,
        "review": 0.7,
        "escalation": 0.4
      },
      "overridden": false,
      "enabled": true,
      "is_system_core": true,
      "available": false
    }
  ]
}
```

---

## Connector Requirements Matrix

| Action | Category | Required Connector(s) | Default Splunk+Jira | With Firewall |
|--------|----------|----------------------|---------------------|---------------|
| lookup_ip | read | splunk | ✅ | ✅ |
| lookup_domain | read | — | ✅ | ✅ |
| search_logs | read | splunk | ✅ | ✅ |
| enrich_alert | read | — | ✅ | ✅ |
| mitre_lookup | read | — | ✅ | ✅ |
| get_alert_context | read | — | ✅ | ✅ |
| add_alert_tag | case | — | ✅ | ✅ |
| close_alert | case | — | ✅ | ✅ |
| create_case | case | jira | ✅ | ✅ |
| add_case_comment | case | — | ✅ | ✅ |
| assign_case | case | — | ✅ | ✅ |
| **quarantine_file** | **containment** | **firewall, edr** | ❌ | ✅ |
| **block_ip** | **containment** | **firewall, edr** | ❌ | ✅ |
| **isolate_host** | **containment** | **firewall, edr** | ❌ | ✅ |
| **disable_user_account** | **containment** | **firewall, edr** | ❌ | ✅ |
| **revoke_session** | **containment** | **firewall, edr** | ❌ | ✅ |
| **delete_object** | **containment** | **firewall, edr** | ❌ | ✅ |
| **firewall_rule_add** | **containment** | **firewall** | ❌ | ✅ |
| **firewall_rule_remove** | **containment** | **firewall** | ❌ | ✅ |

