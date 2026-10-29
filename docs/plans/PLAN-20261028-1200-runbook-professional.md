# PLAN-20261028-1200: Professional Runbook System

## Goal
Fix all identified gaps in the Runbook implementation so it matches the correct
five-layer taxonomy (L1 Governance → L2 Automation Rules → L3 Playbook →
L4 Runbook doc → L5 RunbookEvent).

## Problem Summary
Current /runbook page scores 6/10 because:
1. Only two tabs (Ledger placeholder + Automation Rules) — L1 Governance missing entirely
2. Ledger tab is a static link-list, not a real RunbookEvent viewer with subject selector
3. Automation Rule form lacks: subject_type, approval contracts, data/failure/cost/audit
   contracts, playbook_ref, docs_ref, owner_team
4. Rule cards lack: last fired stats, success/failed counts, linked playbook/docs badges
5. RunbookStep (Ledger) lacks: action_slug link, governance decision detail, actor badge
   color, approval info, duration
6. No Governance catalog view showing action definitions with their contracts

## Files / Services Discovered

| File | Layer | Status |
|---|---|---|
| services/api/app/api/v1/endpoints/runbook.py | L2/L5 API | needs expansion |
| services/api/app/services/runbook/action_catalog.py | L1 catalog | complete |
| services/api/app/services/runbook/contracts.py | L1 contracts | complete |
| services/api/app/services/runbook/gate.py | L1 gate | complete |
| services/api/app/services/runbook/read.py | L5 read | needs more fields |
| apps/web/src/components/runbook/runbook.types.ts | types | needs expansion |
| apps/web/src/components/runbook/AutomationRulesView.tsx | L2 UI | needs expansion |
| apps/web/src/components/runbook/RunbookPage.tsx | L5 UI | needs improvement |
| apps/web/src/components/runbook/internal.tsx | L5 rendering | needs improvement |
| apps/web/src/components/runbook/RunbookEditorView.tsx | L3 UI | existing (OK) |
| apps/web/src/app/(app)/runbook/page.tsx | index page | needs 3rd tab + selector |

## Step-by-Step Plan

- [x] 1. Create plan file  
- [x] 2. Backend: Add GET /runbook/governance — returns ACTIONS catalog with contracts  
- [x] 3. Backend: Expand automation_rules schema with subject_type, playbook_ref,
          docs_ref, owner_team, plus run stats (success_count, failed_count, denied_count)  
- [x] 4. Backend: Expand RunbookStep — policy dict already carries GateDecision data  
- [x] 5. Frontend: Expand runbook.types.ts (RunbookPolicy, GovernanceActionEntry)  
- [x] 6. Frontend: New GovernanceView.tsx (action catalog browser with contracts)  
- [x] 7. Frontend: Upgrade AutomationRulesView (contracts panel, stats badges, linked refs)  
- [x] 8. Frontend: Upgrade RunbookPage + internal.tsx (actor badges, status chips,
          governance panel, Policy tab)  
- [x] 9. Frontend: Upgrade /runbook index page (3 tabs: Ledger/Automation/Governance,
          subject selector, remove static Demo view banner)  

## Modified Files Log

| Step | File | Change |
|---|---|---|
| 1 | docs/plans/PLAN-20261028-1200-runbook-professional.md | created |
| 2 | services/api/app/api/v1/endpoints/runbook.py | GET /governance endpoint |
| 3 | services/api/app/api/v1/endpoints/runbook.py | schema expansion + _ensure_rule_extra_columns |
| 5 | apps/web/src/components/runbook/runbook.types.ts | RunbookPolicy + GovernanceActionEntry types |
| 6 | apps/web/src/components/runbook/GovernanceView.tsx | new component |
| 7 | apps/web/src/components/runbook/AutomationRulesView.tsx | form + RuleRow expanded |
| 8 | apps/web/src/components/runbook/internal.tsx | actor badges, status chips, GovernancePanel |
| 8 | apps/web/src/components/runbook/RunbookPage.tsx | 3-tab layout + Policy tab |
| 9 | apps/web/src/app/(app)/runbook/page.tsx | 3-tab page + subject selector |

## Risks & Dependencies
- DB schema: `automation_rules` table may not have subject_type/playbook_ref/docs_ref/owner_team
  columns → add them via safe ALTER TABLE with DEFAULT NULL (non-breaking migration)
- `runbook_events` table may not have action_slug/duration_ms columns → same pattern
- These ALTERs are runtime-safe (nullable, no FK, no index needed for MVP)
