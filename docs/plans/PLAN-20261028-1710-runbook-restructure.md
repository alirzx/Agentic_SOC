## Goal

Correct the Runbook scope so it matches the actual SOC/MSSP definition and the current delivery priorities:

- Runbook is the standardized operational procedure for a security workflow: what to do, in what order, and under which decision points.
- Enrichment work (custom SPL, rule enrichment, llm_payload creation, query-mode fallback logic) remains valid and must stay in the enrichment layer, not as the full definition of Runbook.
- The current plan was too broad because it mixed four different concepts:
  1. enrichment logic
  2. operational Runbook workflow
  3. lightweight automation rules
  4. SOAR / playbook orchestration

This revised plan keeps only the minimal Runbook scope, keeps Automation Rules as a narrow supporting layer, removes the Visual Editor from the current phase, and excludes SOAR from the immediate scope.

## Approved Scope Decision

### Keep — Automation Rules, but only as a lightweight support layer

- Automation Rules are related to Runbook, but they are not the Runbook itself.
- They should remain as a simple condition -> action mapping layer used by analysts when a straightforward operational rule is helpful.
- Keep them small, readable, and explicit; no broad workflow engine, no visual orchestration, no multi-step playbook runtime.
- If a use case needs a real orchestration engine, it belongs in a separate SOAR initiative and is not part of this plan.

### Defer / remove — Visual Editor

- The Visual Editor is not needed in the current phase.
- It is more complex than the present requirement, introduces unnecessary product surface area, and overlaps with SOAR-style authoring.
- It should be removed from the current Runbook scope and handled only in a future, explicitly scoped design effort.

### Exclude — SOAR

- SOAR is out of scope for this stage.
- The current plan is about operational procedure and analyst guidance, not automated multi-step execution.
- No playbook execution engine, no canvas-based automation authoring, no workflow runtime in this phase.

## Files / Services Discovered

- docs/plans/PLAN-20261027-1501-runbook-page.md
- docs/plans/RUNBOOK-PROGRESS.md
- services/connectors/app/connectors/splunk.py
- services/api/app/services/splunk_enrichment.py
- services/api/app/services/runbook/
- services/api/app/api/v1/endpoints/runbook.py
- services/api/app/models/alert.py
- services/api/app/services/alert_rail.py
- services/api/app/services/case_investigation_brief.py
- apps/web/src/app/(app)/runbook/page.tsx
- apps/web/src/components/runbook/AutomationRulesView.tsx
- apps/web/src/components/runbook/RunbookEditorView.tsx
- apps/web/src/components/runbook/RunbookPage.tsx (if present in branch state)
- services/api/migrations/062_runbook.sql and related migration files

## Keep vs. Remove

### Keep — valid enrichment work

- Custom SPL / simple-query / auto-query logic in the Splunk connector
- Rule enrichment and macro enrichment flow
- llm_payload assembly and fallback logic from alert fields
- Provenance metadata attached to alerts or raw events
- Ledger event recording for operational actions and analyst context
- Minimal policy gate only when it supports recorded governance and not as a full execution engine

### Keep — minimal Runbook structure

- /runbook page shell
- simple operational procedure view
- step-by-step analyst guidance
- decision points and notes
- optional lightweight automation rules list
- minimal API structure for runbook records and rule retrieval
- tenant-aware auth and permission boundaries

### Remove / defer — over-scoped items

- Any concept that treats enrichment as the entire Runbook definition
- Full visual editor / canvas workflow authoring
- SOAR orchestration engine and execution features
- Broad playbook / automation schemas beyond the minimal rules layer
- Template persistence and graphical workflow logic unless explicitly approved later
- Any design that mixes:
  - procedural guidance
  - enrichment logic
  - automation policy
  - SOAR execution
  into one undifferentiated feature set

## Step-by-Step Plan

| Step | File / Service | Action | Status |
|---|---|---|---|
| 1 | docs/plans/PLAN-20261027-1501-runbook-page.md | Treat as legacy / over-scoped reference; do not use as source of truth | [ ] pending |
| 2 | docs/plans/RUNBOOK-PROGRESS.md | Reconcile against the corrected definition and remove false assumptions | [ ] pending |
| 3 | services/connectors/app/connectors/splunk.py | Preserve custom query and enrichment logic as an enrichment capability | [ ] pending |
| 4 | services/api/app/services/splunk_enrichment.py | Keep payload-building and enrichment rules, but do not tie them to the full Runbook stack | [ ] pending |
| 5 | services/api/app/models/alert.py | Keep llm_payload and provenance contracts only where necessary for enrichment support | [ ] pending |
| 6 | services/api/app/services/runbook/ | Keep only a minimal operational record / ledger model and remove broad automation assumptions | [ ] pending |
| 7 | services/api/app/api/v1/endpoints/runbook.py | Rebuild only the minimal API surface for runbook records and simple rule retrieval | [ ] pending |
| 8 | apps/web/src/app/(app)/runbook/page.tsx | Keep a minimal route shell and analyst-oriented workflow layout only | [ ] pending |
| 9 | apps/web/src/components/runbook/AutomationRulesView.tsx | Keep only as a lightweight rule cabinet; avoid building a full automation system | [ ] pending |
| 10 | apps/web/src/components/runbook/RunbookEditorView.tsx | Remove from current scope and defer to a separate initiative | [ ] pending |
| 11 | services/api/migrations/062_runbook.sql and related migrations | Keep the minimal ledger schema only; avoid broad action-template and SOAR database expansion | [ ] pending |
| 12 | docs/operations and app docs | Add a short explanation distinguishing Runbook vs. Playbook vs. Enrichment vs. Automation rules | [ ] pending |

## Modified Files Log

- This document was updated to reflect the approved scope reset.
- No production code changes were made in this step; the scope is now narrowed to the correct Runbook definition before the next implementation pass.

## Risks & Dependencies

- Risk: continuing to equate Runbook with SOAR will create a large, unstable implementation surface.
- Dependency: enrichment logic must remain working and should remain clearly separated from the Runbook workflow itself.
- Dependency: the /runbook UI should stay concise and analyst-first; no visual authoring flow is required for the current phase.
- Risk: schema churn without a clear boundary will expand the feature scope unnecessarily; keep the data model minimal and operational.
- Dependency: after scope approval, implementation should proceed in two passes: first, keep the enrichment and minimal structure intact; second, simplify the UI/API to the minimal Runbook definition.
