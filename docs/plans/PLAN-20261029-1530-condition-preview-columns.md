## Goal
Fix the automation-rule Conditions UX so the selected condition fields are shown as live-preview columns instead of as a noisy note under each condition row.

## Files / Services Discovered
- apps/web/src/components/runbook/AutomationRulesView.tsx
- services/api/app/api/v1/endpoints/runbook.py
- apps/web/src/components/runbook/AutomationRulesView.test.tsx

## Step-by-Step Plan
| File / Service | Step | Status |
| --- | --- | --- |
| apps/web/src/components/runbook/AutomationRulesView.tsx | Inspect the condition editor and live preview layout | [x] done |
| services/api/app/api/v1/endpoints/runbook.py | Add the selected field values to preview results so the UI can render the condition columns | [ ] pending |
| apps/web/src/components/runbook/AutomationRulesView.test.tsx | Add a regression covering the live-preview condition columns | [ ] pending |
| apps/web/src/components/runbook/AutomationRulesView.tsx | Remove the row-level note and render a preview table with the selected condition columns | [ ] pending |
| apps/web | Run the focused automation-rule test suite | [ ] pending |

## Modified Files Log
- none yet

## Risks & Dependencies
- The preview API currently emits only a minimal match model, so additional condition values must be added at the API layer before the UI can render them reliably.
- The UX should remain compact: selected condition fields should be shown in the preview table without repeating the same information under each row.
