## Goal
Repair the failing local Postgres schema after the DB reset so the runbook task table is created in the correct migration order and the Action plan page stops returning SQLAlchemy 500s.

## Files / Services Discovered
- services/api/app/models/runbook_task.py
- services/api/app/api/v1/endpoints/runbook.py
- services/api/migrations/064_runbook_tasks.sql
- services/api/app/scripts/run_migrations.py
- services/api/app/main.py

## Step-by-Step Plan
| Step | File / Service | Action | Status |
|---|---|---|---|
| 1 | services/api | Verify Postgres schema state and migration execution order after the DB rebuild | [ ] pending |
| 2 | services/api/migrations/064_runbook_tasks.sql | Confirm the migration creates the table without invalid tenant references and is safe for first-time DB bootstrap | [ ] pending |
| 3 | services/api/app/models/runbook_task.py | Check model contract against the actual schema and ensure FK / column names match the DB state | [ ] pending |
| 4 | services/api/app/api/v1/endpoints/runbook.py | Validate the runtime query path and confirm the missing table is the failing cause | [ ] pending |
| 5 | services/api | Apply the corrected schema fix, restart the stack, and verify the Action plan route works | [ ] pending |

## Modified Files Log
- None yet

## Risks & Dependencies
- Fresh DB rebuild exposes migration ordering issues and missing dependent tables.
- The app queries the runbook table immediately on route access, so any migration failure leaves the UI in a broken state.
- The tenant table name and FK conventions must match the rest of the schema exactly; using the wrong target table or a broken FK will fail migration startup.
