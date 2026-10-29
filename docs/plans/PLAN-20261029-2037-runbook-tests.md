## Goal
Fix the failing Runbook system integration tests by identifying the exact contract mismatch in the task/calibration workflow and repairing the underlying model or worker logic without broad scope changes.

## Files / Services Discovered
- services/api/tests/test_runbook_integration.py
- services/api/tests/test_calibration_monitor.py
- services/api/tests/test_operational_queries.py
- services/api/app/models/runbook_task.py
- services/api/app/workers/calibration_monitor.py
- services/api/app/services/funnel_stages.py

## Step-by-Step Plan
| File / Service | Status | Notes |
|---|---|---|
| services/api/tests/test_runbook_integration.py | [ ] pending | Reproduce failure mode and compare expected task states vs model behavior |
| services/api/tests/test_calibration_monitor.py | [ ] pending | Verify calibration metrics and SQL assumptions against model schema |
| services/api/tests/test_operational_queries.py | [ ] pending | Confirm direct SQL/enum semantics for status and feedback fields |
| services/api/app/models/runbook_task.py | [ ] pending | Fix enum/status field mismatch or validation issue |
| services/api/app/workers/calibration_monitor.py | [ ] pending | Correct calibration measurement logic if metric contract is wrong |
| services/api/app/services/funnel_stages.py | [ ] pending | Confirm funnel gates align with runbook task workflow |

## Modified Files Log
- None yet

## Risks & Dependencies
- DB schema and enum values must match test assumptions exactly
- Calibration monitor must work with async SQLAlchemy results without changing public behavior unexpectedly
- Runbook task status and feedback semantics are central to approval-gate flows and should remain compatible with existing app logic
