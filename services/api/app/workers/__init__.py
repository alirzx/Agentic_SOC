"""Background workers that run inside the API process.

These workers are started from :func:`app.main.lifespan` and live inside
the API event loop. They are intentionally **not** APScheduler jobs —
the API has no scheduler dependency and we don't want to introduce one
just for periodic loops. Each worker is a long-running ``asyncio.Task``
that owns its own cadence and shutdown semantics.

Workers currently shipped:

* :mod:`oauth_refresh` — auto-rotates expiring OAuth access tokens for
  every connector provisioned via the hosted ``/oauth/start`` flow.
* :mod:`weekly_digest_task` — generates executive digests and emails them
  to tenant admins every Monday at 00:05 UTC (WS-G2).
* :mod:`hunt_scheduler` — scans ``aisoc_saved_hunts`` and executes any hunt
  whose cron schedule says it's due, opening cases for hits (T3.4).
* :mod:`calibration_monitor` — measures LLM confidence calibration via
  analyst feedback from the Runbook and logs ECE metrics (Task 1.2).
* :mod:`rule_evaluator` — evaluates ``alert.created`` automation rules for
  every new alert, including the ones fusion writes straight to Postgres
  (migration 073 marker column).
"""

from __future__ import annotations
