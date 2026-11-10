"""The expected operational procedure for a subject.

This is the answer to "what should happen, in what order" — the half of a
runbook that a ledger cannot provide on its own. It is deliberately **static and
code-defined**: the platform ships one canonical sequence per subject type, and
the ledger only ever *evidences* it. There is no authoring UI, no canvas, and no
stored template (the retired visual editor's ``runbook_templates`` table was
dropped in migration 065).

Status rules
------------
* ``done``    — the ledger has at least one row for this stage.
* ``skipped`` — a later stage has evidence but this one does not; the procedure
  did not need it (e.g. auto-closed alerts never reach ``investigate``).
* ``blocked`` — a pending human task exists and this is the first stage without
  evidence. This is the only place the UI may imply "waiting on you".
* ``pending`` — not reached yet.

Ordering is taken from the sequence, never from wall-clock: a connector can
backfill an ``ingest`` row after triage has already run, and the page must still
read in procedure order.
"""

from __future__ import annotations

from typing import Literal

ProcedureStatus = Literal["done", "skipped", "pending", "blocked"]

#: Canonical stage order per subject type. Mirrors ``read.STAGE_LABELS`` keys and
#: the funnel gates in ``app.services.funnel_stages``.
PROCEDURES: dict[str, tuple[str, ...]] = {
    "alert": ("ingest", "enrich", "triage", "investigate", "funnel", "respond", "close"),
    "case": ("funnel", "investigate", "respond", "itsm", "close"),
    "incident": ("triage", "investigate", "respond", "close"),
}


def sequence_for(subject_type: str) -> tuple[str, ...]:
    """Return the ordered stages for a subject type.

    Unknown subject types get the alert sequence: showing a plausible procedure
    is better than an empty panel, and the caller validates ``subject_type``
    before reaching here.
    """
    return PROCEDURES.get(subject_type, PROCEDURES["alert"])


def build_procedure(
    subject_type: str,
    *,
    observed_stages: set[str],
    has_pending_task: bool,
) -> list[dict[str, str]]:
    """Return ``[{stage, status}]`` in procedure order.

    ``observed_stages`` comes from the ledger rows already loaded for the
    subject — this function does no I/O, which keeps it trivially testable and
    keeps the page from inventing progress.
    """
    sequence = sequence_for(subject_type)
    last_done_index = max(
        (i for i, stage in enumerate(sequence) if stage in observed_stages),
        default=-1,
    )

    blocked_assigned = False
    result: list[dict[str, str]] = []

    for index, stage in enumerate(sequence):
        if stage in observed_stages:
            status: ProcedureStatus = "done"
        elif index < last_done_index:
            status = "skipped"
        elif has_pending_task and not blocked_assigned:
            # The human queue is waiting at the first unreached stage — that is
            # the honest reading of "where is this stuck".
            status = "blocked"
            blocked_assigned = True
        else:
            status = "pending"
        result.append({"stage": stage, "status": status})

    return result
