"""Live progress for one TKG evaluation run.

Why a job exists at all: 98 alerts are resolved a few at a time, and every alert
the graph accepted but has not materialised yet has to be re-probed in waves.
A synchronous request cannot distinguish "slow" from "stuck", and it cannot be
cancelled — so a run is a job with a stage, counters and a cancel flag that the
panel polls while its stepper animates.

The registry is in-process on purpose: it is *progress*, not a record. The
evaluation itself is still persisted to ``case_tkg_evaluations`` when it ends, so
a restart loses only the live view of the run in flight, never its result.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

#: Ordered stages the panel renders as the stepper.
STAGES = ("precheck", "resolve", "context", "materialise", "judge", "persist", "done")

_STATE_RUNNING = "running"
_STATE_FINISHED = "finished"
_STATE_CANCELLED = "cancelled"
_STATE_FAILED = "failed"

#: Keep the last N runs; older ones are dropped when a new run starts.
_KEEP = 20


class RunCancelled(Exception):
    """Raised inside a run when the caller cancelled it."""


@dataclass
class RunJob:
    """One in-flight evaluation, as the panel sees it."""

    id: str
    case_id: UUID
    tenant_id: UUID
    state: str = _STATE_RUNNING
    stage: str = "precheck"
    total: int = 0
    probed: int = 0
    resolved: int = 0
    facts: int = 0
    pending: int = 0
    wave: int = 0
    max_waves: int = 0
    message: str | None = None
    error: str | None = None
    started: float = field(default_factory=time.monotonic)
    elapsed_ms: int = 0
    result: dict[str, Any] | None = None
    #: The evaluation as it stands *right now*, in the same shape as a stored
    #: row (verdict, confidence, attribution alerts). Published after every few
    #: resolved alerts so the panel can show live numbers instead of the last
    #: stored run, and it is what a cancelled run persists.
    partial: dict[str, Any] | None = None
    #: Arguments needed to persist `partial` as a real row if the run is
    #: cancelled or fails. Not serialised to the client.
    partial_store: dict[str, Any] | None = None
    cancel: asyncio.Event = field(default_factory=asyncio.Event)
    #: Set by the panel's *stop waiting* control. It ends this stage only: the
    #: run still judges and stores. ``cancel`` ends the whole run, stores nothing.
    skip_wait: asyncio.Event = field(default_factory=asyncio.Event)
    #: Seconds left before the wait gives up on its own (-1: no cap at all).
    wait_left_s: int = -1
    wait_timeout_s: int = 0
    #: Which pass is sending/scoring right now. A run evaluates the distinct
    #: alerts first and the soft-dedup witnesses second, and the panel says which
    #: one is in flight instead of showing one undifferentiated "materialise".
    #: ``None`` outside the pass loop (precheck/resolve).
    phase: str | None = None
    phase_index: int = 0
    phase_count: int = 0
    phase_total: int = 0

    @property
    def cancelled(self) -> bool:
        return self.cancel.is_set()

    def touch(self, **values: Any) -> None:
        for key, value in values.items():
            setattr(self, key, value)

    def snapshot(self) -> dict[str, Any]:
        if self.state == _STATE_RUNNING:
            self.elapsed_ms = int((time.monotonic() - self.started) * 1000)
        return {
            "run_id": self.id,
            "state": self.state,
            "stage": self.stage,
            "total": self.total,
            "probed": self.probed,
            "resolved": self.resolved,
            "facts": self.facts,
            "pending": self.pending,
            "wave": self.wave,
            "max_waves": self.max_waves,
            "wait_left_s": self.wait_left_s,
            "wait_timeout_s": self.wait_timeout_s,
            "phase": self.phase,
            "phase_index": self.phase_index,
            "phase_count": self.phase_count,
            "phase_total": self.phase_total,
            "can_skip_wait": self.state == _STATE_RUNNING and self.stage == "materialise",
            "message": self.message,
            "error": self.error,
            "elapsed_ms": self.elapsed_ms,
            "result": self.result,
            "partial": self.partial,
        }


_JOBS: dict[str, RunJob] = {}


def start(*, case_id: UUID, tenant_id: UUID) -> RunJob:
    """Register a new run and return its handle."""

    if len(_JOBS) > _KEEP:
        for key in list(_JOBS)[: len(_JOBS) - _KEEP]:
            _JOBS.pop(key, None)
    job = RunJob(id=str(uuid4()), case_id=case_id, tenant_id=tenant_id)
    _JOBS[job.id] = job
    return job


def get(run_id: str, *, case_id: UUID, tenant_id: UUID) -> RunJob | None:
    job = _JOBS.get(run_id)
    if job is None or job.case_id != case_id or job.tenant_id != tenant_id:
        return None
    return job


def cancel(run_id: str, *, case_id: UUID, tenant_id: UUID) -> RunJob | None:
    job = get(run_id, case_id=case_id, tenant_id=tenant_id)
    if job is None:
        return None
    if job.state == _STATE_RUNNING:
        job.cancel.set()
        job.message = "Cancelling…"
    return job


def skip_waiting(run_id: str, *, case_id: UUID, tenant_id: UUID) -> RunJob | None:
    """Stop waiting for the graph without ending the run.

    The alerts already sent keep materialising in the background; this run
    judges and stores what is resolved instead of holding the verdict hostage to
    the graph's queue. Only the wait stage answers to it.
    """

    job = get(run_id, case_id=case_id, tenant_id=tenant_id)
    if job is None:
        return None
    if job.state == _STATE_RUNNING and job.stage == "materialise":
        job.skip_wait.set()
        job.message = "Stopping the wait — the run will judge and store what is resolved."
    return job


def finish(job: RunJob, *, result: dict[str, Any] | None = None) -> None:
    # The message is *not* cleared: a run that stopped waiting with alerts still
    # queued leaves its explanation ("stopped after 3 of 12 waves because the 60s
    # wait window elapsed") on the finished panel.
    job.touch(state=_STATE_FINISHED, stage="done", result=result)
    job.elapsed_ms = int((time.monotonic() - job.started) * 1000)


def fail(job: RunJob, error: str) -> None:
    job.touch(state=_STATE_FAILED, error=error, message=None)
    job.elapsed_ms = int((time.monotonic() - job.started) * 1000)


def cancelled(job: RunJob) -> None:
    # A run that ends after its canonical pass already stored that pass's
    # verdict, so the message names what a cancel cannot undo.
    job.touch(
        state=_STATE_CANCELLED,
        message="Cancelled — the run stopped before it stored its final verdict.",
    )
    job.elapsed_ms = int((time.monotonic() - job.started) * 1000)


def checkpoint(job: RunJob | None) -> None:
    """Abort the run if the caller asked for it. Cheap enough to call often."""

    if job is not None and job.cancelled:
        raise RunCancelled


__all__ = [
    "RunCancelled",
    "RunJob",
    "STAGES",
    "cancel",
    "cancelled",
    "checkpoint",
    "fail",
    "finish",
    "get",
    "skip_waiting",
    "start",
]
