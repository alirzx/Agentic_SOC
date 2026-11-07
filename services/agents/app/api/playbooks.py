"""
Pillar-2 Playbook REST API
===========================
Endpoints:
  GET    /api/v1/playbooks              → list all playbooks
  POST   /api/v1/playbooks              → create a playbook
  GET    /api/v1/playbooks/{id}         → get a playbook
  PUT    /api/v1/playbooks/{id}         → update a playbook
  DELETE /api/v1/playbooks/{id}         → delete a playbook
  POST   /api/v1/playbooks/{id}/run     → execute a playbook against a context
  GET    /api/v1/playbooks/runs/{run_id} → get a run result
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel

from app.playbook import (
    Playbook,
    PlaybookEngine,
    PlaybookRun,
    PlaybookStore,
    StepType,
    draft_from_nl,
    run_store,
)
from app.privacy.tenant import resolve_request_tenant

logger = logging.getLogger("aisoc.api.playbooks")
router = APIRouter(prefix="/api/v1/playbooks", tags=["playbooks"])

# In-memory run store for Pillar-2 (swap for Redis/DB in production)
_runs: dict[str, PlaybookRun] = {}


# ---------------------------------------------------------------------------
# Request / Response helpers
# ---------------------------------------------------------------------------


class RunRequest(BaseModel):
    context: dict[str, Any] = {}
    dry_run: bool = False
    # Caller-supplied at-most-once token. Automation rules re-evaluate a subject
    # on every alert update, so the control-plane API passes a stable key and
    # this endpoint returns the existing run instead of starting a second one.
    dedupe_key: str | None = None
    # ``automation_rule`` marks a start that a stranded approval gate would make
    # dishonest: if this playbook can park and the analyst queue cannot release
    # it, the run must not begin. Manual runs from the console keep their
    # existing behaviour.
    trigger: Literal["manual", "automation_rule"] = "manual"


class DraftFromNLRequest(BaseModel):
    """T3.7 — analyst prompt to draft a playbook from."""

    prompt: str
    # When ``False`` the substrate (no-LLM) drafter is used. CI sets this
    # to ``False`` so tests are hermetic; the production default is
    # ``True`` so the LLM is consulted when configured.
    allow_llm: bool = True


# ---------------------------------------------------------------------------
# NL drafter (T3.7) — declared BEFORE /{playbook_id} so "draft-from-nl" isn't
# parsed as an id.
# ---------------------------------------------------------------------------


@router.post("/draft-from-nl", summary="Draft a playbook from natural language")
async def draft_playbook_from_nl(req: DraftFromNLRequest, request: Request) -> dict:
    """Turn an analyst-authored sentence into a draft playbook.

    The returned playbook ships with ``enabled=false`` so the editor
    is the gate — a human reviews each step before the playbook is
    eligible to run.
    """

    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")
    if len(prompt) > 4000:
        raise HTTPException(status_code=400, detail="prompt is too long (max 4000 chars)")

    from app.privacy.tenant import resolve_request_tenant

    result = await draft_from_nl(
        prompt,
        allow_llm=bool(req.allow_llm),
        tenant_id=resolve_request_tenant(request),
    )
    return result.to_dict()


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def _serialize(playbook: Playbook | dict[str, Any]) -> dict:
    """Playbook payload plus which of its steps this engine cannot execute.

    Authoring in the UI only offers step kinds that have handlers, but playbooks
    created through the API, imported, or drafted can name anything in the schema.
    Without this field the list would show a `disable_user` step as if it would
    run; the engine now aborts on it, so the gallery has to say so up front.

    Some legacy or partially-saved payloads are plain dicts, especially after a
    raw ``steps`` update path bypasses model validation. Convert them before any
    attribute access so the public API remains stable.
    """
    if not isinstance(playbook, Playbook):
        playbook = Playbook.model_validate(playbook)

    from app.playbook.engine import _HANDLERS
    from app.playbook.models import StepType

    # These two are engine-level constructs, not action handlers.
    structural = {StepType.CONDITION, StepType.APPROVAL}
    unsupported = sorted(
        {
            step.type.value
            for step in playbook.steps
            if step.type not in _HANDLERS and step.type not in structural
        }
    )
    return {**playbook.model_dump(mode="json"), "unsupported_step_types": unsupported}


@router.get("", summary="List all playbooks")
async def list_playbooks(enabled_only: bool = False) -> list[dict]:
    store = PlaybookStore.default()
    return [_serialize(pb) for pb in store.list(enabled_only=enabled_only)]


@router.post("", summary="Create a playbook", status_code=201)
async def create_playbook(playbook: Playbook) -> dict:
    store = PlaybookStore.default()
    created = store.create(playbook)
    return created.model_dump()


# ---------------------------------------------------------------------------
# Run queries (declared BEFORE /{playbook_id} so FastAPI matches the literal
# "/runs" prefix instead of treating "runs" as a playbook_id path param).
# ---------------------------------------------------------------------------


@router.get("/runs", summary="List recent playbook runs")
async def list_runs(request: Request, limit: int = 50) -> list[dict]:
    """Recent runs: this process's memory merged with the durable store.

    The durable half is what keeps a parked run visible after the worker that
    started it has gone away. Without a tenant header the endpoint behaves as
    it always did (process-local only).
    """
    from app.playbook import run_store  # noqa: PLC0415

    recent = sorted(
        _runs.values(),
        key=lambda r: r.started_at or "",
        reverse=True,
    )
    merged: list[dict] = [r.to_dict() for r in recent]
    seen = {str(item.get("run_id")) for item in merged}

    tenant = resolve_request_tenant(request)
    if tenant:
        for row in await run_store.list_runs(tenant, limit=limit):
            run_id = str(row.get("id"))
            if run_id in seen:
                continue
            merged.append(_row_to_run_dict(row))
            seen.add(run_id)

    return merged[:limit]


@router.get("/runs/{run_id}", summary="Get a playbook run result")
async def get_run(run_id: str, request: Request) -> dict:
    from app.playbook import run_store  # noqa: PLC0415

    pr = _runs.get(run_id)
    if pr:
        return pr.to_dict()

    # Not in this process: a parked run may have been started by another worker
    # (or before a restart). Fall back to the durable row.
    tenant = resolve_request_tenant(request)
    if tenant:
        row = await run_store.load_run(run_id, tenant)
        if row:
            return _row_to_run_dict(row)

    raise HTTPException(status_code=404, detail="Playbook run not found")


class ResumeRequest(BaseModel):
    """Analyst decision on a playbook approval gate."""

    decision: Literal["approve", "reject"]
    actor: str = "analyst"


@router.post("/runs/{run_id}/resume", summary="Approve or reject a parked playbook run")
async def resume_run_endpoint(run_id: str, body: ResumeRequest, request: Request) -> dict:
    """Release a parked run (approve) or end it (reject).

    Internal surface: authenticated by the HMAC-signed tenant header, exactly
    like ``/api/v1/outcomes/feedback``. The control-plane API is the only
    caller, and it has already checked ``playbooks:approve`` on the user.
    """
    from app.playbook import run_store  # noqa: PLC0415
    from app.playbook.resume import resume_run  # noqa: PLC0415

    tenant = resolve_request_tenant(request)
    if not tenant:
        raise HTTPException(status_code=401, detail="authenticated tenant context required")

    if not run_store.resume_enabled():
        # The surface being off must not look like "no such run".
        raise HTTPException(status_code=503, detail="playbook resume is not enabled")

    row = await run_store.load_run(run_id, tenant)
    if row is None:
        # Cross-tenant and unknown are the same answer: no existence leak.
        raise HTTPException(status_code=404, detail="Playbook run not found")

    if str(row.get("status")) != "pending_approval":
        raise HTTPException(
            status_code=409,
            detail=f"run is {row.get('status')}",
        )

    result = await resume_run(
        row,
        decision=body.decision,
        actor=body.actor,
        tenant_ref=tenant,
    )
    return {"run_id": run_id, **dict(result)}


def _row_to_run_dict(row: dict[str, Any]) -> dict:
    """Shape a ``playbook_runs`` row like ``PlaybookRun.to_dict()``."""
    return {
        "run_id": str(row.get("id")),
        "playbook_id": row.get("playbook_id"),
        "playbook_name": row.get("playbook_name"),
        "status": row.get("status"),
        "context": row.get("context") or {},
        "step_results": row.get("step_results") or [],
        "started_at": row.get("started_at") or "",
        "finished_at": row.get("finished_at") or "",
        "error": row.get("error"),
        "next_step_index": row.get("next_step_index"),
        "gate_step_id": row.get("gate_step_id"),
        "gate_step_name": row.get("gate_step_name"),
        "actor": row.get("actor"),
        "decided_at": row.get("decided_at"),
    }


# ---------------------------------------------------------------------------
# CRUD by id
# ---------------------------------------------------------------------------


@router.get("/{playbook_id}", summary="Get a playbook")
async def get_playbook(playbook_id: str) -> dict:
    store = PlaybookStore.default()
    pb = store.get(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return _serialize(pb)


@router.put("/{playbook_id}", summary="Update a playbook")
async def update_playbook(playbook_id: str, data: dict[str, Any]) -> dict:
    store = PlaybookStore.default()
    updated = store.update(playbook_id, data)
    if not updated:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return _serialize(updated)


@router.delete("/{playbook_id}", summary="Delete a playbook", status_code=204, response_model=None)
async def delete_playbook(playbook_id: str) -> None:
    store = PlaybookStore.default()
    if not store.delete(playbook_id):
        raise HTTPException(status_code=404, detail="Playbook not found")


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


async def _execute(playbook: Playbook, context: dict[str, Any], dry_run: bool, run_holder: list) -> None:
    """Background task: run the playbook and store the result."""
    engine = PlaybookEngine()
    pr = await engine.run(playbook, context, dry_run=dry_run)
    _runs[pr.run_id] = pr
    run_holder.append(pr.run_id)


def _has_approval_step(pb: Playbook) -> bool:
    """Whether this playbook can park at a human gate."""
    return any(step.type == StepType.APPROVAL for step in pb.steps)


@router.post("/{playbook_id}/run", summary="Execute a playbook", status_code=202)
async def run_playbook(
    playbook_id: str,
    body: RunRequest,
    background_tasks: BackgroundTasks,
    request: Request,
) -> dict:
    store = PlaybookStore.default()
    pb = store.get(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    # Stamp the tenant into the run context so a gate reached later persists the
    # row under the right tenant (and so the playbook's own steps can see it).
    context = dict(body.context)
    tenant = resolve_request_tenant(request)
    if tenant and not context.get("tenant_id"):
        context["tenant_id"] = tenant

    # An automation rule that starts a playbook with a gate it cannot clear
    # would leave the run parked with nobody told. Refuse up front instead: the
    # caller records "not started, reason" in the ledger and the operator
    # switches on ``AISOC_PLAYBOOK_RESUME``. A dry run exercises nothing, so it
    # cannot strand and is always allowed.
    if (
        body.trigger == "automation_rule"
        and not body.dry_run
        and not run_store.resume_enabled()
        and _has_approval_step(pb)
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "playbook has an approval step and AISOC_PLAYBOOK_RESUME is off, "
                "so its gate could not be routed to the analyst queue"
            ),
        )

    # Second belt on the caller's dedupe key: return the run that already exists
    # rather than starting a twin. The control-plane's ledger key is the
    # authoritative check; this one closes the window before the background task.
    if body.dedupe_key and tenant:
        existing = await run_store.find_run_by_dedupe(tenant, playbook_id, body.dedupe_key)
        if existing:
            logger.info(
                "playbook.deduplicated",
                extra={"playbook_id": playbook_id, "run_id": existing},
            )
            return {
                "run_id": existing,
                "playbook_id": playbook_id,
                "status": "existing",
                "deduplicated": True,
                "message": "A run already exists for this dedupe key.",
            }

    if body.dedupe_key:
        # Lives in the context so it lands in ``trigger_context`` — the column
        # the lookup above reads.
        context.setdefault("dedupe_key", str(body.dedupe_key)[:128])

    # Create a placeholder run immediately so the caller can poll it
    from app.playbook.engine import PlaybookRun as _PR
    from app.playbook.engine import RunStatus as _RS

    placeholder = _PR(pb, context)
    placeholder.status = _RS.PENDING
    _runs[placeholder.run_id] = placeholder

    background_tasks.add_task(_execute_and_update, pb, context, body.dry_run, placeholder.run_id)

    return {
        "run_id": placeholder.run_id,
        "playbook_id": playbook_id,
        "status": "pending",
        "message": f"Playbook execution started. Poll GET /api/v1/playbooks/runs/{placeholder.run_id}",
    }


async def _execute_and_update(playbook: Playbook, context: dict[str, Any], dry_run: bool, run_id: str) -> None:
    """Background task: overwrite placeholder with real run."""
    engine = PlaybookEngine()
    # Pass the pre-allocated id into the engine: assigning it afterwards left the
    # durable ``playbook_runs`` row keyed by a different id, so the run the
    # caller polls could never be loaded back or resumed.
    pr = await engine.run(playbook, context, dry_run=dry_run, run_id=run_id)
    _runs[run_id] = pr
