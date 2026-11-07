"""
Playbook Engine — Pillar 2
==========================
Executes an AiSOC Playbook against a trigger context (alert/case dict).

Design goals:
- Async, step-by-step execution with per-step structured logging.
- Supports condition gates, on_failure policies, and basic retries.
- Emits events to the realtime service so the UI can stream progress.
- Zero external dependencies beyond httpx + stdlib.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

import httpx

from .bounds import clamp_timeout
from .models import Playbook, PlaybookStep, StepCondition, StepType
from .ssrf_guard import SSRFError, validate_outbound_url

logger = logging.getLogger("aisoc.playbook.engine")

_REALTIME_URL = os.getenv("REALTIME_URL", "http://realtime:3001")
# Internal token used to authenticate the agents service to the realtime
# service. Previously this defaulted to the literal string ``"changeme"``,
# which meant an operator who forgot to wire the secret would silently ship a
# well-known token. We now default to empty and let the call sites treat an
# empty token as "no internal auth" (skip the header) so a misconfigured
# deployment fails closed instead of inheriting a public default.
_INTERNAL_TOKEN = os.getenv("REALTIME_INTERNAL_TOKEN", "")
_API_URL = os.getenv("API_URL", "http://api:8000")


# ---------------------------------------------------------------------------
# Run status
# ---------------------------------------------------------------------------


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    #: Parked at an `approval` step. Nothing after the gate has executed.
    PENDING_APPROVAL = "pending_approval"


class StepStatus(str, Enum):
    PENDING = "pending"
    SKIPPED = "skipped"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    #: An `approval` gate that has not been cleared. The step did not run.
    BLOCKED = "blocked"


# ---------------------------------------------------------------------------
# Run record
# ---------------------------------------------------------------------------


class StepResult(dict):  # thin dict subclass for JSON serialisation
    pass


class PlaybookRun:
    """Mutable run state threaded through the engine.

    ``playbook_snapshot`` freezes the definition the run is executing. A run that
    parks at an approval gate is resumed hours later, against the steps the
    analyst approved — never the current edit of the document.
    """

    def __init__(self, playbook: Playbook, trigger_context: dict[str, Any]) -> None:
        self.run_id: str = str(uuid.uuid4())
        self.playbook_id: str = playbook.id
        self.playbook_name: str = playbook.name
        self.status: RunStatus = RunStatus.PENDING
        self.trigger_context: dict[str, Any] = trigger_context
        # Accumulated output from previous steps — available to later steps as {{prev.*}}
        self.context: dict[str, Any] = dict(trigger_context)
        self.step_results: list[dict[str, Any]] = []
        self.started_at: str = ""
        self.finished_at: str = ""
        self.error: str | None = None
        # Durable-run bookkeeping (see app/playbook/run_store.py).
        self.playbook_snapshot: dict[str, Any] = playbook.model_dump(mode="json")
        self.tenant_ref: str = str(trigger_context.get("tenant_id") or "default")
        self.next_step_index: int | None = None
        self.gate_step_id: str | None = None
        self.gate_step_name: str | None = None
        #: Set when an approved gate actually released the run. Lets the caller
        #: report "resumed" honestly even when a later step fails.
        self.gate_released: bool = False

    @classmethod
    def from_state(
        cls,
        playbook: Playbook,
        *,
        run_id: str,
        trigger_context: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        step_results: list[dict[str, Any]] | None = None,
        status: RunStatus = RunStatus.PENDING,
        next_step_index: int | None = None,
        gate_step_id: str | None = None,
        gate_step_name: str | None = None,
        started_at: str = "",
        error: str | None = None,
        tenant_ref: str | None = None,
    ) -> PlaybookRun:
        """Rebuild a run from its persisted ``playbook_runs`` row."""
        pr = cls(playbook, dict(trigger_context or {}))
        pr.run_id = run_id
        pr.context = dict(context or {})
        pr.step_results = list(step_results or [])
        pr.status = status
        pr.next_step_index = next_step_index
        pr.gate_step_id = gate_step_id
        pr.gate_step_name = gate_step_name
        pr.started_at = started_at
        pr.error = error
        if tenant_ref:
            pr.tenant_ref = tenant_ref
        return pr

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "status": self.status.value,
            "context": self.context,
            "step_results": self.step_results,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "next_step_index": self.next_step_index,
            "gate_step_id": self.gate_step_id,
            "gate_step_name": self.gate_step_name,
        }


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------


def _resolve_field(context: dict[str, Any], field: str) -> Any:
    """Resolve a dot-path field from context, e.g. ``alert.severity`` or
    ``entities.0.name``.

    Supports traversal through both ``dict`` keys and ``list``/``tuple``
    indices. A blank field returns ``None`` (rather than the whole context,
    which would conflate "missing path" with "no path requested").
    """
    if not field:
        return None
    cur: Any = context
    for part in field.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list | tuple):
            # Numeric indices may be specified as bare ints in a dot-path.
            try:
                idx = int(part)
            except (TypeError, ValueError):
                return None
            if -len(cur) <= idx < len(cur):
                cur = cur[idx]
            else:
                return None
        else:
            return None
    return cur


def _to_float(value: Any) -> float | None:
    """Best-effort numeric coercion. Returns ``None`` for non-numeric input
    so callers can decide how to handle the failure rather than crashing.

    ``None`` and ``""`` coerce to ``0.0`` to preserve historical "missing
    means zero" semantics for numeric comparisons.
    """
    if value is None or value == "":
        return 0.0
    if isinstance(value, bool):  # bool is a subclass of int; treat explicitly
        return 1.0 if value else 0.0
    if isinstance(value, int | float):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _evaluate_condition(condition: StepCondition, context: dict[str, Any]) -> bool:
    """Return True if the condition passes.

    Two forms are supported:

    1. Structured: ``StepCondition(field=..., operator=..., value=...)``.
    2. Expression string: ``StepCondition(expression="severity in ['high','critical']")``.
       Evaluated by :func:`_evaluate_expression` with a sandboxed
       ``eval()`` over the run context. Falsy/unparseable expressions
       return ``False`` so a malformed playbook never silently "passes".
    """
    # Expression-string form takes precedence when set. Previously this was
    # silently ignored, which made every expression-only condition evaluate
    # as ``None == None`` (i.e. always true).
    if condition.expression:
        return _evaluate_expression(condition.expression, context)

    if not condition.field:
        # No field and no expression — nothing to evaluate. Treat as "no
        # condition" (i.e. pass) so an empty StepCondition() doesn't gate
        # the step. The engine only invokes us when condition is non-None.
        return True

    value = _resolve_field(context, condition.field)
    op = condition.operator
    expected = condition.value

    if op == "exists":
        return value is not None
    if op == "eq":
        return value == expected
    if op == "ne":
        return value != expected
    if op == "contains":
        # Support both substring containment ("error" contains "err") and
        # set-membership ("severity in ['high','critical']"). The structured
        # form historically used "expected in str(value)" which crashed when
        # expected was a list — and silently false-matched the common SOAR
        # pattern of testing field membership in an allowed set.
        if value is None:
            return False
        if isinstance(expected, list | tuple | set):
            return value in expected
        return str(expected) in str(value)
    if op in ("gt", "lt"):
        lhs = _to_float(value)
        rhs = _to_float(expected)
        if lhs is None or rhs is None:
            return False
        return lhs > rhs if op == "gt" else lhs < rhs
    return False


# Operators allowed in expression-string conditions, in longest-match-first
# order so ``>=`` is tried before ``>``.
_EXPR_OPERATORS: tuple[tuple[str, str], ...] = (
    ("==", "eq"),
    ("!=", "ne"),
    (">=", "gte"),
    ("<=", "lte"),
    (">", "gt"),
    ("<", "lt"),
    (" not in ", "not_in"),
    (" in ", "in_"),
)


def _parse_literal(token: str, context: dict[str, Any]) -> Any:
    """Parse one side of an expression. Strings, numbers, bool/null/None,
    and bracketed list literals are returned as Python values; everything
    else is treated as a dot-path into the run context.
    """
    token = token.strip()
    if not token:
        return None
    if token in ("null", "None"):
        return None
    if token in ("true", "True"):
        return True
    if token in ("false", "False"):
        return False
    # Quoted string literal
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        return token[1:-1]
    # List literal: ['a', 'b'] or ["high","critical"]
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if not inner:
            return []
        return [_parse_literal(piece, context) for piece in inner.split(",")]
    # Numeric literal
    try:
        if "." in token:
            return float(token)
        return int(token)
    except ValueError:
        pass
    # Otherwise: dot-path into context
    return _resolve_field(context, token)


def _evaluate_expression(expression: str, context: dict[str, Any]) -> bool:
    """Evaluate a single ``"<lhs> <op> <rhs>"`` boolean expression.

    Intentionally restricted: no ``and``/``or`` chains, no function calls,
    no Python ``eval``. Callers that need compound logic should use
    multiple structured conditions across multiple steps. Returns
    ``False`` for any malformed input.
    """
    if not expression or not isinstance(expression, str):
        return False
    expr = expression.strip()

    # "<field> exists" / "<field> is null" sugar.
    lowered = expr.lower()
    if lowered.endswith(" is not null") or lowered.endswith(" != null"):
        base = expr[: -len(" is not null")] if lowered.endswith(" is not null") else expr[: -len(" != null")]
        return _resolve_field(context, base.strip()) is not None
    if lowered.endswith(" is null") or lowered.endswith(" == null"):
        base = expr[: -len(" is null")] if lowered.endswith(" is null") else expr[: -len(" == null")]
        return _resolve_field(context, base.strip()) is None

    for token, op in _EXPR_OPERATORS:
        # Use lowercase comparison for the " in "/" not in " word-operators
        # so capitalization doesn't trip us up, but split on the original
        # string to preserve quoted-literal casing.
        haystack = lowered if op in ("in_", "not_in") else expr
        needle = token if op in ("in_", "not_in") else token
        idx = haystack.find(needle)
        if idx == -1:
            continue
        lhs_raw = expr[:idx]
        rhs_raw = expr[idx + len(needle) :]
        lhs = _parse_literal(lhs_raw, context)
        rhs = _parse_literal(rhs_raw, context)
        try:
            if op == "eq":
                return lhs == rhs
            if op == "ne":
                return lhs != rhs
            if op == "gt":
                lf, rf = _to_float(lhs), _to_float(rhs)
                return lf is not None and rf is not None and lf > rf
            if op == "lt":
                lf, rf = _to_float(lhs), _to_float(rhs)
                return lf is not None and rf is not None and lf < rf
            if op == "gte":
                lf, rf = _to_float(lhs), _to_float(rhs)
                return lf is not None and rf is not None and lf >= rf
            if op == "lte":
                lf, rf = _to_float(lhs), _to_float(rhs)
                return lf is not None and rf is not None and lf <= rf
            if op == "in_":
                if rhs is None:
                    return False
                if isinstance(rhs, list | tuple | set):
                    return lhs in rhs
                return str(lhs) in str(rhs)
            if op == "not_in":
                if rhs is None:
                    return True
                if isinstance(rhs, list | tuple | set):
                    return lhs not in rhs
                return str(lhs) not in str(rhs)
        except TypeError:
            return False

    logger.warning("Could not parse playbook condition expression: %r", expression)
    return False


# ---------------------------------------------------------------------------
# Step handlers
# ---------------------------------------------------------------------------


async def _handle_enrich(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    ioc = step.params.get("ioc") or context.get("ioc") or context.get("src_ip", "")
    ioc_type = step.params.get("ioc_type", "ip")
    r = await http.post(
        f"{_API_URL}/api/v1/enrichment/lookup",
        json={"ioc": ioc, "ioc_type": ioc_type},
        timeout=step.timeout_seconds,
    )
    r.raise_for_status()
    return r.json()


async def _handle_investigate(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    case_id = step.params.get("case_id") or context.get("case_id") or context.get("id")
    if not case_id:
        return {"skipped": True, "reason": "no case_id in context"}
    r = await http.post(
        f"{_API_URL}/api/v1/cases/{case_id}/investigate",
        json={"dry_run": step.params.get("dry_run", False)},
        timeout=step.timeout_seconds,
    )
    r.raise_for_status()
    return r.json()


async def _handle_notify(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    channel = step.params.get("channel", "webhook")
    url = step.params.get("url", "")
    message = step.params.get("message", "AiSOC playbook notification")
    # Simple template substitution
    for k, v in context.items():
        message = message.replace(f"{{{{{k}}}}}", str(v))

    if channel == "webhook" and url:
        # SSRF guard: webhook URLs are author-controlled; reject loopback,
        # cloud-metadata, and other unsafe destinations before dispatching.
        try:
            validate_outbound_url(url)
        except SSRFError as exc:
            raise SSRFError(f"notify step rejected: {exc}") from exc
        r = await http.post(url, json={"text": message}, timeout=step.timeout_seconds)
        return {"status": r.status_code}
    return {"channel": channel, "message": message, "delivered": False, "reason": "no url"}


async def _handle_http(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    method = step.params.get("method", "POST").upper()
    url = step.params.get("url", "")
    body = step.params.get("body", {})
    headers = step.params.get("headers", {})
    # SSRF guard: arbitrary HTTP calls from playbooks must not reach
    # loopback, RFC1918, link-local, or cloud-metadata endpoints by default.
    try:
        validate_outbound_url(url)
    except SSRFError as exc:
        raise SSRFError(f"http step rejected: {exc}") from exc
    r = await http.request(method, url, json=body, headers=headers, timeout=step.timeout_seconds)
    return {"status": r.status_code, "body": r.text[:500]}


async def _handle_block_ip(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    ip = step.params.get("ip") or context.get("src_ip", "")
    return {"action": "block_ip", "ip": ip, "simulated": True}


async def _handle_isolate_host(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    host = step.params.get("host") or context.get("host", "")
    return {"action": "isolate_host", "host": host, "simulated": True}


async def _handle_create_ticket(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    return {"action": "create_ticket", "params": step.params, "simulated": True}


async def _handle_close_case(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    case_id = step.params.get("case_id") or context.get("case_id") or context.get("id")
    if not case_id:
        return {"skipped": True, "reason": "no case_id"}
    r = await http.patch(
        f"{_API_URL}/api/v1/cases/{case_id}",
        json={"status": "closed"},
        timeout=step.timeout_seconds,
    )
    r.raise_for_status()
    return {"case_id": case_id, "status": "closed"}


async def _handle_osquery_live_query(step: PlaybookStep, context: dict[str, Any], http: httpx.AsyncClient) -> dict:
    """Dispatch a distributed osquery live query via osctrl, FleetDM, or aisoc-direct.

    Expected ``step.params`` keys
    ------------------------------
    backend : str
        One of ``"osctrl"``, ``"fleetdm"``, ``"aisoc_direct"``.
    instance_id : str
        Connector instance ID (looked up from the API to retrieve credentials).
    target_hosts : list[str]
        Host UUIDs / hostnames to query.
    template : str
        Allowlist template ID (see ``osquery_allowlist``).
    template_params : dict, optional
        Parameters forwarded to the template renderer.
    timeout_seconds : int, optional
        How long to wait for all hosts to respond (default: 60).
    """
    # Import clients here to avoid circular imports at module load time.
    from app.clients.aisoc_direct_client import AiSOCDirectClient  # noqa: PLC0415
    from app.clients.fleetdm_client import FleetDMClient  # noqa: PLC0415
    from app.clients.osctrl_client import OsctrlClient  # noqa: PLC0415
    from app.clients.osquery_allowlist import AllowlistError  # noqa: PLC0415

    backend: str = step.params.get("backend", "osctrl")
    target_hosts: list[str] = step.params.get("target_hosts") or [context.get("host_id") or context.get("host", "")]
    template: str = step.params.get("template", "")
    template_params: dict[str, Any] = step.params.get("template_params") or {}
    # Runtime clamp — params bypass the Pydantic validator on PlaybookStep, so
    # a malicious or malformed playbook could otherwise pin the connector
    # thread for hours. See services/agents/app/playbook/bounds.py.
    timeout_seconds: int = clamp_timeout(step.params.get("timeout_seconds", 60), default=60)

    if not template:
        return {"error": "osquery_live_query: 'template' param is required", "partial": True}

    # Credential resolution: fetch the connector instance config from the API.
    instance_id: str = step.params.get("instance_id") or context.get("connector_instance_id", "")
    creds: dict[str, Any] = {}
    if instance_id:
        try:
            r = await http.get(
                f"{_API_URL}/api/v1/connectors/instances/{instance_id}",
                timeout=10,
            )
            if r.status_code == 200:
                creds = r.json().get("auth_config") or {}
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not fetch connector creds for %s: %s", instance_id, exc)

    try:
        if backend == "osctrl":
            client = OsctrlClient(
                base_url=creds.get("base_url") or step.params.get("base_url", ""),
                environment=creds.get("environment") or step.params.get("environment", "default"),
                api_token=creds.get("api_token") or step.params.get("api_token", ""),
                verify_tls=step.params.get("verify_tls", True),
            )
            return await client.live_query(target_hosts, template, template_params, timeout_seconds)

        if backend == "fleetdm":
            client_fleet = FleetDMClient(
                base_url=creds.get("base_url") or step.params.get("base_url", ""),
                api_token=creds.get("api_token") or step.params.get("api_token") or None,
                username=creds.get("username") or step.params.get("username") or None,
                password=creds.get("password") or step.params.get("password") or None,
                verify_tls=step.params.get("verify_tls", True),
            )
            return await client_fleet.live_query(target_hosts, template, template_params, timeout_seconds)

        if backend == "aisoc_direct":
            client_direct = AiSOCDirectClient(
                base_url=creds.get("base_url") or step.params.get("base_url", ""),
                api_token=creds.get("api_token") or step.params.get("api_token", ""),
            )
            return await client_direct.live_query(target_hosts, template, template_params, timeout_seconds)

        return {"error": f"Unknown osquery backend: {backend!r}", "partial": True}

    except AllowlistError as exc:
        return {"error": f"osquery allowlist violation: {exc}", "partial": True}
    except NotImplementedError as exc:
        return {"error": str(exc), "partial": True, "stub": True}


_HANDLERS = {
    StepType.ENRICH: _handle_enrich,
    StepType.INVESTIGATE: _handle_investigate,
    StepType.NOTIFY: _handle_notify,
    StepType.HTTP: _handle_http,
    StepType.BLOCK_IP: _handle_block_ip,
    StepType.ISOLATE_HOST: _handle_isolate_host,
    StepType.CREATE_TICKET: _handle_create_ticket,
    StepType.CLOSE_CASE: _handle_close_case,
    StepType.OSQUERY_LIVE_QUERY: _handle_osquery_live_query,
}


# ---------------------------------------------------------------------------
# Realtime event helper
# ---------------------------------------------------------------------------


async def _emit(run_id: str, event_type: str, payload: dict, http: httpx.AsyncClient) -> None:
    try:
        headers: dict[str, str] = {}
        # Only include the internal-auth header when an operator has actually
        # configured a token. Sending a literal "changeme" used to make a
        # misconfigured deployment look authenticated to anything that
        # whitelisted the same string.
        if _INTERNAL_TOKEN:
            headers["x-internal-token"] = _INTERNAL_TOKEN
        await http.post(
            f"{_REALTIME_URL}/internal/agent-event",
            json={"channel": f"playbook:{run_id}", "type": event_type, "data": payload},
            headers=headers,
            timeout=3,
        )
    except Exception:
        pass  # non-critical


# ---------------------------------------------------------------------------
# Governance check (Phase 3: Governance Hardening)
# ---------------------------------------------------------------------------

# Step types that perform actions governed by autonomy policy
_GOVERNED_STEP_TYPES = {
    StepType.BLOCK_IP,
    StepType.ISOLATE_HOST,
    StepType.CREATE_TICKET,
    StepType.CLOSE_CASE,
    StepType.OSQUERY_LIVE_QUERY,
}


async def _check_governance(
    step: PlaybookStep,
    alert_context: dict[str, Any],
    tenant_id: str,
    http: httpx.AsyncClient,
) -> dict[str, Any]:
    """Query the API service's autonomy policy for a playbook action.

    Returns:
        {
            "decision": "approved" | "requires_approval" | "error",
            "governance_level": "L1" | "L2" | "L3" | "L4" | None,
            "requires_approval": bool,
            "approved": bool,
            "error": str | None,
        }

    Fail-closed: on network error or unexpected response, returns
    {"requires_approval": True}, blocking the action.
    """
    try:
        alert_id = alert_context.get("alert_id") or alert_context.get("id")
        if not alert_id:
            logger.debug("governance_check.skipped", extra={"reason": "no alert_id"})
            return {"decision": "error", "requires_approval": False, "approved": True}

        severity = str(alert_context.get("severity", "low")).lower()
        confidence = int(alert_context.get("confidence", 50))

        # Map step type to action slug
        action_slug = step.type.value if hasattr(step.type, "value") else str(step.type)

        payload = {
            "alert_id": str(alert_id),
            "action_slug": action_slug,
            "severity": severity,
            "confidence": confidence,
        }

        headers = {"X-Tenant-Id": str(tenant_id)}

        response = await http.post(
            f"{_API_URL}/api/v1/governance/check",
            json=payload,
            headers=headers,
            timeout=5,
        )

        if response.status_code == 200:
            return response.json()

        logger.warning(
            "governance_check.api_error",
            extra={"status": response.status_code, "action": action_slug},
        )
        # Fail-closed: treat API error as "requires approval"
        return {"decision": "error", "requires_approval": True, "approved": False}

    except httpx.RequestError as exc:
        logger.warning("governance_check.network_error", extra={"error": str(exc)})
        # Fail-closed: governance unreachable → block action
        return {"decision": "error", "requires_approval": True, "approved": False}

    except Exception as exc:
        logger.exception("governance_check.error", extra={"error": str(exc)})
        # Fail-closed: unexpected error → block action
        return {"decision": "error", "requires_approval": True, "approved": False}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


# One in-flight execution per run inside this process. Two clicks on the same
# approval must not run the guarded steps twice; cross-worker safety rests on the
# ``pending_approval`` status check in ``resume``.
_RUN_LOCKS: dict[str, asyncio.Lock] = {}


def _run_lock(run_id: str) -> asyncio.Lock:
    lock = _RUN_LOCKS.get(run_id)
    if lock is None:
        lock = asyncio.Lock()
        _RUN_LOCKS[run_id] = lock
    return lock


async def _persist(pr: PlaybookRun) -> None:
    """Best-effort durable write. A missing/unmigrated database must never break a run."""
    try:
        from . import run_store  # noqa: PLC0415 — keeps the DB path optional at import time

        await run_store.persist_run(pr)
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_run.persist_unavailable: %s", exc)


async def _raise_gate_task(pr: PlaybookRun) -> None:
    """Best-effort: put the parked run in the analyst's Action Plan."""
    try:
        from .approvals import create_gate_task  # noqa: PLC0415

        await create_gate_task(pr)
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_gate.task_unavailable: %s", exc)


class PlaybookEngine:
    """Executes playbooks step-by-step, emitting realtime events."""

    async def run(
        self,
        playbook: Playbook,
        trigger_context: dict[str, Any],
        *,
        dry_run: bool = False,
        run_id: str | None = None,
    ) -> PlaybookRun:
        pr = PlaybookRun(playbook, trigger_context)
        # Caller-allocated id (the API hands out a run_id before the run starts so
        # it can be polled). Must be set *before* the first persist, otherwise the
        # durable row and the id the caller was given disagree.
        if run_id:
            pr.run_id = run_id
        pr.started_at = datetime.now(UTC).isoformat()
        pr.status = RunStatus.RUNNING

        async with httpx.AsyncClient() as http:
            await _emit(pr.run_id, "run.started", {"playbook": playbook.name, "dry_run": dry_run}, http)
            # Persist the opening row so a run that parks later has a durable
            # identity even if the process dies before the gate is reached.
            await _persist(pr)
            async with _run_lock(pr.run_id):
                await self._execute(pr, playbook, start_index=0, dry_run=dry_run, http=http)
                await self._finalize(pr, http)

        return pr

    async def resume(
        self,
        pr: PlaybookRun,
        playbook: Playbook,
        *,
        actor: str = "analyst",
    ) -> PlaybookRun:
        """Continue a parked run from its recorded ``next_step_index``.

        Steps before the gate are never re-executed: an approval releases what
        comes *after* it, not a replay of the side effects that already happened.
        """
        if pr.status != RunStatus.PENDING_APPROVAL:
            raise ValueError(f"run {pr.run_id} is not awaiting approval (status={pr.status.value})")

        start_index = pr.next_step_index
        if start_index is None or start_index < 0 or start_index > len(playbook.steps):
            pr.status = RunStatus.FAILED
            pr.error = "gate step no longer present in the playbook snapshot"
            async with httpx.AsyncClient() as http:
                await self._finalize(pr, http)
            return pr

        # The gate was cleared by a human: stop reporting it as blocked.
        if pr.gate_step_id:
            for entry in pr.step_results:
                if entry.get("step_id") == pr.gate_step_id and entry.get("status") == StepStatus.BLOCKED:
                    entry["status"] = StepStatus.SUCCESS
                    entry.setdefault("result", {})["approved_by"] = actor

        pr.status = RunStatus.RUNNING
        pr.error = None
        pr.next_step_index = None
        pr.gate_released = True

        async with httpx.AsyncClient() as http:
            async with _run_lock(pr.run_id):
                await _emit(
                    pr.run_id,
                    "run.resumed",
                    {"actor": actor, "from_step_index": start_index},
                    http,
                )
                await self._execute(pr, playbook, start_index=start_index, dry_run=False, http=http)
                await self._finalize(pr, http)

        return pr

    async def cancel(self, pr: PlaybookRun, *, actor: str, reason: str) -> PlaybookRun:
        """End a parked run without executing anything (a rejected gate)."""
        pr.status = RunStatus.CANCELLED
        pr.error = reason
        pr.next_step_index = None
        async with httpx.AsyncClient() as http:
            await _emit(pr.run_id, "run.cancelled", {"actor": actor, "reason": reason}, http)
            await self._finalize(pr, http)
        return pr

    async def _finalize(self, pr: PlaybookRun, http: httpx.AsyncClient) -> None:
        """Close out a run: settle its terminal status and persist the row."""
        if pr.status == RunStatus.RUNNING:
            pr.status = RunStatus.COMPLETED
        if pr.status != RunStatus.PENDING_APPROVAL:
            pr.finished_at = datetime.now(UTC).isoformat()
        await _emit(pr.run_id, "run.done", pr.to_dict(), http)
        await _persist(pr)
        # A parked run is only useful if the analyst can see it. This covers
        # both a first gate and a later gate reached after a resume.
        if pr.status == RunStatus.PENDING_APPROVAL:
            await _raise_gate_task(pr)

    async def _execute(
        self,
        pr: PlaybookRun,
        playbook: Playbook,
        *,
        start_index: int,
        dry_run: bool,
        http: httpx.AsyncClient,
    ) -> None:
        """Run the step loop from ``start_index``. Mutates ``pr`` in place."""
        # Build a step index for branching
        step_index = {s.id: i for i, s in enumerate(playbook.steps)}
        visited: set[str] = set()
        current_idx = start_index

        while current_idx < len(playbook.steps):
            step = playbook.steps[current_idx]

            if step.id in visited:
                logger.warning("Cycle detected at step %s, aborting", step.id)
                pr.status = RunStatus.FAILED
                pr.error = f"cycle at step {step.id}"
                break
            visited.add(step.id)

            # Condition gate
            condition_passed = True
            if step.condition:
                condition_passed = _evaluate_condition(step.condition, pr.context)

            if not condition_passed:
                pr.step_results.append({"step_id": step.id, "name": step.name, "status": StepStatus.SKIPPED})
                # Branching: use next_false if set
                if step.next_false and step.next_false in step_index:
                    current_idx = step_index[step.next_false]
                else:
                    current_idx += 1
                continue

            # CONDITION type — just branch, no external action
            if step.type == StepType.CONDITION:
                branch_id = step.next_true if condition_passed else step.next_false
                if branch_id and branch_id in step_index:
                    current_idx = step_index[branch_id]
                else:
                    current_idx += 1
                pr.step_results.append({"step_id": step.id, "name": step.name, "status": StepStatus.SUCCESS, "branch": branch_id})
                continue

            # Human-in-the-loop gate. Before this was handled, `approval` fell
            # through to the generic "no handler" branch, was recorded as
            # success with `{"skipped": true}`, and the run continued — so a
            # playbook could isolate a host *after* an approval step nobody
            # had approved. A gate that cannot be cleared now parks the run.
            if step.type == StepType.APPROVAL:
                if dry_run:
                    pr.step_results.append(
                        {
                            "step_id": step.id,
                            "name": step.name,
                            "status": StepStatus.SKIPPED,
                            "result": {
                                "dry_run": True,
                                "would_require_approval": True,
                                "reason": "dry run: approval gate not exercised",
                            },
                        }
                    )
                    current_idx += 1
                    continue

                pr.step_results.append(
                    {
                        "step_id": step.id,
                        "name": step.name,
                        "status": StepStatus.BLOCKED,
                        "result": {
                            "requires_approval": True,
                            "reason": (
                                "playbook parked at an approval step; no further "
                                "steps were executed"
                            ),
                        },
                    }
                )
                pr.status = RunStatus.PENDING_APPROVAL
                pr.error = f"step '{step.name}' requires analyst approval"
                # Record where a resume must start: the step *after* the gate.
                # Without this the parked run has no way back in.
                pr.next_step_index = current_idx + 1
                pr.gate_step_id = step.id
                pr.gate_step_name = step.name
                await _emit(
                    pr.run_id,
                    "run.pending_approval",
                    {"step": step.name, "step_id": step.id},
                    http,
                )
                break

            await _emit(pr.run_id, "step.started", {"step": step.name, "type": step.type}, http)

            result: dict = {}
            step_status = StepStatus.SUCCESS
            attempt = 0
            handler = _HANDLERS.get(step.type)

            if handler is None and not dry_run:
                # A step kind this engine cannot execute must never report
                # success: a `disable_user` that silently skipped would leave
                # an analyst believing the account was disabled. Abort the run
                # regardless of `on_failure`, because the playbook's intent
                # cannot be carried out from here on.
                unsupported = {
                    "error": f"no handler implemented for step type '{step.type.value}'",
                    "unsupported_step_type": step.type.value,
                }
                pr.step_results.append(
                    {
                        "step_id": step.id,
                        "name": step.name,
                        "status": StepStatus.FAILED,
                        "result": unsupported,
                    }
                )
                pr.status = RunStatus.FAILED
                pr.error = unsupported["error"]
                await _emit(
                    pr.run_id,
                    "step.done",
                    {
                        "step": step.name,
                        "status": StepStatus.FAILED,
                        "unsupported_step_type": step.type.value,
                    },
                    http,
                )
                break

            # Phase 3: Governance check for containment actions (before handler execution)
            if step.type in _GOVERNED_STEP_TYPES and not dry_run:
                governance_result = await _check_governance(
                    step=step,
                    alert_context=pr.trigger_context,
                    tenant_id=pr.tenant_ref,
                    http=http,
                )

                if governance_result.get("requires_approval"):
                    # Playbook must pause at approval gate
                    logger.info(
                        "playbook.governance_gate_required",
                        extra={
                            "run_id": pr.run_id,
                            "step_id": step.id,
                            "action": step.type.value,
                            "level": governance_result.get("governance_level", "L2"),
                        },
                    )

                    pr.status = RunStatus.PENDING_APPROVAL
                    pr.gate_step_id = step.id
                    pr.gate_step_name = step.name
                    pr.next_step_index = current_idx  # Resume from this step
                    pr.error = f"step '{step.name}' requires governance approval"

                    pr.step_results.append({
                        "step_id": step.id,
                        "name": step.name,
                        "status": StepStatus.BLOCKED,
                        "result": {
                            "requires_approval": True,
                            "governance_level": governance_result.get("governance_level"),
                            "reason": governance_result.get("reason", "Governance policy requires approval"),
                        },
                    })

                    await _emit(
                        pr.run_id,
                        "step.blocked",
                        {
                            "step": step.name,
                            "reason": "awaiting governance approval",
                            "level": governance_result.get("governance_level"),
                        },
                        http,
                    )
                    break  # Park the run

            while True:
                attempt += 1
                t0 = time.perf_counter()
                try:
                    if dry_run:
                        result = {"dry_run": True, "step": step.name}
                    elif handler:
                        result = await handler(step, pr.context, http)
                    else:
                        # Unreachable: rejected below before the retry loop.
                        raise NotImplementedError(step.type.value)
                    elapsed = time.perf_counter() - t0
                    result["_elapsed_ms"] = round(elapsed * 1000)
                    break  # success
                except Exception as exc:  # noqa: BLE001
                    elapsed = time.perf_counter() - t0
                    logger.error("Step %s attempt %d failed: %s", step.name, attempt, exc)
                    if attempt <= step.retry_max:
                        await asyncio.sleep(min(2**attempt, 30))
                    else:
                        step_status = StepStatus.FAILED
                        result = {"error": str(exc), "_elapsed_ms": round(elapsed * 1000)}
                        break

            pr.step_results.append({"step_id": step.id, "name": step.name, "status": step_status, "result": result})
            # Merge result into context for downstream steps. The namespaced
            # key ``_step_<id>`` always reflects this step's full result.
            pr.context[f"_step_{step.id}"] = result
            # Flatten top-level keys for convenience so downstream steps can
            # reference ``alert.severity`` or ``user_id`` directly without
            # the ``_step_<id>.`` prefix. We *overwrite* prior values so a
            # later enrichment step can refine context (e.g. replacing a
            # placeholder ``user_id`` from the trigger with the resolved
            # canonical id). Keys starting with ``_`` are reserved for
            # engine bookkeeping and never auto-flattened.
            for k, v in result.items():
                if not k.startswith("_"):
                    pr.context[k] = v

            await _emit(
                pr.run_id,
                "step.done",
                {
                    "step": step.name,
                    "status": step_status,
                    "result_keys": list(result.keys()),
                },
                http,
            )

            if step_status == StepStatus.FAILED and step.on_failure == "abort":
                pr.status = RunStatus.FAILED
                pr.error = f"step '{step.name}' failed"
                break

            # Advance: branching on success
            if step_status == StepStatus.SUCCESS and step.next_true and step.next_true in step_index:
                current_idx = step_index[step.next_true]
            else:
                current_idx += 1
