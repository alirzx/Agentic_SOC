"""Execution contracts for governed actions (Runbook Phase 0).

Four contracts, one per axis the platform must be able to answer about any
action it took. They are attached to each
:class:`~app.services.runbook.action_catalog.ActionDefinition`.

* :class:`AuditContract`        — what is written down, and where.
* :class:`DataSafetyContract`   — which fields may be persisted or enter a prompt.
* :class:`FailureContract`      — retry, timeout, and what to do when it breaks.
* :class:`CostBudget`           — the ceiling a single run may spend.

Deliberately code-only in v1
----------------------------
A contract is a property of the *implementation* that has to honour it, so it
lives next to that code rather than in a database row an operator could edit
into a state the executor never reads. Making it editable later is a
migration, not a redesign: the executor already asks the contract object.

Every contract validates itself at construction time (``__post_init__``), so a
malformed definition fails at import — in CI — rather than at 3am on the one
code path that happens to read the broken field.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

__all__ = [
    "AuditContract",
    "DataSafetyContract",
    "FailureContract",
    "CostBudget",
    "REDACTED",
]

REDACTED = "[redacted]"

# Keys that are scrubbed even when the contract allows pass-through. Credential
# material must never reach a ledger row or an LLM prompt, whatever the action.
_ALWAYS_REDACTED = (
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private_key",
    "credential",
    "credentials",
    "client_secret",
)

_FAILURE_MODES = ("abort", "continue", "escalate")


@dataclass(frozen=True)
class AuditContract:
    """What an action must write down.

    ``record_ledger`` is always required by the platform — the Runbook *is* the
    ledger — but it is modelled explicitly so a future ``record_ledger=False``
    decision has to be made out loud in review.

    ``audit_log`` escalates to the legal audit store (``audit_log``, hash
    chained by migration 043). Any action with blast radius ``high`` or above
    must set it: the ledger explains the *operation*, the audit log is what
    compliance exports.
    """

    record_ledger: bool = True
    audit_log: bool = False
    audit_action: str | None = None
    include_input: bool = True
    include_output: bool = True

    def __post_init__(self) -> None:
        if self.audit_log and not self.audit_action:
            raise ValueError(
                "AuditContract.audit_action is required when audit_log=True "
                "(it becomes audit_log.action, which compliance exports key off)"
            )


@dataclass(frozen=True)
class DataSafetyContract:
    """Which fields may be persisted, and how much of them.

    ``allowed_fields`` supports the single wildcard ``"*"`` meaning
    "pass through, minus the always-redacted credential keys". An allow-list of
    concrete names is the stricter form and is what containment actions use:
    the ledger gets the target and the reason, not the whole event payload.
    """

    allowed_fields: tuple[str, ...] = ("*",)
    redact: tuple[str, ...] = ()
    max_payload_bytes: int = 8192
    allow_pii: bool = False

    def __post_init__(self) -> None:
        if self.max_payload_bytes < 128:
            raise ValueError("max_payload_bytes must be at least 128")
        if not self.allowed_fields:
            raise ValueError("allowed_fields must not be empty — use ('*',) for pass-through")

    def sanitize(self, payload: dict[str, Any] | None) -> dict[str, Any]:
        """Return a ledger-safe copy of ``payload``.

        Drops anything outside ``allowed_fields``, replaces credential keys and
        explicitly ``redact``-ed keys with :data:`REDACTED`, then enforces the
        byte budget. When the result would still exceed the budget the payload
        is replaced by an explicit truncation marker — silently shipping a
        partial payload would make the ledger lie about what the action saw.
        """
        if not payload:
            return {}

        passthrough = "*" in self.allowed_fields
        allowed = set(self.allowed_fields)
        redact = set(self.redact) | set(_ALWAYS_REDACTED)
        out: dict[str, Any] = {}

        for key, value in payload.items():
            key_text = str(key)
            if key_text in redact:
                out[key_text] = REDACTED
                continue
            if passthrough or key_text in allowed:
                out[key_text] = value

        try:
            encoded = json.dumps(out, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            return {"_unserializable": True}
        size = len(encoded.encode("utf-8"))
        if size > self.max_payload_bytes:
            return {"_truncated": True, "_bytes": size, "_budget": self.max_payload_bytes}
        return out


@dataclass(frozen=True)
class FailureContract:
    """How an action behaves when it breaks.

    ``on_failure``:
      * ``abort``    — stop; the subject keeps its current state.
      * ``continue`` — record the failure and let the workflow proceed.
      * ``escalate`` — record the failure and raise it to a human.

    ``max_attempts`` counts the first try, so ``1`` means "no retry".
    """

    max_attempts: int = 1
    backoff_seconds: float = 0.0
    timeout_seconds: float = 30.0
    on_failure: str = "abort"

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts counts the first try, so it must be >= 1")
        if self.backoff_seconds < 0:
            raise ValueError("backoff_seconds must be >= 0")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if self.on_failure not in _FAILURE_MODES:
            raise ValueError(f"on_failure must be one of {_FAILURE_MODES}, got {self.on_failure!r}")

    def retry_delay(self, attempt: int) -> float:
        """Seconds to wait before ``attempt`` (1-based); linear backoff.

        Linear, not exponential: these are interactive SOC actions with a
        human waiting, and a 30s+ first retry would be worse than failing.
        """
        if attempt < 1:
            raise ValueError("attempt is 1-based")
        return self.backoff_seconds * attempt


@dataclass(frozen=True)
class CostBudget:
    """Ceiling on what a single run of this action may spend.

    ``None`` means "not budgeted" — the action does not call a metered service
    (a pure REST lookup against the customer's own SIEM, for example).
    ``0.0`` is a real budget and means "no LLM spend allowed", which is what
    containment actions get on purpose.
    """

    max_usd_per_run: float | None = None
    max_tokens: int | None = None
    max_wall_ms: int | None = None

    def __post_init__(self) -> None:
        if self.max_usd_per_run is not None and self.max_usd_per_run < 0:
            raise ValueError("max_usd_per_run must be >= 0")
        if self.max_tokens is not None and self.max_tokens < 0:
            raise ValueError("max_tokens must be >= 0")
        if self.max_wall_ms is not None and self.max_wall_ms <= 0:
            raise ValueError("max_wall_ms must be > 0")

    def exceeded(
        self,
        *,
        usd: float | None = None,
        tokens: int | None = None,
        wall_ms: int | None = None,
    ) -> str | None:
        """Return the breached limit as a short code, or ``None`` when within budget."""
        if self.max_usd_per_run is not None and usd is not None and usd > self.max_usd_per_run:
            return "cost_budget_exceeded:usd"
        if self.max_tokens is not None and tokens is not None and tokens > self.max_tokens:
            return "cost_budget_exceeded:tokens"
        if self.max_wall_ms is not None and wall_ms is not None and wall_ms > self.max_wall_ms:
            return "cost_budget_exceeded:wall_ms"
        return None
