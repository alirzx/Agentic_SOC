"""Safe condition evaluator for Automation Rules.

Evaluates a list of condition objects against an alert/case/incident's
field values. Conditions are data (JSONB from the database) — this module
deliberately never calls ``eval()``, ``compile()``, or ``exec()``.

Condition schema
----------------
Each condition is a dict with three keys:

    {"field": "severity", "op": "eq", "value": "critical"}

``field``
    Dotted path into the subject dict. Depth is bounded to prevent
    traversal attacks. Only the fields listed in ``_ALLOWED_FIELDS`` are
    readable; everything else short-circuits to ``False``.

``op``
    One of the whitelisted comparators in ``_OPS``. Unknown ops always
    return ``False`` (fail-closed).

``value``
    The literal to compare against. May be a string, number, or list
    (for ``in`` / ``not_in``). The field value is coerced to the same
    type before comparison where safe to do so.

Logic
-----
All conditions in the list are ANDed. An empty conditions list matches
every subject (by design: a rule with no conditions is a catch-all, and
the operator chose that explicitly).

Security properties
-------------------
* No ``eval()``, ``compile()``, or ``exec()`` anywhere.
* Field paths are validated against an allowlist before traversal.
* Depth is bounded (``_MAX_DEPTH``).
* Unknown operators fail closed (return ``False``).
* Exceptions from coercion or comparison return ``False`` (fail closed).
* Log injection is mitigated by sanitising field names before logging.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Fields an automation rule may inspect. Dotted paths allowed.
_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "severity",
        "status",
        "priority",
        "confidence",
        "confidence_label",
        "funnel_stage",
        "disposition",
        "category",
        "source",
        "connector_type",
        "title",
        "description",
        "tags",
        "affected_ips",
        "affected_hosts",
        "affected_users",
        "risk_score",
        "mitre_tactics",
        "mitre_techniques",
        "rule_name",
    }
)

_MAX_DEPTH = 2  # dotted paths deeper than this are rejected

def _op_eq(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a.casefold() == b.casefold()
    return a == b


def _op_ne(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a.casefold() != b.casefold()
    return a != b


def _op_in(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, (list, tuple, set)):
        return any(str(item).casefold() == a.casefold() for item in b if item is not None)
    return a in b


def _op_not_in(a: Any, b: Any) -> bool:
    return not _op_in(a, b)


def _op_contains(a: Any, b: Any) -> bool:
    if a is None:
        return False
    if isinstance(a, str):
        return str(b).casefold() in a.casefold()
    if isinstance(a, (list, tuple, set)):
        return str(b).casefold() in {str(item).casefold() for item in a}
    return str(b).casefold() in str(a).casefold()


def _op_not_contains(a: Any, b: Any) -> bool:
    return not _op_contains(a, b)


def _op_startswith(a: Any, b: Any) -> bool:
    return str(a or "").casefold().startswith(str(b).casefold())


def _op_endswith(a: Any, b: Any) -> bool:
    return str(a or "").casefold().endswith(str(b).casefold())


def _op_exists(a: Any, _b: Any) -> bool:
    return a is not None


def _op_not_exists(a: Any, _b: Any) -> bool:
    return a is None


def _op_array_contains(a: Any, b: Any) -> bool:
    if not isinstance(a, list):
        return False
    return any(str(item).casefold() == str(b).casefold() for item in a)


def _op_array_not_contains(a: Any, b: Any) -> bool:
    return not _op_array_contains(a, b)


# Whitelisted operators. Each maps to a Python function.
_OPS: dict[str, Any] = {
    "eq": _op_eq,
    "ne": _op_ne,
    "lt": lambda a, b: a < b,
    "le": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "ge": lambda a, b: a >= b,
    "in": _op_in,
    "not_in": _op_not_in,
    "contains": _op_contains,
    "not_contains": _op_not_contains,
    "startswith": _op_startswith,
    "endswith": _op_endswith,
    "exists": _op_exists,
    "not_exists": _op_not_exists,
    "array_contains": _op_array_contains,
    "array_not_contains": _op_array_not_contains,
}


class ConditionError(ValueError):
    """Raised when a condition definition is structurally invalid."""


def _validate_field(field: str) -> None:
    """Raise ``ConditionError`` if the field path is not allowed."""
    parts = field.split(".")
    if len(parts) > _MAX_DEPTH:
        raise ConditionError(
            f"field depth {len(parts)} exceeds maximum {_MAX_DEPTH}: {field!r}"
        )
    root = parts[0]
    if root not in _ALLOWED_FIELDS:
        raise ConditionError(f"field {root!r} is not in the allowed list")


def _get_field(subject: dict[str, Any], field: str) -> Any:
    """Extract a field value by dotted path. Returns ``None`` on missing."""
    parts = field.split(".", _MAX_DEPTH)
    cur: Any = subject
    for part in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _coerce(value: Any, target: Any) -> Any:
    """Best-effort coerce ``value`` to the same type as ``target``."""
    if target is None or isinstance(value, type(target)):
        return value
    try:
        if isinstance(target, int):
            return int(value)
        if isinstance(target, float):
            return float(value)
        if isinstance(target, str):
            return str(value)
    except (TypeError, ValueError):
        pass
    return value


def evaluate_condition(cond: dict[str, Any], subject: dict[str, Any]) -> bool:
    """Evaluate a single condition dict against ``subject``.

    Returns ``False`` on any structural problem (fail-closed), never raises.
    A condition without a value (empty string or None) is treated as inactive
    and returns ``True`` (passes, doesn't filter matches).
    """
    field = cond.get("field", "")
    op = cond.get("op", "")
    expected = cond.get("value")

    # Conditions without values are inactive and always pass
    if expected == "" or (expected is None and op not in ("exists", "not_exists")):
        return True

    if not isinstance(field, str) or not isinstance(op, str):
        logger.warning(
            "automation.condition.invalid_shape field=%s op=%s",
            str(field).replace("\r", "").replace("\n", " ")[:40],
            str(op).replace("\r", "").replace("\n", " ")[:20],
        )
        return False

    try:
        _validate_field(field)
    except ConditionError as exc:
        logger.warning("automation.condition.invalid_field %s", exc)
        return False

    fn = _OPS.get(op)
    if fn is None:
        logger.warning(
            "automation.condition.unknown_op op=%s",
            op.replace("\r", "").replace("\n", " ")[:20],
        )
        return False

    actual = _get_field(subject, field)
    coerced = _coerce(expected, actual)

    try:
        return bool(fn(actual, coerced))
    except (TypeError, ValueError):
        return False


def evaluate_all(conditions: list[dict[str, Any]], subject: dict[str, Any]) -> bool:
    """Return ``True`` iff ALL conditions in the list pass (AND logic).

    An empty list always returns ``True`` (a rule with no conditions is
    explicitly a catch-all — the operator chose that).
    """
    if not conditions:
        return True
    return all(evaluate_condition(c, subject) for c in conditions)


def validate_conditions(conditions: list[dict[str, Any]]) -> list[str]:
    """Return a list of human-readable errors in ``conditions``.

    Empty list = valid. Used by the API to reject malformed rules before
    they reach the DB.
    """
    errors: list[str] = []
    for i, cond in enumerate(conditions):
        field = cond.get("field", "")
        op = cond.get("op", "")
        if not isinstance(field, str) or not field:
            errors.append(f"condition[{i}]: field must be a non-empty string")
            continue
        try:
            _validate_field(field)
        except ConditionError as exc:
            errors.append(f"condition[{i}]: {exc}")
        if op not in _OPS:
            errors.append(
                f"condition[{i}]: op {op!r} is not one of {sorted(_OPS)}"
            )
    return errors
