"""Analyst-controlled alert scope for a correlation graph.

A correlation graph is built from *every* alert the engine placed in an
observation. Real campaigns carry noise: a scheduled scan that fires next to a
credential-theft burst, a vulnerability alert that shares a host but not the
intrusion. The analyst needs to say "not this one" **and** "not anything whose
payload looks like this" — and have the graph, the timeline and the case that
gets created all agree on the reduced evidence set.

Two mechanisms, deliberately separate:

``excluded_alert_ids``
    Hard, per-alert. Dropped from the analysis and (for a candidate promotion)
    from the alerts the new case claims.

``filters``
    Pattern-level, evaluated against the alert's ``llm_payload`` only. Each
    filter is ``field|op|value|mode``:

    * ``mode=include`` — keep only alerts that match **all** include filters
    * ``mode=exclude`` — drop alerts that match **any** exclude filter

    ``op`` is one of :data:`ALLOWED_OPS`. ``exists`` / ``not_exists`` ignore the
    value.

Scope fields are restricted to ``llm_payload`` on purpose. The denormalised
``alerts.affected_hosts`` / ``affected_ips`` / … columns are not the engine's
input — the correlation keys come from the payload the rule emitted — so
filtering on them here would silently disagree with the graph the analyst is
looking at. A field outside the payload root raises :class:`ScopeError`.

Everything that can be decided without a database session is pure, so the
matching rules are unit-testable directly.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text

#: Field-root the scope is allowed to address. Anything else is rejected.
ROOT = "llm_payload"

#: Convenience aliases: ``payload.x`` → ``llm_payload.x`` and
#: ``alert_fields.x`` → ``llm_payload.alert_fields.x`` (that key is a real
#: sub-object of the payload, so it must not be collapsed into the root).
_ALIAS_ROOTS = {"payload": "", "alert_fields": "alert_fields"}

ALLOWED_OPS = frozenset(
    {"eq", "neq", "contains", "not_contains", "exists", "not_exists", "in", "gt", "lt"}
)
ALLOWED_MODES = frozenset({"include", "exclude"})


class ScopeError(ValueError):
    """A scope the API refuses to interpret (bad field path, op, or mode)."""


@dataclass(frozen=True)
class ScopeFilter:
    """One include/exclude rule over ``llm_payload``."""

    field: str
    op: str
    value: str | None
    mode: str

    def as_raw(self) -> str:
        return f"{self.field}|{self.op}|{self.value or ''}|{self.mode}"


@dataclass
class ScopeResult:
    """Outcome of applying a scope to a set of alerts."""

    known_ids: list[str]
    kept_ids: list[str]
    #: ``{"alert_id", "title", "reason"}`` for every alert the scope removed.
    dropped: list[dict[str, Any]]

    @property
    def dropped_ids(self) -> list[str]:
        return [item["alert_id"] for item in self.dropped]


# ─────────────────────────────────────────────────────────────────────────────
# Parsing / validation (pure)
# ─────────────────────────────────────────────────────────────────────────────


def _normalize_field(raw: str) -> str:
    field = (raw or "").strip()
    if not field:
        raise ScopeError("A scope filter needs a field.")
    head, _, rest = field.partition(".")
    if head in _ALIAS_ROOTS:
        prefix = _ALIAS_ROOTS[head]
        parts = [part for part in (prefix, rest) if part]
        field = ".".join([ROOT, *parts])
    if field == ROOT:
        raise ScopeError(f"A scope filter must name a field under {ROOT}.<path>.")
    if not field.startswith(f"{ROOT}."):
        raise ScopeError(
            f"Only fields under {ROOT} can be filtered — "
            "the denormalised alert columns are not the engine's input."
        )
    # Reject anything that is not a plain key / index path, so a filter can
    # never be interpreted as SQL or as an attribute walk.
    for token in field.split(".")[1:]:
        if not token:
            raise ScopeError(f"Empty path segment in '{field}'.")
        if token.isdigit():
            continue
        if not token.replace("_", "").replace("-", "").isalnum():
            raise ScopeError(f"Unsupported path segment '{token}' in '{field}'.")
    return field


def parse_filter(raw: str) -> ScopeFilter:
    """Parse ``field|op|value|mode``.

    ``exists`` / ``not_exists`` may omit the value; every other op needs one.
    A value may not contain ``|`` (it would be ambiguous with the separator).
    """

    parts = (raw or "").split("|")
    if len(parts) == 3:
        field, op, value, mode = parts[0], parts[1], None, parts[2]
    elif len(parts) >= 4:
        field, op, value = parts[0], parts[1], "|".join(parts[2:-1])
        mode = parts[-1]
    else:
        raise ScopeError(
            "A scope filter must look like 'llm_payload.rule.name|eq|value|exclude'."
        )

    field = _normalize_field(field)
    op = (op or "").strip().lower()
    if op not in ALLOWED_OPS:
        raise ScopeError(f"Unsupported filter op '{op}'. Use one of {sorted(ALLOWED_OPS)}.")
    mode = (mode or "").strip().lower()
    if mode not in ALLOWED_MODES:
        raise ScopeError(f"Unsupported filter mode '{mode}'. Use include or exclude.")

    cleaned = (value or "").strip()
    if op not in {"exists", "not_exists"} and not cleaned:
        raise ScopeError(f"Filter op '{op}' needs a value.")
    return ScopeFilter(field=field, op=op, value=cleaned or None, mode=mode)


def parse_filters(raw_filters: Iterable[str] | None) -> list[ScopeFilter]:
    return [parse_filter(raw) for raw in (raw_filters or [])]


def filters_to_raw(filters: Sequence[ScopeFilter]) -> list[str]:
    return [item.as_raw() for item in filters]


# ─────────────────────────────────────────────────────────────────────────────
# Matching (pure)
# ─────────────────────────────────────────────────────────────────────────────


def resolve_path(payload: Any, field: str) -> Any:
    """Walk ``llm_payload.a.b[0].c`` (dot path with numeric list indices)."""

    current = payload
    for token in field.split(".")[1:]:
        if current is None:
            return None
        if token.isdigit():
            index = int(token)
            if isinstance(current, (list, tuple)) and 0 <= index < len(current):
                current = current[index]
            else:
                return None
            continue
        if isinstance(current, Mapping):
            current = current.get(token)
        else:
            return None
    return current


def _flatten(values: Iterable[Any]) -> list[str]:
    return [str(value).strip().lower() for value in values if value is not None]


def _as_matches(actual: Any) -> list[str]:
    """Normalise a payload value to lower-case strings for comparison."""

    if actual is None:
        return []
    if isinstance(actual, (str, int, float, bool)):
        return [str(actual).strip().lower()]
    if isinstance(actual, Mapping):
        return _flatten(actual.values())
    if isinstance(actual, (list, tuple, set)):
        return [item for value in actual for item in _as_matches(value)]
    return [str(actual).strip().lower()]


def _is_present(actual: Any) -> bool:
    if actual is None:
        return False
    if isinstance(actual, str):
        return bool(actual.strip())
    if isinstance(actual, (list, tuple, set, Mapping)):
        return len(actual) > 0
    return True


def filter_matches(alert: Mapping[str, Any], item: ScopeFilter) -> bool:
    """Does one alert satisfy one filter?"""

    actual = resolve_path(alert.get(ROOT), item.field)
    expected = (item.value or "").strip().lower()

    if item.op == "exists":
        return _is_present(actual)
    if item.op == "not_exists":
        return not _is_present(actual)

    values = _as_matches(actual)
    if not values:
        return False
    if item.op == "eq":
        return expected in values
    if item.op == "neq":
        return expected not in values
    if item.op == "contains":
        return any(expected in value for value in values)
    if item.op == "not_contains":
        return all(expected not in value for value in values)
    if item.op == "in":
        wanted = {part.strip().lower() for part in (item.value or "").split(",") if part.strip()}
        return bool(wanted) and any(value in wanted for value in values)
    if item.op in {"gt", "lt"}:
        try:
            numbers = [float(value) for value in values]
            target = float(expected)
        except (TypeError, ValueError):
            return False
        return any(number > target for number in numbers) if item.op == "gt" else any(
            number < target for number in numbers
        )
    return False


def _decide(
    alert: Mapping[str, Any], filters: Sequence[ScopeFilter]
) -> tuple[bool, str | None]:
    """Return ``(keep, reason_if_dropped)`` for one alert."""

    includes = [item for item in filters if item.mode == "include"]
    excludes = [item for item in filters if item.mode == "exclude"]

    if includes and not all(filter_matches(alert, item) for item in includes):
        return False, f"does not match include filter {includes[0].as_raw()}"
    for item in excludes:
        if filter_matches(alert, item):
            return False, f"matches exclude filter {item.as_raw()}"
    return True, None


def apply_scope(
    alerts: Sequence[Mapping[str, Any]],
    *,
    excluded_ids: Iterable[str] = (),
    filters: Sequence[ScopeFilter] = (),
) -> ScopeResult:
    """Decide which alerts survive the scope.

    ``alerts`` rows need ``id``, an optional ``title`` and the ``llm_payload``
    the filters address.
    """

    explicit = {str(value) for value in excluded_ids if str(value).strip()}
    known: list[str] = []
    kept: list[str] = []
    dropped: list[dict[str, Any]] = []

    for alert in alerts:
        alert_id = str(alert.get("id"))
        known.append(alert_id)
        title = alert.get("title")
        if alert_id in explicit:
            dropped.append(
                {"alert_id": alert_id, "title": title, "reason": "excluded by the analyst"}
            )
            continue
        keep, reason = _decide(alert, filters)
        if keep:
            kept.append(alert_id)
        else:
            dropped.append({"alert_id": alert_id, "title": title, "reason": reason})

    return ScopeResult(known_ids=known, kept_ids=kept, dropped=dropped)


# ─────────────────────────────────────────────────────────────────────────────
# Database helper
# ─────────────────────────────────────────────────────────────────────────────


async def resolve_scope(
    session: Any,
    tenant_id: Any,
    alert_ids: Iterable[str],
    *,
    excluded_ids: Iterable[str] = (),
    filters: Sequence[ScopeFilter] = (),
) -> ScopeResult:
    """Load the alerts of a graph and apply the scope.

    Alerts the tenant cannot see are reported as dropped rather than silently
    missing, so a stale graph cannot hide that its evidence moved.
    """

    ids = [str(value) for value in alert_ids if str(value).strip()]
    if not ids:
        return ScopeResult(known_ids=[], kept_ids=[], dropped=[])

    rows = (
        await session.execute(
            text(
                """
                SELECT id, title, llm_payload
                  FROM alerts
                 WHERE tenant_id = :tenant_id
                   AND id::text = ANY(:ids)
                """
            ),
            {"tenant_id": tenant_id, "ids": ids},
        )
    ).mappings()

    found = [
        {"id": str(row["id"]), "title": row["title"], "llm_payload": row["llm_payload"]}
        for row in rows
    ]
    result = apply_scope(found, excluded_ids=excluded_ids, filters=filters)

    known = set(result.known_ids)
    for alert_id in (value for value in ids if value not in known):
        result.dropped.append(
            {
                "alert_id": alert_id,
                "title": None,
                "reason": "no longer visible to this tenant",
            }
        )
    return result
