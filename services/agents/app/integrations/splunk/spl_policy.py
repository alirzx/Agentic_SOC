"""Read-only SPL validation policy (Phase 8.7)."""

from __future__ import annotations

import re

from .errors import SplunkQueryValidationError

_DANGEROUS_COMMANDS = (
    "| delete",
    "| collect",
    "| outputlookup",
    "| outputcsv",
    "| rest ",
    "| script",
    "| sendemail",
    "| run",
    "inputlookup",
)

_RELATIVE_TIME_RE = re.compile(r"^-(\d+)([mhd])$", re.IGNORECASE)


def validate_spl_query(
    query: str,
    *,
    max_length: int,
    max_window_minutes: int,
    earliest: str | None,
    latest: str | None,
    max_events: int,
    max_events_cap: int,
) -> None:
    """Validate query before network execution. Raises SplunkQueryValidationError."""
    stripped = (query or "").strip()
    if not stripped:
        raise SplunkQueryValidationError("query must not be empty")
    if len(stripped) > max_length:
        raise SplunkQueryValidationError(f"query exceeds max length ({max_length})")
    lowered = stripped.lower()
    for token in _DANGEROUS_COMMANDS:
        if token in lowered:
            raise SplunkQueryValidationError(f"disallowed SPL command: {token.strip()}")
    if max_events > max_events_cap:
        raise SplunkQueryValidationError(f"max_events exceeds cap ({max_events_cap})")
    if max_events < 1:
        raise SplunkQueryValidationError("max_events must be >= 1")
    window_minutes = _relative_window_minutes(earliest)
    if window_minutes is not None and window_minutes > max_window_minutes:
        raise SplunkQueryValidationError(
            f"earliest time window exceeds {max_window_minutes} minutes"
        )
    if latest and latest.lower() not in {"now", ""} and not latest.isdigit():
        raise SplunkQueryValidationError("latest must be 'now' or epoch seconds")


def _relative_window_minutes(earliest: str | None) -> int | None:
    if not earliest:
        return None
    match = _RELATIVE_TIME_RE.match(earliest.strip())
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2).lower()
    if unit == "m":
        return amount
    if unit == "h":
        return amount * 60
    if unit == "d":
        return amount * 24 * 60
    return None


def ensure_search_prefix(query: str) -> str:
    """Ensure SPL is a search command."""
    stripped = query.strip()
    if stripped.lower().startswith("search ") or stripped.startswith("|"):
        return stripped
    return f"search {stripped}"
