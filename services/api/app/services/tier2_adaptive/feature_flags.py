"""Feature-flag helpers for the Tier-2 Adaptive Investigation Engine.

``AISOC_TIER2_ADAPTIVE`` defaults OFF so production keeps the legacy IP-pivot
path until explicitly activated. ``AISOC_TIER2_ADAPTIVE_SHADOW`` runs the
adaptive path for logging/comparison without writing Case/membership side
effects that would duplicate the legacy path.
"""

from __future__ import annotations

from typing import Any


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "on"}


def tier2_adaptive_enabled() -> bool:
    """Return True when the adaptive engine is the selected execution path."""
    try:
        from app.core.config import get_settings

        settings = get_settings()
        return bool(getattr(settings, "TIER2_ADAPTIVE_ENABLED", False))
    except Exception:  # noqa: BLE001 — settings may be unavailable in unit tests
        import os

        return _truthy(os.environ.get("AISOC_TIER2_ADAPTIVE"))


def tier2_adaptive_shadow() -> bool:
    """Return True when adaptive should run in shadow (no mutating side effects)."""
    try:
        from app.core.config import get_settings

        settings = get_settings()
        return bool(getattr(settings, "TIER2_ADAPTIVE_SHADOW", False))
    except Exception:  # noqa: BLE001
        import os

        return _truthy(os.environ.get("AISOC_TIER2_ADAPTIVE_SHADOW"))


def selected_tier2_path() -> str:
    """Loggable execution-path label."""
    if tier2_adaptive_enabled():
        return "adaptive"
    if tier2_adaptive_shadow():
        return "legacy+shadow_adaptive"
    return "legacy"
