"""Tier-2 Adaptive Investigation Engine.

Feature-flagged via ``AISOC_TIER2_ADAPTIVE`` (default OFF). When disabled the
legacy IP-pivot path in ``tier2_ip_pivot`` remains the sole execution path.
"""

from __future__ import annotations

from app.services.tier2_adaptive.entities import (
    ExtractedEntity,
    EntityExtractionResult,
    extract_alert_entities,
)
from app.services.tier2_adaptive.feature_flags import (
    selected_tier2_path,
    tier2_adaptive_enabled,
    tier2_adaptive_shadow,
)
from app.services.tier2_adaptive.profiles import (
    ProfileSelection,
    select_investigation_profiles,
)

__all__ = [
    "ExtractedEntity",
    "EntityExtractionResult",
    "ProfileSelection",
    "extract_alert_entities",
    "select_investigation_profiles",
    "selected_tier2_path",
    "tier2_adaptive_enabled",
    "tier2_adaptive_shadow",
]
