"""Coerce query-string tenant ids into UUIDs.

The web console historically baked ``NEXT_PUBLIC_TENANT_ID=default``. Fusion
entity-risk endpoints type ``tenant_id`` as UUID, so that slug 422s before
the handler runs. Map known aliases to the canonical demo tenant so older
bundles and leftover localStorage values keep working.
"""

from __future__ import annotations

from uuid import UUID

DEMO_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")
_SLUG_ALIASES = {
    "default": DEMO_TENANT_ID,
    "demo": DEMO_TENANT_ID,
}


class TenantIdError(ValueError):
    """Raised when a query tenant id is empty or not a UUID/known slug."""


def coerce_tenant_id(raw: str) -> UUID:
    """Parse a query tenant id, mapping ``default`` / ``demo`` to the demo UUID."""
    text = (raw or "").strip()
    if not text:
        raise TenantIdError("tenant_id is required")
    alias = _SLUG_ALIASES.get(text.lower())
    if alias is not None:
        return alias
    try:
        return UUID(text)
    except ValueError as exc:
        raise TenantIdError("tenant_id must be a UUID") from exc
