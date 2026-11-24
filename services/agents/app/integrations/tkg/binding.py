"""Deployment-owned routes. A credential reference is derived from immutable UUIDs."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID


class BindingError(ValueError):
    pass


@dataclass(frozen=True)
class Binding:
    id: UUID
    tenant_id: UUID
    instance: str
    kb_id: UUID
    source_id: UUID
    tkg_tenant: str
    source_system: str
    source_instance: str
    connector_id: UUID | None

    @classmethod
    def from_row(cls, row, workspace: UUID):
        binding = cls(**{key: row[key] for key in cls.__dataclass_fields__})
        if binding.tenant_id != workspace or not row["enabled"]:
            raise BindingError("binding_unavailable")
        return binding

    def origin(self) -> str:
        origin = os.getenv("AISOC_TKG_ORIGIN_" + self.instance.upper(), "").rstrip("/")
        url = urlsplit(origin)
        if (not url.hostname or url.username or url.password or url.path or url.query
                or url.fragment or not (url.scheme == "https" or origin == "http://soorin-tkg:1516")):
            raise BindingError("instance_origin_invalid")
        return origin

    def credential(self, role: str) -> str:
        if role not in {"reader", "ingest", "diagnostics"}:
            raise BindingError("invalid_credential_role")
        path = Path(os.getenv("AISOC_TKG_SECRET_DIR", "/run/secrets/tkg"))
        try:
            token = (path / role / str(self.tenant_id) / str(self.id)).read_text().strip()
        except (OSError, UnicodeError):
            raise BindingError("binding_credential_unavailable") from None
        if not token or not token.isascii() or any(c.isspace() for c in token):
            raise BindingError("binding_credential_invalid")
        return token
