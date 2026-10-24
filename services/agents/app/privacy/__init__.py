"""Privacy / redaction primitives for the investigation agent.

The single sanctioned way to pseudonymize untrusted evidence before it leaves
the process for a third-party LLM. See :mod:`app.privacy.redactor`.
"""

from __future__ import annotations

from app.privacy.context import PrivacyConfigurationError, current_privacy_gateway, privacy_context, privacy_enabled
from app.privacy.gateway import PrivacyGateway
from app.privacy.redactor import Pseudonymizer, RedactionConfig, default_pseudonymizer
from app.privacy.tenant import (
    CANONICAL_SEED_TENANT_ID,
    normalize_tenant_uuid,
    resolve_canonical_tenant,
    resolve_request_tenant,
    resolve_tenant_for_llm,
    tenant_signature,
)

__all__ = [
    "CANONICAL_SEED_TENANT_ID",
    "PrivacyConfigurationError",
    "PrivacyGateway",
    "Pseudonymizer",
    "RedactionConfig",
    "current_privacy_gateway",
    "default_pseudonymizer",
    "normalize_tenant_uuid",
    "privacy_context",
    "privacy_enabled",
    "resolve_canonical_tenant",
    "resolve_request_tenant",
    "resolve_tenant_for_llm",
    "tenant_signature",
]
