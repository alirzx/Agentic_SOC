"""Privacy / redaction primitives for the investigation agent.

The single sanctioned way to pseudonymize untrusted evidence before it leaves
the process for a third-party LLM. See :mod:`app.privacy.redactor`.
"""

from __future__ import annotations

from app.privacy.context import PrivacyConfigurationError, current_privacy_gateway, privacy_context, privacy_enabled
from app.privacy.gateway import PrivacyGateway
from app.privacy.redactor import Pseudonymizer, RedactionConfig, default_pseudonymizer
from app.privacy.tenant import resolve_request_tenant, tenant_signature

__all__ = [
    "PrivacyConfigurationError",
    "PrivacyGateway",
    "Pseudonymizer",
    "RedactionConfig",
    "current_privacy_gateway",
    "default_pseudonymizer",
    "privacy_context",
    "privacy_enabled",
    "resolve_request_tenant",
    "tenant_signature",
]
