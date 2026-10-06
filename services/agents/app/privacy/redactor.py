"""Tenant-scoped deterministic pseudonymization for external AI egress."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = ["RedactionConfig", "Pseudonymizer", "default_pseudonymizer"]

_USER_FIELDS = frozenset(
    {
        "user",
        "username",
        "user_name",
        "user_id",
        "user_email",
        "principal",
        "actor",
        "dest_owner",
        "subject",
        "account",
        "samaccountname",
        "upn",
        "sender",
        "recipient",
    }
)
_IP_FIELDS = frozenset({"src_ip", "source_ip", "dst_ip", "dest_ip", "destination_ip", "client_ip", "remote_ip", "ip"})
_HOST_FIELDS = frozenset({"host", "host_name", "hostname", "dvc", "device", "device_name", "endpoint", "dest_nt_host", "computer"})
_ASSET_FIELDS = frozenset({"asset", "asset_id", "device_id", "endpoint_id"})
_SECRET_FIELDS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "token",
        "authorization",
        "authorization_header",
        "cookie",
        "cookies",
        "set_cookie",
        "private_key",
        "client_secret",
        "credential",
        "credentials",
    }
)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+")
_UNC_PATH_RE = re.compile(r"\\\\[^\s\"']+")
_UNIX_PATH_RE = re.compile(r"(?:/[A-Za-z0-9._\-]+){2,}/?")
_DOMAIN_USER_RE = re.compile(r"\b[A-Za-z0-9.\-]+\\[A-Za-z0-9._\-]+")
_USER_CONTEXT_RE = re.compile(r"(?i)\b(user(?:name)?|account|principal|actor)\s*([:=])\s*([A-Za-z][A-Za-z0-9._\-]{1,63})")
_IP_RE = re.compile(r"(?<![A-Za-z0-9_:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{2,})(?![A-Za-z0-9_:])")
_FQDN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\.?\b")
_SECRET_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.DOTALL),
    re.compile(r"(?i)\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+[^\s,;]+"),
    re.compile(
        r"(?i)\b(?:password|passwd|secret|key|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|cookie)\s*[:=]\s*[^\s,;]+"
    ),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
)

_DEFAULT_INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".intranet", ".home.arpa")
_TOKEN_VERSION = b"aisoc-privacy-v1"
_MAX_DEPTH = 24


@dataclass(frozen=True)
class RedactionConfig:
    redact_internal_ips: bool = True
    redact_emails: bool = True
    redact_paths: bool = True
    redact_secrets: bool = True
    redact_internal_hostnames: bool = True
    redact_usernames: bool = True
    internal_domain_suffixes: tuple[str, ...] = _DEFAULT_INTERNAL_SUFFIXES


def _normalise_key(key: str | None) -> str:
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", (key or "").strip())
    return camel_split.lower().replace("-", "_").replace(".", "_")


def _canonical(kind: str, value: str) -> str:
    cleaned = value.strip()
    if kind == "IP":
        return str(ipaddress.ip_address(cleaned))
    if kind == "HOST":
        return cleaned.rstrip(".").casefold()
    if kind in {"EMAIL", "USER", "ASSET"}:
        return cleaned.casefold()
    return cleaned


def _network_label(value: str) -> str:
    ip = ipaddress.ip_address(value)
    family = "V4" if ip.version == 4 else "V6"
    if ip.is_loopback:
        scope = "LOOPBACK"
    elif ip.is_link_local:
        scope = "LINKLOCAL"
    elif ip.is_private:
        scope = "PRIVATE"
    elif ip.is_reserved or ip.is_unspecified or ip.is_multicast:
        scope = "RESERVED"
    else:
        scope = "PUBLIC"
    return f"IP_{family}_{scope}"


def _is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


class Pseudonymizer:
    """Stable token codec with an active, in-memory reverse map."""

    def __init__(self, *, tenant_id: str, token_key: str | bytes, config: RedactionConfig | None = None) -> None:
        tenant = str(tenant_id).strip()
        key = token_key.encode("utf-8") if isinstance(token_key, str) else bytes(token_key)
        if not tenant:
            raise ValueError("tenant_id is required for privacy tokenization")
        if len(key) < 32:
            raise ValueError("privacy token key must contain at least 32 bytes")
        self.tenant_id = tenant
        self.config = config or RedactionConfig()
        self._key = key
        self._to_token: dict[tuple[str, str], str] = {}
        self._to_original: dict[str, str] = {}
        self.tokenized_count = 0
        self.masked_secret_count = 0

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self._to_original)

    def redact(self, text: str) -> str:
        if not isinstance(text, str) or not text:
            return text if isinstance(text, str) else ""
        out = text
        # Values already registered from structured fields are authoritative;
        # protect exact repeats in narrative/tool text before generic parsing.
        for token, original in sorted(self._to_original.items(), key=lambda item: len(item[1]), reverse=True):
            if original:
                out = out.replace(original, token)
        if self.config.redact_secrets:
            for pattern in _SECRET_RES:
                out = pattern.sub(self._mask_match, out)
        if self.config.redact_emails:
            out = _EMAIL_RE.sub(lambda match: self._token("EMAIL", match.group(0)), out)
        if self.config.redact_paths:
            out = _WIN_PATH_RE.sub(lambda match: self._token("PATH", match.group(0)), out)
            out = _UNC_PATH_RE.sub(lambda match: self._token("PATH", match.group(0)), out)
            out = _UNIX_PATH_RE.sub(lambda match: self._token("PATH", match.group(0)), out)
        if self.config.redact_usernames:
            out = _DOMAIN_USER_RE.sub(lambda match: self._token("USER", match.group(0)), out)
            out = _USER_CONTEXT_RE.sub(self._contextual_user, out)
        if self.config.redact_internal_hostnames:
            out = _FQDN_RE.sub(self._maybe_internal_host, out)
        if self.config.redact_internal_ips:
            out = _IP_RE.sub(self._maybe_internal_ip, out)
        return out

    def redact_value(self, value: Any, *, _key: str | None = None) -> Any:
        return self._redact_value(value, key=_key, depth=0, seen=set())

    def rehydrate(self, value: Any) -> Any:
        """Exact, mapping-only restoration; unknown tokens remain unchanged."""
        return self._rehydrate(value, depth=0, seen=set())

    def _redact_value(self, value: Any, *, key: str | None, depth: int, seen: set[int]) -> Any:
        if depth > _MAX_DEPTH:
            raise ValueError("privacy projection exceeded maximum nesting depth")
        if isinstance(value, str):
            field = _normalise_key(key)
            if self.config.redact_secrets and (
                field in _SECRET_FIELDS or field.endswith("_password") or field.endswith("_token") or field.endswith("_secret")
            ):
                self.masked_secret_count += 1
                return "[REDACTED_SECRET]"
            if field in _IP_FIELDS:
                try:
                    ipaddress.ip_address(value.strip())
                except ValueError:
                    return self.redact(value)
                return self._token("IP", value)
            if field in _ASSET_FIELDS:
                return self._token("ASSET", value)
            if field in _HOST_FIELDS:
                return self._token("HOST", value)
            if field in _USER_FIELDS:
                return self._token("EMAIL" if _EMAIL_RE.fullmatch(value.strip()) else "USER", value)
            return self.redact(value)
        if isinstance(value, Mapping):
            marker = id(value)
            if marker in seen:
                raise ValueError("privacy projection does not accept recursive mappings")
            seen.add(marker)
            try:
                return {k: self._redact_value(v, key=str(k), depth=depth + 1, seen=seen) for k, v in value.items()}
            finally:
                seen.remove(marker)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            marker = id(value)
            if marker in seen:
                raise ValueError("privacy projection does not accept recursive sequences")
            seen.add(marker)
            try:
                return [self._redact_value(v, key=key, depth=depth + 1, seen=seen) for v in value]
            finally:
                seen.remove(marker)
        return value

    def _rehydrate(self, value: Any, *, depth: int, seen: set[int]) -> Any:
        if depth > _MAX_DEPTH:
            raise ValueError("privacy rehydration exceeded maximum nesting depth")
        if isinstance(value, str):
            out = value
            for token in sorted(self._to_original, key=len, reverse=True):
                out = re.sub(
                    rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])",
                    lambda _match, original=self._to_original[token]: original,
                    out,
                )
            return out
        if isinstance(value, Mapping):
            marker = id(value)
            if marker in seen:
                raise ValueError("privacy rehydration does not accept recursive mappings")
            seen.add(marker)
            try:
                return {k: self._rehydrate(v, depth=depth + 1, seen=seen) for k, v in value.items()}
            finally:
                seen.remove(marker)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            marker = id(value)
            if marker in seen:
                raise ValueError("privacy rehydration does not accept recursive sequences")
            seen.add(marker)
            try:
                return [self._rehydrate(v, depth=depth + 1, seen=seen) for v in value]
            finally:
                seen.remove(marker)
        return value

    def _mask_match(self, _match: re.Match[str]) -> str:
        self.masked_secret_count += 1
        return "[REDACTED_SECRET]"

    def _contextual_user(self, match: re.Match[str]) -> str:
        value = match.group(3)
        replacement = value if value in self._to_original else self._token("USER", value)
        return f"{match.group(1)}{match.group(2)}{replacement}"

    def _token(self, kind: str, original: str) -> str:
        try:
            canonical = _canonical(kind, original)
        except ValueError:
            return original
        identity = (kind, canonical)
        existing = self._to_token.get(identity)
        if existing:
            return existing
        parts = (_TOKEN_VERSION, self.tenant_id.encode(), kind.encode(), canonical.encode())
        payload = b"".join(len(part).to_bytes(4, "big") + part for part in parts)
        digest = hmac.new(self._key, payload, hashlib.sha256).hexdigest()[:24].upper()
        prefix = _network_label(canonical) if kind == "IP" else kind
        token = f"{prefix}_{digest}"
        self._to_token[identity] = token
        self._to_original.setdefault(token, original)
        self.tokenized_count += 1
        return token

    def _maybe_internal_ip(self, match: re.Match[str]) -> str:
        value = match.group(0)
        try:
            canonical = str(ipaddress.ip_address(value))
        except ValueError:
            return value
        return self._token("IP", canonical) if _is_internal_ip(canonical) else value

    def _maybe_internal_host(self, match: re.Match[str]) -> str:
        host = match.group(0)
        canonical = host.rstrip(".").casefold()
        if any(canonical.endswith(suffix) for suffix in self.config.internal_domain_suffixes):
            return self._token("HOST", host)
        return host


def default_pseudonymizer(*, tenant_id: str, token_key: str | bytes) -> Pseudonymizer:
    return Pseudonymizer(tenant_id=tenant_id, token_key=token_key, config=RedactionConfig())
