"""Tenant-scoped deterministic pseudonymization for external AI egress."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

__all__ = ["RedactionConfig", "Pseudonymizer", "default_pseudonymizer"]


class _SemanticKind(str, Enum):
    NONE = "NONE"
    IP = "IP"
    HOST = "HOST"
    USER = "USER"
    EMAIL = "EMAIL"
    ASSET = "ASSET"
    PATH = "PATH"
    SECRET = "SECRET"
    ENDPOINT = "ENDPOINT"
    REFERENCE = "REFERENCE"


_USER_FIELDS = frozenset(
    {
        "user",
        "username",
        "user_name",
        "user_id",
        "principal",
        "actor",
        "dest_owner",
        "subject",
        "account",
        "samaccountname",
        "upn",
        "sender",
        "recipient",
        "src_user",
        "source_user",
        "dest_user",
        "destination_user",
        "target_user",
        "subject_user",
        "initiating_user",
        "account_name",
        "principal_name",
    }
)
_EMAIL_FIELDS = frozenset({"email", "email_address", "user_email", "sender_email", "recipient_email"})
_IP_FIELDS = frozenset(
    {
        "src_ip",
        "source_ip",
        "source_address",
        "source_addr",
        "dst_ip",
        "dest_ip",
        "destination_ip",
        "destination_address",
        "destination_addr",
        "client_ip",
        "remote_ip",
        "local_ip",
        "ip",
        "ip_address",
    }
)
_HOST_FIELDS = frozenset(
    {
        "host",
        "host_name",
        "hostname",
        "dvc",
        "device",
        "device_name",
        "endpoint",
        "endpoint_name",
        "dest_nt_host",
        "computer",
        "computer_name",
        "machine",
        "machine_name",
    }
)
_ASSET_FIELDS = frozenset(
    {
        "asset",
        "asset_id",
        "device_id",
        "endpoint_id",
        "host_id",
        "system_id",
        "machine_id",
    }
)
_PATH_FIELDS = frozenset(
    {
        "path",
        "file_path",
        "process_path",
        "image_path",
        "executable_path",
        "home_directory",
        "working_directory",
        "current_directory",
    }
)
_ENDPOINT_FIELDS = frozenset({"src", "dst", "dest"})
_ENTITY_FIELDS = frozenset({"entity", "risk_object", "normalized_risk_object"})
_CONTEXT_PATH_KINDS: dict[str, _SemanticKind] = {
    "device.name": _SemanticKind.HOST,
    "device.hostname": _SemanticKind.HOST,
    "device.ip": _SemanticKind.IP,
    "src_endpoint.name": _SemanticKind.HOST,
    "src_endpoint.hostname": _SemanticKind.HOST,
    "src_endpoint.ip": _SemanticKind.IP,
    "source_endpoint.name": _SemanticKind.HOST,
    "source_endpoint.hostname": _SemanticKind.HOST,
    "source_endpoint.ip": _SemanticKind.IP,
    "dst_endpoint.name": _SemanticKind.HOST,
    "dst_endpoint.hostname": _SemanticKind.HOST,
    "dst_endpoint.ip": _SemanticKind.IP,
    "destination_endpoint.name": _SemanticKind.HOST,
    "destination_endpoint.hostname": _SemanticKind.HOST,
    "destination_endpoint.ip": _SemanticKind.IP,
    "user.name": _SemanticKind.USER,
    "user.email": _SemanticKind.EMAIL,
    "account.name": _SemanticKind.USER,
    "principal.name": _SemanticKind.USER,
    "actor.user.name": _SemanticKind.USER,
}
_SECRET_FIELDS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "secret",
        "api_key",
        "apikey",
        "access_key",
        "secret_access_key",
        "access_token",
        "refresh_token",
        "session_token",
        "bearer_token",
        "auth_token",
        "token",
        "authorization",
        "authorization_header",
        "auth_header",
        "cookie",
        "cookies",
        "set_cookie",
        "private_key",
        "private_key_pem",
        "client_secret",
        "credential",
        "credentials",
    }
)
_SECRET_SUFFIXES = (
    "_password",
    "_passwd",
    "_passphrase",
    "_token",
    "_secret",
    "_api_key",
    "_private_key",
    "_credential",
    "_credentials",
    "_cookie",
    "_cookies",
    "_authorization",
)

_HOST_CONTAINERS = frozenset(
    {"device", "host", "src_endpoint", "source_endpoint", "dst_endpoint", "destination_endpoint"}
)
_USER_CONTAINERS = frozenset({"user", "account", "principal"})
_ENTITY_TYPE_KINDS: dict[str, _SemanticKind] = {
    "user": _SemanticKind.USER,
    "account": _SemanticKind.USER,
    "principal": _SemanticKind.USER,
    "email": _SemanticKind.EMAIL,
    "system": _SemanticKind.HOST,
    "host": _SemanticKind.HOST,
    "device": _SemanticKind.HOST,
    "endpoint": _SemanticKind.HOST,
    "computer": _SemanticKind.HOST,
    "ip": _SemanticKind.IP,
    "ip_address": _SemanticKind.IP,
    "asset": _SemanticKind.ASSET,
}
_PLACEHOLDERS = frozenset({"unknown", "n/a", "na", "none", "null", "not available", "-"})

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+")
_UNC_PATH_RE = re.compile(r"\\\\[^\s\"']+")
_UNIX_PATH_RE = re.compile(r"(?:/[A-Za-z0-9._\-]+){2,}/?")
_DOMAIN_USER_RE = re.compile(r"\b[A-Za-z0-9.\-]+\\[A-Za-z0-9._\-]+")
_IP_RE = re.compile(r"(?<![A-Za-z0-9_:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{2,})(?![A-Za-z0-9_:])")
_FQDN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\.?\b")
_HOSTNAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?")

_CONTEXT_LABELS = tuple(
    sorted(
        _IP_FIELDS
        | _HOST_FIELDS
        | _USER_FIELDS
        | _EMAIL_FIELDS
        | _ENDPOINT_FIELDS
        | _ENTITY_FIELDS
        | frozenset(_CONTEXT_PATH_KINDS)
        | {"destination"},
        key=len,
        reverse=True,
    )
)
_CONTEXT_LABEL_PATTERN = "|".join(re.escape(label) for label in _CONTEXT_LABELS)
_QUOTED_CONTEXT_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9_])(?P<label>{_CONTEXT_LABEL_PATTERN})(?![A-Za-z0-9_])"
    r"\s*(?P<sep>[:=])\s*(?P<quote>[\"'])(?P<value>.*?)(?P=quote)"
)
_UNQUOTED_CONTEXT_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9_])(?P<label>{_CONTEXT_LABEL_PATTERN})(?![A-Za-z0-9_])"
    r"\s*(?P<sep>[:=])\s*(?P<value>[^\s,;|\"']+)"
)
_BARE_HOST_CONTEXT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?P<label>hostname|host|endpoint|device|computer|dest|destination)"
    r"(?![A-Za-z0-9_])\s+(?P<value>(?:[A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}\.?)"
)
_SECRET_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.DOTALL),
    re.compile(r"(?i)\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+[^\s,;]+"),
    re.compile(
        r"(?i)\b(?:password|passwd|passphrase|secret|key|api[_-]?key|access[_-]?token|refresh[_-]?token|"
        r"session[_-]?token|bearer[_-]?token|client[_-]?secret|credential|cookie)\s*[:=]\s*[^\s,;]+"
    ),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
)

_DEFAULT_INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".intranet", ".home.arpa")
_TOKEN_VERSION = b"aisoc-privacy-v1"
_MAX_DEPTH = 24
_KIND_PRIORITY = ("IP", "IP_OPAQUE", "HOST", "EMAIL", "USER", "ASSET", "PATH")


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
    if kind in {"IP_OPAQUE", "EMAIL", "USER", "ASSET"}:
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


def _is_placeholder(value: str) -> bool:
    return value.strip().casefold() in _PLACEHOLDERS


def _is_secret_field(field: str) -> bool:
    return field in _SECRET_FIELDS or field.endswith(_SECRET_SUFFIXES)


def _field_semantic(path: tuple[str, ...], siblings: Mapping[str, Any] | None) -> _SemanticKind:
    if not path:
        return _SemanticKind.NONE
    leaf = _normalise_key(path[-1])
    parents = tuple(_normalise_key(part) for part in path[:-1])
    parent = parents[-1] if parents else ""

    if _is_secret_field(leaf):
        return _SemanticKind.SECRET
    if leaf in _IP_FIELDS:
        return _SemanticKind.IP
    if leaf in _EMAIL_FIELDS:
        return _SemanticKind.EMAIL
    if leaf in _ASSET_FIELDS:
        return _SemanticKind.ASSET
    if leaf in _HOST_FIELDS:
        return _SemanticKind.HOST
    if leaf in _USER_FIELDS:
        return _SemanticKind.USER
    if leaf in _PATH_FIELDS:
        return _SemanticKind.PATH
    if leaf in _ENDPOINT_FIELDS:
        return _SemanticKind.ENDPOINT

    if leaf in _ENTITY_FIELDS:
        normalised_siblings = {_normalise_key(str(k)): v for k, v in (siblings or {}).items()}
        type_value = normalised_siblings.get("risk_object_type") if leaf != "entity" else None
        type_value = type_value or normalised_siblings.get("entity_type")
        if isinstance(type_value, str):
            semantic = _ENTITY_TYPE_KINDS.get(_normalise_key(type_value))
            if semantic is not None:
                return semantic
        return _SemanticKind.REFERENCE

    if leaf in {"ip", "ip_address"} and parent in _HOST_CONTAINERS:
        return _SemanticKind.IP
    if leaf in {"name", "hostname"} and parent in _HOST_CONTAINERS:
        return _SemanticKind.HOST
    if leaf == "email" and parent in _USER_CONTAINERS:
        return _SemanticKind.EMAIL
    if leaf == "name" and parent in _USER_CONTAINERS:
        return _SemanticKind.USER
    if leaf == "name" and len(parents) >= 2 and parents[-2:] == ("actor", "user"):
        return _SemanticKind.USER
    return _SemanticKind.NONE


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
        self._token_variants: dict[str, set[str]] = {}
        self.tokenized_count = 0
        self.masked_secret_count = 0

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self._to_original)

    def redact(self, text: str) -> str:
        if not isinstance(text, str) or not text:
            return text if isinstance(text, str) else ""
        self._discover_text(text)
        out = self._replace_registered(text)
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
        if self.config.redact_internal_hostnames:
            out = _FQDN_RE.sub(self._maybe_internal_host, out)
        if self.config.redact_internal_ips:
            out = _IP_RE.sub(self._maybe_internal_ip, out)
        return self._replace_registered(out)

    def redact_value(self, value: Any, *, _key: str | None = None) -> Any:
        root_path = ((_key,) if _key else ())
        self.discover_value(value, _key=_key)
        return self._project_value(value, path=root_path, depth=0, seen=set(), siblings=None)

    def discover_value(self, value: Any, *, _key: str | None = None) -> None:
        """Register identities across a complete value tree without projecting it."""
        root_path = ((_key,) if _key else ())
        self._discover_structured(value, path=root_path, depth=0, seen=set(), dynamic=False, siblings=None)
        self._discover_structured(value, path=root_path, depth=0, seen=set(), dynamic=True, siblings=None)
        self._discover_text_values(value, depth=0, seen=set())

    def rehydrate(self, value: Any) -> Any:
        """Exact, mapping-only restoration; unknown tokens remain unchanged."""
        return self._rehydrate(value, depth=0, seen=set())

    def _discover_structured(
        self,
        value: Any,
        *,
        path: tuple[str, ...],
        depth: int,
        seen: set[int],
        dynamic: bool,
        siblings: Mapping[str, Any] | None,
    ) -> None:
        if depth > _MAX_DEPTH:
            raise ValueError("privacy projection exceeded maximum nesting depth")
        if isinstance(value, str):
            semantic = _field_semantic(path, siblings)
            if _is_placeholder(value) or not value.strip():
                return
            if dynamic and semantic == _SemanticKind.ENDPOINT:
                self._token_for_endpoint(value)
            elif not dynamic and semantic not in {
                _SemanticKind.NONE,
                _SemanticKind.SECRET,
                _SemanticKind.ENDPOINT,
                _SemanticKind.REFERENCE,
            }:
                self._token_for_semantic(semantic, value)
            return
        if isinstance(value, Mapping):
            marker = id(value)
            if marker in seen:
                raise ValueError("privacy projection does not accept recursive mappings")
            seen.add(marker)
            try:
                for key, child in value.items():
                    self._discover_structured(
                        child,
                        path=(*path, str(key)),
                        depth=depth + 1,
                        seen=seen,
                        dynamic=dynamic,
                        siblings=value,
                    )
            finally:
                seen.remove(marker)
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            marker = id(value)
            if marker in seen:
                raise ValueError("privacy projection does not accept recursive sequences")
            seen.add(marker)
            try:
                for child in value:
                    self._discover_structured(
                        child,
                        path=path,
                        depth=depth + 1,
                        seen=seen,
                        dynamic=dynamic,
                        siblings=siblings,
                    )
            finally:
                seen.remove(marker)

    def _discover_text_values(self, value: Any, *, depth: int, seen: set[int]) -> None:
        if depth > _MAX_DEPTH:
            raise ValueError("privacy projection exceeded maximum nesting depth")
        if isinstance(value, str):
            self._discover_text(value)
            return
        if isinstance(value, Mapping):
            marker = id(value)
            if marker in seen:
                raise ValueError("privacy projection does not accept recursive mappings")
            seen.add(marker)
            try:
                for child in value.values():
                    self._discover_text_values(child, depth=depth + 1, seen=seen)
            finally:
                seen.remove(marker)
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            marker = id(value)
            if marker in seen:
                raise ValueError("privacy projection does not accept recursive sequences")
            seen.add(marker)
            try:
                for child in value:
                    self._discover_text_values(child, depth=depth + 1, seen=seen)
            finally:
                seen.remove(marker)

    def _project_value(
        self,
        value: Any,
        *,
        path: tuple[str, ...],
        depth: int,
        seen: set[int],
        siblings: Mapping[str, Any] | None,
    ) -> Any:
        if depth > _MAX_DEPTH:
            raise ValueError("privacy projection exceeded maximum nesting depth")
        if isinstance(value, str):
            semantic = _field_semantic(path, siblings)
            if semantic == _SemanticKind.SECRET and self.config.redact_secrets:
                self.masked_secret_count += 1
                return "[REDACTED_SECRET]"
            if not value or _is_placeholder(value):
                return value
            if semantic == _SemanticKind.ENDPOINT:
                return self._token_for_endpoint(value)
            if semantic == _SemanticKind.REFERENCE:
                return self._known_token(value) or self.redact(value)
            if semantic != _SemanticKind.NONE:
                return self._token_for_semantic(semantic, value)
            return self.redact(value)
        if isinstance(value, Mapping):
            marker = id(value)
            if marker in seen:
                raise ValueError("privacy projection does not accept recursive mappings")
            seen.add(marker)
            try:
                return {
                    key: self._project_value(
                        child,
                        path=(*path, str(key)),
                        depth=depth + 1,
                        seen=seen,
                        siblings=value,
                    )
                    for key, child in value.items()
                }
            finally:
                seen.remove(marker)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            marker = id(value)
            if marker in seen:
                raise ValueError("privacy projection does not accept recursive sequences")
            seen.add(marker)
            try:
                return [
                    self._project_value(child, path=path, depth=depth + 1, seen=seen, siblings=siblings)
                    for child in value
                ]
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
                return {key: self._rehydrate(child, depth=depth + 1, seen=seen) for key, child in value.items()}
            finally:
                seen.remove(marker)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            marker = id(value)
            if marker in seen:
                raise ValueError("privacy rehydration does not accept recursive sequences")
            seen.add(marker)
            try:
                return [self._rehydrate(child, depth=depth + 1, seen=seen) for child in value]
            finally:
                seen.remove(marker)
        return value

    def _mask_match(self, _match: re.Match[str]) -> str:
        self.masked_secret_count += 1
        return "[REDACTED_SECRET]"

    def _token_for_semantic(self, semantic: _SemanticKind, original: str) -> str:
        if semantic == _SemanticKind.IP:
            try:
                ipaddress.ip_address(original.strip())
            except ValueError:
                return self._token("IP_OPAQUE", original)
            return self._token("IP", original)
        if semantic == _SemanticKind.USER and _EMAIL_RE.fullmatch(original.strip()):
            return self._token("EMAIL", original)
        return self._token(semantic.value, original)

    def _token_for_endpoint(self, original: str) -> str:
        known = self._known_token(original, kinds=("IP", "IP_OPAQUE", "HOST", "ASSET"))
        if known:
            return known
        try:
            ipaddress.ip_address(original.strip())
        except ValueError:
            if _FQDN_RE.fullmatch(original.strip()) or _HOSTNAME_RE.fullmatch(original.strip()):
                return self._token("HOST", original)
            return self._token("ASSET", original)
        return self._token("IP", original)

    def _token(self, kind: str, original: str) -> str:
        try:
            canonical = _canonical(kind, original)
        except ValueError:
            return original
        identity = (kind, canonical)
        existing = self._to_token.get(identity)
        if existing:
            self._token_variants.setdefault(existing, set()).add(original.strip())
            return existing
        parts = (_TOKEN_VERSION, self.tenant_id.encode(), kind.encode(), canonical.encode())
        payload = b"".join(len(part).to_bytes(4, "big") + part for part in parts)
        digest = hmac.new(self._key, payload, hashlib.sha256).hexdigest()[:24].upper()
        prefix = _network_label(canonical) if kind == "IP" else kind
        token = f"{prefix}_{digest}"
        self._to_token[identity] = token
        self._to_original.setdefault(token, original)
        self._token_variants[token] = {original.strip(), canonical}
        self.tokenized_count += 1
        return token

    def _known_token(self, original: str, *, kinds: tuple[str, ...] = _KIND_PRIORITY) -> str | None:
        for kind in kinds:
            try:
                canonical = _canonical(kind, original)
            except ValueError:
                continue
            token = self._to_token.get((kind, canonical))
            if token:
                self._token_variants.setdefault(token, set()).add(original.strip())
                return token
        return None

    def _replace_registered(self, text: str) -> str:
        out = text
        priority = {kind: index for index, kind in enumerate(_KIND_PRIORITY)}
        replacements: list[tuple[int, str, str, bool]] = []
        for (kind, _canonical_value), token in self._to_token.items():
            case_insensitive = kind in {"IP_OPAQUE", "HOST", "EMAIL", "USER", "ASSET"}
            for original in self._token_variants.get(token, ()):
                if original:
                    replacements.append((priority.get(kind, len(priority)), original, token, case_insensitive))
        replacements.sort(key=lambda item: (-len(item[1]), item[0], item[1].casefold()))
        for _rank, original, token, case_insensitive in replacements:
            flags = re.IGNORECASE if case_insensitive else 0
            out = re.sub(
                rf"(?<![A-Za-z0-9_]){re.escape(original)}(?![A-Za-z0-9_])",
                lambda _match, replacement=token: replacement,
                out,
                flags=flags,
            )
        return out

    def _discover_text(self, text: str) -> None:
        for pattern in (_QUOTED_CONTEXT_RE, _UNQUOTED_CONTEXT_RE, _BARE_HOST_CONTEXT_RE):
            for match in pattern.finditer(text):
                self._context_token(match.group("label"), match.group("value"))

    def _context_token(self, label: str, value: str) -> str | None:
        if not value.strip() or _is_placeholder(value):
            return None
        dotted_label = label.strip().casefold().replace("-", "_")
        path_semantic = _CONTEXT_PATH_KINDS.get(dotted_label)
        if path_semantic is not None:
            return self._token_for_semantic(path_semantic, value)
        field = _normalise_key(label)
        if field in _IP_FIELDS:
            return self._token_for_semantic(_SemanticKind.IP, value)
        if field in _EMAIL_FIELDS:
            return self._token("EMAIL", value) if _EMAIL_RE.fullmatch(value.strip()) else self._token("USER", value)
        if field in _USER_FIELDS:
            return self._token("EMAIL", value) if _EMAIL_RE.fullmatch(value.strip()) else self._token("USER", value)
        if field in _HOST_FIELDS:
            return self._token("HOST", value)
        if field in _ENDPOINT_FIELDS or field == "destination":
            return self._token_for_endpoint(value)
        if field in _ENTITY_FIELDS:
            known = self._known_token(value)
            if known:
                return known
            if _EMAIL_RE.fullmatch(value.strip()):
                return self._token("EMAIL", value)
            try:
                ipaddress.ip_address(value.strip())
            except ValueError:
                if _FQDN_RE.fullmatch(value.strip()) or _HOSTNAME_RE.fullmatch(value.strip()):
                    return self._token("HOST", value)
                return self._token("ASSET", value)
            return self._token("IP", value)
        return None

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
