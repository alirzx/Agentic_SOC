"""Async client for the Soorin TKG HTTP API.

Only read paths the evaluation needs are wrapped: readiness (graph overview),
identity resolution for a notable, and the entity context bundle. Writes stay in
the standalone ``scripts/agentic_soc`` sender — this module never ingests.

Every failure is a :class:`TkgError` with a stable ``code`` so callers can put it
in ``reason_codes`` instead of leaking an httpx exception into the API surface.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.services.tkg.binding import Binding
from app.services.tkg_evaluation.constants import (
    DEFAULT_TIMEOUT_S,
    R_TKG_AUTH,
    R_TKG_KB_MISSING,
    R_TKG_UNREACHABLE,
)

logger = logging.getLogger(__name__)

#: ``/kbs/{kb_id}/...`` — the only place a wrong ``AISOC_TKG_KB_ID`` shows up.
_KB_PREFIX = "/kbs/"
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _kb_segment(path: str) -> str:
    """The kb id inside ``/kbs/{id}/...`` (empty when the path is not KB-scoped)."""

    marker = path.find(_KB_PREFIX)
    if marker < 0:
        return ""
    return path[marker + len(_KB_PREFIX) :].split("/", 1)[0]


def _failure_code(status: int, *, path: str) -> str:
    """Map an HTTP failure to the reason code the panel shows.

    ``tkg_kb_missing`` is a *configuration* answer from a graph that did reply:
    the KB id is wrong (404 on a KB-scoped path) or not even a UUID, which the
    router rejects with 400/422 before the handler runs. Everything that means
    "no answer at all" — timeout, connection error, 5xx, rejected credentials —
    stays ``tkg_unreachable``, so an operator can tell a typo in
    ``AISOC_TKG_KB_ID`` from an outage.

    The source-token route is excluded on purpose: its 404 means the source
    exists without a push token, not that the KB is missing.
    """

    kb_id = _kb_segment(path)
    if not kb_id or "/sources/" in path:
        return R_TKG_UNREACHABLE
    if status == 404:
        return R_TKG_KB_MISSING
    if status in {400, 422} and not _UUID_RE.match(kb_id):
        return R_TKG_KB_MISSING
    return R_TKG_UNREACHABLE


class TkgError(RuntimeError):
    """A TKG call failed. ``code`` is the reason code persisted with the run."""

    def __init__(self, code: str, detail: str = "", *, status: int | None = None) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.status = status


@dataclass(frozen=True)
class TkgConfig:
    """Connection settings, resolved from ``Settings`` by :func:`config_from_settings`."""

    base_url: str
    email: str
    password: str
    kb_id: str
    tenant_id: str = "tenant-blue"
    source_system: str = "splunk"
    source_instance: str = "splunk-e2e"
    timeout_s: float = DEFAULT_TIMEOUT_S
    #: Statements source used by the manual send path (read paths ignore it).
    source_name: str = "agentic-soc-manual-20261116"
    #: Operator opt-in for the write path; read-only evaluation ignores it.
    allow_send: bool = False
    #: Optional static bearer (e.g. a console session token). When set, login is skipped.
    bearer_token: str = field(default="", repr=False)
    binding: Binding | None = None

    @property
    def configured(self) -> bool:
        has_login = bool(self.email and self.password)
        has_token = bool(self.bearer_token)
        return bool(self.base_url and self.kb_id and (has_login or has_token))


def config_from_settings(settings: Any | None = None) -> TkgConfig:
    """Build a :class:`TkgConfig` from the process settings (never logs values)."""

    if settings is None:  # pragma: no cover - imported lazily to avoid cycles
        from app.core.config import settings as _settings

        settings = _settings
    return TkgConfig(
        base_url=(getattr(settings, "AISOC_TKG_URL", "") or "").rstrip("/"),
        email=(getattr(settings, "AISOC_TKG_EMAIL", "") or "").strip(),
        password=getattr(settings, "AISOC_TKG_PASSWORD", "") or "",
        kb_id=(getattr(settings, "AISOC_TKG_KB_ID", "") or "").strip(),
        tenant_id=(getattr(settings, "AISOC_TKG_TENANT", "") or "tenant-blue").strip(),
        source_system=(getattr(settings, "AISOC_TKG_SOURCE_SYSTEM", "") or "splunk").strip(),
        source_instance=(getattr(settings, "AISOC_TKG_SOURCE_INSTANCE", "") or "splunk-e2e").strip(),
        timeout_s=float(getattr(settings, "AISOC_TKG_TIMEOUT_S", DEFAULT_TIMEOUT_S) or DEFAULT_TIMEOUT_S),
        source_name=(getattr(settings, "AISOC_TKG_SOURCE_NAME", "") or "agentic-soc-manual-20261116").strip(),
        allow_send=bool(getattr(settings, "AISOC_TKG_ALLOW_SEND", False)),
        bearer_token=(getattr(settings, "AISOC_TKG_TOKEN", "") or "").strip(),
    )


class TkgClient:
    """Thin async wrapper over ``/api/v1`` with a cached bearer token."""

    def __init__(
        self,
        cfg: TkgConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.cfg = cfg
        self._token: str | None = None
        self._token_at = 0.0
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url,
            timeout=cfg.timeout_s,
            trust_env=False,
            transport=transport,
            headers={"Accept": "application/json"},
        )

    # ------------------------------------------------------------------ lifecycle
    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> TkgClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------------ plumbing
    async def _login(self) -> str:
        """Log in, retrying transport failures.

        The graph runs its own ingestion and answers slowly while it is busy; one
        timed-out login used to fail a whole evaluation and replace the panel with
        an error, which reads as "the integration is broken" rather than "the
        graph was busy for a second".
        """

        if self.cfg.bearer_token:
            self._token = self.cfg.bearer_token
            self._token_at = time.monotonic()
            return self._token
        if not (self.cfg.base_url and self.cfg.email and self.cfg.password):
            raise TkgError(R_TKG_UNREACHABLE, "TKG credentials are not configured")
        response: httpx.Response | None = None
        last: Exception | None = None
        for attempt, delay in enumerate((0.0, 0.4, 1.2)):
            if delay:
                await asyncio.sleep(delay)
            try:
                response = await self._client.post(
                    "/api/v1/auth/login",
                    json={"email": self.cfg.email, "password": self.cfg.password},
                )
                break
            except httpx.TimeoutException as exc:  # pragma: no cover - network
                last = exc
            except httpx.HTTPError as exc:
                last = exc
            if attempt == 2:
                kind = "timed out" if isinstance(last, httpx.TimeoutException) else f"failed: {last}"
                raise TkgError(R_TKG_UNREACHABLE, f"login {kind} after 3 attempts") from last
        if response is None:  # pragma: no cover - defensive
            raise TkgError(R_TKG_UNREACHABLE, "login failed")
        if response.status_code >= 400:
            raise TkgError(R_TKG_AUTH, "TKG rejected the credentials", status=response.status_code)
        token = (response.json() or {}).get("token")
        if not token:
            raise TkgError(R_TKG_AUTH, "login response had no token")
        self._token = str(token)
        self._token_at = time.monotonic()
        return self._token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        retry_auth: bool = True,
    ) -> Any:
        if self.cfg.binding is not None:
            from app.db.database import AsyncSessionLocal
            from sqlalchemy import text

            async with AsyncSessionLocal() as db:
                active = await db.scalar(text("SELECT enabled FROM workspace_tkg_bindings WHERE id=:id AND tenant_id=:tenant AND evaluation"),
                                         {"id": self.cfg.binding.id, "tenant":self.cfg.binding.tenant_id})
            if not active:
                raise TkgError(R_TKG_AUTH, "binding unavailable")
        token = self._token or await self._login()
        try:
            response = await self._client.request(method, path, json=json, headers={"Authorization": f"Bearer {token}"})
        except httpx.TimeoutException as exc:
            raise TkgError(R_TKG_UNREACHABLE, f"{method} {path} timed out") from exc
        except httpx.HTTPError as exc:
            raise TkgError(R_TKG_UNREACHABLE, f"{method} {path} failed: {exc}") from exc

        if response.status_code == 401 and retry_auth and not self.cfg.bearer_token:
            self._token = None
            return await self._request(method, path, json=json, retry_auth=False)
        if response.status_code >= 400:
            code = _failure_code(response.status_code, path=path)
            detail = f"{method} {path} -> HTTP {response.status_code}"
            if code == R_TKG_KB_MISSING:
                detail = f"knowledge base {self.cfg.kb_id} was not found on the TKG"
            raise TkgError(code, detail, status=response.status_code)
        if not response.content.strip():
            return {}
        try:
            return response.json()
        except ValueError:
            return {}

    # ------------------------------------------------------------------ read paths
    async def graph_overview(self) -> dict[str, Any]:
        return await self._request("GET", f"/api/v1/kbs/{self.cfg.kb_id}/graph/overview?limit=1")

    async def resolve(self, notable_id: str) -> dict[str, Any]:
        """Resolve a Splunk notable to its TKG entity (identity layer)."""

        body = {
            "tenant_id": self.cfg.tenant_id,
            "source_system": self.cfg.source_system,
            "source_instance": self.cfg.source_instance,
            "entity_type": "SecurityAlert" if self.cfg.binding else "SplunkNotable",
            "authority_name": "soc_alert_row_id" if self.cfg.binding else "splunk_notable_id",
            "source_identifier": str(notable_id),
        }
        return await self._request("POST", f"/api/v1/kbs/{self.cfg.kb_id}/knowledge/resolve", json=body)

    async def receipts(self) -> dict[str, Any]:
        """The KB's newest 100 ingestion receipts (status + ``failure_code``).

        This is the only read that says *why* a record never appeared: a
        ``submitted`` receipt with ``failure_code='soc_document_failed'`` means
        the extractor gave up (typically an LLM 429 after its own retries), and
        no amount of re-probing ``knowledge/resolve`` will change that.
        """

        return await self._request("GET", f"/api/v1/kbs/{self.cfg.kb_id}/knowledge/receipts")

    async def context(self, entity_id: str, *, limit: int = 40) -> dict[str, Any]:
        # ``tenant_id`` is mandatory on this route (422 without it) even though the
        # KB id already scopes the request.
        body = {
            "tenant_id": self.cfg.tenant_id,
            "entity": str(entity_id),
            "limit": int(limit),
        }
        return await self._request("POST", f"/api/v1/kbs/{self.cfg.kb_id}/knowledge/context", json=body)

    # ------------------------------------------------------------------ write path
    #
    # Only the manual "send missing alerts" action uses these. The evaluation
    # never calls them; the endpoint is gated by AISOC_TKG_ALLOW_SEND and an
    # explicit confirmation in the UI.
    async def ensure_source(self) -> tuple[str, str]:
        """Return ``(source_id, ingest_token)`` for the statements source.

        Reuses the source by name when it exists (the ingest token lives under
        the KB path; ``/sources/{id}/token`` is a 404), otherwise creates one.
        """

        listing = await self._request("GET", f"/api/v1/kbs/{self.cfg.kb_id}/sources")
        for source in listing.get("sources") or []:
            if not isinstance(source, dict):
                continue
            if source.get("kind") != "statements" or source.get("name") != self.cfg.source_name:
                continue
            source_id = str(source.get("id") or "")
            if not source_id:
                continue
            token_data = await self._request("GET", f"/api/v1/kbs/{self.cfg.kb_id}/sources/{source_id}/token")
            token = token_data.get("ingest_token")
            if isinstance(token, str) and token:
                return source_id, token
            raise TkgError(
                R_TKG_UNREACHABLE,
                f"source {source_id} exists but has no push token (rotate it in the TKG console)",
            )

        created = await self._request(
            "POST",
            f"/api/v1/kbs/{self.cfg.kb_id}/sources",
            json={
                "kind": "statements",
                "name": self.cfg.source_name,
                "config": {"note": "manual AiSOC case sync; receipts carry the audit"},
            },
        )
        source = created.get("source") or {}
        source_id = str(source.get("id") or "")
        token = created.get("ingest_token")
        if not source_id or not isinstance(token, str) or not token:
            raise TkgError(R_TKG_UNREACHABLE, "source creation returned no id/token")
        return source_id, token

    async def ingest(self, source_id: str, ingest_token: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST one curated record. The ingest token, not the session, authenticates."""

        if not self.cfg.allow_send:
            raise TkgError("tkg_send_disabled", "AISOC_TKG_ALLOW_SEND is false")
        try:
            response = await self._client.post(
                f"/api/v1/sources/{source_id}/soc/ingest",
                json=body,
                headers={"Authorization": f"Bearer {ingest_token}"},
            )
        except httpx.TimeoutException as exc:
            raise TkgError(R_TKG_UNREACHABLE, "ingest timed out") from exc
        except httpx.HTTPError as exc:
            raise TkgError(R_TKG_UNREACHABLE, f"ingest failed: {exc}") from exc

        if response.status_code == 422:
            code = "normalization_failed"
            try:
                payload = response.json() or {}
                code = str(payload.get("error_code") or payload.get("code") or code)
            except ValueError:
                pass
            raise TkgError(code, response.text[:300], status=422)
        if response.status_code >= 400:
            raise TkgError(
                R_TKG_UNREACHABLE,
                f"ingest -> HTTP {response.status_code}: {response.text[:200]}",
                status=response.status_code,
            )
        return response.json() or {}

    # ------------------------------------------------------------------ composite
    async def readiness(self, *, sample_notable: str | None = None) -> dict[str, Any]:
        """Cheap capability probe: is the KB reachable and its graph populated?

        A healthy KB with an empty graph is *ready* but useless for a verdict;
        the check reports the counts so the UI can say which it is.
        """

        checks: list[dict[str, Any]] = []
        counts: dict[str, Any] = {}
        try:
            overview = await self.graph_overview()
        except TkgError as exc:
            checks.append({"id": "graph", "ok": False, "detail": exc.detail or exc.code})
            # The code, not just a failed check, is what the run persists: a 404
            # or a malformed kb id is ``tkg_kb_missing`` (fix the setting), a
            # timeout/5xx/login rejection stays ``tkg_unreachable``.
            return {
                "ready": False,
                "checks": checks,
                "counts": counts,
                "error": exc.code,
                "kb_id": self.cfg.kb_id,
            }

        counts = {
            "nodes": overview.get("total_nodes"),
            "edges": overview.get("total_edges"),
        }
        nodes = int(overview.get("total_nodes") or 0)
        checks.append(
            {
                "id": "graph",
                "ok": nodes > 0,
                "detail": f"{nodes} entities / {overview.get('total_edges')} facts",
            }
        )

        if sample_notable:
            try:
                resolved = await asyncio.wait_for(self.resolve(sample_notable), timeout=self.cfg.timeout_s)
                status = str(resolved.get("status") or "unknown")
                candidates = resolved.get("candidates") or []
                checks.append(
                    {
                        "id": "resolve",
                        "ok": status in {"resolved", "pending_materialization"},
                        "detail": f"{status} / {len(candidates)} candidate(s)",
                    }
                )
            except (TimeoutError, TkgError) as exc:
                code = getattr(exc, "code", "timeout")
                checks.append({"id": "resolve", "ok": False, "detail": str(code)})

        return {
            "ready": all(check["ok"] for check in checks),
            "checks": checks,
            "counts": counts,
            "kb_id": self.cfg.kb_id,
        }
