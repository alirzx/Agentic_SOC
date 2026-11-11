"""Authenticated streaming proxy for browser-facing Agents LLM surfaces.

When the browser runs Ambient Copilot ``Explain this alert``, the NDJSON
stream is tee'd here so the finished Markdown is persisted onto
``alerts.enrichment_data.contextual_explanation`` for Case Report and
Investigate reuse — without requiring a web rebuild.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser
from app.db.database import AsyncSessionLocal
from app.models.alert import Alert
from app.services.agents_tenant_auth import AgentsTenantAuthError, signed_tenant_headers

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent-llm", tags=["agents-llm-proxy"])

_AGENTS_URL = (
    os.getenv("AGENTS_SERVICE_URL")
    or os.getenv("AGENTS_API_URL")
    or "http://agents:8084"
).rstrip("/")
_SURFACES = frozenset({"contextual", "copilot"})
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./-]{0,256}$")


def _parse_explain_request(body: bytes) -> tuple[str | None, str | None]:
    """Return ``(action, entity_id)`` when the body is contextual explain."""
    try:
        payload = json.loads(body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, None
    if not isinstance(payload, dict):
        return None, None
    action = payload.get("action")
    entity_id = payload.get("entity_id")
    page = payload.get("page")
    if page != "alerts" or action != "explain":
        return None, None
    if not isinstance(entity_id, str) or not entity_id.strip():
        return None, None
    return "explain", entity_id.strip()


def _accumulate_stream_markdown(buffer: bytearray) -> tuple[str, str | None]:
    """Parse NDJSON frames and return ``(markdown, model)``."""
    text = buffer.decode("utf-8", errors="replace")
    markdown_parts: list[str] = []
    model: str | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            frame = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(frame, dict):
            continue
        if isinstance(frame.get("model"), str) and frame["model"].strip():
            model = frame["model"].strip()
        delta = frame.get("delta")
        if isinstance(delta, str):
            markdown_parts.append(delta)
        content = frame.get("content")
        if isinstance(content, str) and content.strip() and not markdown_parts:
            markdown_parts.append(content)
    return "".join(markdown_parts), model


async def _persist_explanation(
    *,
    tenant_id: uuid.UUID,
    entity_id: str,
    markdown: str,
    model: str | None,
) -> None:
    from app.services.alert_contextual_explanation import (
        build_explanation_record,
        merge_explanation_into_enrichment,
    )

    text = (markdown or "").strip()
    if len(text) < 40:
        return
    try:
        alert_id = uuid.UUID(entity_id)
    except ValueError:
        return
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
        )
        alert = result.scalar_one_or_none()
        if alert is None:
            return
        record = build_explanation_record(
            text, model=model, source="contextual_explain_stream"
        )
        values: dict[str, Any] = {
            "enrichment_data": merge_explanation_into_enrichment(
                alert.enrichment_data, record
            ),
        }
        if not (alert.ai_summary or "").strip() and record.get("meaning"):
            values["ai_summary"] = str(record["meaning"])[:2_000]
        await db.execute(
            update(Alert)
            .where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
            .values(**values)
        )
        await db.commit()


async def _proxy_agents_llm(
    surface: str,
    path: str,
    request: Request,
    user: AuthUser,
) -> StreamingResponse:
    if surface not in _SURFACES or not _SAFE_PATH_RE.fullmatch(path) or ".." in path.split("/"):
        raise HTTPException(status_code=404, detail="Agents LLM route not found")
    try:
        auth_headers = signed_tenant_headers(user.tenant_id)
    except AgentsTenantAuthError as exc:
        raise HTTPException(
            status_code=503, detail="Agents tenant authentication is not configured"
        ) from exc

    suffix = f"/{path}" if path else ""
    url = f"{_AGENTS_URL}/api/v1/{surface}{suffix}"
    headers = {
        **auth_headers,
        "accept": request.headers.get("accept", "application/json"),
    }
    content_type = request.headers.get("content-type")
    if content_type:
        headers["content-type"] = content_type

    raw_body = await request.body()
    persist_action, persist_entity_id = (None, None)
    if surface == "contextual" and request.method.upper() == "POST":
        persist_action, persist_entity_id = _parse_explain_request(raw_body)

    client = httpx.AsyncClient(timeout=httpx.Timeout(180.0), follow_redirects=False)
    try:
        upstream_request = client.build_request(
            request.method,
            url,
            params=list(request.query_params.multi_items()),
            headers=headers,
            content=raw_body,
        )
        upstream = await client.send(upstream_request, stream=True)
    except httpx.HTTPError as exc:
        await client.aclose()
        raise HTTPException(status_code=503, detail="Agents service unavailable") from exc

    tee = bytearray()
    should_persist = bool(persist_action == "explain" and persist_entity_id)
    tenant_id = user.tenant_id
    status_code = upstream.status_code

    async def body() -> AsyncIterator[bytes]:
        try:
            async for chunk in upstream.aiter_raw():
                if should_persist and chunk:
                    tee.extend(chunk)
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()
            if should_persist and persist_entity_id and status_code < 400:
                markdown, model = _accumulate_stream_markdown(tee)
                try:
                    await _persist_explanation(
                        tenant_id=tenant_id,
                        entity_id=persist_entity_id,
                        markdown=markdown,
                        model=model,
                    )
                except Exception:  # noqa: BLE001 — never break the stream consumer
                    logger.warning(
                        "agent_llm.persist_explain_failed entity_id=%s",
                        str(persist_entity_id).replace("\r", "").replace("\n", " ")[:64],
                        exc_info=True,
                    )

    response_headers = {
        name: value
        for name, value in upstream.headers.items()
        if name.lower() in {"content-type", "cache-control"}
    }
    return StreamingResponse(
        body(),
        status_code=status_code,
        headers=response_headers,
    )


@router.api_route("/{surface}", methods=["GET", "POST"])
async def proxy_agents_llm_root(
    surface: str,
    request: Request,
    user: AuthUser,
) -> StreamingResponse:
    return await _proxy_agents_llm(surface, "", request, user)


@router.api_route("/{surface}/{path:path}", methods=["GET", "POST"])
async def proxy_agents_llm_path(
    surface: str,
    path: str,
    request: Request,
    user: AuthUser,
) -> StreamingResponse:
    return await _proxy_agents_llm(surface, path, request, user)
