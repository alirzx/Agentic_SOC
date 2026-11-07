"""Authenticated streaming proxy for browser-facing Agents LLM surfaces."""

from __future__ import annotations

import os
import re
from collections.abc import AsyncIterator

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from app.api.v1.deps import AuthUser
from app.services.agents_tenant_auth import AgentsTenantAuthError, signed_tenant_headers

router = APIRouter(prefix="/agent-llm", tags=["agents-llm-proxy"])

_AGENTS_URL = (
    os.getenv("AGENTS_SERVICE_URL")
    or os.getenv("AGENTS_API_URL")
    or "http://agents:8084"
).rstrip("/")
_SURFACES = frozenset({"contextual", "copilot"})
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./-]{0,256}$")


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
        raise HTTPException(status_code=503, detail="Agents tenant authentication is not configured") from exc

    suffix = f"/{path}" if path else ""
    url = f"{_AGENTS_URL}/api/v1/{surface}{suffix}"
    headers = {
        **auth_headers,
        "accept": request.headers.get("accept", "application/json"),
    }
    content_type = request.headers.get("content-type")
    if content_type:
        headers["content-type"] = content_type

    client = httpx.AsyncClient(timeout=httpx.Timeout(180.0), follow_redirects=False)
    try:
        upstream_request = client.build_request(
            request.method,
            url,
            params=list(request.query_params.multi_items()),
            headers=headers,
            content=await request.body(),
        )
        upstream = await client.send(upstream_request, stream=True)
    except httpx.HTTPError as exc:
        await client.aclose()
        raise HTTPException(status_code=503, detail="Agents service unavailable") from exc

    async def body() -> AsyncIterator[bytes]:
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    response_headers = {
        name: value
        for name, value in upstream.headers.items()
        if name.lower() in {"content-type", "cache-control"}
    }
    return StreamingResponse(
        body(),
        status_code=upstream.status_code,
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
