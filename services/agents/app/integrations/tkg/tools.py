"""Read-only tools for one authenticated investigation. Authority is held outside model state."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from contextvars import ContextVar
from datetime import date, datetime
from typing import Annotated
from uuid import UUID

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.runtime.tools import SOCTool, ToolContext, ToolPermissionDenied

from .binding import BindingError

logger = structlog.get_logger()

Short = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
Limit = Annotated[int, Field(ge=1, le=20)]
Moment = date | datetime


class Limits(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AISOC_TKG_RECON_", extra="ignore")
    enabled: bool = False
    preflight_enabled: bool = True
    loop_enabled: bool = False
    max_iterations: int = Field(2, ge=1, le=5)
    max_llm_calls: int = Field(3, ge=1, le=6)
    max_output_tokens: int = Field(640, ge=128, le=1500)
    max_cost_usd: float = Field(0.05, gt=0, le=1)
    max_tool_calls: int = Field(8, ge=1, le=24)
    max_transport_requests: int = Field(16, ge=1, le=48)
    timeout_seconds: float = Field(45, ge=1, le=180)
    tool_timeout_seconds: float = Field(4, gt=0, le=20)
    max_hops: int = Field(2, ge=1, le=4)
    max_entities: int = Field(12, ge=1, le=64)
    max_results: int = Field(3, ge=1, le=10)
    context_bytes: int = Field(24000, ge=1024, le=100000)
    max_bindings: int = Field(4, ge=1, le=12)


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Resolve(Args):
    """Resolve the authenticated investigation's durable alert."""


class Context(Args):
    entity: UUID
    at: Moment | None = None
    as_of: Moment | None = None
    limit: Limit = 5


class Search(Args):
    q: Short
    top_k: Limit = 3
    as_of: Moment | None = None


class Timeline(Args):
    entity: UUID
    since: date | None = None
    until: date | None = None
    as_of: Moment | None = None
    predicate: Short | None = None
    limit: Limit = 5


class Neighbors(Context):
    predicate: Short | None = None
    object_type: Short | None = None


SCHEMAS = {
    "resolve_entity": Resolve,
    "get_entity_context": Context,
    "search_history": Search,
    "get_timeline": Timeline,
    "get_neighbors": Neighbors,
}
active = ContextVar("tkg_recon_session", default=None)
grant = ContextVar("tkg_verified_alert_scope", default=None)


class ReadTool(SOCTool):
    risk_level = "read"
    requires_approval = False
    allowed_agents = frozenset({"ReconAgent"})
    allowed_roles = frozenset({"analyst", "system"})
    permission = "READ_SECURITY_DATA"
    timeout_seconds = 5
    audit_required = True

    def __init__(self, name):
        self.short = name
        self.name = "tkg." + name
        self.description = "Read workspace-authorized TKG evidence: " + name
        self.input_schema = SCHEMAS[name].model_json_schema()

    async def execute(self, input, context: ToolContext):
        session = active.get()
        if not session or str(session.workspace) != context.tenant_id:
            raise ToolPermissionDenied("tkg_workspace_unavailable")
        args = SCHEMAS[self.short].model_validate(input).model_dump(mode="json", exclude_none=True)
        return await session.execute(self.short, args)


def register(registry):
    for name in SCHEMAS:
        registry.register(ReadTool(name))


class ReadError(ValueError):
    pass


class Session:
    def __init__(self, pool, http, workspace, alert_id, connector, bindings, limits):
        self.pool, self.http = pool, http
        self.workspace, self.alert_id, self.connector = workspace, alert_id, connector
        self.bindings, self.limits = bindings, limits
        self.calls = self.requests = self.used_bytes = 0
        self.depth = {}
        self.seen = set()
        self.rpc_ready = set()
        self.evidence = []

    async def post(self, b, path, body):
        if self.requests >= self.limits.max_transport_requests:
            raise ReadError("transport_budget")
        async with self.pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(self.workspace))
            live = await conn.fetchval(
                "SELECT enabled FROM workspace_tkg_bindings WHERE tenant_id=$1 AND id=$2",
                self.workspace,
                b.id,
            )
        if not live:
            raise ReadError("binding_disabled")
        self.requests += 1
        async with self.http.stream(
            "POST", f"{b.origin()}/api/v1/kbs/{b.kb_id}/{path}", json=body, headers={"Authorization": "Bearer " + b.credential("reader")}
        ) as r:
            if r.status_code != 200:
                raise ReadError(f"http_{r.status_code}")
            buf = bytearray()
            async for part in r.aiter_bytes():
                buf.extend(part)
                if len(buf) > 131072:
                    raise ReadError("response_truncated")
            doc = json.loads(buf)
            if not isinstance(doc, dict):
                raise ReadError("invalid_response")
            return doc

    async def rpc(self, b, method, params):
        body = {"jsonrpc": "2.0", "id": self.requests + 1, "method": method, "params": params}
        reply = await self.post(b, "mcp", body)
        if reply.get("jsonrpc") != "2.0" or reply.get("id") != body["id"] or not isinstance(reply.get("result"), dict):
            raise ReadError("mcp_error")
        return reply["result"]

    def remember(self, b, entity, depth):
        try:
            key = (b.id, str(UUID(str(entity))))
        except ValueError:
            return
        if key in self.depth or len(self.depth) < self.limits.max_entities:
            self.depth[key] = min(depth, self.depth.get(key, depth))

    async def lookup(self, b, name, args):
        if name == "resolve_entity":
            body = dict(
                tenant_id=b.tkg_tenant,
                source_system=b.source_system,
                source_instance=b.source_instance,
                entity_type="SecurityAlert",
                authority_name="soc_alert_row_id",
                source_identifier=str(self.alert_id),
            )
            doc = await self.post(b, "knowledge/resolve", body)
            if (
                doc.get("schema_version") != "soorin.identity-resolution.v1"
                or doc.get("knowledge_base_id") != str(b.kb_id)
                or doc.get("tenant_id") != b.tkg_tenant
            ):
                raise ReadError("invalid_scope_or_version")
            candidates = doc.get("candidates")
            if not isinstance(candidates, list) or any(not isinstance(row, dict) for row in candidates):
                raise ReadError("invalid_resolution_candidates")
            if doc.get("status") == "resolved":
                entry = candidates[0] if len(candidates) == 1 else {}
                if (
                    doc.get("automatic") is not True
                    or entry.get("has_conflict") is not False
                    or entry.get("graph_conflict")
                    or entry.get("candidates_truncated")
                    or not entry.get("entity_id")
                ):
                    raise ReadError("ambiguous_resolution")
                UUID(entry["entity_id"])
            return doc
        if name == "search_history":
            data = await self.post(b, "search", {**args, "top_k": min(args["top_k"], self.limits.max_results)})
            results = data.get("results")
            if not isinstance(results, list) or any(not isinstance(row, dict) for row in results):
                raise ReadError("invalid_search_response")
            return {
                **data,
                "status": "candidates" if results else "empty",
                "results": results[: min(args["top_k"], self.limits.max_results)],
            }
        if name == "get_entity_context":
            doc = await self.post(b, "knowledge/context", {"tenant_id": b.tkg_tenant, **args})
            if (
                doc.get("schema_version") != "soorin.knowledge-context.v2"
                or doc.get("tenant_id") != b.tkg_tenant
                or doc.get("knowledge_base_id") != str(b.kb_id)
                or doc.get("requested_entity") != args["entity"]
            ):
                raise ReadError("invalid_scope_or_version")
            facts = doc.get("facts")
            if not isinstance(facts, list) or len(facts) > args["limit"]:
                raise ReadError("invalid_context_facts")
            for fact in facts:
                UUID(fact["id"])
            return doc
        tool = {"get_timeline": "timeline", "get_neighbors": "neighbors"}[name]
        if b.id not in self.rpc_ready:
            hello = await self.rpc(
                b,
                "initialize",
                {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "aisoc-recon", "version": "1"}},
            )
            listed = await self.rpc(b, "tools/list", {})
            names = {t["name"] for t in listed.get("tools", []) if isinstance(t, dict)}
            if hello.get("protocolVersion") != "2025-06-18" or not {"neighbors", "timeline"} <= names or "remember" in names:
                raise ReadError("invalid_read_pat_capabilities")
            self.rpc_ready.add(b.id)
        result = await self.rpc(b, "tools/call", {"name": tool, "arguments": args})
        if result.get("isError"):
            raise ReadError("mcp_tool_failed")
        doc = result.get("structuredContent")
        if not isinstance(doc, dict):
            raise ReadError("structured_evidence_unavailable")
        if doc.get("schema_version") != "soorin.graph-evidence.v1" or doc.get("tool") != tool:
            raise ReadError("structured_evidence_version")
        if not isinstance(doc.get("truncated"), bool) or not isinstance(doc.get("facts"), list) or len(doc["facts"]) > args["limit"]:
            raise ReadError("invalid_graph_evidence")
        for fact in doc["facts"]:
            try:
                UUID(str(fact["id"]))
            except (ValueError, KeyError, TypeError):
                raise ReadError("invalid_graph_fact") from None
        if doc.get("kb_id") != str(b.kb_id) or doc.get("entity_id") != args["entity"]:
            raise ReadError("mcp_scope_mismatch")
        return doc

    async def execute(self, name, args):
        if self.calls >= self.limits.max_tool_calls:
            return [{"tool": "tkg." + name, "status": "call_budget"}]
        self.calls += 1
        results = []
        for b in self.bindings:
            entity = args.get("entity")
            if name == "resolve_entity" and (b.connector_id != self.connector or b.source_system != "splunk"):
                continue
            if entity and (b.id, entity) not in self.depth:
                continue
            key = (b.id, name, entity if name == "get_neighbors" else json.dumps(args, sort_keys=True))
            item = {
                "binding_id": str(b.id),
                "kb_id": str(b.kb_id),
                "source_id": str(b.source_id),
                "source_system": b.source_system,
                "source_instance": b.source_instance,
                "tool": "tkg." + name,
            }
            started = time.monotonic()
            try:
                if key in self.seen or (name == "get_neighbors" and self.depth[b.id, entity] >= self.limits.max_hops):
                    raise ReadError("visited_or_depth_limit")
                self.seen.add(key)
                async with asyncio.timeout(self.limits.tool_timeout_seconds):
                    doc = await self.lookup(b, name, args)
                data = json.dumps(doc, sort_keys=True).encode()
                if self.used_bytes + len(data) > self.limits.context_bytes:
                    raise ReadError("context_truncated")
                self.used_bytes += len(data)
                # Only observations retained under the context budget can authorize a pivot.
                if name == "resolve_entity" and doc.get("status") == "resolved":
                    self.remember(b, doc["candidates"][0]["entity_id"], 0)
                elif name == "get_neighbors":
                    for fact in doc["facts"]:
                        self.remember(b, fact.get("other_id"), self.depth[b.id, entity] + 1)

                item.update(
                    status=doc.get("status")
                    or doc.get("retrieval_status")
                    or ("empty" if name in {"get_neighbors", "get_timeline"} and not doc["facts"] else "ok"),
                    sha256=hashlib.sha256(data).hexdigest(),
                    data=doc,
                )
            except (ReadError, BindingError) as exc:
                item["status"] = str(exc)
            except (TimeoutError, httpx.TransportError):
                item["status"] = "unavailable"
            except (ValueError, TypeError, AttributeError, KeyError):
                item["status"] = "invalid_response"
            logger.info(
                "tkg_read",
                workspace_id=str(self.workspace),
                binding_id=str(b.id),
                tool=name,
                status=item["status"],
                elapsed_ms=round((time.monotonic() - started) * 1000),
            )
            results.append(item)
        if not results:
            results.append({"tool": "tkg." + name, "status": "unverified_entity" if args.get("entity") else "no_source_binding"})
        self.evidence.extend(results)
        return results
