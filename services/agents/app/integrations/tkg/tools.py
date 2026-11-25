"""Read-only tools for one authenticated investigation. Authority is held outside model state."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Annotated, Literal, TypedDict
from uuid import UUID

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.runtime.tools import SOCTool, ToolContext, ToolPermissionDenied

from .binding import BindingError
from .budget import ModelBudget

logger = structlog.get_logger()

Short = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
Limit = Annotated[int, Field(ge=1, le=20)]
Moment = date | datetime


class Limits(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AISOC_TKG_RECON_", extra="ignore", env_ignore_empty=True)
    enabled: bool = False
    preflight_enabled: bool = True
    preflight_seeds: int = Field(2, ge=0, le=3)
    loop_enabled: bool = False
    profile: Literal["standard", "deep_case"] = "standard"
    max_iterations: int = Field(8, ge=1, le=20)
    max_llm_calls: int = Field(9, ge=1, le=21)
    max_output_tokens: int = Field(2048, ge=128, le=4096)
    max_planner_output_tokens: int = Field(512, ge=128, le=1024)
    max_assessment_output_tokens: int | None = Field(None, ge=128, le=4096)
    max_model_tokens: int = Field(100000, ge=4096, le=500000)
    max_cost_usd: float = Field(0.05, gt=0, le=1)
    unknown_input_usd_per_1k: float | None = Field(None, gt=0, le=1)
    unknown_output_usd_per_1k: float | None = Field(None, gt=0, le=1)
    max_tool_calls: int = Field(12, ge=1, le=25)
    max_transport_requests: int = Field(32, ge=1, le=80)
    timeout_seconds: float = Field(120, ge=1, le=360)
    tool_timeout_seconds: float = Field(15, gt=0, le=60)
    resolve_timeout_seconds: float = Field(10, gt=0, le=60)
    mcp_setup_timeout_seconds: float = Field(10, gt=0, le=60)
    search_timeout_seconds: float = Field(30, gt=0, le=90)
    planner_timeout_seconds: float = Field(60, ge=1, le=120)
    assessment_timeout_seconds: float = Field(30, ge=1, le=120)
    max_hops: int = Field(3, ge=1, le=5)
    max_entities: int = Field(32, ge=1, le=100)
    max_results: int = Field(5, ge=1, le=10)
    context_bytes: int = Field(131072, ge=1024, le=524288)
    history_context_tokens: int = Field(8000, ge=512, le=24000)
    semantic_excerpt_chars: int = Field(360, ge=64, le=1000)
    max_case_seeds: int = Field(5, ge=1, le=12)
    max_bindings: int = Field(8, ge=1, le=16)

    @model_validator(mode="before")
    @classmethod
    def profile_defaults(cls, values):
        if values.get("profile") == "deep_case":
            values = {
                "max_iterations": 11, "max_llm_calls": 12, "max_tool_calls": 15,
                "max_transport_requests": 48, "max_planner_output_tokens": 768,
                "max_output_tokens": 3072, "max_hops": 4, "max_entities": 64,
                "max_results": 8, "timeout_seconds": 240, "context_bytes": 262144,
                "max_case_seeds": 10, "history_context_tokens": 16000,
                "tool_timeout_seconds": 20, "search_timeout_seconds": 45,
                "resolve_timeout_seconds": 15, "mcp_setup_timeout_seconds": 15,
                **values,
            }
        return values

    @property
    def assessment_tokens(self):
        return self.max_assessment_output_tokens or self.max_output_tokens

    def tool_deadline(self, name):
        return {"resolve_entity": self.resolve_timeout_seconds, "search_history": self.search_timeout_seconds}.get(
            name, self.tool_timeout_seconds,
        )


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Resolve(Args):
    """Resolve a server-authorized root, defaulting to the primary alert."""

    seed_id: Annotated[str, StringConstraints(pattern=r"^seed-[1-9][0-9]?$")] | None = None
    candidate_id: Annotated[str, StringConstraints(pattern=r"^candidate-[1-9][0-9]{0,3}$")] | None = None

    @model_validator(mode="after")
    def single_target(self):
        if self.seed_id and self.candidate_id:
            raise ValueError("choose one resolve target")
        return self


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
case_grant = ContextVar("tkg_verified_case_scope", default=None)


class ReadTool(SOCTool):
    risk_level = "read"
    requires_approval = False
    allowed_agents = frozenset({"ReconAgent"})
    allowed_roles = frozenset({"analyst", "system"})
    permission = "READ_SECURITY_DATA"
    audit_required = True

    def __init__(self, name):
        self.short = name
        self.name = "tkg." + name
        self.description = {
            "resolve_entity": "Verify an issued alert seed or documented candidate before traversing the graph.",
            "get_entity_context": "Read facts and evidence references for a verified entity at a selected time.",
            "search_history": "Find semantic document and chunk candidates with retrieval status.",
            "get_timeline": "Order dated facts for an established entity using a bounded window.",
            "get_neighbors": "Explore one authorized relationship hop with optional predicate and entity-type filters.",
        }[name]
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
    def __init__(self, code, *, retryable=False):
        super().__init__(code)
        self.retryable = retryable


@dataclass(frozen=True)
class SearchCandidate:
    binding_id: UUID
    document_id: UUID
    chunk_id: UUID


class Objective(TypedDict):
    evidence_gap: str
    expected_observation: str
    hypothesis: str
    question_status: Literal["open", "resolved"]
    last_outcome: str


@dataclass
class ReconInvestigationMemory:
    objectives: dict[str, Objective] = field(default_factory=dict)
    examined: set[str] = field(default_factory=set)
    candidates: dict[str, SearchCandidate] = field(default_factory=dict)
    depth: dict[tuple[UUID, str], int] = field(default_factory=dict)
    completed_queries: set[tuple[UUID, str, str]] = field(default_factory=set)
    retryable_queries: set[tuple[UUID, str, str]] = field(default_factory=set)
    evidence: list[dict] = field(default_factory=list)
    stop_reason: str = "initializing"


class Session:
    def __init__(self, pool, http, workspace, alert_id, connector, bindings, limits, *, seeds=None, case_total=None,
                 case_eligible=None, seed_metadata=None, omitted_bindings=0, investigation_id=None):
        self.pool, self.http = pool, http
        self.workspace, self.alert_id, self.connector = workspace, alert_id, connector
        self.bindings, self.limits = bindings, limits
        self.seeds = seeds if seeds is not None else {"seed-1": (alert_id, connector)}
        self.case_total = case_total
        self.case_eligible = case_eligible if case_eligible is not None else len(self.seeds)
        self.seed_metadata = seed_metadata or {}
        self.omitted_bindings = omitted_bindings
        self.investigation_id = investigation_id
        self.memory = ReconInvestigationMemory()
        self.examined = self.memory.examined
        self.candidates = self.memory.candidates
        self.objectives = self.memory.objectives
        self.model_budget = ModelBudget(limits)
        self.calls = self.requests = self.used_bytes = 0
        self.depth = self.memory.depth
        self.seen = self.memory.completed_queries
        self.evidence = self.memory.evidence
        self.rpc_ready = set()

    async def require_enabled(self, b):
        async with self.pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(self.workspace))
            live = await conn.fetchval(
                "SELECT enabled FROM workspace_tkg_bindings WHERE tenant_id=$1 AND id=$2",
                self.workspace,
                b.id,
            )
        if not live:
            raise ReadError("binding_disabled")

    async def post(self, b, path, body):
        if self.requests >= self.limits.max_transport_requests:
            raise ReadError("transport_budget")
        await self.require_enabled(b)
        self.requests += 1
        async with self.http.stream(
            "POST", f"{b.origin()}/api/v1/kbs/{b.kb_id}/{path}", json=body, headers={"Authorization": "Bearer " + b.credential("reader")}
        ) as r:
            if r.status_code != 200:
                raise ReadError(f"http_{r.status_code}", retryable=r.status_code in {408, 425, 429, 500, 502, 503, 504})
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
            if "candidate_id" in args:
                await self.require_enabled(b)
                return self.verify_candidate(b, args["candidate_id"])
            body = dict(
                tenant_id=b.tkg_tenant,
                source_system=b.source_system,
                source_instance=b.source_instance,
                entity_type="SecurityAlert",
                authority_name="soc_alert_row_id",
                source_identifier=str(self.seeds[args.get("seed_id", "seed-1")][0]),
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
            if doc.get("status") not in ("resolved", "ambiguous", "pending_materialization", "unavailable", "not_found"):
                raise ReadError("invalid_resolution_status")
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
            # TKG's public ChunkView serializes the chunk UUID as "id".
            # Normalize it for the internal candidate/evidence contract. Accept
            # the legacy alias, but never allow two conflicting identities.
            normalized = []
            for row in results[: min(args["top_k"], self.limits.max_results)]:
                try:
                    chunk = UUID(str(row["id"] if "id" in row else row["chunk_id"]))
                    if "chunk_id" in row and UUID(str(row["chunk_id"])) != chunk:
                        raise ValueError("conflicting chunk identities")
                    document = UUID(str(row["document_id"]))
                except (KeyError, ValueError, TypeError):
                    raise ReadError("invalid_search_response") from None
                normalized.append({**row, "id": str(chunk), "chunk_id": str(chunk), "document_id": str(document)})
            return {
                **data,
                "status": "candidates" if normalized else "empty",
                "results": normalized,
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
            if doc.get("retrieval_status") not in ("complete", "partial", "unavailable"):
                raise ReadError("invalid_context_status")
            if not isinstance(facts, list) or len(facts) > args["limit"]:
                raise ReadError("invalid_context_facts")
            for fact in facts:
                UUID(fact["id"])
            return doc
        tool = {"get_timeline": "timeline", "get_neighbors": "neighbors"}[name]
        if b.id not in self.rpc_ready:
            async with asyncio.timeout(self.limits.mcp_setup_timeout_seconds):
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

    def verify_candidate(self, binding, candidate_id):
        candidate = self.candidates[candidate_id]
        targets = set()
        for item in self.evidence:
            if item.get("binding_id") != str(binding.id) or not item.get("current_context"):
                continue
            doc = item.get("data") or {}
            root = doc.get("requested_entity")
            if self.depth.get((binding.id, root)) != 0 or doc.get("knowledge_time") is not None:
                continue
            if doc.get("retrieval_status") != "complete" or doc.get("conflicts") or (doc.get("bounds") or {}).get("truncated"):
                continue
            for ref in doc.get("evidence_references", []):
                source = ref.get("source", {})
                if source.get("document_id") != str(candidate.document_id) or source.get("chunk_id") != str(candidate.chunk_id):
                    continue
                if source.get("stale") or source.get("document_deleted"):
                    continue
                for fact in doc.get("facts", []):
                    if fact.get("id") == ref.get("fact_id") and fact.get("other_id") and not any(
                        fact.get(flag) for flag in ("inferred", "contested", "stale", "invalidated_at", "valid_to")
                    ):
                        since = fact.get("valid_from")
                        if since and date.fromisoformat(since[:10]) > datetime.now(UTC).date():
                            continue
                        targets.add(str(UUID(fact["other_id"])))
        remaining = targets if len(targets) == 1 else set()
        return {
            "status": "resolved" if remaining else "candidate_unverified",
            "candidate_id": candidate_id,
            "candidates": [{"entity_id": target, "has_conflict": False} for target in remaining],
        }

    async def execute(self, name, args):
        if self.calls >= self.limits.max_tool_calls:
            return [{"tool": "tkg." + name, "status": "call_budget"}]
        self.calls += 1
        deadline = time.monotonic() + self.limits.tool_deadline(name)
        results = []
        seed_id = args.get("seed_id", "seed-1")
        candidate_id = args.get("candidate_id") if name == "resolve_entity" else None
        candidate = self.candidates.get(candidate_id)
        seed = self.seeds.get(seed_id) if name == "resolve_entity" and not candidate_id else None
        if name == "resolve_entity" and seed is None and candidate is None:
            return [{"tool": "tkg.resolve_entity", "status": "unauthorized_seed"}]
        for b in self.bindings:
            entity = args.get("entity")
            if candidate is not None and candidate.binding_id != b.id:
                continue
            if seed is not None and (b.connector_id != seed[1] or b.source_system != "splunk"):
                continue
            if entity and (b.id, entity) not in self.depth:
                continue
            canonical = args.copy()
            for field_name in ("at", "as_of"):
                value = canonical.get(field_name)
                if value and "T" in value:
                    instant = datetime.fromisoformat(value)
                    if instant.tzinfo:
                        canonical[field_name] = instant.astimezone(UTC).isoformat()
            key = (b.id, name, seed_id if seed is not None else json.dumps(canonical, sort_keys=True))
            if seed is not None:
                self.examined.add(seed_id)
            item = {
                "binding_id": str(b.id),
                "kb_id": str(b.kb_id),
                "source_id": str(b.source_id),
                "source_system": b.source_system,
                "source_instance": b.source_instance,
                "tool": "tkg." + name,
            }
            if seed is not None:
                item["seed_id"] = seed_id
            if name == "get_entity_context" and "at" not in args and "as_of" not in args:
                item["current_context"] = True
            started = time.monotonic()
            try:
                if key in self.seen or (name == "get_neighbors" and self.depth[b.id, entity] >= self.limits.max_hops):
                    raise ReadError("visited_or_depth_limit")
                self.seen.add(key)
                async with asyncio.timeout(max(0, deadline - time.monotonic())):
                    doc = await self.lookup(b, name, args)
                discovered = {}
                if name == "search_history" and args.get("as_of") is None:
                    for result in doc["results"]:
                        try:
                            ref = SearchCandidate(b.id, UUID(result["document_id"]), UUID(result["chunk_id"]))
                        except (ValueError, TypeError, KeyError, AttributeError):
                            continue
                        handle = f"candidate-{len(self.candidates) + len(discovered) + 1}"
                        result["candidate_id"] = handle
                        discovered[handle] = ref
                data = json.dumps(doc, sort_keys=True).encode()
                if self.used_bytes + len(data) > self.limits.context_bytes:
                    raise ReadError("context_truncated")
                self.used_bytes += len(data)
                self.candidates.update(discovered)
                # Only observations retained under the context budget can authorize a pivot.
                if name == "resolve_entity" and doc.get("status") == "resolved":
                    self.remember(b, doc["candidates"][0]["entity_id"], 1 if candidate else 0)
                elif name == "get_neighbors":
                    for fact in doc["facts"]:
                        self.remember(b, fact.get("other_id"), self.depth[b.id, entity] + 1)

                if name in {"get_neighbors", "get_timeline"}:
                    outcome = "ok" if doc["facts"] else "empty"
                elif name == "get_entity_context":
                    outcome = doc["retrieval_status"]
                else:
                    outcome = doc.get("status", "ok")
                item.update(
                    status=outcome,
                    sha256=hashlib.sha256(data).hexdigest(),
                    data=doc,
                )
            except ReadError as exc:
                item["status"] = str(exc)
                if exc.retryable and key not in self.memory.retryable_queries:
                    self.memory.retryable_queries.add(key)
                    self.seen.discard(key)
            except BindingError:
                item["status"] = "binding_credential_unavailable"
            except (TimeoutError, httpx.TransportError):
                item["status"] = "unavailable"
                if key not in self.memory.retryable_queries:
                    self.memory.retryable_queries.add(key)
                    self.seen.discard(key)
            except (ValueError, TypeError, AttributeError, KeyError):
                item["status"] = "invalid_response"
            item["duration_ms"] = round((time.monotonic() - started) * 1000)
            logger.info(
                "tkg_read",
                workspace_id=str(self.workspace),
                investigation_id=self.investigation_id,
                binding_id=str(b.id),
                tool=name,
                status=item["status"],
                elapsed_ms=item["duration_ms"],
            )
            results.append(item)
        if not results:
            results.append({"tool": "tkg." + name, "status": "unverified_entity" if args.get("entity") else "no_source_binding"})
        self.evidence.extend(results)
        return results
