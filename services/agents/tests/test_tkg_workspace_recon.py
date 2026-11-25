"""Exercise the real registry, HTTP framing, privacy boundary and historical loop with synthetic peers."""

import hashlib
import hmac
import json
from uuid import UUID
from contextlib import asynccontextmanager
from dataclasses import replace

import httpx
import pytest
from langchain_core.messages import AIMessage
from pydantic import ValidationError

from app.integrations.tkg import recon
from app.integrations.tkg.binding import Binding
from app.integrations.tkg.tools import Limits, SCHEMAS, SearchCandidate, Session, active
from app.investigator.state import InvestigatorState
from app.privacy.context import privacy_context
from app.runtime.catalog import build_tool_registry
from app.runtime.tools import ToolContext, ToolPermissionDenied


def uid(n):
    return UUID(int=n)


@pytest.mark.asyncio
async def test_deep_case_retains_objectives_and_reserves_twelfth_model_call(binding):
    b = binding
    other = replace(b, id=uid(23), connector_id=uid(24), kb_id=uid(25))
    limits = Limits(profile="deep_case", loop_enabled=True, preflight_enabled=False)
    session = Session(Live(), None, b.tenant_id, uid(6), b.connector_id, [b, other], limits,
                      seeds={"seed-1": (uid(6), b.connector_id), "seed-2": (uid(16), other.connector_id)})
    state = InvestigatorState(tenant_id=str(b.tenant_id), case_id="synthetic", alert_summary="Synthetic case")
    turns = 0

    async def lookup(binding, name, args):
        if name == "resolve_entity":
            assert binding.connector_id == session.seeds[args.get("seed_id", "seed-1")][1]
            return {"status": "resolved", "candidates": [{"entity_id": str(binding.connector_id)}]}
        assert name == "get_timeline" and args["entity"] == str(other.connector_id)
        return {"facts": [{"id": str(uid(40 + turns))}]}

    async def plan(*_):
        nonlocal turns
        turns += 1
        if turns <= 2:
            name, args = "resolve_entity", {"seed_id": f"seed-{turns}"}
        else:
            assert session.objectives["coverage"]["last_outcome"] in {"resolved", "ok"}
            assert len(session.examined) == 2
            name = "get_timeline"
            args = {"entity": str(other.connector_id), "limit": turns}
        return json.dumps({"action": "call_tool", "tool": name, "arguments": args,
                           "objective_id": "coverage", "evidence_gap": "Check the second source"})

    async def assess(state):
        assert state.recon.history["llm_calls"] == 12
        assert state.recon.history["stop_reason"] == "iteration_budget"
        assert state.recon.history["coverage"]["resolved_seeds"] == 2
        return {"summary": "Synthetic final assessment"}

    session.lookup = lookup
    result = await recon.reason(state, session, build_tool_registry(), assess, planner=plan)
    assert turns == 11 and result["summary"] == "Synthetic final assessment"


@pytest.mark.asyncio
async def test_search_pivot_requires_exact_fact_and_chunk_from_current_root(binding):
    b = binding
    session = Session(Live(), None, b.tenant_id, uid(6), b.connector_id, [b], Limits())
    root, peer, fact, doc, chunk = (uid(n) for n in range(70, 75))
    session.remember(b, str(root), 0)
    session.candidates["candidate-1"] = SearchCandidate(b.id, doc, chunk)
    context = {"requested_entity": str(root), "retrieval_status": "complete",
               "facts": [{"id": str(fact), "other_id": str(peer)}],
               "evidence_references": [{"fact_id": str(fact), "source": {"document_id": str(doc), "chunk_id": str(uid(80))}}]}
    session.evidence.append({"binding_id": str(b.id), "tool": "tkg.get_entity_context", "status": "complete",
                             "current_context": True, "data": context})
    assert session.verify_candidate(b, "candidate-1")["status"] == "candidate_unverified"
    context["evidence_references"][0]["source"]["chunk_id"] = str(chunk)
    context["facts"][0]["contested"] = True
    assert session.verify_candidate(b, "candidate-1")["status"] == "candidate_unverified"
    context["facts"][0]["contested"] = False
    assert session.verify_candidate(replace(b, id=uid(99)), "candidate-1")["status"] == "candidate_unverified"
    assert (await session.execute("resolve_entity", {"candidate_id": "candidate-1"}))[0]["status"] == "resolved"
    assert session.depth[b.id, str(peer)] == 1


class Live:
    enabled = True

    @asynccontextmanager
    async def acquire(self):
        yield self

    transaction = acquire

    async def execute(self, *_):
        return None

    async def fetchval(self, query, workspace, binding):
        return self.enabled and (workspace, binding) == (uid(1), uid(2))


@pytest.fixture
def binding(tmp_path, monkeypatch):
    b = Binding(uid(2), uid(1), "fixture", uid(3), uid(4), "blue", "splunk", "index-a", uid(5))
    monkeypatch.setenv("AISOC_TKG_ORIGIN_FIXTURE", "https://fixture.invalid")
    monkeypatch.setenv("AISOC_TKG_SECRET_DIR", str(tmp_path))
    path = tmp_path / "reader" / str(b.tenant_id) / str(b.id)
    path.parent.mkdir(parents=True)
    path.write_text("fixture-pat")
    return b


@pytest.mark.asyncio
async def test_historical_loop_and_dlp(binding, privacy_enabled, monkeypatch):
    b = binding
    root, peer, fact = map(str, (uid(7), uid(8), uid(9)))
    private = "endpoint01.corp.synthetic.test"
    events = []

    def serve(req):
        assert req.headers["Authorization"] == "Bearer fixture-pat"
        path = req.url.path
        assert path.startswith(f"/api/v1/kbs/{b.kb_id}/")
        body = json.loads(req.content)
        if path.endswith("/resolve"):
            assert body == dict(
                tenant_id="blue",
                source_system="splunk",
                source_instance="index-a",
                entity_type="SecurityAlert",
                authority_name="soc_alert_row_id",
                source_identifier=str(uid(6)),
            )
            events.append("resolve")
            doc = dict(
                schema_version="soorin.identity-resolution.v1",
                knowledge_base_id=str(b.kb_id),
                tenant_id="blue",
                automatic=True,
                status="resolved",
                candidates=[dict(entity_id=root, has_conflict=False)],
            )
        elif path.endswith("/context"):
            events.append("context")
            assert body["entity"] == root
            doc = dict(
                schema_version="soorin.knowledge-context.v2",
                knowledge_base_id=str(b.kb_id),
                tenant_id="blue",
                retrieval_status="partial",
                requested_entity=root,
                facts=[dict(id=fact, subject=private, other_type="Host", other_name=private)],
                limitations=["fixture"],
            )
        elif path.endswith("/search"):
            events.append("search")
            assert body["q"] == "10.8.9.10" and body["top_k"] <= 3
            doc = dict(results=[], retrieval=dict(dense_executed=False, lexical_method="fallback", reranker_status="unavailable"))
        else:
            method = body["method"]
            if method == "initialize":
                events.append(method)
                result = {"protocolVersion": "2025-06-18"}
            elif method == "tools/list":
                events.append(method)
                result = {"tools": [{"name": "neighbors"}, {"name": "timeline"}]}
            else:
                assert method == "tools/call"
                name = body["params"]["name"]
                events.append(name)
                args = body["params"]["arguments"]
                assert args["entity"] == (root if name == "neighbors" else peer)
                result = dict(
                    isError=False,
                    content=[dict(type="text", text="Original MCP text")],
                    structuredContent=dict(
                        schema_version="soorin.graph-evidence.v1",
                        tool=name,
                        kb_id=str(b.kb_id),
                        entity_id=args["entity"],
                        truncated=True,
                        facts=[dict(id=fact, other_id=peer, direction="out", document_ids=[str(uid(10))])],
                    ),
                )
            doc = {"jsonrpc": "2.0", "id": body["id"], "result": result}
        return httpx.Response(200, json=doc)

    class Planner:
        model = "test"

        async def ainvoke(self, messages, **kwargs):
            events.append("assessment")
            provider = messages[-1].content
            assert private not in provider and "HOST_" in provider
            assert "10.8.9.10" not in provider and "IP_V4_PRIVATE_" in provider
            assert "analyst-fixture-17" not in provider and "USER_" in provider
            if peer in provider:
                name, entity = "get_timeline", peer
            else:
                assert root in provider
                name, entity = "get_neighbors", root
            return AIMessage(content=json.dumps({"action": "call_tool", "tool": name, "arguments": {"entity": entity}}))

    monkeypatch.setattr(recon, "make_chat_model", lambda *a, **k: Planner())
    monkeypatch.setenv("AISOC_LLM_PRIVACY_REQUIRED", "1")

    async def final(state):
        events.append("final")
        assert recon.history_prompt(state)
        return {"summary": "Synthetic investigation"}

    async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as client:
        limits = Limits(loop_enabled=True, max_iterations=2, max_llm_calls=3, max_results=3)
        session = Session(Live(), client, b.tenant_id, uid(6), b.connector_id, [b], limits)
        state = InvestigatorState(tenant_id=str(b.tenant_id), case_id="synthetic", alert_summary="10.8.9.10 user=analyst-fixture-17")
        with privacy_context(str(b.tenant_id)):
            await recon.reason(state, session, build_tool_registry(), final)
    assert events == [
        "resolve",
        "context",
        "search",
        "assessment",
        "initialize",
        "tools/list",
        "neighbors",
        "assessment",
        "timeline",
        "final",
    ]
    history = state.recon.history
    assert history["citations"] == [f"{b.kb_id}/{fact}"]
    assert (history["tool_calls"], history["tool_requests"], history["llm_calls"]) == (5, 7, 3)
    assert history["evidence"][-1]["data"]["truncated"]


@pytest.mark.asyncio
async def test_registry_denies_foreign_scope_override_and_cycles(binding):
    b = binding
    registry = build_tool_registry()
    session = Session(Live(), None, b.tenant_id, uid(6), b.connector_id, [b], Limits(max_hops=1))
    token = active.set(session)
    try:
        foreign = ToolContext(tenant_id=str(uid(11)), incident_id="fixture", agent_name="ReconAgent")
        with pytest.raises(ToolPermissionDenied):
            await registry.execute("tkg.resolve_entity", {}, foreign)
        local = foreign.model_copy(update={"tenant_id": str(b.tenant_id)})
        for name in SCHEMAS:
            with pytest.raises(ValidationError):
                await registry.execute("tkg." + name, {"kb_id": str(uid(100))}, local)
        for field in ("workspace", "tenant_id", "source_id", "base_url"):
            with pytest.raises(ValidationError):
                await registry.execute("tkg.resolve_entity", {field: "override"}, local)
        session.remember(b, str(uid(8)), 1)
        for _ in range(2):
            r = await registry.execute("tkg.get_neighbors", {"entity": str(uid(8))}, local)
            assert r[0]["status"] == "visited_or_depth_limit"
        session.pool.enabled = False
        assert (await registry.execute("tkg.resolve_entity", {}, local))[0]["status"] == "binding_disabled"
        assert not session.depth.get((b.id, str(uid(77))))
    finally:
        active.reset(token)


def test_grant_authenticates_durable_alert_and_explicit_workspace(monkeypatch):
    key = "synthetic-grant-key-for-tests-only"
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", key)
    sig = hmac.new(key.encode(), f"tkg-read-v1/{uid(1)}/{uid(6)}".encode(), hashlib.sha256).hexdigest()
    assert recon.verify_grant(sig, str(uid(1)), str(uid(6))) == (uid(1), uid(6))
    for tenant, alert in [(uid(2), uid(6)), (uid(1), uid(9)), ("default", uid(6))]:
        assert recon.verify_grant(sig, str(tenant), str(alert)) is None


@pytest.mark.asyncio
async def test_discarded_result_never_authorizes_graph_pivot(binding):
    b = binding
    entity = str(uid(51))

    def reply(_):
        return httpx.Response(
            200,
            json={
                "schema_version": "soorin.identity-resolution.v1",
                "knowledge_base_id": str(b.kb_id),
                "tenant_id": b.tkg_tenant,
                "status": "resolved",
                "automatic": True,
                "candidates": [{"entity_id": entity, "has_conflict": False, "padding": "x" * 2048}],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
        session = Session(Live(), client, b.tenant_id, uid(6), b.connector_id, [b], Limits(context_bytes=1024, max_tool_calls=2))
        assert (await session.execute("resolve_entity", {}))[0]["status"] == "context_truncated"
        assert (await session.execute("get_neighbors", {"entity": entity}))[0]["status"] == "unverified_entity"
        assert (await session.execute("resolve_entity", {}))[0]["status"] == "call_budget"
        assert session.requests == 1
        assert session.depth == {}


@pytest.mark.asyncio
async def test_mcp_setup_obeys_independent_transport_budget(binding):
    b = binding
    entity = str(uid(51))

    def reply(request):
        rpc = json.loads(request.content)
        assert rpc["method"] == "initialize"
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": rpc["id"], "result": {"protocolVersion": "2025-06-18"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
        session = Session(Live(), client, b.tenant_id, uid(6), b.connector_id, [b], Limits(max_transport_requests=1))
        session.remember(b, entity, 0)
        assert (await session.execute("get_timeline", {"entity": entity, "limit": 1}))[0]["status"] == "transport_budget"
        assert session.calls == session.requests == 1
