"""Exercise the real registry, HTTP framing, privacy boundary and historical loop with synthetic peers."""
import hashlib
import hmac
import json
from uuid import UUID

import httpx
import pytest
from langchain_core.messages import AIMessage
from pydantic import ValidationError

from app.integrations.tkg import recon
from app.integrations.tkg.binding import Binding
from app.integrations.tkg.tools import Limits, SCHEMAS, Session, active
from app.investigator.state import InvestigatorState
from app.privacy.context import privacy_context
from app.runtime.catalog import build_tool_registry
from app.runtime.tools import ToolContext, ToolPermissionDenied


def uid(n):
    return UUID(int=n)


class Live:
    enabled=True

    async def fetchval(self,query,workspace,binding):
        return self.enabled and (workspace,binding)==(uid(1),uid(2))


@pytest.fixture
def binding(tmp_path,monkeypatch):
    b=Binding(uid(2),uid(1),"fixture",uid(3),uid(4),"blue","splunk","index-a",uid(5))
    monkeypatch.setenv("AISOC_TKG_ORIGIN_FIXTURE","https://fixture.invalid")
    monkeypatch.setenv("AISOC_TKG_SECRET_DIR",str(tmp_path))
    path=tmp_path/"reader"/str(b.tenant_id)/str(b.id)
    path.parent.mkdir(parents=True)
    path.write_text("fixture-pat")
    return b


@pytest.mark.asyncio
async def test_historical_loop_and_dlp(binding,privacy_enabled,monkeypatch):
    b=binding
    root,peer,fact=map(str,(uid(7),uid(8),uid(9)))
    private="endpoint01.corp.synthetic.test"
    events=[]
    def serve(req):
        assert req.headers["Authorization"]=="Bearer fixture-pat"
        path=req.url.path
        assert path.startswith(f"/api/v1/kbs/{b.kb_id}/")
        body=json.loads(req.content)
        if path.endswith("/resolve"):
            assert body==dict(tenant_id="blue",source_system="splunk",source_instance="index-a",
                              entity_type="SecurityAlert",authority_name="soc_alert_row_id",source_identifier=str(uid(6)))
            events.append("resolve")
            doc=dict(schema_version="soorin.identity-resolution.v1",knowledge_base_id=str(b.kb_id),
                     tenant_id="blue",automatic=True,status="resolved",candidates=[dict(entity_id=root,has_conflict=False)])
        elif path.endswith("/context"):
            events.append("context")
            assert body["entity"]==root
            doc=dict(schema_version="soorin.knowledge-context.v2",knowledge_base_id=str(b.kb_id),tenant_id="blue",
                     retrieval_status="partial",facts=[dict(id=fact,subject=private,other_type="Host",other_name=private)],limitations=["fixture"])
        elif path.endswith("/search"):
            events.append("search")
            assert body["q"]=="10.8.9.10" and body["top_k"]<=3
            doc=dict(results=[],retrieval=dict(dense_executed=False,lexical_method="fallback",reranker_status="unavailable"))
        else:
            method=body["method"]
            if method=="initialize":
                events.append(method)
                result={"protocolVersion":"2025-06-18"}
            elif method=="tools/list":
                events.append(method)
                result={"tools":[{"name":"neighbors"},{"name":"timeline"}]}
            else:
                assert method=="tools/call"
                name=body["params"]["name"]
                events.append(name)
                args=body["params"]["arguments"]
                assert args["entity"]==(root if name=="neighbors" else peer)
                result=dict(isError=False,content=[dict(type="text",text="Original MCP text")],
                            structuredContent=dict(kb_id=str(b.kb_id),entity_id=args["entity"],truncated=True,
                                facts=[dict(id=fact,other_id=peer,direction="out",document_ids=[str(uid(10))])]))
            doc={"jsonrpc":"2.0","id":body["id"],"result":result}
        return httpx.Response(200,json=doc)

    class Planner:
        model="test"
        async def ainvoke(self,messages,**kwargs):
            events.append("assessment")
            provider=messages[-1].content
            assert private not in provider and "HOST_" in provider
            name,entity = ("get_neighbors",root) if events.count("assessment")==1 else ("get_timeline",peer)
            return AIMessage(content=json.dumps({"tool":name,"arguments":{"entity":entity}}))
    monkeypatch.setattr(recon,"make_chat_model",lambda *a,**k:Planner())
    monkeypatch.setenv("AISOC_LLM_PRIVACY_REQUIRED","1")
    async def final(state):
        events.append("final")
        assert recon.history_prompt(state)
        return {"summary":"Synthetic investigation"}
    async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as client:
        session=Session(Live(),client,b.tenant_id,uid(6),b.connector_id,[b],Limits(loop_enabled=True))
        state=InvestigatorState(tenant_id=str(b.tenant_id),case_id="synthetic",alert_summary="10.8.9.10")
        with privacy_context(str(b.tenant_id)):
            await recon.reason(state,session,build_tool_registry(),final)
    assert events==["resolve","context","search","assessment","initialize","tools/list","neighbors","assessment","timeline","final"]
    history=state.recon.history
    assert history["citations"]==[f"{b.kb_id}/{fact}"]
    assert (history["tool_requests"],history["llm_calls"])==(7,3)
    assert history["evidence"][-1]["data"]["truncated"]


@pytest.mark.asyncio
async def test_registry_denies_foreign_scope_override_and_cycles(binding):
    b=binding
    registry=build_tool_registry()
    session=Session(Live(),None,b.tenant_id,uid(6),b.connector_id,[b],Limits(max_hops=1))
    token=active.set(session)
    try:
        foreign=ToolContext(tenant_id=str(uid(11)),incident_id="fixture",agent_name="ReconAgent")
        with pytest.raises(ToolPermissionDenied):
            await registry.execute("tkg.resolve_entity",{},foreign)
        local=foreign.model_copy(update={"tenant_id":str(b.tenant_id)})
        for name in SCHEMAS:
            with pytest.raises(ValidationError):
                await registry.execute("tkg."+name,{"kb_id":str(uid(100))},local)
        for field in ("workspace","tenant_id","source_id","base_url"):
            with pytest.raises(ValidationError):
                await registry.execute("tkg.resolve_entity",{field:"override"},local)
        session.remember(b,str(uid(8)),1)
        for _ in range(2):
            r=await registry.execute("tkg.get_neighbors",{"entity":str(uid(8))},local)
            assert r[0]["status"]=="visited_or_depth_limit"
        session.pool.enabled=False
        assert (await registry.execute("tkg.resolve_entity",{},local))[0]["status"]=="binding_disabled"
        assert not session.depth.get((b.id,str(uid(77))))
    finally:
        active.reset(token)


def test_grant_authenticates_durable_alert_and_explicit_workspace(monkeypatch):
    key="synthetic-grant-key-for-tests-only"
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY",key)
    sig=hmac.new(key.encode(),f"tkg-read-v1/{uid(1)}/{uid(6)}".encode(),hashlib.sha256).hexdigest()
    assert recon.verify_grant(sig,str(uid(1)),str(uid(6)))==(uid(1),uid(6))
    for tenant,alert in [(uid(2),uid(6)),(uid(1),uid(9)),("default",uid(6))]:
        assert recon.verify_grant(sig,str(tenant),str(alert)) is None
