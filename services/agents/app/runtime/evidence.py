"""Evidence graph helpers (spec §32). Finding → Evidence → ToolExecution → Source."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .contracts import Evidence, Finding, hash_payload


class ToolExecutionRecord(BaseModel):
    id: str
    tool: str
    query: dict[str, Any] = Field(default_factory=dict)
    result_hash: str = ""
    source: str
    agent: str
    agent_version: str


class EvidenceGraphNode(BaseModel):
    kind: str
    id: str
    label: str
    data: dict[str, Any] = Field(default_factory=dict)


class EvidenceGraphEdge(BaseModel):
    source_id: str
    target_id: str
    relation: str


class EvidenceGraph(BaseModel):
    nodes: list[EvidenceGraphNode] = Field(default_factory=list)
    edges: list[EvidenceGraphEdge] = Field(default_factory=list)

    def cite_chain(self, finding_id: str) -> list[str]:
        """Walk Finding → Evidence → ToolExecution → Source as node ids."""
        outgoing: dict[str, list[EvidenceGraphEdge]] = {}
        for edge in self.edges:
            outgoing.setdefault(edge.source_id, []).append(edge)
        walk: list[str] = [finding_id]
        current = finding_id
        seen: set[str] = {finding_id}
        while current in outgoing:
            nxt = outgoing[current][0].target_id
            if nxt in seen:
                break
            walk.append(nxt)
            seen.add(nxt)
            current = nxt
        return walk


def build_evidence_graph(
    *,
    findings: list[Finding],
    evidence: list[Evidence],
    executions: list[ToolExecutionRecord] | None = None,
) -> EvidenceGraph:
    executions = executions or []
    nodes: list[EvidenceGraphNode] = []
    edges: list[EvidenceGraphEdge] = []
    evidence_by_id = {item.id: item for item in evidence}
    exec_by_query = {item.id: item for item in executions}
    for finding in findings:
        nodes.append(
            EvidenceGraphNode(
                kind="finding",
                id=finding.id,
                label=finding.statement,
                data={"confidence": finding.confidence},
            )
        )
        for evidence_id in finding.evidence_ids:
            item = evidence_by_id.get(evidence_id)
            if item is None:
                continue
            nodes.append(
                EvidenceGraphNode(
                    kind="evidence",
                    id=item.id,
                    label=item.type,
                    data={"hash": item.hash, "source": item.source},
                )
            )
            edges.append(EvidenceGraphEdge(source_id=finding.id, target_id=item.id, relation="supported_by"))
            if item.provenance is None:
                continue
            exec_id = item.provenance.query_id or hash_payload(
                {"tool": item.provenance.tool, "hash": item.hash}
            )
            if exec_id not in exec_by_query:
                record = ToolExecutionRecord(
                    id=exec_id,
                    tool=item.provenance.tool,
                    result_hash=item.hash,
                    source=item.provenance.source,
                    agent=item.provenance.agent,
                    agent_version=item.provenance.agent_version,
                )
                exec_by_query[exec_id] = record
            nodes.append(
                EvidenceGraphNode(
                    kind="tool_execution",
                    id=exec_id,
                    label=item.provenance.tool,
                    data={"source": item.provenance.source},
                )
            )
            edges.append(EvidenceGraphEdge(source_id=item.id, target_id=exec_id, relation="retrieved_by"))
            source_id = f"source:{item.provenance.source}"
            nodes.append(
                EvidenceGraphNode(kind="source", id=source_id, label=item.provenance.source)
            )
            edges.append(EvidenceGraphEdge(source_id=exec_id, target_id=source_id, relation="from_source"))
    return EvidenceGraph(nodes=_dedupe_nodes(nodes), edges=edges)


def _dedupe_nodes(nodes: list[EvidenceGraphNode]) -> list[EvidenceGraphNode]:
    seen: dict[str, EvidenceGraphNode] = {}
    for node in nodes:
        seen[node.id] = node
    return list(seen.values())
