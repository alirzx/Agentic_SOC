import { request } from './api';

export type KnowledgeResource = 'case' | 'alert';

export interface KnowledgeCoverage {
  alerts: number;
  eligible_alerts: number;
  configured_bindings: number;
  enabled_bindings: number;
  covered_bindings: number;
  delivery_counts: Record<string, number>;
  accepted_receipts: number;
  recoverable_receipts: number;
  last_updated: string | null;
}

export interface HistoricalFact {
  id: string;
  kb_id: string;
  root_id?: string | null;
  other_id?: string | null;
  direction?: 'in' | 'out' | null;
  predicate_key?: string | null;
  other_type?: string | null;
  valid_from?: string | null;
  valid_to?: string | null;
  recorded_at?: string | null;
  knowledge_time?: string | null;
  contested: boolean;
  stale: boolean;
  inferred: boolean;
  sources: { document_id: string; chunk_id: string }[];
}

export interface ReconHistory {
  profile: 'standard' | 'deep_case' | null;
  historical_status: string | null;
  stop_reason: string | null;
  coverage: Record<string, number | boolean | null>;
  limits: Record<string, number>;
  tool_calls: number | null;
  tool_requests: number | null;
  llm_calls: number | null;
  provider_calls: number | null;
  planner_attempts?: number | null;
  preflight_tool_calls?: number | null;
  assessment_status?: string | null;
  reserved_tokens_charged: number | null;
  estimated_cost_usd: number | null;
  tools: { tool: string; status: string; seed_id: string | null; duration_ms: number | null; fact_count: number; truncated: boolean }[];
  facts: HistoricalFact[];
  entities: { id: string; kb_id: string }[];
  candidates: { kb_id: string; document_id: string; chunk_id: string }[];
  claims: { claim: string; citations: string[]; status: 'requires_analyst_review' }[];
  truncated: boolean;
}

export interface KnowledgeRun {
  run_id: string;
  run_status: string;
  started_at: string;
  history: ReconHistory | null;
}

export const tkgKnowledgeApi = {
  coverage: (workspace: string, kind: KnowledgeResource, id: string) =>
    request<KnowledgeCoverage>(`/api/v1/${kind === 'case' ? 'cases' : 'alerts'}/${encodeURIComponent(id)}/tkg-coverage`, {
      headers: { 'X-Tenant-Id': workspace },
    }),
  history: (workspace: string, kind: KnowledgeResource, id: string, runId: string) =>
    request<KnowledgeRun>(`/api/v1/investigations/${encodeURIComponent(runId)}/tkg-history`, {
      params: { kind, resource_id: id }, headers: { 'X-Tenant-Id': workspace },
    }),
};
