/**
 * SWR Hook for fetching candidates from the correlation engine
 */

import useSWR from 'swr';

export interface CandidateEntity {
  kind: string;
  value: string;
  count?: number;
}

export type CandidateTriageVerdict =
  | 'true_positive'
  | 'likely_tp'
  | 'needs_review'
  | 'escalate'
  | 'unreviewed';

/**
 * Auto-triage verdict distribution across a candidate's member alerts.
 *
 * Display/filter metadata only: the engine excludes auto-closed FP/benign alerts
 * before it forms components, but the surviving verdicts never changed L1/L2/L3.
 */
export interface CandidateTriage {
  verdicts?: Record<string, number>;
  true_positive: number;
  likely_tp: number;
  needs_review: number;
  escalate: number;
  /** Alerts triage has not classified yet. */
  unreviewed: number;
  reviewed: number;
  max_confidence?: number | null;
  avg_confidence?: number | null;
}

export interface CandidateCard {
  candidate_key: string;
  campaign_theme: string;
  /**
   * Peak pair score — the strongest single link (L1+L2+L3) that joined the
   * observations, i.e. the number θ gates. This is what "min score" filters.
   */
  score: number;
  /** Sum of every scored pair. Grows with size; not a quality score. */
  evidence_score?: number;
  pair_count?: number;
  alert_count: number;
  entity_summary: Record<string, number>;
  time_first: string; // ISO datetime
  time_last: string;  // ISO datetime
  severity?: string | null;
  /** Verdict summary of the member alerts (absent on older API builds). */
  triage?: CandidateTriage | null;
  /**
   * Splunk search_name → how many alerts **in view** it fired on. A roll-up, not
   * a list: the API counts rules so the console never re-aggregates alerts. The
   * count follows the same evidence set the Alerts tab lists, which is why a
   * rule carried only by dedup losers still appears with its real weight.
   */
  rules?: Record<string, number>;
}

export type CandidateEntityKind = 'hosts' | 'users' | 'ips' | 'domains' | 'techniques';
export type CandidateSort = 'score' | 'recent' | 'alerts';

export interface CandidateMatchedValue {
  kind: string;
  value: string;
  /** Engine key weight — how much this value added to L1. */
  weight?: number;
  /**
   * Ambient value (hub host, common or tenant-wide domain, high-frequency
   * account). It links the two observations but is worth 0: the engine
   * suppresses it so a tenant-wide domain cannot carry a case on its own.
   */
  ambient?: boolean;
  /** Token set this value aliases (same entity, already counted). */
  alias_of?: string;
}

/** A correlation key an observation contributed, with the weight it added to L1. */
export interface CandidateObservationToken {
  /** Full engine token: `kind:value`, or `process_guid:scope|guid`. */
  token: string;
  kind: string;
  value: string;
  weight: number;
  /** Weight is the per-kind default (row predates migration 080), not scored. */
  estimated?: boolean;
}

/** One atomic attacker action — the output of graph-based dedup. */
export interface CandidateObservation {
  observation_key: string;
  role?: string | null;
  techniques?: string[];
  /** Analytic stories the observation's alerts belong to (engine L2 input). */
  stories?: string[];
  /** Splunk/Lockheed kill-chain phases for this action (engine L2 input). */
  kill_chain?: string[];
  hosts?: string[];
  users?: string[];
  ips?: string[];
  domains?: string[];
  alert_ids?: string[];
  alert_count?: number;
  first_seen?: string | null;
  last_seen?: string | null;
  time_quality?: string | null;
  /** Keys this observation contributed to scoring, strongest first. */
  tokens?: CandidateObservationToken[];
}

/** Which third observation and keys produced an L3 point. */
export interface CandidateL3Explanation {
  via: string;
  left_token: string;
  right_token: string;
}

/** Why a pair of observations scored what it scored. */
export interface CandidatePairScore {
  source: string;
  target: string;
  l1: number;
  l2: number;
  l3: number;
  score: number;
  matched?: CandidateMatchedValue[];
  /** Set only when this pair earned L3 (a 3-hop path exists). */
  l3_via?: CandidateL3Explanation | null;
  threshold_met?: boolean;
}

export interface CandidateTimelineEvent {
  alert_id: string;
  observation_key?: string | null;
  title?: string | null;
  /** Analytic name from the alert's `llm_payload.rule.title`, when it differs from `title`. */
  payload_title?: string | null;
  severity?: string | null;
  time?: string | null;
  techniques?: string[];
  /**
   * Product-funnel stage. `deduplicated` alerts are soft-dedup evidence: they
   * stay case witnesses and are still scored, but are hidden from `/alerts`,
   * so the inspect table labels them rather than showing them as ordinary rows.
   */
  funnel_stage?: string | null;
  deduplicated?: boolean;
  /** Raw events this alert stands for (exact dedupe). */
  occurrence_count?: number | null;
}

export interface CandidateGraphNode {
  id: string;
  kind: string;
  label: string;
  /** Full `kind:value` key for entity/key nodes — the label is truncated. */
  token?: string | null;
  alert_count?: number;
  techniques?: string[];
  /** Kill-chain phases for an observation node. */
  kill_chain?: string[];
  observation_key?: string | null;
}

export interface CandidateGraphEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
  /** Pair score on CORRELATION edges; key weight on key edges. */
  weight?: number;
  threshold_met?: boolean;
  matched?: CandidateMatchedValue[];
  l3_via?: CandidateL3Explanation | null;
  /** Full `kind:value` key this edge connects, on key edges. */
  token?: string | null;
  /** ATT&CK role on OBSERVATION (action) edges. */
  role?: string | null;
  /** Every role collapsed onto this entity pair; `role` is the dominant one. */
  roles?: string[];
  /** Observation keys this action edge stands for. */
  observations?: string[];
  /** How many observations were folded onto this entity pair. */
  count?: number;
  /** Alerts behind those observations. */
  alert_count?: number;
  /** Endpoints of the widest contributing observation (tree-projected above 4). */
  endpoint_count?: number;
}

/**
 * How the API projects observations into the graph.
 *
 * `node` — an observation is a hub node with its entities as leaves (the
 * historical shape). `edge` — an observation is drawn as the relation it is: a
 * role-labelled edge between its own entities.
 */
export type GraphObservationMode = 'node' | 'edge';

export interface CandidateGraph {
  nodes: CandidateGraphNode[];
  edges: CandidateGraphEdge[];
  theta?: number;
  /** Projection this payload carries; absent on older API builds (→ node). */
  observation_mode?: GraphObservationMode;
}

export interface CandidateScoreBreakdown {
  l1: number;
  l2: number;
  l3: number;
  theta: number;
  peak_score?: number;
  component_score: number;
}

/**
 * Analyst scope for a correlation view.
 *
 * `excluded_alert_ids` is per-alert and hard; `filters` are `field|op|value|mode`
 * strings evaluated against the alert's `llm_payload` server-side. Both are
 * applied while the component is rebuilt, so the graph and the scores describe
 * the reduced evidence rather than hiding nodes on the client.
 */
export interface AlertScope {
  excluded_alert_ids: string[];
  filters: string[];
}

export const EMPTY_ALERT_SCOPE: AlertScope = { excluded_alert_ids: [], filters: [] };

export function alertScopeIsEmpty(scope: AlertScope | null | undefined): boolean {
  return !scope || (scope.excluded_alert_ids.length === 0 && scope.filters.length === 0);
}

/** Query string for the scope parameters the API accepts. */
export function buildScopeSearch(scope: AlertScope | null | undefined): string {
  if (alertScopeIsEmpty(scope)) return '';
  const params = new URLSearchParams();
  if (scope!.excluded_alert_ids.length > 0) {
    params.set('exclude', scope!.excluded_alert_ids.join(','));
  }
  for (const filter of scope!.filters) params.append('flt', filter);
  const query = params.toString();
  return query ? `?${query}` : '';
}

/** One alert the scope removed from the analysis, with the reason. */
export interface ScopeDrop {
  alert_id: string;
  title?: string | null;
  reason: string;
}

/** What the server applied to the view (echoed back for the undo affordance). */
export interface CandidateScopeEcho {
  excluded_alert_ids: string[];
  filters: string[];
  dropped: ScopeDrop[];
  available_alert_count: number;
}

export interface CandidateDetail extends CandidateCard {
  alert_ids: string[];
  /**
   * Canonical case membership. `alert_count` is the wider evidence set and
   * also counts soft-dedup losers, so the two differ by exactly the duplicate
   * evidence the campaign carries.
   */
  member_alert_count?: number;
  entities: Record<string, string[]>;
  techniques: string[];
  /**
   * Inspect payload. Optional because an older API build (or the list
   * endpoint) will not send it — the modal degrades to the summary view
   * instead of rendering an empty graph.
   */
  observations?: CandidateObservation[];
  pair_scores?: CandidatePairScore[];
  timeline?: CandidateTimelineEvent[];
  graph?: CandidateGraph | null;
  score_breakdown?: CandidateScoreBreakdown | null;
  /** Present when any exclusion/filter narrowed this view. */
  scope?: CandidateScopeEcho | null;
  /**
   * Rule name → the evidence alerts carrying it, resolved **before** the scope.
   * The Rules tab needs it to exclude a whole rule and to list an excluded one
   * for restore; `rules` only counts the alerts still in view.
   */
  rule_alert_ids?: Record<string, string[]>;
}

export interface CandidatesFilter {
  q?: string;
  minScore?: number;
  severity?: string | null;
  entityKinds?: CandidateEntityKind[];
  /** Keep candidates that contain a member alert with any of these verdicts. */
  triage?: CandidateTriageVerdict[];
  minAlerts?: number | null;
  maxAlerts?: number | null;
  since?: string | null;
  until?: string | null;
  sort?: CandidateSort;
  limit?: number;
  offset?: number;
}

const fetcher = async (url: string) => {
  const response = await fetch(url);
  if (!response.ok) {
    const message = `HTTP ${response.status}`;
    const error = new Error(message) as any;
    error.status = response.status;
    throw error;
  }
  return response.json();
};

export function buildCandidatesQuery(filters?: CandidatesFilter): string {
  const params = new URLSearchParams();

  const search = (filters?.q ?? '').trim();
  if (search) params.set('q', search);
  if (filters?.minScore) params.set('min_score', String(filters.minScore));
  if (filters?.severity) params.set('severity', filters.severity);
  if (filters?.entityKinds?.length) {
    params.set('entity_kind', filters.entityKinds.join(','));
  }
  if (filters?.triage?.length) params.set('triage', filters.triage.join(','));
  if (filters?.minAlerts) params.set('min_alerts', String(filters.minAlerts));
  if (filters?.maxAlerts) params.set('max_alerts', String(filters.maxAlerts));
  if (filters?.since) params.set('since', filters.since);
  if (filters?.until) params.set('until', filters.until);
  if (filters?.sort) params.set('sort', filters.sort);
  params.set('limit', String(filters?.limit ?? 50));
  params.set('offset', String(filters?.offset ?? 0));
  return params.toString();
}

export function useCaseCandidates(filters?: CandidatesFilter) {
  const { data, error, isLoading, mutate } = useSWR<CandidateCard[]>(
    `/api/v1/cases/candidates?${buildCandidatesQuery(filters)}`,
    fetcher,
    { revalidateOnFocus: false, revalidateOnReconnect: false }
  );

  return {
    candidates: data ?? [],
    loading: isLoading,
    error,
    mutate,
  };
}

/** Append the graph-projection override, keeping any scope parameters. */
export function withObservationMode(
  search: string,
  mode?: GraphObservationMode
): string {
  if (!mode) return search;
  const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);
  params.set('observations', mode);
  const query = params.toString();
  return query ? `?${query}` : '';
}

export function useCaseCandidateDetail(
  candidateKey: string | null,
  scope?: AlertScope | null,
  observationMode?: GraphObservationMode
) {
  const search = withObservationMode(buildScopeSearch(scope), observationMode);
  const { data, error, isLoading } = useSWR<CandidateDetail>(
    candidateKey
      ? `/api/v1/cases/candidates/${encodeURIComponent(candidateKey)}${search}`
      : null,
    fetcher,
    { revalidateOnFocus: false, keepPreviousData: true }
  );

  return {
    candidate: data,
    loading: isLoading,
    error,
  };
}

/**
 * Correlation view for a case's own evidence.
 *
 * Same payload as a candidate: the API rebuilds the component from the case's
 * alerts through the correlation engine, so the graph-engine cases are
 * explained by the same modal instead of a second, weaker renderer.
 */
export function useCaseCorrelation(
  caseId: string | null,
  scope?: AlertScope | null,
  observationMode?: GraphObservationMode
) {
  const search = withObservationMode(buildScopeSearch(scope), observationMode);
  const { data, error, isLoading, mutate } = useSWR<CandidateDetail>(
    caseId ? `/api/v1/cases/${encodeURIComponent(caseId)}/correlation${search}` : null,
    fetcher,
    { revalidateOnFocus: false, keepPreviousData: true }
  );

  return { detail: data, loading: isLoading, error, mutate };
}
