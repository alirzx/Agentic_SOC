/**
 * Client for the Soorin TKG second-opinion endpoints.
 *
 * Kept beside `api.ts` rather than inside it: this surface is optional (a
 * deployment without a TKG still renders the case workspace) and the panel is
 * the only consumer.
 */

import { request } from './api';

export interface TkgCheck {
  id: string;
  ok: boolean;
  detail?: string | null;
}

export interface TkgHealth {
  enabled: boolean;
  configured: boolean;
  ready: boolean;
  checks: TkgCheck[];
  counts: Record<string, unknown>;
  kb_id?: string | null;
  error?: string | null;
  /** Manual send path enabled (AISOC_TKG_ALLOW_SEND). Off by default. */
  allow_send?: boolean;
}

export interface TkgSyncResult {
  ok: boolean;
  dry_run: boolean;
  reason?: string | null;
  detail?: string | null;
  source_id?: string | null;
  would_send: Array<{ alert_id: string; notable_id: string; warnings?: string[] }>;
  sent: Array<{ alert_id: string; notable_id: string; receipt_id: string; status?: string }>;
  rejected: Array<{ alert_id: string; notable_id: string; error: string }>;
  failed: Array<{ alert_id: string; notable_id: string; error: string }>;
  already_in_graph: Array<{ alert_id: string; notable_id: string; status?: string }>;
  invalid: Array<{ alert_id: string; error: string }>;
  counts: Record<string, number>;
  allow_send: boolean;
  note?: string | null;
  started_at?: string | null;
}

export interface TkgAttributionAlert {
  alert_id: string;
  /** AiSOC's own alert row id (the resolved id is the notable id the graph got). */
  row_id?: string | null;
  /** The alert's title as the console shows it; older stored runs lack it. */
  title?: string | null;
  rule?: string | null;
  severity?: string | null;
  time?: string | null;
  techniques?: string[];
  status: string;
  entity_id?: string | null;
  canonical_key?: string | null;
  facts: number;
  synthetic_facts: number;
  pass: string;
  error?: string | null;
  /** Soft-dedup witness: scored as evidence, hidden from the alerts workbench. */
  deduplicated?: boolean;
  occurrence_count?: number | null;
}

/** How the wait stage ended for one pass of the run. */
export interface TkgWaitOutcome {
  ended: 'drained' | 'skipped' | 'timeout' | 'failed' | 'partial_first_pass' | string;
  phase?: string;
  waves: number;
  probes: number;
  /** Alerts still queued when the wait ended; the next run reads them. */
  pending: number;
  seconds: number;
  timeout_s?: number;
}

export interface TkgEvaluation {
  evaluation_id: string | null;
  status: 'ok' | 'ineligible' | 'unavailable' | 'partial' | string;
  reason_codes: string[];
  verdict: string | null;
  confidence: number | null;
  passes: string | null;
  agree: boolean | null;
  reasons: Array<{ code?: string; detail?: string } | string>;
  attribution: {
    alerts?: TkgAttributionAlert[];
    /** What a run pushed to the graph before attributing (AISOC_TKG_ALLOW_SEND). */
    send?: {
      eligible: number;
      /** Missing alerts over the per-run cap, left for the next run. */
      deferred?: number;
      sent: Array<{ notable_id: string; receipt_id: string }>;
      rejected: Array<{ notable_id: string; error: string }>;
      failed: Array<{ notable_id: string; error: string }>;
      error?: string;
      /** Set when the graph answered 429 and the batch stopped early. */
      stopped?: string | null;
    };
    /**
     * Queued alerts the graph gave up on. Their receipt carries a terminal
     * `failure_code` (the extractor exhausted its retries, usually on an LLM
     * 429), so no further re-probe will ever project them.
     */
    graph_failures?: {
      count: number;
      error: string;
      alerts?: Array<{ notable_id: string; receipt_id: string; error: string }>;
    };
    passes?: Record<string, number>;
    resolved?: number;
    facts?: number;
    real_facts?: number;
    synthetic_facts?: number;
    synthetic_only?: boolean;
    partial?: boolean;
    /** Which send pass produced this row: canonical members, then the witnesses. */
    phase?: string;
    /** How the materialisation wait ended for this row's pass. */
    wait?: TkgWaitOutcome;
  };
  input_payload?: Record<string, unknown> | null;
  kb_id?: string | null;
  profile?: string | null;
  created_at?: string | null;
  stats: Record<string, number | Record<string, number>>;
  detail?: string | null;
}

/**
 * One in-flight evaluation run, as the panel's stepper renders it.
 *
 * `stage` walks precheck → resolve → context → materialise → judge → persist →
 * done; the counters only ever grow, so a step can show what it has finished
 * rather than a spinner with no number.
 */
export interface TkgRunSnapshot {
  run_id: string;
  state: 'running' | 'finished' | 'cancelled' | 'failed';
  stage: 'precheck' | 'resolve' | 'context' | 'materialise' | 'judge' | 'persist' | 'done' | string;
  total: number;
  probed: number;
  resolved: number;
  facts: number;
  pending: number;
  wave: number;
  /** Re-probe waves so far; `max_waves` is `0` because there is no wave limit. */
  max_waves: number;
  /**
   * Seconds left before this wait gives up on its own (`-1`: no cap). When it
   * runs out the run scores what is resolved instead of holding the verdict
   * hostage to a queue the graph may never drain.
   */
  wait_left_s?: number;
  /** The cap in force for this wait, in seconds (`0`: none). */
  wait_timeout_s?: number;
  /**
   * True only while the run is in the wait stage: *stop waiting* ends that stage
   * and the run still judges and stores. A full cancel stores nothing.
   */
  can_skip_wait?: boolean;
  /**
   * Which pass is in flight: `canonical` (the distinct alerts) or `dedup` (the
   * soft-dedup witnesses). `null` before the first pass starts.
   */
  phase?: 'canonical' | 'dedup' | string | null;
  /** 1-based pass number and the number of passes this run will do. */
  phase_index?: number;
  phase_count?: number;
  /** Alerts this pass is responsible for — 3 versus 1009 is the useful signal. */
  phase_total?: number;
  message?: string | null;
  error?: string | null;
  elapsed_ms: number;
  result?: TkgEvaluation | null;
  /**
   * The run's evaluation as it stands *right now*: same shape as a stored row,
   * rescored with the same rubric after every few resolved alerts. Present once
   * the run has resolved anything; the panel renders it instead of the previous
   * stored run, so confidence and the attribution table move during the run.
   */
  partial?: TkgEvaluation | null;
}

const base = (caseId: string) => `/api/v1/cases/${encodeURIComponent(caseId)}/tkg-evaluation`;

export const caseTkgApi = {
  health: () => request<TkgHealth>('/api/v1/cases/tkg-evaluation/health'),

  latest: (caseId: string) => request<TkgEvaluation>(base(caseId)),

  history: (caseId: string, limit = 10) =>
    request<TkgEvaluation[]>(`${base(caseId)}s`, { params: { limit } }),

  run: (caseId: string, engineVerdict?: string | null, refresh = false) =>
    request<TkgEvaluation>(base(caseId), {
      method: 'POST',
      body: JSON.stringify({ engine_verdict: engineVerdict ?? null, refresh }),
    }),

  /**
   * Starts the same evaluation as a job so its progress can be watched.
   *
   * `send_missing` is the one-click contract: when the deployment allows writes,
   * the run pushes the alerts the graph does not know, then attributes them — so
   * there is no separate "send" step to find.
   */
  startRun: (caseId: string, engineVerdict?: string | null, refresh = false) =>
    request<TkgRunSnapshot>(`${base(caseId)}/run`, {
      method: 'POST',
      body: JSON.stringify({ engine_verdict: engineVerdict ?? null, refresh, send_missing: true }),
    }),

  runSnapshot: (caseId: string, runId: string) =>
    request<TkgRunSnapshot>(`${base(caseId)}/run/${encodeURIComponent(runId)}`),

  cancelRun: (caseId: string, runId: string) =>
    request<TkgRunSnapshot>(`${base(caseId)}/run/${encodeURIComponent(runId)}`, {
      method: 'DELETE',
    }),

  /**
   * End the wait stage only.
   *
   * The alerts already sent keep materialising inside the graph; this run judges
   * and stores what is resolved, so a slow queue cannot hide the verdict. The
   * hard stop is `cancelRun`, which still stores nothing.
   */
  skipWait: (caseId: string, runId: string) =>
    request<TkgRunSnapshot>(
      `${base(caseId)}/run/${encodeURIComponent(runId)}/skip-wait`,
      { method: 'POST' }
    ),

  /**
   * Push the case's *missing* alerts into the graph.
   *
   * Test/setup escape hatch: `dryRun` (the default) only reports what would be
   * sent. Nothing is written without an explicit non-dry run on a deployment
   * that opted in with `AISOC_TKG_ALLOW_SEND`.
   */
  sync: (caseId: string, opts: { dryRun?: boolean; limit?: number; delayS?: number } = {}) =>
    request<TkgSyncResult>(`${base(caseId)}/sync`, {
      method: 'POST',
      body: JSON.stringify({
        dry_run: opts.dryRun ?? true,
        limit: opts.limit ?? 25,
        delay_s: opts.delayS,
      }),
    }),
};
