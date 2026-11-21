'use client';

import { useEffect, useRef, useState } from 'react';
import { clsx } from 'clsx';
import type {
  CandidateEntityKind,
  CandidateSort,
  CandidateTriageVerdict,
} from '@/hooks/useCaseCandidates';
import { InfoTip } from './InfoTip';

export type CandidateWindow = 'any' | '1h' | '24h' | '7d' | '30d' | 'custom';

export interface CandidateFilters {
  q: string;
  /** Peak pair score floor (the number θ gates). */
  minScore: number;
  severity: string | null;
  /** Every listed bucket must be present in the candidate. */
  entityKinds: CandidateEntityKind[];
  /** Any of these auto-triage verdicts must appear among the member alerts. */
  triage: CandidateTriageVerdict[];
  minAlerts: number | null;
  window: CandidateWindow;
  since: string | null;
  until: string | null;
  sort: CandidateSort;
  limit: number;
  offset: number;
}

export const DEFAULT_CANDIDATE_FILTERS: CandidateFilters = {
  q: '',
  minScore: 3,
  severity: null,
  entityKinds: [],
  triage: [],
  minAlerts: null,
  window: 'any',
  since: null,
  until: null,
  sort: 'score',
  limit: 50,
  offset: 0,
};

/**
 * Highest possible peak pair score, matching the engine exactly:
 * L1 = min(sum of shared key weights, 18) + L2 = 1 (shared story or a
 * kill-chain step) + L3 = 1 (a 3-hop path through a third observation) = 20.
 * Keep this in sync with `L1_CAP` / `_score_l1` / `_score_l2` in
 * `services/api/app/services/candidate_discovery.py`.
 */
export const MAX_PEAK_SCORE = 20;

const ENTITY_OPTIONS: Array<{ kind: CandidateEntityKind; label: string }> = [
  { kind: 'hosts', label: 'Host' },
  { kind: 'users', label: 'User' },
  { kind: 'ips', label: 'IP' },
  { kind: 'domains', label: 'Domain' },
  { kind: 'techniques', label: 'ATT&CK' },
];

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info'] as const;

/**
 * Auto-triage verdicts an analyst can filter on. The engine already drops
 * auto-closed FP/benign alerts, so the useful distinction here is "contains a
 * confirmed TP" versus "has not been triaged yet".
 */
const TRIAGE_OPTIONS: Array<{ value: CandidateTriageVerdict; label: string }> = [
  { value: 'true_positive', label: 'True positive' },
  { value: 'likely_tp', label: 'Likely TP' },
  { value: 'needs_review', label: 'Needs review' },
  { value: 'escalate', label: 'Escalated' },
  { value: 'unreviewed', label: 'Unreviewed' },
];

const WINDOW_OPTIONS: Array<{ value: CandidateWindow; label: string }> = [
  { value: 'any', label: 'Any time' },
  { value: '1h', label: 'Last 1 hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: 'custom', label: 'Custom range…' },
];

const WINDOW_MS: Record<Exclude<CandidateWindow, 'any' | 'custom'>, number> = {
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
};

/** ISO start for a relative window. Relative to *now*, not to the newest alert. */
export function sinceForWindow(
  window: CandidateWindow,
  now: Date = new Date()
): string | null {
  if (window === 'any' || window === 'custom') return null;
  return new Date(now.getTime() - WINDOW_MS[window]).toISOString();
}

function toLocalInput(iso: string | null): string {
  if (!iso) return '';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours()
  )}:${pad(date.getMinutes())}`;
}

function fromLocalInput(value: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** Human summary of the active constraints, used above the result grid. */
export function describeFilters(filters: CandidateFilters): string[] {
  const parts: string[] = [`link score ≥ ${filters.minScore}`];
  if (filters.q.trim()) parts.push(`“${filters.q.trim()}”`);
  if (filters.severity) parts.push(filters.severity);
  if (filters.entityKinds.length) {
    const labels = filters.entityKinds
      .map((kind) => ENTITY_OPTIONS.find((option) => option.kind === kind)?.label ?? kind)
      .join(' + ');
    parts.push(`has ${labels}`);
  }
  if (filters.triage.length) {
    const labels = filters.triage
      .map((verdict) => TRIAGE_OPTIONS.find((option) => option.value === verdict)?.label ?? verdict)
      .join(' / ');
    parts.push(`triage ${labels}`);
  }
  if (filters.minAlerts) parts.push(`${filters.minAlerts}+ alerts`);
  if (filters.window !== 'any') {
    if (filters.window === 'custom') {
      const from = filters.since ? new Date(filters.since).toLocaleString() : '…';
      const to = filters.until ? new Date(filters.until).toLocaleString() : 'now';
      parts.push(`${from} → ${to}`);
    } else {
      parts.push(WINDOW_OPTIONS.find((option) => option.value === filters.window)?.label ?? '');
    }
  }
  return parts.filter(Boolean);
}

interface CandidateFilterBarProps {
  filters: CandidateFilters;
  onFiltersChange: (filters: CandidateFilters) => void;
  resultCount?: number;
}

export function CandidateFilterBar({
  filters,
  onFiltersChange,
  resultCount,
}: CandidateFilterBarProps) {
  // The search box is debounced: every keystroke would otherwise become a new
  // SWR key and re-run discovery server-side for a half-typed host name.
  const [search, setSearch] = useState(filters.q);
  const [renderedQ, setRenderedQ] = useState(filters.q);
  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Reset-on-prop-change during render rather than in an effect: an effect here
  // makes every parent filter update paint twice and trips the
  // react-hooks set-state-in-effect rule.
  if (filters.q !== renderedQ) {
    setRenderedQ(filters.q);
    setSearch(filters.q);
  }

  useEffect(() => () => {
    if (debounce.current) clearTimeout(debounce.current);
  }, []);

  const patch = (changes: Partial<CandidateFilters>) =>
    onFiltersChange({ ...filters, ...changes, offset: 0 });

  const onSearchChange = (value: string) => {
    setSearch(value);
    if (debounce.current) clearTimeout(debounce.current);
    debounce.current = setTimeout(() => patch({ q: value }), 300);
  };

  const toggleEntityKind = (kind: CandidateEntityKind) => {
    const active = filters.entityKinds.includes(kind);
    patch({
      entityKinds: active
        ? filters.entityKinds.filter((value) => value !== kind)
        : [...filters.entityKinds, kind],
    });
  };

  const toggleTriage = (verdict: CandidateTriageVerdict) => {
    patch({
      triage: filters.triage.includes(verdict)
        ? filters.triage.filter((value) => value !== verdict)
        : [...filters.triage, verdict],
    });
  };

  const changeWindow = (window: CandidateWindow) => {
    if (window === 'custom') {
      patch({ window, since: filters.since, until: filters.until });
      return;
    }
    patch({ window, since: sinceForWindow(window), until: null });
  };

  const dirty =
    filters.q !== '' ||
    filters.minScore !== DEFAULT_CANDIDATE_FILTERS.minScore ||
    filters.severity !== null ||
    filters.entityKinds.length > 0 ||
    filters.triage.length > 0 ||
    filters.minAlerts !== null ||
    filters.window !== 'any' ||
    filters.sort !== DEFAULT_CANDIDATE_FILTERS.sort ||
    filters.since !== null ||
    filters.until !== null;

  return (
    <div className="space-y-3 rounded-xl border border-[#374151]/60 bg-dark-70/40 p-3">
      {/* Search + sort */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <svg
            aria-hidden="true"
            viewBox="0 0 24 24"
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.7}
          >
            <circle cx="11" cy="11" r="6.5" />
            <path strokeLinecap="round" d="M16 16l4 4" />
          </svg>
          <input
            value={search}
            onChange={(event) => onSearchChange(event.target.value)}
            placeholder="Search host, user, IP, domain, technique or candidate key…"
            aria-label="Search candidates"
            className="w-full rounded-lg border border-[#374151] bg-dark-60 py-2 pl-9 pr-3 text-sm text-gray-200 placeholder:text-gray-500 focus:border-orange-500/60 focus:outline-none focus:ring-1 focus:ring-orange-500/30"
          />
        </div>

        <label className="flex items-center gap-2 text-xs text-gray-400">
          <span className="whitespace-nowrap">Sort</span>
          <select
            value={filters.sort}
            onChange={(event) => patch({ sort: event.target.value as CandidateSort })}
            className="rounded-lg border border-[#374151] bg-dark-60 px-2 py-2 text-xs text-gray-200 focus:border-orange-500/60 focus:outline-none"
          >
            <option value="score">Strongest link</option>
            <option value="alerts">Most alerts</option>
            <option value="recent">Most recent</option>
          </select>
        </label>

        <button
          type="button"
          onClick={() => onFiltersChange({ ...DEFAULT_CANDIDATE_FILTERS })}
          disabled={!dirty}
          className={clsx(
            'rounded-lg border px-3 py-2 text-xs font-medium transition-colors',
            dirty
              ? 'border-red-500/30 bg-red-500/10 text-red-300 hover:bg-red-500/20'
              : 'cursor-not-allowed border-dark-30 bg-dark-40 text-gray-600'
          )}
        >
          Reset
        </button>
      </div>

      {/* Entity evidence + severity */}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
        <div className="flex items-center gap-2">
          <InfoTip label="Show only candidates that contain every selected kind of evidence. Host/User/IP/Domain come from the correlation observations (llm_payload), ATT&CK from the alert's MITRE annotations. Selecting two kinds requires both.">
            <span className="text-xs font-medium text-gray-400">Evidence</span>
          </InfoTip>
          <div className="flex flex-wrap gap-1.5">
            {ENTITY_OPTIONS.map(({ kind, label }) => {
              const active = filters.entityKinds.includes(kind);
              return (
                <button
                  key={kind}
                  type="button"
                  aria-pressed={active}
                  onClick={() => toggleEntityKind(kind)}
                  className={clsx(
                    'rounded border px-2 py-1 text-[11px] font-medium transition-colors',
                    active
                      ? 'border-teal-500/50 bg-teal-500/15 text-teal-300'
                      : 'border-dark-30 bg-dark-40 text-gray-400 hover:bg-dark-50 hover:text-gray-300'
                  )}
                >
                  {label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <InfoTip label="Filters on the highest severity among the candidate's member alerts.">
            <span className="text-xs font-medium text-gray-400">Severity</span>
          </InfoTip>
          <div className="flex flex-wrap gap-1.5">
            {SEVERITY_OPTIONS.map((severity) => {
              const active = filters.severity === severity;
              return (
                <button
                  key={severity}
                  type="button"
                  aria-pressed={active}
                  onClick={() => patch({ severity: active ? null : severity })}
                  className={clsx(
                    'rounded border px-2 py-1 text-[11px] font-medium transition-colors',
                    active
                      ? 'border-orange-500/50 bg-orange-500/20 text-orange-300'
                      : 'border-dark-30 bg-dark-40 text-gray-400 hover:bg-dark-50 hover:text-gray-300'
                  )}
                >
                  {severity.charAt(0).toUpperCase() + severity.slice(1)}
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <InfoTip label="Auto-triage verdicts of the candidate's member alerts. Auto-closed false positives and benign alerts never reach this queue — the engine drops them before correlating — so this facet is about confirming evidence: a candidate with a true positive is stronger than one nobody has triaged yet. Selecting several verdicts keeps candidates that contain any of them.">
            <span className="text-xs font-medium text-gray-400">Triage</span>
          </InfoTip>
          <div className="flex flex-wrap gap-1.5">
            {TRIAGE_OPTIONS.map(({ value, label }) => {
              const active = filters.triage.includes(value);
              return (
                <button
                  key={value}
                  type="button"
                  aria-pressed={active}
                  onClick={() => toggleTriage(value)}
                  className={clsx(
                    'rounded border px-2 py-1 text-[11px] font-medium transition-colors',
                    value === 'unreviewed' &&
                      (active
                        ? 'border-gray-500/50 bg-gray-500/20 text-gray-200'
                        : 'border-dark-30 bg-dark-40 text-gray-400 hover:bg-dark-50 hover:text-gray-300'),
                    value !== 'unreviewed' &&
                      (active
                        ? 'border-emerald-500/50 bg-emerald-500/15 text-emerald-300'
                        : 'border-dark-30 bg-dark-40 text-gray-400 hover:bg-dark-50 hover:text-gray-300')
                  )}
                >
                  {label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Time + score + size */}
      <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
        <div className="flex flex-col gap-1.5">
          <InfoTip label="Matches candidates whose event-time span overlaps the window — a campaign that started yesterday and is still active stays visible in “last 24 hours”. Event time is used, not ingestion time.">
            <span className="text-xs font-medium text-gray-400">Event time</span>
          </InfoTip>
          <select
            value={filters.window}
            onChange={(event) => changeWindow(event.target.value as CandidateWindow)}
            className="rounded-lg border border-[#374151] bg-dark-60 px-2 py-1.5 text-xs text-gray-200 focus:border-orange-500/60 focus:outline-none"
          >
            {WINDOW_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          {filters.window === 'custom' && (
            <div className="flex items-center gap-1.5">
              <input
                type="datetime-local"
                aria-label="From"
                value={toLocalInput(filters.since)}
                onChange={(event) => patch({ since: fromLocalInput(event.target.value) })}
                className="rounded border border-[#374151] bg-dark-60 px-2 py-1 text-[11px] text-gray-200 focus:border-orange-500/60 focus:outline-none"
              />
              <span className="text-[11px] text-gray-500">→</span>
              <input
                type="datetime-local"
                aria-label="To"
                value={toLocalInput(filters.until)}
                onChange={(event) => patch({ until: fromLocalInput(event.target.value) })}
                className="rounded border border-[#374151] bg-dark-60 px-2 py-1 text-[11px] text-gray-200 focus:border-orange-500/60 focus:outline-none"
              />
            </div>
          )}
        </div>

        <div className="flex min-w-[240px] flex-1 flex-col gap-1.5">
          <div className="flex items-center justify-between">
            <InfoTip label="Peak link score for the strongest single pair of observations: L1 (sum of the shared correlation keys' weights — host/user = 2, IP/hash = 3 — capped at 18) + L2 (1 for a shared analytic story or a kill-chain step) + L3 (1 for a 3-hop path through a third observation). θ = 3 is the merge threshold; raising this filters the list only and never splits the candidates the engine already formed.">
              <span className="text-xs font-medium text-gray-400">Min link score</span>
            </InfoTip>
            <span className="text-xs font-semibold tabular-nums text-orange-300">
              ≥ {filters.minScore}
              <span className="ml-1 font-normal text-gray-500">/ {MAX_PEAK_SCORE}</span>
            </span>
          </div>
          <input
            type="range"
            min={3}
            max={MAX_PEAK_SCORE}
            step={1}
            value={filters.minScore}
            aria-label="Minimum peak link score"
            onChange={(event) => patch({ minScore: Number(event.target.value) })}
            className="h-2 w-full cursor-pointer appearance-none rounded-lg bg-dark-40 accent-orange-500"
          />
        </div>

        <label className="flex flex-col gap-1.5">
          <InfoTip label="Component size in member alerts. Useful to hide single-action blips or to focus on campaigns that already span many notables.">
            <span className="text-xs font-medium text-gray-400">Min alerts</span>
          </InfoTip>
          <input
            type="number"
            min={1}
            inputMode="numeric"
            value={filters.minAlerts ?? ''}
            placeholder="any"
            onChange={(event) => {
              const value = event.target.value.trim();
              const parsed = value === '' ? null : Number.parseInt(value, 10);
              patch({ minAlerts: parsed && parsed > 0 ? parsed : null });
            }}
            className="w-24 rounded-lg border border-[#374151] bg-dark-60 px-2 py-1.5 text-xs text-gray-200 placeholder:text-gray-600 focus:border-orange-500/60 focus:outline-none"
          />
        </label>
      </div>

      <p className="text-[11px] text-gray-500">
        {typeof resultCount === 'number'
          ? `${resultCount} candidate${resultCount === 1 ? '' : 's'}`
          : 'Candidates'}{' '}
        · {describeFilters(filters).join(' · ')}
      </p>
    </div>
  );
}
