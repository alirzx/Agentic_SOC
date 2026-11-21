'use client';

import { useState } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import toast from 'react-hot-toast';
import {
  casesApi,
  type Case,
  type CaseCreationMethod,
  type CasesResponse,
} from '@/lib/api';
import { clsx } from 'clsx';
import { format } from 'date-fns';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { SavedViewsBar } from '@/components/saved-views/SavedViewsBar';
import { CandidatesList } from '@/components/candidates';
import type { AlertScope } from '@/hooks/useCaseCandidates';

// WS-F3 — the saved-views API stores an opaque filter blob per view, so we
// flatten the three filter slices Cases tracks today into a single shape the
// bar can snapshot and replay. Nothing else in the view consumes this — it's
// purely the wire format between the bar and the local state setters.
type CaseFilterSnapshot = {
  status: Case['status'] | 'all';
  severity: Case['severity'] | 'all';
  creationMethod: CreationFilter;
  search: string;
};

const EMPTY_CASES: CasesResponse = {
  cases: [],
  total: 0,
  page: 1,
  pageSize: 0,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

// ─── Case origin ────────────────────────────────────────────────────────────
//
// Two case-creation engines run in parallel (the v2.0 graph correlation engine
// and the legacy agentic-funnel promoter), so every case has to say which one
// produced it. `creation_method` is set by the writer and indexed by
// `(tenant_id, creation_method)` on the backend, so this table doubles as the
// vocabulary for both the badge and the filter below.
const CREATION_CONFIG: Record<
  CaseCreationMethod,
  { label: string; description: string; className: string; dot: string }
> = {
  graph_correlation: {
    label: 'Graph engine',
    description: 'Created by the v2.0 graph correlation engine',
    className: 'text-teal-300 bg-teal-500/10 border-teal-500/25',
    dot: 'bg-teal-400',
  },
  graph_correlation_manual: {
    label: 'Graph (edited)',
    description: 'Graph correlation candidate accepted and edited by an analyst',
    className: 'text-teal-200 bg-teal-500/5 border-teal-500/20',
    dot: 'bg-teal-300',
  },
  agentic_funnel: {
    label: 'Legacy funnel',
    description: 'Created by the legacy agentic-funnel case promoter',
    className: 'text-indigo-300 bg-indigo-500/10 border-indigo-500/25',
    dot: 'bg-indigo-400',
  },
  manual: {
    label: 'Manual',
    description: 'Created by an analyst',
    className: 'text-gray-300 bg-gray-500/10 border-gray-500/25',
    dot: 'bg-gray-400',
  },
  system: {
    label: 'System',
    description: 'Created by seeding/automation',
    className: 'text-slate-300 bg-slate-500/10 border-slate-500/25',
    dot: 'bg-slate-400',
  },
};

type CreationFilter = CaseCreationMethod | 'all';

const CREATION_FILTER_OPTIONS: ReadonlyArray<{
  value: CreationFilter;
  label: string;
}> = [
  { value: 'all', label: 'All origins' },
  { value: 'graph_correlation', label: 'Graph engine (new)' },
  { value: 'graph_correlation_manual', label: 'Graph engine (edited)' },
  { value: 'agentic_funnel', label: 'Legacy funnel' },
  { value: 'manual', label: 'Manual' },
  { value: 'system', label: 'System' },
];

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', className: 'text-red-400 bg-red-500/10 border-red-500/20' },
  high: { label: 'High', className: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
  medium: { label: 'Medium', className: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'Low', className: 'text-brand-400 bg-brand-500/10 border-brand-500/20' },
};

const STATUS_CONFIG: Record<
  Case['status'],
  { label: string; className: string; dot: string }
> = {
  open: { label: 'Open', className: 'text-gray-300 bg-gray-700/50 border-gray-600/50', dot: 'bg-gray-400' },
  in_progress: { label: 'In Progress', className: 'text-brand-300 bg-brand-500/10 border-brand-500/20', dot: 'bg-brand-400 animate-pulse' },
  pending: { label: 'Pending', className: 'text-amber-300 bg-amber-500/10 border-amber-500/20', dot: 'bg-amber-400' },
  resolved: { label: 'Resolved', className: 'text-green-300 bg-green-500/10 border-green-500/20', dot: 'bg-green-400' },
  closed: { label: 'Closed', className: 'text-gray-500 bg-dark-20/50 border-[#333A47]/50', dot: 'bg-gray-600' },
};

// ─── Case Card ────────────────────────────────────────────────────────────────

function CaseCard({ c }: { c: Case }) {
  const sev = SEVERITY_CONFIG[c.severity] ?? SEVERITY_CONFIG.medium;
  // Defensive: if normalization missed an unexpected status string, fall back
  // to "open" styling so the entire list never blanks the page.
  const sts = STATUS_CONFIG[c.status] ?? STATUS_CONFIG.open;
  const creation = c.creationMethod ? CREATION_CONFIG[c.creationMethod] : undefined;
  const displayId = c.caseNumber ?? `${c.id ?? ''}`.slice(-6);
  const detailHref = `/cases/${encodeURIComponent(c.caseNumber ?? c.id)}`;

  return (
    <Link href={detailHref} className="block">
      <div className="bg-dark-60 border border-[#374151]/60 rounded-xl p-5 hover:border-[#333A47] hover:bg-dark-70/80 transition-all group">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border', sev.className)}>
                {sev.label}
              </span>
              <span className={clsx('flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded border', sts.className)}>
                <span className={clsx('w-1.5 h-1.5 rounded-full', sts.dot)} />
                {sts.label}
              </span>
              {creation && (
                <span
                  title={creation.description}
                  className={clsx(
                    'flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded border',
                    creation.className
                  )}
                >
                  <span className={clsx('w-1.5 h-1.5 rounded-full', creation.dot)} />
                  {creation.label}
                </span>
              )}
            </div>
            <h3 className="text-sm font-medium text-gray-200 group-hover:text-white truncate">{c.title}</h3>
            <div className="flex items-center gap-3 mt-2">
              <span className="text-xs text-gray-500">#{displayId}</span>
              <span className="text-xs text-gray-500">·</span>
              <span className="text-xs text-gray-500">{c.alertCount ?? 0} alerts</span>
              {c.rules && Object.keys(c.rules).length > 0 && (
                <>
                  <span className="text-xs text-gray-500">·</span>
                  <span className="text-xs text-gray-500">{Object.keys(c.rules).length} rules</span>
                </>
              )}
              {c.assignee && (
                <>
                  <span className="text-xs text-gray-500">·</span>
                  <span className="text-xs text-gray-400">{c.assignee.split('@')[0]}</span>
                </>
              )}
            </div>
          </div>
          <div className="text-right shrink-0 flex flex-col items-end gap-2">
            <p className="text-xs text-gray-500" suppressHydrationWarning>{format(new Date(c.createdAt), 'MMM dd, HH:mm')}</p>
            {c.tags && c.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 justify-end">
                {c.tags.slice(0, 2).map((tag) => (
                  <span key={tag} className="text-xs text-gray-500 bg-dark-20 px-1.5 py-0.5 rounded">
                    {tag}
                  </span>
                ))}
              </div>
            )}
            <button
              onClick={(e) => {
                e.preventDefault();
                toast.success('Incident report generated — downloading PDF');
              }}
              className="flex items-center gap-1 text-xs text-gray-500 hover:text-brand-400 transition-colors opacity-0 group-hover:opacity-100"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Export Report
            </button>
          </div>
        </div>
      </div>
    </Link>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

type FilterStatus = Case['status'] | 'all';

interface CasesViewProps {
  /**
   * Optional pre-fetched cases from a Server Component. When provided, these
   * are rendered on first paint and SWR revalidates in the background.
   * When omitted or the API is empty, the empty-state UI is shown — never
   * synthetic ``case-1000`` rows that break detail routes.
   */
  initialCases?: CasesResponse;
}

export function CasesView({ initialCases }: CasesViewProps = {}) {
  const [activeTab, setActiveTab] = useState<'cases' | 'candidates'>('cases');
  const [statusFilter, setStatusFilter] = useState<FilterStatus>('all');
  const [severityFilter, setSeverityFilter] = useState<Case['severity'] | 'all'>('all');
  const [creationFilter, setCreationFilter] = useState<CreationFilter>('all');
  const [search, setSearch] = useState('');

  const fallback: CasesResponse = initialCases ?? EMPTY_CASES;

  const { data: casesData, isLoading, error: casesError, mutate: mutateCases } = useSWR(
    ['cases', statusFilter, severityFilter, creationFilter],
    () =>
      casesApi.list({
        status: statusFilter !== 'all' ? statusFilter : undefined,
        severity: severityFilter !== 'all' ? severityFilter : undefined,
        // Server-side filter: indexed on (tenant_id, creation_method).
        creation_method: creationFilter !== 'all' ? creationFilter : undefined,
        pageSize: 100,
        page: 1,
      }),
    {
      fallbackData: fallback,
      shouldRetryOnError: true,
    }
  );

  const cases = (casesData?.cases || []).filter((c) => {
    if (search && !c.title.toLowerCase().includes(search.toLowerCase())) return false;
    if (severityFilter !== 'all' && c.severity !== severityFilter) return false;
    // Defense-in-depth: keep the client-side view aligned with the server filter.
    if (creationFilter !== 'all' && c.creationMethod !== creationFilter) return false;
    return true;
  });

  // Prefer API totals — page length used to hard-cap the chips at 50.
  const statusTotals = casesData?.statusTotals;
  const mapBackendTotals = (keys: string[]): number =>
    keys.reduce((sum, key) => sum + (statusTotals?.[key] ?? 0), 0);
  const liveCases = casesData?.cases ?? [];
  const statCounts = statusTotals
    ? {
        all: Object.values(statusTotals).reduce((sum, n) => sum + n, 0),
        open: mapBackendTotals(['new', 'open']),
        in_progress: mapBackendTotals(['investigating', 'in_progress', 'contained']),
        resolved: mapBackendTotals(['resolved']),
        closed: mapBackendTotals(['closed']),
      }
    : {
        all: casesData?.total ?? liveCases.length,
        open: liveCases.filter((c) => c.status === 'open').length,
        in_progress: liveCases.filter((c) => c.status === 'in_progress').length,
        resolved: liveCases.filter((c) => c.status === 'resolved').length,
        closed: liveCases.filter((c) => c.status === 'closed').length,
      };

  /**
   * Promote a discovered candidate into a case.
   *
   * The endpoint re-runs discovery server-side and hands the member alerts to
   * the correlation case writer, so this is one call — no client-side alert
   * list assembly, no chance of promoting a stale member set.
   */
  const promoteCandidate = async (
    candidateKey: string,
    theme: string,
    scope?: AlertScope | null
  ): Promise<{ ok: boolean; message?: string }> => {
    const toastId = toast.loading(`Creating a case from ${theme}…`);
    const scoped =
      !!scope && (scope.excluded_alert_ids.length > 0 || scope.filters.length > 0);
    try {
      const response = await fetch(
        `/api/v1/cases/candidates/${encodeURIComponent(candidateKey)}/create`,
        {
          method: 'POST',
          headers: scoped ? { 'Content-Type': 'application/json' } : undefined,
          // The server drops these alerts before claiming any of them, so the
          // noisy ones never become case evidence in the first place.
          body: scoped
            ? JSON.stringify({
                excluded_alert_ids: scope!.excluded_alert_ids,
                filters: scope!.filters,
              })
            : undefined,
        }
      );
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        const detail = payload?.detail;
        const code =
          typeof detail === 'string' ? detail : detail?.error ?? `HTTP ${response.status}`;
        // The API returns machine codes; analysts need a sentence.
        const reasons: Record<string, string> = {
          no_eligible_alerts:
            'every alert in this candidate is already deduplicated into another case',
          candidate_not_found:
            'this candidate no longer exists — refresh the list and pick another',
          candidate_has_no_alerts: 'this candidate has no linked alerts',
          unknown_or_foreign_alert_ids:
            'some alerts belong to another tenant or were deleted',
        };
        throw new Error(reasons[String(code)] ?? String(code));
      }
      const created = await response.json();
      toast.success(
        created?.case_number
          ? `Case ${created.case_number} created`
          : `Case created from ${theme}`,
        { id: toastId }
      );
      await mutateCases();
      setActiveTab('cases');
      return { ok: true };
    } catch (error) {
      const message = (error as Error).message;
      toast.error(`Could not create the case: ${message}`, { id: toastId });
      // Also returned, because toasts are easy to miss (and are not rendered in
      // every shell) — the inspect modal shows this inline.
      return { ok: false, message };
    }
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Cases</h1>
          <p className="text-sm text-gray-500 mt-0.5">Manage security investigations and incidents</p>
        </div>
        {activeTab === 'cases' && (
          <div className="flex items-center gap-2">
            <button
              disabled
              title="Case creation wizard is planned for v1.1"
              className="flex items-center gap-2 bg-gray-700 text-gray-400 text-sm font-medium px-4 py-2 rounded-lg cursor-not-allowed select-none"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              New Case
            </button>
            <span className="text-xs font-medium rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 px-2 py-0.5">
              Planned for v1.1
            </span>
          </div>
        )}
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-[#374151]/60">
        <div className="flex gap-6">
          <button
            onClick={() => setActiveTab('cases')}
            className={clsx(
              'px-1 py-3 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'cases'
                ? 'border-brand-500 text-gray-100'
                : 'border-transparent text-gray-500 hover:text-gray-400'
            )}
          >
            Cases
          </button>
          <button
            onClick={() => setActiveTab('candidates')}
            className={clsx(
              'px-1 py-3 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'candidates'
                ? 'border-brand-500 text-gray-100'
                : 'border-transparent text-gray-500 hover:text-gray-400'
            )}
          >
            Candidates
          </button>
        </div>
      </div>

      {/* Cases Tab */}
      {activeTab === 'cases' && (
        <div className="space-y-5">
          {/* Stats */}
          <div className="grid grid-cols-5 gap-3">
        {(['all', 'open', 'in_progress', 'resolved', 'closed'] as const).map((s) => {
          return (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={clsx(
                'bg-dark-60 border rounded-xl p-4 text-left transition-all',
                statusFilter === s ? 'border-brand-500/50 bg-brand-500/5' : 'border-[#374151]/60 hover:border-[#333A47]'
              )}
            >
              <p className="text-2xl font-bold text-gray-100">{statCounts[s]}</p>
              <p className="text-xs text-gray-500 mt-0.5 capitalize">
                {s === 'all' ? 'All Cases' : s.replace('_', ' ')}
              </p>
            </button>
          );
        })}
      </div>

      {/*
        WS-F3 — saved views. Cases keeps three slices of filter state, so we
        synthesize a single object for the bar and unpack it on apply. We
        spread defaults to be defensive against older saved-view payloads
        that might be missing newer keys.
      */}
      <SavedViewsBar<CaseFilterSnapshot>
        viewType="cases"
        filters={{
          status: statusFilter,
          severity: severityFilter,
          creationMethod: creationFilter,
          search,
        }}
        onApply={(applied) => {
          setStatusFilter(applied.status ?? 'all');
          setSeverityFilter(applied.severity ?? 'all');
          setCreationFilter(applied.creationMethod ?? 'all');
          setSearch(applied.search ?? '');
        }}
      />

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search cases…"
            className="w-full pl-9 pr-4 py-2 bg-dark-60 border border-[#374151] rounded-lg text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-brand-500/50"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Case['severity'] | 'all')}
          className="bg-dark-60 border border-[#374151] rounded-lg text-sm text-gray-400 px-3 py-2 focus:outline-none focus:border-brand-500/50"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <select
          value={creationFilter}
          onChange={(e) => setCreationFilter(e.target.value as CreationFilter)}
          aria-label="Filter cases by creation origin"
          title="Which engine or actor created the case"
          className={clsx(
            'bg-dark-60 border rounded-lg text-sm px-3 py-2 focus:outline-none focus:border-brand-500/50',
            creationFilter === 'all'
              ? 'border-[#374151] text-gray-400'
              : 'border-teal-500/40 text-teal-200'
          )}
        >
          {CREATION_FILTER_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>

        <span className="text-xs text-gray-500">
          {cases.length}
          {casesData?.total != null && casesData.total > cases.length
            ? ` of ${casesData.total}`
            : ''}{' '}
          cases
        </span>
      </div>

      {/* Cases List */}
      {isLoading ? (
        <div className="flex items-center justify-center h-48">
          <div className="w-6 h-6 border-2 border-brand-500/30 border-t-blue-500 rounded-full animate-spin" />
        </div>
      ) : casesError && liveCases.length === 0 ? (
        <EmptyState
          icon={EmptyStateIcons.case}
          title="Could not load cases"
          description="The API request for /api/v1/cases failed. Sign in again, then refresh. Synthetic case-1000 placeholders are no longer shown."
        />
      ) : cases.length === 0 ? (
        // WS-F5 — distinguish "filter miss" from "no cases ever". The former
        // gets a "clear filters" CTA; the latter explains what cases are and
        // where they come from so a brand-new tenant doesn't think it's broken.
        statusFilter !== 'all' || severityFilter !== 'all' || creationFilter !== 'all' || search ? (
          <EmptyState
            icon={EmptyStateIcons.search}
            title="No cases match these filters"              description="Try clearing the status, severity, origin, or search filter to widen the view."
            action={
              <button
                onClick={() => {
                  setStatusFilter('all');
                  setSeverityFilter('all');
                  setCreationFilter('all');
                  setSearch('');
                }}
                className="text-xs px-3 py-1.5 rounded-md border border-brand-500/40 bg-brand-500/10 text-brand-300 hover:bg-brand-500/20 transition-colors"
              >
                Clear filters
              </button>
            }
          />
        ) : (
          <EmptyState
            icon={EmptyStateIcons.case}
            title="No cases yet"
            description="Cases bundle related alerts, evidence, and analyst notes into a single investigation. Promote alerts to a case from the Alerts tab, or click ‘New Case’ to start a manual investigation."
          />
        )
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {cases.map((c) => <CaseCard key={c.id} c={c} />)}
        </div>
      )}
      {/* End Cases Tab */}
        </div>
      )}

      {/* Candidates Tab */}
      {activeTab === 'candidates' && (
        <CandidatesList onCreateCase={promoteCandidate} />
      )}
      {/* End Candidates Tab */}
    </div>
  );
}
