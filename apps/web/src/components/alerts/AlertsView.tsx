'use client';

import { useState, useCallback, useEffect, type CSSProperties } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { alertsApi, type Alert, type AlertFilters, type ConfidenceLabel, type FunnelStage } from '@/lib/api';
import { clsx } from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import { ChevronLeft, ChevronRight, CirclePlus, Search } from 'lucide-react';
import { EntityRiskQueue } from './EntityRiskQueue';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';
import { SavedViewsBar } from '@/components/saved-views/SavedViewsBar';
import { Card } from '@/components/dashboard/ui';

// Wave 1 of the AiSOC v6 capability roadmap. The "entities" tab renders the
// rolled-up Risk-Based Alerting queue — alerts contribute time-decayed risk
// points to the entities they touch, and the queue surfaces those entities
// (not the raw alerts) to the analyst. The "alerts" tab keeps the legacy
// alert-centric grid for tenants that prefer it or have RBA disabled.
//
// The alerts tab is a full-width queue: clicking a row (or "Open full
// detail") routes straight to the alert page `/alerts/{id}`, which carries the
// narrative, related entities, timeline, recommended actions and Deep Explain.
type ViewMode = 'entities' | 'alerts';

// ─── Config ───────────────────────────────────────────────────────────────────

/** Outlined, lightly tinted pill (light dashboard design). */
function tint(hex: string, text = hex): CSSProperties {
  return { borderColor: `${hex}B3`, backgroundColor: `${hex}1F`, color: text };
}

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', hex: '#FD4E4E' },
  high: { label: 'High', hex: '#F98B3E' },
  medium: { label: 'Medium', hex: '#F2AC49', text: '#D98A1E' },
  low: { label: 'Low', hex: '#4FD2C2', text: '#1C9E8F' },
  info: { label: 'Info', hex: '#939DAD' },
} as const;

const STATUS_CONFIG = {
  new: { label: 'New', hex: '#7B5EE6' },
  triaged: { label: 'Triaged', hex: '#3163CF' },
  investigating: { label: 'Investigating', hex: '#4FD2C2', text: '#1C9E8F' },
  resolved: { label: 'Resolved', hex: '#4ADE80', text: '#16A34A' },
  false_positive: { label: 'False Positive', hex: '#939DAD' },
} as const;

const PILL = 'inline-flex items-center justify-center whitespace-nowrap rounded-md border px-2 py-[3px] text-[11px] leading-none';

// ─── Sub-components ───────────────────────────────────────────────────────────

// Wave 1 — Detection confidence chip rendered inline in the alert grid so an
// analyst can spot low-confidence alerts at a glance without clicking through.
const CONFIDENCE_ROW_CONFIG: Record<ConfidenceLabel, { label: string; hex: string; text?: string }> = {
  high: { label: 'High', hex: '#4FD2C2', text: '#1C9E8F' },
  medium: { label: 'Med', hex: '#F2BD57', text: '#D99A1E' },
  low: { label: 'Low', hex: '#939DAD' },
};

function ConfidencePill({ label }: { label: ConfidenceLabel }) {
  const cfg = CONFIDENCE_ROW_CONFIG[label];
  return (
    <span
      className={clsx(PILL, 'min-w-[38px]')}
      style={tint(cfg.hex, cfg.text)}
      title={`Detection confidence: ${cfg.label}`}
    >
      {cfg.label}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.info;
  return (
    <span className={PILL} style={tint(cfg.hex, 'text' in cfg ? cfg.text : cfg.hex)}>
      {cfg.label}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.new;
  return (
    <span className={PILL} style={tint(cfg.hex, 'text' in cfg ? cfg.text : cfg.hex)}>
      {cfg.label}
    </span>
  );
}

function StagePill({ stage }: { stage: string }) {
  const quiet = stage === 'ingested' || stage === 'suppressed' || stage === 'deduplicated';
  return (
    <span
      className={PILL}
      style={quiet ? tint('#939DAD') : tint('#4FD2C2', '#1C9E8F')}
      title={`Funnel stage: ${stage}`}
    >
      {stage.replace(/_/g, ' ')}
    </span>
  );
}

const SELECT_PILL =
  'h-[42px] cursor-pointer rounded-full border border-surface-border bg-surface-card pl-4 text-[13px] text-fg-secondary focus:outline-none focus:ring-2 focus:ring-teal-20/30';

function FiltersBar({
  filters,
  onChange,
  total,
}: {
  filters: AlertFilters;
  onChange: (f: AlertFilters) => void;
  total: number;
}) {
  const severities = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;
  const statuses = ['all', 'new', 'investigating', 'resolved', 'false_positive'] as const;
  const funnelStages = [
    'all',
    'ingested',
    'triaged',
    'suppressed',
    'investigating',
    'cased',
    'ready_for_jira',
    'jira_pushed',
  ] as const;

  // Search is debounced so typing doesn't fire a request per keystroke; the
  // API filters server-side (`/api/v1/alerts?search=`).
  const [query, setQuery] = useState(filters.search ?? '');
  // Re-sync the box when the search changes from outside (saved view, clear
  // filters) — adjusted during render rather than in an effect.
  const [syncedSearch, setSyncedSearch] = useState(filters.search);
  if (filters.search !== syncedSearch) {
    setSyncedSearch(filters.search);
    setQuery(filters.search ?? '');
  }
  useEffect(() => {
    const next = query.trim() || undefined;
    if (next === (filters.search || undefined)) return;
    const id = window.setTimeout(() => onChange({ ...filters, search: next, page: 1 }), 400);
    return () => window.clearTimeout(id);
  }, [query, filters, onChange]);

  return (
    <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
      <label className="relative flex-1 lg:max-w-[576px]">
        <Search className="pointer-events-none absolute left-4 top-1/2 h-[18px] w-[18px] -translate-y-1/2 text-fg-subtle" strokeWidth={1.5} aria-hidden />
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search alerts…"
          aria-label="Search alerts"
          className="h-[42px] w-full rounded-full border border-surface-border bg-surface-card pl-11 pr-4 text-sm text-fg-primary placeholder:text-fg-subtle focus:outline-none focus:ring-2 focus:ring-teal-20/30"
        />
      </label>
      <div className="flex flex-wrap items-center gap-2 lg:ml-auto">
        <select
          aria-label="Stage"
          value={filters.funnel_stage ?? 'all'}
          onChange={(e) =>
            onChange({
              ...filters,
              funnel_stage: e.target.value === 'all' ? undefined : e.target.value,
              page: 1,
            })
          }
          className={SELECT_PILL}
        >
          {funnelStages.map((s) => (
            <option key={s} value={s}>
              {s === 'all' ? 'Stage' : s.replace(/_/g, ' ')}
            </option>
          ))}
        </select>
        <select
          aria-label="Status"
          value={filters.status ?? 'all'}
          onChange={(e) => onChange({ ...filters, status: e.target.value === 'all' ? undefined : e.target.value, page: 1 })}
          className={SELECT_PILL}
        >
          {statuses.map((s) => (
            <option key={s} value={s}>
              {s === 'all' ? 'Status' : s.replace('_', ' ')}
            </option>
          ))}
        </select>
        <select
          aria-label="Severity"
          value={filters.severity ?? 'all'}
          onChange={(e) => onChange({ ...filters, severity: e.target.value === 'all' ? undefined : e.target.value, page: 1 })}
          className={clsx(SELECT_PILL, 'capitalize')}
        >
          {severities.map((s) => (
            <option key={s} value={s}>
              {s === 'all' ? 'Severity' : s}
            </option>
          ))}
        </select>
        <span className="inline-flex h-[42px] items-center rounded-full border border-surface-border bg-surface-hover px-4 text-xs text-fg-muted tabular-nums">
          {total.toLocaleString('en-US')} total
        </span>
      </div>
    </div>
  );
}

const ROW_GRID =
  'grid grid-cols-[minmax(240px,1fr)_44px_64px_64px_104px_104px_76px_112px] items-center gap-x-3';

const SEVERITY_EDGE: Record<string, string> = {
  critical: '#FD4E4E',
  high: '#F98B3E',
  medium: '#F2AC49',
  low: '#4FD2C2',
  info: '#939DAD',
};

// Each alert is a row card with a severity-coloured left edge. Clicking
// anywhere on the row opens the alert page; the title is a real link so
// Ctrl/Cmd/middle-click still opens it in a new tab, and the Runbook /
// "Open full detail" links keep their own targets.
function AlertRow({ alert }: { alert: Alert }) {
  const router = useRouter();
  const technique = alert.mitreAttack?.[0]?.techniqueId;
  const href = `/alerts/${alert.id}`;
  return (
    <div
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('a,button')) return;
        router.push(href);
      }}
      className={clsx(
        ROW_GRID,
        'cursor-pointer rounded-xl border border-surface-border border-l-[3px] bg-surface-card px-5 py-4 transition-colors hover:bg-surface-subtle',
      )}
      style={{ borderLeftColor: SEVERITY_EDGE[alert.severity] ?? SEVERITY_EDGE.info }}
    >
      <div className="min-w-0">
        <Link
          href={href}
          className="block truncate text-[15px] text-fg-primary hover:text-teal-10"
          title={alert.title}
        >
          {alert.title}
        </Link>
        <p className="mt-1 truncate text-[10px] text-fg-subtle">
          {alert.source}
          {alert.assignee && <> · {alert.assignee}</>}
          {technique && <> · {technique}</>}
        </p>
      </div>
      <div>{alert.confidenceLabel && <ConfidencePill label={alert.confidenceLabel} />}</div>
      <div>
        <SeverityBadge severity={alert.severity} />
      </div>
      <div>
        <StatusBadge status={alert.status} />
      </div>
      <div>
        {alert.funnelStage ? (
          <StagePill stage={alert.funnelStage} />
        ) : (
          <span aria-label="No stage" className="block h-px w-10 bg-gray-600" />
        )}
      </div>
      <span className="truncate text-[11px] text-fg-muted" suppressHydrationWarning>
        {formatDistanceToNow(new Date(alert.createdAt), { addSuffix: true })}
      </span>
      {/* View Runbook — links to /runbook with the alert UUID pre-filled */}
      <Link
        href={`/runbook?type=alert&id=${alert.id}`}
        title="Open Runbook ledger for this alert"
        className={clsx(PILL, 'w-[68px] border-surface-border text-fg-subtle transition-colors hover:border-teal-20/70 hover:text-teal-10')}
      >
        Runbook
      </Link>
      <Link
        href={href}
        className={clsx(PILL, 'border-teal-20/70 bg-teal-20/10 text-teal-10 transition-colors hover:bg-teal-20/20')}
      >
        Open full detail
      </Link>
    </div>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

const FUNNEL_STAGE_QUERY = new Set<string>([
  'ingested',
  'triaged',
  'suppressed',
  'deduplicated',
  'investigating',
  'cased',
  'ready_for_jira',
  'jira_pushed',
]);

export function AlertsView() {
  const searchParams = useSearchParams();
  const stageFromUrl = searchParams.get('funnel_stage');
  const initialStage =
    stageFromUrl && FUNNEL_STAGE_QUERY.has(stageFromUrl)
      ? (stageFromUrl as FunnelStage)
      : undefined;
  const [filters, setFilters] = useState<AlertFilters>({
    page: 1,
    pageSize: 25,
    funnel_stage: initialStage,
  });
  // Default to the alert grid; analysts can flip to the entity-centric
  // Risk-Based Alerting queue from the header tabs.
  const [viewMode, setViewMode] = useState<ViewMode>('alerts');

  const { data, error, isLoading } = useSWR(
    ['alerts', filters],
    () => alertsApi.list(filters),
    {
      refreshInterval: 30000,
      shouldRetryOnError: true,
    }
  );

  const handleFilterChange = useCallback((newFilters: AlertFilters) => {
    setFilters(newFilters);
  }, []);

  const alerts = data?.alerts || [];
  const total = data?.total || 0;

  const critCount = alerts.filter((a) => a.severity === 'critical').length;
  const highCount = alerts.filter((a) => a.severity === 'high').length;
  const newCount = alerts.filter((a) => a.status === 'new').length;

  const tabClass = (active: boolean) =>
    clsx(
      'h-[34px] rounded-full px-5 text-[13px] transition-colors',
      active
        ? 'border border-teal-20/70 bg-teal-20/[0.15] text-teal-10 font-gilroy-medium'
        : 'text-fg-secondary hover:text-fg-primary',
    );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-[26px] leading-tight font-gilroy-semibold text-fg-primary">Alerts</h1>
          <p className="mt-2 text-xs text-fg-secondary">
            {viewMode === 'entities'
              ? 'Risk-Based Alerting · entity-centric triage queue'
              : 'Real-time security event monitoring and triage'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div
            role="tablist"
            aria-label="View mode"
            className="inline-flex h-[42px] items-center gap-1 rounded-full border border-surface-border bg-surface-card p-1"
          >
            <button
              type="button"
              role="tab"
              aria-selected={viewMode === 'alerts'}
              onClick={() => setViewMode('alerts')}
              className={tabClass(viewMode === 'alerts')}
              title="Per-alert triage grid (one row per notable / detection)"
            >
              Alerts
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={viewMode === 'entities'}
              onClick={() => setViewMode('entities')}
              className={tabClass(viewMode === 'entities')}
              title="Risk-Based Alerting: hosts/users/IPs rolled up from contributing alerts"
            >
              Entities
            </button>
          </div>
          <button
            disabled
            title="Manual alert creation is planned for v1.1"
            className="inline-flex h-[42px] cursor-not-allowed select-none items-center gap-2 rounded-full border border-surface-border bg-surface-card px-4 text-[13px] text-fg-subtle"
          >
            <CirclePlus className="h-[18px] w-[18px]" strokeWidth={1.5} aria-hidden />
            Create Alert
          </button>
        </div>
      </div>

      {viewMode === 'entities' ? (
        <EntityRiskQueue />
      ) : (
        <AlertsTable
          alerts={alerts}
          total={total}
          critCount={critCount}
          highCount={highCount}
          newCount={newCount}
          filters={filters}
          isLoading={isLoading}
          error={error}
          onFilterChange={handleFilterChange}
        />
      )}
    </div>
  );
}

// ─── Legacy alert-centric grid (extracted for the view-mode toggle) ──────────

function AlertsTable({
  alerts,
  total,
  critCount,
  highCount,
  newCount,
  filters,
  isLoading,
  error,
  onFilterChange,
}: {
  alerts: Alert[];
  total: number;
  critCount: number;
  highCount: number;
  newCount: number;
  filters: AlertFilters;
  isLoading: boolean;
  error: unknown;
  onFilterChange: (f: AlertFilters) => void;
}) {
  return (
    <div className="space-y-4">
      {/* Stats strip (full width) */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          { label: 'Total', value: total, color: 'text-fg-primary' },
          { label: 'Critical', value: critCount, color: 'text-[#FD4E4E]' },
          { label: 'High', value: highCount, color: 'text-[#F98B3E]' },
          { label: 'Unresolved', value: newCount, color: 'text-[#7B5EE6]' },
        ].map((stat) => (
          <Card key={stat.label} className="px-8 py-6">
            <p className="text-[13px] text-fg-secondary">{stat.label}</p>
            <p className={clsx('mt-4 text-[26px] leading-none font-gilroy-semibold tabular-nums', stat.color)}>
              {stat.value.toLocaleString('en-US')}
            </p>
          </Card>
        ))}
      </div>

      {/*
        WS-F3 — saved views. The bar reads/writes filters straight through
        ``onFilterChange`` so we don't need a parallel state path. We reset
        ``page`` to 1 when applying a preset because saved pagination would
        be confusing — analysts expect to start from the top.
      */}
      <SavedViewsBar<AlertFilters>
        viewType="alerts"
        filters={filters}
        onApply={(applied) =>
          onFilterChange({
            ...applied,
            page: 1,
            pageSize: filters.pageSize ?? 25,
          })
        }
      />

      <FiltersBar filters={filters} onChange={onFilterChange} total={total} />

      <AlertsTableGrid
        alerts={alerts}
        total={total}
        isLoading={isLoading}
        error={error}
        filters={filters}
        onFilterChange={onFilterChange}
      />
    </div>
  );
}

// ─── Queue grid ───────────────────────────────────────────────────────────────

function AlertsTableGrid({
  alerts,
  total,
  isLoading,
  error,
  filters,
  onFilterChange,
}: {
  alerts: Alert[];
  total: number;
  isLoading: boolean;
  error: unknown;
  filters: AlertFilters;
  onFilterChange: (f: AlertFilters) => void;
}) {
  return (
    <Card className="overflow-hidden">
      <div className="overflow-x-auto">
        <div className="min-w-[920px]">
          <div className={clsx(ROW_GRID, 'border-b border-surface-border px-7 py-3.5 text-sm text-fg-secondary')}>
            <span>Alert</span>
            <span />
            <span>Severity</span>
            <span>Status</span>
            <span>Stages</span>
            <span>Time</span>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="w-6 h-6 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : error ? (
            <div className="p-4">
              <ErrorState
                title="Couldn't load alerts"
                description="The alerts feed didn't respond. Check the API service or try again."
                error={error}
              />
            </div>
          ) : alerts.length === 0 ? (
            <div className="p-4">
              {/*
                WS-F5 — distinguish "no data at all" from "filtered out". The
                filter-aware copy is the difference between an analyst thinking
                "the system is broken" and "I should clear my filters".
              */}
              {filters.severity || filters.status || filters.search || filters.funnel_stage ? (
                <EmptyState
                  icon={EmptyStateIcons.search}
                  title="No alerts match these filters"
                  description="Try clearing the search, stage, severity or status filter to widen the results."
                  action={
                    <button
                      onClick={() => onFilterChange({ page: 1, pageSize: filters.pageSize ?? 25 })}
                      className="text-xs px-3 py-1.5 rounded-full border border-teal-20/60 bg-teal-20/10 text-teal-10 hover:bg-teal-20/20 transition-colors"
                    >
                      Clear filters
                    </button>
                  }
                />
              ) : (
                <EmptyState
                  icon={EmptyStateIcons.alert}
                  title="No alerts yet"
                  description="Once a connector ingests events that trip a detection, alerts will appear here. Connect a data source from Settings → Connectors to start streaming."
                />
              )}
            </div>
          ) : (
            <div className="space-y-2 p-2">
              {alerts.map((alert) => (
                <AlertRow key={alert.id} alert={alert} />
              ))}
            </div>
          )}
        </div>
      </div>
      <AlertsPagination
        alerts={alerts}
        total={total}
        filters={filters}
        onFilterChange={onFilterChange}
      />
    </Card>
  );
}

const PAGE_SIZES = [10, 25, 50, 100];

/** Page numbers to show: first, last, current ±1, with gaps as `null`. */
function pageWindow(current: number, last: number): (number | null)[] {
  const pages = new Set([1, last, current - 1, current, current + 1]);
  const sorted = [...pages].filter((p) => p >= 1 && p <= last).sort((a, b) => a - b);
  const out: (number | null)[] = [];
  sorted.forEach((p, i) => {
    if (i > 0 && p - sorted[i - 1] > 1) out.push(null);
    out.push(p);
  });
  return out;
}

function AlertsPagination({
  alerts,
  total,
  filters,
  onFilterChange,
}: {
  alerts: Alert[];
  total: number;
  filters: AlertFilters;
  onFilterChange: (f: AlertFilters) => void;
}) {
  const page = filters.page || 1;
  const pageSize = filters.pageSize || 25;
  // Fall back to "is there a next page?" when the API omits a total.
  const lastPage = total > 0 ? Math.max(1, Math.ceil(total / pageSize)) : alerts.length < pageSize ? page : page + 1;
  const go = (p: number) => onFilterChange({ ...filters, page: Math.min(Math.max(1, p), lastPage) });
  const btn =
    'inline-flex h-6 min-w-6 items-center justify-center rounded-md border px-1.5 text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-40';

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-surface-border px-4 py-4 text-xs text-fg-muted">
      <nav aria-label="Pagination" className="flex items-center gap-1.5">
        <button
          type="button"
          onClick={() => go(page - 1)}
          disabled={page <= 1}
          aria-label="Previous page"
          className={clsx(btn, 'border-surface-border text-fg-muted hover:text-fg-primary')}
        >
          <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
        </button>
        {pageWindow(page, lastPage).map((p, i) =>
          p === null ? (
            <span key={`gap-${i}`} className={clsx(btn, 'border-surface-border')}>
              …
            </span>
          ) : (
            <button
              key={p}
              type="button"
              onClick={() => go(p)}
              aria-current={p === page ? 'page' : undefined}
              className={clsx(
                btn,
                p === page
                  ? 'border-teal-20/70 bg-teal-20/[0.15] text-teal-10'
                  : 'border-surface-border text-fg-muted hover:text-fg-primary',
              )}
            >
              {p}
            </button>
          ),
        )}
        <button
          type="button"
          onClick={() => go(page + 1)}
          disabled={page >= lastPage}
          aria-label="Next page"
          className={clsx(btn, 'border-surface-border text-fg-muted hover:text-fg-primary')}
        >
          <ChevronRight className="h-3.5 w-3.5" aria-hidden />
        </button>
      </nav>
      <div className="flex items-center gap-2">
        <span>Showing</span>
        <select
          aria-label="Alerts per page"
          value={pageSize}
          onChange={(e) => onFilterChange({ ...filters, pageSize: Number(e.target.value), page: 1 })}
          className="h-7 rounded-md border border-surface-border bg-surface-card pl-2 text-xs text-fg-secondary"
        >
          {PAGE_SIZES.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
        <span>
          of {total.toLocaleString('en-US')} {total === 1 ? 'entry' : 'entries'}
        </span>
      </div>
    </div>
  );
}
