'use client';

import { useState, useCallback } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import { alertsApi, type Alert, type AlertFilters, type ConfidenceLabel } from '@/lib/api';
import { clsx } from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import { EntityRiskQueue } from './EntityRiskQueue';
import { InvestigationRail } from './InvestigationRail';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';
import { SavedViewsBar } from '@/components/saved-views/SavedViewsBar';

// Wave 1 of the AiSOC v6 capability roadmap. The "entities" tab renders the
// rolled-up Risk-Based Alerting queue — alerts contribute time-decayed risk
// points to the entities they touch, and the queue surfaces those entities
// (not the raw alerts) to the analyst. The "alerts" tab keeps the legacy
// alert-centric grid for tenants that prefer it or have RBA disabled.
//
// v1.5 W6 — The alerts tab is now a two-pane layout: the dense grid on the
// left, an Investigation Rail on the right. Selecting a row populates the
// rail with the deterministic narrative + related entities + recent events +
// recommended actions envelope from `GET /alerts/{id}`. The legacy
// `ExplainDrawer` is no longer mounted from this view directly; it has been
// demoted to a "Deep Explain" button inside the rail itself, so analysts
// only burn an LLM call when they explicitly ask for it.
type ViewMode = 'entities' | 'alerts';

// ─── Config ───────────────────────────────────────────────────────────────────

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', dot: 'bg-red-500', text: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
  high: { label: 'High', dot: 'bg-orange-500', text: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
  medium: { label: 'Medium', dot: 'bg-yellow-500', text: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'Low', dot: 'bg-brand-500', text: 'text-brand-400', bg: 'bg-brand-500/10 border-brand-500/20' },
  info: { label: 'Info', dot: 'bg-gray-500', text: 'text-gray-400', bg: 'bg-gray-500/10 border-gray-500/20' },
};

const STATUS_CONFIG = {
  new: { label: 'New', color: 'text-purple-400 bg-purple-500/10 border-purple-500/20' },
  triaged: { label: 'Triaged', color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' },
  investigating: { label: 'Investigating', color: 'text-brand-400 bg-brand-500/10 border-brand-500/20' },
  resolved: { label: 'Resolved', color: 'text-green-400 bg-green-500/10 border-green-500/20' },
  false_positive: { label: 'False Positive', color: 'text-gray-400 bg-gray-500/10 border-gray-500/20' },
};

// ─── Sub-components ───────────────────────────────────────────────────────────

// Wave 1 — Detection confidence chip rendered inline in the alert grid so an
// analyst can spot low-confidence alerts at a glance without clicking through.
const CONFIDENCE_ROW_CONFIG: Record<ConfidenceLabel, { label: string; cls: string }> = {
  high: { label: 'HIGH', cls: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' },
  medium: { label: 'MED', cls: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'LOW', cls: 'text-gray-400 bg-gray-500/10 border-gray-500/20' },
};

function ConfidencePill({ label }: { label: ConfidenceLabel }) {
  const cfg = CONFIDENCE_ROW_CONFIG[label];
  return (
    <span
      className={clsx('text-[10px] font-mono font-medium px-1.5 py-0.5 rounded border shrink-0', cfg.cls)}
      title={`Detection confidence: ${cfg.label}`}
    >
      {cfg.label}
    </span>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.info;
  return <span className={clsx('w-2 h-2 rounded-full shrink-0', cfg.dot)} />;
}

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.info;
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded border', cfg.text, cfg.bg)}>
      {cfg.label}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.new;
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded border', cfg.color)}>
      {cfg.label}
    </span>
  );
}

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

  return (
    <div className="flex items-center gap-3 flex-wrap py-3 px-4 bg-dark-70/80 border border-[#374151]/60 rounded-xl">
      <div className="flex items-center gap-1">
        {severities.map((s) => (
          <button
            key={s}
            onClick={() => onChange({ ...filters, severity: s === 'all' ? undefined : s, page: 1 })}
            className={clsx(
              'text-xs px-2.5 py-1 rounded-lg transition-colors capitalize',
              (s === 'all' && !filters.severity) || filters.severity === s
                ? 'bg-brand-600 text-white'
                : 'text-gray-500 hover:text-gray-300 hover:bg-dark-20/60'
            )}
          >
            {s}
          </button>
        ))}
      </div>
      <div className="w-px h-4 bg-gray-700" />
      <div className="flex items-center gap-1">
        {statuses.map((s) => (
          <button
            key={s}
            onClick={() => onChange({ ...filters, status: s === 'all' ? undefined : s, page: 1 })}
            className={clsx(
              'text-xs px-2.5 py-1 rounded-lg transition-colors',
              (s === 'all' && !filters.status) || filters.status === s
                ? 'bg-gray-700 text-gray-200'
                : 'text-gray-500 hover:text-gray-300 hover:bg-dark-20/60'
            )}
          >
            {s === 'all' ? 'All status' : s.replace('_', ' ')}
          </button>
        ))}
      </div>
      <span className="ml-auto text-xs text-gray-600">{total} total</span>
    </div>
  );
}

// v1.5 W6 — AlertRow is now a *selection* affordance. Plain click selects the
// row (which populates the Investigation Rail to the right); modifier-clicks
// or middle-clicks still navigate to the full detail page so we don't break
// "open in new tab" muscle memory. The row gets a left-border highlight
// when selected so the analyst can see at a glance which alert the rail is
// describing.
function AlertRow({
  alert,
  selected,
  onSelect,
}: {
  alert: Alert;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <Link
      href={`/alerts/${alert.id}`}
      onClick={(e) => {
        // Modifier or middle-click → keep the native Link behaviour so
        // analysts can open the alert in a new tab/window. Only a plain
        // left-click is hijacked for in-pane selection.
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button === 1) return;
        e.preventDefault();
        onSelect(alert.id);
      }}
      aria-current={selected ? 'true' : undefined}
      className={clsx(
        'flex items-center gap-4 px-4 py-3 transition-colors border-b border-[#374151]/40 last:border-0 border-l-2',
        selected
          ? 'border-l-blue-500 bg-brand-500/5 hover:bg-brand-500/10'
          : 'border-l-transparent hover:bg-dark-20/20',
      )}
    >
      <SeverityDot severity={alert.severity} />

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <p className="text-sm text-gray-200 truncate hover:text-white">{alert.title}</p>
          {alert.mitreAttack && alert.mitreAttack.length > 0 && (
            <span className="text-xs bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded shrink-0">
              {alert.mitreAttack[0].techniqueId}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="text-xs text-gray-600">{alert.source}</span>
          {alert.assignee && (
            <>
              <span className="text-gray-700">·</span>
              <span className="text-xs text-gray-600">{alert.assignee}</span>
            </>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0">
        {alert.confidenceLabel && <ConfidencePill label={alert.confidenceLabel} />}
        <SeverityBadge severity={alert.severity} />
        <StatusBadge status={alert.status} />
        <span className="text-xs text-gray-600 w-24 text-right" suppressHydrationWarning>
          {formatDistanceToNow(new Date(alert.createdAt), { addSuffix: true })}
        </span>
      </div>
    </Link>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

export function AlertsView() {
  const [filters, setFilters] = useState<AlertFilters>({ page: 1, pageSize: 25 });
  // Default to the entity-centric queue — that's the whole point of Wave 1's
  // RBA work. Analysts can flip back to the raw alert grid for legacy
  // workflows or when triaging a specific alert ID.
  const [viewMode, setViewMode] = useState<ViewMode>('entities');

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

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Alerts</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {viewMode === 'entities'
              ? 'Risk-Based Alerting · entity-centric triage queue'
              : 'Real-time security event monitoring and triage'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div
            role="tablist"
            aria-label="View mode"
            className="inline-flex items-center bg-dark-60 border border-[#374151]/60 rounded-lg p-0.5"
          >
            <button
              type="button"
              role="tab"
              aria-selected={viewMode === 'entities'}
              onClick={() => setViewMode('entities')}
              className={clsx(
                'text-xs px-3 py-1.5 rounded-md transition-colors',
                viewMode === 'entities'
                  ? 'bg-brand-600 text-white'
                  : 'text-gray-400 hover:text-gray-200',
              )}
            >
              Entities
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={viewMode === 'alerts'}
              onClick={() => setViewMode('alerts')}
              className={clsx(
                'text-xs px-3 py-1.5 rounded-md transition-colors',
                viewMode === 'alerts'
                  ? 'bg-gray-700 text-gray-100'
                  : 'text-gray-400 hover:text-gray-200',
              )}
            >
              Alerts
            </button>
          </div>
          <div className="flex items-center gap-2">
            <button
              disabled
              title="Manual alert creation is planned for v1.1"
              className="bg-gray-700 text-gray-400 text-sm px-4 py-2 rounded-lg cursor-not-allowed select-none"
            >
              + Create Alert
            </button>
            <span className="text-xs font-medium rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 px-2 py-0.5">
              Planned for v1.1
            </span>
          </div>
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
  // v1.5 W6 — Selection lives at the AlertsTable level (not AlertsView)
  // because the rail is only rendered inside the "alerts" view mode.
  // Switching to the entities tab unmounts this state cleanly, which is
  // what we want — the rail is alert-scoped, not entity-scoped.
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);

  return (
    <div className="space-y-4">
      {/* Stats strip (full width) */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total', value: total, color: 'text-gray-200' },
          { label: 'Critical', value: critCount, color: 'text-red-400' },
          { label: 'High', value: highCount, color: 'text-orange-400' },
          { label: 'Unresolved', value: newCount, color: 'text-purple-400' },
        ].map((stat) => (
          <div key={stat.label} className="bg-dark-60 border border-[#374151]/60 rounded-xl px-4 py-3">
            <p className="text-xs text-gray-500">{stat.label}</p>
            <p className={clsx('text-2xl font-bold mt-1', stat.color)}>{stat.value}</p>
          </div>
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

      {/*
        v1.5 W6 — two-pane layout. On wide screens the queue takes the left
        seven cols and the Investigation Rail takes the right five; on narrow
        screens they stack so the rail sits beneath the queue rather than
        squeezing the columns into illegibility. The rail is `sticky` so it
        stays in view while the analyst scrolls the queue.
      */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        <div className="xl:col-span-7 space-y-4">
          <AlertsTableGrid
            alerts={alerts}
            isLoading={isLoading}
            error={error}
            filters={filters}
            selectedAlertId={selectedAlertId}
            onSelect={setSelectedAlertId}
            onFilterChange={onFilterChange}
          />
          <AlertsPagination
            alerts={alerts}
            total={total}
            filters={filters}
            onFilterChange={onFilterChange}
          />
        </div>
        <div className="xl:col-span-5">
          <div className="xl:sticky xl:top-4 xl:max-h-[calc(100vh-7rem)] xl:overflow-hidden xl:flex xl:flex-col">
            <InvestigationRail
              alertId={selectedAlertId}
              onClose={() => setSelectedAlertId(null)}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Queue grid (split out from AlertsTable so the two-pane shell stays lean) ─

function AlertsTableGrid({
  alerts,
  isLoading,
  error,
  filters,
  selectedAlertId,
  onSelect,
  onFilterChange,
}: {
  alerts: Alert[];
  isLoading: boolean;
  error: unknown;
  filters: AlertFilters;
  selectedAlertId: string | null;
  onSelect: (id: string) => void;
  onFilterChange: (f: AlertFilters) => void;
}) {
  return (
    <div className="bg-dark-60 border border-[#374151]/60 rounded-xl overflow-hidden">
      <div className="flex items-center px-4 py-2 border-b border-[#374151]/60 bg-dark-70/80">
        <span className="text-xs text-gray-500 flex-1 pl-2">ALERT</span>
        <span className="text-xs text-gray-500 w-20">SEVERITY</span>
        <span className="text-xs text-gray-500 w-24">STATUS</span>
        <span className="text-xs text-gray-500 w-24 text-right">TIME</span>
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
          {filters.severity || filters.status ? (
            <EmptyState
              icon={EmptyStateIcons.search}
              title="No alerts match these filters"
              description="Try clearing the severity or status filter to widen the search."
              action={
                <button
                  onClick={() => onFilterChange({ page: 1, pageSize: filters.pageSize ?? 25 })}
                  className="text-xs px-3 py-1.5 rounded-md border border-brand-500/40 bg-brand-500/10 text-brand-300 hover:bg-brand-500/20 transition-colors"
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
        <div>
          {alerts.map((alert) => (
            <AlertRow
              key={alert.id}
              alert={alert}
              selected={selectedAlertId === alert.id}
              onSelect={onSelect}
            />
          ))}
        </div>
      )}
    </div>
  );
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
  return (
    <div className="flex items-center justify-between text-xs text-gray-500">
      <span>Showing {alerts.length} of {total} alerts</span>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onFilterChange({ ...filters, page: Math.max(1, (filters.page || 1) - 1) })}
          disabled={(filters.page || 1) <= 1}
          className="px-2 py-1 rounded bg-dark-20 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Prev
        </button>
        <span className="px-2">Page {filters.page || 1}</span>
        <button
          onClick={() => onFilterChange({ ...filters, page: (filters.page || 1) + 1 })}
          disabled={alerts.length < (filters.pageSize || 25)}
          className="px-2 py-1 rounded bg-dark-20 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Next
        </button>
      </div>
    </div>
  );
}
