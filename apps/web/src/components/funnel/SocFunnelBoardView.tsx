'use client';

/**
 * SOC Funnel Board — live stage tracking for the product path
 * Ingested → Triaged / Suppressed → Investigating → Cased → Ready for Jira → Jira.
 *
 * Layout (light dashboard design): window stats, a selectable grid of the
 * funnel stages, and the selected stage's alerts (one representative per
 * title, with how many share it) as a severity-filterable table.
 */

import { useMemo, useState, type ReactNode } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import { clsx } from 'clsx';
import { format } from 'date-fns';
import {
  BookOpenCheck,
  CheckCheck,
  ChevronLeft,
  ChevronRight,
  Clock,
  Copy,
  Database,
  EyeOff,
  Folder,
  History,
  RotateCcw,
  ScanSearch,
  Search,
  Send,
  type LucideIcon,
} from 'lucide-react';
import { socFunnelApi, type FunnelBoardAlert, type FunnelBoardStage } from '@/lib/api';
import { Card, StatTile } from '@/components/dashboard/ui';

const TASK_BADGE: Record<string, { label: string; className: string }> = {
  manual_review: {
    label: 'needs review',
    className: 'border-[#F2BD57]/70 bg-[#F2BD57]/10 text-[#D99A1E]',
  },
  approval_gate: {
    label: 'approval',
    className: 'border-[#F98B3E]/70 bg-[#F98B3E]/10 text-[#F98B3E]',
  },
  mssp_sla_check: {
    label: 'SLA',
    className: 'border-[#7B5EE6]/70 bg-[#7B5EE6]/10 text-[#7B5EE6]',
  },
};

/** Icon + accent per stage (light dashboard design). */
const STAGE_STYLE: Record<string, { icon: LucideIcon; hex: string }> = {
  ingested: { icon: Database, hex: '#3163CF' },
  triaged: { icon: ScanSearch, hex: '#4FD2C2' },
  suppressed: { icon: EyeOff, hex: '#7B5EE6' },
  deduplicated: { icon: Copy, hex: '#4FD2C2' },
  investigating: { icon: Search, hex: '#F2BD57' },
  cased: { icon: Folder, hex: '#F98B3E' },
  ready_for_jira: { icon: Send, hex: '#4FD2C2' },
  jira_pushed: { icon: CheckCheck, hex: '#4ADE80' },
};

const SEVERITY_HEX: Record<string, { hex: string; text?: string; label: string }> = {
  critical: { hex: '#FD4E4E', label: 'Critical' },
  high: { hex: '#F98B3E', label: 'High' },
  medium: { hex: '#F2BD57', text: '#D99A1E', label: 'Med' },
  low: { hex: '#939DAD', label: 'Low' },
  info: { hex: '#939DAD', label: 'Info' },
};

const SEVERITY_TABS = ['all', 'critical', 'high', 'medium', 'low'] as const;
type SeverityTab = (typeof SEVERITY_TABS)[number];

const WINDOWS: { hours: number; label: string }[] = [
  { hours: 24, label: '24h' },
  { hours: 48, label: '48h' },
  { hours: 168, label: '7d' },
  { hours: 720, label: '30d' },
];

const PAGE_SIZES = [7, 10, 25];

/** Stages where the primary object is the case, not the alert row. */
const CASE_LINK_STAGES = new Set(['cased', 'ready_for_jira', 'jira_pushed']);

function alertCardHref(stageId: string, alert: FunnelBoardAlert): string {
  if (CASE_LINK_STAGES.has(stageId) && alert.case_id) {
    return `/cases/${alert.case_id}`;
  }
  return `/alerts/${alert.id}`;
}

function stageListHref(stageId: string): string {
  if (CASE_LINK_STAGES.has(stageId)) {
    return '/cases';
  }
  return `/alerts?funnel_stage=${encodeURIComponent(stageId)}`;
}

const compact = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });

function sevKey(severity: string): string {
  const s = (severity || '').toLowerCase();
  return s in SEVERITY_HEX ? s : 'info';
}

// ─── Stage selector card ──────────────────────────────────────────────────────

function StageCard({
  stage,
  selected,
  onSelect,
}: {
  stage: FunnelBoardStage;
  selected: boolean;
  onSelect: () => void;
}) {
  const style = STAGE_STYLE[stage.id] ?? { icon: Database, hex: '#939DAD' };
  const Icon = style.icon;
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={clsx(
        'flex min-w-0 items-start gap-3 rounded-2xl border px-4 py-4 text-left transition-colors',
        selected
          ? 'border-teal-20/80 bg-teal-20/[0.12]'
          : 'border-surface-border bg-surface-card hover:border-teal-20/40',
      )}
    >
      <span
        aria-hidden
        className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full"
        style={{ backgroundColor: `${style.hex}26`, color: style.hex }}
      >
        <Icon className="h-4 w-4" strokeWidth={1.75} />
      </span>
      <span className="min-w-0">
        <span className="block truncate text-[13px] font-gilroy-semibold text-fg-primary">{stage.label}</span>
        <span className="mt-1.5 block text-xs text-fg-muted" title={`${stage.count} alerts`}>
          {stage.count > 0 ? compact.format(stage.count) : 'No alerts in window'}
        </span>
        {(stage.open_tasks ?? 0) > 0 ? (
          <span
            className="mt-1 block text-[11px] text-[#D99A1E]"
            title="These alerts are waiting on an analyst in the Runbook — that is what is holding this stage up."
          >
            {stage.open_tasks} waiting on an analyst
          </span>
        ) : null}
      </span>
    </button>
  );
}

// ─── Selected stage table ─────────────────────────────────────────────────────

const ROW_GRID =
  'grid grid-cols-[minmax(200px,1.6fr)_72px_minmax(110px,0.8fr)_96px_96px_112px] items-center gap-x-4';

function AlertRow({ stageId, alert }: { stageId: string; alert: FunnelBoardAlert }) {
  const copies = alert.same_title_count ?? 1;
  const tasks = alert.open_tasks ?? [];
  const href = alertCardHref(stageId, alert);
  const opensCase = href.startsWith('/cases/');
  const sev = SEVERITY_HEX[sevKey(alert.severity)];
  let lastSeen = '—';
  let lastSeenTitle: string | undefined;
  if (alert.created_at) {
    try {
      const d = new Date(alert.created_at);
      lastSeen = format(d, 'HH:mm:ss');
      lastSeenTitle = format(d, 'PPpp');
    } catch {
      lastSeen = alert.created_at;
    }
  }
  return (
    <div className={clsx(ROW_GRID, 'border-b border-surface-border px-4 py-3 last:border-0 hover:bg-surface-subtle')}>
      <div className="flex min-w-0 items-start gap-2.5">
        <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: sev.hex }} />
        <div className="min-w-0">
          <Link
            href={href}
            className="block truncate text-[13px] text-fg-primary hover:text-teal-10"
            title={opensCase ? 'Open case' : 'Open alert'}
          >
            {alert.title}
          </Link>
          {/* The reason this alert is stuck, and the way out of it. */}
          <div className="mt-1 flex flex-wrap items-center gap-1.5 empty:hidden">
            {opensCase ? <span className="text-[10px] text-fg-subtle">case</span> : null}
            {tasks.map((task) => {
              const badge = TASK_BADGE[task.task_type] ?? TASK_BADGE.manual_review;
              return (
                <span
                  key={`${task.task_type}-${task.title}`}
                  title={task.title}
                  className={`rounded-md border px-1.5 py-[1px] text-[10px] ${badge.className}`}
                >
                  {badge.label}
                </span>
              );
            })}
          </div>
        </div>
      </div>
      <span>
        <span
          className="inline-flex items-center rounded-md border px-2 py-[3px] text-[11px] leading-none"
          style={{ borderColor: `${sev.hex}B3`, backgroundColor: `${sev.hex}1F`, color: sev.text ?? sev.hex }}
        >
          {sev.label}
        </span>
      </span>
      <span className="truncate text-xs capitalize text-fg-secondary">
        {(alert.disposition ?? alert.status ?? '—').replace(/_/g, ' ')}
      </span>
      <span
        className={clsx('text-xs tabular-nums', copies > 1 ? 'text-fg-primary' : 'text-fg-muted')}
        title={`${copies} alert${copies === 1 ? '' : 's'} share this title in this stage`}
      >
        {copies > 1 ? `×${copies.toLocaleString('en-US')}` : '1'}
      </span>
      <span className="text-xs tabular-nums text-fg-secondary" title={lastSeenTitle} suppressHydrationWarning>
        {lastSeen}
      </span>
      <div className="flex items-center justify-end gap-3">
        <Link
          href={`/runbook/alert/${alert.id}`}
          className="text-[11px] text-fg-muted hover:text-teal-10"
          title="Open this alert's Runbook: procedure, ledger, and the task blocking it"
        >
          Runbook →
        </Link>
        <Link
          href={href}
          aria-label={opensCase ? 'Open case' : 'Open alert'}
          className="text-fg-subtle hover:text-teal-10"
        >
          <ChevronRight className="h-4 w-4" aria-hidden />
        </Link>
      </div>
    </div>
  );
}

function StageTable({ stage, alerts }: { stage: FunnelBoardStage | undefined; alerts: FunnelBoardAlert[] }) {
  const [tab, setTab] = useState<SeverityTab>('all');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(PAGE_SIZES[0]);
  // Paging/filter reset per stage via the `key` the parent passes.

  const counts = useMemo(() => {
    const c: Record<SeverityTab, number> = { all: 0, critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of alerts) {
      const n = a.same_title_count ?? 1;
      c.all += n;
      const k = sevKey(a.severity);
      if (k in c) c[k as SeverityTab] += n;
    }
    return c;
  }, [alerts]);

  const filtered = tab === 'all' ? alerts : alerts.filter((a) => sevKey(a.severity) === tab);
  const lastPage = Math.max(1, Math.ceil(filtered.length / pageSize));
  const current = Math.min(page, lastPage);
  const rows = filtered.slice((current - 1) * pageSize, current * pageSize);
  const listed = alerts.reduce((n, a) => n + (a.same_title_count ?? 1), 0);

  if (!stage) return null;
  const listHref = stageListHref(stage.id);

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {SEVERITY_TABS.map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => {
              setTab(t);
              setPage(1);
            }}
            aria-pressed={tab === t}
            className={clsx(
              'h-[38px] rounded-full border px-4 text-xs capitalize transition-colors',
              tab === t
                ? 'border-teal-20/70 bg-teal-20/[0.12] text-teal-10'
                : 'border-surface-border bg-surface-card text-fg-secondary hover:text-fg-primary',
            )}
          >
            {t} ({compact.format(counts[t])})
          </button>
        ))}
        <Link
          href={listHref}
          className="ml-auto text-xs text-fg-muted hover:text-teal-10"
          title={
            CASE_LINK_STAGES.has(stage.id)
              ? `Open cases (${stage.count} alerts in this stage)`
              : `Open all ${stage.count} alerts in Alerts`
          }
        >
          View all {stage.count.toLocaleString('en-US')} in {stage.label} →
        </Link>
      </div>

      <div className="overflow-hidden rounded-2xl border border-surface-border">
        <div className="overflow-x-auto">
          <div className="min-w-[760px]">
            <div className={clsx(ROW_GRID, 'border-b border-surface-border px-4 py-3 text-xs text-fg-secondary')}>
              <span>Alert</span>
              <span>Severity</span>
              <span>Disposition</span>
              <span>Occurrences</span>
              <span>Last seen</span>
              <span className="text-right">Detail</span>
            </div>
            {rows.length === 0 ? (
              <p className="px-4 py-8 text-center text-xs text-fg-muted">
                {alerts.length === 0 ? 'No alerts in window' : 'No alerts with this severity in this stage.'}
              </p>
            ) : (
              rows.map((alert) => <AlertRow key={alert.id} stageId={stage.id} alert={alert} />)
            )}
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-surface-border px-4 py-3 text-xs text-fg-muted">
          <nav aria-label="Pagination" className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setPage(current - 1)}
              disabled={current <= 1}
              aria-label="Previous page"
              className="inline-flex h-6 w-6 items-center justify-center rounded-md border border-surface-border disabled:opacity-40"
            >
              <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
            </button>
            {Array.from({ length: lastPage }, (_, i) => i + 1).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setPage(p)}
                aria-current={p === current ? 'page' : undefined}
                className={clsx(
                  'inline-flex h-6 min-w-6 items-center justify-center rounded-md border px-1.5 text-[11px]',
                  p === current
                    ? 'border-teal-20/70 bg-teal-20/[0.15] text-teal-10'
                    : 'border-surface-border hover:text-fg-primary',
                )}
              >
                {p}
              </button>
            ))}
            <button
              type="button"
              onClick={() => setPage(current + 1)}
              disabled={current >= lastPage}
              aria-label="Next page"
              className="inline-flex h-6 w-6 items-center justify-center rounded-md border border-surface-border disabled:opacity-40"
            >
              <ChevronRight className="h-3.5 w-3.5" aria-hidden />
            </button>
          </nav>
          <div className="flex items-center gap-2">
            <span>Showing</span>
            <select
              aria-label="Rows per page"
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(1);
              }}
              className="h-7 rounded-md border border-surface-border bg-surface-card pl-2 text-xs text-fg-secondary"
            >
              {PAGE_SIZES.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
            <span>
              of {filtered.length} title{filtered.length === 1 ? '' : 's'}
              {listed < stage.count ? ` · ${stage.count.toLocaleString('en-US')} alerts total` : ''}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

const ACTION_PILL =
  'inline-flex h-[42px] items-center gap-2 whitespace-nowrap rounded-full border px-3.5 text-[13px] font-gilroy-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50';

export function SocFunnelBoardView() {
  const [hours, setHours] = useState(24);
  const [backfillMsg, setBackfillMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [selectedStage, setSelectedStage] = useState<string | null>(null);

  const { data, error, isLoading, mutate } = useSWR(
    ['soc-funnel-board', hours],
    () => socFunnelApi.board(hours),
    { refreshInterval: 30_000 },
  );

  const runBackfill = async () => {
    setBusy(true);
    setBackfillMsg(null);
    try {
      const result = await socFunnelApi.backfill(hours);
      const synced = result.stages_updated ?? 0;
      const deduped = Number(
        result.dedupe?.alerts_deduplicated ?? result.dedupe?.alerts_deleted ?? 0,
      );
      setBackfillMsg(
        `Scanned ${result.alerts_scanned}: FP ${result.false_positive_tagged}, cases ${result.cases_created}, linked ${result.alerts_linked}, stages synced ${synced}, deduplicated ${deduped}`,
      );
      await mutate();
    } catch (err) {
      setBackfillMsg(err instanceof Error ? err.message : 'Backfill failed');
    } finally {
      setBusy(false);
    }
  };

  const runDedupe = async () => {
    setBusy(true);
    setBackfillMsg(null);
    try {
      const result = await socFunnelApi.dedupeExact(false);
      const alertMoved =
        result.alerts.alerts_deduplicated ?? result.alerts.alerts_deleted ?? 0;
      setBackfillMsg(
        `Alert occurrence — alerts: ${alertMoved} marked as occurrences ` +
          `(${result.alerts.groups_collapsed} groups), cases: ${result.cases.cases_deleted} merged ` +
          `(${result.cases.groups_collapsed} groups)`,
      );
      await mutate();
    } catch (err) {
      setBackfillMsg(err instanceof Error ? err.message : 'Dedupe failed');
    } finally {
      setBusy(false);
    }
  };

  const runReenrichSplunk = async () => {
    setBusy(true);
    setBackfillMsg(null);
    try {
      const result = await socFunnelApi.reenrichSplunk({ limit: 500, force: true });
      setBackfillMsg(
        `Splunk re-enrich — scanned ${result.scanned}, enriched ${result.enriched}, ` +
          `skipped ${result.skipped}, failed ${result.failed}, cases updated ${result.cases_updated}`,
      );
      await mutate();
    } catch (err) {
      setBackfillMsg(err instanceof Error ? err.message : 'Splunk re-enrich failed');
    } finally {
      setBusy(false);
    }
  };

  const stages = useMemo(() => data?.stages ?? [], [data]);
  const samples = useMemo(() => data?.samples_by_stage ?? {}, [data]);

  // Default to the first stage that has alerts to show; keep the analyst's
  // choice once they pick one.
  const activeStageId = useMemo(() => {
    if (selectedStage && stages.some((s) => s.id === selectedStage)) return selectedStage;
    return (
      stages.find((s) => (samples[s.id] ?? []).length > 0)?.id ??
      stages.find((s) => s.count > 0)?.id ??
      stages[0]?.id ??
      null
    );
  }, [selectedStage, stages, samples]);
  const activeStage = stages.find((s) => s.id === activeStageId);

  const actionButton = (label: string, icon: ReactNode, onClick: () => void, tone: string, title?: string) => (
    <button type="button" disabled={busy} onClick={onClick} className={clsx(ACTION_PILL, tone)} title={title}>
      {icon}
      {busy ? 'Running…' : label}
    </button>
  );

  return (
    <div className="flex flex-col gap-5">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <h1 className="text-[26px] leading-tight font-gilroy-semibold text-fg-primary">SOC Funnel</h1>
          <p className="mt-2 max-w-[420px] text-xs leading-relaxed text-fg-secondary">
            Track alerts from ingest through triage → investigation → case → gated Jira.
            Triage decides if investigation is worth it; Ready for Jira needs evidence, not every TP.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className={clsx(ACTION_PILL, 'border-surface-border bg-surface-card pr-1 text-fg-secondary')}>
            <Clock className="h-4 w-4 shrink-0" strokeWidth={1.5} aria-hidden />
            <select
              aria-label="Time range"
              value={hours}
              onChange={(e) => setHours(Number(e.target.value))}
              className="h-full cursor-pointer appearance-none rounded-full bg-transparent pl-0 text-[13px] font-gilroy-medium text-fg-secondary focus:outline-none"
            >
              {WINDOWS.map((w) => (
                <option key={w.hours} value={w.hours}>
                  Time range · {w.label}
                </option>
              ))}
            </select>
          </label>
          <Link
            href="/runbook?tab=action-plan"
            aria-label="Open Runbook"
            className="inline-flex h-[42px] w-[42px] items-center justify-center rounded-full border border-surface-border bg-surface-card text-fg-secondary transition-colors hover:text-teal-10"
            title="Open Runbook — the analyst queue: every task that is holding an alert in this funnel"
          >
            <BookOpenCheck className="h-[18px] w-[18px]" strokeWidth={1.5} aria-hidden />
          </Link>
          {actionButton(
            'Run Backfill',
            <History className="h-4 w-4" strokeWidth={1.5} aria-hidden />,
            () => void runBackfill(),
            'border-surface-border bg-surface-card text-fg-secondary hover:text-fg-primary',
          )}
          {actionButton(
            'Remove Duplicates',
            <Copy className="h-4 w-4" strokeWidth={1.5} aria-hidden />,
            () => void runDedupe(),
            'border-[#FD4E4E]/60 bg-[#FD4E4E]/10 text-[#FD4E4E] hover:bg-[#FD4E4E]/15',
            'Collapse same logical alert (entity-aware, 15m window) into Alert occurrence; auto-runs on board load',
          )}
          {actionButton(
            'Re-enrich Splunk',
            <RotateCcw className="h-4 w-4" strokeWidth={1.5} aria-hidden />,
            () => void runReenrichSplunk(),
            'border-surface-border bg-surface-card text-fg-secondary hover:text-fg-primary',
            'Re-fetch annotations_mitre_attack and other wide Splunk fields onto existing alerts/cases',
          )}
        </div>
      </header>

      {data ? (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatTile label="Alerts in window" value={data.alerts_total.toLocaleString('en-US')} />
          <StatTile
            label="Suppression rate"
            value={`${Math.round((data.ratios.suppression_rate || 0) * 100)}%`}
          />
          <StatTile
            label="Ready / pushed"
            value={`${Math.round((data.ratios.ready_for_jira_rate || 0) * 100)}%`}
          />
          <StatTile label="Window" value={`${data.window_hours}h`} />
        </div>
      ) : null}

      {backfillMsg ? (
        <p className="rounded-2xl border border-surface-border bg-surface-card px-4 py-3 text-xs text-fg-secondary">
          {backfillMsg}
        </p>
      ) : null}

      {error ? (
        <div className="rounded-2xl border border-red-500/30 bg-red-500/5 px-4 py-3">
          <p className="text-sm text-[#FD4E4E]">Failed to load funnel board.</p>
          <p className="text-xs text-fg-muted font-mono mt-1 break-all">
            {error instanceof Error ? error.message : String(error)}
          </p>
          <p className="text-[11px] text-fg-subtle mt-1">
            If this is 404, rebuild/recreate the API container on the latest commit.
          </p>
        </div>
      ) : null}
      {isLoading && !data ? (
        <p className="text-sm text-fg-muted">Loading funnel stages…</p>
      ) : null}

      {stages.length > 0 ? (
        <Card className="p-6">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {stages.map((stage) => (
              <StageCard
                key={stage.id}
                stage={stage}
                selected={stage.id === activeStageId}
                onSelect={() => setSelectedStage(stage.id)}
              />
            ))}
          </div>
        </Card>
      ) : null}

      {activeStage ? (
        <Card className="p-6">
          <StageTable key={activeStage.id} stage={activeStage} alerts={samples[activeStage.id] || []} />
          <p className="mt-4 text-xs leading-relaxed text-fg-secondary">
            Ready for Jira requires Case + TP/escalate plus an evidence bar: high/critical
            severity, or medium with confidence ≥70% and rule/MITRE metadata, or investigation
            summary — not every heuristic true_positive. needs_review needs analyst approval.
          </p>
        </Card>
      ) : null}
    </div>
  );
}
