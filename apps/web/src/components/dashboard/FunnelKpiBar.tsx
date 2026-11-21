'use client';

/**
 * FunnelKpiBar
 * ============
 * Seven-tile KPI strip that mirrors the reference SOC console's funnel widget.
 *
 * Tiles, left to right:
 *   1. Events of Interest          (24h delta)
 *   2. Correlation Instances       (24h delta)
 *   3. Alerts Generated            (24h delta)
 *   4. Signal / Noise              (24h delta — higher is better)
 *   5. MTTD                        (24h delta — lower is better)
 *   6. Analyst Queue Depth         (24h delta — lower is better)
 *   7. Triage Automation           (no delta — dedup share of triaged alerts)
 *
 * Data source: `GET /api/v1/metrics/funnel?period=…` ({@link metricsApi.getFunnel}).
 * Polls every 60 s with stale-while-revalidate.
 *
 * Author: Beenu Arora <beenu@cyble.com>
 */

import type { ReactNode } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { ArrowDown, ArrowUp, Bell, RefreshCw, Timer, Users } from 'lucide-react';
import { metricsApi, type FunnelMetrics } from '@/lib/api';
import { Card, CardHeader, IconBadge, Pill, type AccentName } from './ui';

type Period = '1h' | '24h' | '7d' | '30d';

interface FunnelKpiBarProps {
  /** Time window for the funnel. Defaults to `24h` (matches DashboardView). */
  period?: Period;
  /** Override the SWR cache key — useful when multiple bars coexist. */
  cacheKey?: string;
}

interface TileProps {
  label: string;
  value: string;
  delta: number | null;
  /**
   * When `true`, a *negative* delta is rendered green (good) and positive is red
   * (worse). When `false`, positive is green. Mirrors the reference console's
   * coloring for MTTD / Queue (lower-is-better) vs Events / Alerts.
   */
  lowerIsBetter?: boolean;
  /** Tiny note under the value (e.g. "events", "alerts/sec"). */
  unit?: string;
  accent: AccentName;
  icon?: ReactNode;
}

const BELL = <Bell className="h-4 w-4" strokeWidth={1.75} />;

function formatNumber(n: number): string {
  if (!Number.isFinite(n)) return '—';
  if (Math.abs(n) >= 1_000_000)
    return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
  if (Math.abs(n) >= 1_000)
    return `${(n / 1_000).toFixed(1).replace(/\.0$/, '')}k`;
  return String(Math.round(n));
}

function formatDurationSeconds(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return '—';
  if (sec < 60) return `${Math.round(sec)}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  return `${(sec / 3600).toFixed(1).replace(/\.0$/, '')}h`;
}

function formatPercent(ratio: number): string {
  if (!Number.isFinite(ratio)) return '—';
  return `${(ratio * 100).toFixed(1).replace(/\.0$/, '')}%`;
}

function formatDelta(delta: number | null): string {
  if (delta === null || !Number.isFinite(delta)) return '—';
  const pct = delta * 100;
  const rounded = Math.abs(pct) >= 10 ? Math.round(pct) : pct.toFixed(1);
  const sign = pct > 0 ? '+' : pct < 0 ? '−' : '';
  return `${sign}${Math.abs(Number(rounded))}%`;
}

function Tile({ label, value, delta, lowerIsBetter = false, unit, accent, icon = BELL }: TileProps) {
  const isGood =
    delta === null || delta === 0
      ? null
      : lowerIsBetter
        ? delta < 0
        : delta > 0;
  const deltaColor =
    isGood === null
      ? 'text-fg-muted'
      : isGood
        ? 'text-teal-20'
        : 'text-[#FD4E4E]';
  const DeltaArrow = delta !== null && delta < 0 ? ArrowDown : delta !== null && delta > 0 ? ArrowUp : null;

  return (
    <div className="rounded-2xl border border-surface-border bg-surface-card p-5 min-w-0">
      <IconBadge accent={accent} size={32}>{icon}</IconBadge>
      <p className="mt-4 text-sm leading-tight text-fg-muted">
        {label}
      </p>
      <p className="text-xl font-gilroy-semibold text-fg-primary mt-3 tabular-nums truncate">
        {value}
      </p>
      <div className={clsx('flex items-center gap-1 mt-2', deltaColor)}>
        {DeltaArrow && <DeltaArrow className="h-3 w-3 shrink-0" aria-hidden />}
        <span className="text-xs tabular-nums">
          {formatDelta(delta)}
        </span>
        {unit && <span className="text-xs truncate">{unit}</span>}
      </div>
    </div>
  );
}

function LoadingTile({ label }: { label: string }) {
  return (
    <div className="rounded-2xl border border-surface-border bg-surface-card p-5 min-w-0">
      <span className="block h-8 w-8 rounded-full bg-dark-20/60 animate-pulse" />
      <p className="mt-4 text-sm text-fg-muted truncate">
        {label}
      </p>
      <div className="mt-2 h-7 w-20 rounded bg-dark-20/60 animate-pulse" />
      <div className="mt-2 h-3 w-12 rounded bg-dark-20/40 animate-pulse" />
    </div>
  );
}

const TILE_LABELS = [
  'Events of Interest',
  'Correlation Instances',
  'Alerts Generated',
  'Signal / Noise',
  'MTTD',
  'Analyst Queue',
  'Triage Automation',
] as const;

const TILE_GRID = 'grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 2xl:grid-cols-7 gap-4';

export function FunnelKpiBar({
  period = '24h',
  cacheKey,
}: FunnelKpiBarProps = {}) {
  const key = cacheKey ?? `funnel-metrics:${period}`;
  const { data, error, isLoading } = useSWR<FunnelMetrics>(
    key,
    () => metricsApi.getFunnel(period),
    {
      refreshInterval: 60_000,
      revalidateOnFocus: false,
      revalidateOnMount: true,
      shouldRetryOnError: true,
      errorRetryCount: 3,
      errorRetryInterval: 4000,
    },
  );

  // Error takes priority over loading and stale data. Without this ordering
  // the loading branch wins after a failure and the user stares at skeleton
  // tiles forever; if we let stale data through silently, the analyst sees
  // confidently-rendered numbers that may be hours old. Bias toward making
  // the failure visible — SWR will keep retrying every 4s underneath.
  if (error) {
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    return (
      <Card className="p-6">
        <CardHeader
          title="Operations Funnel"
          subtitle="Live tenant pipeline: events → correlations → alerts"
          action={<Pill>Last {period}</Pill>}
          className="mb-5"
        />
        <div className="rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          <p className="font-semibold">Funnel metrics unavailable</p>
          <p className="mt-1 text-xs text-red-300/80">{errorMessage}</p>
          <p className="mt-1 text-xs text-red-300/60">
            SWR will keep retrying every 4s; refresh the page if it persists.
          </p>
        </div>
      </Card>
    );
  }

  if (isLoading || !data) {
    return (
      <Card className="p-6">
        <CardHeader
          title="Operations Funnel"
          subtitle="Live tenant pipeline: events → correlations → alerts"
          action={<Pill>Last {period}</Pill>}
          className="mb-5"
        />
        <div className={TILE_GRID}>
          {TILE_LABELS.map((l) => (
            <LoadingTile key={l} label={l} />
          ))}
        </div>
      </Card>
    );
  }

  const { deltas, triage } = data;
  const triageTotal = triage?.total ?? 0;
  const triageReused = triage ? triage.deduplicated + triage.suppressed : 0;

  return (
    <Card className="p-6">
      <CardHeader
        title="Operations Funnel"
        subtitle="Live tenant pipeline: events → correlations → alerts"
        action={<Pill>Last {period}</Pill>}
        className="mb-5"
      />

      <div className={TILE_GRID}>
        <Tile
          label="Events of Interest"
          value={formatNumber(data.events_of_interest)}
          delta={deltas.events_of_interest}
          unit="events"
          accent="blue"
        />
        <Tile
          label="Correlation Instances"
          value={formatNumber(data.correlation_instances)}
          delta={deltas.correlation_instances}
          unit="groups"
          accent="purple"
        />
        <Tile
          label="Alerts Generated"
          value={formatNumber(data.alerts_generated)}
          delta={deltas.alerts_generated}
          unit="alerts"
          accent="green"
        />
        <Tile
          label="Signal / Noise"
          value={formatPercent(data.signal_to_noise)}
          delta={deltas.signal_to_noise}
          unit="of dispositioned"
          accent="yellow"
        />
        <Tile
          label="MTTD"
          value={formatDurationSeconds(data.mttd_seconds)}
          delta={deltas.mttd_seconds}
          lowerIsBetter
          unit="to first-seen"
          accent="teal"
          icon={<Timer className="h-4 w-4" strokeWidth={1.75} />}
        />
        <Tile
          label="Analyst Queue"
          value={formatNumber(data.analyst_queue_depth)}
          delta={deltas.analyst_queue_depth}
          lowerIsBetter
          unit="open"
          accent="violet"
          icon={<Users className="h-4 w-4" strokeWidth={1.75} />}
        />
        <Tile
          label="Triage Automation"
          value={triageTotal > 0 ? formatPercent(triage?.dedup_rate ?? 0) : '—'}
          delta={null}
          unit={
            triageTotal > 0
              ? `${formatNumber(triageReused)}/${formatNumber(triageTotal)} from cache`
              : 'no triage runs'
          }
          accent="teal"
          icon={<RefreshCw className="h-4 w-4" strokeWidth={1.75} />}
        />
      </div>
    </Card>
  );
}

export default FunnelKpiBar;
