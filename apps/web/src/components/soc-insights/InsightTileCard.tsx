/**
 * Single tile on the SOC Insights dashboard (T3.1).
 *
 * Pure presentational — takes the typed payload from the aggregator
 * endpoint and renders value + delta + sparkline. All formatting is
 * keyed off the tile's ``unit`` so a future tile can ship by adding
 * a new branch here instead of teaching every consumer about a new
 * unit.
 */
'use client';

import type { ReactNode } from 'react';
import { clsx } from 'clsx';
import { ArrowDown, ArrowUp, CircleAlert } from 'lucide-react';

import type { InsightTile } from '@/lib/api';

interface InsightTileCardProps {
  tile: InsightTile;
  sparkline: ReactNode;
}

const DIRECTION_TEXT = {
  up: 'text-teal-20',
  down: 'text-[#FD4E4E]',
  flat: 'text-fg-muted',
} as const;

export function InsightTileCard({ tile, sparkline }: InsightTileCardProps) {
  const direction = deltaDirection(tile);
  const deltaLabel = formatDelta(tile.delta_pct);
  const deltaTitle =
    tile.delta_pct === null
      ? 'No data for the previous window — delta undefined.'
      : `Compared to the previous window: ${deltaLabel}.`;
  const Arrow =
    tile.delta_pct === null || tile.delta_pct === 0
      ? null
      : tile.delta_pct > 0
        ? ArrowUp
        : ArrowDown;

  return (
    <div
      className="flex min-h-[122px] flex-col rounded-2xl border border-surface-border bg-surface-card p-4"
      // The `aria-label` rolls the value + delta into one string so a
      // screen reader announces the change without us shipping a
      // table-with-headers.
      aria-label={`${tile.label}: ${formatValue(tile)}, ${deltaTitle}`}
    >
      <div className="flex min-h-[2rem] items-start justify-between gap-2">
        <span className="text-xs leading-snug text-fg-secondary">{tile.label}</span>
        <span title={deltaTitle} className="shrink-0 text-fg-subtle">
          <CircleAlert className="h-[18px] w-[18px]" strokeWidth={1.25} aria-hidden />
        </span>
      </div>

      <div className="mt-2 flex items-center justify-between gap-2">
        <span className="text-lg font-gilroy-semibold text-fg-primary tabular-nums truncate">
          {formatValue(tile)}
        </span>
        <div className={clsx('shrink-0', DIRECTION_TEXT[direction])}>{sparkline}</div>
      </div>

      <div
        className={clsx('mt-auto flex items-center gap-1 pt-2 text-xs', DIRECTION_TEXT[direction])}
        title={deltaTitle}
      >
        {Arrow && <Arrow className="h-3 w-3" aria-hidden />}
        <span className="tabular-nums">
          {tile.delta_pct === 0 ? 'No change' : deltaLabel}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function formatValue(tile: InsightTile): string {
  switch (tile.unit) {
    case 'hours':
      return `${tile.value.toFixed(1)}h`;
    case 'hours_saved':
      // Round whole hours — fractional analyst hours are noise at the
      // dashboard level. The headline number is the talking-point.
      return `${Math.round(tile.value)}h`;
    case 'pct':
      // Server emits 0–1; render as percentage.
      return `${(tile.value * 100).toFixed(1)}%`;
    case 'usd':
      return tile.value < 1
        ? `$${tile.value.toFixed(3)}`
        : `$${tile.value.toFixed(2)}`;
    case 'count':
    default:
      return Number.isInteger(tile.value)
        ? tile.value.toString()
        : tile.value.toFixed(1);
  }
}

export function formatDelta(delta: number | null): string {
  if (delta === null) return '—';
  const sign = delta > 0 ? '+' : '';
  return `${sign}${delta.toFixed(1)}%`;
}

/**
 * Classify the delta into a UX direction.
 *
 * Note: for tiles where "more = worse" (MTTA, MTTR, FP rate, cost,
 * alerts/day) a positive delta should *not* be celebrated. We push
 * those into ``down`` (red) so the colour matches the operator's
 * intuition. ``hours_saved`` and ``cases_per_day`` flip the polarity.
 */
function deltaDirection(tile: InsightTile): 'up' | 'down' | 'flat' {
  if (tile.delta_pct === null || tile.delta_pct === 0) return 'flat';
  const positive = tile.delta_pct > 0;
  const goodWhenUp = tile.key === 'analyst_hours_saved';
  return positive === goodWhenUp ? 'up' : 'down';
}
