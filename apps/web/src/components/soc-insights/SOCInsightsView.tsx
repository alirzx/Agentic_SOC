/**
 * SOC Insights dashboard view (T3.1).
 *
 * Owns the data-fetching + layout for the 7-tile grid. Split out of
 * the route file so the page module can stay a pure server component
 * (per Next.js App Router conventions); this file is the "use client"
 * boundary.
 */
'use client';

import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';
import { Clock, Download } from 'lucide-react';

import { useRealtimeChannel } from '@/lib/realtime';
import {
  type InsightTile,
  type InsightsWindow,
  type SOCInsightsResponse,
  insightsApi,
} from '@/lib/api';

import { InsightTileCard, formatDelta, formatValue } from './InsightTileCard';
import { Sparkline } from './Sparkline';

const WINDOW_OPTIONS: InsightsWindow[] = ['24h', '7d', '30d'];

/** Pill chrome shared by the header controls (light dashboard design). */
const PILL =
  'inline-flex h-[42px] items-center gap-2 rounded-full border border-surface-border bg-surface-card px-4 text-[13px] text-fg-muted';

/** Client-side CSV of the tiles currently on screen (no extra API call). */
function exportTilesCsv(data: SOCInsightsResponse, window: InsightsWindow) {
  const esc = (v: string) => `"${v.replace(/"/g, '""')}"`;
  const rows = [
    ['tile', 'value', 'delta_vs_previous_window', 'window', 'generated_at'],
    ...data.tiles.map((t) => [
      t.label,
      formatValue(t),
      formatDelta(t.delta_pct),
      window,
      data.generated_at ?? '',
    ]),
  ];
  const csv = rows.map((r) => r.map((c) => esc(String(c))).join(',')).join('\r\n');
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `soc-insights-${window}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

interface RealtimePoke {
  type: string;
  reason?: string;
  timestamp?: string;
}

export function SOCInsightsView() {
  const [window, setWindow] = useState<InsightsWindow>('24h');

  const { data, error, isLoading, mutate } = useSWR<SOCInsightsResponse>(
    ['insights:soc', window],
    () => insightsApi.getSOC(window),
    {
      // The realtime channel pokes us every 30s; we also revalidate
      // on focus in case the tab was backgrounded long enough for
      // the WebSocket to disconnect.
      revalidateOnFocus: true,
      revalidateIfStale: true,
      // Don't dedupe identical-key refetches — the realtime poke is
      // explicit "go look again", we want it honoured even if SWR
      // just fetched.
      dedupingInterval: 0,
    },
  );

  // Subscribe to `insights_updated` events from the realtime service.
  // The hook keeps the socket alive and reconnects with exponential
  // backoff; we just react to the last received frame.
  const { last } = useRealtimeChannel<RealtimePoke>('insights');

  useEffect(() => {
    if (last?.type === 'insights_updated' || last?.type === 'case.updated') {
      // Force a re-fetch — pass false to suppress the optimistic
      // "loading" flash; users keep seeing the old tiles for the
      // 100-200ms until the new ones arrive.
      mutate(undefined, { revalidate: true });
    }
  }, [last, mutate]);

  return (
    <div className="space-y-5">
      <Header
        window={window}
        onWindowChange={setWindow}
        generatedAt={data?.generated_at}
        manualMinutes={data?.manual_investigation_minutes}
        onExport={data ? () => exportTilesCsv(data, window) : undefined}
      />

      {error ? (
        <ErrorState
          message={error instanceof Error ? error.message : String(error)}
          onRetry={() => mutate()}
        />
      ) : isLoading || !data ? (
        <LoadingSkeleton />
      ) : (
        <TileGrid tiles={data.tiles} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Subcomponents
// ---------------------------------------------------------------------------

interface HeaderProps {
  window: InsightsWindow;
  onWindowChange: (w: InsightsWindow) => void;
  generatedAt: string | undefined;
  manualMinutes: number | undefined;
  /** Undefined while there is nothing to export (loading / error). */
  onExport?: () => void;
}

function Header({ window, onWindowChange, generatedAt, manualMinutes, onExport }: HeaderProps) {
  const stamp = useMemo(() => {
    if (!generatedAt) return null;
    try {
      return new Date(generatedAt).toLocaleTimeString();
    } catch {
      return generatedAt;
    }
  }, [generatedAt]);

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-[26px] leading-tight font-gilroy-semibold text-fg-primary">SOC Insights</h1>
          <p className="mt-2 max-w-[640px] text-xs leading-relaxed text-fg-secondary">
            Seven operational tiles for the SOC, refreshed every 30 seconds and
            on case changes. Deltas compare against the immediately preceding
            window. Hours-saved assumes {manualMinutes ?? 45} minutes of analyst
            time per auto-closed case.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <WindowSelector value={window} onChange={onWindowChange} />
          <button
            type="button"
            onClick={onExport}
            disabled={!onExport}
            className={`${PILL} transition-colors hover:text-fg-primary disabled:cursor-not-allowed disabled:opacity-50`}
            title="Download the current tiles as CSV"
          >
            <Download className="h-4 w-4" strokeWidth={1.5} aria-hidden />
            Export
          </button>
        </div>
      </div>
      {stamp ? (
        <p className="flex items-center gap-2 text-xs text-fg-secondary" aria-live="polite">
          <span className="h-2 w-2 rounded-full bg-teal-20" aria-hidden />
          Live Updated :<span className="text-fg-subtle">{stamp}</span>
        </p>
      ) : null}
    </div>
  );
}

interface WindowSelectorProps {
  value: InsightsWindow;
  onChange: (w: InsightsWindow) => void;
}

function WindowSelector({ value, onChange }: WindowSelectorProps) {
  return (
    <label className={`${PILL} pr-1`}>
      <Clock className="h-4 w-4 shrink-0" strokeWidth={1.5} aria-hidden />
      <select
        aria-label="Window"
        value={value}
        onChange={(e) => onChange(e.target.value as InsightsWindow)}
        className="h-full cursor-pointer appearance-none rounded-full bg-transparent pl-0 text-[13px] text-fg-muted focus:outline-none"
      >
        {WINDOW_OPTIONS.map((option) => (
          <option key={option} value={option}>
            Time range · {option}
          </option>
        ))}
      </select>
    </label>
  );
}

interface TileGridProps {
  tiles: InsightTile[];
}

function TileGrid({ tiles }: TileGridProps) {
  return (
    <div
      // 7 tiles fit comfortably as a 4×2 grid at lg, 2×4 at md, 1 per
      // row on phones. The grid keeps a constant ratio so the
      // sparkline width doesn't jump between window changes.
      className="grid gap-3 grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7"
      data-testid="soc-insights-tiles"
    >
      {tiles.map((tile) => (
        <InsightTileCard
          key={tile.key}
          tile={tile}
          sparkline={<Sparkline points={tile.sparkline.points} width={48} height={20} area />}
        />
      ))}
    </div>
  );
}

function LoadingSkeleton() {
  // 7 skeleton tiles arranged on the same grid. The fixed heights
  // mean the layout doesn't reflow when the real data arrives.
  return (
    <div
      className="grid gap-3 grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7"
      aria-busy="true"
      aria-label="Loading SOC insights"
    >
      {Array.from({ length: 7 }).map((_, i) => (
        <div
          key={i}
          className="h-[122px] animate-pulse rounded-2xl border border-surface-border bg-surface-card"
        />
      ))}
    </div>
  );
}

interface ErrorStateProps {
  message: string;
  onRetry: () => void;
}

function ErrorState({ message, onRetry }: ErrorStateProps) {
  return (
    <div
      role="alert"
      className="rounded-2xl border border-red-500/30 bg-red-500/5 p-6 text-sm"
    >
      <p className="font-gilroy-semibold text-[#FD4E4E]">
        SOC Insights are temporarily unavailable.
      </p>
      <p className="mt-1 text-fg-muted">{message}</p>
      <button
        type="button"
        onClick={onRetry}
        className="mt-3 rounded-full border border-surface-border bg-surface-card px-4 py-1.5 text-xs text-fg-secondary hover:text-fg-primary"
      >
        Retry
      </button>
    </div>
  );
}
