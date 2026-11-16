'use client';

/**
 * EfficiencyReport
 * ================
 * Composite efficiency card that surfaces the **derived** funnel ratios:
 *
 *   • Correlation efficiency  = alerts / correlation_instances   (clamped 0..1)
 *   • Alert yield             = alerts / events_of_interest      (clamped 0..1)
 *   • MITRE coverage          = covered / total
 *
 * Backed by `GET /api/v1/metrics/funnel`. Designed to sit next to
 * {@link FunnelKpiBar} on the operations dashboard. The report intentionally
 * shares the SWR cache key with the bar so both components stay in lock-step
 * without firing two requests.
 *
 * Author: Beenu Arora <beenu@cyble.com>
 */

import useSWR from 'swr';
import { clsx } from 'clsx';
import { metricsApi, type FunnelMetrics } from '@/lib/api';
import { Card, CardHeader, Pill } from './ui';

type Period = '1h' | '24h' | '7d' | '30d';

interface EfficiencyReportProps {
  /** Time window. Should match the sibling FunnelKpiBar period. */
  period?: Period;
  /** Override the SWR cache key. Defaults to the same key as FunnelKpiBar. */
  cacheKey?: string;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  if (value < 0) return 0;
  if (value > 1) return 1;
  return value;
}

function fmtPct(ratio: number): string {
  if (!Number.isFinite(ratio)) return '—';
  const pct = clamp01(ratio) * 100;
  return `${pct.toFixed(1).replace(/\.0$/, '')}%`;
}

function fmtCoverage(covered: number, total: number): string {
  if (!Number.isFinite(covered) || !Number.isFinite(total) || total <= 0)
    return '—';
  const pct = (covered / total) * 100;
  return `${covered}/${total} • ${pct.toFixed(1).replace(/\.0$/, '')}%`;
}

interface BarRowProps {
  label: string;
  description: string;
  value: number;
  /** Whether the value is "good" close to 1 (true) or close to a target (false). */
  goodHigh?: boolean;
  /** Display value (formatted). */
  display: string;
}

function BarRow({
  label,
  description,
  value,
  goodHigh = true,
  display,
}: BarRowProps) {
  const v = clamp01(value);
  // For "good-high" metrics, color by threshold; for others, neutral.
  let barColor = 'bg-teal-20';
  if (goodHigh) {
    if (v < 0.2) barColor = 'bg-[#FD4E4E]';
    else if (v < 0.5) barColor = 'bg-[#F2BD57]';
    else barColor = 'bg-teal-20';
  }

  return (
    <div>
      <div className="flex items-baseline justify-between gap-3 mb-3">
        <div className="min-w-0">
          <p className="text-sm font-gilroy-semibold text-fg-primary truncate">{label}</p>
          <p className="text-xs text-fg-muted truncate">{description}</p>
        </div>
        <p className="text-sm font-gilroy-semibold text-fg-primary tabular-nums shrink-0">
          {display}
        </p>
      </div>
      <div className="h-1.5 w-full rounded-full bg-gray-700 overflow-hidden">
        <div
          className={clsx('h-full rounded-full transition-[width]', barColor)}
          style={{ width: `${(v * 100).toFixed(1)}%` }}
        />
      </div>
    </div>
  );
}

function LoadingBar({ label }: { label: string }) {
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3 mb-3">
        <p className="text-sm font-gilroy-semibold text-fg-primary truncate">{label}</p>
        <div className="h-4 w-12 rounded bg-dark-20/60 animate-pulse" />
      </div>
      <div className="h-1.5 w-full rounded-full bg-dark-20/40 animate-pulse" />
    </div>
  );
}

export function EfficiencyReport({
  period = '24h',
  cacheKey,
}: EfficiencyReportProps = {}) {
  const key = cacheKey ?? `funnel-metrics:${period}`;
  const { data, error, isLoading } = useSWR<FunnelMetrics>(
    key,
    () => metricsApi.getFunnel(period),
    {
      refreshInterval: 60_000,
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    },
  );

  return (
    <Card className="p-6">
      <CardHeader
        title="Efficiency Report"
        subtitle="How well raw signal converts to actionable alerts"
        action={<Pill>Last {period}</Pill>}
        className="mb-5"
      />

      {error ? (
        <p className="text-sm text-fg-muted">Efficiency metrics unavailable.</p>
      ) : isLoading || !data ? (
        <div className="space-y-5">
          <LoadingBar label="Correlation efficiency" />
          <LoadingBar label="Alert yield" />
          <LoadingBar label="MITRE coverage" />
        </div>
      ) : (
        <div className="space-y-5">
          <BarRow
            label="Correlation efficiency"
            description="Alerts produced per correlation instance"
            value={data.correlation_efficiency}
            display={fmtPct(data.correlation_efficiency)}
          />
          <BarRow
            label="Alert yield"
            description="Alerts produced per event of interest"
            value={data.alert_yield}
            display={fmtPct(data.alert_yield)}
          />
          <BarRow
            label="MITRE coverage"
            description="Tactic + technique IDs surfaced by your alerts"
            value={
              data.mitre_coverage.total > 0
                ? data.mitre_coverage.covered / data.mitre_coverage.total
                : 0
            }
            display={fmtCoverage(
              data.mitre_coverage.covered,
              data.mitre_coverage.total,
            )}
          />
        </div>
      )}
    </Card>
  );
}

export default EfficiencyReport;
