"use client";

import { useCallback, type ReactNode } from "react";
import useSWR from "swr";
import { RefreshCw } from "lucide-react";

import {
  metricsApi,
  investigationsApi,
  type SOCMetrics,
  type AttackHeatmapCell,
  type CalibrationBucket,
  type CostAggregate,
} from "@/lib/api";
import { Card, CardHeader, SectionHeading, StatTile, type Tone } from "./ui";

const EMPTY_SOC_METRICS: SOCMetrics = {
  kpis: {
    mttd_hours: 0,
    mttr_hours: 0,
    mttc_hours: 0,
    false_positive_rate: 0,
    escalation_rate: 0,
    alert_volume_7d: 0,
    cases_opened_7d: 0,
    cases_closed_7d: 0,
    analyst_overrides_7d: 0,
  },
  attack_heatmap: [],
  calibration_curve: [],
};

const EMPTY_COST_AGGREGATE: CostAggregate = {
  window_days: 30,
  by_model: [],
  totals: null,
};

function formatUsd(n: number): string {
  if (n >= 100) return `$${n.toFixed(0)}`;
  if (n >= 1) return `$${n.toFixed(2)}`;
  return `$${n.toFixed(4)}`;
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return `${n}`;
}

/** Threshold state -> design tone (good = teal, warn = amber, bad = red). */
function tone(value: number, warnAbove: number, badAbove: number): Tone {
  return value > badAbove ? "bad" : value > warnAbove ? "warn" : "good";
}

function KpiCard({
  label,
  value,
  unit,
  color,
}: {
  label: string;
  value: string | number;
  unit?: string;
  color?: Tone;
}) {
  return <StatTile label={label} value={value} unit={unit} tone={color ?? "neutral"} />;
}

/** Chip accent per tactic (tinted fill + solid border). */
const TACTIC_COLORS: Record<string, string> = {
  "Initial Access": "#FD4E4E",
  Execution: "#F98B3E",
  Persistence: "#F2BD57",
  "Privilege Escalation": "#F2AC49",
  "Defense Evasion": "#7B5EE6",
  "Credential Access": "#4ADE80",
  Discovery: "#4FD2C2",
  "Lateral Movement": "#8FBCE2",
  Collection: "#3163CF",
  Exfiltration: "#3163CF",
  "Command and Control": "#4FD2C2",
  Impact: "#8531CF",
};

function AttackHeatmap({ cells }: { cells: AttackHeatmapCell[] }) {
  const tacticGroups: Record<string, AttackHeatmapCell[]> = {};
  for (const cell of cells) {
    if (!tacticGroups[cell.tactic]) tacticGroups[cell.tactic] = [];
    tacticGroups[cell.tactic].push(cell);
  }

  const maxCount = Math.max(...cells.map((c) => c.count), 1);

  if (cells.length === 0) {
    return (
      <div className="text-fg-muted text-sm flex items-center justify-center h-32">
        No ATT&amp;CK data in the selected period.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {Object.entries(tacticGroups).map(([tactic, techniques]) => (
        <div key={tactic}>
          <div className="text-xs text-fg-muted mb-2">
            {tactic}
          </div>
          <div className="flex flex-wrap gap-2">
            {techniques.map((cell) => {
              const intensity = Math.max(0.15, cell.count / maxCount);
              const hex = TACTIC_COLORS[tactic] ?? "#939DAD";
              return (
                <div
                  key={cell.technique}
                  title={`${cell.technique}: ${cell.count} alerts`}
                  className="border rounded-md px-2 py-1 text-[11px] text-fg-secondary cursor-default"
                  style={{ opacity: intensity, backgroundColor: `${hex}26`, borderColor: hex }}
                >
                  {cell.technique}
                  <span className="ml-1">({cell.count})</span>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

export function SOCMetricsDashboard({
  topTactics,
}: {
  /** Optional "Top tactics" card rendered beside the technique heatmap. */
  topTactics?: ReactNode;
} = {}) {
  const { data, error, mutate } = useSWR<SOCMetrics>(
    // Opaque cache key — `metricsApi.getSOC()` routes through the
    // tenant- and auth-aware `request()` helper, which attaches
    // `X-Tenant-Id` and `Authorization` headers and is bound to the
    // same-origin proxy in `next.config.*` rewrites.
    "soc-metrics",
    () => metricsApi.getSOC(),
    {
      refreshInterval: 60_000,
      fallbackData: EMPTY_SOC_METRICS,
      shouldRetryOnError: true,
      errorRetryCount: 3,
      errorRetryInterval: 4000,
      revalidateOnMount: true,
      revalidateOnFocus: false,
    }
  );

  const refresh = useCallback(() => mutate(), [mutate]);

  const isValidSOC =
    !!data &&
    typeof data.kpis?.mttd_hours === "number" &&
    Array.isArray(data.attack_heatmap);
  const resolved = isValidSOC ? data : EMPTY_SOC_METRICS;
  const kpis = resolved.kpis;
  const heatmap = resolved.attack_heatmap ?? [];
  const calibration = resolved.calibration_curve ?? [];
  const errorMessage =
    error instanceof Error
      ? error.message
      : error
        ? String(error)
        : null;

  return (
    <div className="space-y-6">
      {errorMessage && (
        <div className="rounded border border-red-900/60 bg-red-950/40 px-3 py-2 text-xs text-red-200">
          <span className="font-semibold">SOC metrics unavailable:</span>{" "}
          {errorMessage}. Panels stay empty until the live API recovers.
        </div>
      )}

      {/* Threat coverage: top tactics + ATT&CK heatmap */}
      <section>
        <SectionHeading>Threat coverage (MITRE ATT&amp;CK)</SectionHeading>
        <div className={topTactics ? "grid grid-cols-1 lg:grid-cols-2 gap-4" : undefined}>
          {topTactics}
          <Card className="p-6">
            <CardHeader
              title="ATT&CK Technique Heatmap"
              subtitle="Technique ID (alert count) by tactic; stronger colour means more alerts"
              className="mb-5"
            />
            <AttackHeatmap cells={heatmap} />
          </Card>
        </div>
      </section>

      {/* KPI Grid */}
      <section>
        <SectionHeading
          action={
            <button
              onClick={refresh}
              className="inline-flex items-center gap-1.5 text-xs text-fg-muted hover:text-fg-primary px-3 py-1.5 border border-surface-border bg-surface-card rounded-full transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden />
              Refresh
            </button>
          }
        >
          SOC Performance
        </SectionHeading>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <KpiCard
            label="MTTD"
            value={kpis?.mttd_hours.toFixed(1) ?? "—"}
            unit="hrs"
            color={tone(kpis?.mttd_hours ?? 0, 2, 4)}
          />
          <KpiCard
            label="MTTR"
            value={kpis?.mttr_hours.toFixed(1) ?? "—"}
            unit="hrs"
            color={tone(kpis?.mttr_hours ?? 0, 8, 24)}
          />
          <KpiCard
            label="MTTC"
            value={kpis?.mttc_hours.toFixed(1) ?? "—"}
            unit="hrs"
            color={tone(kpis?.mttc_hours ?? 0, 8, 24)}
          />
          <KpiCard
            label="Escalation rate"
            value={
              kpis ? `${(kpis.escalation_rate * 100).toFixed(1)}%` : "—"
            }
            color={tone(kpis?.escalation_rate ?? 0, 0.25, 0.5)}
          />
          <KpiCard
            label="False positive rate"
            value={
              kpis
                ? `${(kpis.false_positive_rate * 100).toFixed(1)}%`
                : "—"
            }
            color={tone(kpis?.false_positive_rate ?? 0, 0.15, 0.3)}
          />
          <KpiCard
            label="Alert volume (7d)"
            value={kpis?.alert_volume_7d ?? "—"}
          />
          <KpiCard
            label="Cases opened (7d)"
            value={kpis?.cases_opened_7d ?? "—"}
          />
          <KpiCard
            label="Cases closed (7d)"
            value={kpis?.cases_closed_7d ?? "—"}
            color="good"
          />
        </div>
      </section>

      {/* Confidence Calibration Curve */}
      <section>
        <SectionHeading>AI agent quality</SectionHeading>
        <Card className="p-6">
          <CardHeader
            title="Agent Confidence Calibration (7d)"
            subtitle="Predicted confidence vs. actual true-positive rate. Diagonal alignment indicates well-calibrated confidence."
            action={
              <span className="shrink-0 text-xs text-fg-muted">
                Analyst overrides (7d):{" "}
                <span className="font-gilroy-semibold text-teal-20">
                  {kpis?.analyst_overrides_7d ?? "—"}
                </span>
              </span>
            }
            className="mb-6"
          />
          <CalibrationCurve buckets={calibration} />
        </Card>
      </section>

      {/* Investigation Cost Telemetry */}
      <CostTelemetryPanel />
    </div>
  );
}

function CostTelemetryPanel() {
  const { data, error, isLoading } = useSWR<CostAggregate>(
    "cost-aggregate:30",
    () => investigationsApi.getCostAggregate(30),
    {
      refreshInterval: 60_000,
      fallbackData: EMPTY_COST_AGGREGATE,
      shouldRetryOnError: true,
      errorRetryCount: 3,
      errorRetryInterval: 4000,
      revalidateOnMount: true,
      revalidateOnFocus: false,
    },
  );

  const isValidCost =
    !!data &&
    Array.isArray(data.by_model) &&
    typeof data.window_days === "number";
  const resolved = isValidCost ? data : EMPTY_COST_AGGREGATE;
  const totals = resolved.totals;
  const byModel = resolved.by_model ?? [];
  const maxModelCost = Math.max(...byModel.map((m) => m.total_cost_usd), 0.0001);
  const errorMessage =
    error instanceof Error
      ? error.message
      : error
        ? String(error)
        : null;

  return (
    <section>
      <SectionHeading>Investigation cost (30d)</SectionHeading>
      <p className="-mt-2 mb-4 text-xs text-fg-muted">
        Tokens · Latency · Spend per model, aggregated across runs. Per-run
        breakdowns are available on each investigation detail view.
      </p>

      {errorMessage && (
        <div className="mb-3 rounded border border-red-900/60 bg-red-950/40 px-3 py-2 text-xs text-red-200">
          <span className="font-semibold">Cost telemetry unavailable:</span>{" "}
          {errorMessage}. Showing empty totals until the API recovers.
        </div>
      )}

      {isLoading && !resolved ? (
        <div className="h-32 animate-pulse bg-dark-20 rounded-2xl" />
      ) : !totals || totals.runs === 0 ? (
        <Card className="text-fg-muted text-sm flex items-center justify-center h-24">
          No investigation runs with cost telemetry in the last 30 days.
        </Card>
      ) : (
        <div className="space-y-4">
          {/* Totals strip */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <KpiCard
              label="Total spend"
              value={formatUsd(totals.total_cost_usd)}
              color={tone(totals.total_cost_usd, 25, 100)}
            />
            <KpiCard label="Runs" value={totals.runs.toLocaleString("en-US")} />
            <KpiCard label="LLM calls" value={totals.calls.toLocaleString("en-US")} />
            <KpiCard
              label="Avg $/run"
              value={formatUsd(totals.avg_cost_per_run)}
            />
            <KpiCard
              label="Avg latency/call"
              value={`${(totals.avg_latency_per_call_ms / 1000).toFixed(2)}`}
              unit="s"
              color={tone(totals.avg_latency_per_call_ms, 5_000, 10_000)}
            />
          </div>

          {/* Per-model breakdown */}
          <Card className="overflow-x-auto px-6 py-3">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-fg-muted border-b border-surface-border">
                  <th className="text-left py-3 pr-4 font-normal">Model</th>
                  <th className="text-right py-3 pr-4 font-normal">Runs</th>
                  <th className="text-right py-3 pr-4 font-normal">Calls</th>
                  <th className="text-right py-3 pr-4 font-normal">Prompt tokens</th>
                  <th className="text-right py-3 pr-4 font-normal">Completion tokens</th>
                  <th className="text-right py-3 pr-4 font-normal">Spend</th>
                  <th className="text-left py-3 font-normal">Share</th>
                </tr>
              </thead>
              <tbody>
                {byModel.map((row) => {
                  const sharePct = (row.total_cost_usd / maxModelCost) * 100;
                  return (
                    <tr
                      key={row.model}
                      className="border-b border-surface-border last:border-0"
                    >
                      <td className="py-3 pr-4 text-fg-secondary">
                        {row.model}
                      </td>
                      <td className="py-3 pr-4 text-right text-fg-secondary tabular-nums">
                        {row.runs.toLocaleString("en-US")}
                      </td>
                      <td className="py-3 pr-4 text-right text-fg-secondary tabular-nums">
                        {row.calls.toLocaleString("en-US")}
                      </td>
                      <td className="py-3 pr-4 text-right text-fg-secondary tabular-nums">
                        {formatTokens(row.total_prompt_tokens)}
                      </td>
                      <td className="py-3 pr-4 text-right text-fg-secondary tabular-nums">
                        {formatTokens(row.total_completion_tokens)}
                      </td>
                      <td className="py-3 pr-4 text-right text-fg-primary tabular-nums">
                        {formatUsd(row.total_cost_usd)}
                      </td>
                      <td className="py-3 min-w-[120px]">
                        <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-teal-20 rounded-full"
                            style={{ width: `${sharePct}%` }}
                          />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </Card>
        </div>
      )}
    </section>
  );
}

function CalibrationCurve({ buckets }: { buckets: CalibrationBucket[] }) {
  if (!buckets || buckets.length === 0) {
    return (
      <div className="text-fg-muted text-sm flex items-center justify-center h-40">
        Not enough labeled investigations to compute calibration yet.
      </div>
    );
  }

  const maxSamples = Math.max(...buckets.map((b) => b.sample_count), 1);

  return (
    <div className="space-y-4">
      {/* Header row */}
      <div className="grid grid-cols-[88px_1fr_64px_40px] sm:grid-cols-[108px_1fr_80px_48px] gap-3 text-sm text-fg-muted">
        <div>Bin</div>
        <div>Predicted vs actual TP rate</div>
        <div className="text-right">Actual</div>
        <div className="text-right">N</div>
      </div>
      {buckets.map((bucket) => {
        const lo = (bucket.predicted_lower * 100).toFixed(0);
        const hi = (bucket.predicted_upper * 100).toFixed(0);
        const midpoint = (bucket.predicted_lower + bucket.predicted_upper) / 2;
        const actual = bucket.actual_tp_rate;
        // Drift is gap between actual and the midpoint of the predicted band.
        const drift = Math.abs(actual - midpoint);
        const driftTone: Tone = drift > 0.2 ? "bad" : drift > 0.1 ? "warn" : "good";
        const driftColor =
          driftTone === "bad" ? "#FD4E4E" : driftTone === "warn" ? "#F2BD57" : "#4ADE80";
        const sampleOpacity = Math.max(
          0.2,
          bucket.sample_count / maxSamples
        );

        return (
          <div
            key={`${bucket.predicted_lower}-${bucket.predicted_upper}`}
            className="grid grid-cols-[88px_1fr_64px_40px] sm:grid-cols-[108px_1fr_80px_48px] gap-3 items-center text-sm"
            title={`Predicted ${lo}-${hi}%; actual TP rate ${(actual * 100).toFixed(
              1,
            )}%; ${bucket.sample_count} samples`}
          >
            <div className="text-fg-secondary">
              {lo}–{hi}%
            </div>
            <div className="relative h-[18px] bg-gray-700 rounded">
              {/* Predicted band */}
              <div
                className="absolute top-0 bottom-0 bg-[#8FBCE2] rounded"
                style={{
                  left: `${bucket.predicted_lower * 100}%`,
                  width: `${(bucket.predicted_upper - bucket.predicted_lower) * 100}%`,
                }}
              />
              {/* Actual marker */}
              <div
                className="absolute top-0 bottom-0 w-1 rounded-l"
                style={{
                  left: `calc(${actual * 100}% - 2px)`,
                  opacity: sampleOpacity,
                  backgroundColor: driftColor,
                }}
              />
            </div>
            <div
              className="text-right font-gilroy-semibold tabular-nums"
              style={{ color: driftColor }}
            >
              {(actual * 100).toFixed(1)}%
            </div>
            <div className="text-right text-fg-secondary tabular-nums text-xs">
              {bucket.sample_count}
            </div>
          </div>
        );
      })}
    </div>
  );
}
