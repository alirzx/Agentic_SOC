/**
 * DetectionFuseView — Workflow SOC stage 02, with real rows behind it.
 *
 * The lifecycle page says "rules and correlation promote noise into high-signal
 * alerts". Until this view existed that sentence had no destination: the diagram
 * was the only place the stage appeared. What renders here is the evidence the
 * fusion spine already wrote per alert — which rule fired, which connector and
 * OCSF class produced the event, how much duplicate traffic it absorbed, and
 * whether fusion kept it standalone, merged it, or put it in a windowed incident.
 *
 * Scope discipline: this reads the `alerts` table through one endpoint. It does
 * not re-derive rule names from titles, and the summary counts describe the rows
 * on screen — the page says so rather than implying a full-history total.
 */

'use client';

import { AlertCircle, Layers, Loader, Search } from 'lucide-react';
import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';

import type {
  DetectionActivity,
  DetectionActivityItem,
  FusionState,
} from '@/components/runbook/runbook.types';

const LIMIT = 50;

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-amber-400',
  low: 'bg-sky-400',
  info: 'bg-slate-500',
};

const FUSION_CHIP: Record<FusionState, { label: string; className: string }> = {
  incident: {
    label: 'Incident',
    className: 'text-purple-300 bg-purple-500/10 border-purple-500/20',
  },
  merged: {
    label: 'Merged',
    className: 'text-cyan-300 bg-cyan-500/10 border-cyan-500/20',
  },
  standalone: {
    label: 'Standalone',
    className: 'text-slate-400 bg-slate-800/60 border-slate-700/60',
  },
};

function errMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

export function DetectionFuseView() {
  const [data, setData] = useState<DetectionActivity | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const response = await fetch(`/api/v1/runbook/detections?limit=${LIMIT}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setData((await response.json()) as DetectionActivity);
    } catch (err) {
      setError(errMessage(err, 'Failed to load detection activity'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    void load();
  }, [load]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-10 text-slate-500">
        <Loader className="h-4 w-4 animate-spin" />
        <span className="text-xs">Loading detection activity…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div
        role="alert"
        className="flex items-start gap-2 rounded border border-red-500/25 bg-red-500/10 px-3 py-2 text-xs text-red-300"
      >
        <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>{error}</span>
      </div>
    );
  }

  const summary = data?.summary;
  const items = data?.items ?? [];

  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800/60 bg-slate-950/20 p-6 text-center">
        <Search className="mx-auto mb-2 h-7 w-7 text-slate-600" />
        <p className="text-sm text-slate-300">No alerts have been promoted yet</p>
        <p className="mt-1 text-xs text-slate-500">
          This view reads the alerts the detection and fusion spine wrote. It is empty
          because nothing has been promoted, not because a demo has not been loaded.
        </p>
        <div className="mt-3 flex justify-center gap-2">
          <Link
            href="/connectors"
            className="rounded-md bg-slate-800/60 px-3 py-1.5 text-xs text-slate-300 ring-1 ring-slate-700/60 transition-colors hover:bg-slate-800 hover:text-slate-100"
          >
            Check connectors →
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {summary && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-slate-800/60 bg-slate-900/30 px-3 py-2 text-[11px]">
          <span className="flex items-center gap-1.5 font-medium uppercase tracking-wider text-slate-500">
            <Layers className="h-3 w-3" />
            Last {summary.examined} promotions
          </span>
          <Metric label="distinct rules" value={summary.distinct_rules} />
          <Metric
            label="no rule recorded"
            value={summary.without_rule}
            tone={summary.without_rule > 0 ? 'warn' : 'muted'}
          />
          <Metric label="in an incident" value={summary.incident_linked} />
          <Metric label="merged" value={summary.merged} />
          <Metric label="deduplicated" value={summary.deduplicated} />
        </div>
      )}

      <div className="overflow-hidden rounded-lg border border-slate-800/60">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/60 text-[10px] uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-3 py-2 font-medium">Alert</th>
              <th className="px-3 py-2 font-medium">Detection rule</th>
              <th className="px-3 py-2 font-medium">Source</th>
              <th className="px-3 py-2 font-medium">Confidence</th>
              <th className="px-3 py-2 font-medium">Fusion</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {items.map((item) => (
              <Row key={item.alert_id} item={item} />
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-[10px] text-slate-600">
        Counts describe the {items.length} most recent alerts, not the full history. Rule
        lineage, contributing events and the correlation narrative live behind{' '}
        <span className="text-slate-500">Explain</span> on each alert.
      </p>
    </div>
  );
}

function Metric({
  label,
  value,
  tone = 'default',
}: {
  label: string;
  value: number;
  tone?: 'default' | 'muted' | 'warn';
}) {
  const toneClass =
    tone === 'warn' && value > 0
      ? 'text-amber-300'
      : tone === 'muted' && value === 0
        ? 'text-slate-600'
        : 'text-slate-300';
  return (
    <span className="text-slate-500">
      <span className={`font-semibold ${toneClass}`}>{value}</span> {label}
    </span>
  );
}

function Row({ item }: { item: DetectionActivityItem }) {
  const chip = FUSION_CHIP[item.fusion_state] ?? FUSION_CHIP.standalone;
  const ruleLabel = item.rule_name?.trim() || item.rule_id?.trim();
  const occurred = item.occurrence_count;

  return (
    <tr className="bg-slate-950/20 align-top hover:bg-slate-900/40">
      <td className="px-3 py-2">
        <div className="flex items-start gap-2">
          <span
            className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${SEVERITY_DOT[item.severity] ?? 'bg-slate-600'}`}
            title={item.severity}
          />
          <div className="min-w-0">
            <Link
              href={`/alerts/${item.alert_id}`}
              className="line-clamp-2 text-slate-200 transition-colors hover:text-blue-300"
              title={item.title}
            >
              {item.title}
            </Link>
            {item.created_at && (
              <p className="mt-0.5 text-[10px] text-slate-600">
                {new Date(item.created_at).toLocaleString()}
              </p>
            )}
          </div>
        </div>
      </td>
      <td className="px-3 py-2">
        {ruleLabel ? (
          <>
            <p className="text-slate-300">{ruleLabel}</p>
            {item.rule_id && item.rule_id !== ruleLabel && (
              <p className="mt-0.5 font-mono text-[10px] text-slate-600">{item.rule_id}</p>
            )}
          </>
        ) : (
          <span className="text-amber-300/80">No rule recorded</span>
        )}
      </td>
      <td className="px-3 py-2 text-slate-400">
        {item.connector_type || <span className="text-slate-600">—</span>}
        {occurred > 1 && (
          <p className="mt-0.5 text-[10px] text-slate-500">×{occurred} similar events</p>
        )}
      </td>
      <td className="px-3 py-2 text-slate-400">
        {item.confidence === null || item.confidence === undefined ? (
          <span className="text-slate-600">—</span>
        ) : (
          item.confidence
        )}
      </td>
      <td className="px-3 py-2">
        <span className={`rounded border px-1.5 py-0.5 text-[10px] ${chip.className}`}>
          {chip.label}
        </span>
      </td>
    </tr>
  );
}
