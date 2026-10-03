'use client';

/**
 * SOC Funnel Board — live stage tracking for the product path
 * Ingested → Triaged / Suppressed → Investigating → Cased → Ready for Jira → Jira.
 */

import { useState } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import { clsx } from 'clsx';
import { socFunnelApi, type FunnelBoardAlert, type FunnelBoardStage } from '@/lib/api';

const STAGE_ACCENT: Record<string, string> = {
  ingested: 'border-sky-500/40 bg-sky-500/5',
  triaged: 'border-cyan-500/40 bg-cyan-500/5',
  suppressed: 'border-gray-500/40 bg-gray-500/5',
  investigating: 'border-brand-500/40 bg-brand-500/5',
  cased: 'border-amber-500/40 bg-amber-500/5',
  ready_for_jira: 'border-orange-500/40 bg-orange-500/5',
  jira_pushed: 'border-emerald-500/40 bg-emerald-500/5',
};

function StageColumn({
  stage,
  alerts,
}: {
  stage: FunnelBoardStage;
  alerts: FunnelBoardAlert[];
}) {
  const listed = alerts.reduce((n, a) => n + (a.same_title_count ?? 1), 0);
  return (
    <section
      className={clsx(
        'min-w-[200px] flex-1 rounded-xl border p-3 flex flex-col gap-2',
        STAGE_ACCENT[stage.id] || 'border-[#374151]/60 bg-dark-70/60',
      )}
    >
      <header className="flex items-baseline justify-between gap-2">
        <h2 className="text-sm font-semibold text-gray-100">{stage.label}</h2>
        <Link
          href={`/alerts?funnel_stage=${encodeURIComponent(stage.id)}`}
          className="text-xs font-mono text-gray-400 hover:text-brand-300"
          title={`Open all ${stage.count} alerts in Alerts`}
        >
          {stage.count}
        </Link>
      </header>
      <ul className="flex flex-col gap-1.5 max-h-[420px] overflow-y-auto">
        {alerts.length === 0 ? (
          <li className="text-[11px] text-gray-600 py-2">No alerts in window</li>
        ) : (
          alerts.map((alert) => {
            const copies = alert.same_title_count ?? 1;
            return (
              <li key={alert.id}>
                <Link
                  href={`/alerts/${alert.id}`}
                  className="block rounded-lg border border-[#374151]/50 bg-dark-20/40 px-2.5 py-2 hover:border-brand-500/40 transition-colors"
                >
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-xs text-gray-200 line-clamp-2">{alert.title}</p>
                    {copies > 1 ? (
                      <span
                        className="shrink-0 rounded border border-orange-500/30 bg-orange-500/10 px-1.5 py-0.5 text-[10px] font-mono text-orange-200"
                        title={`${copies} alerts share this title in ${stage.label}`}
                      >
                        ×{copies}
                      </span>
                    ) : null}
                  </div>
                  <p className="mt-1 text-[10px] text-gray-500 font-mono uppercase tracking-wide">
                    {alert.severity}
                    {alert.disposition ? ` · ${alert.disposition}` : ''}
                  </p>
                </Link>
              </li>
            );
          })
        )}
      </ul>
      {stage.count > 0 ? (
        <p className="text-[10px] text-gray-600">
          {alerts.length} title{alerts.length === 1 ? '' : 's'} shown
          {listed < stage.count ? ` · ${stage.count} alerts total` : ''}
          {' · '}
          <Link
            href={`/alerts?funnel_stage=${encodeURIComponent(stage.id)}`}
            className="text-gray-500 hover:text-brand-300 underline-offset-2 hover:underline"
          >
            view all
          </Link>
        </p>
      ) : null}
    </section>
  );
}

export function SocFunnelBoardView() {
  const [hours, setHours] = useState(24);
  const [backfillMsg, setBackfillMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
      setBackfillMsg(
        `Scanned ${result.alerts_scanned}: FP ${result.false_positive_tagged}, cases ${result.cases_created}, linked ${result.alerts_linked}, stages synced ${synced}`,
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
      setBackfillMsg(
        `Removed duplicates — alerts: ${result.alerts.alerts_deleted} deleted ` +
          `(${result.alerts.groups_collapsed} groups), cases: ${result.cases.cases_deleted} deleted ` +
          `(${result.cases.groups_collapsed} groups)`,
      );
      await mutate();
    } catch (err) {
      setBackfillMsg(err instanceof Error ? err.message : 'Dedupe failed');
    } finally {
      setBusy(false);
    }
  };

  const stages = data?.stages ?? [];
  const samples = data?.samples_by_stage ?? {};

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-white">SOC Funnel</h1>
          <p className="text-sm text-gray-400 mt-1 max-w-2xl">
            Track alerts from ingest through triage → investigation → case → gated Jira.
            Triage decides if investigation is worth it; Ready for Jira needs evidence, not every TP.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {[24, 48, 168].map((h) => (
            <button
              key={h}
              type="button"
              onClick={() => setHours(h)}
              className={clsx(
                'text-xs px-2.5 py-1 rounded-lg border transition-colors',
                hours === h
                  ? 'bg-brand-600 border-brand-500 text-white'
                  : 'border-[#374151] text-gray-400 hover:text-gray-200',
              )}
            >
              {h === 168 ? '7d' : `${h}h`}
            </button>
          ))}
          <button
            type="button"
            disabled={busy}
            onClick={() => void runBackfill()}
            className="text-xs px-3 py-1.5 rounded-lg bg-dark-20 border border-[#374151] text-gray-200 hover:border-brand-500/50 disabled:opacity-50"
          >
            {busy ? 'Running…' : 'Run backfill'}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void runDedupe()}
            className="text-xs px-3 py-1.5 rounded-lg bg-orange-500/15 border border-orange-500/40 text-orange-100 hover:bg-orange-500/25 disabled:opacity-50"
            title="Delete alerts/cases that look identical (same title, rule, entities)"
          >
            {busy ? 'Running…' : 'Remove duplicates'}
          </button>
        </div>
      </header>

      {data ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Stat label="Alerts in window" value={String(data.alerts_total)} />
          <Stat
            label="Suppression rate"
            value={`${Math.round((data.ratios.suppression_rate || 0) * 100)}%`}
          />
          <Stat
            label="Ready / pushed"
            value={`${Math.round((data.ratios.ready_for_jira_rate || 0) * 100)}%`}
          />
          <Stat label="Window" value={`${data.window_hours}h`} />
        </div>
      ) : null}

      {backfillMsg ? (
        <p className="text-xs text-gray-400 font-mono border border-[#374151]/50 rounded-lg px-3 py-2">
          {backfillMsg}
        </p>
      ) : null}

      {error ? (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2">
          <p className="text-sm text-red-300">Failed to load funnel board.</p>
          <p className="text-xs text-red-400/90 font-mono mt-1 break-all">
            {error instanceof Error ? error.message : String(error)}
          </p>
          <p className="text-[11px] text-gray-500 mt-1">
            If this is 404, rebuild/recreate the API container on the latest commit.
          </p>
        </div>
      ) : null}
      {isLoading && !data ? (
        <p className="text-sm text-gray-500">Loading funnel stages…</p>
      ) : null}

      <div className="flex gap-3 overflow-x-auto pb-2">
        {stages.map((stage) => (
          <StageColumn
            key={stage.id}
            stage={stage}
            alerts={samples[stage.id] || []}
          />
        ))}
      </div>

      <p className="text-[11px] text-gray-600">
        Ready for Jira requires Case + TP/escalate plus an evidence bar: high/critical
        severity, or medium with confidence ≥70% and rule/MITRE metadata, or investigation
        summary — not every heuristic true_positive. needs_review needs analyst approval.
      </p>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-[#374151]/50 bg-dark-70/70 px-3 py-2.5">
      <p className="text-[11px] text-gray-500 uppercase tracking-wide">{label}</p>
      <p className="text-lg font-semibold text-gray-100 mt-0.5">{value}</p>
    </div>
  );
}
