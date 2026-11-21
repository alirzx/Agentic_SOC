'use client';

/**
 * Case overview panel: evidence + alert reports + investigation actions + outcome.
 */

import type { ReactNode } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { casesApi, type CaseInvestigationBrief } from '@/lib/api';

/** How many pieces of evidence the brief shows before deferring to the rail. */
const EVIDENCE_HIGHLIGHTS = 3;

const OUTCOME_STYLE: Record<string, string> = {
  incident: 'border-red-500/40 bg-red-500/10 text-red-200',
  false_positive: 'border-gray-500/40 bg-gray-500/10 text-gray-300',
  benign: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200',
  needs_review: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  escalated: 'border-orange-500/40 bg-orange-500/10 text-orange-200',
  unknown: 'border-slate-500/40 bg-slate-500/10 text-slate-300',
};

export function CaseInvestigationBriefPanel({ caseId }: { caseId: string }) {
  const { data, error, isLoading, mutate } = useSWR(
    caseId ? ['case-brief', caseId] : null,
    () => casesApi.getInvestigationBrief(caseId),
    { revalidateOnFocus: false },
  );

  if (isLoading && !data) {
    return (
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 text-sm text-slate-500">
        Loading investigation brief…
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300">
        Could not load investigation brief.{' '}
        <button type="button" className="underline" onClick={() => void mutate()}>
          Retry
        </button>
      </div>
    );
  }

  if (!data) return null;

  return <BriefBody brief={data} />;
}

function BriefBody({ brief }: { brief: CaseInvestigationBrief }) {
  const outcomeCls = OUTCOME_STYLE[brief.outcome] || OUTCOME_STYLE.unknown;

  return (
    <section className="rounded-xl border border-slate-800/80 bg-slate-900/50 p-4 md:p-5 space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white">Investigation brief</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            What we did, the strongest evidence highlights, and the resulting outcome. Per-alert
            detail lives in <span className="text-slate-400">Linked alerts</span>.
          </p>
        </div>
        <div className={clsx('rounded-lg border px-3 py-2 text-right', outcomeCls)}>
          <p className="text-[10px] uppercase tracking-wide opacity-80">Outcome</p>
          <p className="text-sm font-semibold">{brief.outcome_label}</p>
        </div>
      </header>

      <p className="text-xs text-slate-400">{brief.outcome_rationale}</p>

      <div className="flex flex-wrap gap-2 text-[11px]">
        {Object.entries(brief.disposition_counts || {}).map(([k, n]) => (
          <span
            key={k}
            className="rounded border border-slate-700/70 bg-slate-800/50 px-2 py-0.5 font-mono text-slate-300"
          >
            {k}: {n}
          </span>
        ))}
        {brief.ready_for_jira && (
          <span className="rounded border border-orange-500/40 bg-orange-500/10 px-2 py-0.5 text-orange-200">
            Ready for Jira
          </span>
        )}
        {brief.jira_pushed && (
          <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-emerald-200">
            Jira pushed
          </span>
        )}
        {brief.mitre_techniques?.slice(0, 6).map((t) => (
          <span
            key={t}
            className="rounded border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 font-mono text-violet-200"
          >
            {t}
          </span>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <BriefColumn title="What we did">
          {brief.what_we_did.length === 0 ? (
            <p className="text-[11px] text-slate-600">No actions recorded yet.</p>
          ) : (
            <ul className="space-y-2">
              {brief.what_we_did.map((a, i) => (
                <li key={`${a.kind}-${i}`} className="text-xs">
                  <p className="text-slate-200 font-medium">{a.label}</p>
                  {a.detail ? <p className="text-slate-500 mt-0.5 line-clamp-3">{a.detail}</p> : null}
                </li>
              ))}
            </ul>
          )}
        </BriefColumn>

        {/*
          Highlights only. This column used to list every alert's report (and a
          third column listed every alert again), which made the same seven
          alerts appear three times on one screen. The per-alert detail —
          title, severity, verdict, confidence, rationale — now lives in the
          `Linked alerts` rail, so this column keeps the first few pieces of
          evidence and points at the rail for the rest.
        */}
        <BriefColumn title="Key evidence">
          {brief.evidence.length === 0 ? (
            <p className="text-[11px] text-slate-600">No evidence snippets yet.</p>
          ) : (
            <>
              <ul className="space-y-2">
                {brief.evidence.slice(0, EVIDENCE_HIGHLIGHTS).map((e, i) => (
                  <li key={`${e.kind}-${i}`} className="text-xs">
                    <p className="text-[10px] uppercase tracking-wide text-slate-500">
                      {e.kind}
                      {e.source ? ` · ${e.source}` : ''}
                    </p>
                    <p className="text-slate-300 mt-0.5 line-clamp-3">{e.text}</p>
                  </li>
                ))}
              </ul>
              {brief.evidence.length > EVIDENCE_HIGHLIGHTS && (
                <p className="mt-2 text-[11px] text-slate-600">
                  +{brief.evidence.length - EVIDENCE_HIGHLIGHTS} more in Linked alerts
                </p>
              )}
            </>
          )}
        </BriefColumn>
      </div>

      {brief.next_step ? (
        <p className="text-xs text-cyan-200/90 border border-cyan-500/20 bg-cyan-500/5 rounded-lg px-3 py-2">
          <span className="font-semibold text-cyan-100">Next: </span>
          {brief.next_step}
        </p>
      ) : null}
    </section>
  );
}

function BriefColumn({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800/70 bg-slate-950/30 p-3 min-h-[140px]">
      <h3 className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 mb-2">
        {title}
      </h3>
      {children}
    </div>
  );
}
