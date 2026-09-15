'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { agenticShadowApi, type AgenticShadowRunDetail } from '@/lib/api';
import { ErrorState } from '@/components/ui/ErrorState';

export function ShadowRunDetailView({ runId }: { runId: string }) {
  const [run, setRun] = useState<AgenticShadowRunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    agenticShadowApi
      .get(runId)
      .then((data) => {
        if (!cancelled) setRun(data);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [runId]);

  if (error) {
    return <ErrorState error={error} />;
  }
  if (!run) {
    return <p className="p-6 text-sm text-amgray-40">Loading…</p>;
  }

  const existing = run.comparison.existing || {};
  const agentic = run.comparison.agentic || {};
  const differences = run.comparison.differences || [];

  return (
    <div className="p-6 space-y-6">
      <Link href="/agentic/shadow-runs" className="text-sm text-sky-400 hover:underline">
        Back to shadow runs
      </Link>
      <h1 className="text-xl font-semibold">Shadow run {run.id}</h1>
      <p className="text-sm text-amgray-50">
        Case {run.case_id || '—'} · Alert {run.alert_id} · {run.status} · {run.duration_ms} ms
      </p>
      <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <dt className="text-amgray-50">Risk</dt>
          <dd>{run.risk_score}</dd>
        </div>
        <div>
          <dt className="text-amgray-50">Confidence</dt>
          <dd>{run.confidence.toFixed(2)}</dd>
        </div>
        <div>
          <dt className="text-amgray-50">Tokens</dt>
          <dd>
            {run.input_tokens} in / {run.output_tokens} out
          </dd>
        </div>
        <div>
          <dt className="text-amgray-50">Est. cost</dt>
          <dd>${run.estimated_cost.toFixed(4)}</dd>
        </div>
      </dl>
      <p className="text-sm">
        <span className="text-amgray-50">Decision: </span>
        {run.decision || '—'}
      </p>
      <p className="text-sm">
        <span className="text-amgray-50">Recommended actions: </span>
        {run.recommended_actions.length ? run.recommended_actions.join(', ') : '—'}
      </p>
      <div className="grid gap-4 md:grid-cols-2">
        <section className="rounded border border-[#374151] p-4">
          <h2 className="mb-2 font-medium">Existing SOC</h2>
          <pre className="whitespace-pre-wrap text-xs text-amgray-20">{JSON.stringify(existing, null, 2)}</pre>
        </section>
        <section className="rounded border border-[#374151] p-4">
          <h2 className="mb-2 font-medium">Agentic SOC</h2>
          <pre className="whitespace-pre-wrap text-xs text-amgray-20">{JSON.stringify(agentic, null, 2)}</pre>
        </section>
      </div>
      <section>
        <h2 className="mb-2 font-medium">Differences</h2>
        {differences.length === 0 ? (
          <p className="text-sm text-amgray-50">No recorded differences.</p>
        ) : (
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {differences.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
