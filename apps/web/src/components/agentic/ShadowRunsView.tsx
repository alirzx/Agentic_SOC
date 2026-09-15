'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { agenticShadowApi, type AgenticShadowRunSummary } from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';

export function ShadowRunsView() {
  const [rows, setRows] = useState<AgenticShadowRunSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    agenticShadowApi
      .list({ limit: 100 })
      .then((data) => {
        if (!cancelled) setRows(data);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return <p className="p-6 text-sm text-amgray-40">Loading shadow runs…</p>;
  }
  if (error) {
    return <ErrorState error={error} />;
  }
  if (rows.length === 0) {
    return (
      <EmptyState
        title="No shadow runs yet"
        description="Enable AGENTIC_SOC_ENABLED=true with SHADOW_MODE=true. Existing SOC flow is unchanged."
      />
    );
  }

  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Agentic SOC — Shadow Runs</h1>
        <p className="text-sm text-amgray-50">
          Parallel investigations. Production Case/Alert status is never modified.
        </p>
      </div>
      <div className="overflow-x-auto rounded border border-[#374151]">
        <table className="min-w-full text-sm">
          <thead className="bg-dark-70 text-left text-amgray-40">
            <tr>
              <th className="px-3 py-2">Case</th>
              <th className="px-3 py-2">Alert</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Duration</th>
              <th className="px-3 py-2">Risk</th>
              <th className="px-3 py-2">Confidence</th>
              <th className="px-3 py-2">Agent</th>
              <th className="px-3 py-2">Tools</th>
              <th className="px-3 py-2">Tokens</th>
              <th className="px-3 py-2">Cost</th>
              <th className="px-3 py-2">Decision</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-t border-[#374151]">
                <td className="px-3 py-2">
                  <Link className="text-sky-400 hover:underline" href={`/agentic/shadow-runs/${row.id}`}>
                    {row.case_id || '—'}
                  </Link>
                </td>
                <td className="px-3 py-2 font-mono text-xs">{row.alert_id}</td>
                <td className="px-3 py-2">{row.status}</td>
                <td className="px-3 py-2">{row.duration_ms} ms</td>
                <td className="px-3 py-2">{row.risk_score}</td>
                <td className="px-3 py-2">{row.confidence.toFixed(2)}</td>
                <td className="px-3 py-2">{row.agent_version}</td>
                <td className="px-3 py-2">{row.tool_call_count}</td>
                <td className="px-3 py-2">{row.input_tokens + row.output_tokens}</td>
                <td className="px-3 py-2">${row.estimated_cost.toFixed(4)}</td>
                <td className="px-3 py-2 max-w-xs truncate">{row.decision || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
