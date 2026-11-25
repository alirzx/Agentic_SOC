'use client';

import { useState } from 'react';
import useSWR from 'swr';

import { Skeleton } from '@/components/ui/Skeleton';
import { useTenant } from '@/components/layout/TenantProvider';
import { ledgerApi } from '@/lib/api';
import { type KnowledgeResource, tkgKnowledgeApi } from '@/lib/tkgKnowledge';

import { TkgEvaluationPanel } from './TkgEvaluationPanel';
import { KnowledgeCoverageView, TkgHistoryView } from './TkgHistoryView';

const readOptions = { revalidateOnFocus: false, shouldRetryOnError: false, keepPreviousData: false };
const section = 'space-y-2 rounded-lg border border-slate-200 dark:border-slate-800 p-4 text-sm';

function errorLabel(error: unknown) {
  const status = (error as { status?: number })?.status;
  if (status === 401 || status === 403) return 'You do not have access to this historical data.';
  if (status === 404) return 'No matching historical data is available.';
  return 'Knowledge data is temporarily unavailable.';
}

export function TkgCoverage({ kind, resourceId }: { kind: KnowledgeResource; resourceId: string }) {
  const workspace = useTenant().current?.id;
  const { data, error, isLoading, mutate } = useSWR(
    workspace ? ['tkg.coverage', workspace, kind, resourceId] as const : null,
    ([, tenant, resourceKind, id]) => tkgKnowledgeApi.coverage(tenant, resourceKind, id),
    readOptions,
  );
  if (!workspace) return <p role="status">Select a workspace to load knowledge coverage.</p>;
  if (error) return <p role="status">{errorLabel(error)} <button className="underline" onClick={() => void mutate()}>Retry</button></p>;
  if (isLoading) return <Skeleton className="h-24 w-full" />;
  if (!data) return null;
  return <>
    <div className="flex justify-end"><button className="text-xs underline" onClick={() => void mutate()}>Refresh delivery status</button></div>
    <KnowledgeCoverageView coverage={data} compact={kind === 'alert'} />
  </>;
}

interface RunProps {
  kind: KnowledgeResource;
  resourceId: string;
  runId?: string | null;
  chooseRun?: boolean;
  compact?: boolean;
}

function HistoryForWorkspace({ kind, resourceId, runId, chooseRun, compact, workspace }: RunProps & { workspace: string }) {
  const [selected, select] = useState<string>();
  const listing = useSWR(
    chooseRun && kind === 'case' ? ['tkg.case-runs', workspace, resourceId] as const : null,
    ([, tenant, id]) => ledgerApi.listRuns({ caseId: id, limit: 20, workspaceId: tenant }),
    readOptions,
  );
  const current = selected ?? runId ?? listing.data?.[0]?.id;
  const detail = useSWR(
    current ? ['tkg.run', workspace, kind, resourceId, current] as const : null,
    ([, tenant, resourceKind, id, active]) => tkgKnowledgeApi.history(tenant, resourceKind, id, active),
    {
      ...readOptions,
      refreshInterval: (value) => value?.run_status === 'running' && Date.now() - Date.parse(value.started_at) < 300_000 ? 4000 : 0,
    },
  );
  return (
    <section className={section} aria-label="Historical investigation">
      <h3 className="font-semibold">{compact ? 'Historical Recon evidence' : 'Historical investigation'}</h3>
      {listing.data && listing.data.length > 0 && <label className="block text-xs">Investigation run
        <select className="ml-2 rounded border bg-transparent p-1" value={current ?? ''} onChange={(event) => select(event.target.value)}>
          {current && !listing.data.some((run) => run.id === current) && <option value={current}>{current.slice(0, 8)}</option>}
          {listing.data.map((run) => <option key={run.id} value={run.id}>{new Date(run.started_at).toLocaleString()} · {run.id.slice(0, 8)}</option>)}
        </select>
      </label>}
      {(listing.error || detail.error) ? <p role="status">{errorLabel(listing.error ?? detail.error)} <button className="underline" onClick={() => void (listing.error ? listing.mutate() : detail.mutate())}>Retry</button></p>
        : listing.isLoading || detail.isLoading ? <Skeleton className="h-20 w-full" />
        : detail.data ? <TkgHistoryView run={detail.data} compact={compact} />
        : <p role="status">No investigation run is selected.</p>}
    </section>
  );
}

export function TkgRunHistory(props: RunProps) {
  const workspace = useTenant().current?.id;
  return workspace ? <HistoryForWorkspace {...props} workspace={workspace} key={`${workspace}/${props.kind}/${props.resourceId}`} /> : null;
}

export function CaseTkgKnowledgePanel({ caseId, runId }: { caseId: string; runId?: string | null }) {
  const workspace = useTenant().current?.id;
  return (
    <div className="space-y-4">
      <TkgCoverage kind="case" resourceId={caseId} />
      <TkgRunHistory kind="case" resourceId={caseId} runId={runId} chooseRun />
      {workspace && <section aria-label="Knowledge evaluation">
        <h3 className="mb-2 text-sm font-semibold">Knowledge evaluation</h3>
        <TkgEvaluationPanel key={`${workspace}/${caseId}`} caseId={caseId} workspace={workspace} />
      </section>}
    </div>
  );
}
