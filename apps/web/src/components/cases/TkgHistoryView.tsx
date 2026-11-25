import type { HistoricalFact, KnowledgeCoverage, KnowledgeRun } from '@/lib/tkgKnowledge';

const label = (value?: string | null) => value?.replace(/^tkg\./, '').replace(/_/g, ' ') ?? 'Unavailable';
const stamp = (value?: string | null) => value ? new Date(value).toLocaleString() : 'Unavailable';
const short = (value: string) => value.slice(0, 8);

const card = 'rounded-lg border border-slate-200 dark:border-slate-800 p-4 text-sm';
const quiet = 'text-xs text-slate-600 dark:text-slate-400';

export function KnowledgeCoverageView({ coverage, compact = false }: { coverage: KnowledgeCoverage; compact?: boolean }) {
  const counts = coverage.delivery_counts;
  const pending = counts.pending_materialization ?? 0;
  const waiting = (counts.not_submitted ?? 0) + (counts.submitting ?? 0);
  const healthy = coverage.enabled_bindings > 0;
  return (
    <section className={card} aria-label="Knowledge coverage">
      <h3 className="font-semibold">Knowledge coverage</h3>
      <p className={quiet}>{healthy ? `${coverage.covered_bindings} applicable of ${coverage.enabled_bindings} enabled bindings`
        : coverage.configured_bindings ? 'Workspace integration is disabled' : 'Workspace integration is not configured'}</p>
      <dl className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {(!compact ? [['Linked alerts', coverage.alerts], ['Eligible alerts', coverage.eligible_alerts]] : []).concat([
          ['Accepted receipts', coverage.accepted_receipts], ['Pending materialization', pending],
          ['Materialized', counts.bound ?? 0], ['Awaiting submission', waiting],
          ['Scheduled submission retry', counts.retry_scheduled ?? 0], ['Recoverable receipt failure', coverage.recoverable_receipts],
          ['Quarantined', counts.quarantined ?? 0],
        ]).map(([term, value]) => (
          <div key={term}><dt className={quiet}>{term}</dt><dd className="font-medium tabular-nums">{value}</dd></div>
        ))}
      </dl>
      <p className={`mt-3 ${quiet}`}>Last delivery update {stamp(coverage.last_updated)}</p>
    </section>
  );
}

function Relationship({ fact }: { fact: HistoricalFact }) {
  const pair = fact.direction === 'in' ? [fact.other_id, fact.root_id] : [fact.root_id, fact.other_id];
  const relationship = pair[0] && pair[1] && fact.direction;
  return (
    <details className="rounded border border-slate-200 px-3 py-2 dark:border-slate-800">
      <summary>
        {relationship ? <><code title={pair[0]!}>{short(pair[0]!)}</code> → {label(fact.predicate_key)} → <code title={pair[1]!}>{short(pair[1]!)}</code></> : label(fact.predicate_key)}
        {fact.other_type ? ` · ${label(fact.other_type)}` : ''}
        {fact.contested ? ' · Conflicting evidence' : fact.stale ? ' · Stale evidence' : fact.inferred ? ' · Inferred fact' : fact.sources.length ? ' · Observed fact' : ' · Fact without a retained source'}
      </summary>
      <dl className={`mt-2 grid grid-cols-2 gap-1 ${quiet}`}>
        <dt>Valid from</dt><dd>{fact.valid_from ?? 'Unavailable'}</dd>
        <dt>Valid to</dt><dd>{fact.valid_to ?? 'Unavailable'}</dd>
        <dt>Recorded time</dt><dd>{fact.recorded_at ?? 'Unavailable'}</dd>
        <dt>Knowledge as of</dt><dd>{fact.knowledge_time ?? 'Unavailable'}</dd>
        <dt>Fact reference</dt><dd className="break-all">{fact.kb_id}/{fact.id}</dd>
      </dl>
      {fact.sources.length > 0 && <ul className={`mt-2 ${quiet}`} aria-label="Evidence sources">
        {fact.sources.map((ref) => <li className="break-all" key={`${ref.document_id}/${ref.chunk_id}`}>Document {ref.document_id} · Chunk {ref.chunk_id}</li>)}
      </ul>}
    </details>
  );
}

export function TkgHistoryView({ run, compact = false }: { run: KnowledgeRun; compact?: boolean }) {
  const history = run.history;
  const budget = (used: number | null, limit?: number) => used === null ? 'Unavailable' : limit === undefined ? used : `${used} / ${limit}`;
  return (
    <div className="space-y-3" aria-label="Historical Recon result">
      <p className={quiet}><code title={run.run_id}>{short(run.run_id)}</code> · {stamp(run.started_at)} · Investigation {label(run.run_status)}</p>
      {!history ? (
        <p role="status" className={quiet}>{run.run_status === 'running' ? 'Historical results are pending.' : 'This run has no saved historical result.'}</p>
      ) : (
        <>
          <p><strong className="capitalize">{label(history.historical_status)}</strong>{history.profile ? ` · ${label(history.profile)} profile` : ''}{history.stop_reason ? ` · Stopped: ${label(history.stop_reason)}` : ''}</p>
          {history.truncated && <p className={quiet}>The saved view contains a bounded selection of historical observations.</p>}
          <dl className={`grid grid-cols-2 gap-1 ${quiet}`}>
            <dt>Tools</dt><dd>{budget(history.tool_calls, history.limits.tools)}</dd>
            <dt>Transport requests</dt><dd>{budget(history.tool_requests, history.limits.requests)}</dd>
            <dt>Model attempts</dt><dd>{budget(history.llm_calls, history.limits.model_calls)}</dd>
            <dt>Provider calls</dt><dd>{budget(history.provider_calls)}</dd>
            <dt>Preflight tools</dt><dd>{budget(history.preflight_tool_calls ?? null)}</dd>
            <dt>Planner attempts</dt><dd>{budget(history.planner_attempts ?? null)}</dd>
            <dt>Final assessment</dt><dd className="capitalize">{label(history.assessment_status)}</dd>
            <dt>Token budget charged</dt><dd>{budget(history.reserved_tokens_charged, history.limits.model_tokens)}</dd>
            <dt>Estimated cost</dt><dd>{history.estimated_cost_usd === null ? 'Unavailable' : `$${history.estimated_cost_usd.toFixed(4)}`}</dd>
            {Object.entries(history.coverage).filter(([, value]) => typeof value === 'number').map(([name, value]) => (
              <div key={name} className="contents"><dt className="capitalize">{label(name)}</dt><dd>{Number(value)}</dd></div>
            ))}
          </dl>
          {history.tools.length > 0 && <details>
            <summary className="font-medium">Recorded tool outcomes</summary>
            <ol className={`mt-2 space-y-1 ${quiet}`}>
              {history.tools.map((tool, index) => <li key={`${tool.tool}-${index}`}>
                {label(tool.tool)} · {label(tool.status)}{tool.seed_id ? ` · ${tool.seed_id}` : ''} · {tool.fact_count} facts
                {tool.duration_ms !== null ? ` · ${tool.duration_ms} ms` : ''}{tool.truncated ? ' · Truncated' : ''}
              </li>)}
            </ol>
          </details>}
          {!compact && history.entities.length > 0 && <details><summary className="font-medium">Resolved entities</summary>
            <ul className={quiet}>{history.entities.map((entity) => <li key={`${entity.kb_id}/${entity.id}`} className="break-all">{entity.kb_id}/{entity.id}</li>)}</ul>
          </details>}
          {history.facts.length > 0 && <details><summary className="font-medium">Historical relationships and evidence</summary>
            <div className="mt-2 space-y-2">{history.facts.map((fact) => <Relationship key={`${fact.kb_id}/${fact.id}`} fact={fact} />)}</div>
          </details>}
          {!compact && history.candidates.length > 0 && <details><summary className="font-medium">Unverified search candidates</summary>
            <ul className={quiet}>{history.candidates.map((item) => <li key={`${item.kb_id}/${item.chunk_id}`} className="break-all">Document {item.document_id} · Chunk {item.chunk_id}</li>)}</ul>
          </details>}
          {history.claims.length > 0 && <div><h4 className="font-medium">Claims requiring analyst review</h4>
            <ul className={`space-y-2 ${quiet}`}>{history.claims.map((claim, index) => <li key={index}>
              {claim.claim}<div className="break-all">{claim.citations.join(' · ')}</div>
            </li>)}</ul>
          </div>}
        </>
      )}
    </div>
  );
}
