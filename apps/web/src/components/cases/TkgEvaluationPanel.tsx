'use client';

/**
 * Second opinion from the Soorin TKG.
 *
 * One number, one place: the four-step chain owns the counts, the headline owns
 * the verdict and its confidence, and the diagnosis explains the arithmetic and
 * names the stage the run stopped at. Nothing is restated in a second panel —
 * a reviewer read the same `5 / 98` four times and could not tell whether the
 * cause was "never sent", "not processed", or "nothing to fetch".
 *
 * The stored evaluation is unchanged by all of this: advisory only, and the
 * case's evidence and status are never touched.
 */

import clsx from 'clsx';
import { useRouter } from 'next/navigation';
import { useMemo, useState } from 'react';

import { useTkgEvaluation } from '@/hooks/useTkgEvaluation';
import type { TkgAttributionAlert, TkgEvaluation, TkgRunSnapshot } from '@/lib/caseTkg';

const VERDICT_STYLE: Record<string, { label: string; className: string }> = {
  true_positive: { label: 'True positive', className: 'bg-rose-500/15 text-rose-300 ring-rose-500/30' },
  likely_tp: { label: 'Likely true positive', className: 'bg-orange-500/15 text-orange-300 ring-orange-500/30' },
  needs_more_evidence: {
    label: 'Needs more evidence',
    className: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
  },
  benign: { label: 'Likely benign', className: 'bg-sky-500/15 text-sky-300 ring-sky-500/30' },
  insufficient: { label: 'Insufficient evidence', className: 'bg-slate-500/15 text-slate-300 ring-slate-500/30' },
};

/**
 * What the graph's identity layer answered for one alert.
 *
 * These strings are the TKG's: `resolved` and `pending_materialization` both
 * mean "the graph has heard of this notable", and only the first has an entity
 * to read facts from. `not_found` is a real miss, not an error.
 */
const STATUS_META: Record<string, { label: string; tone: string; hint: string; cause?: string }> = {
  resolved: {
    label: 'in graph',
    tone: 'text-emerald-300',
    hint: 'The graph knows this notable and returned an entity to read facts from.',
  },
  pending_materialization: {
    label: 'sent · processing',
    tone: 'text-amber-300',
    // The side that owns the fix, in the row itself: nothing to re-send here.
    cause: 'TKG side — accepted, not materialised yet',
    hint: 'The TKG accepted this record (the ingest returned a receipt) but has not projected it into entities and facts yet. The delay is the graph’s own asynchronous processing, not the send path: re-sending changes nothing, so re-run once its queue has drained.',
  },
  not_found: {
    label: 'never sent',
    tone: 'text-rose-300',
    cause: 'AiSOC side — no record in the graph',
    hint: 'The graph has no record of this notable: it was never ingested, or its notable id differs from the identity the graph stores. The fix is on the send side — push it (Send missing alerts / backfill), then re-run. Waiting will not make it appear.',
  },
  unresolved: {
    label: 'sent, no entity',
    tone: 'text-slate-400',
    cause: 'TKG side — resolver returned no entity',
    hint: 'The resolver answered for this notable but returned no candidate entity, so there are no facts to read. Nothing to re-send; the graph holds a record it cannot map.',
  },
  skipped: {
    label: 'skipped',
    tone: 'text-slate-500',
    cause: 'run budget — not probed',
    hint: 'The evaluation hit its time budget before this alert was resolved. Re-run to cover it.',
  },
  unknown: {
    label: 'unknown',
    tone: 'text-slate-500',
    hint: 'The graph returned a status this build does not recognise; the raw value is in the tooltip.',
  },
};

/**
 * How far the graph got with one alert's evidence.
 *
 * `corroborated` needs at least two real facts; synthetic facts can show that
 * the pipeline ran but can never corroborate, which is what `unconfirmed` means.
 */
const PASS_META: Record<string, { label: string; tone: string; hint: string }> = {
  corroborated: {
    label: 'corroborated',
    tone: 'text-emerald-300',
    hint: 'At least two real (non-synthetic) graph facts support this alert.',
  },
  contextualized: {
    label: 'contextualized',
    tone: 'text-emerald-300',
    hint: 'Corroborated by facts, and the judge used them to place the alert in the campaign.',
  },
  unconfirmed: {
    label: 'unconfirmed',
    tone: 'text-amber-300',
    hint: 'Facts exist but they are synthetic-only, or there are fewer than two: enough to see the graph ran, not enough to confirm.',
  },
  none: {
    label: '—',
    tone: 'text-slate-500',
    hint: 'No facts were read, because the alert did not resolve to an entity.',
  },
};

function metaFor<T extends { label: string; tone: string; hint: string }>(
  table: Record<string, T>,
  key: string,
  fallback: T
): T {
  return table[key] ?? fallback;
}

function shortId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}…` : value;
}

function pct(part: number, total: number): string {
  if (total <= 0) return '0%';
  return `${Math.round((part / total) * 100)}%`;
}

function StatusRow({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: string;
  tone?: string;
  hint?: string;
}) {
  return (
    <div
      className="flex items-baseline justify-between gap-3 border-b border-slate-800/60 py-1.5 last:border-0"
      title={hint}
    >
      <span
        className={clsx(
          'text-[11px] uppercase tracking-wide text-slate-500',
          hint && 'cursor-help underline decoration-dotted decoration-slate-700 underline-offset-2'
        )}
      >
        {label}
      </span>
      <span className={clsx('text-xs font-medium', tone ?? 'text-slate-200')}>{value}</span>
    </div>
  );
}

/** The counts every other block in the panel reads from. */
interface RunFacts {
  total: number;
  inGraph: number;
  queued: number;
  notFound: number;
  skipped: number;
  dedup: number;
  facts: number;
  realFacts: number;
  syntheticFacts: number;
  corroborated: number;
  coverage: number;
  confidence: number | null;
  /** The rubric's own arithmetic, reproduced so the panel can show it. */
  scoreFromCoverage: number;
  scoreFromCorroboration: number;
  scoreFromContextualized: number;
}

function readRun(evaluation: TkgEvaluation, alerts: TkgAttributionAlert[]): RunFacts {
  const attribution = evaluation.attribution ?? {};
  let queued = 0;
  let notFound = 0;
  let skipped = 0;
  let corroborated = 0;
  for (const alert of alerts) {
    if (alert.status === 'pending_materialization') queued += 1;
    if (alert.status === 'not_found' || alert.status === 'unresolved') notFound += 1;
    if (alert.status === 'skipped') skipped += 1;
    if (alert.pass === 'corroborated' || alert.pass === 'contextualized') corroborated += 1;
  }
  const total = alerts.length || Number(evaluation.stats?.alerts ?? 0);
  const inGraph = alerts.filter((alert) => Boolean(alert.entity_id)).length;
  const coverage = total > 0 ? inGraph / total : 0;
  const capped = Math.min(corroborated, 4);
  const contextualized = alerts.some((alert) => alert.pass === 'contextualized');
  return {
    total,
    inGraph,
    queued,
    notFound,
    skipped,
    dedup: alerts.filter((alert) => alert.deduplicated).length,
    facts: Number(attribution.facts ?? 0),
    realFacts: Number(attribution.real_facts ?? 0),
    syntheticFacts: Number(attribution.synthetic_facts ?? 0),
    corroborated,
    coverage,
    confidence: typeof evaluation.confidence === 'number' ? evaluation.confidence : null,
    // Mirrors rubric.evidence_floor: int(coverage × 45) + min(corroborated, 4) × 12
    // (+10 when the judge contextualised an alert).
    scoreFromCoverage: Math.trunc(coverage * 45),
    scoreFromCorroboration: capped * 12,
    scoreFromContextualized: contextualized ? 10 : 0,
  };
}

/** One step of the chain; `state` colours the marker, never the wording. */
function Step({
  index,
  title,
  value,
  detail,
  hint,
  state,
  last = false,
}: {
  index: number;
  title: string;
  value: string;
  detail?: string;
  hint: string;
  state: 'done' | 'partial' | 'empty' | 'queued';
  last?: boolean;
}) {
  const marker =
    state === 'done'
      ? 'border-emerald-500/50 bg-emerald-500/15 text-emerald-300'
      : state === 'partial'
        ? 'border-amber-500/50 bg-amber-500/15 text-amber-300'
        : state === 'queued'
          ? 'border-sky-500/50 bg-sky-500/15 text-sky-300'
          : 'border-slate-700 bg-slate-800/40 text-slate-400';
  return (
    <li className="flex gap-2.5" title={hint}>
      <div className="flex flex-col items-center">
        <span
          className={clsx(
            'flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[10px] font-semibold',
            marker
          )}
        >
          {index}
        </span>
        {!last && <span className="mt-1 w-px flex-1 bg-slate-800" />}
      </div>
      <div className="min-w-0 flex-1 pb-2.5">
        <div className="flex flex-wrap items-baseline gap-2">
          <span className="text-[11px] text-slate-300">{title}</span>
          <span className="text-xs font-semibold text-slate-100">{value}</span>
        </div>
        {detail && <p className="mt-0.5 text-[10px] text-slate-500">{detail}</p>}
      </div>
    </li>
  );
}

/**
 * The chain, in order. Each step states its own number once; the breakdown of
 * *where* those numbers went is the diagnosis below, not another copy here.
 */
function FlowSteps({ run }: { run: RunFacts }) {
  return (
    <ol className="rounded border border-slate-800/70 bg-slate-900/30 p-3">
      <Step
        index={1}
        title="Case alert set"
        value={`${run.total} alert${run.total === 1 ? '' : 's'}`}
        detail="the evidence the engine scored; excluded and filtered alerts are never sent"
        hint="Canonical members plus soft-dedup witnesses. That is the denominator of every percentage below."
        state={run.total > 0 ? 'done' : 'empty'}
      />
      <Step
        index={2}
        title="Identity resolved"
        value={`${run.inGraph} / ${run.total} (${pct(run.inGraph, run.total)})`}
        detail="the graph returned an entity for these alerts"
        hint="Each alert is looked up by the notable id the graph was fed with. Only a resolved entity can be read for facts."
        state={
          run.total > 0 && run.inGraph === run.total
            ? 'done'
            : run.inGraph > 0
              ? 'partial'
              : run.queued > 0
                ? 'queued'
                : 'empty'
        }
      />
      <Step
        index={3}
        title="Facts read"
        value={String(run.facts)}
        detail={
          run.inGraph > 0
            ? `claims held about those ${run.inGraph} entit${run.inGraph === 1 ? 'y' : 'ies'}`
            : 'nothing resolved, so nothing could be read'
        }
        hint="Facts are the claims the graph holds about the resolved entities. These are the only evidence the verdict may rest on."
        state={run.facts > 0 ? (run.realFacts > 0 ? 'done' : 'partial') : 'empty'}
      />
      <Step
        index={4}
        title="Alerts corroborated"
        value={run.inGraph > 0 ? `${run.corroborated} of ${run.inGraph} resolved` : '0'}
        detail="two or more real facts support the alert"
        hint="Synthetic facts never corroborate. Coverage below 60% cannot confirm the case whatever this number is."
        state={run.corroborated > 0 ? 'done' : 'empty'}
        last
      />
    </ol>
  );
}

const RUN_STAGE_ORDER = ['precheck', 'resolve', 'context', 'materialise', 'judge', 'persist', 'done'];

function runStageIndex(stage: string): number {
  const index = RUN_STAGE_ORDER.indexOf(stage);
  return index < 0 ? 0 : index;
}

/**
 * What the run is doing right now.
 *
 * The evaluation is not one call: every alert is resolved by id, and the ones
 * the graph accepted without projecting IP are re-probed in waves. A spinner
 * that says only "asking TKG" hides all of that, so each stage prints the
 * counter it owns and the whole panel stays answerable mid-run.
 */
/**
 * What the wait step says under `wave N`.
 *
 * The wave counter is a re-probe round, not a count of alerts — 290 waves for 73
 * queued alerts is correct and used to read as a bug. The line now leads with
 * what is queued and how long the wait may still last.
 */
function waitSub(live: TkgRunSnapshot): string {
  const wave = `wave ${live.wave}`;
  if (live.pending === 0) return `${wave} · nothing queued`;
  if (live.wait_left_s === -1) return `${wave} · waits until the graph has them all`;
  if (live.wait_left_s === undefined) return `${wave} · re-probing the queued set`;
  const left = Math.max(0, live.wait_left_s);
  const minutes = Math.floor(left / 60);
  const seconds = left % 60;
  const clock = minutes > 0 ? `${minutes}m ${String(seconds).padStart(2, '0')}s` : `${seconds}s`;
  return `${wave} · ${live.pending} queued · ${clock} of waiting left`;
}

/**
 * Which pass the run is in: distinct alerts first, witnesses second.
 *
 * Without it the stepper showed one "wait for the graph" stage for both, so a
 * run pushing three canonical alerts looked exactly like one pushing a thousand
 * duplicate witnesses.
 */
function passLabel(live: TkgRunSnapshot): string {
  const index =
    live.phase_index && live.phase_count
      ? `Pass ${live.phase_index} of ${live.phase_count}`
      : 'Pass';
  const name = live.phase === 'dedup' ? 'duplicate witnesses' : 'canonical alerts';
  const total = live.phase_total
    ? ` · ${live.phase_total} alert${live.phase_total === 1 ? '' : 's'}`
    : '';
  return `${index} — ${name}${total}`;
}

function RunProgress({
  live,
  onCancel,
  onSkipWait,
}: {
  live: TkgRunSnapshot;
  onCancel: () => void;
  onSkipWait: () => void;
}) {
  const stage = runStageIndex(live.stage);
  const running = live.state === 'running';
  const elapsed = `${Math.floor(live.elapsed_ms / 1000)}s`;
  const steps = [
    {
      label: 'Read the case',
      value: live.total > 0 ? `${live.total} alerts in the set` : 'collecting the alert set',
      done: stage > 0,
      active: stage === 0,
    },
    {
      label: 'Resolve identities',
      value: live.total > 0 ? `${live.probed} / ${live.total} probed` : 'no alerts to probe',
      sub:
        live.resolved > 0
          ? `${live.resolved} returned an entity · ${live.facts} facts read`
          : 'none returned an entity yet',
      done: stage > 2,
      active: stage === 1 || stage === 2,
    },
    {
      label: live.phase
        ? `Wait for the graph — ${live.phase === 'dedup' ? 'duplicates' : 'canonical'}`
        : 'Wait for the graph',
      value:
        live.pending > 0
          ? `${live.pending} accepted, not projected yet`
          : 'nothing left waiting',
      sub: waitSub(live),
      hint: 'The wait is capped (10 minutes by default) and can be stopped here. Either way the run then judges and stores what is resolved: a queued alert never blocks the verdict.',
      done: stage > 3,
      active: stage === 3,
      skipped: stage < 3 && live.pending === 0 && live.probed < live.total,
    },
    {
      label: 'Judge and store',
      value:
        live.state === 'finished' && live.result
          ? `${live.result.verdict ?? 'no verdict'} · confidence ${live.result.confidence ?? '—'}`
          : stage >= 4
            ? 'scoring the evidence'
            : 'not started yet',
      done: stage >= 6 || live.state === 'finished',
      active: stage === 4 || stage === 5,
    },
  ];

  return (
    <div className="rounded border border-emerald-500/25 bg-emerald-500/[0.04] p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs font-medium text-emerald-200">
            {running ? 'Running — this panel updates itself' : `Run ${live.state}`}
            <span className="ml-2 font-mono text-[10px] text-emerald-300/70">{elapsed}</span>
          </p>
          <p className="mt-0.5 text-[10px] text-slate-500">
            {running
              ? 'The numbers below are this run’s live result — they update as each alert is resolved and sent, and are replaced by the stored run when it finishes.'
              : live.state === 'cancelled' || live.state === 'failed'
                ? 'What the run had scored was stored as a partial result, so it is still below instead of the previous run.'
                : 'The stored run is below.'}
          </p>
          {live.phase && (
            <p className="mt-1">
              <span
                className={clsx(
                  'inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ring-1',
                  live.phase === 'dedup'
                    ? 'bg-slate-500/10 text-slate-300 ring-slate-600/40'
                    : 'bg-emerald-500/10 text-emerald-200 ring-emerald-500/30'
                )}
                title={
                  live.phase === 'dedup'
                    ? 'Second pass: the soft-dedup witnesses. They are evidence, not independent observations, and they are sent only after the distinct alerts have been scored and stored.'
                    : 'First pass: the distinct (canonical) alerts. They are sent, waited on, judged and stored before any duplicate witness is pushed.'
                }
              >
                {passLabel(live)}
              </span>
            </p>
          )}
        </div>
        {running && (
          <div className="flex shrink-0 flex-col items-end gap-1">
            {live.can_skip_wait && (
              <button
                type="button"
                onClick={onSkipWait}
                className="whitespace-nowrap rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-[10px] text-amber-200 hover:border-amber-400 hover:text-amber-100"
                title="Ends the wait for the graph only. The run still judges and stores what is resolved; the queued alerts keep materialising and are read on the next run."
              >
                Stop waiting &amp; score
              </button>
            )}
            <button
              type="button"
              onClick={onCancel}
                              className="shrink-0 rounded border border-slate-700 px-2 py-1 text-[10px] text-slate-300 hover:border-rose-500/40 hover:text-rose-200"
                title="Stops the run at its next checkpoint. What it has already resolved and scored is stored as a partial result."
            >
              Cancel run
            </button>
          </div>
        )}
      </div>

      <ol className="mt-2 space-y-1.5">
        {steps
          .filter((step) => !step.skipped)
          .map((step) => (
            <li key={step.label} className="flex items-start gap-2">
              <span
                className={clsx(
                  'mt-[3px] inline-block h-2.5 w-2.5 shrink-0 rounded-full border',
                  step.done
                    ? 'border-emerald-400 bg-emerald-400/70'
                    : step.active
                      ? 'animate-pulse border-emerald-300 bg-emerald-300/30'
                      : 'border-slate-700'
                )}
              />
              <div className="min-w-0">
                <p className="text-[11px] text-slate-300">
                  {step.label} <span className="text-slate-100">{step.value}</span>
                </p>
                {step.sub && <p className="text-[10px] text-slate-500">{step.sub}</p>}
              </div>
            </li>
          ))}
      </ol>

      {live.message && <p className="mt-2 text-[10px] text-emerald-300/80">{live.message}</p>}
      {live.state === 'failed' && live.error && (
        <p className="mt-2 text-[10px] text-rose-300">{live.error}</p>
      )}
      {running && (
        <p className="mt-2 text-[10px] text-slate-600">
          The wait is capped (10 minutes by default) and can be ended with{' '}
          <span className="text-slate-400">Stop waiting &amp; score</span>: the run judges and
          stores what is resolved, and the queued alerts are read on the next run.{' '}
          <span className="text-slate-400">Cancel run</span> stops the run and stores what it had
          already scored as a partial result.
        </p>
      )}
    </div>
  );
}

interface Finding {
  stage: string;
  headline: string;
  body: string;
  tone: 'blocker' | 'waiting' | 'info';
}

/**
 * Name the stage the run stopped at, in the order the pipeline runs.
 *
 * This is the answer to "confidence is 50 — why?": each finding is a stage that
 * failed, with the action that clears it. Nothing here is inferred from the
 * verdict; every line is a count from the run.
 */
function findingsFor(run: RunFacts, attribution: TkgEvaluation['attribution']): Finding[] {
  const findings: Finding[] = [];
  const sent = attribution.send?.sent?.length ?? 0;
  const rejected = attribution.send?.rejected?.length ?? 0;
  if (sent || rejected) {
    findings.push({
      stage: 'Pushed by this run',
      headline: `${sent} alert${sent === 1 ? '' : 's'} sent to the graph${rejected ? ` · ${rejected} rejected` : ''}`,
      body: rejected
        ? 'The rejected records were refused by the graph normalizer (HTTP 422) — usually a malformed or oversized notable id. They are a send-side problem, not a network one.'
        : 'The graph accepted these during this run; materialisation is asynchronous, so they stay “sent · processing” until it projects them into entities and facts.',
      tone: sent ? 'info' : 'blocker',
    });
  }
  if (run.notFound > 0) {
    findings.push({
      stage: 'Never ingested',
      headline: `${run.notFound} alert${run.notFound === 1 ? '' : 's'} are not in the graph at all`,
      body: 'The graph has no entity for them: they were never pushed, or their notable id differs from the one the graph stores. Re-run with writes enabled and this run sends them itself; otherwise check the ingest pipeline for this source.',
      tone: 'blocker',
    });
  }
  if (run.queued > 0) {
    findings.push({
      stage: 'Not materialised yet',
      headline: `${run.queued} alert${run.queued === 1 ? ' is' : 's are'} accepted but not projected into the graph`,
      body: 'The write succeeded; materialisation is asynchronous. There is nothing to re-send — re-run the evaluation once the graph has projected them.',
      tone: 'waiting',
    });
  }
  const graphFailures = attribution.graph_failures;
  if (graphFailures && graphFailures.count > 0) {
    findings.push({
      stage: 'Graph gave up on the documents',
      headline: `${graphFailures.count} queued document${graphFailures.count === 1 ? '' : 's'} failed inside the graph (${graphFailures.error})`,
      body: 'The graph accepted the record but its extractor stopped on it: it retried a rate limit a few times and then marked the document failed, so re-probing would wait forever. The fix is on the graph side — open TKG → Library, refresh those documents (the per-document refresh re-runs extraction), then re-run this evaluation.',
      tone: 'blocker',
    });
  }
  if (run.inGraph > 0 && run.facts === 0) {
    findings.push({
      stage: 'Nothing to fetch',
      headline: 'The resolved entities returned no facts',
      body: 'The graph knows these alerts as entities but holds no claims around them, so there is nothing the verdict could rest on. Ingest the supporting events for those entities.',
      tone: 'blocker',
    });
  } else if (run.facts > 0 && run.corroborated === 0) {
    findings.push({
      stage: 'Facts too thin',
      headline: 'Facts exist, but no alert reaches two real ones',
      body: 'Corroboration needs at least two non-synthetic facts per alert. Single facts, or facts that all trace to seed documents, leave the alert unconfirmed.',
      tone: 'blocker',
    });
  }
  if (run.coverage > 0 && run.coverage < 0.6) {
    findings.push({
      stage: 'Below the confirm threshold',
      headline: `Coverage is ${pct(run.inGraph, run.total)} — the rubric needs 60% to confirm`,
      body: 'Below that share the strongest possible verdict is “needs more evidence”, even if every resolved alert corroborates. This is a floor, not a judgement about the case.',
      tone: 'info',
    });
  }
  if (run.skipped > 0) {
    findings.push({
      stage: 'Time budget',
      headline: `${run.skipped} alert${run.skipped === 1 ? ' was' : 's were'} skipped`,
      body: 'The run hit its wall-clock budget before reaching them. Re-running usually covers them; a persistently partial run means the graph is answering slowly.',
      tone: 'waiting',
    });
  }
  if (Boolean(attribution?.synthetic_only)) {
    findings.push({
      stage: 'Synthetic evidence',
      headline: 'Every supporting fact is synthetic',
      body: 'A seed/demo graph can corroborate but never confirm: the verdict is capped at “needs more evidence” and confidence at 55.',
      tone: 'blocker',
    });
  }
  return findings;
}

function Diagnosis({
  run,
  findings,
  evaluation,
}: {
  run: RunFacts;
  findings: Finding[];
  evaluation: TkgEvaluation;
}) {
  const toneClass: Record<Finding['tone'], string> = {
    blocker: 'border-rose-500/30 bg-rose-500/5',
    waiting: 'border-amber-500/30 bg-amber-500/5',
    info: 'border-slate-700 bg-slate-900/40',
  };
  const scored = run.scoreFromCoverage + run.scoreFromCorroboration + run.scoreFromContextualized;

  return (
    <div className="space-y-2 rounded border border-slate-800/70 bg-slate-900/20 p-3">
      <div className="flex flex-wrap items-baseline gap-2">
        <p className="text-[11px] font-medium text-slate-300">What held the verdict back</p>
        {run.confidence !== null && (
          <span
            className="cursor-help text-[10px] text-slate-500 underline decoration-dotted decoration-slate-700 underline-offset-2"
            title={`evidence_floor: int(coverage × 45) + min(corroborated, 4) × 12${run.scoreFromContextualized ? ' (+10 contextualized)' : ''} = ${run.scoreFromCoverage} + ${run.scoreFromCorroboration}${run.scoreFromContextualized ? ` + ${run.scoreFromContextualized}` : ''} = ${scored}, capped to 100.`}
          >
how confidence is scored
          </span>
        )}
      </div>

      <p className="font-mono text-[10px] text-slate-500">
        confidence = int({pct(run.inGraph, run.total)} × 45) = {run.scoreFromCoverage} &nbsp;+&nbsp; min(
        {run.corroborated}, 4) × 12 = {run.scoreFromCorroboration}
        {run.scoreFromContextualized ? ` + ${run.scoreFromContextualized}` : ''} &nbsp;=&nbsp; {scored}
      </p>

      {findings.length === 0 ? (
        <p className="text-[11px] text-slate-400">
          Every alert resolved and corroborated: nothing is blocking the verdict.
        </p>
      ) : (
        <ul className="space-y-1.5">
          {findings.map((finding) => (
            <li key={finding.stage} className={clsx('rounded border p-2', toneClass[finding.tone])}>
              <p className="text-[11px] text-slate-200">
                <span className="mr-1.5 rounded bg-slate-800/80 px-1 py-0.5 text-[9px] uppercase tracking-wide text-slate-400">
                  {finding.stage}
                </span>
                {finding.headline}
              </p>
              <p className="mt-1 text-[10px] leading-relaxed text-slate-400">{finding.body}</p>
            </li>
          ))}
        </ul>
      )}

      {evaluation.agree !== null && (
        <p className="text-[10px] text-slate-500">
          The correlation engine&apos;s own verdict is compared with the floor above; a disagreement is
          reported, never resolved by changing the case.
        </p>
      )}
    </div>
  );
}

function Legend() {
  return (
    <details className="rounded border border-slate-800/70 bg-slate-900/20 px-3 py-2 text-[11px] text-slate-400">
      <summary className="cursor-pointer text-slate-300">What the columns mean</summary>
      <div className="mt-2 grid gap-3 sm:grid-cols-2">
        <div>
          <p className="mb-1 text-[10px] uppercase tracking-wide text-slate-500">Status — identity layer</p>
          <ul className="space-y-1">
            {Object.entries(STATUS_META).map(([key, meta]) => (
              <li key={key}>
                <span className={clsx('font-medium', meta.tone)}>{meta.label}</span>{' '}
                <span className="font-mono text-[10px] text-slate-600">{key}</span> — {meta.hint}
                {meta.cause && (
                  <span className="ml-1 text-[10px] text-slate-500">({meta.cause})</span>
                )}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[10px] text-slate-500">
            Read the status as <span className="text-slate-400">whose problem it is</span>:{' '}
            <span className="text-rose-300">never sent</span> means AiSOC has to deliver the record,{' '}
            <span className="text-amber-300">sent · processing</span> means the TKG has it and is still
            materialising it. A re-run only helps the second case.
          </p>
        </div>
        <div>
          <p className="mb-1 text-[10px] uppercase tracking-wide text-slate-500">Pass — evidence layer</p>
          <ul className="space-y-1">
            {Object.entries(PASS_META).map(([key, meta]) => (
              <li key={key}>
                <span className={clsx('font-medium', meta.tone)}>{meta.label}</span>{' '}
                <span className="font-mono text-[10px] text-slate-600">{key}</span> — {meta.hint}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-[10px] text-slate-500">
            <span className="text-slate-400">Facts</span> is how many graph claims were read for that alert&apos;s
            entity; <span className="text-slate-400">(n syn)</span> marks the ones from synthetic documents.
          </p>
        </div>
      </div>
    </details>
  );
}

function AttributionTable({ alerts }: { alerts: TkgAttributionAlert[] }) {
  const router = useRouter();
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [pass, setPass] = useState<string | null>(null);
  // Witnesses are soft-dedup copies of alerts the workbench already shows; they
  // count as evidence but drown the list, so the default view leaves them out.
  const [hideDedup, setHideDedup] = useState(true);

  const dedupCount = useMemo(() => alerts.filter((alert) => alert.deduplicated).length, [alerts]);
  const pool = useMemo(
    () => (hideDedup ? alerts.filter((alert) => !alert.deduplicated) : alerts),
    [alerts, hideDedup]
  );

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const alert of pool) counts[alert.status] = (counts[alert.status] ?? 0) + 1;
    return counts;
  }, [pool]);
  const passCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const alert of pool) counts[alert.pass] = (counts[alert.pass] ?? 0) + 1;
    return counts;
  }, [pool]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return pool.filter((alert) => {
      if (status && alert.status !== status) return false;
      if (pass && alert.pass !== pass) return false;
      if (!needle) return true;
      return [alert.title, alert.rule, alert.alert_id, alert.row_id, alert.entity_id]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle));
    });
  }, [pass, pool, query, status]);

  if (alerts.length === 0) return null;

  const chip = (
    key: string,
    label: string,
    count: number,
    active: boolean,
    onClick: () => void,
    tone = 'text-slate-300'
  ) => (
    <button
      key={key}
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={clsx(
        'rounded border px-1.5 py-0.5 text-[10px] transition-colors',
        active
          ? 'border-teal-500/60 bg-teal-500/10 text-teal-200'
          : 'border-slate-800 text-slate-400 hover:border-slate-600 hover:text-slate-200'
      )}
    >
      <span className={active ? undefined : tone}>{label}</span>{' '}
      <span className="tabular-nums text-slate-500">{count}</span>
    </button>
  );

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1.5">
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filter by title, rule or id…"
          aria-label="Filter attributed alerts"
          className="w-52 rounded border border-slate-800 bg-slate-900/60 px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-600 focus:border-teal-500/60 focus:outline-none"
        />
        {dedupCount > 0 &&
          chip(
            'dedup',
            hideDedup ? 'dedup hidden' : 'hide dedup',
            dedupCount,
            hideDedup,
            () => setHideDedup((current) => !current),
            'text-violet-300'
          )}
        <span className="mx-1 h-3 w-px bg-slate-800" />
        {Object.entries(statusCounts).map(([key, count]) => {
          const meta = metaFor(STATUS_META, key, STATUS_META.unknown);
          return chip(key, meta.label, count, status === key, () =>
            setStatus((current) => (current === key ? null : key)), meta.tone);
        })}
        <span className="mx-1 h-3 w-px bg-slate-800" />
        {Object.entries(passCounts).map(([key, count]) => {
          const meta = metaFor(PASS_META, key, PASS_META.none);
          return chip(`pass:${key}`, meta.label, count, pass === key, () =>
            setPass((current) => (current === key ? null : key)), meta.tone);
        })}
        {(status || pass || query) && (
          <button
            type="button"
            onClick={() => {
              setStatus(null);
              setPass(null);
              setQuery('');
            }}
            className="rounded px-1.5 py-0.5 text-[10px] text-slate-400 underline-offset-2 hover:text-slate-200 hover:underline"
          >
            clear filters
          </button>
        )}
        <span className="ml-auto text-[10px] text-slate-500">
          {visible.length} of {pool.length} alerts
          {hideDedup && dedupCount > 0 ? ` (+${dedupCount} dedup hidden)` : ''}
        </span>
      </div>

      <div className="overflow-hidden rounded border border-slate-800/70">
        <table className="w-full text-left text-[11px]">
          <thead className="bg-slate-900/60 text-slate-500">
            <tr>
              <th
                className="px-2 py-1.5 font-medium"
                title="The alert's title and the rule that fired it. Click a row to open the alert in the workbench; hover for ids and techniques."
              >
                Alert
              </th>
              <th
                className="px-2 py-1.5 font-medium"
                title="Where the identity layer stopped and which side owns the fix: 'never sent' = AiSOC has no record in the graph (send side), 'sent · processing' = the TKG accepted it and is still materialising (TKG side)."
              >
                Status
              </th>
              <th
                className="px-2 py-1.5 text-right font-medium"
                title="Graph facts read for the alert's entity. (n syn) counts the ones that come from synthetic documents."
              >
                Facts
              </th>
              <th
                className="px-2 py-1.5 font-medium"
                title="Whether those facts support the alert: corroborated needs two or more real facts; synthetic-only facts leave it unconfirmed."
              >
                Pass
              </th>
            </tr>
          </thead>
          <tbody>
            {visible.map((alert) => {
              const statusMeta = metaFor(STATUS_META, alert.status, STATUS_META.unknown);
              const passMeta = metaFor(PASS_META, alert.pass, PASS_META.none);
              const name = alert.title || alert.rule || shortId(alert.alert_id);
              const rowTitle = [
                alert.title ?? null,
                alert.rule ? `rule: ${alert.rule}` : null,
                `notable: ${alert.alert_id}`,
                alert.row_id ? `alert: ${alert.row_id}` : null,
                alert.entity_id ? `entity: ${alert.entity_id}` : null,
                alert.time ? `time: ${alert.time}` : null,
                alert.techniques?.length ? `techniques: ${alert.techniques.join(', ')}` : null,
                alert.deduplicated ? 'soft-deduplicated witness' : null,
                alert.error ? `error: ${alert.error}` : null,
              ]
                .filter(Boolean)
                .join('\n');
              // Old stored runs have no AiSOC row id, so there is nothing to open.
              const href = alert.row_id ? `/alerts/${alert.row_id}` : null;
              return (
                <tr
                  key={alert.alert_id}
                  className={clsx(
                    'border-t border-slate-800/60',
                    href && 'cursor-pointer hover:bg-teal-500/[0.07] focus:outline-none focus-visible:bg-teal-500/10'
                  )}
                  title={href ? `${rowTitle}\n\nclick to open the alert` : rowTitle}
                  tabIndex={href ? 0 : undefined}
                  onClick={() => href && router.push(href)}
                  onKeyDown={(event) => {
                    if (!href) return;
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      router.push(href);
                    }
                  }}
                >
                  <td className="max-w-[22rem] px-2 py-1.5">
                    <div className="flex items-center gap-1.5">
                      <span className="truncate text-slate-200">{name}</span>
                      {href && (
                        <span aria-hidden="true" className="shrink-0 text-[10px] text-slate-600">
                          ↗
                        </span>
                      )}
                      {alert.deduplicated && (
                        <span
                          className="shrink-0 rounded bg-violet-500/15 px-1 py-0.5 text-[9px] uppercase tracking-wide text-violet-300 ring-1 ring-violet-500/25"
                          title="Soft-deduplicated evidence: scored as a case witness, hidden from the alerts workbench."
                        >
                          dedup
                          {alert.occurrence_count && alert.occurrence_count > 1
                            ? ` ×${alert.occurrence_count}`
                            : ''}
                        </span>
                      )}
                    </div>
                    {alert.rule && alert.rule !== name && (
                      <p className="truncate font-mono text-[10px] text-slate-500">{alert.rule}</p>
                    )}
                  </td>
                  <td className="px-2 py-1.5">
                    <span className={clsx('font-medium', statusMeta.tone)} title={`${alert.status} — ${statusMeta.hint}`}>
                      {statusMeta.label}
                    </span>
                    {statusMeta.cause && (
                      <p className="text-[9px] leading-tight text-slate-500">{statusMeta.cause}</p>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-right text-slate-400">
                    <span title={`${alert.facts} fact(s) read for this entity`}>{alert.facts}</span>
                    {alert.synthetic_facts > 0 && (
                      <span className="ml-1 text-amber-300" title="Facts derived from synthetic/seed documents">
                        ({alert.synthetic_facts} syn)
                      </span>
                    )}
                  </td>
                  <td className="px-2 py-1.5">
                    <span className={clsx(passMeta.tone)} title={`${alert.pass} — ${passMeta.hint}`}>
                      {passMeta.label}
                    </span>
                  </td>
                </tr>
              );
            })}
            {visible.length === 0 && (
              <tr className="border-t border-slate-800/60">
                <td colSpan={4} className="px-2 py-3 text-center text-slate-500">
                  No alert matches these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function TkgEvaluationPanel({ caseId, workspace, engineVerdict }: { caseId: string; workspace: string; engineVerdict?: string | null }) {
  const {
    evaluation,
    lastUsable,
    health,
    loading,
    neverRun,
    error,
    running,
    live,
    run,
    cancelRun,
    skipWait,
  } = useTkgEvaluation(caseId, workspace);
  // The newest attempt can fail to reach the graph; the panel then keeps showing
  // the last run that did reach it, clearly labelled, instead of a blank error.
  const unusable = Boolean(evaluation && evaluation.status !== 'ok' && evaluation.status !== 'partial');
  // While a run is in flight its own provisional evaluation is what the analyst
  // is judging: confidence, the four-step chain and the attribution table all
  // follow it, so they move alert by alert instead of waiting for the store.
  const liveEvaluation = running && live?.partial ? live.partial : null;
  const showingLive = Boolean(liveEvaluation);
  const shown = liveEvaluation ?? (unusable ? lastUsable : evaluation);
  const alerts = shown?.attribution?.alerts ?? [];
  const summary = useMemo(() => (shown ? readRun(shown, alerts) : null), [shown, alerts]);
  const findings = useMemo(
    () => (summary && shown ? findingsFor(summary, shown.attribution) : []),
    [summary, shown]
  );

  const blocked = health && (!health.configured || !health.ready);
  const disabled = running || loading || Boolean(blocked);
  const verdictStyle = VERDICT_STYLE[shown?.verdict ?? ''] ?? VERDICT_STYLE.insufficient;

  return (
    <section className="space-y-3 rounded-lg border border-slate-800/70 bg-slate-950/40 p-4">
      <header className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-slate-100">Second opinion — Soorin TKG</h2>
          <p className="mt-0.5 text-[11px] text-slate-500">
            Resolves each alert&apos;s identity in the knowledge graph and compares the graph&apos;s verdict with
            the correlation engine&apos;s. One click does the whole job: when the deployment allows writes
            (<code className="text-slate-400">AISOC_TKG_ALLOW_SEND</code>) the run also pushes the alerts the
            graph does not know yet, one at a time, then waits for them to materialise. While it runs, the
            numbers below are this run&apos;s own partial result and update alert by alert — stop it at any point
            and what it scored is stored. Advisory only — the case&apos;s evidence and status are never changed.
          </p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <button
            type="button"
            onClick={() => void run(engineVerdict ?? null, Boolean(evaluation))}
            disabled={disabled}
            className={clsx(
              'whitespace-nowrap rounded border px-3 py-1.5 text-xs font-medium transition-colors',
              disabled
                ? 'cursor-not-allowed border-slate-800 text-slate-600'
                : 'border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10'
            )}
            title={
              health && !health.ready
                ? health.checks.find((check) => !check.ok)?.detail ?? 'TKG is not ready'
                : 'Re-reads the graph for this case’s current alert set and stores a new evaluation.'
            }
          >
            {running ? 'Running…' : evaluation ? 'Re-run evaluation' : 'Ask TKG for a second opinion'}
          </button>
          {health && (
            <span
              className={clsx(
                'cursor-help text-[10px]',
                health.ready ? 'text-emerald-400/80' : 'text-slate-500'
              )}
              title={[
                health.ready ? 'The graph answered a readiness probe.' : 'The graph is not answering.',
                health.error ?? null,
                ...health.checks.filter((check) => !check.ok).map((check) => check.detail ?? check.id),
              ]
                .filter(Boolean)
                .join('\n')}
            >
              {health.ready ? 'graph ready' : health.configured ? 'graph unavailable' : 'not configured'}
              {health.counts?.nodes !== undefined
                ? ` · ${String(health.counts.nodes)} entities · ${String(health.counts.edges ?? 0)} facts`
                : ''}
            </span>
          )}
        </div>
      </header>

      {live && (running || live.state !== 'finished') && (
        <RunProgress
          live={live}
          onCancel={() => void cancelRun()}
          onSkipWait={() => void skipWait()}
        />
      )}

      {error && (
        <p className="rounded border border-rose-500/30 bg-rose-500/10 p-2 text-xs text-rose-200">
          {error instanceof Error ? error.message : String(error)}
        </p>
      )}

      {loading && !evaluation && <p className="text-xs text-slate-500">Loading last evaluation…</p>}

      {health && !health.configured && (
        <p className="rounded border border-amber-500/25 bg-amber-500/[0.05] p-2 text-xs text-amber-100/90">
          TKG credentials are not set on the API (
          <code className="text-amber-200/90">AISOC_TKG_URL</code>,{' '}
          <code className="text-amber-200/90">EMAIL</code>,{' '}
          <code className="text-amber-200/90">PASSWORD</code>,{' '}
          <code className="text-amber-200/90">KB_ID</code>
          ). The Soorin TKG service can be up while AiSOC still cannot call it — add those env vars to the API
          runtime override and recreate the API container.
        </p>
      )}

      {neverRun && !evaluation && !running && health?.configured !== false && (
        <p className="text-xs text-slate-500">
          No evaluation yet. Running one resolves each member alert in the TKG and stores the verdict with the
          exact payload it was judged on.
        </p>
      )}

      {unusable && evaluation && (
        <div className="space-y-2 rounded border border-amber-500/25 bg-amber-500/[0.05] p-2">
          <StatusRow
            label="Latest attempt"
            value={evaluation.status}
            tone={evaluation.status === 'unavailable' ? 'text-amber-300' : 'text-slate-400'}
          />
          {evaluation.detail && <p className="text-xs text-slate-400">{evaluation.detail}</p>}
          {evaluation.reason_codes.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {evaluation.reason_codes.map((code) => (
                <span
                  key={code}
                  className="rounded bg-slate-800/70 px-1.5 py-0.5 font-mono text-[10px] text-slate-400"
                >
                  {code}
                </span>
              ))}
            </div>
          )}
          <p className="text-[10px] text-slate-400">
            {shown
              ? `Below is the last run that reached the graph (${shown.created_at ? new Date(shown.created_at).toLocaleString() : 'earlier'}). Re-run to try again — a transient login timeout does not invalidate the evidence.`
              : 'No earlier run reached the graph, so there is nothing to show yet. Re-run once the graph is answering.'}
          </p>
        </div>
      )}

      {shown &&
        summary &&
        (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={clsx(
                  'rounded px-2 py-0.5 text-[11px] font-bold uppercase tracking-wider ring-1',
                  verdictStyle.className
                )}
              >
                {verdictStyle.label}
              </span>
              {summary.confidence !== null && (
                <span
                  className="cursor-help text-xs text-slate-400 underline decoration-dotted decoration-slate-700 underline-offset-2"
                  title="The evidence floor's score, built from coverage and corroborated alerts. The breakdown is printed under the chain."
                >
                  confidence {summary.confidence}
                </span>
              )}
              {showingLive && (
                <span
                  className="rounded bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-300 ring-1 ring-emerald-500/20"
                  title="A partial result scored from the alerts this run has resolved so far. It replaces the stored run while the job is running and is stored as a partial row if you stop it."
                >
                  live · partial
                </span>
              )}
              {shown.agree === true && (
                <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-300 ring-1 ring-emerald-500/20">
                  agrees with engine
                </span>
              )}
              {shown.agree === false && (
                <span className="rounded bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-300 ring-1 ring-amber-500/20">
                  disagrees with engine
                </span>
              )}
              {shown.status === 'partial' && (
                <span
                  className="rounded bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-300 ring-1 ring-amber-500/20"
                  title="The run hit its time budget: some alerts were skipped. Re-run to cover them."
                >
                  partial run
                </span>
              )}
            </div>

            <FlowSteps run={summary} />
            <Diagnosis run={summary} findings={findings} evaluation={shown} />
            <AttributionTable alerts={alerts} />
            <Legend />

            <details className="text-[10px] text-slate-500">
              <summary className="cursor-pointer text-slate-400">
                Where this run came from — knowledge base, timing, raw reasons
              </summary>
              <div className="mt-2 space-y-1">
                {shown.kb_id && (
                  <p
                    title={`The TKG's own knowledge-base id (AISOC_TKG_KB_ID). Full id: ${shown.kb_id}`}
                    className="cursor-help font-mono"
                  >
                    knowledge base {shown.kb_id}
                  </p>
                )}
                <p>
                  {shown.profile ?? 'agentic-soc.splunk-curated.v1'}
                  {shown.created_at ? ` · ${new Date(shown.created_at).toLocaleString()}` : ''}
                  {typeof shown.stats?.duration_ms === 'number'
                    ? ` · ${shown.stats.duration_ms} ms`
                    : ''}
                  {summary.dedup > 0 ? ` · ${summary.dedup} soft-dedup witnesses included` : ''}
                  {summary.realFacts > 0 || summary.syntheticFacts > 0
                    ? ` · ${summary.realFacts} real / ${summary.syntheticFacts} synthetic facts`
                    : ''}
                </p>
                {shown.reason_codes.length > 0 && (
                  <p className="font-mono">{shown.reason_codes.join(' · ')}</p>
                )}
                {shown.reasons.length > 0 && (
                  <ul className="mt-1 space-y-0.5">
                    {shown.reasons.map((reason, index) => (
                      <li key={index}>
                        • {typeof reason === 'string' ? reason : reason.detail ?? reason.code}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </details>
          </>
      )}
    </section>
  );
}
