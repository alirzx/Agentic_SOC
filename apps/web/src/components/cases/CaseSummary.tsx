'use client';

import { useMemo, useState } from 'react';

import { summariseCaseDescription } from '@/lib/caseDescription';

/**
 * The readable case summary that sits under the case title.
 *
 * Replaces a `<p>{caseRecord.description}</p>` that dumped the engine's whole
 * observation list (up to 8000 characters) into the header. Here the header
 * shows one summary sentence, the case's **live** alert/rule counts, and the
 * engine's creation-time snapshot on its own labelled line; the rule roll-up
 * and provenance are one click away, and the per-observation bullets never
 * render here at all — the Observations tab lists them in full.
 *
 * The counts are deliberately split. `alertCount` and `rules` come from the
 * alerts store on every read, while the description is text the engine wrote
 * when it opened the case. Rendering both as one row is how the header ended up
 * claiming "9 rules" and "17 distinct rules" at the same time.
 */
const MAX_VISIBLE_RULES = 12;

export function CaseSummary({
  description,
  rules,
  alertCount,
}: {
  description?: string | null;
  /** rule name → how many case alerts it fired on */
  rules?: Record<string, number>;
  /** Live count of alerts the case owns (canonical members). */
  alertCount?: number;
}) {
  const summary = useMemo(() => summariseCaseDescription(description), [description]);
  const [showDetails, setShowDetails] = useState(false);

  if (!summary.headline) return null;

  const liveRuleRows = useMemo(
    () =>
      Object.entries(rules ?? {})
        .map(([name, count]) => ({ name, count: Number(count) || 0 }))
        .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
    [rules],
  );
  const liveRules = liveRuleRows.length;
  const shownRuleRows = liveRuleRows.slice(0, MAX_VISIBLE_RULES);
  const liveFacts: string[] = [];
  if (typeof alertCount === 'number') {
    liveFacts.push(`${alertCount} alert${alertCount === 1 ? '' : 's'}`);
  }
  if (liveRules > 0) {
    liveFacts.push(`${liveRules} rule${liveRules === 1 ? '' : 's'}`);
  }

  return (
    <div className="mt-2 max-w-3xl">
      <p className="text-sm text-slate-400">{summary.headline}</p>

      {liveFacts.length > 0 && (
        <div
          className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-slate-400"
          title="Counted live from the alerts store: canonical case members and the rules they carry. Deduplicated copies are evidence in the correlation graph, not separate members."
        >
          {liveFacts.map((fact, index) => (
            <span key={fact} className="inline-flex items-center gap-2">
              {index > 0 && <span className="text-slate-700">·</span>}
              <span>{fact}</span>
            </span>
          ))}
        </div>
      )}

      {(liveRuleRows.length > 0 || summary.details) && (
        <button
          type="button"
          onClick={() => setShowDetails((open) => !open)}
          aria-expanded={showDetails}
          className="mt-1.5 text-[11px] text-slate-500 underline decoration-slate-700 underline-offset-2 transition-colors hover:text-slate-300"
        >
          {showDetails ? 'Hide engine details' : 'Engine details'}
        </button>
      )}

      {showDetails && (
        <div className="mt-1.5 max-h-64 overflow-auto rounded-md border border-slate-800/80 bg-slate-950/60 px-2.5 py-2">
          {liveRuleRows.length > 0 && (
            <div className="mb-2">
              {/*
                Live, not the engine's frozen roll-up: that counted rule
                occurrences per observation over the pre-dedup alert set, so a
                case whose alerts carry nine rules was headed "17 distinct".
                These counts come from the case record on every read.
              */}
              <p className="text-[11px] font-medium text-slate-400">
                Rules ({liveRules})
              </p>
              <ul className="mt-1 space-y-0.5 font-mono text-[11px] leading-relaxed text-slate-400">
                {shownRuleRows.map((rule) => (
                  <li key={rule.name} className="break-words">
                    - {rule.name}
                    {rule.count > 1 ? ` (×${rule.count})` : ''}
                  </li>
                ))}
                {liveRules > shownRuleRows.length && (
                  <li className="text-slate-600">
                    - +{liveRules - shownRuleRows.length} more, listed in the Rules tab
                  </li>
                )}
              </ul>
            </div>
          )}
          {summary.details && (
            <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-slate-500">
              {summary.details}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
