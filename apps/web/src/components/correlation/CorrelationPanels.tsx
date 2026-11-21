'use client';

/**
 * Scope bar and coverage strip for the correlation inspect view.
 *
 * Kept next to the modal rather than inside it: both are pure presentation over
 * the payload and are reused by the candidate and the case surfaces.
 */

import { useMemo, useState } from 'react';
import type { AlertScope, CandidateObservation, CandidateScopeEcho } from '@/hooks/useCaseCandidates';
import { killChainCoverage, techniqueChips } from '@/lib/attackCoverage';

/**
 * Alert scope bar.
 *
 * Three levels of "not this one", deliberately distinct so the analyst knows
 * what each one costs:
 *
 * * **Hide** — the graph's own show/hide controls. Nothing leaves the payload.
 * * **Exclude** — a scope change. The component is rebuilt server-side from the
 *   surviving alerts, so the score, the timeline and the eventual case all
 *   describe the reduced evidence. An excluded alert remains case evidence; it
 *   is only removed from the analysis.
 * * **Filter** — the same, but pattern-level: `llm_payload.<path>|op|value|mode`.
 */
export function ScopeBar({
  scope,
  applied,
  visibleAlerts,
  onChange,
  open: controlledOpen,
  onOpenChange,
  hideToggle = false,
}: {
  scope: AlertScope;
  applied: CandidateScopeEcho | null;
  visibleAlerts: number;
  onChange: (scope: AlertScope) => void;
  /** Controlled by the owner when its toggle lives elsewhere (the modal tab row). */
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  hideToggle?: boolean;
}) {
  const [localOpen, setLocalOpen] = useState(false);
  // Excluding a rule drops every alert it fired on: 56 chips once buried the
  // whole graph. Five chips plus a counter is the default; the rest are one
  // click away and live in a scroll box so they cannot grow again.
  const [showAllExcluded, setShowAllExcluded] = useState(false);
  const open = controlledOpen ?? localOpen;
  const setOpen = onOpenChange ?? setLocalOpen;
  // Empty, not the example path: a prefilled "llm_payload.alert_fields." plus no
  // value made the very first "Add filter" click fail with "This operator needs
  // a value.". The placeholder carries the example instead.
  const [field, setField] = useState('');
  const [op, setOp] = useState('eq');
  const [value, setValue] = useState('');
  const [mode, setMode] = useState<'include' | 'exclude'>('exclude');
  const [error, setError] = useState<string | null>(null);

  const dropped = applied?.dropped ?? [];
  const explicit = scope.excluded_alert_ids;
  const EXCLUDED_CHIP_LIMIT = 5;
  const active = explicit.length > 0 || scope.filters.length > 0;
  // A raw UUID tells the analyst nothing about what they dropped. The server
  // echoes the alert title back in `dropped`, so the chip can name the rule and
  // keep the id in the tooltip for the copy/paste case.
  const titleOf = (alertId: string) =>
    dropped.find((item) => item.alert_id === alertId)?.title ?? null;
  // Excluding a rule excludes every alert it fired on — 56 identical chips for
  // one decision. Same title means same rule firing, so those ids share a chip
  // (`… ×56`) and removing it puts them all back. Ids without a title stay
  // their own chip; they are single alerts the analyst excluded by hand.
  const excludedGroups = useMemo(() => {
    const groups = new Map<string, { key: string; label: string; ids: string[]; title: string | null }>();
    for (const alertId of explicit) {
      const title = titleOf(alertId);
      const key = title ?? alertId;
      const group = groups.get(key) ?? {
        key,
        label: title ?? `${alertId.slice(0, 8)}…`,
        ids: [],
        title,
      };
      group.ids.push(alertId);
      groups.set(key, group);
    }
    return [...groups.values()];
    // `titleOf` reads `dropped`, which is rebuilt on every fetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [explicit, dropped]);
  const hiddenExcluded = Math.max(0, excludedGroups.length - EXCLUDED_CHIP_LIMIT);

  const addFilter = () => {
    const path = field.trim();
    if (!path.includes('.')) {
      setError('Name a payload path, e.g. llm_payload.alert_fields.src_ip');
      return;
    }
    if (!['llm_payload', 'payload', 'alert_fields'].includes(path.split('.')[0])) {
      setError('Only fields under llm_payload can be filtered.');
      return;
    }
    if (op !== 'exists' && op !== 'not_exists' && !value.trim()) {
      setError('This operator needs a value.');
      return;
    }
    setError(null);
    onChange({ ...scope, filters: [...scope.filters, `${path}|${op}|${value.trim()}|${mode}`] });
    setValue('');
  };

  // With nothing excluded, filtered or being built, this row only stated "all N
  // alerts" — a whole line of canvas for a sentence the tab counts already say.
  // The `Field filter` toggle lives in the modal's tab row, so it survives.
  if (!active && !open) return null;

  return (
    <div className="border-b border-[#374151]/60 bg-dark-70/40 px-4 py-2">
      <div className="flex flex-wrap items-center gap-2 text-[11px]">
        <span className="uppercase tracking-wide text-gray-500">Scope</span>
        {!active ? (
          // The long version of this sentence lived in the row on every open,
          // which is where the blank space under the tabs came from. The
          // explanation is a tooltip; the row states the count and nothing else.
          <span
            className="text-gray-500"
            title="Exclude an alert from the Alerts tab, or filter on a llm_payload field."
          >
            all {visibleAlerts} alerts
          </span>
        ) : (
          <span className="text-gray-400">
            {visibleAlerts} in view · {dropped.length || explicit.length} excluded
          </span>
        )}

        {/* Beside the count, not on a row of its own: the chips already wrap
            below, and a lone right-aligned button there cost a whole line. */}
        {active && (
          <button
            type="button"
            onClick={() => onChange({ excluded_alert_ids: [], filters: [] })}
            className="ml-auto rounded border border-[#374151] px-2 py-0.5 text-gray-300 hover:border-gray-500"
          >
            Clear scope
          </button>
        )}

        <div
          className={
            showAllExcluded && explicit.length > 12
              ? 'flex max-h-20 w-full flex-wrap items-center gap-1 overflow-y-auto'
              : 'flex w-full flex-wrap items-center gap-1'
          }
        >
        {(showAllExcluded ? excludedGroups : excludedGroups.slice(0, EXCLUDED_CHIP_LIMIT)).map(
          (group) => (
            <button
              key={group.key}
              type="button"
              onClick={() =>
                onChange({
                  ...scope,
                  excluded_alert_ids: scope.excluded_alert_ids.filter(
                    (id) => !group.ids.includes(id)
                  ),
                })
              }
              title={`${
                group.title ?? group.ids[0]
              }${group.ids.length > 1 ? ` — ${group.ids.length} alerts` : ''}. Click to put ${
                group.ids.length > 1 ? 'them all' : 'this alert'
              } back into the analysis.`}
              className="inline-flex max-w-[240px] items-center gap-1 rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 text-[10px] text-rose-200 hover:bg-rose-500/20"
            >
              <span className={group.title ? 'truncate' : 'font-mono'}>{group.label}</span>
              {group.ids.length > 1 && (
                <span className="shrink-0 tabular-nums text-rose-300/80">×{group.ids.length}</span>
              )}
              <span aria-hidden className="shrink-0 text-rose-300/70">
                ✕
              </span>
            </button>
          )
        )}

        {dropped
          .filter((item) => !explicit.includes(item.alert_id))
          .slice(0, 6)
          .map((item) => (
            <span
              key={item.alert_id}
              title={`${item.title ?? item.alert_id} — ${item.reason}`}
              className="inline-flex max-w-[220px] items-center gap-1 truncate rounded border border-gray-500/30 bg-gray-500/10 px-1.5 py-0.5 text-[10px] text-gray-400"
            >
              <span className="truncate">{item.title ?? `${item.alert_id.slice(0, 8)}…`}</span>
              <span className="shrink-0 text-gray-600">via filter</span>
            </span>
          ))}

        {scope.filters.map((filter) => (
          <button
            key={filter}
            type="button"
            onClick={() =>
              onChange({ ...scope, filters: scope.filters.filter((item) => item !== filter) })
            }
            title={`${filter} — click to remove this filter`}
            className="inline-flex items-center gap-1 rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] text-amber-200 hover:bg-amber-500/20"
          >
            {filter} ✕
          </button>
        ))}

          {hiddenExcluded > 0 && (
            <button
              type="button"
              onClick={() => setShowAllExcluded((value) => !value)}
              aria-expanded={showAllExcluded}
              title={
                showAllExcluded
                  ? 'Collapse the excluded list.'
                  : `Show all ${excludedGroups.length} excluded chips.`
              }
              className="inline-flex items-center rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 text-[10px] text-rose-200 hover:bg-rose-500/20"
            >
              {showAllExcluded ? 'Show fewer' : `+${hiddenExcluded} more`}
            </button>
          )}
        </div>

        <div className="ml-auto flex items-center gap-1.5">
          {!hideToggle && (
            <button
              type="button"
              onClick={() => setOpen(!open)}
              aria-expanded={open}
              className="rounded border border-[#374151] px-2 py-0.5 text-gray-300 hover:border-teal-500/60 hover:text-teal-200"
            >
              {open ? 'Hide filter builder' : 'Field filter'}
            </button>
          )}
        </div>
      </div>

      {open && (
        <div className="mt-2 space-y-1.5">
          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
            <input
              value={field}
              onChange={(event) => setField(event.target.value)}
              placeholder="llm_payload.alert_fields.src_ip"
              aria-label="Payload field path"
              className="w-[280px] rounded border border-[#374151] bg-dark-40 px-2 py-1 font-mono text-[11px] text-gray-200 placeholder:text-gray-600 focus:border-teal-500/60 focus:outline-none"
            />
            <select
              value={op}
              onChange={(event) => setOp(event.target.value)}
              aria-label="Comparison"
              className="rounded border border-[#374151] bg-dark-40 px-2 py-1 text-[11px] text-gray-200 focus:border-teal-500/60 focus:outline-none"
            >
              {[
                'eq',
                'neq',
                'contains',
                'not_contains',
                'in',
                'exists',
                'not_exists',
                'gt',
                'lt',
              ].map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
            <input
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder={op === 'exists' || op === 'not_exists' ? '(no value)' : 'value'}
              aria-label="Filter value"
              className="w-[180px] rounded border border-[#374151] bg-dark-40 px-2 py-1 font-mono text-[11px] text-gray-200 placeholder:text-gray-600 focus:border-teal-500/60 focus:outline-none"
            />
            <select
              value={mode}
              onChange={(event) => setMode(event.target.value as 'include' | 'exclude')}
              aria-label="Keep or drop matches"
              className="rounded border border-[#374151] bg-dark-40 px-2 py-1 text-[11px] text-gray-200 focus:border-teal-500/60 focus:outline-none"
            >
              <option value="exclude">drop matches</option>
              <option value="include">keep only matches</option>
            </select>
            <button
              type="button"
              onClick={addFilter}
              className="rounded border border-teal-500/40 bg-teal-500/10 px-2 py-1 text-teal-200 hover:bg-teal-500/20"
            >
              Add filter
            </button>
            {error && <span className="text-[11px] text-red-300">{error}</span>}
          </div>
          <p className="text-[10px] text-gray-600">
            Evaluated against <span className="font-mono">llm_payload</span> only — the same input
            the engine scored the graph with. Several “keep only” filters are ANDed; “drop matches”
            filters are ORed.
          </p>
        </div>
      )}
    </div>
  );
}

/**
 * Coverage strip under the graph: the techniques the campaign used and how far
 * down the kill chain it travelled.
 *
 * Both rows come from what the engine already scored with. When no observation
 * carries a kill-chain phase the ladder is derived from the ATT&CK technique
 * mapping and labelled as such — an analyst must be able to tell a fact from a
 * mapping.
 */
export function AttackCoverageStrip({
  observations,
  fallbackTechniques,
}: {
  observations: CandidateObservation[];
  fallbackTechniques: string[];
}) {
  const chips = useMemo(() => {
    const built = techniqueChips(observations.map((observation) => observation.techniques ?? []));
    if (built.length > 0) return built;
    // No observation-level techniques (older ledger rows): fall back to the
    // campaign list, counted once each.
    return techniqueChips(fallbackTechniques.map((technique) => [technique]));
  }, [observations, fallbackTechniques]);

  const coverage = useMemo(
    () => killChainCoverage(observations.map((observation) => observation.kill_chain ?? []), chips),
    [observations, chips]
  );

  if (chips.length === 0 && coverage.stages.length === 0) return null;

  return (
    <div className="max-h-[148px] overflow-y-auto border-t border-[#374151]/60 bg-dark-70 px-4 py-2">
      {chips.length > 0 && (
        <div className="flex flex-wrap items-baseline gap-1.5 text-[11px]">
          <span className="mr-1 uppercase tracking-wide text-gray-500">MITRE</span>
          {chips.map((chip) => (
            <span
              key={chip.id}
              title={`${chip.id}${chip.name ? ` — ${chip.name}` : ' (not in the shipped catalog)'}${
                chip.tactics.length ? ` · ${chip.tactics.join(', ')}` : ''
              }`}
              className="inline-flex max-w-[260px] items-center gap-1 truncate rounded border border-red-500/25 bg-red-500/10 px-1.5 py-0.5"
            >
              <span className="font-mono text-red-300">{chip.id}</span>
              {chip.name && <span className="truncate text-red-200/80">{chip.name}</span>}
              {chip.count > 1 && (
                <span className="tabular-nums text-red-400/70">×{chip.count}</span>
              )}
            </span>
          ))}
        </div>
      )}

      {coverage.stages.length > 0 && (
        <div className="mt-1.5 flex flex-wrap items-center gap-1 text-[11px]">
          <span className="mr-1 uppercase tracking-wide text-gray-500">
            {coverage.source === 'engine' ? 'Kill chain' : 'Kill chain (via ATT&CK map)'}
          </span>
          {coverage.stages.map((stage, index) => (
            <span key={stage.key} className="inline-flex items-center gap-1">
              {index > 0 && <span className="text-gray-600">→</span>}
              <span
                title={`${stage.label} — ${stage.count} ${
                  coverage.source === 'engine' ? 'observation(s)' : 'technique use(s)'
                }`}
                className="rounded bg-teal-500/10 px-1.5 py-0.5 text-teal-200"
              >
                {stage.label}
                <span className="ml-1 tabular-nums text-teal-400/70">{stage.count}</span>
              </span>
            </span>
          ))}
          {coverage.source === 'derived' && (
            <span className="text-[10px] text-gray-600">
              engine stored no phase — derived from the technique → tactic map
            </span>
          )}
        </div>
      )}
    </div>
  );
}
