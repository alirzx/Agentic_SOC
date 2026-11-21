'use client';

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import clsx from 'clsx';
import { ExternalLink } from 'lucide-react';

import type { EntityTimeline } from '@/lib/entityTimeline';
import type { ClusterSummary } from '@/lib/graphCommunities';

/**
 * The graph's entities as a list, beside the canvas.
 *
 * The canvas answers "what is connected to what"; it cannot answer "which
 * hosts are in here" without the analyst hunting for a shape. This panel is the
 * same set of nodes in reading order: search, select, hide or drop a leaf, and
 * click a row to put the camera on the node it names. Every row is a leaf of the
 * graph — entities only, because an observation is a relation, not a thing.
 */
export interface GraphEntityRow {
  id: string;
  kind: string;
  label: string;
  /** Full key behind a truncated label (`host:win-dc-01`). */
  token: string | null;
  /** Alerts behind the entity (from the API node). */
  alerts: number;
  /** Incident edges drawn for this entity. */
  links: number;
  /** Observations this entity takes part in. */
  actions: number;
}

/**
 * A named view the analyst parked for later: the visibility state of the graph
 * (focus, hidden, removed, collapsed, expansion) plus the camera it was read at.
 */
export interface SavedGraphView {
  id: string;
  name: string;
  /** ISO timestamp of when it was saved. */
  at: string;
  /** What was on screen, in one line, so the list is readable without opening it. */
  summary: string;
}

interface GraphEntityPanelProps {
  entities: GraphEntityRow[];
  hiddenIds: ReadonlySet<string>;
  removedIds: ReadonlySet<string>;
  /**
   * Node ids the canvas is actually drawing. Hide/Remove, a switched-off kind
   * and a leaf trimmed by the neighbour budget all drop a row out of this set,
   * which is what lets the header say how much of the campaign is on screen.
   */
  drawnIds?: ReadonlySet<string>;
  selectedIds: ReadonlySet<string>;
  activeId: string | null;
  kindLabel: (kind: string) => string;
  kindColor: (kind: string) => string;
  /**
   * The node's own silhouette for a kind (e.g. the host house, the user figure).
   * A coloured circle made every entity look alike in a list of hundreds, and
   * the shape is what lets an analyst match a row to a node on the canvas.
   */
  kindIcon?: (kind: string) => ReactNode;
  onActivate: (id: string) => void;
  onHide: (ids: string[]) => void;
  onShow: (ids: string[]) => void;
  onRemove: (ids: string[]) => void;
  onRestore: (ids: string[]) => void;
  onSetSelection: (ids: string[]) => void;
  onToggleSelection: (id: string) => void;
  onSelectRelated: (ids: string[]) => void;
  onOpenDetails?: (id: string) => void;
  /** Kept for callers that still pass it; the list is always shown now. */
  onClose?: () => void;
  /** Extra classes for the aside — the graph puts its control row above it. */
  className?: string;
  /**
   * The bubbles both views draw. The 3D legend used to float over the scene;
   * it belongs here, behind a tab, so the list and the bubbles share one panel
   * and the analyst can switch between them.
   */
  clusters?: readonly ClusterSummary[];
  onToggleCluster?: (key: string) => void;
  /** Frame every node of one bubble in the graph view. */
  onFocusCluster?: (key: string) => void;
  /**
   * Parked views of the graph. They belong beside Entities and Clusters: the
   * three tabs answer the same question ("what am I looking at?") about the
   * same canvas, and a separate dialog would hide the graph while choosing.
   */
  views?: readonly SavedGraphView[];
  /** Set when the API refused to persist (or load) the saved views. */
  viewError?: string | null;
  onSaveView?: (name: string) => void;
  onApplyView?: (id: string) => void;
  onDeleteView?: (id: string) => void;
}

const clock = (value: string | null): string => {
  if (!value) return 'time unknown';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return 'time unknown';
  return parsed.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
};

export function GraphEntityPanel({
  entities,
  hiddenIds,
  removedIds,
  drawnIds,
  selectedIds,
  activeId,
  kindLabel,
  kindColor,
  kindIcon,
  onActivate,
  onHide,
  onShow,
  onRemove,
  onRestore,
  onSetSelection,
  onToggleSelection,
  onSelectRelated,
  onOpenDetails,
  className,
  clusters,
  onToggleCluster,
  onFocusCluster,
  views,
  viewError,
  onSaveView,
  onApplyView,
  onDeleteView,
}: GraphEntityPanelProps) {
  const [tab, setTab] = useState<'entities' | 'clusters' | 'views'>('entities');
  const [query, setQuery] = useState('');
  const [viewName, setViewName] = useState('');
  const rowRefs = useRef<Record<string, HTMLLIElement | null>>({});

  useEffect(() => {
    if (!activeId) return;
    const row = rowRefs.current[activeId];
    if (row) {
      row.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
    }
  }, [activeId]);

  // Accordion state, per kind. A 440-entity campaign is unreadable as one
  // scroll: folding the groups the analyst is not working in keeps the ones
  // they are on screen.
  const [collapsedKinds, setCollapsedKinds] = useState<Set<string>>(new Set());
  const toggleKind = (kind: string) =>
    setCollapsedKinds((current) => {
      const next = new Set(current);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return entities;
    return entities.filter((entity) =>
      [entity.label, entity.token ?? '', entity.kind].some((value) =>
        value.toLowerCase().includes(needle)
      )
    );
  }, [entities, query]);

  /**
   * Rows grouped the way the evidence rail's "Shared entities" lists them.
   * The incoming order is strongest first (links desc), so the first kind in the
   * map is the kind carrying the strongest entity and rows inside keep that
   * ranking; only the headings are new.
   */
  const groups = useMemo(() => {
    const byKind = new Map<string, typeof filtered>();
    for (const entity of filtered) {
      const list = byKind.get(entity.kind);
      if (list) list.push(entity);
      else byKind.set(entity.kind, [entity]);
    }
    return [...byKind.entries()];
  }, [filtered]);

  // `filtered` is the search result; `visible` also subtracts whatever the
  // canvas is not drawing (Hide/Remove, an entity kind switched off, or a leaf
  // trimmed by the neighbour budget). The header counted `filtered` and so read
  // “45 shown” over a canvas the budget had cut to 19.
  const visible = drawnIds ? filtered.filter((entity) => drawnIds.has(entity.id)) : filtered;
  const selected = [...selectedIds].filter((id) => entities.some((entity) => entity.id === id));
  const hiddenCount = entities.filter((entity) => hiddenIds.has(entity.id)).length;
  const removedCount = entities.filter((entity) => removedIds.has(entity.id)).length;
  const canHide = selected.some((id) => !hiddenIds.has(id) && !removedIds.has(id));
  const canShow = selected.some((id) => hiddenIds.has(id) || removedIds.has(id));
  const allVisibleSelected =
    filtered.length > 0 &&
    filtered.filter((entity) => !removedIds.has(entity.id)).every((entity) => selectedIds.has(entity.id));

  return (
    <aside
      aria-label="Graph entities"
      className={clsx(
        'flex min-h-0 w-full flex-col bg-[#0b1220]',
        className
      )}
    >
      <header className="flex items-center justify-between gap-2 border-b border-[#374151]/60 px-3 py-2">
        <div className="min-w-0">
          <p className="text-[11px] uppercase tracking-wide text-gray-500">Entities</p>
          <p className="text-xs text-gray-300">
            {visible.length}
            {visible.length !== entities.length ? ` of ${entities.length}` : ''} shown
            {selected.length > 0 ? ` · ${selected.length} selected` : ''}
          </p>
        </div>
      </header>

      {((clusters && clusters.length > 0) || views) && (
        <div role="tablist" aria-label="Graph panel" className="flex border-b border-[#374151]/60 text-[11px]">
          {([
            { value: 'entities' as const, label: 'Entities', count: entities.length },
            ...(clusters ? [{ value: 'clusters' as const, label: 'Clusters', count: clusters.length }] : []),
            ...(views ? [{ value: 'views' as const, label: 'Views', count: views.length }] : []),
          ]).map(({ value, label, count }) => (
            <button
              key={value}
              type="button"
              role="tab"
              aria-selected={tab === value}
              onClick={() => setTab(value)}
              className={clsx(
                'flex-1 px-2 py-1.5 transition-colors',
                tab === value
                  ? 'bg-teal-500/10 text-teal-200'
                  : 'text-gray-400 hover:text-gray-200'
              )}
            >
              {label}{' '}
              <span className="tabular-nums text-[10px] text-gray-500">{count}</span>
            </button>
          ))}
        </div>
      )}

      {tab === 'views' && views && (
        <div className="flex min-h-0 flex-1 flex-col">
          <form
            className="flex gap-1 border-b border-[#374151]/60 px-2 py-1.5"
            onSubmit={(event) => {
              event.preventDefault();
              const name = viewName.trim();
              if (!name) return;
              onSaveView?.(name);
              setViewName('');
            }}
          >
            <input
              value={viewName}
              onChange={(event) => setViewName(event.target.value)}
              placeholder="Name this view…"
              aria-label="Name this view"
              className="min-w-0 flex-1 rounded border border-[#374151] bg-transparent px-1.5 py-1 text-[11px] text-gray-200 placeholder:text-gray-600 focus:border-teal-500/60 focus:outline-none"
            />
            <button
              type="submit"
              title="Save what the canvas shows right now — focus, hidden and removed nodes, collapsed bubbles, expansion and camera."
              className="rounded border border-[#374151] px-2 py-1 text-[11px] text-gray-300 transition-colors hover:border-teal-500/60 hover:text-teal-200"
            >
              Save
            </button>
          </form>
          {viewError && (
            <p className="border-b border-[#374151]/60 px-2 py-1 text-[10px] text-amber-300">
              {viewError}
            </p>
          )}
          <ul className="min-h-0 flex-1 overflow-y-auto px-2 py-1.5">
            {views.length === 0 && (
              <li className="px-1 py-2 text-[11px] text-gray-500">
                No saved views yet. Name the current view to park it here.
              </li>
            )}
            {views.map((view) => (
              <li key={view.id} className="flex items-center gap-0.5 rounded hover:bg-white/5">
                <button
                  type="button"
                  onClick={() => onApplyView?.(view.id)}
                  title={`${view.summary} — click to restore this view`}
                  className="min-w-0 flex-1 rounded px-1.5 py-1 text-left"
                >
                  <span className="block truncate text-[11px] text-gray-200">{view.name}</span>
                  <span className="block truncate text-[10px] text-gray-500">
                    {clock(view.at)} · {view.summary}
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => onDeleteView?.(view.id)}
                  aria-label={`Delete view ${view.name}`}
                  title="Delete this saved view"
                  className="shrink-0 px-1.5 text-[11px] text-gray-600 hover:text-red-300"
                >
                  ✕
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {tab === 'clusters' && clusters ? (
        <ul className="min-h-0 flex-1 overflow-y-auto px-2 py-1.5">
          {clusters.map((cluster) => (
            <li
              key={cluster.community}
              className={clsx(
                'flex items-center gap-0.5 rounded',
                cluster.collapsed && 'bg-teal-500/[0.07] ring-1 ring-inset ring-teal-500/25'
              )}
            >
              <button
                type="button"
                onClick={() => onFocusCluster?.(cluster.community)}
                title={`Focus ${cluster.title} — frame its ${cluster.size} nodes`}
                className="flex min-w-0 flex-1 items-start gap-1.5 rounded px-1.5 py-1 text-left transition-colors hover:bg-white/5"
              >
                <span
                  className={clsx(
                    'mt-1 h-2 w-2 shrink-0 rounded-full',
                    cluster.collapsed && 'border border-current bg-transparent'
                  )}
                  style={{ backgroundColor: cluster.collapsed ? undefined : cluster.color }}
                  aria-hidden
                />
                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-1">
                    <span className="min-w-0 truncate text-[11px] text-gray-200">
                      {cluster.title}
                    </span>
                    {cluster.collapsed && (
                      <span className="shrink-0 rounded bg-teal-500/15 px-1 text-[9px] uppercase tracking-wide text-teal-200">
                        collapsed
                      </span>
                    )}
                  </span>
                  <span className="block truncate text-[10px] text-gray-500">
                    {cluster.collapsed ? `${cluster.size} hidden` : cluster.subtitle}
                  </span>
                </span>
                <span className="shrink-0 font-mono text-[10px] text-gray-500">
                  {cluster.size}
                </span>
              </button>
              {onFocusCluster && (
                <button
                  type="button"
                  onClick={() => onFocusCluster(cluster.community)}
                  title={`Focus ${cluster.title} — frame its ${cluster.size} nodes`}
                  className="shrink-0 self-center rounded border border-[#374151] px-1.5 py-0.5 text-[9px] text-gray-400 transition-colors hover:border-gray-500 hover:text-gray-200"
                >
                  Focus
                </button>
              )}
              <button
                type="button"
                onClick={() => onToggleCluster?.(cluster.community)}
                aria-pressed={Boolean(cluster.collapsed)}
                title={
                  cluster.collapsed
                    ? `Expand ${cluster.title} — ${cluster.size} nodes`
                    : `Collapse ${cluster.title} — ${cluster.size} nodes`
                }
                className="shrink-0 self-center rounded border border-[#374151] px-1.5 py-0.5 text-[9px] text-gray-400 transition-colors hover:border-gray-500 hover:text-gray-200"
              >
                {cluster.collapsed ? 'Expand' : 'Collapse'}
              </button>
            </li>
          ))}
        </ul>
      ) : tab === 'entities' ? (
      <>
      <div className="border-b border-[#374151]/60 px-3 py-2">
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filter by value or type…"
          aria-label="Filter entities"
          className="w-full rounded border border-[#374151] bg-black/30 px-2 py-1 text-xs text-gray-200 placeholder:text-gray-600 focus:border-teal-500/60 focus:outline-none"
        />
        <div className="mt-1.5 flex flex-wrap gap-1 text-[11px]">
          <button
            type="button"
            onClick={() => onSetSelection(allVisibleSelected ? [] : filtered.map((entity) => entity.id))}
            className="rounded border border-[#374151] px-1.5 py-0.5 text-gray-300 transition-colors hover:border-gray-500"
          >
            {allVisibleSelected ? 'Clear' : 'Select all'}
          </button>
          <button
            type="button"
            onClick={() => {
              const visible = filtered.map((entity) => entity.id);
              const next = new Set(selectedIds);
              for (const id of visible) {
                if (next.has(id)) next.delete(id);
                else next.add(id);
              }
              onSetSelection([...next]);
            }}
            className="rounded border border-[#374151] px-1.5 py-0.5 text-gray-300 transition-colors hover:border-gray-500"
            title="Select the rows that are not selected, and deselect the ones that are."
          >
            Invert
          </button>
          <button
            type="button"
            onClick={() => onSelectRelated(selected)}
            disabled={selected.length === 0}
            title="Add every entity connected to the selected ones."
            className="rounded border border-[#374151] px-1.5 py-0.5 text-gray-300 transition-colors hover:border-gray-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Related
          </button>
        </div>
        <div className="mt-1.5 flex flex-wrap gap-1 text-[11px]">
          <button
            type="button"
            onClick={() => onHide(selected)}
            disabled={!canHide}
            title="Remove the selected entities from the canvas. They stay in this list."
            className="rounded border border-[#374151] px-1.5 py-0.5 text-gray-300 transition-colors hover:border-gray-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Hide
          </button>
          <button
            type="button"
            onClick={() => onShow(selected)}
            disabled={!canShow}
            title="Put the selected entities back on the canvas."
            className="rounded border border-[#374151] px-1.5 py-0.5 text-gray-300 transition-colors hover:border-gray-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Show
          </button>
          <button
            type="button"
            onClick={() => onRemove(selected)}
            disabled={!canHide}
            title="Drop the selected entities from this view for the rest of the session (restorable from the list)."
            className="rounded border border-[#374151] px-1.5 py-0.5 text-gray-300 transition-colors hover:border-rose-500/60 hover:text-rose-200 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Remove
          </button>
          <button
            type="button"
            onClick={() => onRestore(selected)}
            disabled={!canShow}
            title="Restore the selected entities and make them visible again."
            className="rounded border border-[#374151] px-1.5 py-0.5 text-gray-300 transition-colors hover:border-gray-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Restore
          </button>
        </div>
      </div>

      <ul className="min-h-0 flex-1 overflow-y-auto px-1.5 py-1.5 text-xs">
        {filtered.length === 0 && (
          <li className="px-2 py-3 text-[11px] text-gray-500">
            No entity matches “{query.trim()}”.
          </li>
        )}
        {groups.map(([kind, rows]) => {
          // A search has to show its hits: folding wins only while the list is
          // unfiltered, so typing a value never hides a match inside a folded
          // group.
          const folded = collapsedKinds.has(kind) && query.trim() === '';
          return (
          <li key={kind} className="mt-2 first:mt-0">
            <button
              type="button"
              onClick={() => toggleKind(kind)}
              aria-expanded={!folded}
              title={
                folded
                  ? `Expand ${kindLabel(kind)} — ${rows.length} entities`
                  : `Collapse ${kindLabel(kind)} — ${rows.length} entities`
              }
              className="flex w-full items-baseline justify-between gap-2 rounded px-1.5 py-0.5 transition-colors hover:bg-white/5"
            >
              <span className="flex items-baseline gap-1">
                <span
                  aria-hidden
                  className={clsx(
                    'text-[9px] text-gray-500 transition-transform',
                    !folded && 'rotate-90'
                  )}
                >
                  ▶
                </span>
                <span
                  data-testid="kind-group"
                  className="text-[10px] uppercase tracking-wide text-gray-400"
                >
                  {kindLabel(kind)}
                </span>
              </span>
              <span className="tabular-nums text-[10px] text-gray-600">
                {folded ? `+${rows.length}` : rows.length}
              </span>
            </button>
            {!folded && (
            <ul>
        {rows.map((entity) => {
          const hidden = hiddenIds.has(entity.id);
          const removed = removedIds.has(entity.id);
          const isSelected = selectedIds.has(entity.id);
          return (
            <li
              key={entity.id}
              ref={(node) => {
                rowRefs.current[entity.id] = node;
              }}
              className={clsx(
                'group flex items-start gap-1.5 rounded border px-1.5 py-1 transition-colors',
                activeId === entity.id
                  ? 'border-teal-500/60 bg-teal-500/10 shadow-[0_0_0_1px_rgba(45,212,191,0.15)]'
                  : isSelected
                    ? 'border-teal-500/25 bg-teal-500/[0.05]'
                    : 'border-transparent hover:bg-white/5',
                (hidden || removed) && 'opacity-50'
              )}
            >
              <input
                type="checkbox"
                checked={isSelected}
                onChange={() => onToggleSelection(entity.id)}
                aria-label={`Select ${entity.label}`}
                className="mt-0.5 h-3 w-3 shrink-0 accent-teal-500"
              />
              <button
                type="button"
                onClick={() => onActivate(entity.id)}
                title={`Show ${entity.label} on the graph`}
                className="min-w-0 flex-1 text-left"
              >
                <span className="flex items-center gap-1.5">
                  {kindIcon ? (
                    kindIcon(entity.kind)
                  ) : (
                    <span
                      className="h-2 w-2 shrink-0 rounded-full"
                      style={{ backgroundColor: kindColor(entity.kind) }}
                      aria-hidden
                    />
                  )}
                  <span className="truncate text-[10px] uppercase tracking-wide text-gray-500">
                    {kindLabel(entity.kind)}
                  </span>
                  {(hidden || removed) && (
                    <span className="rounded border border-[#374151] px-1 text-[9px] uppercase text-gray-400">
                      {removed ? 'removed' : 'hidden'}
                    </span>
                  )}
                </span>
                <span className="block truncate font-mono text-[11px] text-gray-200">
                  {entity.label}
                </span>
                <span className="block text-[10px] text-gray-500">
                  {entity.links} link{entity.links === 1 ? '' : 's'}
                  {entity.actions > 0 ? ` · ${entity.actions} action${entity.actions === 1 ? '' : 's'}` : ''}
                  {entity.alerts > 0 ? ` · ${entity.alerts} alert${entity.alerts === 1 ? '' : 's'}` : ''}
                </span>
              </button>
              <button
                type="button"
                onClick={() => {
                  // This is the explicit override: it must force-open the details
                  // pane even when Auto Details is off, without also re-triggering
                  // the list-selection auto-open path.
                  onOpenDetails?.(entity.id);
                }}
                aria-label={`Open details for ${entity.label}`}
                title="Open this entity in the details panel even if the global Details toggle is off."
                className="shrink-0 rounded border border-transparent px-1 text-[11px] text-gray-500 opacity-0 transition-colors hover:border-teal-500/60 hover:text-teal-200 group-hover:opacity-100 focus:opacity-100"
              >
                D
              </button>
              <button
                type="button"
                onClick={() => onActivate(entity.id)}
                aria-label={`Select ${entity.label}`}
                // This button highlights and selects the row's node; it does not
                // hide the rest. Calling it "Focus" next to the inspector's real
                // Focus made the button look broken.
                title="Select and highlight this entity on the graph (3D also centres the camera). Use Details for Focus, which hides the rest."
                className="shrink-0 rounded border border-transparent px-1 text-[11px] text-gray-500 opacity-0 transition-colors hover:border-teal-500/60 hover:text-teal-200 group-hover:opacity-100 focus:opacity-100"
              >
                focus
              </button>
              <button
                type="button"
                onClick={() => (hidden || removed ? onRestore([entity.id]) : onHide([entity.id]))}
                aria-label={`${hidden || removed ? 'Show' : 'Hide'} ${entity.label}`}
                title={hidden || removed ? 'Show on the graph' : 'Hide from the graph'}
                className="shrink-0 rounded border border-transparent px-1 text-[11px] text-gray-500 opacity-0 transition-colors hover:border-[#374151] hover:text-gray-200 group-hover:opacity-100 focus:opacity-100"
              >
                {hidden || removed ? 'show' : 'hide'}
              </button>
            </li>
          );
        })}
            </ul>
            )}
          </li>
          );
        })}
      </ul>

      {(hiddenCount > 0 || removedCount > 0) && (
        <footer className="flex items-center justify-between gap-2 border-t border-[#374151]/60 px-3 py-1.5 text-[10px] text-gray-500">
          <span>
            {hiddenCount} hidden{removedCount > 0 ? ` · ${removedCount} removed` : ''}
          </span>
          <button
            type="button"
            onClick={() => {
              const ids = entities
                .filter((entity) => hiddenIds.has(entity.id) || removedIds.has(entity.id))
                .map((entity) => entity.id);
              onRestore(ids);
            }}
            className="text-teal-300 hover:underline"
          >
            show all
          </button>
        </footer>
      )}
      </>
      ) : null}
    </aside>
  );
}

/**
 * The per-entity timeline. It used to sit above the filter inside the entity
 * panel, pushing the list down every time a row was opened; it now floats over
 * the graph instead, so opening a row never costs list space.
 */
export function EntityDetailCard({
  detail,
}: {
  detail: { label: string; kind: string; timeline: EntityTimeline };
  onClose?: () => void;
}) {
  return (
    <section
      aria-label="Entity timeline"
      className="w-full max-w-full overflow-y-auto rounded-none border-0 bg-transparent p-0 shadow-none backdrop-blur-none"
    >
      {detail.timeline.firstObservation ? (
        <p className="mt-1.5 text-[11px] leading-snug text-gray-400">
          First linked by{' '}
          <span className="font-mono text-teal-300">{detail.timeline.firstObservation.key}</span>{' '}
          · {clock(detail.timeline.firstObservation.at)}
          {detail.timeline.firstObservation.role
            ? ` · ${detail.timeline.firstObservation.role}`
            : ''}
        </p>
      ) : (
        <p className="mt-1.5 text-[11px] text-gray-500">
          No observation in this candidate touches it.
        </p>
      )}

      {detail.timeline.events.length > 0 ? (
        <ol className="mt-2 space-y-1">
          {detail.timeline.events.map((event) => (
            <li
              key={`${event.alertId}:${event.at ?? ''}`}
              className="flex items-start gap-1.5 text-[11px] leading-snug"
            >
              <span className="w-[86px] shrink-0 font-mono text-[10px] text-gray-500">
                {clock(event.at)}
              </span>
              <span className="min-w-0 flex-1">
                {/* The timeline names the alert; opening it must not cost the
                    analyst the correlation they are reading, so it leaves in a
                    new tab — the same rule the Alerts table follows. */}
                <a
                  href={`/alerts/${event.alertId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  title="Open the full alert in a new tab"
                  className="group flex items-start gap-1 text-gray-200 hover:text-teal-300"
                >
                  <span className="min-w-0 flex-1 truncate" title={event.title}>
                    {event.title}
                  </span>
                  <ExternalLink
                    className="mt-0.5 h-3 w-3 shrink-0 text-gray-500 group-hover:text-teal-300"
                    aria-hidden="true"
                  />
                </a>
                <span className="text-gray-500">
                  {event.observation ?? 'unattributed'}
                  {event.severity ? ` · ${event.severity}` : ''}
                </span>
              </span>
            </li>
          ))}
        </ol>
      ) : null}
    </section>
  );
}
