'use client';

/**
 * Edge inspector for the correlation graph.
 *
 * Clicking a link used to be a dead end unless it happened to be a scored
 * observation↔observation pair. Both link classes now explain themselves here:
 *
 * * **CORRELATION** — the pair score, its L1/L2/L3 split, the keys that earned
 *   L1 and (when it fired) the third observation that earned L3.
 * * **key links** (host / user / ip / domain / hash / process / other key) — the
 *   shared value, the weight it added to L1, and every other observation that
 *   touches the same value. That list is the answer to "why are these two
 *   actions in one campaign".
 *
 * The two endpoints are rendered as cards with the same kind chip the canvas
 * draws, and each can be focused or hidden, so a question raised by a link can
 * be followed without hunting for the node on the canvas.
 */

import { clsx } from 'clsx';
import type {
  CandidateGraphEdge,
  CandidateGraphNode,
  CandidatePairScore,
} from '@/hooks/useCaseCandidates';
import {
  KIND_LABEL,
  KindIcon,
  metaForKind,
  observationColor,
} from '@/components/candidates/CandidateGraphView';

/** Plain-English name for an edge class, so the chip is read, not decoded. */
const EDGE_LABEL: Record<string, string> = {
  CORRELATION: 'pair link',
  OBSERVATION: 'action (observation)',
  OBSERVED_ON: 'shared host',
  INVOLVES_USER: 'shared user',
  USES_IP: 'shared IP',
  QUERIED_DOMAIN: 'shared domain',
  MATCHES_HASH: 'shared file hash',
  INVOKES_PROCESS: 'shared process',
  CONTRIBUTES_KEY: 'shared key',
};

function EndpointCard({
  node,
  fallbackId,
  role,
  onFocus,
  onHide,
}: {
  node: CandidateGraphNode | undefined;
  fallbackId: string;
  role: 'source' | 'target';
  onFocus: (id: string) => void;
  onHide: (id: string) => void;
}) {
  // `metaForKind` rather than a bare table lookup: an unknown kind still gets
  // the generic key glyph here, the same one the canvas and the legend show.
  const meta = node ? metaForKind(node.kind) : undefined;
  return (
    <div className="min-w-0 flex-1 rounded border border-[#374151]/70 bg-dark-60 px-2 py-1.5">
      <p className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-gray-600">
        {role}
        <span className="normal-case tracking-normal text-gray-500">
          {node ? (KIND_LABEL[node.kind] ?? node.kind) : 'node'}
        </span>
      </p>
      <p className="mt-0.5 flex items-center gap-1.5 text-[11px] text-gray-100">
        {meta ? <KindIcon meta={meta} /> : null}
        <span className="truncate" title={node?.label ?? fallbackId}>
          {node?.label ?? fallbackId}
        </span>
        {typeof node?.alert_count === 'number' && node.alert_count > 0 && (
          <span className="shrink-0 text-[10px] text-gray-500">{node.alert_count} alerts</span>
        )}
      </p>
      {node?.token && (
        <p className="mt-0.5 truncate font-mono text-[10px] text-gray-500" title={node.token}>
          {node.token}
        </p>
      )}
      <div className="mt-1 flex items-center gap-1">
        <button
          type="button"
          onClick={() => onFocus(node?.id ?? fallbackId)}
          title="Keep this node and its direct neighbours, hide the rest of the canvas."
          className="rounded border border-[#374151] px-1.5 py-0.5 text-[10px] text-gray-400 transition-colors hover:border-teal-500/60 hover:text-teal-200"
        >
          Focus
        </button>
        <button
          type="button"
          onClick={() => onHide(node?.id ?? fallbackId)}
          title="Remove this node (and its links) from the view. The graph toolbar's “show all” brings it back."
          className="rounded border border-[#374151] px-1.5 py-0.5 text-[10px] text-gray-400 transition-colors hover:border-rose-500/60 hover:text-rose-200"
        >
          Hide
        </button>
      </div>
    </div>
  );
}

export function EdgeInspector({
  edge,
  pair,
  nodes,
  siblings = [],
  onDismiss,
  onFocus,
  onHide,
}: {
  edge: CandidateGraphEdge;
  pair: CandidatePairScore | null;
  nodes: Map<string, CandidateGraphNode>;
  /** Other observations that touch the same key (key links only). */
  siblings?: CandidateGraphNode[];
  onDismiss: () => void;
  onFocus: (nodeId: string) => void;
  onHide: (nodeId: string) => void;
}) {
  const isPair = edge.kind === 'CORRELATION';
  // An observation drawn as a relation between its own entities.
  const isAction = edge.kind === 'OBSERVATION';
  const actionColor = isAction ? observationColor(edge.role) : undefined;
  const source = nodes.get(edge.source);
  const target = nodes.get(edge.target);
  const belowTheta = edge.threshold_met === false;
  // A shared host can be touched by dozens of observations of the same action,
  // which repeated one identical chip per observation. Group them by what the
  // chip actually says (label + technique) and keep the count; clicking focuses
  // the first observation of the group.
  const siblingGroups = (() => {
    if (isPair || !siblings?.length) return [];
    const groups = new Map<string, { label: string; technique: string | null; ids: string[] }>();
    for (const node of siblings) {
      const technique = node.techniques?.[0] ?? null;
      const key = `${node.label}|${technique ?? ''}`;
      const entry = groups.get(key);
      if (entry) entry.ids.push(node.id);
      else groups.set(key, { label: node.label, technique, ids: [node.id] });
    }
    return [...groups.values()].sort(
      (a, b) => b.ids.length - a.ids.length || a.label.localeCompare(b.label)
    );
  })();

  return (
    <div className="max-h-[280px] overflow-y-auto border-t border-[#374151]/60 bg-dark-70 px-5 py-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
        <span
          className={clsx(
            'rounded px-1.5 py-0.5 text-[11px]',
            isPair
              ? 'bg-teal-500/10 text-teal-300'
              : isAction
                ? 'bg-dark-40 text-gray-100'
                : 'bg-dark-40 text-gray-300'
          )}
          style={
            actionColor
              ? { backgroundColor: `${actionColor}22`, color: actionColor }
              : undefined
          }
        >
          {isAction && edge.role
            ? edge.role
            : (EDGE_LABEL[edge.kind] ?? edge.kind.toLowerCase().replace(/_/g, ' '))}
        </span>
        {isAction ? (
          <>
            <span className="tabular-nums text-gray-200" title="Alerts behind the observations this edge stands for">
              {edge.alert_count ?? 0} alerts
            </span>
            {(edge.count ?? 1) > 1 && (
              <span className="text-gray-500" title="Several observations related the same two entities">
                {edge.count} actions collapsed
              </span>
            )}
            {(edge.endpoint_count ?? 0) > 4 && (
              <span
                className="rounded bg-dark-40 px-1.5 py-0.5 text-[10px] text-gray-400"
                title="Wide observation: only a spanning tree of its endpoints is drawn, not every pair."
              >
                tree projection · {edge.endpoint_count} endpoints
              </span>
            )}
          </>
        ) : (
          <span
            className="tabular-nums text-gray-200"
            title={
              isPair
                ? 'L1 (shared keys) + L2 (technique/story/kill-chain proximity) + L3 (3-hop path), gated by θ'
                : 'Weight this key added to L1. 3 = strong (rare host, public IP), 2 = medium, 1 = weak/hub.'
            }
          >
            {isPair ? 'score' : 'weight'} {edge.weight ?? 0}
          </span>
        )}
        {isPair && pair && (
          <span className="text-gray-500">
            L1 {pair.l1} · L2 {pair.l2} · L3 {pair.l3}
          </span>
        )}
        {belowTheta && (
          <span className="rounded bg-yellow-500/10 px-1.5 py-0.5 text-[10px] text-yellow-300">
            below θ
          </span>
        )}
        <button
          onClick={onDismiss}
          className="ml-auto text-[11px] text-gray-500 hover:text-gray-300"
        >
          Dismiss
        </button>
      </div>

      <div className="mt-2 flex flex-col gap-1.5 sm:flex-row sm:items-stretch">
        <EndpointCard
          node={source}
          fallbackId={edge.source}
          role="source"
          onFocus={onFocus}
          onHide={onHide}
        />
        <div className="flex items-center justify-center px-1 text-[11px] text-gray-600">
          {isPair ? '↔' : '—'}
        </div>
        <EndpointCard
          node={target}
          fallbackId={edge.target}
          role="target"
          onFocus={onFocus}
          onHide={onHide}
        />
      </div>

      {isPair && pair?.l3_via && (
        <div className="mt-2 rounded border border-teal-500/20 bg-teal-500/5 px-2 py-1.5">
          <p className="text-[11px] text-teal-200">
            L3 — path through a third observation:{' '}
            <span className="break-all font-mono text-teal-300">{pair.l3_via.via}</span>
          </p>
          <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[10px] text-gray-400">
            <span className="font-mono text-gray-300">{pair.l3_via.left_token}</span>
            <span>↔</span>
            <span className="font-mono text-gray-300">{pair.l3_via.right_token}</span>
            <span className="text-gray-600">
              (each side reaches the middle observation on a different key)
            </span>
          </div>
        </div>
      )}

      {isPair && (pair?.matched ?? edge.matched ?? []).length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-1">
          <span className="text-[10px] uppercase tracking-wide text-gray-600">L1</span>
          {(pair?.matched ?? edge.matched ?? []).map((value) => (
            <span
              key={`${value.kind}:${value.value}`}
              className={clsx(
                'rounded px-1 py-0.5 font-mono text-[10px]',
                value.ambient
                  ? 'bg-dark-40/60 text-gray-500 line-through decoration-gray-600/60'
                  : 'bg-dark-40 text-gray-300'
              )}
              title={
                value.ambient
                  ? `${value.kind}: ambient value — the tenant sees it constantly, so it links the two actions but adds nothing to L1`
                  : `${value.kind} (weight ${value.weight ?? 1}) → +${value.weight ?? 1} to L1`
              }
            >
              {value.kind}:{value.value}
              <span className="ml-1 text-gray-500">
                ×{value.ambient ? 0 : (value.weight ?? 1)}
              </span>
            </span>
          ))}
        </div>
      )}

      {isAction && (edge.observations ?? []).length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-1">
          <span className="text-[10px] uppercase tracking-wide text-gray-600">observations</span>
          {(edge.observations ?? []).map((key) => (
            <span
              key={key}
              title={`Observation ${key}`}
              className="max-w-[280px] truncate rounded bg-dark-40 px-1 py-0.5 font-mono text-[10px] text-gray-300"
            >
              {key}
            </span>
          ))}
          {(edge.roles ?? []).length > 1 && (
            <span className="text-[10px] text-gray-500">roles: {(edge.roles ?? []).join(', ')}</span>
          )}
        </div>
      )}

      {!isPair && siblings && siblings.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-1">
          <span className="text-[10px] uppercase tracking-wide text-gray-600">
            also on this key
          </span>
          {siblingGroups.map((group) => (
            <button
              key={`${group.label}|${group.technique ?? ''}`}
              type="button"
              onClick={() => onFocus(group.ids[0])}
              title={`${group.label}${
                group.technique ? ` ${group.technique}` : ''
              } — ${group.ids.length} observation${
                group.ids.length === 1 ? '' : 's'
              } on this key; click to focus the first`}
              className="rounded bg-dark-40 px-1 py-0.5 text-[10px] text-gray-300 hover:bg-dark-40/60 hover:text-teal-200"
            >
              <span>{group.label}</span>
              {group.technique && <span className="ml-1 text-gray-500">{group.technique}</span>}
              {group.ids.length > 1 && (
                <span className="ml-1 text-gray-600">· {group.ids.length}</span>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
