'use client';

/**
 * Correlation graph for a candidate.
 *
 * Two node classes, three edge classes:
 *
 *   observation  the attacker action the engine deduplicated alerts into
 *   entity       host / user / ip / domain — the substrate that links actions
 *   CORRELATION  observation↔observation, labelled with the L1+L2+L3 score.
 *                Solid when the pair cleared θ, dashed when it did not, so a
 *                near-miss is visible instead of silently dropped.
 *
 * The component takes data as a prop (no fetching) — the candidate detail
 * endpoint already returns this shape, and the parent owns selection.
 *
 * `Link ≥` narrows the pair links that are *drawn* by score. It is a view
 * filter, not a scope change: the component, its scores and the case keep the
 * evidence, which is what the alert scope bar is for.
 */

import dynamic from 'next/dynamic';
import { useEffect, useImperativeHandle, useMemo, useRef, useState, type Ref } from 'react';
import cytoscape, {
  type Core,
  type ElementDefinition,
  type EventObject,
  type NodeSingular,
  type SingularElementReturnValue,
} from 'cytoscape';
import cola from 'cytoscape-cola';
import fcose from 'cytoscape-fcose';

import type { CandidateObservation, CandidateTimelineEvent } from '@/hooks/useCaseCandidates';
import { edgeLengthFor, repulsionFor } from '@/lib/forceParams';
import { graphPalette, useGraphTheme, type GraphTheme } from '@/lib/graphTheme';
import { expandRadii, MAX_EXPAND_LAYERS, selectBudgetedEdges } from '@/lib/graphBudget';
import type { ClusterSummary } from '@/lib/graphCommunities';
import { applyMagnetism, type MagneticEdge } from '@/lib/magneticLayout';
import { relatedEntities } from '@/lib/relatedEntities';
import { arrangeStars } from '@/lib/starLayout';
import {
  CLUSTER_COLORS,
  clusterGraph,
  describeCluster,
  separateCommunities,
} from '@/lib/graphCommunities';
import { caseGraphViewsApi } from '@/lib/api';
import type { Graph3DHandle } from '@/components/correlation/Graph3DView';
import {
  GraphEntityPanel,
  type GraphEntityRow,
  type SavedGraphView,
} from '@/components/correlation/GraphEntityPanel';

// three.js is only fetched when the analyst asks for the 3D view: the 2D canvas
// is what everyone else uses, and WebGL is a demo/very-large-graph affordance.
const Graph3DView = dynamic(
  () => import('@/components/correlation/Graph3DView').then((mod) => mod.Graph3DView),
  {
    ssr: false,
    loading: () => (
      <div className="flex flex-1 items-center justify-center text-xs text-gray-500">
        Loading 3D view…
      </div>
    ),
  }
);
import { clsx } from 'clsx';
import type { CandidateGraph, CandidateGraphNode } from '@/hooks/useCaseCandidates';

if (typeof window !== 'undefined') {
  cytoscape.use(fcose);
  cytoscape.use(cola);
}

// Role → hue. Roles come from the normalizer as `family:detail`
// (e.g. `credential_access:lsass`), so match on the family prefix.
const ROLE_COLORS: Array<[RegExp, string]> = [
  [/credential/i, '#e11d48'],
  [/lateral/i, '#ea580c'],
  [/execution|powershell|script/i, '#d97706'],
  [/persist|registry/i, '#7c3aed'],
  [/exfil|collection/i, '#0284c7'],
  [/command|command_and_control|c2|beacon/i, '#db2777'],
  [/discovery|recon/i, '#0d9488'],
  // `general:intrusion` is the engine's catch-all role and by far the most
  // common one. It used to fall through to an undocumented grey; giving it a
  // declared entry keeps the canvas and the legend honest about every role the
  // engine actually emits.
  [/general|intrusion|impact/i, '#94a3b8'],
];

export function observationColor(role?: string | null): string {
  if (!role) return '#64748b';
  for (const [pattern, color] of ROLE_COLORS) {
    if (pattern.test(role)) return color;
  }
  return '#64748b';
}

/** Cap on drawn observation↔observation edges (keeps fcose readable). */
const MAX_PAIR_EDGES = 60;

/**
 * One fixed visual language for the graph: every kind has a stable colour AND a
 * stable shape, so an analyst learns "purple house = host, pink person = user"
 * once and reads the next candidate without re-checking the legend. Nothing
 * here may be randomised — the legend chip and the node must always look like
 * each other.
 *
 * There is exactly one picture per kind: the silhouette in `shape`, plus
 * `points` for the two cytoscape has no built-in for — a house for hosts and a
 * person for users. The legend chip draws that same silhouette, so the toolbar
 * and the canvas cannot disagree about what a kind looks like.
 */
interface KindMeta {
  kind: string;
  label: string;
  color: string;
  hint: string;
  shape: 'polygon' | 'hexagon' | 'diamond' | 'tag' | 'octagon' | 'ellipse';
  points?: number[];
  width: number;
  height: number;
}

// Clockwise from the roof apex: eave right, wall right, base, wall left, eave left.
const HOUSE_POINTS = [0, -1, 0.9, -0.22, 0.62, -0.22, 0.62, 1, -0.62, 1, -0.62, -0.22, -0.9, -0.22];

// Head + shoulders as one silhouette (a person, not a blob).
const PERSON_POINTS = [
  0, -1, 0.3, -0.86, 0.44, -0.55, 0.34, -0.26, 0.22, -0.14, 0.58, -0.02, 0.86, 0.34, 0.96, 0.72,
  0.96, 1, -0.96, 1, -0.96, 0.72, -0.86, 0.34, -0.58, -0.02, -0.22, -0.14, -0.34, -0.26, -0.44, -0.55,
  -0.3, -0.86,
];

// Rectangle with cut corners (top-left, top-right, bottom-right, bottom-left).
const CUT_RECTANGLE_POINTS = [
  -0.8, -1, 0.8, -1, 1, -0.8, 1, 0.8, 0.8, 1, -0.8, 1, -1, 0.8, -1, -0.8,
];

// Normalized outlines (the −1..1 box the points above use) for the shapes
// cytoscape has built in, so a legend chip can draw exactly what the canvas
// draws for kinds that do not carry their own `points`.
const SHAPE_POINTS: Record<string, number[]> = {
  // Copied vertex-for-vertex from cytoscape's own node shapes (`hexagon` is a
  // fitted 6-gon, `tag`/`diamond` are literal point lists) so a chip is the same
  // outline the canvas paints, not an approximation of it.
  hexagon: [-0.5, 1, -1, 0, -0.5, -1, 0.5, -1, 1, 0, 0.5, 1],
  diamond: [0, 1, 1, 0, 0, -1, -1, 0],
  tag: [-1, -1, 0.25, -1, 1, 0, 0.25, 1, -1, 1],
  octagon: [0.414, 1, -0.414, 1, -1, 0.414, -1, -0.414, -0.414, -1, 0.414, -1, 1, -0.414, 1, 0.414],
};
const FALLBACK_SHAPE_POINTS = [0, -1, 1, 0, 0, 1, -1, 0];

const KIND_META: KindMeta[] = [
  {
    kind: 'observation',
    label: 'Observations',
    color: '#e11d48',
    hint: 'The attacker actions the engine deduplicated alerts into. Colour follows the ATT&CK role; the silhouette is always this hexagon. Hiding them leaves the entities and the shared-key links between them.',
    shape: 'hexagon',
    width: 52,
    height: 40,
  },
  {
    kind: 'host',
    label: 'Host',
    color: '#8b5cf6',
    hint: 'Host the action was observed on (weight 2, or 1 for a hub).',
    shape: 'polygon',
    points: HOUSE_POINTS,
    width: 36,
    height: 36,
  },
  {
    kind: 'user',
    label: 'User',
    color: '#ec4899',
    hint: 'Account involved in the action (weight 2, or 1 for service/system accounts).',
    shape: 'polygon',
    points: PERSON_POINTS,
    width: 34,
    height: 34,
  },
  {
    kind: 'ip',
    label: 'IP',
    color: '#3b82f6',
    hint: 'Remote or source address (weight 3 public, 2 private).',
    shape: 'diamond',
    width: 28,
    height: 28,
  },
  {
    kind: 'domain',
    label: 'Domain',
    color: '#f59e0b',
    hint: 'Domain or FQDN referenced by the action (weight 2, 1 when common).',
    shape: 'tag',
    width: 36,
    height: 28,
  },
  {
    kind: 'hash',
    label: 'Hash',
    color: '#22c55e',
    hint: 'File hash (weight 3 for a rare file, 2 for a common one).',
    shape: 'octagon',
    width: 26,
    height: 26,
  },
  {
    kind: 'process_guid',
    label: 'Process',
    color: '#14b8a6',
    hint: 'Host-scoped process GUID — the strongest key when it is shared.',
    shape: 'polygon',
    points: CUT_RECTANGLE_POINTS,
    width: 32,
    height: 24,
  },
  {
    kind: 'key',
    label: 'Other key',
    color: '#94a3b8',
    hint: 'A correlation key outside the entity buckets the console groups by.',
    shape: 'ellipse',
    width: 20,
    height: 20,
  },
];

// Exported so the edge inspector can draw the same chip and name the same kind
// as the canvas; a second copy of this table would drift.
export const KIND_BY_NAME: Record<string, KindMeta> = Object.fromEntries(
  KIND_META.map((meta) => [meta.kind, meta])
);

/**
 * A link's colour pushed away from the canvas, for the hover tint.
 *
 * On the dark canvas that means lighter (toward white); on the light one it
 * means darker, because a lighter line on white is a line that disappeared.
 *
 * cytoscape hands back computed colours as `rgb(r, g, b)`; hex is accepted too
 * so the helper is usable on a literal when one is handy.
 */
function hoverTint(value: string, theme: GraphTheme): string {
  const rgb = value.match(/rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/i);
  const channels = rgb
    ? [Number(rgb[1]), Number(rgb[2]), Number(rgb[3])]
    : (() => {
        const hex = value.trim().replace('#', '');
        if (hex.length !== 6) return [148, 163, 184];
        return [0, 2, 4].map((index) => parseInt(hex.slice(index, index + 2), 16));
      })();
  const target = theme === 'light' ? 0 : 255;
  const amount = theme === 'light' ? 0.35 : 0.45;
  const mix = channels.map((channel) => Math.round(channel + (target - channel) * amount));
  return `rgb(${mix[0]}, ${mix[1]}, ${mix[2]})`;
}

/**
 * Kind → outline for the 3D point sprites. It reads the same KIND_META the
 * canvas draws from, so a house stays a house and a tag stays a tag when the
 * analyst switches projection; only the rasterisation happens in 3D.
 */
export function kindShapeFor(kind: string): {
  points?: number[];
  round?: boolean;
  height: number;
} {
  const meta = KIND_BY_NAME[kind] ?? FALLBACK_KIND_META;
  if (meta.points) return { points: meta.points, height: meta.height };
  if (meta.shape === 'ellipse') return { round: true, height: meta.height };
  return { points: SHAPE_POINTS[meta.shape] ?? FALLBACK_SHAPE_POINTS, height: meta.height };
}

export const KIND_LABEL: Record<string, string> = Object.fromEntries(
  KIND_META.map((meta) => [meta.kind, meta.label])
);

/**
 * A node kind this build has no table entry for.
 *
 * The backend maps every correlation token onto one of the kinds above
 * (`services/api/app/services/candidate_discovery.py` → `_build_graph`; unknown
 * token kinds collapse to `key`), but a future backend key must not be able to
 * paint a node the toolbar cannot name or switch off. Such a node falls back to
 * the matte grey circle, and `kindOptions` below mints it a chip.
 */
const FALLBACK_KIND_META: KindMeta = {
  kind: 'unknown',
  label: 'Other',
  color: '#64748b',
  hint: 'A node kind this build has no shape for — drawn as a generic circle.',
  shape: 'ellipse',
  width: 24,
  height: 24,
};

function humanizeKind(kind: string): string {
  const words = kind.replace(/[_-]+/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : 'Other';
}

/** Table entry for a kind, minted from the fallback when the kind is new. */
const kindColorFor = (kind: string): string => metaForKind(kind).color;

export function metaForKind(kind: string): KindMeta {
  return KIND_BY_NAME[kind] ?? { ...FALLBACK_KIND_META, kind, label: humanizeKind(kind) };
}

/**
 * Kind chip — the node silhouette, at 12×12, in the kind colour.
 *
 * Deliberately a silhouette and nothing more: the canvas can only paint a
 * silhouette, and a second, different picture in the legend is what made
 * `Process` a plain teal cut-rectangle on the graph and a grid glyph in the
 * key. One shape per kind, drawn the same way in both places.
 */
export function KindIcon({ meta, muted }: { meta: KindMeta; muted?: boolean }) {
  if (meta.shape === 'ellipse') {
    return (
      <svg viewBox="-1.25 -1.25 2.5 2.5" aria-hidden="true" className="h-3 w-3 shrink-0">
        <circle
          r={1}
          fill={muted ? 'transparent' : meta.color}
          stroke={meta.color}
          strokeWidth={muted ? 0.22 : 0}
        />
      </svg>
    );
  }
  const points = meta.points ?? SHAPE_POINTS[meta.shape] ?? FALLBACK_SHAPE_POINTS;
  const polygon: string[] = [];
  for (let i = 0; i < points.length; i += 2) polygon.push(`${points[i]},${points[i + 1]}`);
  return (
    <svg viewBox="-1.25 -1.25 2.5 2.5" aria-hidden="true" className="h-3 w-3 shrink-0">
      <polygon
        points={polygon.join(' ')}
        fill={muted ? 'transparent' : meta.color}
        stroke={meta.color}
        strokeWidth={muted ? 0.22 : 0}
        strokeLinejoin="round"
      />
    </svg>
  );
}

/**
 * How many neighbours of a single node are drawn by default.
 *
 * A hub entity can touch dozens of observations; drawing all of them turns the
 * canvas into a hairball and buries the twenty leaves the analyst actually needs
 * to reason about. The budget is per node and can be raised per node (Expand).
 */
const NEIGHBOUR_BUDGETS = [4, 8, 16, 'all'] as const;
type NeighbourBudget = (typeof NEIGHBOUR_BUDGETS)[number];

/** Node ids the analyst asked to expand / hide, exposed to the parent rail. */
export interface CandidateGraphHandle {
  /** Reveal one more neighbour layer; returns the depth now drawn. */
  expandNode: (id: string) => number;
  /** Layers already revealed around one node (0 = never expanded). */
  expandDepthOf: (id: string) => number;
  /** Forget every expansion, back to the plain budgeted graph. */
  resetExpansion: () => void;
  hideNode: (id: string) => void;
  focusNode: (id: string) => void;
  /** Undo the last Focus: restore the nodes it hid and re-fit the graph. */
  unfocus: () => void;
  showAll: () => void;
  /** Re-fit the whole graph — the parent calls it after its viewport changes. */
  fit: () => void;
}

function shortLabel(value: string, max = 26): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

/**
 * Separate the graph's communities after a full layout.
 *
 * A candidate graph is one connected component, so `fcose` has no reason to
 * hold clusters apart: on a campaign with hundreds of observations the entity
 * rings interleave and the picture only becomes readable after the analyst
 * drags hubs around by hand. This pass recovers that separation for them —
 * communities are found on the structural (entity) links, then moved as rigid
 * bodies until their bounding circles no longer overlap. Below 40 nodes the
 * layout is already legible and the extra distance only wastes the viewport.
 */
function spreadClusters(
  instance: Core,
  partition: ReadonlyMap<string, string>,
  roomy: boolean
): void {
  const visibleNodes = instance.nodes().filter((node) => node.visible());
  if (visibleNodes.length < 40) return;
  const ids = visibleNodes.map((node) => node.id());
  // The partition is computed over the whole graph, not over what is currently
  // drawn: hiding a node (or collapsing a bubble) must not reshape the rest.
  const membership = new Map(
    ids.filter((id) => partition.has(id)).map((id) => [id, partition.get(id)!] as const)
  );
  if (new Set(membership.values()).size < 2) return;
  const positions = new Map(
    ids.map((id) => {
      const point = instance.getElementById(id).position();
      return [id, { x: point.x, y: point.y }] as const;
    })
  );
  const spread = separateCommunities(positions, membership, {
    gap: 60,
    margin: 34,
    iterations: 240,
  });
  instance.batch(() => {
    for (const [id, point] of spread) instance.getElementById(id).position(point);
  });

  // Forces leave a busy hub's leaves in one tight ring, and the ring of the hub
  // next door reaches into the same space. Give each big star its own mushroom
  // cap (leaves on an arc aimed away from its trunk), then keep the caps apart.
  const adjacency = new Map<string, string[]>();
  for (const id of ids) adjacency.set(id, []);
  for (const edge of instance.edges()) {
    if (!edge.visible()) continue;
    const source = String(edge.data('source'));
    const target = String(edge.data('target'));
    if (!adjacency.has(source) || !adjacency.has(target)) continue;
    adjacency.get(source)!.push(target);
    adjacency.get(target)!.push(source);
  }
  const arranged = arrangeStars(new Map(spread), adjacency, {
    minLeaves: roomy ? 6 : 5,
    leafSpacing: roomy ? 54 : 40,
    minRadius: roomy ? 64 : 48,
    capGap: roomy ? 30 : 18,
  });
  instance.batch(() => {
    for (const [id, point] of arranged) {
      const element = instance.getElementById(id);
      if (!element.empty()) element.position(point);
    }
  });
}

/**
 * fcose parameters for a spacing mode.
 *
 * Shared by the first render, the post-drag settle and Reset so a candidate
 * cannot end up on one layout density and then relax into another.
 */
function spacingParams(spacing: 'roomy' | 'compact') {
  const roomy = spacing === 'roomy';
  return {
    padding: roomy ? 72 : 40,
    nodeSeparation: roomy ? 190 : 90,
    // Both forces scale with fan-out. A flat repulsion pulls every leaf of a
    // busy hub onto one ring, and the ring of the hub next door lands in the
    // same space — the leaves of A and B weave together. A hub that pushes
    // harder, with longer first edges, leaves room for its own fan and keeps
    // neighbouring fans from reaching into it.
    idealEdgeLength: (edge: {
      source(): { degree(): number };
      target(): { degree(): number };
    }) => edgeLengthFor(Math.max(edge.source().degree(), edge.target().degree()), spacing),
    nodeRepulsion: (node: { degree(): number }) => repulsionFor(node.degree(), spacing),
    gravity: roomy ? 0.18 : 0.3,
    numIter: roomy ? 2500 : 1000,
  };
}

/** Zoom steps for the toolbar buttons. */
const ZOOM_STEP = 1.3;

/**
 * Everything the canvas can be showing, captured so Undo/Redo and saved views
 * can put it back: which nodes are hidden, removed, collapsed or expanded, which
 * node / bubble is focused, and the 2D camera it was read at.
 */
export type GraphViewState = Record<string, unknown> & {
  hidden: string[];
  removed: string[];
  collapsed: [string, string[]][];
  expanded: [string, number][];
  activeEntity: string | null;
  activeCluster: string | null;
  focus: string | null;
  zoom: number | null;
  pan: { x: number; y: number } | null;
};

/** A parked view: the panel's row data plus the state needed to restore it. */
interface ParkedView extends SavedGraphView {
  state: GraphViewState;
}

/**
 * When each element of the reveal appears, as a fraction of the run.
 *
 * Reveal speed follows a bump: slow at both ends, fast in the middle. A
 * decay-only schedule (ever shorter gaps) is ease-in by construction — it opens
 * gently and dumps the tail in a burst. Here the gaps widen again towards the
 * end, so the last elements are seen arriving instead of blinking in.
 *
 * The first beat is still a beat of its own: the opening node holds for up to
 * ~10% of the run before the second element lands, which is what makes the
 * direction of the walk readable.
 */
export function buildRevealSchedule(
  count: number,
  budgetMs: number
): { fractions: number[]; totalMs: number } {
  if (count <= 1) return { fractions: [0], totalMs: 0 };
  const totalMs = Math.max(1, budgetMs);
  // Opening hold: long enough to register the first node, short enough that a
  // 60-element graph is not standing still for a tenth of its run.
  const hold = Math.min(600, totalMs * 0.1);
  const span = Math.max(1, totalMs - hold);
  // A gap is the inverse of speed, and speed is a bump over the run: a third of
  // full speed at the edges, full speed in the middle. With the budget spread
  // over 171 elements that is ~105ms between the first and last pairs against
  // ~32ms through the middle — readable at both ends without the middle crawling.
  const speed = (progress: number) => 0.3 + 0.7 * Math.sin(Math.PI * progress) ** 2;
  const weights: number[] = [];
  let weightTotal = 0;
  for (let index = 1; index < count; index += 1) {
    const weight = 1 / speed((index - 0.5) / (count - 1));
    weights.push(weight);
    weightTotal += weight;
  }
  const fractions: number[] = [0];
  let cumulative = 0;
  for (const weight of weights) {
    cumulative += weight;
    fractions.push((hold + (span * cumulative) / weightTotal) / totalMs);
  }
  return { fractions, totalMs };
}

/** Hand a `data:` image to the browser as a download. */
function downloadDataUrl(dataUrl: string, filename: string) {
  const link = document.createElement('a');
  link.href = dataUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
}

interface CandidateGraphViewProps {
  graph: CandidateGraph | null | undefined;
  /** Node id to focus (set from the summary rail). */
  focusId?: string | null;
  /**
   * `source` says where the pick came from: a click on the canvas should open
   * the inspector, a click on a list row should not (the caller decides).
   */
  onSelectNode?: (node: CandidateGraphNode | null, source?: 'canvas' | 'list') => void;
  /** Emits the tapped edge id (CORRELATION or entity link), or null on background. */
  onSelectEdge?: (edgeId: string | null) => void;
  /** Edge the parent is inspecting — highlighted so the panel has an obvious owner. */
  selectedEdgeId?: string | null;
  className?: string;
  /**
   * Maximise control, owned by the parent because the parent is what knows the
   * full set of panels that belong in full screen (this graph *and* the
   * ATT&CK / kill-chain strip are siblings in the modal). Omit to hide it.
   */
  onToggleFullscreen?: () => void;
  fullscreenActive?: boolean;
  /** Lets the parent rail expand / hide / focus a node it owns the selection for. */
  ref?: Ref<CandidateGraphHandle>;
  /** Projection this graph was built with (API echo) and the control that flips it. */
  observationMode?: 'node' | 'edge';
  onToggleObservationMode?: (mode: 'node' | 'edge') => void;
  /**
   * Toggle the auto-open preference for the inspector when the user selects a
   * node from the graph or entity list. The panel itself remains controlled by
   * the parent, and the row-level D action is the explicit override.
   */
  onToggleDetails?: () => void;
  /** Open the selected node details explicitly, even when the global Details toggle is off. */
  onOpenDetails?: (id: string) => void;
  /** Told to drop the parent's own Focus state when Clear view resets it. */
  onClearFocus?: () => void;
  /** Told which node Undo/Redo put the focus on, so the parent's state follows. */
  onFocusRestore?: (id: string | null) => void;
  /**
   * Where parked views belong on the server. Supplied by the case correlation
   * view (a case outlives the session, so its views do too); omitted for a
   * one-off candidate graph, where the Views tab stays in-memory.
   */
  viewStore?: { caseId: string };
  detailsOpen?: boolean;
  /** False until a node is selected: the panel has nothing to show before that. */
  hasSelectedNode?: boolean;
  /**
   * Candidate timeline and observations, so the entity list can say when an
   * entity's alerts fired and which observation found it first. The graph alone
   * carries no times, so the panel stays empty when these are omitted.
   */
  timeline?: readonly CandidateTimelineEvent[];
  observations?: readonly CandidateObservation[];
}

interface HoverCard {
  x: number;
  y: number;
  kind: string;
  label: string;
  token: string | null;
  alerts: number;
  collapsed: number;
}

export function CandidateGraphView({
  graph,
  focusId,
  onSelectNode,
  onSelectEdge,
  selectedEdgeId = null,
  className,
  onToggleFullscreen,
  fullscreenActive = false,
  ref,
  observationMode,
  onToggleObservationMode,
  onToggleDetails,
  onOpenDetails,
  onClearFocus,
  onFocusRestore,
  viewStore,
  detailsOpen = false,
  hasSelectedNode = false,
  timeline,
  observations,
}: CandidateGraphViewProps) {
  // The canvas cannot read the theme's CSS tokens, so the palette is handed to
  // cytoscape explicitly; a theme switch rebuilds the styles in place.
  const theme = useGraphTheme();
  const palette = graphPalette(theme);
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  // Node positions survive a rebuild. Hiding one entity from the list or the
  // toolbar re-creates the canvas (the element set changed); without this the
  // whole graph would jump to a new random arrangement on every toggle.
  const positionsRef = useRef<Map<string, { x: number; y: number }>>(new Map());
  // Set by the canvas effect; Reset re-fits and must re-place the labels too.
  // Off by default? No — everything on, so the first view is the whole campaign.
  // The analyst then turns off what they are not reasoning about (e.g. users).
  const [hiddenKinds, setHiddenKinds] = useState<Set<string>>(new Set());
  const [hiddenNodes, setHiddenNodes] = useState<Set<string>>(new Set());
  // "Removed" is the stronger of the two view states: the node is off the
  // canvas *and* carries a removed badge in the entity list. Both are local to
  // this view — nothing is deleted from the case.
  const [removedNodes, setRemovedNodes] = useState<Set<string>>(new Set());
  const [selectedEntityIds, setSelectedEntityIds] = useState<Set<string>>(new Set());
  const [show3d, setShow3d] = useState(false);
  // Camera commands from the orbit view, so the shared zoom buttons are not
  // dead while 3D is on screen: cytoscape is still mounted underneath but its
  // canvas is hidden, which is why clicking them used to do nothing.
  const graph3dRef = useRef<Graph3DHandle | null>(null);
  // The canvas effect below tears down and rebuilds the cytoscape instance, and
  // a rebuild starts at zoom 1 / pan 0 — a much closer view than the one the
  // analyst was looking at. Callers pass the select handlers inline, so their
  // identity changed on every parent render (toggling the Evidence rail, an SWR
  // revalidation) and the graph rebuilt behind the analyst's back: the drawing
  // jumped to a hard zoom as soon as the layout around it changed. The handlers
  // are read through refs instead, so a render cannot rebuild the canvas.
  const onSelectNodeRef = useRef(onSelectNode);
  const onSelectEdgeRef = useRef(onSelectEdge);
  useEffect(() => {
    onSelectNodeRef.current = onSelectNode;
    onSelectEdgeRef.current = onSelectEdge;
  });
  // What was on screen before Focus hid everything else, so Unfocus restores
  // exactly that instead of the analyst's manual hides.
  const focusRestoreRef = useRef<Set<string> | null>(null);
  // Expand adds nodes that were previously budgeted out; without a fit they
  // land outside the visible viewport and the button looks like it did nothing.
  const fitAfterLayoutRef = useRef(false);
  /** No fit has framed the current elements at a real canvas size yet. */
  const pendingInitialFitRef = useRef(true);
  // Collapsed bubbles keep their label on the canvas and hide their members.
  const [collapsedClusters, setCollapsedClusters] = useState<Map<string, string[]>>(new Map());
  // Undo/Redo of the view (not of the case) and the views the analyst parked.
  // Fifty steps is enough to walk back through an investigation and cheap to
  // keep: a snapshot is a handful of id arrays.
  const historyRef = useRef<GraphViewState[]>([]);
  const historyIndexRef = useRef(-1);
  const [historyStatus, setHistoryStatus] = useState({ canUndo: false, canRedo: false });
  const [settingsOpen, setSettingsOpen] = useState(false);
  // The reveal animation: the graph builds itself in alert order, so the first
  // thing the analyst sees is where the analysis starts.
  const [revealPlayback, setRevealPlayback] = useState<'idle' | 'playing' | 'paused' | 'done'>(
    'idle'
  );
  const revealListRef = useRef<string[]>([]);
  /** When each element appears, as a fraction of the whole run. */
  const revealScheduleRef = useRef<number[]>([0]);
  const revealIndexRef = useRef(0);
  const revealFractionRef = useRef(1);
  const revealElapsedRef = useRef(0);
  const revealStartedAtRef = useRef(0);
  const revealDurationRef = useRef(0);
  const revealRafRef = useRef<number | null>(null);
  const revealBootedRef = useRef(false);
  const [savedViews, setSavedViews] = useState<ParkedView[]>([]);
  /** Set when the saved-views API refused a write/read, so the tab can say so. */
  const [viewError, setViewError] = useState<string | null>(null);
  // Bubbles as the 3D scene sees them, reported for the panel's Clusters tab.
  const [clusters3d, setClusters3d] = useState<ClusterSummary[]>([]);

  const [activeEntityId, setActiveEntityId] = useState<string | null>(null);
  /** The bubble the analyst focused from the Clusters tab, if any. */
  const [activeClusterKey, setActiveClusterKey] = useState<string | null>(null);

  // How many layers each expanded node has already revealed (node id → depth).
  // The inspector's Expand button increments it, so a second click opens the
  // next ring instead of re-drawing the same one.
  const [expandedDepths, setExpandedDepths] = useState<Map<string, number>>(new Map());
  const expandedDepthsRef = useRef<Map<string, number>>(new Map());
  // Default to every neighbour: the modal opens on the whole campaign, and a
  // budget that starts at 8 hides most of it behind `+N` before the analyst has
  // asked for anything.
  const [neighbourBudget, setNeighbourBudget] = useState<NeighbourBudget>('all');
  const [showPairs, setShowPairs] = useState(true);
  // Display filter on the pair score. It only decides which links are drawn —
  // the component, its scores and the case are untouched (that is what the
  // alert scope is for, and the footer says so).
  const [minLinkScore, setMinLinkScore] = useState<number | null>(null);
  const [spacing, setSpacing] = useState<'roomy' | 'compact'>('roomy');
  // Magnetic pass: springs along the links, repulsion only between leaves that
  // share none. Runs after the engine's layout; off leaves the plain fcose
  // picture exactly as before.
  const [magnetic, setMagnetic] = useState(true);
  // Live mode swaps the one-shot fcose pass for a continuous cola simulation:
  // the picture keeps relaxing, so dragging a leaf pushes its neighbours like
  // magnets instead of replaying a batch layout.
  const [liveLayout, setLiveLayout] = useState(false);
  // Labels are zoom-driven on the canvas (always on unless the analyst hides
  // them) and off by default in 3D, where each name costs a texture.
  const [labels2d, setLabels2d] = useState(true);
  // The 3D scene opens with its names on, like the 2D canvas: a picture of
  // anonymous marks is not a correlation graph an analyst can read.
  const [labels3d, setLabels3d] = useState(true);
  const magneticPassRef = useRef<(() => void) | null>(null);
  const [autoTidy, setAutoTidy] = useState(true);
  const [renderError, setRenderError] = useState<string | null>(null);
  const [hovered, setHovered] = useState<HoverCard | null>(null);

  // Kept in a ref so toggling auto-tidy does not rebuild the canvas (which
  // would throw away the arrangement the analyst just drew).
  const autoTidyRef = useRef(autoTidy);
  useEffect(() => {
    autoTidyRef.current = autoTidy;
  }, [autoTidy]);

  // A 47-observation component scores 1 081 pairs, 575 of them above θ —
  // drawing all of them is unreadable. Entity links carry the "why" and the
  // strongest scoring edges carry the emphasis, so the canvas stays legible.
  const counts = useMemo(() => {
    const nodes = graph?.nodes ?? [];
    const edges = graph?.edges ?? [];
    const correlation = edges.filter((edge) => edge.kind === 'CORRELATION');
    const byKind = new Map<string, number>();
    for (const node of nodes) {
      byKind.set(node.kind, (byKind.get(node.kind) ?? 0) + 1);
    }
    const visibleEntities = nodes.filter(
      (node) => node.kind !== 'observation' && !hiddenKinds.has(node.kind)
    ).length;
    return {
      observations: nodes.filter((node) => node.kind === 'observation').length,
      entities: nodes.filter((node) => node.kind !== 'observation').length,
      visibleEntities,
      byKind,
      correlationEdges: correlation.length,
      aboveTheta: correlation.filter((edge) => edge.threshold_met !== false).length,
      entityEdges: edges.filter((edge) => edge.kind !== 'CORRELATION').length,
      // Observations drawn as relations instead of hub nodes (edge projection).
      roleEdges: edges.filter((edge) => edge.kind === 'OBSERVATION').length,
      collapsedActions: edges
        .filter((edge) => edge.kind === 'OBSERVATION')
        .reduce((total, edge) => total + Math.max(0, (edge.count ?? 1) - 1), 0),
    };
  }, [graph, hiddenKinds]);

  /**
   * The leaf entities behind the canvas, as rows for the side panel.
   *
   * An entity's row carries what helps place it without hovering the graph:
   * how many links it draws and how many observations it takes part in, next
   * to the alert count the node already knows.
   */
  const entityRows = useMemo<GraphEntityRow[]>(() => {
    if (!graph) return [];
    const kindOf = new Map(graph.nodes.map((node) => [node.id, node.kind]));
    const links = new Map<string, number>();
    const actions = new Map<string, number>();
    for (const edge of graph.edges) {
      links.set(edge.source, (links.get(edge.source) ?? 0) + 1);
      links.set(edge.target, (links.get(edge.target) ?? 0) + 1);
      if (edge.kind === 'OBSERVATION') {
        actions.set(edge.source, (actions.get(edge.source) ?? 0) + 1);
        actions.set(edge.target, (actions.get(edge.target) ?? 0) + 1);
        continue;
      }
      const sourceIsObservation = kindOf.get(edge.source) === 'observation';
      const targetIsObservation = kindOf.get(edge.target) === 'observation';
      if (sourceIsObservation !== targetIsObservation) {
        const entity = sourceIsObservation ? edge.target : edge.source;
        actions.set(entity, (actions.get(entity) ?? 0) + 1);
      }
    }
    return graph.nodes
      .filter((node) => node.kind !== 'observation')
      .map((node) => ({
        id: node.id,
        kind: node.kind,
        label: node.label,
        token: node.token ?? null,
        alerts: node.alert_count ?? 0,
        links: links.get(node.id) ?? 0,
        actions: actions.get(node.id) ?? 0,
      }))
      .sort((a, b) => b.links - a.links || a.label.localeCompare(b.label));
  }, [graph]);

  /**
   * The bubble partition, computed once per graph.
   *
   * It is deliberately independent of what is hidden or collapsed: a bubble
   * must mean the same thing before and after the analyst collapses it, and
   * hiding one node must not re-shuffle the others into new groups.
   */
  const clusterPartition = useMemo(() => {
    if (!graph || graph.nodes.length < 40) return new Map<string, string>();
    const ids = graph.nodes.map((node) => node.id);
    const structure = graph.edges
      .filter((edge) => edge.kind !== 'CORRELATION')
      .map((edge) => ({ source: edge.source, target: edge.target }));
    return clusterGraph(ids, structure);
  }, [graph]);

  const clusterMembers = useMemo(() => {
    const groups = new Map<string, string[]>();
    for (const [id, key] of clusterPartition) {
      const list = groups.get(key);
      if (list) list.push(id);
      else groups.set(key, [id]);
    }
    return groups;
  }, [clusterPartition]);

  /**
   * Bubbles for the panel, derived from the partition itself rather than from
   * the canvas: the canvas labels were removed and only published their names
   * once a layout settled, so the Clusters tab used to be missing until then.
   */
  const clusterSummaries2d = useMemo<ClusterSummary[]>(() => {
    const nodes = graph?.nodes ?? [];
    if (nodes.length === 0 || clusterMembers.size === 0) return [];
    const nodeOf = new Map(nodes.map((node) => [node.id, node]));
    const degree = new Map<string, number>();
    for (const edge of graph?.edges ?? []) {
      if (edge.kind === 'CORRELATION') continue;
      degree.set(edge.source, (degree.get(edge.source) ?? 0) + 1);
      degree.set(edge.target, (degree.get(edge.target) ?? 0) + 1);
    }
    const keys = [...clusterMembers.keys()].sort((a, b) => a.localeCompare(b));
    return keys.map((key, index) => {
      const members = clusterMembers.get(key) ?? [];
      const described = describeCluster(
        members
          .map((id) => nodeOf.get(id))
          .filter((node): node is CandidateGraphNode => Boolean(node)),
        degree
      );
      return {
        community: key,
        title: shortLabel(described.title, 22),
        subtitle: described.subtitle,
        // Same rule the 3D scene uses (sorted keys into CLUSTER_COLORS), so a
        // bubble keeps its colour when the projection changes.
        color: CLUSTER_COLORS[index % CLUSTER_COLORS.length],
        size: members.length,
        collapsed: collapsedClusters.has(key),
      };
    });
  }, [graph, clusterMembers, collapsedClusters]);

  // A stable identity for the 3D ring layer: a fresh Set every render would
  // redraw every ring (and re-allocate their materials) on each pan.
  const activeClusterIds = useMemo<ReadonlySet<string>>(
    () => {
      // A collapsed bubble keeps nothing of its focus: its members are off the
      // canvas, so the highlight has to go with them. It used to stay, leaving
      // rings and borders around nodes that were no longer drawn.
      if (!activeClusterKey || collapsedClusters.has(activeClusterKey)) return new Set<string>();
      return new Set(clusterMembers.get(activeClusterKey) ?? []);
    },
    [activeClusterKey, clusterMembers, collapsedClusters]
  );

  /** One list for the panel, whichever view is on screen. */
  const clusterSummaries = show3d ? clusters3d : clusterSummaries2d;

  // A stable identity for the 3D view: it rebuilds its scene from this set, and
  // a fresh Set on every render would restart the camera.
  const collapsedClusterKeys = useMemo(
    () => new Set(collapsedClusters.keys()),
    [collapsedClusters]
  );

  const toggleCluster = (key: string) => {
    const members = clusterMembers.get(key) ?? [];
    if (members.length === 0) return;
    const collapsing = !collapsedClusters.has(key);
    // Collapsing the bubble you were focused on is what "unfocus by collapse"
    // means: drop the focus with it instead of keeping half the state.
    if (collapsing && activeClusterKey === key) setActiveClusterKey(null);
    setCollapsedClusters((current) => {
      const next = new Map(current);
      if (collapsing) next.set(key, members);
      else next.delete(key);
      return next;
    });
    setHiddenNodes((current) => {
      const next = new Set(current);
      for (const id of members) {
        if (collapsing) next.add(id);
        else next.delete(id);
      }
      return next;
    });
    if (collapsing) setActiveEntityId(null);
  };

  /**
   * Frame one bubble's nodes. 2D pans to the bubble and keeps the analyst's
   * zoom; 3D dollies to the shell, so the Clusters tab means the same thing in
   * both views.
   */
  const focusCluster = (key: string) => {
    // Same idea as the entity row: focus also has to show which nodes it picked.
    setActiveClusterKey(key);
    setActiveEntityId(null);
    // A bubble is not an entity, so whatever node inspector was open no longer
    // describes what the analyst is looking at.
    onSelectNode?.(null, 'list');
    if (show3d) {
      graph3dRef.current?.focusCluster(key);
      return;
    }
    const cy = cyRef.current;
    const members = clusterMembers.get(key) ?? [];
    if (!cy || members.length === 0) return;
    const wanted = new Set(members);
    const eles = cy.nodes().filter((node) => wanted.has(node.id()));
    if (eles.empty()) return;
    // Centre the bubble and keep the analyst's zoom. Fitting it to the viewport
    // zoomed so far in that the leaves hanging off the cluster fell outside the
    // frame, and it threw away the zoom the analyst had set. So: pan only —
    // except when the bubble is larger than the viewport at the current zoom,
    // where the only way to see all of it is to zoom *out* (never in).
    const box = eles.boundingBox();
    const zoom = cy.zoom();
    const pad = 60;
    const available = {
      width: Math.max(1, cy.width() - pad * 2),
      height: Math.max(1, cy.height() - pad * 2),
    };
    const boxWidth = Math.max(1, box.w);
    const boxHeight = Math.max(1, box.h);
    const needed = Math.min(available.width / boxWidth, available.height / boxHeight);
    const nextZoom = needed < zoom ? needed : zoom;
    const pan = {
      x: cy.width() / 2 - ((box.x1 + box.x2) / 2) * nextZoom,
      y: cy.height() / 2 - ((box.y1 + box.y2) / 2) * nextZoom,
    };
    cy.animate(nextZoom === zoom ? { pan } : { pan, zoom: nextZoom }, { duration: 300 });
  };

  const addTo = (current: Set<string>, ids: string[]) => {
    const next = new Set(current);
    for (const id of ids) next.add(id);
    return next;
  };
  const removeFrom = (current: Set<string>, ids: string[]) => {
    if (!ids.some((id) => current.has(id))) return current;
    const next = new Set(current);
    for (const id of ids) next.delete(id);
    return next;
  };

  const restoreVisibleIds = (ids: string[]) => {
    const keysToExpand = [...collapsedClusters.keys()].filter((key) =>
      (clusterMembers.get(key) ?? []).some((id) => ids.includes(id))
    );
    if (keysToExpand.length === 0) {
      setHiddenNodes((current) => removeFrom(current, ids));
      setRemovedNodes((current) => removeFrom(current, ids));
      return;
    }

    setCollapsedClusters((current) => {
      const next = new Map(current);
      for (const key of keysToExpand) next.delete(key);
      return next;
    });
    setHiddenNodes((current) => {
      let next = new Set(current);
      for (const key of keysToExpand) {
        for (const id of clusterMembers.get(key) ?? []) next.delete(id);
      }
      for (const id of ids) next.delete(id);
      return next;
    });
    setRemovedNodes((current) => {
      let next = new Set(current);
      for (const key of keysToExpand) {
        for (const id of clusterMembers.get(key) ?? []) next.delete(id);
      }
      for (const id of ids) next.delete(id);
      return next;
    });
    if (keysToExpand.includes(activeClusterKey ?? '')) setActiveClusterKey(null);
  };

  /**
   * Add the leaves exactly one edge away. `relatedEntities` owns the rule (one
   * edge, never a walk, never an observation or key token), so the button and
   * its tests cannot drift apart.
   */
  const selectRelatedEntities = (ids: string[]) => {
    if (!graph || ids.length === 0) return;
    const selected = new Set(ids);
    const related = relatedEntities(graph.nodes, graph.edges, selected);
    if (related.length === 0) return;
    setSelectedEntityIds((current) => {
      const next = new Set(current);
      for (const node of related) next.add(node.id);
      return next;
    });
  };

  /** Role → colour legend for the action edges, in first-seen order. */
  const roleLegend = useMemo(() => {
    const legend = new Map<string, { role: string; color: string; count: number }>();
    for (const edge of graph?.edges ?? []) {
      if (edge.kind !== 'OBSERVATION') continue;
      const role = edge.role ?? 'action';
      const entry = legend.get(role);
      if (entry) entry.count += 1;
      else legend.set(role, { role, color: observationColor(role), count: 1 });
    }
    return [...legend.values()];
  }, [graph]);

  /**
   * Types this candidate actually has, in toolbar order — plus any kind this
   * build's table does not know yet. A node the toolbar cannot name would be
   * un-hideable, so an unknown kind always gets a chip minted from the
   * fallback entry (same grey key look the canvas gives it).
   */
  const kindOptions = useMemo(() => {
    const known = KIND_META.filter((meta) => (counts.byKind.get(meta.kind) ?? 0) > 0);
    const extra = [...counts.byKind.keys()]
      .filter((kind) => !KIND_BY_NAME[kind])
      .sort()
      .map((kind) => metaForKind(kind));
    return [...known, ...extra];
  }, [counts]);

  const toggleKind = (kind: string) => {
    setHiddenKinds((current) => {
      const next = new Set(current);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });
  };

  /** Every score an above-θ pair link actually carries, for the min-link control. */
  const linkScoreOptions = useMemo(() => {
    const scores = new Set<number>();
    for (const edge of graph?.edges ?? []) {
      if (edge.kind === 'CORRELATION' && edge.threshold_met !== false) {
        scores.add(edge.weight ?? 0);
      }
    }
    return [...scores].sort((a, b) => a - b);
  }, [graph]);

  const pairLinksInRange = useMemo(() => {
    if (!graph) return 0;
    return graph.edges.filter(
      (edge) =>
        edge.kind === 'CORRELATION' &&
        edge.threshold_met !== false &&
        (minLinkScore === null || (edge.weight ?? 0) >= minLinkScore)
    ).length;
  }, [graph, minLinkScore]);

  const strongestPairs = useMemo(() => {
    if (!graph) return [];
    return graph.edges
      .filter((edge) => edge.kind === 'CORRELATION' && edge.threshold_met !== false) // θ is the gate; below-θ pairs stay in the data, not on the canvas
      .filter((edge) => minLinkScore === null || (edge.weight ?? 0) >= minLinkScore)
      .sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0))
      .slice(0, MAX_PAIR_EDGES);
  }, [graph, minLinkScore]);

  const { elements, trimmedNodes } = useMemo(() => {
    if (!graph) return { elements: [] as ElementDefinition[], trimmedNodes: 0 };

    const candidateNodes = graph.nodes.filter(
      (node) =>
        !hiddenKinds.has(node.kind) && !hiddenNodes.has(node.id) && !removedNodes.has(node.id)
    );
    const candidates = new Set(candidateNodes.map((node) => node.id));

    const edgeCandidates = (
      showPairs
        ? graph.edges.filter((edge) => edge.kind !== 'CORRELATION' || strongestPairs.includes(edge))
        : graph.edges.filter((edge) => edge.kind !== 'CORRELATION')
    ).filter((edge) => candidates.has(edge.source) && candidates.has(edge.target));

    // Per-node neighbour budget. A hub entity can touch dozens of observations;
    // drawing all of them buries the handful the analyst actually needs, so the
    // budget applies to each node's own incident edges — kept strongest-first,
    // and a node expanded by hand keeps every link. (The old selector kept an
    // edge when *either* endpoint wanted it, which let a hub accumulate every
    // leaf that listed the hub in its top-N and defeated the control entirely.)
    // An expanded node exempts its own ring, and every further click widens it.
    const expandedNodes = expandRadii(edgeCandidates, expandedDepths);
    const visibleEdges = selectBudgetedEdges(edgeCandidates, neighbourBudget, expandedNodes);

    const degree = new Map<string, number>();
    const incidentTotal = new Map<string, number>();
    for (const edge of visibleEdges) {
      degree.set(edge.source, (degree.get(edge.source) ?? 0) + 1);
      degree.set(edge.target, (degree.get(edge.target) ?? 0) + 1);
    }
    for (const edge of edgeCandidates) {
      incidentTotal.set(edge.source, (incidentTotal.get(edge.source) ?? 0) + 1);
      incidentTotal.set(edge.target, (incidentTotal.get(edge.target) ?? 0) + 1);
    }

    // A node with nothing left to connect to would float as an unexplained
    // orphan; drop it and say so in the footer instead.
    const drawnNodes = candidateNodes.filter(
      (node) => (degree.get(node.id) ?? 0) > 0 || visibleEdges.length === 0
    );
    const drawn = new Set(drawnNodes.map((node) => node.id));

    const elementList: ElementDefinition[] = drawnNodes.map((node) => {
      const collapsed = Math.max(0, (incidentTotal.get(node.id) ?? 0) - (degree.get(node.id) ?? 0));
      return {
        classes: collapsed > 0 ? 'collapsed' : undefined,
        data: {
          id: node.id,
          label: [
            node.kind === 'observation' ? shortLabel(node.label, 22) : shortLabel(node.label, 24),
            // Entities carry how many actions touch them — a host used by six
            // observations is not the same lead as a domain seen once.
            node.kind !== 'observation' && (node.alert_count ?? 0) > 1
              ? `·${node.alert_count}`
              : '',
            // `+N` = neighbours the budget is holding back, expandable.`
            collapsed > 0 ? `+${collapsed}` : '',
          ]
            .filter(Boolean)
            .join(' '),
          fullLabel: node.label,
          kind: node.kind,
          collapsed,
          alertCount: node.alert_count ?? 0,
          techniques: node.techniques ?? [],
          observationKey: node.observation_key ?? null,
          // Full key for entity/key nodes — the label on the canvas is truncated.
          token: node.token ?? null,
          // Colour comes from the same KIND_META the legend chip renders, so
          // the toolbar and the canvas can never disagree about what a kind
          // looks like. A kind missing from the table falls back to the
          // generic key look (and gets a minted chip below).
          color:
            node.kind === 'observation'
              ? observationColor(node.label)
              : metaForKind(node.kind).color,
        },
      };
    });

    for (const edge of visibleEdges) {
      if (!drawn.has(edge.source) || !drawn.has(edge.target)) continue;
      const isCorrelation = edge.kind === 'CORRELATION';
      // An action edge is one observation (or several collapsed onto the same
      // entity pair) drawn as a relation: role on the label, ×N when folded.
      const isAction = edge.kind === 'OBSERVATION';
      const collapsedCount = Math.max(0, (edge.count ?? 1) - 1);
      const label = isAction
        ? [shortLabel(edge.role ?? 'action', 24), collapsedCount > 0 ? `×${edge.count}` : '']
            .filter(Boolean)
            .join(' ')
        : isCorrelation
          ? String(edge.weight ?? '')
          : '';
      elementList.push({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          kind: edge.kind,
          score: edge.weight ?? 0,
          // Pair score on CORRELATION edges; the key's L1 weight otherwise.
          weight: edge.weight ?? 1,
          thresholdMet: edge.threshold_met !== false,
          // Cytoscape boolean data selectors are unreliable across versions;
          // a string discriminator keeps the dashed near-miss style honest.
          threshold: edge.threshold_met === false ? 'below' : 'met',
          label,
          // Cytoscape cannot map a role string to a colour, so the colour the
          // role resolves to travels with the element.
          color: isAction ? observationColor(edge.role) : '#334155',
          alertCount: edge.alert_count ?? 0,
          actionCount: edge.count ?? 1,
        },
      });
    }

    return { elements: elementList, trimmedNodes: candidateNodes.length - drawnNodes.length };
  }, [
    graph,
    hiddenKinds,
    hiddenNodes,
    removedNodes,
    expandedDepths,
    neighbourBudget,
    showPairs,
    strongestPairs,
  ]);

  /**
   * What the 2D canvas actually drew, as id sets. The 3D view gets the whole
   * candidate graph (so its bubble names and colours match the 2D pills) plus
   * these sets, so the SHOW filters, the NBRS budget and the pair-link toggle
   * keep working after switching views.
   */
  const drawnIds = useMemo(() => {
    const nodes = new Set<string>();
    const edges = new Set<string>();
    for (const element of elements) {
      const data = element.data as { id?: string; source?: string };
      if (!data.id) continue;
      if (data.source === undefined) nodes.add(data.id);
      else edges.add(data.id);
    }
    return { nodes, edges };
  }, [elements]);

  /**
   * The order the graph draws itself in: alert time, earliest first.
   *
   * Observation nodes carry the time of the first alert that reports them; an
   * entity inherits the earliest observation that names it, and a key or pair
   * edge appears once both ends exist. Nodes with no timestamp sort last, so an
   * undated payload still reveals coherently.
   */
  const revealOrder = useMemo(() => {
    const graphNodes = graph?.nodes ?? [];
    const graphEdges = graph?.edges ?? [];
    const observationTime = new Map<string, number>();
    for (const event of timeline ?? []) {
      if (!event.observation_key || !event.time) continue;
      const at = Date.parse(event.time);
      if (!Number.isFinite(at)) continue;
      const current = observationTime.get(event.observation_key);
      observationTime.set(
        event.observation_key,
        current === undefined ? at : Math.min(current, at)
      );
    }

    const nodeTime = new Map<string, number>();
    for (const node of graphNodes) {
      if (node.kind !== 'observation' || !node.observation_key) continue;
      const at = observationTime.get(node.observation_key);
      if (at !== undefined) nodeTime.set(node.id, at);
    }
    // An entity is as old as the earliest action that names it.
    for (const edge of graphEdges) {
      const source = nodeTime.get(edge.source);
      const target = nodeTime.get(edge.target);
      if (source !== undefined && target === undefined) nodeTime.set(edge.target, source);
      if (target !== undefined && source === undefined) nodeTime.set(edge.source, target);
      if (source !== undefined && target !== undefined) {
        nodeTime.set(edge.source, Math.min(source, target));
        nodeTime.set(edge.target, Math.min(source, target));
      }
    }

    const at = (id: string) => nodeTime.get(id) ?? Number.POSITIVE_INFINITY;
    const nodeIds = graphNodes.map((node) => node.id);
    // A link cannot be drawn before either end: it takes the later of the two.
    const edgeIds = graphEdges.map((edge) => edge.id);
    const edgeTime = new Map<string, number>();
    for (const edge of graphEdges) {
      edgeTime.set(edge.id, Math.max(at(edge.source), at(edge.target)));
    }
    // A link appears in the same beat as its second endpoint, never before it:
    // on equal times nodes sort ahead of edges, so `max(from, to)` is enough.
    const isEdge = new Set(edgeIds);
    return [...nodeIds, ...edgeIds].sort((a, b) => {
      const left = nodeTime.get(a) ?? edgeTime.get(a) ?? Number.POSITIVE_INFINITY;
      const right = nodeTime.get(b) ?? edgeTime.get(b) ?? Number.POSITIVE_INFINITY;
      return left - right || Number(isEdge.has(a)) - Number(isEdge.has(b)) || a.localeCompare(b);
    });
  }, [graph, timeline]);

  // Surfacing a render failure is a side effect of building the canvas, and
  // the state write is deferred so the effect body stays free of synchronous
  // setState (React's cascading-render lint).
  const reportRenderError = (message: string | null) => {
    queueMicrotask(() => setRenderError(message));
  };

  useEffect(() => {
    if (!containerRef.current) return;
    // The canvas itself is transparent; the theme's surface shows through it, and
    // it has to be the exact colour the label halos are painted in.
    containerRef.current.style.backgroundColor = palette.surface;
    if (elements.length === 0) {
      reportRenderError(null);
      return;
    }

    const previous = positionsRef.current;
    const pinned = elements.flatMap((element) => {
      const id = element.data?.id === undefined ? null : String(element.data.id);
      const position = id ? previous.get(id) : undefined;
      return id && position ? [{ nodeId: id, position }] : [];
    });
    const keepArrangement = pinned.length > 0;

    let cy: Core;
    try {
      cy = cytoscape({
        container: containerRef.current,
        elements,
        wheelSensitivity: 0.2,
        style: [
          {
            selector: 'node',
            style: {
              // Declared here so both directions of the `.reveal-hidden` flip
              // animate: cytoscape only transitions a property that the visible
              // state declares too.
              'transition-property': 'opacity',
              'transition-duration': '230ms',
              'transition-timing-function': 'ease-in-out',
              'background-color': 'data(color)',
              'background-opacity': 0.9,
              label: 'data(label)',
              'font-size': 10,
              color: palette.ink,
              'text-valign': 'bottom',
              'text-margin-y': 6,
              'text-outline-width': 2,
              'text-outline-color': palette.surface,
              'text-wrap': 'wrap',
              'text-max-width': '112px',
              // Below this zoom the labels collapse into mush; hiding them keeps
              // the silhouette legible until the analyst zooms in on a cluster.
              'min-zoomed-font-size': 7,
              width: 30,
              height: 30,
              'border-width': 2,
              'border-color': palette.surface,
            } as never,
          },
          // One silhouette per kind, taken from KIND_META so the legend chip and
          // the canvas can never drift apart.
          ...KIND_META.map((meta) => ({
            selector: `node[kind = "${meta.kind}"]`,
            style: {
              shape: meta.shape,
              width: meta.width,
              height: meta.height,
              ...(meta.points ? { 'shape-polygon-points': meta.points } : {}),
              ...(meta.kind === 'observation' ? { 'font-weight': 'bold' } : {}),
            },
          })) as never,
          {
            // `+N` means the neighbour budget is hiding some of this node's
            // links; a dashed ring says "expandable" without a second legend.
            selector: 'node.collapsed',
            style: {
              'border-style': 'dashed',
              'border-width': 2,
              'border-color': palette.inkMuted,
            } as never,
          },
          {
            selector: 'edge',
            style: {
              'transition-property': 'opacity',
              'transition-duration': '230ms',
              'transition-timing-function': 'ease-in-out',
              width: 1,
              // Anything a projection adds without a rule of its own still has to
              // be readable on the canvas; #334155 was not.
              'line-color': palette.edge,
              'curve-style': 'bezier',
              'target-arrow-shape': 'none',
              opacity: 0.7,
            } as never,
          },
          {
            selector: 'edge[kind = "CORRELATION"]',
            style: {
              'line-color': palette.scoreLine,
              width: 'mapData(score, 1, 12, 1.5, 6)',
              opacity: 0.85,
              label: 'data(label)',
              'font-size': 8,
              color: palette.scoreInk,
              'text-outline-width': 2,
              'text-outline-color': palette.surface,
            } as never,
          },
          // Key edges: width is the weight that key added to L1 (3/2/1), so a
          // strong shared value is visibly different from a weak one.
          {
            selector: 'edge[kind = "MATCHES_HASH"]',
            style: {
              'line-color': '#22c55e',
              width: 'mapData(weight, 1, 3, 1, 3)',
              opacity: 0.7,
            } as never,
          },
          {
            selector: 'edge[kind = "INVOKES_PROCESS"]',
            style: {
              'line-color': '#14b8a6',
              width: 'mapData(weight, 1, 3, 1, 3)',
              opacity: 0.7,
            } as never,
          },
          {
            selector: 'edge[kind = "CONTRIBUTES_KEY"]',
            style: {
              'line-color': palette.inkMuted,
              width: 'mapData(weight, 1, 3, 1, 3)',
              opacity: 0.6,
            } as never,
          },
          // The node projection links an observation to what it touched. These
          // four kinds had no rule at all, so they fell back to the flat grey
          // default and read as faint hairlines against the dark canvas. Each
          // one now carries the colour of the entity kind it ends on.
          {
            selector: 'edge[kind = "OBSERVED_ON"]',
            style: {
              'line-color': '#8b5cf6',
              width: 1.4,
              opacity: 0.6,
            } as never,
          },
          {
            selector: 'edge[kind = "INVOLVES_USER"]',
            style: {
              'line-color': '#ec4899',
              width: 1.4,
              opacity: 0.6,
            } as never,
          },
          {
            selector: 'edge[kind = "USES_IP"]',
            style: {
              'line-color': '#3b82f6',
              width: 1.4,
              opacity: 0.6,
            } as never,
          },
          {
            selector: 'edge[kind = "QUERIED_DOMAIN"]',
            style: {
              'line-color': '#f59e0b',
              width: 1.4,
              opacity: 0.6,
            } as never,
          },
          // Action edges: the observation drawn as the relation it is. Colour is
          // the role family, width the alerts behind it, label the role (+ ×N
          // when several actions collapsed onto the same entity pair).
          {
            selector: 'edge[kind = "OBSERVATION"]',
            style: {
              'line-color': 'data(color)',
              width: 'mapData(alertCount, 1, 40, 1.5, 5)',
              opacity: 0.9,
              label: 'data(label)',
              'font-size': 8,
              color: palette.actionInk,
              'text-outline-width': 2,
              'text-outline-color': palette.surface,
            } as never,
          },
          {
            selector: 'edge[threshold = "below"]',
            style: {
              'line-style': 'dashed',
              'line-color': '#64748b',
              opacity: 0.5,
            } as never,
          },
          {
            // A hovered link brightens in its own family colour instead of
            // dimming the rest of the canvas: the analyst pointing at one edge
            // is following that link, not asking for everything else to be
            // unsaid. The tint is mixed toward white at hover time and carried
            // on the element, so `data(color)` edges keep their hue.
            selector: 'edge.hovered',
            style: {
              'line-color': 'data(hoverColor)',
              'target-arrow-color': 'data(hoverColor)',
              width: 3,
              opacity: 1,
              'z-index': 90,
            } as never,
          },
          {
            selector: 'edge.selected',
            style: {
              'line-color': palette.edgeStrong,
              'target-arrow-color': palette.edgeStrong,
              width: 3.5,
              opacity: 1,
              'z-index': 99,
            } as never,
          },
          {
            selector: '.faded',
            style: { opacity: 0.14 } as never,
          },
          {
            selector: 'node.focused',
            style: { 'border-width': 4, 'border-color': palette.edgeStrong } as never,
          },
          {
            // Selection made in the entity list, visible on the canvas: an
            // underlay halo reads behind the node without repainting its kind
            // colour, so the analyst can still tell a host from a user.
            selector: 'node.entity-selected',
            style: {
              'underlay-color': palette.selection,
              'underlay-opacity': 0.32,
              'underlay-padding': 7,
              'border-width': 3,
              'border-color': palette.selectionBorder,
            } as never,
          },
          {
            // The analyst asked to hide every name on the canvas.
            selector: 'node.labels-off, edge.labels-off',
            style: { 'text-opacity': 0 } as never,
          },
          {
            // The row the analyst clicked. Same teal language as the 3D halo
            // (`activeId`), so "the leaf I just picked" reads the same in both
            // views.
            selector: 'node.entity-active',
            style: {
              'underlay-color': palette.selection,
              'underlay-opacity': 0.45,
              'underlay-padding': 10,
              'border-width': 4,
              'border-color': palette.selectionBorder,
            } as never,
          },
          {
            // Focusing a bubble marks every node it holds: the same teal
            // language, one step softer than a single picked row, because a
            // cluster is a set and hundreds of full-strength halos glare.
            selector: 'node.cluster-active',
            style: {
              'underlay-color': palette.selection,
              'underlay-opacity': 0.28,
              'underlay-padding': 7,
              'border-width': 3,
              'border-color': palette.selectionBorder,
            } as never,
          },
          // The reveal animation hides elements with a class rather than taking
          // them out of the canvas: they keep their place in the layout and in
          // the bounding box, so nothing re-fits or jumps while it plays.
          // Last in the list on purpose — the edge rule above sets `opacity`,
          // and cytoscape resolves ties by source order, so an earlier rule lost
          // and links stayed visible through the whole reveal.
          {
            // The class flip is instant; the transition is what turns it into a
            // fade. Declared on the hidden rule *and* on nodes/edges below, since
            // cytoscape only animates a property that both states declare.
            selector: '.reveal-hidden',
            style: {
              opacity: 0,
              events: 'no',
              'transition-property': 'opacity',
              'transition-duration': '230ms',
              'transition-timing-function': 'ease-in-out',
            } as never,
          },
        ] as never,
        // Leaves were packed shoulder to shoulder: `nodeSeparation: 90` and a
        // 110px edge length put every host/user/domain ring right on top of its
        // neighbours, which is unreadable once a candidate has dozens of them.
        // Roomy is the default; compact stays available for small components on
        // a narrow screen.
        layout: (liveLayout && !keepArrangement
          ? {
              // Continuous force simulation: the graph keeps relaxing after the
              // first settle, so a drag pushes its neighbours like a magnet
              // instead of replaying a batch layout.
              name: 'cola',
              animate: true,
              animationDuration: 300,
              fit: true,
              padding: 40,
              continuous: true,
              avoidOverlap: true,
              handleDisconnected: true,
              nodeSpacing: (node: { degree(): number }) =>
                10 + Math.min(24, node.degree() * 2),
              idealEdgeLength: (edge: {
                source(): { degree(): number };
                target(): { degree(): number };
              }) =>
                edgeLengthFor(
                  Math.max(edge.source().degree(), edge.target().degree()),
                  spacing
                ),
              // A stronger link behaves as a stiffer spring.
              edgeElasticity: (edge: { data(name: string): unknown }) => {
                const weight = Math.max(0, Number(edge.data('weight') ?? 1));
                return Math.min(1, 0.25 + weight * 0.04);
              },
              numIter: 1000,
            }
          : {
              name: 'fcose',
              animate: false,
              randomize: !keepArrangement,
              fit: !keepArrangement,
              ...spacingParams(spacing),
              packComponents: !keepArrangement,
              uniformNodeDimensions: false,
              // Nodes already on screen are fixed where they were; only the ones
              // that just appeared are laid out.
              ...(keepArrangement
                ? { fixedNodeConstraint: pinned, numIter: 600, idealEdgeLength: 90 }
                : {}),
            }) as never,
      });
    } catch (error) {
      console.error('Failed to initialise candidate graph', error);
      reportRenderError('The graph could not be rendered in this browser.');
      return;
    }

    cyRef.current = cy;
    // A new instance starts at zoom 1 / pan 0, which for a graph this wide
    // reads as a hard zoom-in with most of the graph off screen. Frame
    // immediately when the container is already measurable; otherwise let the
    // ResizeObserver do it when the real size arrives.
    if ((containerRef.current?.clientWidth ?? 0) > 0) {
      cy.fit(cy.elements(), 56);
      pendingInitialFitRef.current = false;
    } else {
      pendingInitialFitRef.current = true;
    }


    /**
     * Nudge the settled layout toward the analyst's mental model: linked leaves
     * sit at a rest length that shrinks with link strength, unlinked leaves push
     * apart only when they are too close. Positions only — the graph, its
     * selection and its filters are untouched.
     */
    const magneticPass = () => {
      if (!magnetic) return;
      const current = cy.nodes().map((node) => ({ id: node.id(), ...node.position() }));
      const links: MagneticEdge[] = [];
      cy.edges().forEach((edge) => {
        if (edge.data('kind') === 'CORRELATION') return;
        links.push({
          source: edge.data('source'),
          target: edge.data('target'),
          weight: Number(edge.data('weight') ?? 1),
        });
      });
      const relaxed = applyMagnetism(current, links, {
        targetLength: spacing === 'roomy' ? 150 : 105,
        padding: spacing === 'roomy' ? 20 : 14,
      });
      cy.batch(() => {
        cy.nodes().forEach((node) => {
          const next = relaxed.get(node.id());
          if (next) node.position(next);
        });
      });
    };
    magneticPassRef.current = magneticPass;

    // The layout above runs asynchronously; spread the communities as soon as
    // it settles, then fit the (now larger) picture instead of the overlapping
    // one the fit inside the layout config measured. A rebuild that kept the
    // arrangement (hide / remove from the entity list) must not re-pack it.
    cy.one('layoutstop', () => {
      // Live physics owns the positions: the community spread and the magnetic
      // pass would both fight the running simulation.
      if (!keepArrangement && !liveLayout) {
        spreadClusters(cy, clusterPartition, spacing === 'roomy');
      }
      if (!liveLayout) magneticPassRef.current?.();
      if (!keepArrangement) {
        cy.fit(cy.elements(), 56);
      }
      if (fitAfterLayoutRef.current) {
        fitAfterLayoutRef.current = false;
        cy.fit(cy.elements(), 56);
      }
    });

    // Dragging one node used to move only that node: every edge stretched and
    // the crowded leaves the analyst was trying to separate stayed put. A drag
    // now carries its neighbourhood (1-hop fully, 2-hop at a third of the
    // distance) and, on release, a constrained fcose pass re-tidies the whole
    // canvas around the node the analyst dropped.
    let dragOrigin: {
      nodeId: string;
      positions: Map<string, { x: number; y: number }>;
    } | null = null;

    const settleAround = (anchorId: string) => {
      const anchor = cy.getElementById(anchorId);
      if (anchor.empty()) return;
      const position = { ...anchor.position() };
      cy.layout({
        name: 'fcose',
        animate: true,
        animationDuration: 320,
        animationEasing: 'ease-out',
        fit: false,
        // Start from what is on screen, not from a random seed — the analyst's
        // arrangement is the input, the settle only removes overlaps around it.
        randomize: false,
        ...spacingParams(spacing),
        numIter: 1500,
        packComponents: false,
        // The dropped node stays exactly where it was placed. Everything else
        // relaxes around it, which is the reaction the drag was asking for.
        fixedNodeConstraint: [{ nodeId: anchorId, position }],
      } as never).run();
    };

    cy.on('grab', 'node', (event) => {
      const positions = new Map<string, { x: number; y: number }>();
      cy.nodes().forEach((member) => {
        positions.set(member.id(), { ...member.position() });
      });
      dragOrigin = { nodeId: event.target.id(), positions };
    });

    cy.on('drag', 'node', (event) => {
      const origin = dragOrigin;
      if (!origin) return;
      const node = event.target as NodeSingular;
      const start = origin.positions.get(node.id());
      if (!start) return;
      const position = node.position();
      const dx = position.x - start.x;
      const dy = position.y - start.y;
      if (dx === 0 && dy === 0) return;

      const pull = (ids: string[], factor: number) => {
        for (const id of ids) {
          const base = origin.positions.get(id);
          if (!base) continue;
          cy.getElementById(id).position({ x: base.x + dx * factor, y: base.y + dy * factor });
        }
      };

      const firstHop = node.neighborhood('node').map((member) => member.id());
      const secondHop = node
        .neighborhood('node')
        .neighborhood('node')
        .filter((member) => member.id() !== node.id() && !firstHop.includes(member.id()))
        .map((member) => member.id());

      pull(firstHop, 0.6);
      pull(secondHop, 0.28);
    });

    cy.on('dragfree', 'node', () => {
      const released = dragOrigin?.nodeId;
      dragOrigin = null;
      if (!autoTidyRef.current || !released) return;
      settleAround(released);
    });

    cy.on('tap', 'node', (event) => {
      const data = event.target.data();
      setActiveEntityId(data.id);
      onSelectEdgeRef.current?.(null);
      onSelectNodeRef.current?.(
        {
          id: data.id,
          kind: data.kind,
          // The rail shows the untruncated name, never the canvas label.
          label: data.fullLabel ?? data.label,
          alert_count: data.alertCount,
          techniques: data.techniques,
          observation_key: data.observationKey,
          token: data.token ?? null,
        },
        'canvas'
      );
    });

    // Tapping a pair link opens the pair inspector: score breakdown plus, for
    // L3, the third observation and the two keys that produced the point.
    cy.on('tap', 'edge', (event) => {
      setActiveEntityId(null);
      onSelectNodeRef.current?.(null);
      onSelectEdgeRef.current?.(event.target.id());
    });

    cy.on('tap', (event) => {
      if (event.target === cy) {
        setActiveEntityId(null);
        onSelectNodeRef.current?.(null);
        onSelectEdgeRef.current?.(null);
      }
    });

    // Hovering an element dims everything not directly connected to it, which
    // is how an analyst traces one action's blast radius at a glance.
    const dimOthers = (element: SingularElementReturnValue) => {
      cy.elements().addClass('faded');
      element.removeClass('faded');
      element.connectedEdges().removeClass('faded');
      element.connectedEdges().connectedNodes().removeClass('faded');
    };

    /**
     * Offset tooltip position, clamped inside the canvas so a node near the right
     * edge does not push the card out of the panel.
     */
    const pointerInCanvas = (event: EventObject) => {
      const container = cy.container();
      const rect = container?.getBoundingClientRect();
      const original = event.originalEvent as MouseEvent | undefined;
      if (!rect || !original) return null;
      const width = container?.clientWidth ?? 320;
      return {
        x: Math.max(6, Math.min(original.clientX - rect.left + 14, width - 210)),
        y: Math.max(6, original.clientY - rect.top - 12),
      };
    };

    // Hovering a node names it without a click: the canvas label is truncated
    // (`win-dc-85…`) and the full token only lived in the inspector.
    cy.on('mouseover', 'node', (event) => {
      const element = event.target;
      dimOthers(element);
      const data = element.data();
      const point = pointerInCanvas(event);
      if (!point) return;
      setHovered({
        x: point.x,
        y: point.y,
        kind: String(data.kind ?? ''),
        label: String(data.fullLabel ?? data.label ?? ''),
        token: data.token ?? null,
        alerts: Number(data.alertCount ?? 0),
        collapsed: Number(data.collapsed ?? 0),
      });
    });
    cy.on('mousemove', 'node', (event) => {
      const point = pointerInCanvas(event);
      if (!point) return;
      setHovered((current) => (current ? { ...current, x: point.x, y: point.y } : current));
    });
    cy.on('mouseout', 'node', () => {
      cy.elements().removeClass('faded');
      setHovered(null);
    });

    cy.on('mouseover', 'edge', (event) => {
      const element = event.target;
      element.data('hoverColor', hoverTint(element.style('line-color'), theme));
      element.addClass('hovered');
    });
    cy.on('mouseout', 'edge', (event) => {
      event.target.removeClass('hovered');
    });

    return () => {
      // Merge, do not replace: members hidden by a collapsed bubble are not in
      // this instance, and their last position is what re-expands them in place.
      const snapshot = new Map(positionsRef.current);
      cy.nodes().forEach((node) => {
        snapshot.set(node.id(), { ...node.position() });
      });
      positionsRef.current = snapshot;
      magneticPassRef.current = null;
      setHovered(null);
      cy.destroy();
      cyRef.current = null;
    };
  }, [
    elements,
    spacing,
    show3d,
    clusterPartition,
    clusterMembers,
    collapsedClusters,
    graph,
    magnetic,
    liveLayout,
    palette,
    theme,
  ]);

  // Mark the edge the parent is inspecting. The panel below the canvas and the
  // highlighted link must be the same object, or the analyst has to guess which
  // of a dozen teal lines the numbers describe.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.edges().removeClass('selected');
    if (selectedEdgeId) cy.getElementById(selectedEdgeId).addClass('selected');
  }, [selectedEdgeId, elements]);

  // Mirror the entity panel's checkbox selection onto the canvas. Kept separate
  // from `.focused` (single node, camera target) so a multi-select halo can sit
  // next to the focused node instead of overwriting it.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().removeClass('entity-selected');
    for (const id of selectedEntityIds) {
      const element = cy.getElementById(id);
      if (!element.empty()) element.addClass('entity-selected');
    }
  }, [selectedEntityIds, elements]);

  // A new payload is a new picture: frame it once the canvas has a real size.
  //
  // The comparison is on the *drawn set*, not on the array's identity. A
  // revalidated payload rebuilds `elements` with the same nodes; re-arming the
  // pending fit there made the next size change — the Evidence rail closing after
  // its timeout, or the analyst hiding it — run `cy.fit()` and leap to a much
  // larger zoom without anyone touching the camera.
  const drawnSignatureRef = useRef<string>('');
  useEffect(() => {
    const signature = elements
      .map((element) => String((element.data as { id?: string }).id ?? ''))
      .join('|');
    if (signature === drawnSignatureRef.current) return;
    drawnSignatureRef.current = signature;
    pendingInitialFitRef.current = true;
  }, [elements]);

  // Switching into the orbit view should open framed, not at whatever camera
  // the previous scene left behind. The scene is built on this render, so wait
  // for its handle (a few frames at most) instead of guessing a delay.
  useEffect(() => {
    if (!show3d) return;
    let tries = 0;
    let timer = 0;
    const tryFit = () => {
      if (graph3dRef.current) {
        graph3dRef.current.fit();
        return;
      }
      if (tries < 40) {
        tries += 1;
        timer = window.setTimeout(tryFit, 50);
      }
    };
    tryFit();
    return () => window.clearTimeout(timer);
  }, [show3d]);

  // One class on every element hides the canvas names; the zoom rules that
  // normally bring them in stay untouched underneath.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    if (labels2d) cy.elements().removeClass('labels-off');
    else cy.elements().addClass('labels-off');
  }, [labels2d, elements]);

  // The bubble the analyst focused: every member gets the same teal border and
  // underlay the active row uses, so a cluster focus is visible on the canvas.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().removeClass('cluster-active');
    if (activeClusterIds.size === 0) return;
    cy.nodes()
      .filter((node) => activeClusterIds.has(node.id()))
      .addClass('cluster-active');
  }, [activeClusterIds, elements]);

  // The clicked row keeps a stronger border than the multi-select halo.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().removeClass('entity-active');
    if (!activeEntityId) return;
    const element = cy.getElementById(activeEntityId);
    if (!element.empty()) element.addClass('entity-active');
  }, [activeEntityId, elements]);

  /**
   * Bring a node into view without hijacking the camera.
   *
   * Selecting a row used to jump to `Math.max(zoom, 1.05)`, which on a wide
   * campaign is a ~3× zoom onto a single leaf: the row answered “this node
   * exists” while destroying the analyst's answer to “where is it?”. The graph is
   * a map, so the camera only moves when it has to:
   *
   *   • node already inside the padded viewport → no move at all (the halo and
   *     the row highlight carry the selection);
   *   • node outside → pan by exactly the distance needed to bring it in;
   *   • node too small to identify at the current zoom → zoom in just far enough
   *     to make it legible, never past 1:1.
   */
  const revealNode = (id: string) => {
    const cy = cyRef.current;
    if (!cy) return;
    const node = cy.getElementById(id);
    if (node.empty()) return;

    const pad = 56;
    const width = cy.width();
    const height = cy.height();
    const zoom = cy.zoom();
    const box = node.renderedBoundingBox({ includeLabels: true });
    const smallest = Math.min(box.w, box.h);
    // A leaf is a handful of pixels at 0.35×; below ~26px neither the halo nor
    // the label reads, so “focus” would point at nothing. Grow only as far as
    // legibility needs, and never zoom *out* (that would hide the neighbourhood).
    const legible = smallest > 0 ? zoom * (26 / smallest) : zoom;
    const targetZoom = Math.min(Math.max(zoom, legible), 1);

    if (targetZoom > zoom + 0.001) {
      const centre = node.position();
      cy.animate(
        {
          zoom: targetZoom,
          pan: { x: width / 2 - centre.x * targetZoom, y: height / 2 - centre.y * targetZoom },
        },
        { duration: 240, easing: 'ease-out' }
      );
      return;
    }

    // The smallest pan that puts the node (with its label) inside the frame.
    const dx = box.x1 < pad ? pad - box.x1 : box.x2 > width - pad ? width - pad - box.x2 : 0;
    const dy = box.y1 < pad ? pad - box.y1 : box.y2 > height - pad ? height - pad - box.y2 : 0;
    if (dx === 0 && dy === 0) return;
    const pan = cy.pan();
    cy.animate({ pan: { x: pan.x + dx, y: pan.y + dy } }, { duration: 220, easing: 'ease-out' });
  };

  // Reveal the entity the analyst clicked in the list. Runs after the canvas
  // effect above, so a node that had to be unhidden is already drawn.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !activeEntityId) return;
    const element = cy.getElementById(activeEntityId);
    if (element.empty()) return;
    cy.elements().removeClass('focused');
    element.addClass('focused');
    revealNode(activeEntityId);
  }, [activeEntityId, elements]);

  // Focus a node requested by the summary rail.
  useEffect(() => {
    const cy = cyRef.current;
    if (show3d) {
      if (focusId) graph3dRef.current?.focusNode(focusId);
      return;
    }
    if (!cy || !focusId) return;
    const node = cy.getElementById(focusId);
    if (node.empty()) return;
    cy.elements().removeClass('focused');
    node.addClass('focused');
    revealNode(focusId);
  }, [focusId, show3d]);

  /**
   * Put the camera on an entity chosen from the list, revealing it first if a
   * filter, Focus or a Remove had taken it off the canvas.
   */
  const activateEntity = (id: string) => {
    setHiddenNodes((current) => removeFrom(current, [id]));
    setRemovedNodes((current) => removeFrom(current, [id]));
    setActiveEntityId(id);
    // One highlight at a time: a single row and a whole bubble at once was two
    // answers to "what did I just pick?".
    setActiveClusterKey(null);
    // Row activation must also move the orbit camera while 3D is on screen;
    // otherwise it centres a canvas nobody can see.
    if (show3d) graph3dRef.current?.focusNode(id);
    const node = graph?.nodes.find((candidate) => candidate.id === id) ?? null;
    if (node) onSelectNode?.(node, 'list');
  };

  const fit = () => {
    if (show3d && graph3dRef.current) {
      graph3dRef.current.fit();
      return;
    }
    cyRef.current?.animate({ fit: { eles: cyRef.current.elements(), padding: 48 } }, { duration: 250 });
  };

  /**
   * Zoom about the middle of the viewport rather than the graph's top-left.
   *
   * `zoom: level` alone keeps the pan fixed, which throws the node the analyst
   * is looking at off screen. Computing the model point under the viewport
   * centre and re-deriving the pan keeps it pinned where it was.
   */
  const zoomBy = (factor: number) => {
    if (show3d && graph3dRef.current) {
      graph3dRef.current.zoomBy(factor);
      return;
    }
    const cy = cyRef.current;
    const container = cy?.container();
    if (!cy || !container) return;
    const anchor = { x: container.clientWidth / 2, y: container.clientHeight / 2 };
    const pan = cy.pan();
    const zoom = cy.zoom();
    const modelPoint = {
      x: (anchor.x - pan.x) / zoom,
      y: (anchor.y - pan.y) / zoom,
    };
    const level = Math.min(4, Math.max(0.1, zoom * factor));
    cy.animate(
      {
        zoom: level,
        pan: { x: anchor.x - modelPoint.x * level, y: anchor.y - modelPoint.y * level },
      },
      { duration: 180, easing: 'ease-out' }
    );
  };

  /**
   * Throw away the analyst's manual arrangement and recompute the engine's
   * layout from scratch (random seed, fit to viewport). Dragging is useful for
   * untangling a cluster, but there was no way back to the layout that reflects
   * the data rather than the last drag.
   */
  /**
   * Frame whatever the next render draws.
   *
   * Focus and Expand change the visible element set, so the canvas is rebuilt
   * and laid out asynchronously: a fit called straight away measures the old
   * picture. The layoutstop hook does the fit when it settles; the timeout is
   * the fallback for arrangements that keep their positions (no fresh layout).
   */
  const refitSoon = (frame3d = true) => {
    fitAfterLayoutRef.current = true;
    if (show3d) {
      // The 3D scene rebuilds after this render; frame it once it exists.
      if (frame3d) window.setTimeout(() => graph3dRef.current?.fit(), 80);
      return;
    }
    window.setTimeout(() => {
      const cy = cyRef.current;
      if (cy) cy.fit(cy.elements(), 56);
    }, 140);
  };

  /**
   * One click back to the whole campaign.
   *
   * Undoing a drill-down used to mean knowing which of four mechanisms had put
   * a node off screen — Focus (Unfocus), Expand (four clicks), Hide/Remove (the
   * entity panel's `show all`) and a collapsed bubble (its own toggle). This is
   * the single "start over" that resets all of them and reframes the graph.
   */
  const clearView = () => {
    focusRestoreRef.current = null;
    expandedDepthsRef.current = new Map();
    setExpandedDepths(new Map());
    setHiddenNodes(new Set());
    setRemovedNodes(new Set());
    setCollapsedClusters(new Map());
    setActiveClusterKey(null);
    setActiveEntityId(null);
    // Nothing is selected any more, so the inspector has nothing to describe.
    onSelectNode?.(null, 'list');
    onClearFocus?.();
    fitAfterLayoutRef.current = true;
    if (show3d) {
      // The scene rebuilds after this render; frame it once it exists.
      window.setTimeout(() => graph3dRef.current?.fit(), 80);
    }
  };

  // ── reveal playback ────────────────────────────────────────────────────────
  // Elements are always in the canvas; the animation only flips a class, so the
  // layout, the bounding box and the camera never move while it plays. That is
  // what keeps it from looking like a series of fits.
  const applyReveal = (fraction: number) => {
    const cy = cyRef.current;
    const list = revealListRef.current;
    if (!cy || list.length === 0) return;
    // The schedule is not linear: the first gap is a beat of its own so the
    // opening node can be read, and the gaps shrink from there.
    const schedule = revealScheduleRef.current;
    let target = 0;
    while (target < schedule.length && schedule[target] <= fraction) target += 1;
    target = Math.min(list.length, target);
    const current = revealIndexRef.current;
    if (target === current) return;
    cy.batch(() => {
      if (target > current) {
        for (let index = current; index < target; index += 1) {
          cy.getElementById(list[index]).removeClass('reveal-hidden');
        }
      } else {
        for (let index = target; index < current; index += 1) {
          cy.getElementById(list[index]).addClass('reveal-hidden');
        }
      }
    });
    revealIndexRef.current = target;
  };

  const hideRevealed = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().addClass('reveal-hidden');
    revealIndexRef.current = 0;
  };

  const tickReveal = () => {
    // Runs from requestAnimationFrame, never during render; the wall clock is
    // the point of it.
    // eslint-disable-next-line react-hooks/purity
    const now = performance.now();
    const elapsed = revealElapsedRef.current + (now - revealStartedAtRef.current);
    const duration = revealDurationRef.current;
    const fraction = duration <= 0 ? 1 : Math.min(1, elapsed / duration);
    revealFractionRef.current = fraction;
    applyReveal(fraction);
    if (fraction >= 1) {
      revealElapsedRef.current = duration;
      revealRafRef.current = null;
      setRevealPlayback('done');
      return;
    }
    revealRafRef.current = requestAnimationFrame(tickReveal);
  };

  const playReveal = (restart = false) => {
    if (!cyRef.current || revealListRef.current.length === 0) return;
    // Playing a finished (or never-started) reveal starts it from the top; only
    // a paused one resumes where it stopped.
    if (restart || revealFractionRef.current >= 1) {
      revealElapsedRef.current = 0;
      revealFractionRef.current = 0;
      hideRevealed();
    }
    if (revealRafRef.current !== null) cancelAnimationFrame(revealRafRef.current);
    revealStartedAtRef.current = performance.now();
    setRevealPlayback('playing');
    revealRafRef.current = requestAnimationFrame(tickReveal);
  };

  const pauseReveal = () => {
    if (revealRafRef.current !== null) {
      cancelAnimationFrame(revealRafRef.current);
      revealRafRef.current = null;
    }
    revealElapsedRef.current += performance.now() - revealStartedAtRef.current;
    setRevealPlayback('paused');
  };

  const toggleReveal = () => {
    if (revealPlayback === 'playing') pauseReveal();
    else playReveal();
  };

  // Keep the playback list and its duration in step with the graph. Ten seconds
  // is the ceiling and five the floor: a small campaign should not crawl, and a
  // large one must still finish in the promised window.
  useEffect(() => {
    revealListRef.current = revealOrder;
    // A little more room than before: the ease-out tail spends real time on the
    // last elements, and 171 elements in 5s left the middle too fast to read.
    const budget = Math.min(12_000, Math.max(6_000, revealOrder.length * 18));
    const { fractions, totalMs } = buildRevealSchedule(revealOrder.length, budget);
    revealDurationRef.current = totalMs;
    revealScheduleRef.current = fractions;
  }, [revealOrder]);

  // First load only: the modal opens on a still frame, then the campaign builds
  // itself. Delayed past the first layout so it does not race the engine.
  useEffect(() => {
    if (revealBootedRef.current || show3d) return;
    if (elements.length === 0 || revealListRef.current.length === 0) return;
    revealBootedRef.current = true;
    const timer = window.setTimeout(() => playReveal(true), 500);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one-shot boot
  }, [elements.length, show3d]);

  // A rebuild during playback (a filter, a collapse) re-creates the canvas and
  // drops the classes with it: put the animation back where it was.
  useEffect(() => {
    if (!revealBootedRef.current) return;
    const fraction = revealFractionRef.current;
    if (fraction >= 1) return;
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().addClass('reveal-hidden');
    revealIndexRef.current = 0;
    applyReveal(fraction);
  }, [elements]);

  useEffect(
    () => () => {
      if (revealRafRef.current !== null) cancelAnimationFrame(revealRafRef.current);
    },
    []
  );

  /**
   * The nodes Focus hides for a node.
   *
   * A snapshot stores the focus id and only the *extra* hidden ids, and derives
   * the rest when it is restored: a focus on a 900-node graph implies hundreds
   * of ids, which would blow the saved-views payload cap for no benefit.
   */
  const hiddenFromFocus = (focus: string): Set<string> => {
    const keep = new Set<string>([focus]);
    for (const edge of graph?.edges ?? []) {
      if (edge.source === focus) keep.add(edge.target);
      else if (edge.target === focus) keep.add(edge.source);
    }
    return new Set(
      (graph?.nodes ?? []).map((node) => node.id).filter((id) => !keep.has(id))
    );
  };

  /** The canvas as it stands, for Undo and for saved views. */
  const snapshotView = (): GraphViewState => {
    const cy = cyRef.current;
    const focus = focusId ?? null;
    const implied = focus ? hiddenFromFocus(focus) : null;
    return {
      hidden: [...hiddenNodes].filter((id) => !implied || !implied.has(id)),
      removed: [...removedNodes],
      collapsed: [...collapsedClusters.entries()].map(
        ([key, members]) => [key, [...members]] as [string, string[]]
      ),
      expanded: [...expandedDepths.entries()],
      activeEntity: activeEntityId,
      activeCluster: activeClusterKey,
      focus,
      zoom: show3d || !cy ? null : cy.zoom(),
      pan: show3d || !cy ? null : { ...cy.pan() },
    };
  };

  /**
   * Record one step. The camera is part of the snapshot but not part of the
   * "did anything change" test, so panning around does not fill the history
   * with steps that differ only by where the view happened to be.
   */
  const pushHistory = (state: GraphViewState) => {
    const shape = JSON.stringify({ ...state, zoom: null, pan: null });
    const current = historyRef.current[historyIndexRef.current];
    if (current && JSON.stringify({ ...current, zoom: null, pan: null }) === shape) return;
    const next = historyRef.current.slice(0, historyIndexRef.current + 1);
    next.push(state);
    if (next.length > 50) next.shift();
    historyRef.current = next;
    historyIndexRef.current = next.length - 1;
    setHistoryStatus({ canUndo: next.length > 1, canRedo: false });
  };

  /** Put a snapshot back on the canvas, camera included. */
  const applyView = (state: GraphViewState) => {
    expandedDepthsRef.current = new Map(state.expanded);
    setExpandedDepths(new Map(state.expanded));
    // Focus hides by implication; only the extra hidden ids travel in the state.
    const restoredHidden = new Set(state.hidden);
    if (state.focus) {
      for (const id of hiddenFromFocus(state.focus)) restoredHidden.add(id);
    }
    setHiddenNodes(restoredHidden);
    setRemovedNodes(new Set(state.removed));
    setCollapsedClusters(new Map(state.collapsed));
    setActiveEntityId(state.activeEntity);
    setActiveClusterKey(state.activeCluster);
    onFocusRestore?.(state.focus);
    if (show3d) {
      const focus = state.focus;
      // The scene rebuilds after this render, so the camera move comes after it.
      window.setTimeout(() => {
        if (focus) graph3dRef.current?.focusNode(focus);
        else graph3dRef.current?.fit();
      }, 80);
      return;
    }
    if (state.zoom !== null && state.pan) {
      const camera = { zoom: state.zoom, pan: state.pan };
      window.setTimeout(() => {
        const cy = cyRef.current;
        if (!cy) return;
        cy.zoom(camera.zoom);
        cy.pan(camera.pan);
      }, 180);
      return;
    }
    refitSoon();
  };

  const undo = () => {
    if (historyIndexRef.current <= 0) return;
    historyIndexRef.current -= 1;
    applyView(historyRef.current[historyIndexRef.current]);
    setHistoryStatus({ canUndo: historyIndexRef.current > 0, canRedo: true });
  };

  const redo = () => {
    if (historyIndexRef.current >= historyRef.current.length - 1) return;
    historyIndexRef.current += 1;
    applyView(historyRef.current[historyIndexRef.current]);
    setHistoryStatus({
      canUndo: historyIndexRef.current > 0,
      canRedo: historyIndexRef.current < historyRef.current.length - 1,
    });
  };

  // Every visibility change is one step. The effect records the state *after*
  // each change; Undo walks back through them and Redo replays them. Restoring a
  // step re-renders with exactly that state, which `pushHistory` recognises as
  // already recorded and does not append — that is what keeps Redo alive.
  useEffect(() => {
    pushHistory(snapshotView());
    // eslint-disable-next-line react-hooks/exhaustive-deps -- snapshotView reads exactly these
  }, [hiddenNodes, removedNodes, collapsedClusters, expandedDepths, activeEntityId, activeClusterKey, focusId]);

  // A filter that changes what is drawn re-frames the canvas, so the analyst
  // sees the result of the control they just pressed instead of a slice of it.
  // Spacing changes the layout itself, so it counts as a filter too.
  const filtersRef = useRef<{
    link: number | null;
    nbrs: NeighbourBudget;
    spacing: 'roomy' | 'compact';
  } | null>(null);
  useEffect(() => {
    const previous = filtersRef.current;
    filtersRef.current = { link: minLinkScore, nbrs: neighbourBudget, spacing };
    if (!previous) return;
    if (
      previous.link === minLinkScore &&
      previous.nbrs === neighbourBudget &&
      previous.spacing === spacing
    )
      return;
    refitSoon();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- refitSoon reads refs and show3d
  }, [minLinkScore, neighbourBudget, spacing]);

  // Escape closes the settings popover, like every other overlay here.
  useEffect(() => {
    if (!settingsOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setSettingsOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [settingsOpen]);

  const saveView = (name: string) => {
    const state = snapshotView();
    const summary = [
      state.focus ? 'focused' : 'whole graph',
      `${state.hidden.length} hidden`,
      state.removed.length > 0 ? `${state.removed.length} removed` : null,
      state.collapsed.length > 0 ? `${state.collapsed.length} collapsed` : null,
      state.expanded.length > 0 ? `${state.expanded.length} expanded` : null,
    ]
      .filter(Boolean)
      .join(' · ');
    const localId = `local-${Date.now()}`;
    const entry: ParkedView = { id: localId, name, at: new Date().toISOString(), summary, state };
    setSavedViews((current) => [entry, ...current]);
    if (!viewStore) return;
    // A case outlives the session, so its views do too: persisted in the backend.
    void caseGraphViewsApi
      .create(viewStore.caseId, {
        name,
        view_state: state,
      })
      .then((row) => {
        setViewError(null);
        setSavedViews((current) =>
          current.map((item) =>
            item.id === localId ? { ...item, id: row.id, at: row.updated_at } : item
          )
        );
      })
      .catch((error: Error) => {
        setViewError(`Saved for this session only — the API refused it: ${error.message}`);
      });
  };

  // Views saved earlier for this case, so reopening the modal finds them again.
  useEffect(() => {
    const caseId = viewStore?.caseId;
    if (!caseId) return;
    let cancelled = false;
    caseGraphViewsApi
      .list(caseId)
      .then((rows) => {
        if (cancelled) return;
        const mine = rows
          .map((row) => ({
            id: row.id,
            name: row.name,
            at: row.updated_at,
            summary: '', // Will be computed from state if needed
            state: (row.view_state as GraphViewState) ?? undefined,
          }))
          .filter((row): row is ParkedView => Boolean(row.state));
        // Anything saved in this session but not yet round-tripped stays put.
        setSavedViews((current) => {
          const pending = current.filter((item) => item.id.startsWith('local-'));
          const seen = new Set(mine.map((item) => item.id));
          return [...pending.filter((item) => !seen.has(item.id)), ...mine];
        });
        setViewError(null);
      })
      .catch((error: Error) => {
        if (!cancelled) setViewError(`Could not load saved views: ${error.message}`);
      });
    return () => {
      cancelled = true;
    };
  }, [viewStore?.caseId]);

  const applySavedView = (id: string) => {
    const view = savedViews.find((entry) => entry.id === id);
    if (view) applyView(view.state);
  };

  const deleteSavedView = (id: string) => {
    setSavedViews((current) => current.filter((entry) => entry.id !== id));
    if (!viewStore || id.startsWith('local-')) return;
    void caseGraphViewsApi.delete(viewStore.caseId, id).catch((error: Error) => {
      setViewError(`Could not delete the saved view: ${error.message}`);
    });
  };

  /**
   * Download what is drawn right now as a PNG.
   *
   * The 2D export renders the whole element set at 2x (`full: true`), not the
   * viewport, so every leaf, edge and label reaches the file even when the
   * screen is zoomed into one corner — which is the state an analyst is in when
   * they want the picture for a report. 3D has no off-screen render target, so
   * it exports the frame the camera is showing.
   */
  const exportPng = () => {
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    if (show3d) {
      const dataUrl = graph3dRef.current?.snapshot();
      if (dataUrl) downloadDataUrl(dataUrl, `correlation-3d-${stamp}.png`);
      return;
    }
    const cy = cyRef.current;
    if (!cy) return;
    // A campaign this wide at 2x would be a multi-thousand-pixel bitmap (a
    // browser canvas stops at ~32k px per side), so the scale shrinks with the
    // graph instead of failing on the large ones.
    const box = cy.elements().boundingBox();
    const widest = Math.max(box.w, box.h, 1);
    const scale = Math.min(2, Math.max(0.5, 8000 / widest));
    const dataUrl = cy.png({ full: true, scale, bg: palette.surface });
    downloadDataUrl(dataUrl, `correlation-2d-${stamp}.png`);
  };

  const resetLayout = (nextSpacing: 'roomy' | 'compact' = spacing) => {
    // The 3D placement is deterministic — no physics to re-run — so "reset"
    // means returning to the fitted camera rather than rebuilding a hidden
    // cytoscape layout the analyst cannot see.
    if (show3d && graph3dRef.current) {
      graph3dRef.current.fit();
      return;
    }
    const cy = cyRef.current;
    if (!cy) return;
    cy.one('layoutstop', () => {
      if (!liveLayout) {
        spreadClusters(cy, clusterPartition, nextSpacing === 'roomy');
        magneticPassRef.current?.();
      }
      cy.fit(cy.elements(), 56);
    });
    cy.layout(
      (liveLayout
        ? {
            name: 'cola',
            animate: true,
            fit: true,
            padding: 40,
            continuous: true,
            avoidOverlap: true,
            randomize: true,
            numIter: 1000,
          }
        : {
            name: 'fcose',
            animate: true,
            animationDuration: 400,
            animationEasing: 'ease-out',
            randomize: true,
            fit: true,
            ...spacingParams(nextSpacing),
            packComponents: true,
            uniformNodeDimensions: false,
          }) as never
    ).run();
  };

  // Cytoscape keeps the canvas at the size it mounted with, so growing the
  // container (full screen, window resize, a split pane) needs an explicit
  // resize or the drawing stays in the old viewport.
  //
  // The first measured size is also the first trustworthy moment to fit: the
  // fit the layout does on mount can run while the modal is still opening and
  // the canvas is 0×0, which is why the graph used to open off screen. Fit once
  // when the real size arrives, and again whenever a new payload replaces the
  // elements.
  useEffect(() => {
    const container = containerRef.current;
    if (!container || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(() => {
      const cy = cyRef.current;
      if (!cy || container.clientWidth <= 0) return;
      // The model point sitting in the middle of the old viewport, because a
      // size change must not move the picture: `resize()` keeps the zoom but
      // leaves the pan in viewport pixels, so a wider canvas slid the graph
      // sideways. Framing is only for the first real size and for a genuinely
      // new payload.
      const zoom = cy.zoom();
      const pan = { ...cy.pan() };
      const centre = {
        x: (cy.width() / 2 - pan.x) / zoom,
        y: (cy.height() / 2 - pan.y) / zoom,
      };
      cy.resize();
      if (pendingInitialFitRef.current) {
        pendingInitialFitRef.current = false;
        cy.fit(cy.elements(), 56);
        return;
      }
      cy.pan({
        x: cy.width() / 2 - centre.x * zoom,
        y: cy.height() / 2 - centre.y * zoom,
      });
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  /** Every node id the candidate knows, so Focus can blanket-hide the rest. */
  const allNodeIds = useMemo(() => (graph?.nodes ?? []).map((node) => node.id), [graph]);

  /** The entity edges an expansion walks — the same ones the canvas draws. */
  const structuralEdges = useMemo(
    () =>
      (graph?.edges ?? [])
        .filter((edge) => edge.kind !== 'CORRELATION')
        .map((edge) => ({ id: edge.id, source: edge.source, target: edge.target })),
    [graph]
  );

  const neighboursOf = (id: string): Set<string> => {
    const found = new Set<string>();
    for (const edge of graph?.edges ?? []) {
      if (edge.source === id) found.add(edge.target);
      else if (edge.target === id) found.add(edge.source);
    }
    return found;
  };

  // The parent rail owns the selection, so it drives expand / hide / focus
  // through this handle instead of duplicating the graph's visibility state.
  useImperativeHandle(
    ref,
    () => ({
      expandNode: (id: string) => {
        // One more layer per click, capped so a hub cannot un-hide an entire
        // campaign by accident. The depth is returned so the button can say
        // which layer is on screen now.
        //
        // While focused, the canvas already shows two rings around the node, so
        // the first two clicks were no-ops: the button counted up to "Expand 3
        // layers" while nothing changed. Skip the layers that are already
        // drawn and land on the first one that actually reveals a hidden node.
        // Outside focus nothing is hidden, so each click still widens the
        // neighbour budget by exactly one layer.
        const focused = focusRestoreRef.current !== null;
        const hiddenNow = new Set(hiddenNodes);
        let depth = Math.min(MAX_EXPAND_LAYERS, (expandedDepthsRef.current.get(id) ?? 0) + 1);
        let reveal = expandRadii(structuralEdges, new Map([[id, depth]]));
        while (
          focused &&
          depth < MAX_EXPAND_LAYERS &&
          ![...reveal].some((nodeId) => hiddenNow.has(nodeId))
        ) {
          depth += 1;
          reveal = expandRadii(structuralEdges, new Map([[id, depth]]));
        }
        const next = new Map(expandedDepthsRef.current);
        next.set(id, depth);
        expandedDepthsRef.current = next;
        setExpandedDepths(next);
        // Focus hides everything but the node and its direct neighbours, which
        // made a second Expand look like a no-op: the new edges were drawn but
        // their endpoints were still hidden. Reveal the layer as well.
        setHiddenNodes((current) => {
          const revealed = new Set(current);
          let changed = false;
          for (const nodeId of reveal) {
            if (revealed.delete(nodeId)) changed = true;
          }
          return changed ? revealed : current;
        });
        refitSoon();
        return depth;
      },
      hideNode: (id: string) => {
        setHiddenNodes((current) => new Set(current).add(id));
        if (expandedDepthsRef.current.has(id)) {
          const next = new Map(expandedDepthsRef.current);
          next.delete(id);
          expandedDepthsRef.current = next;
          setExpandedDepths(next);
        }
        onSelectNode?.(null);
      },
      focusNode: (id: string) => {
        const keep = neighboursOf(id);
        keep.add(id);
        focusRestoreRef.current = new Set(hiddenNodes);
        setHiddenNodes(new Set(allNodeIds.filter((nodeId) => !keep.has(nodeId))));
        if (show3d) {
          // The 3D focus already frames the kept nodes.
          graph3dRef.current?.focusNode(id);
          refitSoon(false);
        } else {
          refitSoon();
        }
      },
      unfocus: () => {
        // Layers revealed while focused belong to that focus; leaving it must
        // not leave the canvas stuck four layers deep.
        if (expandedDepthsRef.current.size > 0) {
          expandedDepthsRef.current = new Map();
          setExpandedDepths(new Map());
        }
        // Unfocus means "get me back to the whole campaign", so it also drops
        // the Hide / Remove / Collapse states instead of leaving the analyst to
        // find `show all` afterwards.
        focusRestoreRef.current = null;
        setHiddenNodes(new Set());
        setRemovedNodes(new Set());
        setCollapsedClusters(new Map());
        setActiveClusterKey(null);
        // Restoring the nodes re-creates the canvas, so an immediate fit would
        // frame the small focused set it is replacing. With Expand on top the
        // keep-arrangement rebuild then re-placed the revealed nodes without a
        // fit at all and the rest of the campaign stayed off screen: frame the
        // rebuilt (whole) graph instead.
        refitSoon();
      },
      showAll: () => {
        setHiddenNodes(new Set());
        setRemovedNodes(new Set());
        setCollapsedClusters(new Map());
        refitSoon();
      },
      expandDepthOf: (id: string) => expandedDepthsRef.current.get(id) ?? 0,
      resetExpansion: () => {
        if (expandedDepthsRef.current.size === 0) return;
        expandedDepthsRef.current = new Map();
        setExpandedDepths(new Map());
      },
      fit: () => fit(),
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- neighboursOf/allNodeIds follow graph
    [graph, allNodeIds, onSelectNode, hiddenNodes, show3d, structuralEdges]
  );

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className={clsx('flex h-full items-center justify-center px-8 text-center', className)}>
        <div>
          <p className="text-sm text-gray-400">No correlation graph for this candidate yet.</p>
          <p className="mt-1 text-xs text-gray-500">
            The graph is built from correlated observations. Check that:
          </p>
          <ul className="mt-2 text-xs text-gray-500 space-y-1">
            <li>• The correlation service is running</li>
            <li>• The worker has processed these alerts (check logs)</li>
            <li>• Alerts meet the correlation threshold (θ ≥ 3)</li>
          </ul>
        </div>
      </div>
    );
  }

  return (
    <div className={clsx('relative flex h-full min-h-0 min-w-0 flex-col', className)}>
      <div className="border-b border-[#374151]/60 px-4 py-2">
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="mr-1 text-[11px] uppercase tracking-wide text-gray-500">Show</span>
          {kindOptions.map((meta) => {
            const hidden = hiddenKinds.has(meta.kind);
            const count = counts.byKind.get(meta.kind) ?? 0;
            return (
              <button
                key={meta.kind}
                type="button"
                onClick={() => toggleKind(meta.kind)}
                aria-pressed={!hidden}
                title={`${meta.hint} ${hidden ? 'Hidden — click to show.' : 'Click to hide.'}`}
                className={clsx(
                  'inline-flex items-center gap-1.5 rounded border px-2 py-1 transition-colors',
                  hidden
                    ? 'border-[#374151] text-gray-500 hover:border-gray-500'
                    : 'border-[#374151] text-gray-200 hover:border-gray-500'
                )}
              >
                <KindIcon meta={meta} muted={hidden} />
                <span className={hidden ? 'line-through' : undefined}>{meta.label}</span>
                <span className="tabular-nums text-[10px] text-gray-500">{count}</span>
              </button>
            );
          })}

          {roleLegend.length > 0 && (
            <>
              <span className="mx-1 h-4 w-px bg-[#374151]" aria-hidden />
              <span className="text-[10px] uppercase tracking-wide text-gray-500">Actions</span>
              {roleLegend.map((entry) => (
                <span
                  key={entry.role}
                  className="inline-flex items-center gap-1.5 rounded border border-[#374151] px-2 py-1"
                  title={`${entry.count} edge${entry.count === 1 ? '' : 's'} for ${entry.role} — each observation drawn as the relation between its own entities`}
                >
                  <span
                    className="h-0.5 w-4 rounded"
                    style={{ backgroundColor: entry.color }}
                    aria-hidden
                  />
                  <span className="max-w-[160px] truncate text-gray-200">{entry.role}</span>
                  <span className="tabular-nums text-[10px] text-gray-500">{entry.count}</span>
                </span>
              ))}
            </>
          )}

          <div className="relative ml-auto flex items-center gap-2">
            {/* The view controls outgrew the row, so they live behind one
                Settings button and the row keeps the per-selection actions. */}
            {settingsOpen && (
              <>
                <div
                  className="fixed inset-0 z-20"
                  onClick={() => setSettingsOpen(false)}
                  aria-hidden
                />
                <div
                  role="dialog"
                  aria-label="Graph settings"
                  className="absolute right-0 top-full z-30 mt-1 flex w-[300px] max-w-[calc(100vw-2rem)] flex-col items-stretch gap-1.5 rounded-md border border-[#374151] bg-dark-70/95 p-2.5 shadow-2xl backdrop-blur-sm"
                >
                  <span className="w-full text-[10px] uppercase tracking-wide text-gray-500">
                    Graph settings
                  </span>
            <div
              role="group"
              aria-label="Neighbours drawn per node"
              title="How many neighbours each node draws. Lower it to keep only the strongest links; nodes with more links show +N and can be expanded individually."
              className="flex w-full overflow-hidden rounded border border-[#374151] [&>button]:flex-1"
            >
              <span className="px-1.5 py-1 text-[10px] uppercase tracking-wide text-gray-500">
                Nbrs
              </span>
              {NEIGHBOUR_BUDGETS.map((value) => (
                <button
                  key={String(value)}
                  type="button"
                  onClick={() => setNeighbourBudget(value)}
                  aria-pressed={neighbourBudget === value}
                  className={clsx(
                    'border-l border-[#374151] px-2 py-1 text-[11px] tabular-nums transition-colors',
                    neighbourBudget === value
                      ? 'bg-teal-500/10 text-teal-200'
                      : 'text-gray-400 hover:text-gray-200'
                  )}
                >
                  {value === 'all' ? 'All' : value}
                </button>
              ))}
            </div>
            <div
              role="group"
              aria-label="Graph spacing"
              className="flex w-full overflow-hidden rounded border border-[#374151] [&>button]:flex-1"
            >
              {(['roomy', 'compact'] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => {
                    if (value === spacing) return;
                    setSpacing(value);
                    // Spacing only reaches the physics on a fresh layout, so
                    // pressing it re-lays the graph out instead of doing
                    // nothing until the next Reset.
                    resetLayout(value);
                  }}
                  aria-pressed={spacing === value}
                  title={
                    value === 'roomy'
                      ? 'Spread the nodes out — leaves stop overlapping, at the cost of panning.'
                      : 'Pack the nodes tighter — fits a small component on screen without panning.'
                  }
                  className={clsx(
                    'px-2 py-1 text-[11px] transition-colors',
                    spacing === value
                      ? 'bg-teal-500/10 text-teal-200'
                      : 'text-gray-400 hover:text-gray-200'
                  )}
                >
                  {value === 'roomy' ? 'Spacious' : 'Compact'}
                </button>
              ))}
            </div>
            {/* One segmented control, like Spacious/Compact: the two modes are
                alternatives, so they read as one choice rather than two
                unrelated buttons. */}
            <div
              role="group"
              aria-label="Layout forces"
              className="flex w-full overflow-hidden rounded border border-[#374151] [&>button]:flex-1"
            >
              <button
                type="button"
                onClick={() =>
                  setMagnetic((value) => {
                    const next = !value;
                    if (next) setLiveLayout(false);
                    return next;
                  })
                }
                disabled={show3d}
                aria-pressed={magnetic}
                title={
                  show3d
                    ? 'Magnetic layout is a 2D pass; switch back to 2D.'
                    : 'Magnetic pass: strong links pull their leaves together and leaves with no shared link push apart, applied after the engine settles. Off = the plain engine layout.'
                }
                className={clsx(
                  'px-2 py-1 text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-40',
                  magnetic
                    ? 'bg-teal-500/10 text-teal-200'
                    : 'text-gray-400 hover:text-gray-200'
                )}
              >
                Magnetic
              </button>
              <button
                type="button"
                onClick={() =>
                  setLiveLayout((value) => {
                    const next = !value;
                    // One physics model at a time: a continuous simulation and
                    // a post-pass relaxation would fight over the positions.
                    if (next) setMagnetic(false);
                    return next;
                  })
                }
                disabled={show3d}
                aria-pressed={liveLayout}
                title={
                  show3d
                    ? 'Live layout is a 2D force simulation; switch back to 2D.'
                    : 'Live layout: a continuous physics simulation instead of a one-shot pass. Dragging a leaf pushes its neighbours. Heaviest option — best under a few hundred nodes.'
                }
                className={clsx(
                  'border-l border-[#374151] px-2 py-1 text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-40',
                  liveLayout
                    ? 'bg-teal-500/10 text-teal-200'
                    : 'text-gray-400 hover:text-gray-200'
                )}
              >
                Live
              </button>
            </div>
            {onToggleObservationMode && (
              <div
                role="group"
                aria-label="Observation projection"
                className="flex w-full overflow-hidden rounded border border-[#374151] [&>button]:flex-1"
              >
                {(['edge', 'node'] as const).map((value) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => onToggleObservationMode(value)}
                    aria-pressed={observationMode === value}
                    title={
                      value === 'edge'
                        ? 'Each observation becomes one role edge between its own entities. Reads as “user did X on host”, and keeps the canvas small because there is no hub node per action.'
                        : 'Each observation becomes its own hub node with an edge to every entity it mentions. The historical layout: pick one action on the canvas, at the cost of a node per action.'
                    }
                    className={clsx(
                      'px-2 py-1 text-[11px] transition-colors',
                      observationMode === value
                        ? 'bg-teal-500/10 text-teal-200'
                        : 'text-gray-400 hover:text-gray-200'
                    )}
                  >
                    {value === 'edge' ? 'Actions as edges' : 'Actions as nodes'}
                  </button>
                ))}
              </div>
            )}
            <button
              type="button"
              onClick={() => setAutoTidy((value) => !value)}
              aria-pressed={autoTidy}
              title={
                autoTidy
                  ? 'After you drop a node the rest of the graph relaxes around it. Turn off to keep every other node exactly where it is.'
                  : 'Dropping a node leaves the rest of the graph untouched. Turn on to re-tidy the canvas around the node you drop.'
              }
              className={clsx(
                // Same 11px type as the rest of the row: without it these fell
                // back to the toolbar's 12px and stood a couple of pixels taller.
                'w-full rounded border px-2 py-1 text-[11px] transition-colors',
                autoTidy
                  ? 'border-teal-500/40 bg-teal-500/10 text-teal-200'
                  : 'border-[#374151] text-gray-400 hover:border-gray-500'
              )}
            >
              Auto-tidy
            </button>
            <label
              title="Draw only pair links at or above this score. A view filter: the component, its scores and the case are unchanged."
              className="flex w-full items-center justify-between gap-1 rounded border border-[#374151] px-1.5 py-1"
            >
              <span className="text-[10px] uppercase tracking-wide text-gray-500">Link ≥</span>
              <select
                value={minLinkScore ?? 'all'}
                onChange={(event) =>
                  setMinLinkScore(
                    event.target.value === 'all' ? null : Number(event.target.value)
                  )
                }
                aria-label="Minimum pair link score drawn"
                className="bg-transparent text-[11px] tabular-nums text-gray-200 focus:outline-none"
              >
                <option value="all" className="bg-dark-70">all</option>
                {linkScoreOptions.map((score) => (
                  <option key={score} value={score} className="bg-dark-70">
                    {score}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              onClick={() => setShowPairs((value) => !value)}
              aria-pressed={showPairs}
              title="Draw observation↔observation links labelled with the L1+L2+L3 pair score."
              className={clsx(
                'w-full rounded border px-2 py-1 text-[11px] transition-colors',
                showPairs
                  ? 'border-teal-500/40 bg-teal-500/10 text-teal-200'
                  : 'border-[#374151] text-gray-400 hover:border-gray-500'
              )}
            >
              Pair links
            </button>
            {onToggleDetails && (
              <button
                type="button"
                onClick={onToggleDetails}
                aria-pressed={detailsOpen}
                title={
                  detailsOpen
                    ? 'Disable auto-opening details when a node or entity is selected.'
                    : 'Enable auto-opening details when a node or entity is selected.'
                }
                className={clsx(
                  'w-full rounded border px-2 py-1 text-[11px] transition-colors',
                  detailsOpen
                    ? 'border-teal-500/40 bg-teal-500/10 text-teal-200'
                    : 'border-[#374151] text-gray-400 hover:border-gray-500'
                )}
              >
                Auto Details
              </button>
            )}
                </div>
              </>
            )}
            {/* View history and export: about the picture, not about the data,
                so they sit with the view controls and work in both views. */}
            <div
              role="group"
              aria-label="View history"
              className="flex overflow-hidden rounded border border-[#374151]"
            >
              <button
                type="button"
                onClick={undo}
                disabled={!historyStatus.canUndo}
                title="Undo the last graph change (focus, expand, hide, remove, collapse, saved view)."
                className="px-2 py-1 text-[11px] text-gray-300 transition-colors hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-40"
              >
                ↶ Undo
              </button>
              <button
                type="button"
                onClick={redo}
                disabled={!historyStatus.canRedo}
                title="Redo the change you just undid."
                className="border-l border-[#374151] px-2 py-1 text-[11px] text-gray-300 transition-colors hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-40"
              >
                ↷ Redo
              </button>
            </div>
            <button
              type="button"
              onClick={exportPng}
              title={
                show3d
                  ? 'Download the 3D scene as the camera shows it right now (PNG).'
                  : 'Download every drawn node, edge and label as a 2x PNG — the whole graph, not just the part on screen.'
              }
              className="rounded border border-[#374151] px-2 py-1 text-[11px] text-gray-300 transition-colors hover:border-teal-500/60 hover:text-teal-200"
            >
              Export PNG
            </button>
            <button
              type="button"
              onClick={() => setSettingsOpen((value) => !value)}
              aria-expanded={settingsOpen}
              aria-haspopup="dialog"
              title="Graph settings: neighbours per node, spacing, layout forces, action projection, auto-tidy and link filters."
              className={clsx(
                'rounded border px-2 py-1 text-[11px] transition-colors',
                settingsOpen
                  ? 'border-teal-500/40 bg-teal-500/10 text-teal-200'
                  : 'border-[#374151] text-gray-400 hover:border-gray-500'
              )}
            >
              Settings
            </button>
            {onToggleFullscreen && (
              <button
                type="button"
                onClick={onToggleFullscreen}
                aria-pressed={fullscreenActive}
                title={
                  fullscreenActive
                    ? 'Leave full screen (Esc)'
                    : 'Show this graph, its toolbar and the ATT&CK / kill-chain strip on the whole screen.'
                }
                className={clsx(
                  'rounded border px-2 py-1 text-[11px] transition-colors',
                  fullscreenActive
                    ? 'border-teal-500/40 bg-teal-500/10 text-teal-200'
                    : 'border-[#374151] text-gray-300 hover:border-gray-500'
                )}
              >
                {fullscreenActive ? 'Exit full screen' : 'Maximize'}
              </button>
            )}
          </div>
        </div>

        {(hiddenKinds.size > 0 || hiddenNodes.size > 0) && (
          <p className="mt-1.5 text-[11px] text-gray-500">
            Hidden:{' '}
            {[
              [...hiddenKinds].map((kind) => KIND_LABEL[kind] ?? kind).join(', '),
              hiddenNodes.size > 0 ? `${hiddenNodes.size} node${hiddenNodes.size === 1 ? '' : 's'}` : '',
            ]
              .filter(Boolean)
              .join(' · ')}{' '}
            —{' '}
            <button
              type="button"
              onClick={() => {
                setHiddenKinds(new Set());
                setHiddenNodes(new Set());
                setRemovedNodes(new Set());
                setCollapsedClusters(new Map());
              }}
              className="text-teal-300 hover:underline"
            >
              show all
            </button>
          </p>
        )}
      </div>

      {/* The entity list stays beside the scene in 3D too: the analyst should
          not lose the list (or its timeline) by switching projection. */}
      {/* `min-w-0` + `overflow-hidden` keep the entity column on screen: the
          canvases inside carry pixel widths, which made this flex row refuse to
          shrink — with the Evidence rail open the graph pushed the 300px column
          past the modal's edge, so Entities simply vanished until the rail was
          closed. */}
      <div className="relative flex min-h-0 min-w-0 flex-1 overflow-hidden">
        {show3d ? (
        <Graph3DView
          graph={graph}
          hiddenIds={hiddenNodes}
          removedIds={removedNodes}
          colorFor={kindColorFor}
          shapeFor={kindShapeFor}
          onSelectNode={(node) => {
            // Mirror the 2D canvas semantics: a node tap marks the active row,
            // clears edge selection, and reports a canvas-origin node selection.
            if (node) {
              setActiveEntityId(node.id);
              onSelectEdgeRef.current?.(null);
              onSelectNodeRef.current?.(node, 'canvas');
              return;
            }
            setActiveEntityId(null);
            onSelectNodeRef.current?.(null);
            onSelectEdgeRef.current?.(null);
          }}
          onSelectEdge={(edgeId) => {
            // Same contract as the canvas: a link tap clears the node selection
            // and hands the edge to the inspector below the view.
            if (edgeId) {
              setActiveEntityId(null);
              onSelectNodeRef.current?.(null);
              onSelectEdgeRef.current?.(edgeId);
              return;
            }
            onSelectEdgeRef.current?.(null);
          }}
          selectedEdgeId={selectedEdgeId}
          onClose={() => setShow3d(false)}
          drawnNodeIds={drawnIds.nodes}
          drawnEdgeIds={drawnIds.edges}
          compact={spacing !== 'roomy'}
          collapsedClusters={collapsedClusterKeys}
          onToggleCluster={toggleCluster}
          activeClusterIds={activeClusterIds}
          onClusters={setClusters3d}
          activeId={activeEntityId}
          showLabels={labels3d}
          onToggleLabels={() => setLabels3d((value) => !value)}
          onClearView={clearView}
          onApi={(api) => {
            graph3dRef.current = api;
          }}
        />
        ) : (
        <div className="relative min-h-0 min-w-0 flex-1 overflow-hidden">
        <div ref={containerRef} className="h-full w-full bg-dark-80" />

        {/* The same corner the 3D overlay uses: view controls belong inside the
            graph, not in a row above the entity list. */}
        <div className="absolute right-3 top-2 z-10 flex items-center gap-1 text-[11px]">
          <button
            type="button"
            onClick={() => setLabels2d((value) => !value)}
            aria-pressed={labels2d}
            title="Show or hide the names on the canvas. Labels normally appear as you zoom in."
            className={clsx(
              'rounded border px-2 py-1 backdrop-blur-sm transition-colors',
              labels2d
                ? 'border-teal-500/40 bg-teal-500/10 text-teal-200'
                : 'border-[#374151] bg-dark-70/85 text-gray-300 hover:border-gray-500'
            )}
          >
            Labels
          </button>
          <div
            role="group"
            aria-label="Graph zoom"
            className="flex overflow-hidden rounded border border-[#374151] bg-dark-70/85 backdrop-blur-sm"
          >
            <button
              type="button"
              onClick={() => zoomBy(1 / ZOOM_STEP)}
              aria-label="Zoom out"
              title="Zoom out around the middle of the view."
              className="px-2 py-1 text-gray-300 transition-colors hover:bg-white/5"
            >
              −
            </button>
            <button
              type="button"
              onClick={() => zoomBy(ZOOM_STEP)}
              aria-label="Zoom in"
              title="Zoom in around the middle of the view."
              className="border-l border-[#374151] px-2 py-1 text-gray-300 transition-colors hover:bg-white/5"
            >
              +
            </button>
          </div>
          <button
            type="button"
            onClick={fit}
            title="Frame every drawn node (and bubble) in the view."
            className="rounded border border-[#374151] bg-dark-70/85 px-2 py-1 text-gray-300 backdrop-blur-sm transition-colors hover:border-gray-500"
          >
            Fit
          </button>
          <button
            type="button"
            onClick={() => resetLayout()}
            title="Discard manual dragging and recompute the engine's layout."
            className="rounded border border-[#374151] bg-dark-70/85 px-2 py-1 text-gray-300 backdrop-blur-sm transition-colors hover:border-gray-500"
          >
            Reset
          </button>
          {!show3d && (
            <button
              type="button"
              onClick={toggleReveal}
              title={
                revealPlayback === 'playing'
                  ? 'Pause the reveal.'
                  : 'Replay the graph building itself in alert order — where the analysis starts, and how it grew.'
              }
              className={clsx(
                'rounded border px-2 py-1 backdrop-blur-sm transition-colors',
                revealPlayback === 'playing'
                  ? 'border-teal-500/40 bg-teal-500/10 text-teal-200'
                  : 'border-[#374151] bg-dark-70/85 text-gray-300 hover:border-teal-500/60 hover:text-teal-200'
              )}
            >
              {revealPlayback === 'playing' ? '⏸ Pause' : revealPlayback === 'done' ? '↻ Replay' : '▶ Play'}
            </button>
          )}
          <button
            type="button"
            onClick={clearView}
            title="Undo Focus, expansion, Hide and Remove in one click — back to the whole campaign, framed."
            className="rounded border border-[#374151] bg-dark-70/85 px-2 py-1 text-gray-300 backdrop-blur-sm transition-colors hover:border-teal-500/60 hover:text-teal-200"
          >
            Clear view
          </button>
          <button
            type="button"
            onClick={() => setShow3d((value) => !value)}
            aria-pressed={show3d}
            title="Orbit the campaign in 3D: the same clusters, given depth. Loaded on demand (WebGL)."
            className={clsx(
              'rounded border px-2 py-1 backdrop-blur-sm transition-colors',
              show3d
                ? 'border-teal-500/40 bg-teal-500/10 text-teal-200'
                : 'border-[#374151] bg-dark-70/85 text-gray-300 hover:border-gray-500'
            )}
          >
            3D
          </button>
        </div>

        {renderError && (
          <div className="absolute inset-0 flex items-center justify-center bg-dark-80/90 px-6 text-center text-sm text-red-300">
            {renderError}
          </div>
        )}

        {/* Hover card — names come from the data, not the truncated canvas label. */}
        {hovered && (
          <div
            className="pointer-events-none absolute z-10 max-w-[320px] rounded-md border border-[#374151] bg-dark-70/95 px-2.5 py-1.5 shadow-xl backdrop-blur-sm"
            style={{ left: hovered.x, top: hovered.y }}
            role="tooltip"
          >
            <p className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-gray-500">
              <KindIcon meta={metaForKind(hovered.kind)} />
              {KIND_LABEL[hovered.kind] ?? hovered.kind}
              {hovered.alerts > 0 && (
                <span className="normal-case tracking-normal">· {hovered.alerts} alerts</span>
              )}
            </p>
            <p className="mt-0.5 break-all text-xs text-gray-100">{hovered.label}</p>
            {hovered.token && (
              <p className="mt-0.5 break-all font-mono text-[10px] text-gray-500">{hovered.token}</p>
            )}
            {hovered.collapsed > 0 && (
              <p className="mt-0.5 text-[10px] text-teal-300">
                +{hovered.collapsed} more — select the node to expand
              </p>
            )}
          </div>
        )}

        <p className="pointer-events-none absolute bottom-2 left-3 text-[11px] text-gray-600">
          {hiddenKinds.has('observation')
            ? 'entities only'
            : counts.roleEdges > 0
              ? `${counts.roleEdges} action edge${counts.roleEdges === 1 ? '' : 's'}` +
                (counts.collapsedActions > 0 ? ` (${counts.collapsedActions} collapsed)` : '') +
                ` · ${counts.observations} action${counts.observations === 1 ? '' : 's'}`
              : `${counts.observations} observations`}{' '}
          · {counts.visibleEntities}
          {counts.visibleEntities !== counts.entities ? ` of ${counts.entities}` : ''} entities ·{' '}
          {showPairs
            ? `top ${Math.min(MAX_PAIR_EDGES, pairLinksInRange)} of ${pairLinksInRange} pair links`
            : `${counts.aboveTheta} pair links hidden`}
          {showPairs && minLinkScore !== null
            ? ` · ≥${minLinkScore} (${counts.aboveTheta - pairLinksInRange} below filter)`
            : ''}
          {neighbourBudget !== 'all' ? ` · ${neighbourBudget} nbrs/node` : ' · all neighbours'}
          {trimmedNodes > 0 ? ` · ${trimmedNodes} leaves hidden by budget` : ''}
        </p>
        </div>
        )}

        {/* Entity list column. It is always on screen: the list is how the
            analyst reads the campaign, and hiding it only ever saved space the
            graph could not use. */}
        <div className="flex w-[300px] shrink-0 flex-col border-l border-[#374151]/60">
          <GraphEntityPanel
            className="min-h-0 flex-1"
            clusters={clusterSummaries}
            onToggleCluster={toggleCluster}
            onFocusCluster={focusCluster}
            entities={entityRows}
            hiddenIds={hiddenNodes}
            removedIds={removedNodes}
            drawnIds={drawnIds.nodes}
            selectedIds={selectedEntityIds}
            activeId={activeEntityId}
            kindLabel={(kind) => KIND_LABEL[kind] ?? kind}
            kindColor={(kind) => metaForKind(kind).color}
            kindIcon={(kind) => <KindIcon meta={metaForKind(kind)} />}
            onActivate={activateEntity}
            onHide={(ids) => setHiddenNodes((current) => addTo(current, ids))}
            onShow={restoreVisibleIds}
            onRemove={(ids) => {
              setRemovedNodes((current) => addTo(current, ids));
              setActiveEntityId((current) =>
                current && ids.includes(current) ? null : current
              );
            }}
            onRestore={restoreVisibleIds}
            onSetSelection={(ids) => setSelectedEntityIds(new Set(ids))}
            onToggleSelection={(id) =>
              setSelectedEntityIds((current) => {
                const next = new Set(current);
                if (next.has(id)) next.delete(id);
                else next.add(id);
                return next;
              })
            }
            onSelectRelated={(ids) => selectRelatedEntities(ids)}
            onOpenDetails={(id) => {
              const node = graph?.nodes.find((candidate) => candidate.id === id) ?? null;
              setActiveEntityId(id);
              // The explicit D action is an override, not a list click. Its job is
              // to force the panel open, not to re-fire the selection auto-open
              // policy that only respects the Auto Details toggle.
              onOpenDetails?.(id);
            }}
            views={savedViews}
            viewError={viewError}
            onSaveView={saveView}
            onApplyView={applySavedView}
            onDeleteView={deleteSavedView}
          />
        </div>

      </div>
    </div>
  );
}
