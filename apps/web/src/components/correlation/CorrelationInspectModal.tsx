'use client';

/**
 * Candidate inspection workbench.
 *
 * The card list answers "should I look at this?"; this view has to answer
 * "why did the engine put these alerts together, and is it right?". So the
 * default surface is the correlation graph (actions joined through shared
 * hosts/users/IPs, with the score on every scored pair), and everything else
 * — the L1/L2/L3 breakdown, the timeline, the raw observations and the member
 * alerts — sits next to it rather than behind another click.
 */

import { clsx } from 'clsx';
import { format } from 'date-fns';

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type {
  AlertScope,
  CandidateDetail,
  CandidateGraphEdge,
  CandidateGraphNode,
  CandidateObservation,
  CandidatePairScore,
  CandidateTimelineEvent,
} from '@/hooks/useCaseCandidates';
import { AlertLink } from '@/components/candidates/AlertLink';
import {
  CandidateGraphView,
  KIND_LABEL,
  type CandidateGraphHandle,
} from '@/components/candidates/CandidateGraphView';
import { EntityDetailCard } from '@/components/correlation/GraphEntityPanel';
import { buildEntityTimeline } from '@/lib/entityTimeline';
import { createPortal } from 'react-dom';

import { MAX_EXPAND_LAYERS } from '@/lib/graphBudget';

import { AttackCoverageStrip, ScopeBar } from './CorrelationPanels';
import { EdgeInspector } from './EdgeInspector';

export interface CorrelationInspectModalProps {
  /** Correlation payload — the same shape for a candidate and for a case. */
  detail: CandidateDetail | null;
  loading?: boolean;
  onClose: () => void;
  /** Small label above the title: where this evidence came from. */
  eyebrow: string;
  /** Muted note beside the eyebrow ("candidate" / "case"). */
  eyebrowNote?: string | null;
  /** Title override; the campaign theme is humanised by default. */
  title?: string | null;
  /** Identifier line under the title (candidate key, case number, …). */
  subtitle?: string | null;
  /**
   * Case this correlation belongs to. When present, the graph's saved views are
   * persisted per case instead of living only for the session.
   */
  caseId?: string | null;
  /**
   * Primary actions owned by the caller (Close / Save scope / Create case).
   * Rendered in the header beside the ✕ so the body keeps the full height —
   * a footer bar cost ~56px of graph for nothing but two buttons.
   */
  actions?: ReactNode;
  /** Analyst scope currently applied. Empty scope = nothing excluded. */
  scope: AlertScope;
  onScopeChange: (scope: AlertScope) => void;
  /** Set false for read-only surfaces (no scope bar). */
  allowScopeEditing?: boolean;
  /** Exclude one alert from the analysis (persisted by the caller). */
  onExcludeAlert?: (alertId: string) => void;
  /** Shown instead of the view when the payload never arrives. */
  emptyMessage?: string;
  /** Graph projection in use, and the control that flips it (owner re-fetches). */
  observationMode?: 'node' | 'edge';
  onToggleObservationMode?: (mode: 'node' | 'edge') => void;
}

type Tab = 'graph' | 'timeline' | 'observations' | 'alerts' | 'rules';

const ENTITY_KINDS: Array<{ key: keyof CandidateDetail['entities']; kind: string }> = [
  { key: 'hosts', kind: 'host' },
  { key: 'users', kind: 'user' },
  { key: 'ips', kind: 'ip' },
  { key: 'domains', kind: 'domain' },
];

/**
 * How long the evidence rail stays open on its own after the modal opens.
 *
 * Long enough to read the member counts, short enough that it does not keep a
 * third of the graph hidden. Clicking Evidence pins it and cancels this.
 */
const RAIL_AUTO_HIDE_MS = 10_000;

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-green-500',
  info: 'bg-sky-500',
};

function humanizeTheme(theme: string): string {
  const cleaned = theme.replace(/^APT_ACTIVITY_/, '').replace(/^APT_/, '');
  const words = cleaned.toLowerCase().replace(/_/g, ' ');
  if (!words) return 'Correlated activity';
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/**
 * An observation key is a machine identity (`alert|<uuid>`, `entity|<technique>|<digest>`),
 * not a label. Printing it raw put `entity|T1547.012|1e842df15d1cff34` in front of an
 * analyst; keep the readable parts and leave the exact key in the tooltip.
 */
function prettyObservationKey(key: string): string {
  const [head, ...rest] = key.split('|');
  if (head === 'alert' && rest[0]) return `alert · ${rest[0].slice(0, 8)}…`;
  if (head === 'entity' && rest.length >= 1) {
    const [technique, digest] = rest;
    return digest
      ? `entity · ${technique} · ${digest.slice(0, 10)}…`
      : `entity · ${technique}`;
  }
  return key;
}

/**
 * Token values can be a whole hash set (`sha1=…,md5=…` with newlines). A chip
 * is a label, not a payload: flatten it and keep the full value in the tooltip.
 */
function shortToken(value: string): string {
  const flat = value.replace(/\s+/g, ' ').trim();
  return flat.length > 44 ? `${flat.slice(0, 44)}…` : flat;
}

function formatSpan(from?: string | null, to?: string | null): string {
  if (!from || !to) return '—';
  const start = new Date(from).getTime();
  const end = new Date(to).getTime();
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return '—';
  const minutes = Math.round((end - start) / 60000);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  if (hours < 24) return rest ? `${hours}h ${rest}m` : `${hours}h`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}

function safeFormat(value?: string | null, pattern = 'MMM d, HH:mm:ss'): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : format(date, pattern);
}

/**
 * True when both timestamps fall on the same calendar day.
 *
 * An observation can span weeks. Printing only `HH:mm:ss` on both ends then
 * rendered “11:10:14 – 10:37:41”, which reads as a range that ends before it
 * starts; the date is only worth the columns when it actually differs.
 */
function sameDay(a?: string | null, b?: string | null): boolean {
  if (!a || !b) return false;
  const left = new Date(a);
  const right = new Date(b);
  if (Number.isNaN(left.getTime()) || Number.isNaN(right.getTime())) return false;
  return (
    left.getFullYear() === right.getFullYear() &&
    left.getMonth() === right.getMonth() &&
    left.getDate() === right.getDate()
  );
}

/** Gap marker between two timeline events, so pauses in an attack are legible. */
function gapLabel(previous: string | null | undefined, current: string | null | undefined): string | null {
  if (!previous || !current) return null;
  const delta = new Date(current).getTime() - new Date(previous).getTime();
  if (Number.isNaN(delta) || delta < 6 * 60 * 1000) return null;
  return `+${formatSpan(previous, current)}`;
}

/**
 * One row of the Alerts table.
 *
 * Extracted because the canonical alerts and the soft-dedup witnesses behind
 * their own accordion have to render identically — two copies of this markup
 * would drift apart the first time either side gained a column.
 */
function AlertRow({
  event,
  observationIndex,
  onExcludeAlert,
}: {
  event: CandidateTimelineEvent;
  observationIndex: Map<string, CandidateObservation>;
  onExcludeAlert?: (alertId: string) => void;
}) {
  return (
    <tr className="hover:bg-dark-40/40">
      <td className="whitespace-nowrap px-4 py-2 font-mono text-[11px] text-gray-400">
        {safeFormat(event.time, 'MMM d, HH:mm')}
      </td>
      <td className="max-w-[420px] px-4 py-2 align-top">
        <AlertLink
          alertId={event.alert_id}
          title={event.title}
          payloadTitle={event.payload_title}
        />
        {event.deduplicated && (
          <span
            className="mt-1 inline-flex items-center gap-1 rounded border border-violet-500/30 bg-violet-500/10 px-1 py-0.5 text-[9px] uppercase tracking-wide text-violet-300"
            title="Soft-deduplicated evidence: still a case witness and still scored, but hidden from the Alerts workbench. The canonical alert is the one it was merged into."
          >
            {'deduplicated'}
            {event.occurrence_count && event.occurrence_count > 1
              ? ` ×${event.occurrence_count}`
              : ''}
          </span>
        )}
      </td>
      <td className="px-4 py-2">
        <span className="flex items-center gap-1.5 text-xs text-gray-300">
          <span
            className={clsx(
              'h-1.5 w-1.5 rounded-full',
              SEVERITY_DOT[event.severity ?? ''] ?? 'bg-gray-500'
            )}
          />
          {event.severity ?? '—'}
        </span>
      </td>
      <td className="hidden max-w-[220px] truncate px-4 py-2 font-mono text-[10px] text-gray-500 lg:table-cell">
        {observationIndex.get(event.observation_key ?? '')?.role ??
          event.observation_key ??
          '—'}
      </td>
      <td className="px-4 py-2 text-right">
        {onExcludeAlert && (
          <button
            type="button"
            onClick={() => onExcludeAlert(event.alert_id)}
            title="Drop this alert from the correlation analysis. It stays case evidence; the graph, timeline and scores are recomputed without it."
            className="rounded border border-[#374151] px-1.5 py-0.5 text-[11px] text-gray-400 transition-colors hover:border-rose-500/60 hover:text-rose-200"
          >
            Exclude
          </button>
        )}
      </td>
    </tr>
  );
}

export function CorrelationInspectModal({
  detail,
  loading,
  onClose,
  eyebrow,
  eyebrowNote = null,
  title = null,
  subtitle = null,
  caseId = null,
  actions = null,
  scope,
  onScopeChange,
  allowScopeEditing = true,
  onExcludeAlert,
  emptyMessage = 'The correlation payload could not be loaded. The API may be unavailable, or the alerts behind this item are no longer visible.',
  observationMode,
  onToggleObservationMode,
}: CorrelationInspectModalProps) {
  // The body below was written for the candidate surface and reads `candidate`
  // throughout; keeping the alias means one implementation, not two that drift.
  const candidate = detail;
  const [activeTab, setActiveTab] = useState<Tab>('graph');
  // Evidence is open by default but can be closed on any screen size, not just
  // hidden below the xl breakpoint.
  const [railOpen, setRailOpen] = useState(true);
  // The filter builder lives in the scope bar, but its toggle sits in the tab
  // row: the right side of that row repeated the tab counts and the span, which
  // is the space a control actually worth clicking should use.
  const [scopeOpen, setScopeOpen] = useState(false);
  // Soft-dedup witnesses are copies of alerts the workbench already shows once —
  // the same set the TKG attribution table hides behind its `dedup hidden` chip.
  // They stay in the scores (they are case evidence), but 89 copies of one alert
  // drown a graph of nine real actions, so the default view leaves them out.
  const [hideDedup, setHideDedup] = useState(true);
  // The dedup rows still exist one click away: an accordion under the table, not
  // a separate tab and not a hidden count.
  const [dedupOpen, setDedupOpen] = useState(false);

  // The rail is the first thing an analyst wants when the modal opens, so it
  // shows itself — then steps aside after a few seconds so the graph gets the
  // width back. The timer runs at every viewport size: it used to be gated on a
  // narrow window, so on a normal desktop the Evidence button never switched
  // itself off and looked stuck. Clicking Evidence pins the rail and cancels the
  // auto-hide — a deliberate click must not be undone a second later.
  const railPinned = useRef(false);
  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (!railPinned.current) setRailOpen(false);
    }, RAIL_AUTO_HIDE_MS);
    return () => window.clearTimeout(timer);
  }, []);
  const toggleRail = () => {
    railPinned.current = true;
    setRailOpen((value) => !value);
  };
  // Expand / focus / hide live in the canvas; the rail drives them by handle.
  const graphRef = useRef<CandidateGraphHandle | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [focusId, setFocusId] = useState<string | null>(null);
  // How many neighbour layers the Expand button has revealed for the node the
  // inspector is showing. Reset whenever a different node is opened.
  const [expandDepth, setExpandDepth] = useState(0);
  const [selectedNode, setSelectedNode] = useState<CandidateGraphNode | null>(null);
  // The node inspector is opt-in: on a crowded campaign it eats a third of the
  // modal for information the analyst often does not need. The graph can auto-
  // open it when Auto Details is enabled, but an entity/cluster row only selects
  // unless the analyst deliberately opens the details for that row.
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [autoDetailsEnabled, setAutoDetailsEnabled] = useState(false);
  // Moving to another leaf starts its own inspection: the layers expanded
  // around the previous node are forgotten, so Expand never appears stuck.
  useEffect(() => {
    graphRef.current?.resetExpansion();
    setExpandDepth(0);
  }, [selectedNode]);

  // The graph, its toolbar *and* the ATT&CK / kill-chain strip are one panel.
  // Maximise targets the panel rather than the canvas: a dense campaign does not
  // fit the modal, but dropping the coverage strip on the way to full screen
  // would trade one blind spot for another. 'native' = Fullscreen API,
  // 'css' = overlay fallback, 'off' = inline.
  const graphPanelRef = useRef<HTMLDivElement>(null);
  const [graphFullscreen, setGraphFullscreen] = useState<'off' | 'native' | 'css'>('off');
  const graphMaximised = graphFullscreen !== 'off';

  // Reset the view whenever a different candidate is opened — otherwise the
  // graph selection of the previous candidate leaks into the next one.
  // Adjusting state during render (rather than in an effect) is the pattern
  // React recommends for "prop changed → reset derived UI state".
  const [renderedKey, setRenderedKey] = useState(candidate?.candidate_key);
  if (candidate?.candidate_key !== renderedKey) {
    setRenderedKey(candidate?.candidate_key);
    setActiveTab('graph');
    setSelectedNode(null);
    setSelectedEdgeId(null);
    setFocusId(null);
  }

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      // Esc leaves full screen first; closing the whole workbench because the
      // analyst wanted their sidebar back would lose their place.
      if (event.key === 'Escape' && !graphMaximised) onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose, graphMaximised]);

  useEffect(() => {
    const onFullscreenChange = () => {
      const panel = graphPanelRef.current;
      const active = panel !== null && document.fullscreenElement === panel;
      setGraphFullscreen((current) => {
        if (active) return 'native';
        return current === 'native' ? 'off' : current;
      });
    };
    document.addEventListener('fullscreenchange', onFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', onFullscreenChange);
  }, []);

  useEffect(() => {
    if (graphFullscreen !== 'css') return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setGraphFullscreen('off');
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [graphFullscreen]);

  // Cytoscape resizes itself, but a bigger viewport needs a re-fit or the
  // analyst lands on the fragment that happened to be centred.
  useEffect(() => {
    if (!graphMaximised) return;
    const timer = window.setTimeout(() => graphRef.current?.fit(), 280);
    return () => window.clearTimeout(timer);
  }, [graphMaximised]);

  const toggleGraphFullscreen = () => {
    const panel = graphPanelRef.current;
    if (!panel) return;

    if (graphFullscreen !== 'off') {
      if (document.fullscreenElement === panel) {
        void document.exitFullscreen().catch(() => undefined);
      }
      setGraphFullscreen('off');
      return;
    }

    // Optimistic: some Chromium embeddings return a `requestFullscreen()`
    // promise that never settles, so awaiting it left the button looking dead.
    // Assume native and downgrade to the overlay when the document never
    // actually became full screen.
    setGraphFullscreen('native');
    const request = panel.requestFullscreen?.();
    if (request) void request.catch(() => setGraphFullscreen('css'));
    window.setTimeout(() => {
      if (document.fullscreenElement !== panel) {
        setGraphFullscreen((current) => (current === 'native' ? 'css' : current));
      }
    }, 320);
  };

  const breakdown = candidate?.score_breakdown ?? null;
  const observations = candidate?.observations ?? [];
  const timeline = candidate?.timeline ?? [];
  // Alerts the analyst excluded are gone from the scoped timeline, so without
  // this the row simply vanished and there was nothing left to put back. The
  // server echo keeps the id and the alert title, which is enough to list the
  // row as excluded and offer Restore.
  const excludedAlertRows = useMemo(() => {
    const excluded = new Set(scope.excluded_alert_ids);
    const shown = new Set(timeline.map((event) => event.alert_id));
    return (candidate?.scope?.dropped ?? []).filter(
      (item) => excluded.has(item.alert_id) && !shown.has(item.alert_id)
    );
  }, [candidate, scope.excluded_alert_ids, timeline]);
  const pairScores = candidate?.pair_scores ?? [];
  const rulesDict = candidate?.rules ?? {};
  const ruleEntries = Object.entries(rulesDict);
  // Rule → the evidence alerts that carry it, resolved before the scope. It is
  // what lets a rule be excluded as a unit and then listed again for restore.
  const ruleAlertIds = useMemo(
    () => new Map(Object.entries(candidate?.rule_alert_ids ?? {})),
    [candidate]
  );
  const excludedAlertIdSet = useMemo(() => new Set(scope.excluded_alert_ids), [scope.excluded_alert_ids]);
  const excludedRuleEntries = useMemo(
    () =>
      [...ruleAlertIds.entries()].filter(
        ([rule, ids]) =>
          ids.length > 0 &&
          ids.every((id) => excludedAlertIdSet.has(id)) &&
          !(rule in rulesDict)
      ),
    // `rulesDict` is rebuilt from the payload on every fetch.
    [ruleAlertIds, excludedAlertIdSet, rulesDict]
  );
  // ``score_breakdown.l1/l2/l3`` are sums over every scored pair, so they can
  // read like a per-pair value that breaks the documented cap ("L1 capped at
  // 18" next to 92). The explainer therefore shows the strongest pair's own
  // L1/L2/L3 — the link that actually decided the campaign — and keeps the
  // totals on one labelled line.
  const peakPair = useMemo(
    () =>
      pairScores.reduce<CandidatePairScore | null>(
        (best, pair) => (!best || pair.score > best.score ? pair : best),
        null
      ),
    [pairScores]
  );
  const graph = candidate?.graph ?? null;

  // Which alerts are soft-dedup witnesses, which observations are nothing but
  // witnesses, and the two projections the switch picks between. The graph is
  // drawn from `displayGraph`, so the toggle changes the canvas itself rather
  // than a legend next to it.
  const dedupAlertIds = useMemo(
    () => new Set(timeline.filter((event) => event.deduplicated).map((event) => event.alert_id)),
    [timeline]
  );
  const dedupObservationKeys = useMemo(() => {
    const keys = new Set<string>();
    for (const observation of observations) {
      const ids = observation.alert_ids ?? [];
      // A mixed observation (one canonical alert plus witnesses) is still a real
      // action: only all-witness observations are hidden.
      if (
        observation.observation_key &&
        ids.length > 0 &&
        ids.every((id) => dedupAlertIds.has(id))
      ) {
        keys.add(observation.observation_key);
      }
    }
    return keys;
  }, [observations, dedupAlertIds]);
  const dedupCount = dedupAlertIds.size;
  const primaryTimeline = useMemo(
    () => timeline.filter((event) => !dedupAlertIds.has(event.alert_id)),
    [timeline, dedupAlertIds]
  );
  const dedupTimeline = useMemo(
    () => timeline.filter((event) => dedupAlertIds.has(event.alert_id)),
    [timeline, dedupAlertIds]
  );
  // What the table shows: the canonical rows normally, everything when the
  // toggle is off. The dedup rows never leave the map — they move into the
  // accordion below the table.
  const shownTimeline = hideDedup ? primaryTimeline : timeline;
  const displayGraph = useMemo(() => {
    if (!graph || !hideDedup || dedupObservationKeys.size === 0) return graph;
    const hiddenNodeIds = new Set(
      graph.nodes
        .filter((node) => node.observation_key && dedupObservationKeys.has(node.observation_key))
        .map((node) => node.id)
    );
    const edges = graph.edges.filter((edge) => {
      if (hiddenNodeIds.has(edge.source) || hiddenNodeIds.has(edge.target)) return false;
      // Edge mode draws an observation as a relation, not a hub: the edge carries
      // the observation keys it stands for.
      const keys = edge.observations ?? [];
      return !(keys.length > 0 && keys.every((key) => dedupObservationKeys.has(key)));
    });
    const used = new Set<string>();
    for (const edge of edges) {
      used.add(edge.source);
      used.add(edge.target);
    }
    // A shared key left without any live observation is noise on the canvas.
    const nodes = graph.nodes.filter(
      (node) => !hiddenNodeIds.has(node.id) && used.has(node.id)
    );
    return { ...graph, nodes, edges };
  }, [graph, hideDedup, dedupObservationKeys]);

  // The canvas draws every key as a node — hosts, users, domains and process
  // GUIDs. The payload's `entities` buckets carry only the first three, so the
  // rail used to report 19 entities over a canvas showing 45. One number for
  // both: what the graph draws, minus the observations.
  const graphEntityCount = displayGraph
    ? displayGraph.nodes.filter((node) => node.kind !== 'observation').length
    : Object.values(candidate?.entities ?? {}).reduce(
        (total, values) => total + values.length,
        0
      );
  // Processes are drawn as graph nodes but are not "shared identities" (they
  // never score L1), so the rail lists 19 while the canvas draws 45.
  const processNodeCount = displayGraph
    ? displayGraph.nodes.filter((node) => node.kind === 'process_guid').length
    : 0;
  const evidenceAlertCount = candidate?.alert_count ?? 0;
  const memberAlertCount = candidate?.member_alert_count || evidenceAlertCount;
  // Observations only carry alert ids; the timeline carries their titles. An
  // id lookup lets the Observations tab link each alert the same way the Alerts
  // table does.
  const alertIndex = useMemo(() => {
    const index = new Map<string, CandidateTimelineEvent>();
    for (const event of candidate?.timeline ?? []) index.set(event.alert_id, event);
    return index;
  }, [candidate]);
  const selectedEdge: CandidateGraphEdge | null =
    displayGraph?.edges.find((edge) => edge.id === selectedEdgeId) ?? null;
  const observationIndex = useMemo(
    () =>
      new Map(
        (candidate?.observations ?? []).map((observation) => [
          observation.observation_key,
          observation,
        ])
      ),
    [candidate]
  );
  // A pair link only exists for CORRELATION edges; entity links have no score.
  const selectedPair = selectedEdge
    ? pairScores.find(
        (pair) =>
          selectedEdge.id === `obs:${pair.source}~obs:${pair.target}` ||
          selectedEdge.id === `obs:${pair.target}~obs:${pair.source}`
      ) ?? null
    : null;

  // Node inspector support: which observation a selected node stands for, and
  // (when a pair link is also selected) which of its keys are the ones the two
  // actions actually share — the evidence behind the L1 number.
  const nodeObservation = selectedNode?.observation_key
    ? observationIndex.get(selectedNode.observation_key) ?? null
    : null;
  const pairPartner =
    selectedPair && nodeObservation
      ? selectedPair.source === nodeObservation.observation_key
        ? selectedPair.target
        : selectedPair.target === nodeObservation.observation_key
          ? selectedPair.source
          : null
      : null;
  const sharedWithSelection = new Set<string>(
    selectedPair && pairPartner
      ? (selectedPair.matched ?? []).map((value) => `${value.kind}:${value.value}`)
      : []
  );
  // The selected link, resolved to the two graph nodes it joins. A pair link
  // joins two observations; a key link joins one observation to the value both
  // actions share, which is the "why" behind the grouping.
  const graphNodes = useMemo(() => {
    const index = new Map<string, CandidateGraphNode>();
    for (const node of displayGraph?.nodes ?? []) index.set(node.id, node);
    return index;
  }, [displayGraph]);
  // Other observations touching the same key (key links only), so the panel can
  // show the full fan-out of a shared host/user/hash instead of just one hop.
  const selectedEdgeSiblings = useMemo(() => {
    if (!selectedEdge || selectedEdge.kind === 'CORRELATION') return [];
    const entityId =
      selectedEdge.source.startsWith('obs:') ? selectedEdge.target : selectedEdge.source;
    return (graph?.edges ?? [])
      .filter(
        (edge) =>
          edge.kind === selectedEdge.kind &&
          edge.id !== selectedEdge.id &&
          (edge.target === entityId || edge.source === entityId)
      )
      .map((edge) => graphNodes.get(edge.source === entityId ? edge.target : edge.source))
      .filter((node): node is CandidateGraphNode => Boolean(node));
  }, [selectedEdge, graph, graphNodes]);

  // Which observations contributed a selected entity/hash/GUID node.
  const contributing = selectedNode
    ? (graph?.edges ?? [])
        .filter(
          (edge) =>
            edge.target === selectedNode.id &&
            edge.source.startsWith('obs:') &&
            edge.kind !== 'CORRELATION'
        )
        .map((edge) => ({
          key: edge.source.slice('obs:'.length),
          kind: edge.kind,
          weight: edge.weight ?? 1,
        }))
    : [];

  // One chip per role, not per observation: a host touched by sixty spray
  // observations used to render sixty identical "credential_access:spray ×2"
  // chips. The count and the summed weight are what the analyst wants to see.
  const contributingGroups = (() => {
    const groups = new Map<string, { label: string; weight: number; count: number }>();
    for (const edge of contributing) {
      const label = observationIndex.get(edge.key)?.role ?? edge.key;
      const entry = groups.get(label);
      if (entry) {
        entry.weight += edge.weight;
        entry.count += 1;
      } else {
        groups.set(label, { label, weight: edge.weight, count: 1 });
      }
    }
    return [...groups.values()].sort(
      (a, b) => b.count - a.count || b.weight - a.weight || a.label.localeCompare(b.label)
    );
  })();

  // A load that produced nothing must say so: a silent `null` leaves the button
  // that opened this dialog looking broken.
  if (!candidate && !loading) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-3 backdrop-blur-sm sm:p-5">
        <div
          role="dialog"
          aria-modal="true"
          aria-label={`${eyebrow} unavailable`}
          className="w-full max-w-md rounded-2xl border border-[#374151]/70 bg-dark-60 p-6"
        >
          <h2 className="text-sm font-semibold text-gray-100">{eyebrow} unavailable</h2>
          <p className="mt-2 text-xs leading-relaxed text-gray-400">{emptyMessage}</p>
          <div className="mt-4 flex justify-end">
            <button
              onClick={onClose}
              className="rounded-lg border border-gray-500/30 bg-gray-500/10 px-3 py-1.5 text-sm font-medium text-gray-300 transition-colors hover:bg-gray-500/20"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    );
  }

  const focusEntity = (kind: string, value: string) => {
    setActiveTab('graph');
    setFocusId(`${kind}:${value}`);
  };

  const tabs: Array<{ id: Tab; label: string; count?: number }> = [
    { id: 'graph', label: 'Graph', count: displayGraph?.nodes.length },
    { id: 'timeline', label: 'Timeline', count: timeline.length },
    { id: 'observations', label: 'Observations', count: observations.length },
    { id: 'alerts', label: 'Alerts', count: candidate?.alert_count },
    { id: 'rules', label: 'Rules', count: Object.keys(candidate?.rules ?? {}).length },
  ];

  // The per-entity timeline follows the inspected node, not the entity list's
  // last active row, so clicking a leaf on the canvas updates both surfaces at
  // once instead of leaving the card on the previous entity.
  const entityDetail = useMemo(() => {
    if (!selectedNode || selectedNode.kind === 'observation') return null;
    return {
      label: selectedNode.label,
      kind: KIND_LABEL[selectedNode.kind] ?? selectedNode.kind,
      timeline: buildEntityTimeline(
        {
          id: selectedNode.id,
          kind: selectedNode.kind,
          label: selectedNode.label,
          token: selectedNode.token ?? null,
        },
        observations,
        candidate?.timeline ?? []
      ),
    };
  }, [selectedNode, observations, candidate?.timeline]);

  // `flex`/`fixed` and `h-full`/`inset-2` are competing utilities and the
  // stylesheet — not the class order — decides; emitting only one variant of
  // each keeps the maximised panel filling the viewport instead of collapsing.
  const graphPanel = (
    <div
      ref={graphPanelRef}
      className={
        graphFullscreen === 'css'
          ? 'fixed inset-2 z-[70] flex min-h-0 flex-col overflow-hidden rounded-lg border border-[#374151] bg-[#0b1220] shadow-2xl'
          : 'flex h-full min-h-0 flex-col'
      }
    >
      {/* The canvas gets its own flexible box: the component's root is `h-full`,
          so handing it the panel directly would size it to the whole panel and
          push the inspector strip past the bottom edge, where it was clipped. */}
      <div className="flex min-h-0 min-w-0 flex-1">
        <CandidateGraphView
          ref={graphRef}
          graph={displayGraph}
          focusId={focusId}
          onSelectNode={(node, source) => {
            setSelectedNode(node);
            if (!node) {
              setDetailsOpen(false);
              return;
            }
            // Auto-open follows the separate Auto Details preference. The explicit
            // D action in the row remains the only override that forces the panel
            // open while the preference stays off.
            if (source === 'canvas' || source === 'list') {
              setDetailsOpen(autoDetailsEnabled);
            }
          }}
          onSelectEdge={setSelectedEdgeId}
          selectedEdgeId={selectedEdgeId}
          onToggleFullscreen={toggleGraphFullscreen}
          fullscreenActive={graphMaximised}
          observationMode={observationMode ?? displayGraph?.observation_mode}
          onToggleObservationMode={onToggleObservationMode}
          onToggleDetails={() => setAutoDetailsEnabled((value) => !value)}
          onOpenDetails={(id) => {
            const node = graph?.nodes.find((candidate) => candidate.id === id) ?? null;
            setSelectedNode(node);
            setDetailsOpen(Boolean(node));
          }}
          detailsOpen={autoDetailsEnabled}
          viewStore={caseId ? { caseId } : undefined}
          onClearFocus={() => setFocusId(null)}
          onFocusRestore={(id) => {
            // Undo/Redo and saved views restore the focus together with the
            // hidden set, so the Unfocus button has to follow them.
            setFocusId(id);
            setExpandDepth(id ? (graphRef.current?.expandDepthOf(id) ?? 0) : 0);
          }}
          hasSelectedNode={Boolean(selectedNode)}
          timeline={candidate?.timeline}
          observations={candidate?.observations}
          className="min-h-0 min-w-0 flex-1"
        />
      </div>

      {/* Footer panels in both normal and fullscreen modes. `shrink-0` keeps the
          selected node/edge readable in full screen, and the cap turns a tall
          inspector into a scroll area instead of letting it eat the canvas. */}
      <div
        className={clsx(
          'flex shrink-0 flex-col',
          graphMaximised && 'max-h-[46vh] overflow-y-auto'
        )}
      >
        <AttackCoverageStrip
          observations={observations}
          fallbackTechniques={candidate?.techniques ?? []}
        />
        
        {/* Info panels - Edge Inspector */}
        {selectedEdge && (
          <EdgeInspector
            edge={selectedEdge}
            pair={selectedPair}
            nodes={graphNodes}
            siblings={selectedEdgeSiblings}
            onDismiss={() => setSelectedEdgeId(null)}
            onFocus={(nodeId) => {
              setFocusId(nodeId);
              graphRef.current?.focusNode(nodeId);
            }}
            onHide={(nodeId) => graphRef.current?.hideNode(nodeId)}
          />
        )}
        
        {/* Info panels - Node Inspector */}
        {selectedNode && detailsOpen && (
          <div className="flex max-h-[38vh] min-h-0 items-stretch gap-3 overflow-hidden border-t border-[#374151]/60 bg-dark-70 px-5 py-3">
            {/* The entity's alert timeline is part of this selection, so it sits
                beside the inspector: floating over the canvas it covered the
                graph it was describing, and — driven by the list's active row —
                it kept showing the previous entity after the analyst clicked a
                different node. */}
            {entityDetail && (
              <div className="w-[50%] min-w-0 max-w-[50%] shrink-0 overflow-y-auto pr-2">
                <EntityDetailCard
                  detail={entityDetail}
                  onClose={() => setSelectedNode(null)}
                />
              </div>
            )}
            <div
              id="candidate-node-inspector"
              className="min-h-0 min-w-0 flex-1 overflow-y-auto pr-1"
            >
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
              <span
                className={clsx(
                  'rounded px-1.5 py-0.5 text-[11px]',
                  selectedNode.kind === 'observation'
                    ? 'bg-rose-500/10 text-rose-300'
                    : 'bg-dark-40 text-gray-300'
                )}
              >
                {selectedNode.kind}
              </span>
              <span className="font-mono text-gray-200">{selectedNode.label}</span>
              {typeof selectedNode.alert_count === 'number' && selectedNode.alert_count > 0 && (
                <span className="text-gray-500">{selectedNode.alert_count} alerts</span>
              )}
              {(selectedNode.techniques ?? []).map((technique) => (
                <span key={technique} className="text-[11px] text-red-300">
                  {technique}
                </span>
              ))}
              {selectedNode.observation_key && (
                <span className="break-all font-mono text-[10px] text-gray-500">
                  {selectedNode.observation_key}
                </span>
              )}
              <div className="ml-auto flex items-center gap-1.5">
                {/* Same command as the one floating on the canvas: the analyst
                    is looking at the canvas from here, so the framing control
                    belongs here too. */}
                <button
                  type="button"
                  onClick={() => graphRef.current?.fit()}
                  title="Frame every drawn node in the view, exactly as the Fit button on the canvas does."
                  className="rounded border border-[#374151] px-1.5 py-0.5 text-[11px] text-gray-300 transition-colors hover:border-teal-500/60 hover:text-teal-200"
                >
                  Fit
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setExpandDepth(graphRef.current?.expandNode(selectedNode.id) ?? 0)
                  }
                  disabled={expandDepth >= MAX_EXPAND_LAYERS}
                  title={
                    expandDepth === 0
                      ? 'Draw every node this one links to, even where the neighbour budget is hiding them. Click again for the next layer.'
                      : expandDepth >= MAX_EXPAND_LAYERS
                        ? `All ${MAX_EXPAND_LAYERS} layers around this node are on screen.`
                        : `One layer drawn. Click again to add the next one (up to ${MAX_EXPAND_LAYERS}).`
                  }
                  className="rounded border border-[#374151] px-1.5 py-0.5 text-[11px] text-gray-300 transition-colors hover:border-teal-500/60 hover:text-teal-200 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {expandDepth === 0
                    ? 'Expand'
                    : `Expand ${expandDepth} layer${expandDepth === 1 ? '' : 's'}`}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    // Focus also centres the node: hiding the rest used to leave
                    // the camera wherever the entity list had put it, so the
                    // leaf the analyst just clicked stayed off screen.
                    graphRef.current?.resetExpansion();
                    setExpandDepth(0);
                    setFocusId(selectedNode.id);
                    graphRef.current?.focusNode(selectedNode.id);
                  }}
                  title="Keep this node and its direct neighbours, hide the rest of the canvas, and centre it in the view."
                  className="rounded border border-[#374151] px-1.5 py-0.5 text-[11px] text-gray-300 transition-colors hover:border-teal-500/60 hover:text-teal-200"
                >
                  Focus
                </button>
                {focusId && (
                  <button
                    type="button"
                    onClick={() => {
                      setFocusId(null);
                      setExpandDepth(0);
                      graphRef.current?.unfocus();
                    }}
                    title="Undo Focus: bring back the nodes it hid and fit the graph again."
                    className="rounded border border-[#374151] px-1.5 py-0.5 text-[11px] text-teal-200 transition-colors hover:border-teal-500/60"
                  >
                    Unfocus
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => graphRef.current?.hideNode(selectedNode.id)}
                  title="Remove this node (and its links) from the view. The graph toolbar's show all brings it back."
                  className="rounded border border-[#374151] px-1.5 py-0.5 text-[11px] text-gray-300 transition-colors hover:border-rose-500/60 hover:text-rose-200"
                >
                  Hide
                </button>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-[11px] text-gray-500 hover:text-gray-300"
                >
                  Dismiss
                </button>
              </div>
            </div>

            {selectedNode.kind !== 'observation' && selectedNode.token && (
              <p className="mt-1 break-all font-mono text-[10px] text-gray-500">
                {selectedNode.token}
              </p>
            )}

            {selectedNode.kind === 'observation' && (
              <div className="mt-2 flex flex-wrap items-center gap-1">
                <span className="text-[10px] uppercase tracking-wide text-gray-600">
                  keys
                </span>
                {(nodeObservation?.tokens ?? []).length === 0 && (
                  <span className="text-[10px] text-gray-500">
                    no persisted keys — the engine has not refreshed this observation yet
                  </span>
                )}
                {(nodeObservation?.tokens ?? []).map((token) => {
                  const shared = sharedWithSelection.has(token.token);
                  return (
                    <span
                      key={token.token}
                      title={`${token.token} → +${token.weight} to L1${
                        token.estimated ? ' (estimated: row predates weighting)' : ''
                      }${shared ? ' — shared with the other side of the selected link' : ''}`}
                      className={clsx(
                        'rounded px-1 py-0.5 font-mono text-[10px]',
                        shared
                          ? 'bg-teal-500/15 text-teal-200 ring-1 ring-teal-500/40'
                          : 'bg-dark-40 text-gray-300'
                      )}
                    >
                      {token.kind}:{token.value}
                      <span className="ml-1 text-gray-500">×{token.weight}</span>
                    </span>
                  );
                })}
              </div>
            )}

            {selectedNode.kind !== 'observation' && contributing.length > 0 && (
              <div className="mt-2">
                <span className="text-[10px] uppercase tracking-wide text-gray-600">
                  contributed by · {contributingGroups.length} role
                  {contributingGroups.length === 1 ? '' : 's'} · {contributing.length}{' '}
                  observation{contributing.length === 1 ? '' : 's'}
                </span>
                {/* A hub can be contributed to by hundreds of observations; the
                    list used to push the graph out of the modal. It scrolls
                    inside a capped box instead. */}
                <div className="mt-1 flex max-h-[72px] flex-wrap content-start gap-1 overflow-y-auto pr-1">
                  {contributingGroups.map((group) => (
                    <span
                      key={group.label}
                      title={`${group.label} — ${group.count} observation${
                        group.count === 1 ? '' : 's'
                      }, +${group.weight} to L1 in total`}
                      className="rounded bg-dark-40 px-1 py-0.5 text-[10px] text-gray-300"
                    >
                      {group.label}
                      <span className="ml-1 text-gray-500">×{group.weight}</span>
                      {group.count > 1 && (
                        <span className="ml-1 text-gray-600">· {group.count}</span>
                      )}
                    </span>
                  ))}
                </div>
              </div>
            )}
            </div>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-3 backdrop-blur-sm sm:p-5">
      <div
        role="dialog"
        aria-modal="true"
        aria-label={
          candidate ? `${eyebrow} — ${title ?? humanizeTheme(candidate.campaign_theme)}` : eyebrow
        }
        className="flex h-[92vh] w-[97vw] max-w-[1560px] flex-col overflow-hidden rounded-2xl border border-[#374151]/70 bg-dark-60 shadow-2xl"
      >
        {/* ── Header ─────────────────────────────────────────────────────── */}
        <header className="flex items-start justify-between gap-4 border-b border-[#374151]/60 bg-dark-70 px-6 py-3">
          <div className="min-w-0">
            {loading ? (
              <div className="h-6 w-72 animate-pulse rounded bg-dark-40" />
            ) : (
              <>
                {/* The identity sits on the eyebrow row instead of on its own line:
                    one header line saved is ~16px of canvas, and the key is short
                    enough to read beside the kind badge. Full key in the tooltip. */}
                <div className="flex min-w-0 items-center gap-2">
                  <span className="shrink-0 rounded border border-teal-500/30 bg-teal-500/10 px-2 py-0.5 text-[11px] font-medium text-teal-300">
                    {eyebrow}
                  </span>
                  {eyebrowNote && (
                    <span className="shrink-0 text-[11px] text-gray-500">{eyebrowNote}</span>
                  )}
                  <span
                    className="min-w-0 truncate font-mono text-[11px] text-gray-500"
                    title={subtitle ?? candidate!.candidate_key}
                  >
                    {(subtitle ?? candidate!.candidate_key).replace(/^case:/, '')}
                  </span>
                </div>
                <h2 className="mt-1.5 truncate text-lg font-semibold text-gray-100">
                  {title ?? humanizeTheme(candidate!.campaign_theme)}
                </h2>
              </>
            )}
          </div>

          <div className="flex shrink-0 flex-wrap items-center justify-end gap-4">
            {candidate && (
              <>
                <div className="text-right" title="Peak pair score: strongest single link (L1+L2+L3) that joined the observations — same formula the engine used">
                  <p className="text-[11px] uppercase tracking-wide text-gray-500">Peak link</p>
                  <p className="text-2xl font-semibold tabular-nums text-orange-400">
                    {candidate.score}
                    <span className="ml-1 text-xs font-normal text-gray-500">
                      / θ {breakdown?.theta ?? 3}
                    </span>
                  </p>
                </div>
                {candidate.severity && (
                  <span className="flex items-center gap-1.5 rounded border border-[#374151] px-2 py-1 text-xs text-gray-300">
                    <span
                      className={clsx(
                        'h-1.5 w-1.5 rounded-full',
                        SEVERITY_DOT[candidate.severity] ?? 'bg-gray-400'
                      )}
                    />
                    {candidate.severity.charAt(0).toUpperCase() + candidate.severity.slice(1)}
                  </span>
                )}
              </>
            )}
            {/* The rail used to appear only at xl width; on a narrow screen the
                evidence existed but could not be opened at all. */}
            {!loading && candidate && (
              <button
                type="button"
                onClick={toggleRail}
                aria-pressed={railOpen}
                aria-expanded={railOpen}
                aria-controls="candidate-evidence-rail"
                title={
                  railOpen
                    ? 'Hide the evidence rail (member counts, why these alerts form one campaign, shared entities)'
                    : 'Show the evidence rail'
                }
                className={clsx(
                  'rounded border px-2 py-1 text-xs transition-colors',
                  railOpen
                    ? 'border-teal-500/40 bg-teal-500/10 text-teal-200'
                    : 'border-[#374151] text-gray-400 hover:border-gray-500'
                )}
              >
                Evidence
              </button>
            )}
            {actions && (
              <div className="flex items-center gap-2 border-l border-[#374151]/60 pl-3">
                {actions}
              </div>
            )}
            <button
              onClick={onClose}
              aria-label="Close"
              className="rounded-md p-1.5 text-gray-400 transition-colors hover:bg-dark-40 hover:text-gray-200"
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </header>

        {/* ── Body ───────────────────────────────────────────────────────── */}
        <div className="flex min-h-0 min-w-0 flex-1">
          {/* Left rail — the evidence, always visible */}
          {!loading && candidate && (
            <aside
              id="candidate-evidence-rail"
              className={clsx(
                'shrink-0 overflow-y-auto border-r border-[#374151]/60',
                railOpen ? 'w-[300px] xl:w-[340px]' : 'hidden'
              )}
            >
              <div className="grid grid-cols-2 divide-x divide-y divide-[#374151]/40 border-b border-[#374151]/60 text-sm">
                <div className="px-4 py-3">
                  <p className="text-[11px] text-gray-500">Member alerts</p>
                  <p className="text-lg font-semibold tabular-nums text-gray-200">
                    {memberAlertCount}
                  </p>
                  {evidenceAlertCount > memberAlertCount && (
                    <p
                      className="text-[10px] text-violet-300/80"
                      title="Soft-deduplicated losers whose canonical alert is a member: they are scored evidence, not separate members."
                    >
                      +{evidenceAlertCount - memberAlertCount} dedup evidence
                    </p>
                  )}
                </div>
                <div className="px-4 py-3">
                  <p className="text-[11px] text-gray-500">Observations</p>
                  <p className="text-lg font-semibold tabular-nums text-gray-200">
                    {observations.length}
                  </p>
                </div>
                <div className="px-4 py-3">
                  <p className="text-[11px] text-gray-500">Time span</p>
                  <p className="text-lg font-semibold text-gray-200">
                    {formatSpan(candidate.time_first, candidate.time_last)}
                  </p>
                </div>
                <div className="px-4 py-3">
                  <p
                    className="text-[11px] text-gray-500"
                    title="Every node the graph draws, including process GUIDs."
                  >
                    Entities
                  </p>
                  <p className="text-lg font-semibold tabular-nums text-gray-200">
                    {graphEntityCount}
                  </p>
                </div>
              </div>

              <section className="border-b border-[#374151]/60 px-4 py-4">
                <h3 className="text-xs font-medium text-gray-400">Why these alerts are one campaign</h3>
                <dl className="mt-3 space-y-2 text-xs">
                  <div className="flex items-baseline justify-between gap-2">
                    <dt className="text-gray-400">
                      L1 · shared keys
                      <span className="block text-[10px] text-gray-600">
                        strongest pair&apos;s weighted sum of shared hosts, users, IPs, hashes — capped
                        at 18
                      </span>
                    </dt>
                    <dd className="tabular-nums text-gray-200">{peakPair?.l1 ?? '—'}</dd>
                  </div>
                  <div className="flex items-baseline justify-between gap-2">
                    <dt className="text-gray-400">
                      L2 · campaign progression
                      <span className="block text-[10px] text-gray-600">
                        same pair: shared analytic story or the next kill-chain step
                      </span>
                    </dt>
                    <dd className="tabular-nums text-gray-200">{peakPair?.l2 ?? '—'}</dd>
                  </div>
                  <div className="flex items-baseline justify-between gap-2">
                    <dt className="text-gray-400">
                      L3 · graph proximity
                      <span className="block text-[10px] text-gray-600">
                        {peakPair && peakPair.l3 === 0
                          ? 'no 3-hop path through a third observation'
                          : '3-hop path through a third observation'}
                      </span>
                    </dt>
                    <dd className="tabular-nums text-gray-200">{peakPair?.l3 ?? '—'}</dd>
                  </div>
                  <div className="flex items-baseline justify-between gap-2 border-t border-[#374151]/40 pt-2">
                    <dt className="font-medium text-gray-300">
                      Peak link
                      <span className="block text-[10px] font-normal text-gray-600">
                        strongest single pair — the number θ gates
                      </span>
                    </dt>
                    <dd className="tabular-nums text-orange-300">
                      {breakdown?.peak_score ?? candidate.score}
                    </dd>
                  </div>
                  <div className="flex items-baseline justify-between gap-2">
                    <dt className="text-gray-300">
                      Evidence total
                      <span className="block text-[10px] text-gray-600">
                        Σ score over {pairScores.length} scored pairs — grows with size
                      </span>
                    </dt>
                    <dd className="tabular-nums text-gray-200">
                      {breakdown?.component_score ?? candidate.evidence_score ?? 0}
                    </dd>
                  </div>
                </dl>
                {breakdown && pairScores.length > 1 && (
                  <p className="mt-2 border-t border-[#374151]/40 pt-2 text-[10px] tabular-nums text-gray-600">
                    Totals across {pairScores.length} pairs: L1 {breakdown.l1} · L2{' '}
                    {breakdown.l2} · L3 {breakdown.l3}
                  </p>
                )}
              </section>

              <section className="border-b border-[#374151]/60 px-4 py-4">
                <div className="flex items-baseline justify-between">
                  <h3 className="text-xs font-medium text-gray-400">Shared identities</h3>
                  <span className="text-[10px] text-gray-600">click to locate</span>
                </div>
                {processNodeCount > 0 && (
                  <p className="mt-1 text-[10px] text-gray-600">
                    {processNodeCount} process node{processNodeCount === 1 ? '' : 's'} are drawn on the
                    graph but do not score identity links, so they are not listed here.
                  </p>
                )}
                <div className="mt-3 space-y-3">
                  {ENTITY_KINDS.map(({ key, kind }) => {
                    const values = candidate.entities?.[key] ?? [];
                    if (values.length === 0) return null;
                    return (
                      <div key={kind}>
                        <p className="text-[10px] uppercase tracking-wide text-gray-600">
                          {kind} · {values.length}
                        </p>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {values.slice(0, 12).map((value) => (
                            <button
                              key={value}
                              onClick={() => focusEntity(kind, value)}
                              title={value}
                              className="max-w-full truncate rounded border border-[#374151]/70 bg-dark-40 px-1.5 py-0.5 font-mono text-[11px] text-gray-300 transition-colors hover:border-teal-500/50 hover:text-teal-200"
                            >
                              {value}
                            </button>
                          ))}
                          {values.length > 12 && (
                            <span className="px-1 py-0.5 text-[11px] text-gray-600">
                              +{values.length - 12}
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                  {Object.values(candidate.entities ?? {}).every((values) => values.length === 0) && (
                    <p className="text-xs text-gray-500">No entities were extracted from these alerts.</p>
                  )}
                </div>
              </section>

              <section className="px-4 py-4">
                <h3 className="text-xs font-medium text-gray-400">
                  Techniques · {candidate.techniques.length}
                </h3>
                <div className="mt-3 flex flex-wrap gap-1">
                  {candidate.techniques.length > 0 ? (
                    candidate.techniques.map((technique) => (
                      <span
                        key={technique}
                        className="rounded border border-red-500/25 bg-red-500/10 px-1.5 py-0.5 text-[11px] font-medium text-red-300"
                      >
                        {technique}
                      </span>
                    ))
                  ) : (
                    <p className="text-xs text-gray-500">No MITRE technique mapped on these alerts.</p>
                  )}
                </div>
              </section>
            </aside>
          )}

          {/* Right pane — tabs */}
          <div className="flex min-w-0 flex-1 flex-col">
            <div className="flex items-center gap-1 border-b border-[#374151]/60 px-4">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  // Without this the accessible name is the label and the count
                  // run together — screen readers announced “Graph54”.
                  aria-label={
                    typeof tab.count === 'number' && tab.count > 0
                      ? `${tab.label} (${tab.count})`
                      : tab.label
                  }
                  className={clsx(
                    'relative -mb-px border-b-2 px-3 py-3 text-sm font-medium transition-colors',
                    activeTab === tab.id
                      ? 'border-brand-500 text-gray-100'
                      : 'border-transparent text-gray-500 hover:text-gray-300'
                  )}
                >
                  {tab.label}
                  {typeof tab.count === 'number' && tab.count > 0 && (
                    <span className="ml-1.5 text-[11px] tabular-nums text-gray-500">{tab.count}</span>
                  )}
                </button>
              ))}

              {/* The summary that used to sit here repeated the tab counts
                  (`Alerts (98)`, `Rules (9)`) and the rail's time span, so it
                  spent the row's only free space on numbers already on screen. */}
              <div className="ml-auto flex items-center gap-1">
                {candidate && dedupCount > 0 && (
                  <button
                    type="button"
                    onClick={() => setHideDedup((current) => !current)}
                    aria-pressed={hideDedup}
                    title="Soft-deduplicated alerts are copies of alerts the workbench already shows once. They still count as evidence in the scores; hiding them drops their observations from the graph and folds their rows into an accordion under the Alerts table."
                    className={clsx(
                      'rounded border px-2 py-1 text-[11px] transition-colors',
                      hideDedup
                        ? 'border-violet-500/40 bg-violet-500/10 text-violet-200'
                        : 'border-[#374151] text-gray-300 hover:border-violet-500/60 hover:text-violet-200'
                    )}
                  >
                    {hideDedup ? 'Dedup hidden' : 'Hide dedup'}{' '}
                    <span className="tabular-nums text-gray-400">{dedupCount}</span>
                  </button>
                )}
                {allowScopeEditing && candidate && (
                  <button
                    type="button"
                    onClick={() => setScopeOpen((open) => !open)}
                    aria-expanded={scopeOpen}
                    title="Narrow the analysis by a llm_payload field, or exclude an alert from the Alerts tab."
                    className={clsx(
                      'rounded border px-2 py-1 text-[11px] transition-colors',
                      scopeOpen
                        ? 'border-teal-500/40 bg-teal-500/10 text-teal-200'
                        : 'border-[#374151] text-gray-300 hover:border-teal-500/60 hover:text-teal-200'
                    )}
                  >
                    Field filter
                  </button>
                )}
              </div>
            </div>

            {allowScopeEditing && candidate && (
              <ScopeBar
                scope={scope}
                applied={candidate.scope ?? null}
                visibleAlerts={candidate.alert_count}
                onChange={onScopeChange}
                open={scopeOpen}
                onOpenChange={setScopeOpen}
                hideToggle
              />
            )}

            {loading ? (
              <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-6">
                {[...Array(5)].map((_, index) => (
                  <div key={index} className="h-16 animate-pulse rounded bg-dark-40" />
                ))}
              </div>
            ) : (
              <div className="min-h-0 flex-1 overflow-hidden">
                {activeTab === 'graph' &&
                  (graphFullscreen === 'css' && typeof document !== 'undefined'
                    ? createPortal(graphPanel, document.body)
                    : graphPanel)}

                {activeTab === 'timeline' && (
                  <div className="h-full overflow-y-auto px-5 py-4">
                    {timeline.length === 0 ? (
                      <p className="text-sm text-gray-500">
                        {eyebrowNote === 'case'
                          ? 'No alert-level timeline for this case.'
                          : 'No alert-level timeline for this candidate.'}
                      </p>
                    ) : (
                      <ol className="relative ml-2 border-l border-[#374151]/60">
                        {timeline.map((event, index) => {
                          const previous = index > 0 ? timeline[index - 1].time : null;
                          const gap = gapLabel(previous, event.time);
                          const role =
                            observations.find(
                              (observation) =>
                                observation.observation_key === event.observation_key
                            )?.role ?? null;
                          return (
                            <li key={`${event.alert_id}-${index}`} className="relative pl-5 pb-4">
                              <span
                                className={clsx(
                                  'absolute -left-[5px] top-1.5 h-2.5 w-2.5 rounded-full ring-2 ring-dark-60',
                                  SEVERITY_DOT[event.severity ?? ''] ?? 'bg-gray-500'
                                )}
                              />
                              {gap && (
                                <p className="mb-1.5 inline-block rounded bg-dark-40 px-1.5 py-0.5 text-[10px] text-gray-500">
                                  {gap} gap
                                </p>
                              )}
                              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                                <span className="font-mono text-[11px] tabular-nums text-gray-400">
                                  {safeFormat(event.time, 'MMM d, HH:mm:ss')}
                                </span>
                                {event.severity && (
                                  <span className="text-[10px] uppercase tracking-wide text-gray-600">
                                    {event.severity}
                                  </span>
                                )}
                                {role && (
                                  <span className="rounded bg-dark-40 px-1.5 py-0.5 text-[10px] text-teal-300">
                                    {role}
                                  </span>
                                )}
                              </div>
                              <div className="mt-0.5 max-w-[520px]">
                                <AlertLink
                                  alertId={event.alert_id}
                                  title={event.title}
                                  payloadTitle={event.payload_title}
                                />
                              </div>
                              <div className="mt-1 flex flex-wrap gap-1">
                                {(event.techniques ?? []).map((technique) => (
                                  <span
                                    key={technique}
                                    className="rounded border border-red-500/20 px-1 py-0.5 text-[10px] text-red-300"
                                  >
                                    {technique}
                                  </span>
                                ))}
                              </div>
                            </li>
                          );
                        })}
                      </ol>
                    )}
                  </div>
                )}

                {activeTab === 'observations' && (
                  <div className="h-full overflow-y-auto">
                    {observations.length === 0 ? (
                      <p className="p-6 text-sm text-gray-500">
                        The worker has not written observations for these alerts yet.
                      </p>
                    ) : (
                      <ul className="divide-y divide-[#374151]/40">
                        {observations.map((observation: CandidateObservation) => (
                          <li key={observation.observation_key} className="px-5 py-4">
                            <div className="flex flex-wrap items-baseline justify-between gap-2">
                              <div className="flex items-center gap-2">
                                <span className="rounded border border-teal-500/25 bg-teal-500/10 px-1.5 py-0.5 text-[11px] text-teal-300">
                                  {observation.role ?? 'unclassified'}
                                </span>
                                <span
                                  className="text-xs text-gray-500"
                                  title="Alerts grouped into this observation; duplicates are folded in and still listed."
                                >
                                  {observation.alert_count ?? observation.alert_ids?.length ?? 0}{' '}
                                  {(observation.alert_count ?? observation.alert_ids?.length ?? 0) === 1
                                    ? 'alert'
                                    : 'alerts'}{' '}
                                  folded in
                                </span>
                              </div>
                              <span className="font-mono text-[11px] text-gray-500">
                                {safeFormat(
                                  observation.first_seen,
                                  sameDay(observation.first_seen, observation.last_seen)
                                    ? 'HH:mm:ss'
                                    : 'MMM d, HH:mm'
                                )}
                                {observation.last_seen && observation.last_seen !== observation.first_seen
                                  ? ` – ${safeFormat(
                                      observation.last_seen,
                                      sameDay(observation.first_seen, observation.last_seen)
                                        ? 'HH:mm:ss'
                                        : 'MMM d, HH:mm'
                                    )}`
                                  : ''}
                              </span>
                            </div>

                            <p
                              className="mt-1.5 break-all font-mono text-[11px] text-gray-500"
                              title={observation.observation_key}
                            >
                              {prettyObservationKey(observation.observation_key)}
                            </p>

                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {(observation.techniques ?? []).map((technique) => (
                                <span
                                  key={technique}
                                  className="rounded border border-red-500/20 px-1 py-0.5 text-[10px] text-red-300"
                                >
                                  {technique}
                                </span>
                              ))}
                              {(observation.tokens ?? []).length > 0
                                ? (observation.tokens ?? []).map((token) => (
                                    <span
                                      key={token.token}
                                      title={`${token.token} → +${token.weight} to L1${
                                        token.estimated ? ' (estimated: row predates weighting)' : ''
                                      }`}
                                      className="max-w-full truncate rounded bg-dark-40 px-1 py-0.5 font-mono text-[10px] text-gray-400"
                                    >
                                      {token.kind}:{shortToken(token.value)}
                                      <span className="ml-1 text-gray-600">×{token.weight}</span>
                                    </span>
                                  ))
                                : // Rows written before migration 079 have no token
                                  // set; the entity buckets are the best available.
                                  [...(observation.hosts ?? []), ...(observation.users ?? [])].map(
                                    (value) => (
                                      <span
                                        key={`${observation.observation_key}-${value}`}
                                        className="rounded bg-dark-40 px-1 py-0.5 font-mono text-[10px] text-gray-400"
                                      >
                                        {value}
                                      </span>
                                    )
                                  )}
                            </div>

                            {(observation.alert_ids ?? []).length > 0 && (
                              <details className="mt-2 text-xs text-gray-500">
                                <summary className="cursor-pointer select-none text-gray-400 hover:text-gray-300">
                                  Show {observation.alert_ids!.length} deduplicated alert IDs
                                </summary>
                                <div className="mt-1.5 space-y-1">
                                  {observation.alert_ids!.map((alertId) => (
                                    <AlertLink
                                      key={alertId}
                                      alertId={alertId}
                                      title={alertIndex.get(alertId)?.title}
                                      payloadTitle={alertIndex.get(alertId)?.payload_title}
                                      compact
                                    />
                                  ))}
                                </div>
                              </details>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}

                {activeTab === 'alerts' && (
                  <div className="h-full overflow-y-auto">
                    <table className="w-full text-left text-sm">
                      <thead className="sticky top-0 bg-dark-70 text-[11px] uppercase tracking-wide text-gray-500">
                        <tr>
                          <th className="px-4 py-2 font-medium">Time</th>
                          <th className="px-4 py-2 font-medium">Alert</th>
                          <th className="px-4 py-2 font-medium">Severity</th>
                          <th className="hidden px-4 py-2 font-medium lg:table-cell">Observation</th>
                          <th className="px-4 py-2" />
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#374151]/40">
                        {shownTimeline.length === 0 && excludedAlertRows.length === 0 && (
                          <tr>
                            <td colSpan={5} className="px-4 py-6 text-sm text-gray-500">
                              {hideDedup && dedupTimeline.length > 0
                                ? `All ${dedupTimeline.length} member alert${dedupTimeline.length === 1 ? '' : 's'} left here are soft-dedup witnesses — open the accordion below, or show dedup.`
                                : 'No member alerts left in this view. Restore an excluded alert, or remove a filter.'}
                            </td>
                          </tr>
                        )}
                        {excludedAlertRows.map((item) => (
                          <tr key={`excluded-${item.alert_id}`} className="bg-rose-500/[0.04]">
                            <td className="whitespace-nowrap px-4 py-2 font-mono text-[11px] text-gray-600">
                              —
                            </td>
                            <td className="max-w-[420px] px-4 py-2 align-top">
                              <span className="flex flex-wrap items-center gap-1.5">
                                <span className="truncate text-sm text-gray-400">
                                  {item.title ?? `${item.alert_id.slice(0, 8)}…`}
                                </span>
                                <span className="rounded border border-rose-500/30 bg-rose-500/10 px-1 py-0.5 text-[9px] uppercase tracking-wide text-rose-200">
                                  excluded
                                </span>
                              </span>
                              <span className="mt-0.5 block font-mono text-[10px] text-gray-600">
                                {item.alert_id}
                              </span>
                            </td>
                            <td className="px-4 py-2 text-xs text-gray-600">—</td>
                            <td className="hidden px-4 py-2 text-[10px] text-gray-600 lg:table-cell">
                              {item.reason}
                            </td>
                            <td className="px-4 py-2 text-right">
                              <button
                                type="button"
                                onClick={() =>
                                  onScopeChange({
                                    ...scope,
                                    excluded_alert_ids: scope.excluded_alert_ids.filter(
                                      (id) => id !== item.alert_id
                                    ),
                                  })
                                }
                                title="Put this alert back into the analysis."
                                className="rounded border border-[#374151] px-1.5 py-0.5 text-[11px] text-gray-400 transition-colors hover:border-teal-500/60 hover:text-teal-200"
                              >
                                Include
                              </button>
                            </td>
                          </tr>
                        ))}
                        {shownTimeline.map((event) => (
                          <AlertRow
                            key={event.alert_id}
                            event={event}
                            observationIndex={observationIndex}
                            onExcludeAlert={onExcludeAlert}
                          />
                        ))}
                      </tbody>
                    </table>

                    {/* The witnesses stay one click away rather than off the
                        screen: an accordion, so the count is visible without
                        spending a row on each copy. */}
                    {hideDedup && dedupTimeline.length > 0 && (
                      <div className="border-t border-[#374151]/60">
                        <button
                          type="button"
                          onClick={() => setDedupOpen((open) => !open)}
                          aria-expanded={dedupOpen}
                          title="Soft-deduplicated evidence: still a case witness and still scored, but hidden from the Alerts workbench. The canonical alert is the one it was merged into."
                          className="flex w-full items-center gap-2 px-4 py-2 text-left text-[11px] text-gray-400 transition-colors hover:bg-dark-40/40"
                        >
                          <span className="rounded border border-violet-500/30 bg-violet-500/10 px-1 py-0.5 text-[9px] uppercase tracking-wide text-violet-300">
                            deduplicated
                          </span>
                          <span>
                            {dedupTimeline.length} soft-dedup witness
                            {dedupTimeline.length === 1 ? '' : 'es'} hidden from this list
                          </span>
                          <span className="ml-auto text-gray-500 underline-offset-2 hover:underline">
                            {dedupOpen ? 'Hide' : 'Show'}
                          </span>
                        </button>
                        {dedupOpen && (
                          <table className="w-full text-left text-sm">
                            <thead className="text-[11px] uppercase tracking-wide text-gray-600">
                              <tr>
                                <th className="px-4 py-2 font-medium">Time</th>
                                <th className="px-4 py-2 font-medium">Alert</th>
                                <th className="px-4 py-2 font-medium">Severity</th>
                                <th className="hidden px-4 py-2 font-medium lg:table-cell">
                                  Observation
                                </th>
                                <th className="px-4 py-2" />
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-[#374151]/40">
                              {dedupTimeline.map((event) => (
                                <AlertRow
                                  key={`dedup-${event.alert_id}`}
                                  event={event}
                                  observationIndex={observationIndex}
                                  onExcludeAlert={onExcludeAlert}
                                />
                              ))}
                            </tbody>
                          </table>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'rules' && (
                  <div className="h-full overflow-y-auto px-5 py-4">
                    <p className="mb-3 text-[11px] text-gray-500">
                      One row per rule firing in the evidence this view scores. A rule can fire
                      more than once, so the count is alerts — not distinct detections.
                    </p>
                    {ruleEntries.length === 0 && excludedRuleEntries.length === 0 ? (
                      <p className="text-sm text-gray-500">
                        No distinct rules found for this case.
                      </p>
                    ) : (
                      <ul className="divide-y divide-[#374151]/40">
                        {excludedRuleEntries.map(([ruleName, ids]) => (
                          <li
                            key={`excluded-${ruleName}`}
                            className="flex items-center justify-between gap-3 bg-rose-500/[0.04] px-2 py-3"
                          >
                            <span className="flex min-w-0 flex-wrap items-center gap-2">
                              <span className="truncate font-mono text-[11px] text-gray-400">
                                {ruleName}
                              </span>
                              <span className="rounded border border-rose-500/30 bg-rose-500/10 px-1 py-0.5 text-[9px] uppercase tracking-wide text-rose-200">
                                excluded · {ids.length} alert{ids.length === 1 ? '' : 's'}
                              </span>
                            </span>
                            <button
                              type="button"
                              onClick={() =>
                                onScopeChange({
                                  ...scope,
                                  excluded_alert_ids: scope.excluded_alert_ids.filter(
                                    (id) => !ruleAlertIds.get(ruleName)?.includes(id)
                                  ),
                                })
                              }
                              title="Put every alert this rule fired on back into the analysis."
                              className="shrink-0 rounded border border-[#374151] px-1.5 py-0.5 text-[11px] text-gray-400 transition-colors hover:border-teal-500/60 hover:text-teal-200"
                            >
                              Include
                            </button>
                          </li>
                        ))}
                        {ruleEntries.map(([ruleName, count]) => (
                          <li
                            key={ruleName}
                            className="flex items-center justify-between gap-3 px-2 py-3"
                          >
                            <span className="min-w-0 truncate font-mono text-[11px] text-gray-400">
                              {ruleName}
                            </span>
                            <span className="flex shrink-0 items-center gap-3">
                              <span
                                className="text-[11px] font-medium tabular-nums text-gray-500"
                                title={`${count} of the ${evidenceAlertCount} alerts in view carry this rule`}
                              >
                                {count}
                              </span>
                              {(ruleAlertIds.get(ruleName)?.length ?? 0) > 0 && (
                                <button
                                  type="button"
                                  onClick={() =>
                                    onScopeChange({
                                      ...scope,
                                      excluded_alert_ids: Array.from(
                                        new Set([
                                          ...scope.excluded_alert_ids,
                                          ...(ruleAlertIds.get(ruleName) ?? []),
                                        ])
                                      ),
                                    })
                                  }
                                  title="Drop every alert this rule fired on from the analysis. They stay case evidence; the graph, timeline and scores are recomputed without them."
                                  className="rounded border border-[#374151] px-1.5 py-0.5 text-[11px] text-gray-400 transition-colors hover:border-rose-500/60 hover:text-rose-200"
                                >
                                  Exclude
                                </button>
                              )}
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>
            )}

          </div>
        </div>

      </div>
    </div>
  );
}
