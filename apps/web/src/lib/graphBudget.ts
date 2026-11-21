/**
 * How many neighbours each node may draw.
 *
 * The previous implementation kept an edge when it was in *either* endpoint's
 * top-N list, so a hub accumulated every leaf for which the hub was among that
 * leaf's strongest four — a host with sixty observations still rendered sixty
 * spokes while the control said 4. On an 875-node campaign that is the
 * difference between a readable skeleton and a hairball.
 *
 * This keeps the promise the control makes: no node draws more than `budget`
 * edges. Edges are considered strongest-first, and an edge is drawn only when
 * *both* endpoints still have room, so the heaviest links win the seats. A node
 * the analyst expanded by hand is exempt and keeps every edge, which is how you
 * drill into the leaves a budget hid.
 */

export interface BudgetEdge {
  id: string;
  source: string;
  target: string;
  weight?: number | null;
}

/** How many layers one node may be expanded by hand before the button stops. */
export const MAX_EXPAND_LAYERS = 4;

/**
 * Which nodes an analyst's per-node expansion exempts from the budget.
 *
 * Expanding used to be one boolean per node: one click drew every edge of that
 * node and there was no way to ask for the next ring. A depth map makes the
 * button a drill-down — `depth` counts the layers already drawn, so depth 1 is
 * the node itself, depth 2 adds its neighbours, depth 3 adds *their*
 * neighbours — and the exemption is the union over every expanded node, because
 * an edge draws as soon as either endpoint is exempt.
 */
export function expandRadii<T extends BudgetEdge>(
  edges: readonly T[],
  depths: ReadonlyMap<string, number>
): Set<string> {
  const exempt = new Set<string>();
  if (depths.size === 0) return exempt;

  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    if (edge.source === edge.target) continue;
    const fromSource = adjacency.get(edge.source);
    if (fromSource) fromSource.push(edge.target);
    else adjacency.set(edge.source, [edge.target]);
    const fromTarget = adjacency.get(edge.target);
    if (fromTarget) fromTarget.push(edge.source);
    else adjacency.set(edge.target, [edge.source]);
  }

  for (const [seed, depth] of depths) {
    if (depth <= 0) continue;
    let frontier = [seed];
    exempt.add(seed);
    // depth 1 = the node alone; each extra layer walks one more hop.
    for (let layer = 1; layer < depth; layer += 1) {
      const next: string[] = [];
      for (const id of frontier) {
        for (const neighbour of adjacency.get(id) ?? []) {
          if (exempt.has(neighbour)) continue;
          exempt.add(neighbour);
          next.push(neighbour);
        }
      }
      if (next.length === 0) break;
      frontier = next;
    }
  }
  return exempt;
}

export function selectBudgetedEdges<T extends BudgetEdge>(
  edges: readonly T[],
  budget: number | 'all',
  expanded: ReadonlySet<string> = new Set()
): T[] {
  if (budget === 'all') return [...edges];

  const ordered = [...edges].sort(
    (a, b) => (b.weight ?? 0) - (a.weight ?? 0) || a.id.localeCompare(b.id)
  );
  const spent = new Map<string, number>();
  const kept: T[] = [];

  for (const edge of ordered) {
    if (expanded.has(edge.source) || expanded.has(edge.target)) {
      kept.push(edge);
      continue;
    }
    const sourceSpent = spent.get(edge.source) ?? 0;
    const targetSpent = spent.get(edge.target) ?? 0;
    if (sourceSpent >= budget || targetSpent >= budget) continue;
    spent.set(edge.source, sourceSpent + 1);
    spent.set(edge.target, targetSpent + 1);
    kept.push(edge);
  }

  return kept;
}
