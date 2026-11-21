/**
 * Community separation for the correlation graph.
 *
 * `fcose` lays out one connected graph as one physical system: a shared entity
 * pulls its observations together, and on a candidate with hundreds of
 * observations the bubbles interleave until every leaf sits on top of a
 * neighbour's leaf. The analyst then has to drag hubs apart by hand to see the
 * shape of the campaign.
 *
 * These two pure functions do that pass for the layout engine:
 *
 * 1. `findCommunities` — label propagation over the *structural* edges (the
 *    entity links), so "what belongs together" is decided by which entities an
 *    observation actually shares, not by correlation-score links that would
 *    merge everything into one blob.
 * 2. `separateCommunities` — treats each community as a rigid body and pushes
 *    the bodies apart until their bounding circles no longer overlap. Internal
 *    shape is untouched, so this only adds distance between clusters.
 *
 * Both are deterministic (ties broken by id), which keeps a relayout stable
 * across renders and testable without a browser.
 */

/** Palette for community chrome (bubbles, 3D shells, cluster labels). */
export const CLUSTER_COLORS = [
  '#38bdf8',
  '#f472b6',
  '#34d399',
  '#fbbf24',
  '#a78bfa',
  '#fb7185',
  '#22d3ee',
  '#a3e635',
  '#f97316',
  '#e879f9',
  '#4ade80',
  '#60a5fa',
] as const;

/**
 * One bubble as both views describe it. Shared so the 3D legend and the 2D
 * pills cannot drift: same key, same name, same colour, same size, and the
 * collapse state the two views already share.
 */
export interface ClusterSummary {
  community: string;
  title: string;
  subtitle: string;
  color: string;
  size: number;
  collapsed?: boolean;
}

export interface Point {
  x: number;
  y: number;
}

export interface CommunityEdge {
  source: string;
  target: string;
}

/** Label propagation over the structural edges; deterministic, bounded sweeps. */
export function findCommunities(
  nodeIds: readonly string[],
  edges: readonly CommunityEdge[],
  options: { maxSweeps?: number } = {}
): Map<string, string> {
  const maxSweeps = options.maxSweeps ?? 12;
  const adjacency = new Map<string, string[]>();
  for (const id of nodeIds) adjacency.set(id, []);
  for (const edge of edges) {
    if (edge.source === edge.target) continue;
    adjacency.get(edge.source)?.push(edge.target);
    adjacency.get(edge.target)?.push(edge.source);
  }

  const label = new Map<string, string>(nodeIds.map((id) => [id, id]));
  const order = [...nodeIds].sort((a, b) => a.localeCompare(b));

  for (let sweep = 0; sweep < maxSweeps; sweep += 1) {
    let changed = false;
    for (const id of order) {
      const neighbours = adjacency.get(id) ?? [];
      if (neighbours.length === 0) continue;
      const counts = new Map<string, number>();
      for (const neighbour of neighbours) {
        const current = label.get(neighbour);
        if (!current) continue;
        counts.set(current, (counts.get(current) ?? 0) + 1);
      }
      let best = label.get(id)!;
      let bestCount = 0;
      // Sorted iteration makes the tie-break ("smallest label wins") explicit
      // rather than dependent on insertion order.
      for (const [candidate, count] of [...counts].sort(([a], [b]) => a.localeCompare(b))) {
        if (count > bestCount) {
          best = candidate;
          bestCount = count;
        }
      }
      if (best !== label.get(id)) {
        label.set(id, best);
        changed = true;
      }
    }
    if (!changed) break;
  }

  // Compact the raw labels into c0, c1, … in first-seen order so the result is
  // comparable across runs (the raw values are node ids and depend on seeding).
  const canonical = new Map<string, string>();
  const result = new Map<string, string>();
  for (const id of order) {
    const raw = label.get(id)!;
    let name = canonical.get(raw);
    if (!name) {
      name = `c${canonical.size}`;
      canonical.set(raw, name);
    }
    result.set(id, name);
  }
  return result;
}

/**
 * Deterministic fallback partition for a graph label propagation collapses
 * into one blob (the common case on a campaign where every observation shares
 * an entity with the next).
 *
 * The `k` highest-degree nodes become seeds and a multi-source BFS assigns
 * every other node to the seed that reaches it first, so each region is
 * contiguous in the graph — the same "bubbles joined by lines" picture an
 * analyst builds by dragging hubs apart by hand, but stable across renders.
 */
export function partitionByHubs(
  nodeIds: readonly string[],
  edges: readonly CommunityEdge[],
  k: number
): Map<string, string> {
  const adjacency = new Map<string, string[]>();
  for (const id of nodeIds) adjacency.set(id, []);
  for (const edge of edges) {
    if (edge.source === edge.target) continue;
    adjacency.get(edge.source)?.push(edge.target);
    adjacency.get(edge.target)?.push(edge.source);
  }

  const order = [...nodeIds].sort((a, b) => a.localeCompare(b));
  const seeds = [...order]
    .sort((a, b) => {
      const degreeDiff = (adjacency.get(b)?.length ?? 0) - (adjacency.get(a)?.length ?? 0);
      return degreeDiff !== 0 ? degreeDiff : a.localeCompare(b);
    })
    .slice(0, Math.max(1, Math.min(k, order.length)));

  const community = new Map<string, string>();
  let frontier = [...seeds].sort((a, b) => a.localeCompare(b));
  for (const seed of frontier) community.set(seed, `h:${seed}`);

  while (frontier.length > 0) {
    const next: string[] = [];
    for (const id of frontier) {
      const home = community.get(id)!;
      for (const neighbour of [...(adjacency.get(id) ?? [])].sort((a, b) => a.localeCompare(b))) {
        if (community.has(neighbour)) continue;
        community.set(neighbour, home);
        next.push(neighbour);
      }
    }
    frontier = next;
  }

  // Never-connected nodes still need a home or the separation pass would drag
  // them around as their own cluster.
  for (const id of order) {
    if (!community.has(id)) community.set(id, 'h:isolated');
  }
  return community;
}

/**
 * The partition the views actually draw, in one place.
 *
 * Label propagation first; when it collapses into a few blob-like groups, the
 * degree-seeded BFS partition takes over. Both the 2D canvas (separation +
 * cluster labels) and the 3D scene use this so a bubble means the same thing in
 * either view.
 */
export function clusterGraph(
  nodeIds: readonly string[],
  edges: readonly CommunityEdge[]
): Map<string, string> {
  const target = Math.min(24, Math.max(4, Math.round(nodeIds.length / 40)));
  const membership = findCommunities(nodeIds, edges);
  if (new Set(membership.values()).size < Math.ceil(target / 2)) {
    return partitionByHubs(nodeIds, edges, target);
  }
  return membership;
}

export interface SeparationOptions {
  /** Extra distance between two cluster circles. */
  gap?: number;
  /** Per-cluster padding, so the circles enclose node bodies, not just centres. */
  margin?: number;
  iterations?: number;
}

/**
 * Name a bubble: the entity that carries it, plus the role its observations
 * share. A cluster of one kind only still gets a sensible name.
 */
export function describeCluster(
  members: readonly { id: string; kind: string; label: string }[],
  links: ReadonlyMap<string, number>
): { title: string; subtitle: string } {
  const entities = members
    .filter((member) => member.kind !== 'observation')
    .sort(
      (a, b) => (links.get(b.id) ?? 0) - (links.get(a.id) ?? 0) || a.label.localeCompare(b.label)
    );

  const roles = new Map<string, number>();
  for (const member of members) {
    if (member.kind !== 'observation') continue;
    const role = member.label.split(':')[0];
    roles.set(role, (roles.get(role) ?? 0) + 1);
  }
  const role = [...roles.entries()].sort(
    ([a, countA], [b, countB]) => countB - countA || a.localeCompare(b)
  )[0]?.[0];

  // An entity names the bubble; a role is the fallback when the group holds no
  // leaf the analyst can recognise.
  const title = entities[0]?.label ?? (role ? `${role} cluster` : 'cluster');
  return {
    title,
    subtitle: role ? `${members.length} · ${role}` : `${members.length} nodes`,
  };
}

/**
 * Push communities apart as rigid bodies until no two bounding circles overlap.
 *
 * Every node keeps its offset from its community's centre, so the local shape
 * `fcose` produced survives; only the distance between clusters changes. The
 * whole picture is re-centred afterwards so the fit that follows is not off by
 * the drift of the packing.
 */
export function separateCommunities(
  positions: ReadonlyMap<string, Point>,
  communityOf: ReadonlyMap<string, string>,
  options: SeparationOptions = {}
): Map<string, Point> {
  const gap = options.gap ?? 48;
  const margin = options.margin ?? 28;
  const iterations = options.iterations ?? 200;

  const groups = new Map<string, string[]>();
  for (const [id, community] of communityOf) {
    if (!positions.has(id)) continue;
    const list = groups.get(community);
    if (list) list.push(id);
    else groups.set(community, [id]);
  }
  const keys = [...groups.keys()].sort((a, b) => a.localeCompare(b));
  if (keys.length < 2) return new Map(positions);

  const centreOf = (ids: string[]): Point => {
    let x = 0;
    let y = 0;
    for (const id of ids) {
      const point = positions.get(id)!;
      x += point.x;
      y += point.y;
    }
    return { x: x / ids.length, y: y / ids.length };
  };

  const centres = new Map<string, Point>(keys.map((key) => [key, centreOf(groups.get(key)!)]));
  const radius = new Map<string, number>();
  const offset = new Map<string, Point>(keys.map((key) => [key, { x: 0, y: 0 }]));
  for (const key of keys) {
    const centre = centres.get(key)!;
    let far = 0;
    for (const id of groups.get(key)!) {
      const point = positions.get(id)!;
      far = Math.max(far, Math.hypot(point.x - centre.x, point.y - centre.y));
    }
    radius.set(key, far + margin + gap / 2);
  }

  // Deterministic push direction for exactly coincident clusters.
  const angleFor = (a: string, b: string): number => {
    let hash = 0;
    for (const ch of `${a}|${b}`) hash = (hash * 31 + ch.charCodeAt(0)) % 360;
    return (hash * Math.PI) / 180;
  };

  for (let step = 0; step < iterations; step += 1) {
    let moved = false;
    for (let i = 0; i < keys.length; i += 1) {
      for (let j = i + 1; j < keys.length; j += 1) {
        const left = keys[i];
        const right = keys[j];
        const a = centres.get(left)!;
        const b = centres.get(right)!;
        const oa = offset.get(left)!;
        const ob = offset.get(right)!;
        const ax = a.x + oa.x;
        const ay = a.y + oa.y;
        const bx = b.x + ob.x;
        const by = b.y + ob.y;
        const dx = bx - ax;
        const dy = by - ay;
        const distance = Math.hypot(dx, dy);
        const needed = radius.get(left)! + radius.get(right)!;
        if (distance >= needed) continue;
        const overlap = (needed - distance) / 2;
        let ux: number;
        let uy: number;
        if (distance < 1e-6) {
          const angle = angleFor(left, right);
          ux = Math.cos(angle);
          uy = Math.sin(angle);
        } else {
          ux = dx / distance;
          uy = dy / distance;
        }
        oa.x -= ux * overlap;
        oa.y -= uy * overlap;
        ob.x += ux * overlap;
        ob.y += uy * overlap;
        moved = true;
      }
    }
    if (!moved) break;
  }

  // Pairwise pushes can stall in a ring of three clusters (each push feeds the
  // next). One uniform expansion of the cluster centres finishes the job: it
  // preserves the arrangement the pushes found and is guaranteed to clear every
  // remaining overlap, because the factor is derived from the worst pair.
  let scale = 1;
  for (let i = 0; i < keys.length; i += 1) {
    for (let j = i + 1; j < keys.length; j += 1) {
      const left = keys[i];
      const right = keys[j];
      const a = centres.get(left)!;
      const b = centres.get(right)!;
      const oa = offset.get(left)!;
      const ob = offset.get(right)!;
      const distance = Math.hypot(
        b.x + ob.x - (a.x + oa.x),
        b.y + ob.y - (a.y + oa.y)
      );
      const needed = radius.get(left)! + radius.get(right)!;
      if (distance < 1e-6) continue;
      scale = Math.max(scale, (needed + 1) / distance);
    }
  }
  if (scale > 1) {
    let anchorX = 0;
    let anchorY = 0;
    for (const point of positions.values()) {
      anchorX += point.x;
      anchorY += point.y;
    }
    anchorX /= positions.size || 1;
    anchorY /= positions.size || 1;
    for (const key of keys) {
      const centre = centres.get(key)!;
      const shift = offset.get(key)!;
      const movedX = centre.x + shift.x;
      const movedY = centre.y + shift.y;
      shift.x = anchorX + (movedX - anchorX) * scale - centre.x;
      shift.y = anchorY + (movedY - anchorY) * scale - centre.y;
    }
  }

  // Keep the picture where it was: translate so the area-weighted centre of all
  // nodes is unchanged.
  let beforeX = 0;
  let beforeY = 0;
  let afterX = 0;
  let afterY = 0;
  for (const [id, point] of positions) {
    const member = communityOf.get(id);
    if (!member) continue;
    const shift = offset.get(member)!;
    beforeX += point.x;
    beforeY += point.y;
    afterX += point.x + shift.x;
    afterY += point.y + shift.y;
  }
  const count = [...positions.keys()].filter((id) => communityOf.has(id)).length || 1;
  const driftX = (afterX - beforeX) / count;
  const driftY = (afterY - beforeY) / count;

  const result = new Map<string, Point>();
  for (const [id, point] of positions) {
    const member = communityOf.get(id);
    if (!member) {
      result.set(id, point);
      continue;
    }
    const shift = offset.get(member)!;
    result.set(id, { x: point.x + shift.x - driftX, y: point.y + shift.y - driftY });
  }
  return result;
}
