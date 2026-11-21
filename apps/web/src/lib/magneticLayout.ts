/**
 * A short magnetic relaxation pass for the 2D correlation graph.
 *
 * `fcose` gives us a global layout: every edge is a spring, every node repels
 * every other node by the same degree-scaled constant. That cannot express the
 * thing an analyst actually wants to see — "leaves that share a link sit
 * together, leaves that share nothing push apart" — because its repulsion has
 * no notion of a pair.
 *
 * This pass runs after the layout has settled and works only on positions:
 *
 * * every drawn edge pulls its two endpoints toward a rest length that shrinks
 *   as the link gets stronger (a ×120 alert pair sits closer than a ×1 one);
 * * two nodes **without** an edge push apart only while they are closer than
 *   `padding`, so unrelated leaves stop overlapping without the whole component
 *   inflating;
 * * movement is capped per iteration, so the pass nudges the settled picture
 *   instead of replacing it.
 *
 * Deterministic (sorted input, fixed iteration order, no randomness) and pure,
 * so the curve is testable without a browser.
 */

export interface MagneticNode {
  id: string;
  x: number;
  y: number;
}

export interface MagneticEdge {
  source: string;
  target: string;
  /** Pair score or collapsed-alert count; larger pulls its ends closer. */
  weight?: number;
}

export interface MagneticOptions {
  iterations?: number;
  /** Minimum distance between two leaves that are not linked. */
  padding?: number;
  /** Rest length of the weakest link, in model units. */
  targetLength?: number;
  /** How hard a spring pulls, as a fraction of the gap per iteration. */
  attraction?: number;
  /** How hard unrelated leaves shove each other out of `padding`. */
  repulsion?: number;
  /** Cap on a node's movement per iteration. */
  maxStep?: number;
}

export interface MagneticPoint {
  x: number;
  y: number;
}

const pairKey = (a: string, b: string): string => (a < b ? `${a}|${b}` : `${b}|${a}`);

/**
 * Rest length for one link: strong links are short, weak links are long. The
 * floor stops a very strong pair from collapsing onto the same point.
 */
function restFor(weight: number, targetLength: number): number {
  const strength = Math.min(24, Math.max(0, weight));
  return targetLength * Math.max(0.45, 1 / (1 + 0.12 * strength));
}

export function applyMagnetism(
  nodes: readonly MagneticNode[],
  edges: readonly MagneticEdge[],
  options: MagneticOptions = {}
): Map<string, MagneticPoint> {
  const iterations = options.iterations ?? 28;
  const padding = options.padding ?? 18;
  const targetLength = options.targetLength ?? 140;
  const attraction = options.attraction ?? 0.35;
  const repulsion = options.repulsion ?? 0.5;
  const maxStep = options.maxStep ?? 10;

  const sorted = [...nodes].sort((a, b) => a.id.localeCompare(b.id));
  const index = new Map(sorted.map((node, position) => [node.id, position]));
  const points = sorted.map((node) => ({ x: node.x, y: node.y }));

  // One spring per linked pair; parallel edges keep the strongest (shortest).
  const springs: { a: number; b: number; rest: number }[] = [];
  const linked = new Set<string>();
  const bestRest = new Map<string, number>();
  for (const edge of edges) {
    const a = index.get(edge.source);
    const b = index.get(edge.target);
    if (a === undefined || b === undefined || a === b) continue;
    const key = pairKey(edge.source, edge.target);
    const rest = restFor(edge.weight ?? 1, targetLength);
    const known = bestRest.get(key);
    if (known === undefined || rest < known) bestRest.set(key, rest);
  }
  for (const [key, rest] of [...bestRest.entries()].sort(([x], [y]) => x.localeCompare(y))) {
    const [aId, bId] = key.split('|');
    const a = index.get(aId);
    const b = index.get(bId);
    if (a === undefined || b === undefined) continue;
    linked.add(key);
    springs.push({ a, b, rest });
  }

  const cell = Math.max(8, padding * 2);
  for (let step = 0; step < iterations; step += 1) {
    const shiftX = new Float64Array(points.length);
    const shiftY = new Float64Array(points.length);

    // Attraction along the drawn links.
    for (const spring of springs) {
      const a = points[spring.a];
      const b = points[spring.b];
      let vx = b.x - a.x;
      let vy = b.y - a.y;
      let distance = Math.hypot(vx, vy);
      if (distance < 1e-6) {
        // Seed a deterministic direction so coincident nodes can separate.
        vx = spring.a < spring.b ? 1 : -1;
        vy = 0;
        distance = 1;
      }
      const gap = distance - spring.rest;
      const move = Math.max(-maxStep, Math.min(maxStep, gap * attraction)) / 2;
      const ux = (vx / distance) * move;
      const uy = (vy / distance) * move;
      shiftX[spring.a] += ux;
      shiftY[spring.a] += uy;
      shiftX[spring.b] -= ux;
      shiftY[spring.b] -= uy;
    }

    // Repulsion, but only between leaves that share no link, and only while
    // they are closer than `padding`. Buckets keep this linear-ish on a
    // 900-node component instead of scanning every pair.
    const buckets = new Map<string, number[]>();
    for (let position = 0; position < points.length; position += 1) {
      const bucket = `${Math.floor(points[position].x / cell)}:${Math.floor(points[position].y / cell)}`;
      const list = buckets.get(bucket);
      if (list) list.push(position);
      else buckets.set(bucket, [position]);
    }
    for (let position = 0; position < points.length; position += 1) {
      const a = points[position];
      const cellX = Math.floor(a.x / cell);
      const cellY = Math.floor(a.y / cell);
      const aId = sorted[position].id;
      for (let dx = -1; dx <= 1; dx += 1) {
        for (let dy = -1; dy <= 1; dy += 1) {
          const list = buckets.get(`${cellX + dx}:${cellY + dy}`);
          if (!list) continue;
          for (const other of list) {
            if (other <= position) continue;
            const b = points[other];
            if (linked.has(pairKey(aId, sorted[other].id))) continue;
            let vx = b.x - a.x;
            let vy = b.y - a.y;
            let distance = Math.hypot(vx, vy);
            if (distance >= padding) continue;
            if (distance < 1e-6) {
              vx = 0.5;
              vy = 0.5;
              distance = Math.hypot(vx, vy);
            }
            const push = ((padding - distance) * repulsion) / 2;
            const ux = (vx / distance) * push;
            const uy = (vy / distance) * push;
            shiftX[position] -= ux;
            shiftY[position] -= uy;
            shiftX[other] += ux;
            shiftY[other] += uy;
          }
        }
      }
    }

    let moved = 0;
    for (let position = 0; position < points.length; position += 1) {
      const sx = Math.max(-maxStep, Math.min(maxStep, shiftX[position]));
      const sy = Math.max(-maxStep, Math.min(maxStep, shiftY[position]));
      if (sx === 0 && sy === 0) continue;
      points[position].x += sx;
      points[position].y += sy;
      moved += Math.abs(sx) + Math.abs(sy);
    }
    // Settled: no visible movement, stop spending frames on it.
    if (moved < 0.01) break;
  }

  return new Map(sorted.map((node, position) => [node.id, { ...points[position] }]));
}
