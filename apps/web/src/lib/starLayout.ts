/**
 * Star radialisation for the 2D correlation graph.
 *
 * A force layout only knows attraction to your own hub and a global repulsion.
 * A hub with twenty leaves gets a ring whose radius is one edge length, so its
 * leaves sit shoulder to shoulder and — worse — the ring of the hub next to it
 * reaches into the same space. The result is the "leaves of A weave between the
 * leaves of B" picture, with no way to read either tree.
 *
 * This pass gives each big star its own geometry after the forces have settled:
 *
 * * Leaves are placed on a circle around their hub, spaced by a fixed arc, so
 *   the ring is as large as the leaf count needs.
 * * The arc is aimed away from the hub's non-leaf neighbours, which turns each
 *   hub into a mushroom: the trunk (the link onward) points one way, the cap of
 *   leaves the other, instead of a ring that wraps around the trunk.
 * * Every leaf carries its own subtree with it, so a two-level tree (host →
 *   observation → entity) keeps its own bush shape while being moved.
 * * Finally the star caps are pushed apart as rigid bodies, so two mushrooms
 *   never share leaf space.
 *
 * Pure: takes positions, returns new ones. Deterministic ordering by id.
 */

export interface StarPoint {
  x: number;
  y: number;
}

export interface StarOptions {
  /** A hub needs at least this many leaves to be laid out as a star. */
  minLeaves?: number;
  /** Arc distance between two neighbouring leaves on a ring. */
  leafSpacing?: number;
  /** Smallest ring radius, so a two-leaf star still reads as a star. */
  minRadius?: number;
  /** Extra distance kept between two star caps. */
  capGap?: number;
  /** Skip entirely below this node count: small graphs already read fine. */
  minNodes?: number;
  iterations?: number;
}

const TAU = Math.PI * 2;

export function arrangeStars(
  positions: ReadonlyMap<string, StarPoint>,
  adjacency: ReadonlyMap<string, readonly string[]>,
  options: StarOptions = {}
): Map<string, StarPoint> {
  const minLeaves = options.minLeaves ?? 5;
  const leafSpacing = options.leafSpacing ?? 46;
  const minRadius = options.minRadius ?? 52;
  const capGap = options.capGap ?? 24;
  const minNodes = options.minNodes ?? 80;
  const iterations = options.iterations ?? 120;

  if (positions.size < minNodes) return new Map(positions);

  const degree = (id: string) => adjacency.get(id)?.length ?? 0;
  const isLeafLike = (id: string) => degree(id) <= 2;

  const stars = [...adjacency.keys()]
    .map((hub) => {
      const neighbours = [...(adjacency.get(hub) ?? [])];
      return {
        hub,
        leaves: neighbours.filter(isLeafLike).sort((a, b) => a.localeCompare(b)),
        anchors: neighbours.filter((id) => !isLeafLike(id)).sort((a, b) => a.localeCompare(b)),
      };
    })
    .filter((star) => star.leaves.length >= minLeaves && positions.has(star.hub))
    .sort((a, b) => b.leaves.length - a.leaves.length || a.hub.localeCompare(b.hub));

  if (stars.length === 0) return new Map(positions);

  const result = new Map(positions);
  const radiusOf = (leaves: number) =>
    Math.max(minRadius, (leaves * leafSpacing) / TAU);

  // The subtree a moved leaf drags with it (everything below it, never the hub).
  const subtreeOf = (leaf: string, hub: string, blocked: ReadonlySet<string>): string[] => {
    const seen = new Set<string>([hub]);
    const stack = [leaf];
    const out: string[] = [];
    while (stack.length > 0) {
      const id = stack.pop()!;
      if (seen.has(id) || blocked.has(id)) continue;
      seen.add(id);
      out.push(id);
      for (const neighbour of adjacency.get(id) ?? []) {
        if (!seen.has(neighbour)) stack.push(neighbour);
      }
    }
    return out;
  };

  // Another star's hub is where a subtree must stop: it owns its own cap, and a
  // node cannot belong to two rigid bodies or it would be moved twice.
  const hubIds = new Set(stars.map((star) => star.hub));

  const caps: { hub: string; centre: StarPoint; radius: number; members: Set<string> }[] = [];

  for (const star of stars) {
    const hubPoint = result.get(star.hub);
    if (!hubPoint) continue;
    // Never pull leaves inward: the force layout may already have given a busy
    // hub a wider fan (degree-aware repulsion), and regularising the angles
    // should not undo that. Keep whichever ring is larger.
    let currentMean = 0;
    let measured = 0;
    for (const leaf of star.leaves) {
      const point = result.get(leaf);
      if (!point) continue;
      currentMean += Math.hypot(point.x - hubPoint.x, point.y - hubPoint.y);
      measured += 1;
    }
    const radius = Math.max(
      radiusOf(star.leaves.length),
      measured > 0 ? currentMean / measured : 0
    );

    // Aim the cap away from where the star connects onward, so the trunk has
    // its own side of the picture.
    let away = -Math.PI / 2;
    if (star.anchors.length > 0) {
      let ax = 0;
      let ay = 0;
      for (const anchor of star.anchors) {
        const point = result.get(anchor);
        if (!point) continue;
        ax += point.x - hubPoint.x;
        ay += point.y - hubPoint.y;
      }
      if (Math.abs(ax) > 1e-6 || Math.abs(ay) > 1e-6) away = Math.atan2(ay, ax) + Math.PI;
    }
    const sweep = star.anchors.length > 0 ? Math.PI * 1.5 : TAU;
    const step = sweep / star.leaves.length;
    const start = away - sweep / 2 + step / 2;

    const moved = new Set<string>([star.hub]);
    const blocked = new Set<string>([...hubIds].filter((id) => id !== star.hub));
    star.leaves.forEach((leaf, index) => {
      const current = result.get(leaf);
      if (!current) return;
      const angle = start + index * step;
      const target = {
        x: hubPoint.x + Math.cos(angle) * radius,
        y: hubPoint.y + Math.sin(angle) * radius,
      };
      const dx = target.x - current.x;
      const dy = target.y - current.y;
      const subtree = subtreeOf(leaf, star.hub, new Set([...moved, ...blocked]));
      for (const id of subtree) {
        const point = result.get(id);
        if (!point) continue;
        result.set(id, { x: point.x + dx, y: point.y + dy });
        moved.add(id);
      }
    });

    // The rigid body is exactly what placement moved, so pushing caps apart
    // never tears a leaf away from its own children.
    caps.push({
      hub: star.hub,
      centre: hubPoint,
      radius: radius + leafSpacing / 2,
      members: moved,
    });
  }

  // Push caps apart as rigid bodies. Only the star's own hub + leaves move, so
  // a neighbouring star's internal composition is never distorted.
  for (let step = 0; step < iterations; step += 1) {
    let moved = false;
    for (let i = 0; i < caps.length; i += 1) {
      for (let j = i + 1; j < caps.length; j += 1) {
        const a = caps[i];
        const b = caps[j];
        if (a.members.has(b.hub) || b.members.has(a.hub)) continue;
        const dx = b.centre.x - a.centre.x;
        const dy = b.centre.y - a.centre.y;
        const distance = Math.hypot(dx, dy);
        const needed = a.radius + b.radius + capGap;
        if (distance >= needed) continue;
        const push = (needed - distance) / 2;
        const ux = distance < 1e-6 ? 1 : dx / distance;
        const uy = distance < 1e-6 ? 0 : dy / distance;
        for (const [cap, sign] of [
          [a, -1],
          [b, 1],
        ] as const) {
          const shiftX = ux * push * sign;
          const shiftY = uy * push * sign;
          for (const id of cap.members) {
            const point = result.get(id);
            if (point) result.set(id, { x: point.x + shiftX, y: point.y + shiftY });
          }
          cap.centre = { x: cap.centre.x + shiftX, y: cap.centre.y + shiftY };
        }
        moved = true;
      }
    }
    if (!moved) break;
  }

  return result;
}
