/**
 * Deterministic 3D placement for the correlation graph.
 *
 * The 2D canvas earns its readability from the community pass: bubbles joined
 * by their shared evidence. The 3D view keeps that same partition and gives
 * each bubble volume — a cluster becomes a small sphere of nodes, and the
 * clusters themselves sit on a larger sphere so orbiting reveals the campaign
 * from every side without a physics simulation.
 *
 * Pure and deterministic (ids sorted, golden-angle spirals), so the scene is
 * identical on every open and testable without WebGL.
 */

export interface NodePosition3D {
  x: number;
  y: number;
  z: number;
}

export interface Layout3DOptions {
  /** Multiplier on the radius that carries the cluster centres. */
  spread?: number;
}

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

/**
 * Radius of one community's own sphere, grown by its member count.
 *
 * The cube root keeps the density of a bubble constant as it fills up, which is
 * what a plain packing would do — but a mark has a floor below which it stops
 * being clickable, so a 84-node bubble needs visibly more air per node than a
 * 12-node one, not the same. The relief term is that extra air: it grows the
 * bubbles (and, because the shell is sized from the widest bubble, the gaps
 * between them) only once a community is already busy, so a small campaign
 * looks exactly as it did before.
 */
function clusterRadius(size: number): number {
  const shell = Math.cbrt(Math.max(1, size));
  const relief = 1 + 0.12 * Math.max(0, shell - 2);
  return 18 + 14 * shell * relief;
}

export function layoutGraph3D(
  nodeIds: readonly string[],
  communityOf: ReadonlyMap<string, string>,
  options: Layout3DOptions = {}
): Map<string, NodePosition3D> {
  const spread = options.spread ?? 1;

  const groups = new Map<string, string[]>();
  for (const id of [...nodeIds].sort((a, b) => a.localeCompare(b))) {
    const community = communityOf.get(id) ?? 'h:isolated';
    const members = groups.get(community);
    if (members) members.push(id);
    else groups.set(community, [id]);
  }

  // Biggest community at the north pole-ish start, then by id: a stable order
  // is what makes the scene the same on every open.
  const keys = [...groups.keys()].sort((a, b) => {
    const sizeDiff = groups.get(b)!.length - groups.get(a)!.length;
    return sizeDiff !== 0 ? sizeDiff : a.localeCompare(b);
  });
  const count = keys.length;
  const widest = Math.max(...keys.map((key) => clusterRadius(groups.get(key)!.length)));
  const shell = spread * widest * (1.5 + 0.9 * Math.sqrt(count));
  // A flatter sphere: orbiting is easier to follow when the scene is not a
  // perfect ball, and labels at the poles stop fighting the camera.
  const verticalSquash = 0.72;

  const result = new Map<string, NodePosition3D>();
  keys.forEach((key, clusterIndex) => {
    const members = groups.get(key)!;
    const y = count === 1 ? 0 : 1 - (2 * (clusterIndex + 0.5)) / count;
    const ring = Math.sqrt(Math.max(0, 1 - y * y));
    const theta = GOLDEN_ANGLE * clusterIndex;
    const centre = {
      x: Math.cos(theta) * ring * shell,
      y: y * shell * verticalSquash,
      z: Math.sin(theta) * ring * shell,
    };
    const radius = clusterRadius(members.length);

    members.forEach((id, memberIndex) => {
      const memberY = 1 - (2 * (memberIndex + 0.5)) / members.length;
      const memberRing = Math.sqrt(Math.max(0, 1 - memberY * memberY));
      const memberTheta = GOLDEN_ANGLE * memberIndex + (clusterIndex % 11) * 0.7;
      result.set(id, {
        x: centre.x + Math.cos(memberTheta) * memberRing * radius,
        y: centre.y + memberY * radius,
        z: centre.z + Math.sin(memberTheta) * memberRing * radius,
      });
    });
  });

  return result;
}

/**
 * Typical distance between neighbouring nodes in a finished layout.
 *
 * The orbit view needs this to size a mark: the mark must stay narrower than
 * the room the layout gives it, or a campaign with dedup switched off paints a
 * ball of overlapping silhouettes that hides both its nodes and its links.
 *
 * Sampled, not exact. The full pairwise matrix is 810k distance tests on a
 * 900-node campaign, and the mark only needs the order of magnitude, so every
 * `sampleSize`-th node is measured against all of them. Distances are in the
 * layout's own world units and scale with the scene, so callers should express
 * a mark size as a fraction of this rather than as an absolute number.
 */
export function estimateNodeSpacing(
  positions: ReadonlyMap<string, NodePosition3D>,
  ids: readonly string[],
  sampleSize = 220
): number {
  const points: NodePosition3D[] = [];
  for (const id of ids) {
    const point = positions.get(id);
    if (point) points.push(point);
  }
  if (points.length < 2) return 0;

  const step = Math.max(1, Math.ceil(points.length / sampleSize));
  const nearest: number[] = [];
  for (let index = 0; index < points.length; index += step) {
    const from = points[index];
    let best = Infinity;
    for (let other = 0; other < points.length; other += 1) {
      if (other === index) continue;
      const to = points[other];
      const distance = Math.hypot(from.x - to.x, from.y - to.y, from.z - to.z);
      if (distance < best) best = distance;
    }
    if (Number.isFinite(best)) nearest.push(best);
  }
  if (nearest.length === 0) return 0;

  nearest.sort((a, b) => a - b);
  // The lower quartile rather than the median: the cap exists to protect the
  // tightest corner of the scene, not the average bubble.
  return nearest[Math.floor(nearest.length * 0.25)];
}
