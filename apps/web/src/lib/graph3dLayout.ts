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

/** Radius of one community's own sphere, grown by its member count. */
function clusterRadius(size: number): number {
  return 18 + 14 * Math.cbrt(Math.max(1, size));
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
