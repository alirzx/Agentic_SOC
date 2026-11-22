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

export interface FitCameraOptions {
  /** The points the frame must contain. */
  points: readonly NodePosition3D[];
  /** The orbit target: the camera always looks at this point. */
  centre: NodePosition3D;
  /** Unit vector from the centre to the camera. */
  direction: NodePosition3D;
  /** Vertical field of view, in degrees. */
  fovDegrees: number;
  /** Viewport width / height. */
  aspect: number;
  /**
   * Fraction of the viewport half-axis the points may fill. Under 1 leaves a
   * margin; 1 touches the edge exactly.
   */
  fill?: number;
  /** World-space radius added around each point — a node mark's half size. */
  pad?: number;
}

const dot = (a: NodePosition3D, b: NodePosition3D) =>
  a.x * b.x + a.y * b.y + a.z * b.z;

const cross = (a: NodePosition3D, b: NodePosition3D): NodePosition3D => ({
  x: a.y * b.z - a.z * b.y,
  y: a.z * b.x - a.x * b.z,
  z: a.x * b.y - a.y * b.x,
});

function unit(vector: NodePosition3D): NodePosition3D {
  const length = Math.hypot(vector.x, vector.y, vector.z) || 1;
  return { x: vector.x / length, y: vector.y / length, z: vector.z / length };
}

/**
 * Camera distance at which every point fits the frame at the requested fill.
 *
 * The orbit view used to frame itself from the bounding radius (a fixed
 * multiple of it), which is the wrong quantity: those bounds span the empty gaps
 * between bubbles as well as the bubbles themselves, so a campaign floated in
 * the middle third of the canvas and Fit read as a zoom-out.
 *
 * The projection is solved instead of approximated: each point is projected into
 * the camera's own axes at a trial distance, and its mark is padded by `pad`
 * (marks are camera-facing sprites of fixed world width, so the padding is a
 * share of the depth). The camera always looks at `centre` from the same
 * direction, so the view axes are constant and only the depth changes with the
 * distance — which makes the fit monotonic and a bisection exact to well under a
 * pixel.
 */
export function fitCameraDistance(options: FitCameraOptions): number {
  const fill = options.fill ?? 0.92;
  const pad = options.pad ?? 0;
  const halfVertical = Math.tan((Math.max(1, options.fovDegrees) * Math.PI) / 360);
  const aspect = Math.max(0.01, options.aspect);
  const direction = unit(options.direction);
  // Any up vector that is not the view direction; the frame is symmetric, so
  // only the magnitudes of the projected coordinates matter.
  const up =
    Math.abs(direction.y) > 0.99 ? { x: 1, y: 0, z: 0 } : { x: 0, y: 1, z: 0 };
  const right = unit(cross(up, direction));
  const upAxis = cross(direction, right);

  const offsets = options.points.map((point) => {
    const offset = {
      x: point.x - options.centre.x,
      y: point.y - options.centre.y,
      z: point.z - options.centre.z,
    };
    return {
      x: dot(offset, right),
      y: dot(offset, upAxis),
      depth: dot(offset, direction),
      radius: Math.hypot(offset.x, offset.y, offset.z),
    };
  });
  if (offsets.length === 0) return 1;

  const fits = (distance: number) =>
    offsets.every((offset) => {
      const depth = distance - offset.depth;
      if (depth <= 1e-6) return false;
      const padNdc = pad / (depth * halfVertical);
      return (
        Math.abs(offset.x) / (depth * halfVertical * aspect) + padNdc <= fill &&
        Math.abs(offset.y) / (depth * halfVertical) + padNdc <= fill
      );
    });

  // Start from "just outside the furthest point" and open up until it fits, then
  // bisect. The distance that fits is unique because every term falls as the
  // camera backs away.
  let high = Math.max(...offsets.map((offset) => offset.radius)) + 1;
  for (let guard = 0; guard < 64 && !fits(high); guard += 1) high *= 2;
  let low = 0;
  for (let step = 0; step < 48; step += 1) {
    const middle = (low + high) / 2;
    if (fits(middle)) high = middle;
    else low = middle;
  }
  return high;
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
