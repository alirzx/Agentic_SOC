/**
 * Collision avoidance for the 2D cluster pills.
 *
 * Pills sit on their bubble's centroid, and centroids are not spread out: at
 * mid zoom two neighbouring bubbles project their pills onto almost the same
 * screen point, and the names stack into an unreadable pile exactly where the
 * analyst is zooming in to read them. A real label engine (d3-force-collide,
 * simulated annealing) is overkill for a dozen pills; an AABB push apart along
 * the axis of least overlap is enough, and it is deterministic.
 *
 * The boxes are already in screen pixels and each pill is drawn centred on its
 * point (`-translate-x-1/2 -translate-y-1/2`), which is the geometry used here.
 */

export interface PillBox {
  key: string;
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface PlacedPill {
  x: number;
  y: number;
}

export interface PlaceOptions {
  /** Breathing room between two pills, in px. */
  padding?: number;
  /** Bounded sweeps; a dozen pills settle in a handful. */
  iterations?: number;
  /** A pill never travels further than this from its bubble's centroid (px). */
  maxShift?: number;
}

const clamp = (value: number, min: number, max: number): number =>
  Math.min(max, Math.max(min, value));

export function placePills(
  boxes: readonly PillBox[],
  options: PlaceOptions = {}
): Map<string, PlacedPill> {
  const padding = options.padding ?? 6;
  const iterations = options.iterations ?? 24;
  const maxShift = options.maxShift ?? 140;

  const placed = boxes
    .slice()
    .sort((a, b) => a.key.localeCompare(b.key))
    .map((box) => ({ ...box, originX: box.x, originY: box.y }));

  for (let sweep = 0; sweep < iterations; sweep += 1) {
    let moved = false;
    for (let i = 0; i < placed.length; i += 1) {
      for (let j = i + 1; j < placed.length; j += 1) {
        const a = placed[i];
        const b = placed[j];
        const overlapX = (a.width + b.width) / 2 + padding - Math.abs(a.x - b.x);
        const overlapY = (a.height + b.height) / 2 + padding - Math.abs(a.y - b.y);
        if (overlapX <= 0 || overlapY <= 0) continue;
        moved = true;

        // Split along the axis that needs less travel, so a stack of pills
        // slides apart instead of all jumping sideways.
        if (overlapY <= overlapX) {
          const direction = a.y <= b.y ? 1 : -1;
          const step = overlapY / 2 + 0.5;
          a.y -= direction * step;
          b.y += direction * step;
        } else {
          const direction = a.x <= b.x ? 1 : -1;
          const step = overlapX / 2 + 0.5;
          a.x -= direction * step;
          b.x += direction * step;
        }

        a.y = clamp(a.y, a.originY - maxShift, a.originY + maxShift);
        b.y = clamp(b.y, b.originY - maxShift, b.originY + maxShift);
        a.x = clamp(a.x, a.originX - maxShift, a.originX + maxShift);
        b.x = clamp(b.x, b.originX - maxShift, b.originX + maxShift);
      }
    }
    if (!moved) break;
  }

  return new Map(placed.map((pill) => [pill.key, { x: pill.x, y: pill.y }]));
}

/** Overlap test used by the tests and by callers that want to assert the result. */
export function pillsOverlap(a: PillBox, b: PillBox, padding = 0): boolean {
  return (
    Math.abs(a.x - b.x) < (a.width + b.width) / 2 + padding &&
    Math.abs(a.y - b.y) < (a.height + b.height) / 2 + padding
  );
}
