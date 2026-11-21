/**
 * Degree-aware force parameters for the 2D correlation graph.
 *
 * A force layout treats every node the same: a hub with twenty leaves pulls
 * each of them to one edge length, so its leaves form a tight ring and the ring
 * of the hub next door reaches into the same space. The usual cure is not a
 * hand-drawn star but a hub that pushes harder and a longer first edge:
 *
 * * `nodeRepulsion` grows with the node's own degree, so a hub clears a larger
 *   area before its leaves settle — two busy hubs end up far enough apart that
 *   their fans cannot interleave.
 * * `idealEdgeLength` grows with the fan-out at either end, so a host-to-leaf
 *   edge attached to a busy hub is longer than the same edge between two quiet
 *   nodes. The result is the "tree with a trunk" silhouette rather than rings
 *   wrapped around each other.
 *
 * Pure functions so the curve is testable without a browser; the graph passes
 * them straight to `fcose`, which accepts callables for both options.
 */

export type SpacingMode = 'roomy' | 'compact';

const REPULSION_BASE: Record<SpacingMode, number> = { roomy: 14000, compact: 5000 };
const EDGE_BASE: Record<SpacingMode, number> = { roomy: 165, compact: 110 };

/** Repulsion for a node, growing with how many links it has to keep apart. */
export function repulsionFor(degree: number, mode: SpacingMode): number {
  const fanOut = Math.min(48, Math.max(0, degree));
  return REPULSION_BASE[mode] * (1 + fanOut ** 1.3);
}

/** Edge length for the busier endpoint, so a fan has room to spread. */
export function edgeLengthFor(degree: number, mode: SpacingMode): number {
  const fanOut = Math.min(24, Math.max(0, degree));
  return EDGE_BASE[mode] * (1 + 0.14 * fanOut);
}
