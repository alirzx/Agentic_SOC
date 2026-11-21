/**
 * "Related" in the entity panel: the leaves one edge away from the selection.
 *
 * The rule is deliberately literal — one edge, not a neighbourhood walk. A
 * selected host used to drag in everything it could reach through key tokens
 * and observation hubs, which is a campaign-wide selection nobody asked for.
 * One edge means a direct `OBSERVATION` / key-projection link between two
 * entities.
 *
 * Observation nodes and `key:` tokens are not leaves: an observation is the
 * relation between entities and a key token is an attribute of one, so neither
 * is selected as "related" even though the canvas draws edges to them.
 *
 * In the **node projection** the relation is a node, so a leaf's only neighbour
 * is the observation: `host —(OBSERVATION)— observation —(OBSERVATION)— user`.
 * Reading that literally made `Related` a no-op on that projection ("actions as
 * edges" worked, "actions as nodes" did not), so the rule now takes exactly one
 * step *through an observation* — the other participants of the action the
 * selection was part of. It still never walks through a key token or a second
 * observation, so a hub cannot drag the campaign in.
 */

interface EdgeLike {
  source: string;
  target: string;
  kind: string;
}

interface NodeLike {
  id: string;
  kind: string;
}

export interface RelatedOptions {
  /**
   * Kinds that never count as a related leaf. `observation` is the relation
   * itself; `key` is the alert's own token.
   */
  excludeKinds?: Iterable<string>;
}

const DEFAULT_EXCLUDED = ['observation', 'key'];

export function relatedEntities<T extends NodeLike>(
  nodes: readonly T[],
  edges: readonly EdgeLike[],
  selectedIds: Iterable<string>,
  options: RelatedOptions = {}
): T[] {
  const selected = new Set(selectedIds);
  if (selected.size === 0) return [];

  const excluded = new Set(options.excludeKinds ?? DEFAULT_EXCLUDED);
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const found = new Set<string>();

  for (const edge of edges) {
    // Pair links describe observation↔observation similarity, not a relation
    // between two leaves the analyst can act on.
    if (edge.kind === 'CORRELATION') continue;
    if (selected.has(edge.source) && !selected.has(edge.target)) found.add(edge.target);
    else if (selected.has(edge.target) && !selected.has(edge.source)) found.add(edge.source);
  }

  // One step through the relation itself: an observation reached from the
  // selection contributes the entities on its other ends. Only `observation`
  // hops, never `key`, and only one hop — `found` is not extended again.
  const actions = new Set<string>();
  for (const id of found) {
    if (byId.get(id)?.kind === 'observation') actions.add(id);
  }
  if (actions.size > 0) {
    const viaAction = new Set<string>();
    for (const edge of edges) {
      if (edge.kind === 'CORRELATION') continue;
      if (actions.has(edge.source) && !actions.has(edge.target)) viaAction.add(edge.target);
      else if (actions.has(edge.target) && !actions.has(edge.source)) viaAction.add(edge.source);
    }
    // The selection can be on the far end of the same action: never hand it
    // back as "related" to itself.
    for (const id of viaAction) if (!selected.has(id)) found.add(id);
  }

  const related: T[] = [];
  for (const id of found) {
    const node = byId.get(id);
    if (!node) continue;
    if (excluded.has(node.kind)) continue;
    related.push(node);
  }
  return related;
}
