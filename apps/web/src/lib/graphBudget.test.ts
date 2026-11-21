import { describe, expect, it } from 'vitest';

import { expandRadii, selectBudgetedEdges, type BudgetEdge } from './graphBudget';

const star = (spokes: number, weight: (index: number) => number): BudgetEdge[] =>
  Array.from({ length: spokes }, (_, index) => ({
    id: `hub-l${index}`,
    source: 'host:hub',
    target: `obs:${index}`,
    weight: weight(index),
  }));

const degree = (edges: BudgetEdge[]): Map<string, number> => {
  const counts = new Map<string, number>();
  for (const edge of edges) {
    counts.set(edge.source, (counts.get(edge.source) ?? 0) + 1);
    counts.set(edge.target, (counts.get(edge.target) ?? 0) + 1);
  }
  return counts;
};

describe('selectBudgetedEdges', () => {
  it('caps a hub at the budget instead of letting leaves add their own', () => {
    // Regression: this hub used to draw all ten spokes, because each leaf kept
    // the hub in its own top-4 list regardless of the hub's budget.
    const kept = selectBudgetedEdges(star(10, () => 1), 4);
    expect(kept).toHaveLength(4);
    expect(degree(kept).get('host:hub')).toBe(4);
  });

  it('gives the seats to the strongest links', () => {
    const kept = selectBudgetedEdges(star(10, (index) => index), 3);
    expect(kept.map((edge) => edge.id).sort()).toEqual(['hub-l7', 'hub-l8', 'hub-l9']);
  });

  it('never exceeds the budget on any node, not just the strongest', () => {
    const edges: BudgetEdge[] = [
      { id: 'a1', source: 'h1', target: 'x', weight: 5 },
      { id: 'a2', source: 'h1', target: 'y', weight: 4 },
      { id: 'b1', source: 'h2', target: 'x', weight: 3 },
      { id: 'b2', source: 'h2', target: 'z', weight: 2 },
      { id: 'c1', source: 'x', target: 'w', weight: 1 },
    ];
    const kept = selectBudgetedEdges(edges, 2);
    for (const count of degree(kept).values()) expect(count).toBeLessThanOrEqual(2);
    // `x` filled its two seats with the stronger links, so the weakest goes.
    expect(kept.map((edge) => edge.id)).not.toContain('c1');
  });

  it('keeps every edge of a node the analyst expanded', () => {
    const kept = selectBudgetedEdges(star(10, () => 1), 2, new Set(['host:hub']));
    expect(kept).toHaveLength(10);
  });

  it('draws everything when the budget is all', () => {
    const edges = star(10, () => 1);
    expect(selectBudgetedEdges(edges, 'all')).toHaveLength(10);
  });

  it('breaks ties deterministically', () => {
    const edges: BudgetEdge[] = [
      { id: 'b', source: 'h', target: 'y', weight: 1 },
      { id: 'a', source: 'h', target: 'x', weight: 1 },
    ];
    expect(selectBudgetedEdges(edges, 1).map((edge) => edge.id)).toEqual(['a']);
    expect(selectBudgetedEdges([...edges].reverse(), 1).map((edge) => edge.id)).toEqual(['a']);
  });
});

describe('expandRadii', () => {
  // h — a — b — c, a line the expand button walks one layer at a time.
  const line: BudgetEdge[] = [
    { id: 'h-a', source: 'h', target: 'a' },
    { id: 'a-b', source: 'a', target: 'b' },
    { id: 'b-c', source: 'b', target: 'c' },
  ];

  it('exempts only the node itself at depth 1', () => {
    expect([...expandRadii(line, new Map([['h', 1]]))]).toEqual(['h']);
  });

  it('adds one ring per extra layer', () => {
    expect([...expandRadii(line, new Map([['h', 2]]))].sort()).toEqual(['a', 'h']);
    expect([...expandRadii(line, new Map([['h', 3]]))].sort()).toEqual(['a', 'b', 'h']);
    expect([...expandRadii(line, new Map([['h', 4]]))].sort()).toEqual(['a', 'b', 'c', 'h']);
  });

  it('stops at the edge of the graph instead of looping', () => {
    // Undirected walk from the far end reaches the whole line and terminates.
    expect([...expandRadii(line, new Map([['c', 9]]))].sort()).toEqual(['a', 'b', 'c', 'h']);
  });

  it('unions every expanded node', () => {
    const both = expandRadii(line, new Map([['h', 2], ['c', 2]]));
    expect([...both].sort()).toEqual(['a', 'b', 'c', 'h']);
  });

  it('exempts nothing when no node was expanded', () => {
    expect(expandRadii(line, new Map()).size).toBe(0);
  });

  it('widens what the budget lets through', () => {
    // Each extra layer exempts more endpoints, so more edges survive budget 1.
    const shallow = selectBudgetedEdges(line, 1, expandRadii(line, new Map([['h', 1]])));
    const deep = selectBudgetedEdges(line, 1, expandRadii(line, new Map([['h', 3]])));
    expect(deep.length).toBeGreaterThan(shallow.length);
    expect(deep).toHaveLength(line.length);
  });
});
