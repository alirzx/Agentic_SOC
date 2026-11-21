import { describe, expect, it } from 'vitest';

import { arrangeStars, type StarPoint } from './starLayout';

/** Symmetric adjacency from an undirected edge list. */
const build = (edges: [string, string][]) => {
  const adjacency = new Map<string, string[]>();
  for (const [a, b] of edges) {
    if (!adjacency.has(a)) adjacency.set(a, []);
    if (!adjacency.has(b)) adjacency.set(b, []);
    adjacency.get(a)!.push(b);
    adjacency.get(b)!.push(a);
  }
  return adjacency;
};

const hubWithLeaves = (hub: string, count: number) =>
  Array.from({ length: count }, (_, index) => [hub, `${hub}-${index}`] as [string, string]);

const positionsFor = (ids: string[], at: StarPoint = { x: 0, y: 0 }) =>
  new Map(ids.map((id) => [id, { ...at }]));

describe('arrangeStars', () => {
  it('places a hub’s leaves on a ring instead of on top of each other', () => {
    const edges = hubWithLeaves('hub', 8);
    const adjacency = build(edges);
    const ids = [...adjacency.keys()];
    const positions = positionsFor(ids, { x: 100, y: 100 });

    const arranged = arrangeStars(positions, adjacency, { minNodes: 1 });
    const hub = arranged.get('hub')!;
    const leaves = ids.filter((id) => id !== 'hub').map((id) => arranged.get(id)!);

    const radii = leaves.map((leaf) => Math.hypot(leaf.x - hub.x, leaf.y - hub.y));
    const radius = radii[0];
    expect(radius).toBeGreaterThan(40);
    for (const value of radii) expect(value).toBeCloseTo(radius, 6);

    // Evenly spaced: the angular gap between neighbours is constant.
    const angles = leaves
      .map((leaf) => Math.atan2(leaf.y - hub.y, leaf.x - hub.x))
      .sort((a, b) => a - b);
    const gaps = angles.slice(1).map((angle, index) => angle - angles[index]);
    for (const gap of gaps) expect(gap).toBeCloseTo(gap, 6);
    expect(Math.min(...gaps)).toBeGreaterThan(0.3);
  });

  it('aims the cap away from the trunk', () => {
    // hub has one anchor (its onward link) plus eight leaves.
    const edges: [string, string][] = [...hubWithLeaves('hub', 8), ['hub', 'trunk']];
    // Give the trunk its own neighbours so it is not leaf-like.
    edges.push(['trunk', 't1'], ['trunk', 't2'], ['trunk', 't3']);
    const adjacency = build(edges);
    const positions = positionsFor([...adjacency.keys()]);
    positions.set('trunk', { x: 200, y: 0 });
    positions.set('t1', { x: 300, y: 0 });
    positions.set('t2', { x: 300, y: 60 });
    positions.set('t3', { x: 300, y: -60 });

    const arranged = arrangeStars(positions, adjacency, { minNodes: 1 });
    const hub = arranged.get('hub')!;
    const trunk = arranged.get('trunk')!;
    const towardTrunk = { x: trunk.x - hub.x, y: trunk.y - hub.y };

    const leaves = [...adjacency.keys()].filter((id) => id.startsWith('hub-'));
    const ahead = leaves.filter((id) => {
      const leaf = arranged.get(id)!;
      const dot = (leaf.x - hub.x) * towardTrunk.x + (leaf.y - hub.y) * towardTrunk.y;
      return dot > 0;
    });
    // The cap sits on the far side: at most the one leaf per shoulder crosses.
    expect(ahead.length).toBeLessThanOrEqual(2);
  });

  it('drags a leaf’s own subtree with it, keeping the bush shape', () => {
    // `hub-0` keeps degree 2 (hub + its own child), so it is still leaf-like
    // and its child rides along with it.
    const edges: [string, string][] = [...hubWithLeaves('hub', 6), ['hub-0', 'sub-1']];
    const adjacency = build(edges);
    const ids = [...adjacency.keys()];
    const positions = positionsFor(ids, { x: 0, y: 0 });
    positions.set('sub-1', { x: 10, y: 4 });

    const arranged = arrangeStars(positions, adjacency, { minNodes: 1 });
    const leaf = arranged.get('hub-0')!;
    const before = positions.get('hub-0')!;
    const dx = leaf.x - before.x;
    const dy = leaf.y - before.y;
    expect(dx * dx + dy * dy).toBeGreaterThan(1);

    expect(arranged.get('sub-1')!.x).toBeCloseTo(10 + dx, 6);
    expect(arranged.get('sub-1')!.y).toBeCloseTo(4 + dy, 6);
  });

  it('keeps two neighbouring stars out of each other’s leaves', () => {
    const edges: [string, string][] = [...hubWithLeaves('a', 10), ...hubWithLeaves('b', 10), ['a', 'b']];
    const adjacency = build(edges);
    const positions = positionsFor([...adjacency.keys()]);

    const arranged = arrangeStars(positions, adjacency, { minNodes: 1 });
    const a = arranged.get('a')!;
    const b = arranged.get('b')!;
    const radius = Math.hypot(arranged.get('a-0')!.x - a.x, arranged.get('a-0')!.y - a.y);
    expect(Math.hypot(b.x - a.x, b.y - a.y)).toBeGreaterThan(radius * 1.5);
  });

  it('leaves small hubs and small graphs alone', () => {
    const small = build(hubWithLeaves('hub', 4));
    const positions = positionsFor([...small.keys()], { x: 5, y: 5 });
    expect([...arrangeStars(positions, small, { minNodes: 1 }).entries()]).toEqual([...positions.entries()]);
  });

  it('is deterministic regardless of input order', () => {
    const adjacency = build([...hubWithLeaves('hub', 7), ['hub', 'trunk'], ['trunk', 'x'], ['trunk', 'y']]);
    const ids = [...adjacency.keys()];
    const positions = positionsFor(ids);
    const first = arrangeStars(positions, adjacency, { minNodes: 1 });
    const reversed = new Map([...positions.entries()].reverse());
    const second = arrangeStars(reversed, adjacency, { minNodes: 1 });
    for (const id of ids) {
      expect(second.get(id)!.x).toBeCloseTo(first.get(id)!.x, 6);
      expect(second.get(id)!.y).toBeCloseTo(first.get(id)!.y, 6);
    }
  });
});
