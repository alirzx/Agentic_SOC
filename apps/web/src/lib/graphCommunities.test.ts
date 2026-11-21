import { describe, expect, it } from 'vitest';

import {
  clusterGraph,
  describeCluster,
  findCommunities,
  partitionByHubs,
  separateCommunities,
  type Point,
} from './graphCommunities';

const centroid = (points: Point[]): Point => ({
  x: points.reduce((sum, point) => sum + point.x, 0) / points.length,
  y: points.reduce((sum, point) => sum + point.y, 0) / points.length,
});

describe('findCommunities', () => {
  it('keeps two dense groups apart', () => {
    const ids = ['a1', 'a2', 'a3', 'b1', 'b2', 'b3'];
    const edges = [
      { source: 'a1', target: 'a2' },
      { source: 'a2', target: 'a3' },
      { source: 'a1', target: 'a3' },
      { source: 'b1', target: 'b2' },
      { source: 'b2', target: 'b3' },
      { source: 'b1', target: 'b3' },
    ];

    const membership = findCommunities(ids, edges);
    expect(membership.get('a1')).toBe(membership.get('a2'));
    expect(membership.get('a2')).toBe(membership.get('a3'));
    expect(membership.get('b1')).toBe(membership.get('b2'));
    expect(membership.get('b2')).toBe(membership.get('b3'));
    expect(membership.get('a1')).not.toBe(membership.get('b1'));
  });

  it('groups a hub with the leaves it alone connects', () => {
    // Two observation hubs, each with its own entities, no link between them.
    const ids = ['obs:1', 'host:1', 'user:1', 'obs:2', 'host:2', 'user:2'];
    const edges = [
      { source: 'obs:1', target: 'host:1' },
      { source: 'obs:1', target: 'user:1' },
      { source: 'obs:2', target: 'host:2' },
      { source: 'obs:2', target: 'user:2' },
    ];

    const membership = findCommunities(ids, edges);
    expect(membership.get('host:1')).toBe(membership.get('obs:1'));
    expect(membership.get('user:1')).toBe(membership.get('obs:1'));
    expect(membership.get('host:2')).toBe(membership.get('obs:2'));
    expect(membership.get('obs:1')).not.toBe(membership.get('obs:2'));
  });

  it('is deterministic across runs and input order', () => {
    const ids = ['n1', 'n2', 'n3', 'n4'];
    const edges = [
      { source: 'n1', target: 'n2' },
      { source: 'n3', target: 'n4' },
    ];
    const first = findCommunities(ids, edges);
    const second = findCommunities([...ids].reverse(), [...edges].reverse());
    for (const id of ids) expect(second.get(id)).toBe(first.get(id));
  });

  it('leaves isolated nodes in their own community', () => {
    const membership = findCommunities(['solo'], []);
    expect(membership.get('solo')).toBe('c0');
  });
});

describe('partitionByHubs', () => {
  it('splits a chain of hubs into contiguous regions', () => {
    // A→B→C→D, no shortcuts: label propagation keeps this as one community.
    const ids = ['a', 'b', 'c', 'd'];
    const edges = [
      { source: 'a', target: 'b' },
      { source: 'b', target: 'c' },
      { source: 'c', target: 'd' },
    ];
    const membership = partitionByHubs(ids, edges, 2);
    expect(new Set(membership.values()).size).toBe(2);
    expect(membership.get('a')).toBe(membership.get('b'));
    expect(membership.get('c')).toBe(membership.get('d'));
  });

  it('gives every node a community, including isolated ones', () => {
    const membership = partitionByHubs(['a', 'b', 'solo'], [{ source: 'a', target: 'b' }], 3);
    expect(membership.size).toBe(3);
    expect(membership.get('solo')).toBeDefined();
  });

  it('is deterministic', () => {
    const ids = ['a', 'b', 'c', 'd', 'e'];
    const edges = [
      { source: 'a', target: 'b' },
      { source: 'b', target: 'c' },
      { source: 'd', target: 'e' },
    ];
    const first = partitionByHubs(ids, edges, 2);
    const second = partitionByHubs([...ids].reverse(), [...edges].reverse(), 2);
    for (const id of ids) expect(second.get(id)).toBe(first.get(id));
  });
});

describe('describeCluster', () => {
  it('names a bubble after its most connected entity', () => {
    const described = describeCluster(
      [
        { id: 'host:a', kind: 'host', label: 'win-dc-01' },
        { id: 'user:b', kind: 'user', label: 'administrator' },
        { id: 'obs:1', kind: 'observation', label: 'credential_access:lsass' },
      ],
      new Map([
        ['host:a', 3],
        ['user:b', 9],
      ])
    );

    expect(described.title).toBe('administrator');
    expect(described.subtitle).toBe('3 · credential_access');
  });

  it('falls back to the dominant role when the bubble holds no entity', () => {
    const described = describeCluster(
      [
        { id: 'obs:1', kind: 'observation', label: 'lateral_movement:smb' },
        { id: 'obs:2', kind: 'observation', label: 'lateral_movement:smb2' },
        { id: 'obs:3', kind: 'observation', label: 'impact:ransom' },
      ],
      new Map()
    );

    expect(described.title).toBe('lateral_movement cluster');
    expect(described.subtitle).toBe('3 · lateral_movement');
  });

  it('breaks ties deterministically', () => {
    const members = [
      { id: 'host:b', kind: 'host', label: 'host-b' },
      { id: 'host:a', kind: 'host', label: 'host-a' },
    ];
    const first = describeCluster(members, new Map());
    const second = describeCluster([...members].reverse(), new Map());
    expect(first.title).toBe('host-a');
    expect(second.title).toBe('host-a');
  });
});

describe('clusterGraph', () => {
  it('gives every node a community and never exceeds the cap', () => {
    const ids = Array.from({ length: 120 }, (_, index) => `n${index}`);
    const edges = ids.slice(1).map((id, index) => ({ source: ids[index], target: id }));
    const membership = clusterGraph(ids, edges);

    expect(membership.size).toBe(ids.length);
    const communities = new Set(membership.values());
    expect(communities.size).toBeGreaterThanOrEqual(2);
    expect(communities.size).toBeLessThanOrEqual(24);
  });
});

describe('separateCommunities', () => {
  it('pushes overlapping cluster circles apart without deforming them', () => {
    const positions = new Map<string, Point>([
      ['a1', { x: 0, y: 0 }],
      ['a2', { x: 40, y: 0 }],
      ['a3', { x: 0, y: 40 }],
      ['b1', { x: 10, y: 10 }],
      ['b2', { x: 50, y: 10 }],
      ['b3', { x: 10, y: 50 }],
    ]);
    const communityOf = new Map<string, string>([
      ['a1', 'c0'],
      ['a2', 'c0'],
      ['a3', 'c0'],
      ['b1', 'c1'],
      ['b2', 'c1'],
      ['b3', 'c1'],
    ]);

    const spread = separateCommunities(positions, communityOf, { gap: 40, margin: 20 });
    const a = centroid(['a1', 'a2', 'a3'].map((id) => spread.get(id)!));
    const b = centroid(['b1', 'b2', 'b3'].map((id) => spread.get(id)!));

    // Rigid bodies: the intra-cluster offsets are untouched.
    expect(spread.get('a2')!.x - spread.get('a1')!.x).toBeCloseTo(40, 6);
    expect(spread.get('a3')!.y - spread.get('a1')!.y).toBeCloseTo(40, 6);
    expect(spread.get('b2')!.x - spread.get('b1')!.x).toBeCloseTo(40, 6);

    // Radius (max member distance from the cluster centre + margin + half the
    // gap) must not overlap.
    const radiusOf = (ids: string[]) => {
      const points = ids.map((id) => positions.get(id)!);
      const centre = centroid(points);
      const far = Math.max(...points.map((point) => Math.hypot(point.x - centre.x, point.y - centre.y)));
      return far + 20 + 20;
    };
    const needed = radiusOf(['a1', 'a2', 'a3']) + radiusOf(['b1', 'b2', 'b3']);
    expect(Math.hypot(b.x - a.x, b.y - a.y)).toBeGreaterThanOrEqual(needed - 1);
  });

  it('keeps the overall picture centred', () => {
    const positions = new Map<string, Point>([
      ['a', { x: 0, y: 0 }],
      ['b', { x: 5, y: 5 }],
    ]);
    const communityOf = new Map<string, string>([
      ['a', 'c0'],
      ['b', 'c1'],
    ]);
    const spread = separateCommunities(positions, communityOf, { gap: 20, margin: 10 });
    const before = centroid([...positions.values()]);
    const after = centroid([...spread.values()]);
    expect(after.x).toBeCloseTo(before.x, 6);
    expect(after.y).toBeCloseTo(before.y, 6);
  });

  it('is a no-op when everything is one community', () => {
    const positions = new Map<string, Point>([
      ['a', { x: 0, y: 0 }],
      ['b', { x: 10, y: 10 }],
    ]);
    const communityOf = new Map<string, string>([
      ['a', 'c0'],
      ['b', 'c0'],
    ]);
    expect([...separateCommunities(positions, communityOf).entries()]).toEqual([...positions.entries()]);
  });

  it('separates exactly coincident clusters deterministically', () => {
    const positions = new Map<string, Point>([
      ['a', { x: 0, y: 0 }],
      ['b', { x: 0, y: 0 }],
    ]);
    const communityOf = new Map<string, string>([
      ['a', 'c0'],
      ['b', 'c1'],
    ]);
    const first = separateCommunities(positions, communityOf);
    const second = separateCommunities(positions, communityOf);
    expect(first.get('a')).toEqual(second.get('a'));
    expect(Math.hypot(first.get('a')!.x - first.get('b')!.x, first.get('a')!.y - first.get('b')!.y)).toBeGreaterThan(1);
  });
});
