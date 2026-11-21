import { describe, expect, it } from 'vitest';

import { applyMagnetism, type MagneticEdge, type MagneticNode } from './magneticLayout';

const distance = (
  positions: Map<string, { x: number; y: number }>,
  a: string,
  b: string
): number => {
  const pa = positions.get(a)!;
  const pb = positions.get(b)!;
  return Math.hypot(pa.x - pb.x, pa.y - pb.y);
};

const linked: MagneticEdge[] = [{ source: 'host:a', target: 'user:b', weight: 6 }];

const nodes = (): MagneticNode[] => [
  { id: 'host:a', x: 0, y: 0 },
  { id: 'user:b', x: 300, y: 0 },
  { id: 'ip:1', x: 4, y: 0 },
];

describe('applyMagnetism', () => {
  it('pulls a linked pair toward its rest length', () => {
    const before = distance(new Map(nodes().map((n) => [n.id, { x: n.x, y: n.y }])), 'host:a', 'user:b');
    const after = applyMagnetism(nodes(), [{ source: 'host:a', target: 'user:b', weight: 2 }], {
      iterations: 20,
    });
    expect(distance(after, 'host:a', 'user:b')).toBeLessThan(before);
  });

  it('keeps a strong link shorter than a weak one', () => {
    const strong = applyMagnetism(nodes(), [{ source: 'host:a', target: 'user:b', weight: 12 }], {
      iterations: 30,
      targetLength: 200,
    });
    const weak = applyMagnetism(nodes(), [{ source: 'host:a', target: 'user:b', weight: 0 }], {
      iterations: 30,
      targetLength: 200,
    });
    expect(distance(strong, 'host:a', 'user:b')).toBeLessThan(
      distance(weak, 'host:a', 'user:b')
    );
  });

  it('pushes two unlinked leaves out of the padding', () => {
    const after = applyMagnetism(
      [
        { id: 'ip:1', x: 0, y: 0 },
        { id: 'ip:2', x: 2, y: 0 },
      ],
      [],
      { iterations: 20, padding: 20 }
    );
    expect(distance(after, 'ip:1', 'ip:2')).toBeGreaterThan(10);
  });

  it('leaves a linked pair alone even inside the padding', () => {
    const after = applyMagnetism(
      [
        { id: 'host:a', x: 0, y: 0 },
        { id: 'user:b', x: 2, y: 0 },
      ],
      // Very weak link: the spring wants a long edge, but the point of this test
      // is that adjacency suppresses repulsion entirely.
      [{ source: 'host:a', target: 'user:b', weight: 0 }],
      { iterations: 1, padding: 20, attraction: 0, repulsion: 0.5 }
    );
    expect(distance(after, 'host:a', 'user:b')).toBe(2);
  });

  it('never moves a node further than the per-iteration cap', () => {
    const after = applyMagnetism(nodes(), linked, { iterations: 3, maxStep: 4 });
    const origin = nodes().find((node) => node.id === 'user:b')!;
    const moved = Math.abs(after.get('user:b')!.x - origin.x);
    expect(moved).toBeLessThanOrEqual(12);
  });

  it('is deterministic', () => {
    const first = applyMagnetism(nodes(), linked, { iterations: 12 });
    const second = applyMagnetism([...nodes()].reverse(), [...linked], { iterations: 12 });
    for (const node of nodes()) {
      expect(first.get(node.id)).toEqual(second.get(node.id));
    }
  });

  it('handles empty input', () => {
    expect(applyMagnetism([], []).size).toBe(0);
  });
});
