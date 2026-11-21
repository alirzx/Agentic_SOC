import { describe, expect, it } from 'vitest';

import { layoutGraph3D } from './graph3dLayout';

const distance3D = (
  a: { x: number; y: number; z: number },
  b: { x: number; y: number; z: number }
) => Math.hypot(a.x - b.x, a.y - b.y, a.z - b.z);

const centroid = (points: { x: number; y: number; z: number }[]) => ({
  x: points.reduce((sum, point) => sum + point.x, 0) / points.length,
  y: points.reduce((sum, point) => sum + point.y, 0) / points.length,
  z: points.reduce((sum, point) => sum + point.z, 0) / points.length,
});

describe('layoutGraph3D', () => {
  const ids = ['a1', 'a2', 'a3', 'b1', 'b2', 'b3'];
  const communityOf = new Map([
    ['a1', 'c0'],
    ['a2', 'c0'],
    ['a3', 'c0'],
    ['b1', 'c1'],
    ['b2', 'c1'],
    ['b3', 'c1'],
  ]);

  it('places every node once, with finite coordinates', () => {
    const positions = layoutGraph3D(ids, communityOf);
    expect(positions.size).toBe(ids.length);
    for (const point of positions.values()) {
      expect(Number.isFinite(point.x)).toBe(true);
      expect(Number.isFinite(point.y)).toBe(true);
      expect(Number.isFinite(point.z)).toBe(true);
    }
  });

  it('keeps the two communities apart in space', () => {
    const positions = layoutGraph3D(ids, communityOf);
    const a = centroid(['a1', 'a2', 'a3'].map((id) => positions.get(id)!));
    const b = centroid(['b1', 'b2', 'b3'].map((id) => positions.get(id)!));
    expect(distance3D(a, b)).toBeGreaterThan(30);
  });

  it('keeps nodes of one community closer to each other than to the other community', () => {
    const positions = layoutGraph3D(ids, communityOf);
    const near = distance3D(positions.get('a1')!, positions.get('a2')!);
    const far = distance3D(positions.get('a1')!, positions.get('b1')!);
    expect(near).toBeLessThan(far);
  });

  it('is deterministic regardless of input order', () => {
    const first = layoutGraph3D(ids, communityOf);
    const second = layoutGraph3D([...ids].reverse(), communityOf);
    for (const id of ids) {
      expect(second.get(id)).toEqual(first.get(id));
    }
  });

  it('handles a single community without dividing by zero', () => {
    const one = new Map([['a', 'c0'], ['b', 'c0']]);
    const positions = layoutGraph3D(['a', 'b'], one);
    expect(positions.size).toBe(2);
    expect(distance3D(positions.get('a')!, positions.get('b')!)).toBeGreaterThan(0);
  });

  it('honours the spread multiplier', () => {
    const tight = layoutGraph3D(ids, communityOf, { spread: 0.5 });
    const wide = layoutGraph3D(ids, communityOf, { spread: 2 });
    const tightSpan = distance3D(tight.get('a1')!, tight.get('b1')!);
    const wideSpan = distance3D(wide.get('a1')!, wide.get('b1')!);
    expect(wideSpan).toBeGreaterThan(tightSpan);
  });
});
