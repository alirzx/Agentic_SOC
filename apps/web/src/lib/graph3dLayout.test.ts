import { describe, expect, it } from 'vitest';
import * as THREE from 'three';

import { fitCameraDistance, layoutGraph3D, estimateNodeSpacing } from './graph3dLayout';

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

  it('reports a positive gap between neighbouring nodes', () => {
    const positions = layoutGraph3D(ids, communityOf);
    const gap = estimateNodeSpacing(positions, ids);
    expect(gap).toBeGreaterThan(0);
    // The quartile cannot exceed the longest leg of the layout.
    expect(gap).toBeLessThan(distance3D(positions.get('a1')!, positions.get('b1')!));
  });

  it('frames every point inside the requested fill', () => {
    const points = Array.from({ length: 60 }, (_, index) => ({
      x: Math.cos(index) * 120,
      y: Math.sin(index * 1.7) * 90,
      z: Math.cos(index * 0.6) * 150,
    }));
    const centre = { x: 0, y: 0, z: 0 };
    const direction = { x: 0.45, y: 0.35, z: 1 };
    const distance = fitCameraDistance({
      points,
      centre,
      direction,
      fovDegrees: 55,
      aspect: 1.6,
      fill: 0.92,
    });

    // Verified through three's own projection rather than by repeating the
    // implementation's arithmetic.
    const camera = new THREE.PerspectiveCamera(55, 1.6, 1, 100000);
    const dir = new THREE.Vector3(0.45, 0.35, 1).normalize();
    camera.position.set(0, 0, 0).addScaledVector(dir, distance);
    camera.lookAt(0, 0, 0);
    camera.updateMatrixWorld();
    const probe = new THREE.Vector3();
    let widest = 0;
    for (const point of points) {
      probe.set(point.x, point.y, point.z).project(camera);
      widest = Math.max(widest, Math.abs(probe.x), Math.abs(probe.y));
    }
    expect(widest).toBeGreaterThan(0.9);
    expect(widest).toBeLessThanOrEqual(0.92 + 1e-3);
  });

  it('frames tighter on a wide canvas than on a tall one', () => {
    const points = [
      { x: -300, y: -20, z: 0 },
      { x: 300, y: 20, z: 0 },
    ];
    const centre = { x: 0, y: 0, z: 0 };
    const direction = { x: 0, y: 0, z: 1 };
    const wide = fitCameraDistance({ points, centre, direction, fovDegrees: 55, aspect: 2 });
    const tall = fitCameraDistance({ points, centre, direction, fovDegrees: 55, aspect: 0.5 });
    expect(tall).toBeGreaterThan(wide);
  });

  it('backs off to leave room for the marks around each point', () => {
    const points = [
      { x: -100, y: 0, z: 0 },
      { x: 100, y: 0, z: 0 },
    ];
    const centre = { x: 0, y: 0, z: 0 };
    const direction = { x: 0, y: 0, z: 1 };
    const bare = fitCameraDistance({ points, centre, direction, fovDegrees: 55, aspect: 1 });
    const padded = fitCameraDistance({
      points,
      centre,
      direction,
      fovDegrees: 55,
      aspect: 1,
      pad: 12,
    });
    expect(padded).toBeGreaterThan(bare);
  });

  it('gives a busy bubble more room per node than a small one', () => {
    const small = ['s1', 's2', 's3', 's4'];
    const large = Array.from({ length: 60 }, (_, index) => `l${index}`);
    const smallMap = new Map(small.map((id) => [id, 'c0']));
    const largeMap = new Map(large.map((id) => [id, 'c0']));
    const smallGap = estimateNodeSpacing(layoutGraph3D(small, smallMap), small);
    const largeGap = estimateNodeSpacing(layoutGraph3D(large, largeMap), large);
    expect(largeGap).toBeGreaterThan(0);
    // A bubble of 60 must not keep the density of a bubble of 4.
    expect(largeGap).toBeLessThan(smallGap);
  });
});
