import { describe, expect, it } from 'vitest';

import { edgeLengthFor, repulsionFor } from './forceParams';

describe('repulsionFor', () => {
  it('grows with the fan-out', () => {
    expect(repulsionFor(20, 'roomy')).toBeGreaterThan(repulsionFor(2, 'roomy'));
    expect(repulsionFor(60, 'roomy')).toBeGreaterThan(repulsionFor(20, 'roomy'));
  });

  it('caps the growth so one node cannot own the canvas', () => {
    expect(repulsionFor(48, 'roomy')).toBe(repulsionFor(400, 'roomy'));
  });

  it('keeps the compact mode tighter than roomy at the same degree', () => {
    expect(repulsionFor(10, 'compact')).toBeLessThan(repulsionFor(10, 'roomy'));
  });
});

describe('edgeLengthFor', () => {
  it('lengthens edges attached to a busy hub', () => {
    expect(edgeLengthFor(12, 'roomy')).toBeGreaterThan(edgeLengthFor(1, 'roomy'));
  });

  it('caps the length so a hub does not push its leaves off-screen', () => {
    expect(edgeLengthFor(24, 'roomy')).toBe(edgeLengthFor(200, 'roomy'));
  });

  it('scales both modes equally', () => {
    expect(edgeLengthFor(6, 'compact')).toBeLessThan(edgeLengthFor(6, 'roomy'));
  });
});
