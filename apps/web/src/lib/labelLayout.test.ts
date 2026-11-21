import { describe, expect, it } from 'vitest';

import { placePills, pillsOverlap, type PillBox } from './labelLayout';

const pill = (key: string, x: number, y: number, width = 80, height = 20): PillBox => ({
  key,
  x,
  y,
  width,
  height,
});

describe('placePills', () => {
  it('separates two pills sitting on the same point', () => {
    const boxes = [pill('a', 100, 100), pill('b', 100, 100)];
    const placed = placePills(boxes);
    const a = { ...boxes[0], ...placed.get('a')! };
    const b = { ...boxes[1], ...placed.get('b')! };

    expect(pillsOverlap(a, b)).toBe(false);
  });

  it('leaves pills that are already apart untouched', () => {
    const boxes = [pill('a', 0, 0), pill('b', 400, 300)];
    const placed = placePills(boxes);

    expect(placed.get('a')).toEqual({ x: 0, y: 0 });
    expect(placed.get('b')).toEqual({ x: 400, y: 300 });
  });

  it('clears a crowded row of five pills', () => {
    const boxes = [0, 20, 40, 60, 80].map((offset, index) => pill(`p${index}`, 200, 100 + offset));
    const placed = placePills(boxes, { maxShift: 400 });
    const resolved = boxes.map((box) => ({ ...box, ...placed.get(box.key)! }));

    for (let i = 0; i < resolved.length; i += 1) {
      for (let j = i + 1; j < resolved.length; j += 1) {
        expect(pillsOverlap(resolved[i], resolved[j])).toBe(false);
      }
    }
  });

  it('keeps each pill within its shift budget', () => {
    const boxes = Array.from({ length: 8 }, (_, index) => pill(`p${index}`, 100, 100));
    const placed = placePills(boxes, { maxShift: 30 });

    for (const box of boxes) {
      const point = placed.get(box.key)!;
      expect(Math.abs(point.x - box.x)).toBeLessThanOrEqual(30);
      expect(Math.abs(point.y - box.y)).toBeLessThanOrEqual(30);
    }
  });

  it('is deterministic for the same input', () => {
    const boxes = [pill('b', 10, 10), pill('a', 12, 11)];
    const first = placePills(boxes);
    const second = placePills([...boxes].reverse());

    expect([...first.entries()]).toEqual([...second.entries()]);
  });
});
