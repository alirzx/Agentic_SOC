import { describe, expect, it } from 'vitest';

import { relatedEntities } from './relatedEntities';

const nodes = [
  { id: 'host:a', kind: 'host' },
  { id: 'user:bob', kind: 'user' },
  { id: 'ip:1.2.3.4', kind: 'ip' },
  { id: 'key:dsn', kind: 'key' },
  { id: 'obs:1', kind: 'observation' },
  { id: 'host:far', kind: 'host' },
  // The node projection: host:a's only neighbour is the action it took part in.
  { id: 'obs:2', kind: 'observation' },
  { id: 'ip:9.9.9.9', kind: 'ip' },
  { id: 'obs:3', kind: 'observation' },
  { id: 'host:third', kind: 'host' },
];

const edges = [
  { source: 'host:a', target: 'user:bob', kind: 'OBSERVATION' },
  { source: 'host:a', target: 'key:dsn', kind: 'CONTRIBUTES_KEY' },
  { source: 'obs:1', target: 'host:far', kind: 'OBSERVATION' },
  { source: 'user:bob', target: 'ip:1.2.3.4', kind: 'CORRELATION' },
  { source: 'host:a', target: 'obs:2', kind: 'OBSERVATION' },
  { source: 'obs:2', target: 'ip:9.9.9.9', kind: 'OBSERVATION' },
  // Two hops away from the action: never reached.
  { source: 'obs:2', target: 'obs:3', kind: 'CORRELATION' },
  { source: 'obs:3', target: 'host:third', kind: 'OBSERVATION' },
];

describe('relatedEntities', () => {
  it('returns the leaves one edge away', () => {
    // host:a is linked to user:bob directly and to ip:9.9.9.9 through obs:2.
    const related = relatedEntities(nodes, edges, ['host:a']).map((node) => node.id);
    expect(related).toHaveLength(2);
    expect(related).toEqual(expect.arrayContaining(['user:bob', 'ip:9.9.9.9']));
  });

  it('does not select key tokens or observation nodes', () => {
    const related = relatedEntities(nodes, edges, ['host:a']).map((node) => node.kind);
    expect(related).not.toContain('key');
    expect(related).not.toContain('observation');
  });

  it('does not walk two edges out', () => {
    // obs:1 → host:far is one hop from an observation host:a is not part of.
    const related = relatedEntities(nodes, edges, ['host:a']);
    expect(related.some((node) => node.id === 'host:far')).toBe(false);
  });

  it('reaches the other participants of an action the selection took part in', () => {
    // Actions-as-nodes: host:a — obs:2 — ip:9.9.9.9.
    const related = relatedEntities(nodes, edges, ['host:a']).map((node) => node.id);
    expect(related).toContain('ip:9.9.9.9');
    expect(related).toContain('user:bob');
    // The observation itself and the key token are still not leaves.
    expect(related).not.toContain('obs:2');
    expect(related).not.toContain('key:dsn');
    // And it stops there: obs:3 is behind a pair link from obs:2.
    expect(related).not.toContain('host:third');
  });

  it('ignores pair links', () => {
    // ip:1.2.3.4 is reachable only through a CORRELATION link, which is not a
    // relation between two leaves.
    const related = relatedEntities(nodes, edges, ['user:bob']).map((node) => node.id);
    expect(related).toEqual(['host:a']);
  });

  it('never returns something already selected', () => {
    const related = relatedEntities(nodes, edges, ['host:a', 'user:bob']).map((node) => node.id);
    expect(related).not.toContain('host:a');
    expect(related).not.toContain('user:bob');
    expect(related).toEqual(['ip:9.9.9.9']);
  });

  it('is empty without a selection', () => {
    expect(relatedEntities(nodes, edges, [])).toEqual([]);
  });
});
