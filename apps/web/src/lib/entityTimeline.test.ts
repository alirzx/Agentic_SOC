import { describe, expect, it } from 'vitest';

import { buildEntityTimeline, observationHasEntity, type ObservationLike } from './entityTimeline';

const observation = (overrides: Partial<ObservationLike>): ObservationLike => ({
  observation_key: 'entity|T1003|aaa',
  role: 'credential_access:lsass',
  first_seen: '2026-11-14T08:00:00Z',
  ...overrides,
});

const entity = { id: 'host:b_104', kind: 'host', label: 'b_104', token: 'host:b_104' };

describe('observationHasEntity', () => {
  it('matches on the engine token', () => {
    expect(
      observationHasEntity(observation({ tokens: [{ token: 'host:b_104' }] }), entity)
    ).toBe(true);
  });

  it('falls back to the kind’s entity list', () => {
    expect(observationHasEntity(observation({ hosts: ['b_104'] }), entity)).toBe(true);
    expect(observationHasEntity(observation({ hosts: ['other'] }), entity)).toBe(false);
  });

  it('does not match a different value of the same kind', () => {
    expect(
      observationHasEntity(observation({ tokens: [{ token: 'host:b_105' }] }), entity)
    ).toBe(false);
  });
});

describe('buildEntityTimeline', () => {
  const observations = [
    observation({
      observation_key: 'later',
      first_seen: '2026-11-14T10:00:00Z',
      hosts: ['b_104'],
    }),
    observation({
      observation_key: 'first',
      first_seen: '2026-11-14T07:30:00Z',
      hosts: ['b_104'],
    }),
    observation({ observation_key: 'unrelated', hosts: ['other'] }),
  ];
  const timeline = [
    { alert_id: 'a2', observation_key: 'later', title: 'Second', time: '2026-11-14T10:05:00Z' },
    { alert_id: 'a1', observation_key: 'first', title: 'First', time: '2026-11-14T07:31:00Z' },
    { alert_id: 'a0', observation_key: 'first', title: 'Earlier', time: '2026-11-14T07:20:00Z' },
    { alert_id: 'z9', observation_key: 'unrelated', title: 'Other', time: '2026-11-14T06:00:00Z' },
  ];

  it('links the entity to the observation that saw it first', () => {
    const detail = buildEntityTimeline(entity, observations, timeline);
    expect(detail.firstObservation?.key).toBe('first');
    expect(detail.firstObservation?.at).toBe('2026-11-14T07:20:00.000Z');
  });

  it('orders events by time and drops unrelated observations', () => {
    const detail = buildEntityTimeline(entity, observations, timeline);
    expect(detail.events.map((event) => event.alertId)).toEqual(['a0', 'a1', 'a2']);
    expect(detail.events.map((event) => event.title)).toEqual(['Earlier', 'First', 'Second']);
  });

  it('counts each observation’s own events', () => {
    const detail = buildEntityTimeline(entity, observations, timeline);
    expect(detail.observations.map((entry) => [entry.key, entry.events])).toEqual([
      ['first', 2],
      ['later', 1],
    ]);
  });

  it('uses first_seen when an observation has no events in the timeline', () => {
    const detail = buildEntityTimeline(entity, observations, []);
    expect(detail.firstObservation?.key).toBe('first');
    expect(detail.firstObservation?.at).toBe('2026-11-14T07:30:00.000Z');
    expect(detail.events).toHaveLength(0);
  });

  it('returns an empty timeline for an entity nothing links to', () => {
    const detail = buildEntityTimeline(
      { id: 'host:ghost', kind: 'host', label: 'ghost', token: 'host:ghost' },
      observations,
      timeline
    );
    expect(detail.firstObservation).toBeNull();
    expect(detail.events).toHaveLength(0);
  });
});
