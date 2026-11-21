/**
 * Per-entity timeline for the graph's entity list.
 *
 * The canvas can say "this host is in nine observations"; it cannot say when
 * each of those fired or which one found the host first. That ordering is what
 * tells an analyst whether the host was the entry point or a later hop, so the
 * panel turns an entity into:
 *
 * * the observations that touch it (matched on the engine token, with a
 *   kind→field fallback for graphs built without tokens),
 * * the alerts behind those observations, in time order,
 * * and the earliest of them — the observation that linked the entity first.
 *
 * Pure so the ordering and matching rules are testable without a browser.
 */

export interface EntityRef {
  id: string;
  kind: string;
  label: string;
  token?: string | null;
}

export interface ObservationLike {
  observation_key: string;
  role?: string | null;
  alert_ids?: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  tokens?: { token: string }[];
  hosts?: string[];
  users?: string[];
  ips?: string[];
  domains?: string[];
}

export interface TimelineEventLike {
  alert_id: string;
  observation_key?: string | null;
  title?: string | null;
  payload_title?: string | null;
  severity?: string | null;
  time?: string | null;
}

export interface EntityTimelineEvent {
  alertId: string;
  at: string | null;
  title: string;
  severity: string | null;
  observation: string | null;
}

export interface EntityTimelineObservation {
  key: string;
  role: string | null;
  at: string | null;
  events: number;
}

export interface EntityTimeline {
  firstObservation: EntityTimelineObservation | null;
  events: EntityTimelineEvent[];
  observations: EntityTimelineObservation[];
}

const KIND_FIELD: Record<string, keyof ObservationLike> = {
  host: 'hosts',
  user: 'users',
  ip: 'ips',
  domain: 'domains',
};

/** Does this observation contain the entity? Token first, then kind→field. */
export function observationHasEntity(observation: ObservationLike, entity: EntityRef): boolean {
  const token = entity.token ?? null;
  if (token) {
    if (observation.tokens?.some((entry) => entry.token === token)) return true;
    // `host:win-dc-01` → compare against the host list when tokens are absent.
    const [kind, ...rest] = token.split(':');
    const value = rest.join(':');
    const field = KIND_FIELD[kind] ?? KIND_FIELD[entity.kind];
    const bucket = field ? observation[field] : undefined;
    if (value && Array.isArray(bucket) && (bucket as string[]).includes(value)) return true;
  }
  const field = KIND_FIELD[entity.kind];
  const bucket = field ? observation[field] : undefined;
  return Boolean(bucket && Array.isArray(bucket) && (bucket as string[]).includes(entity.label));
}

const timeValue = (value: string | null | undefined): number => {
  if (!value) return Number.POSITIVE_INFINITY;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? Number.POSITIVE_INFINITY : parsed;
};

export function buildEntityTimeline(
  entity: EntityRef,
  observations: readonly ObservationLike[],
  timeline: readonly TimelineEventLike[]
): EntityTimeline {
  const touching = observations.filter((observation) =>
    observationHasEntity(observation, entity)
  );
  const keys = new Set(touching.map((observation) => observation.observation_key));

  const events: EntityTimelineEvent[] = timeline
    .filter((event) => {
      if (event.observation_key) return keys.has(event.observation_key);
      return false;
    })
    .map((event) => ({
      alertId: event.alert_id,
      at: event.time ?? null,
      title: event.payload_title || event.title || event.alert_id,
      severity: event.severity ?? null,
      observation: event.observation_key ?? null,
    }))
    .sort((a, b) => timeValue(a.at) - timeValue(b.at) || a.alertId.localeCompare(b.alertId));

  const described: EntityTimelineObservation[] = touching
    .map((observation) => {
      const own = events.filter((event) => event.observation === observation.observation_key);
      const earliestEvent = own
        .map((event) => timeValue(event.at))
        .filter((value) => Number.isFinite(value))
        .sort((a, b) => a - b)[0];
      const earliest = Math.min(
        timeValue(observation.first_seen),
        earliestEvent ?? Number.POSITIVE_INFINITY
      );
      return {
        key: observation.observation_key,
        role: observation.role ?? null,
        at: Number.isFinite(earliest) ? new Date(earliest).toISOString() : null,
        events: own.length,
        sortAt: earliest,
      };
    })
    .sort(
      (a, b) => a.sortAt - b.sortAt || a.key.localeCompare(b.key)
    )
    .map(({ sortAt: _sortAt, ...observation }) => observation);

  return {
    firstObservation: described[0] ?? null,
    events,
    observations: described,
  };
}
