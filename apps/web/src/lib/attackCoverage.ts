/**
 * ATT&CK coverage helpers for the correlation view.
 *
 * The inspect modal ends with a coverage strip: which MITRE techniques the
 * campaign actually used, and how far down the kill chain it got. Both come
 * from data the engine already scored with — the observation's `techniques` and
 * `kill_chain` (Splunk analytic-story phases) — so nothing here is inferred when
 * the engine knows the answer.
 *
 * When observations carry no kill-chain phase (common for connectors that do
 * not populate analytic stories), the ladder is derived from the technique →
 * tactic mapping (`mitreTactics.ts`) and labelled as derived, so the analyst can
 * tell engine evidence from a mapping.
 */

import { ATTACK_CATALOG } from './tools/attack-catalog';
import { TACTIC_BY_ID, tacticsFor } from './mitreTactics';

const NAME_BY_ID = new Map(ATTACK_CATALOG.map((technique) => [technique.id, technique.name]));

/** Curated ATT&CK name for a technique, or the parent's name, or null. */
export function techniqueName(id: string): string | null {
  const trimmed = (id || '').trim();
  if (!trimmed) return null;
  return NAME_BY_ID.get(trimmed) ?? NAME_BY_ID.get(trimmed.split('.')[0]) ?? null;
}

export interface TechniqueChip {
  id: string;
  /** Curated name; null when the technique is outside the shipped catalog. */
  name: string | null;
  /** Observations carrying this technique, when counted from observations. */
  count: number;
  /** ATT&CK tactics this technique maps to (short names, for display). */
  tactics: string[];
  /** The same tactics as ATT&CK ids — what the kill-chain derivation uses. */
  tacticIds: string[];
}

/** Count technique usage across the observations of a campaign. */
export function techniqueChips(techniqueLists: string[][]): TechniqueChip[] {
  const counts = new Map<string, number>();
  for (const list of techniqueLists) {
    for (const raw of list ?? []) {
      const id = String(raw || '').trim().toUpperCase();
      if (!id) continue;
      counts.set(id, (counts.get(id) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([id, count]) => {
      const tacticIds = tacticsFor(id);
      return {
        id,
        name: techniqueName(id),
        count,
        tacticIds,
        tactics: tacticIds
          .map((tacticId) => TACTIC_BY_ID.get(tacticId)?.shortName ?? null)
          .filter((value): value is string => Boolean(value)),
      };
    });
}

/**
 * ATT&CK tactic id → kill-chain stage key.
 *
 * Mapped by *id*, not by display name: the ladder and the ATT&CK matrix use
 * different short names (`C&C` vs `C2`), so a name comparison silently drops
 * command-and-control coverage.
 */
const TACTIC_PHASE: Record<string, string> = {
  TA0043: 'reconnaissance',
  TA0001: 'delivery',
  TA0002: 'execution',
  TA0003: 'persistence',
  TA0004: 'privilege-escalation',
  TA0005: 'defense-evasion',
  TA0006: 'credential-access',
  TA0007: 'discovery',
  TA0008: 'lateral-movement',
  TA0009: 'collection',
  TA0011: 'command-and-control',
  TA0010: 'exfiltration',
  TA0040: 'impact',
};

/** Kill-chain ladder, in the engine's own phase order. */
export const KILL_CHAIN_LADDER: Array<{ key: string; label: string }> = [
  { key: 'reconnaissance', label: 'Recon' },
  { key: 'delivery', label: 'Delivery' },
  { key: 'exploitation', label: 'Exploit' },
  { key: 'installation', label: 'Install' },
  { key: 'execution', label: 'Execution' },
  { key: 'persistence', label: 'Persistence' },
  { key: 'privilege-escalation', label: 'Priv Esc' },
  { key: 'defense-evasion', label: 'Defense Evasion' },
  { key: 'credential-access', label: 'Cred Access' },
  { key: 'discovery', label: 'Discovery' },
  { key: 'lateral-movement', label: 'Lateral' },
  { key: 'collection', label: 'Collection' },
  { key: 'command-and-control', label: 'C2' },
  { key: 'exfiltration', label: 'Exfil' },
  { key: 'impact', label: 'Impact' },
];

const LADDER_INDEX = new Map(KILL_CHAIN_LADDER.map((stage, index) => [stage.key, index]));

/** Normalise the phase spellings different normalizers produce. */
export function normalisePhase(raw: string): string | null {
  const key = (raw || '')
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, '-')
    .replace(/-+/g, '-');
  if (!key) return null;
  if (key === 'recon') return 'reconnaissance';
  if (key === 'exploit') return 'exploitation';
  if (key === 'actions-on-objective') return 'impact';
  if (key === 'c2' || key === 'command-and-control' || key === 'commandandcontrol') {
    return 'command-and-control';
  }
  return LADDER_INDEX.has(key) ? key : null;
}

export interface StageCoverage {
  key: string;
  label: string;
  /** Observations (or techniques) sitting on this stage. */
  count: number;
}

/**
 * Kill-chain coverage of a campaign.
 *
 * `source` says what the ladder is built from: engine phases when any
 * observation carries one, otherwise tactics derived from the techniques.
 */
export function killChainCoverage(
  observationPhases: string[][],
  techniques: TechniqueChip[]
): { stages: StageCoverage[]; source: 'engine' | 'derived' | 'none' } {
  const counts = new Map<string, number>();
  for (const phases of observationPhases) {
    const seen = new Set<string>();
    for (const raw of phases ?? []) {
      const key = normalisePhase(String(raw));
      if (!key || seen.has(key)) continue;
      seen.add(key);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
  }

  if (counts.size > 0) {
    return {
      stages: KILL_CHAIN_LADDER.filter((stage) => counts.has(stage.key)).map((stage) => ({
        ...stage,
        count: counts.get(stage.key) ?? 0,
      })),
      source: 'engine',
    };
  }

  const derived = new Map<string, number>();
  for (const chip of techniques) {
    const stages = new Set(
      (chip.tacticIds ?? [])
        .map((tacticId) => TACTIC_PHASE[tacticId])
        .filter((key): key is string => Boolean(key))
    );
    for (const key of stages) {
      // One technique counts once per stage, however many of its tactics land
      // there — otherwise a broad technique inflates the ladder.
      derived.set(key, (derived.get(key) ?? 0) + chip.count);
    }
  }
  if (derived.size === 0) return { stages: [], source: 'none' };

  return {
    stages: KILL_CHAIN_LADDER.filter((stage) => derived.has(stage.key)).map((stage) => ({
      ...stage,
      count: derived.get(stage.key) ?? 0,
    })),
    source: 'derived',
  };
}
