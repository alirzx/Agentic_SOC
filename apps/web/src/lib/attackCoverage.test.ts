import { describe, expect, it } from 'vitest';
import { killChainCoverage, normalisePhase, techniqueChips, techniqueName } from './attackCoverage';

describe('techniqueName', () => {
  it('resolves a curated name and falls back to the parent technique', () => {
    expect(techniqueName('T1003')).toBe('OS Credential Dumping');
    expect(techniqueName('T1003.001')).toBe('OS Credential Dumping');
  });

  it('is null for a technique outside the shipped catalog', () => {
    expect(techniqueName('T9999.999')).toBeNull();
  });
});

describe('techniqueChips', () => {
  it('counts usage across observations and keeps a stable order', () => {
    const chips = techniqueChips([['T1003', 'T1021'], ['T1003'], []]);
    expect(chips.map((chip) => [chip.id, chip.count])).toEqual([
      ['T1003', 2],
      ['T1021', 1],
    ]);
  });

  it('marks techniques without a catalog name instead of inventing one', () => {
    const [chip] = techniqueChips([['T9999']]);
    expect(chip.name).toBeNull();
  });
});

describe('normalisePhase', () => {
  it('accepts the spellings different normalizers emit', () => {
    expect(normalisePhase('Credential Access')).toBe('credential-access');
    expect(normalisePhase('lateral_movement')).toBe('lateral-movement');
    expect(normalisePhase('recon')).toBe('reconnaissance');
    expect(normalisePhase('nonsense')).toBeNull();
  });
});

describe('killChainCoverage', () => {
  it('uses the engine phases when observations carry them', () => {
    const { stages, source } = killChainCoverage(
      [['credential-access'], ['lateral-movement', 'credential-access']],
      []
    );
    expect(source).toBe('engine');
    expect(stages.map((stage) => [stage.key, stage.count])).toEqual([
      ['credential-access', 2],
      ['lateral-movement', 1],
    ]);
  });

  it('derives the ladder from techniques when no phase was stored', () => {
    const chips = techniqueChips([['T1003'], ['T1021.002']]);
    const { stages, source } = killChainCoverage([], chips);
    expect(source).toBe('derived');
    expect(stages.map((stage) => stage.key)).toEqual([
      'credential-access',
      'lateral-movement',
    ]);
  });

  it('maps tactics by id, so C&C does not fall off the ladder', () => {
    // ATT&CK calls the tactic "C&C"; the kill-chain ladder labels it "C2".
    const chips = techniqueChips([['T1071']]);
    const { stages } = killChainCoverage([], chips);
    expect(stages.map((stage) => stage.key)).toContain('command-and-control');
  });

  it('counts a technique once per stage even when several tactics land there', () => {
    const chips = techniqueChips([['T1078']]); // valid accounts → several tactics
    const { stages } = killChainCoverage([], chips);
    for (const stage of stages) expect(stage.count).toBeLessThanOrEqual(1);
  });

  it('reports nothing when there is neither a phase nor a mapped technique', () => {
    expect(killChainCoverage([[]], []).source).toBe('none');
  });
});
