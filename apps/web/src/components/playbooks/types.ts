/**
 * Shared TypeScript types for the Playbook editor and list UI.
 * Mirrors services/agents/app/playbook/models.py
 */

export type StepType =
  | 'enrich'
  | 'investigate'
  | 'notify'
  | 'block_ip'
  | 'isolate_host'
  | 'create_ticket'
  | 'close_case'
  | 'http'
  | 'condition';

export type OnFailure = 'abort' | 'continue' | 'retry';

export interface StepCondition {
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'lt' | 'contains' | 'exists';
  value?: unknown;
}

export interface PlaybookStep {
  id: string;
  name: string;
  type: StepType;
  params: Record<string, unknown>;
  condition?: StepCondition;
  on_failure: OnFailure;
  retry_max: number;
  timeout_seconds: number;
  next_true?: string;
  next_false?: string;
}

export interface PlaybookTrigger {
  on: 'alert' | 'case' | 'manual' | 'schedule';
  severity?: string[];
  tags?: string[];
  cron?: string;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  version: string;
  tags: string[];
  trigger: PlaybookTrigger;
  steps: PlaybookStep[];
  author: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  /**
   * Step kinds this engine has no handler for (from the agents API). A playbook
   * containing one will abort at that step, so the gallery warns instead of
   * implying the whole chain would run.
   */
  unsupported_step_types?: string[];
}

export type PlaybookRunStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  // Parked at an `approval` step: nothing after the gate ran.
  | 'pending_approval';

export interface PlaybookRunStep {
  step_id: string;
  step_name: string;
  status: 'pending' | 'running' | 'completed' | 'skipped' | 'failed' | 'blocked';
  started_at?: string;
  completed_at?: string;
  output?: unknown;
  error?: string;
}

/**
 * One entry of a run's `step_results`, exactly as the engine serialises it.
 * The engine writes `name` (not `step_name`) and nests output under `result`;
 * reading `steps`/`step_name` off the payload silently produced empty progress.
 */
export interface PlaybookRunStepResult {
  step_id: string;
  name: string;
  status: PlaybookRunStepStatus;
  result?: Record<string, unknown>;
  branch?: string | null;
}

export type PlaybookRunStepStatus =
  | 'pending'
  | 'running'
  | 'success'
  | 'skipped'
  | 'failed'
  | 'blocked';

export interface PlaybookRun {
  run_id: string;
  playbook_id: string;
  playbook_name: string;
  status: PlaybookRunStatus;
  started_at?: string;
  finished_at?: string;
  error?: string | null;
  step_results: PlaybookRunStepResult[];
  context: Record<string, unknown>;
  // Parked at an approval step (Phase 11/12).
  next_step_index?: number | null;
  gate_step_id?: string | null;
  gate_step_name?: string | null;
  actor?: string | null;
  decided_at?: string | null;
  dry_run?: boolean;
}
