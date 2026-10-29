export interface RunbookPolicy {
  layer?: string;
  autonomy_level?: string;
  decision?: string;
  reason?: string;
  confidence?: number;
  blast_radius?: string;
  action?: string;
  approval_required?: boolean;
  approval_actor?: string;
  approval_at?: string;
  [key: string]: unknown;
}

export interface RunbookStep {
  /** Monotonic sequence number per subject (ledger order, not wall-clock). */
  seq: number;
  occurred_at: string; // ISO-8601 from the API; rendered client-side.
  stage: string;
  stage_label: string;
  kind: string;
  /** The action catalog slug, e.g. "misp_lookup", "close_alert". */
  action_name: string | null;
  actor_type: string;
  actor_label: string | null;
  summary: string;
  detail: string | null;
  status: string;
  policy: RunbookPolicy | null;
}

export type ProcedureStageStatus = "done" | "skipped" | "pending" | "blocked";

/** One expected step of the operational procedure for a subject. */
export interface ProcedureStage {
  stage: string;
  stage_label: string;
  status: ProcedureStageStatus;
}

export interface RunbookEnvelope {
  subject_type: "alert" | "case" | "incident";
  subject_id: string;
  total_steps: number;
  workflow_name: string;
  workflow_objective: string;
  supporting_rule_count: number;
  /** What should happen, in order — derived from the ledger, never authored. */
  procedure: ProcedureStage[];
  steps: RunbookStep[];
  empty: boolean;
  empty_reason: string | null;
}

// ── Manual tasks (control plane) ──────────────────────────────────────────────

export type RunbookTaskType = "manual_review" | "approval_gate" | "mssp_sla_check";
export type RunbookTaskStatus = "pending" | "in_progress" | "completed";

/** A task the machine could not (or must not) finish alone. */
export interface RunbookTask {
  id: string;
  task_type: RunbookTaskType;
  title: string;
  description?: string | null;
  alert_id?: string | null;
  case_id?: string | null;
  assigned_to?: string | null;
  status: RunbookTaskStatus;
  due_at?: string | null;
  completed_at?: string | null;
  resolution?: string | null;
  feedback_to_llm?: string | null;
  created_by: string;
  created_at: string;
  /**
   * The confidence at task submission time (0–1). Used for calibration
   * monitoring to measure whether policy thresholds are well-tuned.
   */
  confidence_at_submission?: number | null;
  /**
   * Playbook gate tasks: the parked run this task releases. Present only on
   * tasks raised by the playbook engine, not on governance approval gates.
   */
  playbook_run_id?: string | null;
  /**
   * Did approving actually continue the run?
   * `true` = the agents service confirmed it moved past the gate;
   * `false` = the decision was recorded but the run did not move;
   * `null`/absent = not a gate task, or no resume was attempted.
   */
  resume_applied?: boolean | null;
}

/**
 * How much the analyst feedback loop actually changed outcome memory.
 *
 * `priors_updated` counts completions where the agents service confirmed a
 * prior moved. `feedback_unapplied` is the rest of the submitted feedback —
 * no prior existed for the signature, the service was unreachable, or the row
 * predates the flag being stored at all. Showing only the numerator would make
 * a loop that never closes look healthy.
 */
export interface RunbookFeedbackStats {
  tasks_total: number;
  tasks_pending: number;
  tasks_completed: number;
  completions_with_feedback: number;
  priors_updated: number;
  feedback_unapplied: number;
}

// ── Detect & Fuse (Workflow SOC stage 02) ─────────────────────────────────────

export type FusionState = "incident" | "merged" | "standalone";

/** One alert, reduced to the evidence of how it was produced. */
export interface DetectionActivityItem {
  alert_id: string;
  title: string;
  severity: string;
  created_at: string | null;
  rule_id: string | null;
  rule_name: string | null;
  connector_type: string | null;
  confidence: number | null;
  occurrence_count: number;
  fusion_state: FusionState;
  fusion_incident_id: string | null;
  parent_alert_id: string | null;
}

/** Counts over exactly the rows returned, not the whole table. */
export interface DetectionActivitySummary {
  examined: number;
  distinct_rules: number;
  without_rule: number;
  merged: number;
  incident_linked: number;
  deduplicated: number;
}

export interface DetectionActivity {
  summary: DetectionActivitySummary;
  items: DetectionActivityItem[];
}

// ── Governance catalog ────────────────────────────────────────────────────────

export interface GovernanceThresholds {
  auto: number;
  review: number;
  escalation: number;
}

export interface GovernanceAudit {
  record_ledger: boolean;
  audit_log: boolean;
  include_input: boolean;
  include_output: boolean;
}

export interface GovernanceDataSafety {
  allowed_fields: string[];
  max_payload_bytes: number;
  allow_pii: boolean;
}

export interface GovernanceFailure {
  max_attempts: number;
  backoff_seconds: number;
  timeout_seconds: number;
  on_failure: string;
}

export interface GovernanceCost {
  max_usd_per_run: number | null;
  max_tokens: number | null;
  max_wall_ms: number | null;
}

export type GovernanceCategory = "read" | "case" | "containment";
export type BlastRadius = "read" | "low" | "medium" | "high" | "critical";

export interface GovernanceActionEntry {
  name: string;
  label: string;
  category: GovernanceCategory;
  blast_radius: BlastRadius;
  always_requires_approval: boolean;
  dry_run_default: boolean;
  thresholds: GovernanceThresholds;
  audit: GovernanceAudit;
  data_safety: GovernanceDataSafety;
  failure: GovernanceFailure;
  cost: GovernanceCost;
  /** Whether this action is currently enabled for the tenant. */
  enabled?: boolean;
  /** Always true for governance actions — these are system core capabilities. */
  is_system_core?: boolean;
  /** Whether required connectors are active; False means the action cannot execute. */
  available?: boolean;
}
