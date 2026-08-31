/**
 * Soorin Agentic SOC contracts (TypeScript mirror of services/agents/app/runtime).
 * Spec §§8–28. Runtime remains Python; these types are for the web console.
 */

export type AgentResultStatus = "success" | "failed" | "blocked";
export type ToolRiskLevel = "read" | "low" | "medium" | "high" | "critical";
export type IncidentState =
  | "NEW"
  | "TRIAGING"
  | "INVESTIGATING"
  | "CORRELATING"
  | "RISK_ASSESSMENT"
  | "DECISION"
  | "WAITING_APPROVAL"
  | "RESPONDING"
  | "VALIDATING"
  | "REPORTING"
  | "RESOLVED"
  | "CLOSED";
export type RiskBand = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "EMERGENCY";
export type ApprovalTier = "none" | "recommend" | "mandatory" | "critical";

export interface EvidenceProvenance {
  agent: string;
  agentVersion: string;
  tool: string;
  queryId?: string;
  source: string;
  retrievedAt: string;
}

export interface Evidence {
  id: string;
  incidentId: string;
  type: string;
  source: string;
  data: Record<string, unknown>;
  confidence: number;
  timestamp: string;
  hash: string;
  provenance?: EvidenceProvenance;
}

export interface Finding {
  id: string;
  statement: string;
  evidenceIds: string[];
  confidence: number;
  mitreTechniques: string[];
}

export interface AgentAction {
  name: string;
  tool: string;
  input: Record<string, unknown>;
  output?: Record<string, unknown>;
  riskLevel: ToolRiskLevel;
}

export interface NextTask {
  agent: string;
  objective: string;
  priority: number;
}

export interface AgentConstraints {
  maxIterations: number;
  maxToolCalls: number;
  timeoutMs: number;
}

export interface IncidentStateSnapshot {
  state: IncidentState;
  severity?: string;
  riskScore: number;
  confidence: number;
  summary: Record<string, unknown>;
  rawAlert: Record<string, unknown>;
}

export interface AgentContext {
  incidentId: string;
  tenantId: string;
  objective: string;
  state: IncidentStateSnapshot;
  evidence: Evidence[];
  previousActions: AgentAction[];
  availableTools: string[];
  constraints: AgentConstraints;
  metadata: Record<string, unknown>;
  correlationId: string;
  iteration: number;
}

export interface AgentResult {
  status: AgentResultStatus;
  findings: Finding[];
  evidence: Evidence[];
  actions: AgentAction[];
  nextTasks: NextTask[];
  confidence: number;
  reasoning?: string;
  uncertainty?: string[];
}

export interface RiskFactors {
  alertSeverity: string;
  assetCriticality: number;
  userPrivilege: number;
  threatIntel: number;
  behavioralAnomaly: number;
  correlation: number;
  attackChain: number;
}

export interface RiskAssessment {
  score: number;
  band: RiskBand;
  factors: RiskFactors;
  reasons: string[];
}

export interface IncidentReportPackage {
  incidentId: string;
  title: string;
  executiveSummary: string;
  uncertainties: string[];
  evidence: Evidence[];
  mitreTechniques: string[];
}

export type AgenticShadowRunStatus =
  | "created"
  | "running"
  | "completed"
  | "failed"
  | "timeout";

export interface AgenticSocSnapshot {
  severity?: string;
  classification?: string;
  risk?: number;
  riskScore?: number;
  confidence?: number;
  affectedAssets?: string[];
  affectedUsers?: string[];
  iocs?: string[];
  mitreTechniques?: string[];
  recommendedActions?: string[];
}

export interface AgenticComparison {
  caseId: string;
  existing: AgenticSocSnapshot;
  agentic: AgenticSocSnapshot;
  differences: string[];
}

export type AgenticEvaluationRunStatus =
  | "created"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface AgenticEvaluationRunSummary {
  id: string;
  datasetId: string;
  datasetVersion: string;
  status: AgenticEvaluationRunStatus;
  totalCases: number;
  completedCases: number;
  failedCases: number;
  comparisonSummary: Record<string, unknown>;
  productionReadiness: Record<string, unknown>;
}
