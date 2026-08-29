/**
 * Tool registry.
 *
 * Single export the server depends on, so adding a new tool is a one-line
 * change here and a single new file under `./tools/`. The order of this
 * array is the order tools are advertised to MCP hosts; we keep the
 * "discovery" tools (alerts/list, cases/list, query) before deep-dive
 * tools so an agent reading the listing top-to-bottom builds an
 * intuition of how to navigate the surface.
 */
import { getAlertTool, listAlertsTool } from "./alerts.js";
import {
  getCaseTool,
  listCasesTool,
  runInvestigationTool,
} from "./cases.js";
import {
  getDetectionRuleTool,
  queryDetectionsTool,
} from "./detections.js";
import {
  explainStepTool,
  getInvestigationTool,
  listInvestigationsTool,
  replayDecisionTool,
} from "./investigations.js";
import { lakeQueryTool, lakeSchemaTool } from "./lake.js";
import type { ToolDefinition } from "./types.js";

export const ALL_TOOLS: ToolDefinition[] = [
  // Discovery
  listAlertsTool,
  listCasesTool,
  queryDetectionsTool,
  listInvestigationsTool,
  lakeSchemaTool,
  // Deep-dive
  getAlertTool,
  getCaseTool,
  getDetectionRuleTool,
  getInvestigationTool,
  // Lake query (warm tier — gated by lake:query permission server-side).
  // Listed near the bottom because it's the most expensive surface and
  // the schema tool above is the recommended discovery path; agents that
  // read the listing top-to-bottom should reach for SELECT only after
  // they've seen the structured tools.
  lakeQueryTool,
  // Action / replay
  runInvestigationTool,
  replayDecisionTool,
  explainStepTool,
];

/** Convenience for the server: name → definition lookup. */
export const TOOL_BY_NAME: Record<string, ToolDefinition> = Object.fromEntries(
  ALL_TOOLS.map((t) => [t.metadata.name, t]),
);
