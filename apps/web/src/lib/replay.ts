/**
 * Client + server helpers for the public investigation-replay page (`/r/<slug>`).
 *
 * The snapshot shape mirrors `services/api/app/services/replay_redaction.py`.
 * Everything here is already redacted server-side, so it is safe to render
 * publicly and to embed in OG cards.
 */

export interface ReplayStepDecision {
  reason?: string | null;
  tool?: string | null;
  confidence?: number | null;
}

export interface ReplayStep {
  seq: number;
  kind: string;
  agent: string;
  summary: string;
  durationMs: number;
  decision?: ReplayStepDecision | null;
}

export interface ReplayEvidenceCard {
  seq: number;
  summary: string;
  source: string;
}

export interface ReplayGraphNode {
  id: string;
  label: string;
  kind: string;
}

export interface ReplayGraphEdge {
  source: string;
  target: string;
  label?: string;
}

export interface ReplaySnapshot {
  schemaVersion: number;
  caseId: string;
  title: string;
  verdict: string;
  model: string;
  elapsedMs: number;
  stepCount: number;
  toolCallCount: number;
  llmCallCount: number;
  evidenceSourceCount: number;
  techniques: string[];
  steps: ReplayStep[];
  evidenceCards: ReplayEvidenceCard[];
  attackGraph: { nodes: ReplayGraphNode[]; edges: ReplayGraphEdge[] };
}

export interface PublicReplay {
  slug: string;
  title: string;
  case_id: string;
  snapshot: ReplaySnapshot;
  view_count: number;
  created_at: string;
}

/** Internal API origin for server-side fetches (mirrors next.config rewrites). */
function apiBase(): string {
  return (
    process.env.API_URL ||
    process.env.INTERNAL_API_URL ||
    process.env.NEXT_PUBLIC_API_URL ||
    "http://localhost:8000"
  ).replace(/\/$/, "");
}

/** Server-side fetch of a published replay. Returns null on 404 / error. */
export async function fetchPublicReplay(slug: string): Promise<PublicReplay | null> {
  try {
    const res = await fetch(`${apiBase()}/api/v1/r/${encodeURIComponent(slug)}`, {
      // Public, cacheable content; revalidate periodically at the edge.
      next: { revalidate: 300 },
    });
    if (!res.ok) return null;
    return (await res.json()) as PublicReplay;
  } catch {
    return null;
  }
}
