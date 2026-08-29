import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { fetchPublicReplay } from "../../../lib/replay";
import { getPublicSiteUrl } from "../../../lib/site";
import { ReplayPlayer } from "./ReplayPlayer";

interface PageProps {
  params: Promise<{ slug: string }>;
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { slug } = await params;
  const replay = await fetchPublicReplay(slug);
  if (!replay) {
    return { title: "Replay not found · AiSOC" };
  }
  const s = replay.snapshot;
  const title = `${replay.title} · AiSOC investigation replay`;
  const description = `Verdict: ${s.verdict.replace(/_/g, " ")} · investigated in ${(s.elapsedMs / 1000).toFixed(
    0,
  )}s across ${s.stepCount} steps and ${s.toolCallCount} tool calls. Watch the agent reason through it step-by-step.`;
  const url = `${getPublicSiteUrl()}/r/${slug}`;
  return {
    title,
    description,
    alternates: { canonical: url },
    openGraph: { title, description, url, type: "article" },
    twitter: { card: "summary_large_image", title, description },
  };
}

export default async function ReplayPage({ params }: PageProps) {
  const { slug } = await params;
  const replay = await fetchPublicReplay(slug);
  if (!replay) notFound();

  const s = replay.snapshot;
  return (
    <main style={{ background: "#0b1020", minHeight: "100vh", color: "#e6e9f5", padding: "48px 24px" }}>
      <div style={{ maxWidth: 1040, margin: "0 auto" }}>
        <Link href="/" style={{ color: "#8b93b7", textDecoration: "none", fontSize: 14 }}>
          ← AiSOC
        </Link>
        <header style={{ margin: "16px 0 32px" }}>
          <div style={{ color: "#8b93b7", fontSize: 13, textTransform: "uppercase", letterSpacing: 1 }}>
            Public investigation replay · redacted
          </div>
          <h1 style={{ fontSize: 30, fontWeight: 800, margin: "8px 0 0" }}>{replay.title}</h1>
          <p style={{ color: "#8b93b7", fontSize: 14, marginTop: 8 }}>
            {s.model} · {s.stepCount} steps · {s.toolCallCount} tool calls · {(s.elapsedMs / 1000).toFixed(0)}s ·{" "}
            {replay.view_count.toLocaleString()} views
          </p>
        </header>

        <ReplayPlayer snapshot={s} />

        <footer style={{ marginTop: 48, borderTop: "1px solid #232b4d", paddingTop: 20, color: "#64748b", fontSize: 13 }}>
          Entity names, IPs, and identities are redacted. This is a read-only snapshot of an{" "}
          <a href="https://github.com/beenuar/AiSOC" style={{ color: "#8b93b7" }}>
            open-source AiSOC
          </a>{" "}
          investigation. Reproduce the demo with <code>npx aisoc triage --demo</code>.
        </footer>
      </div>
    </main>
  );
}
