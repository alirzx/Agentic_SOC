import { notFound } from "next/navigation";
import { RunbookPage } from "@/components/runbook/RunbookPage";
import type { RunbookEnvelope } from "@/components/runbook/runbook.types";
import { request } from "@/lib/api";

export const metadata = {
  title: "Runbook",
};

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const fetchCache = "force-no-store";

type Props = {
  params: Promise<{ subjectType: string; subjectId: string }>;
};

async function loadRunbook(subjectType: string, subjectId: string): Promise<RunbookEnvelope> {
  return request<RunbookEnvelope>(`/api/v1/runbook/${subjectType}/${subjectId}`);
}

export default async function RunbookPageWrapper({ params }: Props) {
  const { subjectType, subjectId } = await params;

  if (!["alert", "case", "incident"].includes(subjectType)) {
    notFound();
  }

  let initialEnvelope: RunbookEnvelope;
  try {
    initialEnvelope = await loadRunbook(subjectType, subjectId);
  } catch {
    notFound();
  }

  return (
    <RunbookPage
      subjectType={subjectType as "alert" | "case" | "incident"}
      subjectId={subjectId}
      initialEnvelope={initialEnvelope}
    />
  );
}
