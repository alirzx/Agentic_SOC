import { WorkflowSocView } from '@/components/workflow/WorkflowSocView';

export const metadata = {
  title: 'Workflow SOC',
};

/**
 * `?stage=<step id>` opens the lifecycle on that stage and holds the animation
 * there. The Runbook uses it for its "View lifecycle" link so the operator sees
 * where the surface they were working in sits in the full pipeline.
 */
export default async function WorkflowSocPage({
  searchParams,
}: {
  searchParams: Promise<{ stage?: string }>;
}) {
  const { stage } = await searchParams;
  return <WorkflowSocView initialStage={stage} />;
}
