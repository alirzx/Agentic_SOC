import { ShadowRunDetailView } from '@/components/agentic/ShadowRunDetailView';

export const metadata = { title: 'Shadow Run' };

export default async function AgenticShadowRunDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <ShadowRunDetailView runId={id} />;
}
