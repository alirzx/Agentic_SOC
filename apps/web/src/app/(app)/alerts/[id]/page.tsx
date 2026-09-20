import { AlertDetailView } from '@/components/alerts/AlertDetailView';
import { ClientOnly } from '@/components/util/ClientOnly';
import { SkeletonCard } from '@/components/ui/Skeleton';

export const metadata = {
  title: 'Alert Detail',
};

export default async function AlertDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ title?: string; host?: string }>;
}) {
  const { id } = await params;
  const query = await searchParams;
  return (
    <ClientOnly
      fallback={
        <div className="space-y-4 p-6">
          <SkeletonCard />
          <SkeletonCard />
        </div>
      }
    >
      <AlertDetailView alertId={id} title={query.title} host={query.host} />
    </ClientOnly>
  );
}
