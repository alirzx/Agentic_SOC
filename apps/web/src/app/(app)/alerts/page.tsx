import { Suspense } from 'react';
import { AlertsView } from '@/components/alerts/AlertsView';

export const metadata = {
  title: 'Alerts',
};

export default function AlertsPage() {
  return (
    <Suspense fallback={null}>
      <AlertsView />
    </Suspense>
  );
}
