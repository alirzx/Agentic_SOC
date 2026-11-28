import { CoverageView } from '@/components/detections/CoverageView';

export const metadata = { title: 'Coverage Gap Advisor' };

export default function CoverageAdvisorPage() {
  return (
    <>
      <p role="status" className="mx-6 mt-4 rounded border border-slate-500 p-3 text-sm">
        The dedicated gap advisor is unavailable in this release. The detection coverage matrix below shows shipped rule coverage, not workspace-specific recommendations.
      </p>
      <CoverageView />
    </>
  );
}
