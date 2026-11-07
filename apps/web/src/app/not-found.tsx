import type { Metadata } from 'next';
import Link from 'next/link';

/**
 * Global 404 — console destinations only.
 *
 * Analysts hit this from stale Investigation Rail pivots and typos inside
 * the authenticated app. The old marketing shell (StickyNav + Popular
 * destinations + Footer) pulled them out of the product; keep this page
 * minimal and point back into the console.
 */

export const metadata: Metadata = {
  title: '404 — page not found · AiSOC',
  robots: { index: false, follow: false },
};

const DESTINATIONS: ReadonlyArray<{ label: string; href: string }> = [
  { label: 'Alerts', href: '/alerts' },
  { label: 'Cases', href: '/cases' },
  { label: 'Attack Graph', href: '/graph' },
  { label: 'SOC Funnel', href: '/soc-funnel' },
  { label: 'Dashboard', href: '/dashboard' },
];

export default function NotFoundPage() {
  return (
    <main className="min-h-screen bg-surface-base text-fg-primary flex items-center justify-center px-6">
      <div className="max-w-md w-full space-y-6 text-center">
        <p className="text-xs font-mono uppercase tracking-wider text-gray-500">404</p>
        <h1 className="text-2xl font-semibold text-white">Page not found</h1>
        <p className="text-sm text-gray-400">
          That URL is not part of the AiSOC console. Use one of the links below
          to get back to work.
        </p>
        <ul className="grid gap-2 text-left">
          {DESTINATIONS.map((d) => (
            <li key={d.href}>
              <Link
                href={d.href}
                className="block rounded-lg border border-[#374151]/60 bg-dark-60/80 px-3 py-2 text-sm text-gray-200 hover:border-brand-500/40 hover:text-white transition-colors"
              >
                {d.label}
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </main>
  );
}
