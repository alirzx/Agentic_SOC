import type { Metadata } from 'next';
import { SoorinHero } from '@/components/landing/SoorinHero';
import { BRAND } from '@/lib/brand';
import { getPublicSiteUrl } from '@/lib/site';

const siteUrl = getPublicSiteUrl();

export const metadata: Metadata = {
  title: { absolute: `${BRAND.product}.` },
  description:
    'Detect threats, investigate security incidents, and automate your security operations with AI-powered intelligence. Correlate alerts, uncover hidden attack patterns, and accelerate incident response with autonomous AI agents.',
  alternates: { canonical: '/' },
  openGraph: {
    title: BRAND.product,
    description:
      'AI-powered SOC: correlate alerts, uncover hidden attack patterns, and accelerate incident response with autonomous AI agents.',
    url: siteUrl,
    siteName: BRAND.product,
    type: 'website',
    locale: 'en_US',
  },
};

/**
 * Product root (`/`) — a single-screen splash matching the Soorin hero
 * art. Marketing sections (nav, FAQ, pricing, footer) are intentionally
 * omitted so the URL is just the entry to Log in / Get started.
 */
export default function HomePage() {
  return <SoorinHero />;
}
