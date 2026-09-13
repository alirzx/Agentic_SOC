import type { Metadata } from 'next';
import { SoorinHero } from '@/components/landing/SoorinHero';
import { BRAND } from '@/lib/brand';
import { getPublicSiteUrl } from '@/lib/site';

const siteUrl = getPublicSiteUrl();

export const metadata: Metadata = {
  title: { absolute: `${BRAND.product}.` },
  description:
    'Discover relationships between assets, services, users, and network activity. Analyze connections, detect anomalies, and investigate your infrastructure with AI-powered insights.',
  alternates: { canonical: '/' },
  openGraph: {
    title: BRAND.product,
    description:
      'Analyze connections, detect anomalies, and investigate your infrastructure with AI-powered insights.',
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
