import type { Metadata, Viewport } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { Toaster } from 'react-hot-toast';
import './globals.css';
import { PwaBootstrap } from '@/components/pwa/PwaBootstrap';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import { themeBootstrapScript } from '@/components/theme/themeScript';
import { docs } from '@/lib/docs';
import { BRAND } from '@/lib/brand';
import { DISCOVERY_KEYWORDS, getPublicSiteUrl } from '@/lib/site';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
  // Only load on demand — monospace font is used in code blocks, not every page,
  // so preloading eagerly causes "preloaded but unused" browser warnings.
  preload: false,
});

const siteUrl = getPublicSiteUrl();

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  applicationName: BRAND.product,
  title: {
    default: `${BRAND.product} — ${BRAND.tagline}`,
    template: `%s | ${BRAND.shortName}`,
  },
  description:
    `${BRAND.product} is a self-hostable AI-powered Security Operations Center from ${BRAND.company}. Real-time threat detection, alert fusion, MITRE ATT&CK-aware autonomous investigation, and detection-as-code.`,
  keywords: [...DISCOVERY_KEYWORDS],
  authors: [{ name: BRAND.company, url: BRAND.githubUrl }],
  creator: BRAND.company,
  publisher: BRAND.company,
  category: 'cybersecurity',
  classification: 'Security Software',
  openGraph: {
    title: `${BRAND.product} — ${BRAND.tagline}`,
    description:
      `Self-hostable AI SOC from ${BRAND.company}: real-time threat detection, alert fusion, MITRE ATT&CK investigation, and detection-as-code.`,
    type: 'website',
    siteName: BRAND.product,
    url: siteUrl,
    locale: 'en_US',
    images: [
      {
        url: '/og-image.svg',
        width: 1200,
        height: 630,
        alt: `${BRAND.product} — AI SOC platform for security operations teams`,
        type: 'image/svg+xml',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: `${BRAND.product} — AI SOC Platform`,
    description:
      `${BRAND.tagline}: threat detection, alert fusion, MITRE ATT&CK mapping, and detection-as-code. Self-host from ${BRAND.githubUrl}.`,
  },
  icons: {
    // Single SVG favicon — modern browsers (Chrome 80+, Safari 16+, Firefox 41+,
    // Edge) all support this. We intentionally do not advertise /favicon.ico
    // because we don't ship a binary .ico file; declaring one only produces
    // 404s in the browser network tab.
    icon: [{ url: '/favicon.svg', type: 'image/svg+xml' }],
    apple: [{ url: '/icons/icon-192.svg', type: 'image/svg+xml' }],
  },
  manifest: '/manifest.json',
  appleWebApp: {
    capable: true,
    title: BRAND.shortName,
    statusBarStyle: 'black-translucent',
  },
  robots: { index: true, follow: true, googleBot: { index: true, follow: true } },
  alternates: { canonical: siteUrl },
};

export const viewport: Viewport = {
  themeColor: '#121724',
  width: 'device-width',
  initialScale: 1,
};

const jsonLd = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'Organization',
      name: BRAND.company,
      url: siteUrl,
      logo: `${siteUrl}/logo/logo-mark.svg`,
      description:
        `${BRAND.product} — self-hostable AI security operations platform from ${BRAND.company}.`,
      sameAs: [
        BRAND.githubUrl,
        BRAND.website,
        BRAND.linkedin,
      ],
      contactPoint: {
        '@type': 'ContactPoint',
        contactType: 'technical support',
        url: 'https://github.com/SoorinSecurity/Agentic_SOC/issues',
      },
    },
    {
      '@type': 'SoftwareApplication',
      name: BRAND.product,
      alternateName: ['Soorin', 'Agentic SOC', 'Soorin Security SOC'],
      applicationCategory: 'SecurityApplication',
      applicationSubCategory: 'Security Operations Center',
      operatingSystem: 'Linux, macOS, Docker',
      license: 'https://opensource.org/licenses/MIT',
      offers: {
        '@type': 'Offer',
        price: '0',
        priceCurrency: 'USD',
        description: 'Free, open-source, self-hostable',
      },
      url: siteUrl,
      downloadUrl: 'https://github.com/SoorinSecurity/Agentic_SOC',
      installUrl: docs('quickstart'),
      releaseNotes: 'https://github.com/SoorinSecurity/Agentic_SOC/releases',
      featureList: [
        'Click-and-connect 26 security sources (EDR, SIEM, cloud, IAM, SaaS) with encrypted credential vault',
        'Real-time threat detection and alert fusion',
        'Entity risk-based alerting (RBA) queue',
        'Autonomous alert triage agent with confidence-scored verdicts',
        'Conversational, multi-turn investigation copilot',
        'MITRE ATT&CK mapping, coverage heatmap, and gap advisor',
        'Purple team simulation with detection drift tracking',
        'Detection-as-code with Sigma rule support and NL authoring',
        'Federated search across Splunk, Sentinel, and Elastic',
        'Hunt-as-code threat hunting engine',
        'Detection proposals and community-driven rule lifecycle',
        'Adversary simulation eval harness (200 incidents)',
        'SLA tracking, automated compliance evidence, and AI-generated incident reports',
        'MSSP multi-tenant support, shift-handoff dashboard, and team analytics',
        'External Attack Surface Management (EASM) and detection tuning workbench',
        'STIX 2.1 / TAXII 2.1 publishing and air-gap deployment configuration',
        'Self-hosted deployment with Docker Compose',
      ],
      screenshot: `${siteUrl}/og-image.svg`,
    },
    {
      '@type': 'WebSite',
      name: BRAND.product,
      url: siteUrl,
      description: `${BRAND.product} — ${BRAND.tagline}`,
      potentialAction: {
        '@type': 'SearchAction',
        target: `${siteUrl}/search?q={search_term_string}`,
        'query-input': 'required name=search_term_string',
      },
    },
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    // Default to `data-theme="dark"` for SSR so that the markup React sends
    // matches what the bootstrap script will write before hydration. The
    // bootstrap script (rendered first thing inside <body>) flips this to
    // light/system if the user previously chose so, before any pixels are
    // painted — that's why we don't see a flash.
    <html
      lang="en"
      data-theme="dark"
      className={`${inter.variable} ${jetbrainsMono.variable}`}
      suppressHydrationWarning
    >
      <body className="bg-surface-base text-fg-primary font-sans antialiased">
        <script
          // eslint-disable-next-line react/no-danger -- pre-hydration theme bootstrap
          dangerouslySetInnerHTML={{ __html: themeBootstrapScript }}
        />
        <script
          type="application/ld+json"
          // eslint-disable-next-line react/no-danger -- JSON-LD for SEO crawlers
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        <PwaBootstrap />
        <ThemeProvider>
          {children}
          <Toaster
            position="bottom-right"
            toastOptions={{
              duration: 4000,
              style: {
                background: 'var(--surface-raised)',
                color: 'var(--fg-primary)',
                border: '1px solid var(--surface-border)',
                fontSize: '0.875rem',
                fontFamily: 'Gilory-Medium, Gilroy, system-ui, sans-serif',
              },
              success: {
                iconTheme: { primary: '#64FF99', secondary: '#121724' },
              },
              error: {
                iconTheme: { primary: '#ef4444', secondary: '#121724' },
              },
            }}
          />
        </ThemeProvider>
      </body>
    </html>
  );
}
