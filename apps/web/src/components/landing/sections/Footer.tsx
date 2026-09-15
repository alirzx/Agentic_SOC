'use client';

/**
 * Footer — `footer` section from §6.16.
 *
 * Five-column link grid (Product · Resources · Company · Legal ·
 * Status & GitHub) plus a bottom row with the copyright, the social
 * icons (GitHub, Discord, X) and the static VERSION (`7.3.1` today —
 * sourced from /VERSION at build time once the metadata pass lands).
 *
 * No fancy motion. The page closes on the FinalCta band — the footer
 * is informational chrome.
 */

import type { ReactElement, SVGProps } from 'react';
import Link from 'next/link';
import { GithubMark } from './icons';
import { docs } from '@/lib/docs';
import { BrandLogo } from '@/components/brand/BrandLogo';
import { BRAND } from '@/lib/brand';

interface LinkSpec {
  label: string;
  href: string;
}

interface LinkColumn {
  heading: string;
  links: ReadonlyArray<LinkSpec>;
}

// Footer link targets. Where we have a real shipping artefact (LICENSE,
// SECURITY.md, ROADMAP.md, CHANGELOG.md, the docs portal, the GitHub repo)
// we link to it directly rather than wrapping it in a stub page that adds no
// information. Everything else routes to a real page under
// apps/web/src/app/(marketing)/ (about, contact, press, privacy, terms,
// pricing) or to the existing landing-page anchor.
const COLUMNS: ReadonlyArray<LinkColumn> = [
  {
    heading: 'Product',
    links: [
      // All four agents live in the same `#solution` section on the
      // home page. We surface them as separate footer links because
      // that's how buyers compare AI-SOC vendors — by named agent —
      // but they all land on the same anchor today. When the agent
      // deep-dives ship we'll point each row at its own page.
      { label: 'Detect agent', href: '/#solution' },
      { label: 'Triage agent', href: '/#solution' },
      { label: 'Hunt agent', href: '/#solution' },
      { label: 'Respond agent', href: '/#solution' },
      { label: 'Connectors', href: docs('connectors') },
      { label: 'Marketplace', href: '/marketplace' },
    ],
  },
  {
    heading: 'Resources',
    links: [
      { label: 'Docs', href: docs('intro') },
      { label: 'Architecture', href: docs('architecture') },
      { label: 'Benchmark', href: '/benchmark' },
      { label: 'Blog', href: '/blog' },
      {
        label: 'Changelog',
        href: 'https://github.com/SoorinSecurity/Agentic_SOC/blob/main/CHANGELOG.md',
      },
      {
        label: 'Roadmap',
        href: 'https://github.com/SoorinSecurity/Agentic_SOC/blob/main/ROADMAP.md',
      },
    ],
  },
  {
    heading: 'Company',
    links: [
      { label: 'About', href: '/about' },
      { label: 'Sovereign', href: '/sovereign' },
      { label: 'Customers', href: '/customers' },
      { label: 'Pricing', href: '/pricing' },
      { label: 'Contact', href: '/contact' },
      { label: 'Press', href: '/press' },
    ],
  },
  {
    heading: 'Legal',
    links: [
      {
        label: 'License (MIT)',
        href: 'https://github.com/SoorinSecurity/Agentic_SOC/blob/main/LICENSE',
      },
      { label: 'Privacy', href: '/privacy' },
      { label: 'Terms', href: '/terms' },
      {
        label: 'Security policy',
        href: 'https://github.com/SoorinSecurity/Agentic_SOC/blob/main/SECURITY.md',
      },
    ],
  },
  {
    // Renamed from 'Status & GitHub'. The status.tryaisoc.com subdomain
    // does not exist yet (DNS returns NXDOMAIN), so we removed the
    // "Status page" row rather than ship a link to nowhere. Re-add it
    // here as `{ label: 'Status page', href: 'https://status.tryaisoc.com' }`
    // once the subdomain ships (e.g. Statuspage, Better Stack, or a
    // hosted Grafana panel) and the column heading can revert to
    // 'Status & GitHub'.
    heading: 'GitHub & community',
    links: [
      { label: 'GitHub repo', href: 'https://github.com/SoorinSecurity/Agentic_SOC' },
      { label: 'Website', href: 'https://soorinsec.ir' },
      { label: 'Releases', href: 'https://github.com/SoorinSecurity/Agentic_SOC/releases' },
    ],
  },
];

const VERSION = '7.3.1';

function isExternal(href: string) {
  return /^https?:\/\//.test(href);
}

function FooterLink({ label, href }: LinkSpec) {
  const external = isExternal(href);
  return (
    <li>
      <Link
        href={href}
        rel={external ? 'noreferrer' : undefined}
        target={external ? '_blank' : undefined}
        className="text-sm text-velvet-content-tertiary transition-colors duration-200 hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
      >
        {label}
      </Link>
    </li>
  );
}

const SOCIAL_LINKS: ReadonlyArray<{
  label: string;
  href: string;
  Icon: (props: SVGProps<SVGSVGElement>) => ReactElement;
}> = [
  { label: 'GitHub', href: 'https://github.com/SoorinSecurity/Agentic_SOC', Icon: GithubMark },
];

export function Footer() {
  return (
    <footer className="relative border-t border-velvet-border bg-velvet-surface-base/80 backdrop-blur-sm">
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 sm:py-14 lg:px-8 lg:py-16">
        <div className="grid gap-10 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 lg:gap-8">
          {COLUMNS.map((column) => (
            <nav key={column.heading} aria-label={column.heading}>
              <h3 className="font-velvet-display font-normal text-xs uppercase tracking-[0.12em] text-velvet-content-primary">
                {column.heading}
              </h3>
              <ul className="mt-4 space-y-3">
                {column.links.map((link) => (
                  <FooterLink key={link.label} {...link} />
                ))}
              </ul>
            </nav>
          ))}
        </div>

        <div className="mt-12 flex flex-col items-start justify-between gap-4 border-t border-velvet-border pt-8 sm:flex-row sm:items-center">
          <div className="flex items-center gap-3">
            <BrandLogo variant="mark" size={28} />
            <p className="text-xs text-velvet-content-tertiary">
              © {new Date().getFullYear()} {BRAND.company} · {BRAND.product} · MIT-licensed · v
              {VERSION}
            </p>
          </div>
          <ul className="flex items-center gap-3">
            {SOCIAL_LINKS.map(({ label, href, Icon }) => (
              <li key={label}>
                <Link
                  href={href}
                  rel="noreferrer"
                  target="_blank"
                  aria-label={`${BRAND.shortName} on ${label}`}
                  className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-velvet-border text-velvet-content-tertiary transition-colors duration-200 hover:border-velvet-emerald/40 hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
                >
                  <Icon className="h-4 w-4" />
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </footer>
  );
}
