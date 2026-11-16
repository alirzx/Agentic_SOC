'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { clsx } from 'clsx';
import {
  BookOpenCheck,
  Bot,
  BriefcaseBusiness,
  Building2,
  CalendarClock,
  ChartNoAxesColumnIncreasing,
  ChartPie,
  CircleDollarSign,
  ClipboardCheck,
  Compass,
  Crosshair,
  FileLock,
  FolderSearch,
  Funnel,
  Globe,
  Grid3x3,
  KeyRound,
  LayoutDashboard,
  LibraryBig,
  ListTodo,
  MessagesSquare,
  Newspaper,
  NotebookPen,
  Plug,
  Radar,
  Rocket,
  ScanEye,
  ScrollText,
  Settings,
  ShieldCheck,
  ShieldUser,
  SlidersHorizontal,
  Sparkles,
  Swords,
  Timer,
  Users,
  Waypoints,
  Workflow,
  type LucideIcon,
} from 'lucide-react';
import packageJson from '../../../package.json';
import { LiveQueueBadge } from './LiveQueueBadge';
import { BrandWordmark } from '@/components/brand/BrandWordmark';
import { BRAND } from '@/lib/brand';

const APP_VERSION = packageJson.version;

interface NavItem {
  label: string;
  href: string;
  icon: React.ReactNode;
  badge?: number;
  badgeColor?: string;
  /**
   * Optional live-data right slot. Renders in place of the static ``badge``
   * pill when present, so nav items that need real-time counts (e.g. the
   * Investigation Queue) can own their own polling without bloating this
   * component.
   */
  liveBadge?: React.ReactNode;
}

interface NavSection {
  title?: string;
  items: NavItem[];
}

/** Sidebar icon: lucide outline at the design's 22px / 1.5 stroke. */
function navIcon(Icon: LucideIcon) {
  return <Icon className="h-[22px] w-[22px]" strokeWidth={1.5} aria-hidden="true" />;
}

const navSections: NavSection[] = [
  {
    items: [
      {
        label: 'Dashboard',
        href: '/dashboard',
        icon: navIcon(LayoutDashboard),
      },
      {
        label: 'SOC Insights',
        href: '/dashboards/soc-insights',
        icon: navIcon(ChartNoAxesColumnIncreasing),
      },
    ],
  },
  {
    title: 'Threat Operations',
    items: [
      {
        label: 'Alerts',
        href: '/alerts',
        icon: navIcon(FolderSearch),
        badge: 0,
        badgeColor: 'bg-red-500',
      },
      {
        label: 'SOC Funnel',
        href: '/soc-funnel',
        icon: navIcon(Funnel),
      },
      {
        label: 'Investigation Queue',
        href: '/queue',
        icon: navIcon(ListTodo),
        liveBadge: <LiveQueueBadge />,
      },
      {
        label: 'Cases',
        href: '/cases',
        icon: navIcon(BriefcaseBusiness),
      },
      {
        label: 'Hunt',
        href: '/hunt',
        icon: navIcon(Crosshair),
      },
      {
        label: 'Explore',
        href: '/explore',
        icon: navIcon(Compass),
      },
      {
        label: 'Detection Rules',
        href: '/detection',
        icon: navIcon(ScanEye),
      },
      {
        label: 'Detection Catalog',
        href: '/detection/catalog',
        icon: navIcon(LibraryBig),
      },
      {
        label: 'MITRE Coverage',
        href: '/detection/coverage',
        icon: navIcon(Grid3x3),
      },
      {
        label: 'Detection Tuning',
        href: '/detection/tuning',
        icon: navIcon(SlidersHorizontal),
      },
      {
        label: 'Shifts',
        href: '/shifts',
        icon: navIcon(CalendarClock),
      },
    ],
  },
  {
    title: 'Intelligence',
    items: [
      {
        label: 'Threat Intel',
        href: '/threat-intel',
        icon: navIcon(Radar),
      },
      {
        label: 'Attack Graph',
        href: '/graph',
        icon: navIcon(Waypoints),
      },
      {
        label: 'AI Copilot',
        href: '/copilot',
        icon: navIcon(Sparkles),
      },
      {
        label: 'Investigation Chat',
        href: '/investigate',
        icon: navIcon(MessagesSquare),
      },
      {
        label: 'Agentic Shadow Runs',
        href: '/agentic/shadow-runs',
        icon: navIcon(Bot),
      },
      {
        label: 'Coverage Advisor',
        href: '/coverage-advisor',
        icon: navIcon(ShieldCheck),
      },
      {
        label: 'EASM',
        href: '/easm',
        icon: navIcon(Globe),
      },
    ],
  },
  {
    title: 'Automation',
    items: [
      {
        label: 'Workflow SOC',
        href: '/workflow-soc',
        icon: navIcon(Workflow),
      },
      {
        label: 'Playbooks',
        href: '/playbooks',
        icon: navIcon(BookOpenCheck),
      },
      {
        label: 'File Integrity (FIM)',
        href: '/fim',
        icon: navIcon(FileLock),
      },
      {
        label: 'Honeytokens',
        href: '/honeytokens',
        icon: navIcon(KeyRound),
      },
      {
        label: 'Purple Team',
        href: '/purple-team',
        icon: navIcon(Swords),
      },
      {
        label: 'Runbook',
        href: '/runbook',
        icon: navIcon(NotebookPen),
      },
    ],
  },
  {
    title: 'Platform',
    items: [
      {
        label: 'Get started',
        href: '/onboarding',
        icon: navIcon(Rocket),
      },
      {
        label: 'Connectors',
        href: '/connectors',
        icon: navIcon(Plug),
      },
      {
        label: 'Users',
        href: '/settings/users',
        icon: navIcon(Users),
      },
      {
        label: 'Roles & Permissions',
        href: '/settings/rbac',
        icon: navIcon(ShieldUser),
      },
      {
        label: 'Compliance',
        href: '/compliance',
        icon: navIcon(ClipboardCheck),
      },
      {
        label: 'MSSP Dashboard',
        href: '/mssp',
        icon: navIcon(Building2),
      },
      {
        label: 'Team Analytics',
        href: '/analytics/team',
        icon: navIcon(ChartPie),
      },
      {
        label: 'SLA Tracking',
        href: '/sla',
        icon: navIcon(Timer),
      },
      {
        label: 'Executive Digest',
        href: '/reports/digest',
        icon: navIcon(Newspaper),
      },
      {
        label: 'Cost Dashboard',
        href: '/costs',
        icon: navIcon(CircleDollarSign),
      },
      {
        label: 'Audit Log',
        href: '/audit',
        icon: navIcon(ScrollText),
      },
      {
        label: 'Settings',
        href: '/settings',
        icon: navIcon(Settings),
      },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  const isActive = (href: string) => {
    if (href === '/dashboard') return pathname === '/dashboard';
    return pathname.startsWith(href);
  };

  return (
    <>
      {/* Mobile hamburger */}
      <button
        type="button"
        aria-label="Open navigation"
        onClick={() => setMobileOpen(true)}
        className="md:hidden fixed top-4 left-4 z-40 p-2 rounded-lg bg-surface-card/90 text-fg-secondary hover:text-fg-primary"
      >
        <svg className="w-5 h-5" aria-hidden="true" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </button>

      {/* Backdrop */}
      {mobileOpen && (
        <div
          className="md:hidden fixed inset-0 z-30 bg-black/60"
          onClick={() => setMobileOpen(false)}
        />
      )}

    <aside
      aria-label="Application sidebar"
      className={clsx(
        'fixed inset-y-0 left-0 w-[304px] flex flex-col gap-2 p-3 z-40 transition-transform duration-200 bg-surface-base md:bg-transparent',
        mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
      )}
    >
      {/* Logo card */}
      <div className="flex items-center pl-6 pr-4 h-[62px] shrink-0 rounded-2xl border border-surface-border bg-surface-card">
        <Link href="/dashboard" className="min-w-0" aria-label={BRAND.product}>
          <BrandWordmark height={40} />
        </Link>
      </div>

      {/* Nav card */}
      <div className="flex min-h-0 flex-1 flex-col rounded-2xl border border-surface-border bg-surface-card">
      <nav aria-label="Main navigation" className="flex-1 overflow-y-auto py-5 px-6 space-y-5">
        {navSections.map((section, si) => (
          <div key={si}>
            {section.title && (
              <p className="px-4 mb-1.5 text-xs font-gilroy-semibold text-amgray-50 uppercase tracking-wider">
                {section.title}
              </p>
            )}
            <ul className="space-y-1">
              {section.items.map((item) => {
                const active = isActive(item.href);
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      onClick={() => setMobileOpen(false)}
                      className={clsx(
                        'group flex items-center gap-3 px-4 py-2.5 rounded-full text-[15px] font-gilroy-medium transition-all duration-150',
                        active
                          ? 'bg-teal-20/[0.12] text-teal-10'
                          : 'text-fg-primary hover:text-teal-10 hover:bg-surface-hover'
                      )}
                    >
                      <span className={clsx('shrink-0', active ? 'text-teal-10' : 'text-fg-primary group-hover:text-teal-10')}>{item.icon}</span>
                      <span>{item.label}</span>
                      {item.liveBadge
                        ? item.liveBadge
                        : typeof item.badge === 'number' && item.badge > 0 && (
                            <span
                              className={`ml-auto text-xs font-bold px-1.5 py-0.5 rounded-full text-white ${item.badgeColor ?? 'bg-gray-600'}`}
                            >
                              {item.badge > 99 ? '99+' : item.badge}
                            </span>
                          )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-surface-border">
        <div className="flex items-center gap-2 rounded-[10px] bg-teal-20 px-3 py-2 text-xs text-dark-80 font-gilroy-semibold">
          <span className="font-mono">v{APP_VERSION}</span>
          <span>·</span>
          <a
            href="https://github.com/SoorinSecurity/Agentic_SOC"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:opacity-80 transition-opacity"
          >
            MIT License
          </a>
        </div>
      </div>
      </div>
    </aside>
    </>
  );
}
