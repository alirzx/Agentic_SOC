'use client';

import { useEffect, useState } from 'react';
import { usePathname } from 'next/navigation';
import { ThemeToggle } from '@/components/theme/ThemeToggle';
import { TimeWindowSelector } from './TimeWindowSelector';
import { TenantSwitcher } from './TenantSwitcher';
import { RoleBadge } from './RoleBadge';
import { useTenant } from './TenantProvider';

// Order matters: longer/more specific paths first so startsWith() picks
// the right label for nested routes (e.g. /detection/catalog before /detection).
const routeLabels: Record<string, { title: string; description: string }> = {
  '/detection/catalog': { title: 'Detection Catalog', description: 'Curated rule packs and templates' },
  '/settings/rbac': { title: 'Roles & Permissions', description: 'Access control and team management' },
  '/dashboard': { title: 'Dashboard', description: 'SOC overview and metrics' },
  '/alerts': { title: 'Alerts', description: 'Security alerts and incidents' },
  '/cases': { title: 'Cases', description: 'Incident case management' },
  '/hunt': { title: 'Threat Hunting', description: 'Proactive threat hunts and queries' },
  '/detection': { title: 'Detection Rules', description: 'SIEM detection rules and tuning' },
  '/threat-intel': { title: 'Threat Intelligence', description: 'IOC lookup and threat feeds' },
  '/graph': { title: 'Attack Graph', description: 'Visualize relationships across alerts and assets' },
  '/copilot': { title: 'AI Copilot', description: 'AI-assisted investigation and triage' },
  '/playbooks': { title: 'Playbooks', description: 'Automated response and SOAR workflows' },
  '/marketplace': { title: 'Marketplace', description: 'Plugins, integrations, and content packs' },
  '/honeytokens': { title: 'Honeytokens', description: 'Deception assets and trip-wire alerts' },
  '/purple-team': { title: 'Purple Team', description: 'Adversary emulation and detection coverage' },
  '/connectors': { title: 'Connectors', description: 'Security tool integrations' },
  '/compliance': { title: 'Compliance', description: 'Frameworks, controls, and evidence' },
  '/sla': { title: 'SLA Tracking', description: 'Response time targets and breach risk' },
  '/audit': { title: 'Audit Log', description: 'Platform activity and security events' },
  '/settings': { title: 'Settings', description: 'Platform configuration' },
  '/': { title: 'Dashboard', description: 'SOC overview and metrics' },
};

interface TopBarProps {
  /**
   * When true, the demo banner is rendered above this bar so we shift the
   * fixed-position TopBar down by its height (h-9 = 36px). Driven by
   * `AppShell` which reads `isDemoMode()` once at render.
   */
  demoOffset?: boolean;
}

export function TopBar({ demoOffset = false }: TopBarProps) {
  const pathname = usePathname();
  const [now, setNow] = useState<Date | null>(null);
  const [shortcut, setShortcut] = useState<'⌘K' | 'Ctrl K'>('⌘K');
  const { userRole } = useTenant();

  // Update the clock every second on the client only (avoids hydration drift).
  useEffect(() => {
    setNow(new Date());
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);

  // Show the right OS-specific shortcut hint without breaking SSR.
  useEffect(() => {
    if (typeof navigator === 'undefined') return;
    const isMac = /Mac|iPod|iPhone|iPad/.test(navigator.platform);
    setShortcut(isMac ? '⌘K' : 'Ctrl K');
  }, []);

  // Match the most specific path first. Object insertion order is preserved
  // and routeLabels lists nested routes (e.g. /detection/catalog) before
  // their parents so startsWith() picks the deepest match.
  const routeKey = Object.keys(routeLabels).find(
    (key) => key !== '/' && pathname.startsWith(key)
  ) || (pathname === '/' ? '/' : null);

  // Derive a sensible title for unknown routes from the URL itself instead
  // of silently falling back to "Alerts", which used to make every page
  // look like the alerts page.
  const fallbackFromPath = (() => {
    const segment = pathname.split('/').filter(Boolean)[0] ?? '';
    const title = segment
      ? segment
          .split('-')
          .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
          .join(' ')
      : 'Soorin';
    return { title, description: '' };
  })();

  const routeInfo = routeKey ? routeLabels[routeKey] : fallbackFromPath;

  const openPalette = () => {
    // Synthesize the same keystroke the palette listens for. Keeps a single
    // source of truth — the palette itself owns the open/close logic.
    const event = new KeyboardEvent('keydown', {
      key: 'k',
      metaKey: true,
      ctrlKey: true,
      bubbles: true,
    });
    window.dispatchEvent(event);
  };

  const timeStr = now
    ? now.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      })
    : '—';
  const dateStr = now
    ? now.toLocaleDateString('en-US', {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      })
    : '';

  return (
    <header
      className={`fixed left-60 right-0 h-16 flex items-center justify-between px-6 bg-dark-70/95 backdrop-blur-sm border-b border-[#374151] z-20 ${
        demoOffset ? 'top-9' : 'top-0'
      }`}
    >
      {/* Page title */}
      <div>
        <h1 className="text-base font-gilroy-semibold text-white leading-tight">{routeInfo.title}</h1>
        <p className="text-xs text-amgray-50 font-gilroy-medium">{routeInfo.description}</p>
      </div>

      {/* Center: command palette launcher — AssetManagement search pill */}
      <div className="flex-1 max-w-lg mx-8">
        <button
          type="button"
          onClick={openPalette}
          aria-label="Open command palette"
          className="group relative flex w-full items-center gap-3 rounded-full border border-[#374151] bg-dark-70 h-[42px] px-4 text-left text-sm text-amgray-30 transition-all hover:border-teal-20/50 hover:text-teal-10 focus:border-teal-20 focus:outline-none focus:ring-2 focus:ring-teal-20/30"
        >
          <svg
            className="h-4 w-4 text-amgray-50 transition-colors group-hover:text-teal-10"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          <span className="flex-1 truncate text-amgray-30 group-hover:text-amgray-20 font-gilroy-medium">
            Search alerts, cases, rules, or run a command…
          </span>
          <kbd className="pointer-events-none rounded-[6px] bg-dark-20 border border-[#333A47] px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-amgray-30">
            {shortcut}
          </kbd>
        </button>
      </div>

      {/* Right: time window, tenant, role badge, clock, theme toggle, notifications, user */}
      <div className="flex items-center gap-3">
        {/*
          v1.5 W4: Global time-window selector. Lives next to the tenant
          switcher in the TopBar so every page reads from the same context.
          Hidden on small screens to keep the bar from wrapping.
        */}
        <div className="hidden md:block">
          <TimeWindowSelector />
        </div>

        {/*
          v1.5 W5: Tenant switcher. For MSSP parents this is a dropdown of
          tenants they can pivot into; for standalone tenants this collapses
          into a read-only badge.
        */}
        <div className="hidden md:block">
          <TenantSwitcher />
        </div>

        {/*
          v1.5 W5: Role badge — surfaces the operator's effective role
          (analyst / analyst-lead / admin / viewer / mssp-admin) so
          permission boundaries are visible at a glance. The badge intentionally
          renders even when userRole is null so the slot doesn't reflow as it
          resolves.
        */}
        <div className="hidden lg:block">
          <RoleBadge role={userRole} />
        </div>

        <div className="hidden lg:block h-6 w-px bg-[#374151]" aria-hidden />

        {/* Clock */}
        <div className="text-right hidden lg:block">
          <p className="text-sm font-mono text-amgray-20" suppressHydrationWarning>{timeStr}</p>
          <p className="text-xs text-amgray-50" suppressHydrationWarning>{dateStr}</p>
        </div>

        <ThemeToggle />

        {/* Notifications — circular chrome like AssetManagement */}
        <button
          type="button"
          aria-label="Open notifications"
          className="relative flex h-10 w-10 items-center justify-center rounded-full border border-[#374151] text-amgray-30 hover:text-teal-10 hover:border-teal-20/40 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-20/50"
        >
          <svg
            className="w-5 h-5"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            aria-hidden
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
          </svg>
          <span
            aria-hidden
            className="absolute top-1.5 right-1.5 w-2 h-2 bg-teal-20 rounded-full ring-2 ring-dark-70 shadow-[0_0_10px_0_#3AC7B6]"
          />
        </button>

        {/* User avatar */}
        <div className="flex items-center gap-2 cursor-pointer group">
          <div className="w-8 h-8 rounded-full bg-teal-20 flex items-center justify-center text-xs font-gilroy-bold text-dark-80">
            SO
          </div>
          <div className="hidden lg:block">
            <p className="text-xs font-gilroy-medium text-amgray-20">SOC Analyst</p>
            <p className="text-xs text-amgray-50">Admin</p>
          </div>
        </div>
      </div>
    </header>
  );
}
