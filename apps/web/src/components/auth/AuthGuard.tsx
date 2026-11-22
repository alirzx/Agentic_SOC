'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { authApi } from '@/lib/api';
import { isDemoMode } from '@/lib/demoMode';

function loginHref(pathname: string): string {
  const next = pathname && pathname !== '/login' ? pathname : '/dashboard';
  return `/login?next=${encodeURIComponent(next)}`;
}

function workspacesHref(pathname: string): string {
  const next = pathname && pathname !== '/workspaces' ? pathname : '/dashboard';
  return `/workspaces?next=${encodeURIComponent(next)}`;
}

/**
 * Blocks the SOC console until a live (unexpired) session exists and a
 * workspace has been selected. Expired tokens clear and send the operator
 * back to /login; missing workspace selection sends them to /workspaces.
 */
export function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [allowed, setAllowed] = useState(false);

  useEffect(() => {
    const allow = () => {
      if (!authApi.hasSelectedWorkspace()) {
        setAllowed(false);
        router.replace(workspacesHref(pathname));
        return;
      }
      setAllowed(true);
    };

    if (authApi.isAuthenticated()) {
      allow();
      return;
    }
    if (isDemoMode()) {
      const started = Date.now();
      const timer = window.setInterval(() => {
        if (authApi.isAuthenticated()) {
          window.clearInterval(timer);
          allow();
          return;
        }
        if (Date.now() - started > 4000) {
          window.clearInterval(timer);
          router.replace(loginHref(pathname));
        }
      }, 150);
      return () => window.clearInterval(timer);
    }
    setAllowed(false);
    router.replace(loginHref(pathname));
  }, [pathname, router]);

  if (!allowed) {
    return (
      <div className="min-h-screen bg-surface-base flex items-center justify-center text-sm text-gray-400">
        Checking session…
      </div>
    );
  }
  return <>{children}</>;
}
