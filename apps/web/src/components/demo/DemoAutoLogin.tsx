'use client';

/**
 * DemoAutoLogin — silent auto-login for the hosted demo at tryaisoc.com.
 *
 * Logs in as the demo user when needed, then binds the home workspace so
 * AuthGuard does not bounce the visitor to /workspaces.
 */

import { useEffect } from 'react';
import { useSWRConfig } from 'swr';
import { authApi, workspacesApi } from '@/lib/api';
import { isDemoMode } from '@/lib/demoMode';

const DEMO_EMAIL =
  process.env.NEXT_PUBLIC_DEMO_AUTOLOGIN_EMAIL?.trim() || 'demo@tryaisoc.com';
const DEMO_PASSWORD =
  process.env.NEXT_PUBLIC_DEMO_AUTOLOGIN_PASSWORD?.trim() || 'aisoc-demo';

async function ensureDemoWorkspace(): Promise<void> {
  if (authApi.hasSelectedWorkspace()) return;
  const list = await workspacesApi.list();
  const home = list.find((w) => w.is_home) ?? list[0];
  if (!home) return;
  await authApi.selectWorkspace(home.id);
}

export function DemoAutoLogin() {
  const { mutate } = useSWRConfig();

  useEffect(() => {
    if (!isDemoMode()) return;
    if (typeof window === 'undefined') return;

    let cancelled = false;
    (async () => {
      try {
        if (!authApi.isAuthenticated()) {
          await authApi.login(DEMO_EMAIL, DEMO_PASSWORD);
        }
        if (cancelled) return;
        await ensureDemoWorkspace();
        if (cancelled) return;
        await mutate(() => true, undefined, { revalidate: true });
      } catch {
        /* swallow — demo still readable without auth */
      }
    })();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return null;
}
