'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import {
  authApi,
  getActiveTenantId,
  msspApi,
  setActiveTenantId,
  workspacesApi,
  type AuthUser,
  type ChildTenant,
  type WorkspaceSummary,
} from '@/lib/api';

export interface TenantOption {
  /** Stable tenant UUID — matches the `X-Tenant-Id` header value. */
  id: string;
  /** Human-readable display name. */
  name: string;
  /** What kind of tenant this is (parent / child / standalone / workspace). */
  role: 'parent' | 'child' | 'standalone';
}

interface TenantContextValue {
  /** Workspace the active session is currently operating against. */
  current: TenantOption | null;
  /** Every workspace the operator can flip to (incl. `current`). */
  available: TenantOption[];
  /** The signed-in user's *org-level* role (analyst / responder / admin / …). */
  userRole: string | null;
  /** Switch the active workspace (rebinds JWT + reloads). */
  setTenant: (tenantId: string) => void;
  /** True while we're loading the workspace list (e.g. on first paint). */
  loading: boolean;
  /** Last error, if any — surfaced through the TopBar role badge tooltip. */
  error: string | null;
}

const TenantContext = createContext<TenantContextValue | null>(null);

function fromWorkspace(ws: WorkspaceSummary): TenantOption {
  return { id: ws.id, name: ws.name, role: 'standalone' };
}

function fromChild(t: ChildTenant): TenantOption {
  return {
    id: t.id,
    name: t.name,
    role: t.mssp_role === 'parent' || t.mssp_role === 'child' ? t.mssp_role : 'standalone',
  };
}

/**
 * Tracks the active workspace + every workspace the user can flip to.
 *
 * Memberships come from ``GET /workspaces``. MSSP children are still merged
 * in for parent operators. Switching calls ``authApi.selectWorkspace`` so the
 * API ``CurrentUser.tenant_id`` rebinds, then hard-reloads to flush SWR.
 */
export function TenantProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<TenantOption | null>(null);
  const [available, setAvailable] = useState<TenantOption[]>([]);
  const [userRole, setUserRole] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const user: AuthUser | null = authApi.currentUser();
      if (!cancelled) setUserRole(user?.role ?? null);

      if (!authApi.isAuthenticated()) {
        if (!cancelled) setLoading(false);
        return;
      }

      try {
        const memberships = await workspacesApi.list();
        if (cancelled) return;
        const list: TenantOption[] = memberships.map(fromWorkspace);

        // MSSP parents may also flip into child tenants they manage.
        try {
          const children = await msspApi.listChildren();
          for (const child of children) {
            if (!list.some((t) => t.id === child.id)) {
              list.push(fromChild(child));
            }
          }
        } catch {
          /* non-fatal for non-MSSP users */
        }
        if (cancelled) return;

        const activeId = getActiveTenantId();
        let activeOption = list.find((t) => t.id === activeId) ?? list[0] ?? null;
        if (user?.tenant_id) {
          const bound = list.find((t) => t.id === user.tenant_id);
          if (bound) activeOption = bound;
        }

        setAvailable(list);
        setCurrent(activeOption);
        setError(null);
      } catch (err) {
        if (cancelled) return;
        const message = err instanceof Error ? err.message : 'Failed to load workspaces';
        setError(message);
        if (user) {
          const fallback: TenantOption = {
            id: user.tenant_id,
            name: 'My workspace',
            role: 'standalone',
          };
          setCurrent(fallback);
          setAvailable([fallback]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const setTenant = useCallback((tenantId: string) => {
    void (async () => {
      try {
        await authApi.selectWorkspace(tenantId);
        setActiveTenantId(tenantId);
        setCurrent((prev) => {
          const next = available.find((t) => t.id === tenantId);
          return next ?? prev;
        });
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('aisoc:tenant-switched', { detail: { tenantId } }));
          window.location.reload();
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to switch workspace';
        setError(message);
      }
    })();
  }, [available]);

  const value = useMemo<TenantContextValue>(
    () => ({ current, available, userRole, setTenant, loading, error }),
    [current, available, userRole, setTenant, loading, error],
  );

  return <TenantContext.Provider value={value}>{children}</TenantContext.Provider>;
}

export function useTenant(): TenantContextValue {
  const ctx = useContext(TenantContext);
  if (!ctx) {
    throw new Error('useTenant() must be used inside <TenantProvider>');
  }
  return ctx;
}
