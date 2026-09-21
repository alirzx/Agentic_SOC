'use client';

import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import {
  ApiError,
  authApi,
  tenantsApi,
  type CreateTenantUserInput,
  type TenantUser,
  type TenantUserRole,
} from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';

const ROLE_OPTIONS: ReadonlyArray<{ value: TenantUserRole; label: string }> = [
  { value: 'super_admin', label: 'Super admin' },
  { value: 'platform_admin', label: 'Platform admin' },
  { value: 'admin', label: 'Admin' },
  { value: 'tenant_admin', label: 'Tenant admin' },
  { value: 'soc_lead', label: 'SOC lead' },
  { value: 'soc_analyst', label: 'SOC analyst' },
  { value: 'threat_hunter', label: 'Threat hunter' },
  { value: 'viewer', label: 'Viewer' },
];

const PRIVILEGED = new Set(['super_admin', 'platform_admin', 'admin']);

function roleLabel(role: string): string {
  return ROLE_OPTIONS.find((item) => item.value === role)?.label ?? role.replace(/_/g, ' ');
}

function formatWhen(value: string | null): string {
  if (!value) {
    return 'Never';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '—';
  }
  return date.toLocaleString();
}

export function UsersView() {
  const { data, error, isLoading, mutate } = useSWR('tenant-users', () => tenantsApi.listUsers());
  const [canAssignPrivileged, setCanAssignPrivileged] = useState(false);
  useEffect(() => {
    setCanAssignPrivileged(PRIVILEGED.has((authApi.currentUser()?.role ?? '').toLowerCase()));
  }, []);
  const [creating, setCreating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState<CreateTenantUserInput>({
    email: '',
    username: '',
    password: '',
    role: 'soc_analyst',
  });

  const assignableRoles = useMemo(
    () => ROLE_OPTIONS.filter((item) => canAssignPrivileged || !PRIVILEGED.has(item.value)),
    [canAssignPrivileged],
  );

  const createUser = async (event: React.FormEvent) => {
    event.preventDefault();
    if (saving) {
      return;
    }
    setSaving(true);
    try {
      await tenantsApi.createUser(form);
      toast.success('User created');
      setForm({ email: '', username: '', password: '', role: 'soc_analyst' });
      setCreating(false);
      await mutate();
    } catch (err) {
      const message = err instanceof ApiError ? err.body || err.message : 'Could not create user';
      toast.error(String(message).slice(0, 240));
    } finally {
      setSaving(false);
    }
  };

  const changeRole = async (user: TenantUser, role: TenantUserRole) => {
    try {
      await tenantsApi.updateUser(user.id, { role });
      toast.success(`Updated ${user.email}`);
      await mutate();
    } catch (err) {
      const message = err instanceof ApiError ? err.body || err.message : 'Could not update role';
      toast.error(String(message).slice(0, 240));
    }
  };

  const toggleActive = async (user: TenantUser) => {
    try {
      await tenantsApi.updateUser(user.id, { is_active: !user.is_active });
      await mutate();
    } catch (err) {
      toast.error('Could not update user status');
    }
  };

  if (error instanceof ApiError && error.status === 403) {
    return (
      <ErrorState
        title="Super admin required"
        description="You need users:write (super admin / admin) to manage team members."
      />
    );
  }
  if (error) {
    return <ErrorState title="Could not load users" description="Check that the API is reachable and you are signed in." />;
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-100">Users</h2>
          <p className="text-sm text-gray-400 mt-1">
            Create operators and change their roles. Super admins can assign admin access.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setCreating((open) => !open)}
          className="bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium px-4 py-2 rounded-lg"
        >
          {creating ? 'Cancel' : 'Add user'}
        </button>
      </div>

      {creating && (
        <form onSubmit={createUser} className="bg-dark-60 border border-[#374151]/60 rounded-xl p-5 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <label className="block text-sm text-gray-300">
              Email
              <input
                type="email"
                required
                value={form.email}
                onChange={(event) => setForm({ ...form, email: event.target.value })}
                className="mt-1 w-full bg-dark-20 border border-[#333A47] rounded-lg px-3 py-2 text-sm"
              />
            </label>
            <label className="block text-sm text-gray-300">
              Username
              <input
                type="text"
                required
                minLength={1}
                value={form.username}
                onChange={(event) => setForm({ ...form, username: event.target.value })}
                className="mt-1 w-full bg-dark-20 border border-[#333A47] rounded-lg px-3 py-2 text-sm"
              />
            </label>
            <label className="block text-sm text-gray-300">
              Password
              <input
                type="password"
                required
                minLength={8}
                value={form.password}
                onChange={(event) => setForm({ ...form, password: event.target.value })}
                className="mt-1 w-full bg-dark-20 border border-[#333A47] rounded-lg px-3 py-2 text-sm"
              />
            </label>
            <label className="block text-sm text-gray-300">
              Role
              <select
                value={form.role}
                onChange={(event) => setForm({ ...form, role: event.target.value as TenantUserRole })}
                className="mt-1 w-full bg-dark-20 border border-[#333A47] rounded-lg px-3 py-2 text-sm"
              >
                {assignableRoles.map((item) => (
                  <option key={item.value} value={item.value}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <button
            type="submit"
            disabled={saving}
            className="bg-teal-600 hover:bg-teal-500 disabled:opacity-60 text-white text-sm font-medium px-4 py-2 rounded-lg"
          >
            {saving ? 'Creating…' : 'Create user'}
          </button>
        </form>
      )}

      {isLoading && !data ? (
        <p className="text-sm text-gray-500">Loading users…</p>
      ) : !data || data.length === 0 ? (
        <EmptyState title="No users yet" description="Create the first operator for this tenant." />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[#374151]/60">
          <table className="w-full text-sm">
            <thead className="bg-dark-60 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-4 py-3">User</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Last login</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.map((user) => (
                <tr key={user.id} className="border-t border-[#374151]/40">
                  <td className="px-4 py-3">
                    <div className="text-gray-100">{user.username}</div>
                    <div className="text-xs text-gray-500">{user.email}</div>
                  </td>
                  <td className="px-4 py-3">
                    <select
                      value={user.role}
                      onChange={(event) => changeRole(user, event.target.value as TenantUserRole)}
                      className="bg-dark-20 border border-[#333A47] rounded-lg px-2 py-1 text-sm"
                    >
                      {(PRIVILEGED.has(user.role) && !canAssignPrivileged
                        ? ROLE_OPTIONS
                        : assignableRoles
                      ).map((item) => (
                        <option key={item.value} value={item.value}>
                          {item.label}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4 py-3">
                    <span className={user.is_active ? 'text-emerald-300' : 'text-gray-500'}>
                      {user.is_active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400">{formatWhen(user.last_login)}</td>
                  <td className="px-4 py-3">
                    <button
                      type="button"
                      onClick={() => toggleActive(user)}
                      className="text-xs text-gray-300 hover:text-white"
                    >
                      {user.is_active ? 'Disable' : 'Enable'}
                    </button>
                    <span className="sr-only">{roleLabel(user.role)}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
