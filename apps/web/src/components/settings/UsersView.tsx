'use client';

import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import {
  ApiError,
  authApi,
  tenantsApi,
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

interface UserFormState {
  email: string;
  username: string;
  password: string;
  role: TenantUserRole;
  is_active: boolean;
}

const EMPTY_FORM: UserFormState = {
  email: '',
  username: '',
  password: '',
  role: 'soc_analyst',
  is_active: true,
};

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

function toForm(user: TenantUser): UserFormState {
  return {
    email: user.email,
    username: user.username,
    password: '',
    role: (ROLE_OPTIONS.some((item) => item.value === user.role) ? user.role : 'soc_analyst') as TenantUserRole,
    is_active: user.is_active,
  };
}

export function UsersView() {
  const { data, error, isLoading, mutate } = useSWR('tenant-users', () => tenantsApi.listUsers());
  const [canAssignPrivileged, setCanAssignPrivileged] = useState(false);
  const [selfId, setSelfId] = useState<string | null>(null);
  useEffect(() => {
    const me = authApi.currentUser();
    setCanAssignPrivileged(PRIVILEGED.has((me?.role ?? '').toLowerCase()));
    setSelfId(me?.id ?? null);
  }, []);
  const [saving, setSaving] = useState(false);
  const [editingId, setEditingId] = useState<string | 'new' | null>(null);
  const [form, setForm] = useState<UserFormState>(EMPTY_FORM);
  const [changePassword, setChangePassword] = useState(false);
  const assignableRoles = useMemo(
    () => ROLE_OPTIONS.filter((item) => canAssignPrivileged || !PRIVILEGED.has(item.value)),
    [canAssignPrivileged],
  );

  const openCreate = () => {
    setEditingId('new');
    setChangePassword(false);
    setForm(EMPTY_FORM);
  };

  const openEdit = (user: TenantUser) => {
    setEditingId(user.id);
    setChangePassword(false);
    setForm(toForm(user));
  };

  const closeEditor = () => {
    setEditingId(null);
    setChangePassword(false);
    setForm(EMPTY_FORM);
  };

  const saveUser = async (event: React.FormEvent) => {
    event.preventDefault();
    if (saving || !editingId) {
      return;
    }
    setSaving(true);
    try {
      if (editingId === 'new') {
        await tenantsApi.createUser({
          email: form.email.trim(),
          username: form.username.trim(),
          password: form.password.trim(),
          role: form.role,
        });
        toast.success('User created');
      } else {
        const payload: {
          email: string;
          username: string;
          role: TenantUserRole;
          is_active: boolean;
          password?: string;
        } = {
          email: form.email.trim(),
          username: form.username.trim(),
          role: form.role,
          is_active: form.is_active,
        };
        if (changePassword && form.password.trim()) {
          payload.password = form.password.trim();
        }
        await tenantsApi.updateUser(editingId, payload);
        toast.success('User updated');
      }
      closeEditor();
      await mutate();
    } catch (err) {
      const message = err instanceof ApiError ? err.body || err.message : 'Could not save user';
      toast.error(String(message).slice(0, 240));
    } finally {
      setSaving(false);
    }
  };

  const toggleActive = async (user: TenantUser) => {
    if (user.id === selfId) {
      toast.error('You cannot disable your own account');
      return;
    }
    try {
      await tenantsApi.updateUser(user.id, { is_active: !user.is_active });
      await mutate();
    } catch (err) {
      const message = err instanceof ApiError ? err.body || err.message : 'Could not update user status';
      toast.error(String(message).slice(0, 240));
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

  const isCreate = editingId === 'new';
  const editorOpen = editingId !== null;

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-100">Users</h2>
          <p className="text-sm text-gray-400 mt-1">
            Create, edit, and change operator roles. You cannot disable your own login.
          </p>
        </div>
        <button
          type="button"
          onClick={() => (editorOpen ? closeEditor() : openCreate())}
          className="bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium px-4 py-2 rounded-lg"
        >
          {editorOpen ? 'Cancel' : 'Add user'}
        </button>
      </div>

      {editorOpen && (
        <form onSubmit={saveUser} autoComplete="off" className="bg-dark-60 border border-[#374151]/60 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-semibold text-gray-100">{isCreate ? 'New user' : 'Edit user'}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <label className="block text-sm text-gray-300">
              Email
              <input
                type="email"
                name="aisoc-user-email"
                autoComplete="off"
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
                name="aisoc-user-username"
                autoComplete="off"
                required
                minLength={1}
                value={form.username}
                onChange={(event) => setForm({ ...form, username: event.target.value })}
                className="mt-1 w-full bg-dark-20 border border-[#333A47] rounded-lg px-3 py-2 text-sm"
              />
            </label>
            {isCreate ? (
              <label className="block text-sm text-gray-300">
                Password
                <input
                  type="password"
                  name="aisoc-user-password"
                  autoComplete="new-password"
                  required
                  minLength={8}
                  value={form.password}
                  onChange={(event) => setForm({ ...form, password: event.target.value })}
                  className="mt-1 w-full bg-dark-20 border border-[#333A47] rounded-lg px-3 py-2 text-sm"
                />
              </label>
            ) : (
              <div className="block text-sm text-gray-300 md:col-span-2 space-y-2">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={changePassword}
                    onChange={(event) => {
                      setChangePassword(event.target.checked);
                      if (!event.target.checked) {
                        setForm({ ...form, password: '' });
                      }
                    }}
                  />
                  Set a new password
                </label>
                {changePassword ? (
                  <input
                    type="password"
                    name="aisoc-user-new-password"
                    autoComplete="new-password"
                    required
                    minLength={8}
                    value={form.password}
                    onChange={(event) => setForm({ ...form, password: event.target.value })}
                    className="w-full bg-dark-20 border border-[#333A47] rounded-lg px-3 py-2 text-sm"
                    placeholder="At least 8 characters"
                  />
                ) : (
                  <p className="text-xs text-gray-500">Leave unchecked to keep the current password.</p>
                )}
              </div>
            )}
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
            {!isCreate && (
              <label className="flex items-center gap-2 text-sm text-gray-300 md:col-span-2">
                <input
                  type="checkbox"
                  checked={form.is_active}
                  disabled={editingId === selfId}
                  onChange={(event) => setForm({ ...form, is_active: event.target.checked })}
                />
                Active (can sign in)
              </label>
            )}
          </div>
          <button
            type="submit"
            disabled={saving}
            className="bg-teal-600 hover:bg-teal-500 disabled:opacity-60 text-white text-sm font-medium px-4 py-2 rounded-lg"
          >
            {saving ? 'Saving…' : isCreate ? 'Create user' : 'Save changes'}
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
                  <td className="px-4 py-3 text-gray-200">{roleLabel(user.role)}</td>
                  <td className="px-4 py-3">
                    <span className={user.is_active ? 'text-emerald-300' : 'text-gray-500'}>
                      {user.is_active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400">{formatWhen(user.last_login)}</td>
                  <td className="px-4 py-3 space-x-3">
                    <button
                      type="button"
                      onClick={() => openEdit(user)}
                      className="text-xs text-teal-300 hover:text-white"
                    >
                      Edit
                    </button>
                    {user.id !== selfId && (
                      <button
                        type="button"
                        onClick={() => toggleActive(user)}
                        className="text-xs text-gray-300 hover:text-white"
                      >
                        {user.is_active ? 'Disable' : 'Enable'}
                      </button>
                    )}
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
