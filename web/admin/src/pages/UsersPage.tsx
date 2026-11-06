import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  TableContainer,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  TableToolbar,
  TableToolbarContent,
  TableToolbarSearch,
  Button,
  Pagination,
  DataTableSkeleton,
  InlineNotification,
  Modal,
  TextInput,
  PasswordInput,
  Select,
  SelectItem,
  Toggle,
  Checkbox,
  Tag,
  Tabs,
  TabList,
  Tab,
  TabPanels,
  TabPanel,
  Stack,
  Search,
} from '@carbon/react';
import {
  Add,
  Edit,
  TrashCan,
  Renew,
  UserAvatar,
  UserMultiple,
  Security,
} from '@carbon/icons-react';
import { PageHeader } from '../components/common';
import { apiService } from '../services/api';
import { useAuth } from '../context/AuthContext';
import type {
  UserRecord,
  RoleRecord,
  PermissionRecord,
  UserPayload,
  RolePayload,
} from '../types';
import './UsersPage.scss';

function formatRoleName(name?: string): string {
  if (!name) return '—';
  const special: Record<string, string> = {
    super_admin: 'Super Admin',
    admin: 'Admin',
    operator: 'Operator',
    viewer: 'Viewer',
    auditor: 'Auditor',
    secops_auditor: 'SecOps Auditor',
  };
  if (special[name.toLowerCase()]) return special[name.toLowerCase()];
  return name
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatCategoryName(category: string): string {
  const map: Record<string, string> = {
    users: 'Users & Roles',
    waf: 'WAF',
    traffic: 'Traffic Control',
    bot: 'Bot Protection',
    api: 'API Shield',
    access: 'Edge Access',
    proxy: 'Proxy & Routing',
    ssl: 'SSL Certificates',
    system: 'System Settings',
    audit: 'Audit Logs',
    modules: 'Modules',
    alerts: 'Alerts',
    general: 'General',
  };
  return map[category.toLowerCase()] || category.charAt(0).toUpperCase() + category.slice(1);
}

function formatLastLogin(val?: string): string {
  if (!val || val.startsWith('0001')) return 'Never';
  const date = new Date(val);
  return Number.isNaN(date.getTime()) ? 'Never' : date.toLocaleString();
}

export const UsersPage: React.FC = () => {
  const { user: currentUser } = useAuth();

  const [activeTab, setActiveTab] = useState<number>(0);
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [roles, setRoles] = useState<RoleRecord[]>([]);
  const [permissions, setPermissions] = useState<PermissionRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [roleSearchQuery, setRoleSearchQuery] = useState<string>('');
  const [errorNotification, setErrorNotification] = useState<string | null>(null);
  const [successNotification, setSuccessNotification] = useState<string | null>(null);

  const [page, setPage] = useState<number>(1);
  const [limit, setLimit] = useState<number>(10);
  const [totalUsers, setTotalUsers] = useState<number>(0);

  const [isAddUserOpen, setIsAddUserOpen] = useState<boolean>(false);
  const [isEditUserOpen, setIsEditUserOpen] = useState<boolean>(false);
  const [isDeleteUserOpen, setIsDeleteUserOpen] = useState<boolean>(false);
  const [selectedUser, setSelectedUser] = useState<UserRecord | null>(null);

  const [userFormUsername, setUserFormUsername] = useState<string>('');
  const [userFormEmail, setUserFormEmail] = useState<string>('');
  const [userFormRoleId, setUserFormRoleId] = useState<string>('');
  const [userFormPassword, setUserFormPassword] = useState<string>('');
  const [userFormIsActive, setUserFormIsActive] = useState<boolean>(true);
  const [userFormSubmitting, setUserFormSubmitting] = useState<boolean>(false);
  const [userFormError, setUserFormError] = useState<string | null>(null);

  const [isAddRoleOpen, setIsAddRoleOpen] = useState<boolean>(false);
  const [isEditRoleOpen, setIsEditRoleOpen] = useState<boolean>(false);
  const [isDeleteRoleOpen, setIsDeleteRoleOpen] = useState<boolean>(false);
  const [selectedRole, setSelectedRole] = useState<RoleRecord | null>(null);
  const [viewRolePermissions, setViewRolePermissions] = useState<RoleRecord | null>(null);

  const [roleFormName, setRoleFormName] = useState<string>('');
  const [roleFormDesc, setRoleFormDesc] = useState<string>('');
  const [roleFormPermissions, setRoleFormPermissions] = useState<string[]>([]);
  const [roleFormSubmitting, setRoleFormSubmitting] = useState<boolean>(false);
  const [roleFormError, setRoleFormError] = useState<string | null>(null);
  const [roleFormPermSearch, setRoleFormPermSearch] = useState<string>('');

  const loadData = useCallback(async () => {
    setLoading(true);
    setErrorNotification(null);
    try {
      const [usersRes, rolesRes, permsRes] = await Promise.all([
        apiService.getUsers(page, limit).catch((err) => {
          console.warn('[UsersPage] getUsers error:', err);
          return { data: [], meta: { page: 1, limit, total: 0, total_pages: 1 } };
        }),
        apiService.getRoles().catch((err) => {
          console.warn('[UsersPage] getRoles error:', err);
          return { data: [] };
        }),
        apiService.getPermissions().catch((err) => {
          console.warn('[UsersPage] getPermissions error:', err);
          return { data: [] };
        }),
      ]);

      setUsers(usersRes.data || []);
      setTotalUsers(usersRes.meta?.total ?? (usersRes.data?.length || 0));
      setRoles(rolesRes.data || []);
      setPermissions(permsRes.data || []);
    } catch (err: any) {
      setErrorNotification(err?.message || 'Failed to load users and roles.');
    } finally {
      setLoading(false);
    }
  }, [page, limit]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const rolesById = useMemo(() => {
    const map = new Map<string, RoleRecord>();
    roles.forEach((r) => map.set(r.id, r));
    return map;
  }, [roles]);

  const activeSuperAdminCount = useMemo(() => {
    const superAdminRole = roles.find((r) => r.name === 'super_admin');
    if (!superAdminRole) return 0;
    return users.filter(
      (u) => u.is_active && u.role_id === ((superAdminRole as any).id || (superAdminRole as any).ID)
    ).length;
  }, [roles, users]);

  const usersCountByRole = useMemo(() => {
    const map = new Map<string, number>();
    users.forEach((u) => {
      map.set(u.role_id, (map.get(u.role_id) || 0) + 1);
    });
    return map;
  }, [users]);

  const filteredUsers = useMemo(() => {
    if (!searchQuery.trim()) return users;
    const q = searchQuery.toLowerCase().trim();
    return users.filter((u) => {
      const roleName = rolesById.get(u.role_id)?.name?.toLowerCase() || '';
      const formatted = formatRoleName(roleName).toLowerCase();
      return (
        u.username.toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q) ||
        roleName.includes(q) ||
        formatted.includes(q)
      );
    });
  }, [users, searchQuery, rolesById]);

  const filteredRoles = useMemo(() => {
    if (!roleSearchQuery.trim()) return roles;
    const q = roleSearchQuery.toLowerCase().trim();
    return roles.filter((r) => {
      const formatted = formatRoleName(r.name).toLowerCase();
      return (
        r.name.toLowerCase().includes(q) ||
        formatted.includes(q) ||
        (r.description && r.description.toLowerCase().includes(q))
      );
    });
  }, [roles, roleSearchQuery]);

  const permissionsByCategory = useMemo(() => {
    const map = new Map<string, PermissionRecord[]>();
    permissions.forEach((perm) => {
      const category = perm.slug.includes(':') ? perm.slug.split(':')[0] : 'general';
      const list = map.get(category) || [];
      list.push(perm);
      map.set(category, list);
    });
    return map;
  }, [permissions]);

  const filteredPermissionsByCategory = useMemo(() => {
    const q = roleFormPermSearch.toLowerCase().trim();
    const map = new Map<string, PermissionRecord[]>();

    permissionsByCategory.forEach((perms, category) => {
      const catFormatted = formatCategoryName(category).toLowerCase();
      const matched = perms.filter((p) => {
        if (!q) return true;
        return (
          p.slug.toLowerCase().includes(q) ||
          (p.description && p.description.toLowerCase().includes(q)) ||
          catFormatted.includes(q)
        );
      });
      if (matched.length > 0) {
        map.set(category, matched);
      }
    });

    return map;
  }, [permissionsByCategory, roleFormPermSearch]);

  const isEditingSelf = Boolean(
    selectedUser && currentUser && selectedUser.id === currentUser.id
  );

  const isSelectedUserLastSuperAdmin = Boolean(
    selectedUser &&
      selectedUser.is_active &&
      rolesById.get(selectedUser.role_id)?.name === 'super_admin' &&
      activeSuperAdminCount <= 1
  );

  const handleOpenAddUser = () => {
    setUserFormUsername('');
    setUserFormEmail('');
    setUserFormRoleId(roles[0]?.id || '');
    setUserFormPassword('');
    setUserFormIsActive(true);
    setUserFormError(null);
    setIsAddUserOpen(true);
  };

  const handleOpenEditUser = (user: UserRecord) => {
    setSelectedUser(user);
    setUserFormUsername(user.username);
    setUserFormEmail(user.email);
    setUserFormRoleId(user.role_id);
    setUserFormPassword('');
    setUserFormIsActive(user.is_active);
    setUserFormError(null);
    setIsEditUserOpen(true);
  };

  const handleOpenDeleteUser = (user: UserRecord) => {
    setSelectedUser(user);
    setIsDeleteUserOpen(true);
  };

  const handleSaveAddUser = async () => {
    if (!userFormUsername.trim() || !userFormEmail.trim() || !userFormRoleId) {
      setUserFormError('Username, email, and role are required.');
      return;
    }
    if (!userFormPassword || userFormPassword.length < 8) {
      setUserFormError('Password must be at least 8 characters.');
      return;
    }
    setUserFormSubmitting(true);
    setUserFormError(null);
    try {
      const payload: UserPayload = {
        username: userFormUsername.trim(),
        email: userFormEmail.trim(),
        role_id: userFormRoleId,
        password: userFormPassword,
      };
      await apiService.createUser(payload);
      setIsAddUserOpen(false);
      setSuccessNotification(`User "${payload.username}" created successfully.`);
      loadData();
    } catch (err: any) {
      setUserFormError(err?.message || 'Failed to create user.');
    } finally {
      setUserFormSubmitting(false);
    }
  };

  const handleSaveEditUser = async () => {
    if (!selectedUser) return;
    if (!userFormUsername.trim() || !userFormEmail.trim() || !userFormRoleId) {
      setUserFormError('Username, email, and role are required.');
      return;
    }
    if (userFormPassword && userFormPassword.length < 8) {
      setUserFormError('Password must be at least 8 characters.');
      return;
    }
    setUserFormSubmitting(true);
    setUserFormError(null);
    try {
      const payload: UserPayload = {
        id: selectedUser.id,
        username: userFormUsername.trim(),
        email: userFormEmail.trim(),
        role_id: userFormRoleId,
        is_active: userFormIsActive,
      };
      if (userFormPassword) {
        payload.password = userFormPassword;
      }
      await apiService.updateUser(payload);
      setIsEditUserOpen(false);
      setSuccessNotification(`User "${payload.username}" updated successfully.`);
      loadData();
    } catch (err: any) {
      setUserFormError(err?.message || 'Failed to update user.');
    } finally {
      setUserFormSubmitting(false);
    }
  };

  const handleConfirmDeleteUser = async () => {
    if (!selectedUser) return;
    setUserFormSubmitting(true);
    try {
      await apiService.deleteUser(selectedUser.id);
      setIsDeleteUserOpen(false);
      setSuccessNotification(`User "${selectedUser.username}" deactivated.`);
      loadData();
    } catch (err: any) {
      setErrorNotification(err?.message || 'Failed to deactivate user.');
    } finally {
      setUserFormSubmitting(false);
    }
  };

  const handleOpenAddRole = () => {
    setRoleFormName('');
    setRoleFormDesc('');
    setRoleFormPermissions([]);
    setRoleFormPermSearch('');
    setRoleFormError(null);
    setIsAddRoleOpen(true);
  };

  const handleOpenEditRole = (role: RoleRecord) => {
    setSelectedRole(role);
    setRoleFormName(role.name);
    setRoleFormDesc(role.description || '');
    const currentSlugs = role.permissions?.map((p) => p.slug) || [];
    setRoleFormPermissions(currentSlugs);
    setRoleFormPermSearch('');
    setRoleFormError(null);
    setIsEditRoleOpen(true);
  };

  const handleOpenDeleteRole = (role: RoleRecord) => {
    setSelectedRole(role);
    setIsDeleteRoleOpen(true);
  };

  const handleSaveAddRole = async () => {
    const trimmedName = roleFormName.trim().toLowerCase();
    if (!trimmedName) {
      setRoleFormError('Role name is required.');
      return;
    }
    if (!/^[a-z][a-z0-9_-]{1,63}$/.test(trimmedName)) {
      setRoleFormError(
        'Role name must start with a letter and contain only lowercase letters, numbers, underscores, or hyphens (2-64 characters).'
      );
      return;
    }
    if (roleFormPermissions.length === 0) {
      setRoleFormError('Please select at least one permission.');
      return;
    }
    setRoleFormSubmitting(true);
    setRoleFormError(null);
    try {
      const payload: RolePayload = {
        name: trimmedName,
        description: roleFormDesc.trim(),
        permissions: roleFormPermissions,
      };
      await apiService.createRole(payload);
      setIsAddRoleOpen(false);
      setSuccessNotification(`Role "${trimmedName}" created successfully.`);
      loadData();
    } catch (err: any) {
      setRoleFormError(err?.message || 'Failed to create role.');
    } finally {
      setUserFormSubmitting(false);
    }
  };

  const handleSaveEditRole = async () => {
    if (!selectedRole) return;
    const trimmedName = roleFormName.trim().toLowerCase();
    if (!trimmedName) {
      setRoleFormError('Role name is required.');
      return;
    }
    if (!/^[a-z][a-z0-9_-]{1,63}$/.test(trimmedName)) {
      setRoleFormError(
        'Role name must start with a letter and contain only lowercase letters, numbers, underscores, or hyphens.'
      );
      return;
    }
    if (roleFormPermissions.length === 0) {
      setRoleFormError('Please select at least one permission.');
      return;
    }
    setRoleFormSubmitting(true);
    setRoleFormError(null);
    try {
      const payload: RolePayload = {
        id: selectedRole.id,
        name: trimmedName,
        description: roleFormDesc.trim(),
        permissions: roleFormPermissions,
      };
      await apiService.updateRole(payload);
      setIsEditRoleOpen(false);
      setSuccessNotification(`Role "${trimmedName}" updated successfully.`);
      loadData();
    } catch (err: any) {
      setRoleFormError(err?.message || 'Failed to update role.');
    } finally {
      setUserFormSubmitting(false);
    }
  };

  const handleConfirmDeleteRole = async () => {
    if (!selectedRole) return;
    setRoleFormSubmitting(true);
    try {
      await apiService.deleteRole(selectedRole.id);
      setIsDeleteRoleOpen(false);
      setSuccessNotification(`Role "${selectedRole.name}" deleted.`);
      loadData();
    } catch (err: any) {
      setErrorNotification(err?.message || 'Failed to delete role.');
    } finally {
      setUserFormSubmitting(false);
    }
  };

  const togglePermission = (slug: string) => {
    setRoleFormPermissions((prev) =>
      prev.includes(slug) ? prev.filter((s) => s !== slug) : [...prev, slug]
    );
  };

  const toggleCategoryPermissions = (perms: PermissionRecord[]) => {
    const slugs = perms.map((p) => p.slug);
    const allSelected = slugs.every((s) => roleFormPermissions.includes(s));
    if (allSelected) {
      setRoleFormPermissions((prev) => prev.filter((s) => !slugs.includes(s)));
    } else {
      setRoleFormPermissions((prev) => Array.from(new Set([...prev, ...slugs])));
    }
  };

  const handleSelectAllPermissions = () => {
    setRoleFormPermissions(permissions.map((p) => p.slug));
  };

  const handleClearAllPermissions = () => {
    setRoleFormPermissions([]);
  };

  return (
    <div className="users-page">
      <PageHeader
        kicker="System"
        title="Users"
        subtitle="Manage users, roles, and permissions."
        icon={UserMultiple}
        action={
          <div className="users-page-header-actions">
            <Button
              kind="ghost"
              renderIcon={Renew}
              hasIconOnly
              iconDescription="Refresh"
              onClick={loadData}
              disabled={loading}
            />
            {activeTab === 0 ? (
              <Button kind="primary" renderIcon={Add} onClick={handleOpenAddUser}>
                Add user
              </Button>
            ) : (
              <Button kind="primary" renderIcon={Add} onClick={handleOpenAddRole}>
                Create role
              </Button>
            )}
          </div>
        }
      />

      {errorNotification && (
        <InlineNotification
          kind="error"
          lowContrast
          title="Error"
          subtitle={errorNotification}
          onCloseButtonClick={() => setErrorNotification(null)}
          className="users-notification"
        />
      )}

      {successNotification && (
        <InlineNotification
          kind="success"
          lowContrast
          title="Success"
          subtitle={successNotification}
          onCloseButtonClick={() => setSuccessNotification(null)}
          className="users-notification"
        />
      )}

      <Tabs
        selectedIndex={activeTab}
        onChange={({ selectedIndex }) => setActiveTab(selectedIndex)}
      >
        <TabList aria-label="Users and roles" className="users-tabs">
          <Tab>Users ({totalUsers})</Tab>
          <Tab>Roles ({roles.length})</Tab>
        </TabList>

        <TabPanels>
          <TabPanel>
            {loading && users.length === 0 ? (
              <DataTableSkeleton columnCount={6} rowCount={6} />
            ) : (
              <TableContainer
                title="Users"
                description="User accounts with console access."
              >
                <TableToolbar>
                  <TableToolbarContent>
                    <TableToolbarSearch
                      persistent
                      placeholder="Search users by name, email, or role..."
                      value={searchQuery}
                      onChange={(e: any) =>
                        setSearchQuery(e?.target?.value ?? (typeof e === 'string' ? e : ''))
                      }
                    />
                    <Button
                      kind="primary"
                      size="md"
                      renderIcon={Add}
                      onClick={handleOpenAddUser}
                    >
                      Add user
                    </Button>
                  </TableToolbarContent>
                </TableToolbar>

                <Table size="md" useZebraStyles={false} aria-label="Users table">
                  <TableHead>
                    <TableRow>
                      <TableHeader>User</TableHeader>
                      <TableHeader>Email</TableHeader>
                      <TableHeader>Role</TableHeader>
                      <TableHeader>Status</TableHeader>
                      <TableHeader>Last login</TableHeader>
                      <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {filteredUsers.length === 0 ? (
                      <TableRow>
                        <TableCell
                          colSpan={6}
                          style={{
                            textAlign: 'center',
                            padding: '48px 16px',
                            color: 'var(--cds-text-secondary)',
                          }}
                        >
                          <UserAvatar
                            size={32}
                            style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }}
                          />
                          <div
                            style={{
                              fontWeight: 600,
                              fontSize: '14px',
                              marginBottom: '4px',
                              color: 'var(--cds-text-primary)',
                            }}
                          >
                            No users found
                          </div>
                          <div
                            style={{
                              color: 'var(--cds-text-secondary)',
                              fontSize: '13px',
                              marginBottom: '16px',
                            }}
                          >
                            {searchQuery
                              ? 'No user accounts match your search filter.'
                              : 'No user accounts have been created yet.'}
                          </div>
                          {!searchQuery && (
                            <Button
                              kind="tertiary"
                              size="sm"
                              renderIcon={Add}
                              onClick={handleOpenAddUser}
                            >
                              Add user
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ) : (
                      filteredUsers.map((user) => {
                        const role = rolesById.get(user.role_id);
                        const isSelf = currentUser?.id === user.id;

                        return (
                          <TableRow key={user.id}>
                            <TableCell>
                              <div className="users-table-user-cell">
                                <div className="users-table-avatar">
                                  <UserAvatar size={14} />
                                </div>
                                <span className="users-table-username">{user.username}</span>
                                {isSelf && <span className="users-you-pill">(you)</span>}
                              </div>
                            </TableCell>

                            <TableCell style={{ color: 'var(--cds-text-secondary)' }}>
                              {user.email}
                            </TableCell>

                            <TableCell>
                              <Tag type={role?.is_builtin ? 'blue' : 'purple'} size="sm">
                                {formatRoleName(role?.name || user.role_id)}
                              </Tag>
                            </TableCell>

                            <TableCell>
                              <Tag type={user.is_active ? 'green' : 'gray'} size="sm">
                                {user.is_active ? 'Active' : 'Inactive'}
                              </Tag>
                            </TableCell>

                            <TableCell style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                              {formatLastLogin(user.last_login_at)}
                            </TableCell>

                            <TableCell style={{ textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', gap: '4px' }}>
                                <Button
                                  kind="ghost"
                                  size="sm"
                                  renderIcon={Edit}
                                  hasIconOnly
                                  iconDescription="Edit user"
                                  onClick={() => handleOpenEditUser(user)}
                                />
                                <Button
                                  kind="ghost"
                                  size="sm"
                                  renderIcon={TrashCan}
                                  hasIconOnly
                                  iconDescription={
                                    isSelf ? 'Cannot deactivate your own account' : 'Deactivate user'
                                  }
                                  onClick={() => handleOpenDeleteUser(user)}
                                  disabled={isSelf}
                                />
                              </div>
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>

                <Pagination
                  totalItems={totalUsers}
                  pageSize={limit}
                  pageSizes={[10, 20, 50]}
                  page={page}
                  onChange={({ page: newPage, pageSize: newLimit }) => {
                    if (newPage !== page) setPage(newPage);
                    if (newLimit !== limit) setLimit(newLimit);
                  }}
                />
              </TableContainer>
            )}
          </TabPanel>

          <TabPanel>
            <TableContainer
              title="Roles"
              description="Permissions assigned to users."
            >
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    placeholder="Search roles by name or description..."
                    value={roleSearchQuery}
                    onChange={(e: any) =>
                      setRoleSearchQuery(e?.target?.value ?? (typeof e === 'string' ? e : ''))
                    }
                  />
                  <Button kind="primary" size="md" renderIcon={Add} onClick={handleOpenAddRole}>
                    Create role
                  </Button>
                </TableToolbarContent>
              </TableToolbar>

              <Table size="md" useZebraStyles={false} aria-label="Roles table">
                <TableHead>
                  <TableRow>
                    <TableHeader>Role</TableHeader>
                    <TableHeader>Description</TableHeader>
                    <TableHeader>Type</TableHeader>
                    <TableHeader>Users</TableHeader>
                    <TableHeader>Permissions</TableHeader>
                    <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredRoles.length === 0 ? (
                    <TableRow>
                      <TableCell
                        colSpan={6}
                        style={{
                          textAlign: 'center',
                          padding: '48px 16px',
                          color: 'var(--cds-text-secondary)',
                        }}
                      >
                        <Security
                          size={32}
                          style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }}
                        />
                        <div
                          style={{
                            fontWeight: 600,
                            fontSize: '14px',
                            marginBottom: '4px',
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          No roles found
                        </div>
                        <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                          No roles match your search filter.
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredRoles.map((role) => {
                      const rolePerms = role.permissions || [];
                      const userCount = usersCountByRole.get(role.id) || 0;
                      const isSuperAdmin = role.name === 'super_admin';

                      return (
                        <TableRow key={role.id}>
                          <TableCell>
                            <div style={{ display: 'flex', flexDirection: 'column' }}>
                              <span style={{ fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                                {formatRoleName(role.name)}
                              </span>
                              <span
                                style={{
                                  fontSize: '11px',
                                  color: 'var(--cds-text-secondary)',
                                  fontFamily: 'var(--cds-font-family-mono, monospace)',
                                }}
                              >
                                {role.name}
                              </span>
                            </div>
                          </TableCell>

                          <TableCell style={{ color: 'var(--cds-text-secondary)', maxWidth: '340px' }}>
                            {role.description || '—'}
                          </TableCell>

                          <TableCell>
                            <Tag type={role.is_builtin ? 'blue' : 'purple'} size="sm">
                              {role.is_builtin ? 'Built-in' : 'Custom'}
                            </Tag>
                          </TableCell>

                          <TableCell>
                            <Tag type="cool-gray" size="sm">
                              {userCount} {userCount === 1 ? 'user' : 'users'}
                            </Tag>
                          </TableCell>

                          <TableCell>
                            {isSuperAdmin ? (
                              <span style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                                Full access
                              </span>
                            ) : (
                              <Button
                                kind="ghost"
                                size="sm"
                                onClick={() => setViewRolePermissions(role)}
                                style={{ padding: '0 4px', color: 'var(--cds-link-primary)' }}
                              >
                                {rolePerms.length} permissions
                              </Button>
                            )}
                          </TableCell>

                          <TableCell style={{ textAlign: 'right' }}>
                            {!role.is_builtin ? (
                              <div style={{ display: 'inline-flex', gap: '4px' }}>
                                <Button
                                  kind="ghost"
                                  size="sm"
                                  renderIcon={Edit}
                                  hasIconOnly
                                  iconDescription="Edit role"
                                  onClick={() => handleOpenEditRole(role)}
                                />
                                <Button
                                  kind="ghost"
                                  size="sm"
                                  renderIcon={TrashCan}
                                  hasIconOnly
                                  iconDescription="Delete role"
                                  onClick={() => handleOpenDeleteRole(role)}
                                />
                              </div>
                            ) : (
                              <span style={{ color: 'var(--cds-text-placeholder)', fontSize: '13px' }}>
                                —
                              </span>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </TabPanel>
        </TabPanels>
      </Tabs>

      <Modal
        open={isAddUserOpen}
        modalHeading="Add user"
        primaryButtonText={userFormSubmitting ? 'Creating...' : 'Add user'}
        secondaryButtonText="Cancel"
        primaryButtonDisabled={userFormSubmitting}
        onRequestClose={() => setIsAddUserOpen(false)}
        onRequestSubmit={handleSaveAddUser}
      >
        <Stack gap={6} style={{ paddingTop: '1rem' }}>
          {userFormError && (
            <InlineNotification
              kind="error"
              lowContrast
              title="Error"
              subtitle={userFormError}
              onCloseButtonClick={() => setUserFormError(null)}
            />
          )}

          <TextInput
            id="addUser-username"
            labelText="Username"
            placeholder="e.g. alex"
            value={userFormUsername}
            onChange={(e) => setUserFormUsername(e.target.value)}
            helperText="1 to 64 alphanumeric characters."
            required
            autoFocus
          />

          <TextInput
            id="addUser-email"
            labelText="Email address"
            type="email"
            placeholder="e.g. user@example.com"
            value={userFormEmail}
            onChange={(e) => setUserFormEmail(e.target.value)}
            required
          />

          <Select
            id="addUser-role"
            labelText="Role"
            value={userFormRoleId}
            onChange={(e) => setUserFormRoleId(e.target.value)}
          >
            {roles.map((role) => (
              <SelectItem
                key={role.id}
                value={role.id}
                text={`${formatRoleName(role.name)} (${role.is_builtin ? 'Built-in' : 'Custom'})`}
              />
            ))}
          </Select>

          <PasswordInput
            id="addUser-password"
            labelText="Password"
            placeholder="••••••••"
            value={userFormPassword}
            onChange={(e) => setUserFormPassword(e.target.value)}
            helperText="Minimum 8 characters."
            required
          />
        </Stack>
      </Modal>

      <Modal
        open={isEditUserOpen}
        modalHeading={`Edit user: ${selectedUser?.username || ''}`}
        primaryButtonText={userFormSubmitting ? 'Saving...' : 'Save changes'}
        secondaryButtonText="Cancel"
        primaryButtonDisabled={userFormSubmitting}
        onRequestClose={() => setIsEditUserOpen(false)}
        onRequestSubmit={handleSaveEditUser}
      >
        <Stack gap={6} style={{ paddingTop: '1rem' }}>
          {userFormError && (
            <InlineNotification
              kind="error"
              lowContrast
              title="Error"
              subtitle={userFormError}
              onCloseButtonClick={() => setUserFormError(null)}
            />
          )}

          {isEditingSelf && (
            <InlineNotification
              kind="info"
              lowContrast
              title="Current account"
              subtitle="You cannot change your own role or deactivate your own account."
            />
          )}

          <TextInput
            id="editUser-username"
            labelText="Username"
            value={userFormUsername}
            onChange={(e) => setUserFormUsername(e.target.value)}
            required
          />

          <TextInput
            id="editUser-email"
            labelText="Email address"
            type="email"
            value={userFormEmail}
            onChange={(e) => setUserFormEmail(e.target.value)}
            required
          />

          <Select
            id="editUser-role"
            labelText="Role"
            value={userFormRoleId}
            onChange={(e) => setUserFormRoleId(e.target.value)}
            disabled={isEditingSelf}
          >
            {roles.map((role) => (
              <SelectItem
                key={role.id}
                value={role.id}
                text={`${formatRoleName(role.name)} (${role.is_builtin ? 'Built-in' : 'Custom'})`}
              />
            ))}
          </Select>

          <PasswordInput
            id="editUser-password"
            labelText="New password"
            placeholder="Leave blank to keep current password"
            value={userFormPassword}
            onChange={(e) => setUserFormPassword(e.target.value)}
            helperText="Leave empty to retain current password. If updating, must be at least 8 characters."
          />

          <Toggle
            id="editUser-active"
            labelText="Status"
            labelA="Inactive"
            labelB="Active"
            toggled={userFormIsActive}
            onToggle={(checked) => setUserFormIsActive(checked)}
            disabled={isEditingSelf}
          />
        </Stack>
      </Modal>

      <Modal
        open={isDeleteUserOpen}
        danger
        modalHeading="Deactivate user"
        primaryButtonText={userFormSubmitting ? 'Deactivating...' : 'Deactivate user'}
        secondaryButtonText="Cancel"
        primaryButtonDisabled={userFormSubmitting || isEditingSelf || isSelectedUserLastSuperAdmin}
        onRequestClose={() => setIsDeleteUserOpen(false)}
        onRequestSubmit={handleConfirmDeleteUser}
      >
        <Stack gap={4} style={{ paddingTop: '1rem' }}>
          {isEditingSelf ? (
            <InlineNotification
              kind="error"
              lowContrast
              title="Action not allowed"
              subtitle="You cannot deactivate your own account."
            />
          ) : isSelectedUserLastSuperAdmin ? (
            <InlineNotification
              kind="error"
              lowContrast
              title="Action not allowed"
              subtitle="This is the only active super administrator account. At least one active super administrator is required to maintain access."
            />
          ) : (
            <>
              <p>
                Are you sure you want to deactivate <strong>{selectedUser?.username}</strong>?
              </p>
              <p style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                Deactivating will immediately sign out this user and prevent them from logging in.
              </p>
            </>
          )}
        </Stack>
      </Modal>

      <Modal
        open={isAddRoleOpen}
        modalHeading="Create role"
        primaryButtonText={roleFormSubmitting ? 'Creating...' : 'Create role'}
        secondaryButtonText="Cancel"
        primaryButtonDisabled={roleFormSubmitting}
        onRequestClose={() => setIsAddRoleOpen(false)}
        onRequestSubmit={handleSaveAddRole}
      >
        <Stack gap={6} style={{ paddingTop: '1rem' }}>
          {roleFormError && (
            <InlineNotification
              kind="error"
              lowContrast
              title="Error"
              subtitle={roleFormError}
              onCloseButtonClick={() => setRoleFormError(null)}
            />
          )}

          <TextInput
            id="addRole-name"
            labelText="Role name"
            placeholder="e.g. auditor"
            value={roleFormName}
            onChange={(e) => setRoleFormName(e.target.value)}
            helperText="Lowercase letters, numbers, underscores, or hyphens."
            required
            autoFocus
          />

          <TextInput
            id="addRole-desc"
            labelText="Description"
            placeholder="Brief description"
            value={roleFormDesc}
            onChange={(e) => setRoleFormDesc(e.target.value)}
          />

          <div className="users-perm-picker">
            <div className="users-perm-picker-toolbar">
              <label className="cds--label" style={{ margin: 0 }}>
                Permissions ({roleFormPermissions.length} of {permissions.length} selected)
              </label>
              <div style={{ display: 'flex', gap: '8px' }}>
                <Button
                  kind="ghost"
                  size="sm"
                  onClick={handleSelectAllPermissions}
                  style={{ height: '24px', padding: '0 8px', fontSize: '12px' }}
                >
                  Select all
                </Button>
                <Button
                  kind="ghost"
                  size="sm"
                  onClick={handleClearAllPermissions}
                  style={{ height: '24px', padding: '0 8px', fontSize: '12px' }}
                >
                  Clear all
                </Button>
              </div>
            </div>

            <Search
              id="addRole-search-perms"
              size="sm"
              labelText="Search permissions"
              placeholder="Search permissions..."
              value={roleFormPermSearch}
              onChange={(e) => setRoleFormPermSearch(e.target.value)}
              onClear={() => setRoleFormPermSearch('')}
            />

            <div className="users-perm-picker-scroll">
              {Array.from(filteredPermissionsByCategory.entries()).map(([cat, perms]) => {
                const categorySlugs = perms.map((p) => p.slug);
                const allCatSelected = categorySlugs.every((s) => roleFormPermissions.includes(s));
                const someCatSelected =
                  categorySlugs.some((s) => roleFormPermissions.includes(s)) && !allCatSelected;

                return (
                  <div key={cat} className="users-perm-group">
                    <div className="users-perm-group-header">
                      <span className="users-perm-group-title">
                        {formatCategoryName(cat)} ({perms.filter((p) => roleFormPermissions.includes(p.slug)).length}/{perms.length})
                      </span>
                      <Checkbox
                        id={`addRole-cat-toggle-${cat}`}
                        labelText="Select category"
                        hideLabel
                        checked={allCatSelected}
                        indeterminate={someCatSelected}
                        onChange={() => toggleCategoryPermissions(perms)}
                      />
                    </div>
                    {perms.map((p) => (
                      <div key={p.slug} className="users-perm-item">
                        <Checkbox
                          id={`addRole-perm-${p.slug}`}
                          labelText={p.slug}
                          checked={roleFormPermissions.includes(p.slug)}
                          onChange={() => togglePermission(p.slug)}
                        />
                        {p.description && (
                          <div className="users-perm-desc">{p.description}</div>
                        )}
                      </div>
                    ))}
                  </div>
                );
              })}
              {filteredPermissionsByCategory.size === 0 && (
                <div style={{ textAlign: 'center', padding: '24px 8px', color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                  No permissions match "{roleFormPermSearch}"
                </div>
              )}
            </div>
          </div>
        </Stack>
      </Modal>

      <Modal
        open={isEditRoleOpen}
        modalHeading={`Edit role: ${formatRoleName(selectedRole?.name)}`}
        primaryButtonText={roleFormSubmitting ? 'Saving...' : 'Save changes'}
        secondaryButtonText="Cancel"
        primaryButtonDisabled={roleFormSubmitting}
        onRequestClose={() => setIsEditRoleOpen(false)}
        onRequestSubmit={handleSaveEditRole}
      >
        <Stack gap={6} style={{ paddingTop: '1rem' }}>
          {roleFormError && (
            <InlineNotification
              kind="error"
              lowContrast
              title="Error"
              subtitle={roleFormError}
              onCloseButtonClick={() => setRoleFormError(null)}
            />
          )}

          <TextInput
            id="editRole-name"
            labelText="Role name"
            value={roleFormName}
            onChange={(e) => setRoleFormName(e.target.value)}
            required
          />

          <TextInput
            id="editRole-desc"
            labelText="Description"
            value={roleFormDesc}
            onChange={(e) => setRoleFormDesc(e.target.value)}
          />

          <div className="users-perm-picker">
            <div className="users-perm-picker-toolbar">
              <label className="cds--label" style={{ margin: 0 }}>
                Permissions ({roleFormPermissions.length} of {permissions.length} selected)
              </label>
              <div style={{ display: 'flex', gap: '8px' }}>
                <Button
                  kind="ghost"
                  size="sm"
                  onClick={handleSelectAllPermissions}
                  style={{ height: '24px', padding: '0 8px', fontSize: '12px' }}
                >
                  Select all
                </Button>
                <Button
                  kind="ghost"
                  size="sm"
                  onClick={handleClearAllPermissions}
                  style={{ height: '24px', padding: '0 8px', fontSize: '12px' }}
                >
                  Clear all
                </Button>
              </div>
            </div>

            <Search
              id="editRole-search-perms"
              size="sm"
              labelText="Search permissions"
              placeholder="Search permissions..."
              value={roleFormPermSearch}
              onChange={(e) => setRoleFormPermSearch(e.target.value)}
              onClear={() => setRoleFormPermSearch('')}
            />

            <div className="users-perm-picker-scroll">
              {Array.from(filteredPermissionsByCategory.entries()).map(([cat, perms]) => {
                const categorySlugs = perms.map((p) => p.slug);
                const allCatSelected = categorySlugs.every((s) => roleFormPermissions.includes(s));
                const someCatSelected =
                  categorySlugs.some((s) => roleFormPermissions.includes(s)) && !allCatSelected;

                return (
                  <div key={cat} className="users-perm-group">
                    <div className="users-perm-group-header">
                      <span className="users-perm-group-title">
                        {formatCategoryName(cat)} ({perms.filter((p) => roleFormPermissions.includes(p.slug)).length}/{perms.length})
                      </span>
                      <Checkbox
                        id={`editRole-cat-toggle-${cat}`}
                        labelText="Select category"
                        hideLabel
                        checked={allCatSelected}
                        indeterminate={someCatSelected}
                        onChange={() => toggleCategoryPermissions(perms)}
                      />
                    </div>
                    {perms.map((p) => (
                      <div key={p.slug} className="users-perm-item">
                        <Checkbox
                          id={`editRole-perm-${p.slug}`}
                          labelText={p.slug}
                          checked={roleFormPermissions.includes(p.slug)}
                          onChange={() => togglePermission(p.slug)}
                        />
                        {p.description && (
                          <div className="users-perm-desc">{p.description}</div>
                        )}
                      </div>
                    ))}
                  </div>
                );
              })}
              {filteredPermissionsByCategory.size === 0 && (
                <div style={{ textAlign: 'center', padding: '24px 8px', color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                  No permissions match "{roleFormPermSearch}"
                </div>
              )}
            </div>
          </div>
        </Stack>
      </Modal>

      <Modal
        open={isDeleteRoleOpen}
        danger
        modalHeading={`Delete role: ${formatRoleName(selectedRole?.name)}`}
        primaryButtonText={roleFormSubmitting ? 'Deleting...' : 'Delete role'}
        secondaryButtonText="Cancel"
        primaryButtonDisabled={
          roleFormSubmitting ||
          Boolean(selectedRole && (usersCountByRole.get(selectedRole.id) || 0) > 0)
        }
        onRequestClose={() => setIsDeleteRoleOpen(false)}
        onRequestSubmit={handleConfirmDeleteRole}
      >
        <Stack gap={4} style={{ paddingTop: '1rem' }}>
          {selectedRole && (usersCountByRole.get(selectedRole.id) || 0) > 0 ? (
            <InlineNotification
              kind="error"
              lowContrast
              title="Cannot delete role"
              subtitle={`This role is assigned to ${usersCountByRole.get(selectedRole.id)} user(s). Reassign them before deleting.`}
            />
          ) : (
            <>
              <p>
                Are you sure you want to delete role <strong>{formatRoleName(selectedRole?.name)}</strong>?
              </p>
              <p style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                This action cannot be undone.
              </p>
            </>
          )}
        </Stack>
      </Modal>

      <Modal
        open={Boolean(viewRolePermissions)}
        modalHeading={`Permissions: ${formatRoleName(viewRolePermissions?.name)}`}
        passiveModal
        onRequestClose={() => setViewRolePermissions(null)}
      >
        <div style={{ paddingTop: '1rem' }}>
          <p style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
            {viewRolePermissions?.description || 'No description provided.'}
          </p>

          <div style={{ maxHeight: '380px', overflowY: 'auto' }}>
            {Array.from(permissionsByCategory.entries()).map(([cat, catPerms]) => {
              const assignedPerms = catPerms.filter((p) =>
                viewRolePermissions?.permissions?.some((rp) => rp.slug === p.slug)
              );
              if (assignedPerms.length === 0) return null;

              return (
                <div key={cat} style={{ marginBottom: '16px' }}>
                  <div
                    style={{
                      fontSize: '12px',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      color: 'var(--cds-text-secondary)',
                      letterSpacing: '0.05em',
                      borderBottom: '1px solid var(--cds-border-subtle)',
                      paddingBottom: '4px',
                      marginBottom: '8px',
                    }}
                  >
                    {formatCategoryName(cat)} ({assignedPerms.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {assignedPerms.map((p) => (
                      <div
                        key={p.slug}
                        style={{
                          padding: '6px 10px',
                          background: 'var(--cds-layer-01)',
                          border: '1px solid var(--cds-border-subtle)',
                        }}
                      >
                        <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                          {p.slug}
                        </div>
                        {p.description && (
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                            {p.description}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default UsersPage;
