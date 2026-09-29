/**
 * User Management implementation
 * Source of truth: web/admin/src/users.ts
 * Runtime output: web/admin/dist/js/users.js
 */
import { api } from './api.js';
import * as AdminDOM from './core/dom.js';
import * as AdminEvents from './core/events.js';
import { SectionUI } from './sections/ui-components.js';
import { notify } from './core/notify.js';
const DEFAULT_PRECONFIGURED_ROLES = [
    { id: 'super_admin', name: 'super_admin', description: 'Full administrative access across all system functions' },
    { id: 'admin', name: 'admin', description: 'Administrative access across security policies, traffic routing, and certificates' },
    { id: 'auditor', name: 'auditor', description: 'Compliance and security audit review with access to audit logs, events, and telemetry' },
    { id: 'viewer', name: 'viewer', description: 'Read-only observability access to dashboards, logs, and metrics' }
];
const usersState = {
    usersData: [],
    rolesData: [],
    permissionCatalog: [],
    page: 1,
    limit: 10,
    total: 0,
    totalPages: 1,
    editingUser: null,
    userModalKeyCleanup: null,
    eventsBound: false
};
export async function loadUsersPage(page = usersState.page) {
    bindUsersEvents();
    const container = AdminDOM.getById('users-container');
    if (!container)
        return;
    container.innerHTML = SectionUI.renderLoading('Loading users...');
    try {
        const requestedPage = Math.max(1, page);
        const [usersRes, rolesRes, permissionsRes] = await Promise.all([
            fetch(`/api/users?page=${requestedPage}&limit=${usersState.limit}`),
            fetch('/api/roles'),
            fetch('/api/permissions')
        ]);
        if (!usersRes.ok || !rolesRes.ok || !permissionsRes.ok) {
            throw new Error('Failed to load users or roles');
        }
        const usersPayload = (await usersRes.json());
        usersState.usersData = usersPayload.data || [];
        usersState.page = usersPayload.meta?.page || requestedPage;
        usersState.total = usersPayload.meta?.total || usersState.usersData.length;
        usersState.totalPages = Math.max(1, usersPayload.meta?.total_pages || 1);
        const rolesPayload = (await rolesRes.json());
        usersState.rolesData = (rolesPayload.data && rolesPayload.data.length > 0)
            ? rolesPayload.data
            : DEFAULT_PRECONFIGURED_ROLES;
        const permissionsPayload = (await permissionsRes.json());
        usersState.permissionCatalog = permissionsPayload.data || [];
        renderUsersTable(container);
    }
    catch (error) {
        console.error(error);
        container.innerHTML = '<div class="text-danger p-20 text-center">Failed to load users or roles</div>';
    }
}
function renderUsersTable(container) {
    const canWrite = canManageUsers();
    const table = SectionUI.renderEnterpriseTable({
        columns: ['User', 'Role', 'Status', 'Last sign-in', 'Actions'],
        rows: usersState.usersData.map(user => renderUserRow(user)),
        className: 'users-account-table',
        emptyTitle: 'No user accounts',
        emptyMessage: 'Add an account to grant administrator access.'
    });
    const content = `
    <div class="users-operator-stack">
      ${SectionUI.renderOperatorSection('User accounts', `
        <div class="users-account-surface">${table}</div>
        ${renderUsersPagination()}
      `, {
        subtitle: `${usersState.total} account${usersState.total === 1 ? '' : 's'} total. ${canWrite ? 'Manage access from this page.' : 'You can view accounts but cannot edit them.'}`,
        className: 'users-catalog-section'
    })}
    </div>
  `;
    const page = SectionUI.renderOperatorFrame({
        title: 'Users',
        kicker: 'System',
        subtitle: 'Manage administrator accounts, authentication credentials, and preconfigured role bindings.',
        actions: canWrite ? `<button type="button" class="btn btn-primary" data-action="users-open-modal"><span class="users-button-icon" aria-hidden="true">${SectionUI.icons.users}</span>Add user</button>` : '',
        content,
        className: 'users-operator-frame'
    });
    container.innerHTML = `${page}${renderUserModal()}`;
}
function renderUserRow(user) {
    const userId = escapeAttr(user.id);
    const canWrite = canManageUsers();
    const actions = canWrite ? SectionUI.renderActionMenu({
        id: `user-actions-${toDOMId(user.id)}`,
        label: 'More',
        ariaLabel: `Actions for ${user.username}`,
        items: [
            { label: 'Edit user', attrs: `data-action="users-edit" data-user-id="${userId}"` },
            { label: 'Deactivate user', attrs: `data-action="users-delete" data-user-id="${userId}"`, tone: 'danger' }
        ],
        className: 'users-row-menu'
    }) : '<span class="users-readonly-note">Read only</span>';
    const identity = canWrite
        ? `<button type="button" class="users-account-link" data-action="users-edit" data-user-id="${userId}">${escapeHtml(user.username)}</button>`
        : `<span class="users-account-name">${escapeHtml(user.username)}</span>`;
    return [
        `<div class="users-account-identity">
      <span class="users-account-icon" aria-hidden="true">${SectionUI.icons.userCheck}</span>
      <span class="users-account-copy">
        ${identity}
        <span class="users-account-email">${escapeHtml(user.email)}</span>
      </span>
    </div>`,
        SectionUI.renderStatusPill(escapeHtml(usersGetRoleName(user.role_id)), 'neutral'),
        SectionUI.renderStatusPill(user.is_active ? 'Active' : 'Inactive', user.is_active ? 'success' : 'neutral'),
        `<span class="users-last-login">${formatLastLogin(user.last_login_at)}</span>`,
        `<div class="operator-control-actions users-row-actions">${actions}</div>`
    ];
}
function renderUserModal() {
    const availableRoles = usersState.rolesData.length > 0 ? usersState.rolesData : DEFAULT_PRECONFIGURED_ROLES;
    const roleOptions = availableRoles
        .map(role => `<option value="${escapeAttr(role.id)}">${escapeHtml(formatRoleName(role.name))}</option>`)
        .join('');
    return `
    <div id="user-modal" class="modal-overlay hidden" data-action="users-modal-overlay">
      <div class="modal-content section-modal users-modal-content" role="dialog" aria-modal="true" aria-labelledby="user-modal-title" aria-describedby="user-modal-description">
        <div class="modal-header users-modal-header">
          <div>
            <h3 id="user-modal-title">Add User</h3>
            <p id="user-modal-description">Create an administrator account and assign a preconfigured access role.</p>
          </div>
          <button type="button" class="modal-close" data-action="users-close-modal" aria-label="Close user form">&times;</button>
        </div>
        <form id="user-form">
          <div class="modal-body section-modal users-modal-body">
            <input type="hidden" id="user-id">
            <div class="users-form-grid">
              <div class="settings-field users-form-field">
                <label for="user-username">Username <span aria-hidden="true">*</span></label>
                <input type="text" id="user-username" required class="settings-input" placeholder="admin_user" autocomplete="off">
              </div>
              <div class="settings-field users-form-field">
                <label for="user-email">Email <span aria-hidden="true">*</span></label>
                <input type="email" id="user-email" required class="settings-input" placeholder="admin@example.com" autocomplete="off">
              </div>
              <div class="settings-field users-form-field">
                <label for="user-role">Role <span aria-hidden="true">*</span></label>
                <select id="user-role" class="settings-input" required>
                  ${roleOptions}
                </select>
                <div id="user-role-permissions" class="users-role-permissions" aria-live="polite"></div>
              </div>
              <div class="settings-field users-form-field">
                <label for="user-password">Password</label>
                <input type="password" id="user-password" class="settings-input" placeholder="••••••••••••" autocomplete="new-password">
                <span class="settings-hint">Leave blank when editing to keep the current password.</span>
              </div>
            </div>
            <label class="users-account-state">
              <input type="checkbox" id="user-active" checked>
              <span>Account is active and allowed to sign in</span>
            </label>
          </div>
          <div class="modal-footer users-modal-footer">
            <button type="button" class="btn btn-outline" data-action="users-close-modal">Cancel</button>
            <button type="submit" class="btn btn-primary">Save user</button>
          </div>
        </form>
      </div>
    </div>
  `;
}
function formatLastLogin(value) {
    if (!value)
        return 'Never';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Unknown' : escapeHtml(date.toLocaleString());
}
function toDOMId(value) {
    return value.replace(/[^a-zA-Z0-9_-]/g, '-');
}
function canManageUsers() {
    return api.hasPermission('users:write');
}
function renderUsersPagination() {
    if (usersState.totalPages <= 1)
        return '';
    const start = usersState.total === 0 ? 0 : ((usersState.page - 1) * usersState.limit) + 1;
    const end = Math.min(usersState.total, usersState.page * usersState.limit);
    return `
    <nav class="users-pagination" aria-label="User account pages">
      <span class="users-pagination-summary">Showing ${start}–${end} of ${usersState.total}</span>
      <span class="users-pagination-actions">
        <button type="button" class="btn btn-outline btn-xs" data-action="users-page" data-page="${usersState.page - 1}" ${usersState.page <= 1 ? 'disabled' : ''}>Previous</button>
        <span class="users-pagination-page">Page ${usersState.page} of ${usersState.totalPages}</span>
        <button type="button" class="btn btn-outline btn-xs" data-action="users-page" data-page="${usersState.page + 1}" ${usersState.page >= usersState.totalPages ? 'disabled' : ''}>Next</button>
      </span>
    </nav>
  `;
}
function updateRolePermissionPreview(roleID = AdminDOM.selectValue('user-role')) {
    const preview = AdminDOM.getById('user-role-permissions');
    if (!preview)
        return;
    const availableRoles = usersState.rolesData.length > 0 ? usersState.rolesData : DEFAULT_PRECONFIGURED_ROLES;
    const role = availableRoles.find(item => item.id === roleID || item.name === roleID);
    if (!role) {
        preview.innerHTML = '<span>Select a role to review its access.</span>';
        return;
    }
    const description = role.description || (role.permissions?.length ? `${role.permissions.length} permissions configured.` : 'Standard role access.');
    preview.innerHTML = `
    <strong>${escapeHtml(formatRoleName(role.name))}</strong>
    <span>${escapeHtml(description)}</span>
  `;
}
function bindUsersEvents() {
    if (usersState.eventsBound)
        return;
    usersState.eventsBound = true;
    AdminEvents.delegateEvent(document, 'click', '#users-container [data-action="users-open-modal"]', event => {
        event.preventDefault();
        openUserModal();
    });
    AdminEvents.delegateEvent(document, 'click', '#users-container [data-action="users-edit"]', (event, target) => {
        event.preventDefault();
        const userId = target.dataset.userId;
        if (userId)
            editUser(userId);
    });
    AdminEvents.delegateEvent(document, 'click', '#users-container [data-action="users-delete"]', (event, target) => {
        event.preventDefault();
        const userId = target.dataset.userId;
        if (userId)
            void deleteUser(userId);
    });
    AdminEvents.delegateEvent(document, 'click', '#users-container [data-action="users-page"]', (event, target) => {
        event.preventDefault();
        const page = Number.parseInt(target.dataset.page || '', 10);
        if (!Number.isNaN(page) && page >= 1 && page <= usersState.totalPages) {
            void loadUsersPage(page);
        }
    });
    AdminEvents.delegateEvent(document, 'change', '#users-container #user-role', (_event, target) => {
        updateRolePermissionPreview(target.value);
    });
    AdminEvents.delegateEvent(document, 'click', '#users-container [data-action="users-close-modal"]', event => {
        event.preventDefault();
        closeUserModal();
    });
    AdminEvents.delegateEvent(document, 'click', '#users-container [data-action="users-modal-overlay"]', (event, target) => {
        if (event.target === target) {
            closeUserModal();
        }
    });
    AdminEvents.delegateEvent(document, 'submit', '#users-container #user-form', event => {
        void saveUser(event);
    });
}
function usersGetRoleName(id) {
    const availableRoles = usersState.rolesData.length > 0 ? usersState.rolesData : DEFAULT_PRECONFIGURED_ROLES;
    const role = availableRoles.find(roleItem => roleItem.id === id || roleItem.name === id);
    return role ? formatRoleName(role.name) : (id || 'Unknown');
}
function openUserModal(user = null) {
    usersState.editingUser = user;
    const modal = AdminDOM.getById('user-modal');
    const title = AdminDOM.getById('user-modal-title');
    const description = AdminDOM.getById('user-modal-description');
    const form = AdminDOM.getById('user-form');
    const idInput = AdminDOM.getInput('user-id');
    const usernameInput = AdminDOM.getInput('user-username');
    const emailInput = AdminDOM.getInput('user-email');
    const roleInput = AdminDOM.getSelect('user-role');
    const activeInput = AdminDOM.getInput('user-active');
    const passwordInput = AdminDOM.getInput('user-password');
    modal?.classList.remove('hidden');
    if (usersState.userModalKeyCleanup)
        usersState.userModalKeyCleanup();
    usersState.userModalKeyCleanup = AdminEvents.bindEscape(() => {
        closeUserModal();
    });
    if (user) {
        if (title)
            title.textContent = 'Edit User';
        if (description)
            description.textContent = 'Update this identity, role assignment, and account availability.';
        if (idInput)
            idInput.value = user.id;
        if (usernameInput)
            usernameInput.value = user.username;
        if (emailInput)
            emailInput.value = user.email;
        if (roleInput)
            roleInput.value = user.role_id;
        updateRolePermissionPreview(user.role_id);
        if (activeInput)
            activeInput.checked = user.is_active;
        if (passwordInput) {
            passwordInput.value = '';
            passwordInput.required = false;
        }
        usernameInput?.focus();
        return;
    }
    if (title)
        title.textContent = 'Add User';
    if (description)
        description.textContent = 'Create an administrator account and assign a preconfigured access role.';
    form?.reset();
    if (idInput)
        idInput.value = '';
    if (activeInput)
        activeInput.checked = true;
    if (passwordInput)
        passwordInput.required = true;
    updateRolePermissionPreview(roleInput?.value || '');
    usernameInput?.focus();
}
function closeUserModal() {
    AdminDOM.getById('user-modal')?.classList.add('hidden');
    if (usersState.userModalKeyCleanup) {
        usersState.userModalKeyCleanup();
        usersState.userModalKeyCleanup = null;
    }
    usersState.editingUser = null;
}
function editUser(id) {
    const user = usersState.usersData.find(userItem => userItem.id === id);
    if (user)
        openUserModal(user);
}
async function saveUser(event) {
    event.preventDefault();
    if (!canManageUsers()) {
        usersShowToast('You do not have permission to manage user accounts.', 'error');
        return;
    }
    const id = AdminDOM.inputValue('user-id');
    const payload = {
        username: AdminDOM.inputValue('user-username'),
        email: AdminDOM.inputValue('user-email'),
        role_id: AdminDOM.selectValue('user-role'),
        is_active: AdminDOM.checkboxValue('user-active'),
        password: AdminDOM.inputValue('user-password')
    };
    if (!payload.role_id) {
        usersShowToast('Select a role before saving', 'error');
        return;
    }
    if (id)
        payload.id = id;
    const result = await api.requestResult('users', id ? 'PUT' : 'POST', payload);
    if (result.error) {
        usersShowToast(result.error.message, 'error');
        return;
    }
    closeUserModal();
    await loadUsersPage();
    usersShowToast(id ? 'User Updated' : 'User Created', 'success');
}
async function deleteUser(id) {
    if (!canManageUsers()) {
        usersShowToast('You do not have permission to manage user accounts.', 'error');
        return;
    }
    SectionUI.openConfirmModal('Deactivate User', 'This immediately revokes the user’s access while retaining the identity and audit history.', 'Deactivate', 'var(--danger)', () => {
        void confirmDeleteUser(id);
    });
}
async function confirmDeleteUser(id) {
    SectionUI.closeModal();
    const result = await api.requestResult(`users?id=${encodeURIComponent(id)}`, 'DELETE');
    if (result.error) {
        usersShowToast(result.error.message, 'error');
        return;
    }
    await loadUsersPage();
    usersShowToast('User deactivated and access revoked', 'success');
}
function usersShowToast(message, type = 'info') {
    notify(message, type);
}
function formatRoleName(value) {
    return value
        .replace(/[_-]+/g, ' ')
        .replace(/\b\w/g, char => char.toUpperCase());
}
function escapeHtml(value) {
    return value.replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char] || char));
}
function escapeAttr(value) {
    return escapeHtml(value);
}
