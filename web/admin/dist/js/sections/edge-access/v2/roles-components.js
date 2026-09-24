import { SectionUI } from '../../ui-components.js';
import { escapeHTML } from '../view-helpers.js';
import { renderCreateBack, renderSetupCheckboxRow, renderSetupHeading } from './setup-components.js';
function action(label, name, attributes = '', primary = false, icon = '') {
    return `<button type="button" class="btn ${primary ? 'btn-primary' : 'btn-outline'}" data-edge-access-v2-action="${name}" ${attributes}>${icon ? `<span class="edge-access-v2-button-icon" aria-hidden="true">${icon}</span>` : ''}${escapeHTML(label)}</button>`;
}
function accessSummary(role) {
    const direct = role.permissions.includes('*')
        ? 'Full access'
        : `${role.permissions.length} ${role.permissions.length === 1 ? 'permission' : 'permissions'}`;
    const inherited = role.inherits.length
        ? `<span>${role.inherits.length} inherited ${role.inherits.length === 1 ? 'role' : 'roles'}</span>`
        : '';
    return `<div class="edge-access-v2-role-access"><strong>${direct}</strong>${inherited}</div>`;
}
export function renderManagedRolePicker(resource, selected, options = {}) {
    const name = options.name || 'roles';
    const label = options.label || 'Roles';
    const roles = (resource.value || []).filter(role => role.id !== options.excludeID);
    let content = '';
    if (resource.loading && !resource.value) {
        content = SectionUI.renderLoading('Loading roles...');
    }
    else if (resource.error) {
        content = `<div class="section-error" role="alert"><div class="error-message">${escapeHTML(resource.error)}</div><button type="button" class="btn btn-outline" data-edge-access-v2-action="roles-retry">Retry</button></div>`;
    }
    else if (!roles.length) {
        content = `<p class="text-muted">${escapeHTML(options.emptyMessage || 'Create a role before assigning role-based access.')}</p>`;
    }
    else {
        content = `<div class="edge-access-v2-role-picker-options">${roles.map(role => renderSetupCheckboxRow({
            name,
            value: role.id,
            checked: selected.includes(role.id),
            title: role.name,
            description: `${role.permissions.length} ${role.permissions.length === 1 ? 'permission' : 'permissions'}`,
            className: 'edge-access-v2-role-option'
        })).join('')}</div>`;
    }
    return `<fieldset class="edge-access-v2-role-picker"><legend>${escapeHTML(label)}</legend>${content}</fieldset>`;
}
function renderRoleForm(state) {
    const editing = state.route.roleMode === 'edit';
    const role = editing ? (state.roles.catalog.value || []).find(item => item.id === state.route.roleID) : undefined;
    if (state.roles.catalog.loading && !state.roles.catalog.value) {
        return `<div class="edge-access-v2-create-shell">${renderCreateBack('Roles', 'Back to roles', 'role-back')}${SectionUI.renderLoading('Loading roles...')}</div>`;
    }
    if (editing && (!role || role.is_builtin)) {
        return `<div class="edge-access-v2-create-shell">${renderCreateBack('Roles', 'Back to roles', 'role-back')}${SectionUI.renderOperatorSection('Role unavailable', SectionUI.renderEmptyState('This role cannot be edited', 'System roles are protected. Return to Roles and create a role instead.', 'info'))}</div>`;
    }
    const permissions = role?.permissions.join(', ') || '';
    return `<div class="edge-access-v2-create-shell edge-access-v2-role-editor-shell">
    ${renderCreateBack('Roles', 'Back to roles', 'role-back')}
    ${SectionUI.renderOperatorSection(editing ? `Edit ${escapeHTML(role?.name || 'role')}` : 'Create role', `
      <form class="edge-access-v2-role-form" data-edge-access-v2-role-form="true" data-edge-access-v2-role-id="${escapeHTML(role?.id || '')}">
        <section class="edge-access-v2-setup-section">
          ${renderSetupHeading('Role details', 'Define a stable role identifier and a clear administrative name.')}
          <div class="edge-access-v2-provider-form-grid">
            <label class="edge-access-v2-setup-field"><span>Role ID</span><input class="input" name="id" required value="${escapeHTML(role?.id || '')}" placeholder="support_operator"${editing ? ' readonly' : ''}></label>
            <label class="edge-access-v2-setup-field"><span>Display name</span><input class="input" name="name" required value="${escapeHTML(role?.name || '')}" placeholder="Support operator"></label>
            <label class="edge-access-v2-setup-field edge-access-v2-setup-field--wide"><span>Description</span><textarea class="input" name="description" rows="3" placeholder="Describe the responsibilities granted by this role">${escapeHTML(role?.description || '')}</textarea></label>
          </div>
        </section>
        <section class="edge-access-v2-setup-section">
          ${renderSetupHeading('Permissions', 'List the RBAC permissions granted directly by this role.')}
          <label class="edge-access-v2-setup-field edge-access-v2-setup-field--wide"><span>Permission identifiers</span><textarea class="input" name="permissions" rows="4" required placeholder="read:incidents, write:incidents">${escapeHTML(permissions)}</textarea><small>Separate permissions with commas.</small></label>
        </section>
        <section class="edge-access-v2-setup-section">
          ${renderSetupHeading('Inherited roles', 'Optionally include permissions from existing roles.')}
          ${renderManagedRolePicker(state.roles.catalog, role?.inherits || [], { name: 'inherits', label: 'Available roles', excludeID: role?.id, emptyMessage: 'No other roles are available to inherit.' })}
        </section>
        <footer class="edge-access-v2-create-actions"><div class="operator-control-actions">${action(editing ? 'Save Changes' : 'Create role', 'role-save', '', true, SectionUI.icons.tag)}</div></footer>
      </form>
    `, { subtitle: 'Roles provide reusable permission sets for identities and access policies.', className: 'edge-access-v2-new-app-section edge-access-v2-role-editor-section' })}
  </div>`;
}
function renderRoleInventory(state) {
    const resource = state.roles.catalog;
    const actions = action('Add role', 'role-new', '', true, SectionUI.icons.tag);
    if (resource.loading && !resource.value) {
        return SectionUI.renderOperatorSection('Roles', SectionUI.renderLoading('Loading roles...'), { subtitle: 'Manage reusable RBAC permission sets.', actions });
    }
    if (resource.error) {
        return SectionUI.renderOperatorSection('Roles', `<div class="section-error" role="alert"><div class="error-message">${escapeHTML(resource.error)}</div>${action('Retry', 'roles-retry')}</div>`, { subtitle: 'Manage reusable RBAC permission sets.', actions });
    }
    const rows = (resource.value || []).slice().sort((left, right) => Number(right.is_builtin) - Number(left.is_builtin) || left.name.localeCompare(right.name)).map(role => {
        const rowActions = role.is_builtin
            ? '<span class="text-muted" aria-label="No actions">&mdash;</span>'
            : SectionUI.renderActionMenu({
                id: `edge-access-v2-role-actions-${role.id}`,
                ariaLabel: `Actions for ${role.name}`,
                label: 'More',
                items: [
                    { label: 'Edit role', attrs: `data-edge-access-v2-action="role-edit" data-edge-access-v2-role-id="${escapeHTML(role.id)}"` },
                    { label: 'Delete role', attrs: `data-edge-access-v2-action="role-delete" data-edge-access-v2-role-id="${escapeHTML(role.id)}"`, tone: 'danger' }
                ]
            });
        return [
            `<div class="edge-access-v2-role-cell"><div class="edge-access-v2-role-cell-title"><strong>${escapeHTML(role.name)}</strong></div>${role.description ? `<span>${escapeHTML(role.description)}</span>` : ''}</div>`,
            accessSummary(role),
            rowActions
        ];
    });
    const table = SectionUI.renderEnterpriseTable({
        columns: ['Role', 'Access', 'Actions'],
        rows,
        emptyTitle: 'No roles',
        emptyMessage: 'Create a role to define reusable permissions for identities and policies.'
    });
    return SectionUI.renderOperatorSection('Roles', table, {
        subtitle: 'Manage reusable permission sets for identities and access policies.',
        actions,
        className: 'edge-access-v2-roles-section'
    });
}
export function renderV2Roles(state) {
    return state.route.roleMode === 'list' ? renderRoleInventory(state) : renderRoleForm(state);
}
