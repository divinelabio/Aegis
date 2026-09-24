/**
 * Upstream groups page
 * Source of truth: web/admin/src/upstreams.ts
 * Runtime output: web/admin/dist/js/upstreams.js
 */
import { api } from './api.js';
import * as AdminDOM from './core/dom.js';
import * as AdminEvents from './core/events.js';
import { SectionUI } from './sections/ui-components.js';
import { notify } from './core/notify.js';
const upstreamsState = {
    upstreamGroups: [],
    runtimeStatus: [],
    runtimeStatusByTarget: new Map(),
    runtimeStatusAvailable: true,
    editingGroup: null
};
let upstreamsBindingsInitialized = false;
function encodeGroupName(name) {
    return encodeURIComponent(name);
}
function decodeGroupName(value) {
    return value ? decodeURIComponent(value) : '';
}
function escapeHTML(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
function formatStrategy(strategy = 'round_robin') {
    const labels = {
        round_robin: 'Round robin',
        weighted_rr: 'Weighted round robin',
        least_conn: 'Least connections',
        ip_hash: 'IP hash'
    };
    return labels[strategy] || strategy.replace(/_/g, ' ');
}
function parseExpectedStatuses(value) {
    if (!value.trim())
        return [];
    const statuses = value.split(',').map(item => Number(item.trim()));
    if (statuses.some(status => !Number.isInteger(status) || status < 100 || status > 599))
        return null;
    return Array.from(new Set(statuses));
}
export async function loadUpstreamsPage() {
    ensureUpstreamsBindings();
    const container = AdminDOM.getById('upstream-container');
    if (!container)
        return;
    container.innerHTML = '<div class="table-empty p-40">Loading origins...</div>';
    try {
        const [data, runtimeStatus] = await Promise.all([
            api.get('upstreams'),
            loadUpstreamRuntimeStatus()
        ]);
        upstreamsState.upstreamGroups = Array.isArray(data) ? data : [];
        upstreamsState.runtimeStatus = runtimeStatus.data;
        upstreamsState.runtimeStatusByTarget = indexRuntimeStatus(runtimeStatus.data);
        upstreamsState.runtimeStatusAvailable = runtimeStatus.available;
        renderUpstreams(container);
    }
    catch (error) {
        console.warn('Origins API error', error);
        container.innerHTML = '<div class="table-empty p-40 text-danger">Failed to load origins</div>';
    }
}
function renderUpstreams(container) {
    const rows = upstreamsState.upstreamGroups.map(group => renderGroupRow(group));
    const table = SectionUI.renderEnterpriseTable({
        columns: ['Origin pool', 'Targets', 'Origin policy', 'Health checks', 'Session affinity', 'Actions'],
        rows,
        className: 'origins-pool-table',
        emptyTitle: 'No origin pools',
        emptyMessage: 'Create a reusable Origin pool before attaching it to a Route.'
    });
    const content = `
    <div class="origins-operator-stack">
      ${SectionUI.renderOperatorSection('Origin pools', `
        <div class="origins-pool-surface">${table}</div>
      `, {
        subtitle: 'Reusable Origin endpoints and delivery policies available to Routing.',
        className: 'origins-catalog-section'
    })}
    </div>
  `;
    container.innerHTML = SectionUI.renderOperatorFrame({
        title: 'Origins',
        kicker: 'Network',
        subtitle: 'Manage reusable Origin pools, health checks, and session affinity for Routing.',
        actions: `<button type="button" class="btn btn-primary" data-upstreams-action="open-group-editor"><span class="origins-button-icon" aria-hidden="true">${SectionUI.icons.database}</span>Add pool</button>`,
        content,
        className: 'origins-operator-frame'
    });
}
async function loadUpstreamRuntimeStatus() {
    try {
        const response = await fetch('/api/upstreams/status', { headers: { Accept: 'application/json' } });
        if (response.status === 404)
            return { data: [], available: false };
        if (!response.ok) {
            console.warn(`Origins runtime status unavailable: HTTP ${response.status}`);
            return { data: [], available: false };
        }
        const data = await response.json();
        return { data: Array.isArray(data) ? data : [], available: true };
    }
    catch (error) {
        console.warn('Origins runtime status unavailable', error);
        return { data: [], available: false };
    }
}
function findRuntimeTarget(groupName, targetURL) {
    return upstreamsState.runtimeStatusByTarget.get(runtimeTargetKey(groupName, targetURL));
}
function indexRuntimeStatus(groups) {
    const indexed = new Map();
    for (const group of groups) {
        for (const target of group.targets) {
            indexed.set(runtimeTargetKey(group.name, target.url), target);
        }
    }
    return indexed;
}
function runtimeTargetKey(groupName, targetURL) {
    return `${groupName}\u0000${targetURL}`;
}
function renderTarget(groupName, target) {
    const runtime = findRuntimeTarget(groupName, target.url);
    let label = upstreamsState.runtimeStatusAvailable ? 'Not checked' : 'Status unavailable';
    let tone = 'neutral';
    if (runtime?.health_check_enabled) {
        label = runtime.healthy ? `Healthy${runtime.last_latency_ms ? ` · ${runtime.last_latency_ms} ms` : ''}` : 'Down';
        tone = runtime.healthy ? 'success' : 'danger';
    }
    const details = runtime?.last_error || (runtime?.last_check ? `Last checked ${runtime.last_check}` : label);
    return `<div class="origins-target-entry" title="${escapeHTML(details)}">
    <span class="origins-target-url" title="${escapeHTML(target.url)}">${escapeHTML(target.url)}</span>
    ${SectionUI.renderStatusPill(label, tone)}
  </div>`;
}
function renderGroupRow(group) {
    const targets = group.targets || [];
    const healthCheck = group.health_check || { enabled: false };
    const sticky = group.sticky || { enabled: false };
    const groupName = encodeGroupName(group.name);
    const actions = SectionUI.renderActionMenu({
        id: `origins-pool-actions-${groupName}`,
        label: 'More',
        ariaLabel: `Actions for ${group.name}`,
        items: [
            { label: 'Edit pool', attrs: `data-upstreams-action="edit-group" data-group-name="${groupName}"` },
            { label: 'Delete pool', attrs: `data-upstreams-action="delete-group" data-group-name="${groupName}"`, tone: 'danger' }
        ],
        className: 'origins-row-menu'
    });
    return [
        `<div class="origins-pool-identity">
      <span class="origins-pool-icon" aria-hidden="true">${SectionUI.icons.database}</span>
      <button type="button" class="btn-link origins-pool-link" data-upstreams-action="edit-group" data-group-name="${groupName}">${escapeHTML(group.name)}</button>
    </div>`,
        targets.length
            ? `<div class="origins-target-list">${targets.map(target => renderTarget(group.name, target)).join('')}</div>`
            : '<span class="origins-empty-value">No targets configured</span>',
        SectionUI.renderStatusPill(escapeHTML(formatStrategy(group.strategy)), 'neutral'),
        SectionUI.renderStatusPill(healthCheck.enabled && !upstreamsState.runtimeStatusAvailable
            ? 'Configured'
            : healthCheck.enabled
                ? `${targets.filter(target => findRuntimeTarget(group.name, target.url)?.healthy).length}/${targets.length} healthy`
                : 'Disabled', healthCheck.enabled && upstreamsState.runtimeStatusAvailable && targets.some(target => !findRuntimeTarget(group.name, target.url)?.healthy) ? 'danger' : healthCheck.enabled && upstreamsState.runtimeStatusAvailable ? 'success' : 'neutral'),
        SectionUI.renderStatusPill(sticky.enabled ? 'Enabled' : 'Disabled', sticky.enabled ? 'primary' : 'neutral'),
        `<div class="operator-control-actions origins-row-actions">${actions}</div>`
    ];
}
function ensureUpstreamsBindings() {
    if (upstreamsBindingsInitialized)
        return;
    upstreamsBindingsInitialized = true;
    AdminEvents.delegateEvent(document, 'click', '[data-upstreams-action]', (_event, target) => {
        const action = target.dataset.upstreamsAction;
        const groupName = decodeGroupName(target.dataset.groupName);
        switch (action) {
            case 'open-group-editor':
                openGroupEditor();
                break;
            case 'close-group-editor':
                closeGroupEditor();
                break;
            case 'save-group':
                void saveGroup();
                break;
            case 'edit-group':
                if (groupName)
                    editGroup(groupName);
                break;
            case 'delete-group':
                if (groupName)
                    void deleteGroup(groupName);
                break;
            case 'add-target-row':
                addTargetRow(target);
                break;
            case 'remove-target-row':
                target.closest('.target-row')?.remove();
                break;
            default:
                break;
        }
    });
    AdminEvents.delegateEvent(document, 'change', '#origin-healthcheck, #origin-sticky', () => {
        syncOriginEditorControls();
    });
    AdminEvents.delegateEvent(document, 'submit', '#origin-group-form', event => {
        event.preventDefault();
        void saveGroup();
    });
}
export function openOriginEditor() {
    openGroupEditor();
}
function openGroupEditor(group = null) {
    const container = AdminDOM.getById('upstream-container');
    if (container)
        renderOriginEditor(container, group);
}
function closeGroupEditor() {
    const container = AdminDOM.getById('upstream-container');
    if (!container)
        return;
    upstreamsState.editingGroup = null;
    renderUpstreams(container);
}
function renderOriginTargetRow(target = { url: '', weight: 1 }) {
    return `
    <div class="origins-editor-target-row target-row">
      <div class="settings-field">
        <label>Target URL</label>
        <input type="text" class="input target-url" value="${escapeHTML(target.url)}" placeholder="http://10.0.0.1:8080" autocomplete="off">
      </div>
      <div class="settings-field origins-editor-weight-field">
        <label>Weight</label>
        <input type="number" class="input target-weight" value="${escapeHTML(target.weight || 1)}" min="1" max="1000">
      </div>
      <button type="button" class="btn btn-outline btn-sm origins-editor-remove-target" data-upstreams-action="remove-target-row">Remove</button>
    </div>
  `;
}
function renderOriginEditor(container, group = null) {
    upstreamsState.editingGroup = group;
    const isEditing = Boolean(group);
    const name = group?.name || '';
    const healthCheck = group?.health_check;
    const sticky = group?.sticky;
    const healthEnabled = Boolean(healthCheck?.enabled);
    const stickyEnabled = Boolean(sticky?.enabled);
    const hasAdvancedSettings = healthEnabled || stickyEnabled;
    const strategy = group?.strategy || 'round_robin';
    const targets = group?.targets?.length ? group.targets : [{ url: '', weight: 1 }];
    const selected = (value) => strategy === value ? ' selected' : '';
    const saveLabel = isEditing ? 'Save changes' : 'Create pool';
    const saveIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><path d="M17 21v-8H7v8"/><path d="M7 3v5h8"/></svg>';
    const content = `
    <form id="origin-group-form" class="origins-editor-form">
      <input type="hidden" id="origin-existing-name" value="${escapeHTML(name)}">

      <section class="origins-editor-setup-section" aria-labelledby="origin-details-title">
        <div class="origins-editor-setup-heading">
          <h3 id="origin-details-title">Origin details</h3>
        </div>
        <div class="origins-editor-field-grid origins-editor-basics-grid">
          <div class="settings-field">
            <label for="origin-name">Origin name${isEditing ? '' : ' <span class="origins-editor-required">Required</span>'}</label>
            <input type="text" id="origin-name" required class="input" value="${escapeHTML(name)}" placeholder="API servers" autocomplete="off"${isEditing ? ' readonly' : ''}>
          </div>
          <div class="settings-field">
            <label for="origin-strategy">Origin policy</label>
            <select id="origin-strategy" class="input">
              <option value="round_robin"${selected('round_robin')}>Round robin</option>
              <option value="weighted_rr"${selected('weighted_rr')}>Weighted round robin</option>
              <option value="least_conn"${selected('least_conn')}>Least connections</option>
              <option value="ip_hash"${selected('ip_hash')}>IP hash</option>
            </select>
          </div>
        </div>
      </section>

      <section class="origins-editor-setup-section" aria-labelledby="origin-targets-title">
        <div class="origins-editor-section-line">
          <div class="origins-editor-setup-heading">
            <h3 id="origin-targets-title">Targets</h3>
          </div>
          <button type="button" class="btn btn-outline btn-sm" data-upstreams-action="add-target-row">Add target</button>
        </div>
        <div id="origin-targets-container" class="origins-editor-targets">
          ${targets.map(target => renderOriginTargetRow(target)).join('')}
        </div>
      </section>

      <details class="origins-editor-advanced" ${hasAdvancedSettings ? 'open' : ''}>
        <summary><span>Advanced settings</span></summary>
        <div class="origins-editor-advanced-body">
          <section class="origins-editor-advanced-group">
            <label class="origins-editor-toggle-row">
              <span>Health checks</span>
              <span class="switch origins-editor-switch">
                <input type="checkbox" id="origin-healthcheck"${healthEnabled ? ' checked' : ''}>
                <span class="switch-slider"></span>
              </span>
            </label>
            <div id="origin-health-settings" class="origins-editor-field-grid origins-editor-field-grid--two"${healthEnabled ? '' : ' hidden'}>
              <div class="settings-field">
                <label for="origin-health-interval">Interval</label>
                <input type="text" id="origin-health-interval" class="input" value="${escapeHTML(healthCheck?.interval ?? '10s')}" placeholder="10s">
              </div>
              <div class="settings-field">
                <label for="origin-health-path">Path</label>
                <input type="text" id="origin-health-path" class="input" value="${escapeHTML(healthCheck?.path ?? '/')}" placeholder="/health">
              </div>
              <div class="settings-field">
                <label for="origin-health-timeout">Timeout</label>
                <input type="text" id="origin-health-timeout" class="input" value="${escapeHTML(healthCheck?.timeout ?? '3s')}" placeholder="3s">
              </div>
              <div class="settings-field">
                <label for="origin-health-method">Method</label>
                <select id="origin-health-method" class="input">
                  <option value="GET"${!healthCheck?.method || healthCheck.method === 'GET' ? ' selected' : ''}>GET</option>
                  <option value="HEAD"${healthCheck?.method === 'HEAD' ? ' selected' : ''}>HEAD</option>
                </select>
              </div>
              <div class="settings-field">
                <label for="origin-expected-statuses">Expected statuses</label>
                <input type="text" id="origin-expected-statuses" class="input" value="${escapeHTML((healthCheck?.expected_statuses || []).join(','))}" placeholder="200, 204">
              </div>
              <div class="origins-editor-thresholds">
                <div class="settings-field">
                  <label for="origin-healthy-threshold">Healthy threshold</label>
                  <input type="number" id="origin-healthy-threshold" class="input" value="${escapeHTML(healthCheck?.healthy_threshold ?? 2)}" min="1" max="20">
                </div>
                <div class="settings-field">
                  <label for="origin-unhealthy-threshold">Unhealthy threshold</label>
                  <input type="number" id="origin-unhealthy-threshold" class="input" value="${escapeHTML(healthCheck?.unhealthy_threshold ?? 3)}" min="1" max="20">
                </div>
              </div>
            </div>
          </section>

          <section class="origins-editor-advanced-group">
            <label class="origins-editor-toggle-row">
              <span>Session affinity</span>
              <span class="switch origins-editor-switch">
                <input type="checkbox" id="origin-sticky"${stickyEnabled ? ' checked' : ''}>
                <span class="switch-slider"></span>
              </span>
            </label>
            <div id="origin-sticky-settings" class="origins-editor-field-grid origins-editor-field-grid--two"${stickyEnabled ? '' : ' hidden'}>
              <div class="settings-field">
                <label for="origin-sticky-cookie">Cookie name</label>
                <input type="text" id="origin-sticky-cookie" class="input" value="${escapeHTML(sticky?.cookie ?? '')}" placeholder="Automatic">
              </div>
              <div class="settings-field">
                <label for="origin-sticky-ttl">Cookie TTL</label>
                <input type="text" id="origin-sticky-ttl" class="input" value="${escapeHTML(sticky?.ttl ?? '24h')}" placeholder="24h">
              </div>
            </div>
          </section>
        </div>
      </details>

      <footer class="origins-editor-actions">
        <div class="operator-control-actions">
          <button type="submit" class="btn btn-primary">${saveIcon}${saveLabel}</button>
        </div>
      </footer>
    </form>
  `;
    container.innerHTML = SectionUI.renderOperatorFrame({
        title: 'Origins',
        content: `
      <div class="origins-editor-create-shell">
        ${SectionUI.renderOperatorBackButton({
            label: 'Back to Origins',
            ariaLabel: 'Back to Origins',
            attrs: 'data-upstreams-action="close-group-editor"'
        })}
        ${SectionUI.renderOperatorSection(isEditing ? 'Edit origin' : 'Add origin', content, { className: 'origins-editor-create-section' })}
      </div>
    `,
        className: 'origins-operator-frame origins-editor-operator-frame'
    });
    syncOriginEditorControls();
    window.requestAnimationFrame(() => AdminDOM.getInput('origin-name')?.focus());
}
function syncOriginEditorControls() {
    const healthSettings = document.getElementById('origin-health-settings');
    const stickySettings = document.getElementById('origin-sticky-settings');
    if (healthSettings)
        healthSettings.hidden = !AdminDOM.checkboxValue('origin-healthcheck', false);
    if (stickySettings)
        stickySettings.hidden = !AdminDOM.checkboxValue('origin-sticky', false);
}
async function saveGroup() {
    const existing = upstreamsState.editingGroup;
    const isEditing = Boolean(existing);
    const name = isEditing ? existing?.name || '' : AdminDOM.inputValue('origin-name').trim();
    const strategy = AdminDOM.selectValue('origin-strategy', 'round_robin');
    const healthEnabled = AdminDOM.checkboxValue('origin-healthcheck', false);
    const stickyEnabled = AdminDOM.checkboxValue('origin-sticky', false);
    const expectedStatuses = parseExpectedStatuses(AdminDOM.inputValue('origin-expected-statuses'));
    const targets = [];
    AdminDOM.queryAll('#origin-targets-container .target-row').forEach(row => {
        const url = (AdminDOM.query('.target-url', row)?.value || '').trim();
        const weight = Number.parseInt(AdminDOM.query('.target-weight', row)?.value || '', 10) || 1;
        if (url)
            targets.push({ url, weight });
    });
    if (!name) {
        upstreamsShowToast('Origin name is required', 'error');
        return;
    }
    if (targets.length === 0) {
        upstreamsShowToast('At least one origin target is required', 'error');
        return;
    }
    if (!expectedStatuses) {
        upstreamsShowToast('Expected statuses must be comma-separated HTTP status codes', 'error');
        return;
    }
    const healthInterval = AdminDOM.inputValue('origin-health-interval').trim() || (healthEnabled ? '10s' : existing?.health_check?.interval || '');
    const healthPath = AdminDOM.inputValue('origin-health-path').trim() || (healthEnabled ? '/' : existing?.health_check?.path || '');
    const healthTimeout = AdminDOM.inputValue('origin-health-timeout').trim() || (healthEnabled ? '3s' : existing?.health_check?.timeout || '');
    const stickyTTL = AdminDOM.inputValue('origin-sticky-ttl').trim() || (stickyEnabled ? '24h' : existing?.sticky?.ttl || '');
    const group = {
        ...(existing || {}),
        name,
        strategy,
        targets,
        health_check: {
            ...(existing?.health_check || {}),
            enabled: healthEnabled,
            interval: healthInterval,
            timeout: healthTimeout,
            path: healthPath,
            method: AdminDOM.selectValue('origin-health-method', 'GET'),
            expected_statuses: expectedStatuses,
            healthy_threshold: AdminDOM.numberValue('origin-healthy-threshold', 2),
            unhealthy_threshold: AdminDOM.numberValue('origin-unhealthy-threshold', 3)
        },
        sticky: {
            ...(existing?.sticky || {}),
            enabled: stickyEnabled,
            cookie: AdminDOM.inputValue('origin-sticky-cookie').trim(),
            ttl: stickyTTL
        }
    };
    const success = await api.post('upstreams', group);
    if (success) {
        upstreamsState.editingGroup = null;
        upstreamsShowToast(isEditing ? 'Origin pool updated' : 'Origin pool created', 'success');
        await loadUpstreamsPage();
    }
}
async function deleteGroup(name) {
    SectionUI.openConfirmModal('Delete Origin Pool', `Are you sure you want to delete origin pool "${escapeHTML(name)}"?`, 'Delete', 'var(--danger)', () => {
        void confirmDeleteGroup(name);
    });
}
async function confirmDeleteGroup(name) {
    SectionUI.closeModal();
    const result = await api.request('upstreams', 'DELETE', { name });
    if (result) {
        upstreamsShowToast('Origin pool deleted', 'success');
        await loadUpstreamsPage();
    }
}
function editGroup(name) {
    const group = upstreamsState.upstreamGroups.find(groupItem => groupItem.name === name);
    if (group)
        openGroupEditor(group);
}
function addTargetRow(_button) {
    const container = document.getElementById('origin-targets-container');
    if (!(container instanceof HTMLElement))
        return;
    container.insertAdjacentHTML('beforeend', renderOriginTargetRow());
}
function upstreamsShowToast(message, type = 'info') {
    notify(message, type);
}
