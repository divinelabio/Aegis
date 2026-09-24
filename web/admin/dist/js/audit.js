/**
 * Audit logs page
 * Source of truth: web/admin/src/audit.ts
 * Runtime output: web/admin/dist/js/audit.js
 */
import * as AdminDOM from './core/dom.js';
import * as AdminEvents from './core/events.js';
import { notify } from './core/notify.js';
import { api } from './api.js';
import { SectionUI } from './sections/ui-components.js';
const auditPageSizes = [20, 50, 100, 200];
const auditState = {
    bound: false,
    pageSize: 20,
    pageIndex: 0,
    nextCursor: '',
    pages: [],
    filters: {
        action: '',
        actor: '',
        from: '',
        to: ''
    }
};
export async function loadAuditLogsPage() {
    bindAuditInteractions();
    auditState.pageIndex = 0;
    auditState.nextCursor = '';
    auditState.pages = [];
    await fetchAuditPage('', 0);
}
async function fetchAuditPage(cursor, targetPage) {
    const container = AdminDOM.getById('audit-logs-container');
    if (!container)
        return;
    container.innerHTML = SectionUI.renderLoading('Loading audit activity...');
    try {
        const query = buildAuditQuery(cursor);
        const response = await fetch(`/api/audit-logs?${query.toString()}`);
        if (!response.ok)
            throw new Error(`Audit log request failed with status ${response.status}`);
        const payload = (await response.json());
        const logs = payload.data || [];
        auditState.pageIndex = targetPage;
        auditState.nextCursor = payload.meta?.next_cursor || '';
        auditState.pages[targetPage] = { logs, meta: payload.meta };
        auditState.pages.length = targetPage + 1;
        renderAuditTable(container, logs, payload.meta);
    }
    catch (error) {
        console.error(error);
        container.innerHTML = SectionUI.renderOperatorFrame({
            title: 'Audit Logs',
            kicker: 'System',
            subtitle: 'Review administrative actions, forensic compliance events, and control plane audit records.',
            actions: renderRefreshButton(),
            content: SectionUI.renderEmptyState('Audit logs unavailable', 'The latest administrative activity could not be loaded. Refresh to try again.', 'alertCircle'),
            className: 'audit-operator-frame'
        });
    }
}
function bindAuditInteractions() {
    if (auditState.bound)
        return;
    auditState.bound = true;
    AdminEvents.delegateEvent(document, 'click', '[data-audit-action]', (event, target) => {
        event.preventDefault();
        const action = target.dataset.auditAction || '';
        if (action === 'next')
            void loadNextAuditPage();
        if (action === 'previous')
            showPreviousAuditPage();
        if (action === 'clear-filters') {
            auditState.filters = { action: '', actor: '', from: '', to: '' };
            void loadAuditLogsPage();
        }
        if (action === 'export')
            void exportAuditLogs();
    });
    AdminEvents.delegateEvent(document, 'submit', 'form[data-audit-filter-form]', (event, form) => {
        event.preventDefault();
        const data = new FormData(form);
        auditState.filters = {
            action: String(data.get('action') || '').trim(),
            actor: String(data.get('actor') || '').trim(),
            from: String(data.get('from') || '').trim(),
            to: String(data.get('to') || '').trim()
        };
        void loadAuditLogsPage();
    });
    AdminEvents.delegateEvent(document, 'change', '[data-audit-page-size]', (_event, target) => {
        const pageSize = Number(target.value);
        if (!auditPageSizes.includes(pageSize))
            return;
        auditState.pageSize = pageSize;
        void loadAuditLogsPage();
    });
}
async function loadNextAuditPage() {
    if (!auditState.nextCursor)
        return;
    await fetchAuditPage(auditState.nextCursor, auditState.pageIndex + 1);
}
function showPreviousAuditPage() {
    if (auditState.pageIndex <= 0)
        return;
    const page = auditState.pages[auditState.pageIndex - 1];
    if (!page)
        return;
    auditState.pageIndex -= 1;
    auditState.nextCursor = page.meta?.next_cursor || '';
    const container = AdminDOM.getById('audit-logs-container');
    if (container)
        renderAuditTable(container, page.logs, page.meta);
}
function buildAuditQuery(cursor = '') {
    const query = new URLSearchParams();
    query.set('limit', String(auditState.pageSize));
    if (cursor)
        query.set('cursor', cursor);
    if (auditState.filters.action)
        query.set('action', auditState.filters.action);
    if (auditState.filters.actor)
        query.set('actor', auditState.filters.actor);
    const from = toAuditISOTime(auditState.filters.from);
    const to = toAuditISOTime(auditState.filters.to);
    if (from)
        query.set('from', from);
    if (to)
        query.set('to', to);
    return query;
}
function toAuditISOTime(value) {
    if (!value)
        return '';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '' : date.toISOString();
}
async function exportAuditLogs() {
    api.showLoading();
    api.resetSessionTimer();
    try {
        const query = buildAuditQuery();
        query.set('limit', '5000');
        const response = await fetch(`/api/audit-logs/export?${query.toString()}`, { headers: { Accept: 'text/csv' } });
        if (!response.ok)
            throw new Error(`Audit export failed with status ${response.status}`);
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'aegis-audit-logs.csv';
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        notify(response.headers.get('X-Aegis-Export-Truncated') === 'true'
            ? 'Exported the first 5,000 matching audit records.'
            : 'Audit log export downloaded.', 'success');
    }
    catch (error) {
        console.error(error);
        notify(error instanceof Error ? error.message : 'Audit export failed.', 'error');
    }
    finally {
        api.hideLoading();
    }
}
function renderAuditTable(container, logs, meta) {
    const table = SectionUI.renderEnterpriseTable({
        columns: ['Time', 'Actor', 'Activity', 'Source IP'],
        rows: logs.map(log => renderAuditRow(log)),
        className: 'audit-event-table',
        emptyTitle: 'No audit records',
        emptyMessage: 'Administrative activity matching the current filters appears here.'
    });
    const content = `
    <div class="audit-operator-stack">
      ${SectionUI.renderOperatorSection('Recent activity', `
        <div class="audit-event-surface">${renderAuditFilters()}${table}${renderAuditPagination(meta)}</div>
      `, {
        subtitle: 'Filter by exact action, administrator, or local time. CSV exports are available from the page header.',
        className: 'audit-catalog-section'
    })}
    </div>
  `;
    container.innerHTML = SectionUI.renderOperatorFrame({
        title: 'Audit Logs',
        kicker: 'System',
        subtitle: 'Review administrative actions, forensic compliance events, and control plane audit records.',
        actions: `${renderRefreshButton()}${renderExportButton()}`,
        content,
        className: 'audit-operator-frame'
    });
}
function renderAuditRow(log) {
    const sourceIP = log.ip_address || '-';
    const sourceDetail = log.ip_address_source
        ? `${log.ip_address_source}${log.peer_ip_address ? ` via ${log.peer_ip_address}` : ''}`
        : '';
    const activity = describeAuditActivity(log);
    return [
        `<time class="audit-event-time">${formatAuditTime(log.created_at)}</time>`,
        `<div class="audit-actor"><span class="audit-actor-icon" aria-hidden="true">${SectionUI.icons.userCheck}</span><span class="audit-actor-name">${escapeHTML(log.username || 'System')}</span></div>`,
        `<div class="audit-activity"><strong>${escapeHTML(activity.title)}</strong><span>${escapeHTML(activity.detail)}</span></div>`,
        `<span class="audit-source-ip" title="${escapeHTML(sourceDetail || sourceIP)}">${escapeHTML(sourceIP)}</span>`
    ];
}
function describeAuditActivity(log) {
    const action = log.action || 'system:event';
    const titles = {
        'auth:login_success': 'Signed in',
        'auth:login_failure': 'Sign-in failed',
        'auth:logout': 'Signed out',
        'auth:mfa_enable': 'Enabled multi-factor authentication',
        'auth:mfa_disable': 'Disabled multi-factor authentication',
        'auth:mfa_failure': 'Multi-factor authentication failed',
        'alerts:read': 'Viewed alerts'
    };
    const details = {
        'auth:login_success': 'Administrator session established.',
        'auth:logout': 'Administrator session ended.',
        'auth:mfa_enable': 'Multi-factor authentication is now enabled.',
        'auth:mfa_disable': 'Multi-factor authentication is now disabled.'
    };
    const rawDetail = log.details || log.metadata || '';
    const resource = log.resource && !isOpaqueAuditResource(log.resource) ? `Affected: ${log.resource}` : '';
    return {
        title: titles[action] || formatAuditAction(action),
        detail: details[action] || rawDetail || resource || 'No additional context was recorded.'
    };
}
function formatAuditAction(action) {
    return action
        .split(':')
        .filter(Boolean)
        .map(part => part.replace(/[_-]+/g, ' ').replace(/\b\w/g, character => character.toUpperCase()))
        .join(': ') || 'System event';
}
function isOpaqueAuditResource(resource) {
    return /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(resource);
}
function renderAuditFilters() {
    return `
		<form data-audit-filter-form class="audit-filter-toolbar">
			<label class="audit-filter-field" for="audit-filter-action"><span>Action</span><input id="audit-filter-action" class="settings-input" name="action" value="${escapeHTML(auditState.filters.action)}" maxlength="128" placeholder="auth:login_success"></label>
			<label class="audit-filter-field" for="audit-filter-actor"><span>Actor</span><input id="audit-filter-actor" class="settings-input" name="actor" value="${escapeHTML(auditState.filters.actor)}" maxlength="128" placeholder="security-operator"></label>
			<fieldset class="audit-filter-range"><legend>Time range</legend><div class="audit-filter-range-controls"><input id="audit-filter-from" class="settings-input" name="from" type="datetime-local" value="${escapeHTML(auditState.filters.from)}" aria-label="From local time"><span class="audit-filter-range-separator" aria-hidden="true">to</span><input id="audit-filter-to" class="settings-input" name="to" type="datetime-local" value="${escapeHTML(auditState.filters.to)}" aria-label="To local time"></div></fieldset>
			<div class="audit-filter-actions"><button class="btn btn-sm" type="submit">Apply</button><button class="btn btn-outline btn-sm" type="button" data-audit-action="clear-filters">Clear</button></div>
		</form>`;
}
function renderAuditPagination(meta) {
    const previousDisabled = auditState.pageIndex <= 0 ? ' disabled' : '';
    const nextDisabled = !meta?.next_cursor ? ' disabled' : '';
    const pageSizeOptions = auditPageSizes
        .map(size => `<option value="${size}"${size === auditState.pageSize ? ' selected' : ''}>${size}</option>`)
        .join('');
    const count = meta?.count || 0;
    const start = count ? (auditState.pageIndex * auditState.pageSize) + 1 : 0;
    const end = start ? start + count - 1 : 0;
    return `<nav class="security-events-pagination" aria-label="Audit log pages"><span class="security-events-pagination-summary">${start ? `Showing ${start}–${end}` : 'No audit records'}</span><span class="security-events-pagination-controls"><button type="button" class="btn btn-sm btn-outline" data-audit-action="previous"${previousDisabled}>Previous</button><span class="security-events-pagination-page">Page ${auditState.pageIndex + 1}</span><button type="button" class="btn btn-sm btn-outline" data-audit-action="next"${nextDisabled}>Next</button><label class="security-events-page-size-label">Rows per page<select class="security-events-page-size" data-audit-page-size aria-label="Rows per page">${pageSizeOptions}</select></label></span></nav>`;
}
function renderRefreshButton() {
    return `
    <button type="button" class="btn btn-outline" data-action="refresh-audit-logs">
      <span class="audit-button-icon" aria-hidden="true">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12a9 9 0 0 1-15.6 6.1L3 16"></path>
          <path d="M3 22v-6h6"></path>
          <path d="M3 12a9 9 0 0 1 15.6-6.1L21 8"></path>
          <path d="M21 2v6h-6"></path>
        </svg>
      </span>
      Refresh
    </button>
  `;
}
function renderExportButton() {
    return '<button type="button" class="btn btn-outline" data-audit-action="export">Export CSV</button>';
}
function formatAuditTime(value) {
    if (!value)
        return 'Unknown';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Unknown' : escapeHTML(date.toLocaleString());
}
function escapeHTML(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
