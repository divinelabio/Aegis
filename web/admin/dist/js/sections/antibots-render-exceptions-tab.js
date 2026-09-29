import { SectionUI } from './ui-components.js';
const EXCEPTION_FIELDS = [
    {
        key: 'ips',
        label: 'IPs',
        title: 'IP / CIDR',
        modalLabel: 'IP address or CIDR',
        icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10A15.3 15.3 0 0 1 8 12a15.3 15.3 0 0 1 4-10z"/></svg>`,
        placeholder: '203.0.113.10 or 198.51.100.0/24',
        accent: 'success',
    },
    {
        key: 'paths',
        label: 'Paths',
        title: 'Path',
        modalLabel: 'Request path',
        icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`,
        placeholder: '/health or /api/webhooks/stripe',
        accent: 'primary',
    },
    {
        key: 'methods',
        label: 'Methods',
        title: 'HTTP Method',
        modalLabel: 'HTTP method',
        icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`,
        placeholder: 'OPTIONS',
        accent: 'warning',
    },
    {
        key: 'headers',
        label: 'Headers',
        title: 'Header Pair',
        modalLabel: 'Header name and value',
        icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>`,
        placeholder: 'X-Internal-Check:true',
        accent: 'secondary',
    },
    {
        key: 'user_agents',
        label: 'User Agents',
        title: 'User Agent',
        modalLabel: 'User agent',
        icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4M8 16h0M16 16h0"/></svg>`,
        placeholder: 'UptimeRobot',
        accent: 'danger',
    },
];
/* ── helpers ────────────────────────────────────────────────────── */
function esc(value) {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
function exceptionList(whitelist, key) {
    const value = whitelist[key];
    return Array.isArray(value)
        ? value.filter((entry) => typeof entry === 'string' && entry.trim() !== '')
        : [];
}
function exceptionEntries(whitelist) {
    return EXCEPTION_FIELDS.flatMap((field) => exceptionList(whitelist, field.key).map((value) => ({ key: field.key, value, field })));
}
/* ── icons ──────────────────────────────────────────────────────── */
const ICON_INFO = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
const ICON_PLUS = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 5v14M5 12h14"/></svg>`;
const ICON_TRASH = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v5M14 11v5"/></svg>`;
/* exception table */
function renderExceptionRow(entry, index) {
    const field = entry.field;
    const key = String(entry.key);
    const value = entry.value;
    const displayValue = value.length > 96 ? `${value.slice(0, 93)}...` : value;
    return `
    <tr class="exc-table-row">
        <td class="exc-table-cell exc-table-index">
            <span class="exc-row-num">${index + 1}</span>
        </td>
        <td class="exc-table-cell exc-table-type">
            <div class="exc-type-pill exc-type-${field.accent}">
                <span class="exc-type-icon">${field.icon}</span>
                <span>${esc(field.title)}</span>
            </div>
        </td>
        <td class="exc-table-cell exc-table-values">
            <code class="exc-value-code" title="${esc(value)}">${esc(displayValue)}</code>
        </td>
        <td class="exc-table-cell exc-table-action">
            <button
                class="exc-icon-btn exc-danger-btn"
                type="button"
                data-antibot-action="remove-exception"
                data-antibot-key="${esc(key)}"
                data-antibot-value="${esc(value)}"
                title="Remove exception"
                aria-label="Remove exception">
                ${ICON_TRASH}
            </button>
        </td>
    </tr>`;
}
function renderExceptionsTable(whitelist) {
    const entries = exceptionEntries(whitelist);
    const rows = entries.length
        ? entries.map((entry, index) => renderExceptionRow(entry, index)).join('')
        : `<tr class="exc-empty-table-row">
            <td colspan="4">
                <div class="exc-empty-state">
                    ${ICON_INFO}
                    <div>
                        <strong>No exceptions yet</strong>
                        <span>Add an IP, path, method, header, or user agent to bypass Bot Protection for trusted traffic.</span>
                    </div>
                </div>
            </td>
        </tr>`;
    return `
    <div class="exc-table-card">
        <div class="exc-table-toolbar">
            <div class="exc-table-toolbar-title">
                <span>${entries.length}</span>
                <strong>${entries.length === 1 ? 'exception' : 'exceptions'}</strong>
            </div>
            <button class="btn btn-primary exc-add-btn" type="button" data-antibot-action="show-add-exception-modal">
                ${ICON_PLUS}
                Add Exception
            </button>
        </div>
        <table class="exc-table">
            <thead>
                <tr>
                    <th class="exc-th-index">#</th>
                    <th>Type</th>
                    <th>Value</th>
                    <th class="exc-th-action">Action</th>
                </tr>
            </thead>
            <tbody>
                ${rows}
            </tbody>
        </table>
    </div>`;
}
function renderAddExceptionModal(open) {
    if (!open)
        return '';
    return `
    <div class="modal-overlay open is-open is-visible" data-antibot-action="close-self-if-overlay" data-antibot-close-action="close-exception-modal">
        <div class="modal-content section-modal w-500" role="dialog" aria-modal="true" aria-labelledby="bot-exception-modal-title">
            <div class="modal-header">
                <h3 id="bot-exception-modal-title">Bot Protection: Add Exception</h3>
                <button type="button" class="modal-close" data-antibot-action="close-exception-modal" aria-label="Close dialog">&times;</button>
            </div>
            <div class="modal-body section-modal">
                <div class="mb-24">
                    <div class="text-sm font-600 mb-12">Type</div>
                    <div class="exc-type-options" role="radiogroup" aria-label="Exception type">
                        ${EXCEPTION_FIELDS.map((field, index) => `
                            <label class="exc-type-option exc-type-${field.accent}">
                                <input
                                    type="radio"
                                    name="bot-exception-type"
                                    value="${esc(String(field.key))}"
                                    ${index === 0 ? 'checked' : ''}
                                >
                                <span class="exc-type-option-icon">${field.icon}</span>
                                <span class="text-sm font-500">${esc(field.title)}</span>
                            </label>
                        `).join('')}
                    </div>
                </div>
                <div class="mb-24">
                    <label class="text-sm font-600 mb-12 block">Value</label>
                    <input id="bot-exception-value" class="section-input w-100" type="text" placeholder="Enter exception value" autocomplete="off" spellcheck="false">
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-outline" type="button" data-antibot-action="close-exception-modal">Cancel</button>
                <button class="btn btn-primary" type="button" data-antibot-action="save-exception-value">
                    ${ICON_PLUS}
                    Add Exception
                </button>
            </div>
        </div>
    </div>`;
}
/* ── standardized metric strip ───────────────────────────────────── */
function renderExceptionsMetricStrip(whitelist) {
    const ipCount = exceptionList(whitelist, 'ips').length;
    const pathCount = exceptionList(whitelist, 'paths').length;
    const methodCount = exceptionList(whitelist, 'methods').length;
    const headerCount = exceptionList(whitelist, 'headers').length;
    const uaCount = exceptionList(whitelist, 'user_agents').length;
    const total = ipCount + pathCount + methodCount + headerCount + uaCount;
    return SectionUI.renderOperatorMetricStrip([
        {
            label: 'Total exceptions',
            value: total.toLocaleString(),
            sub: total === 1 ? '1 active bypass rule' : `${total.toLocaleString()} active bypass rules`,
            tone: 'neutral'
        },
        {
            label: 'IP & CIDR rules',
            value: ipCount.toLocaleString(),
            sub: ipCount === 1 ? '1 network target' : `${ipCount.toLocaleString()} network targets`,
            tone: 'neutral'
        },
        {
            label: 'Path & method rules',
            value: (pathCount + methodCount).toLocaleString(),
            sub: `${pathCount} ${pathCount === 1 ? 'path' : 'paths'}, ${methodCount} ${methodCount === 1 ? 'method' : 'methods'}`,
            tone: 'neutral'
        },
        {
            label: 'Header & Agent rules',
            value: (headerCount + uaCount).toLocaleString(),
            sub: `${headerCount} ${headerCount === 1 ? 'header' : 'headers'}, ${uaCount} ${uaCount === 1 ? 'user agent' : 'user agents'}`,
            tone: 'neutral'
        }
    ], 'bot-exceptions-metrics mb-16');
}
/* ── main export ────────────────────────────────────────────────── */
export function renderAntibotExceptionsTab(config, renderSectionHeader, renderSaveButton, isAddExceptionModalOpen = false) {
    const whitelist = config.whitelist || {};
    return `
        ${renderSectionHeader('shield', 'Exceptions & Allowlist', 'Traffic matching these rules bypasses all managed Bot Protection decisions.')}
        ${renderExceptionsMetricStrip(whitelist)}

        ${renderExceptionsTable(whitelist)}

        <div class="exc-save-row">
            ${renderSaveButton()}
        </div>

        ${renderAddExceptionModal(isAddExceptionModalOpen)}
    `;
}
