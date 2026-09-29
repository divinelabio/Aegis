/**
 * WAF Exclusions (Community)
 * Scoped false-positive rule exclusions, paths, parameters, IP CIDRs, and expiration rules.
 */
import { SectionUI } from '../ui-components.js';
import { escapeWafHtml } from '../waf-runtime-helpers.js';
import { WAFExclusion, WAFExclusionScope } from './types.js';

export function isExclusionExpired(exclusion: WAFExclusion): boolean {
    if (!exclusion.expires_at) return false;
    const expires = new Date(exclusion.expires_at).getTime();
    return !Number.isNaN(expires) && expires < Date.now();
}

export function renderExclusionsTab(
    exclusions: WAFExclusion[],
    exclusionQuery: string,
    exclusionScope: WAFExclusionScope,
    renderStatusCard: (title: string, desc: string, icon: string, enabled: boolean, actions: string, status: string) => string
): string {
    const list = exclusions || [];
    const count = list.length;
    const activeCount = list.filter(e => e.enabled !== false && !isExclusionExpired(e)).length;
    const expiredCount = list.filter(e => isExclusionExpired(e)).length;

    const filtered = list.filter(ex => {
        if (exclusionQuery) {
            const query = exclusionQuery.toLowerCase();
            const matchesRule = (ex.rule_id || '').toLowerCase().includes(query);
            const matchesPath = (ex.path_pattern || '').toLowerCase().includes(query);
            const matchesComment = (ex.comment || '').toLowerCase().includes(query);
            if (!matchesRule && !matchesPath && !matchesComment) return false;
        }
        if (exclusionScope === 'global') return !ex.rule_id;
        if (exclusionScope === 'rule') return Boolean(ex.rule_id);
        if (exclusionScope === 'active') return ex.enabled !== false && !isExclusionExpired(ex);
        if (exclusionScope === 'inactive') return ex.enabled === false || isExclusionExpired(ex);
        return true;
    });

    const tableRows = filtered.map(ex => {
        const enabled = ex.enabled !== false;
        const expired = isExclusionExpired(ex);
        const scope = ex.rule_id ? `Rule ${escapeWafHtml(ex.rule_id)}` : 'Global';
        const condition = ex.path_pattern ? escapeWafHtml(ex.path_pattern) : 'All paths';
        const expires = ex.expires_at ? new Date(ex.expires_at).toLocaleDateString() : 'Never';
        return [
            `<div class="config-table-primary">${escapeWafHtml(ex.comment || ex.id)}</div><div class="config-table-sub">${escapeWafHtml(ex.id)}</div>`,
            `<span class="config-table-sub">${scope}</span>`,
            `<span class="config-table-sub config-table-code">${condition}</span>`,
            `<span class="config-table-sub ${expired ? 'text-danger' : ''}">${expires}</span>`,
            `<div class="config-table-actions">
                ${SectionUI.renderSwitch({
                    checked: enabled,
                    className: 'section-switch-sm',
                    attrs: `aria-label="${enabled ? 'Disable' : 'Enable'} Exclusion ${escapeWafHtml(ex.id)}" data-waf-action="toggle-exclusion" data-waf-value="${escapeWafHtml(ex.id)}"`
                })}
                <button type="button" class="btn btn-ghost btn-sm section-excl-delete-btn text-danger" data-waf-action="delete-exclusion" data-waf-value="${escapeWafHtml(ex.id)}" aria-label="Delete exclusion ${escapeWafHtml(ex.id)}">Delete</button>
            </div>`
        ];
    });

    return `
        ${renderStatusCard(
            'Rule Exclusions',
            'Create targeted exceptions when valid traffic is incorrectly detected.',
            'filter',
            expiredCount === 0,
            '',
            expiredCount > 0 ? 'Needs Review' : 'Active'
        )}
        <div class="config-list-stack">
            <div class="config-toolbar">
                <input type="text" class="section-input config-toolbar-search" value="${escapeWafHtml(exclusionQuery)}" data-waf-state="exclusionQuery" placeholder="Search exclusions">
                <select class="section-input config-toolbar-select" data-waf-state="exclusionScope">
                    <option value="all" ${exclusionScope === 'all' ? 'selected' : ''}>All Scopes</option>
                    <option value="global" ${exclusionScope === 'global' ? 'selected' : ''}>Global Only</option>
                    <option value="rule" ${exclusionScope === 'rule' ? 'selected' : ''}>Rule-Specific</option>
                    <option value="active" ${exclusionScope === 'active' ? 'selected' : ''}>Active</option>
                    <option value="inactive" ${exclusionScope === 'inactive' ? 'selected' : ''}>Inactive</option>
                </select>
                <div class="config-toolbar-spacer"></div>
                <button type="button" class="btn btn-primary btn-sm section-btn-inline" data-waf-action="show-exclusion-modal">Add Exclusion</button>
            </div>
            ${SectionUI.renderOperatorMetricStrip([
                {
                    label: 'Total exclusions',
                    value: count.toLocaleString(),
                    sub: count === 1 ? '1 configured rule' : `${count.toLocaleString()} configured rules`,
                    tone: 'neutral'
                },
                {
                    label: 'Active exceptions',
                    value: activeCount.toLocaleString(),
                    sub: activeCount === count && count > 0 ? 'All exceptions active' : `${activeCount.toLocaleString()} currently enforcing`,
                    tone: activeCount > 0 ? 'success' : 'neutral'
                },
                {
                    label: 'Expired rules',
                    value: expiredCount.toLocaleString(),
                    sub: expiredCount > 0 ? (expiredCount === 1 ? '1 expired exception' : `${expiredCount.toLocaleString()} expired exceptions`) : 'No expired exceptions',
                    tone: expiredCount > 0 ? 'danger' : 'neutral'
                },
                {
                    label: 'Filtered view',
                    value: filtered.length.toLocaleString(),
                    sub: filtered.length === count ? 'Showing all rules' : `${filtered.length.toLocaleString()} matching filters`,
                    tone: 'neutral'
                }
            ], 'firewall-exclusions-metrics')}
            ${SectionUI.renderEnterpriseTable({
                columns: ['Rule', 'Scope', 'Condition', 'Expires', 'Actions'],
                rows: tableRows,
                emptyTitle: 'No exclusions found',
                emptyMessage: 'Adjust the filters or add an exception for valid traffic that needs it.',
                emptyAction: '<button type="button" class="btn btn-primary btn-sm section-btn-inline" data-waf-action="show-exclusion-modal">Add Exclusion</button>',
                className: 'firewall-exclusions-table'
            })}
            <div id="exclusion-modal-container"></div>
        </div>
    `;
}
