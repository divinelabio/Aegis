/**
 * WAF Custom Rules (Community)
 * Visual rule builder, custom rule listings, rule target conditions, and CRUD editor.
 */
import { SectionUI } from '../ui-components.js';
import { escapeWafHtml } from '../waf-runtime-helpers.js';
export function renderCustomRulesList(rules) {
    const tableRows = (rules || []).map(rule => {
        const isEnabled = rule.enabled !== false;
        const isValid = rule.valid !== false;
        const expression = (rule.targets || []).map(target => {
            const zone = target.field ? `${target.zone}:${target.field}` : target.zone;
            const op = target.operator || '@rx';
            const pattern = target.patterns?.[0] || '';
            return `${target.negate ? 'NOT ' : ''}${zone} ${op} ${pattern}`.trim();
        }).join(' | ') || rule.message || 'No expression';
        return [
            `<div class="config-table-primary">${escapeWafHtml(rule.name)}</div><div class="config-table-sub">${escapeWafHtml(rule.id)}</div>`,
            `<span class="config-table-sub config-table-code">${escapeWafHtml(expression)}</span>`,
            `<span class="config-table-sub">${escapeWafHtml(rule.severity || 'medium')}</span>`,
            `<span class="config-table-sub">${escapeWafHtml(String(rule.score ?? '-'))}</span>`,
            `<div class="config-table-actions">
                <button type="button" class="btn btn-ghost btn-sm" data-waf-action="open-rule-editor" data-waf-value="${escapeWafHtml(rule.id)}">Edit</button>
                <button type="button" class="btn btn-ghost btn-sm text-danger" data-waf-action="delete-rule" data-waf-value="${escapeWafHtml(rule.id)}">Delete</button>
                ${SectionUI.renderSwitch({
                checked: isEnabled,
                className: 'section-switch-sm',
                attrs: `aria-label="${isEnabled ? 'Disable' : 'Enable'} ${escapeWafHtml(rule.name || rule.id)}" data-waf-action="toggle-custom-rule" data-waf-value="${escapeWafHtml(rule.id)}" ${isValid ? '' : 'disabled title="Repair this rule before enabling it"'}`
            })}
            </div>`
        ];
    });
    return SectionUI.renderEnterpriseTable({
        columns: ['Name', 'Expression', 'Severity', 'Score', 'Actions'],
        rows: tableRows,
        emptyTitle: 'No custom rules',
        emptyMessage: 'Create a rule for an application-specific protection need.',
        className: 'firewall-custom-rules-table'
    });
}
export function renderRuleEditor(editingRule, renderVisualBuilder) {
    const rule = editingRule;
    const isEdit = !!rule;
    const title = isEdit ? 'Edit Custom Rule' : 'Create Custom Rule';
    return `
        ${SectionUI.renderOperatorBackButton({
        label: 'Back to Rules',
        attrs: 'data-waf-action="cancel-editor"'
    })}
        <div class="card section-panel mb-24">
            <div class="flex justify-between align-center">
                <div class="flex align-center gap-16">
                    <div class="p-10 rounded-8 bg-depth bordered text-main">
                        ${SectionUI.icons.edit}
                    </div>
                    <div>
                        <h4 class="m-0 mb-4 text-18 font-600 text-main">${title}</h4>
                        <p class="m-0 text-13 text-muted">${isEdit ? 'Update how this rule identifies and handles requests.' : 'Create a rule for a specific application security need.'}</p>
                    </div>
                </div>
            </div>
        </div>

        ${renderVisualBuilder(rule)}

        <div class="section-editor-footer">
            <button type="button" class="btn btn-outline btn-sm section-btn-inline" data-waf-action="cancel-editor">
                ${SectionUI.icons.x || ''} Cancel
            </button>
            <button type="button" class="btn btn-primary btn-sm section-btn-inline" data-waf-action="submit-custom-rule" data-waf-value="${isEdit}">
                ${SectionUI.icons.check} ${isEdit ? 'Update Rule' : 'Create Rule'}
            </button>
        </div>
    `;
}
