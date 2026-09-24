import { SectionUI } from './ui-components.js';
function getRuleConditionIcon(field) {
    const conditionField = (field || '').toLowerCase();
    if (conditionField === 'ip' || conditionField === 'asn' || conditionField === 'country') {
        return '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>';
    }
    if (conditionField.includes('header') || conditionField.includes('cookie') || conditionField.includes('agent')) {
        return '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';
    }
    if (conditionField === 'bot_score') {
        return '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>';
    }
    return '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>';
}
function getRuleActionIcon(action) {
    if (action === 'block') {
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>';
    }
    if (action === 'allow') {
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
    }
    if (action === 'challenge') {
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
    }
    return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M4 12h16"/><path d="M12 4v16"/></svg>';
}
function normalizeRuleAction(action) {
    const actionMap = { 0: 'allow', 1: 'block', 2: 'challenge', 5: 'log' };
    return typeof action === 'number' ? actionMap[action] || 'block' : (action || 'block');
}
function renderBotScopePills(rule) {
    const pills = [];
    const applyGood = rule.apply_to_good_bots;
    const applyAI = rule.apply_to_ai_crawlers;
    // Only show a pill when the rule is SKIPPING that bot type (unchecked)
    if (applyGood === false) {
        pills.push(`<span class="section-rule-scope-pill skip" title="Skips verified good bots">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            Skip good bots
        </span>`);
    }
    if (applyAI === false) {
        pills.push(`<span class="section-rule-scope-pill skip" title="Skips AI crawlers">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/></svg>
            Skip AI crawlers
        </span>`);
    }
    return pills.join('');
}
export function renderAntibotRulesTab(rules, escapeHTML, renderSectionHeader) {
    void renderSectionHeader;
    const totalRules = rules.length;
    const enabledRules = rules.filter((rule) => rule.enabled !== false).length;
    const disabledRules = totalRules - enabledRules;
    const matchTotal = rules.reduce((total, rule) => total + (rule.conditions || []).length + (rule.expression ? 1 : 0), 0);
    const tableRows = rules.map((rule, idx) => {
        const isFirst = idx === 0;
        const isLast = idx === rules.length - 1;
        const actStr = normalizeRuleAction(rule.action);
        const conditionCount = (rule.conditions || []).length + (rule.expression ? 1 : 0);
        const matchSummary = conditionCount === 1 ? '1 match condition' : `${conditionCount} match conditions`;
        const ruleName = String(rule.name || `Rule ${idx + 1}`);
        const ruleLabel = escapeHTML(ruleName);
        const matchChips = `
            <div class="section-rule-conditions bot-rules-table-matches">
                ${rule.expression ? `
                    <span class="section-rule-condition-chip">
                        <span class="section-rule-condition-icon">${getRuleConditionIcon('expression')}</span>
                        <span class="section-rule-condition-field">expression</span>
                        <span class="section-rule-condition-value">${escapeHTML(rule.expression)}</span>
                    </span>
                ` : ''}
                ${(rule.conditions || []).map((c) => {
            const iconSvg = getRuleConditionIcon(c.field || '');
            return `
                    <span class="section-rule-condition-chip">
                        <span class="section-rule-condition-icon">${iconSvg}</span>
                        <span class="section-rule-condition-field">${escapeHTML(c.field || '')}</span>
                        <span class="section-rule-condition-operator">${escapeHTML(c.operator || '')}</span>
                        <span class="section-rule-condition-value">${escapeHTML(c.value || 'N/A')}</span>
                    </span>`;
        }).join('')}
                ${!rule.expression && !(rule.conditions || []).length ? '<span class="bot-rules-muted">No match criteria</span>' : ''}
            </div>`;
        const priorityControls = `
            <div class="section-rule-priority bot-rules-priority-control" aria-label="Priority ${idx + 1}">
                <button type="button" class="section-rule-priority-btn ${isFirst ? 'disabled' : ''}"
                        data-antibot-action="move-rule" data-antibot-index="${idx}" data-antibot-value="-1" title="Move rule higher" aria-label="Move rule higher" ${isFirst ? 'disabled' : ''}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m18 15-6-6-6 6"/></svg>
                </button>
                <div class="section-rule-priority-index">${idx + 1}</div>
                <button type="button" class="section-rule-priority-btn ${isLast ? 'disabled' : ''}"
                        data-antibot-action="move-rule" data-antibot-index="${idx}" data-antibot-value="1" title="Move rule lower" aria-label="Move rule lower" ${isLast ? 'disabled' : ''}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m6 9 6 6 6-6"/></svg>
                </button>
            </div>`;
        const actionBadge = `
            <span class="section-rule-action-badge ${actStr}">
                ${getRuleActionIcon(actStr)}
                ${escapeHTML(actStr)}
            </span>`;
        const enabledSwitch = `
            <label class="section-switch section-rule-toggle bot-rules-status-toggle" title="${rule.enabled !== false ? 'Disable rule' : 'Enable rule'}">
                <input type="checkbox" ${rule.enabled !== false ? 'checked' : ''} aria-label="${rule.enabled !== false ? 'Disable' : 'Enable'} ${ruleLabel}" data-antibot-action="toggle-rule-status" data-antibot-index="${idx}">
                <span class="switch-slider"></span>
            </label>`;
        const actions = `<div class="operator-control-actions bot-rules-table-actions">${SectionUI.renderActionMenu({
            id: `bot-rule-actions-${idx}`,
            ariaLabel: `Actions for ${ruleName}`,
            label: 'More',
            items: [
                { label: 'Edit rule', attrs: `data-antibot-action="edit-rule" data-antibot-index="${idx}"` },
                { label: 'Delete rule', attrs: `data-antibot-action="delete-rule" data-antibot-index="${idx}"`, tone: 'danger' }
            ],
            className: 'bot-rules-action-menu'
        })}</div>`;
        const ruleCell = `
            <div class="bot-rules-table-rule">
                <span class="bot-rules-table-rule-icon" aria-hidden="true">${SectionUI.icons.list || SectionUI.icons.shield}</span>
                <div class="bot-rules-table-rule-copy">
                    <div class="bot-rules-table-rule-title">
                        <button type="button" class="btn-link" data-antibot-action="edit-rule" data-antibot-index="${idx}">${ruleLabel}</button>
                    </div>
                    <div class="bot-rules-table-rule-meta">
                        <span>${escapeHTML(matchSummary)}</span>
                        ${renderBotScopePills(rule)}
                    </div>
                </div>
            </div>`;
        return [ruleCell, matchChips, actionBadge, priorityControls, enabledSwitch, actions];
    });
    const table = SectionUI.renderEnterpriseTable({
        columns: ['Rule', 'Match', 'Action', 'Priority', 'Enabled', 'Actions'],
        rows: tableRows,
        emptyTitle: 'No custom rules',
        emptyMessage: 'Create a rule to allow, challenge, log, or block matching bot traffic.',
        emptyAction: '<button type="button" class="btn btn-outline btn-sm" data-antibot-action="show-add-rule-modal">Create First Rule</button>',
        className: 'operator-table-panel bot-rules-enterprise-table'
    });
    return SectionUI.renderOperatorSection('Custom Rules Engine', `
            <div class="bot-rules-table-surface">
                <div class="bot-rules-table-toolbar" aria-label="Custom rule summary">
                    <div class="bot-rules-table-metrics">
                        <span><strong>${totalRules}</strong> ${totalRules === 1 ? 'rule' : 'rules'}</span>
                        <span><strong>${enabledRules}</strong> enabled</span>
                        <span><strong>${disabledRules}</strong> disabled</span>
                        <span><strong>${matchTotal}</strong> ${matchTotal === 1 ? 'matcher' : 'matchers'}</span>
                    </div>
                    <span class="bot-rules-table-note">Rules run in priority order before managed bot actions.</span>
                </div>
                ${table}
                ${totalRules ? SectionUI.renderTableScrollHint() : ''}
            </div>
        `, {
        subtitle: 'Define high-precision traffic control rules based on headers, IPs, cookies, and behavioral scores. Rules are evaluated in priority order.',
        actions: `
            <button type="button" class="btn btn-primary" data-antibot-action="show-add-rule-modal">
                <span class="section-rules-hero-plus" aria-hidden="true">+</span> Create Rule
            </button>
        `,
        className: 'bot-rules-overview-section bot-rules-table-section'
    });
}
