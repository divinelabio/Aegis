import { SectionUI } from './ui-components.js';
function escapeRuleModalText(value) {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
export function closeAntibotRuleModal(getNode) {
    const modal = getNode('rule-modal');
    if (!modal)
        return;
    modal.classList.remove('open', 'is-visible');
}
export function promptDeleteAntibotRule(ruleName, onConfirm) {
    const safeRuleName = escapeRuleModalText(ruleName || 'Untitled rule');
    SectionUI.openConfirmModal('Delete Rule', `<div class="section-confirm-rule-name">${safeRuleName}</div><p>Deleting this bot protection rule removes it from evaluation immediately. This action cannot be undone.</p>`, 'Delete', 'var(--danger)', onConfirm);
}
export function confirmDeleteAntibotRuleAt(rules, idx) {
    if (!Number.isFinite(idx) || idx < 0 || idx >= rules.length)
        return false;
    rules.splice(idx, 1);
    SectionUI.closeModal();
    return true;
}
export function moveAntibotRule(rules, idx, direction) {
    const newIdx = idx + direction;
    if (newIdx < 0 || newIdx >= rules.length)
        return false;
    const temp = rules[idx];
    rules[idx] = rules[newIdx];
    rules[newIdx] = temp;
    rules.forEach((rule, index) => {
        rule.priority = (index + 1) * 10;
    });
    return true;
}
export function toggleAntibotRuleStatus(rules, idx) {
    if (!rules[idx])
        return false;
    rules[idx].enabled = !rules[idx].enabled;
    return true;
}
