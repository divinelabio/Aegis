import { SectionUI } from './ui-components.js';
export function createEnsureAntibotBindings(deps) {
    let initialized = false;
    const dirtyActions = new Set([
        'apply-mode-preset',
        'set-field',
        'move-rule',
        'toggle-rule-status',
        'delete-rule',
        'save-new-rule',
        'select-rule-action',
        'toggle-good-bot',
        'set-ai-rule',
        'apply-exception-list',
        'remove-exception',
        'save-exception-value',
        'add-exception-value',
        'apply-advanced-preset'
    ]);
    return () => {
        if (initialized)
            return;
        initialized = true;
        document.addEventListener('click', (event) => {
            if (!(event.target instanceof Element))
                return;
            const target = event.target.closest('[data-antibot-action]');
            if (!target)
                return;
            const action = target.dataset.antibotAction || '';
            const value = target.dataset.antibotValue || '';
            switch (action) {
                case 'switch-tab':
                    deps.switchTab(value);
                    break;
                case 'apply-mode-preset':
                    deps.applyModePreset(value);
                    break;
                case 'set-field': {
                    const path = target.dataset.antibotFieldPath || '';
                    if (!path)
                        break;
                    deps.updateField(path, value);
                    if (target.dataset.antibotRender === 'true')
                        deps.render();
                    break;
                }
                case 'move-rule': {
                    const idx = Number.parseInt(target.dataset.antibotIndex || '', 10);
                    const direction = Number.parseInt(value, 10);
                    if (Number.isFinite(idx) && Number.isFinite(direction))
                        deps.moveRule(idx, direction);
                    break;
                }
                case 'edit-rule': {
                    const idx = Number.parseInt(target.dataset.antibotIndex || '', 10);
                    if (Number.isFinite(idx))
                        deps.editRule(idx);
                    break;
                }
                case 'toggle-rule-status': {
                    const idx = Number.parseInt(target.dataset.antibotIndex || '', 10);
                    if (Number.isFinite(idx))
                        deps.toggleRuleStatus(idx);
                    break;
                }
                case 'delete-rule': {
                    const idx = Number.parseInt(target.dataset.antibotIndex || '', 10);
                    if (Number.isFinite(idx))
                        deps.deleteRule(idx);
                    break;
                }
                case 'show-add-rule-modal':
                    deps.showAddRuleModal();
                    break;
                case 'close-rule-modal':
                    deps.closeRuleModal();
                    break;
                case 'close-self-if-overlay':
                    if (event.target === target) {
                        const closeAction = target.dataset.antibotCloseAction || '';
                        if (closeAction === 'close-rule-modal')
                            deps.closeRuleModal();
                        if (closeAction === 'close-good-bots-modal')
                            deps.closeGoodBotsModal();
                        if (closeAction === 'close-exception-modal')
                            deps.closeExceptionModal();
                    }
                    break;
                case 'save-new-rule':
                    deps.saveNewRule();
                    break;
                case 'select-rule-action':
                    deps.selectAction(value);
                    break;
                case 'show-good-bots-modal':
                    deps.showGoodBotsModal();
                    break;
                case 'close-good-bots-modal':
                    deps.closeGoodBotsModal();
                    break;
                case 'toggle-good-bot':
                    deps.toggleGoodBot(value);
                    break;
                case 'set-ai-rule': {
                    const botName = target.dataset.antibotBot || '';
                    if (!botName)
                        break;
                    deps.updateAIRule(botName, value);
                    deps.render();
                    break;
                }
                case 'save-config':
                    void Promise.resolve(deps.saveConfig()).then(saved => {
                        if (saved)
                            SectionUI.markSaveActionBarClean('data-antibot-action');
                    });
                    break;
                case 'reset-config':
                    void deps.loadConfig().then(loaded => {
                        if (!loaded)
                            return;
                        deps.render();
                        SectionUI.markSaveActionBarClean('data-antibot-action');
                    });
                    break;
                case 'apply-analytics-filters':
                    void deps.applyAnalyticsFilters();
                    break;
                case 'reset-analytics-filters':
                    void deps.resetAnalyticsFilters();
                    break;
                case 'refresh-analytics':
                    void deps.refreshAnalytics();
                    break;
                case 'toggle-analytics-event':
                    deps.toggleAnalyticsEvent(value);
                    break;
                case 'create-rule-from-event':
                    void deps.createRuleFromEvent(target.dataset.antibotRuleKind || '', target.dataset.antibotRuleTarget || '', target.dataset.antibotRuleAction || 'block');
                    break;
                case 'apply-advanced-preset':
                    void deps.applyAdvancedPreset(target.dataset.antibotScope || '', value);
                    break;
                case 'apply-exception-list': {
                    const key = value;
                    const textarea = deps.getNode(`bot-exception-${key}`);
                    if (textarea instanceof HTMLTextAreaElement) {
                        deps.applyExceptionList(key, textarea.value);
                    }
                    break;
                }
                case 'remove-exception': {
                    const exKey = target.dataset.antibotKey || '';
                    const exValue = target.dataset.antibotValue || '';
                    if (exKey && exValue) {
                        void deps.removeExceptionValue(exKey, exValue);
                    }
                    break;
                }
                case 'show-add-exception-modal':
                    deps.showAddExceptionModal();
                    break;
                case 'close-exception-modal':
                    deps.closeExceptionModal();
                    break;
                case 'save-exception-value':
                    void deps.saveExceptionFromModal();
                    break;
                case 'add-exception-value':
                    void deps.addExceptionValue(target.dataset.antibotExceptionKey || '', target.dataset.antibotExceptionValue || '');
                    break;
                default:
                    break;
            }
            if (dirtyActions.has(action)) {
                SectionUI.markSaveActionBarDirty('data-antibot-action');
            }
        });
        document.addEventListener('keydown', (event) => {
            if (event.key !== 'Enter' && event.key !== ' ')
                return;
            if (!(event.target instanceof Element))
                return;
            const target = event.target.closest('[data-antibot-action="switch-tab"][role="button"]');
            if (!target)
                return;
            event.preventDefault();
            deps.switchTab(target.dataset.antibotValue || 'overview');
        });
        document.addEventListener('change', (event) => {
            const target = event.target;
            if (!(target instanceof HTMLInputElement || target instanceof HTMLSelectElement || target instanceof HTMLTextAreaElement))
                return;
            const changeAction = target.dataset.antibotChangeAction || '';
            if (changeAction === 'toggle-rule-fields') {
                deps.toggleRuleFields();
            }
            const path = target.dataset.antibotFieldPath;
            if (!path)
                return;
            deps.updateField(path, deps.parseDatasetValue(target));
            if (target.dataset.antibotRender === 'true') {
                deps.render();
            }
            SectionUI.markSaveActionBarDirty('data-antibot-action');
        });
        document.addEventListener('input', (event) => {
            const target = event.target;
            if (!(target instanceof HTMLInputElement || target instanceof HTMLSelectElement || target instanceof HTMLTextAreaElement))
                return;
            const inputAction = target.dataset.antibotInputAction || '';
            if (inputAction === 'filter-good-bots') {
                deps.filterGoodBots(target.value);
                return;
            }
        });
    };
}
