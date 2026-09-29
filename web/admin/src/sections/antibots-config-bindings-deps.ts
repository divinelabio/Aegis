import type { AntibotModeName } from './antibots-config-shared.js';

type AntibotsBindingsRuntime = {
    switchTab(id: string): void;
    applyModePreset(modeName: AntibotModeName): void;
    updateField(path: string, value: unknown): void;
    render(): void;
    moveRule(index: number, direction: number): void;
    editRule(index: number): void;
    toggleRuleStatus(index: number): void;
    deleteRule(index: number): void;
    showAddRuleModal(): void;
    closeRuleModal(): void;
    closeGoodBotsModal(): void;
    saveNewRule(): void;
    selectAction(action: string): void;
    showGoodBotsModal(): void;
    toggleGoodBot(bot: string): void;
    updateAIRule(botName: string, action: string): void;
    saveConfig(): Promise<boolean> | boolean;
    loadConfig(): Promise<boolean>;
    toggleRuleFields(): void;
    filterGoodBots(query: string): void;
    applyAnalyticsFilters(): Promise<unknown> | void;
    resetAnalyticsFilters(): Promise<unknown> | void;
    refreshAnalytics(): Promise<unknown> | void;
    toggleAnalyticsEvent(eventId: string): void;
    createRuleFromEvent(kind: string, target: string, action: string): Promise<unknown> | void;
    applyExceptionList(key: string, value: string): void;
    showAddExceptionModal(): void;
    closeExceptionModal(): void;
    addExceptionValue(key: string, value: string): Promise<unknown> | void;
    saveExceptionFromModal(): Promise<unknown> | void;
    removeExceptionValue(key: string, value: string): Promise<unknown> | void;
    applyAdvancedPreset(scope: string, preset: string): Promise<unknown> | void;
};

type AntibotsBindingsDepsHelpers = {
    isModeName(value: string): value is AntibotModeName;
    parseDatasetValue(target: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement): unknown;
    getNode(id: string): HTMLElement | null;
};

export function createAntibotsBindingsDeps(
    runtime: AntibotsBindingsRuntime,
    helpers: AntibotsBindingsDepsHelpers
) {
    const bindRuntimeMethod = <T extends (...args: never[]) => unknown>(method: T): T =>
        method.bind(runtime) as T;

    const switchTab = bindRuntimeMethod(runtime.switchTab);
    const updateField = bindRuntimeMethod(runtime.updateField);
    const render = bindRuntimeMethod(runtime.render);
    const moveRule = bindRuntimeMethod(runtime.moveRule);
    const editRule = bindRuntimeMethod(runtime.editRule);
    const toggleRuleStatus = bindRuntimeMethod(runtime.toggleRuleStatus);
    const deleteRule = bindRuntimeMethod(runtime.deleteRule);
    const showAddRuleModal = bindRuntimeMethod(runtime.showAddRuleModal);
    const closeRuleModal = bindRuntimeMethod(runtime.closeRuleModal);
    const closeGoodBotsModal = bindRuntimeMethod(runtime.closeGoodBotsModal);
    const saveNewRule = bindRuntimeMethod(runtime.saveNewRule);
    const selectAction = bindRuntimeMethod(runtime.selectAction);
    const showGoodBotsModal = bindRuntimeMethod(runtime.showGoodBotsModal);
    const toggleGoodBot = bindRuntimeMethod(runtime.toggleGoodBot);
    const updateAIRule = bindRuntimeMethod(runtime.updateAIRule);
    const saveConfig = bindRuntimeMethod(runtime.saveConfig);
    const loadConfig = bindRuntimeMethod(runtime.loadConfig);
    const toggleRuleFields = bindRuntimeMethod(runtime.toggleRuleFields);
    const filterGoodBots = bindRuntimeMethod(runtime.filterGoodBots);
    const applyAnalyticsFilters = bindRuntimeMethod(runtime.applyAnalyticsFilters);
    const resetAnalyticsFilters = bindRuntimeMethod(runtime.resetAnalyticsFilters);
    const refreshAnalytics = bindRuntimeMethod(runtime.refreshAnalytics);
    const toggleAnalyticsEvent = bindRuntimeMethod(runtime.toggleAnalyticsEvent);
    const createRuleFromEvent = bindRuntimeMethod(runtime.createRuleFromEvent);
    const applyExceptionList = bindRuntimeMethod(runtime.applyExceptionList);
    const showAddExceptionModal = bindRuntimeMethod(runtime.showAddExceptionModal);
    const closeExceptionModal = bindRuntimeMethod(runtime.closeExceptionModal);
    const addExceptionValue = bindRuntimeMethod(runtime.addExceptionValue);
    const saveExceptionFromModal = bindRuntimeMethod(runtime.saveExceptionFromModal);
    const removeExceptionValue = bindRuntimeMethod(runtime.removeExceptionValue);
    const applyAdvancedPreset = bindRuntimeMethod(runtime.applyAdvancedPreset);

    return {
        switchTab,
        applyModePreset: (modeName: string) => {
            if (helpers.isModeName(modeName)) runtime.applyModePreset(modeName);
        },
        updateField,
        render,
        moveRule,
        editRule,
        toggleRuleStatus,
        deleteRule,
        showAddRuleModal,
        closeRuleModal,
        closeGoodBotsModal,
        saveNewRule,
        selectAction,
        showGoodBotsModal,
        toggleGoodBot,
        updateAIRule,
        saveConfig,
        loadConfig,
        toggleRuleFields,
        filterGoodBots,
        applyAnalyticsFilters,
        resetAnalyticsFilters,
        refreshAnalytics,
        toggleAnalyticsEvent,
        createRuleFromEvent,
        applyExceptionList,
        showAddExceptionModal,
        closeExceptionModal,
        addExceptionValue,
        saveExceptionFromModal,
        removeExceptionValue,
        applyAdvancedPreset,
        parseDatasetValue: helpers.parseDatasetValue,
        getNode: helpers.getNode
    };
}
