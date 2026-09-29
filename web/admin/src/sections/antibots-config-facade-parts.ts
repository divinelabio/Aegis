import { AntibotsHelpers } from './antibots-helpers.js';
import type { AntibotAnalyticsState, AntibotConfigState, AntibotModeName, AntibotRule, AntibotStatsState } from './antibots-config-shared.js';
import { getAntibotIcon, renderAntibotSaveButton, showAntibotToast } from './antibots-runtime-helpers.js';

export type AntibotsRuntime = {
    currentTab: string;
    config: AntibotConfigState;
    rules: AntibotRule[];
    stats: AntibotStatsState;
    analytics: AntibotAnalyticsState;
    isLoading: boolean;
    loadError: string | null;
    isGoodBotModalOpen: boolean;
    isAddExceptionModalOpen: boolean;
    goodBotFilter: string;
    init(): Promise<void>;
    loadConfig(): Promise<boolean>;
    loadRules(): Promise<void>;
    loadStats(): Promise<void>;
    loadAnalytics(): Promise<void>;
    saveRules(): Promise<void>;
    saveConfig(options?: { successMessage?: string | null; errorMessage?: string }): Promise<boolean>;
    render(): void;
    renderTabContent(): string;
    renderOverview(): string;
    renderRules(): string;
    renderClassification(): string;
    renderAICrawlers(): string;
    renderExceptions(): string;
    switchTab(id: string): void;
    applyModePreset(modeName: AntibotModeName): void;
    updateField(path: string, value: unknown): void;
    moveRule(idx: number, direction: number): void;
    editRule(idx: number): void;
    toggleRuleStatus(idx: number): void;
    deleteRule(idx: number): void;
    showAddRuleModal(): void;
    closeRuleModal(): void;
    saveNewRule(): void;
    toggleRuleFields(): void;
    selectAction(action: string): void;
    showGoodBotsModal(): void;
    closeGoodBotsModal(): void;
    toggleGoodBot(bot: string): void;
    updateAIRule(botName: string, action: string): void;
    filterGoodBots(query: string): void;
    applyAnalyticsFilters(): Promise<void>;
    resetAnalyticsFilters(): Promise<void>;
    refreshAnalytics(): Promise<void>;
    toggleAnalyticsEvent(eventId: string): void;
    createRuleFromEvent(kind: string, target: string, action: string): Promise<void>;
    applyExceptionList(key: string, value: string): void;
    showAddExceptionModal(): void;
    closeExceptionModal(): void;
    addExceptionValue(key: string, value: string): Promise<void>;
    saveExceptionFromModal(): Promise<void>;
    removeExceptionValue(key: string, value: string): Promise<void>;
    applyAdvancedPreset(scope: string, preset: string): Promise<void>;
};

export function createAntibotsFacadeParts(runtime: AntibotsRuntime) {
    const bindRuntimeMethod = <T extends (...args: never[]) => unknown>(method: T): T =>
        method.bind(runtime) as T;

    const init = bindRuntimeMethod(runtime.init);
    const loadConfig = bindRuntimeMethod(runtime.loadConfig);
    const loadRules = bindRuntimeMethod(runtime.loadRules);
    const loadStats = bindRuntimeMethod(runtime.loadStats);
    const saveRules = bindRuntimeMethod(runtime.saveRules);
    const saveConfig = bindRuntimeMethod(runtime.saveConfig);
    const render = bindRuntimeMethod(runtime.render);
    const renderTabContent = bindRuntimeMethod(runtime.renderTabContent);
    const renderOverview = bindRuntimeMethod(runtime.renderOverview);
    const renderRules = bindRuntimeMethod(runtime.renderRules);
    const renderClassification = bindRuntimeMethod(runtime.renderClassification);
    const renderAICrawlers = bindRuntimeMethod(runtime.renderAICrawlers);
    const renderExceptions = bindRuntimeMethod(runtime.renderExceptions);
    const getBotLogo = AntibotsHelpers.getBotLogo.bind(AntibotsHelpers);
    const switchTab = bindRuntimeMethod(runtime.switchTab);
    const applyModePreset = bindRuntimeMethod(runtime.applyModePreset);
    const updateField = bindRuntimeMethod(runtime.updateField);
    const moveRule = bindRuntimeMethod(runtime.moveRule);
    const toggleRuleStatus = bindRuntimeMethod(runtime.toggleRuleStatus);
    const deleteRule = bindRuntimeMethod(runtime.deleteRule);
    const showAddRuleModal = bindRuntimeMethod(runtime.showAddRuleModal);
    const closeRuleModal = bindRuntimeMethod(runtime.closeRuleModal);
    const saveNewRule = bindRuntimeMethod(runtime.saveNewRule);
    const toggleRuleFields = bindRuntimeMethod(runtime.toggleRuleFields);
    const selectAction = bindRuntimeMethod(runtime.selectAction);
    const showGoodBotsModal = bindRuntimeMethod(runtime.showGoodBotsModal);
    const closeGoodBotsModal = bindRuntimeMethod(runtime.closeGoodBotsModal);
    const toggleGoodBot = bindRuntimeMethod(runtime.toggleGoodBot);
    const updateAIRule = bindRuntimeMethod(runtime.updateAIRule);
    const showAddExceptionModal = bindRuntimeMethod(runtime.showAddExceptionModal);
    const closeExceptionModal = bindRuntimeMethod(runtime.closeExceptionModal);
    const saveExceptionFromModal = bindRuntimeMethod(runtime.saveExceptionFromModal);
    const removeExceptionValue = bindRuntimeMethod(runtime.removeExceptionValue);

    const state = {
        get currentTab(): string { return runtime.currentTab; },
        set currentTab(value: string) { runtime.currentTab = value; },
        get config() { return runtime.config; },
        set config(value) { runtime.config = value; },
        get rules() { return runtime.rules; },
        set rules(value) { runtime.rules = value; },
        get stats() { return runtime.stats; },
        set stats(value) { runtime.stats = value; },
        get isLoading(): boolean { return runtime.isLoading; },
        set isLoading(value: boolean) { runtime.isLoading = value; },
        get loadError(): string | null { return runtime.loadError; },
        set loadError(value: string | null) { runtime.loadError = value; },
        get isGoodBotModalOpen(): boolean { return runtime.isGoodBotModalOpen; },
        set isGoodBotModalOpen(value: boolean) { runtime.isGoodBotModalOpen = value; },
        get isAddExceptionModalOpen(): boolean { return runtime.isAddExceptionModalOpen; },
        set isAddExceptionModalOpen(value: boolean) { runtime.isAddExceptionModalOpen = value; },
        get goodBotFilter(): string { return runtime.goodBotFilter; },
        set goodBotFilter(value: string) { runtime.goodBotFilter = value; }
    };

    const service = {
        init,
        loadConfig,
        loadRules,
        loadStats,
        saveRules,
        saveConfig
    };

    const view = {
        render,
        renderTabContent,
        renderOverview,
        renderRules,
        renderClassification,
        renderAICrawlers,
        renderExceptions,
        renderSaveButton: renderAntibotSaveButton,
        showToast: showAntibotToast,
        getIcon: getAntibotIcon,
        escapeHTML: AntibotsHelpers.escapeHTML,
        escapeAttr: AntibotsHelpers.escapeAttr,
        getBotLogo
    };

    const controller = {
        switchTab,
        applyModePreset,
        updateField,
        moveRule,
        toggleRuleStatus,
        deleteRule,
        showAddRuleModal,
        closeRuleModal,
        saveNewRule,
        toggleRuleFields,
        selectAction,
        showGoodBotsModal,
        closeGoodBotsModal,
        toggleGoodBot,
        updateAIRule,
        showAddExceptionModal,
        closeExceptionModal,
        saveExceptionFromModal,
        removeExceptionValue
    };

    const serviceMethods = ['init', 'loadConfig', 'loadRules', 'loadStats', 'saveRules', 'saveConfig'] as const;
    const viewMethods = [
        'render',
        'renderTabContent',
        'renderOverview',
        'renderRules',
        'renderClassification',
        'renderAICrawlers',
        'renderExceptions',
        'renderSaveButton',
        'showToast',
        'getIcon',
        'escapeHTML',
        'escapeAttr',
        'getBotLogo'
    ] as const;

    const target = {
        init,
        switchTab,
        state
    };

    return { state, service, view, controller, serviceMethods, viewMethods, target };
}
