import { AntibotsHelpers } from './antibots-helpers.js';
import { getAntibotIcon, renderAntibotSaveButton, showAntibotToast } from './antibots-runtime-helpers.js';
export function createAntibotsFacadeParts(runtime) {
    const bindRuntimeMethod = (method) => method.bind(runtime);
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
        get currentTab() { return runtime.currentTab; },
        set currentTab(value) { runtime.currentTab = value; },
        get config() { return runtime.config; },
        set config(value) { runtime.config = value; },
        get rules() { return runtime.rules; },
        set rules(value) { runtime.rules = value; },
        get stats() { return runtime.stats; },
        set stats(value) { runtime.stats = value; },
        get isLoading() { return runtime.isLoading; },
        set isLoading(value) { runtime.isLoading = value; },
        get loadError() { return runtime.loadError; },
        set loadError(value) { runtime.loadError = value; },
        get isGoodBotModalOpen() { return runtime.isGoodBotModalOpen; },
        set isGoodBotModalOpen(value) { runtime.isGoodBotModalOpen = value; },
        get isAddExceptionModalOpen() { return runtime.isAddExceptionModalOpen; },
        set isAddExceptionModalOpen(value) { runtime.isAddExceptionModalOpen = value; },
        get goodBotFilter() { return runtime.goodBotFilter; },
        set goodBotFilter(value) { runtime.goodBotFilter = value; }
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
    const serviceMethods = ['init', 'loadConfig', 'loadRules', 'loadStats', 'saveRules', 'saveConfig'];
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
    ];
    const target = {
        init,
        switchTab,
        state
    };
    return { state, service, view, controller, serviceMethods, viewMethods, target };
}
