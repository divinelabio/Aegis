export function createAntibotsBindingsDeps(runtime, helpers) {
    const bindRuntimeMethod = (method) => method.bind(runtime);
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
        applyModePreset: (modeName) => {
            if (helpers.isModeName(modeName))
                runtime.applyModePreset(modeName);
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
