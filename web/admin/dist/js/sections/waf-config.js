// WAF Configuration Interface
// Maps to internal/sections/waf/config.go
import { SectionUI } from './ui-components.js';
import { api } from '../api.js';
import { FEATURES, renderUpgradeBanner } from '../core/features.js';
import * as AdminDOM from '../core/dom.js';
import { showSectionToast } from './section-toast-helpers.js';
import { saveSectionConfig } from './section-mutation-helpers.js';
import { escapeWafHtml, parseWafCSVList } from './waf-runtime-helpers.js';
import { renderOverviewTab } from './waf/overview.js';
import { renderLeakProtectionTab, leakMimeGroups } from './waf/leak-protection.js';
import { renderManagedRulesFolder } from './waf/managed.js';
function wafCfgErrorMessage(error, fallback) {
    return error instanceof Error ? error.message : fallback;
}
const defaultWafLeakProtectionConfig = {
    enabled: true,
    mode: 'detect',
    max_body_size: 1024 * 1024,
    inspect_content_types: ['text/html', 'text/plain', 'application/json', 'application/javascript', 'text/xml', 'application/xml'],
    skip_content_types: ['image/*', 'video/*', 'audio/*', 'font/*', 'application/octet-stream', 'application/pdf'],
    redaction_enabled: true,
    default_action: 'detect',
    block_status_code: 403,
    replacement_body: 'Response blocked by Aegis Leak Protection',
    rules: {},
    custom_patterns: [],
    allowlist: []
};
function getWafLeakProtectionConfig(config) {
    const configured = config.leak_protection || {};
    return {
        ...defaultWafLeakProtectionConfig,
        ...configured,
        inspect_content_types: Array.isArray(configured.inspect_content_types)
            ? [...configured.inspect_content_types]
            : [...defaultWafLeakProtectionConfig.inspect_content_types],
        skip_content_types: Array.isArray(configured.skip_content_types)
            ? [...configured.skip_content_types]
            : [...defaultWafLeakProtectionConfig.skip_content_types],
        rules: { ...(configured.rules || {}) },
        custom_patterns: Array.isArray(configured.custom_patterns)
            ? configured.custom_patterns.map(pattern => ({ ...pattern }))
            : [],
        allowlist: Array.isArray(configured.allowlist)
            ? configured.allowlist.map(entry => ({ ...entry }))
            : []
    };
}
function formatWafBytes(value) {
    const bytes = typeof value === 'number' ? value : Number(value);
    if (!Number.isFinite(bytes) || bytes <= 0)
        return 'Not configured';
    const units = ['B', 'KiB', 'MiB', 'GiB'];
    let size = bytes;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit += 1;
    }
    const precision = size >= 10 || unit === 0 ? 0 : 1;
    return `${size.toFixed(precision)} ${units[unit]}`;
}
function formatWafMebibytes(value) {
    const bytes = typeof value === 'number' ? value : Number(value);
    if (!Number.isFinite(bytes) || bytes <= 0)
        return '1';
    const mebibytes = bytes / (1024 * 1024);
    return String(Math.round(mebibytes * 10) / 10);
}
async function wafCfgParseJson(response) {
    try {
        const raw = await response.text();
        if (!raw.trim())
            return null;
        return JSON.parse(raw);
    }
    catch {
        return null;
    }
}
function wafCfgApiErrorMessage(data, fallback) {
    if (!data)
        return fallback;
    if (typeof data.error === 'string' && data.error.trim())
        return data.error.trim();
    if (typeof data.message === 'string' && data.message.trim())
        return data.message.trim();
    if (typeof data.detail === 'string' && data.detail.trim())
        return data.detail.trim();
    return fallback;
}
function wafCfgGetElementById(id) {
    const element = globalThis['document'].getElementById(id);
    return element instanceof HTMLElement ? element : null;
}
function wafCfgGetControlById(id) {
    const control = wafCfgGetElementById(id);
    return (control instanceof HTMLInputElement ||
        control instanceof HTMLSelectElement ||
        control instanceof HTMLTextAreaElement)
        ? control
        : null;
}
function wafCfgGetControlValue(id, fallback = '') {
    return wafCfgGetControlById(id)?.value ?? fallback;
}
function wafCfgGetCheckboxValue(id) {
    const checkbox = wafCfgGetElementById(id);
    return checkbox?.checked ?? false;
}
let wafBindingsInitialized = false;
const wafMutationActions = new Set([
    'open-rule-editor',
    'submit-custom-rule',
    'bulk-toggle-crs',
    'toggle-custom-rule',
    'delete-rule',
    'add-rule-condition',
    'remove-section-condition-row',
    'toggle-negate',
    'show-exclusion-modal',
    'add-exclusion',
    'delete-exclusion',
    'apply-profile',
    'add-leak-pattern',
    'remove-leak-pattern',
    'add-leak-allowlist',
    'remove-leak-allowlist',
    'add-leak-mime',
    'remove-leak-mime',
    'toggle-leak-mime-group'
]);
function wafCanWrite() {
    return api.hasPermission('waf:write');
}
function applyWafPermissionState(root) {
    if (wafCanWrite()) {
        root.removeAttribute('data-waf-read-only');
        return;
    }
    root.setAttribute('data-waf-read-only', 'true');
    const controls = root.querySelectorAll('[data-waf-field], [data-waf-mode-toggle="true"], [data-waf-action], [data-waf-mime-input]');
    controls.forEach(control => {
        const action = control.dataset.wafAction || '';
        const isMutation = control.hasAttribute('data-waf-field')
            || control.dataset.wafModeToggle === 'true'
            || control.hasAttribute('data-waf-mime-input')
            || wafMutationActions.has(action)
            || action === 'toggle-crs-file'
            || action === 'toggle-exclusion';
        if (!isMutation)
            return;
        control.setAttribute('aria-disabled', 'true');
        control.setAttribute('title', 'Requires WAF write permission');
        if (control instanceof HTMLButtonElement
            || control instanceof HTMLInputElement
            || control instanceof HTMLSelectElement
            || control instanceof HTMLTextAreaElement) {
            control.disabled = true;
        }
        else {
            control.tabIndex = -1;
        }
    });
}
function parseWafDatasetValue(target) {
    const valueType = target.dataset.wafValueType || '';
    const rawValue = target.value;
    switch (valueType) {
        case 'checkbox':
            return target instanceof HTMLInputElement ? target.checked : rawValue === 'true';
        case 'number': {
            const scale = Number(target.dataset.wafValueScale || '1');
            const parsed = target.dataset.wafValueScale
                ? Number.parseFloat(rawValue)
                : Number.parseInt(rawValue, 10);
            if (!Number.isFinite(parsed))
                return 0;
            return Number.isFinite(scale) && scale > 0
                ? Math.round(parsed * scale)
                : parsed;
        }
        case 'csv':
            return parseWafCSVList(rawValue);
        default:
            return rawValue;
    }
}
function ensureWafBindings() {
    if (wafBindingsInitialized)
        return;
    wafBindingsInitialized = true;
    document.addEventListener('click', (event) => {
        if (!(event.target instanceof Element))
            return;
        const fieldTarget = event.target.closest('[data-waf-field]');
        if (fieldTarget &&
            !(fieldTarget instanceof HTMLInputElement) &&
            !(fieldTarget instanceof HTMLSelectElement) &&
            !(fieldTarget instanceof HTMLTextAreaElement)) {
            if (!wafCanWrite()) {
                event.preventDefault();
                showSectionToast('WAF configuration is read-only for your role', 'warning');
                return;
            }
            const field = fieldTarget.dataset.wafField;
            if (field) {
                const valueType = fieldTarget.dataset.wafValueType || '';
                const rawValue = fieldTarget.dataset.wafValue || '';
                const parsedValue = valueType === 'number' ? Number.parseInt(rawValue, 10) : rawValue;
                WAFConfig.updateField(field, valueType === 'number' && Number.isFinite(parsedValue) ? parsedValue : rawValue);
            }
            return;
        }
        const target = event.target.closest('[data-waf-action]');
        if (!target)
            return;
        if (target.dataset.wafStopPropagation === 'true') {
            event.stopPropagation();
        }
        const action = target.dataset.wafAction;
        const value = target.dataset.wafValue || '';
        if (action && wafMutationActions.has(action) && !wafCanWrite()) {
            event.preventDefault();
            showSectionToast('WAF configuration is read-only for your role', 'warning');
            return;
        }
        switch (action) {
            case 'switch-tab':
                if (value === 'overview' || value === 'leak_protection' || value === 'managed' || value === 'custom' || value === 'exclusions') {
                    WAFConfig.switchTab(value);
                }
                break;
            case 'open-leak-protection-page':
                if (value === 'advanced' || value === 'credentials' || value === 'debug' || value === 'files' || value === 'custom_detectors' || value === 'allowlist') {
                    WAFConfig.leakProtectionPage = value;
                    WAFConfig.render();
                }
                break;
            case 'back-leak-protection-page':
                WAFConfig.leakProtectionPage = 'advanced';
                WAFConfig.render();
                break;
            case 'close-leak-protection-page':
                WAFConfig.leakProtectionPage = '';
                WAFConfig.render();
                break;
            case 'set-rules-view':
                if (value === 'main' || value === 'managed' || value === 'editor') {
                    WAFConfig.rulesView = value;
                    if (value === 'main' && WAFConfig.currentTab === 'managed') {
                        WAFConfig.currentTab = 'custom';
                    }
                    WAFConfig.render();
                }
                break;
            case 'open-rule-editor':
                void WAFConfig.openRuleEditor(value || undefined);
                break;
            case 'toggle-advanced-settings':
                WAFConfig.toggleAdvancedSettings();
                break;
            case 'cancel-editor':
                WAFConfig.rulesView = 'main';
                WAFConfig.editingRule = null;
                WAFConfig.render();
                break;
            case 'submit-custom-rule':
                void WAFConfig.submitCustomRule(value === 'true');
                break;
            case 'bulk-toggle-crs':
                void WAFConfig.bulkToggleCRS(value === 'true');
                break;
            case 'open-crs-editor':
                if (value)
                    void WAFConfig.openCRSEditor(value);
                break;
            case 'toggle-custom-rule':
                if (target instanceof HTMLInputElement) {
                    void WAFConfig.toggleCustomRule(value, target.checked);
                }
                break;
            case 'delete-rule':
                void WAFConfig.deleteRule(value);
                break;
            case 'close-crs-editor-modal':
                wafCfgGetElementById('crs-editor-modal')?.remove();
                break;
            case 'close-modal-by-id':
                if (value)
                    wafCfgGetElementById(value)?.remove();
                break;
            case 'close-self-if-overlay':
                if (event.target === target)
                    target.remove();
                break;
            case 'add-rule-condition':
                WAFConfig.addRuleCondition();
                break;
            case 'remove-section-condition-row': {
                const row = target.closest('.section-condition-row');
                if (row)
                    row.remove();
                WAFConfig.updatePreview();
                const container = wafCfgGetElementById('cr-conditions');
                if (container && container.children.length === 0) {
                    container.innerHTML = WAFConfig.renderEmptyConditionsState();
                }
                break;
            }
            case 'toggle-negate': {
                const input = target.closest('.section-condition-row')?.querySelector('input.section-condition-negate');
                if (input instanceof HTMLInputElement) {
                    input.checked = !input.checked;
                    target.classList.toggle('btn-danger', input.checked);
                    target.classList.toggle('btn-outline', !input.checked);
                    target.setAttribute('aria-pressed', String(input.checked));
                    WAFConfig.updatePreview();
                }
                break;
            }
            case 'show-exclusion-modal':
                WAFConfig.showExclusionModal();
                break;
            case 'close-exclusion-modal': {
                const modalContainer = wafCfgGetElementById('exclusion-modal-container');
                if (modalContainer)
                    modalContainer.innerHTML = '';
                break;
            }
            case 'close-exclusion-overlay':
                if (event.target === target) {
                    const modalContainer = wafCfgGetElementById('exclusion-modal-container');
                    if (modalContainer)
                        modalContainer.innerHTML = '';
                }
                break;
            case 'add-exclusion':
                void WAFConfig.addExclusion();
                break;
            case 'delete-exclusion':
                void WAFConfig.deleteExclusion(value);
                break;
            case 'apply-profile':
                WAFConfig.applyProfile(value);
                break;
            case 'add-leak-pattern':
                WAFConfig.addLeakPattern();
                break;
            case 'remove-leak-pattern':
                WAFConfig.removeLeakPattern(value);
                break;
            case 'add-leak-allowlist':
                WAFConfig.addLeakAllowlist();
                break;
            case 'remove-leak-allowlist':
                WAFConfig.removeLeakAllowlist(value);
                break;
            case 'add-leak-mime':
                WAFConfig.addLeakMime(value);
                break;
            case 'remove-leak-mime':
                WAFConfig.removeLeakMime(value, target.dataset.wafMimeType || '');
                break;
            default:
                break;
        }
    });
    document.addEventListener('change', (event) => {
        const target = event.target;
        if (!(target instanceof HTMLInputElement || target instanceof HTMLSelectElement || target instanceof HTMLTextAreaElement))
            return;
        const isMutation = target.dataset.wafModeToggle === 'true'
            || target.dataset.wafAction === 'toggle-crs-file'
            || target.dataset.wafAction === 'toggle-exclusion'
            || target.dataset.wafAction === 'toggle-leak-mime-group'
            || Boolean(target.dataset.wafField);
        if (isMutation && !wafCanWrite()) {
            event.preventDefault();
            showSectionToast('WAF configuration is read-only for your role', 'warning');
            return;
        }
        if (target.dataset.wafModeToggle === 'true' && target instanceof HTMLInputElement) {
            if (!target.checked) {
                const currentMode = WAFConfig.config.mode;
                if (currentMode === 'detection' || currentMode === 'blocking') {
                    WAFConfig.lastEnabledMode = currentMode;
                }
                WAFConfig.updateField('mode', 'off');
                return;
            }
            WAFConfig.updateField('mode', WAFConfig.lastEnabledMode);
            return;
        }
        if (target.dataset.wafAction === 'toggle-crs-file' && target instanceof HTMLInputElement) {
            void WAFConfig.toggleCRSFile(target.dataset.wafValue || '', target.checked);
            return;
        }
        if (target.dataset.wafAction === 'toggle-exclusion' && target instanceof HTMLInputElement) {
            void WAFConfig.toggleExclusionEnabled(target.dataset.wafValue || '', target.checked);
            return;
        }
        if (target.dataset.wafAction === 'toggle-leak-mime-group' && target instanceof HTMLInputElement) {
            WAFConfig.toggleLeakMimeGroup(target.dataset.wafGroup || '', target.checked);
            return;
        }
        if (target.dataset.wafState) {
            WAFConfig[target.dataset.wafState] = target.value;
            WAFConfig.render();
            return;
        }
        if (target.dataset.wafField) {
            WAFConfig.updateField(target.dataset.wafField, parseWafDatasetValue(target));
            return;
        }
        if (target.classList.contains('section-condition-zone') || target.classList.contains('section-condition-operator')) {
            WAFConfig.toggleConditionField(target);
            WAFConfig.updatePreview();
            return;
        }
        if (target.classList.contains('section-condition-transform') && target instanceof HTMLInputElement) {
            if (target.parentElement)
                target.parentElement.classList.toggle('active', target.checked);
            WAFConfig.updatePreview();
        }
    });
    document.addEventListener('keydown', (event) => {
        const target = event.target;
        if (!(target instanceof HTMLInputElement) || target.dataset.wafMimeInput !== 'true' || event.key !== 'Enter')
            return;
        event.preventDefault();
        if (!wafCanWrite()) {
            showSectionToast('WAF configuration is read-only for your role', 'warning');
            return;
        }
        WAFConfig.addLeakMime(target.dataset.wafMimeScope || '');
    });
    document.addEventListener('input', (event) => {
        const target = event.target;
        if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement))
            return;
        const stateKey = target.dataset.wafState;
        if (stateKey) {
            WAFConfig[stateKey] = target.value;
            WAFConfig.render();
            return;
        }
        if (target.id === 'cr-id' || target.id === 'cr-msg' || target.id === 'cr-score' ||
            target.classList.contains('section-condition-field') || target.classList.contains('section-condition-pattern')) {
            WAFConfig.updatePreview();
        }
    });
}
const WAFConfig = {
    currentTab: 'overview',
    leakProtectionPage: '',
    config: {},
    health: {},
    stats: {},
    rules: [], // Custom rules
    crsRules: [], // Managed rules (files)
    crsGroups: {}, // Grouped managed rules
    profiles: [],
    exclusions: [],
    exclusionQuery: '',
    exclusionScope: 'all',
    managedRuleQuery: '',
    managedRuleStatusFilter: 'all',
    isLoading: false,
    loadError: null,
    rulesView: 'main', // 'main' | 'managed' | 'editor'
    editingRule: null, // Rule being edited (null = creating new)
    lastEnabledMode: 'detection',
    get tabs() {
        const hasDLP = api.hasFeature(FEATURES.WAF_LEAK_PROTECTION);
        const tabs = [
            { id: 'overview', name: 'Overview', icon: 'shield' },
            ...(hasDLP ? [{ id: 'leak_protection', name: 'Leak Protection', icon: 'eye' }] : []),
            { id: 'managed', name: 'Managed Rulesets', icon: 'folder' },
            { id: 'custom', name: 'Custom Rules', icon: 'list' },
            { id: 'exclusions', name: 'Exclusions', icon: 'filter' }
        ];
        return tabs;
    },
    // Icon helper - matches Traffic/Antibots pattern
    getIcon(name) {
        return SectionUI.icons[name] || SectionUI.icons.shield;
    },
    // Render a section header card (matches Antibots renderSectionHeader)
    renderSectionHeader(_icon, _title, _desc) {
        return '';
    },
    renderWafModuleStatusCard(_title, _description, _icon, _enabled, _actions = '', _statusLabel) {
        return '';
    },
    async init() {
        ensureWafBindings();
        const hasLoadedData = Boolean(this.config && Object.keys(this.config).length > 0);
        if (!hasLoadedData) {
            this.isLoading = true;
            this.loadError = null;
            this.render(); // Show loading state
        }
        else {
            this.render();
        }
        try {
            await Promise.all([
                this.loadConfig(),
                this.loadStats(hasLoadedData),
                this.loadRules(),
                this.loadProfiles(),
                this.loadExclusions()
            ]);
        }
        catch (err) {
            if (!hasLoadedData) {
                this.loadError = wafCfgErrorMessage(err, 'Failed to load configuration');
            }
            console.error('Init error:', err);
        }
        finally {
            this.isLoading = false;
            this.render();
            // Start auto-refresh
            this.startRefresh();
        }
    },
    startRefresh() {
        if (this.refreshInterval !== undefined)
            clearInterval(this.refreshInterval);
        if (this.visibilityHandler) {
            document.removeEventListener('visibilitychange', this.visibilityHandler);
        }
        this.statsAbortController?.abort();
        const refreshIfActive = () => {
            const container = wafCfgGetElementById('waf-config-content');
            if (!container) {
                if (this.refreshInterval !== undefined) {
                    clearInterval(this.refreshInterval);
                    this.refreshInterval = undefined;
                }
                if (this.visibilityHandler) {
                    document.removeEventListener('visibilitychange', this.visibilityHandler);
                    this.visibilityHandler = undefined;
                }
                this.statsAbortController?.abort();
                return;
            }
            if (document.visibilityState !== 'visible') {
                this.statsAbortController?.abort();
                return;
            }
            void this.loadStats(true);
        };
        this.visibilityHandler = refreshIfActive;
        document.addEventListener('visibilitychange', refreshIfActive);
        this.refreshInterval = window.setInterval(refreshIfActive, 30000);
    },
    // Data Loading
    async loadConfig() {
        try {
            const data = await api.get('sections/waf_core/config');
            this.config = data?.config || {};
            if (!this.config.active_profile_id && typeof this.config.active_policy_id === 'string') {
                this.config.active_profile_id = this.config.active_policy_id;
            }
            if (this.config.mode === 'detection' || this.config.mode === 'blocking') {
                this.lastEnabledMode = this.config.mode;
            }
            this.health = data?.health || {};
        }
        catch (e) {
            console.error('Failed to load WAF config', e);
            throw e;
        }
    },
    async loadStats(silent = false) {
        if (this.statsRequest) {
            return this.statsRequest;
        }
        const controller = new AbortController();
        this.statsAbortController = controller;
        const request = (async () => {
            try {
                const data = await api.get('sections/waf_core/dashboard?window=24h', { signal: controller.signal });
                if (controller.signal.aborted || !data)
                    return;
                this.stats = data.dashboard || {};
                if (!silent)
                    this.render();
                else
                    this.updateDashboardUI();
            }
            catch (e) {
                if (!silent && !controller.signal.aborted)
                    console.error('Failed to load stats', e);
            }
        })();
        this.statsRequest = request;
        try {
            await request;
        }
        finally {
            if (this.statsRequest === request)
                this.statsRequest = undefined;
            if (this.statsAbortController === controller)
                this.statsAbortController = undefined;
        }
    },
    async loadRules() {
        try {
            const [customData, crsData] = await Promise.all([
                api.get('sections/waf_core/rules/custom'),
                api.get('sections/waf_core/rules/crs')
            ]);
            this.rules = customData?.rules || [];
            // Backend now returns objects {name, enabled}, but legacy might return strings
            this.crsRules = (crsData?.files || []).map((f) => {
                if (typeof f === 'string')
                    return { name: f, enabled: true };
                return f;
            });
            this.crsGroups = this.processCRSRules(this.crsRules);
        }
        catch (e) {
            console.error('Failed to load rules', e);
            this.rules = [];
            this.crsRules = [];
        }
    },
    async loadProfiles() {
        try {
            const data = await api.get('sections/waf_core/profiles');
            this.profiles = data?.profiles || [];
        }
        catch (e) {
            try {
                const data = await api.get('sections/waf_core/policies');
                this.profiles = data?.profiles || data?.policies || [];
            }
            catch (fallbackError) {
                console.error('Failed to load protection profiles', e, fallbackError);
                this.profiles = [];
            }
        }
    },
    async loadExclusions() {
        try {
            const data = await api.get('sections/waf_core/exclusions');
            this.exclusions = data?.exclusions || [];
        }
        catch (e) {
            console.error('Failed to load exclusions', e);
        }
    },
    // Rendering
    render() {
        const container = wafCfgGetElementById('waf-config-content');
        if (!container)
            return;
        if (this.currentTab === 'leak_protection' && !api.hasFeature(FEATURES.WAF_LEAK_PROTECTION)) {
            this.currentTab = 'overview';
        }
        // Show loading state
        if (this.isLoading) {
            container.innerHTML = SectionUI.renderLoading('Loading Application Firewall configuration...');
            return;
        }
        // Show error state
        if (this.loadError) {
            container.innerHTML = SectionUI.renderError(this.loadError, 'WAFConfig.init()');
            return;
        }
        const wafMode = this.config.mode || 'off';
        const wafEnabled = wafMode !== 'off';
        const wafStatusLabel = wafMode === 'blocking' ? 'Blocking' : wafMode === 'detection' ? 'Detection' : 'Off';
        const wafStatusTone = wafMode === 'blocking' ? 'danger' : wafMode === 'detection' ? 'warning' : 'neutral';
        const wafToggleLabel = wafEnabled
            ? `Disable Application Firewall (${wafStatusLabel} mode)`
            : `Enable Application Firewall in ${this.lastEnabledMode === 'blocking' ? 'Blocking' : 'Detection'} mode`;
        const readOnlyNotice = wafCanWrite() ? '' : `
            <div class="section-warning-box" data-waf-read-only-notice="true" role="status">
                <div class="section-warning-icon">${SectionUI.icons.info || SectionUI.icons.shield}</div>
                <div>
                    <div class="section-warning-title">Read-only Application Firewall access</div>
                    <div class="section-warning-text">You can review protection settings and rules, but only an authorized administrator can make changes.</div>
                </div>
            </div>
        `;
        const wafSwitch = SectionUI.renderSwitch({
            checked: wafEnabled,
            attrs: `title="${wafToggleLabel}" data-waf-mode-toggle="true" aria-label="${wafToggleLabel}"`
        });
        const consoleMetaMap = {
            overview: {
                title: 'Overview',
                kicker: 'Application Firewall',
                subtitle: 'Real-time security posture, active rule counts, inspection engine state, and threat telemetry.',
                actions: wafSwitch
            },
            managed: {
                title: 'Managed Rulesets',
                kicker: 'Application Firewall',
                subtitle: 'Core Rule Set protection with anomaly scoring, paranoia level tuning, and attack vector defense.'
            },
            custom: {
                title: 'Custom Rules',
                kicker: 'Application Firewall',
                subtitle: 'Wire-speed expression filtering using Wireshark-syntax rules and custom action pipelines.',
                actions: this.rulesView === 'editor'
                    ? '<button type="button" class="btn btn-outline btn-sm" data-waf-action="cancel-rule-editor">Cancel Editor</button>'
                    : ''
            },
            exclusions: {
                title: 'Exclusions',
                kicker: 'Application Firewall',
                subtitle: 'Path-scoped rule bypasses, parameter exclusions, and false-positive suppression without disabling rules globally.'
            },
            leak_protection: {
                title: 'Leak Protection',
                kicker: 'Application Firewall',
                subtitle: 'Deep inspection of response bodies to detect, mask, or block credit cards, SSNs, API tokens, and private database credentials.'
            }
        };
        const activeConsole = consoleMetaMap[this.currentTab] || consoleMetaMap.overview;
        container.innerHTML = SectionUI.renderOperatorFrame({
            title: activeConsole.title,
            kicker: activeConsole.kicker,
            subtitle: activeConsole.subtitle,
            actions: activeConsole.actions,
            tabs: [],
            content: `${readOnlyNotice}<div class="config-console-content" id="waf-tab-content">${this.renderTabContent()}</div>`,
            className: 'waf-operator-frame firewall-operator-frame'
        });
        applyWafPermissionState(container);
        // Post-render: populate conditions in visual editor
        if (this.currentTab === 'custom' && this.rulesView === 'editor') {
            requestAnimationFrame(wafPopulateVisualRuleConditions);
        }
    },
    switchTab(id) {
        if (id === 'leak_protection' && !api.hasFeature(FEATURES.WAF_LEAK_PROTECTION)) {
            id = 'overview';
        }
        this.currentTab = id;
        if (id !== 'leak_protection')
            this.leakProtectionPage = '';
        if (id === 'custom' && this.rulesView === 'managed')
            this.rulesView = 'main';
        this.render();
        if (id === 'overview')
            void this.loadStats(true);
        const tabTargetMap = {
            overview: 'waf_config',
            managed: 'waf_managed',
            custom: 'waf_custom',
            exclusions: 'waf_exclusions',
            leak_protection: 'dlp_config'
        };
        const target = tabTargetMap[id];
        if (target) {
            AdminDOM.queryAll('.nav-link').forEach((el) => el.classList.remove('active'));
            const link = AdminDOM.query(`.nav-link[data-nav-target="${target}"]`);
            if (link)
                link.classList.add('active');
        }
    },
    toggleAdvancedSettings() {
        const advanced = wafCfgGetElementById('waf-advanced-settings');
        if (!advanced)
            return;
        advanced.classList.toggle('is-open');
    },
    renderTabContent() {
        switch (this.currentTab) {
            case 'overview': return this.renderOverview();
            case 'leak_protection': return api.hasFeature(FEATURES.WAF_LEAK_PROTECTION)
                ? this.renderLeakProtection()
                : renderUpgradeBanner('professional', 'Data Leak Protection');
            case 'managed': return this.renderManagedRules();
            case 'custom': return this.renderRules();
            case 'exclusions': return this.renderExclusions();
            default: return '<div>Unknown tab</div>';
        }
    },
    // ========== TAB 1: OVERVIEW ==========
    renderOverview() {
        return renderOverviewTab(this.config, this.profiles, this.crsRules, this.rules, this.exclusions, this.stats, this.health, (e) => this.isExclusionExpired(e), (name) => this.getIcon(name));
    },
    renderManagedRules() {
        const failedReload = this.health.reload?.status === 'failed';
        return renderManagedRulesFolder(this.crsRules, failedReload);
    },
    // ========== TAB 2: LEAK PROTECTION (PRO) ==========
    renderLeakProtection() {
        return renderLeakProtectionTab(this.config.leak_protection, this.leakProtectionPage, (name) => this.getIcon(name));
    },
    renderReloadHealth() {
        const reload = this.health.reload || {};
        const rules = this.health.rules || {};
        const failed = reload.status === 'failed';
        return `
            <div class="section-overview-stats-grid">
                ${this.renderOverviewStat('Reload', failed ? 'failed' : (reload.status || 'ok'), failed ? 'danger' : 'success')}
				${this.renderOverviewStat('CRS rules', rules.crs_rules_loaded || 0, 'primary')}
                ${this.renderOverviewStat('Custom', rules.custom_rules_loaded || 0, 'primary')}
                ${this.renderOverviewStat('Exclusions', rules.active_exclusions || 0, 'warning')}
            </div>
            ${failed ? `<div class="section-warning-box mt-16"><div class="section-warning-icon">${SectionUI.icons.alertTriangle}</div><div><div class="section-warning-title">The latest protection update was not applied</div><div class="section-warning-text">Your previous protection settings remain active. Review the configuration and try again.</div></div></div>` : ''}
        `;
    },
    renderOverviewStat(label, value, color) {
        return `
            <div class="section-overview-stat ${color}">
                <div class="section-overview-stat-value">${value}</div>
                <div class="section-overview-stat-label">${label}</div>
            </div>
        `;
    },
    getParanoiaDescription(level) {
        const descriptions = {
            1: "<strong>Level 1:</strong> Baseline protection with minimal impact on normal traffic.",
            2: "<strong>Level 2:</strong> Balanced protection for most applications.",
            3: "<strong>Level 3:</strong> More thorough inspection that may require additional exceptions.",
            4: "<strong>Level 4:</strong> Maximum inspection for active attacks or thoroughly tested applications."
        };
        return descriptions[level] || descriptions[1];
    },
    renderTrafficChart(history) {
        if (!history || history.length < 2) {
            return `<div class="section-chart-empty">
                Insufficient data for chart
            </div>`;
        }
        // Simple SVG Line Chart implementation
        // Points: timestamp, total_requests, blocked_requests
        const width = 600; // viewBox width implies aspect ratio
        const height = 200;
        const padding = 20;
        // Find min/max
        const maxReq = Math.max(...history.map(p => p.total_requests), 10);
        // Helper to map Point to coordinate
        const getX = (i) => padding + (i / (history.length - 1)) * (width - 2 * padding);
        const getY = (val) => height - padding - (val / maxReq) * (height - 2 * padding);
        // Make Total Request Path (Area)
        let areaPath = `M ${getX(0)} ${height - padding}`;
        let linePath = `M ${getX(0)} ${getY(history[0].total_requests)}`;
        // Make Blocked Request Path (Line)
        let blockedPath = `M ${getX(0)} ${getY(history[0].blocked_requests)}`;
        history.forEach((p, i) => {
            const x = getX(i);
            const y = getY(p.total_requests);
            linePath += ` L ${x} ${y}`;
            areaPath += ` L ${x} ${y}`;
            const yBlocked = getY(p.blocked_requests);
            blockedPath += ` L ${x} ${yBlocked}`;
        });
        areaPath += ` L ${getX(history.length - 1)} ${height - padding} Z`;
        return `
            <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" class="section-chart-svg">
                <!-- Background Grid -->
                <line x1="${padding}" y1="${getY(maxReq)}" x2="${width - padding}" y2="${getY(maxReq)}" stroke="var(--border)" stroke-dasharray="4"/>
                <line x1="${padding}" y1="${getY(maxReq / 2)}" x2="${width - padding}" y2="${getY(maxReq / 2)}" stroke="var(--border)" stroke-dasharray="4"/>
                <line x1="${padding}" y1="${height - padding}" x2="${width - padding}" y2="${height - padding}" stroke="var(--border)"/>

                <!-- Total Requests Area -->
                <path d="${areaPath}" fill="rgba(37, 99, 235, 0.12)" />
                <!-- Total Requests Line -->
                <path d="${linePath}" fill="none" stroke="var(--primary)" stroke-width="2" />
                
                <!-- Blocked Requests Line -->
                <path d="${blockedPath}" fill="none" stroke="var(--danger)" stroke-width="2" />

                <!-- Legend / Overlay Info (Static for now) -->
               <text x="${padding}" y="12" font-size="10" fill="var(--primary)">Total Traffic</text>
               <text x="${padding + 70}" y="12" font-size="10" fill="var(--danger)">Blocked</text>
            </svg>
        `;
    },
    getAttackColor(type) {
        const colors = {
            'sqli': '#ef4444', // red
            'xss': '#f97316', // orange
            'rce': '#7c3aed', // violet
            'lfi': '#ec4899', // pink
            'protocol': '#3b82f6', // blue
            'scanner': '#6b7280', // gray
        };
        return colors[type] || '#10b981'; // default green
    },
    renderFeatureCard(tabKey, title, subtitle, iconKey, isActive) {
        const icon = SectionUI.icons[iconKey] || SectionUI.icons.shield;
        return `
            <div class="section-flat-link ${isActive ? 'is-active' : ''}"
                 data-waf-action="switch-tab" data-waf-value="${tabKey}">
                <div class="section-flat-link-icon">${icon}</div>
                <div class="section-flat-link-copy">
                    <div class="section-flat-link-title">${title}</div>
                    <div class="section-flat-link-desc">${subtitle}</div>
                </div>
                <div class="section-flat-link-state">${isActive ? 'on' : 'off'}</div>
            </div>
        `;
    },
    renderModeOption(value, title, subtitle, iconName) {
        const isActive = this.config.mode === value;
        const tone = value === 'blocking' ? 'danger' : (value === 'detection' ? 'primary' : 'muted');
        const icon = SectionUI.icons[iconName] || '';
        return `
            <div data-waf-field="mode" data-waf-value="${value}" data-waf-render="true"
                 class="section-mode-option tone-${tone} ${isActive ? 'is-active' : ''}">
                <div class="section-mode-icon">${icon}</div>
                <div class="section-mode-title">${title}</div>
                ${subtitle ? `<div class="section-mode-subtitle">${subtitle}</div>` : ''}
            </div>
        `;
    },
    renderParanoiaCard(level, title, tone, subtitle, isRecommended = false) {
        const currentLevel = this.config.rule_strictness || 1;
        const isActive = currentLevel === level;
        // Recommended badge logic
        const recommendedBadge = isRecommended ?
            '<div class="section-paranoia-recommended">Recommended</div>'
            : '';
        return `
            <div data-waf-field="rule_strictness" data-waf-value="${level}" data-waf-value-type="number"
                 class="section-paranoia-card tone-${tone} ${isActive ? 'is-active' : ''} ${isRecommended ? 'is-recommended' : ''}">
                ${recommendedBadge}
                <div class="section-paranoia-title">
                    <div class="section-paranoia-dot"></div>
                    ${title}
                </div>
                ${subtitle ? `<div class="section-paranoia-subtitle">${subtitle}</div>` : ''}
                ${isActive ? `<div class="section-paranoia-active-check">${SectionUI.icons.check || '✓'}</div>` : ''}
            </div>
        `;
    },
    getAttackCount(type) {
        if (!this.stats.attack_types)
            return 0;
        const attack = this.stats.attack_types.find(a => a.type === type);
        return attack ? attack.count : 0;
    },
    updateDashboardUI() {
        const container = wafCfgGetElementById('waf-config-content');
        if (!container || this.currentTab !== 'overview')
            return;
        const total = this.stats.total_requests || 0;
        const blocked = this.stats.blocked_requests || 0;
        const blockRate = total > 0 ? (blocked / total) * 100 : 0;
        const update = (key, value, note) => {
            const valueNode = container.querySelector(`[data-waf-kpi-value="${key}"]`);
            if (valueNode)
                valueNode.textContent = value;
            const noteNode = container.querySelector(`[data-waf-kpi-note="${key}"]`);
            if (!noteNode)
                return;
            if (note !== undefined)
                noteNode.textContent = note;
        };
        update('requests', total.toLocaleString(), 'Last 24 hours');
        update('blocked', blocked.toLocaleString(), `${blockRate.toFixed(1)}% block rate`);
    },
    // ========== TAB 2: RULES ==========
    renderRules() {
        switch (this.rulesView) {
            case 'managed': return this.renderManagedRulesFolder();
            case 'editor': return this.renderRuleEditor();
            default: return this.renderRulesMain();
        }
    },
    renderRulesMain() {
        const crsCount = this.crsRules.length;
        const crsEnabled = this.crsRules.filter(f => f.enabled !== false).length;
        const customCount = this.rules.length;
        const customEnabled = this.rules.filter(rule => rule.enabled !== false).length;
        return `
        <div class="config-list-stack">
            <div class="config-toolbar">
                <div class="config-toolbar-summary">
                    <strong>${customEnabled.toLocaleString()}/${customCount.toLocaleString()}</strong>
                    <span>custom enabled</span>
                </div>
                <div class="config-toolbar-summary">
                    <strong>${crsEnabled.toLocaleString()}/${crsCount.toLocaleString()}</strong>
                    <span>managed enabled</span>
                </div>
                <div class="config-toolbar-spacer"></div>
                <button type="button" class="btn btn-primary btn-sm section-btn-inline" data-waf-action="open-rule-editor">Create Rule</button>
            </div>
            ${this.renderCustomRulesList()}
        </div>
    `;
    },
    formatManagedRuleName(fileName) {
        const acronymMap = {
            api: 'API',
            csrf: 'CSRF',
            dos: 'DoS',
            lfi: 'LFI',
            php: 'PHP',
            rce: 'RCE',
            rfi: 'RFI',
            sqli: 'SQL Injection',
            sql: 'SQL',
            xss: 'XSS',
            xml: 'XML'
        };
        const normalized = String(fileName || '')
            .replace(/\.disabled$/i, '')
            .replace(/\.conf$/i, '')
            .replace(/^(REQUEST|RESPONSE|RESPONSE-BODY)-/i, '')
            .replace(/^\d{3,4}-/, '')
            .replace(/[-_]+/g, ' ')
            .trim()
            .toLowerCase();
        if (!normalized)
            return 'Managed Protection';
        return normalized
            .split(/\s+/)
            .map(part => acronymMap[part] || part.charAt(0).toUpperCase() + part.slice(1))
            .join(' ')
            .replace(/\bSql Injection\b/g, 'SQL Injection')
            .replace(/\bCross Site Scripting\b/g, 'Cross-Site Scripting');
    },
    managedRuleDescription(file) {
        const friendlyName = this.formatManagedRuleName(file.name);
        const group = String(file.group || '').trim();
        const groupText = group && group.toLowerCase() !== friendlyName.toLowerCase()
            ? `${group.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, char => char.toUpperCase())} protection`
            : 'Built-in protection';
        const category = String(file.category || '').toLowerCase();
        if (category === 'response')
            return `${friendlyName} checks responses for sensitive data and information leaks.`;
        if (category === 'request')
            return `${friendlyName} checks incoming requests using ${groupText}.`;
        return `${friendlyName} provides built-in protection for your application.`;
    },
    managedRuleStatus(file) {
        if (file.enabled === false)
            return { label: 'Disabled', tone: 'muted' };
        const status = String(file.status || '').toLowerCase();
        if (status === 'error')
            return { label: 'Error', tone: 'danger' };
        if (status === 'warning')
            return { label: 'Needs review', tone: 'warning' };
        return { label: 'Enabled', tone: 'success' };
    },
    managedRulePolicyGroup(file) {
        const name = this.formatManagedRuleName(file.name).toLowerCase();
        const group = String(file.group || '').replace(/[_-]+/g, ' ').toLowerCase();
        const combined = `${name} ${group}`;
        const category = String(file.category || '').toLowerCase();
        if (category === 'response') {
            return {
                key: 'response-protection',
                label: 'Response Protection',
                description: 'Inspect responses for sensitive data and information leaks.',
                tone: 'response'
            };
        }
        if (/\b(scanner|recon|crawler|automation|bot)\b/.test(combined)) {
            return {
                key: 'scanner-detection',
                label: 'Scanner Detection',
                description: 'Identify reconnaissance and automated probing before it reaches your application.',
                tone: 'request'
            };
        }
        if (/\b(protocol|method|header|encoding|content type|file upload|multipart)\b/.test(combined)) {
            return {
                key: 'protocol-enforcement',
                label: 'Protocol Enforcement',
                description: 'Validate requests against expected HTTP formats and inputs.',
                tone: 'other'
            };
        }
        if (/\b(sql|xss|injection|rce|rfi|lfi|php|java|attack|exploit|scripting)\b/.test(combined)) {
            return {
                key: 'attack-protection',
                label: 'Attack Protection',
                description: 'Detect common attacks such as injection and scripting attempts.',
                tone: 'request'
            };
        }
        if (category === 'request') {
            return {
                key: 'request-protection',
                label: 'Request Protection',
                description: 'Inspect incoming requests for suspicious activity.',
                tone: 'request'
            };
        }
        return {
            key: 'general-protection',
            label: 'General Protection',
            description: 'Apply additional built-in protections to incoming and outgoing traffic.',
            tone: 'other'
        };
    },
    managedPolicyGroupStatus(files) {
        if (files.some(file => String(file.status || '').toLowerCase() === 'error'))
            return { label: 'Error', tone: 'danger' };
        if (files.some(file => String(file.status || '').toLowerCase() === 'warning'))
            return { label: 'Needs review', tone: 'warning' };
        if (files.every(file => file.enabled === false))
            return { label: 'Disabled', tone: 'muted' };
        if (files.some(file => file.enabled === false))
            return { label: 'Partially enabled', tone: 'warning' };
        return { label: 'Enabled', tone: 'success' };
    },
    renderManagedPolicyRuleRow(file) {
        const isEnabled = file.enabled !== false;
        const title = this.formatManagedRuleName(file.name);
        return `
            <tr class="section-row ${isEnabled ? '' : 'section-row-dim'}">
                <td class="section-td">
                    <div class="section-row-main">
                        <div class="section-row-icon tone-other" aria-hidden="true">
                            ${SectionUI.icons.shield || SectionUI.icons.fileText}
                        </div>
                        <div>
                            <div class="section-managed-rule-name">${escapeWafHtml(title)}</div>
                        </div>
                    </div>
                </td>
                <td class="section-td">
                    <div class="section-row-sub section-managed-rule-description">${escapeWafHtml(this.managedRuleDescription(file))}</div>
                </td>
                <td class="section-td section-td-right">
                    ${SectionUI.renderSwitch({
            checked: isEnabled,
            className: 'section-switch-sm',
            attrs: `aria-label="${isEnabled ? 'Disable' : 'Enable'} ${escapeWafHtml(title)}" data-waf-action="toggle-crs-file" data-waf-value="${escapeWafHtml(file.name)}"`
        })}
                </td>
            </tr>
        `;
    },
    renderManagedPolicyGroup(group, _index) {
        return `
            <details class="section-managed-policy-group">
                <summary class="section-managed-policy-summary">
                    <div class="section-managed-policy-main">
                        <div class="section-row-icon tone-${group.tone}" aria-hidden="true">
                            ${SectionUI.icons.shield || SectionUI.icons.folder}
                        </div>
                        <div>
                            <div class="section-managed-policy-title">${escapeWafHtml(group.label)}</div>
                            <div class="section-managed-policy-desc">${escapeWafHtml(group.description)}</div>
                        </div>
                    </div>
                    <div class="section-managed-policy-meta">
                        <span class="section-managed-policy-chevron" aria-hidden="true">${SectionUI.icons.chevronDown || 'v'}</span>
                    </div>
                </summary>
                <div class="section-managed-policy-body">
                    <div class="table-container section-table-wrap">
                        <table class="section-table table-hover section-managed-table">
                            <thead class="section-table-head">
                                <tr>
                                    <th class="section-th">Protection</th>
                                    <th class="section-th">Description</th>
                                    <th class="section-th section-th-right">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${group.files.map(file => this.renderManagedPolicyRuleRow(file)).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </details>
        `;
    },
    renderManagedRulesFolder() {
        const files = this.crsRules;
        const failedReload = this.health.reload?.status === 'failed';
        const policyGroups = Array.from(files.reduce((groups, file) => {
            const policyGroup = this.managedRulePolicyGroup(file);
            const existing = groups.get(policyGroup.key);
            if (existing) {
                existing.files.push(file);
            }
            else {
                groups.set(policyGroup.key, { ...policyGroup, files: [file] });
            }
            return groups;
        }, new Map()).values())
            .sort((a, b) => a.label.localeCompare(b.label));
        return `
        <div class="section-managed-console">
            ${failedReload ? `<div class="section-warning-box section-managed-warning"><div class="section-warning-icon">${SectionUI.icons.alertTriangle}</div><div><div class="section-warning-title">The latest protection update was not applied</div><div class="section-warning-text">Your previous managed rule settings remain active. Review the configuration and try again.</div></div></div>` : ''}

            ${files.length === 0 ? `
                <div class="section-card-flush section-managed-empty">
                    <div class="section-folder-empty">
                        <div class="section-folder-empty-icon">${SectionUI.icons.file}</div>
                        No managed protections found
                    </div>
                </div>
            ` : `
            <div class="section-managed-policy-list">
                ${policyGroups.map((group, index) => this.renderManagedPolicyGroup(group, index)).join('')}
            </div>`}

            <div class="crs-copyright" style="text-align: center; font-size: 11px; color: var(--text-muted); margin-top: 24px; margin-bottom: 16px;">
                Powered by OWASP ModSecurity Core Rule Set (CRS)
            </div>
        </div>
    `;
    },
    renderCustomRulesList() {
        const tableRows = (this.rules || []).map(rule => {
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
            emptyAction: '<button type="button" class="btn btn-primary btn-sm section-btn-inline" data-waf-action="open-rule-editor">Create Rule</button>',
            className: 'firewall-custom-rules-table'
        });
    },
    // ========== CRS TEXT EDITOR MODAL ==========
    async openCRSEditor(filename) {
        wafCfgGetElementById('crs-editor-modal')?.remove();
        const overlay = document.createElement('div');
        overlay.id = 'crs-editor-modal';
        overlay.className = 'section-modal-overlay is-open is-visible';
        overlay.dataset.wafAction = 'close-self-if-overlay';
        const panel = document.createElement('div');
        panel.className = 'section-modal-panel section-modal-dialog section-crs-viewer-dialog';
        const header = document.createElement('div');
        header.className = 'section-modal-head section-modal-header';
        const heading = document.createElement('div');
        const title = document.createElement('h3');
        title.className = 'section-modal-title';
        const icon = document.createElement('span');
        icon.innerHTML = SectionUI.icons.fileText || SectionUI.icons.file || '';
        title.append(icon, document.createTextNode(` ${filename}`));
        const meta = document.createElement('span');
        meta.className = 'section-modal-meta';
        meta.textContent = 'Built-in protection · Read only';
        heading.append(title, meta);
        const headerClose = document.createElement('button');
        headerClose.type = 'button';
        headerClose.className = 'btn btn-ghost btn-sm';
        headerClose.dataset.wafAction = 'close-crs-editor-modal';
        headerClose.setAttribute('aria-label', 'Close managed rule viewer');
        headerClose.innerHTML = SectionUI.icons.x || 'X';
        header.append(heading, headerClose);
        const body = document.createElement('div');
        body.className = 'section-modal-body';
        const textarea = document.createElement('textarea');
        textarea.id = 'crs-editor-textarea';
        textarea.className = 'section-modal-textarea';
        textarea.readOnly = true;
        textarea.value = 'Loading file content...';
        body.append(textarea);
        const footer = document.createElement('div');
        footer.className = 'section-modal-footer';
        const note = document.createElement('span');
        note.className = 'section-modal-note';
        note.textContent = 'Built-in protections cannot be edited here.';
        const actions = document.createElement('div');
        actions.className = 'section-modal-actions';
        const footerClose = document.createElement('button');
        footerClose.type = 'button';
        footerClose.className = 'btn btn-ghost btn-sm';
        footerClose.dataset.wafAction = 'close-crs-editor-modal';
        footerClose.textContent = 'Close';
        actions.append(footerClose);
        footer.append(note, actions);
        panel.append(header, body, footer);
        overlay.append(panel);
        document.body.append(overlay);
        requestAnimationFrame(wafShowCRSEditorModal);
        // Fetch file content (backend returns raw text with ?content=true)
        try {
            const encodedFilename = encodeURIComponent(filename);
            const resp = await fetch('/api/sections/waf_core/rules/crs?file=' + encodedFilename + '&content=true', {
                credentials: 'include'
            });
            const activeTextarea = wafCfgGetElementById('crs-editor-textarea');
            if (activeTextarea) {
                if (resp.ok) {
                    activeTextarea.value = await resp.text();
                }
                else {
                    const data = await wafCfgParseJson(resp);
                    const message = wafCfgApiErrorMessage(data, 'File not found or not readable (HTTP ' + resp.status + ')');
                    activeTextarea.value = '# ' + message;
                }
            }
        }
        catch (e) {
            const activeTextarea = wafCfgGetElementById('crs-editor-textarea');
            if (activeTextarea) {
                activeTextarea.value = '# Error loading file: ' + wafCfgErrorMessage(e, 'Unknown error');
            }
        }
    },
    async bulkToggleCRS(enable) {
        const files = this.crsRules.map(file => file.name);
        if (files.length === 0)
            return;
        const result = await api.requestResult('sections/waf_core/rules/crs/bulk', 'POST', { action: enable ? 'enable' : 'disable', files });
        if (result.error) {
            const details = Array.isArray(result.error.details)
                ? result.error.details
                    .map(item => {
                    const failure = item;
                    return `${failure.file || 'file'}: ${failure.error || 'validation failed'}`;
                })
                    .join('; ')
                : '';
            showSectionToast('Managed rule bulk change failed: ' + (details || result.error.message), 'error');
            await this.loadRulesAndRender();
            return;
        }
        const changed = new Set(result.data?.changed || []);
        const skipped = new Set(result.data?.skipped || []);
        this.crsRules.forEach(file => {
            if (changed.has(file.name) || skipped.has(file.name))
                file.enabled = enable;
        });
        this.crsGroups = this.processCRSRules(this.crsRules);
        showSectionToast(enable ? 'All managed rules enabled' : 'All managed rules disabled', 'success');
        this.render();
    },
    // ========== FULL-PAGE RULE EDITOR ==========
    async openRuleEditor(ruleId) {
        if (ruleId) {
            const data = await api.get('sections/waf_core/rules/custom/' + encodeURIComponent(ruleId));
            if (!data?.rule) {
                showSectionToast('Unable to load the complete rule definition', 'error');
                return;
            }
            this.editingRule = {
                ...data.rule,
                valid: data.valid,
                validation_errors: data.validation_errors
            };
        }
        else {
            this.editingRule = null;
        }
        this.rulesView = 'editor';
        this.render();
    },
    renderRuleEditor() {
        const rule = this.editingRule;
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

        ${this.renderVisualBuilder(rule)}

        <div class="section-editor-footer">
            <button type="button" class="btn btn-outline btn-sm section-btn-inline" data-waf-action="cancel-editor">
                ${SectionUI.icons.x || ''} Cancel
            </button>
            <button type="button" class="btn btn-primary btn-sm section-btn-inline" data-waf-action="submit-custom-rule" data-waf-value="${isEdit}">
                ${SectionUI.icons.check} ${isEdit ? 'Update Rule' : 'Create Rule'}
            </button>
        </div>
    `;
    },
    renderVisualBuilder(rule) {
        // Generate existing conditions HTML if editing
        const conditionsHtml = this.renderConditionRowsFromTargets(rule?.targets);
        /*
         * Note about transforms: rule.targets[0].transforms is array of strings.
         * The renderConditionRow handles selection by checking if value is in that array.
         */
        return `
        <div class="card section-editor-card">
            <h4 class="section-editor-section-title">
                ${SectionUI.icons.tag} Rule Identity
            </h4>
            <div class="section-rule-identity-grid">
                <div class="section-form-group">
                    <label class="section-form-label" for="cr-id">Rule ID</label>
                    <input type="text" id="cr-id" class="section-input ${rule ? 'section-input-readonly' : ''}" placeholder="100001" value="${rule ? escapeWafHtml(rule.id) : ''}" ${rule ? 'readonly' : ''}>
                </div>
                <div class="section-form-group">
                    <label class="section-form-label" for="cr-name">Rule Name</label>
                    <input type="text" id="cr-name" class="section-input" placeholder="e.g. Block Malicious User Agents" value="${rule ? escapeWafHtml(rule.name) : ''}">
                </div>
                <div class="section-form-group">
                    <label class="section-form-label" for="cr-sev">Severity</label>
                    <select id="cr-sev" class="section-input">
                        <option value="critical" ${rule && rule.severity === 'critical' ? 'selected' : ''}>Critical</option>
                        <option value="high" ${rule && rule.severity === 'high' ? 'selected' : ''}>High</option>
                        <option value="medium" ${rule && rule.severity === 'medium' ? 'selected' : ''}>Medium</option>
                        <option value="low" ${rule && rule.severity === 'low' ? 'selected' : ''}>Low</option>
                    </select>
                </div>
            </div>
            <div class="section-rule-identity-grid-secondary">
                <div class="section-form-group">
                    <label class="section-form-label" for="cr-msg">Log Message</label>
                    <input type="text" id="cr-msg" class="section-input" placeholder="e.g. Malicious User Agent Detected" value="${rule ? escapeWafHtml(rule.message || '') : ''}">
                </div>
                <div class="section-form-group">
                    <label class="section-form-label" for="cr-score">Anomaly Score</label>
                    <input type="number" min="1" max="1000" id="cr-score" class="section-input" value="${escapeWafHtml(String(rule?.score || 25))}">
                </div>
                <div class="section-form-group">
                    <label class="section-form-label" for="cr-tags">Tags</label>
                    <input type="text" id="cr-tags" class="section-input" placeholder="custom, account-protection" value="${escapeWafHtml((rule?.tags || ['custom', 'local']).join(', '))}">
                </div>
            </div>
            <div class="section-code-note">
                <div class="section-code-note-icon">${SectionUI.icons.info}</div>
                <div class="section-code-note-text">
                    A matching rule contributes to the request score. The selected protection mode and threshold determine whether the request is logged or blocked.
                </div>
            </div>
            ${rule?.valid === false ? `
                <div class="section-warning-box section-managed-warning">
                    <div class="section-warning-icon">${SectionUI.icons.alertTriangle}</div>
                    <div>
                        <div class="section-warning-title">This stored rule is inactive until repaired</div>
                        <div class="section-warning-text">${escapeWafHtml((rule.validation_errors || ['Invalid rule definition']).join('; '))}</div>
                    </div>
                </div>
            ` : ''}
        </div>

        <div class="card section-editor-card">
            <div class="section-conditions-head">
                <h4 class="section-editor-section-title compact">
                    ${SectionUI.icons.filter} Match Conditions
                </h4>
                <button type="button" class="btn btn-outline btn-sm section-btn-inline" data-waf-action="add-rule-condition">
                    <span>+</span> Add Condition
                </button>
            </div>
            <div id="cr-conditions" class="section-conditions-list">
                ${conditionsHtml}
            </div>
            ${!conditionsHtml ? this.renderEmptyConditionsState() : ''}
        </div>

            <div class="card section-preview-card">
                <h4 class="section-preview-title">
                    ${SectionUI.icons.eye} Rule Preview
                </h4>
                <pre id="rule-preview" class="section-preview-code"># Add conditions to preview this rule</pre>
            </div>
        `;
    },
    renderEmptyConditionsState() {
        return '<div id="cr-empty-conditions" class="section-conditions-empty">Add a condition to define what this rule should match.</div>';
    },
    addRuleCondition(zone = 'headers', field = '', pattern = '', negate = false, operator = '@rx', transforms = []) {
        const container = wafCfgGetElementById('cr-conditions');
        if (!container)
            return;
        // Remove empty state if present
        const emptyState = wafCfgGetElementById('cr-empty-conditions');
        if (emptyState)
            emptyState.remove();
        const rowHtml = this.renderConditionRow(zone, field, pattern, negate, operator, transforms);
        // Create a temp container to turn string into DOM nodes
        const temp = document.createElement('div');
        temp.innerHTML = rowHtml;
        const row = temp.firstElementChild;
        if (!row)
            return;
        container.appendChild(row);
        const operatorField = row.querySelector('.section-condition-operator');
        if (operatorField)
            this.toggleConditionField(operatorField); // Initialize field visibility
        this.updatePreview();
    },
    populateVisualRuleConditions(rule = null) {
        if (rule && rule.targets && rule.targets.length > 0) {
            rule.targets.forEach((target) => {
                if (!target.patterns || target.patterns.length === 0)
                    return;
                target.patterns.forEach((pattern) => {
                    this.addRuleCondition(target.zone, target.field, pattern, target.negate || false, target.operator || '@rx', target.transforms || []);
                });
            });
            return;
        }
        this.addRuleCondition();
    },
    renderConditionRow(zone = 'headers', field = '', pattern = '', negate = false, operator = '@rx', transforms = []) {
        const txOptions = ['lowercase', 'url_decode', 'html_entity_decode', 'base64_decode', 'hex_decode', 'remove_comments', 'remove_whitespace', 'compress_whitespace', 'normalize_path'];
        return `
        <div class="section-condition-row">
            <div class="section-condition-head">
                 <h5 class="section-condition-title">Condition</h5>
                 <button type="button" class="btn-icon section-condition-remove"
                         data-waf-action="remove-section-condition-row" aria-label="Remove condition">
                    <span class="section-condition-remove-icon">×</span>
                </button>
            </div>

            <div class="section-condition-grid">
                <div class="section-form-group">
                    <label class="section-form-label">Zone</label>
                    <select class="section-condition-zone section-input" aria-label="Zone">
                        <option value="headers" ${zone === 'headers' ? 'selected' : ''}>Headers</option>
                        <option value="args" ${zone === 'args' ? 'selected' : ''}>Query Params</option>
                        <option value="cookies" ${zone === 'cookies' ? 'selected' : ''}>Cookies</option>
                        <option value="body" ${zone === 'body' ? 'selected' : ''}>Body</option>
                        <option value="uri" ${zone === 'uri' ? 'selected' : ''}>Request URI</option>
                        <option value="path" ${zone === 'path' ? 'selected' : ''}>URL Path</option>
                        <option value="method" ${zone === 'method' ? 'selected' : ''}>Method</option>
                        <option value="client_ip" ${zone === 'client_ip' ? 'selected' : ''}>Client IP</option>
                    </select>
                </div>
                <div class="section-form-group">
                    <label class="section-form-label">Operator</label>
                    <div class="section-operator-row">
                         <button type="button" class="btn ${negate ? 'btn-danger' : 'btn-outline'}"
                                 data-waf-action="toggle-negate"
                                 title="Invert match condition" aria-pressed="${negate ? 'true' : 'false'}">
                            NOT
                        </button>
                        <input type="checkbox" class="section-condition-negate section-hidden-input" ${negate ? 'checked' : ''} aria-hidden="true" tabindex="-1">
                        <select class="section-condition-operator section-input" aria-label="Match operator">
                            <option value="@rx" ${operator === '@rx' ? 'selected' : ''}>Regex</option>
                            <option value="@streq" ${operator === '@streq' ? 'selected' : ''}>Equals</option>
                            <option value="@contains" ${operator === '@contains' ? 'selected' : ''}>Contains</option>
                            <option value="@ipMatch" ${operator === '@ipMatch' ? 'selected' : ''}>IP Match</option>
                        </select>
                    </div>
                </div>
                <div class="section-form-group">
                    <label class="section-form-label">Field Name</label>
                    <input type="text" class="section-condition-field section-input" aria-label="Field name" placeholder="e.g. User-Agent" value="${escapeWafHtml(field || '')}">
                </div>
                <div class="section-form-group">
                    <label class="section-form-label">Pattern</label>
                    <input type="text" class="section-condition-pattern section-input section-pattern-input" aria-label="Match pattern" placeholder="Regex or value" value="${escapeWafHtml(pattern || '')}">
                </div>
            </div>
            <div class="section-form-group">
                <label class="section-form-label">Transforms</label>
                <div class="section-transform-list">
                    ${txOptions.map(t => `
                        <label class="section-transform-chip ${transforms.includes(t) ? 'active' : ''}">
                            <input type="checkbox" class="section-condition-transform section-hidden-input" value="${escapeWafHtml(t)}" ${transforms.includes(t) ? 'checked' : ''}>
                            ${escapeWafHtml(t.replace(/_/g, ' '))}
                        </label>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
    },
    toggleConditionField(element) {
        const row = element.closest('.section-condition-row');
        if (!row)
            return;
        const zoneSelect = row.querySelector('.section-condition-zone');
        const operatorSelect = row.querySelector('.section-condition-operator');
        const fieldInput = row.querySelector('.section-condition-field');
        const patternInput = row.querySelector('.section-condition-pattern');
        const fieldWrap = fieldInput ? fieldInput.closest('.section-form-group') : null;
        const patternWrap = patternInput ? patternInput.closest('.section-form-group') : null;
        if (!zoneSelect || !operatorSelect)
            return;
        const needsField = ['headers', 'args', 'cookies'].includes(zoneSelect.value);
        if (fieldWrap)
            fieldWrap.classList.toggle('is-hidden', !needsField);
        const op = operatorSelect.value;
        if (patternInput && patternWrap) {
            patternWrap.classList.remove('is-hidden');
            if (op === '@ipMatch' || zoneSelect.value === 'client_ip') {
                patternInput.placeholder = 'IP or CIDR (e.g. 192.168.1.0/24)';
            }
            else if (op === '@streq') {
                patternInput.placeholder = 'Exact string match';
            }
            else if (op === '@contains') {
                patternInput.placeholder = 'Substring to match';
            }
            else {
                patternInput.placeholder = 'Regex pattern';
            }
        }
    },
    updatePreview() {
        const preview = wafCfgGetElementById('rule-preview');
        if (!preview)
            return;
        const id = wafCfgGetControlValue('cr-id', '100001');
        const msg = wafCfgGetControlValue('cr-msg', 'Custom Rule');
        const score = wafCfgGetControlValue('cr-score', '25');
        const conditions = [];
        document.querySelectorAll('#cr-conditions .section-condition-row').forEach((row) => {
            const zone = row.querySelector('.section-condition-zone')?.value || '';
            const op = row.querySelector('.section-condition-operator')?.value || '@rx';
            const field = row.querySelector('.section-condition-field')?.value || '';
            const pattern = row.querySelector('.section-condition-pattern')?.value || '';
            const negate = row.querySelector('.section-condition-negate')?.checked || false;
            const transforms = Array.from(row.querySelectorAll('.section-condition-transform:checked')).map((cb) => cb.value);
            let zoneName = zone.toUpperCase();
            if (zoneName === 'HEADERS')
                zoneName = 'REQUEST_HEADERS';
            if (zoneName === 'BODY')
                zoneName = 'REQUEST_BODY';
            if (zoneName === 'URI')
                zoneName = 'REQUEST_URI';
            if (zoneName === 'PATH')
                zoneName = 'URL_PATH';
            if (zoneName === 'METHOD')
                zoneName = 'REQUEST_METHOD';
            if (zoneName === 'CLIENT_IP')
                zoneName = 'REMOTE_ADDR';
            if (field)
                zoneName += ':' + field;
            conditions.push({ zoneName, op, pattern, negate, transforms });
        });
        if (conditions.length === 0) {
            preview.textContent = '# Add conditions above to see a preview';
            return;
        }
        const operatorLabels = {
            '@rx': 'matches regex',
            '@streq': 'equals',
            '@contains': 'contains',
            '@ipMatch': 'matches IP/CIDR'
        };
        const lines = conditions.map((condition, index) => {
            const transformText = condition.transforms.length > 0
                ? ` after ${condition.transforms.join(' → ')}`
                : '';
            return `${index + 1}. ${condition.negate ? 'NOT ' : ''}${condition.zoneName} ${operatorLabels[condition.op] || condition.op} ${JSON.stringify(condition.pattern)}${transformText}`;
        });
        preview.textContent = [
            `Rule ${id}: ${msg}`,
            'Evaluation: match when ANY condition below succeeds.',
            ...lines,
            `On match: add ${score} to the request anomaly score.`
        ].join('\n');
    },
    async submitCustomRule(isEdit = false) {
        const id = wafCfgGetControlValue('cr-id').trim();
        const name = wafCfgGetControlValue('cr-name').trim();
        const msg = wafCfgGetControlValue('cr-msg');
        const sev = wafCfgGetControlValue('cr-sev');
        const score = Number.parseInt(wafCfgGetControlValue('cr-score', '25'), 10);
        const tags = parseWafCSVList(wafCfgGetControlValue('cr-tags', 'custom, local'));
        if (!id || !name) {
            showSectionToast('Rule ID and Name are required', 'error');
            return;
        }
        if (!Number.isFinite(score) || score < 1 || score > 1000) {
            showSectionToast('Anomaly score must be between 1 and 1000', 'error');
            return;
        }
        const targets = [];
        document.querySelectorAll('#cr-conditions .section-condition-row').forEach((row) => {
            const zone = row.querySelector('.section-condition-zone')?.value || '';
            const operator = row.querySelector('.section-condition-operator')?.value || '@rx';
            const field = row.querySelector('.section-condition-field')?.value.trim() || '';
            const pattern = row.querySelector('.section-condition-pattern')?.value.trim() || '';
            const negate = row.querySelector('.section-condition-negate')?.checked || false;
            const transforms = Array.from(row.querySelectorAll('.section-condition-transform:checked')).map((o) => o.value);
            if (pattern) {
                targets.push({
                    zone, operator, field: field || undefined,
                    patterns: [pattern], negate,
                    transforms: transforms.length > 0 ? transforms : undefined
                });
            }
        });
        if (targets.length === 0) {
            showSectionToast('At least one condition with a pattern is required', 'error');
            return;
        }
        const payload = {
            schema_version: this.editingRule?.schema_version || 1,
            id,
            name,
            message: msg || name,
            severity: sev,
            score,
            enabled: this.editingRule?.enabled !== false,
            tags: tags.length > 0 ? tags : ['custom', 'local'],
            targets
        };
        const result = await api.requestResult('sections/waf_core/rules/custom' + (isEdit ? '/' + encodeURIComponent(id) : ''), isEdit ? 'PUT' : 'POST', payload);
        if (result.error) {
            showSectionToast('Failed to ' + (isEdit ? 'update' : 'create') + ' rule: ' + result.error.message, 'error');
            return;
        }
        showSectionToast('Rule ' + (isEdit ? 'updated' : 'created') + ' successfully', 'success');
        await this.loadRules();
        this.rulesView = 'main';
        this.editingRule = null;
        this.render();
    },
    processCRSRules(files) {
        const groups = {};
        files.forEach(f => {
            const group = f.group || 'Other Rules';
            if (!groups[group])
                groups[group] = [];
            groups[group].push(f);
        });
        return groups;
    },
    // ========== RULE ACTIONS ==========
    async toggleCustomRule(id, enabled) {
        const rule = this.rules.find(r => r.id === id);
        if (!rule)
            return;
        const previous = rule.enabled !== false;
        rule.enabled = enabled;
        const result = await api.requestResult('sections/waf_core/rules/custom/' + encodeURIComponent(id) + '/enabled', 'PATCH', { enabled });
        if (result.error) {
            rule.enabled = previous;
            showSectionToast('Failed to update rule status: ' + result.error.message, 'error');
            this.render();
            return;
        }
        if (result.data?.rule)
            Object.assign(rule, result.data.rule);
        showSectionToast('Rule ' + (enabled ? 'enabled' : 'disabled'), 'success');
    },
    async toggleCRSFile(filename, enabled) {
        const action = enabled ? 'enable' : 'disable';
        const result = await api.requestResult('sections/waf_core/rules/crs?file=' + encodeURIComponent(filename) + '&action=' + action, 'POST');
        if (result.error) {
            showSectionToast('Failed to toggle rule file: ' + result.error.message, 'error');
            await this.loadRulesAndRender();
            return;
        }
        const file = this.crsRules.find(f => f.name === filename);
        if (file)
            file.enabled = enabled;
        this.crsGroups = this.processCRSRules(this.crsRules);
        showSectionToast('File ' + action + 'd', 'success');
    },
    async deleteRule(id) {
        if (!confirm('Delete rule ' + id + '?'))
            return;
        const deleted = await api.delete('sections/waf_core/rules/custom/' + encodeURIComponent(id));
        if (!deleted) {
            showSectionToast('Failed to delete rule', 'error');
            return;
        }
        showSectionToast('Rule deleted', 'success');
        this.rules = this.rules.filter(r => r.id !== id);
        this.render();
    },
    // ========== OTHER TABS ==========
    renderExclusions() {
        const normalized = [...this.exclusions].sort((a, b) => {
            const enabledA = a.enabled !== false;
            const enabledB = b.enabled !== false;
            if (enabledA !== enabledB)
                return enabledA ? -1 : 1;
            const createdA = Date.parse(a.created_at || '') || 0;
            const createdB = Date.parse(b.created_at || '') || 0;
            return createdB - createdA;
        });
        const filtered = this.getFilteredExclusions(normalized);
        const count = normalized.length;
        const activeCount = normalized.filter(e => e.enabled !== false && !this.isExclusionExpired(e)).length;
        const expiredCount = this.countExpiredExclusions(normalized);
        const tableRows = filtered.map(ex => {
            const scopeParts = [];
            if (ex.paths && ex.paths.length)
                scopeParts.push(...ex.paths.map(p => `Path: ${p}`));
            if (ex.params && ex.params.length)
                scopeParts.push(...ex.params.map(p => `Param: ${p}`));
            if (ex.ips && ex.ips.length)
                scopeParts.push(...ex.ips.map(ip => `IP: ${ip}`));
            const expired = this.isExclusionExpired(ex);
            const enabled = ex.enabled !== false;
            const reason = ex.reason || ex.description || '-';
            const expiryText = ex.expires_at ? new Date(ex.expires_at).toLocaleString() : 'Never';
            return [
                `<div class="config-table-primary">${escapeWafHtml(ex.rule_id || 'Global')}</div><div class="config-table-sub">${ex.rule_id ? 'Specific rule' : 'All rules'}</div>`,
                `<span class="config-table-sub">${escapeWafHtml(scopeParts.join(', ') || 'Global scope')}</span>`,
                `<span class="config-table-sub">${escapeWafHtml(reason)}</span>`,
                `<span class="config-table-sub">${escapeWafHtml(expiryText)}</span>`,
                `<div class="config-table-actions">
                    ${SectionUI.renderSwitch({
                    checked: enabled,
                    className: 'section-switch-sm',
                    attrs: `aria-label="${enabled ? 'Disable' : 'Enable'} Exclusion ${escapeWafHtml(ex.id)}" data-waf-action="toggle-exclusion" data-waf-value="${escapeWafHtml(ex.id)}"`
                })}
                    <button type="button" class="btn btn-ghost btn-sm text-danger" data-waf-action="delete-exclusion" data-waf-value="${escapeWafHtml(ex.id)}">Delete</button>
                </div>`
            ];
        });
        return `
            ${this.renderWafModuleStatusCard('Rule Exclusions', 'Create targeted exceptions when valid traffic is incorrectly detected.', 'filter', expiredCount === 0, '', expiredCount > 0 ? 'Needs Review' : 'Active')}
            <div class="config-list-stack">
                <div class="config-toolbar">
                    <input type="text" class="section-input config-toolbar-search" value="${escapeWafHtml(this.exclusionQuery)}" data-waf-state="exclusionQuery" placeholder="Search exclusions">
                    <select class="section-input config-toolbar-select" data-waf-state="exclusionScope">
                        <option value="all" ${this.exclusionScope === 'all' ? 'selected' : ''}>All Scopes</option>
                        <option value="global" ${this.exclusionScope === 'global' ? 'selected' : ''}>Global Only</option>
                        <option value="rule" ${this.exclusionScope === 'rule' ? 'selected' : ''}>Rule-Specific</option>
                        <option value="active" ${this.exclusionScope === 'active' ? 'selected' : ''}>Active</option>
                        <option value="inactive" ${this.exclusionScope === 'inactive' ? 'selected' : ''}>Inactive</option>
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
    },
    renderConditionRowsFromTargets(targets = []) {
        return targets.map((target) => this.renderConditionRowFromTarget(target)).join('');
    },
    showExclusionModal() {
        const container = wafCfgGetElementById('exclusion-modal-container');
        if (!container)
            return;
        container.innerHTML = `
            <div class="section-modal-overlay section-modal-overlay-padded section-excl-modal-overlay is-open is-visible" data-waf-action="close-exclusion-overlay">
                <div class="section-modal-panel section-modal-panel-md section-excl-modal-dialog">
                    <div class="section-modal-head">
                        <div class="section-excl-modal-head-main">
                            <div class="section-excl-modal-icon">${this.getIcon('filter')}</div>
                            <div>
                                <h3 class="section-modal-title">Add Rule Exclusion</h3>
                                <div class="section-modal-sub">Add an exception for valid traffic that should not be blocked.</div>
                            </div>
                        </div>
                        <button type="button" class="btn btn-ghost btn-sm section-excl-modal-close" data-waf-action="close-exclusion-modal" aria-label="Close dialog">&times;</button>
                    </div>

                    <div class="section-modal-body section-excl-modal-body">
                        <div class="section-excl-field">
                            <label class="section-excl-label">Rule ID <span>(leave empty for global)</span></label>
                            <input id="excl-rule-id" type="text" class="section-input section-excl-input-mono" placeholder="e.g. 942100">
                        </div>

                        <div class="section-excl-field">
                            <label class="section-excl-label">Paths <span>(comma-separated)</span></label>
                            <input id="excl-paths" type="text" class="section-input" placeholder="e.g. /api/upload, /webhook">
                        </div>

                        <div class="section-excl-field">
                            <label class="section-excl-label">Parameters <span>(comma-separated)</span></label>
                            <input id="excl-params" type="text" class="section-input" placeholder="e.g. ARGS:content, ARGS:body, ARGS:payload">
                        </div>

                        <div class="section-excl-field">
                            <label class="section-excl-label">IP/CIDR <span>(comma-separated, optional)</span></label>
                            <input id="excl-ips" type="text" class="section-input" placeholder="e.g. 192.168.1.10, 10.0.0.0/24">
                        </div>

                        <div class="section-excl-field">
                            <label class="section-excl-label">Expires At <span>(optional)</span></label>
                            <input id="excl-expires-at" type="datetime-local" class="section-input">
                        </div>

                        <div class="section-excl-field tight">
                            <label class="section-excl-label">Reason</label>
                            <input id="excl-reason" type="text" class="section-input" placeholder="Why is this exclusion needed?">
                        </div>

                        <div class="section-excl-enabled-wrap">
                            ${SectionUI.renderSwitch({
            id: 'excl-enabled',
            checked: true,
            label: 'Enable immediately'
        })}
                        </div>
                    </div>

                    <div class="section-modal-footer section-excl-modal-footer">
                        <button type="button" class="btn btn-ghost" data-waf-action="close-exclusion-modal">Cancel</button>
                        <button type="button" class="btn btn-primary" data-waf-action="add-exclusion">Add Exclusion</button>
                    </div>
                </div>
            </div>
        `;
    },
    async addExclusion() {
        const ruleId = wafCfgGetControlValue('excl-rule-id').trim();
        const pathsRaw = wafCfgGetControlValue('excl-paths').trim();
        const paramsRaw = wafCfgGetControlValue('excl-params').trim();
        const ipsRaw = wafCfgGetControlValue('excl-ips').trim();
        const reason = wafCfgGetControlValue('excl-reason').trim();
        const expiresRaw = wafCfgGetControlValue('excl-expires-at').trim();
        const enabled = wafCfgGetCheckboxValue('excl-enabled');
        if (ruleId && !/^\d+$/.test(ruleId)) {
            showSectionToast('Rule ID must be numeric', 'error');
            return;
        }
        const paths = parseWafCSVList(pathsRaw);
        const params = parseWafCSVList(paramsRaw);
        const ips = parseWafCSVList(ipsRaw);
        if (!ruleId && paths.length === 0) {
            showSectionToast('Add a path for a global exclusion, or enter a rule ID.', 'error');
            return;
        }
        if (!ruleId && (params.length > 0 || ips.length > 0)) {
            showSectionToast('Parameter and IP exclusions need a rule ID.', 'error');
            return;
        }
        const exclusion = {
            reason: reason || '',
            enabled
        };
        if (ruleId)
            exclusion.rule_id = ruleId;
        if (paths.length)
            exclusion.paths = paths;
        if (params.length)
            exclusion.params = params;
        if (ips.length)
            exclusion.ips = ips;
        if (expiresRaw)
            exclusion.expires_at = new Date(expiresRaw).toISOString();
        try {
            const data = await api.post('sections/waf_core/exclusions', exclusion);
            if (!data)
                throw new Error('The exclusion was not saved');
            const createdExclusion = data && typeof data === 'object' && 'exclusion' in data
                ? data.exclusion
                : undefined;
            if (createdExclusion)
                this.exclusions.push(createdExclusion);
            else
                await this.loadExclusions();
            const modalContainer = wafCfgGetElementById('exclusion-modal-container');
            if (modalContainer)
                modalContainer.innerHTML = '';
            showSectionToast('Exclusion added', 'success');
            this.render();
        }
        catch (e) {
            console.error('Failed to add exclusion', e);
            showSectionToast(wafCfgErrorMessage(e, 'Failed to add exclusion'), 'error');
        }
    },
    async deleteExclusion(id) {
        if (!confirm('Delete this exclusion?'))
            return;
        const deleted = await api.delete('sections/waf_core/exclusions/' + encodeURIComponent(id));
        if (!deleted) {
            showSectionToast('Failed to delete exclusion', 'error');
            return;
        }
        this.exclusions = this.getExclusionsWithoutId(id);
        showSectionToast('Exclusion deleted', 'success');
        this.render();
    },
    async toggleExclusionEnabled(id, enabled) {
        const current = this.exclusions.find(e => e.id === id);
        if (!current)
            return;
        const payload = {
            ...current,
            reason: current.reason || current.description || '',
            enabled
        };
        const result = await api.requestResult('sections/waf_core/exclusions/' + encodeURIComponent(id), 'PUT', payload);
        if (result.error) {
            showSectionToast('Failed to update exclusion: ' + result.error.message, 'error');
            this.render();
            return;
        }
        const idx = this.exclusions.findIndex(e => e.id === id);
        if (idx >= 0) {
            this.exclusions[idx] = result.data?.exclusion || { ...current, enabled };
        }
        showSectionToast(`Exclusion ${enabled ? 'enabled' : 'disabled'}`, 'success');
        this.render();
    },
    matchesExclusionFilter(ex) {
        const scope = this.exclusionScope;
        const isGlobal = !ex.rule_id;
        const enabled = ex.enabled !== false;
        if (scope === 'global' && !isGlobal)
            return false;
        if (scope === 'rule' && isGlobal)
            return false;
        if (scope === 'active' && !enabled)
            return false;
        if (scope === 'inactive' && enabled)
            return false;
        const q = (this.exclusionQuery || '').trim().toLowerCase();
        if (!q)
            return true;
        const haystack = [
            ex.rule_id,
            ex.reason,
            ex.description,
            ...(ex.paths || []),
            ...(ex.params || []),
            ...(ex.ips || [])
        ].filter(Boolean).join(' ').toLowerCase();
        return haystack.includes(q);
    },
    isExclusionExpired(ex) {
        if (!ex.expires_at)
            return false;
        const ts = Date.parse(ex.expires_at);
        if (!ts)
            return false;
        return Date.now() > ts;
    },
    showCRSEditorModal() {
        const modal = wafCfgGetElementById('crs-editor-modal');
        if (modal)
            modal.classList.add('is-visible');
    },
    renderConditionRowFromTarget(target) {
        return this.renderConditionRow(target.zone, target.field, target.patterns ? target.patterns[0] : '', target.negate, target.operator, target.transforms);
    },
    getFilteredExclusions(exclusions) {
        const filtered = [];
        for (const exclusion of exclusions) {
            if (this.matchesExclusionFilter(exclusion)) {
                filtered.push(exclusion);
            }
        }
        return filtered;
    },
    countExpiredExclusions(exclusions) {
        let count = 0;
        for (const exclusion of exclusions) {
            if (this.isExclusionExpired(exclusion))
                count++;
        }
        return count;
    },
    getExclusionsWithoutId(id) {
        const exclusions = [];
        for (const exclusion of this.exclusions) {
            if (exclusion.id !== id)
                exclusions.push(exclusion);
        }
        return exclusions;
    },
    async loadRulesAndRender() {
        await this.loadRules();
        this.render();
    },
    renderProtectionProfiles() {
        const currentId = this.config.active_profile_id;
        if (!this.profiles || this.profiles.length === 0) {
            return `
                <div class="section-profile-library-empty">
                    <div class="section-profile-library-empty-icon">${SectionUI.icons.search || ''}</div>
                    <p>No protection profiles are available yet.</p>
                </div>
            `;
        }
        return this.profiles.map(p => {
            const isActive = currentId === p.id;
            const icon = (SectionUI.icons[p.icon || ''] || SectionUI.icons.file) || '';
            let levelTone = 'success';
            if ((p.paranoia_level || 1) >= 4)
                levelTone = 'danger';
            else if ((p.paranoia_level || 1) >= 3)
                levelTone = 'warning';
            return `
                <button type="button" class="section-profile-row ${isActive ? 'is-active' : ''}" data-waf-action="apply-profile" data-waf-value="${escapeWafHtml(p.id)}" aria-pressed="${isActive ? 'true' : 'false'}" aria-label="${isActive ? 'Active protection profile' : 'Apply protection profile'}: ${escapeWafHtml(p.name)}">
                    <div class="section-profile-row-icon ${levelTone}">
                        ${String(icon).replace('width="16"', 'width="18"').replace('height="16"', 'height="18"')}
                    </div>
                    <div class="section-profile-row-main">
                        <div class="section-profile-row-title">${escapeWafHtml(p.name)}</div>
                        <div class="section-profile-row-desc">${escapeWafHtml(p.description || 'Balanced protection for common application traffic.')}</div>
                    </div>
                    <div class="section-profile-row-meta">
                        <span>PL ${escapeWafHtml(String(p.paranoia_level || 1))}</span>
                        <span>${escapeWafHtml(String(p.anomaly_threshold || 5))} pts</span>
                        <strong>${isActive ? 'Active' : 'Apply'}</strong>
                    </div>
                </button>
            `;
        }).join('');
    },
    applyProfile(id) {
        this.updateField('active_profile_id', id);
    },
    stageLeakConfig(leak) {
        this.config.leak_protection = {
            ...leak,
            inspect_content_types: [...(leak.inspect_content_types || [])],
            skip_content_types: [...(leak.skip_content_types || [])],
            rules: { ...(leak.rules || {}) },
            custom_patterns: (leak.custom_patterns || []).map(pattern => ({ ...pattern })),
            allowlist: (leak.allowlist || []).map(entry => ({ ...entry }))
        };
        this.render();
        SectionUI.markSaveActionBarDirty('data-section-action');
    },
    addLeakMime(scope) {
        if (scope !== 'inspect' && scope !== 'skip')
            return;
        const mimeType = wafCfgGetControlValue('firewall-leak-mime-' + scope).trim().toLowerCase();
        if (!/^[^/\s]+\/[^/\s]+$/.test(mimeType)) {
            showSectionToast('Enter a MIME type such as application/json or image/*', 'warning');
            return;
        }
        const leak = getWafLeakProtectionConfig(this.config);
        const field = scope === 'inspect' ? 'inspect_content_types' : 'skip_content_types';
        const configured = [...(leak[field] || [])];
        if (configured.some(value => value.toLowerCase() === mimeType)) {
            showSectionToast('That MIME type is already configured', 'info');
            return;
        }
        leak[field] = [...configured, mimeType];
        this.stageLeakConfig(leak);
    },
    removeLeakMime(scope, mimeType) {
        if ((scope !== 'inspect' && scope !== 'skip') || !mimeType)
            return;
        const leak = getWafLeakProtectionConfig(this.config);
        const field = scope === 'inspect' ? 'inspect_content_types' : 'skip_content_types';
        leak[field] = (leak[field] || []).filter(value => value.toLowerCase() !== mimeType.toLowerCase());
        this.stageLeakConfig(leak);
    },
    toggleLeakMimeGroup(groupId, enabled) {
        const leak = getWafLeakProtectionConfig(this.config);
        const group = leakMimeGroups.find(g => g.id === groupId);
        if (!group)
            return;
        let current = [...(leak.inspect_content_types || [])];
        if (enabled) {
            for (const mime of group.mimeTypes) {
                if (!current.some(m => m.toLowerCase() === mime.toLowerCase())) {
                    current.push(mime);
                }
            }
        }
        else {
            current = current.filter(m => !group.mimeTypes.some(gm => gm.toLowerCase() === m.toLowerCase()));
        }
        leak.inspect_content_types = current;
        this.stageLeakConfig(leak);
    },
    addLeakPattern() {
        const name = wafCfgGetControlValue('firewall-leak-pattern-name').trim();
        const pattern = wafCfgGetControlValue('firewall-leak-pattern-expression').trim();
        const category = wafCfgGetControlValue('firewall-leak-pattern-category', 'custom').trim() || 'custom';
        const action = wafCfgGetControlValue('firewall-leak-pattern-action').trim();
        if (!name || !pattern) {
            showSectionToast('Provide a detector name and regular expression', 'warning');
            return;
        }
        const leak = getWafLeakProtectionConfig(this.config);
        leak.custom_patterns = [
            ...(leak.custom_patterns || []),
            {
                id: 'leak.custom.' + Date.now().toString(36),
                name,
                pattern,
                category,
                severity: 'medium',
                action,
                enabled: true,
                confidence: 75
            }
        ];
        this.stageLeakConfig(leak);
    },
    removeLeakPattern(id) {
        if (!id)
            return;
        const leak = getWafLeakProtectionConfig(this.config);
        leak.custom_patterns = (leak.custom_patterns || []).filter(pattern => pattern.id !== id);
        this.stageLeakConfig(leak);
    },
    addLeakAllowlist() {
        const host = wafCfgGetControlValue('firewall-leak-allowlist-host').trim();
        const path = wafCfgGetControlValue('firewall-leak-allowlist-path').trim();
        const contentType = wafCfgGetControlValue('firewall-leak-allowlist-content-type').trim();
        const category = wafCfgGetControlValue('firewall-leak-allowlist-category').trim();
        const reason = wafCfgGetControlValue('firewall-leak-allowlist-reason').trim();
        const expiryValue = wafCfgGetControlValue('firewall-leak-allowlist-expires').trim();
        if (!host && !path && !contentType) {
            showSectionToast('Bound the exception to a host, path, or content type', 'warning');
            return;
        }
        if (!reason) {
            showSectionToast('Add a reason before staging an allowlist exception', 'warning');
            return;
        }
        let expiresAt = '';
        if (expiryValue) {
            const expiry = new Date(expiryValue + 'T00:00:00.000Z');
            if (Number.isNaN(expiry.getTime())) {
                showSectionToast('Enter a valid allowlist expiry date', 'warning');
                return;
            }
            expiresAt = expiry.toISOString();
        }
        const leak = getWafLeakProtectionConfig(this.config);
        leak.allowlist = [
            ...(leak.allowlist || []),
            {
                id: 'leak.allowlist.' + Date.now().toString(36),
                enabled: true,
                category,
                host,
                path,
                content_type: contentType,
                expires_at: expiresAt,
                reason
            }
        ];
        this.stageLeakConfig(leak);
    },
    removeLeakAllowlist(id) {
        if (!id)
            return;
        const leak = getWafLeakProtectionConfig(this.config);
        leak.allowlist = (leak.allowlist || []).filter(entry => entry.id !== id);
        this.stageLeakConfig(leak);
    },
    resolveProfileNumber(profile, keys, fallback) {
        for (const key of keys) {
            const value = profile[key];
            if (typeof value === 'number' && Number.isFinite(value))
                return value;
            if (typeof value === 'string' && value.trim() !== '') {
                const parsed = Number.parseInt(value, 10);
                if (Number.isFinite(parsed))
                    return parsed;
            }
        }
        return fallback;
    },
    applyProfileDefaults(profile) {
        if (profile.enforcement_mode === 'blocking' || profile.enforcement_mode === 'detection') {
            this.config.mode = profile.enforcement_mode;
        }
        this.config.rule_strictness = this.resolveProfileNumber(profile, ['paranoia_level', 'rule_strictness', 'strictness', 'paranoiaLevel'], this.config.rule_strictness || 1);
        this.config.anomaly_threshold = this.resolveProfileNumber(profile, ['anomaly_threshold', 'threshold', 'anomalyThreshold', 'score_threshold'], this.config.anomaly_threshold || 5);
        if (typeof profile.response_inspection === 'boolean') {
            this.config.response_inspection = profile.response_inspection;
        }
    },
    updateField(field, value) {
        const path = field.split('.').filter(Boolean);
        if (path.length <= 1) {
            this.config[field] = value;
        }
        else {
            if (path[0] === 'leak_protection') {
                this.config.leak_protection = getWafLeakProtectionConfig(this.config);
            }
            let target = this.config;
            for (let index = 0; index < path.length - 1; index += 1) {
                const key = path[index];
                const current = target[key];
                if (!current || typeof current !== 'object' || Array.isArray(current)) {
                    target[key] = {};
                }
                target = target[key];
            }
            target[path[path.length - 1]] = value;
        }
        if (field === 'mode' && (value === 'detection' || value === 'blocking')) {
            this.lastEnabledMode = value;
        }
        // SMART GUARDRAILS: Auto-update related settings when profile changes
        if (field === 'active_profile_id') {
            const profile = this.profiles.find(p => p.id === value);
            if (profile) {
                this.applyProfileDefaults(profile);
                showSectionToast(`Applied recommended settings for ${profile.name}`, 'info');
            }
        }
        // CUSTOM MODE LOGIC: Switch to Custom if detailed settings are tweaked manually
        if (field === 'rule_strictness' || field === 'anomaly_threshold') {
            if (this.config.active_profile_id) {
                this.config.active_profile_id = ""; // Switch to Custom
                showSectionToast('Switched to Custom Configuration', 'info');
            }
        }
        this.render(); // Re-render to show pending change state (save button will be available)
        SectionUI.markSaveActionBarDirty('data-section-action');
    },
    async saveConfig() {
        await saveSectionConfig({
            endpoint: 'sections/waf_core/config',
            config: this.config,
            successMessage: 'Configuration saved successfully',
            failureMessage: 'Failed to save configuration'
        });
        await this.loadConfig();
        this.render();
        SectionUI.markSaveActionBarClean('data-section-action');
    }
};
const wafPopulateVisualRuleConditions = () => {
    WAFConfig.populateVisualRuleConditions(WAFConfig.editingRule);
};
const wafShowCRSEditorModal = WAFConfig.showCRSEditorModal.bind(WAFConfig);
const WAFConfigState = {
    get currentTab() { return WAFConfig.currentTab; },
    set currentTab(value) { WAFConfig.currentTab = value; },
    get config() { return WAFConfig.config; },
    set config(value) { WAFConfig.config = value; },
    get health() { return WAFConfig.health; },
    set health(value) { WAFConfig.health = value; },
    get stats() { return WAFConfig.stats; },
    set stats(value) { WAFConfig.stats = value; },
    get rules() { return WAFConfig.rules; },
    set rules(value) { WAFConfig.rules = value; },
    get crsRules() { return WAFConfig.crsRules; },
    set crsRules(value) { WAFConfig.crsRules = value; },
    get crsGroups() { return WAFConfig.crsGroups; },
    set crsGroups(value) { WAFConfig.crsGroups = value; },
    get profiles() { return WAFConfig.profiles; },
    set profiles(value) { WAFConfig.profiles = value; },
    get exclusions() { return WAFConfig.exclusions; },
    set exclusions(value) { WAFConfig.exclusions = value; },
    get exclusionQuery() { return WAFConfig.exclusionQuery; },
    set exclusionQuery(value) { WAFConfig.exclusionQuery = value; },
    get exclusionScope() { return WAFConfig.exclusionScope; },
    set exclusionScope(value) { WAFConfig.exclusionScope = value; },
    get isLoading() { return WAFConfig.isLoading; },
    set isLoading(value) { WAFConfig.isLoading = value; },
    get loadError() { return WAFConfig.loadError; },
    set loadError(value) { WAFConfig.loadError = value; },
    get rulesView() { return WAFConfig.rulesView; },
    set rulesView(value) { WAFConfig.rulesView = value; },
    get editingRule() { return WAFConfig.editingRule; },
    set editingRule(value) { WAFConfig.editingRule = value; },
    get refreshInterval() { return WAFConfig.refreshInterval; },
    set refreshInterval(value) { WAFConfig.refreshInterval = value; }
};
const WAFConfigService = {
    init: () => WAFConfig.init(),
    startRefresh: () => WAFConfig.startRefresh(),
    loadConfig: () => WAFConfig.loadConfig(),
    loadStats: (silent) => WAFConfig.loadStats(silent),
    loadRules: () => WAFConfig.loadRules(),
    loadProfiles: () => WAFConfig.loadProfiles(),
    loadExclusions: () => WAFConfig.loadExclusions(),
    saveConfig: () => WAFConfig.saveConfig()
};
const WAFConfigView = {
    getIcon: WAFConfig.getIcon.bind(WAFConfig),
    renderSectionHeader: (icon, title, desc) => WAFConfig.renderSectionHeader(icon, title, desc),
    render: () => WAFConfig.render(),
    renderTabContent: () => WAFConfig.renderTabContent(),
    renderOverview: () => WAFConfig.renderOverview(),
    renderManagedRules: () => WAFConfig.renderManagedRules(),
    renderReloadHealth: () => WAFConfig.renderReloadHealth(),
    renderRules: () => WAFConfig.renderRules(),
    renderExclusions: () => WAFConfig.renderExclusions(),
    renderProtectionProfiles: () => WAFConfig.renderProtectionProfiles(),
    renderRuleEditor: () => WAFConfig.renderRuleEditor(),
    renderManagedRulesFolder: () => WAFConfig.renderManagedRulesFolder(),
    renderCustomRulesList: () => WAFConfig.renderCustomRulesList(),
    renderRulesMain: () => WAFConfig.renderRulesMain(),
    renderTrafficChart: (history) => WAFConfig.renderTrafficChart(history),
    updateDashboardUI: () => WAFConfig.updateDashboardUI(),
    showToast: showSectionToast
};
const WAFConfigController = {
    switchTab: (id) => WAFConfig.switchTab(id),
    toggleAdvancedSettings: () => WAFConfig.toggleAdvancedSettings(),
    openCRSEditor: (filename) => WAFConfig.openCRSEditor(filename),
    bulkToggleCRS: (enable) => WAFConfig.bulkToggleCRS(enable),
    openRuleEditor: (ruleId) => WAFConfig.openRuleEditor(ruleId),
    addRuleCondition: (zone, field, pattern, negate, operator, transforms) => WAFConfig.addRuleCondition(zone, field, pattern, negate, operator, transforms),
    toggleConditionField: (element) => WAFConfig.toggleConditionField(element),
    updatePreview: () => WAFConfig.updatePreview(),
    submitCustomRule: (isEdit) => WAFConfig.submitCustomRule(isEdit),
    toggleCustomRule: (id, enabled) => WAFConfig.toggleCustomRule(id, enabled),
    toggleCRSFile: (filename, enabled) => WAFConfig.toggleCRSFile(filename, enabled),
    deleteRule: (id) => WAFConfig.deleteRule(id),
    showExclusionModal: () => WAFConfig.showExclusionModal(),
    addExclusion: () => WAFConfig.addExclusion(),
    deleteExclusion: (id) => WAFConfig.deleteExclusion(id),
    toggleExclusionEnabled: (id, enabled) => WAFConfig.toggleExclusionEnabled(id, enabled),
    applyProfile: (profileId) => WAFConfig.applyProfile(profileId),
    updateField: (key, value) => WAFConfig.updateField(key, value)
};
const wafServiceMethods = new Set([
    'init',
    'startRefresh',
    'loadConfig',
    'loadStats',
    'loadRules',
    'loadProfiles',
    'loadExclusions',
    'saveConfig'
]);
const wafViewMethods = new Set([
    'getIcon',
    'renderSectionHeader',
    'render',
    'renderTabContent',
    'renderOverview',
    'renderManagedRules',
    'renderReloadHealth',
    'renderRules',
    'renderExclusions',
    'renderProtectionProfiles',
    'renderRuleEditor',
    'renderManagedRulesFolder',
    'renderCustomRulesList',
    'renderRulesMain',
    'renderTrafficChart',
    'updateDashboardUI',
    'showToast'
]);
export const WAFConfigFacade = new Proxy({}, {
    get(_target, prop) {
        if (prop === 'state')
            return WAFConfigState;
        if (typeof prop !== 'string')
            return undefined;
        if (wafServiceMethods.has(prop)) {
            return WAFConfigService[prop];
        }
        if (wafViewMethods.has(prop)) {
            return WAFConfigView[prop];
        }
        if (prop in WAFConfigController) {
            return WAFConfigController[prop];
        }
        const value = WAFConfig[prop];
        return typeof value === 'function' ? value.bind(WAFConfig) : value;
    },
    set(_target, prop, value) {
        if (typeof prop === 'string' && prop in WAFConfig) {
            WAFConfig[prop] = value;
            return true;
        }
        return false;
    }
});
