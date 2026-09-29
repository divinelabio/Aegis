// Application Security Configuration - Standard UI
// Aligned with TrafficConfig / AccessControlConfig patterns
import { api } from '../../api.js';
import * as AdminEvents from '../../core/events.js';
import * as AdminDOM from '../../core/dom.js';
import { SectionUI } from '../ui-components.js';
import { renderHTTPSecuritySaveButtons } from '../httpsecurity-render-helpers.js';
import { showSectionToast } from '../section-toast-helpers.js';
import { escapeHTTPSecurityHtml, formatHTTPSecurityHeaderMap, parseHTTPSecurityHeaderMap } from '../httpsecurity-runtime-helpers.js';
import { httpSecurityJSONRequest } from './api.js';
import { HTTPSEC_DIRTY_ACTIONS } from './actions.js';
import { HTTPSEC_BOUNDARY_PROFILES, HTTPSEC_ADVANCED_CONFIG_ROOTS, HTTPSEC_CONTENT_TYPE_PROFILES, HTTPSEC_COOKIE_PROFILES, HTTPSEC_EXTENSION_GROUPS, HTTPSEC_FALLBACK_CAPABILITIES, HTTPSEC_METHOD_PROFILES, HTTPSEC_PAYLOAD_INSPECTION_PROFILES, HTTPSEC_PAYLOAD_PROFILES, HTTPSEC_RESPONSE_PROFILES, HTTPSEC_ROOT_CAPABILITY, HTTPSEC_UPLOAD_PROFILES, HTTP_SECURITY_EFFECTIVE_STATE_ENDPOINT } from './constants.js';
import { getHTTPSecurityCapability, isHTTPSecurityConfigurable, normalizeHTTPSecurityCapability, normalizeHTTPSecurityExtension } from './normalize.js';
import { buildHTTPSecurityConfigFromViewModel, buildHTTPSecuritySavePayloadFromViewModel, createHTTPSecurityViewModel } from './view-model.js';
import { applyHTTPSecurityCSPPreset, applyHTTPSecurityPermissionsPreset, isValidHTTPSecurityExtension, isValidHTTPSecurityHeaderName, parseHTTPSecurityCSP, parseHTTPSecurityPermissionsPolicy, serializeHTTPSecurityCSP, serializeHTTPSecurityPermissionsPolicy, validateHTTPSecurityConfig } from './validation.js';
import { createHTTPSecurityInitialState } from './state.js';
import { renderHTTPSecurityRequestPolicy } from './render-request-policy.js';
import { renderHTTPSecurityPayloadProtection, renderHTTPSecurityUploadSecurity } from './render-payload-upload.js';
import { renderHTTPSecurityResponseProtection } from './render-response-protection.js';
let httpSecurityBindingsInitialized = false;
let httpSecurityBoundRoot = null;
let httpSecurityBindingDisposers = [];
const HTTPSEC_INITIAL_STATE = createHTTPSecurityInitialState();
function encodeHTTPSecurityValue(value) {
    return encodeURIComponent(String(value));
}
function decodeHTTPSecurityValue(value) {
    return value ? decodeURIComponent(value) : '';
}
function httpsecSizeToMb(value) {
    const raw = String(value || '10MB').trim().toUpperCase();
    const numeric = Number.parseInt(raw, 10);
    if (!Number.isFinite(numeric) || numeric <= 0)
        return 10;
    return raw.includes('GB') ? numeric * 1024 : numeric;
}
function httpsecSizeToBytes(value) {
    return httpsecSizeToMb(value) * 1024 * 1024;
}
function parseHTTPSecurityFieldValue(element) {
    const valueType = element.dataset.httpsecValueType || 'string';
    if (valueType === 'checkbox' && element instanceof HTMLInputElement) {
        return element.checked;
    }
    if (valueType === 'number') {
        const parsed = Number.parseInt(element.value, 10);
        return Number.isFinite(parsed) ? parsed : 0;
    }
    if (valueType === 'size-mb') {
        const parsed = Number.parseInt(element.value, 10);
        return `${Number.isFinite(parsed) && parsed > 0 ? parsed : 1}MB`;
    }
    if (valueType === 'bytes-mb') {
        const parsed = Number.parseInt(element.value, 10);
        return (Number.isFinite(parsed) && parsed > 0 ? parsed : 1) * 1024 * 1024;
    }
    if (valueType === 'header-map') {
        return parseHTTPSecurityHeaderMap(element.value);
    }
    if (valueType === 'csv') {
        return element.value.split(',').map((item) => item.trim()).filter(Boolean);
    }
    return element.value;
}
function setHTTPSecurityFieldFromElement(element) {
    if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement))
        return false;
    const path = element.dataset.httpsecPath;
    if (!path)
        return false;
    if (!HTTPSecurityConfig.canMutatePath(path))
        return false;
    const updated = HTTPSecurityConfig.updateField(path, parseHTTPSecurityFieldValue(element));
    if (element.dataset.httpsecRender === 'true') {
        HTTPSecurityConfig.render();
    }
    return updated !== false;
}
function ensureHTTPSecurityBindings() {
    if (httpSecurityBindingsInitialized)
        return;
    httpSecurityBindingsInitialized = true;
    const dirtyActions = new Set(HTTPSEC_DIRTY_ACTIONS);
    httpSecurityBindingDisposers.push(AdminEvents.delegateEvent(document, 'click', '[data-httpsec-action]', (_event, target) => {
        const action = target.dataset.httpsecAction;
        if (!action)
            return;
        const tab = target.dataset.httpsecTab;
        const headerTab = target.dataset.httpsecHeaderTab;
        const path = target.dataset.httpsecPath;
        const rawValue = target.dataset.httpsecValue;
        const decodedValue = decodeHTTPSecurityValue(rawValue);
        const valueType = target.dataset.httpsecValueType || 'string';
        const shouldRender = target.dataset.httpsecRender === 'true';
        const actionHandlers = {
            'switch-tab': () => {
                if (tab)
                    HTTPSecurityConfig.switchTab(tab);
                return false;
            },
            'set-header-tab': () => {
                if (headerTab)
                    HTTPSecurityConfig.setHeaderTab(headerTab);
                return false;
            },
            'select-request-control': () => {
                if (rawValue) {
                    HTTPSecurityConfig.requestControl = decodedValue;
                    HTTPSecurityConfig.render();
                }
                return false;
            },
            save: () => {
                void HTTPSecurityConfig.saveConfig()
                    .then((saved) => {
                    if (saved)
                        SectionUI.markSaveActionBarClean('data-httpsec-action');
                });
                return false;
            },
            reset: () => {
                void HTTPSecurityConfig.resetConfig()
                    .finally(() => SectionUI.markSaveActionBarClean('data-httpsec-action'));
                return false;
            },
            'save-securitytxt': () => {
                void HTTPSecurityConfig.saveSecurityTxt();
                return false;
            },
            'verify-securitytxt': () => {
                void HTTPSecurityConfig.verifySecurityTxt().then(() => HTTPSecurityConfig.render());
                return false;
            },
            'focus-validation': () => {
                HTTPSecurityConfig.focusValidation(decodedValue);
                return false;
            },
            'set-field': () => {
                if (!path)
                    return false;
                const updated = HTTPSecurityConfig.updateField(path, valueType === 'boolean' ? decodedValue === 'true' : decodedValue);
                if (shouldRender)
                    HTTPSecurityConfig.render();
                return updated !== false;
            },
            'set-number-field': () => {
                if (!path)
                    return false;
                const updated = HTTPSecurityConfig.updateField(path, Number.parseInt(decodedValue, 10) || 0);
                if (shouldRender)
                    HTTPSecurityConfig.render();
                return updated !== false;
            },
            'add-tag': () => {
                if (path)
                    return HTTPSecurityConfig.addTag(path, decodedValue) !== false;
                return false;
            },
            'remove-tag': () => {
                if (path)
                    return HTTPSecurityConfig.removeTag(path, decodedValue) !== false;
                return false;
            },
            'add-tag-from-input': () => {
                if (!path)
                    return false;
                const inputId = target.dataset.httpsecInputId;
                const input = inputId ? AdminDOM.getInput(inputId) : null;
                if (!(input instanceof HTMLInputElement))
                    return false;
                const values = input.value.split(/[\s,]+/).map((value) => value.trim()).filter(Boolean);
                const updated = values.some((value) => HTTPSecurityConfig.addTag(path, value) !== false);
                input.value = '';
                return updated;
            },
            'toggle-array-item': () => {
                if (path)
                    return HTTPSecurityConfig.toggleArrayItem(path, decodedValue) !== false;
                return false;
            },
            'toggle-method-pill': () => HTTPSecurityConfig.toggleMethodPill(decodedValue) !== false,
            'set-method-mode': () => HTTPSecurityConfig.setMethodMode(decodedValue) !== false,
            'apply-request-boundary-preset': () => HTTPSecurityConfig.applyRequestBoundaryPreset(decodedValue) !== false,
            'apply-request-method-profile': () => HTTPSecurityConfig.applyRequestMethodProfile(decodedValue) !== false,
            'apply-content-type-profile': () => HTTPSecurityConfig.applyContentTypeProfile(decodedValue) !== false,
            'apply-payload-profile': () => HTTPSecurityConfig.applyPayloadProfile(decodedValue) !== false,
            'apply-payload-inspection-profile': () => HTTPSecurityConfig.applyPayloadInspectionProfile(decodedValue) !== false,
            'open-payload-expert': () => {
                HTTPSecurityConfig.payloadExpertPage = true;
                HTTPSecurityConfig.payloadInspectionCustomSelected = true;
                HTTPSecurityConfig.render();
                return false;
            },
            'close-payload-expert': () => {
                HTTPSecurityConfig.payloadExpertPage = false;
                HTTPSecurityConfig.render();
                return false;
            },
            'open-request-policy-page': () => {
                const page = String(decodedValue || '');
                if (!['host_validator', 'method_enforcer', 'request_size_guard', 'content_type_validator', 'header_manager'].includes(page))
                    return false;
                HTTPSecurityConfig.requestPolicyPage = page;
                HTTPSecurityConfig.render();
                return false;
            },
            'close-request-policy-page': () => {
                HTTPSecurityConfig.requestPolicyPage = null;
                HTTPSecurityConfig.render();
                return false;
            },
            'open-response-protection-page': () => {
                const page = String(decodedValue || '');
                if (!['browser', 'privacy', 'cookies', 'headers'].includes(page))
                    return false;
                HTTPSecurityConfig.responseProtectionPage = page;
                HTTPSecurityConfig.render();
                return false;
            },
            'close-response-protection-page': () => {
                HTTPSecurityConfig.responseProtectionPage = null;
                HTTPSecurityConfig.render();
                return false;
            },
            'apply-upload-profile': () => HTTPSecurityConfig.applyUploadProfile(decodedValue) !== false,
            'apply-response-header-profile': () => HTTPSecurityConfig.applyResponseHeaderProfile(decodedValue) !== false,
            'apply-cookie-profile': () => HTTPSecurityConfig.applyCookieProfile(decodedValue) !== false,
            'add-header-row': () => {
                if (!path)
                    return false;
                const nameInput = AdminDOM.getInput(target.dataset.httpsecNameInputId || '');
                const valueInput = AdminDOM.getInput(target.dataset.httpsecValueInputId || '');
                if (!(nameInput instanceof HTMLInputElement) || !(valueInput instanceof HTMLInputElement))
                    return false;
                const updated = HTTPSecurityConfig.addHeaderRow(path, nameInput.value, valueInput.value) !== false;
                if (updated) {
                    nameInput.value = '';
                    valueInput.value = '';
                }
                return updated;
            },
            'remove-header-row': () => path ? HTTPSecurityConfig.removeHeaderRow(path, decodedValue) !== false : false,
            'add-csp-source': () => {
                const input = AdminDOM.getInput(target.dataset.httpsecInputId || '');
                if (!(input instanceof HTMLInputElement))
                    return false;
                const updated = HTTPSecurityConfig.addCSPSource(decodedValue, input.value) !== false;
                if (updated)
                    input.value = '';
                return updated;
            },
            'remove-csp-source': () => HTTPSecurityConfig.removeCSPSource(decodedValue) !== false,
            'apply-csp-preset': () => HTTPSecurityConfig.applyCSPPreset(decodedValue) !== false,
            'apply-permissions-policy-preset': () => HTTPSecurityConfig.applyPermissionsPolicyPreset(decodedValue) !== false,
            'add-extension-group': () => path ? HTTPSecurityConfig.addExtensionGroup(path, decodedValue) !== false : false,
            'open-file-type-policy': () => {
                if (!path)
                    return false;
                HTTPSecurityConfig.fileTypePolicyModal = {
                    path,
                    title: target.dataset.httpsecTitle || 'File types',
                    countLabel: target.dataset.httpsecCountLabel || 'configured'
                };
                HTTPSecurityConfig.render();
                return false;
            },
            'close-file-type-policy': () => {
                HTTPSecurityConfig.fileTypePolicyModal = null;
                HTTPSecurityConfig.render();
                return false;
            },
            'prompt-add-host': () => HTTPSecurityConfig.promptAddHost() !== false
        };
        const handler = actionHandlers[action];
        if (!handler) {
            console.warn('[Application Security] Missing httpsec action handler:', action);
            return;
        }
        const mutated = handler();
        if (mutated && dirtyActions.has(action)) {
            SectionUI.markSaveActionBarDirty('data-httpsec-action');
        }
    }));
    httpSecurityBindingDisposers.push(AdminEvents.delegateEvent(document, 'change', '[data-httpsec-action="update-header-row"], [data-httpsec-action="set-permissions-policy-feature"]', (_event, target) => {
        const action = target.dataset.httpsecAction;
        let mutated = false;
        if (action === 'update-header-row' && target instanceof HTMLInputElement) {
            mutated = HTTPSecurityConfig.updateHeaderRow(target.dataset.httpsecHeaderPath || '', decodeHTTPSecurityValue(target.dataset.httpsecOldName || ''), target.dataset.httpsecHeaderField || '', target.value) !== false;
        }
        if (action === 'set-permissions-policy-feature' && target instanceof HTMLSelectElement) {
            mutated = HTTPSecurityConfig.setPermissionsPolicyFeature(decodeHTTPSecurityValue(target.dataset.httpsecValue || ''), target.value) !== false;
        }
        if (mutated) {
            SectionUI.markSaveActionBarDirty('data-httpsec-action');
        }
    }));
    httpSecurityBindingDisposers.push(AdminEvents.delegateEvent(document, 'change', '[data-httpsec-path]', (_event, target) => {
        if (setHTTPSecurityFieldFromElement(target)) {
            SectionUI.markSaveActionBarDirty('data-httpsec-action');
        }
    }));
    httpSecurityBindingDisposers.push(AdminEvents.delegateEvent(document, 'change', 'select[data-httpsec-profile-select="response"]', (_event, target) => {
        if (HTTPSecurityConfig.applyResponseHeaderProfile(target.value) !== false) {
            SectionUI.markSaveActionBarDirty('data-httpsec-action');
        }
    }));
    httpSecurityBindingDisposers.push(AdminEvents.delegateEvent(document, 'change', '[data-httpsec-method-toggle]', (_event, target) => {
        if (!(target instanceof HTMLInputElement))
            return;
        if (HTTPSecurityConfig.setMethodEnabled(target.dataset.httpsecMethodToggle || '', target.checked) !== false) {
            SectionUI.markSaveActionBarDirty('data-httpsec-action');
        }
    }));
    httpSecurityBindingDisposers.push(AdminEvents.delegateEvent(document, 'change', '[data-httpsec-array-toggle]', (_event, target) => {
        if (!(target instanceof HTMLInputElement))
            return;
        if (HTTPSecurityConfig.setArrayItem(target.dataset.httpsecArrayToggle || '', target.value, target.checked) !== false) {
            SectionUI.markSaveActionBarDirty('data-httpsec-action');
        }
    }));
    httpSecurityBindingDisposers.push(AdminEvents.delegateEvent(document, 'change', '[data-httpsec-file-type-toggle]', (_event, target) => {
        const path = target.dataset.httpsecFileTypePath;
        if (!path)
            return;
        if (HTTPSecurityConfig.setArrayItem(path, target.value, target.checked) !== false) {
            SectionUI.markSaveActionBarDirty('data-httpsec-action');
        }
    }));
    httpSecurityBindingDisposers.push(AdminEvents.delegateEvent(document, 'keydown', '[data-httpsec-enter-action="add-tag-from-input"]', (event, target) => {
        if (!(event instanceof KeyboardEvent) || event.key !== 'Enter')
            return;
        event.preventDefault();
        const path = target.dataset.httpsecPath;
        if (!path)
            return;
        const values = String(target.value || '').split(/[\s,]+/).map((value) => value.trim()).filter(Boolean);
        if (!values.some((value) => HTTPSecurityConfig.addTag(path, value) !== false))
            return;
        target.value = '';
        SectionUI.markSaveActionBarDirty('data-httpsec-action');
        if (target.dataset.httpsecRender === 'true')
            HTTPSecurityConfig.render();
    }));
    httpSecurityBindingDisposers.push(AdminEvents.delegateEvent(document, 'keydown', '[data-httpsec-action="switch-tab"][role="button"], [data-httpsec-action="open-request-policy-page"][role="button"], [data-httpsec-action="open-response-protection-page"][role="button"]', (event, target) => {
        if (!(event instanceof KeyboardEvent) || (event.key !== 'Enter' && event.key !== ' '))
            return;
        event.preventDefault();
        if (target.dataset.httpsecAction === 'switch-tab') {
            const tab = target.dataset.httpsecTab;
            if (tab)
                HTTPSecurityConfig.switchTab(tab);
            return;
        }
        if (target.dataset.httpsecAction === 'open-request-policy-page') {
            const page = target.dataset.httpsecValue;
            if (page) {
                HTTPSecurityConfig.requestPolicyPage = page;
                HTTPSecurityConfig.render();
            }
            return;
        }
        const page = target.dataset.httpsecValue;
        if (page) {
            HTTPSecurityConfig.responseProtectionPage = page;
            HTTPSecurityConfig.render();
        }
    }));
    httpSecurityBindingDisposers.push(AdminEvents.delegateEvent(document, 'keydown', '#httpsec-securitytxt-contact', (event) => {
        if (!(event instanceof KeyboardEvent) || event.key !== 'Enter')
            return;
        event.preventDefault();
        void HTTPSecurityConfig.saveSecurityTxt();
    }));
}
function disposeHTTPSecurityBindings() {
    for (const dispose of httpSecurityBindingDisposers.splice(0)) {
        dispose();
    }
    httpSecurityBindingsInitialized = false;
    httpSecurityBoundRoot = null;
}
const HTTPSecurityConfig = {
    currentTab: HTTPSEC_INITIAL_STATE.currentTab,
    requestControl: HTTPSEC_INITIAL_STATE.requestControl,
    config: HTTPSEC_INITIAL_STATE.config,
    capabilities: HTTPSEC_INITIAL_STATE.capabilities,
    effectiveState: HTTPSEC_INITIAL_STATE.effectiveState,
    viewModel: HTTPSEC_INITIAL_STATE.viewModel,
    edition: HTTPSEC_INITIAL_STATE.edition,
    functions: HTTPSEC_INITIAL_STATE.functions,
    securityTxtContact: HTTPSEC_INITIAL_STATE.securityTxtContact,
    securityTxtVerification: HTTPSEC_INITIAL_STATE.securityTxtVerification,
    validationIssues: HTTPSEC_INITIAL_STATE.validationIssues,
    stats: HTTPSEC_INITIAL_STATE.stats,
    tabs: HTTPSEC_INITIAL_STATE.tabs,
    headerManagerTab: HTTPSEC_INITIAL_STATE.headerManagerTab,
    fileTypePolicyModal: null,
    payloadExpertPage: false,
    payloadInspectionCustomSelected: false,
    requestPolicyPage: null,
    responseProtectionPage: null,
    icons: {
        shield: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        lock: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
        unlock: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 5-5 5 5 0 0 1 5 5"/></svg>',
        zap: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
        check: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>',
        upload: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
        file: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>',
        sliders: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/></svg>',
        globe: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
        eye: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
        cookie: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="8" cy="9" r="1" fill="currentColor"/><circle cx="15" cy="8" r="1" fill="currentColor"/><circle cx="10" cy="14" r="1" fill="currentColor"/><circle cx="16" cy="13" r="1" fill="currentColor"/></svg>',
        arrowRight: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>',
        code: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        compress: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="14" y1="10" x2="21" y2="3"/><line x1="3" y1="21" x2="10" y2="14"/></svg>',
        activity: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
        x: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'
    },
    async init() {
        ensureHTTPSecurityBindings();
        await this.loadCapabilities();
        await this.loadConfig();
        await this.loadEffectiveState();
        await this.loadGlobalConfig();
        await this.loadStats();
        this.render();
    },
    async loadCapabilities() {
        try {
            const data = await api.get('sections/http_security/functions');
            const rows = Array.isArray(data) ? data : [];
            const capabilities = {};
            rows.forEach((info) => {
                if (!info?.id)
                    return;
                capabilities[info.id] = normalizeHTTPSecurityCapability(info);
            });
            this.functions = rows;
            this.capabilities = { ...HTTPSEC_FALLBACK_CAPABILITIES, ...capabilities };
            this.refreshViewModel();
        }
        catch (error) {
            console.error('Application Security capabilities load error', error);
            this.capabilities = { ...HTTPSEC_FALLBACK_CAPABILITIES };
            this.refreshViewModel();
        }
    },
    async loadConfig() {
        try {
            const data = await api.get('sections/http_security/config');
            if (data) {
                this.config = data;
                this.validationIssues = [];
                this.normalizeForEdition();
                this.refreshViewModel();
            }
            else {
                throw new Error('Failed to load');
            }
        }
        catch (error) {
            console.error('Application Security config load error', error);
            showSectionToast('Failed to load Application Security configuration', 'error');
        }
    },
    normalizeForEdition() {
        if (!this.config || typeof this.config !== 'object')
            this.config = {};
        for (const key of HTTPSEC_ADVANCED_CONFIG_ROOTS) {
            const capabilityID = HTTPSEC_ROOT_CAPABILITY[key];
            if (!this.canConfigure(capabilityID)) {
                delete this.config[key];
            }
        }
        const upload = this.config.upload_protection;
        const legacyExtensions = this.config.extension_filter;
        if (this.canConfigure('upload_protection') && upload && typeof upload === 'object' && !Array.isArray(upload)) {
            const merged = [
                ...(Array.isArray(upload.blocked_extensions) ? upload.blocked_extensions : []),
                ...(Array.isArray(legacyExtensions?.blocked_extensions) ? legacyExtensions.blocked_extensions : [])
            ].map((value) => {
                const normalized = String(value || '').trim().toLowerCase();
                return normalized && !normalized.startsWith('.') ? `.${normalized}` : normalized;
            }).filter(Boolean);
            upload.blocked_extensions = [...new Set(merged)];
            if (legacyExtensions && typeof legacyExtensions === 'object' && !Array.isArray(legacyExtensions)) {
                legacyExtensions.blocked_extensions = [...upload.blocked_extensions];
                legacyExtensions.enabled = false;
            }
        }
        const bodyGuard = this.config.request_body_guard;
        const bodyLimit = this.config.upload_limit?.max_body_size;
        if (this.canConfigure('request_body_guard') && bodyGuard && typeof bodyGuard === 'object' && !Array.isArray(bodyGuard) && bodyLimit) {
            bodyGuard.max_body_size = httpsecSizeToBytes(bodyLimit);
        }
        this.refreshViewModel();
    },
    async loadEffectiveState() {
        try {
            const data = await api.get(HTTP_SECURITY_EFFECTIVE_STATE_ENDPOINT);
            this.effectiveState = data && typeof data === 'object'
                ? data
                : { effective_state: 'DEGRADED', reason: 'Effective runtime state is unavailable.' };
        }
        catch (error) {
            console.error('Application Security effective state load error', error);
            this.effectiveState = { effective_state: 'DEGRADED', reason: 'Effective runtime state is unavailable.' };
        }
    },
    refreshViewModel() {
        this.viewModel = createHTTPSecurityViewModel(this.config, this.capabilities, this.securityTxtContact, this.edition);
        return this.viewModel;
    },
    async loadStats() {
        try {
            const data = await api.get('sections/http_security/stats');
            if (data)
                this.stats = data;
        }
        catch (e) {
            console.error('Failed to load stats:', e);
        }
    },
    async loadGlobalConfig() {
        try {
            const response = await fetch('/api/config', { headers: { Accept: 'application/json' } });
            if (!response.ok)
                throw new Error(`Global config request failed: ${response.status}`);
            const data = (await response.json());
            this.securityTxtContact = data.security_txt?.contact || '';
            await this.verifySecurityTxt();
            this.refreshViewModel();
        }
        catch (error) {
            console.error('Security.txt config load error', error);
            showSectionToast('Failed to load Security.txt settings', 'error');
        }
    },
    async saveConfig() {
        this.normalizeForEdition();
        this.refreshViewModel();
        const configForSave = buildHTTPSecurityConfigFromViewModel(this.viewModel);
        const validation = validateHTTPSecurityConfig(configForSave);
        if (validation.errors.length) {
            this.validationIssues = validation.errors.map((message) => ({ path: '', message }));
            showSectionToast(validation.errors[0], 'error');
            this.render();
            return false;
        }
        if (validation.warnings.length) {
            showSectionToast(validation.warnings[0], 'warning');
        }
        const payload = buildHTTPSecuritySavePayloadFromViewModel(this.viewModel);
        try {
            await httpSecurityJSONRequest('sections/http_security/config', 'PATCH', payload);
            this.validationIssues = [];
            showSectionToast('Application Security configuration saved!', 'success');
            await this.loadCapabilities();
            await this.loadConfig();
            await this.loadEffectiveState();
            return true;
        }
        catch (error) {
            console.error('Application Security save error', error);
            const err = error;
            const details = Array.isArray(err?.payload?.error?.details) ? err.payload.error.details : [];
            this.validationIssues = details.map((detail) => ({
                path: String(detail?.path || ''),
                message: String(detail?.message || err?.message || 'Invalid value')
            }));
            if (this.validationIssues.length)
                this.render();
            showSectionToast(err?.message || 'Failed to save configuration', 'error');
            return false;
        }
    },
    async resetConfig() {
        await this.loadCapabilities();
        await this.loadConfig();
        await this.loadEffectiveState();
        await this.loadGlobalConfig();
        await this.loadStats();
        this.render();
        showSectionToast('Application Security configuration reloaded', 'info');
    },
    async saveSecurityTxt() {
        const input = AdminDOM.getInput('httpsec-securitytxt-contact');
        const contact = input instanceof HTMLInputElement ? input.value.trim() : this.securityTxtContact.trim();
        if (contact && !this.isValidSecurityTxtContact(contact)) {
            showSectionToast('Enter an email address, mailto URI, or HTTPS URL.', 'error');
            input?.focus();
            return false;
        }
        try {
            await httpSecurityJSONRequest('config', 'POST', { 'security_txt.contact': contact });
            this.securityTxtContact = contact;
            const published = await this.verifySecurityTxt();
            this.refreshViewModel();
            showSectionToast(contact === '' ? 'Security.txt publication removed' : published ? 'Security.txt published and verified' : 'Contact saved, but the public file could not be verified', contact === '' || published ? 'success' : 'warning');
            this.render();
            return true;
        }
        catch (error) {
            console.error('Security.txt save error', error);
            const err = error;
            showSectionToast(err?.message || 'Failed to save Security.txt contact', 'error');
            return false;
        }
    },
    isValidSecurityTxtContact(contact) {
        const value = String(contact || '').trim();
        if (!value)
            return true;
        if (/[\r\n\0]/.test(value) || value.length > 2048)
            return false;
        if (/^https:\/\/[^\s/@]+(?:[/:?#]|$)/i.test(value))
            return true;
        const email = value.replace(/^mailto:/i, '');
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    },
    normalizeSecurityTxtContact(contact) {
        const value = String(contact || '').trim();
        if (!value)
            return '';
        if (/^mailto:/i.test(value))
            return `mailto:${value.slice(value.indexOf(':') + 1)}`;
        if (/^https:/i.test(value))
            return value;
        return `mailto:${value}`;
    },
    async verifySecurityTxt() {
        const contact = String(this.securityTxtContact || '').trim();
        if (!contact) {
            this.securityTxtVerification = {
                status: 'not_configured',
                message: 'Add a contact to publish the public disclosure file.'
            };
            return false;
        }
        this.securityTxtVerification = {
            status: 'checking',
            message: 'Checking the public disclosure file.'
        };
        try {
            const response = await fetch('/.well-known/security.txt', {
                headers: { Accept: 'text/plain' },
                cache: 'no-store'
            });
            if (!response.ok) {
                this.securityTxtVerification = {
                    status: 'unavailable',
                    message: `Public route returned HTTP ${response.status}.`
                };
                return false;
            }
            const expected = `Contact: ${this.normalizeSecurityTxtContact(contact)}`;
            const lines = (await response.text()).split(/\r?\n/).map((line) => line.trim());
            if (!lines.includes(expected)) {
                this.securityTxtVerification = {
                    status: 'mismatch',
                    message: 'The public file does not match the saved contact.'
                };
                return false;
            }
            this.securityTxtVerification = {
                status: 'published',
                message: 'The public route is available and matches the saved contact.'
            };
            return true;
        }
        catch (error) {
            console.error('Security.txt verification error', error);
            this.securityTxtVerification = {
                status: 'unavailable',
                message: 'The public disclosure route could not be reached.'
            };
            return false;
        }
    },
    capability(id) {
        return getHTTPSecurityCapability(this.capabilities, id);
    },
    canConfigure(id) {
        return isHTTPSecurityConfigurable(this.capabilities, id);
    },
    isUpgrade(_id) {
        return false;
    },
    canMutatePath(_path) {
        return true;
    },
    updateField(path, value) {
        if (!this.canMutatePath(path))
            return false;
        const parts = path.split('.');
        let obj = this.config;
        for (let i = 0; i < parts.length - 1; i++) {
            const key = parts[i];
            const current = obj[key];
            if (typeof current !== 'object' || current === null || Array.isArray(current))
                obj[key] = {};
            obj = obj[key];
        }
        obj[parts[parts.length - 1]] = value;
        this.clearValidationIssue(path);
        if (path === 'upload_limit.max_body_size' && this.canConfigure('request_body_guard') && this.config.request_body_guard) {
            this.config.request_body_guard.max_body_size = httpsecSizeToBytes(value);
        }
        return true;
    },
    clearValidationIssue(path) {
        const normalized = String(path || '');
        this.validationIssues = (this.validationIssues || []).filter((issue) => {
            const issuePath = String(issue?.path || '');
            return issuePath && issuePath !== normalized && !issuePath.startsWith(`${normalized}.`) && !normalized.startsWith(`${issuePath}.`);
        });
        AdminDOM.queryAll('#httpsecurity-config-content [data-httpsec-path]').forEach((element) => {
            if (element instanceof HTMLElement && element.dataset.httpsecPath === normalized)
                element.removeAttribute('aria-invalid');
        });
    },
    getField(path, fallback) {
        const parts = path.split('.');
        let obj = this.config;
        for (const p of parts) {
            if (obj == null)
                return fallback;
            if (typeof obj !== 'object' || Array.isArray(obj))
                return fallback;
            obj = obj[p];
        }
        return (obj ?? fallback);
    },
    render() {
        const container = AdminDOM.getById('httpsecurity-config-content');
        if (!container)
            return;
        ensureHTTPSecurityBindings();
        this.refreshViewModel();
        const openAdvancedDetails = AdminDOM.queryAll('#httpsecurity-config-content .httpsec-advanced-details')
            .map((details, index) => details instanceof HTMLDetailsElement && details.open ? index : -1)
            .filter((index) => index >= 0);
        const visibleTabs = this.tabs;
        // If current tab was hidden, reset to first visible
        if (!visibleTabs.find((t) => t.id === this.currentTab)) {
            this.currentTab = visibleTabs[0]?.id ?? 'overview';
        }
        const configuredEnabled = this.config?.enabled === true;
        const consoleMetaMap = {
            overview: {
                title: 'Overview',
                kicker: 'Application Security',
                subtitle: 'Harden HTTP responses, inject security headers, and suppress server signatures.'
            },
            request_policy: {
                title: 'Request Policy',
                kicker: 'Application Security',
                subtitle: 'Validate allowed HTTP verbs, enforce valid Host headers, and verify Content-Type signatures.'
            },
            payload_protection: {
                title: 'Payload Protection',
                kicker: 'Application Security',
                subtitle: 'Enforce maximum request body depth, chunked transfer limits, and buffer boundaries.'
            },
            upload_security: {
                title: 'Upload Security',
                kicker: 'Application Security',
                subtitle: 'Validate uploaded file extensions, enforce MIME types, and apply deep binary inspection and archive guards.'
            },
            response_protection: {
                title: 'Response Protection',
                kicker: 'Application Security',
                subtitle: 'Enforce HSTS, Content Security Policy, X-Frame-Options, server cloaking, and cookie flags.'
            }
        };
        const currentMeta = consoleMetaMap[this.currentTab] || consoleMetaMap.overview;
        container.innerHTML = SectionUI.renderOperatorFrame({
            title: currentMeta.title,
            kicker: currentMeta.kicker,
            subtitle: currentMeta.subtitle,
            tabs: [],
            activeTab: this.currentTab,
            actions: this.currentTab === 'overview' ? `
				<label class="section-switch" title="${configuredEnabled ? 'Disable' : 'Enable'} Application Security">
					<input type="checkbox" ${configuredEnabled ? 'checked' : ''} data-httpsec-path="enabled" data-httpsec-value-type="checkbox" data-httpsec-render="true" aria-label="Enable Application Security">
					<span class="switch-slider"></span>
				</label>` : '',
            content: `${this.renderValidationSummary()}<div id="httpsec-tab-content">${this.renderTabContent()}</div>`,
            className: 'httpsec-operator-frame'
        });
        AdminDOM.queryAll('#httpsecurity-config-content .httpsec-advanced-details').forEach((details, index) => {
            if (details instanceof HTMLDetailsElement && openAdvancedDetails.includes(index)) {
                details.open = true;
            }
        });
        this.syncGaugeFills();
        this.applyValidationMarkers();
    },
    renderValidationSummary() {
        const issues = Array.isArray(this.validationIssues) ? this.validationIssues : [];
        if (!issues.length)
            return '';
        return `
			<div class="httpsec-validation-summary" role="alert" tabindex="-1" id="httpsec-validation-summary">
				<div>
					<strong>Configuration needs attention</strong>
					<span>Fix ${issues.length} ${issues.length === 1 ? 'issue' : 'issues'} before saving.</span>
				</div>
				<ul>
					${issues.map((issue) => {
            const path = String(issue?.path || '');
            const message = String(issue?.message || 'Invalid value');
            return `<li><button type="button" data-httpsec-action="focus-validation" data-httpsec-value="${encodeHTTPSecurityValue(path)}"><span>${path ? `${escapeHTTPSecurityHtml(path)}: ` : ''}</span>${escapeHTTPSecurityHtml(message)}</button></li>`;
        }).join('')}
				</ul>
			</div>`;
    },
    tabForValidationPath(path) {
        const root = String(path || '').split('.')[0];
        if (['upload_limit', 'request_body_guard'].includes(root))
            return 'payload_protection';
        if (['extension_filter', 'upload_protection'].includes(root))
            return 'upload_security';
        if (['security_headers', 'info_hiding', 'cookie_hardener', 'https_redirect', 'gzip', 'html_injector'].includes(root))
            return 'response_protection';
        if (root === 'header_manager' && String(path).includes('response'))
            return 'response_protection';
        if (['method_enforcer', 'host_validator', 'content_type_validator', 'request_size_guard', 'header_manager'].includes(root))
            return 'request_policy';
        return 'overview';
    },
    focusValidation(path) {
        const normalized = String(path || '');
        this.currentTab = this.tabForValidationPath(normalized);
        this.render();
        requestAnimationFrame(() => {
            const fields = AdminDOM.queryAll('#httpsecurity-config-content [data-httpsec-path]');
            const exact = fields.find((element) => element instanceof HTMLElement && element.dataset.httpsecPath === normalized);
            const root = normalized.split('.')[0];
            const fallback = fields.find((element) => element instanceof HTMLElement && String(element.dataset.httpsecPath || '').startsWith(`${root}.`));
            const target = exact || fallback || AdminDOM.getById('httpsec-validation-summary');
            if (target instanceof HTMLElement) {
                target.scrollIntoView({ block: 'center', behavior: 'smooth' });
                target.focus({ preventScroll: true });
            }
        });
    },
    applyValidationMarkers() {
        const issuePaths = new Set((this.validationIssues || []).map((issue) => String(issue?.path || '')).filter(Boolean));
        AdminDOM.queryAll('#httpsecurity-config-content [data-httpsec-path]').forEach((element) => {
            if (!(element instanceof HTMLElement))
                return;
            const path = String(element.dataset.httpsecPath || '');
            const invalid = Array.from(issuePaths).some((issuePath) => issuePath === path || issuePath.startsWith(`${path}.`) || path.startsWith(`${issuePath}.`));
            if (invalid)
                element.setAttribute('aria-invalid', 'true');
            else
                element.removeAttribute('aria-invalid');
        });
    },
    syncGaugeFills() {
        const fills = AdminDOM.queryAll('#httpsecurity-config-content .gauge-fill[data-pct]');
        fills.forEach((el) => {
            const pct = Number(el.dataset.pct || 0);
            const normalized = Number.isFinite(pct) ? Math.max(0, Math.min(100, pct)) : 0;
            el.style.setProperty('--pct', `${normalized}%`);
        });
    },
    switchTab(id) {
        const legacyTabs = {
            request: 'request_policy',
            payload_uploads: 'payload_protection',
            body_guard: 'payload_protection',
            upload_protection: 'upload_security',
            payload_protection: 'payload_protection',
            upload_security: 'upload_security',
            response: 'response_protection',
            content: 'overview'
        };
        this.requestPolicyPage = null;
        this.responseProtectionPage = null;
        this.currentTab = legacyTabs[id] || id;
        this.render();
        const targetMap = {
            overview: 'httpsecurity_config',
            request_policy: 'httpsec_request',
            payload_protection: 'httpsec_payload',
            upload_security: 'httpsec_upload',
            response_protection: 'httpsec_response'
        };
        const activeNavTarget = targetMap[this.currentTab];
        if (activeNavTarget) {
            AdminDOM.queryAll('.nav-link').forEach(el => el.classList.remove('active'));
            const matchedLink = AdminDOM.query(`.nav-link[data-nav-target="${activeNavTarget}"]`);
            if (matchedLink)
                matchedLink.classList.add('active');
        }
    },
    setHeaderTab(tab) {
        this.headerManagerTab = tab;
        this.render();
    },
    renderTabContent() {
        switch (this.currentTab) {
            case 'overview': return this.renderOverview();
            case 'request_policy': return renderHTTPSecurityRequestPolicy(this);
            case 'payload_protection': return renderHTTPSecurityPayloadProtection(this);
            case 'upload_security': return renderHTTPSecurityUploadSecurity(this);
            case 'response_protection': return renderHTTPSecurityResponseProtection(this);
            default: return '';
        }
    },
    // ========== OVERVIEW ==========
    renderOverview() {
        const st = this.stats;
        const effective = this.effectiveState || {};
        const gzipEnabled = this.config?.gzip?.enabled === true;
        const hasBodyGuard = this.canConfigure('request_body_guard');
        const hasUploadProtection = this.canConfigure('upload_protection');
        // Count active modules
        const modules = [
            { key: 'method_enforcer', name: 'Request Policy', desc: 'Methods, hosts, media types, request boundaries, and request headers', icon: 'sliders', tab: 'request_policy' },
            { key: 'upload_limit', name: 'Payload Protection', desc: hasBodyGuard ? 'Body limits and structured request inspection' : 'Request body size limits', icon: 'activity', tab: 'payload_protection' },
            { key: 'extension_filter', name: 'Upload Security', desc: hasUploadProtection ? 'File validation, deep content inspection, and archive guards' : 'File extension validation', icon: 'upload', tab: 'upload_security' },
            { key: 'security_headers', name: 'Response Protection', desc: 'Browser headers, cookies, information hiding, and response headers', icon: 'shield', tab: 'response_protection' }
        ];
        const coverage = effective.route_coverage || {};
        const activeCount = Number(coverage.protected || 0);
        const totalCount = Number(coverage.total || 0);
        const healthPercent = Number.isFinite(Number(coverage.percentage)) ? Number(coverage.percentage) : 0;
        const state = String(effective.effective_state || 'DEGRADED');
        const stateTone = state === 'ENFORCING' ? 'success' : (state === 'MONITORING' || state === 'PARTIALLY_ENFORCED') ? 'warning' : 'danger';
        const overviewMetrics = SectionUI.renderOperatorMetricStrip([
            { label: 'Protected routes', value: `${activeCount}/${totalCount}`, sub: 'Effective coverage', tone: 'neutral' },
            { label: 'Total Requests', value: this.formatNumber(st.total_requests || 0), sub: 'Observed traffic', tone: 'neutral' },
            { label: 'Blocked', value: this.formatNumber(st.blocked_requests || 0), sub: 'Mitigated requests', tone: 'danger' },
            { label: 'Coverage', value: `${healthPercent}%`, sub: 'Effective policy posture', tone: stateTone }
        ]);
        return `
            <div class="httpsec-overview-stack">
                ${SectionUI.renderOperatorSection('Protection statistics', overviewMetrics, {
            subtitle: gzipEnabled
                ? 'Coverage and request activity across security functions. Gzip is delivery-only and excluded.'
                : 'Coverage and request activity across application security functions.'
        })}

                ${SectionUI.renderOperatorSection('Security functions', `
                    <div class="operator-control-list httpsec-module-list">
                        ${this.renderModuleCards(modules)}
                    </div>
                `, {
            subtitle: 'Jump into each control area without leaving the Application Security surface.'
        })}
            </div>
			${renderHTTPSecuritySaveButtons()}
        `;
    },
    formatNumber(value) {
        const numeric = Number(value || 0);
        if (!Number.isFinite(numeric))
            return '0';
        if (numeric >= 1000000)
            return `${(numeric / 1000000).toFixed(2)}M`;
        if (numeric >= 1000)
            return `${(numeric / 1000).toFixed(1)}k`;
        return numeric.toString();
    },
    renderOverviewStat(label, value, color) {
        const formatted = typeof value === 'number' ? (value >= 1000 ? (value / 1000).toFixed(1) + 'k' : value.toString()) : value;
        return `
            <div class="section-overview-stat ${color}">
                <div class="section-overview-stat-value">${formatted}</div>
                <div class="section-overview-stat-label">${label}</div>
            </div>
        `;
    },
    renderModuleCards(modules) {
        return modules.map((module) => this.renderModuleCard(module)).join('');
    },
    renderModuleCard(mod) {
        const row = Array.isArray(this.effectiveState?.functions)
            ? this.effectiveState.functions.find((item) => item?.id === mod.key)
            : null;
        const isCardActive = row?.status === 'active' || row?.effective_mode === 'enforce';
        const status = row?.status === 'unavailable' ? 'Unavailable' : row?.status === 'degraded' ? 'Degraded' : isCardActive ? 'Active' : 'Off';
        return SectionUI.renderOperatorControlRow({
            title: mod.name,
            description: mod.desc,
            icon: this.icons[mod.icon],
            enabled: isCardActive,
            actions: this.icons.arrowRight,
            className: 'httpsec-module-row',
            attrs: `role="button" tabindex="0" data-httpsec-action="switch-tab" data-httpsec-tab="${mod.tab}"`
        });
    },
    addTag(path, value) {
        if (!this.canMutatePath(path))
            return false;
        let v = String(value || '').trim();
        if (!v)
            return false;
        if (path.includes('extensions')) {
            v = normalizeHTTPSecurityExtension(v);
            if (!isValidHTTPSecurityExtension(v)) {
                showSectionToast('Enter a valid extension such as .jpg or .pdf.', 'warning');
                return false;
            }
        }
        if (path.includes('headers') && !isValidHTTPSecurityHeaderName(v)) {
            showSectionToast('Enter a valid HTTP header name.', 'warning');
            return false;
        }
        const arr = this.getField(path, []);
        if (!arr.includes(v)) {
            arr.push(v);
            this.updateField(path, arr);
        }
        this.render();
        return true;
    },
    removeTag(path, value) {
        if (!this.canMutatePath(path))
            return false;
        const arr = this.getField(path, []).filter((x) => x !== value);
        this.updateField(path, arr);
        this.render();
        return true;
    },
    toggleArrayItem(path, value) {
        if (!this.canMutatePath(path))
            return false;
        const arr = this.getField(path, []);
        const idx = arr.indexOf(value);
        if (idx >= 0)
            arr.splice(idx, 1);
        else
            arr.push(value);
        this.updateField(path, [...arr]);
        this.render();
        return true;
    },
    toggleMethodPill(method) {
        const mode = (this.config.method_enforcer || {}).mode || 'blocklist';
        const field = mode === 'blocklist' ? 'method_enforcer.blocked_methods' : 'method_enforcer.allowed_methods';
        return this.toggleArrayItem(field, method);
    },
    setArrayItem(path, value, enabled) {
        if (!path || !value)
            return false;
        if (!this.canMutatePath(path))
            return false;
        let normalizedValue = value;
        if (path.includes('extensions')) {
            normalizedValue = normalizeHTTPSecurityExtension(value);
            if (!isValidHTTPSecurityExtension(normalizedValue)) {
                showSectionToast('Enter a valid extension such as .jpg or .pdf.', 'warning');
                return false;
            }
        }
        if (path.includes('headers') && !isValidHTTPSecurityHeaderName(normalizedValue)) {
            showSectionToast('Enter a valid HTTP header name.', 'warning');
            return false;
        }
        const current = this.getField(path, []);
        const arr = Array.isArray(current) ? [...current] : [];
        const next = enabled ? [...new Set([...arr, normalizedValue])] : arr.filter((item) => item !== normalizedValue);
        this.updateField(path, next);
        this.render();
        return true;
    },
    setMethodEnabled(method, enabled) {
        if (!method)
            return false;
        const mode = (this.config.method_enforcer || {}).mode || 'blocklist';
        const field = mode === 'blocklist' ? 'method_enforcer.blocked_methods' : 'method_enforcer.allowed_methods';
        return this.setArrayItem(field, method, enabled);
    },
    setMethodMode(mode) {
        if (mode !== 'blocklist' && mode !== 'allowlist')
            return false;
        if (!this.canMutatePath('method_enforcer.mode'))
            return false;
        if (typeof this.config.method_enforcer !== 'object' || this.config.method_enforcer === null || Array.isArray(this.config.method_enforcer))
            this.config.method_enforcer = {};
        this.config.method_enforcer.mode = mode;
        if (!Array.isArray(this.config.method_enforcer.blocked_methods))
            this.config.method_enforcer.blocked_methods = [];
        if (!Array.isArray(this.config.method_enforcer.allowed_methods))
            this.config.method_enforcer.allowed_methods = [];
        this.render();
        return true;
    },
    getRequestMethodProfile(me) {
        const mode = me.mode || 'blocklist';
        const blocked = me.blocked_methods || [];
        const allowed = me.allowed_methods || [];
        const same = (left, right) => left.length === right.length && right.every((item) => left.includes(item));
        if (mode === 'blocklist' && same(blocked, HTTPSEC_METHOD_PROFILES.recommended.methods))
            return HTTPSEC_METHOD_PROFILES.recommended;
        if (mode === 'allowlist' && same(allowed, HTTPSEC_METHOD_PROFILES.api_strict.methods))
            return HTTPSEC_METHOD_PROFILES.api_strict;
        if (mode === 'allowlist' && same(allowed, HTTPSEC_METHOD_PROFILES.read_only.methods))
            return HTTPSEC_METHOD_PROFILES.read_only;
        return { id: 'custom', label: 'Custom', note: `${mode === 'allowlist' ? allowed.length : blocked.length} selected` };
    },
    getContentTypeProfile(ctv) {
        const required = ctv.required_on || [];
        const same = (right) => required.length === right.length && right.every((item) => required.includes(item));
        if (ctv.enabled === false || required.length === 0)
            return HTTPSEC_CONTENT_TYPE_PROFILES.off;
        if (same(HTTPSEC_CONTENT_TYPE_PROFILES.writes.requiredOn))
            return HTTPSEC_CONTENT_TYPE_PROFILES.writes;
        if (same(HTTPSEC_CONTENT_TYPE_PROFILES.strict_writes.requiredOn))
            return HTTPSEC_CONTENT_TYPE_PROFILES.strict_writes;
        return { id: 'custom', label: 'Custom', note: `${required.length} methods` };
    },
    getRequestBoundaryProfile(rsg) {
        const values = {
            max_url_length: rsg.max_url_length || 2048,
            max_query_length: rsg.max_query_length || 2048,
            max_header_count: rsg.max_header_count || 50,
            max_single_header_size: rsg.max_single_header_size || 8192
        };
        const matches = (preset) => Object.keys(values).every((key) => values[key] === preset[key]);
        if (matches(HTTPSEC_BOUNDARY_PROFILES.relaxed))
            return HTTPSEC_BOUNDARY_PROFILES.relaxed;
        if (matches(HTTPSEC_BOUNDARY_PROFILES.balanced))
            return HTTPSEC_BOUNDARY_PROFILES.balanced;
        if (matches(HTTPSEC_BOUNDARY_PROFILES.strict))
            return HTTPSEC_BOUNDARY_PROFILES.strict;
        return { id: 'custom', label: 'Custom', note: `URL ${values.max_url_length} bytes` };
    },
    getPayloadProfile() {
        const body = this.config.request_body_guard || {};
        if (!this.canConfigure('request_body_guard'))
            return HTTPSEC_PAYLOAD_PROFILES.size_only;
        if (body.enabled !== true)
            return HTTPSEC_PAYLOAD_PROFILES.size_only;
        if ((body.mode || 'detect') === 'detect')
            return HTTPSEC_PAYLOAD_PROFILES.monitor;
        if (body.mode === 'block')
            return HTTPSEC_PAYLOAD_PROFILES.block_obvious;
        return HTTPSEC_PAYLOAD_PROFILES.custom;
    },
    getPayloadInspectionProfile() {
        const body = this.config.request_body_guard || {};
        if (!this.canConfigure('request_body_guard') || body.enabled !== true)
            return HTTPSEC_PAYLOAD_INSPECTION_PROFILES.balanced;
        const matches = (profile) => Number(body.max_findings || 100) === profile.maxFindings
            && Number(body.json?.max_depth || 32) === profile.jsonDepth
            && Number(body.json?.max_keys || 2000) === profile.jsonKeys
            && Number(body.form?.max_parameters || 1000) === profile.formParameters
            && Number(body.multipart?.max_parts || 100) === profile.multipartParts;
        for (const profile of [HTTPSEC_PAYLOAD_INSPECTION_PROFILES.relaxed, HTTPSEC_PAYLOAD_INSPECTION_PROFILES.balanced, HTTPSEC_PAYLOAD_INSPECTION_PROFILES.strict]) {
            if (matches(profile))
                return profile;
        }
        return HTTPSEC_PAYLOAD_INSPECTION_PROFILES.custom;
    },
    getUploadProfile() {
        const upload = this.config.upload_protection || {};
        const legacy = this.config.extension_filter || {};
        if (!this.canConfigure('upload_protection')) {
            return legacy.enabled === true ? HTTPSEC_UPLOAD_PROFILES.basic_extension_filter : HTTPSEC_UPLOAD_PROFILES.basic_extension_filter;
        }
        if (upload.enabled === true && (upload.mode || 'detect') === 'detect')
            return HTTPSEC_UPLOAD_PROFILES.strict_file_validation;
        if (upload.enabled === true)
            return HTTPSEC_UPLOAD_PROFILES.custom;
        return HTTPSEC_UPLOAD_PROFILES.basic_extension_filter;
    },
    getResponseProfile() {
        const sh = this.config.security_headers || {};
        const strictCSP = applyHTTPSecurityCSPPreset('strict');
        const strictPermissions = applyHTTPSecurityPermissionsPreset('strict');
        const baselineCSP = applyHTTPSecurityCSPPreset('baseline');
        const baselinePermissions = applyHTTPSecurityPermissionsPreset('baseline');
        const compatibilityCSP = applyHTTPSecurityCSPPreset('compatibility');
        const compatibilityPermissions = applyHTTPSecurityPermissionsPreset('compatibility');
        if (sh.x_frame_options === 'DENY' && sh.hsts === 'max-age=63072000; includeSubDomains; preload' && sh.csp === strictCSP && sh.permissions_policy === strictPermissions)
            return HTTPSEC_RESPONSE_PROFILES.strict_browser;
        if (sh.x_frame_options === 'DENY' && sh.hsts === 'max-age=31536000; includeSubDomains' && sh.x_content_type_options === 'nosniff' && sh.csp === baselineCSP && sh.permissions_policy === baselinePermissions)
            return HTTPSEC_RESPONSE_PROFILES.baseline;
        if (sh.x_frame_options === 'SAMEORIGIN' && !sh.hsts && sh.csp === compatibilityCSP && sh.permissions_policy === compatibilityPermissions)
            return HTTPSEC_RESPONSE_PROFILES.compatibility;
        return HTTPSEC_RESPONSE_PROFILES.custom;
    },
    getCookieProfile() {
        const ch = this.config.cookie_hardener || {};
        if (ch.enabled === false)
            return HTTPSEC_COOKIE_PROFILES.preserve;
        if (ch.force_secure === true && ch.force_httponly === true && ch.force_samesite === 'Strict')
            return HTTPSEC_COOKIE_PROFILES.strict;
        if (ch.force_secure === true && ch.force_httponly === true && (ch.force_samesite || 'Lax') === 'Lax')
            return HTTPSEC_COOKIE_PROFILES.balanced;
        return HTTPSEC_COOKIE_PROFILES.custom;
    },
    applyRequestMethodProfile(profile) {
        if (!this.canMutatePath('method_enforcer.enabled'))
            return false;
        if (typeof this.config.method_enforcer !== 'object' || this.config.method_enforcer === null || Array.isArray(this.config.method_enforcer))
            this.config.method_enforcer = {};
        this.config.method_enforcer.enabled = true;
        const normalizedProfile = profile === 'api' ? 'api_strict' : (profile === 'readonly' ? 'read_only' : profile);
        const selected = HTTPSEC_METHOD_PROFILES[normalizedProfile] || HTTPSEC_METHOD_PROFILES.recommended;
        if (selected.mode === 'allowlist') {
            this.config.method_enforcer.mode = 'allowlist';
            this.config.method_enforcer.allowed_methods = [...(selected.methods || [])];
            this.config.method_enforcer.blocked_methods = [];
        }
        else {
            this.config.method_enforcer.mode = 'blocklist';
            this.config.method_enforcer.blocked_methods = [...(HTTPSEC_METHOD_PROFILES.recommended.methods || [])];
            this.config.method_enforcer.allowed_methods = [];
        }
        this.requestControl = 'method_enforcer';
        this.render();
        return true;
    },
    applyContentTypeProfile(profile) {
        if (!this.canMutatePath('content_type_validator.enabled'))
            return false;
        if (typeof this.config.content_type_validator !== 'object' || this.config.content_type_validator === null || Array.isArray(this.config.content_type_validator))
            this.config.content_type_validator = {};
        const normalizedProfile = profile === 'api' ? 'writes' : (profile === 'strict' ? 'strict_writes' : profile);
        const selected = HTTPSEC_CONTENT_TYPE_PROFILES[normalizedProfile] || HTTPSEC_CONTENT_TYPE_PROFILES.writes;
        this.config.content_type_validator.enabled = selected.enabled;
        this.config.content_type_validator.required_on = [...selected.requiredOn];
        this.requestControl = 'content_type_validator';
        this.render();
        return true;
    },
    applyRequestBoundaryPreset(preset) {
        if (!this.canMutatePath('request_size_guard.enabled'))
            return false;
        const values = HTTPSEC_BOUNDARY_PROFILES[preset] || HTTPSEC_BOUNDARY_PROFILES.balanced;
        if (typeof this.config.request_size_guard !== 'object' || this.config.request_size_guard === null || Array.isArray(this.config.request_size_guard))
            this.config.request_size_guard = {};
        this.config.request_size_guard.enabled = true;
        Object.assign(this.config.request_size_guard, {
            max_url_length: values.max_url_length,
            max_query_length: values.max_query_length,
            max_header_count: values.max_header_count,
            max_single_header_size: values.max_single_header_size
        });
        this.requestControl = 'request_size_guard';
        this.render();
        return true;
    },
    applyPayloadProfile(profile) {
        this.payloadExpertPage = false;
        if (profile === 'custom') {
            this.requestControl = 'payload_custom';
            this.render();
            return false;
        }
        if (!this.canMutatePath('upload_limit.enabled'))
            return false;
        if (typeof this.config.upload_limit !== 'object' || this.config.upload_limit === null || Array.isArray(this.config.upload_limit))
            this.config.upload_limit = {};
        this.config.upload_limit.enabled = true;
        if (profile === 'size_only') {
            if (this.config.request_body_guard && typeof this.config.request_body_guard === 'object')
                this.config.request_body_guard.enabled = false;
            this.render();
            return true;
        }
        if (typeof this.config.request_body_guard !== 'object' || this.config.request_body_guard === null || Array.isArray(this.config.request_body_guard))
            this.config.request_body_guard = {};
        this.config.request_body_guard.enabled = true;
        if (profile === 'block_obvious')
            this.config.request_body_guard.mode = 'block';
        else
            this.config.request_body_guard.mode = 'detect';
        this.render();
        return true;
    },
    applyPayloadInspectionProfile(profileID) {
        const profile = HTTPSEC_PAYLOAD_INSPECTION_PROFILES[profileID];
        if (!profile || profileID === 'custom' || !this.canConfigure('request_body_guard'))
            return false;
        if (typeof this.config.request_body_guard !== 'object' || this.config.request_body_guard === null || Array.isArray(this.config.request_body_guard))
            this.config.request_body_guard = {};
        const body = this.config.request_body_guard;
        this.payloadInspectionCustomSelected = false;
        body.enabled = true;
        body.max_findings = profile.maxFindings;
        body.json = { ...(body.json || {}), max_depth: profile.jsonDepth, max_keys: profile.jsonKeys };
        body.form = { ...(body.form || {}), max_parameters: profile.formParameters };
        body.multipart = { ...(body.multipart || {}), max_parts: profile.multipartParts };
        this.render();
        return true;
    },
    applyUploadProfile(profile) {
        if (profile === 'custom') {
            this.requestControl = 'upload_custom';
            this.render();
            return false;
        }
        if (profile === 'basic_extension_filter') {
            if (typeof this.config.extension_filter !== 'object' || this.config.extension_filter === null || Array.isArray(this.config.extension_filter))
                this.config.extension_filter = {};
            this.config.extension_filter.enabled = true;
            if (this.config.upload_protection && typeof this.config.upload_protection === 'object')
                this.config.upload_protection.enabled = false;
            this.render();
            return true;
        }
        if (typeof this.config.upload_protection !== 'object' || this.config.upload_protection === null || Array.isArray(this.config.upload_protection))
            this.config.upload_protection = {};
        this.config.upload_protection.enabled = true;
        if (profile === 'strict_file_validation')
            this.config.upload_protection.mode = 'detect';
        this.render();
        return true;
    },
    applyResponseHeaderProfile(profile) {
        if (profile === 'custom') {
            this.requestControl = 'response_custom';
            this.render();
            return false;
        }
        if (!this.canMutatePath('security_headers.enabled'))
            return false;
        if (typeof this.config.security_headers !== 'object' || this.config.security_headers === null || Array.isArray(this.config.security_headers))
            this.config.security_headers = {};
        const sh = this.config.security_headers;
        sh.enabled = true;
        if (profile === 'strict_browser') {
            sh.x_frame_options = 'DENY';
            sh.hsts = 'max-age=63072000; includeSubDomains; preload';
            sh.x_content_type_options = 'nosniff';
            sh.referrer_policy = 'no-referrer';
            sh.csp = applyHTTPSecurityCSPPreset('strict');
            sh.permissions_policy = applyHTTPSecurityPermissionsPreset('strict');
        }
        else if (profile === 'compatibility') {
            sh.x_frame_options = 'SAMEORIGIN';
            sh.hsts = '';
            sh.x_content_type_options = 'nosniff';
            sh.referrer_policy = 'strict-origin-when-cross-origin';
            sh.csp = applyHTTPSecurityCSPPreset('compatibility');
            sh.permissions_policy = applyHTTPSecurityPermissionsPreset('compatibility');
        }
        else {
            sh.x_frame_options = 'DENY';
            sh.hsts = 'max-age=31536000; includeSubDomains';
            sh.x_content_type_options = 'nosniff';
            sh.referrer_policy = 'strict-origin-when-cross-origin';
            sh.csp = applyHTTPSecurityCSPPreset('baseline');
            sh.permissions_policy = applyHTTPSecurityPermissionsPreset('baseline');
            if (!sh.permissions_policy)
                sh.permissions_policy = applyHTTPSecurityPermissionsPreset('baseline');
        }
        this.render();
        return true;
    },
    applyCookieProfile(profile) {
        if (profile === 'custom') {
            this.requestControl = 'cookie_custom';
            this.render();
            return false;
        }
        if (!this.canMutatePath('cookie_hardener.enabled'))
            return false;
        if (typeof this.config.cookie_hardener !== 'object' || this.config.cookie_hardener === null || Array.isArray(this.config.cookie_hardener))
            this.config.cookie_hardener = {};
        const ch = this.config.cookie_hardener;
        if (profile === 'preserve') {
            ch.enabled = false;
        }
        else {
            ch.enabled = true;
            ch.force_secure = true;
            ch.force_httponly = true;
            ch.force_samesite = profile === 'strict' ? 'Strict' : 'Lax';
        }
        this.render();
        return true;
    },
    addHeaderRow(path, name, value) {
        if (!this.canMutatePath(path))
            return false;
        const cleanName = String(name || '').trim();
        if (!isValidHTTPSecurityHeaderName(cleanName)) {
            showSectionToast('Enter a valid HTTP header name.', 'warning');
            return false;
        }
        const map = { ...(this.getField(path, {}) || {}) };
        const duplicate = Object.keys(map).find((key) => key.toLowerCase() === cleanName.toLowerCase());
        if (duplicate) {
            showSectionToast('That header is already configured.', 'warning');
            return false;
        }
        map[cleanName] = String(value || '').trim();
        this.updateField(path, map);
        this.render();
        return true;
    },
    updateHeaderRow(path, oldName, field, value) {
        if (!this.canMutatePath(path))
            return false;
        const map = { ...(this.getField(path, {}) || {}) };
        const previous = String(oldName || '').trim();
        if (!Object.prototype.hasOwnProperty.call(map, previous))
            return false;
        if (field === 'name') {
            const nextName = String(value || '').trim();
            if (!isValidHTTPSecurityHeaderName(nextName)) {
                showSectionToast('Enter a valid HTTP header name.', 'warning');
                return false;
            }
            const duplicate = Object.keys(map).find((key) => key.toLowerCase() === nextName.toLowerCase() && key !== previous);
            if (duplicate) {
                showSectionToast('That header is already configured.', 'warning');
                return false;
            }
            const existingValue = map[previous];
            delete map[previous];
            map[nextName] = existingValue;
        }
        else {
            map[previous] = String(value || '').trim();
        }
        this.updateField(path, map);
        this.render();
        return true;
    },
    removeHeaderRow(path, name) {
        if (!this.canMutatePath(path))
            return false;
        const map = { ...(this.getField(path, {}) || {}) };
        delete map[String(name || '').trim()];
        this.updateField(path, map);
        this.render();
        return true;
    },
    applyCSPPreset(preset) {
        if (!this.canMutatePath('security_headers.csp'))
            return false;
        if (typeof this.config.security_headers !== 'object' || this.config.security_headers === null || Array.isArray(this.config.security_headers))
            this.config.security_headers = {};
        this.config.security_headers.csp = applyHTTPSecurityCSPPreset(preset, this.config.security_headers.csp || '');
        this.render();
        return true;
    },
    addCSPSource(directive, source) {
        if (!this.canMutatePath('security_headers.csp'))
            return false;
        const cleanDirective = String(directive || '').trim();
        const cleanSource = String(source || '').trim();
        if (!cleanDirective || !cleanSource)
            return false;
        const map = parseHTTPSecurityCSP(this.config.security_headers?.csp || '');
        map[cleanDirective] = [...new Set([...(map[cleanDirective] || []), cleanSource])];
        this.updateField('security_headers.csp', serializeHTTPSecurityCSP(map));
        this.render();
        return true;
    },
    removeCSPSource(value) {
        if (!this.canMutatePath('security_headers.csp'))
            return false;
        const [directive, source] = String(value || '').split('|');
        if (!directive || !source)
            return false;
        const map = parseHTTPSecurityCSP(this.config.security_headers?.csp || '');
        map[directive] = (map[directive] || []).filter((item) => item !== source);
        this.updateField('security_headers.csp', serializeHTTPSecurityCSP(map));
        this.render();
        return true;
    },
    setPermissionsPolicyFeature(feature, value) {
        if (!this.canMutatePath('security_headers.permissions_policy'))
            return false;
        const map = parseHTTPSecurityPermissionsPolicy(this.config.security_headers?.permissions_policy || '');
        map[String(feature || '').trim()] = String(value || '()').trim();
        this.updateField('security_headers.permissions_policy', serializeHTTPSecurityPermissionsPolicy(map));
        this.render();
        return true;
    },
    applyPermissionsPolicyPreset(preset) {
        if (!this.canMutatePath('security_headers.permissions_policy'))
            return false;
        this.updateField('security_headers.permissions_policy', applyHTTPSecurityPermissionsPreset(preset));
        this.render();
        return true;
    },
    addExtensionGroup(path, groupID) {
        if (!this.canMutatePath(path))
            return false;
        const group = HTTPSEC_EXTENSION_GROUPS[groupID];
        if (!group)
            return false;
        const current = this.getField(path, []);
        const next = [...new Set([...(Array.isArray(current) ? current : []), ...group.values].map(normalizeHTTPSecurityExtension).filter(Boolean))];
        this.updateField(path, next);
        this.render();
        return true;
    },
    promptAddHost() {
        const host = prompt('Enter hostname (e.g. example.com):');
        if (host && host.trim())
            return this.addTag('host_validator.allowed_hosts', host.trim());
        return false;
    },
};
const HTTPSecurityConfigState = {
    get currentTab() { return HTTPSecurityConfig.currentTab; },
    set currentTab(value) { HTTPSecurityConfig.currentTab = value; },
    get config() { return HTTPSecurityConfig.config; },
    set config(value) { HTTPSecurityConfig.config = value; },
    get stats() { return HTTPSecurityConfig.stats; },
    set stats(value) { HTTPSecurityConfig.stats = value; },
    get capabilities() { return HTTPSecurityConfig.capabilities; },
    set capabilities(value) { HTTPSecurityConfig.capabilities = value; },
    get effectiveState() { return HTTPSecurityConfig.effectiveState; },
    set effectiveState(value) { HTTPSecurityConfig.effectiveState = value; },
    get functions() { return HTTPSecurityConfig.functions; },
    set functions(value) { HTTPSecurityConfig.functions = value; },
    get tabs() { return HTTPSecurityConfig.tabs; },
    set tabs(value) { HTTPSecurityConfig.tabs = value; },
    get headerManagerTab() { return HTTPSecurityConfig.headerManagerTab; },
    set headerManagerTab(value) { HTTPSecurityConfig.headerManagerTab = value; },
    get icons() { return HTTPSecurityConfig.icons; },
    set icons(value) { HTTPSecurityConfig.icons = value; }
};
const HTTPSecurityConfigService = {
    init: () => HTTPSecurityConfig.init(),
    loadCapabilities: () => HTTPSecurityConfig.loadCapabilities(),
    loadConfig: () => HTTPSecurityConfig.loadConfig(),
    loadEffectiveState: () => HTTPSecurityConfig.loadEffectiveState(),
    loadStats: () => HTTPSecurityConfig.loadStats(),
    saveConfig: () => HTTPSecurityConfig.saveConfig()
};
const HTTPSecurityConfigView = {
    escapeHtml: escapeHTTPSecurityHtml,
    showToast: showSectionToast,
    render: () => HTTPSecurityConfig.render(),
    syncGaugeFills: () => HTTPSecurityConfig.syncGaugeFills(),
    renderTabContent: () => HTTPSecurityConfig.renderTabContent(),
    renderOverview: () => HTTPSecurityConfig.renderOverview(),
    renderOverviewStat: (label, value, color) => HTTPSecurityConfig.renderOverviewStat(label, value, color),
    renderModuleCard: (mod) => HTTPSecurityConfig.renderModuleCard(mod),
    renderResponseSecurity: () => renderHTTPSecurityResponseProtection(HTTPSecurityConfig),
    renderSaveButtons: renderHTTPSecuritySaveButtons,
    formatHeaderMap: formatHTTPSecurityHeaderMap
};
const HTTPSecurityConfigController = {
    dispose: () => disposeHTTPSecurityBindings(),
    updateField: (path, value) => HTTPSecurityConfig.updateField(path, value),
    getField: (path, fallback) => HTTPSecurityConfig.getField(path, fallback),
    switchTab: (id) => HTTPSecurityConfig.switchTab(id),
    setHeaderTab: (tab) => HTTPSecurityConfig.setHeaderTab(tab),
    addTag: (path, value) => HTTPSecurityConfig.addTag(path, value),
    removeTag: (path, value) => HTTPSecurityConfig.removeTag(path, value),
    toggleArrayItem: (path, value) => HTTPSecurityConfig.toggleArrayItem(path, value),
    toggleMethodPill: (method) => HTTPSecurityConfig.toggleMethodPill(method),
    promptAddHost: () => HTTPSecurityConfig.promptAddHost(),
    parseHeaderMap: (path, text) => HTTPSecurityConfig.updateField(path, parseHTTPSecurityHeaderMap(text))
};
const httpSecurityServiceMethods = new Set([
    'init',
    'loadCapabilities',
    'loadConfig',
    'loadEffectiveState',
    'loadStats',
    'saveConfig'
]);
const httpSecurityViewMethods = new Set([
    'escapeHtml',
    'showToast',
    'render',
    'syncGaugeFills',
    'renderTabContent',
    'renderOverview',
    'renderOverviewStat',
    'renderModuleCard',
    'renderResponseSecurity',
    'renderSaveButtons',
    'formatHeaderMap'
]);
export const HTTPSecurityConfigFacade = new Proxy({}, {
    get(_target, prop) {
        if (prop === 'state')
            return HTTPSecurityConfigState;
        if (typeof prop !== 'string')
            return undefined;
        if (httpSecurityServiceMethods.has(prop)) {
            return HTTPSecurityConfigService[prop];
        }
        if (httpSecurityViewMethods.has(prop)) {
            return HTTPSecurityConfigView[prop];
        }
        if (prop in HTTPSecurityConfigController) {
            return HTTPSecurityConfigController[prop];
        }
        const value = HTTPSecurityConfig[prop];
        return typeof value === 'function' ? value.bind(HTTPSecurityConfig) : value;
    },
    set(_target, prop, value) {
        if (typeof prop === 'string' && prop in HTTPSecurityConfig) {
            HTTPSecurityConfig[prop] = value;
            return true;
        }
        return false;
    }
});
