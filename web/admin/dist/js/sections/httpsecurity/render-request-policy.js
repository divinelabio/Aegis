import { SectionUI } from '../ui-components.js';
import { renderHTTPSecuritySaveButtons } from '../httpsecurity-render-helpers.js';
import { escapeHTTPSecurityHtml } from '../httpsecurity-runtime-helpers.js';
import { renderHeaderMapBuilder, renderHeaderRemoveBuilder } from './controls/header-builder.js';
function encodeHTTPSecurityValue(value) {
    return encodeURIComponent(String(value));
}
export function renderHTTPSecurityRequestPolicy(runtime) {
    const view = runtime;
    const requestPolicy = view.viewModel?.requestPolicy || {};
    const me = requestPolicy.methodEnforcer || {};
    const hv = requestPolicy.hostValidator || {};
    const ctv = requestPolicy.contentTypeValidator || {};
    const rsg = requestPolicy.requestSizeGuard || {};
    const hm = requestPolicy.headerManager || {};
    const hasHeaderManager = view.canConfigure('header_manager');
    const hosts = hv.allowed_hosts || [];
    const methodProfile = view.getRequestMethodProfile(me);
    const contentProfile = view.getContentTypeProfile(ctv);
    const boundaryProfile = view.getRequestBoundaryProfile(rsg);
    const headerRules = hasHeaderManager ? Object.keys(hm.add_request_headers || {}).length + (hm.remove_request_headers || []).length : 0;
    const methodMode = me.mode || 'blocklist';
    const selectedMethods = methodMode === 'allowlist' ? (me.allowed_methods || []) : (me.blocked_methods || []);
    const allMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'TRACK', 'CONNECT', 'DEBUG'];
    const showMethodCustom = view.requestControl === 'methods_custom' || methodProfile.id === 'custom';
    const showContentCustom = view.requestControl === 'content_type_custom' || contentProfile.id === 'custom';
    const showLimitsCustom = view.requestControl === 'limits_custom' || boundaryProfile.id === 'custom';
    const modeCard = (active, icon, title, desc, meta, attrs) => `
            <button type="button" class="httpsec-mode-card httpsec-policy-choice-card ${active ? 'is-active' : ''}" aria-pressed="${active}" ${attrs}>
                <span class="httpsec-choice-check">${view.icons.check}</span>
                <span class="httpsec-policy-choice-icon" aria-hidden="true">${icon}</span>
                <span class="httpsec-policy-choice-copy">
                    <strong>${title}</strong>
                    <small>${desc}</small>
                    <span class="httpsec-policy-choice-meta">${meta}</span>
                </span>
            </button>`;
    const compactModeOption = (active, title, desc, attrs) => `
            <button type="button" class="httpsec-compact-mode-option ${active ? 'is-active' : ''}" aria-pressed="${active}" ${attrs}>
                <span class="httpsec-compact-mode-indicator" aria-hidden="true"></span>
                <span class="httpsec-compact-mode-copy">
                    <strong>${title}</strong>
                    <small>${desc}</small>
                </span>
            </button>`;
    const customEditorHeader = (title, desc, meta) => `
            <div class="httpsec-custom-editor-head">
                <span class="httpsec-custom-editor-copy">
                    <strong>${title}</strong>
                    <small>${desc}</small>
                </span>
                ${meta ? `<span class="httpsec-custom-editor-meta">${meta}</span>` : ''}
            </div>`;
    const moduleSwitch = (key, enabled, title) => `<label class="section-switch section-policy-toggle-switch" title="${enabled ? 'Disable' : 'Enable'} ${title}"><input type="checkbox" ${enabled ? 'checked' : ''} data-httpsec-path="${key}.enabled" data-httpsec-value-type="checkbox" data-httpsec-render="true"><span class="switch-slider"></span></label>`;
    const methodTiles = () => `<div class="httpsec-check-grid httpsec-method-grid">${allMethods.map((method) => `<label class="httpsec-check-tile ${selectedMethods.includes(method) ? 'is-active' : ''}"><input type="checkbox" value="${method}" ${selectedMethods.includes(method) ? 'checked' : ''} data-httpsec-method-toggle="${method}"><span>${method}</span></label>`).join('')}</div>`;
    const contentTiles = () => `<div class="httpsec-check-grid httpsec-method-grid">${['POST', 'PUT', 'PATCH', 'DELETE'].map((method) => `<label class="httpsec-check-tile ${(ctv.required_on || []).includes(method) ? 'is-active' : ''}"><input type="checkbox" value="${method}" ${(ctv.required_on || []).includes(method) ? 'checked' : ''} data-httpsec-array-toggle="content_type_validator.required_on"><span>${method}</span></label>`).join('')}</div>`;
    const domainContent = `
            <div class="httpsec-mode-cards httpsec-policy-choice-cards" role="group" aria-label="Host admission mode">
                ${modeCard(hv.enabled !== true, view.icons.globe, 'Open onboarding', 'Accept any Host header while applications are still being added.', 'PERMISSIVE ADMISSION', 'data-httpsec-action="set-field" data-httpsec-path="host_validator.enabled" data-httpsec-value="false" data-httpsec-value-type="boolean" data-httpsec-render="true"')}
                ${modeCard(hv.enabled === true, view.icons.globe, 'Domain inventory', 'Reject unknown Host headers and serve only configured domains.', 'HOST ALLOWLIST', 'data-httpsec-action="set-field" data-httpsec-path="host_validator.enabled" data-httpsec-value="true" data-httpsec-value-type="boolean" data-httpsec-render="true"')}
            </div>
            ${hv.enabled === true ? `<div class="httpsec-compact-editor httpsec-custom-editor">
                ${customEditorHeader('Allowed domains', 'Add the exact Host values this application may serve.', `${hosts.length} configured`)}
              <div class="section-inline-form"><input type="text" id="host-add-input" placeholder="example.com" class="section-input text-mono" data-httpsec-enter-action="add-tag-from-input" data-httpsec-path="host_validator.allowed_hosts"><button type="button" class="btn btn-outline btn-sm" data-httpsec-action="add-tag-from-input" data-httpsec-path="host_validator.allowed_hosts" data-httpsec-input-id="host-add-input">Add</button></div>
                <div class="httpsec-extension-grid">${hosts.map((host) => `<button class="httpsec-extension-chip" type="button" data-httpsec-action="remove-tag" data-httpsec-path="host_validator.allowed_hosts" data-httpsec-value="${encodeHTTPSecurityValue(host)}"><span>${escapeHTTPSecurityHtml(host)}</span><span class="httpsec-extension-remove" aria-hidden="true">&times;</span></button>`).join('') || '<div class="httpsec-empty-note">No domains listed yet.</div>'}</div>
            </div>` : ''}
        `;
    const methodContent = `
            <div class="httpsec-mode-cards httpsec-mode-cards-4 httpsec-policy-choice-cards" role="group" aria-label="HTTP method profile">
                ${modeCard(methodProfile.id === 'recommended' && !showMethodCustom, view.icons.shield, 'Recommended', 'Block TRACE, TRACK, CONNECT, and DEBUG.', 'DENYLIST BASELINE', 'data-httpsec-action="apply-request-method-profile" data-httpsec-value="recommended"')}
                ${modeCard(methodProfile.id === 'api_strict' && !showMethodCustom, view.icons.code, 'API strict', 'Allow common API methods only.', 'API ALLOWLIST', 'data-httpsec-action="apply-request-method-profile" data-httpsec-value="api_strict"')}
                ${modeCard(methodProfile.id === 'read_only' && !showMethodCustom, view.icons.eye, 'Read-only', 'Only GET, HEAD, and OPTIONS pass.', 'READ-ONLY PROFILE', 'data-httpsec-action="apply-request-method-profile" data-httpsec-value="read_only"')}
                ${modeCard(showMethodCustom, view.icons.sliders, 'Custom', `${methodMode === 'allowlist' ? 'Allow' : 'Block'} ${selectedMethods.length} selected method${selectedMethods.length === 1 ? '' : 's'}.`, 'CUSTOM METHOD POLICY', 'data-httpsec-action="select-request-control" data-httpsec-value="methods_custom"')}
            </div>
            ${showMethodCustom ? `
                <div class="httpsec-compact-editor httpsec-custom-editor">
                    ${customEditorHeader('Custom method policy', 'Choose the rule behavior, then select the affected HTTP methods.', `${selectedMethods.length} selected`)}
                    <div class="httpsec-compact-mode-switch" role="group" aria-label="Custom HTTP method behavior">
                        ${compactModeOption(methodMode === 'blocklist', 'Block selected', 'Selected methods are denied.', 'data-httpsec-action="set-field" data-httpsec-path="method_enforcer.mode" data-httpsec-value="blocklist" data-httpsec-render="true"')}
                        ${compactModeOption(methodMode === 'allowlist', 'Allow selected', 'Only selected methods can pass.', 'data-httpsec-action="set-field" data-httpsec-path="method_enforcer.mode" data-httpsec-value="allowlist" data-httpsec-render="true"')}
                    </div>
                    <div class="httpsec-custom-field-label"><strong>Methods</strong><small>Select one or more verbs for this rule.</small></div>
                    ${methodTiles()}
                </div>` : ''}
        `;
    const contentTypeContent = `
            <div class="httpsec-mode-cards httpsec-mode-cards-4 httpsec-policy-choice-cards" role="group" aria-label="Write hygiene profile">
                ${modeCard(contentProfile.id === 'off' && !showContentCustom, view.icons.x, 'Off', 'Do not require Content-Type.', 'VALIDATION DISABLED', 'data-httpsec-action="apply-content-type-profile" data-httpsec-value="off"')}
                ${modeCard(contentProfile.id === 'writes' && !showContentCustom, view.icons.file, 'Writes', 'Require it on POST, PUT, and PATCH.', 'STANDARD WRITES', 'data-httpsec-action="apply-content-type-profile" data-httpsec-value="writes"')}
                ${modeCard(contentProfile.id === 'strict_writes' && !showContentCustom, view.icons.file, 'Strict writes', 'Also require it on DELETE.', 'STRICT WRITE POLICY', 'data-httpsec-action="apply-content-type-profile" data-httpsec-value="strict_writes"')}
                ${modeCard(showContentCustom, view.icons.sliders, 'Custom', `${(ctv.required_on || []).length} write method${(ctv.required_on || []).length === 1 ? '' : 's'} selected.`, 'CUSTOM MEDIA POLICY', 'data-httpsec-action="select-request-control" data-httpsec-value="content_type_custom"')}
            </div>
            ${showContentCustom ? `<div class="httpsec-compact-editor httpsec-custom-editor">
                ${customEditorHeader('Required write methods', 'Choose which state-changing requests must include Content-Type.', `${(ctv.required_on || []).length} selected`)}
                ${contentTiles()}
            </div>` : ''}
        `;
    const limitsContent = `
            <div class="httpsec-mode-cards httpsec-mode-cards-4 httpsec-policy-choice-cards" role="group" aria-label="Request boundary profile">
                ${modeCard(boundaryProfile.id === 'relaxed' && !showLimitsCustom, view.icons.activity, 'Relaxed', 'Large APIs and verbose headers.', 'HIGH-THROUGHPUT PROFILE', 'data-httpsec-action="apply-request-boundary-preset" data-httpsec-value="relaxed"')}
                ${modeCard(boundaryProfile.id === 'balanced' && !showLimitsCustom, view.icons.activity, 'Balanced', 'Recommended default for most apps.', 'RECOMMENDED BOUNDARIES', 'data-httpsec-action="apply-request-boundary-preset" data-httpsec-value="balanced"')}
                ${modeCard(boundaryProfile.id === 'strict' && !showLimitsCustom, view.icons.shield, 'Strict', 'Tighter public endpoint profile.', 'PUBLIC EDGE PROFILE', 'data-httpsec-action="apply-request-boundary-preset" data-httpsec-value="strict"')}
                ${modeCard(showLimitsCustom, view.icons.sliders, 'Custom', `URL ${rsg.max_url_length || 2048} bytes.`, 'CUSTOM REQUEST LIMITS', 'data-httpsec-action="select-request-control" data-httpsec-value="limits_custom"')}
            </div>
            ${showLimitsCustom ? `
                <div class="httpsec-compact-editor httpsec-custom-editor">
                    ${customEditorHeader('Custom request boundaries', 'Set explicit limits for URLs, queries, and headers.', '')}
                    <div class="httpsec-request-limit-grid">
                        <label class="httpsec-request-limit"><span>URL length</span><div><input type="number" min="0" value="${rsg.max_url_length || 2048}" data-httpsec-path="request_size_guard.max_url_length" data-httpsec-value-type="number"><b>bytes</b></div></label>
                        <label class="httpsec-request-limit"><span>Query length</span><div><input type="number" min="0" value="${rsg.max_query_length || 2048}" data-httpsec-path="request_size_guard.max_query_length" data-httpsec-value-type="number"><b>bytes</b></div></label>
                        <label class="httpsec-request-limit"><span>Header count</span><div><input type="number" min="0" value="${rsg.max_header_count || 50}" data-httpsec-path="request_size_guard.max_header_count" data-httpsec-value-type="number"><b>headers</b></div></label>
                        <label class="httpsec-request-limit"><span>Header size</span><div><input type="number" min="0" value="${rsg.max_single_header_size || 8192}" data-httpsec-path="request_size_guard.max_single_header_size" data-httpsec-value-type="number"><b>bytes</b></div></label>
                    </div>
                </div>` : ''}
        `;
    const headerContent = `
            <div class="httpsec-mode-cards httpsec-policy-choice-cards" role="group" aria-label="Upstream header behavior">
                ${modeCard(hm.enabled !== true, view.icons.arrowRight, 'Leave unchanged', 'Requests are forwarded without custom header changes.', 'PASS-THROUGH REQUESTS', 'data-httpsec-action="set-field" data-httpsec-path="header_manager.enabled" data-httpsec-value="false" data-httpsec-value-type="boolean" data-httpsec-render="true"')}
                ${modeCard(hm.enabled === true, view.icons.sliders, 'Apply header rules', `${headerRules || 'No'} configured rule${headerRules === 1 ? '' : 's'}.`, 'UPSTREAM TRANSFORMATION', 'data-httpsec-action="set-field" data-httpsec-path="header_manager.enabled" data-httpsec-value="true" data-httpsec-value-type="boolean" data-httpsec-render="true"')}
            </div>
            ${hm.enabled === true ? `<div class="httpsec-compact-editor">
                ${renderHeaderMapBuilder('Add request headers', 'header_manager.add_request_headers', hm.add_request_headers || {}, 'req-add-header')}
                ${renderHeaderRemoveBuilder('Remove request headers', 'header_manager.remove_request_headers', hm.remove_request_headers || [], 'rm-req-hdr')}
            </div>` : ''}
        `;
    const statusPill = (enabled, on = 'Active', off = 'Off') => `<span class="config-status-pill tone-${enabled ? 'success' : 'neutral'}">${enabled ? on : off}</span>`;
    const policyRow = (key, title, description, icon, enabled, content, titleHeadingLevel = 3) => SectionUI.renderOperatorControlRow({
        title,
        description,
        icon: view.icons[icon] || view.icons.shield,
        enabled,
        titleHeadingLevel,
        actions: `<label class="section-switch section-policy-toggle-switch" title="${enabled ? 'Disable' : 'Enable'} ${title}"><input type="checkbox" ${enabled ? 'checked' : ''} data-httpsec-path="${key}.enabled" data-httpsec-value-type="checkbox" data-httpsec-render="true"><span class="switch-slider"></span></label>`,
        content,
        className: 'httpsec-response-overview-row'
    });
    const requestAreaRow = (id, title, description, icon, enabled) => SectionUI.renderOperatorControlRow({
        title,
        description,
        icon: view.icons[icon] || view.icons.shield,
        enabled,
        actions: statusPill(enabled),
        className: 'httpsec-response-area-row',
        attrs: `role="button" tabindex="0" data-httpsec-action="open-request-policy-page" data-httpsec-value="${id}"`
    });
    const requestAreas = `
            <div class="operator-control-list httpsec-response-area-list">
                ${requestAreaRow('host_validator', 'Host admission', hv.enabled === true ? `${hosts.length || 0} domain${hosts.length === 1 ? '' : 's'} allowed` : 'Open onboarding', 'globe', hv.enabled === true)}
                ${requestAreaRow('method_enforcer', 'HTTP methods', `${methodProfile.label} — ${methodMode === 'allowlist' ? 'Allow' : 'Block'} ${selectedMethods.length} verb${selectedMethods.length === 1 ? '' : 's'}`, 'sliders', me.enabled === true)}
                ${requestAreaRow('request_size_guard', 'Request boundaries', `${boundaryProfile.label} — Max URL ${rsg.max_url_length || 2048} B, Query ${rsg.max_query_length || 2048} B`, 'activity', rsg.enabled === true)}
                ${requestAreaRow('content_type_validator', 'Write hygiene', `${contentProfile.label} — ${(ctv.required_on || []).length ? (ctv.required_on || []).join(', ') : 'No verbs enforced'}`, 'file', ctv.enabled === true)}
                ${hasHeaderManager ? requestAreaRow('header_manager', 'Upstream headers', hm.enabled === true ? `${headerRules} rule${headerRules === 1 ? '' : 's'} applied` : 'Unchanged', 'sliders', hm.enabled === true) : ''}
            </div>`;
    const requestPages = {
        host_validator: {
            content: `<div class="operator-control-list">${policyRow('host_validator', 'Host admission', 'Control which Host headers this application serves.', 'globe', hv.enabled === true, domainContent)}</div>`
        },
        method_enforcer: {
            content: `<div class="operator-control-list">${policyRow('method_enforcer', 'HTTP methods', 'Choose which HTTP verbs can pass through the edge.', 'sliders', me.enabled === true, methodContent)}</div>`
        },
        request_size_guard: {
            content: `<div class="operator-control-list">${policyRow('request_size_guard', 'Request boundaries', 'Bound URI, query-string, header count, and single-header size.', 'activity', rsg.enabled === true, limitsContent)}</div>`
        },
        content_type_validator: {
            content: `<div class="operator-control-list">${policyRow('content_type_validator', 'Write hygiene', 'Require valid media types on state-changing requests.', 'file', ctv.enabled === true, contentTypeContent)}</div>`
        },
        header_manager: {
            content: `<div class="operator-control-list">${policyRow('header_manager', 'Upstream headers', 'Add or strip request headers before traffic reaches protected applications.', 'sliders', hm.enabled === true, headerContent)}</div>`
        }
    };
    const selectedPage = requestPages[String(runtime.requestPolicyPage || '')];
    return `
            <div class="httpsec-overview-stack httpsec-response-overview-stack">
                ${selectedPage ? `
                    <header class="httpsec-response-page-header">
                        ${SectionUI.renderOperatorBackButton({
        label: 'Back to Request Policy',
        attrs: 'data-httpsec-action="close-request-policy-page"',
        className: 'httpsec-response-page-back'
    })}
                    </header>
                    ${selectedPage.content}
                ` : SectionUI.renderOperatorSection('Request policy', requestAreas, {
        subtitle: 'Choose an area to configure request admission and boundary rules.'
    })}
            </div>
            ${renderHTTPSecuritySaveButtons()}
        `;
}
