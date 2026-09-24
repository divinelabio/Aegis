/**
 * WAF Leak Protection
 * Data Loss Prevention (DLP), exposed secret redaction, custom detectors, and allowlists.
 */
import { SectionUI } from '../ui-components.js';
import { escapeWafHtml } from '../waf-runtime-helpers.js';
import { WAFLeakProtectionConfig, WAFLeakProtectionPage } from './types.js';

export const defaultWafLeakProtectionConfig: WAFLeakProtectionConfig = {
    enabled: false,
    mode: 'detect',
    default_action: 'detect',
    max_body_size: 1048576,
    custom_patterns: [],
    allowlist: [],
    inspect_content_types: ['text/plain', 'text/html', 'text/xml', 'application/json', 'application/xml', 'application/javascript'],
    skip_content_types: ['image/*', 'audio/*', 'video/*', 'application/octet-stream', 'application/pdf', 'application/zip']
};

export interface LeakMimeGroup {
    id: string;
    title: string;
    description: string;
    mimeTypes: string[];
    icon: string;
}

export const leakMimeGroups: LeakMimeGroup[] = [
    {
        id: 'json_api',
        title: 'REST & JSON APIs',
        description: 'Scans API responses, JSON payloads, and error objects for leaked tokens, keys, and credentials.',
        mimeTypes: ['application/json', 'application/problem+json'],
        icon: 'database'
    },
    {
        id: 'web_pages',
        title: 'Web Pages & HTML',
        description: 'Scans rendered HTML pages, exception views, and plain-text output for stack traces and credentials.',
        mimeTypes: ['text/html', 'text/plain'],
        icon: 'globe'
    },
    {
        id: 'xml_soap',
        title: 'XML & SOAP Services',
        description: 'Scans XML endpoints, structured data feeds, and SOAP payloads for connection strings and passwords.',
        mimeTypes: ['text/xml', 'application/xml'],
        icon: 'fileText'
    },
    {
        id: 'scripts',
        title: 'JavaScript & Scripts',
        description: 'Scans dynamic JavaScript assets for accidentally embedded private keys and internal tokens.',
        mimeTypes: ['application/javascript', 'text/javascript'],
        icon: 'file'
    }
];

export function formatWafBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KiB`;
    return `${(bytes / 1048576).toFixed(1)} MiB`;
}

export function formatWafMebibytes(bytes: number): string {
    const mib = bytes / 1048576;
    return Number.isInteger(mib) ? `${mib}` : mib.toFixed(1);
}

export function renderLeakProtectionTab(
    leakConfig: WAFLeakProtectionConfig | undefined,
    leakProtectionPage: WAFLeakProtectionPage,
    getIcon: (name: string) => string
): string {
    const leak = leakConfig || defaultWafLeakProtectionConfig;
    const normalizeAction = (raw: unknown, fallback = 'detect') => {
        if (typeof raw !== 'string') return fallback;
        if (raw === 'monitoring') return 'detect';
        if (raw === 'blocking') return 'block';
        if (raw === 'off') return 'allow';
        return ['allow', 'detect', 'redact', 'block'].includes(raw) ? raw : fallback;
    };
    const mode = normalizeAction(leak.mode);
    const defaultAction = normalizeAction(leak.default_action);
    const enabled = leak.enabled === true;
    const maxBodySize = typeof leak.max_body_size === 'number' && leak.max_body_size > 0
        ? leak.max_body_size
        : defaultWafLeakProtectionConfig.max_body_size || 1048576;
    const actionOptions = [
        { value: 'allow', label: 'Bypass inspection' },
        { value: 'detect', label: 'Monitor only' },
        { value: 'redact', label: 'Redact matches' },
        { value: 'block', label: 'Block responses' }
    ];
    const categoryGroups = [
        {
            id: 'credentials',
            title: 'Credentials and tokens',
            description: '6 categories',
            items: [
                { category: 'private_key', title: 'Private keys' },
                { category: 'cloud_secret', title: 'Cloud credentials' },
                { category: 'api_token', title: 'API tokens' },
                { category: 'jwt', title: 'JWTs' },
                { category: 'env_file', title: 'Environment dumps' },
                { category: 'db_connection', title: 'Database connections' }
            ]
        },
        {
            id: 'debug',
            title: 'Debug and source exposure',
            description: '4 categories',
            items: [
                { category: 'stack_trace', title: 'Stack traces' },
                { category: 'debug_page', title: 'Debug pages' },
                { category: 'source_code', title: 'Source code' },
                { category: 'internal_network', title: 'Internal network details' }
            ]
        },
        {
            id: 'files',
            title: 'Browsable files',
            description: '2 categories',
            items: [
                { category: 'directory_listing', title: 'Directory listings' },
                { category: 'backup_config', title: 'Backup and config files' }
            ]
        }
    ];
    const actionSelect = (path: string, value: string, label: string, includeDefault = false) => `
        <select class="select-sm" aria-label="${escapeWafHtml(label)}" data-waf-field="${escapeWafHtml(path)}">
            ${includeDefault ? `<option value="" ${value === '' ? 'selected' : ''}>Use policy default</option>` : ''}
            ${actionOptions.map(option => `<option value="${option.value}" ${value === option.value ? 'selected' : ''}>${option.label}</option>`).join('')}
        </select>`;
    const renderMimeGroupCards = () => `
        <div class="operator-control-list firewall-leak-mime-list">
            ${leakMimeGroups.map(group => {
                const isEnabled = (leak.inspect_content_types || []).some(m =>
                    group.mimeTypes.some(gm => gm.toLowerCase() === m.toLowerCase())
                );
                return SectionUI.renderOperatorControlRow({
                    title: escapeWafHtml(group.title),
                    description: escapeWafHtml(group.description),
                    icon: getIcon(group.icon),
                    enabled: isEnabled,
                    actions: `<label class="section-switch" title="${isEnabled ? 'Disable' : 'Enable'} ${escapeWafHtml(group.title)}"><input type="checkbox" ${isEnabled ? 'checked' : ''} data-waf-action="toggle-leak-mime-group" data-waf-group="${escapeWafHtml(group.id)}"><span class="switch-slider"></span></label>`,
                    className: 'firewall-leak-mime-row'
                });
            }).join('')}
        </div>`;
    const configuredPatterns = (leak.custom_patterns || []).map(pattern => `
        <li class="firewall-leak-list-row">
            <div><strong>${escapeWafHtml(pattern.name || pattern.id)}</strong><span>${escapeWafHtml(pattern.category || 'custom')} · ${escapeWafHtml(pattern.action || 'policy default')} · ${pattern.enabled === false ? 'disabled' : 'enabled'}</span></div>
            <button type="button" class="btn btn-ghost btn-sm" data-waf-action="remove-leak-pattern" data-waf-value="${escapeWafHtml(pattern.id)}">Remove</button>
        </li>`).join('');
    const configuredAllowlist = (leak.allowlist || []).map(entry => `
        <li class="firewall-leak-list-row">
            <div><strong>${escapeWafHtml(entry.reason || entry.id)}</strong><span>${escapeWafHtml([entry.category || 'any category', entry.host || 'any host', entry.path || 'any path', entry.content_type || 'any content type'].join(' · '))}</span></div>
            <button type="button" class="btn btn-ghost btn-sm" data-waf-action="remove-leak-allowlist" data-waf-value="${escapeWafHtml(entry.id)}">Remove</button>
        </li>`).join('');
    const customDetectorContent = `
        <div class="firewall-leak-inline-form">
            <label class="bot-overview-field"><span>Name</span><input id="firewall-leak-pattern-name" class="section-input" type="text" placeholder="e.g. Internal API key" aria-label="Custom leak detector name"></label>
            <label class="bot-overview-field firewall-leak-form-field--pattern"><span>Pattern</span><input id="firewall-leak-pattern-expression" class="section-input" type="text" placeholder="Regular expression" aria-label="Custom leak detector regular expression"></label>
            <label class="bot-overview-field"><span>Category</span><input id="firewall-leak-pattern-category" class="section-input" type="text" value="custom" aria-label="Custom leak detector category"></label>
            <label class="bot-overview-field"><span>Response</span><select id="firewall-leak-pattern-action" class="select-sm" aria-label="Custom leak detector action"><option value="">Policy default</option><option value="detect">Monitor only</option><option value="redact">Redact matches</option><option value="block">Block responses</option></select></label>
            <div class="firewall-leak-inline-form-action"><button type="button" class="btn btn-outline btn-sm" data-waf-action="add-leak-pattern">Add detector</button></div>
        </div>
        ${configuredPatterns ? `<ul class="firewall-leak-list">${configuredPatterns}</ul>` : '<p class="firewall-leak-empty-state">No custom detectors are staged.</p>'}`;
    const allowlistContent = `
        <div class="firewall-leak-inline-form firewall-leak-inline-form--allowlist">
            <label class="bot-overview-field"><span>Host</span><input id="firewall-leak-allowlist-host" class="section-input" type="text" placeholder="Optional" aria-label="Leak allowlist host"></label>
            <label class="bot-overview-field"><span>Path</span><input id="firewall-leak-allowlist-path" class="section-input" type="text" placeholder="e.g. /health" aria-label="Leak allowlist path"></label>
            <label class="bot-overview-field"><span>Content type</span><input id="firewall-leak-allowlist-content-type" class="section-input" type="text" placeholder="Optional" aria-label="Leak allowlist content type"></label>
            <label class="bot-overview-field"><span>Category</span><input id="firewall-leak-allowlist-category" class="section-input" type="text" placeholder="Optional" aria-label="Leak allowlist category"></label>
            <label class="bot-overview-field"><span>Reason</span><input id="firewall-leak-allowlist-reason" class="section-input" type="text" placeholder="Required" aria-label="Leak allowlist reason"></label>
            <label class="bot-overview-field"><span>Expires</span><input id="firewall-leak-allowlist-expires" class="section-input" type="date" aria-label="Leak allowlist expiry"></label>
            <div class="firewall-leak-inline-form-action"><button type="button" class="btn btn-outline btn-sm" data-waf-action="add-leak-allowlist">Add exception</button></div>
        </div>
        ${configuredAllowlist ? `<ul class="firewall-leak-list">${configuredAllowlist}</ul>` : '<p class="firewall-leak-empty-state">No allowlist exceptions are staged.</p>'}`;
    const renderCategoryRules = (group: typeof categoryGroups[number]) => `
        <div class="operator-control-list">
            ${group.items.map(item => {
                const rulesObj = (leak.categories || {}) as Record<string, string>;
                const configuredAction = String(rulesObj[item.category] || '');
                const action = configuredAction ? normalizeAction(configuredAction) : '';
                return SectionUI.renderOperatorControlRow({
                    title: item.title,
                    icon: getIcon('shield'),
                    enabled: action !== '',
                    actions: actionSelect(`leak_protection.categories.${item.category}`, action, `${item.title} leak response action`, true)
                });
            }).join('')}
        </div>`;
    const selectedCategory = categoryGroups.find(group => group.id === leakProtectionPage);
    const isAdvancedChildPage = Boolean(selectedCategory) || leakProtectionPage === 'custom_detectors' || leakProtectionPage === 'allowlist';
    const categoryExceptions = mode === 'block'
        ? `<p class="firewall-leak-summary">Block applies to every finding.</p>`
        : mode === 'allow'
            ? `<p class="firewall-leak-summary">Select Monitor, Redact, or Block to use exceptions.</p>`
            : categoryGroups.map(group => {
                const rulesObj = (leak.categories || {}) as Record<string, string>;
                const configuredCount = group.items.filter(item => Boolean(rulesObj[item.category])).length;
                return SectionUI.renderOperatorControlRow({
                    title: group.title,
                    description: group.description,
                    icon: getIcon('shield'),
                    enabled: configuredCount > 0,
                    actions: SectionUI.icons.arrowRight,
                    className: 'firewall-leak-category-area-row',
                    attrs: `role="button" tabindex="0" data-waf-action="open-leak-protection-page" data-waf-value="${group.id}"`
                });
            }).join('');
    const activeGroupCount = leakMimeGroups.filter(group =>
        (leak.inspect_content_types || []).some(m =>
            group.mimeTypes.some(gm => gm.toLowerCase() === m.toLowerCase())
        )
    ).length;
    const rulesMap = (leak.categories || {}) as Record<string, string>;
    const exceptionCount = Object.keys(rulesMap).length + (leak.custom_patterns || []).length + (leak.allowlist || []).length;
    const advancedSummary = `${activeGroupCount} of ${leakMimeGroups.length} response categories enabled${exceptionCount ? ` · ${exceptionCount} exception${exceptionCount === 1 ? '' : 's'}` : ''}`;

    return `
        <div class="firewall-overview-stack firewall-leak-protection-stack">
            ${leakProtectionPage === '' ? `
            ${SectionUI.renderOperatorSection('Leak protection', `
                <div class="operator-control-list">
                    ${SectionUI.renderOperatorControlRow({
                        title: 'Inspect responses for exposed secrets',
                        description: 'Scan outbound application responses to detect and prevent leakage of API keys, tokens, and credentials.',
                        icon: getIcon('eye'),
                        enabled,
                        actions: `<label class="section-switch" title="${enabled ? 'Disable' : 'Enable'} leak protection"><input type="checkbox" ${enabled ? 'checked' : ''} data-waf-field="leak_protection.enabled" data-waf-value-type="checkbox"><span class="switch-slider"></span></label>`
                    })}
                    ${SectionUI.renderOperatorControlRow({
                        title: 'Response action',
                        description: 'Monitor records findings in analytics; Redact masks detected secrets with [REDACTED]; Block halts response delivery.',
                        icon: getIcon('shield'),
                        enabled: mode !== 'allow',
                        actions: actionSelect('leak_protection.mode', mode, 'Leak protection response action')
                    })}
                </div>
            `, {
                subtitle: 'Control whether sensitive response content is monitored, redacted, or blocked.'
            })}

            ${SectionUI.renderOperatorSection('Inspection coverage', `
                <div class="operator-control-list">
                    ${SectionUI.renderOperatorControlRow({
                        title: 'Maximum response size',
                        description: 'Maximum response payload size scanned for sensitive data leakage. Response bytes exceeding this threshold bypass scanning (up to 64 MiB).',
                        icon: getIcon('fileText'),
                        enabled: true,
                        actions: `<label class="operator-number"><input type="number" min="0.5" max="64" step="0.5" value="${formatWafMebibytes(maxBodySize)}" inputmode="decimal" aria-label="Maximum response size for leak inspection in MiB" data-waf-field="leak_protection.max_body_size" data-waf-value-type="number" data-waf-value-scale="1048576"><span>MiB</span></label>`
                    })}
                    ${SectionUI.renderOperatorControlRow({
                        title: 'Advanced settings',
                        description: advancedSummary,
                        icon: getIcon('sliders'),
                        enabled: exceptionCount > 0,
                        actions: SectionUI.icons.arrowRight,
                        className: 'firewall-leak-area-row',
                        attrs: 'role="button" tabindex="0" data-waf-action="open-leak-protection-page" data-waf-value="advanced"'
                    })}
                </div>
            `, {
                subtitle: 'Eligible text responses are inspected. Encoded, binary, and oversized responses are skipped or partially covered.'
            })}
            ` : ''}

            ${leakProtectionPage !== '' ? `
                <header class="firewall-leak-page-header">
                    ${SectionUI.renderOperatorBackButton({
                        label: isAdvancedChildPage ? 'Back to Advanced settings' : 'Back to Leak Protection',
                        attrs: isAdvancedChildPage ? 'data-waf-action="back-leak-protection-page"' : 'data-waf-action="close-leak-protection-page"',
                        className: 'firewall-leak-page-back'
                    })}
                </header>
                ${selectedCategory
                    ? SectionUI.renderOperatorSection(selectedCategory.title, renderCategoryRules(selectedCategory), {
                        subtitle: 'Choose the response for each detection category.'
                    })
                    : leakProtectionPage === 'custom_detectors'
                        ? SectionUI.renderOperatorSection('Custom detectors', customDetectorContent, {
                            subtitle: 'Add narrowly scoped detectors when the built-in categories are not enough.'
                        })
                        : leakProtectionPage === 'allowlist'
                            ? SectionUI.renderOperatorSection('Allowlist exceptions', allowlistContent, {
                                subtitle: 'Suppress only known-safe findings with a bounded exception.'
                            })
                    : SectionUI.renderOperatorSection('Advanced settings', `
                    ${renderMimeGroupCards()}
                    ${mode === 'redact' || defaultAction === 'redact' ? `
                        <div class="operator-control-list mt-16">
                            ${SectionUI.renderOperatorControlRow({
                                title: 'Replace detected values',
                                description: 'When a redaction action applies, replace each detected value with [REDACTED] before delivery.',
                                icon: getIcon('eye'),
                                enabled: leak.redaction_enabled === true,
                                actions: `<label class="section-switch" title="${leak.redaction_enabled === true ? 'Disable' : 'Enable'} response redaction"><input type="checkbox" ${leak.redaction_enabled === true ? 'checked' : ''} data-waf-field="leak_protection.redaction_enabled" data-waf-value-type="checkbox"><span class="switch-slider"></span></label>`
                            })}
                        </div>` : ''}
                    ${mode === 'block' || defaultAction === 'block' ? `
                        <div class="firewall-leak-advanced-grid firewall-leak-block-settings">
                            <label class="bot-overview-field"><span>Block response status</span><label class="operator-number"><input type="number" min="400" max="599" step="1" value="${Math.min(599, Math.max(400, Number(leak.block_status_code || 403)))}" aria-label="Leak protection block response status" data-waf-field="leak_protection.block_status_code" data-waf-value-type="number"><span>HTTP</span></label></label>
                            <label class="bot-overview-field"><span>Blocked response body</span><textarea rows="3" class="section-input" aria-label="Leak protection blocked response body" data-waf-field="leak_protection.replacement_body">${escapeWafHtml(String(leak.replacement_body || ''))}</textarea><small>Keep the message free of implementation details.</small></label>
                        </div>` : ''}
                    <div class="firewall-leak-subhead">
                        <h4>Detection category exceptions</h4>
                        <p>Choose specific responses for individual secret classifications.</p>
                    </div>
                    <div class="operator-control-list firewall-leak-exception-groups">
                        ${categoryExceptions}
                    </div>
                    <div class="operator-control-list mt-16">
                        ${SectionUI.renderOperatorControlRow({
                            title: 'Custom detectors',
                            description: `${(leak.custom_patterns || []).length} configured`,
                            icon: getIcon('activity'),
                            enabled: (leak.custom_patterns || []).length > 0,
                            actions: SectionUI.icons.arrowRight,
                            className: 'firewall-leak-category-area-row',
                            attrs: 'role="button" tabindex="0" data-waf-action="open-leak-protection-page" data-waf-value="custom_detectors"'
                        })}
                        ${SectionUI.renderOperatorControlRow({
                            title: 'Allowlist exceptions',
                            description: `${(leak.allowlist || []).length} configured`,
                            icon: getIcon('eye'),
                            enabled: (leak.allowlist || []).length > 0,
                            actions: SectionUI.icons.arrowRight,
                            className: 'firewall-leak-category-area-row',
                            attrs: 'role="button" tabindex="0" data-waf-action="open-leak-protection-page" data-waf-value="allowlist"'
                        })}
                    </div>
                `, {
                    subtitle: 'Response types and targeted exceptions.'
                })}
            ` : ''}
        </div>
        ${SectionUI.renderSaveButton('WAFConfig')}
    `;
}
