/**
 * WAF Managed Rules (Community)
 * OWASP ModSecurity Core Rule Set (CRS) inspection profiles and file rules.
 */
import { SectionUI } from '../ui-components.js';
import { escapeWafHtml } from '../waf-runtime-helpers.js';
export function formatManagedRuleName(fileName) {
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
}
export function managedRuleDescription(file) {
    const friendlyName = formatManagedRuleName(file.name);
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
}
export function managedRuleStatus(file) {
    if (file.enabled === false)
        return { label: 'Disabled', tone: 'muted' };
    const status = String(file.status || '').toLowerCase();
    if (status === 'error')
        return { label: 'Error', tone: 'danger' };
    if (status === 'warning')
        return { label: 'Needs review', tone: 'warning' };
    return { label: 'Enabled', tone: 'success' };
}
export function managedRulePolicyGroup(file) {
    const name = formatManagedRuleName(file.name).toLowerCase();
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
}
export function renderManagedPolicyRuleRow(file) {
    const isEnabled = file.enabled !== false;
    const title = formatManagedRuleName(file.name);
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
                <div class="section-row-sub section-managed-rule-description">${escapeWafHtml(managedRuleDescription(file))}</div>
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
}
export function renderManagedPolicyGroup(group) {
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
                            ${group.files.map(file => renderManagedPolicyRuleRow(file)).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        </details>
    `;
}
export function renderManagedRulesFolder(crsRules, reloadFailed) {
    const files = crsRules;
    const policyGroups = Array.from(files.reduce((groups, file) => {
        const policyGroup = managedRulePolicyGroup(file);
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
            ${reloadFailed ? `<div class="section-warning-box section-managed-warning"><div class="section-warning-icon">${SectionUI.icons.alertTriangle}</div><div><div class="section-warning-title">The latest protection update was not applied</div><div class="section-warning-text">Your previous managed rule settings remain active. Review the configuration and try again.</div></div></div>` : ''}

            ${files.length === 0 ? `
                <div class="section-card-flush section-managed-empty">
                    <div class="section-folder-empty">
                        <div class="section-folder-empty-icon">${SectionUI.icons.file}</div>
                        No managed protections found
                    </div>
                </div>
            ` : `
            <div class="section-managed-policy-list">
                ${policyGroups.map((group) => renderManagedPolicyGroup(group)).join('')}
            </div>`}

            <div class="crs-copyright" style="text-align: center; font-size: 11px; color: var(--text-muted); margin-top: 24px; margin-bottom: 16px;">
                Powered by OWASP ModSecurity Core Rule Set (CRS)
            </div>
        </div>
    `;
}
