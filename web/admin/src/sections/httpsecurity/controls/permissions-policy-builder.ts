import { escapeHTTPSecurityHtml } from '../../httpsecurity-runtime-helpers.js';
import { HTTPSEC_PERMISSION_FEATURES } from '../constants.js';
import { applyHTTPSecurityPermissionsPreset, parseHTTPSecurityPermissionsPolicy } from '../validation.js';

function encodeValue(value: unknown): string {
    return encodeURIComponent(String(value || ''));
}

export function renderPermissionsPolicyBuilder(value: unknown): string {
    const currentValue = String(value || '').trim();
    const map = parseHTTPSecurityPermissionsPolicy(value);
    const activePreset = ['baseline', 'strict', 'compatibility'].find((preset) =>
        currentValue === applyHTTPSecurityPermissionsPreset(preset)
    ) || '';
    const presets = [
        { id: 'baseline', title: 'Baseline', description: 'Privacy-first production defaults.' },
        { id: 'strict', title: 'Strict', description: 'Deny every common browser capability.' },
        { id: 'compatibility', title: 'Compatibility', description: 'Allow selected same-origin features.' }
    ];
    return `
        <div class="httpsec-builder httpsec-permissions-builder">
            <div class="httpsec-builder-head">
                <span class="httpsec-builder-head-copy">
                    <strong>Permissions Policy</strong>
                    <small>Control access to sensitive browser capabilities.</small>
                </span>
                <span class="httpsec-builder-count">${Object.keys(map).length || 0} features</span>
            </div>
            <div class="httpsec-builder-presets" role="group" aria-label="Permissions Policy presets">
                ${presets.map((preset) => {
                    const active = activePreset === preset.id;
                    return `<button type="button" class="httpsec-builder-preset ${active ? 'is-active' : ''}" data-httpsec-action="apply-permissions-policy-preset" data-httpsec-value="${preset.id}" aria-pressed="${active}">
                        <span><strong>${preset.title}</strong><small>${preset.description}</small></span>
                        <i aria-hidden="true"></i>
                    </button>`;
                }).join('')}
            </div>
            <div class="httpsec-permissions-grid">
                ${HTTPSEC_PERMISSION_FEATURES.map((feature) => {
                    const current = map[feature] || '()';
                    const label = feature.split('-').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(' ');
                    return `<label class="httpsec-permission-field"><span><strong>${escapeHTTPSecurityHtml(label)}</strong><small>${current === '()' ? 'Denied' : current === '(self)' ? 'Same origin' : 'Any origin'}</small></span><select data-httpsec-action="set-permissions-policy-feature" data-httpsec-value="${encodeValue(feature)}" aria-label="${escapeHTTPSecurityHtml(label)} permission">
                        <option value="()" ${current === '()' ? 'selected' : ''}>None</option>
                        <option value="(self)" ${current === '(self)' ? 'selected' : ''}>Self</option>
                        <option value="*" ${current === '*' ? 'selected' : ''}>All</option>
                    </select></label>`;
                }).join('')}
            </div>
        </div>
    `;
}
