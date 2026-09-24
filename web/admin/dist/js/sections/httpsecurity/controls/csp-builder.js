import { escapeHTTPSecurityHtml } from '../../httpsecurity-runtime-helpers.js';
import { HTTPSEC_CSP_DIRECTIVES } from '../constants.js';
import { applyHTTPSecurityCSPPreset, parseHTTPSecurityCSP } from '../validation.js';
function encodeValue(value) {
    return encodeURIComponent(String(value || ''));
}
export function renderCSPBuilder(value) {
    const currentValue = String(value || '').trim();
    const map = parseHTTPSecurityCSP(value);
    const activePreset = ['baseline', 'strict', 'compatibility'].find((preset) => currentValue === applyHTTPSecurityCSPPreset(preset).trim()) || '';
    const warnings = currentValue.includes("'unsafe-inline'") || currentValue.includes("'unsafe-eval'")
        ? '<div class="httpsec-builder-warning">CSP contains unsafe inline or eval sources.</div>'
        : '';
    const presets = [
        { id: 'baseline', title: 'Baseline', description: 'Safe default for most applications.' },
        { id: 'strict', title: 'Strict', description: 'No inline scripts or styles.' },
        { id: 'compatibility', title: 'Compatibility', description: 'Broader legacy-friendly sources.' }
    ];
    return `
        <div class="httpsec-builder httpsec-csp-builder">
            <div class="httpsec-builder-head">
                <span class="httpsec-builder-head-copy">
                    <strong>Content Security Policy</strong>
                    <small>Control which sources browsers may load for this application.</small>
                </span>
                <span class="httpsec-builder-count">${Object.keys(map).length || 0} directives</span>
            </div>
            <div class="httpsec-builder-presets" role="group" aria-label="Content Security Policy presets">
                ${presets.map((preset) => {
        const active = activePreset === preset.id;
        return `<button type="button" class="httpsec-builder-preset ${active ? 'is-active' : ''}" data-httpsec-action="apply-csp-preset" data-httpsec-value="${preset.id}" aria-pressed="${active}">
                        <span><strong>${preset.title}</strong><small>${preset.description}</small></span>
                        <i aria-hidden="true"></i>
                    </button>`;
    }).join('')}
            </div>
            ${warnings}
            <div class="httpsec-csp-directives">
                ${HTTPSEC_CSP_DIRECTIVES.map((directive) => `
                    <div class="httpsec-csp-row">
                        <span class="httpsec-csp-row-label">
                            <strong>${directive}</strong>
                            <small>${(map[directive] || []).length} source${(map[directive] || []).length === 1 ? '' : 's'}</small>
                        </span>
                        <div class="httpsec-csp-row-editor">
                            <div class="httpsec-extension-grid">
                                ${(map[directive] || []).map((source) => `<button class="httpsec-extension-chip" type="button" data-httpsec-action="remove-csp-source" data-httpsec-value="${encodeValue(`${directive}|${source}`)}"><span>${escapeHTTPSecurityHtml(source)}</span><span class="httpsec-extension-remove" aria-hidden="true">&times;</span></button>`).join('') || '<div class="httpsec-empty-note">No sources configured.</div>'}
                            </div>
                            <div class="section-inline-form">
                                <input id="csp-${directive}-source" class="section-input text-mono" placeholder="Add source, for example 'self'" aria-label="Add source to ${directive}">
                                <button type="button" class="btn btn-outline btn-sm" data-httpsec-action="add-csp-source" data-httpsec-value="${encodeValue(directive)}" data-httpsec-input-id="csp-${directive}-source">Add</button>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}
