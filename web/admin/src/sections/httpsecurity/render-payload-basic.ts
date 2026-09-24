/**
 * HTTP Security - Payload Protection
 * Standard request body size ceilings, enforcement modes, and presets.
 */
import { SectionUI } from '../ui-components.js';
import { HTTPSEC_PAYLOAD_INSPECTION_PROFILES } from './constants.js';

export function httpsecSizeToMb(value: unknown): number {
    const raw = String(value || '10MB').trim().toUpperCase();
    const numeric = Number.parseInt(raw, 10);
    if (!Number.isFinite(numeric) || numeric <= 0)
        return 10;
    return raw.includes('GB') ? numeric * 1024 : numeric;
}

export function encodeHTTPSecurityValue(value: unknown): string {
    return encodeURIComponent(String(value));
}

export function renderPayloadPresetButton(active: boolean, title: string, attrs: string): string {
    return `
        <button type="button" role="radio" aria-checked="${active ? 'true' : 'false'}" class="httpsec-request-preset httpsec-payload-choice-preset ${active ? 'is-active' : ''}" ${attrs}>
            ${title}
        </button>`;
}

export function renderBasicBodyCeiling(view: Record<string, any>, limit: Record<string, any>, currentSize: string, currentSizeMb: number): string {
    const sizePresets = [
        { label: '1 MB', value: '1MB' },
        { label: '5 MB', value: '5MB' },
        { label: '10 MB', value: '10MB' },
        { label: '25 MB', value: '25MB' },
        { label: '50 MB', value: '50MB' },
        { label: '100 MB', value: '100MB' }
    ];

    return `
        <div class="httpsec-payload-limit-editor">
            <div class="httpsec-payload-limit-status">
                <span class="operator-control-icon">${view.icons.compress}</span>
                <div><strong>Request body limit</strong><span>${limit.enabled === true ? 'Enforced before inspection' : 'Not enforced'}</span></div>
                <label class="section-switch"><input type="checkbox" ${limit.enabled === true ? 'checked' : ''} data-httpsec-path="upload_limit.enabled" data-httpsec-value-type="checkbox" data-httpsec-render="true"><span class="switch-slider"></span></label>
            </div>
            <div class="httpsec-payload-limit-controls">
                <label class="bot-overview-field"><span>Maximum size</span><div class="httpsec-unit-input"><input type="number" min="1" step="1" value="${currentSizeMb}" class="section-input text-center text-mono font-600" data-httpsec-path="upload_limit.max_body_size" data-httpsec-value-type="size-mb" data-httpsec-render="true"><span>MB</span></div></label>
                <div class="httpsec-payload-limit-presets"><span>Common limits</span><div class="httpsec-request-presets" aria-label="Request body size presets">${sizePresets.map((p: any) => `<button type="button" data-httpsec-action="set-field" data-httpsec-path="upload_limit.max_body_size" data-httpsec-value="${encodeHTTPSecurityValue(p.value)}" data-httpsec-render="true" class="httpsec-request-preset ${currentSize === p.value ? 'is-active' : ''}">${p.label}</button>`).join('')}</div></div>
            </div>
        </div>`;
}

export function renderPayloadEnforcementProfiles(
    view: Record<string, any>,
    bodyProfile: Record<string, any>,
    inspectionProfile: Record<string, any>,
    customInspectionSelected: boolean,
    canOpenPayloadExpert: boolean
): string {
    return `
        <div class="operator-control-list httpsec-payload-choice-list">
            ${SectionUI.renderOperatorControlRow({
                title: 'Enforcement mode',
                description: 'Choose whether detected payload anomalies are logged for review (Monitor) or terminated (Block).',
                icon: view.icons.activity,
                className: 'httpsec-payload-choice-row',
                actions: `<div class="httpsec-request-presets httpsec-payload-choice-presets httpsec-payload-mode-presets" role="radiogroup" aria-label="Payload enforcement mode">
                    ${renderPayloadPresetButton(bodyProfile.id !== 'block_obvious', 'Monitor', 'data-httpsec-action="apply-payload-profile" data-httpsec-value="monitor"')}
                    ${renderPayloadPresetButton(bodyProfile.id === 'block_obvious', 'Block', 'data-httpsec-action="apply-payload-profile" data-httpsec-value="block_obvious"')}
                </div>`
            })}
            ${SectionUI.renderOperatorControlRow({
                title: 'Inspection profile',
                description: 'Select depth and parser complexity thresholds (Balanced: production standard; Strict: rigid depth checks).',
                icon: view.icons.sliders,
                className: 'httpsec-payload-choice-row',
                actions: `<div class="httpsec-request-presets httpsec-payload-choice-presets httpsec-payload-profile-presets" role="radiogroup" aria-label="Payload inspection profile">
                    ${renderPayloadPresetButton(!customInspectionSelected && inspectionProfile.id === 'relaxed', HTTPSEC_PAYLOAD_INSPECTION_PROFILES.relaxed.label, 'data-httpsec-action="apply-payload-inspection-profile" data-httpsec-value="relaxed"')}
                    ${renderPayloadPresetButton(!customInspectionSelected && inspectionProfile.id === 'balanced', HTTPSEC_PAYLOAD_INSPECTION_PROFILES.balanced.label, 'data-httpsec-action="apply-payload-inspection-profile" data-httpsec-value="balanced"')}
                    ${renderPayloadPresetButton(!customInspectionSelected && inspectionProfile.id === 'strict', HTTPSEC_PAYLOAD_INSPECTION_PROFILES.strict.label, 'data-httpsec-action="apply-payload-inspection-profile" data-httpsec-value="strict"')}
                    ${canOpenPayloadExpert ? renderPayloadPresetButton(customInspectionSelected, HTTPSEC_PAYLOAD_INSPECTION_PROFILES.custom.label, 'data-httpsec-action="open-payload-expert"') : ''}
                </div>`
            })}
        </div>`;
}
