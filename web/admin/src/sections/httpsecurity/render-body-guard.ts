/**
 * HTTP Security - Request Body Guard
 * Deep parser complexity inspection for JSON, XML, Form, Multipart, Encoding, and GraphQL.
 */
import { SectionUI } from '../ui-components.js';

export function renderNumberField(label: string, path: string, value: unknown): string {
    return `<label class="bot-overview-field"><span>${label}</span><input type="number" value="${Number(value || 0)}" data-httpsec-path="${path}" data-httpsec-value-type="number"></label>`;
}

export function renderToggleField(label: string, path: string, checked: boolean): string {
    return `<label class="bot-overview-field httpsec-toggle-field"><span>${label}</span><span class="section-switch"><input type="checkbox" ${checked ? 'checked' : ''} data-httpsec-path="${path}" data-httpsec-value-type="checkbox"><span class="switch-slider"></span></span></label>`;
}

export function renderGuardPanel(
    title: string,
    basePath: string,
    cfg: Record<string, any>,
    numbers: Array<[string, string, number]>,
    toggles: Array<[string, string]> = []
): string {
    const enabled = cfg.enabled !== false;
    return `
        <section class="operator-control-panel ${enabled ? 'is-active' : ''}">
            ${SectionUI.renderOperatorControlRow({
                title,
                enabled,
                actions: `<label class="section-switch"><input type="checkbox" ${enabled ? 'checked' : ''} data-httpsec-path="${basePath}.enabled" data-httpsec-value-type="checkbox"><span class="switch-slider"></span></label>`,
                className: 'httpsec-control-head'
            })}
            <div class="operator-control-panel-body httpsec-guard-panel-body">
                ${numbers.map(([label, key, fallback]) => renderNumberField(label, `${basePath}.${key}`, cfg[key] || fallback)).join('')}
                ${toggles.map(([label, key]) => renderToggleField(label, `${basePath}.${key}`, cfg[key] === true || cfg[key] === undefined)).join('')}
            </div>
        </section>
    `;
}

export function renderBodyExpertThreshold(body: Record<string, any>): string {
    return `
        <div class="httpsec-payload-expert-threshold">
            ${renderNumberField('Max Findings', 'request_body_guard.max_findings', body.max_findings || 100)}
        </div>`;
}

export function renderBodyExpertGuards(body: Record<string, any>): string {
    return `
        <div class="httpsec-payload-guard-grid mt-12">
            ${renderGuardPanel('JSON', 'request_body_guard.json', body.json || {}, [
                ['Max Depth', 'max_depth', 32],
                ['Max Keys', 'max_keys', 2000],
                ['Max Array Length', 'max_array_length', 1000],
                ['Max String Length', 'max_string_length', 65536]
            ])}
            ${renderGuardPanel('XML', 'request_body_guard.xml', body.xml || {}, [
                ['Max Depth', 'max_depth', 32],
                ['Max Elements', 'max_elements', 5000],
                ['Max Attributes', 'max_attributes', 1000],
                ['Max Text Length', 'max_text_length', 65536]
            ], [
                ['Block DOCTYPE', 'block_doctype'],
                ['Block External Entities', 'block_external_entities']
            ])}
            ${renderGuardPanel('Forms', 'request_body_guard.form', body.form || {}, [
                ['Max Parameters', 'max_parameters', 1000],
                ['Max Name Length', 'max_parameter_name_length', 256],
                ['Max Value Length', 'max_parameter_value_length', 65536]
            ])}
            ${renderGuardPanel('Multipart', 'request_body_guard.multipart', body.multipart || {}, [
                ['Max Parts', 'max_parts', 100],
                ['Max Field Count', 'max_field_count', 80],
                ['Max Name Length', 'max_field_name_length', 256],
                ['Max Value Length', 'max_field_value_length', 65536]
            ])}
            ${renderGuardPanel('Encoding', 'request_body_guard.encoding', body.encoding || {}, [
                ['Decode Passes', 'max_decoding_passes', 2]
            ], [
                ['Reject Invalid UTF-8', 'reject_invalid_utf8'],
                ['Detect Mixed Encoding', 'detect_mixed_encoding']
            ])}
            ${renderGuardPanel('GraphQL', 'request_body_guard.graphql', body.graphql || {}, [
                ['Max Depth', 'max_depth', 12],
                ['Max Aliases', 'max_aliases', 20],
                ['Max Fields', 'max_fields', 250],
                ['Max Fragments', 'max_fragments', 25],
                ['Max Batched Ops', 'max_batched_operations', 5]
            ], [
                ['Block Introspection', 'block_introspection'],
                ['Require Operation Name', 'require_operation_name']
            ])}
        </div>`;
}
