import { escapeHTTPSecurityHtml } from '../../httpsecurity-runtime-helpers.js';

function encodeValue(value: unknown): string {
    return encodeURIComponent(String(value || ''));
}

export function renderHeaderMapBuilder(title: string, path: string, map: Record<string, unknown> | null | undefined, inputPrefix: string): string {
    const rows = Object.entries(map || {});
    const nameInput = `${inputPrefix}-name`;
    const valueInput = `${inputPrefix}-value`;
    return `
        <div class="httpsec-builder httpsec-header-builder">
            <div class="httpsec-builder-head"><strong>${escapeHTTPSecurityHtml(title)}</strong><span>${rows.length} configured</span></div>
            <div class="httpsec-header-builder-rows">
                ${rows.map(([name, value]) => `
                    <div class="httpsec-header-row">
                        <input class="section-input text-mono" value="${escapeHTTPSecurityHtml(name)}" data-httpsec-action="update-header-row" data-httpsec-header-path="${path}" data-httpsec-old-name="${encodeValue(name)}" data-httpsec-header-field="name">
                        <input class="section-input text-mono" value="${escapeHTTPSecurityHtml(String(value ?? ''))}" data-httpsec-action="update-header-row" data-httpsec-header-path="${path}" data-httpsec-old-name="${encodeValue(name)}" data-httpsec-header-field="value">
                        <button type="button" class="btn btn-outline btn-sm" data-httpsec-action="remove-header-row" data-httpsec-path="${path}" data-httpsec-value="${encodeValue(name)}">Remove</button>
                    </div>
                `).join('') || '<div class="httpsec-empty-note">No headers added.</div>'}
            </div>
            <div class="httpsec-header-row httpsec-header-row-add">
                <input id="${nameInput}" class="section-input text-mono" placeholder="Header-Name">
                <input id="${valueInput}" class="section-input text-mono" placeholder="Header value">
                <button type="button" class="btn btn-outline btn-sm" data-httpsec-action="add-header-row" data-httpsec-path="${path}" data-httpsec-name-input-id="${nameInput}" data-httpsec-value-input-id="${valueInput}">Add</button>
            </div>
        </div>
    `;
}

export function renderHeaderRemoveBuilder(title: string, path: string, values: unknown[] | null | undefined, inputId: string): string {
    const rows = Array.isArray(values) ? values : [];
    return `
        <div class="httpsec-builder httpsec-header-remove-builder">
            <div class="httpsec-builder-head"><strong>${escapeHTTPSecurityHtml(title)}</strong><span>${rows.length} configured</span></div>
            <div class="httpsec-extension-grid">
                ${rows.map((header) => `<button class="httpsec-extension-chip" type="button" data-httpsec-action="remove-tag" data-httpsec-path="${path}" data-httpsec-value="${encodeValue(header)}"><span>${escapeHTTPSecurityHtml(header)}</span><span class="httpsec-extension-remove" aria-hidden="true">&times;</span></button>`).join('') || '<div class="httpsec-empty-note">No headers removed.</div>'}
            </div>
            <div class="section-inline-form">
                <input type="text" id="${inputId}" placeholder="Header-Name" class="section-input text-mono" data-httpsec-enter-action="add-tag-from-input" data-httpsec-path="${path}">
      <button type="button" class="btn btn-outline btn-sm" data-httpsec-action="add-tag-from-input" data-httpsec-path="${path}" data-httpsec-input-id="${inputId}">Add</button>
            </div>
        </div>
    `;
}
