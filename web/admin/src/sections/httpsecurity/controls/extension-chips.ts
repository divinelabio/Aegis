import { escapeHTTPSecurityHtml } from '../../httpsecurity-runtime-helpers.js';
import { HTTPSEC_EXTENSION_GROUPS } from '../constants.js';

export function renderExtensionChips(title: string, path: string, values: unknown[] | null | undefined, _inputId?: string, options: { groups?: boolean; countLabel?: string } = {}): string {
    const rows = Array.isArray(values) ? values : [];
    const countLabel = options.countLabel || 'configured';
    return `
        <div class="httpsec-extension-panel">
            <div class="operator-control-row httpsec-file-policy-summary">
                <div class="operator-control-main">
                    <span class="operator-control-copy">
                        <span class="operator-control-title">${escapeHTTPSecurityHtml(title)}</span>
                        <span class="operator-control-desc">${rows.length} ${escapeHTTPSecurityHtml(countLabel)}</span>
                    </span>
                </div>
                <div class="operator-control-actions">
                    <button type="button" class="btn btn-outline btn-sm" data-httpsec-action="open-file-type-policy" data-httpsec-path="${path}" data-httpsec-title="${escapeHTTPSecurityHtml(title)}" data-httpsec-count-label="${escapeHTTPSecurityHtml(countLabel)}">Manage types</button>
                </div>
            </div>
        </div>
    `;
}

type FileTypePolicyModalOptions = {
    title: string;
    path: string;
    values: unknown[];
    countLabel?: string;
    icon: string;
};

function catalogEntries(values: unknown[]): Array<{ extension: string; category: string }> {
    const known = new Map<string, string>();
    Object.values(HTTPSEC_EXTENSION_GROUPS).forEach((group) => {
        group.values.forEach((extension) => {
            if (!known.has(extension)) known.set(extension, group.label);
        });
    });
    (Array.isArray(values) ? values : []).forEach((value) => {
        const extension = String(value || '').trim().toLowerCase();
        if (extension && !known.has(extension)) known.set(extension, 'Custom');
    });
    return [...known.entries()].map(([extension, category]) => ({ extension, category }));
}

function extensionMark(extension: string): string {
    return extension.replace(/^\./, '').slice(0, 4).toUpperCase() || 'FILE';
}

export function renderFileTypePolicyModal(options: FileTypePolicyModalOptions): string {
    const selected = new Set((Array.isArray(options.values) ? options.values : []).map(value => String(value || '').trim().toLowerCase()).filter(Boolean));
    const catalog = catalogEntries(options.values);
    const selectedCount = catalog.filter(item => selected.has(item.extension)).length;
    const inputId = 'httpsec-file-type-custom-input';
    return `
        <div class="section-modal-overlay section-modal-overlay-padded section-modal-overlay-soft open is-visible">
            <div class="section-modal-panel section-modal-panel-wide section-goodbot-panel httpsec-filetype-modal">
                <div class="section-modal-head section-goodbot-head">
                    <div class="section-goodbot-head-main">
                        <div class="section-goodbot-head-icon">${options.icon}</div>
                        <div>
                            <h3 class="section-modal-title">Manage ${escapeHTTPSecurityHtml(options.title)}</h3>
                            <div class="section-modal-sub">Select the file types this policy should apply to.</div>
                        </div>
                    </div>
                    <div class="section-goodbot-head-stats"><span>${selectedCount} ${escapeHTTPSecurityHtml(options.countLabel || 'configured')}</span><span>${catalog.length} available</span></div>
                    <button type="button" class="section-modal-close section-goodbot-close" data-httpsec-action="close-file-type-policy" aria-label="Close file type policy">&times;</button>
                </div>
                <div class="section-modal-body section-goodbot-body">
                    <div class="section-goodbot-toolbar httpsec-filetype-toolbar">
                        <div class="httpsec-filetype-custom-input">
                            <label class="section-form-label" for="${inputId}">Custom file types</label>
                            <input type="text" id="${inputId}" placeholder=".custom, .internal" class="section-input text-mono" data-httpsec-enter-action="add-tag-from-input" data-httpsec-path="${options.path}" data-httpsec-render="true">
                            <p class="section-form-hint">Separate entries with commas, then press Enter.</p>
                        </div>
                        <div class="section-goodbot-toolbar-meta">
                            <div class="section-goodbot-toolbar-count">${selectedCount} ${escapeHTTPSecurityHtml(options.countLabel || 'configured')} / ${catalog.length} available</div>
                            <div class="section-goodbot-toolbar-note">Toggle a file type to include or remove it from this policy.</div>
                        </div>
                    </div>
                    <div class="section-goodbot-grid httpsec-filetype-grid">
                        ${catalog.map(({ extension, category }) => {
        const active = selected.has(extension);
        return `<label class="section-goodbot-card ${active ? 'active' : ''}">
                            <div class="section-goodbot-icon httpsec-filetype-icon"><span>${extensionMark(extension)}</span></div>
                            <div class="section-goodbot-meta"><div class="section-goodbot-name text-mono">${escapeHTTPSecurityHtml(extension)}</div><div class="httpsec-filetype-category">${escapeHTTPSecurityHtml(category)}</div></div>
                            <div class="section-switch"><input type="checkbox" value="${escapeHTTPSecurityHtml(extension)}" ${active ? 'checked' : ''} data-httpsec-file-type-toggle data-httpsec-file-type-path="${options.path}"><span class="switch-slider"></span></div>
                        </label>`;
    }).join('')}
                    </div>
                </div>
                <div class="section-modal-footer section-goodbot-footer"><button type="button" class="btn btn-outline" data-httpsec-action="close-file-type-policy">Done</button></div>
            </div>
        </div>
    `;
}
