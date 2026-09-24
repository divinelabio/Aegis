/**
 * HTTP Security - Upload Security Controls
 * Primary upload limits, validation policies, deep binary inspection, and archive guards.
 */
import { SectionUI } from '../ui-components.js';
import { renderNumberField, renderToggleField } from './render-body-guard.js';

export function bytesToMb(value: unknown, fallback: number): number {
    const numeric = Number(value || fallback);
    if (!Number.isFinite(numeric) || numeric <= 0)
        return Math.max(1, Math.round(fallback / (1024 * 1024)));
    return Math.max(1, Math.round(numeric / (1024 * 1024)));
}

export function renderUploadSizeField(label: string, path: string, value: unknown, fallback: number): string {
    return `<label class="bot-overview-field"><span>${label}</span><div class="httpsec-unit-input"><input type="number" min="1" step="1" value="${bytesToMb(value, fallback)}" class="section-input text-mono" data-httpsec-path="${path}" data-httpsec-value-type="bytes-mb"><span>MB</span></div></label>`;
}

export function renderSelectField(label: string, path: string, value: unknown, options: Array<string | { value: string; label: string }>): string {
    return `<label class="bot-overview-field"><span>${label}</span><select data-httpsec-path="${path}">${options.map(option => {
        const optionValue = typeof option === 'string' ? option : option.value;
        const optionLabel = typeof option === 'string' ? option : option.label;
        return `<option value="${optionValue}" ${value === optionValue ? 'selected' : ''}>${optionLabel}</option>`;
    }).join('')}</select></label>`;
}

export function renderUploadPrimaryControls(upload: Record<string, any>): string {
    return `
        <div class="httpsec-upload-primary-grid">
            ${renderSelectField('Upload action', 'upload_protection.mode', upload.mode || 'detect', [
                { value: 'detect', label: 'Detect' },
                { value: 'block', label: 'Block' },
                { value: 'allow', label: 'Allow' }
            ])}
            ${renderNumberField('Files per request', 'upload_protection.max_files', upload.max_files || 20)}
            ${renderUploadSizeField('Maximum file size', 'upload_protection.max_file_size', upload.max_file_size, 10485760)}
            ${renderUploadSizeField('Total request size', 'upload_protection.max_total_upload_size', upload.max_total_upload_size, 52428800)}
            ${renderNumberField('Filename length', 'upload_protection.max_filename_length', upload.max_filename_length || 180)}
            ${renderSelectField('MIME handling', 'upload_protection.mime_policy', upload.mime_policy || 'validate', [
                { value: 'validate', label: 'Validate' },
                { value: 'allow', label: 'Allow' }
            ])}
        </div>`;
}

export function renderContentSignatureCard(
    title: string,
    desc: string,
    path: string,
    checked: boolean
): string {
    return SectionUI.renderOperatorControlRow({
        title,
        description: desc,
        enabled: checked,
        actions: `<label class="section-switch" title="${checked ? 'Disable' : 'Enable'} ${title}">
            <input type="checkbox" ${checked ? 'checked' : ''} data-httpsec-path="${path}" data-httpsec-value-type="checkbox">
            <span class="switch-slider"></span>
        </label>`,
        className: 'httpsec-signature-card'
    });
}

export function renderUploadAdvancedControls(
    upload: Record<string, any>,
    content: Record<string, any>,
    archive: Record<string, any>,
    _quarantine?: Record<string, any>
): string {
    return `
        <div class="httpsec-upload-advanced-grid">
            <div class="httpsec-upload-advanced-group">
                <div class="httpsec-upload-signatures-grid">
                    ${renderContentSignatureCard(
                        'Executable Magic Bytes',
                        'Validates binary magic bytes to block disguised Windows PE, Linux ELF, and Mac Mach-O binaries masked as images or documents.',
                        'upload_protection.content_rules.detect_executable_bytes',
                        content.detect_executable_bytes !== false
                    )}
                    ${renderContentSignatureCard(
                        'Server Code &amp; Web Shells',
                        'Scans uploaded assets for embedded PHP, JSP, ASPX, Python, and shell script syntax disguised inside media files.',
                        'upload_protection.content_rules.detect_server_side_code',
                        content.detect_server_side_code !== false
                    )}
                    ${renderContentSignatureCard(
                        'Malicious Macro Documents',
                        'Inspects OLE2 and OOXML containers for embedded VBA macros, auto-exec triggers, and suspicious automation.',
                        'upload_protection.content_rules.detect_macro_documents',
                        content.detect_macro_documents !== false
                    )}
                    ${renderContentSignatureCard(
                        'Scriptable SVG &amp; Polyglots',
                        'Inspects SVG vector images for embedded &lt;script&gt; tags, onload event handlers, CDATA vectors, and XSS payloads.',
                        'upload_protection.content_rules.detect_svg_script',
                        content.detect_svg_script !== false
                    )}
                    ${renderContentSignatureCard(
                        'Disguised HTML &amp; Phishing',
                        'Prevents HTML and client script markup from being uploaded under non-HTML extensions to abuse domain trust.',
                        'upload_protection.content_rules.detect_html_upload',
                        content.detect_html_upload !== false
                    )}
                    ${renderContentSignatureCard(
                        'Active PDF &amp; Embedded Exploits',
                        'Inspects PDF documents for embedded /JavaScript, /Launch actions, /OpenAction triggers, and hidden binary droppers.',
                        'upload_protection.content_rules.detect_pdf_exploits',
                        content.detect_pdf_exploits !== false
                    )}
                    ${renderContentSignatureCard(
                        'High-Entropy &amp; Packed Payloads',
                        'Analyzes Shannon entropy to detect UPX-packed binaries, encrypted shellcode stubs, and obfuscated ransomware loaders.',
                        'upload_protection.content_rules.detect_high_entropy',
                        content.detect_high_entropy !== false
                    )}
                </div>
            </div>
            <div class="httpsec-upload-advanced-group">
                <div class="httpsec-upload-advanced-group-head">
                    <strong>Deep inspection buffer</strong>
                </div>
                <div class="httpsec-upload-field-grid">
                    ${renderNumberField('Inspect First Bytes', 'upload_protection.inspect_first_bytes', upload.inspect_first_bytes || 8192)}
                </div>
            </div>
            <div class="httpsec-upload-advanced-group">
                <div class="httpsec-upload-advanced-group-head">
                    <strong>Archive &amp; zip-bomb guard</strong>
                </div>
                <div class="httpsec-upload-field-grid">
                    ${renderToggleField('Archive Inspection', 'upload_protection.archive_policy.enabled', archive.enabled !== false)}
                    ${renderNumberField('Compression Ratio', 'upload_protection.archive_policy.max_compression_ratio', archive.max_compression_ratio || 100)}
                    ${renderUploadSizeField('Max Expanded Size', 'upload_protection.archive_policy.max_expanded_size', archive.max_expanded_size, 104857600)}
                    ${renderNumberField('Max Archive Entries', 'upload_protection.archive_policy.max_entries', archive.max_entries || 512)}
                    ${renderToggleField('Nested Archives', 'upload_protection.archive_policy.block_nested_archives', archive.block_nested_archives !== false)}
                    ${renderToggleField('Encrypted Archives', 'upload_protection.archive_policy.block_encrypted_archives', archive.block_encrypted_archives !== false)}
                    ${renderToggleField('Path Traversal (ZipSlip)', 'upload_protection.archive_policy.block_traversal_paths', archive.block_traversal_paths !== false)}
                </div>
            </div>
        </div>`;
}
