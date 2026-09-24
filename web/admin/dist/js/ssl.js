/**
 * SSL certificates page
 * Source of truth: web/admin/src/ssl.ts
 * Runtime output: web/admin/dist/js/ssl.js
 */
import { api } from './api.js';
import * as AdminDOM from './core/dom.js';
import * as AdminEvents from './core/events.js';
import { SectionUI } from './sections/ui-components.js';
import { notify } from './core/notify.js';
const sslState = {
    certificates: [],
    tlsConfig: {
        enabled: false,
        auto: false,
        domains: [],
        email: ''
    }
};
let sslBindingsInitialized = false;
let sslConfigDirty = false;
let sslSaveInFlight = false;
function encodeSslValue(value) {
    return encodeURIComponent(value);
}
function decodeSslValue(value) {
    return value ? decodeURIComponent(value) : '';
}
function escapeHTML(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
export async function loadSSLPage() {
    ensureSSLBindings();
    const container = AdminDOM.getById('ssl-container');
    if (!container)
        return;
    container.innerHTML = SectionUI.renderLoading('Loading SSL configuration...');
    try {
        const [certsRes, configRes] = await Promise.all([
            api.get('certificates'),
            api.get('certificates/config')
        ]);
        if (certsRes === null || configRes === null) {
            throw new Error('One or more SSL endpoints did not return data');
        }
        sslState.certificates = certsRes;
        sslState.tlsConfig = configRes;
        sslConfigDirty = false;
        renderSSLPage(container);
    }
    catch (error) {
        console.error('Failed to load SSL data', error);
        sslShowToast('Failed to load SSL settings', 'error');
        container.innerHTML = SectionUI.renderError('Failed to load SSL configuration', 'loadSSLPage()');
    }
}
function renderSSLPage(container) {
    if (!sslState.tlsConfig.domains)
        sslState.tlsConfig.domains = [];
    const content = `
    <div class="ssl-operator-stack">
      ${SectionUI.renderOperatorSection('HTTPS', `
        <div class="operator-control-row">
          <div class="operator-control-main">
            <span class="operator-control-icon" aria-hidden="true">${sslIcon('certificate')}</span>
            <span class="operator-control-copy">
              <strong style="display: inline-flex; align-items: center;">
                Enable HTTPS
                ${SectionUI.renderInfoTooltip('A restart is required after changing this setting.')}
              </strong>
            </span>
          </div>
          <div class="operator-control-actions">
            ${SectionUI.renderSwitch({
        id: 'tls-enabled-toggle',
        checked: sslState.tlsConfig.enabled,
        className: 'round'
    })}
          </div>
        </div>
      `, {
        subtitle: 'Secure connections to your public sites with HTTPS.',
        className: 'ssl-catalog-section'
    })}
      <div class="ssl-configuration-grid">
      ${SectionUI.renderOperatorSection('Auto-TLS', `
        <div class="ssl-auto-settings">
          <div class="operator-control-row ssl-auto-toggle-row">
            <div class="operator-control-main">
              <span class="operator-control-icon" aria-hidden="true">${sslIcon('automation')}</span>
              <span class="operator-control-copy">
                <strong style="display: inline-flex; align-items: center;">
                  Automatic certificate management
                  ${SectionUI.renderInfoTooltip('Automatically issue and renew TLS certificates for public hostnames via ACME, or use manual certificates.')}
                </strong>
              </span>
            </div>
            <div class="operator-control-actions">
              ${SectionUI.renderSwitch({
        id: 'auto-tls-toggle',
        checked: sslState.tlsConfig.auto,
        className: 'round'
    })}
            </div>
          </div>
          <div id="auto-tls-settings" class="ssl-auto-dependent transition-opacity ${sslState.tlsConfig.auto ? '' : 'is-disabled'}">
            ${renderDomainManager()}
            <div class="operator-control-row ssl-contact-row">
              <div class="operator-control-main">
                <span class="operator-control-copy">
                  <span class="operator-control-title" style="display: inline-flex; align-items: center;">
                    Contact email
                    ${SectionUI.renderInfoTooltip('Used for certificate expiration and security notices.')}
                  </span>
                </span>
              </div>
              <div class="operator-control-actions ssl-contact-control">
                <input type="email" id="acme-email" class="settings-input ssl-contact-input" value="${escapeHTML(sslState.tlsConfig.email || '')}" placeholder="admin@example.com" aria-label="ACME contact email">
              </div>
            </div>
          </div>
        </div>
      `, {
        subtitle: 'Automatically issue and renew certificates for public hostnames.',
        className: 'ssl-catalog-section ssl-auto-section'
    })}

      ${SectionUI.renderOperatorSection('Certificates', `
        <div class="ssl-certificate-table-surface">${renderCertificatesList()}</div>
      `, {
        subtitle: 'View and manage the certificates available to Aegis.',
        actions: `<button type="button" class="btn btn-outline btn-sm" data-ssl-action="show-upload-cert-modal">${sslIcon('upload')}Upload</button>`,
        className: 'ssl-catalog-section ssl-inventory-section'
    })}
      </div>
      ${SectionUI.renderSaveActionBar({
        actionAttr: 'data-ssl-action',
        resetAction: 'reset-tls-config',
        saveAction: 'save-tls-config',
        resetLabel: 'Reset',
        saveLabel: 'Save Changes'
    })}
    </div>
  `;
    container.innerHTML = SectionUI.renderOperatorFrame({
        title: 'SSL Certificates',
        kicker: 'Network',
        subtitle: 'Issue, renew, and monitor TLS certificates used by public listeners.',
        content,
        className: 'ssl-operator-frame'
    });
    if (sslConfigDirty) {
        SectionUI.markSaveActionBarDirty('data-ssl-action');
    }
}
function renderDomainManager() {
    const domains = sslState.tlsConfig.domains || [];
    const rows = domains.map(domain => {
        const encodedDomain = encodeSslValue(domain);
        const actions = SectionUI.renderActionMenu({
            id: `ssl-domain-actions-${encodedDomain}`,
            label: 'More',
            ariaLabel: `Actions for ${domain}`,
            items: [
                { label: 'Remove domain', attrs: `data-ssl-action="remove-domain" data-domain="${encodedDomain}"`, tone: 'danger' }
            ],
            className: 'ssl-domain-row-menu'
        });
        return [
            `<div class="ssl-domain-identity">
        <span class="ssl-domain-icon" aria-hidden="true">${sslIcon('certificate')}</span>
        <code>${escapeHTML(domain)}</code>
      </div>`,
            SectionUI.renderStatusPill('Auto-TLS', 'primary'),
            `<div class="operator-control-actions ssl-domain-row-actions">${actions}</div>`
        ];
    });
    const table = SectionUI.renderEnterpriseTable({
        columns: ['Domain', 'Coverage', 'Actions'],
        rows,
        className: 'ssl-domain-table',
        emptyTitle: 'No managed domains',
        emptyMessage: 'Add a public hostname to include it in automatic certificate issuance.'
    });
    return `
        <div class="ssl-domain-manager">
            <div class="ssl-domain-manager-head">
                <div>
                    <strong style="display: inline-flex; align-items: center;">
                        Managed domains
                        ${SectionUI.renderInfoTooltip('Public hostnames included in automatic certificate issuance and renewal.')}
                    </strong>
                </div>
                <div class="ssl-domain-compose">
                    <input type="text" id="domain-input" class="settings-input ssl-domain-input" placeholder="example.com" aria-label="Public domain hostname">
                    <button type="button" class="btn btn-outline btn-sm ssl-domain-add" data-ssl-action="add-domain">Add domain</button>
                </div>
            </div>
            <div class="ssl-domain-table-surface">${table}</div>
        </div>
    `;
}
function renderCertificatesList() {
    const rows = sslState.certificates.map(cert => {
        const certID = encodeSslValue(cert.id);
        const title = cert.domain || cert.cn || 'Certificate';
        const menu = cert.deletable
            ? SectionUI.renderActionMenu({
                id: `ssl-certificate-actions-${certID}`,
                label: 'More',
                ariaLabel: `Actions for ${title}`,
                items: [
                    { label: 'Delete inactive certificate', attrs: `data-ssl-action="delete-cert" data-cert-id="${certID}"`, tone: 'danger' }
                ],
                className: 'ssl-row-menu'
            })
            : '<span class="text-muted">—</span>';
        const statusTone = cert.status === 'expired' || cert.valid === false
            ? 'danger'
            : cert.status === 'expiring' ? 'warning' : 'success';
        return [
            `<div class="ssl-certificate-identity">
        <span class="ssl-certificate-icon" aria-hidden="true">${sslIcon('certificate')}</span>
        <span class="ssl-certificate-copy">
          <strong>${escapeHTML(title)}</strong>
          <small>${cert.active ? 'Active · ' : ''}${escapeHTML(cert.issuer || (cert.managed ? 'Auto-managed' : 'Manual upload'))}</small>
        </span>
      </div>`,
            `<span class="ssl-certificate-expiry">${escapeHTML(formatCertDate(cert.not_after))}</span>`,
            SectionUI.renderStatusPill(escapeHTML(certificateStatusLabel(cert)), statusTone),
            `<div class="operator-control-actions ssl-row-actions">${menu}</div>`
        ];
    });
    return SectionUI.renderEnterpriseTable({
        columns: ['Certificate', 'Expires', 'Status', 'Actions'],
        rows,
        className: 'ssl-certificate-table',
        emptyTitle: 'No certificates available',
        emptyMessage: 'Enable Auto-TLS or upload a certificate to populate the inventory.'
    });
}
function sslIcon(name) {
    if (name === 'automation') {
        return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 7h-9"/><path d="M14 17H5"/><circle cx="17" cy="17" r="3"/><circle cx="7" cy="7" r="3"/></svg>';
    }
    if (name === 'upload') {
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5-5 5 5"/><path d="M12 5v12"/></svg>';
    }
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
}
function ensureSSLBindings() {
    if (sslBindingsInitialized)
        return;
    sslBindingsInitialized = true;
    AdminEvents.delegateEvent(document, 'change', '#auto-tls-toggle', (_event, target) => {
        toggleAutoTLS(target.checked);
    });
    AdminEvents.delegateEvent(document, 'change', '#tls-enabled-toggle', (_event, target) => {
        sslState.tlsConfig.enabled = target.checked;
        markTLSConfigDirty();
        const container = AdminDOM.getById('ssl-container');
        if (container)
            renderSSLPage(container);
    });
    AdminEvents.delegateEvent(document, 'input', '#acme-email', (_event, target) => {
        sslState.tlsConfig.email = target.value;
        markTLSConfigDirty();
    });
    AdminEvents.delegateEvent(document, 'click', '[data-ssl-action]', (_event, target) => {
        const action = target.dataset.sslAction;
        const domain = decodeSslValue(target.dataset.domain);
        const certId = decodeSslValue(target.dataset.certId);
        switch (action) {
            case 'focus-domain-input':
                AdminDOM.focusById('domain-input');
                break;
            case 'remove-domain':
                if (domain)
                    removeDomain(domain);
                break;
            case 'add-domain':
                addDomainFromInput();
                break;
            case 'add-detected-domain':
                if (domain)
                    addDomain(domain);
                break;
            case 'save-tls-config':
                if (!sslConfigDirty || sslSaveInFlight)
                    break;
                sslSaveInFlight = true;
                target.setAttribute('aria-busy', 'true');
                target.setAttribute('disabled', '');
                void saveTLSConfig().finally(() => {
                    sslSaveInFlight = false;
                    target.removeAttribute('aria-busy');
                    target.removeAttribute('disabled');
                });
                break;
            case 'reset-tls-config':
                if (sslConfigDirty && !sslSaveInFlight)
                    void loadSSLPage();
                break;
            case 'show-upload-cert-modal':
                showUploadCertModal();
                break;
            case 'close-modal':
                SectionUI.closeModal();
                break;
            case 'upload-certificate':
                void uploadCertificate();
                break;
            case 'delete-cert':
                if (certId)
                    void deleteCert(certId);
                break;
            default:
                break;
        }
    });
    AdminEvents.delegateEvent(document, 'keydown', '#domain-input', event => {
        if (event instanceof KeyboardEvent)
            handleDomainInput(event);
    });
}
function toggleAutoTLS(checked) {
    const email = AdminDOM.getInput('acme-email');
    if (email)
        sslState.tlsConfig.email = email.value;
    sslState.tlsConfig.auto = checked;
    markTLSConfigDirty();
    const container = AdminDOM.getById('ssl-container');
    if (container)
        renderSSLPage(container);
}
function handleDomainInput(event) {
    if (event.key !== 'Enter')
        return;
    event.preventDefault();
    addDomainFromInput();
}
function addDomainFromInput() {
    const input = AdminDOM.getInput('domain-input');
    if (!input)
        return;
    if (addDomain(input.value))
        input.value = '';
}
function addDomain(value) {
    const domain = normalizeDomain(value);
    if (!domain) {
        sslShowToast('Enter a valid domain name', 'error');
        return false;
    }
    if (sslState.tlsConfig.domains.includes(domain)) {
        sslShowToast('This domain is already managed', 'warning');
        return false;
    }
    sslState.tlsConfig.domains.push(domain);
    markTLSConfigDirty();
    const container = AdminDOM.getById('ssl-container');
    if (container)
        renderSSLPage(container);
    window.setTimeout(() => {
        AdminDOM.focusById('domain-input');
    }, 0);
    return true;
}
function normalizeDomain(value) {
    const input = value.trim().replace(/\.$/, '');
    if (!input || /[:/\\*@?#]/u.test(input)) {
        return '';
    }
    let domain = '';
    try {
        // URL normalizes internationalized hostnames to their ASCII IDNA form,
        // matching the backend Auto-TLS allow-list rather than rejecting IDNs in
        // the browser before they can be validated server-side.
        domain = new URL(`https://${input}`).hostname.toLowerCase();
    }
    catch {
        return '';
    }
    if (domain.length > 253 || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(domain)) {
        return '';
    }
    return domain;
}
function removeDomain(domain) {
    sslState.tlsConfig.domains = sslState.tlsConfig.domains.filter(item => item !== domain);
    markTLSConfigDirty();
    const container = AdminDOM.getById('ssl-container');
    if (container)
        renderSSLPage(container);
}
function markTLSConfigDirty() {
    sslConfigDirty = true;
    SectionUI.markSaveActionBarDirty('data-ssl-action');
}
async function saveTLSConfig() {
    const emailEl = AdminDOM.getInput('acme-email');
    if (emailEl)
        sslState.tlsConfig.email = emailEl.value.trim();
    if (sslState.tlsConfig.enabled && sslState.tlsConfig.auto && (!sslState.tlsConfig.domains || sslState.tlsConfig.domains.length === 0)) {
        sslShowToast('Auto-TLS requires at least one domain', 'error');
        AdminDOM.focusById('domain-input');
        return;
    }
    const result = await api.requestResult('certificates/config', 'PUT', sslState.tlsConfig);
    if (result.error) {
        sslShowToast(result.error.message, 'error');
        return;
    }
    sslConfigDirty = false;
    SectionUI.markSaveActionBarClean('data-ssl-action');
    sslShowToast(result.data?.restart_required ? 'Configuration saved. Restart Aegis to apply it.' : 'TLS configuration applied.', result.data?.restart_required ? 'warning' : 'success');
    await loadSSLPage();
}
export function showUploadCertModal() {
    const content = `
            <div class="modal-header">
                <h3>Upload SSL Certificate</h3>
                <button type="button" class="modal-close" data-ssl-action="close-modal" aria-label="Close dialog">&times;</button>
            </div>
            <div class="modal-body section-modal">
                <div class="mb-24">
                    <label class="text-sm font-600 mb-12 block" style="display: flex; align-items: center;">
                        Domain (optional)
                        ${SectionUI.renderInfoTooltip('If supplied, the certificate SAN must cover this exact hostname or IP. Leave blank for automatic detection.')}
                    </label>
                    <input type="text" id="cert-domain" class="settings-input w-100" placeholder="e.g., example.com">
                </div>
                <div class="mb-24">
                    <label class="text-sm font-600 mb-12 block">Certificate File (.crt, .pem)</label>
                    <input type="file" id="cert-file" accept=".crt,.pem,.cer" class="settings-input w-100">
                </div>
                <div class="mb-24">
                    <label class="text-sm font-600 mb-12 block">Private Key File (.key, .pem)</label>
                    <input type="file" id="key-file" accept=".key,.pem" class="settings-input w-100">
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline" data-ssl-action="close-modal">Cancel</button>
                <button type="button" class="btn btn-primary" data-ssl-action="upload-certificate"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5-5 5 5"/><path d="M12 5v12"/></svg>Upload Certificate</button>
            </div>
    `;
    SectionUI.showModal(content, { panelClass: 'modal-content section-modal w-500' });
}
async function uploadCertificate() {
    const domain = AdminDOM.inputValue('cert-domain').trim();
    const certFile = AdminDOM.firstFile('cert-file');
    const keyFile = AdminDOM.firstFile('key-file');
    if (!certFile || !keyFile) {
        sslShowToast('Please select both certificate and key files', 'error');
        return;
    }
    if (certFile.size > 1024 * 1024 || keyFile.size > 1024 * 1024) {
        sslShowToast('Certificate and key files must each be 1 MiB or smaller', 'error');
        return;
    }
    const formData = new FormData();
    formData.append('domain', domain);
    formData.append('certificate', certFile);
    formData.append('key', keyFile);
    api.showLoading();
    try {
        if (!api.csrfToken)
            await api.checkSession();
        const response = await fetch('/api/certificates', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': api.csrfToken || ''
            },
            body: formData
        });
        const responseData = await response.json().catch(() => ({}));
        if (response.ok && (responseData.status === 'activated' || responseData.status === 'staged')) {
            SectionUI.closeModal();
            const warningSuffix = responseData.warnings?.length ? ` ${responseData.warnings.join(' ')}` : '';
            sslShowToast(`${responseData.restart_required ? 'Certificate staged. Restart Aegis to activate it.' : 'Certificate validated and activated.'}${warningSuffix}`, responseData.restart_required || responseData.warnings?.length ? 'warning' : 'success');
            await loadSSLPage();
            return;
        }
        sslShowToast(responseData.error || 'Failed to upload certificate', 'error');
    }
    catch (error) {
        sslShowToast('Error uploading certificate', 'error');
        console.error(error);
    }
    finally {
        api.hideLoading();
    }
}
async function deleteCert(id) {
    SectionUI.openConfirmModal('Delete Certificate', 'Are you sure you want to delete this certificate?', 'Delete', 'var(--danger)', () => {
        void confirmDeleteCert(id);
    });
}
async function confirmDeleteCert(id) {
    SectionUI.closeModal();
    const result = await api.requestResult('certificates', 'DELETE', { id });
    if (result.error) {
        sslShowToast(result.error.message, 'error');
        return;
    }
    if (result.data?.status !== 'deleted') {
        sslShowToast('The certificate was not deleted', 'error');
        return;
    }
    sslShowToast(result.data.warnings?.length ? result.data.warnings.join(' ') : 'Inactive certificate deleted', result.data.warnings?.length ? 'warning' : 'success');
    await loadSSLPage();
}
function formatCertDate(value) {
    if (!value)
        return 'N/A';
    const date = new Date(value);
    if (Number.isNaN(date.getTime()))
        return value;
    return date.toLocaleDateString();
}
function certificateStatusLabel(cert) {
    if (cert.status === 'not_yet_valid')
        return 'Not yet valid';
    if (cert.status === 'expired' || cert.valid === false)
        return 'Expired';
    if (cert.status === 'expiring')
        return 'Expiring';
    if (cert.active)
        return 'Active';
    if (cert.auto_renew)
        return 'Auto-renewed';
    return 'Valid';
}
function sslShowToast(message, type = 'info') {
    notify(message, type);
}
