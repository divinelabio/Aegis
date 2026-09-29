/**
 * Profile page
 * Source of truth: web/admin/src/profile.ts
 * Runtime output: web/admin/dist/js/profile.js
 */
import { api } from './api.js';
import * as AdminEvents from './core/events.js';
import { SectionUI } from './sections/ui-components.js';
import * as AdminDOM from './core/dom.js';
import { notify } from './core/notify.js';
const profileState = {
    mfaWizardStep: 0,
    mfaSecretData: null
};
function bindProfileInteractions() {
    if (bindProfileInteractions.initialized)
        return;
    bindProfileInteractions.initialized = true;
    AdminEvents.delegateEvent(document, 'click', '[data-action="profile-setup-mfa"]', event => {
        event.preventDefault();
        void setupMFA();
    });
    AdminEvents.delegateEvent(document, 'click', '[data-action="profile-disable-mfa"]', event => {
        event.preventDefault();
        void disableMFA();
    });
    AdminEvents.delegateEvent(document, 'click', '[data-action="profile-update-password"]', event => {
        event.preventDefault();
        void updateProfilePassword();
    });
    AdminEvents.delegateEvent(document, 'click', '[data-action="profile-close-mfa-modal"]', event => {
        event.preventDefault();
        closeMFAModal();
    });
    AdminEvents.delegateEvent(document, 'click', '[data-action="profile-start-mfa-flow"]', event => {
        event.preventDefault();
        void startMFAFlow();
    });
    AdminEvents.delegateEvent(document, 'click', '[data-action="profile-enable-mfa"]', event => {
        event.preventDefault();
        void enableMFA();
    });
    AdminEvents.delegateEvent(document, 'click', '[data-action="profile-mfa-back"]', event => {
        event.preventDefault();
        profileState.mfaWizardStep = 1;
        renderMFAWizard();
    });
    AdminEvents.delegateEvent(document, 'keyup', '#mfa-verify-code', event => {
        if (event instanceof KeyboardEvent) {
            checkAutoSubmit(event);
        }
    });
}
export async function loadProfilePage() {
    const container = AdminDOM.getById('profile-container');
    if (!container)
        return;
    const user = api.currentUser;
    if (!user) {
        container.innerHTML = '<div class="p-40 text-center">Please log in to view profile.</div>';
        return;
    }
    const profile = await loadProfileDetails();
    const usernameRaw = profile?.username || user.username || 'admin';
    const username = escapeHtml(usernameRaw);
    const roleName = escapeHtml(profileGetRoleName(profile?.role_id || user.roleId));
    const initials = escapeHtml(usernameRaw.slice(0, 2).toUpperCase());
    const mfaEnabled = profile?.mfa_enabled === true;
    const accountDetailsContent = `
    <div class="profile-field-grid">
      <div class="profile-readonly-field">
        <span>Username</span>
        <strong>${username}</strong>
      </div>
      <div class="profile-readonly-field">
        <span>Role</span>
        <strong>${roleName}</strong>
      </div>
      <div class="profile-readonly-field">
        <span>User ID</span>
        <strong>${escapeHtml(String(profile?.id || user.id || '-'))}</strong>
      </div>
      <div class="profile-readonly-field">
        <span>MFA Status</span>
        <strong>${mfaEnabled ? 'Enabled' : 'Not configured'}</strong>
      </div>
    </div>
  `;
    const passwordContent = `
    <div class="profile-password-form">
      <label class="profile-form-field">
        <span>New Password</span>
        <input type="password" id="profile-new-pass" placeholder="Enter new password" class="settings-input" autocomplete="new-password">
      </label>
      <label class="profile-form-field">
        <span>Confirm Password</span>
        <input type="password" id="profile-confirm-pass" placeholder="Confirm new password" class="settings-input" autocomplete="new-password">
      </label>
      <div class="profile-form-footer">
        <span>Minimum 8 characters.</span>
        <button type="button" class="btn btn-primary" data-action="profile-update-password">Update Password</button>
      </div>
    </div>
  `;
    const verificationActions = `
    <div class="profile-verification-actions">
      <button type="button" class="btn btn-sm ${mfaEnabled ? 'btn-outline' : 'btn-primary'}" data-action="profile-setup-mfa">${mfaEnabled ? 'Reconfigure' : 'Enable'}</button>
      <button type="button" class="btn btn-outline btn-sm ${mfaEnabled ? 'btn-outline-warning' : ''}" data-action="profile-disable-mfa" ${mfaEnabled ? '' : 'disabled'}>Disable</button>
    </div>
  `;
    const verificationContent = `
    <div class="profile-verification-card ${mfaEnabled ? 'enabled' : ''}">
      <div class="profile-security-icon">${renderIcon(mfaEnabled ? 'check' : 'shield')}</div>
      <div class="profile-verification-main">
        <div class="profile-verification-title">${mfaEnabled ? 'Verification is active' : 'Verification is not configured'}</div>
        <div class="profile-verification-sub">${mfaEnabled ? 'This account requires a fresh code during protected sign-in flows.' : 'Pair a verification device to reduce account takeover risk.'}</div>
      </div>
      <div class="profile-verification-state">${mfaEnabled ? 'Enabled' : 'Action needed'}</div>
    </div>
  `;
    const content = `
    <div class="profile-operator-stack">
      <section class="profile-summary-panel">
        <div class="profile-avatar-large">${initials}</div>
        <div class="profile-summary-main">
          <div class="profile-summary-kicker">Signed in as</div>
          <h3>${username}</h3>
          <p>${roleName}</p>
        </div>
      </section>

      <div class="profile-configuration-grid">
        ${SectionUI.renderOperatorSection('Account Details', accountDetailsContent, {
        subtitle: 'Read-only identity details for the current admin session.',
        className: 'profile-catalog-section'
    })}

        ${SectionUI.renderOperatorSection('Password', passwordContent, {
        subtitle: 'Use a strong password for this administrator account.',
        className: 'profile-catalog-section'
    })}
      </div>

      ${SectionUI.renderOperatorSection('Login Verification', verificationContent, {
        subtitle: 'Require a rotating verification code after password sign-in.',
        actions: verificationActions,
        className: 'profile-catalog-section profile-verification-section'
    })}
    </div>
  `;
    const operatorFrame = SectionUI.renderOperatorFrame({
        title: 'My Profile',
        kicker: 'Account Security',
        subtitle: 'Manage identity, password rotation, and login verification.',
        content,
        className: 'profile-operator-frame'
    });
    container.innerHTML = `
    ${operatorFrame}
    <div id="mfa-modal" class="modal-overlay hidden">
      <div class="modal-content modal-narrow profile-mfa-modal">
        <div class="modal-header">
          <h3>Login Verification</h3>
          <button type="button" data-action="profile-close-mfa-modal" class="modal-close" aria-label="Close login verification setup">&times;</button>
        </div>
        <div class="modal-body">
          <div id="mfa-wizard-content"></div>
        </div>
      </div>
    </div>
  `;
    bindProfileInteractions();
}
async function loadProfileDetails() {
    try {
        const response = await fetch('/api/profile', { headers: { Accept: 'application/json' } });
        if (!response.ok)
            return null;
        return (await response.json());
    }
    catch {
        return null;
    }
}
function renderIcon(name) {
    if (name === 'check') {
        return '<svg viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>';
    }
    if (name === 'alert') {
        return '<svg viewBox="0 0 24 24"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>';
    }
    return '<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>';
}
async function setupMFA() {
    profileState.mfaWizardStep = 1;
    renderMFAWizard();
    AdminDOM.getById('mfa-modal')?.classList.remove('hidden');
}
function closeMFAModal() {
    AdminDOM.getById('mfa-modal')?.classList.add('hidden');
    profileState.mfaWizardStep = 0;
    profileState.mfaSecretData = null;
}
function renderMFAWizard() {
    const container = AdminDOM.getById('mfa-wizard-content');
    if (!container)
        return;
    let html = '';
    if (profileState.mfaWizardStep === 1) {
        html = `
            <div class="profile-mfa-step">
                <div class="profile-mfa-icon">${renderIcon('shield')}</div>
                <h4>Set up login verification</h4>
                <p>Pair this account with a verification device. Future protected sign-ins will require a fresh six-digit code.</p>
                <button type="button" class="btn btn-primary w-100" data-action="profile-start-mfa-flow">Begin Pairing</button>
            </div>
        `;
    }
    else if (profileState.mfaWizardStep === 2) {
        const qr = profileState.mfaSecretData?.qr_image || '';
        const secret = profileState.mfaSecretData?.secret || 'Loading...';
        html = `
            <div class="profile-mfa-step">
                <h4>Pair your verification device</h4>
                <p>Scan the secure pairing code, then enter the current six-digit code to activate verification.</p>
                <div class="profile-mfa-pairing-body">
                    <div class="profile-qr-card">
                        <img src="${escapeAttr(qr)}" alt="MFA QR code">
                    </div>
                    
                    <div class="profile-secret-row">
                        <span>Manual pairing key</span>
                        <strong>${escapeHtml(secret)}</strong>
                    </div>

                    <div class="profile-form-field">
                        <span>Verification code</span>
                        <div class="profile-mfa-code-row">
                            <input type="text" id="mfa-verify-code" placeholder="000 000" maxlength="6" 
                                class="settings-input">
                            <button type="button" class="btn btn-primary" data-action="profile-enable-mfa" id="btn-enable-mfa">Activate</button>
                        </div>
                    </div>
                </div>
                ${SectionUI.renderOperatorBackButton({
            label: 'Back',
            ariaLabel: 'Back to pairing instructions',
            attrs: 'data-action="profile-mfa-back"',
            className: 'profile-mfa-back'
        })}
            </div>
        `;
    }
    else if (profileState.mfaWizardStep === 3) {
        html = `
            <div class="profile-mfa-step">
                <div class="profile-mfa-icon success">${renderIcon('check')}</div>
                <h4>Login verification enabled</h4>
                <p>This account now requires a rotating verification code during protected sign-in flows.</p>
                <button type="button" class="btn btn-primary w-100" data-action="profile-close-mfa-modal">Done</button>
            </div>
        `;
    }
    else if (profileState.mfaWizardStep === -1) {
        html = '<div class="profile-mfa-loading">Preparing secure pairing...</div>';
    }
    container.innerHTML = html;
    if (profileState.mfaWizardStep === 2) {
        const input = AdminDOM.getInput('mfa-verify-code');
        input?.focus();
    }
}
async function startMFAFlow() {
    profileState.mfaWizardStep = -1;
    renderMFAWizard();
    try {
        const result = await api.requestResult('mfa/setup', 'POST');
        if (result.error || !result.data)
            throw new Error(result.error?.message || 'Failed to generate secret');
        profileState.mfaSecretData = result.data;
        profileState.mfaWizardStep = 2;
        renderMFAWizard();
    }
    catch (error) {
        profileShowToast(error instanceof Error ? error.message : 'Failed to start MFA', 'error');
        profileState.mfaWizardStep = 1;
        renderMFAWizard();
    }
}
function checkAutoSubmit(event) {
    if (event.key === 'Enter') {
        void enableMFA();
    }
}
async function enableMFA() {
    const input = AdminDOM.getInput('mfa-verify-code');
    const button = AdminDOM.getById('btn-enable-mfa');
    if (!input || !button)
        return;
    const code = input.value.replace(/\s/g, '');
    if (!code || code.length !== 6) {
        profileShowToast('Please enter a valid 6-digit code', 'error');
        input.classList.add('shake');
        window.setTimeout(() => input.classList.remove('shake'), 500);
        return;
    }
    button.disabled = true;
    button.textContent = '...';
    const result = await api.requestResult('mfa/enable', 'POST', { code });
    if (!result.error) {
        profileShowToast('MFA enabled. Sign in again to continue.', 'success');
        window.setTimeout(() => {
            window.location.href = '/admin/login';
        }, 500);
        return;
    }
    profileShowToast(result.error.message || 'Invalid code. Please try again.', 'error');
    if (result.error.status !== 401) {
        button.disabled = false;
        button.textContent = 'Verify';
        input.value = '';
        input.focus();
    }
}
async function disableMFA() {
    if (!window.confirm('Disable login verification for this account?'))
        return;
    const code = window.prompt('Enter the current six-digit verification code to disable login verification.')?.replace(/\s/g, '');
    if (!code || code.length !== 6) {
        profileShowToast('A valid six-digit verification code is required', 'error');
        return;
    }
    const result = await api.requestResult('mfa/disable', 'POST', { code });
    if (result.error) {
        profileShowToast(result.error.message, 'error');
        return;
    }
    profileShowToast('Login verification disabled. Sign in again to continue.', 'success');
    window.setTimeout(() => {
        window.location.href = '/admin/login';
    }, 500);
}
async function updateProfilePassword() {
    const pass = AdminDOM.inputValue('profile-new-pass');
    const confirm = AdminDOM.inputValue('profile-confirm-pass');
    if (!pass || pass.length < 8) {
        profileShowToast('Password must be at least 8 characters', 'error');
        return;
    }
    if (pass !== confirm) {
        profileShowToast('Passwords do not match', 'error');
        return;
    }
    const result = await api.requestResult('profile', 'PUT', { password: pass });
    if (result.error) {
        profileShowToast(result.error.message, 'error');
        return;
    }
    profileShowToast('Password updated. Sign in again to continue.', 'success');
    window.setTimeout(() => {
        window.location.href = '/admin/login';
    }, 500);
}
function profileGetRoleName(id) {
    const roles = {
        'a1b2c3d4-e5f6-7890-1234-567890abcdef': 'Super Admin',
        'b2c3d4e5-f6a7-8901-2345-678901abcdef': 'Network Admin',
        'c3d4e5f6-a7b8-9012-3456-789012abcdef': 'Security Analyst',
        'd4e5f6a7-b8c9-0123-4567-890123abcdef': 'Viewer'
    };
    return id ? roles[String(id)] || 'Active User' : 'Active User';
}
function profileShowToast(message, type = 'info') {
    notify(message, type);
}
function escapeHtml(value) {
    return value.replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char] || char));
}
function escapeAttr(value) {
    return escapeHtml(value);
}
void closeMFAModal;
void startMFAFlow;
void disableMFA;
void checkAutoSubmit;
void renderMFAWizard;
