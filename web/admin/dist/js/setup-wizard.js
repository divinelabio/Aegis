import { api } from './api.js';
import * as AdminDOM from './core/dom.js';
import { router } from './router.js';
import { selectSettingsTab } from './settings.js';
import { escapeSectionAttr, escapeSectionHtml } from './sections/section-runtime-helpers.js';
import { SectionUI } from './sections/ui-components.js';
import { Toast } from './toast.js';
import { showLicenseCongratulationsModal, showLicenseErrorModal } from './licensing-modal.js';
const THEME_STORAGE_KEY = 'aegis-admin-theme';
const steps = ['UI mode', 'Database', 'Admin account', 'Get Pro', 'Review'];
const postgreSQLSSLModes = ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full'];
let wizardState = null;
let activeStep = 0;
let setupStatusRequested = false;
let setupBindingsReady = false;
let wizardBusy = false;
let passwordEditOpen = false;
let clickHouseWarningOpen = false;
let clickHouseSkipConfirmed = false;
let postgreSQLVerifiedSignature = '';
export async function maybeShowSetupWizard(options = {}) {
    if (setupStatusRequested || wizardState)
        return Boolean(wizardState);
    setupStatusRequested = true;
    const status = await fetchJSON('/api/setup/status');
    if (!status || status.completed || !status.setup_required) {
        deactivateSetupShell();
        return false;
    }
    if (options.firstRunOnly && status.user_count > 0 && !api.currentUser) {
        setupStatusRequested = false;
        return false;
    }
    const bootstrap = await fetchJSON('/api/setup/bootstrap');
    wizardState = {
        status,
        config: bootstrap?.config || {},
        roles: bootstrap?.roles || [],
        users: bootstrap?.users || [],
        modules: bootstrap?.modules || {},
        theme: getStoredTheme()
    };
    activeStep = 0;
    passwordEditOpen = false;
    clickHouseWarningOpen = false;
    clickHouseSkipConfirmed = false;
    postgreSQLVerifiedSignature = '';
    activateSetupShell();
    ensureSetupBindings();
    renderSetupWizard();
    return true;
}
async function fetchJSON(url) {
    try {
        const response = await fetch(url, { headers: { Accept: 'application/json' } });
        if (!response.ok)
            return null;
        return await response.json();
    }
    catch (error) {
        console.warn(`[Aegis setup] ${url} failed`, error);
        return null;
    }
}
async function requestPublicSetupResult(endpoint, method, data) {
    try {
        const response = await fetch(`/api/${endpoint}`, {
            method,
            headers: {
                Accept: 'application/json',
                'Content-Type': 'application/json'
            },
            body: data === undefined ? null : JSON.stringify(data)
        });
        const payload = await parseResponseJSON(response);
        if (!response.ok) {
            return {
                data: null,
                error: {
                    status: response.status,
                    code: setupErrorCode(payload),
                    message: setupErrorMessage(payload, `Request failed: ${response.status} for ${endpoint}`)
                }
            };
        }
        return { data: payload, error: null };
    }
    catch (error) {
        return {
            data: null,
            error: {
                status: 0,
                message: error instanceof Error ? error.message : 'Setup request failed.'
            }
        };
    }
}
function setupRequestResult(authenticatedEndpoint, firstRunEndpoint, method, data) {
    if (setupFirstRunPublicMode()) {
        return requestPublicSetupResult(firstRunEndpoint, method, data);
    }
    return api.requestResult(authenticatedEndpoint, method, data);
}
async function parseResponseJSON(response) {
    try {
        return await response.json();
    }
    catch {
        return null;
    }
}
function setupErrorCode(payload) {
    const error = payload?.error;
    if (error && typeof error === 'object' && 'code' in error && typeof error.code === 'string')
        return error.code;
    if (typeof payload?.code === 'string')
        return payload.code;
    if (typeof error === 'string')
        return error;
    return undefined;
}
function setupErrorMessage(payload, fallback) {
    const error = payload?.error;
    if (typeof payload?.message === 'string' && payload.message)
        return payload.message;
    if (typeof error === 'string' && error)
        return error;
    if (error && typeof error === 'object' && 'message' in error && typeof error.message === 'string' && error.message) {
        return error.message;
    }
    return fallback;
}
function ensureSetupBindings() {
    if (setupBindingsReady)
        return;
    setupBindingsReady = true;
    document.addEventListener('click', event => {
        if (!(event.target instanceof Element))
            return;
        const actionTarget = event.target.closest('[data-setup-action]');
        if (!(actionTarget instanceof HTMLElement))
            return;
        event.preventDefault();
        void handleSetupAction(actionTarget.dataset.setupAction || '');
    });
    document.addEventListener('change', event => {
        if (!(event.target instanceof Element))
            return;
        const themeInput = event.target.closest('[data-setup-theme]');
        if (themeInput instanceof HTMLInputElement) {
            applySetupTheme(themeInput.value === 'dark' ? 'dark' : 'light');
        }
        if (event.target instanceof HTMLElement && event.target.id === 'setup-postgresql-ssl') {
            updateDatabaseGateUI();
        }
    });
    document.addEventListener('input', event => {
        if (!(event.target instanceof HTMLElement))
            return;
        if (event.target.id.startsWith('setup-postgresql-')) {
            updateDatabaseGateUI();
        }
    });
}
async function handleSetupAction(action) {
    if (!wizardState || wizardBusy)
        return;
    switch (action) {
        case 'back':
            clickHouseWarningOpen = false;
            activeStep = Math.max(0, activeStep - 1);
            renderSetupWizard();
            break;
        case 'next':
            if (activeStep === 2 && !postgreSQLReadyForSetup()) {
                Toast.show('Test the PostgreSQL connection successfully before continuing.', 'warning');
                updateDatabaseGateUI();
                break;
            }
            if (activeStep === 3 && !adminReadyForSetup()) {
                Toast.show('Create an administrator account before continuing.', 'warning');
                updateAdminGateUI();
                break;
            }
            if (shouldPromptForMissingClickHouse()) {
                clickHouseWarningOpen = true;
                renderSetupWizard();
                break;
            }
            advanceSetupStep();
            break;
        case 'close-clickhouse-warning':
            clickHouseWarningOpen = false;
            renderSetupWizard();
            break;
        case 'continue-without-clickhouse':
            clickHouseWarningOpen = false;
            clickHouseSkipConfirmed = true;
            advanceSetupStep();
            break;
        case 'finish':
            await finishSetupWizard();
            break;
        case 'test-postgresql':
            await testPostgreSQLConnection();
            break;
        case 'save-postgresql':
            await savePostgreSQLConfiguration();
            break;
        case 'test-clickhouse':
            await testClickHouseConnection();
            break;
        case 'save-clickhouse':
            await saveClickHouseConfiguration();
            break;
        case 'create-admin':
            await createAdminAccount();
            break;
        case 'edit-password':
            passwordEditOpen = true;
            renderSetupWizard();
            break;
        case 'cancel-password':
            passwordEditOpen = false;
            renderSetupWizard();
            break;
        case 'save-current-password':
            await updateCurrentAdminPassword();
            break;
        case 'open-users':
            deactivateSetupShell();
            router.navigate('users');
            Toast.show('User management opened.', 'info');
            break;
        case 'open-license':
            deactivateSetupShell();
            selectSettingsTab('license');
            router.navigate('settings');
            Toast.show('Licence settings opened.', 'info');
            break;
        case 'activate-license':
            await activateSetupLicense();
            break;
    }
}
function renderSetupWizard() {
    if (!wizardState)
        return;
    const root = ensureSetupRoot();
    const isLastStep = activeStep === steps.length;
    const primaryAction = isLastStep ? 'finish' : 'next';
    const tier = (wizardState?.modules.license_tier || 'community').toLowerCase();
    const isCommunity = tier === 'community';
    const primaryLabel = isLastStep ? 'Finish setup' : activeStep === 0 ? 'Start setup' : activeStep === 4 ? (isCommunity ? 'Continue with Community' : 'Next') : 'Next';
    const primaryDisabled = primaryAction === 'next' && ((activeStep === 2 && !postgreSQLReadyForSetup())
        || (activeStep === 3 && !adminReadyForSetup()))
        ? ' disabled aria-disabled="true"'
        : '';
    const stepIndex = activeStep - 1;
    const activeStepLabel = activeStep === 0 ? 'Welcome' : steps[stepIndex] || 'Review';
    const stepKey = ['welcome', 'theme', 'database', 'admin', 'pro', 'review'][activeStep] || 'review';
    root.innerHTML = `
    <div class="setup-wizard-page">
      <section class="setup-wizard-card" aria-labelledby="setup-wizard-title">
        <header class="setup-wizard-header">
          <div class="setup-wizard-heading">
            <h2 id="setup-wizard-title">Setup Wizard</h2>
            <p>${escapeSectionHtml(activeStepLabel)}</p>
          </div>
          <ol class="setup-stepper" aria-label="Setup progress">
            ${steps.map((step, index) => `
              <li class="${index === stepIndex ? 'is-active' : ''}${index < stepIndex ? ' is-complete' : ''}"${index === stepIndex ? ' aria-current="step"' : ''}>
                <span>${index + 1}</span>
                <strong>${escapeSectionHtml(step)}</strong>
              </li>
            `).join('')}
          </ol>
        </header>
        <div class="setup-wizard-body">
          <div class="setup-step-content setup-step-content-${stepKey}">
            ${renderActiveStep()}
          </div>
        </div>
        <footer class="setup-wizard-footer">
          <button type="button" class="btn btn-outline setup-back" data-setup-action="back"${activeStep === 0 ? ' disabled' : ''}>Back</button>
          <button type="button" class="btn btn-primary setup-next" data-setup-action="${primaryAction}"${primaryDisabled}>${primaryLabel}</button>
        </footer>
      </section>
      ${clickHouseWarningOpen ? renderClickHouseWarningModal() : ''}
    </div>
  `;
    window.setTimeout(() => {
        const card = AdminDOM.query('.setup-wizard-card', root);
        const body = AdminDOM.query('.setup-wizard-body', root);
        card?.scrollIntoView({ block: 'start' });
        body?.scrollTo({ top: 0 });
        const focusTarget = AdminDOM.query('[data-setup-autofocus]', root)
            || AdminDOM.query('.setup-next', root);
        try {
            focusTarget?.focus({ preventScroll: true });
        }
        catch {
            focusTarget?.focus();
        }
    }, 0);
}
function ensureSetupRoot() {
    let root = AdminDOM.getById('setup-wizard-root');
    if (root)
        return root;
    const viewRoot = AdminDOM.getById('view-root');
    if (viewRoot) {
        viewRoot.innerHTML = '<div class="view setup-wizard-view"><div id="setup-wizard-root"></div></div>';
        root = AdminDOM.getById('setup-wizard-root');
        if (root)
            return root;
    }
    root = document.createElement('div');
    root.id = 'setup-wizard-root';
    document.body.appendChild(root);
    return root;
}
function renderActiveStep() {
    switch (activeStep) {
        case 0:
            return renderWelcomeStep();
        case 1:
            return renderThemeStep();
        case 2:
            return renderDatabaseStep();
        case 3:
            return renderAdminStep();
        case 4:
            return renderProStep();
        default:
            return renderReviewStep();
    }
}
function renderWelcomeStep() {
    return `
    <div class="setup-welcome-panel">
      <div class="setup-welcome-copy">
        <span class="setup-wizard-kicker">AEGIS</span>
        <h3>Welcome to Aegis</h3>
        <p>Let's get started configuring your console.</p>
      </div>
    </div>
  `;
}
function renderThemeStep() {
    const theme = wizardState?.theme || getStoredTheme();
    return `
    <div class="setup-step-copy">
      <p>Choose the console mode for this browser.</p>
    </div>
    <div class="setup-radio-grid" role="radiogroup" aria-label="UI mode">
      ${renderThemeCard('dark', 'Dark', 'Low-glare control room mode.', theme)}
      ${renderThemeCard('light', 'Light', 'Bright mode for daylight work.', theme)}
    </div>
  `;
}
function renderThemeCard(value, title, description, activeTheme) {
    const selected = activeTheme === value;
    return `
    <label class="setup-radio-card${selected ? ' is-selected' : ''}">
      <input type="radio" name="setup-theme" value="${value}" data-setup-theme="${value}"${selected ? ' checked' : ''}>
      <span class="setup-radio-preview setup-radio-preview-${value}" aria-hidden="true">
        <span></span><span></span><span></span>
      </span>
      <span class="setup-radio-title">${title}</span>
      <span class="setup-radio-desc">${description}</span>
    </label>
  `;
}
function renderDatabaseStep() {
    const state = requireWizardState();
    const control = state.config.storage?.control || {};
    const analytics = state.config.storage?.analytics || {};
    const controlStatus = state.status.storage.control;
    const analyticsStatus = state.status.storage.analytics;
    const controlDisabled = controlStatus.environment_locked ? ' disabled' : '';
    const analyticsDisabled = analyticsStatus.environment_locked ? ' disabled' : '';
    const controlLockedAction = controlStatus.environment_locked ? ' disabled data-setup-locked="true"' : '';
    const analyticsLockedAction = analyticsStatus.environment_locked ? ' disabled data-setup-locked="true"' : '';
    const controlConfigured = controlStatus.configured;
    const controlHost = controlConfigured ? control.host || '' : '';
    const controlPort = controlConfigured && validPort(control.port) ? String(control.port) : '';
    const controlDatabase = controlConfigured ? control.database || '' : '';
    const controlUsername = controlConfigured ? control.username || '' : '';
    const controlSecret = controlConfigured ? normalizedSecretRef(control.password_secret_ref) : '';
    const analyticsPort = validPort(analytics.port) ? analytics.port : 9000;
    const sslMode = controlConfigured && postgreSQLSSLModes.includes(control.ssl_mode || '') ? control.ssl_mode || 'disable' : 'disable';
    return `
    <div class="setup-step-copy">
      <p>Storage uses the same controls as Settings. Save changes here as pending, then restart Aegis to apply them.</p>
    </div>
    <div class="settings-operator-frame legacy-admin-settings-shell setup-storage-settings">
      <div class="settings-panel-content storage-settings">
        <div class="storage-configuration-grid">
          ${SectionUI.renderOperatorSection('PostgreSQL', `
            <div class="storage-settings-panel">
              <p class="storage-runtime-status">${storageStatusText(controlStatus, 'Control storage is not configured.')}</p>
              <div class="storage-settings-grid">
                ${renderStorageSettingsField('Host', 'setup-postgresql-host', controlHost, controlDisabled)}
                ${renderStorageSettingsField('Port', 'setup-postgresql-port', controlPort, controlDisabled, 'number', '', ' min="1" max="65535" inputmode="numeric"')}
                ${renderStorageSettingsField('Database name', 'setup-postgresql-database', controlDatabase, controlDisabled)}
                ${renderStorageSettingsField('Username', 'setup-postgresql-username', controlUsername, controlDisabled)}
                ${renderStorageSettingsField('Password', 'setup-postgresql-password', '', controlDisabled, 'password', 'Used for testing only. Never saved.')}
                ${renderStorageSettingsField('Password secret reference', 'setup-postgresql-secret', controlSecret, controlDisabled, 'text', 'Environment variable reference. Re-enter to replace.', ' placeholder="env:AEGIS_CONTROL_DB_PASSWORD" spellcheck="false"')}
                <div class="storage-settings-options storage-settings-options--single">
                  <div class="settings-field">
                    <label for="setup-postgresql-ssl">TLS mode</label>
                    <select id="setup-postgresql-ssl" class="settings-input"${controlDisabled}>
                      ${postgreSQLSSLModes.map(mode => `<option value="${mode}"${mode === sslMode ? ' selected' : ''}>${mode}</option>`).join('')}
                    </select>
                  </div>
                </div>
              </div>
              <div class="storage-settings-actions">
                <button type="button" class="btn btn-outline" data-setup-action="test-postgresql"${controlLockedAction}>Test connection</button>
                <button type="button" class="btn btn-primary" data-setup-action="save-postgresql"${controlLockedAction}>Save</button>
              </div>
              <p id="setup-postgresql-gate" class="setup-db-gate${postgreSQLReadyForSetup(controlStatus) ? ' is-ready' : ''}">${postgreSQLGateText(controlStatus)}</p>
            </div>
          `, {
        subtitle: 'Control plane',
        className: 'settings-storage-card'
    })}

          ${SectionUI.renderOperatorSection('ClickHouse', `
            <div class="storage-settings-panel">
              <p class="storage-runtime-status">${storageStatusText(analyticsStatus, 'ClickHouse analytics is not configured.')}</p>
              <div class="storage-settings-grid">
                ${renderStorageSettingsField('Host', 'setup-clickhouse-host', analytics.host || 'localhost', analyticsDisabled)}
                ${renderStorageSettingsField('Port', 'setup-clickhouse-port', String(analyticsPort), analyticsDisabled, 'number', '', ' min="1" max="65535" inputmode="numeric"')}
                ${renderStorageSettingsField('Database name', 'setup-clickhouse-database', analytics.database || 'aegis', analyticsDisabled)}
                ${renderStorageSettingsField('Username', 'setup-clickhouse-username', analytics.username || 'default', analyticsDisabled)}
                ${renderStorageSettingsField('Temporary password', 'setup-clickhouse-password', '', analyticsDisabled, 'password', 'Used for testing only. Never saved.')}
                ${renderStorageSettingsField('Password secret reference', 'setup-clickhouse-secret', normalizedSecretRef(analytics.password_secret_ref), analyticsDisabled, 'text', 'Environment variable reference. Re-enter to replace.', ' placeholder="env:AEGIS_ANALYTICS_DB_PASSWORD" spellcheck="false"')}
                <div class="storage-settings-options storage-settings-options--single">
                  <div class="storage-tls-control">
                    ${SectionUI.renderSwitch({
        id: 'setup-clickhouse-secure',
        checked: analytics.secure === true,
        label: 'Use TLS for ClickHouse',
        className: 'storage-tls-switch',
        attrs: analyticsDisabled.trim()
    })}
                  </div>
                </div>
              </div>
              <div class="storage-settings-actions">
                <button type="button" class="btn btn-outline" data-setup-action="test-clickhouse"${analyticsLockedAction}>Test connection</button>
                <button type="button" class="btn btn-primary" data-setup-action="save-clickhouse"${analyticsLockedAction}>Save</button>
              </div>
            </div>
          `, {
        subtitle: 'Analytics storage',
        className: 'settings-storage-card'
    })}
        </div>
      </div>
    </div>
  `;
}
function renderAdminStep() {
    const state = requireWizardState();
    const currentUser = api.currentUser?.username || state.config.server?.admin?.username || 'admin';
    const currentUserId = String(api.currentUser?.id || '');
    const superAdminRole = findSuperAdminRole();
    const canCreate = Boolean(superAdminRole) && (setupFirstRunPublicMode(state) || api.hasPermission('users:write'));
    const hasAccounts = hasExistingAdminAccounts(state);
    if (passwordEditOpen) {
        return `
      <div class="setup-admin-single">
        ${renderCurrentPasswordPanel()}
      </div>
    `;
    }
    if (!hasAccounts) {
        return `
      <div class="setup-admin-single">
        ${renderCreateAdminPanel(canCreate)}
      </div>
    `;
    }
    const user = state.users.find(candidate => isCurrentSetupUser(candidate, currentUserId)) || {
        id: currentUserId,
        username: currentUser,
        email: '',
        is_active: true,
        role: { name: state.users[0]?.role?.name || 'administrator' }
    };
    return `
    <div class="setup-step-copy">
      <p>Existing administrator access was found. Confirm the account or edit its password before continuing.</p>
    </div>
    <div class="setup-admin-single">
      <section class="setup-section-block">
        <div class="setup-section-head">
          <div>
            <h3>Administrator account</h3>
            <p>${escapeSectionHtml(user.username)} is signed in.</p>
          </div>
        </div>
        <div class="setup-user-list">
          ${renderSetupUserRow(user, currentUserId)}
        </div>
      </section>
    </div>
  `;
}
function renderSetupUserRow(user, currentUserId) {
    const isCurrent = isCurrentSetupUser(user, currentUserId);
    const role = user.role?.name || 'administrator';
    const action = isCurrent
        ? '<button type="button" class="btn btn-outline btn-sm" data-setup-action="edit-password">Edit password</button>'
        : api.hasPermission('users:read')
            ? '<button type="button" class="btn btn-outline btn-sm" data-setup-action="open-users">Manage</button>'
            : '';
    return `
    <div class="setup-user-row">
      <div class="setup-user-main">
        <span>${escapeSectionHtml(user.username)}${isCurrent ? '<em>Signed in</em>' : ''}</span>
        ${user.email ? `<small>${escapeSectionHtml(user.email)}</small>` : ''}
        <strong>${escapeSectionHtml(role)}</strong>
      </div>
      ${action}
    </div>
  `;
}
function renderCreateAdminPanel(canCreate) {
    return `
    <section class="setup-section-block setup-admin-form-card setup-admin-create-card">
      <div class="setup-section-head">
        <div>
          <h3>Create your admin account</h3>
          <p>${canCreate ? 'Create a super administrator for day-to-day administration.' : 'User creation is unavailable for this session.'}</p>
        </div>
      </div>
      <div class="setup-form-grid setup-admin-create-grid">
        ${renderSetupField('Username', 'setup-admin-username', '', canCreate ? '' : ' disabled')}
        ${renderSetupField('Email', 'setup-admin-email', '', canCreate ? '' : ' disabled', 'email')}
        ${renderSetupField('Password', 'setup-admin-password', '', canCreate ? '' : ' disabled', 'password', 'Use at least 8 characters.', 'setup-field-wide')}
      </div>
      <div class="setup-inline-actions setup-admin-form-actions">
        <button type="button" class="btn btn-primary" data-setup-action="create-admin"${canCreate ? '' : ' disabled data-setup-locked="true"'}>Create account</button>
      </div>
    </section>
  `;
}
function renderCurrentPasswordPanel() {
    return `
    <section class="setup-section-block setup-admin-form-card setup-admin-password-card">
      <div class="setup-section-head">
        <div>
          <h3>Edit password</h3>
          <p>Update the signed-in administrator password.</p>
        </div>
      </div>
      <div class="setup-form-grid setup-admin-password-grid">
        ${renderSetupField('New password', 'setup-current-password', '', '', 'password', 'Use at least 8 characters.')}
        ${renderSetupField('Confirm password', 'setup-current-password-confirm', '', '', 'password')}
      </div>
      <div class="setup-inline-actions setup-admin-form-actions">
        <button type="button" class="btn btn-outline" data-setup-action="cancel-password">Cancel</button>
        <button type="button" class="btn btn-primary" data-setup-action="save-current-password">Save password</button>
      </div>
    </section>
  `;
}
function renderProStep() {
    const tier = (wizardState?.modules.license_tier || 'community').toLowerCase();
    const isCommunity = tier === 'community';
    return `
    <div class="setup-pro-panel">
      <div class="setup-pro-copy">
        <span class="setup-wizard-kicker">Licence</span>
        <h3>${isCommunity ? 'Licence and capabilities' : `Licence active (${escapeSectionHtml(tier.toUpperCase())})`}</h3>
        <p>${isCommunity ? 'Activate your Aegis commercial licence key or continue with Community Edition.' : `This installation is running verified ${escapeSectionHtml(tier)} features.`}</p>
      </div>

      ${isCommunity ? `
      <div class="setup-license-box" style="background: var(--bg-surface-2, rgba(255,255,255,0.03)); border: 1px solid var(--border-color, rgba(255,255,255,0.1)); border-radius: 8px; padding: 16px; margin: 16px 0;">
        <label for="setup-license-key" style="display: block; font-weight: 600; margin-bottom: 6px; font-size: 0.9rem;">Commercial Licence Key</label>
        <div style="display: flex; gap: 8px; align-items: center;">
          <input id="setup-license-key" class="settings-input text-mono" type="text" autocomplete="off" spellcheck="false" placeholder="AEGIS-PRO-..." style="flex: 1; font-family: monospace; letter-spacing: 0.5px;" />
          <button type="button" class="btn btn-primary" data-setup-action="activate-license" id="btn-setup-activate-license">Activate Licence</button>
        </div>
        <div id="setup-license-feedback" style="margin-top: 8px; font-size: 0.85rem; display: none;"></div>
        <p style="margin-top: 8px; margin-bottom: 0; font-size: 0.8rem; color: var(--text-muted, #888);">
          Validates securely with <code>license.divinelab.io</code>. Don't have a key? You can continue using the open-source Community Edition.
        </p>
      </div>
      ` : `
      <div class="setup-license-box setup-license-box--active" style="background: rgba(89, 171, 143, 0.08); border: 1px solid rgba(89, 171, 143, 0.28); border-radius: 8px; padding: 14px 18px; margin: 16px 0; display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 50%; background: #59ab8f; color: white; font-weight: bold; font-size: 14px;">✓</span>
          <div>
            <strong style="color: #59ab8f; font-size: 1rem;">Licence Activated (${escapeSectionHtml(tier.toUpperCase())})</strong>
            <div style="font-size: 0.85rem; color: var(--text-muted, #aaa);">All ${escapeSectionHtml(tier)} enterprise security sections and modules unlocked.</div>
          </div>
        </div>
        <button type="button" class="btn btn-outline" data-setup-action="open-license" style="font-size: 0.85rem;">Manage in Settings</button>
      </div>
      `}

      <div class="setup-pro-features">
        ${renderProFeature('Advanced analytics', 'Longer retention, richer traffic views, and investigation-friendly event history.')}
        ${renderProFeature('Managed rule operations', 'Safer WAF changes with reviewable updates and production-focused controls.')}
        ${renderProFeature('Priority response', 'Faster support windows for incidents, upgrades, and deployment issues.')}
        ${renderProFeature('Platform lifecycle', 'Licence controls, rollout workflows, and operational guardrails for larger environments.')}
      </div>

      <div class="setup-inline-actions">
        ${isCommunity ? '<button type="button" class="btn btn-outline" data-setup-action="open-license">View licence settings</button>' : ''}
      </div>
    </div>
  `;
}
async function activateSetupLicense() {
    const input = document.getElementById('setup-license-key');
    const feedback = document.getElementById('setup-license-feedback');
    const button = document.getElementById('btn-setup-activate-license');
    const key = input?.value.trim() || '';
    if (!key) {
        showLicenseErrorModal('Please enter a licence key before activating.');
        if (feedback) {
            feedback.style.display = 'block';
            feedback.style.color = 'var(--danger, #ef4444)';
            feedback.textContent = 'Please enter a valid licence key.';
        }
        return;
    }
    if (button) {
        button.disabled = true;
        button.textContent = 'Activating...';
    }
    if (feedback) {
        feedback.style.display = 'block';
        feedback.style.color = 'var(--text-muted, #888)';
        feedback.textContent = 'Verifying licence key with license.divinelab.io...';
    }
    try {
        const res = await api.requestResult('license/activate', 'POST', { key });
        if (res.error) {
            showLicenseErrorModal(res.error.message || 'Licence verification failed.');
            if (feedback) {
                feedback.style.display = 'block';
                feedback.style.color = 'var(--danger, #ef4444)';
                feedback.textContent = res.error.message || 'Licence verification failed.';
            }
            if (button) {
                button.disabled = false;
                button.textContent = 'Activate Licence';
            }
            return;
        }
        if (!res.data || !res.data.license) {
            showLicenseErrorModal('The licence activation response was invalid or empty.');
            if (button) {
                button.disabled = false;
                button.textContent = 'Activate Licence';
            }
            return;
        }
        const tier = res.data.license.licensed_tier || res.data.license.effective_tier || 'professional';
        if (wizardState) {
            wizardState.modules.license_tier = tier;
        }
        document.dispatchEvent(new CustomEvent('aegis:license-changed'));
        Toast.show(`Licence activated: ${tier.toUpperCase()} edition.`, 'success');
        renderSetupWizard();
        showLicenseCongratulationsModal(tier, {
            expiresAt: res.data.license.expires_at,
            offlineUntil: res.data.license.offline_until,
            status: res.data.license.status
        });
    }
    catch (err) {
        showLicenseErrorModal(err?.message || 'Licence verification failed.');
        if (feedback) {
            feedback.style.display = 'block';
            feedback.style.color = 'var(--danger, #ef4444)';
            feedback.textContent = err?.message || 'Licence verification failed. Check the key and network connection.';
        }
        if (button) {
            button.disabled = false;
            button.textContent = 'Activate Licence';
        }
    }
}
function renderProFeature(title, description) {
    return `
    <div class="setup-pro-feature">
      <strong>${escapeSectionHtml(title)}</strong>
      <span>${escapeSectionHtml(description)}</span>
    </div>
  `;
}
function renderReviewStep() {
    const state = requireWizardState();
    const theme = state.theme === 'dark' ? 'Dark' : 'Light';
    const controlText = storageStatusText(state.status.storage.control, 'PostgreSQL is not configured.');
    const analyticsText = storageStatusText(state.status.storage.analytics, 'ClickHouse analytics is disabled.');
    return `
    <div class="setup-step-copy">
      <p>Review the first-run choices before opening the console.</p>
    </div>
    <div class="setup-review-grid">
      ${renderReviewItem('UI mode', theme)}
      ${renderReviewItem('PostgreSQL', controlText)}
      ${renderReviewItem('ClickHouse', analyticsText)}
      ${renderReviewItem('Administrators', `${state.users.length || state.status.user_count} configured`)}
    </div>
    <div class="setup-review-note">
      Storage changes saved from this wizard are pending until Aegis restarts.
    </div>
  `;
}
function renderReviewItem(label, value) {
    return `
    <div class="setup-review-item">
      <span>${escapeSectionHtml(label)}</span>
      <strong>${escapeSectionHtml(value)}</strong>
    </div>
  `;
}
function renderSetupField(label, id, value, disabled = '', type = 'text', hint = '', className = '') {
    return `
    <label class="setup-field${className ? ` ${escapeSectionAttr(className)}` : ''}">
      <span>${escapeSectionHtml(label)}</span>
      <input id="${id}" type="${type}" value="${escapeSectionAttr(value)}" class="settings-input"${disabled} autocomplete="off">
      ${hint ? `<small>${escapeSectionHtml(hint)}</small>` : ''}
    </label>
  `;
}
function renderStorageSettingsField(label, id, value, disabled = '', type = 'text', hint = '', attrs = '') {
    const hintId = hint ? `${id}-hint` : '';
    return `
    <div class="settings-field">
      <label for="${id}">${escapeSectionHtml(label)}</label>
      <input id="${id}" type="${type}" value="${escapeSectionAttr(value)}" autocomplete="off" class="settings-input"${disabled}${attrs}${hintId ? ` aria-describedby="${hintId}"` : ''}>
      ${hint ? `<span id="${hintId}" class="settings-hint">${escapeSectionHtml(hint)}</span>` : ''}
    </div>
  `;
}
function renderClickHouseWarningModal() {
    return `
    <div class="setup-inline-modal-backdrop">
      <section class="setup-inline-modal" role="dialog" aria-modal="true" aria-labelledby="setup-clickhouse-warning-title">
        <span class="setup-wizard-kicker">Analytics storage</span>
        <h3 id="setup-clickhouse-warning-title">Continue without ClickHouse?</h3>
        <p>Analytics dashboards and long-term event reporting will not work until ClickHouse is configured.</p>
        <div class="setup-inline-modal-actions">
          <button type="button" class="btn btn-outline" data-setup-action="close-clickhouse-warning">Configure ClickHouse</button>
          <button type="button" class="btn btn-primary" data-setup-action="continue-without-clickhouse">Continue anyway</button>
        </div>
      </section>
    </div>
  `;
}
function storageStatusText(status, emptyMessage) {
    if (status.restart_required)
        return 'Pending configuration is saved. Restart Aegis to apply it.';
    if (status.available)
        return 'Active connection is healthy.';
    if (status.mode === 'disabled')
        return 'Analytics is disabled.';
    if (status.configured && status.active)
        return 'Active connection is currently unavailable.';
    if (status.environment_locked)
        return 'Configuration is managed outside Aegis.';
    return emptyMessage;
}
async function testPostgreSQLConnection() {
    const input = postgreSQLInput();
    if (!validatePostgreSQLInput(input, true))
        return;
    const passwordInput = AdminDOM.getInput('setup-postgresql-password');
    setWizardBusy(true);
    Toast.show('Testing PostgreSQL connection...', 'info');
    try {
        const result = await setupRequestResult('storage/control/postgresql/preflight', 'setup/storage/control/postgresql/preflight', 'POST', {
            host: input.host,
            port: input.port,
            database: input.database,
            username: input.username,
            password: input.password,
            ssl_mode: input.sslMode
        });
        if (result.error || result.data?.status !== 'ok') {
            postgreSQLVerifiedSignature = '';
            updateDatabaseGateUI();
            Toast.show('PostgreSQL connection could not be established.', 'error');
            return;
        }
        postgreSQLVerifiedSignature = postgreSQLConnectionSignature(input);
        updateDatabaseGateUI();
        Toast.show('PostgreSQL connection succeeded. Nothing was saved.', 'success');
    }
    finally {
        if (passwordInput)
            passwordInput.value = '';
        setWizardBusy(false);
    }
}
async function savePostgreSQLConfiguration() {
    const input = postgreSQLInput();
    if (!validatePostgreSQLInput(input, false))
        return;
    setWizardBusy(true);
    try {
        const result = await setupRequestResult('storage/control/postgresql/pending', 'setup/storage/control/postgresql/pending', 'POST', {
            host: input.host,
            port: input.port,
            database: input.database,
            username: input.username,
            password_secret_ref: input.secretRef,
            ssl_mode: input.sslMode
        });
        if (result.error || result.data?.status !== 'pending') {
            Toast.show(result.error?.message || 'PostgreSQL configuration could not be saved.', 'error');
            return;
        }
        Toast.show('PostgreSQL configuration saved as pending.', 'success');
        await refreshSetupRuntimeState();
        renderSetupWizard();
    }
    finally {
        setWizardBusy(false);
    }
}
async function testClickHouseConnection() {
    const input = clickHouseInput();
    if (!validateClickHouseInput(input, true))
        return;
    const passwordInput = AdminDOM.getInput('setup-clickhouse-password');
    setWizardBusy(true);
    Toast.show('Testing ClickHouse connection...', 'info');
    try {
        const result = await setupRequestResult('storage/analytics/clickhouse/preflight', 'setup/storage/analytics/clickhouse/preflight', 'POST', {
            host: input.host,
            port: input.port,
            database: input.database,
            username: input.username,
            password: input.password,
            secure: input.secure
        });
        if (result.error || result.data?.status !== 'ok') {
            Toast.show('ClickHouse connection could not be established.', 'error');
            return;
        }
        Toast.show('ClickHouse connection succeeded. Nothing was saved.', 'success');
    }
    finally {
        if (passwordInput)
            passwordInput.value = '';
        setWizardBusy(false);
    }
}
async function saveClickHouseConfiguration() {
    const input = clickHouseInput();
    if (!validateClickHouseInput(input, false))
        return;
    setWizardBusy(true);
    try {
        const result = await setupRequestResult('storage/analytics/clickhouse/pending', 'setup/storage/analytics/clickhouse/pending', 'POST', {
            mode: input.mode,
            host: input.host,
            port: input.port,
            database: input.database,
            username: input.username,
            password_secret_ref: input.secretRef,
            secure: input.secure
        });
        if (result.error || result.data?.status !== 'pending') {
            Toast.show(result.error?.message || 'ClickHouse configuration could not be saved.', 'error');
            return;
        }
        Toast.show('ClickHouse configuration saved as pending.', 'success');
        await refreshSetupRuntimeState();
        renderSetupWizard();
    }
    finally {
        setWizardBusy(false);
    }
}
async function createAdminAccount() {
    const role = findSuperAdminRole();
    if (!role) {
        Toast.show('Super administrator role is unavailable.', 'error');
        return;
    }
    const username = AdminDOM.inputValue('setup-admin-username').trim();
    const email = AdminDOM.inputValue('setup-admin-email').trim();
    const password = AdminDOM.inputValue('setup-admin-password');
    if (!username || !email || password.length < 8) {
        Toast.show('Enter a username, valid email, and password with at least 8 characters.', 'error');
        return;
    }
    setWizardBusy(true);
    try {
        const firstRun = setupFirstRunPublicMode();
        const result = firstRun
            ? await requestPublicSetupResult('setup/first-admin', 'POST', { username, email, password })
            : await api.requestResult('users', 'POST', {
                username,
                email,
                password,
                role_id: role.id
            });
        if (result.error || result.data?.status !== 'created') {
            Toast.show(result.error?.message || 'Administrator account could not be created.', 'error');
            return;
        }
        if (firstRun) {
            api.csrfToken = result.data.csrf_token || null;
            api.currentUser = {
                id: result.data.id,
                username: result.data.username || username,
                roleId: result.data.role_id || role.id,
                permissions: result.data.permissions || [],
                features: [],
                edition: wizardState?.modules.license_tier
            };
        }
        Toast.show('Administrator account created.', 'success');
        passwordEditOpen = false;
        AdminDOM.getInput('setup-admin-username').value = '';
        AdminDOM.getInput('setup-admin-email').value = '';
        AdminDOM.getInput('setup-admin-password').value = '';
        if (firstRun && wizardState) {
            wizardState.users = [{
                    id: result.data.id,
                    username: result.data.username || username,
                    email,
                    is_active: true,
                    role: { name: role.name }
                }];
            wizardState.status.user_count = 1;
        }
        else {
            await refreshSetupUsers();
        }
        renderSetupWizard();
    }
    finally {
        setWizardBusy(false);
    }
}
async function updateCurrentAdminPassword() {
    const password = AdminDOM.inputValue('setup-current-password');
    const confirm = AdminDOM.inputValue('setup-current-password-confirm');
    if (!password || password.length < 8) {
        Toast.show('Password must be at least 8 characters.', 'error');
        return;
    }
    if (password !== confirm) {
        Toast.show('Passwords do not match.', 'error');
        return;
    }
    setWizardBusy(true);
    try {
        const result = await api.requestResult('profile', 'PUT', { password });
        if (result.error) {
            Toast.show(result.error.message || 'Password could not be updated.', 'error');
            return;
        }
        Toast.show('Password updated. Sign in again to continue.', 'success');
        window.setTimeout(() => {
            window.location.href = '/admin/login';
        }, 500);
    }
    finally {
        setWizardBusy(false);
    }
}
async function finishSetupWizard() {
    setWizardBusy(true);
    try {
        const result = await api.requestResult('setup/complete', 'POST', {});
        if (result.error || result.data?.completed !== true) {
            Toast.show(result.error?.message || 'Setup could not be completed.', 'error');
            return;
        }
        const root = AdminDOM.getById('setup-wizard-root');
        if (root)
            root.innerHTML = '';
        wizardState = null;
        deactivateSetupShell();
        Toast.show('Setup complete. Welcome to Aegis.', 'success');
        router.navigate('dashboard');
    }
    finally {
        setWizardBusy(false);
    }
}
async function refreshSetupRuntimeState() {
    if (!wizardState)
        return;
    const [status, bootstrap] = await Promise.all([
        fetchJSON('/api/setup/status'),
        fetchJSON('/api/setup/bootstrap')
    ]);
    if (status)
        wizardState.status = status;
    if (bootstrap?.config)
        wizardState.config = bootstrap.config;
    if (bootstrap?.roles)
        wizardState.roles = bootstrap.roles;
    if (bootstrap?.modules)
        wizardState.modules = bootstrap.modules;
    if (bootstrap?.users)
        wizardState.users = bootstrap.users;
}
async function refreshSetupUsers() {
    if (!wizardState)
        return;
    const bootstrap = await fetchJSON('/api/setup/bootstrap');
    if (bootstrap?.users) {
        wizardState.users = bootstrap.users;
        wizardState.status.user_count = bootstrap.users.length;
    }
}
function activateSetupShell() {
    document.body.classList.add('setup-wizard-active');
}
function deactivateSetupShell() {
    document.body.classList.remove('setup-wizard-active');
}
function advanceSetupStep() {
    activeStep = Math.min(steps.length, activeStep + 1);
    renderSetupWizard();
}
function postgreSQLReadyForSetup(status = wizardState?.status.storage.control) {
    if (!status)
        return false;
    if (status.environment_locked)
        return status.configured;
    if (status.configured && status.available)
        return true;
    return postgreSQLVerifiedSignature !== '' && postgreSQLVerifiedSignature === currentPostgreSQLSignature();
}
function postgreSQLGateText(status = wizardState?.status.storage.control) {
    if (!status)
        return 'Test PostgreSQL before continuing.';
    if (status.environment_locked && status.configured)
        return 'PostgreSQL is managed outside Aegis.';
    if (status.configured && status.available)
        return 'PostgreSQL is connected. You can continue.';
    if (postgreSQLReadyForSetup(status))
        return 'PostgreSQL connection tested. You can continue.';
    return 'Test PostgreSQL successfully before continuing.';
}
function updateDatabaseGateUI() {
    if (activeStep !== 2)
        return;
    const root = AdminDOM.getById('setup-wizard-root');
    if (!root)
        return;
    const nextButton = AdminDOM.query('.setup-next[data-setup-action="next"]', root);
    if (nextButton) {
        nextButton.disabled = wizardBusy || !postgreSQLReadyForSetup();
        nextButton.setAttribute('aria-disabled', nextButton.disabled ? 'true' : 'false');
    }
    const gate = AdminDOM.getById('setup-postgresql-gate');
    if (gate) {
        const ready = postgreSQLReadyForSetup();
        gate.classList.toggle('is-ready', ready);
        gate.textContent = postgreSQLGateText();
    }
}
function adminReadyForSetup(state = wizardState) {
    return hasExistingAdminAccounts(state);
}
function updateAdminGateUI() {
    if (activeStep !== 3)
        return;
    const root = AdminDOM.getById('setup-wizard-root');
    if (!root)
        return;
    const nextButton = AdminDOM.query('.setup-next[data-setup-action="next"]', root);
    if (nextButton) {
        nextButton.disabled = wizardBusy || !adminReadyForSetup();
        nextButton.setAttribute('aria-disabled', nextButton.disabled ? 'true' : 'false');
    }
}
function setupFirstRunPublicMode(state = wizardState) {
    return Boolean(state?.status.setup_required && state.status.user_count === 0 && !api.currentUser);
}
function shouldPromptForMissingClickHouse() {
    if (activeStep !== 2 || clickHouseSkipConfirmed || !wizardState)
        return false;
    const status = wizardState.status.storage.analytics;
    if (status.environment_locked || status.configured)
        return false;
    return !validSecretRef(AdminDOM.inputValue('setup-clickhouse-secret').trim());
}
function desiredClickHouseMode() {
    const mode = wizardState?.config.storage?.analytics?.mode;
    return mode === 'required' ? 'required' : 'optional';
}
function hasExistingAdminAccounts(state = wizardState) {
    if (!state)
        return false;
    return state.users.length > 0 || state.status.user_count > 0;
}
function isCurrentSetupUser(user, currentUserId) {
    const activeUser = api.currentUser;
    if (currentUserId && String(user.id) === currentUserId)
        return true;
    return Boolean(activeUser?.username && user.username === activeUser.username);
}
function setWizardBusy(isBusy) {
    wizardBusy = isBusy;
    const root = AdminDOM.getById('setup-wizard-root');
    if (!root)
        return;
    root.classList.toggle('is-busy', isBusy);
    AdminDOM.queryAll('button', root).forEach(button => {
        const action = button.dataset.setupAction || '';
        const locked = button.dataset.setupLocked === 'true';
        const blockedByDatabaseGate = action === 'next' && activeStep === 2 && !postgreSQLReadyForSetup();
        const blockedByAdminGate = action === 'next' && activeStep === 3 && !adminReadyForSetup();
        button.disabled = isBusy || locked || blockedByDatabaseGate || blockedByAdminGate || (action === 'back' && activeStep === 0);
        button.setAttribute('aria-disabled', button.disabled ? 'true' : 'false');
    });
}
function postgreSQLInput() {
    return {
        host: AdminDOM.inputValue('setup-postgresql-host').trim(),
        port: Number(AdminDOM.inputValue('setup-postgresql-port')),
        database: AdminDOM.inputValue('setup-postgresql-database').trim(),
        username: AdminDOM.inputValue('setup-postgresql-username').trim(),
        password: AdminDOM.inputValue('setup-postgresql-password'),
        secretRef: AdminDOM.inputValue('setup-postgresql-secret').trim(),
        sslMode: AdminDOM.getSelect('setup-postgresql-ssl')?.value || 'disable'
    };
}
function clickHouseInput() {
    return {
        mode: desiredClickHouseMode(),
        host: AdminDOM.inputValue('setup-clickhouse-host').trim(),
        port: Number(AdminDOM.inputValue('setup-clickhouse-port')),
        database: AdminDOM.inputValue('setup-clickhouse-database').trim(),
        username: AdminDOM.inputValue('setup-clickhouse-username').trim(),
        password: AdminDOM.inputValue('setup-clickhouse-password'),
        secretRef: AdminDOM.inputValue('setup-clickhouse-secret').trim(),
        secure: Boolean(AdminDOM.getInput('setup-clickhouse-secure')?.checked)
    };
}
function currentPostgreSQLSignature() {
    const input = postgreSQLInput();
    return postgreSQLConnectionSignature(input);
}
function postgreSQLConnectionSignature(input) {
    return [
        input.host,
        String(input.port),
        input.database,
        input.username,
        input.sslMode
    ].join('\u001f');
}
function validatePostgreSQLInput(input, requirePassword) {
    if (!input.host || !validPort(input.port) || !input.database || !input.username) {
        Toast.show('Enter valid PostgreSQL connection details.', 'error');
        return false;
    }
    if (requirePassword && !input.password) {
        Toast.show('Enter the PostgreSQL password for this test.', 'error');
        return false;
    }
    if (!requirePassword && !validSecretRef(input.secretRef)) {
        Toast.show('Use an environment variable secret reference, for example env:AEGIS_CONTROL_DB_PASSWORD.', 'error');
        return false;
    }
    if (!postgreSQLSSLModes.includes(input.sslMode)) {
        Toast.show('Select a supported PostgreSQL TLS mode.', 'error');
        return false;
    }
    return true;
}
function validateClickHouseInput(input, requirePassword) {
    if (!input.host || !validPort(input.port) || !input.database || !input.username) {
        Toast.show('Enter valid ClickHouse connection details.', 'error');
        return false;
    }
    if (requirePassword && !input.password) {
        Toast.show('Enter the ClickHouse password for this test.', 'error');
        return false;
    }
    if (!requirePassword && !validSecretRef(input.secretRef)) {
        Toast.show('Use an environment variable secret reference, for example env:AEGIS_ANALYTICS_DB_PASSWORD.', 'error');
        return false;
    }
    return true;
}
function validPort(port) {
    return Number.isInteger(port) && Number(port) >= 1 && Number(port) <= 65535;
}
function validSecretRef(value) {
    return /^env:[A-Z_][A-Z0-9_]*$/.test(value);
}
function normalizedSecretRef(value) {
    return typeof value === 'string' && value !== '[REDACTED]' ? value : '';
}
function findSuperAdminRole() {
    const roles = wizardState?.roles || [];
    return roles.find(role => role.name === 'super_admin') || roles[0] || null;
}
function getStoredTheme() {
    try {
        return window.localStorage.getItem(THEME_STORAGE_KEY) === 'light' ? 'light' : 'dark';
    }
    catch {
        return 'dark';
    }
}
function applySetupTheme(theme) {
    if (wizardState)
        wizardState.theme = theme;
    document.documentElement.dataset.theme = theme === 'dark' ? 'dark' : 'light';
    try {
        window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    }
    catch {
        // Local storage can be unavailable in restricted browser contexts.
    }
    const switchInput = AdminDOM.getById('admin-theme-switch');
    const label = AdminDOM.getById('theme-state-label');
    if (switchInput) {
        switchInput.checked = theme === 'dark';
        switchInput.setAttribute('aria-checked', theme === 'dark' ? 'true' : 'false');
    }
    if (label)
        label.textContent = theme === 'dark' ? 'Dark' : 'Light';
    renderSetupWizard();
}
function requireWizardState() {
    if (!wizardState)
        throw new Error('Setup wizard state is not available');
    return wizardState;
}
