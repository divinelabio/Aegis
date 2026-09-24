/**
 * Captcha module configuration
 * Source of truth: web/admin/src/modules/captcha-config.ts
 * Runtime output: web/admin/dist/js/modules/captcha-config.js
 */
import * as AdminEvents from '../core/events.js';
import * as AdminDOM from '../core/dom.js';
import { notify } from '../core/notify.js';
import { api } from '../api.js';
import { SectionUI } from '../sections/ui-components.js';
function captchaCfgIsRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function createDefaultCaptchaConfig() {
    return {
        enabled: false,
        provider_name: 'recaptcha_v2',
        site_key: '',
        secret_key_ref: ''
    };
}
function asCaptchaModuleConfig(value) {
    if (!captchaCfgIsRecord(value))
        return createDefaultCaptchaConfig();
    return { ...createDefaultCaptchaConfig(), ...value };
}
async function captchaCfgParseJson(response) {
    try {
        const raw = await response.text();
        if (!raw.trim())
            return null;
        return JSON.parse(raw);
    }
    catch {
        return null;
    }
}
function captchaCfgErrorMessage(data, fallback) {
    if (!data)
        return fallback;
    if (typeof data.error === 'string' && data.error.trim())
        return data.error.trim();
    if (typeof data.message === 'string' && data.message.trim())
        return data.message.trim();
    if (typeof data.detail === 'string' && data.detail.trim())
        return data.detail.trim();
    return fallback;
}
function captchaCfgEscapeAttribute(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}
const captchaProviders = [
    { id: 'recaptcha_v2', name: 'ReCaptcha V2', desc: 'Google' },
    { id: 'recaptcha_v3', name: 'ReCaptcha V3', desc: 'Google (Invisible)' },
    { id: 'turnstile', name: 'Turnstile', desc: 'Cloudflare' },
    { id: 'hcaptcha', name: 'hCaptcha', desc: 'Intuition Machines' },
    { id: 'mtcaptcha', name: 'MTCaptcha', desc: 'MTCaptcha' },
    { id: 'friendlycaptcha', name: 'Friendly Captcha', desc: 'Privacy-first verification' }
];
const captchaProviderLogos = {
    recaptcha_v2: `
    <svg viewBox="0 0 40 40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="8" fill="#fff"></rect>
      <path d="M20 7a13 13 0 0 1 12 8" fill="none" stroke="#4285f4" stroke-width="4" stroke-linecap="round"></path>
      <path d="M32 15a13 13 0 0 1-2 13" fill="none" stroke="#34a853" stroke-width="4" stroke-linecap="round"></path>
      <path d="M30 28a13 13 0 0 1-13 4" fill="none" stroke="#fbbc05" stroke-width="4" stroke-linecap="round"></path>
      <path d="M17 32A13 13 0 0 1 8 12" fill="none" stroke="#ea4335" stroke-width="4" stroke-linecap="round"></path>
      <path d="M13.5 19.5l4.2 4.2 8.8-9.4" fill="none" stroke="#4285f4" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"></path>
    </svg>
  `,
    recaptcha_v3: `
    <svg viewBox="0 0 40 40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="8" fill="#fff"></rect>
      <path d="M20 7a13 13 0 0 1 12 8" fill="none" stroke="#4285f4" stroke-width="4" stroke-linecap="round"></path>
      <path d="M32 15a13 13 0 0 1-2 13" fill="none" stroke="#34a853" stroke-width="4" stroke-linecap="round"></path>
      <path d="M30 28a13 13 0 0 1-13 4" fill="none" stroke="#fbbc05" stroke-width="4" stroke-linecap="round"></path>
      <path d="M17 32A13 13 0 0 1 8 12" fill="none" stroke="#ea4335" stroke-width="4" stroke-linecap="round"></path>
      <text x="20" y="24" text-anchor="middle" font-family="Arial, sans-serif" font-size="12" font-weight="700" fill="#4285f4">v3</text>
    </svg>
  `,
    turnstile: `
    <svg viewBox="0 0 40 40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="8" fill="var(--control-accent-soft)"></rect>
      <path d="M12 24.5h18.3a5.1 5.1 0 0 0-1.3-10 7.6 7.6 0 0 0-14.7 2 4.2 4.2 0 0 0-2.3 8z" fill="#f38020"></path>
      <path d="M15 26.2h13.7c2 0 3.7-.9 4.8-2.3-.8 3.7-4.1 6.5-8 6.5H14.8a4.8 4.8 0 0 1 .2-4.2z" fill="#faae40"></path>
    </svg>
  `,
    hcaptcha: `
    <svg viewBox="0 0 40 40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="8" fill="#eef2ff"></rect>
      <circle cx="20" cy="20" r="12" fill="#346df1"></circle>
      <path d="M15 13v14M25 13v14M15 20h10" fill="none" stroke="#fff" stroke-width="3.4" stroke-linecap="round"></path>
    </svg>
  `,
    mtcaptcha: `
    <svg viewBox="0 0 40 40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="8" fill="#f1f5f9"></rect>
      <rect x="10" y="11" width="20" height="18" rx="5" fill="#0f766e"></rect>
      <text x="20" y="24" text-anchor="middle" font-family="Arial, sans-serif" font-size="10" font-weight="800" fill="#fff">MT</text>
    </svg>
  `,
    friendlycaptcha: `
    <svg viewBox="0 0 40 40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="8" fill="#fff8cc"></rect>
      <path d="M29.5 18.5a10.5 10.5 0 1 1-19 0" fill="none" stroke="#f5c400" stroke-width="4" stroke-linecap="round"></path>
      <circle cx="15.5" cy="17" r="1.8" fill="#1f2937"></circle>
      <circle cx="24.5" cy="17" r="1.8" fill="#1f2937"></circle>
    </svg>
  `
};
export const CaptchaConfig = {
    config: createDefaultCaptchaConfig(),
    eventsBound: false,
    async init() {
        this.bindEvents();
        await this.loadConfig();
        this.render();
    },
    bindEvents() {
        if (this.eventsBound)
            return;
        this.eventsBound = true;
        AdminEvents.delegateEvent(document, 'click', '#captcha-config-content [data-action="captcha-select-provider"]', (_event, target) => {
            const providerId = target.dataset.providerId;
            if (!providerId)
                return;
            this.updateField('provider_name', providerId);
            this.render();
            SectionUI.markSaveActionBarDirty('data-action');
        });
        AdminEvents.delegateEvent(document, 'click', '#captcha-config-content [data-action="captcha-save"]', event => {
            event.preventDefault();
            void this.save();
        });
        AdminEvents.delegateEvent(document, 'click', '#captcha-config-content [data-action="captcha-reset"]', event => {
            event.preventDefault();
            void this.loadConfig().then(() => this.render()).finally(() => SectionUI.markSaveActionBarClean('data-action'));
        });
        AdminEvents.delegateEvent(document, 'input', '#captcha-config-content [data-action="captcha-update-text"]', (_event, target) => {
            const field = target.dataset.field;
            if (!field)
                return;
            this.updateField(field, target.value);
            SectionUI.markSaveActionBarDirty('data-action');
        });
        AdminEvents.delegateEvent(document, 'change', '#captcha-config-content [data-action="captcha-toggle-enabled"]', (_event, target) => {
            this.updateField('enabled', target.checked);
            const status = AdminDOM.query('#captcha-config-content [data-captcha-section-status]');
            if (status) {
                status.textContent = target.checked ? 'Enabled' : 'Disabled';
                status.className = `config-status-pill tone-${target.checked ? 'success' : 'neutral'}`;
            }
            SectionUI.markSaveActionBarDirty('data-action');
        });
        AdminEvents.delegateEvent(document, 'input', '#captcha-config-content [data-action="captcha-update-score"]', (_event, target) => {
            this.updateField('score_threshold', Number.parseFloat(target.value));
            SectionUI.markSaveActionBarDirty('data-action');
        });
    },
    async loadConfig() {
        try {
            const response = await fetch('/api/modules/captcha/config');
            const data = await captchaCfgParseJson(response);
            if (!response.ok) {
                throw new Error(captchaCfgErrorMessage(data, 'Failed to load captcha config'));
            }
            this.config = asCaptchaModuleConfig(data);
        }
        catch (error) {
            console.error('Failed to load captcha config', error);
            this.config = createDefaultCaptchaConfig();
        }
    },
    render() {
        this.renderOperator();
    },
    renderOperator() {
        const app = AdminDOM.getById('captcha-config-content');
        if (!app)
            return;
        const config = this.config;
        const sectionEnabled = config.enabled === true;
        const isMTCaptcha = config.provider_name === 'mtcaptcha';
        const isFriendlyCaptcha = config.provider_name === 'friendlycaptcha';
        const secretLabel = isFriendlyCaptcha ? 'API key reference' : (isMTCaptcha ? 'Private key reference' : 'Secret key reference');
        const secretMigrationRequired = config.secret_key_migration_required === true;
        const secretHint = secretMigrationRequired
            ? 'Add a secret reference before saving to keep this credential protected.'
            : 'Use an environment reference, for example env:AEGIS_CAPTCHA_SECRET. Leave blank to retain the configured reference.';
        const providerCards = captchaProviders.map(provider => `
      <button type="button"
              class="captcha-provider-card ${config.provider_name === provider.id ? 'is-active' : ''}"
              data-action="captcha-select-provider"
              data-provider-id="${provider.id}"
              aria-pressed="${config.provider_name === provider.id}">
        <span class="captcha-provider-mark" aria-hidden="true">${captchaProviderLogos[provider.id]}</span>
        <span class="captcha-provider-copy">
          <strong>${provider.name}</strong>
          <small>${provider.desc}</small>
        </span>
        <span class="captcha-provider-check" aria-hidden="true">
          <svg viewBox="0 0 16 16"><path d="m3.5 8 2.8 2.8L12.5 4.8"></path></svg>
        </span>
      </button>
    `).join('');
        const credentials = `
      <div class="captcha-credentials-panel">
        <div class="captcha-field-grid">
          <div class="settings-field">
            <label for="captcha-site-key">Site key</label>
            <input id="captcha-site-key" type="text" value="${captchaCfgEscapeAttribute(config.site_key)}" class="settings-input"
                   placeholder="Public key"
                   data-action="captcha-update-text"
                   data-field="site_key">
          </div>
          <div class="settings-field">
            <label for="captcha-secret-key-ref">${secretLabel}</label>
            <input id="captcha-secret-key-ref" type="text" value="${captchaCfgEscapeAttribute(config.secret_key_ref)}" class="settings-input"
                   placeholder="env:AEGIS_CAPTCHA_SECRET"
                   autocomplete="off"
                   data-action="captcha-update-text"
                   data-field="secret_key_ref">
            <span class="settings-hint">${secretHint}</span>
          </div>
          ${config.provider_name === 'recaptcha_v3' ? `
            <div class="settings-field captcha-score-field">
              <label for="captcha-score-threshold">Score threshold</label>
              <input id="captcha-score-threshold" type="number" step="0.1" min="0" max="1" value="${captchaCfgEscapeAttribute(config.score_threshold ?? 0.5)}" class="settings-input"
                     data-action="captcha-update-score">
              <span class="settings-hint">Requests below this score are treated as automated.</span>
            </div>
          ` : ''}
        </div>
        <div class="captcha-form-note">
          <span class="captcha-note-icon" aria-hidden="true">!</span>
          <span>Provider credentials are resolved only from the server environment.</span>
        </div>
      </div>
    `;
        const content = `
      <div class="captcha-operator-stack">
        <div class="captcha-operator-grid">
          ${SectionUI.renderOperatorSection('Provider selection', `
            <div class="operator-control-list captcha-provider-list">
              ${providerCards}
            </div>
          `, {
            subtitle: 'Choose the verification service used by protected flows.',
            className: 'captcha-section'
        })}

          ${SectionUI.renderOperatorSection('Provider credentials', credentials, {
            subtitle: 'Connect the selected service to your tenant.',
            className: 'captcha-section'
        })}
        </div>

        ${SectionUI.renderSaveActionBar({
            actionAttr: 'data-action',
            resetAction: 'captcha-reset',
            saveAction: 'captcha-save',
            saveLabel: 'Save Changes'
        })}
      </div>
    `;
        app.innerHTML = SectionUI.renderOperatorFrame({
            title: 'CAPTCHA',
            kicker: 'Modules',
            subtitle: 'Connect a verification provider for protected application flows.',
            actions: SectionUI.renderSwitch({
                checked: sectionEnabled,
                attrs: 'title="Enable or disable Captcha" data-action="captcha-toggle-enabled" aria-label="Enable Captcha"'
            }),
            content,
            className: 'captcha-operator-frame flow-operator-frame'
        });
    },
    updateField(key, value) {
        this.config[key] = value;
    },
    async save() {
        const siteKey = String(this.config.site_key || '').trim();
        const secretKeyRef = String(this.config.secret_key_ref || '').trim();
        const secretConfigured = this.config.secret_key_configured === true;
        const secretMigrationRequired = this.config.secret_key_migration_required === true;
        if (!siteKey || (!secretKeyRef && (!secretConfigured || secretMigrationRequired))) {
            this.showToast('A Site Key and environment credential reference are required to configure CAPTCHA', 'error');
            return;
        }
        if (secretKeyRef && !/^env:[A-Z_][A-Z0-9_]*$/.test(secretKeyRef)) {
            this.showToast('Use an environment variable reference such as env:AEGIS_CAPTCHA_SECRET', 'error');
            return;
        }
        let scoreThreshold = Number(this.config.score_threshold ?? 0);
        if (this.config.provider_name === 'recaptcha_v3') {
            scoreThreshold = Number.parseFloat(String(this.config.score_threshold ?? 0.5));
            if (Number.isNaN(scoreThreshold) || scoreThreshold < 0 || scoreThreshold > 1) {
                this.showToast('Score Threshold must be between 0.0 and 1.0', 'error');
                return;
            }
            this.config.score_threshold = scoreThreshold;
        }
        try {
            if (!api.csrfToken && !(await api.checkSession())) {
                throw new Error('No active session is available to save CAPTCHA settings.');
            }
            const payload = {
                enabled: this.config.enabled === true,
                provider_name: String(this.config.provider_name || ''),
                site_key: siteKey,
                secret_key_ref: secretKeyRef,
                score_threshold: scoreThreshold
            };
            const response = await fetch('/api/modules/captcha/config', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                    ...(api.csrfToken ? { 'X-CSRF-Token': api.csrfToken } : {})
                },
                body: JSON.stringify(payload)
            });
            const data = await captchaCfgParseJson(response);
            if (!response.ok) {
                this.showToast(captchaCfgErrorMessage(data, 'Failed to save settings'), 'error');
                return;
            }
            this.config.secret_key_ref = '';
            this.config.secret_key_configured = true;
            this.config.secret_key_migration_required = false;
            this.showToast('Settings saved successfully');
            SectionUI.markSaveActionBarClean('data-action');
        }
        catch (error) {
            const message = error instanceof Error ? error.message : 'Failed to save settings';
            this.showToast(message, 'error');
        }
    },
    showToast(message, type = 'success') {
        notify(message, type);
    }
};
