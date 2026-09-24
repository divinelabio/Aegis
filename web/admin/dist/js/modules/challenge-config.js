/**
 * Smart challenge module configuration
 * Source of truth: web/admin/src/modules/challenge-config.ts
 * Runtime output: web/admin/dist/js/modules/challenge-config.js
 */
import * as AdminEvents from '../core/events.js';
import * as AdminDOM from '../core/dom.js';
import { notify } from '../core/notify.js';
import { SectionUI } from '../sections/ui-components.js';
const INTERACTIVE_VERIFICATION_METHODS = [
    { id: 'hold', label: 'Hold to verify' },
    { id: 'click', label: 'Click to verify' },
    { id: 'slide', label: 'Slide to verify' },
    { id: 'sequence', label: 'Number sequence' },
    { id: 'match', label: 'Symbol match' }
];
function challengeCfgIsRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function createDefaultChallengeConfig() {
    return {
        enabled: true,
        theme: 'dark',
        custom_title: 'Checking your browser...',
        custom_message: 'Please wait a moment while we verify your request.',
        mode: 'managed',
        invisible_enabled: true,
        managed_enabled: true,
        interactive_enabled: true,
        interactive_style: 'hold',
        captcha_enabled: false,
        escalation_policy: 'progressive',
        cooldown_seconds: 1800,
        max_failures: 3,
        failure_action: 'block',
        cookie_ttl: 3600
    };
}
function createDefaultCaptchaConfigForChallenge() {
    return {
        enabled: false,
        provider_name: 'recaptcha_v2',
        site_key: '',
        secret_key: ''
    };
}
function asChallengeModuleConfig(value) {
    if (!challengeCfgIsRecord(value))
        return createDefaultChallengeConfig();
    return {
        ...createDefaultChallengeConfig(),
        ...value,
        enabled: value.enabled !== false,
        interactive_style: normalizeInteractiveVerificationMethod(value.interactive_style)
    };
}
function asChallengeCaptchaConfig(value) {
    if (!challengeCfgIsRecord(value))
        return createDefaultCaptchaConfigForChallenge();
    return { ...createDefaultCaptchaConfigForChallenge(), ...value };
}
async function challengeCfgParseJson(response) {
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
function challengeCfgErrorMessage(data, fallback) {
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
function challengeCfgEscapeHTML(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
function normalizeInteractiveVerificationMethod(value) {
    return value === 'click' || value === 'slide' || value === 'sequence' || value === 'match' ? value : 'hold';
}
function shuffleChallengePreviewValues(values) {
    const shuffled = [...values];
    const randomValues = new Uint32Array(shuffled.length);
    window.crypto.getRandomValues(randomValues);
    for (let index = shuffled.length - 1; index > 0; index -= 1) {
        const swapIndex = randomValues[index] % (index + 1);
        [shuffled[index], shuffled[swapIndex]] = [shuffled[swapIndex], shuffled[index]];
    }
    return shuffled;
}
function createSequencePreview() {
    const sequence = shuffleChallengePreviewValues([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).slice(0, 3);
    if (sequence[0] === 1 && sequence[1] === 2 && sequence[2] === 3) {
        [sequence[0], sequence[2]] = [sequence[2], sequence[0]];
    }
    return { sequence, choices: shuffleChallengePreviewValues(sequence) };
}
function createSymbolPreview() {
    const choices = shuffleChallengePreviewValues(['◆', '●', '▲', '■', '★', '✚', '⬟', '⬢', '◇', '○', '△', '□']).slice(0, 3);
    return {
        target: choices[window.crypto.getRandomValues(new Uint32Array(1))[0] % choices.length],
        choices: shuffleChallengePreviewValues(choices)
    };
}
function challengeShowToast(message, type = 'info') {
    notify(message, type);
}
export const ChallengeConfig = {
    config: createDefaultChallengeConfig(),
    captchaConfig: null,
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
        AdminEvents.delegateEvent(document, 'click', '#challenge-config-content [data-action="challenge-set-theme"]', (event, target) => {
            event.preventDefault();
            const theme = target.dataset.challengeTheme || target.dataset.theme;
            if (!theme)
                return;
            this.updateField('theme', theme);
            this.render();
            SectionUI.markSaveActionBarDirty('data-action');
        });
        AdminEvents.delegateEvent(document, 'click', '#challenge-config-content [data-action="challenge-save"]', event => {
            event.preventDefault();
            void this.save();
        });
        AdminEvents.delegateEvent(document, 'click', '#challenge-config-content [data-action="challenge-reset"]', event => {
            event.preventDefault();
            void this.loadConfig().then(() => this.render()).finally(() => SectionUI.markSaveActionBarClean('data-action'));
        });
        AdminEvents.delegateEvent(document, 'input', '#challenge-config-content [data-action="challenge-update-preview"]', (_event, target) => {
            const field = target.dataset.field;
            if (!field)
                return;
            this.updateField(field, target.value);
            this.updatePreview();
            SectionUI.markSaveActionBarDirty('data-action');
        });
        AdminEvents.delegateEvent(document, 'input', '#challenge-config-content textarea[data-action="challenge-update-preview"]', (_event, target) => {
            const field = target.dataset.field;
            if (!field)
                return;
            this.updateField(field, target.value);
            this.updatePreview();
            SectionUI.markSaveActionBarDirty('data-action');
        });
        AdminEvents.delegateEvent(document, 'change', '#challenge-config-content [data-action="challenge-update-mode"]', (_event, target) => {
            this.updateField('mode', target.value);
            this.render();
            SectionUI.markSaveActionBarDirty('data-action');
        });
        AdminEvents.delegateEvent(document, 'change', '#challenge-config-content [data-action="challenge-update-field"]', (_event, target) => {
            const field = target.dataset.field;
            if (!field)
                return;
            if (target instanceof HTMLInputElement && target.type === 'checkbox') {
                this.updateField(field, target.checked);
            }
            else if (target.dataset.valueType === 'number') {
                this.updateField(field, Number.parseInt(target.value, 10));
            }
            else {
                this.updateField(field, target.value);
            }
            this.render();
            SectionUI.markSaveActionBarDirty('data-action');
        });
        AdminEvents.delegateEvent(document, 'change', '#challenge-config-content [data-action="challenge-update-cookie-ttl"]', (_event, target) => {
            this.updateField('cookie_ttl', Number.parseInt(target.value, 10));
            SectionUI.markSaveActionBarDirty('data-action');
        });
    },
    async loadConfig() {
        try {
            const [challengeResponse, captchaResponse] = await Promise.all([
                fetch('/api/modules/challenge/config'),
                fetch('/api/modules/captcha/config')
            ]);
            const [challengeData, captchaData] = await Promise.all([
                challengeCfgParseJson(challengeResponse),
                challengeCfgParseJson(captchaResponse)
            ]);
            if (!challengeResponse.ok) {
                throw new Error(challengeCfgErrorMessage(challengeData, 'Failed to load challenge configuration'));
            }
            this.config = asChallengeModuleConfig(challengeData);
            if (captchaResponse.ok) {
                this.captchaConfig = asChallengeCaptchaConfig(captchaData);
            }
            else {
                this.captchaConfig = createDefaultCaptchaConfigForChallenge();
            }
            this.normalizeForAvailableProviders();
        }
        catch (error) {
            console.error('Failed to load config', error);
            this.config = createDefaultChallengeConfig();
            this.captchaConfig = createDefaultCaptchaConfigForChallenge();
            this.normalizeForAvailableProviders();
        }
    },
    render() {
        const app = AdminDOM.getById('challenge-config-content');
        if (!app)
            return;
        const config = this.config;
        const darkActive = !config.theme || config.theme === 'dark';
        const lightActive = config.theme === 'light';
        const previewThemeClass = lightActive ? 'preview-light' : 'preview-dark';
        const previewInnerClass = lightActive ? 'preview-inner-light' : 'preview-inner-dark';
        const titleThemeClass = lightActive ? 'preview-title-light' : 'preview-title-dark';
        const msgThemeClass = lightActive ? 'preview-msg-light' : 'preview-msg-dark';
        const footerThemeClass = lightActive ? 'preview-footer-light' : 'preview-footer-dark';
        const captchaReady = this.isCaptchaConfigured();
        const mode = String(config.mode || 'managed');
        const previewBody = this.renderChallengePreview(config, titleThemeClass, msgThemeClass);
        const previewTitle = mode === 'invisible' ? 'No Live Preview' : 'Live Preview';
        const previewMarkup = mode === 'invisible' ? `
      <div id="preview-container" class="preview-box preview-empty">
        <div class="preview-empty-state">
          <div class="preview-empty-icon" aria-hidden="true">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <strong>Invisible Background Check</strong>
          <span>Suspicious requests are verified silently via telemetry without presenting an interstitial challenge screen.</span>
        </div>
      </div>
    ` : `
      <div id="preview-container" class="preview-box ${previewThemeClass} challenge-runtime-preview">
        <div class="challenge-runtime-preview-content" aria-label="Aegis visitor challenge preview">
          ${previewBody}
        </div>
        <div class="challenge-runtime-preview-footer ${footerThemeClass}">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span>DDoS Protection by <strong>Aegis</strong></span>
        </div>
      </div>
    `;
        this.renderOperator(app, previewMarkup, previewTitle, darkActive, lightActive, captchaReady);
        this.bindPreviewInteractions();
    },
    renderOperator(app, previewMarkup, previewTitle, darkActive, lightActive, captchaReady) {
        const config = this.config;
        const activeMode = String(config.mode || 'managed');
        const modeOptions = [
            { id: 'managed', label: 'Managed proof-of-work', disabled: false },
            { id: 'invisible', label: 'Invisible check', disabled: false },
            { id: 'interactive', label: 'Interactive challenge', disabled: false },
            { id: 'captcha', label: captchaReady ? 'Captcha' : 'Captcha (configure Captcha first)', disabled: !captchaReady }
        ];
        const content = `
      <div class="challenge-operator-stack">
        <div class="challenge-editor-grid">
          <div class="challenge-editor-column">
            ${SectionUI.renderOperatorSection('Verification policy', `
              <div class="challenge-appearance-panel">
                <div class="settings-field">
                  <label for="challenge-mode-select">Challenge type ${SectionUI.renderInfoTooltip('Choose how suspicious requests are verified before access is granted.')}</label>
                  <select id="challenge-mode-select" class="settings-input challenge-mode-select" data-action="challenge-update-mode">
                    ${modeOptions.map(option => `
                      <option value="${option.id}" ${activeMode === option.id ? 'selected' : ''} ${option.disabled ? 'disabled' : ''}>${option.label}</option>
                    `).join('')}
                  </select>
                </div>

                ${activeMode === 'interactive' ? `
                  <div class="settings-field">
                    <label for="challenge-interactive-method">Verification method ${SectionUI.renderInfoTooltip('Choose the interaction visitors complete before access is granted.')}</label>
                    <select id="challenge-interactive-method"
                            class="settings-input"
                            data-action="challenge-update-field"
                            data-field="interactive_style">
                      ${INTERACTIVE_VERIFICATION_METHODS.map(option => `
                        <option value="${option.id}" ${normalizeInteractiveVerificationMethod(config.interactive_style) === option.id ? 'selected' : ''}>${option.label}</option>
                      `).join('')}
                    </select>
                  </div>
                ` : ''}
              </div>
            `, {
            subtitle: 'Choose how suspicious requests are verified before access is granted.',
            className: 'challenge-operator-section'
        })}

            ${SectionUI.renderOperatorSection('Visitor experience', `
              <div class="challenge-appearance-panel">
                <div class="settings-field">
                  <label for="challenge-page-title">Page title ${SectionUI.renderInfoTooltip('Primary heading displayed above the verification widget.')}</label>
                  <input id="challenge-page-title" type="text" value="${challengeCfgEscapeHTML(config.custom_title || 'Checking your browser...')}"
                         class="settings-input"
                         placeholder="Checking your browser..."
                         data-action="challenge-update-preview"
                         data-field="custom_title">
                </div>

                <div class="settings-field">
                  <label for="challenge-user-message">User message ${SectionUI.renderInfoTooltip('Contextual message explaining the verification step to legitimate users.')}</label>
                  <textarea id="challenge-user-message" class="settings-input challenge-message-input"
                            placeholder="Explain why the visitor is waiting..."
                            data-action="challenge-update-preview"
                            data-field="custom_message">${challengeCfgEscapeHTML(config.custom_message || 'Please wait a moment while we verify your request.')}</textarea>
                </div>

                <div class="settings-field">
                  <label id="challenge-theme-label">Challenge appearance ${SectionUI.renderInfoTooltip('Color theme rendered on the visitor challenge screen.')}</label>
                  <div class="challenge-theme-group" role="radiogroup" aria-labelledby="challenge-theme-label">
                    <button type="button" class="challenge-theme-btn ${darkActive ? 'is-active' : ''}" data-action="challenge-set-theme" data-challenge-theme="dark" role="radio" aria-checked="${darkActive}">
                      <svg viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z"></path></svg>
                      Dark Mode
                    </button>
                    <button type="button" class="challenge-theme-btn ${lightActive ? 'is-active' : ''}" data-action="challenge-set-theme" data-challenge-theme="light" role="radio" aria-checked="${lightActive}">
                      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path></svg>
                      Light Mode
                    </button>
                  </div>
                </div>
              </div>
            `, {
            subtitle: 'Customize page title, user message, and visitor screen theme.',
            className: 'challenge-operator-section'
        })}
          </div>

          ${SectionUI.renderOperatorSection(previewTitle, `
            <div class="challenge-operator-preview">${previewMarkup}</div>
          `, {
            subtitle: activeMode === 'invisible'
                ? 'Invisible checks run without a visitor-facing page.'
                : 'Preview the current challenge page.',
            className: 'challenge-operator-section challenge-preview-operator-section'
        })}
        </div>

        ${SectionUI.renderSaveActionBar({
            actionAttr: 'data-action',
            resetAction: 'challenge-reset',
            saveAction: 'challenge-save',
            saveLabel: 'Save Changes'
        })}
      </div>
    `;
        app.innerHTML = SectionUI.renderOperatorFrame({
            title: 'Smart Challenge',
            kicker: 'Bot Defense',
            subtitle: 'Configure challenge policy and the visitor experience.',
            content,
            className: 'challenge-operator-frame flow-operator-frame'
        });
    },
    renderChallengePreview(config, titleThemeClass, msgThemeClass) {
        const mode = String(config.mode || 'managed');
        const title = challengeCfgEscapeHTML(config.custom_title || 'Checking your browser...');
        const message = challengeCfgEscapeHTML(config.custom_message || 'Please wait a moment while we verify your request.');
        const isLightPreview = titleThemeClass === 'preview-title-light';
        const titleStyle = isLightPreview
            ? ' style="color: #171b22 !important; background: transparent !important; border: 0 !important; box-shadow: none !important; opacity: 1;"'
            : ' style="color: #f4f6f8 !important; background: transparent !important; border: 0 !important; box-shadow: none !important; opacity: 1;"';
        const messageStyle = isLightPreview
            ? ' style="color: #606a78 !important; background: transparent !important; border: 0 !important; box-shadow: none !important; opacity: 1;"'
            : ' style="color: #a2aab6 !important; background: transparent !important; border: 0 !important; box-shadow: none !important; opacity: 1;"';
        const titleMarkup = `<h3 id="preview-title" class="text-small mb-8 ${titleThemeClass}"${titleStyle}>${title}</h3>`;
        const messageMarkup = `<p id="preview-msg" class="text-xs lh-15 ${msgThemeClass}"${messageStyle}>${message}</p>`;
        if (mode === 'interactive') {
            const method = normalizeInteractiveVerificationMethod(config.interactive_style);
            if (method === 'click') {
                return `
          ${titleMarkup}
          ${messageMarkup}
          <button type="button"
                  class="preview-click-control"
                  data-preview-action="click"
                  aria-pressed="false">
            <span class="preview-click-check"></span>
            <span class="preview-click-copy">
              <span class="preview-widget-title" data-preview-primary>Verify you are human</span>
              <span class="preview-widget-subtitle" data-preview-secondary>Click to continue</span>
            </span>
            <span class="preview-click-brand">AEGIS</span>
          </button>
        `;
            }
            if (method === 'slide') {
                return `
          ${titleMarkup}
          ${messageMarkup}
          <div class="preview-slide-control"
               data-preview-action="slide"
               role="slider"
               tabindex="0"
               aria-label="Slide to verify"
               aria-valuemin="0"
               aria-valuemax="100"
               aria-valuenow="0">
            <span class="preview-slide-thumb">
              <svg viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"></path></svg>
            </span>
            <span class="preview-slide-copy" data-preview-primary>Slide to verify</span>
            <span class="preview-slide-end">
              <svg viewBox="0 0 24 24"><path d="m7 12 3 3 7-7"></path></svg>
            </span>
          </div>
        `;
            }
            if (method === 'sequence') {
                const preview = createSequencePreview();
                return `
          ${titleMarkup}
          ${messageMarkup}
          <div class="preview-sequence-control"
               data-preview-action="sequence"
               data-preview-sequence="${preview.sequence.join(',')}"
               role="group"
               aria-label="Number sequence verification">
            <span class="preview-method-label">Select ${preview.sequence.join(' → ')}</span>
            <span class="preview-sequence-steps">
              ${preview.choices.map(value => `<button type="button" data-preview-value="${value}">${value}</button>`).join('')}
            </span>
          </div>
        `;
            }
            if (method === 'match') {
                const preview = createSymbolPreview();
                return `
          ${titleMarkup}
          ${messageMarkup}
          <div class="preview-match-control"
               data-preview-action="match"
               data-preview-target="${preview.target}"
               role="group"
               aria-label="Symbol match verification">
            <span class="preview-match-prompt">Target <strong>${preview.target}</strong></span>
            <span class="preview-match-options">
              ${preview.choices.map(value => `<button type="button" data-preview-value="${value}" aria-label="Choose ${value}">${value}</button>`).join('')}
            </span>
          </div>
        `;
            }
            return `
        ${titleMarkup}
        ${messageMarkup}
        <button type="button"
                class="preview-widget-box"
                data-preview-action="hold"
                aria-pressed="false">
          <span class="preview-widget-action-icon" aria-hidden="true"></span>
          <span class="preview-widget-main">
            <span class="preview-widget-title" data-preview-primary>Hold to verify</span>
            <span class="preview-widget-subtitle" data-preview-secondary>Press and hold to continue</span>
          </span>
          <span class="preview-widget-brand" aria-hidden="true">›</span>
        </button>
      `;
        }
        if (mode === 'captcha') {
            return `
        ${titleMarkup}
        ${messageMarkup}
        <div class="preview-captcha-box" aria-hidden="true">
          <span class="preview-captcha-check"></span>
          <span class="preview-captcha-text">I'm not a robot</span>
        </div>
      `;
        }
        return `
      <div class="spinner-preview" style="background: transparent !important; box-shadow: none !important;"></div>
      ${titleMarkup}
      ${messageMarkup}
    `;
    },
    bindPreviewInteractions() {
        const preview = AdminDOM.getById('preview-container');
        if (!preview)
            return;
        const holdControl = preview.querySelector('[data-preview-action="hold"]');
        if (holdControl) {
            const primary = holdControl.querySelector('[data-preview-primary]');
            const secondary = holdControl.querySelector('[data-preview-secondary]');
            let holdTimer = 0;
            const resetHold = () => {
                window.clearTimeout(holdTimer);
                holdTimer = 0;
                holdControl.classList.remove('is-holding', 'is-complete');
                holdControl.setAttribute('aria-pressed', 'false');
                if (primary)
                    primary.textContent = 'Hold to verify';
                if (secondary)
                    secondary.textContent = 'Press and hold to continue';
            };
            const completeHold = () => {
                window.clearTimeout(holdTimer);
                holdTimer = 0;
                holdControl.classList.remove('is-holding');
                holdControl.classList.add('is-complete');
                holdControl.setAttribute('aria-pressed', 'true');
                if (primary)
                    primary.textContent = 'Verified';
                if (secondary)
                    secondary.textContent = 'Preview complete';
            };
            const startHold = () => {
                resetHold();
                holdControl.classList.add('is-holding');
                if (secondary)
                    secondary.textContent = 'Keep holding…';
                holdTimer = window.setTimeout(completeHold, 1100);
            };
            const cancelHold = () => {
                if (!holdControl.classList.contains('is-complete'))
                    resetHold();
            };
            holdControl.addEventListener('pointerdown', event => {
                event.preventDefault();
                holdControl.setPointerCapture(event.pointerId);
                startHold();
            });
            holdControl.addEventListener('pointerup', cancelHold);
            holdControl.addEventListener('pointercancel', cancelHold);
            holdControl.addEventListener('lostpointercapture', cancelHold);
            holdControl.addEventListener('keydown', event => {
                if ((event.key === ' ' || event.key === 'Enter') && !event.repeat) {
                    event.preventDefault();
                    startHold();
                }
            });
            holdControl.addEventListener('keyup', event => {
                if (event.key === ' ' || event.key === 'Enter') {
                    event.preventDefault();
                    cancelHold();
                }
            });
            holdControl.addEventListener('blur', cancelHold);
        }
        const clickControl = preview.querySelector('[data-preview-action="click"]');
        if (clickControl) {
            const primary = clickControl.querySelector('[data-preview-primary]');
            const secondary = clickControl.querySelector('[data-preview-secondary]');
            clickControl.addEventListener('click', () => {
                const complete = !clickControl.classList.contains('is-complete');
                clickControl.classList.toggle('is-complete', complete);
                clickControl.setAttribute('aria-pressed', String(complete));
                if (primary)
                    primary.textContent = complete ? 'Verified' : 'Verify you are human';
                if (secondary)
                    secondary.textContent = complete ? 'Preview complete' : 'Click to continue';
            });
        }
        const slideControl = preview.querySelector('[data-preview-action="slide"]');
        if (slideControl) {
            const thumb = slideControl.querySelector('.preview-slide-thumb');
            const label = slideControl.querySelector('[data-preview-primary]');
            let dragging = false;
            let progress = 0;
            const paintSlide = (nextProgress) => {
                progress = Math.max(0, Math.min(100, nextProgress));
                const trackWidth = Math.max(0, slideControl.clientWidth - (thumb?.offsetWidth || 46) - 10);
                slideControl.style.setProperty('--preview-slide-progress', `${trackWidth * (progress / 100)}px`);
                slideControl.setAttribute('aria-valuenow', String(Math.round(progress)));
            };
            const resetSlide = () => {
                dragging = false;
                slideControl.classList.remove('is-dragging', 'is-complete');
                if (label)
                    label.textContent = 'Slide to verify';
                paintSlide(0);
            };
            const completeSlide = () => {
                dragging = false;
                slideControl.classList.remove('is-dragging');
                slideControl.classList.add('is-complete');
                if (label)
                    label.textContent = 'Verified';
                paintSlide(100);
            };
            const updateSlideFromPointer = (event) => {
                const rect = slideControl.getBoundingClientRect();
                const thumbWidth = thumb?.offsetWidth || 46;
                const usableWidth = Math.max(1, rect.width - thumbWidth - 10);
                const offset = event.clientX - rect.left - 5 - (thumbWidth / 2);
                paintSlide((offset / usableWidth) * 100);
            };
            slideControl.addEventListener('pointerdown', event => {
                event.preventDefault();
                if (slideControl.classList.contains('is-complete'))
                    resetSlide();
                dragging = true;
                slideControl.classList.add('is-dragging');
                slideControl.setPointerCapture(event.pointerId);
                updateSlideFromPointer(event);
            });
            slideControl.addEventListener('pointermove', event => {
                if (dragging)
                    updateSlideFromPointer(event);
            });
            slideControl.addEventListener('pointerup', () => {
                if (!dragging)
                    return;
                if (progress >= 88)
                    completeSlide();
                else
                    resetSlide();
            });
            slideControl.addEventListener('pointercancel', resetSlide);
            slideControl.addEventListener('keydown', event => {
                let nextProgress = progress;
                if (event.key === 'ArrowRight' || event.key === 'ArrowUp')
                    nextProgress += 10;
                else if (event.key === 'ArrowLeft' || event.key === 'ArrowDown')
                    nextProgress -= 10;
                else if (event.key === 'Home')
                    nextProgress = 0;
                else if (event.key === 'End')
                    nextProgress = 100;
                else
                    return;
                event.preventDefault();
                slideControl.classList.remove('is-complete');
                if (nextProgress >= 88)
                    completeSlide();
                else {
                    if (label)
                        label.textContent = 'Slide to verify';
                    paintSlide(nextProgress);
                }
            });
        }
        const sequenceControl = preview.querySelector('[data-preview-action="sequence"]');
        if (sequenceControl) {
            const sequence = String(sequenceControl.dataset.previewSequence || '')
                .split(',')
                .map(value => value.trim())
                .filter(Boolean);
            const label = sequenceControl.querySelector('.preview-method-label');
            const buttons = Array.from(sequenceControl.querySelectorAll('[data-preview-value]'));
            const defaultLabel = label?.textContent || '';
            let position = 0;
            let resetTimer = 0;
            const resetSequence = () => {
                window.clearTimeout(resetTimer);
                resetTimer = 0;
                position = 0;
                sequenceControl.classList.remove('is-complete', 'is-wrong');
                buttons.forEach(button => button.classList.remove('is-selected', 'is-wrong'));
                if (label)
                    label.textContent = defaultLabel;
            };
            buttons.forEach(button => {
                button.addEventListener('click', () => {
                    if (sequenceControl.classList.contains('is-complete'))
                        resetSequence();
                    const value = String(button.dataset.previewValue || '');
                    if (value !== sequence[position]) {
                        sequenceControl.classList.add('is-wrong');
                        button.classList.add('is-wrong');
                        if (label)
                            label.textContent = 'Try the sequence again';
                        resetTimer = window.setTimeout(resetSequence, 650);
                        return;
                    }
                    button.classList.add('is-selected');
                    position += 1;
                    if (position === sequence.length) {
                        sequenceControl.classList.add('is-complete');
                        if (label)
                            label.textContent = 'Verified';
                    }
                    else if (label) {
                        label.textContent = `Next: ${sequence[position]}`;
                    }
                });
            });
        }
        const matchControl = preview.querySelector('[data-preview-action="match"]');
        if (matchControl) {
            const target = String(matchControl.dataset.previewTarget || '');
            const prompt = matchControl.querySelector('.preview-match-prompt');
            const buttons = Array.from(matchControl.querySelectorAll('[data-preview-value]'));
            const defaultPrompt = prompt?.innerHTML || '';
            let resetTimer = 0;
            const resetMatch = () => {
                window.clearTimeout(resetTimer);
                resetTimer = 0;
                matchControl.classList.remove('is-complete', 'is-wrong');
                buttons.forEach(button => button.classList.remove('is-selected', 'is-wrong'));
                if (prompt)
                    prompt.innerHTML = defaultPrompt;
            };
            buttons.forEach(button => {
                button.addEventListener('click', () => {
                    if (matchControl.classList.contains('is-complete'))
                        resetMatch();
                    if (String(button.dataset.previewValue || '') === target) {
                        button.classList.add('is-selected');
                        matchControl.classList.add('is-complete');
                        if (prompt)
                            prompt.textContent = 'Verified';
                        return;
                    }
                    matchControl.classList.add('is-wrong');
                    button.classList.add('is-wrong');
                    if (prompt)
                        prompt.textContent = 'Try another symbol';
                    resetTimer = window.setTimeout(resetMatch, 650);
                });
            });
        }
    },
    updateField(key, value) {
        if (key === 'mode') {
            if (value === 'captcha' && !this.isCaptchaConfigured()) {
                this.config.mode = 'managed';
                this.applyModeDefaults('managed');
                challengeShowToast('Captcha-based challenge modes require the Captcha module to be configured first.', 'warning');
                return;
            }
            this.config.mode = String(value || 'managed');
            this.applyModeDefaults(this.config.mode);
            return;
        }
        this.config[key] = value;
    },
    isCaptchaConfigured() {
        return Boolean(String(this.captchaConfig?.site_key || '').trim());
    },
    applyModeDefaults(mode) {
        this.config.preset = 'custom';
        this.config.invisible_enabled = mode === 'invisible';
        this.config.managed_enabled = mode === 'managed' || mode === 'captcha';
        this.config.interactive_enabled = mode === 'interactive';
        this.config.captcha_enabled = mode === 'captcha' && this.isCaptchaConfigured();
        this.config.escalation_policy = 'fixed';
    },
    normalizeForAvailableProviders() {
        if (this.isCaptchaConfigured())
            return;
        this.config.captcha_enabled = false;
        if (this.config.mode === 'captcha') {
            this.config.mode = 'managed';
            this.applyModeDefaults('managed');
        }
    },
    updatePreview() {
        const title = AdminDOM.getById('preview-title');
        const message = AdminDOM.getById('preview-msg');
        if (title)
            title.textContent = String(this.config.custom_title || 'Checking your browser...');
        if (message)
            message.textContent = String(this.config.custom_message || 'Please wait a moment while we verify your request.');
    },
    async save() {
        try {
            if (typeof this.config.enabled !== 'boolean') {
                this.config.enabled = true;
            }
            const response = await fetch('/api/modules/challenge/config', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(this.config)
            });
            const data = await challengeCfgParseJson(response);
            if (!response.ok) {
                challengeShowToast(challengeCfgErrorMessage(data, 'Failed to save settings'), 'error');
                return;
            }
            challengeShowToast('Settings saved successfully', 'success');
            SectionUI.markSaveActionBarClean('data-action');
        }
        catch (error) {
            const message = error instanceof Error ? error.message : 'Failed to save settings';
            challengeShowToast(message, 'error');
        }
    }
};
