/**
 * Settings page
 * Source of truth: web/admin/src/settings.ts
 * Runtime output: web/admin/dist/js/settings.js
 */

import { api } from './api.js';
import * as AdminDOM from './core/dom.js';
import * as AdminEvents from './core/events.js';
import { SectionUI } from './sections/ui-components.js';
import { escapeSectionAttr, escapeSectionHtml } from './sections/section-runtime-helpers.js';
import { notify } from './core/notify.js';
import { showLicenseCongratulationsModal, showLicenseErrorModal } from './licensing-modal.js';
import { openSystemUpdateModal, checkSystemUpdates } from './system-update.js';

type ServerSettings = {
  port?: number;
  admin?: {
    host?: string;
    port?: number;
    username?: string;
    secure_cookies?: boolean;
  };
};

type TelemetrySettings = {
  prometheus_enabled?: boolean;
  prometheus_path?: string;
  prometheus_token?: string;
  retention_days?: number;
  snapshot_interval?: number;
  request_logging?: boolean;
};

type ControlPlaneStorageSettings = {
  enabled?: boolean;
  driver?: string;
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  ssl_mode?: string;
  password_secret_ref?: string;
};

type StorageSettings = {
  control?: ControlPlaneStorageSettings;
  analytics?: ClickHouseAnalyticsSettings;
};

type ClickHouseAnalyticsSettings = {
  mode?: 'required' | 'optional' | 'disabled';
  driver?: 'clickhouse';
  host?: string;
  port?: number;
  database?: string;
  username?: string;
  secure?: boolean;
  password_secret_ref?: string;
};

type PostgreSQLPreflightRequest = {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  ssl_mode: string;
};

type PostgreSQLPreflightConnection = {
  driver: 'postgresql';
  host: string;
  port: number;
  database: string;
  ssl_mode: string;
};

type PostgreSQLPreflightResponse = {
	status: 'ok';
	connection: PostgreSQLPreflightConnection;
};

type PostgreSQLControlPendingRequest = {
  host: string;
  port: number;
  database: string;
  username: string;
  password_secret_ref: string;
  ssl_mode: string;
};

type PostgreSQLControlPendingResponse = {
  status: 'pending';
  restart_required: true;
};

type ClickHousePreflightRequest = {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  secure: boolean;
};

type ClickHousePreflightResponse = {
  status: 'ok';
  connection: {
    driver: 'clickhouse';
    host: string;
    port: number;
    database: string;
    secure: boolean;
  };
};

type ClickHouseAnalyticsPendingRequest = {
  mode: 'required' | 'optional' | 'disabled';
  host: string;
  port: number;
  database: string;
  username: string;
  password_secret_ref: string;
  secure: boolean;
};

type ClickHouseAnalyticsPendingResponse = {
  status: 'pending';
  restart_required: true;
};

type UpstreamSettings = {
  target?: string;
  max_idle_conns?: number;
  max_idle_conns_per_host?: number;
  max_conns_per_host?: number;
  idle_timeout?: string;
  tls_timeout?: string;
  health_check_concurrency?: number;
  insecure_skip_verify?: boolean;
};

type UpstreamRuntimeAvailability = 'available' | 'unsupported' | 'forbidden' | 'unavailable';
type ErrorPageTheme = 'auto' | 'light' | 'dark';

type ErrorPagesSettings = {
  enabled?: boolean;
  theme?: ErrorPageTheme;
  page_403?: string;
  page_404?: string;
  page_503?: string;
  templates?: ErrorPageTemplate[];
  active_template_id?: string;
};

type ErrorPageTemplate = {
  id: string;
  name: string;
  html: string;
};

type ModulesSettings = {
  errorpages?: ErrorPagesSettings;
};

type SettingsState = {
  server?: ServerSettings;
  telemetry?: TelemetrySettings;
  storage?: StorageSettings;
  upstream?: UpstreamSettings;
  modules?: ModulesSettings;
  [key: string]: unknown;
};
type SettingsUpdates = Record<string, unknown>;
type SettingsTabMeta = {
  id: string;
  name: string;
  desc: string;
  icon: string;
};

type StorageRuntimeStatus = {
  driver: string;
  configured: boolean;
  environment_locked: boolean;
  active: boolean;
  available: boolean;
  mode?: 'required' | 'optional' | 'disabled';
  restart_required: boolean;
};

type StorageStatusResponse = {
  control: StorageRuntimeStatus;
  analytics: StorageRuntimeStatus;
};

type LicenseSnapshot = {
  build_tier: string;
  licensed_tier: string;
  effective_tier: string;
  status: string;
  activation_id?: string;
  expires_at?: string;
  offline_until?: string;
  subscription_end?: string;
  last_refresh?: string;
  last_error?: string;
  features?: string[];
  upgrade?: {
    required?: boolean;
    state?: string;
    target_tier?: string;
    target_version?: string;
  };
};

let currentSettings: SettingsState = {};
let storageRuntimeStatus: StorageStatusResponse | null = null;
let activeSettingsTab = 'general';
let settingsBindingsInitialized = false;
let upstreamRuntimeAvailability: UpstreamRuntimeAvailability = 'available';
let currentLicense: LicenseSnapshot | null = null;
let licenseLoadError = '';
let activeErrorPageTemplateID = 'aegis';
let errorPageTemplateDrafts: ErrorPageTemplate[] | null = null;
let errorPagesEnabledDraft: boolean | null = null;
let errorPagesThemeDraft: ErrorPageTheme | null = null;
let activeErrorPagePreviewStatus: ErrorPagePreviewStatus = '403';

function getSettingsTabs(): SettingsTabMeta[] {
  return [
    { id: 'general', name: 'General', desc: 'Listeners and administrator access.', icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>' },
    { id: 'database', name: 'Storage', desc: 'Control and analytics storage.', icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>' },
    { id: 'advanced', name: 'Telemetry', desc: 'Metrics and request logging.', icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="m19 9-5 5-4-4-3 3"/></svg>' },
    { id: 'upstream', name: 'Origin settings', desc: 'Fallback delivery.', icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.66 3.58 3 8 3s8-1.34 8-3V5"/><path d="M4 11v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/></svg>' },
    { id: 'appearance', name: 'Error Pages', desc: 'Browser error responses.', icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>' },
    { id: 'backups', name: 'Backups', desc: 'Import, export, and recovery.', icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>' },
    { id: 'license', name: 'License', desc: 'License and activation management.', icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="m11 12 8-8 2 2-2 2 2 2-3 3-2-2-2 2"/></svg>' }
  ];
}

export async function loadSettingsPage(): Promise<void> {
  ensureSettingsBindings();
  try {
    const urlTab = new URLSearchParams(window.location.search).get('tab');
    if (urlTab) selectSettingsTab(urlTab);
  } catch {}
  const container = AdminDOM.getById('settings-container');
  if (!container) return;

  container.innerHTML = SectionUI.renderLoading('Loading settings...');

  try {
    const configResponse = await fetch('/api/config');
    if (!configResponse.ok) throw new Error(`Settings request failed with status ${configResponse.status}`);
    currentSettings = (await configResponse.json()) as SettingsState;
    clearErrorPageDraftState();
    renderSettingsPage(container);
    if (activeSettingsTab === 'license') void loadLicense();

    void Promise.all([loadUpstreamRuntimeSettings(), loadStorageRuntimeStatus()]).then(([upstreamSettings, runtimeStatus]) => {
      upstreamRuntimeAvailability = upstreamSettings.availability;
      storageRuntimeStatus = runtimeStatus;
      if (upstreamSettings.data) currentSettings.upstream = upstreamSettings.data;

      if (activeSettingsTab !== 'database' && activeSettingsTab !== 'upstream') return;
      const content = AdminDOM.getById('settings-content');
      if (content) content.innerHTML = renderSettingsTabContent(activeSettingsTab);
    });
  } catch (error) {
    console.error(error);
    container.innerHTML = SectionUI.renderError('Failed to load settings. Please try again.', 'loadSettingsPage()');
  }
}

export function selectSettingsTab(tabId: string): void {
  const normalized = (tabId === 'error-pages' || tabId === 'error_pages' || tabId === 'errorpages') ? 'appearance' : tabId;
  activeSettingsTab = getSettingsTabs().some(tab => tab.id === normalized) ? normalized : 'general';
}

function renderSettingsPage(container: HTMLElement): void {
  const tabs = getSettingsTabs();
  const activeTab = tabs.find(tab => tab.id === activeSettingsTab) || tabs[0];
  const content = `
    <div class="settings-operator-stack">
      ${SectionUI.renderOperatorSection(
        `<span id="settings-active-title">${activeTab.name}</span>`,
        `<div class="settings-content content-fade" id="settings-content" aria-live="polite">
          ${renderSettingsTabContent(activeSettingsTab)}
        </div>`,
        {
          subtitle: `<span id="settings-active-description">${activeTab.desc}</span>`,
          className: 'settings-catalog-section'
        }
      )}
    </div>
  `;

  container.innerHTML = SectionUI.renderOperatorFrame({
    title: 'Settings',
    kicker: 'System',
    subtitle: 'Configure administration listeners, storage backends, telemetry exports, error pages, and enterprise licenses.',
    tabs,
    activeTab: activeSettingsTab,
    tabAction: '',
    tabActionAttr: 'data-ignore',
    tabValueAttr: 'data-settings-tab',
    actions: '<button type="button" class="btn btn-outline btn-sm" data-nav-target="dashboard" data-dashboard-tab="system">System Health</button>',
    content,
    className: 'settings-operator-frame legacy-admin-settings-shell'
  });
}

async function loadStorageRuntimeStatus(): Promise<StorageStatusResponse | null> {
  try {
    const response = await fetch('/api/storage/status', { headers: { Accept: 'application/json' } });
    if (!response.ok) return null;
    const payload = await response.json() as Partial<StorageStatusResponse>;
    if (!payload.control || !payload.analytics) return null;
    return payload as StorageStatusResponse;
  } catch {
    return null;
  }
}

async function loadUpstreamRuntimeSettings(): Promise<{ data: UpstreamSettings | null; availability: UpstreamRuntimeAvailability }> {
  try {
    const response = await fetch('/api/upstreams/settings', { headers: { Accept: 'application/json' } });
    if (response.status === 404) return { data: null, availability: 'unsupported' };
    if (response.status === 401 || response.status === 403) return { data: null, availability: 'forbidden' };
    if (!response.ok) {
      console.warn(`Origin runtime settings unavailable: HTTP ${response.status}`);
      return { data: null, availability: 'unavailable' };
    }
    return { data: await response.json() as UpstreamSettings, availability: 'available' };
  } catch (error) {
    console.warn('Origin runtime settings unavailable', error);
    return { data: null, availability: 'unavailable' };
  }
}

function ensureSettingsBindings(): void {
  if (settingsBindingsInitialized) return;
  settingsBindingsInitialized = true;

  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-settings-tab]', (_event, target) => {
    const tabId = target.dataset.settingsTab;
    if (!tabId) return;
    switchSettingsTab(tabId);
  });

  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-settings-action]', (_event, target) => {
    const action = target.dataset.settingsAction;
    if (!action) return;

    switch (action) {
      case 'save-general':
        void saveGeneralSettings();
        break;
      case 'save-advanced':
        void saveAdvancedSettings();
        break;
      case 'test-postgresql-control':
        void testPostgreSQLControlPlaneConnection();
        break;
      case 'save-postgresql-control-pending':
        void savePostgreSQLControlPlanePending();
        break;
      case 'test-clickhouse-analytics':
        void testClickHouseAnalyticsConnection();
        break;
      case 'save-clickhouse-analytics-pending':
        void saveClickHouseAnalyticsPending();
        break;
      case 'save-upstream':
        void saveUpstreamSettings();
        break;
      case 'open-error-page-template-creator':
        openErrorPageTemplateCreator();
        break;
      case 'cancel-error-page-template-creator':
        closeErrorPageTemplateCreator();
        break;
      case 'create-error-page-template':
        createErrorPageTemplate();
        break;
      case 'delete-error-page-template':
        deleteErrorPageTemplate(target.dataset.errorPageTemplate || '');
        break;
      case 'save-error-pages':
        void saveErrorPages();
        break;
      case 'export-config':
        exportConfig();
        break;
      case 'create-backup':
        createBackup();
        break;
      case 'factory-reset':
        factoryReset();
        break;
      case 'activate-license':
        void activateLicense();
        break;
      case 'apply-upgrade':
        void applyUpgrade();
        break;
      case 'refresh-license':
        void refreshLicense();
        break;
      case 'reload-license':
        void loadLicense();
        break;
      case 'check-system-update':
        void handleCheckSystemUpdate();
        break;
      case 'deactivate-license':
        deactivateLicense();
        break;
      default:
        break;
    }
  });

  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-import-target]', (_event, target) => {
    const inputId = target.dataset.importTarget;
    if (!inputId) return;
    AdminDOM.getInput(inputId)?.click();
  });

  AdminEvents.delegateEvent<HTMLInputElement>(document, 'change', 'input[type="file"][data-settings-action="import-config"]', (_event, target) => {
    importConfig(target);
  });

  AdminEvents.delegateEvent<HTMLButtonElement>(document, 'click', 'button[data-error-page-template]:not([data-settings-action])', (_event, target) => {
    selectErrorPageTemplate(target.dataset.errorPageTemplate || '');
  });

  AdminEvents.delegateEvent<HTMLSelectElement>(document, 'change', 'select[data-error-page-template]', (_event, target) => {
    selectErrorPageTemplate(target.value);
  });

  AdminEvents.delegateEvent<HTMLButtonElement>(document, 'click', 'button[data-error-page-preview-status]', (_event, target) => {
    selectErrorPagePreviewStatus(target.dataset.errorPagePreviewStatus || '');
  });

  AdminEvents.delegateEvent<HTMLTextAreaElement>(document, 'input', 'textarea[data-error-page-template-content]', () => {
    updateErrorPageTemplatePreview();
  });

  AdminEvents.delegateEvent<HTMLButtonElement>(document, 'click', 'button[data-error-page-theme]', (_event, target) => {
    selectErrorPageTheme(target.dataset.errorPageTheme || '');
  });

}

function switchSettingsTab(tabId: string): void {
  if (activeSettingsTab === 'appearance') clearErrorPageDraftState();

  activeSettingsTab = tabId;
  const activeTab = getSettingsTabs().find(tab => tab.id === tabId);

  try {
    const url = new URL(window.location.href);
    url.searchParams.set('tab', tabId === 'appearance' ? 'error-pages' : tabId);
    window.history.replaceState({}, '', `${url.pathname}${url.search}`);
  } catch {}

  AdminDOM.queryAll<HTMLElement>('#settings-container [data-settings-tab]').forEach(element => {
    const isActive = element.dataset.settingsTab === tabId;
    element.classList.toggle('is-active', isActive);
    if (isActive) {
      element.setAttribute('aria-current', 'page');
    } else {
      element.removeAttribute('aria-current');
    }
  });
  if (activeTab) {
    const title = AdminDOM.getById('settings-active-title');
    const desc = AdminDOM.getById('settings-active-description');
    if (title) title.textContent = activeTab.name;
    if (desc) desc.textContent = activeTab.desc;
  }

  const content = AdminDOM.getById('settings-content');
  if (!content) return;

  content.classList.add('is-faded');
  window.setTimeout(() => {
    content.innerHTML = renderSettingsTabContent(tabId);
    content.classList.remove('is-faded');
    if (tabId === 'license') void loadLicense();
  }, 150);
}

function renderSettingsTabContent(tabId: string): string {
  switch (tabId) {
    case 'general':
      return renderGeneralSettings();
    case 'database':
      return renderDatabaseSettings();
    case 'advanced':
      return renderAdvancedSettings();
    case 'upstream':
      return renderUpstreamSettings();
    case 'appearance':
      return renderErrorPagesSettings();
    case 'backups':
      return renderBackupsSettings();
    case 'license':
      return renderLicenseSettings();
    default:
      return '';
  }
}

function renderGeneralSettings(): string {
  const server = currentSettings.server || {};
  const admin = server.admin || {};
  const proxyPort = Number.isInteger(server.port) && server.port && server.port > 0 ? server.port : 8080;
  const adminHost = admin.host || '127.0.0.1';
  const adminPort = Number.isInteger(admin.port) && admin.port && admin.port > 0 ? admin.port : 8081;
  const adminIsExternal = !isLoopbackHost(adminHost);

  return `
        <div class="settings-panel-content">
            <div class="settings-section">
                <div class="settings-section-title">Listener configuration</div>
                <span class="settings-hint">Changes apply after restart.</span>
                <div class="settings-grid">
                    <div class="settings-field">
                        <label for="set-server-port">Public proxy port</label>
                        <input type="number" id="set-server-port" value="${proxyPort}" min="1" max="65535" inputmode="numeric" class="settings-input">
                    </div>
                    <div class="settings-field">
                        <label for="set-admin-host">Admin listener host</label>
                        <input type="text" id="set-admin-host" value="${escapeSectionAttr(adminHost)}" autocomplete="off" class="settings-input">
                        <span class="settings-hint">${adminIsExternal
                          ? 'External access requires HTTPS and secure cookies.'
                          : 'Keep this on 127.0.0.1 (loopback) unless the admin listener is protected by a private network or VPN.'}</span>
                    </div>
                    <div class="settings-field">
                        <label for="set-admin-port">Admin listener port</label>
                        <input type="number" id="set-admin-port" value="${adminPort}" min="1" max="65535" inputmode="numeric" class="settings-input">
                    </div>
                </div>
            </div>
            <div class="settings-section">
                <div class="settings-section-title">Administrator accounts</div>
                <span class="settings-hint">Manage users and roles in Users.</span>
                <div class="settings-inline-actions"><button type="button" class="btn btn-outline" data-nav-target="users">Open Users</button></div>
            </div>
            <div class="settings-actions">
                <button type="button" class="btn btn-primary" data-settings-action="save-general">Save for next restart</button>
            </div>
        </div>
    `;
}

function renderErrorPagesSettings(): string {
  const errorPages = currentSettings.modules?.errorpages || {};
  const templates = getErrorPageTemplateOptions(errorPages);
  const customTemplateCount = templates.filter(template => template.source === 'custom').length;
  const canAddCustomTemplate = customTemplateCount < MAX_ERROR_PAGE_TEMPLATES;
  if (!templates.some(template => template.id === activeErrorPageTemplateID)) {
    activeErrorPageTemplateID = templates.some(template => template.id === errorPages.active_template_id)
      ? errorPages.active_template_id || 'aegis'
      : 'aegis';
  }
  const activeTemplate = templates.find(template => template.id === activeErrorPageTemplateID) || templates[0];
  const enabled = errorPagesEnabledDraft ?? errorPages.enabled === true;
  const theme = errorPagesThemeDraft ?? normalizeErrorPageTheme(errorPages.theme);
  return `
    <div class="settings-panel-content error-pages-settings">
      <div class="settings-section error-pages-control">
        <div class="settings-section-title">Browser error responses</div>
        ${SectionUI.renderSwitch({
          id: 'set-error-pages-enabled',
          checked: enabled,
          label: 'Serve custom browser error pages'
        })}
      </div>

      <section class="settings-section error-pages-form-workspace" aria-label="Error page editor">
        <div class="challenge-editor-grid error-pages-editor-grid">
          ${SectionUI.renderOperatorSection('Appearance', `
            <div class="challenge-appearance-panel error-pages-appearance-panel">
            <div class="settings-field">
              <label for="set-error-page-template">Template</label>
              <select id="set-error-page-template" class="settings-input" data-error-page-template>
                <optgroup label="Built-in templates">
                  ${BUILT_IN_ERROR_PAGE_TEMPLATES.map(template => `<option value="${escapeSectionAttr(template.id)}"${template.id === activeTemplate.id ? ' selected' : ''}>${escapeSectionHtml(template.name)}</option>`).join('')}
                </optgroup>
                ${templates.some(template => template.source === 'custom') ? `<optgroup label="Custom templates">${templates.filter(template => template.source === 'custom').map(template => `<option value="${escapeSectionAttr(template.id)}"${template.id === activeTemplate.id ? ' selected' : ''}>${escapeSectionHtml(template.name)}</option>`).join('')}</optgroup>` : ''}
              </select>
            </div>
            ${activeTemplate.source === 'built-in' ? `
              <div class="settings-field">
                <label>Color mode</label>
                <div class="challenge-theme-group error-pages-theme-group" role="group" aria-label="Error page color mode">
                  <button type="button" class="challenge-theme-btn error-pages-theme-btn${theme === 'auto' ? ' is-active' : ''}" data-error-page-theme="auto" aria-pressed="${theme === 'auto'}">
                    <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3.5" y="4.5" width="17" height="12" rx="1.5"></rect><path d="M8.5 20h7M12 16.5V20"></path></svg>
                    Auto
                  </button>
                  <button type="button" class="challenge-theme-btn error-pages-theme-btn${theme === 'light' ? ' is-active' : ''}" data-error-page-theme="light" aria-pressed="${theme === 'light'}">
                    <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path></svg>
                    Light
                  </button>
                  <button type="button" class="challenge-theme-btn error-pages-theme-btn${theme === 'dark' ? ' is-active' : ''}" data-error-page-theme="dark" aria-pressed="${theme === 'dark'}">
                    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z"></path></svg>
                    Dark
                  </button>
                </div>
              </div>` : ''}
            <div class="error-pages-custom-actions">
              <div>
                <strong>Custom templates</strong>
              </div>
              ${canAddCustomTemplate
                ? '<button class="btn btn-outline" type="button" data-settings-action="open-error-page-template-creator">Add template</button>'
                : `<span class="error-pages-template-limit">Maximum ${MAX_ERROR_PAGE_TEMPLATES}</span>`}
            </div>
            ${renderErrorPageTemplateCreator()}
            ${activeTemplate.source === 'custom' ? renderCustomErrorPageTemplateEditor(activeTemplate) : ''}
            </div>
          `, {
            subtitle: 'Choose one template for all browser errors.',
            className: 'challenge-operator-section error-pages-operator-section'
          })}

          ${SectionUI.renderOperatorSection('Live preview', `
            <div class="challenge-operator-preview error-pages-operator-preview">
              <div class="error-pages-preview-toolbar">
                <strong id="error-page-preview-title">${escapeSectionHtml(activeTemplate.name)}</strong>
                <nav class="error-pages-preview-tabs" aria-label="Preview error response">
                  ${ERROR_PAGE_PREVIEW_RESPONSES.map(response => renderErrorPagePreviewStatusTab(response)).join('')}
                </nav>
              </div>
              <div class="error-pages-preview-panel">
                <iframe id="error-pages-preview" title="${escapeSectionAttr(errorPagePreviewTitle(activeTemplate, theme))}" sandbox="" referrerpolicy="no-referrer" srcdoc="${escapeSectionAttr(getErrorPageTemplatePreview(activeTemplate, activeErrorPagePreviewStatus, theme))}"></iframe>
              </div>
            </div>
          `, {
            className: 'challenge-operator-section error-pages-operator-section'
          })}
        </div>
      </section>

      <div class="settings-actions">
        <button type="button" class="btn btn-primary" data-settings-action="save-error-pages">Save error pages</button>
      </div>
    </div>
  `;
}

type ErrorPageTemplateOption = ErrorPageTemplate & { source: 'built-in' | 'custom' };
type ErrorPagePreviewStatus = '403' | '404' | '503';
type ErrorPagePreviewResponse = {
  status: ErrorPagePreviewStatus;
  label: string;
  title: string;
  message: string;
  category: string;
  nextStep: string;
};

const BUILT_IN_ERROR_PAGE_TEMPLATES: ErrorPageTemplateOption[] = [
  { id: 'aegis', name: 'Aegis default', html: '', source: 'built-in' },
  { id: 'minimal', name: 'Minimal response', html: '', source: 'built-in' },
  { id: 'status', name: 'Service status', html: '', source: 'built-in' }
];
const MAX_ERROR_PAGE_TEMPLATES = 12;

const ERROR_PAGE_PREVIEW_RESPONSES: ErrorPagePreviewResponse[] = [
  {
    status: '403',
    label: '403 Denied',
    title: 'Access denied',
    message: 'This request was rejected by the application security layer.',
    category: 'Access control',
    nextStep: 'Contact the service owner if you believe this is unexpected.'
  },
  {
    status: '404',
    label: '404 Not found',
    title: 'Page not found',
    message: 'The page or endpoint you requested does not exist.',
    category: 'Route lookup',
    nextStep: 'Check the address or return to the service entry point.'
  },
  {
    status: '503',
    label: '503 Unavailable',
    title: 'Temporarily unavailable',
    message: 'The service is temporarily unavailable. Please try again in a few moments.',
    category: 'Service availability',
    nextStep: 'Try again shortly or contact the service owner if the issue continues.'
  }
];

function getErrorPagePreviewResponse(status: ErrorPagePreviewStatus): ErrorPagePreviewResponse {
  return ERROR_PAGE_PREVIEW_RESPONSES.find(response => response.status === status) || ERROR_PAGE_PREVIEW_RESPONSES[0];
}

function renderErrorPagePreviewStatusTab(response: ErrorPagePreviewResponse): string {
  const isActive = response.status === activeErrorPagePreviewStatus;
  return `<button type="button" class="error-pages-preview-tab${isActive ? ' is-active' : ''}" data-error-page-preview-status="${response.status}" aria-pressed="${isActive}" aria-controls="error-pages-preview">${response.label}</button>`;
}

function errorPagePreviewTitle(template: ErrorPageTemplateOption, theme = getSelectedErrorPageTheme()): string {
  const response = getErrorPagePreviewResponse(activeErrorPagePreviewStatus);
  return `${template.name} - ${response.status} ${errorPageThemeLabel(theme)} preview`;
}

function normalizeErrorPageTheme(value: unknown): ErrorPageTheme {
  return value === 'light' || value === 'dark' || value === 'auto' ? value : 'auto';
}

function errorPageThemeLabel(theme: ErrorPageTheme): string {
  return theme === 'auto' ? 'Auto' : theme === 'light' ? 'Light' : 'Dark';
}

function getErrorPageTemplateOptions(errorPages: ErrorPagesSettings): ErrorPageTemplateOption[] {
  const customTemplates = errorPageTemplateDrafts || (Array.isArray(errorPages.templates) ? errorPages.templates : []);
  return [
    ...BUILT_IN_ERROR_PAGE_TEMPLATES,
    ...customTemplates
      .filter(template => template && typeof template.id === 'string' && typeof template.name === 'string' && typeof template.html === 'string')
      .map(template => ({ ...template, source: 'custom' as const }))
  ];
}

function renderErrorPageTemplateCreator(): string {
  return `
    <div class="error-pages-template-creator" id="error-page-template-creator" hidden>
      <div class="error-pages-template-creator-copy">
        <strong>Add a custom template</strong>
        <span>Use your own HTML for all browser error responses.</span>
      </div>
      <label for="error-page-template-name">Template name</label>
      <input id="error-page-template-name" class="settings-input" data-settings-transient maxlength="120" autocomplete="off" placeholder="e.g. Brand maintenance page">
      <div class="settings-inline-actions">
        <button type="button" class="btn" data-settings-action="create-error-page-template">Create template</button>
        <button type="button" class="btn btn-outline" data-settings-action="cancel-error-page-template-creator">Cancel</button>
      </div>
    </div>`;
}

function renderCustomErrorPageTemplateEditor(template: ErrorPageTemplateOption): string {
  const isActive = template.id === activeErrorPageTemplateID;
  return `
    <div class="error-pages-custom-editor" data-error-page-template-editor="${escapeSectionAttr(template.id)}"${isActive ? '' : ' hidden'}>
      <div class="error-pages-custom-editor-head">
        <div>
          <strong>Custom HTML</strong>
          <span>Maximum 64 KiB</span>
        </div>
        <button class="btn btn-outline btn-danger" type="button" data-settings-action="delete-error-page-template" data-error-page-template="${escapeSectionAttr(template.id)}">Delete</button>
      </div>
      <label for="error-page-template-name-${escapeSectionAttr(template.id)}">Template name</label>
      <input id="error-page-template-name-${escapeSectionAttr(template.id)}" class="settings-input" data-error-page-template-name="${escapeSectionAttr(template.id)}" maxlength="120" value="${escapeSectionAttr(template.name)}" autocomplete="off">
      <label for="error-page-template-html-${escapeSectionAttr(template.id)}">HTML document</label>
      <textarea id="error-page-template-html-${escapeSectionAttr(template.id)}" class="settings-input error-code-editor" data-error-page-template-content="${escapeSectionAttr(template.id)}" rows="14" spellcheck="false">${escapeSectionHtml(template.html)}</textarea>
      <span class="settings-hint">Variables: <code>{{status}}</code>, <code>{{title}}</code>, <code>{{message}}</code>.</span>
    </div>
  `;
}

function getErrorPageTemplatePreview(template: ErrorPageTemplateOption, status: ErrorPagePreviewStatus, theme = getSelectedErrorPageTheme()): string {
  if (template.source === 'custom') {
    const html = AdminDOM.getTextarea(`error-page-template-html-${template.id}`)?.value || template.html;
    return applyErrorPageThemePolicy(renderCustomErrorPageTemplate(html, getErrorPagePreviewResponse(status)), theme);
  }
  return errorPageDocumentForStatus(errorPagePresetPages(template.id as ErrorPagePreset, theme), status);
}

function errorPageDocumentForStatus(documents: ErrorPageDocuments, status: ErrorPagePreviewStatus): string {
  switch (status) {
    case '403':
      return documents.page403;
    case '404':
      return documents.page404;
    case '503':
      return documents.page503;
  }
}

function renderCustomErrorPageTemplate(html: string, response: ErrorPagePreviewResponse): string {
  return html
    .replace(/\{\{\s*status\s*\}\}/gi, response.status)
    .replace(/\{\{\s*title\s*\}\}/gi, response.title)
    .replace(/\{\{\s*message\s*\}\}/gi, response.message);
}

function applyErrorPageThemePolicy(html: string, theme: ErrorPageTheme): string {
  const policy = `<style data-aegis-error-page-theme>${renderErrorPageThemeVariables(theme, '--aegis-error-page-bg:#0b0d12;--aegis-error-page-surface:#11141a;--aegis-error-page-text:#f8fafc;--aegis-error-page-muted:#a6b1c0;--aegis-error-page-line:#2a3039;--aegis-error-page-quiet:#737d8c', '--aegis-error-page-bg:#f6f7f9;--aegis-error-page-surface:#fff;--aegis-error-page-text:#171b22;--aegis-error-page-muted:#606a78;--aegis-error-page-line:#d8dde5;--aegis-error-page-quiet:#7b8695')}</style>`;
  return /<\/head\s*>/i.test(html)
    ? html.replace(/<\/head\s*>/i, `${policy}</head>`)
    : `${policy}${html}`;
}

function getSelectedErrorPageTheme(): ErrorPageTheme {
  return normalizeErrorPageTheme(errorPagesThemeDraft ?? currentSettings.modules?.errorpages?.theme);
}

function captureErrorPagesThemeDraft(): void {
  errorPagesThemeDraft = getSelectedErrorPageTheme();
}

function selectErrorPageTheme(themeValue: string): void {
  if (themeValue !== 'auto' && themeValue !== 'light' && themeValue !== 'dark') return;
  const theme = themeValue as ErrorPageTheme;
  if (theme === getSelectedErrorPageTheme()) return;
  errorPagesThemeDraft = theme;
  AdminDOM.queryAll<HTMLButtonElement>('[data-error-page-theme]').forEach(button => {
    const isActive = button.dataset.errorPageTheme === theme;
    button.classList.toggle('is-active', isActive);
    button.setAttribute('aria-pressed', String(isActive));
  });
  updateErrorPageTemplatePreview();
}

function getActiveErrorPageTemplate(): ErrorPageTemplateOption {
  const templates = getErrorPageTemplateOptions(currentSettings.modules?.errorpages || {});
  return templates.find(template => template.id === activeErrorPageTemplateID) || templates[0];
}

function selectErrorPageTemplate(templateID: string): void {
  const template = getErrorPageTemplateOptions(currentSettings.modules?.errorpages || {}).find(item => item.id === templateID);
  if (!template || templateID === activeErrorPageTemplateID) return;
  captureErrorPagesEnabledDraft();
  captureErrorPagesThemeDraft();
  errorPageTemplateDrafts = captureErrorPageTemplateDrafts();
  activeErrorPageTemplateID = templateID;
  rerenderErrorPagesWorkspace();
}

function updateErrorPageTemplatePreview(): void {
  const preview = AdminDOM.getById<HTMLIFrameElement>('error-pages-preview');
  if (!preview) return;
  const template = getActiveErrorPageTemplate();
  const theme = getSelectedErrorPageTheme();
  preview.title = errorPagePreviewTitle(template, theme);
  preview.srcdoc = getErrorPageTemplatePreview(template, activeErrorPagePreviewStatus, theme);
}

function selectErrorPagePreviewStatus(statusValue: string): void {
  if (statusValue !== '403' && statusValue !== '404' && statusValue !== '503') return;
  const status = statusValue as ErrorPagePreviewStatus;
  if (status === activeErrorPagePreviewStatus) return;
  activeErrorPagePreviewStatus = status;
  AdminDOM.queryAll<HTMLButtonElement>('[data-error-page-preview-status]').forEach(button => {
    const isActive = button.dataset.errorPagePreviewStatus === status;
    button.classList.toggle('is-active', isActive);
    button.setAttribute('aria-pressed', String(isActive));
  });
  updateErrorPageTemplatePreview();
}

function openErrorPageTemplateCreator(): void {
  const creator = AdminDOM.getById('error-page-template-creator');
  if (!creator) return;
  creator.hidden = false;
  AdminDOM.getInput('error-page-template-name')?.focus();
}

function closeErrorPageTemplateCreator(): void {
  const creator = AdminDOM.getById('error-page-template-creator');
  if (creator) creator.hidden = true;
}

function captureErrorPageTemplateDrafts(): ErrorPageTemplate[] {
  const existing = errorPageTemplateDrafts || (Array.isArray(currentSettings.modules?.errorpages?.templates)
    ? currentSettings.modules.errorpages.templates
    : []);
  return existing
    .filter(template => template && typeof template.id === 'string')
    .map(template => ({
      id: template.id,
      name: AdminDOM.getInput(`error-page-template-name-${template.id}`)?.value.trim() || template.name,
      html: AdminDOM.getTextarea(`error-page-template-html-${template.id}`)?.value || template.html
    }));
}

function customErrorPageTemplateStarter(): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{status}} - {{title}}</title>
<style>:root{color-scheme:light dark;--aegis-error-page-bg:#0b0d12;--aegis-error-page-surface:#11141a;--aegis-error-page-text:#f8fafc;--aegis-error-page-muted:#a6b1c0;--aegis-error-page-line:#2a3039;--aegis-error-page-quiet:#737d8c}@media(prefers-color-scheme:light){:root{--aegis-error-page-bg:#f6f7f9;--aegis-error-page-surface:#fff;--aegis-error-page-text:#171b22;--aegis-error-page-muted:#606a78;--aegis-error-page-line:#d8dde5;--aegis-error-page-quiet:#7b8695}}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;box-sizing:border-box;background:var(--aegis-error-page-bg);color:var(--aegis-error-page-text);font-family:Inter,ui-sans-serif,system-ui,sans-serif}main{width:min(620px,100%);padding:40px;box-sizing:border-box;border:1px solid var(--aegis-error-page-line);background:var(--aegis-error-page-surface)}.eyebrow{margin:0 0 12px;color:#f97316;font-size:11px;font-weight:800;letter-spacing:.1em;text-transform:uppercase}h1{margin:0;font-size:40px;letter-spacing:-.035em}p{max-width:48ch;margin:16px 0 0;color:var(--aegis-error-page-muted);line-height:1.6}.reference{margin-top:28px;padding-top:16px;border-top:1px solid var(--aegis-error-page-line);color:var(--aegis-error-page-quiet);font-size:11px}</style>
</head><body><main><p class="eyebrow">Aegis edge protection</p><h1>{{title}}</h1><p>{{message}}</p><p class="reference">HTTP {{status}}</p></main></body></html>`;
}

function createErrorPageTemplate(): void {
  const name = getInputValue('error-page-template-name').trim();
  if (!name) {
    settingsShowToast('Enter a template name.', 'error');
    AdminDOM.focusById('error-page-template-name');
    return;
  }
  const templates = captureErrorPageTemplateDrafts();
  if (templates.length >= MAX_ERROR_PAGE_TEMPLATES) {
    settingsShowToast(`You can store up to ${MAX_ERROR_PAGE_TEMPLATES} custom templates.`, 'warning');
    return;
  }
  const id = `custom-${Date.now().toString(36)}`;
  captureErrorPagesEnabledDraft();
  captureErrorPagesThemeDraft();
  errorPageTemplateDrafts = [...templates, { id, name, html: customErrorPageTemplateStarter() }];
  activeErrorPageTemplateID = id;
  rerenderErrorPagesWorkspace();
  settingsShowToast('Custom template created. Edit its HTML, then save to apply it to all browser error responses.', 'info');
}

function deleteErrorPageTemplate(templateID: string): void {
  const templates = captureErrorPageTemplateDrafts();
  const template = templates.find(item => item.id === templateID);
  if (!template) return;
  if (!window.confirm(`Delete the ${template.name} template?`)) return;
  captureErrorPagesEnabledDraft();
  captureErrorPagesThemeDraft();
  errorPageTemplateDrafts = templates.filter(item => item.id !== templateID);
  activeErrorPageTemplateID = 'aegis';
  rerenderErrorPagesWorkspace();
  settingsShowToast('Custom template removed. Save error pages to apply this change.', 'info');
}

function clearErrorPageTemplateDraftState(): void {
  errorPageTemplateDrafts = null;
  activeErrorPageTemplateID = currentSettings.modules?.errorpages?.active_template_id || 'aegis';
}

type ErrorPagePreset = 'aegis' | 'minimal' | 'status';
type ErrorPageDocuments = { page403: string; page404: string; page503: string };
function errorPagePresetPages(preset: ErrorPagePreset, theme: ErrorPageTheme): ErrorPageDocuments {
  switch (preset) {
    case 'minimal':
      return createErrorPageDocuments(renderMinimalErrorPage, theme);
    case 'status':
      return createErrorPageDocuments(renderServiceStatusErrorPage, theme);
    default:
      return createErrorPageDocuments(renderAegisBlockingErrorPage, theme);
  }
}

type ErrorPageRenderer = (status: string, title: string, message: string, theme: ErrorPageTheme) => string;

function createErrorPageDocuments(render: ErrorPageRenderer, theme: ErrorPageTheme): ErrorPageDocuments {
  return {
    page403: renderErrorPageResponse(render, '403', theme),
    page404: renderErrorPageResponse(render, '404', theme),
    page503: renderErrorPageResponse(render, '503', theme)
  };
}

function createCustomErrorPageDocuments(html: string, theme: ErrorPageTheme): ErrorPageDocuments {
  return {
    page403: applyErrorPageThemePolicy(renderCustomErrorPageTemplate(html, getErrorPagePreviewResponse('403')), theme),
    page404: applyErrorPageThemePolicy(renderCustomErrorPageTemplate(html, getErrorPagePreviewResponse('404')), theme),
    page503: applyErrorPageThemePolicy(renderCustomErrorPageTemplate(html, getErrorPagePreviewResponse('503')), theme)
  };
}

function renderErrorPageResponse(render: ErrorPageRenderer, status: ErrorPagePreviewStatus, theme: ErrorPageTheme): string {
  const response = getErrorPagePreviewResponse(status);
  return render(response.status, response.title, response.message, theme);
}

function errorPageServiceState(status: string): string {
  switch (status) {
    case '403':
      return 'Access restricted';
    case '404':
      return 'Route unavailable';
    default:
      return 'Service degraded';
  }
}

function renderErrorPageResponseIcon(status: string, className: string): string {
  switch (status) {
    case '403':
      return `<svg class="${className}" width="56" height="56" viewBox="0 0 96 96" aria-hidden="true" focusable="false"><path fill="rgba(255,106,0,.14)" stroke="currentColor" stroke-width="2.35" stroke-linejoin="round" d="M34 10h28l20 20v36L62 86H34L14 66V30l20-20Z"/><path fill="none" stroke="currentColor" stroke-width="3.25" stroke-linecap="round" stroke-linejoin="round" d="m36 36 24 24m0-24L36 60"/></svg>`;
    case '404':
      return `<svg class="${className}" width="56" height="56" viewBox="0 0 96 96" aria-hidden="true" focusable="false"><path fill="none" stroke="currentColor" stroke-width="3.25" stroke-linecap="round" stroke-linejoin="round" d="M29 11h29l16 16v58H29zM58 11v17h16M37 58l22-22m0 22L37 36"/></svg>`;
    default:
      return `<svg class="${className}" width="56" height="56" viewBox="0 0 96 96" aria-hidden="true" focusable="false"><path fill="none" stroke="currentColor" stroke-width="3.25" stroke-linecap="round" stroke-linejoin="round" d="M16 64h11l9-28 16 42 10-25h18M16 78h64"/><path fill="none" stroke="currentColor" stroke-width="3.25" stroke-linejoin="round" d="M70 18h12v12H70z"/></svg>`;
  }
}

function renderErrorPageThemeVariables(theme: ErrorPageTheme, dark: string, light: string): string {
  if (theme === 'light') return `:root{color-scheme:light;${light}}`;
  if (theme === 'dark') return `:root{color-scheme:dark;${dark}}`;
  return `:root{color-scheme:light dark;${dark}}@media (prefers-color-scheme: light){:root{color-scheme:light;${light}}}`;
}

function renderAegisBlockingErrorPage(status: string, title: string, message: string, theme: ErrorPageTheme): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${status} - ${title}</title><style>
:root{color-scheme:dark;--page-bg:#11141a;--surface:#11141a;--surface-muted:#0d1015;--line:#2a3039;--text:#f4f6f8;--text-muted:#a2aab6;--text-dim:#737d8c;--primary:#f97316}*{box-sizing:border-box}html{min-height:100%;background:var(--page-bg)}body{min-height:100vh;min-height:100svh;margin:0;padding:24px;display:flex;flex-direction:column;overflow-x:hidden;background:var(--page-bg);color:var(--text);font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}.challenge-shell{width:min(100%,520px);flex:1 0 auto;align-self:center;display:grid;grid-template-rows:minmax(0,1fr) auto}.container{width:100%;display:grid;grid-row:1 / -1;grid-template-rows:minmax(0,1fr) auto}.challenge-content{padding:36px 32px;text-align:center;align-self:center}.block-icon{display:block;width:108px;height:108px;margin:0 auto 22px;color:#ff6a00}.block-icon .icon-octagon{fill:rgba(255,106,0,.14);stroke:currentColor;stroke-width:2.35;stroke-linejoin:round}.block-icon .icon-cross{fill:none;stroke:currentColor;stroke-width:3.25;stroke-linecap:round;stroke-linejoin:round}h1{margin:0 0 10px;color:var(--text);font-size:22px;font-weight:700;line-height:1.25;letter-spacing:-.025em}p{max-width:390px;margin:0 auto;color:var(--text-muted);font-size:14px;line-height:1.55}.request-reference{margin-top:20px;color:var(--text-dim);font-size:11px;line-height:1.35}.request-reference code{color:var(--text-muted);font:inherit}.footer{padding:24px 0 2px;color:var(--text-dim);font-size:11px;line-height:1.35;text-align:center}.footer strong{color:var(--text-muted);font-weight:650}@media(max-width:560px){body{padding:14px}.challenge-content{padding:32px 20px}.block-icon{width:92px;height:92px;margin-bottom:20px}h1{font-size:20px}}
</style><style>${renderErrorPageThemeVariables(theme, '--page-bg:#11141a;--surface:#11141a;--surface-muted:#0d1015;--line:#2a3039;--text:#f4f6f8;--text-muted:#a2aab6;--text-dim:#737d8c;--primary:#f97316', '--page-bg:#f6f7f9;--surface:#f6f7f9;--surface-muted:#eef1f4;--line:#d8dde5;--text:#171b22;--text-muted:#606a78;--text-dim:#7b8695;--primary:#f97316')}</style></head><body><main class="challenge-shell"><section class="container" aria-labelledby="error-title"><div class="challenge-content">${renderErrorPageResponseIcon(status, 'block-icon')}<h1 id="error-title">${title}</h1><p>${message}</p><p class="request-reference">Response status: <code>HTTP ${status}</code></p></div></section></main></body></html>`;
}

function renderMinimalErrorPage(status: string, title: string, message: string, theme: ErrorPageTheme): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${status} - ${title}</title><style>
:root{color-scheme:light;--ink:#16181d;--muted:#6b7280}*{box-sizing:border-box}body{min-height:100vh;min-height:100svh;margin:0;padding:28px;display:grid;place-items:center;background:#fff;color:var(--ink);font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.message{width:min(100%,460px)}.status{margin:0 0 14px;color:var(--muted);font-size:13px;font-weight:600;letter-spacing:.03em}h1{margin:0;font-size:clamp(34px,7vw,48px);font-weight:650;letter-spacing:-.045em;line-height:1.08}p{max-width:38ch;margin:14px 0 0;color:var(--muted);font-size:16px;line-height:1.6}@media(max-width:560px){body{padding:24px}p{font-size:15px}}
</style><style>${renderErrorPageThemeVariables(theme, '--page:#11141a;--ink:#f4f6f8;--muted:#a2aab6', '--page:#fff;--ink:#16181d;--muted:#6b7280')}body{background:var(--page)}</style></head><body><main class="message" aria-labelledby="error-title"><p class="status">HTTP ${status}</p><h1 id="error-title">${title}</h1><p>${message}</p></main></body></html>`;
}

function renderServiceStatusErrorPage(status: string, title: string, message: string, theme: ErrorPageTheme): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${status} - ${title}</title><style>
:root{color-scheme:light;--page:#f5f6f8;--surface:#fff;--line:#e5e7eb;--text:#181b20;--muted:#69707d;--quiet:#8a919d;--accent:#b45309}*{box-sizing:border-box}body{min-height:100vh;min-height:100svh;margin:0;padding:28px;background:var(--page);color:var(--text);font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.status-page{width:min(100%,720px);margin:0 auto}.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:10px 0 26px;color:var(--muted);font-size:12px}.topbar strong{color:var(--text);font-size:14px;font-weight:700}.topbar span{color:var(--quiet)}.summary{padding:28px 30px;border:1px solid var(--line);background:var(--surface)}.eyebrow{margin:0;color:var(--accent);font-size:11px;font-weight:750;letter-spacing:.08em;text-transform:uppercase}h1{margin:10px 0 0;font-size:30px;font-weight:680;letter-spacing:-.04em;line-height:1.15}.summary > p:last-child{max-width:48ch;margin:12px 0 0;color:var(--muted);font-size:15px;line-height:1.6}.status-list{margin:16px 0 0;border:1px solid var(--line);background:var(--surface)}.status-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:16px;align-items:center;padding:17px 20px;border-bottom:1px solid var(--line)}.status-row:last-child{border-bottom:0}.status-row dt{color:var(--muted);font-size:13px}.status-row dd{margin:0;color:var(--text);font-size:13px;font-weight:650;text-align:right}.status-row--state dd{color:var(--accent)}.footnote{margin:20px 0 0;color:var(--quiet);font-size:12px;line-height:1.5}@media(max-width:560px){body{padding:20px}.topbar{padding-bottom:20px}.summary{padding:24px 20px}.status-row{grid-template-columns:1fr;gap:5px;padding:16px}.status-row dd{text-align:left}}
</style><style>${renderErrorPageThemeVariables(theme, '--page:#0e1116;--surface:#151a22;--line:#29313c;--text:#f1f4f8;--muted:#a9b3c1;--quiet:#7d8795;--accent:#fb923c', '--page:#f5f6f8;--surface:#fff;--line:#e5e7eb;--text:#181b20;--muted:#69707d;--quiet:#8a919d;--accent:#b45309')}</style></head><body><main class="status-page" aria-labelledby="error-title"><section class="summary"><p class="eyebrow">${getErrorPagePreviewResponse(status as ErrorPagePreviewStatus).category}</p><h1 id="error-title">${title}</h1><p>${message}</p></section><dl class="status-list"><div class="status-row status-row--state"><dt>Current state</dt><dd>${errorPageServiceState(status)}</dd></div><div class="status-row"><dt>HTTP response</dt><dd>${status}</dd></div><div class="status-row"><dt>Recommended action</dt><dd>${getErrorPagePreviewResponse(status as ErrorPagePreviewStatus).nextStep}</dd></div></dl><p class="footnote">This status reflects the response to your current request.</p></main></body></html>`;
}

function captureErrorPagesEnabledDraft(): void {
  const enabled = AdminDOM.getInput('set-error-pages-enabled');
  if (enabled) errorPagesEnabledDraft = enabled.checked;
}

function rerenderErrorPagesWorkspace(): void {
  const content = AdminDOM.getById('settings-content');
  if (!content || activeSettingsTab !== 'appearance') return;
  content.innerHTML = renderSettingsTabContent('appearance');
}

function clearErrorPageDraftState(): void {
  errorPagesEnabledDraft = null;
  errorPagesThemeDraft = null;
  clearErrorPageTemplateDraftState();
}

async function saveErrorPages(): Promise<void> {
  const templates = captureErrorPageTemplateDrafts();
  const enabled = getCheckboxValue('set-error-pages-enabled');
  const theme = getSelectedErrorPageTheme();
  const selected = getErrorPageTemplateOptions({ templates }).find(template => template.id === activeErrorPageTemplateID);
  if (!selected) {
    settingsShowToast('Choose an error page template before saving.', 'error');
    return;
  }
  if (templates.some(template => !template.name.trim() || new TextEncoder().encode(template.html).byteLength > 64 * 1024)) {
    settingsShowToast('Every custom template needs a name and must be 64 KiB or smaller.', 'error');
    return;
  }
  const pages = selected.source === 'custom'
    ? createCustomErrorPageDocuments(selected.html, theme)
    : errorPagePresetPages(selected.id as ErrorPagePreset, theme);
  await saveSettings({
    'modules.errorpages.enabled': enabled,
    'modules.errorpages.theme': theme,
    'modules.errorpages.page_403': pages.page403,
    'modules.errorpages.page_404': pages.page404,
    'modules.errorpages.page_503': pages.page503,
    'modules.errorpages.active_template_id': selected.id,
    'modules.errorpages.templates': templates
  }, 'Error page template and color mode saved. They now apply to all browser error responses.');
}

function renderAdvancedSettings(): string {
  const telemetry = currentSettings.telemetry || {};

  return `
        <div class="settings-panel-content">
            <div class="settings-section">
                <div class="settings-section-title">Prometheus Metrics</div>
                ${SectionUI.renderSwitch({
                    id: 'set-prometheus-enabled',
                    checked: telemetry.prometheus_enabled,
                    label: 'Enable Prometheus Exporter'
                })}
                <div class="settings-field mt-16">
                    <label for="set-prometheus-path">Scrape path</label>
                    <input type="text" id="set-prometheus-path" value="${escapeSectionAttr(telemetry.prometheus_path || '/metrics')}" class="settings-input w-200">
                <span class="settings-hint">Use a non-API path, for example <code>/metrics</code>.</span>
                </div>
                <div class="settings-field mt-16">
                    <label for="set-prometheus-token">Bearer token</label>
                    <input type="password" id="set-prometheus-token" placeholder="${telemetry.prometheus_token ? 'Token configured - leave blank to keep current' : 'Optional scrape token'}" class="settings-input">
                </div>
                ${telemetry.prometheus_token ? `
                    ${SectionUI.renderSwitch({
                        id: 'set-prometheus-token-clear',
                        checked: false,
                        label: 'Clear configured bearer token',
                        className: 'mt-16'
                    })}
                ` : ''}
            </div>

            <div class="settings-section">
                <div class="settings-section-title">Detailed Request Logging</div>
                ${SectionUI.renderSwitch({
                    id: 'set-request-logging',
                    checked: telemetry.request_logging !== false,
                    label: 'Store per-request analytics logs'
                })}
                <span class="settings-hint hint-indent">Stores individual request logs for analytics. Aggregate counters continue when disabled.</span>
            </div>

            <div class="settings-actions">
                <button type="button" class="btn btn-primary" data-settings-action="save-advanced">Save Changes</button>
            </div>
        </div>
    `;
}

function renderBackupsSettings(): string {
  return `
        <div class="settings-panel-content">
            <div class="settings-section">
                <div class="settings-section-title">Backup & Export</div>
                <div class="data-cards settings-action-cards">
                    <div class="data-card">
                        <div class="data-card-icon">${settingsActionIcon('download')}</div>
                        <div class="data-card-content">
                            <h4>Configuration and rules archive</h4>
                            <p>Configuration and rules only. Secrets and user data are excluded.</p>
                        </div>
                        <button type="button" class="btn btn-outline" data-settings-action="create-backup">Download</button>
                    </div>
                    <div class="data-card">
                        <div class="data-card-icon">${settingsActionIcon('file')}</div>
                        <div class="data-card-content">
                            <h4>Export sanitized config</h4>
                            <p>Shareable configuration without secret values.</p>
                        </div>
                        <button type="button" class="btn btn-outline" data-settings-action="export-config">Export</button>
                    </div>
                </div>
            </div>
            
            <div class="settings-section">
                <div class="settings-section-title">Restore Backup</div>
                <div class="data-cards settings-action-cards">
                    <div class="data-card">
                        <div class="data-card-icon">${settingsActionIcon('upload')}</div>
                        <div class="data-card-content">
                            <h4>Import Configuration</h4>
                            <p>Imports apply after restart. Provide missing secrets separately.</p>
                        </div>
                        <input type="file" id="import-file" accept=".yaml,.yml,.tar.gz,.tgz,application/gzip" class="hidden" data-settings-action="import-config">
                        <button type="button" class="btn btn-outline" data-import-target="import-file">Import</button>
                    </div>
                </div>
            </div>
            
            <div class="settings-section danger-zone">
                <div class="settings-section-title text-danger">Danger Zone</div>
                <div class="data-card border-danger">
                    <div class="data-card-icon">${settingsActionIcon('reset')}</div>
                    <div class="data-card-content">
                        <h4 class="text-danger">Factory Reset</h4>
                        <p>Stages default configuration for the next start. Existing data is kept.</p>
                    </div>
                    <button type="button" class="btn btn-danger" data-settings-action="factory-reset">Reset</button>
                </div>
            </div>
        </div>
    `;
}

function settingsActionIcon(type: 'download' | 'upload' | 'file' | 'reset'): string {
  const icons = {
    download: '<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>',
    upload: '<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/></svg>',
    file: '<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8"/><path d="M8 17h5"/></svg>',
    reset: '<svg viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 3v6h6"/></svg>',
  };
  return icons[type];
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().replace(/^\[|\]$/g, '').toLowerCase();
  return normalized === 'localhost' || normalized.startsWith('127.') || normalized === '::1';
}

function isValidPrometheusPath(path: string): boolean {
  return /^\/(?!api(?:\/|$))[A-Za-z0-9/._~-]+$/.test(path) && path !== '/';
}

async function saveGeneralSettings(): Promise<void> {
  const proxyPort = getNumberValue('set-server-port');
  const adminHost = getInputValue('set-admin-host').trim();
  const adminPort = getNumberValue('set-admin-port');
  if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
    settingsShowToast('Enter a valid public proxy port.', 'error');
    AdminDOM.focusById('set-server-port');
    return;
  }
  if (!adminHost) {
    settingsShowToast('Enter an admin listener host.', 'error');
    AdminDOM.focusById('set-admin-host');
    return;
  }
  if (!isLoopbackHost(adminHost) && currentSettings.server?.admin?.secure_cookies !== true) {
    settingsShowToast('External admin listeners require secure cookies. Set server.admin.secure_cookies in the HTTPS deployment configuration before saving this host.', 'error');
    AdminDOM.focusById('set-admin-host');
    return;
  }
  if (!Number.isInteger(adminPort) || adminPort < 1 || adminPort > 65535) {
    settingsShowToast('Enter a valid admin listener port.', 'error');
    AdminDOM.focusById('set-admin-port');
    return;
  }
  const updates: SettingsUpdates = {
    'server.port': proxyPort,
    'server.admin.host': adminHost,
    'server.admin.port': adminPort
  };
  await saveSettings(updates, 'Listener configuration saved. Restart Aegis to apply it.');
}

async function saveAdvancedSettings(): Promise<void> {
  const prometheusPath = getInputValue('set-prometheus-path').trim();
  if (!isValidPrometheusPath(prometheusPath)) {
    settingsShowToast('Use a non-root absolute scrape path outside /api (letters, numbers, /, -, ., _, and ~ only).', 'error');
    AdminDOM.focusById('set-prometheus-path');
    return;
  }
  const updates: SettingsUpdates = {
    'telemetry.prometheus_enabled': getCheckboxValue('set-prometheus-enabled'),
    'telemetry.prometheus_path': prometheusPath,
    'telemetry.request_logging': getCheckboxValue('set-request-logging')
  };
  const token = getInputValue('set-prometheus-token');
  if (token) updates['telemetry.prometheus_token'] = token;
  if (getCheckboxValue('set-prometheus-token-clear')) updates['telemetry.prometheus_token'] = '';
  await saveSettings(updates, 'Advanced settings saved!');
}

function renderDatabaseSettings(): string {
  const control = currentSettings.storage?.control || {};
  const analytics = currentSettings.storage?.analytics || {};
	const controlRuntimeStatus = renderStorageRuntimeStatus(storageRuntimeStatus?.control, 'PostgreSQL status is unavailable until Aegis reports it.');
	const analyticsRuntimeStatus = renderStorageRuntimeStatus(storageRuntimeStatus?.analytics, 'ClickHouse status is unavailable until Aegis reports it.');
  const configuredPort = control.port;
  const port = typeof configuredPort === 'number'
    && Number.isInteger(configuredPort) && configuredPort > 0 && configuredPort <= 65535
    ? configuredPort
    : 5432;
  const configuredSSLMode = control.ssl_mode || '';
  const sslMode = supportedPostgreSQLSSLModes().includes(configuredSSLMode)
    ? configuredSSLMode
    : 'disable';
	const passwordSecretRef = typeof control.password_secret_ref === 'string'
		&& control.password_secret_ref !== '[REDACTED]'
		? control.password_secret_ref
		: '';
  const analyticsPort = typeof analytics.port === 'number' && Number.isInteger(analytics.port) && analytics.port > 0 && analytics.port <= 65535
    ? analytics.port
    : 9000;
  const analyticsPasswordSecretRef = typeof analytics.password_secret_ref === 'string' && analytics.password_secret_ref !== '[REDACTED]'
    ? analytics.password_secret_ref
    : '';

  return `
    <div class="settings-panel-content storage-settings">
      <div class="storage-configuration-grid">
        ${SectionUI.renderOperatorSection('PostgreSQL', `
          <div class="storage-settings-panel">
            <p class="storage-runtime-status">${controlRuntimeStatus}</p>
            <div class="storage-settings-grid">
              <div class="settings-field">
                <label for="set-postgresql-host">Host</label>
                <input type="text" id="set-postgresql-host" value="${escapeSectionAttr(control.host || 'localhost')}" autocomplete="off" class="settings-input" required>
              </div>
              <div class="settings-field">
                <label for="set-postgresql-port">Port</label>
                <input type="number" id="set-postgresql-port" value="${port}" min="1" max="65535" inputmode="numeric" class="settings-input" required>
              </div>
              <div class="settings-field">
                <label for="set-postgresql-database">Database name</label>
                <input type="text" id="set-postgresql-database" value="${escapeSectionAttr(control.database || 'aegis')}" autocomplete="off" class="settings-input" required>
              </div>
              <div class="settings-field">
                <label for="set-postgresql-username">Username</label>
                <input type="text" id="set-postgresql-username" value="${escapeSectionAttr(control.username || 'aegis')}" autocomplete="username" class="settings-input" required>
              </div>
              <div class="settings-field">
                <label for="set-postgresql-password">Password</label>
                <input type="password" id="set-postgresql-password" autocomplete="new-password" class="settings-input" required aria-describedby="set-postgresql-password-hint">
                <span id="set-postgresql-password-hint" class="settings-hint">Used for testing only. Never saved.</span>
              </div>
              <div class="settings-field">
                <label for="set-postgresql-password-secret-ref">Password secret reference</label>
                <input type="text" id="set-postgresql-password-secret-ref" value="${escapeSectionAttr(passwordSecretRef)}" placeholder="env:AEGIS_CONTROL_DB_PASSWORD" autocomplete="off" spellcheck="false" class="settings-input" required aria-describedby="set-postgresql-password-secret-ref-hint">
                <span id="set-postgresql-password-secret-ref-hint" class="settings-hint">Environment variable reference. Re-enter to replace.</span>
              </div>
              <div class="storage-settings-options storage-settings-options--single">
                <div class="settings-field">
                  <label for="set-postgresql-ssl-mode">TLS mode</label>
                  <select id="set-postgresql-ssl-mode" class="settings-input">
                    ${renderPostgreSQLSSLOptions(sslMode)}
                  </select>
                </div>
              </div>
            </div>
            <div class="storage-settings-actions">
              <button type="button" class="btn btn-outline" data-settings-action="test-postgresql-control">Test connection</button>
              <button type="button" class="btn btn-primary" data-settings-action="save-postgresql-control-pending">Save</button>
            </div>
          </div>
        `, {
          subtitle: 'Control plane',
          className: 'settings-storage-card'
        })}

        ${SectionUI.renderOperatorSection('ClickHouse', `
          <div class="storage-settings-panel">
            <p class="storage-runtime-status">${analyticsRuntimeStatus}</p>
            <div class="storage-settings-grid">
              <div class="settings-field">
                <label for="set-clickhouse-host">Host</label>
                <input type="text" id="set-clickhouse-host" value="${escapeSectionAttr(analytics.host || 'localhost')}" autocomplete="off" class="settings-input">
              </div>
              <div class="settings-field">
                <label for="set-clickhouse-port">Port</label>
                <input type="number" id="set-clickhouse-port" value="${analyticsPort}" min="1" max="65535" inputmode="numeric" class="settings-input">
              </div>
              <div class="settings-field">
                <label for="set-clickhouse-database">Database name</label>
                <input type="text" id="set-clickhouse-database" value="${escapeSectionAttr(analytics.database || 'aegis')}" autocomplete="off" class="settings-input">
              </div>
              <div class="settings-field">
                <label for="set-clickhouse-username">Username</label>
                <input type="text" id="set-clickhouse-username" value="${escapeSectionAttr(analytics.username || 'default')}" autocomplete="username" class="settings-input">
              </div>
              <div class="settings-field">
                <label for="set-clickhouse-password">Temporary password</label>
                <input type="password" id="set-clickhouse-password" autocomplete="new-password" class="settings-input" aria-describedby="set-clickhouse-password-hint">
                <span id="set-clickhouse-password-hint" class="settings-hint">Used for testing only. Never saved.</span>
              </div>
              <div class="settings-field">
                <label for="set-clickhouse-password-secret-ref">Password secret reference</label>
                <input type="text" id="set-clickhouse-password-secret-ref" value="${escapeSectionAttr(analyticsPasswordSecretRef)}" placeholder="env:AEGIS_ANALYTICS_DB_PASSWORD" autocomplete="off" spellcheck="false" class="settings-input">
                <span class="settings-hint">Environment variable reference. Re-enter to replace.</span>
              </div>
              <div class="storage-settings-options storage-settings-options--single">
                <div class="storage-tls-control">
                  ${SectionUI.renderSwitch({
                    id: 'set-clickhouse-secure',
                    checked: analytics.secure === true,
                    label: 'Use TLS for ClickHouse',
                    className: 'storage-tls-switch'
                  })}
                </div>
              </div>
            </div>
            <div class="storage-settings-actions">
              <button type="button" class="btn btn-outline" data-settings-action="test-clickhouse-analytics">Test connection</button>
              <button type="button" class="btn btn-primary" data-settings-action="save-clickhouse-analytics-pending">Save</button>
            </div>
          </div>
        `, {
          subtitle: 'Analytics storage',
          className: 'settings-storage-card'
        })}
      </div>
    </div>
  `;
}

function supportedPostgreSQLSSLModes(): readonly string[] {
  return ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full'];
}

function renderPostgreSQLSSLOptions(selectedMode: string): string {
  return supportedPostgreSQLSSLModes().map(mode => (
    `<option value="${mode}" ${mode === selectedMode ? 'selected' : ''}>${mode}</option>`
  )).join('');
}

function supportedAnalyticsModes(): readonly ClickHouseAnalyticsPendingRequest['mode'][] {
  return ['required', 'optional', 'disabled'];
}

function currentClickHouseAnalyticsMode(): ClickHouseAnalyticsPendingRequest['mode'] {
  const mode = currentSettings.storage?.analytics?.mode;
  return mode && supportedAnalyticsModes().includes(mode) ? mode : 'disabled';
}

function renderStorageRuntimeStatus(status: StorageRuntimeStatus | undefined, unavailableMessage: string): string {
  if (!status) return unavailableMessage;
  if (status.restart_required) return 'A pending configuration is saved. Restart Aegis to apply it.';
  if (status.available) return 'Active connection is healthy.';
  if (status.mode === 'disabled') return 'Analytics is disabled in the active settings.';
  if (status.configured && status.active) return 'The active connection is currently unavailable.';
  if (status.environment_locked) return 'This connection is managed outside Aegis.';
  return 'No active connection is available.';
}

async function testPostgreSQLControlPlaneConnection(): Promise<void> {
  const host = getInputValue('set-postgresql-host').trim();
  const port = getNumberValue('set-postgresql-port');
  const database = getInputValue('set-postgresql-database').trim();
  const username = getInputValue('set-postgresql-username').trim();
  const passwordInput = AdminDOM.getInput('set-postgresql-password');
  const password = passwordInput?.value || '';
  const sslMode = getSelectValue('set-postgresql-ssl-mode');

  if (!host) {
    settingsShowToast('Enter a PostgreSQL host before testing.', 'error');
    AdminDOM.focusById('set-postgresql-host');
    return;
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    settingsShowToast('Enter a PostgreSQL port between 1 and 65535.', 'error');
    AdminDOM.focusById('set-postgresql-port');
    return;
  }
  if (!database) {
    settingsShowToast('Enter a PostgreSQL database name before testing.', 'error');
    AdminDOM.focusById('set-postgresql-database');
    return;
  }
  if (!username) {
    settingsShowToast('Enter a PostgreSQL username before testing.', 'error');
    AdminDOM.focusById('set-postgresql-username');
    return;
  }
  if (!password) {
    settingsShowToast('Enter the PostgreSQL password for this test.', 'error');
    AdminDOM.focusById('set-postgresql-password');
    return;
  }
  if (!supportedPostgreSQLSSLModes().includes(sslMode)) {
    settingsShowToast('Select a supported PostgreSQL TLS mode.', 'error');
    AdminDOM.focusById('set-postgresql-ssl-mode');
    return;
  }

  const request: PostgreSQLPreflightRequest = { host, port, database, username, password, ssl_mode: sslMode };
  settingsShowToast('Testing PostgreSQL connection…', 'info');

  try {
    const result = await api.requestResult<PostgreSQLPreflightResponse>(
      'storage/control/postgresql/preflight',
      'POST',
      request
    );
    if (result.error || result.data?.status !== 'ok' || !result.data.connection) {
      settingsShowToast('PostgreSQL connection could not be established. Confirm the details and try again.', 'error');
      return;
    }
    settingsShowToast('PostgreSQL connection succeeded. Nothing has been saved or activated.', 'success');
  } finally {
    if (passwordInput) passwordInput.value = '';
  }
}

async function savePostgreSQLControlPlanePending(): Promise<void> {
  const host = getInputValue('set-postgresql-host').trim();
  const port = getNumberValue('set-postgresql-port');
  const database = getInputValue('set-postgresql-database').trim();
  const username = getInputValue('set-postgresql-username').trim();
  const passwordSecretRef = getInputValue('set-postgresql-password-secret-ref').trim();
  const sslMode = getSelectValue('set-postgresql-ssl-mode');

  if (!host || !Number.isInteger(port) || port < 1 || port > 65535 || !database || !username) {
    settingsShowToast('Enter valid PostgreSQL connection details before saving.', 'error');
    return;
  }
  if (!/^env:[A-Z_][A-Z0-9_]*$/.test(passwordSecretRef)) {
    settingsShowToast('Use an environment variable secret reference, for example env:AEGIS_CONTROL_DB_PASSWORD.', 'error');
    AdminDOM.focusById('set-postgresql-password-secret-ref');
    return;
  }
  if (!supportedPostgreSQLSSLModes().includes(sslMode)) {
    settingsShowToast('Select a supported PostgreSQL TLS mode.', 'error');
    AdminDOM.focusById('set-postgresql-ssl-mode');
    return;
  }

  const request: PostgreSQLControlPendingRequest = {
    host,
    port,
    database,
    username,
    password_secret_ref: passwordSecretRef,
    ssl_mode: sslMode
  };
  const result = await api.requestResult<PostgreSQLControlPendingResponse>(
    'storage/control/postgresql/pending',
    'POST',
    request
  );
  if (result.error || result.data?.status !== 'pending' || !result.data.restart_required) {
    settingsShowToast('PostgreSQL configuration could not be saved. Update the installation settings, then try again.', 'error');
    return;
  }

  currentSettings.storage = {
    ...currentSettings.storage,
    control: {
      enabled: true,
      driver: 'postgresql',
      host,
      port,
      database,
      username,
      ssl_mode: sslMode
    }
  };
  settingsShowToast('PostgreSQL configuration saved as pending. Restart Aegis to apply it.', 'success');
}

function clickHouseAnalyticsInput(): Omit<ClickHouseAnalyticsPendingRequest, 'password_secret_ref'> & { password_secret_ref: string; password: string } {
  return {
    mode: currentClickHouseAnalyticsMode(),
    host: getInputValue('set-clickhouse-host').trim(),
    port: getNumberValue('set-clickhouse-port'),
    database: getInputValue('set-clickhouse-database').trim(),
    username: getInputValue('set-clickhouse-username').trim(),
    password_secret_ref: getInputValue('set-clickhouse-password-secret-ref').trim(),
    password: AdminDOM.getInput('set-clickhouse-password')?.value || '',
    secure: getCheckboxValue('set-clickhouse-secure')
  };
}

function validateClickHouseAnalyticsInput(input: ReturnType<typeof clickHouseAnalyticsInput>, requirePassword: boolean): boolean {
  if (input.mode === 'disabled') return true;
  if (!input.host || !Number.isInteger(input.port) || input.port < 1 || input.port > 65535 || !input.database || !input.username) {
    settingsShowToast('Enter valid ClickHouse connection details.', 'error');
    return false;
  }
  if (requirePassword && !input.password) {
    settingsShowToast('Enter the ClickHouse password for this test.', 'error');
    AdminDOM.focusById('set-clickhouse-password');
    return false;
  }
  if (!requirePassword && !/^env:[A-Z_][A-Z0-9_]*$/.test(input.password_secret_ref)) {
    settingsShowToast('Use an environment variable secret reference, for example env:AEGIS_ANALYTICS_DB_PASSWORD.', 'error');
    AdminDOM.focusById('set-clickhouse-password-secret-ref');
    return false;
  }
  return true;
}

async function testClickHouseAnalyticsConnection(): Promise<void> {
  const input = clickHouseAnalyticsInput();
  if (input.mode === 'disabled') {
    settingsShowToast('ClickHouse is disabled in the current configuration, so it cannot be tested.', 'warning');
    return;
  }
  if (!validateClickHouseAnalyticsInput(input, true)) return;
  const passwordInput = AdminDOM.getInput('set-clickhouse-password');
  const request: ClickHousePreflightRequest = {
    host: input.host, port: input.port, database: input.database, username: input.username,
    password: input.password, secure: input.secure
  };
  settingsShowToast('Testing ClickHouse connection…', 'info');
  try {
    const result = await api.requestResult<ClickHousePreflightResponse>('storage/analytics/clickhouse/preflight', 'POST', request);
    if (result.error || result.data?.status !== 'ok' || !result.data.connection) {
      settingsShowToast('ClickHouse connection could not be established. Confirm the details and try again.', 'error');
      return;
    }
    settingsShowToast('ClickHouse connection succeeded. Nothing has been saved or activated.', 'success');
  } finally {
    if (passwordInput) passwordInput.value = '';
  }
}

async function saveClickHouseAnalyticsPending(): Promise<void> {
  const input = clickHouseAnalyticsInput();
  if (!validateClickHouseAnalyticsInput(input, false)) return;
  const request: ClickHouseAnalyticsPendingRequest = {
    mode: input.mode,
    host: input.host,
    port: input.port,
    database: input.database,
    username: input.username,
    password_secret_ref: input.password_secret_ref,
    secure: input.secure
  };
  const result = await api.requestResult<ClickHouseAnalyticsPendingResponse>('storage/analytics/clickhouse/pending', 'POST', request);
  if (result.error || result.data?.status !== 'pending' || !result.data.restart_required) {
    settingsShowToast('ClickHouse configuration could not be saved. Update the installation settings, then try again.', 'error');
    return;
  }
  currentSettings.storage = {
    ...currentSettings.storage,
    analytics: {
      mode: input.mode,
      driver: 'clickhouse',
      host: input.host,
      port: input.port,
      database: input.database,
      username: input.username,
      secure: input.secure
    }
  };
  settingsShowToast('ClickHouse configuration saved as pending. Restart Aegis to apply it.', 'success');
}

function renderUpstreamSettings(): string {
  const upstream = currentSettings.upstream || {};
  const runtimeSettingsAvailable = upstreamRuntimeAvailability === 'available';

  return `
      <div class="settings-panel-content origin-settings">
        <div class="settings-section">
            <div class="settings-section-title">Fallback delivery</div>
            <span class="settings-hint">${upstreamRuntimeAvailabilityMessage()}</span>
            <div class="settings-field">
                <label for="set-upstream-target">Fallback backend URL</label>
                <input type="url" id="set-upstream-target" value="${escapeSectionAttr(upstream.target || '')}" placeholder="http://127.0.0.1:9090" class="settings-input">
                <span class="settings-hint">Used when no route selects an Origin.</span>
            </div>
        </div>

        <div class="settings-section origin-tuning-section">
            <div class="settings-section-title">Connection behavior</div>
            <div class="origin-tuning-groups">
              <div class="origin-tuning-group">
                <div class="origin-tuning-group-head">
                  <strong>Connection capacity</strong>
                </div>
                <div class="settings-grid origin-tuning-grid">
                  <div class="settings-field">
                    <label for="set-max-idle">Max idle connections, total</label>
                    <input type="number" id="set-max-idle" value="${upstream.max_idle_conns || 1000}" min="1" max="10000" class="settings-input">
                  </div>
                  <div class="settings-field">
                    <label for="set-max-idle-per-host">Max idle connections per Origin</label>
                    <input type="number" id="set-max-idle-per-host" value="${upstream.max_idle_conns_per_host || 20}" min="1" max="2000" class="settings-input">
                  </div>
                  <div class="settings-field">
                    <label for="set-max-conns-per-host">Max connections per Origin</label>
                    <input type="number" id="set-max-conns-per-host" value="${upstream.max_conns_per_host || 100}" min="1" max="10000" class="settings-input">
                  </div>
                </div>
              </div>
              <div class="origin-tuning-group">
                <div class="origin-tuning-group-head">
                  <strong>Timeouts and health checks</strong>
                </div>
                <div class="settings-grid origin-tuning-grid">
                  <div class="settings-field">
                    <label for="set-idle-timeout">Idle timeout</label>
                    <input type="text" id="set-idle-timeout" value="${escapeSectionAttr(upstream.idle_timeout || '90s')}" placeholder="90s" class="settings-input">
                  </div>
                  <div class="settings-field">
                    <label for="set-tls-timeout">TLS handshake timeout</label>
                    <input type="text" id="set-tls-timeout" value="${escapeSectionAttr(upstream.tls_timeout || '10s')}" placeholder="10s" class="settings-input">
                  </div>
                  <div class="settings-field">
                    <label for="set-health-concurrency">Health-probe concurrency</label>
                    <input type="number" id="set-health-concurrency" value="${upstream.health_check_concurrency || 32}" min="1" max="256" class="settings-input">
                  </div>
                </div>
              </div>
            </div>
        </div>

        <div class="settings-section origin-security-section">
            <div class="settings-section-title">Transport verification</div>
            ${SectionUI.renderSwitch({
              id: 'set-skip-verify',
              checked: upstream.insecure_skip_verify === true,
              label: 'Skip TLS certificate verification',
              className: 'settings-danger-toggle'
            })}
            <span class="settings-hint hint-indent">Disables origin TLS certificate validation. Use only for internal Origin backends with self-signed certificates.</span>
        </div>

        <div class="settings-actions">
          <button type="button" class="btn btn-primary" data-settings-action="save-upstream" ${runtimeSettingsAvailable ? '' : 'disabled title="Saving is currently unavailable"'}>Save Changes</button>
        </div>
      </div>
    `;
}

async function saveUpstreamSettings(): Promise<void> {
  if (upstreamRuntimeAvailability !== 'available') {
    settingsShowToast(upstreamRuntimeAvailabilityMessage(), upstreamRuntimeAvailability === 'forbidden' ? 'error' : 'warning');
    return;
  }
  const settings: UpstreamSettings = {
    target: getInputValue('set-upstream-target').trim(),
    max_idle_conns: getNumberValue('set-max-idle'),
    max_idle_conns_per_host: getNumberValue('set-max-idle-per-host'),
    max_conns_per_host: getNumberValue('set-max-conns-per-host'),
    idle_timeout: getInputValue('set-idle-timeout').trim(),
    tls_timeout: getInputValue('set-tls-timeout').trim(),
    health_check_concurrency: getNumberValue('set-health-concurrency'),
    insecure_skip_verify: getCheckboxValue('set-skip-verify')
  };
  const result = await api.requestResult<UpstreamSettings>('upstreams/settings', 'POST', settings);
  if (result.error || !result.data) {
    settingsShowToast(result.error?.message || 'Failed to save Origin settings', 'error');
    return;
  }
  currentSettings.upstream = result.data;
  settingsShowToast('Origin settings applied', 'success');
}

function upstreamRuntimeAvailabilityMessage(): string {
  switch (upstreamRuntimeAvailability) {
    case 'available':
      return 'Changes apply to new requests.';
    case 'unsupported':
      return 'Origin settings are unavailable in this installation.';
    case 'forbidden':
      return 'Your account cannot change Origin settings.';
    default:
      return 'Origin settings are unavailable. Check Aegis and try again.';
  }
}

async function saveSettings(updates: SettingsUpdates, successMsg: string): Promise<void> {
  const result = await api.requestResult<Record<string, unknown>>('config', 'POST', updates);
  if (result.error) {
    settingsShowToast(result.error.message, 'error');
    return;
  }
  settingsShowToast(successMsg, 'success');
  const refreshed = await api.get<SettingsState>('config');
  if (refreshed) currentSettings = refreshed;
}

function exportConfig(): void {
  window.location.href = '/api/config/export';
}

async function importConfig(input: HTMLInputElement): Promise<void> {
  const file = input.files?.[0];
  if (!file) return;

  const formData = new FormData();
  formData.append('config', file);

  try {
    settingsShowToast(`Importing ${file.name}...`, 'info');
    if (!api.csrfToken) await api.checkSession();
    const response = await fetch('/api/config/import', {
      method: 'POST',
      headers: api.csrfToken ? { 'X-CSRF-Token': api.csrfToken } : undefined,
      body: formData
    });
    if (!response.ok) {
      const message = await response.text();
      settingsShowToast(message || 'Failed to import config', 'error');
      return;
    }
    settingsShowToast('Configuration import is staged. The running service is unchanged; restart Aegis to apply it.', 'success');
  } catch {
    settingsShowToast('Error importing config', 'error');
  } finally {
    input.value = '';
  }
}

function createBackup(): void {
  settingsShowToast('Creating backup...', 'info');
  window.location.href = '/api/config/backup';
}

function factoryReset(): void {
  SectionUI.openConfirmModal(
    'Reset configuration file',
    'Replace config.yaml with Aegis defaults?<br><br><strong>This does not delete rules, certificates, users, sessions, or database data.</strong><br>A restart is required before all runtime components use the new configuration.',
    'RESET CONFIGURATION',
    'var(--danger)',
    async () => {
      SectionUI.closeModal();
      try {
        const result = await api.requestResult<Record<string, string>>('config/reset', 'POST');
        if (result.error) {
          settingsShowToast(result.error.message || 'Failed to reset configuration', 'error');
          return;
        }
        settingsShowToast('Factory reset is staged. The running service is unchanged; restart Aegis to apply it.', 'success');
      } catch {
        settingsShowToast('Error resetting configuration', 'error');
      }
    }
  );
}

async function loadLicense(): Promise<void> {
  currentLicense = null;
  licenseLoadError = '';
  renderLicensePanel();
  const snapshot = await api.get<LicenseSnapshot>('license');
  if (!snapshot) {
    licenseLoadError = 'The licence service is currently unavailable. Please try again.';
    renderLicensePanel();
    return;
  }
  currentLicense = snapshot;
  renderLicensePanel();
}

function renderLicensePanel(): void {
  const content = AdminDOM.getById('settings-content');
  if (content && activeSettingsTab === 'license') content.innerHTML = renderLicenseSettings();
}

function renderLicenseSettings(): string {
  if (licenseLoadError) {
    return `
      <div class="settings-panel-content license-workspace">
        <div class="settings-section license-error-state" role="alert">
          <div class="settings-section-title">Licence service unavailable</div>
          <p>${escapeSectionHtml(licenseLoadError)}</p>
          <div class="settings-inline-actions"><button class="btn btn-outline" type="button" data-settings-action="reload-license">Try again</button></div>
        </div>
      </div>`;
  }
  if (!currentLicense) return SectionUI.renderLoading('Loading licence status...');
  const license = currentLicense;
  const upgrade = license.upgrade || {};
  const normalizedStatus = license.status.toLowerCase();
  const isCommunityBuild = (license.build_tier || '').toLowerCase() === 'community';
  const isActivated = ['active', 'grace', 'past_due', 'upgrade_required', 'deactivation_pending'].includes(normalizedStatus);
  const statusTone = ['active', 'grace'].includes(normalizedStatus) ? 'is-positive' : normalizedStatus === 'community' ? 'is-neutral' : 'is-warning';
  const upgradeNotice = upgrade.required
    ? `<div class="settings-section license-upgrade-notice">
         <div class="settings-section-title">Upgrade ready</div>
         <p>Install the matching Aegis release to enable <strong>${escapeSectionHtml(formatLicenseLabel(upgrade.target_tier || 'this upgrade'))}</strong>${upgrade.target_version ? ` ${escapeSectionHtml(upgrade.target_version)}` : ''}.</p>
         <div class="settings-inline-actions" style="margin-top: 10px;">
           <button class="btn btn-primary" type="button" data-settings-action="apply-upgrade" data-license-action>Apply upgrade now</button>
         </div>
       </div>`
    : '';
  const licenseOverview = renderLicenseOverview(license, statusTone, isCommunityBuild);
  const communityHint = isCommunityBuild
    ? `<p class="settings-hint" style="margin-bottom: 12px;">Entering a licence key will activate advanced platform capabilities for this installation.</p>`
    : '';

  return `
    <div class="settings-panel-content license-workspace">
      ${licenseOverview}
      ${upgradeNotice}
      <div class="settings-section update-management-section">
        <div class="settings-section-title">Software updates</div>
        <p class="settings-hint" style="margin-bottom: 12px;">Check for official Aegis releases, security advisories, and system enhancements.</p>
        <div class="settings-inline-actions">
          <button class="btn btn-outline" type="button" data-settings-action="check-system-update">Check for updates</button>
        </div>
      </div>
      <div class="settings-section license-action-panel">
        <div class="settings-section-title">${isActivated ? 'Replace licence' : 'Activate this installation'}</div>
        ${communityHint}
        <div class="settings-field">
          <label for="aegis-license-key">Licence key</label>
          <input id="aegis-license-key" class="settings-input text-mono" type="password" autocomplete="off" spellcheck="false" data-settings-transient placeholder="AEGIS-PRO-…">
        </div>
        <div class="settings-inline-actions">
          <button class="btn" type="button" data-settings-action="activate-license" data-license-action>${isActivated ? 'Replace licence' : 'Activate licence'}</button>
          ${isActivated ? '<button class="btn btn-outline" type="button" data-settings-action="refresh-license" data-license-action>Refresh now</button>' : ''}
        </div>
        ${isActivated ? `<div class="license-danger-actions"><div><strong>Deactivate this installation</strong><span>Remove the current licence from Aegis.</span></div><button class="btn btn-outline btn-danger" type="button" data-settings-action="deactivate-license" data-license-action>Deactivate licence</button></div>` : ''}
      </div>
    </div>`;
}

function renderLicenseOverview(license: LicenseSnapshot, statusTone: string, isCommunityBuild: boolean): string {
  const facts = [
    ['Licensed plan', escapeSectionHtml(formatLicenseLabel(license.licensed_tier))],
    ['Effective plan', escapeSectionHtml(formatLicenseLabel(license.effective_tier))],
    ...(isCommunityBuild ? [] : [
      ['Lease expires', formatLicenseDate(license.expires_at)],
      ['Offline grace ends', formatLicenseDate(license.offline_until)],
      ['Last checked', formatLicenseDate(license.last_refresh)]
    ])
  ];
  return `
    <section class="settings-section license-overview" aria-label="Installation licence status">
      <div class="license-overview-head">
        <div>
          <span class="license-overview-eyebrow">Installation licence</span>
          <strong>${escapeSectionHtml(formatLicenseLabel(license.effective_tier))}</strong>
        </div>
        ${['community', 'unlicensed'].includes((license.status || '').toLowerCase()) ? '' : `<span class="license-status ${statusTone}">${escapeSectionHtml(formatLicenseLabel(license.status))}</span>`}
      </div>
      <dl class="license-facts">
        ${facts.map(([label, value]) => `<div class="license-fact"><dt>${escapeSectionHtml(label)}</dt><dd>${value}</dd></div>`).join('')}
      </dl>
      ${license.last_error ? `<div class="license-warning" role="alert">${escapeSectionHtml(license.last_error)}</div>` : ''}
    </section>`;
}

function formatLicenseDate(value?: string): string {
  if (!value || value.startsWith('0001-')) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : escapeSectionHtml(date.toLocaleString());
}

function formatLicenseLabel(value?: string): string {
  if (!value) return 'Not available';
  return value.replace(/[_-]+/g, ' ').replace(/\b\w/g, character => character.toUpperCase());
}

function setLicenseActionsDisabled(isDisabled: boolean): void {
  AdminDOM.queryAll<HTMLButtonElement>('[data-license-action]').forEach(button => {
    button.disabled = isDisabled;
  });
  const panel = AdminDOM.query<HTMLElement>('.settings-panel-content');
  if (panel) panel.setAttribute('aria-busy', isDisabled ? 'true' : 'false');
}

function notifyLicenseChanged(): void {
  document.dispatchEvent(new CustomEvent('aegis:license-changed'));
}

async function applyUpgrade(): Promise<void> {
  openSystemUpdateModal();
}

async function handleCheckSystemUpdate(): Promise<void> {
  notify('Checking for software updates...', 'info');
  const status = await checkSystemUpdates(true);
  if (!status) {
    notify('Could not retrieve release catalog. Please check network connectivity.', 'error');
    return;
  }
  if (status.update_available) {
    openSystemUpdateModal(status);
  } else {
    notify(`Aegis is up to date (${status.current_version}).`, 'success');
  }
}

async function activateLicense(): Promise<void> {
  const key = AdminDOM.inputValue('aegis-license-key').trim();
  if (!key) {
    showLicenseErrorModal('Please enter a licence key before activating.');
    return;
  }
  setLicenseActionsDisabled(true);
  try {
    const res = await api.requestResult<{ license: LicenseSnapshot }>('license/activate', 'POST', { key });
    if (res.error) {
      showLicenseErrorModal(res.error.message || 'Licence activation failed.');
      return;
    }
    if (!res.data || !res.data.license) {
      showLicenseErrorModal('The licence activation response was invalid or empty.');
      return;
    }
    const input = AdminDOM.getInput('aegis-license-key');
    if (input) input.value = '';
    currentLicense = res.data.license;
    renderLicensePanel();
    notifyLicenseChanged();
    showLicenseCongratulationsModal(res.data.license.licensed_tier || res.data.license.effective_tier || 'professional', {
      expiresAt: res.data.license.expires_at,
      offlineUntil: res.data.license.offline_until,
      status: res.data.license.status
    });
    settingsShowToast(res.data.license.status === 'upgrade_required' ? 'Licence accepted; upgrade is ready' : 'Licence activated successfully', 'success');
  } catch (err: any) {
    showLicenseErrorModal(err?.message || 'Licence activation failed.');
  } finally {
    setLicenseActionsDisabled(false);
  }
}

async function refreshLicense(): Promise<void> {
  setLicenseActionsDisabled(true);
  try {
    const snapshot = await api.post<LicenseSnapshot>('license/refresh');
    if (!snapshot) return;
    currentLicense = snapshot;
    renderLicensePanel();
    notifyLicenseChanged();
    settingsShowToast('Licence refreshed', 'success');
  } finally {
    setLicenseActionsDisabled(false);
  }
}

function deactivateLicense(): void {
  SectionUI.openConfirmModal(
    'Deactivate licence',
    'Deactivate this installation and release its activation slot?',
    'Deactivate',
    'var(--danger)',
    async () => {
      SectionUI.closeModal();
      setLicenseActionsDisabled(true);
      try {
        const snapshot = await api.post<LicenseSnapshot>('license/deactivate');
        if (!snapshot) {
          await loadLicense();
          return;
        }
        currentLicense = snapshot;
        renderLicensePanel();
        notifyLicenseChanged();
        settingsShowToast('Installation deactivated', 'success');
      } finally {
        setLicenseActionsDisabled(false);
      }
    }
  );
}

function settingsShowToast(message: string, type: ToastType = 'info'): void {
  notify(message, type);
}

function getInputValue(id: string): string {
  return AdminDOM.inputValue(id);
}

function getCheckboxValue(id: string): boolean {
  return AdminDOM.checkboxValue(id);
}

function getNumberValue(id: string): number {
  return AdminDOM.numberValue(id);
}

function getSelectValue(id: string): string {
  return AdminDOM.selectValue(id);
}

function getTextareaValue(id: string): string {
  return AdminDOM.getTextarea(id)?.value || '';
}
