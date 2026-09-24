/**
 * Proxy settings page
 * Source of truth: web/admin/src/proxy-settings.ts
 * Runtime output: web/admin/dist/js/proxy-settings.js
 */

import { api, getErrorMessage, parseJsonSafe } from './api.js';
import * as AdminDOM from './core/dom.js';
import * as AdminEvents from './core/events.js';
import { notify } from './core/notify.js';
import { SectionUI } from './sections/ui-components.js';

type DeploymentMode = 'standalone' | 'behind_proxy' | 'sidecar' | 'kubernetes_ingress';
type ProxyProvider = 'nginx' | 'traefik' | 'apache' | 'caddy';

interface TrustedProxySettings {
  enabled: boolean;
  cidrs: string[];
  real_ip_headers: string[];
  proto_header: string;
  host_header: string;
  forwarded_header: boolean;
  recursive: boolean;
  source_urls: string[];
  source_files: string[];
  source_root: string;
  combined_list: string;
}

interface InfrastructureSettings {
  mode: DeploymentMode;
  proxy_provider: ProxyProvider;
  public_base_url: string;
  aegis_address: string;
  trusted_proxies: TrustedProxySettings;
}

interface ProxySettingsResponse {
  settings: InfrastructureSettings;
  runtime: {
    applied: boolean;
    restart_required: boolean;
    revision: string;
  };
  trusted_list: {
    path: string;
    exists: boolean;
    entries: number;
    updated_at?: string;
    configured_sources: number;
    error?: string;
  };
}

interface LegacyConfigResponse {
  infrastructure?: Partial<InfrastructureSettings> & {
    trusted_proxies?: Partial<TrustedProxySettings>;
  };
  server?: { port?: number };
}

interface ProxyGuideResponse {
  provider: string;
  title?: string;
  subtitle?: string;
  steps?: string[];
  template?: string;
}

const deploymentModeLabels: Record<DeploymentMode, string> = {
  standalone: 'Standalone (Direct)',
  behind_proxy: 'Behind Reverse Proxy',
  sidecar: 'Sidecar',
  kubernetes_ingress: 'Kubernetes Ingress'
};

const proxyProviderLabels: Record<ProxyProvider, string> = {
  nginx: 'Nginx',
  traefik: 'Traefik',
  apache: 'Apache',
  caddy: 'Caddy'
};

const proxyState = {
  bindingsReady: false,
  endpointAvailable: true,
  loaded: false,
  dirty: false,
  saving: false,
  mode: 'standalone' as DeploymentMode,
  provider: 'nginx' as ProxyProvider,
  publicBaseURL: 'https://example.com',
  aegisAddress: 'http://127.0.0.1:8080',
  trustedCIDRs: '127.0.0.1/32\n::1/128',
  trustedHeaders: 'X-Forwarded-For\nX-Real-IP',
  trustedSources: '',
  trustedFiles: '',
  sourceRoot: './data/trusted-proxies/sources',
  combinedList: './data/trusted-proxies/combined.list',
  recursive: true,
  forwardedHeader: false,
  runtimeApplied: false,
  restartRequired: false,
  revision: '',
  trustedListExists: false,
  trustedListEntries: 0,
  trustedListUpdatedAt: '',
  configuredSources: 0,
  trustedListError: '',
  guideTimer: 0,
  guideRequest: null as AbortController | null
};

export async function loadProxySettingsPage(): Promise<void> {
  bindProxySettingsEvents();
  const container = AdminDOM.getById('proxy-settings-container');
  if (!container) return;

  container.innerHTML = SectionUI.renderLoading('Loading proxy settings...');
  const response = await loadProxySettings();
  if (!response) {
    container.innerHTML = SectionUI.renderOperatorFrame({
      title: 'Proxy Settings',
      subtitle: 'The proxy settings configuration could not be loaded.',
      content: '<div class="empty-state"><p>Check the admin API and your infrastructure permissions, then reload this page.</p></div>',
      className: 'proxy-operator-frame'
    });
    return;
  }

  hydrateProxyState(response);
  proxyState.loaded = true;
  proxyState.dirty = false;
  renderProxySettings(container);
  void renderProxyGuide();
}

async function loadProxySettings(): Promise<ProxySettingsResponse | null> {
  try {
    const response = await fetch('/api/infrastructure/proxy-settings', { headers: { Accept: 'application/json' } });
    if (response.status === 404) {
      proxyState.endpointAvailable = false;
      const legacy = await api.get<LegacyConfigResponse>('config');
      return legacy ? legacyProxySettingsResponse(legacy) : null;
    }
    if (!response.ok) {
      const payload = await parseJsonSafe<{ error?: string }>(response, {});
      throw new Error(payload.error || `Request failed: ${response.status} for infrastructure/proxy-settings`);
    }
    proxyState.endpointAvailable = true;
    return await parseJsonSafe<ProxySettingsResponse | null>(response, null);
  } catch (error) {
    console.error('[Aegis Proxy Settings]', error);
    notify(getErrorMessage(error, 'Failed to load proxy settings'), 'error');
    return null;
  }
}

function legacyProxySettingsResponse(cfg: LegacyConfigResponse): ProxySettingsResponse {
  const infrastructure: NonNullable<LegacyConfigResponse['infrastructure']> = cfg.infrastructure || {};
  const trusted: Partial<TrustedProxySettings> = infrastructure.trusted_proxies || {};
  const mode = normalizeMode(infrastructure.mode);
  return {
    settings: {
      mode,
      proxy_provider: normalizeProvider(infrastructure.proxy_provider),
      public_base_url: infrastructure.public_base_url || 'https://example.com',
      aegis_address: infrastructure.aegis_address || `http://127.0.0.1:${cfg.server?.port || 8080}`,
      trusted_proxies: {
        enabled: mode !== 'standalone',
        cidrs: trusted.cidrs || ['127.0.0.1/32', '::1/128'],
        real_ip_headers: trusted.real_ip_headers || ['X-Forwarded-For', 'X-Real-IP'],
        proto_header: 'X-Forwarded-Proto',
        host_header: 'X-Forwarded-Host',
        forwarded_header: trusted.forwarded_header === true,
        recursive: trusted.recursive !== false,
        source_urls: trusted.source_urls || [],
        source_files: trusted.source_files || [],
        source_root: trusted.source_root || './data/trusted-proxies/sources',
        combined_list: trusted.combined_list || './data/trusted-proxies/combined.list'
      }
    },
    runtime: { applied: false, restart_required: true, revision: 'legacy-backend' },
    trusted_list: {
      path: trusted.combined_list || './data/trusted-proxies/combined.list',
      exists: false,
      entries: 0,
      configured_sources: (trusted.source_urls?.length || 0) + (trusted.source_files?.length || 0)
    }
  };
}

function hydrateProxyState(response: ProxySettingsResponse): void {
  const settings = response.settings;
  const trusted = settings.trusted_proxies;
  proxyState.mode = normalizeMode(settings.mode);
  proxyState.provider = normalizeProvider(settings.proxy_provider);
  proxyState.publicBaseURL = settings.public_base_url || 'https://example.com';
  proxyState.aegisAddress = settings.aegis_address || 'http://127.0.0.1:8080';
  proxyState.trustedCIDRs = (trusted.cidrs || []).join('\n');
  proxyState.trustedHeaders = (trusted.real_ip_headers || []).join('\n');
  proxyState.trustedSources = (trusted.source_urls || []).join('\n');
  proxyState.trustedFiles = (trusted.source_files || []).join('\n');
  proxyState.sourceRoot = trusted.source_root || './data/trusted-proxies/sources';
  proxyState.combinedList = trusted.combined_list || './data/trusted-proxies/combined.list';
  proxyState.recursive = trusted.recursive !== false;
  proxyState.forwardedHeader = trusted.forwarded_header === true;
  proxyState.runtimeApplied = response.runtime.applied;
  proxyState.restartRequired = response.runtime.restart_required;
  proxyState.revision = response.runtime.revision;
  proxyState.trustedListExists = response.trusted_list.exists;
  proxyState.trustedListEntries = response.trusted_list.entries;
  proxyState.trustedListUpdatedAt = response.trusted_list.updated_at || '';
  proxyState.configuredSources = response.trusted_list.configured_sources;
  proxyState.trustedListError = response.trusted_list.error || '';
}

function renderProxySettings(container: HTMLElement): void {
  const isStandalone = proxyState.mode === 'standalone';

  const content = `
    <div class="proxy-operator-stack">
      <div class="proxy-operator-grid">
        <div class="proxy-config-column">
          ${SectionUI.renderOperatorSection('Proxy Configuration', `
            <div class="proxy-settings-surface">
              <div class="operator-control-row proxy-setting-row">
                <div class="operator-control-main">
                  <span class="operator-control-copy">
                    <span class="operator-control-title">Deployment mode</span>
                  </span>
                </div>
                <div class="operator-control-actions proxy-setting-control">
                  <select id="proxy-mode" class="settings-input" data-proxy-settings-input aria-label="Deployment mode">
                    ${Object.entries(deploymentModeLabels).map(([value, label]) => `<option value="${value}" ${proxyState.mode === value ? 'selected' : ''}>${label}</option>`).join('')}
                  </select>
                </div>
              </div>

              ${proxyState.mode === 'behind_proxy' ? `
                <div class="operator-control-row proxy-setting-row">
                  <div class="operator-control-main">
                    <span class="operator-control-copy">
                      <span class="operator-control-title">Proxy server</span>
                    </span>
                  </div>
                  <div class="operator-control-actions proxy-setting-control">
                    <select id="proxy-provider" class="settings-input" data-proxy-settings-input aria-label="Proxy server">
                      ${Object.entries(proxyProviderLabels).map(([value, label]) => `<option value="${value}" ${proxyState.provider === value ? 'selected' : ''}>${label}</option>`).join('')}
                    </select>
                  </div>
                </div>` : ''}

              <div id="proxy-dynamic-fields" class="proxy-dynamic-fields">
                ${renderProxyFields(isStandalone)}
              </div>
            </div>
          `, { className: 'proxy-catalog-section proxy-ingress-section' })}
        </div>

        <div class="proxy-guide-column">
          ${SectionUI.renderOperatorSection('Configuration Guide', `
            <div class="proxy-guide-surface">
              <div class="proxy-guide-body">
                <div id="proxy-guide-steps" class="proxy-guide-steps"></div>
                <div id="proxy-guide-code-wrap" class="proxy-guide-code-wrap hidden">
                  <div class="proxy-guide-code-bar">
                    <span id="proxy-guide-filename" class="proxy-guide-filename">configuration</span>
                    <button type="button" class="btn btn-outline btn-xs" data-proxy-action="copy-guide-config">Copy</button>
                  </div>
                  <pre id="proxy-guide-config" class="proxy-guide-config"></pre>
                </div>
              </div>
            </div>
          `, { className: 'proxy-catalog-section proxy-guide-section' })}
        </div>
      </div>
    </div>
    ${SectionUI.renderSaveActionBar({
      actionAttr: 'data-proxy-settings-action',
      resetAction: 'reset',
      saveAction: 'save',
      resetLabel: 'Reset',
      saveLabel: 'Save Changes'
    })}`;

  container.innerHTML = SectionUI.renderOperatorFrame({
    title: 'Proxy Settings',
    kicker: 'Network',
    subtitle: 'Configure reverse proxy headers, deployment modes, and trusted client IP resolution.',
    content,
    className: 'proxy-operator-frame'
  });

  if (proxyState.dirty && !proxyState.saving) {
    SectionUI.markSaveActionBarDirty('data-proxy-settings-action');
  }
}

function renderProxyFields(isStandalone: boolean): string {
  if (isStandalone) {
    return '<div class="operator-inline-notice">Aegis is running in standalone mode. Reverse proxy headers and trusted CIDRs are disabled.</div>';
  }

  return `
    ${proxySettingRow('Public URL', '', `<input id="proxy-public-base-url" class="settings-input" aria-label="Public URL" value="${escapeHTML(proxyState.publicBaseURL)}" data-proxy-settings-input placeholder="https://example.com">`)}
    ${proxySettingRow('Aegis address', '', `<input id="proxy-aegis-address" class="settings-input" aria-label="Aegis address" value="${escapeHTML(proxyState.aegisAddress)}" data-proxy-settings-input placeholder="http://127.0.0.1:8080">`)}
    ${proxySettingRow('Trusted proxy CIDRs', 'One CIDR per line.', `<textarea id="proxy-trusted-cidrs" class="settings-input text-mono text-small" aria-label="Trusted proxy CIDRs" rows="4" data-proxy-settings-input placeholder="127.0.0.1/32&#10;::1/128">${escapeHTML(proxyState.trustedCIDRs)}</textarea>`, true)}
    ${proxySettingRow('Trusted proxy lists', 'One URL per line.', `<textarea id="proxy-trusted-sources" class="settings-input text-mono text-small" aria-label="Trusted proxy lists" rows="3" data-proxy-settings-input placeholder="https://example.com/ips.txt">${escapeHTML(proxyState.trustedSources)}</textarea>`, true)}
    ${proxyState.trustedListError ? `<div class="settings-hint text-danger" style="margin: 8px 18px 12px;">${escapeHTML(proxyState.trustedListError)}</div>` : ''}
    ${proxyToggleRow('Resolve proxy chains', 'Walk proxy chain backwards to determine original client IP.', 'proxy-recursive', proxyState.recursive)}
    <details class="proxy-advanced-settings">
      <summary>Advanced settings</summary>
      <div class="proxy-advanced-body">
        ${proxySettingRow('Real IP headers', 'One header per line in preference order.', `<textarea id="proxy-trusted-headers" class="settings-input text-mono text-small" aria-label="Real IP headers" rows="3" data-proxy-settings-input placeholder="X-Forwarded-For&#10;X-Real-IP">${escapeHTML(proxyState.trustedHeaders)}</textarea>`, true)}
        ${proxySettingRow('Local list files', 'One path per line.', `<textarea id="proxy-trusted-files" class="settings-input text-mono text-small" aria-label="Local list files" rows="2" data-proxy-settings-input placeholder="./data/trusted.list">${escapeHTML(proxyState.trustedFiles)}</textarea>`, true)}
        ${proxySettingRow('Local source root', '', `<input id="proxy-source-root" class="settings-input" aria-label="Local source root" value="${escapeHTML(proxyState.sourceRoot)}" data-proxy-settings-input placeholder="./data/trusted-proxies/sources">`)}
        ${proxyToggleRow('Accept Forwarded header', 'Parse standard RFC 7239 Forwarded headers.', 'proxy-forwarded-header', proxyState.forwardedHeader)}
      </div>
    </details>`;
}

function proxySettingRow(title: string, description: string, control: string, tall = false): string {
  return `<div class="operator-control-row proxy-setting-row${tall ? ' proxy-setting-row-tall' : ''}">
    <div class="operator-control-main">
      <span class="operator-control-copy">
        <span class="operator-control-title">${title}</span>
        ${description ? `<span class="operator-control-desc">${description}</span>` : ''}
      </span>
    </div>
    <div class="operator-control-actions proxy-setting-control">${control}</div>
  </div>`;
}

function proxyToggleRow(title: string, description: string, id: string, checked: boolean): string {
  return `<div class="operator-control-row proxy-setting-row proxy-toggle-row">
    <div class="operator-control-main">
      <span class="operator-control-copy">
        <label for="${id}" class="operator-control-title" style="cursor:pointer">${title}</label>
        ${description ? `<span class="operator-control-desc">${description}</span>` : ''}
      </span>
    </div>
    <div class="operator-control-actions">
      ${SectionUI.renderSwitch({
        id,
        checked,
        className: 'round',
        attrs: 'data-proxy-settings-input'
      })}
    </div>
  </div>`;
}

function bindProxySettingsEvents(): void {
  if (proxyState.bindingsReady) return;
  proxyState.bindingsReady = true;

  AdminEvents.delegateEvent<HTMLElement>(document, 'input', '#proxy-settings-container [data-proxy-settings-input]', () => {
    readProxyForm();
    markProxySettingsDirty();
    scheduleProxyGuide();
  });

  AdminEvents.delegateEvent<HTMLSelectElement>(document, 'change', '#proxy-settings-container #proxy-mode, #proxy-settings-container #proxy-provider', () => {
    readProxyForm();
    markProxySettingsDirty();
    const container = AdminDOM.getById('proxy-settings-container');
    if (container) renderProxySettings(container);
    void renderProxyGuide();
  });

  AdminEvents.delegateEvent<HTMLInputElement>(document, 'change', '#proxy-settings-container input[type="checkbox"][data-proxy-settings-input]', () => {
    readProxyForm();
    markProxySettingsDirty();
    scheduleProxyGuide();
  });

  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '#proxy-settings-container [data-proxy-action="copy-guide-config"]', async () => {
    const config = AdminDOM.getById('proxy-guide-config');
    const text = config?.textContent || '';
    if (!text.trim()) return;
    try {
      await navigator.clipboard.writeText(text);
      notify('Configuration copied to clipboard', 'success');
      const btn = AdminDOM.query<HTMLElement>('[data-proxy-action="copy-guide-config"]');
      if (btn) {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        window.setTimeout(() => { btn.textContent = orig; }, 2000);
      }
    } catch {
      notify('Could not copy to clipboard', 'error');
    }
  });

  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '#proxy-settings-container [data-proxy-settings-action="save"]', event => {
    event.preventDefault();
    void saveProxySettings();
  });

  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '#proxy-settings-container [data-proxy-settings-action="reset"]', event => {
    event.preventDefault();
    if (!proxyState.dirty || proxyState.saving) return;
    void loadProxySettingsPage();
  });
}

function readProxyForm(): void {
  proxyState.mode = normalizeMode(AdminDOM.selectValue('proxy-mode', proxyState.mode));
  proxyState.provider = normalizeProvider(AdminDOM.selectValue('proxy-provider', proxyState.provider));
  if (proxyState.mode === 'standalone') return;
  proxyState.publicBaseURL = AdminDOM.inputValue('proxy-public-base-url') || proxyState.publicBaseURL;
  proxyState.aegisAddress = AdminDOM.inputValue('proxy-aegis-address') || proxyState.aegisAddress;
  proxyState.trustedCIDRs = AdminDOM.textareaValue('proxy-trusted-cidrs');
  proxyState.trustedHeaders = AdminDOM.textareaValue('proxy-trusted-headers') || proxyState.trustedHeaders;
  proxyState.trustedSources = AdminDOM.textareaValue('proxy-trusted-sources');
  proxyState.trustedFiles = AdminDOM.textareaValue('proxy-trusted-files');
  proxyState.sourceRoot = AdminDOM.inputValue('proxy-source-root') || proxyState.sourceRoot;
  proxyState.recursive = AdminDOM.checkboxValue('proxy-recursive', true);
  proxyState.forwardedHeader = AdminDOM.checkboxValue('proxy-forwarded-header', false);
}

function markProxySettingsDirty(): void {
  proxyState.dirty = true;
  SectionUI.markSaveActionBarDirty('data-proxy-settings-action');
}

function buildProxySettingsPayload(): InfrastructureSettings {
  const standalone = proxyState.mode === 'standalone';
  return {
    mode: proxyState.mode,
    proxy_provider: proxyState.provider,
    public_base_url: proxyState.publicBaseURL,
    aegis_address: proxyState.aegisAddress,
    trusted_proxies: {
      enabled: !standalone,
      cidrs: lines(proxyState.trustedCIDRs),
      real_ip_headers: lines(proxyState.trustedHeaders),
      proto_header: 'X-Forwarded-Proto',
      host_header: 'X-Forwarded-Host',
      forwarded_header: !standalone && proxyState.forwardedHeader,
      recursive: proxyState.recursive,
      source_urls: lines(proxyState.trustedSources),
      source_files: lines(proxyState.trustedFiles),
      source_root: proxyState.sourceRoot,
      combined_list: proxyState.combinedList
    }
  };
}

async function saveProxySettings(): Promise<void> {
  if (!proxyState.loaded || proxyState.saving) return;
  readProxyForm();
  proxyState.saving = true;
  const container = AdminDOM.getById('proxy-settings-container');
  if (container) renderProxySettings(container);

  const payload = buildProxySettingsPayload();
  let response: ProxySettingsResponse | null = null;
  if (proxyState.endpointAvailable) {
    const result = await api.put<ProxySettingsResponse>('infrastructure/proxy-settings', payload);
    response = result === false ? null : result;
  } else {
    const result = await api.post('config', { infrastructure: payload });
    if (result !== false) {
      response = legacyProxySettingsResponse({ infrastructure: payload });
    }
  }

  proxyState.saving = false;
  if (!response) {
    if (container) renderProxySettings(container);
    return;
  }
  hydrateProxyState(response);
  proxyState.dirty = false;
  if (container) renderProxySettings(container);
  void renderProxyGuide();
  notify(response.runtime.restart_required ? 'Proxy settings saved. Restart Aegis to apply them.' : 'Proxy settings saved and applied live', response.runtime.restart_required ? 'warning' : 'success');
}

function scheduleProxyGuide(): void {
  if (proxyState.guideTimer) window.clearTimeout(proxyState.guideTimer);
  proxyState.guideTimer = window.setTimeout(() => void renderProxyGuide(), 250);
}

function getGuideFilename(provider: string): string {
  switch (provider) {
    case 'nginx': return 'nginx.conf';
    case 'traefik': return 'traefik.yaml';
    case 'caddy': return 'Caddyfile';
    case 'apache': return 'httpd.conf';
    case 'sidecar': return 'sidecar.yaml';
    case 'kubernetes_ingress': return 'ingress.yaml';
    default: return 'config.yaml';
  }
}

async function renderProxyGuide(): Promise<void> {
  const steps = AdminDOM.getById('proxy-guide-steps');
  const config = AdminDOM.getById('proxy-guide-config');
  const codeWrap = AdminDOM.getById('proxy-guide-code-wrap');
  const filename = AdminDOM.getById('proxy-guide-filename');
  const sectionTitle = AdminDOM.query('#proxy-settings-container .proxy-guide-section .operator-section-title');
  if (!steps || !config) return;

  proxyState.guideRequest?.abort();
  const controller = new AbortController();
  proxyState.guideRequest = controller;
  const provider = proxyState.mode === 'behind_proxy' ? proxyState.provider : proxyState.mode;
  const query = new URLSearchParams({ public_base_url: proxyState.publicBaseURL, aegis_address: proxyState.aegisAddress });
  const metaFilename = getGuideFilename(provider);
  if (filename) filename.textContent = metaFilename;

  try {
    const response = await fetch(`/api/infrastructure/templates/${encodeURIComponent(provider)}?${query}`, { headers: { Accept: 'application/json' }, signal: controller.signal });
    if (!response.ok) throw new Error(`Guide request failed: ${response.status}`);
    const guide = await parseJsonSafe<ProxyGuideResponse>(response, { provider });
    if (controller.signal.aborted) return;
    const display = compactGuide(provider, guide.title || '', guide.steps || []);
    if (sectionTitle) sectionTitle.textContent = `${display.title} Guide`;
    steps.innerHTML = display.steps.map((step, i) => `
      <div class="proxy-guide-step">
        <span class="proxy-guide-step-idx">${i + 1}</span>
        <span class="proxy-guide-step-text">${escapeHTML(step)}</span>
      </div>
    `).join('');
    config.textContent = guide.template || '';
    const hasTemplate = Boolean(guide.template?.trim());
    if (codeWrap) codeWrap.classList.toggle('hidden', !hasTemplate);
    config.classList.toggle('hidden', !hasTemplate);
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    if (sectionTitle) sectionTitle.textContent = 'Configuration Guide';
    steps.innerHTML = '';
    config.textContent = '';
    if (codeWrap) codeWrap.classList.add('hidden');
    config.classList.add('hidden');
  }
}

function compactGuide(provider: string, fallbackTitle: string, fallbackSteps: string[]): { title: string; steps: string[] } {
  const guides: Record<string, { title: string; steps: string[] }> = {
    standalone: {
      title: 'Standalone',
      steps: [
        'Configure TLS in SSL Certificates.',
        'Define route rules in Routing.',
        'Configure upstream backends in Origins.'
      ]
    },
    nginx: {
      title: 'Nginx',
      steps: [
        'Configure your Nginx server block with the snippet below.',
        'Forward incoming traffic to your Aegis address.',
        'Add the Nginx server IP or subnet to Trusted proxy CIDRs.'
      ]
    },
    traefik: {
      title: 'Traefik',
      steps: [
        'Create a router and service pointing to Aegis.',
        'Forward client headers to Aegis.',
        'Add the Traefik IP or subnet to Trusted proxy CIDRs.'
      ]
    },
    caddy: {
      title: 'Caddy',
      steps: [
        'Add reverse_proxy directive pointing to your Aegis address.',
        'Add the Caddy server IP or subnet to Trusted proxy CIDRs.'
      ]
    },
    apache: {
      title: 'Apache',
      steps: [
        'Enable mod_proxy and mod_proxy_http.',
        'Configure ProxyPass to forward requests to Aegis.',
        'Add the Apache server IP or subnet to Trusted proxy CIDRs.'
      ]
    },
    sidecar: {
      title: 'Sidecar',
      steps: [
        'Route incoming container traffic through the Aegis sidecar.',
        'Add the local pod or container network to Trusted proxy CIDRs.'
      ]
    },
    kubernetes_ingress: {
      title: 'Kubernetes Ingress',
      steps: [
        'Create a Kubernetes Service pointing to your Aegis pods.',
        'Configure an Ingress resource directing traffic to the Service.',
        'Add the ingress controller CIDRs to Trusted proxy CIDRs.'
      ]
    }
  };
  return guides[provider] || { title: fallbackTitle || 'Configuration', steps: fallbackSteps.slice(0, 3) };
}

function normalizeMode(value: unknown): DeploymentMode {
  return value === 'behind_proxy' || value === 'sidecar' || value === 'kubernetes_ingress' ? value : 'standalone';
}

function normalizeProvider(value: unknown): ProxyProvider {
  return value === 'traefik' || value === 'apache' || value === 'caddy' ? value : 'nginx';
}

function lines(value: string): string[] {
  return value.split('\n').map(item => item.trim()).filter(Boolean);
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function escapeHTML(value: string): string {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
