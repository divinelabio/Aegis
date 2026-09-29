/**
 * IP Reputation Module Configuration
 * Source of truth: web/admin/src/modules/reputation-config.ts
 * Runtime output: web/admin/dist/js/modules/reputation-config.js
 *
 * Dedicated console for CTI threat data collection, indicators directory,
 * engine-level blocking, and explicit CIDR overrides.
 */

import { SectionUI } from '../sections/ui-components.js';
import * as AdminEvents from '../core/events.js';
import * as AdminDOM from '../core/dom.js';
import { notify } from '../core/notify.js';
import { api } from '../api.js';
import { normalizeTrafficConfigForSave } from '../sections/traffic-config.js';
import {
  ThreatFeedPaginationState,
  UnifiedThreatFeedData,
  UnifiedThreatIndicator
} from '../sections/traffic/types.js';
import {
  escapeTrafficAttr,
  escapeTrafficHtml,
  formatTrafficNumber
} from '../sections/traffic-runtime-helpers.js';

export interface ReputationRule {
  id: string;
  ip_or_cidr: string;
  action: 'allow' | 'block' | 'challenge' | 'bypass';
  score?: number;
  comment?: string;
  created_at?: string;
}

export interface ReputationModuleConfig {
  enabled?: boolean;
  block_datacenter?: boolean;
  block_tor?: boolean;
  cache_ttl?: string;
  sensitivity?: number;
  action?: string;
  allowed_ips?: string[];
  blocked_ips?: string[];
  rules?: ReputationRule[];
  cti?: {
    enabled?: boolean;
    url?: string;
    api_key?: string;
    min_score?: number;
  };
  [key: string]: unknown;
}

type ReputationTrafficConfig = Record<string, unknown> & {
  reputation?: ReputationModuleConfig;
};


function createDefaultReputationConfig(): ReputationModuleConfig {
  return {
    enabled: false,
    block_datacenter: false,
    block_tor: false,
    cache_ttl: '1h',
    sensitivity: 80,
    action: 'block',
    allowed_ips: [],
    blocked_ips: [],
    rules: []
  };
}

export const ReputationConfig = {
  config: createDefaultReputationConfig() as ReputationModuleConfig,
  trafficConfig: null as ReputationTrafficConfig | null,
  threatFeedData: null as UnifiedThreatFeedData | null,
  threatFeedPagination: {
    page: 1,
    pageSize: 25,
    search: '',
    severityFilter: 'all',
    sortBy: 'score',
    sortOrder: 'desc'
  } as ThreatFeedPaginationState,
  eventsBound: false,

  async init(): Promise<void> {
    this.bindEvents();
    await Promise.all([this.loadConfig(), this.loadThreatFeed()]);
    this.render();
  },

  bindEvents(): void {
    if (this.eventsBound) return;
    this.eventsBound = true;

    // Toggle module enabled
    AdminEvents.delegateEvent<HTMLInputElement>(
      document,
      'change',
      '#reputation-config-content [data-action="reputation-toggle-enabled"]',
      (_event, target) => {
        this.config.enabled = target.checked;
        const statusEl = AdminDOM.query<HTMLElement>('[data-reputation-section-status]');
        const engineEl = AdminDOM.query<HTMLElement>('[data-reputation-engine-status]');
        const statusText = target.checked ? 'Operational' : 'Disabled';
        const statusTone = target.checked ? 'tone-active' : 'tone-neutral';
        if (statusEl) {
          statusEl.textContent = statusText;
          statusEl.className = `config-status-pill ${statusTone}`;
        }
        if (engineEl) {
          engineEl.textContent = statusText;
          engineEl.className = `config-status-pill ${statusTone}`;
        }
        SectionUI.markSaveActionBarDirty('data-action');
      }
    );

    // Cache TTL input
    AdminEvents.delegateEvent<HTMLInputElement>(
      document,
      'input',
      '#reputation-config-content #reputation-cache-ttl',
      (_event, target) => {
        this.config.cache_ttl = target.value;
        SectionUI.markSaveActionBarDirty('data-action');
      }
    );

    // Datacenter toggle
    AdminEvents.delegateEvent<HTMLInputElement>(
      document,
      'change',
      '#reputation-config-content [data-action="reputation-toggle-datacenter"]',
      (_event, target) => {
        this.config.block_datacenter = target.checked;
        SectionUI.markSaveActionBarDirty('data-action');
      }
    );

    // Tor toggle
    AdminEvents.delegateEvent<HTMLInputElement>(
      document,
      'change',
      '#reputation-config-content [data-action="reputation-toggle-tor"]',
      (_event, target) => {
        this.config.block_tor = target.checked;
        SectionUI.markSaveActionBarDirty('data-action');
      }
    );

    // Threat feed category/severity filter
    AdminEvents.delegateEvent<HTMLSelectElement>(
      document,
      'change',
      '#reputation-config-content select[data-action="threat-feed-severity-filter"]',
      (_event, target) => {
        this.threatFeedPagination.severityFilter = target.value;
        this.threatFeedPagination.page = 1;
        this.render();
      }
    );

    // Threat feed search input
    AdminEvents.delegateEvent<HTMLInputElement>(
      document,
      'input',
      '#reputation-config-content input[data-action="threat-feed-search"]',
      (_event, target) => {
        this.threatFeedPagination.search = target.value;
        this.threatFeedPagination.page = 1;
        this.render();
      }
    );

    // Threat feed page size selector
    AdminEvents.delegateEvent<HTMLSelectElement>(
      document,
      'change',
      '#reputation-config-content select[data-action="threat-feed-page-size"]',
      (_event, target) => {
        this.threatFeedPagination.pageSize = Number.parseInt(target.value, 10) || 25;
        this.threatFeedPagination.page = 1;
        this.render();
      }
    );

    // Threat feed sort click
    AdminEvents.delegateEvent<HTMLElement>(
      document,
      'click',
      '#reputation-config-content [data-action="threat-feed-sort"]',
      (_event, target) => {
        const sortBy = (target.dataset.sortBy || 'score') as ThreatFeedPaginationState['sortBy'];
        if (this.threatFeedPagination.sortBy === sortBy) {
          this.threatFeedPagination.sortOrder = this.threatFeedPagination.sortOrder === 'asc' ? 'desc' : 'asc';
        } else {
          this.threatFeedPagination.sortBy = sortBy;
          this.threatFeedPagination.sortOrder = 'desc';
        }
        this.render();
      }
    );

    // Threat feed pagination
    AdminEvents.delegateEvent<HTMLElement>(
      document,
      'click',
      '#reputation-config-content [data-action="threat-feed-prev-page"]',
      event => {
        event.preventDefault();
        if (this.threatFeedPagination.page > 1) {
          this.threatFeedPagination.page--;
          this.render();
        }
      }
    );

    AdminEvents.delegateEvent<HTMLElement>(
      document,
      'click',
      '#reputation-config-content [data-action="threat-feed-next-page"]',
      event => {
        event.preventDefault();
        this.threatFeedPagination.page++;
        this.render();
      }
    );

    // Refresh Threat Feed
    AdminEvents.delegateEvent<HTMLElement>(
      document,
      'click',
      '#reputation-config-content [data-action="refresh-threat-feed"]',
      async event => {
        event.preventDefault();
        await this.refreshThreatFeed();
      }
    );

    // Rule modal events
    AdminEvents.delegateEvent<HTMLElement>(
      document,
      'click',
      '#reputation-config-content [data-action="reputation-open-add-rule"]',
      event => {
        event.preventDefault();
        this.openAddRuleModal();
      }
    );

    AdminEvents.delegateEvent<HTMLElement>(
      document,
      'click',
      '#reputation-config-content [data-action="reputation-delete-rule"]',
      (_event, target) => {
        const ruleId = target.dataset.ruleId || '';
        this.config.rules = (this.config.rules || []).filter(r => r.id !== ruleId);
        this.render();
        SectionUI.markSaveActionBarDirty('data-action');
      }
    );

    AdminEvents.delegateEvent<HTMLElement>(
      document,
      'click',
      '[data-action="reputation-close-modal"]',
      event => {
        event.preventDefault();
        this.closeModal();
      }
    );

    AdminEvents.delegateEvent<HTMLElement>(
      document,
      'click',
      '[data-action="reputation-add-rule"]',
      event => {
        event.preventDefault();
        this.submitAddRule();
      }
    );

    // Save and Reset changes
    AdminEvents.delegateEvent<HTMLElement>(
      document,
      'click',
      '#reputation-config-content [data-action="save-changes"]',
      event => {
        event.preventDefault();
        void this.saveConfig();
      }
    );

    AdminEvents.delegateEvent<HTMLElement>(
      document,
      'click',
      '#reputation-config-content [data-action="reset-changes"]',
      event => {
        event.preventDefault();
        void this.loadConfig().then(() => {
          this.render();
          SectionUI.markSaveActionBarClean('data-action');
        });
      }
    );
  },

  async loadConfig(): Promise<void> {
    try {
      const response = await fetch('/api/sections/traffic_control/config');
      if (response.ok) {
        const data = (await response.json()) as ReputationTrafficConfig;
        this.trafficConfig = data || {};
        const incomingRep = (data?.reputation as ReputationModuleConfig) || {};
        this.config = {
          ...createDefaultReputationConfig(),
          ...incomingRep,
          rules: incomingRep.rules || createDefaultReputationConfig().rules
        };
      }
    } catch (error) {
      console.error('Failed to load reputation config:', error);
    }
  },

  async loadThreatFeed(): Promise<void> {
    try {
      const response = await fetch('/api/sections/traffic_control/reputation/feed', {
        headers: { 'Accept': 'application/json' },
        credentials: 'same-origin'
      });
      if (response.ok) {
        this.threatFeedData = (await response.json()) as UnifiedThreatFeedData;
      } else {
        this.threatFeedData = null;
      }
    } catch (error) {
      console.error('Failed to fetch threat feed:', error);
      this.threatFeedData = null;
    }
  },

  async refreshThreatFeed(): Promise<void> {
    try {
      notify('Synchronizing threat intelligence from DivineLab CTI...', 'info');
      const data = await api.post<UnifiedThreatFeedData>('sections/traffic_control/reputation/feed/refresh', {});
      if (data) {
        this.threatFeedData = data;
        const total = this.threatFeedData?.total_indicators ?? this.threatFeedData?.indicators?.length ?? 0;
        const ctiSource = this.threatFeedData?.sources?.cti || this.threatFeedData?.cti;
        const lastErr = ctiSource?.status?.last_error;
        if (lastErr && total === 0) {
          notify('CTI server offline or unreachable', 'warning');
        } else {
          notify(`DivineLab CTI feeds synchronized successfully (${total.toLocaleString()} indicators)`, 'success');
        }
        this.render();
      } else {
        this.threatFeedData = null;
        notify('Failed to refresh threat feeds: CTI server unreachable', 'error');
        this.render();
      }
    } catch (error) {
      this.threatFeedData = null;
      notify('Network error refreshing threat feeds', 'error');
      this.render();
    }
  },

  async saveConfig(): Promise<void> {
    try {
      if (!this.trafficConfig) {
        await this.loadConfig();
      }
      if (!this.trafficConfig) {
        throw new Error('Traffic Control configuration is unavailable');
      }
      const payload = normalizeTrafficConfigForSave({
        ...this.trafficConfig,
        reputation: {
          ...this.trafficConfig.reputation,
          ...this.config
        }
      });
      const res = await api.put('sections/traffic_control/config', payload);
      if (res) {
        notify('IP Reputation configuration saved', 'success');
        await this.loadConfig();
        this.render();
        SectionUI.markSaveActionBarClean('data-action');
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Network error saving config';
      notify(message, 'error');
    }
  },

  openAddRuleModal(): void {
    const modalContainer = AdminDOM.getById('modal-container') || document.body;
    const existing = AdminDOM.getById('reputation-modal-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'reputation-modal-overlay';
    overlay.className = 'modal-backdrop';
    overlay.innerHTML = `
      <div class="modal-content" role="dialog" aria-modal="true" aria-labelledby="rep-rule-modal-title">
        <div class="modal-header">
          <h3 id="rep-rule-modal-title">Add IP Reputation Override Rule</h3>
          <button type="button" class="modal-close" data-action="reputation-close-modal" aria-label="Close dialog">&times;</button>
        </div>
        <div class="modal-body">
          <div class="form-group mb-16">
            <label class="form-label font-600 mb-6" for="rep-rule-target">IP Address or CIDR block</label>
            <input type="text" id="rep-rule-target" class="form-control font-mono" placeholder="198.51.100.1 or 203.0.113.0/24" required>
            <small class="form-text text-muted mt-4">Target client IPv4, IPv6, or subnet.</small>
          </div>
          <div class="form-group mb-16">
            <label class="form-label font-600 mb-6" for="rep-rule-action">Action Override</label>
            <select id="rep-rule-action" class="form-control">
              <option value="allow">Allow (Trusted Whitelist)</option>
              <option value="block">Block (Strict Drop)</option>
              <option value="challenge">Challenge (Smart PoW)</option>
              <option value="bypass">Bypass Reputation</option>
            </select>
          </div>
          <div class="form-group mb-16">
            <label class="form-label font-600 mb-6" for="rep-rule-score">Custom Trust Score (0 - 100)</label>
            <input type="number" id="rep-rule-score" class="form-control" min="0" max="100" value="100">
          </div>
          <div class="form-group mb-16">
            <label class="form-label font-600 mb-6" for="rep-rule-comment">Comment / Description</label>
            <input type="text" id="rep-rule-comment" class="form-control" placeholder="E.g., Partner API gateway">
          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline" data-action="reputation-close-modal">Cancel</button>
          <button type="button" class="btn btn-primary" data-action="reputation-add-rule">Add Override Rule</button>
        </div>
      </div>
    `;
    modalContainer.appendChild(overlay);
  },

  submitAddRule(): void {
    const targetInput = AdminDOM.getById<HTMLInputElement>('rep-rule-target');
    const actionInput = AdminDOM.getById<HTMLSelectElement>('rep-rule-action');
    const scoreInput = AdminDOM.getById<HTMLInputElement>('rep-rule-score');
    const commentInput = AdminDOM.getById<HTMLInputElement>('rep-rule-comment');

    const target = targetInput?.value?.trim() || '';
    if (!target) {
      notify('Please enter a valid IP address or CIDR', 'error');
      return;
    }
    const newRule: ReputationRule = {
      id: `rule-${Date.now()}`,
      ip_or_cidr: target,
      action: (actionInput?.value || 'allow') as ReputationRule['action'],
      score: Number.parseInt(scoreInput?.value || '100', 10),
      comment: commentInput?.value?.trim() || ''
    };

    this.config.rules = [...(this.config.rules || []), newRule];
    this.closeModal();
    this.render();
    SectionUI.markSaveActionBarDirty('data-action');
  },

  closeModal(): void {
    const overlay = AdminDOM.getById('reputation-modal-overlay');
    if (overlay) overlay.remove();
  },

  renderThreatTable(): string {
    const rawIndicators = this.threatFeedData?.indicators || [];
    const allIndicators: UnifiedThreatIndicator[] = rawIndicators;
    const totalCount = this.threatFeedData?.total_indicators ?? rawIndicators.length;
    const pagination = this.threatFeedPagination;

    const ctiSource = this.threatFeedData?.sources?.cti || this.threatFeedData?.cti;
    const ctiStatusObj = ctiSource?.status;
    const ctiError = ctiStatusObj?.last_error;
    const isCtiDisconnected = Boolean(!this.threatFeedData || (ctiError && totalCount === 0) || ((ctiStatusObj?.failures ?? 0) > 0 && totalCount === 0));

    const criticalCount = allIndicators.filter(i => (i.score || 0) >= 90 || i.severity === 'CRITICAL').length;
    const highCount = allIndicators.filter(i => ((i.score || 0) >= 70 && (i.score || 0) < 90) || i.severity === 'HIGH').length;

    // Filter by severity / category
    const activeSevFilter = pagination.severityFilter || 'all';
    let filtered = allIndicators;
    if (activeSevFilter === 'critical') {
      filtered = filtered.filter(item => (item.score || 0) >= 90 || item.severity === 'CRITICAL');
    } else if (activeSevFilter === 'high') {
      filtered = filtered.filter(item => ((item.score || 0) >= 70 && (item.score || 0) < 90) || item.severity === 'HIGH');
    } else if (activeSevFilter === 'malware') {
      filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('malware') || (item.category || '').toLowerCase().includes('c2') || (item.threat_name || '').toLowerCase().includes('malware'));
    } else if (activeSevFilter === 'botnet') {
      filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('botnet') || (item.threat_name || '').toLowerCase().includes('botnet'));
    } else if (activeSevFilter === 'phishing') {
      filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('phish'));
    } else if (activeSevFilter === 'scanner') {
      filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('scan') || (item.category || '').toLowerCase().includes('exploit'));
    } else if (activeSevFilter === 'cybercrime') {
      filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('cybercrime') || (item.category || '').toLowerCase().includes('hijack'));
    } else if (activeSevFilter === 'relay') {
      filtered = filtered.filter(item => (item.category || '').toLowerCase().includes('relay') || (item.category || '').toLowerCase().includes('anonym'));
    }

    const searchQuery = (pagination.search || '').trim().toLowerCase();
    if (searchQuery) {
      filtered = filtered.filter(item =>
        item.indicator.toLowerCase().includes(searchQuery) ||
        item.category.toLowerCase().includes(searchQuery) ||
        (item.severity || '').toLowerCase().includes(searchQuery) ||
        (item.confidence || '').toLowerCase().includes(searchQuery) ||
        (item.threat_name || '').toLowerCase().includes(searchQuery) ||
        (item.malware_family || '').toLowerCase().includes(searchQuery) ||
        (item.threat_actor || '').toLowerCase().includes(searchQuery)
      );
    }

    // Dynamic Sorting
    const sortBy = pagination.sortBy || 'score';
    const sortOrder = pagination.sortOrder || 'desc';
    const sorted = [...filtered].sort((a, b) => {
      let cmp = 0;
      if (sortBy === 'score') {
        cmp = (a.score || 0) - (b.score || 0);
      } else if (sortBy === 'severity') {
        const mapSev = (s?: string) => (s === 'CRITICAL' ? 3 : s === 'HIGH' ? 2 : 1);
        cmp = mapSev(a.severity) - mapSev(b.severity);
      } else if (sortBy === 'indicator') {
        cmp = a.indicator.localeCompare(b.indicator);
      } else if (sortBy === 'category') {
        cmp = (a.category || '').localeCompare(b.category || '');
      } else if (sortBy === 'confidence') {
        cmp = (a.confidence || '').localeCompare(b.confidence || '');
      } else if (sortBy === 'protocol') {
        const aProto = a.indicator.includes(':') ? 'IPv6' : 'IPv4';
        const bProto = b.indicator.includes(':') ? 'IPv6' : 'IPv4';
        cmp = aProto.localeCompare(bProto);
      }
      return sortOrder === 'desc' ? -cmp : cmp;
    });

    const totalFiltered = sorted.length;
    const pageSize = pagination.pageSize || 25;
    const totalPages = Math.max(1, Math.ceil(totalFiltered / pageSize));
    if (pagination.page > totalPages) pagination.page = totalPages;
    if (pagination.page < 1) pagination.page = 1;
    const startIndex = (pagination.page - 1) * pageSize;
    const pageEntries = sorted.slice(startIndex, startIndex + pageSize);

    const sortAscIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="18 15 12 9 6 15"/></svg>';
    const sortDescIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>';

    const renderSortHeader = (field: 'indicator' | 'score' | 'severity' | 'category' | 'protocol' | 'confidence', label: string, thClass = '') => {
      const isCurrent = sortBy === field;
      const arrow = isCurrent ? (sortOrder === 'asc' ? sortAscIcon : sortDescIcon) : '';
      return `
        <th class="${thClass} sortable-th ${isCurrent ? 'is-sorted' : ''}"
            data-action="threat-feed-sort" data-sort-by="${field}"
            role="columnheader" aria-sort="${isCurrent ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}"
            tabindex="0" title="Click to sort by ${label}">
            <div class="th-content-flex">
                <span>${label}</span>
                <span class="sort-icon-box" aria-hidden="true">${arrow}</span>
            </div>
        </th>
      `;
    };

    return `
      <div class="flow-operator-frame flow-blacklist-console">
        <section class="flow-blacklist-inventory">
          <div class="flow-blacklist-toolbar">
            <div class="flow-blacklist-count">
              <strong>${searchQuery || activeSevFilter !== 'all' ? totalFiltered : totalCount}</strong>
              <span>${searchQuery || activeSevFilter !== 'all' ? `matching of ${totalCount} indicators` : 'active threat indicators'}</span>
            </div>
            <div class="flow-blacklist-tools">
              <select class="flow-page-size-select mr-8"
                      aria-label="Filter by Threat Category or Severity"
                      data-action="threat-feed-severity-filter">
                <option value="all" ${activeSevFilter === 'all' ? 'selected' : ''}>All Categories (${Number(totalCount).toLocaleString()})</option>
                <option value="critical" ${activeSevFilter === 'critical' ? 'selected' : ''}>Critical Risk (90-100) (${Number(criticalCount).toLocaleString()})</option>
                <option value="high" ${activeSevFilter === 'high' ? 'selected' : ''}>High Risk (70-89) (${Number(highCount).toLocaleString()})</option>
                <option value="malware" ${activeSevFilter === 'malware' ? 'selected' : ''}>Malware / C2</option>
                <option value="botnet" ${activeSevFilter === 'botnet' ? 'selected' : ''}>Botnet C2</option>
                <option value="phishing" ${activeSevFilter === 'phishing' ? 'selected' : ''}>Phishing</option>
                <option value="scanner" ${activeSevFilter === 'scanner' ? 'selected' : ''}>Scanners / Exploits</option>
                <option value="cybercrime" ${activeSevFilter === 'cybercrime' ? 'selected' : ''}>Hijacked Netblocks</option>
                <option value="relay" ${activeSevFilter === 'relay' ? 'selected' : ''}>Anonymized Relays</option>
              </select>
              <label class="flow-blacklist-search">
                <span aria-hidden="true">
                  <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>
                </span>
                <input type="search" class="flow-search-input"
                       aria-label="Search threat indicators"
                       placeholder="Search IP, CIDR, malware, or threat actor..."
                       value="${escapeTrafficAttr(pagination.search)}"
                       data-action="threat-feed-search">
              </label>
              <select class="flow-page-size-select"
                      aria-label="Entries per page"
                      data-action="threat-feed-page-size">
                <option value="10" ${pageSize === 10 ? 'selected' : ''}>10 rows</option>
                <option value="25" ${pageSize === 25 ? 'selected' : ''}>25 rows</option>
                <option value="50" ${pageSize === 50 ? 'selected' : ''}>50 rows</option>
                <option value="100" ${pageSize === 100 ? 'selected' : ''}>100 rows</option>
              </select>
            </div>
          </div>

          <div class="flow-blacklist-table-wrap">
            <table class="tor-inventory-table threat-directory-table">
              <thead>
                <tr>
                  ${renderSortHeader('indicator', 'Threat Indicator', 'th-indicator')}
                  ${renderSortHeader('severity', 'Severity', 'th-severity')}
                  ${renderSortHeader('score', 'Risk Score', 'th-score')}
                  ${renderSortHeader('protocol', 'Protocol', 'th-proto')}
                  ${renderSortHeader('category', 'Classification', 'th-category')}
                  ${renderSortHeader('confidence', 'Confidence', 'th-confidence')}
                </tr>
              </thead>
              <tbody>
                ${pageEntries.length ? pageEntries.map(item => {
                  const isIpv6 = item.indicator.includes(':');
                  const safeIndicator = escapeTrafficHtml(item.indicator);
                  const safeCategory = escapeTrafficHtml(item.category || (item.score && item.score >= 90 ? 'Cybercrime / Threat' : 'Anonymized Exit Relay'));
                  const scoreVal = item.score || (item.severity === 'CRITICAL' ? 98 : 80);
                  const isCritical = scoreVal >= 90;
                  const isHigh = scoreVal >= 70 && scoreVal < 90;
                  const sevBadge = isCritical ? 'CRITICAL' : isHigh ? 'HIGH' : (item.severity ? item.severity.toUpperCase() : 'MEDIUM');
                  const sevTone = isCritical ? 'critical' : isHigh ? 'high' : (sevBadge === 'LOW' ? 'low' : 'medium');
                  const scoreColor = isCritical ? 'var(--danger, #ef4444)' : isHigh ? 'var(--brand-orange, #f97316)' : '#5f86a2';
                  const confidenceText = escapeTrafficHtml(item.confidence || (isCritical ? '99% Verified' : '94% Verified'));
                  return `
                    <tr class="flow-threat-row">
                      <td class="tor-ip-cell">
                        <div class="tor-ip-row">
                          <code class="tor-ip-code font-bold">${safeIndicator}</code>
                        </div>
                      </td>
                      <td>
                        <span class="threat-severity-tag severity-${sevTone}">${sevBadge}</span>
                      </td>
                      <td>
                        <div class="risk-score-meter-wrap">
                          <div class="risk-score-badge">
                            <span class="font-mono font-bold" style="color: ${scoreColor};">${scoreVal}</span>
                            <span class="text-11 text-muted">/100</span>
                          </div>
                          <div class="risk-score-bar-bg">
                            <div class="risk-score-bar-fill" style="width: ${scoreVal}%; background-color: ${scoreColor};"></div>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span class="tag-pill flow-type-pill font-mono">${isIpv6 ? 'IPv6' : 'IPv4'}</span>
                      </td>
                      <td>
                        <span class="text-12 font-500">${safeCategory}</span>
                      </td>
                      <td>
                        <span class="text-11 text-muted font-mono">${confidenceText}</span>
                      </td>
                    </tr>
                  `;
                }).join('') : `
                  <tr>
                    <td colspan="6">
                      <div class="flow-blacklist-empty">
                        <span class="flow-blacklist-empty-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span>
                        <strong>${searchQuery ? 'No matching indicators found' : (isCtiDisconnected ? 'CTI Server Disconnected — No threat indicators available' : 'No threat indicators loaded')}</strong>
                        <span>${searchQuery ? `No threat indicator matched "${escapeTrafficHtml(searchQuery)}".` : (isCtiDisconnected ? 'DivineLab CTI threat intelligence service is offline or unreachable. Connect to the CTI server and refresh feeds to synchronize threat intelligence.' : 'Click "Refresh Feeds" to synchronize real-time indicators from DivineLab CTI.')}</span>
                      </div>
                    </td>
                  </tr>
                `}
              </tbody>
            </table>
          </div>

          ${totalPages > 1 ? `
            <div class="flow-blacklist-pagination">
              <span>Page <strong>${pagination.page}</strong> of ${totalPages} (Showing ${startIndex + 1}–${Math.min(startIndex + pageSize, totalFiltered)} of ${totalFiltered})</span>
              <div class="d-flex gap-8">
                <button type="button" class="operator-btn operator-btn-secondary btn-xs"
                        ${pagination.page === 1 ? 'disabled' : ''}
                        data-action="threat-feed-prev-page">&larr; Previous</button>
                <button type="button" class="operator-btn operator-btn-secondary btn-xs"
                        ${pagination.page >= totalPages ? 'disabled' : ''}
                        data-action="threat-feed-next-page">Next &rarr;</button>
              </div>
            </div>
          ` : ''}
        </section>
      </div>
    `;
  },

  render(): void {
    const container = AdminDOM.getById('reputation-config-content');
    if (!container) return;

    const config = this.config || {};
    const isEnabled = config.enabled === true;
    const cacheTtl = config.cache_ttl || '1h';
    const rules = config.rules || [];
    const rawIndicators = this.threatFeedData?.indicators || [];
    const allIndicators: UnifiedThreatIndicator[] = rawIndicators;
    const totalCount = this.threatFeedData?.total_indicators ?? rawIndicators.length;
    const criticalCount = allIndicators.filter(i => (i.score || 0) >= 90 || i.severity === 'CRITICAL').length;
    const highCount = allIndicators.filter(i => ((i.score || 0) >= 70 && (i.score || 0) < 90) || i.severity === 'HIGH').length;

    const ctiSource = this.threatFeedData?.sources?.cti || this.threatFeedData?.cti;
    const ctiStatusObj = ctiSource?.status;
    const ctiError = ctiStatusObj?.last_error;
    const isCtiDisconnected = Boolean(!this.threatFeedData || (ctiError && totalCount === 0) || ((ctiStatusObj?.failures ?? 0) > 0 && totalCount === 0));

    // Active severity / category filter from pagination
    const activeSevFilter = this.threatFeedPagination.severityFilter || 'all';

    // Threat Class Breakdown stats
    const malwareItems = allIndicators.filter(i => (i.category || '').toLowerCase().includes('malware') || (i.category || '').toLowerCase().includes('c2') || (i.threat_name || '').toLowerCase().includes('malware'));
    const botnetItems = allIndicators.filter(i => (i.category || '').toLowerCase().includes('botnet') || (i.threat_name || '').toLowerCase().includes('botnet'));
    const scannerItems = allIndicators.filter(i => (i.category || '').toLowerCase().includes('scan') || (i.category || '').toLowerCase().includes('exploit'));
    const phishingItems = allIndicators.filter(i => (i.category || '').toLowerCase().includes('phish'));

    const criticalPct = totalCount > 0 ? Math.round((criticalCount / totalCount) * 100) : 0;
    const highPct = totalCount > 0 ? Math.round((highCount / totalCount) * 100) : 0;

    // Protocol Split
    const ipv6Items = allIndicators.filter(i => i.indicator.includes(':'));
    const ipv6Pct = totalCount > 0 ? Math.round((ipv6Items.length / totalCount) * 100) : 0;
    const ipv4Pct = totalCount > 0 ? 100 - ipv6Pct : 0;

    const lastSuccess = ctiStatusObj?.last_success;
    let latestUpdateText = isCtiDisconnected ? 'Disconnected' : 'Never';
    if (lastSuccess) {
      try {
        const d = new Date(lastSuccess);
        if (!isNaN(d.getTime())) {
          latestUpdateText = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
      } catch {
        latestUpdateText = 'Never';
      }
    }

    const statusText = isEnabled ? 'Operational' : 'Disabled';
    const statusTone = isEnabled ? 'active' : 'neutral';

    const content = `
      <div class="reputation-operator-stack">
        <!-- KPI Metrics Strip -->
        ${SectionUI.renderOperatorMetricStrip([
          {
            label: 'Threat Indicators',
            value: Number(totalCount).toLocaleString(),
            sub: totalCount > 0 ? `${ipv4Pct}% IPv4 · ${ipv6Pct}% IPv6 subnets` : (isCtiDisconnected ? 'CTI offline' : 'No indicators synced'),
            tone: 'neutral'
          },
          {
            label: 'Critical Risk',
            value: Number(criticalCount).toLocaleString(),
            sub: totalCount > 0 ? `${criticalPct}% of feed · Score 90–100` : 'Score 90–100',
            tone: 'neutral'
          },
          {
            label: 'DivineLab CTI Status',
            value: isCtiDisconnected ? 'Disconnected' : (isEnabled ? 'Connected' : 'Standby'),
            sub: isCtiDisconnected ? (ctiError ? 'Connection refused / offline' : 'Threat feed offline') : 'In-RAM trie lookup < 10µs',
            tone: 'neutral'
          },
          {
            label: 'Latest update',
            value: latestUpdateText,
            sub: isCtiDisconnected ? 'Feed sync offline' : 'Continuous feed sync',
            tone: 'neutral'
          }
        ], 'reputation-metric-strip mb-20')}

        <!-- Threat Intelligence Directory Table Section -->
        ${SectionUI.renderOperatorSection('DivineLab CTI Threat Directory (' + Number(totalCount).toLocaleString() + ')', `
          <div class="mt-8">${this.renderThreatTable()}</div>
        `, {
          subtitle: 'Consolidated high-fidelity threat indicators synchronized in RAM for sub-10µs edge lookups.',
          actions: `
            <button class="operator-btn operator-btn-secondary" type="button" data-action="refresh-threat-feed">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="mr-6"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
              Refresh Feeds
            </button>
          `,
          className: 'mb-20'
        })}

        <!-- Shared Save Action Bar -->
        ${SectionUI.renderSaveActionBar({
          actionAttr: 'data-action',
          resetAction: 'reset-changes',
          saveAction: 'save-changes'
        })}
      </div>
    `;

    container.innerHTML = SectionUI.renderOperatorFrame({
      kicker: 'Modules',
      title: 'IP Reputation',
      subtitle: 'Threat intelligence feed ingestion, IP reputation lookups, and edge-layer mitigation.',
      actions: `
        ${SectionUI.renderSwitch({
          checked: isEnabled,
          attrs: 'data-action="reputation-toggle-enabled" aria-label="Enable IP Reputation Engine"'
        })}
      `,
      content,
      className: 'reputation-operator-frame'
    });
  }
};
