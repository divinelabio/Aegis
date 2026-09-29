/**
 * In-app alert notification UI
 * Source of truth: web/admin/src/alerts.ts
 * Runtime output: web/admin/dist/js/alerts.js
 */

import { router } from './router.js';
import { api } from './api.js';
import * as AdminDOM from './core/dom.js';
import * as AdminEvents from './core/events.js';
import { SectionUI } from './sections/ui-components.js';

type AlertLevel = 'critical' | 'warning' | 'info';
type AlertFilter = 'all' | AlertLevel;

interface AlertItem {
  id: string;
  level: AlertLevel | string;
  title: string;
  message: string;
  created_at: string;
  read?: boolean;
  source?: string;
  route?: string;
  action_label?: string;
  group_count?: number;
  unresolved?: boolean;
  meta?: Record<string, string | number | boolean | null | undefined>;
}

interface AlertsResponse {
  alerts?: AlertItem[];
  unread_count?: number;
}

const alertsState = {
  alertsCache: [] as AlertItem[],
  filter: 'all' as AlertFilter,
  alertDropdownOpen: false
};
let alertsLoadInFlight = false;

function bindAlertInteractions(): void {
  if ((bindAlertInteractions as { initialized?: boolean }).initialized) return;
  (bindAlertInteractions as { initialized?: boolean }).initialized = true;

  AdminEvents.delegateEvent(document, 'click', '[data-action="alerts-mark-all-read"]', event => {
    event.preventDefault();
    event.stopPropagation();
    void markAllAlertsRead();
  });

  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-action="alerts-open-detail"]', (event, target) => {
    event.preventDefault();
    if (event.target instanceof Element && event.target.closest('.alert-action-btn')) return;
    const alertId = target.dataset.alertId;
    if (alertId) openAlertDetail(alertId);
  });

  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-action="alerts-filter"]', (event, target) => {
    event.preventDefault();
    const filter = target.dataset.alertFilter as AlertFilter | undefined;
    if (filter) {
      alertsState.filter = filter;
      renderAlertDropdown();
    }
  });

  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-action="alerts-open-route"]', (event, target) => {
    event.preventDefault();
    event.stopPropagation();
    const route = target.dataset.route;
    if (route) {
      closeAlertDropdown();
      SectionUI.closeModal();
      router.navigate(route);
    }
  });

  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-action="alerts-mark-one-read"]', (event, target) => {
    event.preventDefault();
    event.stopPropagation();
    const alertId = target.dataset.alertId;
    if (alertId) void markAlertRead(alertId);
  });

  AdminEvents.delegateEvent(document, 'click', '[data-action="alerts-view-all"]', event => {
    event.preventDefault();
    viewAllAlerts();
  });

  AdminEvents.delegateEvent(document, 'click', '[data-action="alerts-close-detail"]', event => {
    event.preventDefault();
    SectionUI.closeModal();
  });
}

document.addEventListener('DOMContentLoaded', () => {
  bindAlertInteractions();
  void loadAlerts();

  const bell = AdminDOM.getById('alert-bell');
  if (bell) {
    bell.setAttribute('aria-expanded', 'false');
  }

  window.setInterval(loadAlerts, 30000);

  document.addEventListener('click', event => {
    const bellElement = AdminDOM.getById('alert-bell');
    const target = event.target;
    if (bellElement && target instanceof Node && !bellElement.contains(target) && alertsState.alertDropdownOpen) {
      closeAlertDropdown();
    }
  });
});

async function loadAlerts(): Promise<void> {
  if (!api.currentUser) {
    updateAlertBadge(0);
    return;
  }
  if (alertsLoadInFlight) return;
  alertsLoadInFlight = true;
  try {
    const response = await fetch('/api/alerts', { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error(`Alert fetch failed: ${response.status}`);
    const data = (await response.json()) as AlertsResponse;
    alertsState.alertsCache = mergeAlerts(normalizeAlerts(data.alerts || []));
    updateAlertBadge(countUnread(alertsState.alertsCache));
    if (alertsState.alertDropdownOpen) renderAlertDropdown();
  } catch (error) {
    console.error('[Aegis] Alert fetch error:', error);
  } finally {
    alertsLoadInFlight = false;
  }
}

function updateAlertBadge(count: number): void {
  const badge = AdminDOM.getById('alert-count');
  if (!badge) return;

  if (count > 0) {
    badge.textContent = count > 99 ? '99+' : String(count);
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
}

export function toggleAlertDropdown(): void {
  if (alertsState.alertDropdownOpen) {
    closeAlertDropdown();
  } else {
    openAlertDropdown();
  }
}

export function refreshAlerts(): void {
  void loadAlerts();
}

function openAlertDropdown(): void {
  const dropdown = AdminDOM.getById('alert-dropdown');
  if (!dropdown) return;

  alertsState.alertDropdownOpen = true;
  SectionUI.setOpen(dropdown, true, { expandedTarget: 'alert-bell' });

  renderAlertDropdown();
}

function closeAlertDropdown(): void {
  const dropdown = AdminDOM.getById('alert-dropdown');
  if (!dropdown) return;

  alertsState.alertDropdownOpen = false;
  SectionUI.setOpen(dropdown, false, { expandedTarget: 'alert-bell' });
}

function renderAlertDropdown(): void {
  const dropdown = AdminDOM.getById('alert-dropdown');
  if (!dropdown) return;

  const visibleAlerts = getFilteredAlerts();
  const counts = getAlertCounts(alertsState.alertsCache);

  if (alertsState.alertsCache.length === 0) {
    dropdown.innerHTML = `
            <div class="alert-dropdown-header">
                <div>
                    <h4>Security Inbox</h4>
                    <span class="alert-dropdown-subtitle">No active operational alerts</span>
                </div>
            </div>
            <div class="alert-empty">
                <div class="alert-empty-icon">OK</div>
                <div class="text-small text-muted">Health checks and section signals look quiet.</div>
            </div>
        `;
    return;
  }

  dropdown.innerHTML = `
        <div class="alert-dropdown-header">
            <div>
                <h4>Security Inbox</h4>
                <span class="alert-dropdown-subtitle">${countUnread(alertsState.alertsCache)} unread · ${countUnresolved(alertsState.alertsCache)} unresolved</span>
            </div>
            <button type="button" class="btn btn-sm btn-outline btn-xs" data-action="alerts-mark-all-read">Mark all read</button>
        </div>
        <div class="alert-filter-row">
            ${renderAlertFilter('all', 'All', alertsState.alertsCache.length)}
            ${renderAlertFilter('critical', 'Critical', counts.critical)}
            ${renderAlertFilter('warning', 'Warning', counts.warning)}
            ${renderAlertFilter('info', 'Info', counts.info)}
        </div>
        ${visibleAlerts.length === 0
          ? `
            <div class="alert-empty compact">
                <div class="text-small text-muted">No ${alertsState.filter} alerts right now.</div>
            </div>
          `
          : visibleAlerts
          .slice(0, 10)
          .map(renderAlertItem)
          .join('')}
        ${visibleAlerts.length > 10
          ? `
            <div class="alert-view-all">
                <a href="#" class="inline-link text-small" data-action="alerts-view-all">
                    View all ${visibleAlerts.length} matching alerts
                </a>
            </div>
        `
          : ''}
    `;
}

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diff = (now.getTime() - date.getTime()) / 1000;

  if (diff < 60) return 'Just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

async function markAllAlertsRead(): Promise<void> {
  try {
    await persistReadState({ all: true });
    alertsState.alertsCache.forEach(alert => {
      alert.read = true;
    });
    updateAlertBadge(0);
    renderAlertDropdown();
  } catch (error) {
    console.error('[Aegis] Mark read error:', error);
  }
}

function openAlertDetail(alertId: string): void {
  const alert = alertsState.alertsCache.find(item => item.id === alertId);
  if (!alert) return;
  if (!alert.read) void markAlertRead(alert.id);
  closeAlertDropdown();
  SectionUI.showModal(`
        <div class="modal-content modal-narrow alert-detail-modal">
            <div class="modal-header">
                <h3>${escapeHtml(alert.title)}</h3>
                <button type="button" class="modal-close" data-action="alerts-close-detail" aria-label="Close dialog">&times;</button>
            </div>
            <div class="modal-body">
                <div class="alert-detail-head">
                    <span class="alert-level-badge ${escapeAttr(normalizeLevel(alert.level))}">${escapeHtml(normalizeLevel(alert.level))}</span>
                    <span class="alert-source-pill">${escapeHtml(alert.source || inferSource(alert))}</span>
                    <span class="alert-item-time">${escapeHtml(formatTimeAgo(alert.created_at))}</span>
                </div>
                <p class="alert-detail-message">${escapeHtml(alert.message)}</p>
                ${renderAlertMeta(alert)}
            </div>
            <div class="modal-footer">
                ${alert.route ? `<button type="button" class="btn btn-primary" data-action="alerts-open-route" data-route="${escapeAttr(alert.route)}">${escapeHtml(alert.action_label || 'Investigate')}</button>` : ''}
                <button type="button" class="btn btn-outline" data-action="alerts-close-detail">Close</button>
            </div>
        </div>
    `, { panelClass: '' });
}

function viewAllAlerts(): void {
  closeAlertDropdown();
  router.navigate('security_analytics');
}

async function markAlertRead(alertId: string): Promise<void> {
  const alert = alertsState.alertsCache.find(item => item.id === alertId);
  if (!alert || alert.read) return;
  try {
    await persistReadState({ ids: [alertId] });
    alert.read = true;
    updateAlertBadge(countUnread(alertsState.alertsCache));
    if (alertsState.alertDropdownOpen) renderAlertDropdown();
  } catch (error) {
    console.error('[Aegis] Mark read error:', error);
  }
}

async function persistReadState(body: { all?: boolean; ids?: string[] }): Promise<void> {
  if (!api.csrfToken && !(await api.checkSession())) {
    throw new Error('No active session is available to save the acknowledgement.');
  }
  const response = await fetch('/api/alerts/read', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(api.csrfToken ? { 'X-CSRF-Token': api.csrfToken } : {})
    },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error(`Alert acknowledgement failed: ${response.status}`);
}

function normalizeAlerts(alerts: AlertItem[]): AlertItem[] {
  return alerts.map((alert, index) => {
    const id = String(alert.id || `backend-${index}-${alert.title}`);
    return {
      ...alert,
      id,
      level: normalizeLevel(alert.level),
      source: alert.source || inferSource(alert),
      route: alert.route || inferRoute(alert),
      action_label: alert.action_label || 'Investigate',
      created_at: alert.created_at || new Date().toISOString(),
      read: alert.read === true
    };
  });
}

function mergeAlerts(alerts: AlertItem[]): AlertItem[] {
  const byId = new Map<string, AlertItem>();
  alerts.forEach(alert => {
    if (!byId.has(alert.id)) byId.set(alert.id, alert);
  });
  return Array.from(byId.values()).sort((a, b) => {
    const severityDelta = severityRank(b.level) - severityRank(a.level);
    if (severityDelta !== 0) return severityDelta;
    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  });
}

function renderAlertFilter(filter: AlertFilter, label: string, count: number): string {
  const active = alertsState.filter === filter ? 'active' : '';
  return `
        <button type="button" class="alert-filter-pill ${active}" data-action="alerts-filter" data-alert-filter="${escapeAttr(filter)}">
            <span>${escapeHtml(label)}</span>
            <strong>${formatNumber(count)}</strong>
        </button>
    `;
}

function renderAlertItem(alert: AlertItem): string {
  const level = normalizeLevel(alert.level);
  const source = alert.source || inferSource(alert);
  const countLabel = alert.group_count && alert.group_count > 1 ? `<span class="alert-group-count">${formatNumber(alert.group_count)}</span>` : '';
  const detailButton = `<button type="button" class="btn btn-ghost btn-xs" data-action="alerts-open-detail" data-alert-id="${escapeAttr(alert.id)}">View details</button>`;
  const routeButton = alert.route
    ? `<button type="button" class="btn btn-outline btn-xs" data-action="alerts-open-route" data-route="${escapeAttr(alert.route)}">${escapeHtml(alert.action_label || 'Open')}</button>`
    : '';
  return `
        <article class="alert-item ${!alert.read ? 'unread' : ''} ${alert.unresolved ? 'unresolved' : ''}">
            <div class="alert-item-header">
                <div class="alert-title-wrap">
                    <span class="alert-level-badge ${escapeAttr(level)}">${escapeHtml(level)}</span>
                    <span class="alert-source-pill">${escapeHtml(source)}</span>
                    ${countLabel}
                </div>
                <span class="alert-item-time">${escapeHtml(formatTimeAgo(alert.created_at))}</span>
            </div>
            <div class="alert-item-title">${escapeHtml(alert.title)}</div>
            <div class="alert-item-message">${escapeHtml(alert.message)}</div>
            <div class="alert-item-actions">
                ${detailButton}
                ${routeButton}
                ${!alert.read ? `<button type="button" class="btn btn-ghost btn-xs" data-action="alerts-mark-one-read" data-alert-id="${escapeAttr(alert.id)}">Ack</button>` : ''}
            </div>
        </article>
    `;
}

function renderAlertMeta(alert: AlertItem): string {
  const entries = Object.entries(alert.meta || {}).filter(([, value]) => value !== undefined && value !== null && value !== '');
  if (entries.length === 0) return '';
  return `
        <div class="alert-detail-meta">
            ${entries.map(([key, value]) => `
                <div>
                    <span>${escapeHtml(titleCase(key.replace(/_/g, ' ')))}</span>
                    <strong>${escapeHtml(String(value))}</strong>
                </div>
            `).join('')}
        </div>
    `;
}

function getFilteredAlerts(): AlertItem[] {
  if (alertsState.filter === 'all') return alertsState.alertsCache;
  return alertsState.alertsCache.filter(alert => normalizeLevel(alert.level) === alertsState.filter);
}

function getAlertCounts(alerts: AlertItem[]): Record<AlertLevel, number> {
  return alerts.reduce<Record<AlertLevel, number>>((counts, alert) => {
    counts[normalizeLevel(alert.level)] += 1;
    return counts;
  }, { critical: 0, warning: 0, info: 0 });
}

function countUnread(alerts: AlertItem[]): number {
  return alerts.filter(alert => !alert.read).length;
}

function countUnresolved(alerts: AlertItem[]): number {
  return alerts.filter(alert => alert.unresolved !== false).length;
}

function normalizeLevel(level: string | undefined): AlertLevel {
  const normalized = String(level || 'info').toLowerCase();
  if (['critical', 'error', 'danger', 'severe', 'high'].includes(normalized)) return 'critical';
  if (['warning', 'warn', 'medium', 'degraded'].includes(normalized)) return 'warning';
  return 'info';
}

function severityRank(level: string): number {
  const normalized = normalizeLevel(level);
  if (normalized === 'critical') return 3;
  if (normalized === 'warning') return 2;
  return 1;
}

function inferSource(alert: AlertItem): string {
  const text = `${alert.source || ''} ${alert.title || ''} ${alert.message || ''}`.toLowerCase();
  if (text.includes('bot')) return 'Bot Protection';
  if (text.includes('waf') || text.includes('rule')) return 'WAF';
  if (text.includes('rate') || text.includes('traffic')) return 'Traffic Control';
  if (text.includes('http')) return 'Application Security';
  if (text.includes('api')) return 'API Security';
  if (text.includes('access') || text.includes('auth')) return 'Edge Access';
  return 'System';
}

function inferRoute(alert: AlertItem): string {
  const source = inferSource(alert);
  if (source === 'WAF') return 'waf_config';
  if (source === 'Bot Protection') return 'antibots_config';
  if (source === 'Traffic Control') return 'traffic_config';
  if (source === 'Edge Access' || source === 'Access') return 'access_config';
  if (source === 'API Security') return 'apisecurity_config';
  if (source === 'Application Security' || source === 'App Security') return 'httpsecurity_config';
  return 'security_analytics';
}

function titleCase(value: string): string {
  return value.replace(/\b\w/g, letter => letter.toUpperCase());
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value);
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char] || char));
}

function escapeAttr(value: string): string {
  return escapeHtml(value);
}
