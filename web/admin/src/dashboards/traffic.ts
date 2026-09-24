import {
  renderMetricSkeleton,
  renderMetricSubSkeleton,
  renderChartSkeleton,
  renderBreakdownSkeleton,
  renderProtectionCardsSkeleton,
  renderTableSkeleton,
  renderTextSkeleton
} from './skeletons.js';

type TrafficWindow = string;

type TrafficFilterKey = 'action' | 'reason' | 'rule_id' | 'ip' | 'path' | 'country' | 'method' | 'status';
type TrafficFilters = Partial<Record<TrafficFilterKey, string>>;

interface TrafficSummary {
  total_requests?: number;
  blocked_requests?: number;
  allowed_requests?: number;
  challenged_requests?: number;
  rate_limited?: number;
  error_requests?: number;
  block_rate?: number;
  avg_latency_ms?: number;
  p95_latency_ms?: number;
  unique_source_ips?: number;
  unique_countries?: number;
  top_reason?: string;
  active_bans?: number;
  active_connections?: number;
  dropped_events?: number;
  window?: string;
}

interface TrafficTimeseriesPoint {
  timestamp: number;
  counts?: Record<string, number>;
  avg_latency_ms?: number;
  p95_latency_ms?: number;
}

interface TrafficBreakdownItem {
  key: string;
  label: string;
  count: number;
  blocked?: number;
  challenged?: number;
  rate_limited?: number;
  block_rate?: number;
  percent?: number;
  last_seen?: number;
  avg_latency_ms?: number;
}

interface TrafficEventRow {
  id: string;
  timestamp: number;
  client_ip?: string;
  country?: string;
  method?: string;
  path?: string;
  status_code?: number;
  action?: string;
  user_agent?: string;
  user_agent_family?: string;
  rule_id?: string;
  rule_name?: string;
  rule_type?: string;
  latency_ms?: number;
  request_id?: string;
  metadata?: Record<string, string>;
}

interface TrafficHealth {
  db_available?: boolean;
  ingestion_lag_seconds?: number;
  dropped_events?: number;
  freshness_status?: string;
  message?: string;
}

interface TrafficEnforcementSummary {
  requests_enforced?: number;
  blocked_requests?: number;
  rate_limited?: number;
  challenged?: number;
  enforcement_rate?: number;
  active_bans?: number;
  active_connections?: number;
}

interface TrafficModuleEffectiveness {
  modules?: TrafficBreakdownItem[];
  top_rules?: TrafficBreakdownItem[];
  application_flood_count?: number;
  ddos_count?: number;
  rate_limit_count?: number;
  geo_count?: number;
  blacklist_count?: number;
  reputation_count?: number;
  trusted_exception_count?: number;
  challenge_count?: number;
}

interface TrafficPressureIntelligence {
  ddos_reasons?: TrafficBreakdownItem[];
  rate_limit_triggers?: TrafficBreakdownItem[];
  reputation_score_bands?: TrafficBreakdownItem[];
  challenge_strategies?: TrafficBreakdownItem[];
  repeat_offenders?: TrafficBreakdownItem[];
}

interface TrafficPolicyHealth {
  status?: string;
  enabled_state?: string;
  protection_level?: number;
  enabled_modules?: Record<string, boolean>;
  geo_mode?: string;
  blacklist_entries?: number;
  rate_limit_action?: string;
  challenge_state?: string;
  telemetry_freshness?: string;
  dropped_events?: number;
  config_message?: string;
}

interface TrafficActiveControls {
  active_bans?: number;
  active_connections?: number;
  active_blocklist_entries?: number;
  geo_scope?: string;
  priority_bypass_summary?: string;
}

interface TrafficDashboardPayload {
  summary?: TrafficSummary;
  timeseries?: TrafficTimeseriesPoint[];
  breakdowns?: Record<string, TrafficBreakdownItem[]>;
  events?: { events?: TrafficEventRow[] };
  health?: TrafficHealth;
  enforcement_summary?: TrafficEnforcementSummary;
  module_effectiveness?: TrafficModuleEffectiveness;
  pressure_intelligence?: TrafficPressureIntelligence;
  policy_health?: TrafficPolicyHealth;
  active_controls?: TrafficActiveControls;
  warnings?: string[];
}

interface TrafficDashboardResponse {
  success?: boolean;
  dashboard?: TrafficDashboardPayload;
}

type TrafficValueMap = Record<string, unknown>;

interface TrafficOperations {
  health?: { status?: string; message?: string };
  revision?: TrafficValueMap;
  modules?: TrafficValueMap;
  state?: TrafficValueMap;
  telemetry?: TrafficValueMap;
  freshness?: TrafficValueMap;
  module_readiness?: Record<string, string>;
  decision_logs?: Record<string, number>;
}

interface TrafficBreakdownFilter {
  key: TrafficFilterKey;
  value: (item: TrafficBreakdownItem) => string;
}

let selectedWindow: TrafficWindow = '24h';
let filters: TrafficFilters = {};
let requestVersion = 0;
let eventsBound = false;
let visibleEvents: TrafficEventRow[] = [];

const escapeHTML = (value: unknown): string => String(value ?? '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#039;');

const formatNumber = (value: number | undefined): string => new Intl.NumberFormat('en-US').format(Math.max(0, Number(value) || 0));

function valueMap(value: unknown): TrafficValueMap {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as TrafficValueMap : {};
}

function valueNumber(value: unknown): number {
  const normalized = Number(value);
  return Number.isFinite(normalized) ? Math.max(0, normalized) : 0;
}

function valueString(value: unknown, fallback = 'Unavailable'): string {
  const normalized = String(value ?? '').trim();
  return normalized || fallback;
}

function readableLabel(value: unknown): string {
  return valueString(value, 'None').replace(/[_-]/g, ' ').replace(/\b\w/g, character => character.toUpperCase());
}

function byId<T extends HTMLElement = HTMLElement>(id: string): T | null {
  return document.getElementById(id) as T | null;
}

function isMounted(): boolean {
  return Boolean(byId('traffic-dashboard'));
}

function setText(id: string, value: string): void {
  const element = byId(id);
  if (element) element.textContent = value;
}

function setBanner(message = '', tone: 'warning' | 'danger' = 'warning'): void {
  const banner = byId('traffic-dashboard-banner');
  if (!banner) return;
  banner.hidden = !message;
  banner.classList.toggle('is-danger', Boolean(message) && tone === 'danger');
  banner.textContent = message;
}

function timeRangeLabel(window = selectedWindow): string {
  const labels: Record<string, string> = {
    '15m': 'Last 15 minutes',
    '1h': 'Last hour',
    '24h': 'Last 24 hours',
    '7d': 'Last 7 days',
    '30d': 'Last 30 days'
  };
  if (labels[window]) return labels[window];
  const match = window.match(/^(\d+)(m|h)$/);
  if (!match) return 'Last 24 hours';
  const amount = Number(match[1]);
  if (match[2] === 'm') return `Last ${amount} minute${amount === 1 ? '' : 's'}`;
  if (amount % 168 === 0) return `Last ${amount / 168} week${amount === 168 ? '' : 's'}`;
  if (amount % 24 === 0) return `Last ${amount / 24} day${amount === 24 ? '' : 's'}`;
  return `Last ${amount} hour${amount === 1 ? '' : 's'}`;
}

function dateFromTimestamp(timestamp: number | undefined): Date | null {
  if (!timestamp) return null;
  const date = new Date(timestamp < 100_000_000_000 ? timestamp * 1000 : timestamp);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatTime(timestamp: number | undefined): string {
  const date = dateFromTimestamp(timestamp);
  if (!date) return '—';
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' }).format(date);
}

function shortTime(timestamp: number | undefined): string {
  const date = dateFromTimestamp(timestamp);
  if (!date) return '';
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(date);
}

function timelineTick(timestamp: number | undefined): string {
  const date = dateFromTimestamp(timestamp);
  if (!date) return '';
  return new Intl.DateTimeFormat(undefined, { hour: 'numeric', hour12: true }).format(date);
}

function actionLabel(action?: string): string {
  const normalized = String(action || '').toLowerCase();
  if (normalized === 'ratelimit' || normalized === 'rate_limit') return 'Rate limited';
  if (normalized === 'challenge') return 'Challenged';
  if (normalized === 'block') return 'Blocked';
  if (normalized === 'allow') return 'Allowed';
  if (normalized === 'error') return 'Error';
  return action ? action.replace(/[_-]/g, ' ').replace(/\b\w/g, value => value.toUpperCase()) : 'Recorded';
}

function actionTone(action?: string): string {
  const normalized = String(action || '').toLowerCase();
  if (normalized === 'block') return 'danger';
  if (normalized === 'ratelimit' || normalized === 'rate_limit' || normalized === 'challenge') return 'warning';
  if (normalized === 'allow') return 'success';
  return 'primary';
}

function reasonLabel(reason?: string): string {
  const normalized = String(reason || '').toLowerCase();
  const labels: Record<string, string> = {
    ratelimit: 'Rate Limiting',
    rate_limit: 'Rate Limiting',
    ddos: 'Application Flood',
    application_flood: 'Application Flood',
    geo: 'Geo-Blocking',
    blacklist: 'IP Blacklist',
    reputation: 'IP Reputation',
    trusted_exception: 'Trusted Exceptions',
    challenge: 'Challenge'
  };
  return labels[normalized] || String(reason || '').replace(/[_-]/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
}

function filterAttributes(key: TrafficFilterKey | undefined, value: string, label: string): string {
  if (!key || !value.trim()) return '';
  return ` data-traffic-dashboard-filter-key="${escapeHTML(key)}" data-traffic-dashboard-filter-value="${escapeHTML(value)}" role="button" tabindex="0" aria-label="Filter by ${escapeHTML(label)}"`;
}

function filterLabel(key: TrafficFilterKey, value: string): string {
  const labels: Record<TrafficFilterKey, string> = {
    action: 'Decision',
    reason: 'Module',
    rule_id: 'Rule',
    ip: 'Source IP',
    path: 'Path',
    country: 'Country',
    method: 'Method',
    status: 'Status'
  };
  const displayValue = key === 'action' ? actionLabel(value) : key === 'reason' ? reasonLabel(value) : value;
  return `${labels[key]}: ${displayValue}`;
}

function renderHeaderTime(): void {
  const target = byId('traffic-dashboard-header-time');
  if (!target) return;
  const label = timeRangeLabel();
  const presets: Array<[string, string]> = [['15m', '15m'], ['1h', '1h'], ['24h', '24h'], ['7d', '7d'], ['30d', '30d']];
  target.innerHTML = `
    <div class="security-events-time-menu waf-dashboard-time-menu">
      <button type="button" id="traffic-dashboard-time-trigger" class="security-time-dropdown-trigger" data-traffic-dashboard-action="toggle-time-panel" aria-label="Time range: ${escapeHTML(label)}" aria-haspopup="true" aria-expanded="false" aria-controls="traffic-dashboard-time-panel">
        <svg class="security-time-trigger-icon" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 10h18"/></svg>
        <strong>${escapeHTML(label)}</strong>
        <svg class="security-time-trigger-chevron" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
      </button>
      <div id="traffic-dashboard-time-panel" class="security-time-panel hidden">
        <div class="security-time-panel-head"><span>Time range</span><strong>${escapeHTML(label)}</strong></div>
        <div class="security-time-presets" aria-label="Quick time ranges">
          ${presets.map(([value, presetLabel]) => `<button type="button" class="security-time-preset ${selectedWindow === value ? 'is-active' : ''}" data-traffic-dashboard-action="apply-time-preset" data-traffic-time-preset="${value}">${presetLabel}</button>`).join('')}
        </div>
        <div class="security-time-field"><span>Custom last</span><div class="security-time-inline">
          <input id="traffic-dashboard-relative-amount" type="number" min="1" max="999" value="24" aria-label="Last amount">
          <select id="traffic-dashboard-relative-unit" aria-label="Last unit"><option value="minutes">minutes</option><option value="hours" selected>hours</option><option value="days">days</option><option value="weeks">weeks</option></select>
          <button type="button" class="security-time-apply" data-traffic-dashboard-action="apply-last-range">Apply</button>
        </div></div>
      </div>
    </div>`;
}

function renderHeaderFilters(): void {
  const target = byId('traffic-dashboard-header-filters');
  if (!target) return;
  const entries = Object.entries(filters).flatMap(([rawKey, rawValue]) => {
    const value = String(rawValue || '').trim();
    return value ? [{ key: rawKey as TrafficFilterKey, value, label: filterLabel(rawKey as TrafficFilterKey, value) }] : [];
  });
  target.innerHTML = entries.length ? `<div class="waf-dashboard-filter-chips" aria-label="Active filters">
    ${entries.map(entry => `<button type="button" class="waf-dashboard-filter-chip" data-traffic-dashboard-action="remove-filter" data-traffic-filter-key="${entry.key}">${escapeHTML(entry.label)}<span aria-hidden="true">×</span></button>`).join('')}
    <button type="button" class="waf-dashboard-clear-filters" data-traffic-dashboard-action="clear-filters">Clear</button>
  </div>` : '';
  target.closest('.waf-dashboard-command-bar')?.classList.toggle('is-empty', entries.length === 0);
}

function applyFilter(key: TrafficFilterKey, rawValue: string): void {
  const value = key === 'country' ? rawValue.trim().toUpperCase() : rawValue.trim();
  if (!value) return;
  if (filters[key] === value) delete filters[key];
  else filters = { ...filters, [key]: value };
  renderHeaderFilters();
  void loadTrafficDashboard();
}

function removeFilter(key?: TrafficFilterKey): void {
  if (!key) return;
  delete filters[key];
  renderHeaderFilters();
  void loadTrafficDashboard();
}

function clearFilters(): void {
  if (!Object.keys(filters).length) return;
  filters = {};
  renderHeaderFilters();
  void loadTrafficDashboard();
}

function setWindow(window: string): void {
  selectedWindow = window;
  renderHeaderTime();
  void loadTrafficDashboard();
}

function toggleTimePanel(): void {
  const panel = byId('traffic-dashboard-time-panel');
  if (!panel) return;
  panel.classList.toggle('hidden');
  byId('traffic-dashboard-time-trigger')?.setAttribute('aria-expanded', String(!panel.classList.contains('hidden')));
}

function applyLastRange(): void {
  const amount = Math.max(1, Math.min(999, Math.floor(Number(byId<HTMLInputElement>('traffic-dashboard-relative-amount')?.value) || 1)));
  const unit = byId<HTMLSelectElement>('traffic-dashboard-relative-unit')?.value || 'hours';
  const windows: Record<string, string> = { minutes: `${amount}m`, hours: `${amount}h`, days: `${amount * 24}h`, weeks: `${amount * 168}h` };
  setWindow(windows[unit] || windows.hours);
}

function createEmptyTrafficDashboard(message = 'Analytics storage is currently unavailable.'): TrafficDashboardPayload {
  return {
    summary: {
      total_requests: 0,
      blocked_requests: 0,
      allowed_requests: 0,
      challenged_requests: 0,
      rate_limited: 0,
      unique_source_ips: 0,
      unique_countries: 0,
      top_reason: 'none',
      active_bans: 0,
      active_connections: 0,
      dropped_events: 0,
      window: selectedWindow
    },
    timeseries: [],
    breakdowns: {
      reasons: [],
      actions: [],
      paths: [],
      ips: [],
      geo_countries: []
    },
    module_effectiveness: {
      modules: []
    },
    events: {
      events: []
    },
    health: {
      db_available: false,
      freshness_status: 'offline',
      ingestion_lag_seconds: 0,
      dropped_events: 0,
      message
    },
    warnings: [message]
  };
}

function normalizedTrafficAction(value: string | undefined): string {
  const normalized = String(value || '').toLowerCase();
  return normalized === 'rate_limit' || normalized === 'rate_limited' ? 'ratelimit' : normalized;
}

function normalizedTrafficReason(value: string | undefined): string {
  const normalized = String(value || '').toLowerCase();
  return normalized === 'ddos' ? 'application_flood' : normalized;
}

function eventMatchesTrafficFilters(event: TrafficEventRow): boolean {
  const reason = normalizedTrafficReason(event.rule_type || event.metadata?.reason);
  if (filters.action && normalizedTrafficAction(event.action) !== normalizedTrafficAction(filters.action)) return false;
  if (filters.reason && !reason.includes(normalizedTrafficReason(filters.reason)) && !normalizedTrafficReason(filters.reason).includes(reason)) return false;
  if (filters.rule_id) {
    const rid = filters.rule_id.toLowerCase();
    const matches = [event.rule_id, event.rule_name, event.metadata?.matched_rule, event.metadata?.protected_object, event.metadata?.exception_id]
      .filter(Boolean)
      .some(val => String(val).toLowerCase().includes(rid) || rid.includes(String(val).toLowerCase()));
    if (!matches) return false;
  }
  if (filters.ip && event.client_ip !== filters.ip) return false;
  if (filters.path) {
    const fp = filters.path.toLowerCase();
    const ep = (event.path || '').toLowerCase();
    if (!ep.includes(fp) && !fp.includes(ep)) return false;
  }
  if (filters.country && event.country?.toUpperCase() !== filters.country.toUpperCase()) return false;
  if (filters.method && event.method?.toUpperCase() !== filters.method.toUpperCase()) return false;
  if (filters.status && String(event.status_code ?? '') !== filters.status) return false;
  return true;
}


function renderBreakdown(items: TrafficBreakdownItem[] | undefined, emptyText: string, filter?: TrafficBreakdownFilter): string {
  const visible = (items || []).filter(item => item && item.count > 0).slice(0, 5);
  if (!visible.length) return `<div class="waf-dashboard-empty">${escapeHTML(emptyText)}</div>`;
  const maximum = Math.max(...visible.map(item => item.count), 1);
  return `<div class="waf-dashboard-breakdown-list">${visible.map(item => {
    const width = Math.max(4, Math.round((item.count / maximum) * 100));
    const value = filter?.value(item) || '';
    const label = item.label || item.key;
    return `<div class="waf-dashboard-breakdown-row${value ? ' is-filterable' : ''}"${filterAttributes(filter?.key, value, label)}>
      <span class="waf-dashboard-breakdown-label" title="${escapeHTML(label)}">${escapeHTML(label)}</span>
      <span class="waf-dashboard-breakdown-track"><svg viewBox="0 0 100 4" preserveAspectRatio="none" role="img" aria-label="${escapeHTML(`${label}: ${formatNumber(item.count)}`)}"><rect class="waf-dashboard-breakdown-svg-track" x="0" y="0" width="100" height="4" /><rect class="waf-dashboard-breakdown-svg-fill" x="0" y="0" width="${width}" height="4" /></svg></span>
      <strong>${formatNumber(item.count)}</strong>
    </div>`;
  }).join('')}</div>`;
}

function trafficCount(point: TrafficTimeseriesPoint, ...keys: string[]): number {
  return keys.reduce((total, key) => total + Math.max(0, Number(point.counts?.[key]) || 0), 0);
}

function renderTimeline(points: TrafficTimeseriesPoint[] | undefined): string {
  const visible = (points || []).slice(-24);
  if (!visible.length) return '<div class="waf-dashboard-chart-empty">No Traffic Control activity in this window.</div>';
  const totalFor = (point: TrafficTimeseriesPoint) => Math.max(0, Number(point.counts?.total || point.counts?.requests) || trafficCount(point, 'allow', 'block', 'ratelimit', 'rate_limit', 'challenge', 'observe', 'error'));
  const maximum = Math.max(...visible.map(totalFor), 1);
  const width = 720;
  const height = 260;
  const left = 26;
  const right = 714;
  const top = 6;
  const bottom = 226;
  const plotHeight = bottom - top;
  const slot = visible.length > 1 ? (right - left) / (visible.length - 1) : 0;
  const values = visible.map((point, index) => {
    const total = totalFor(point);
    const blocked = trafficCount(point, 'block', 'blocked');
    const rateLimited = trafficCount(point, 'ratelimit', 'rate_limit', 'rate_limited');
    const challenged = trafficCount(point, 'challenge', 'challenged');
    const x = visible.length === 1 ? (left + right) / 2 : left + (slot * index);
    return { x, y: bottom - ((total / maximum) * plotHeight), timestamp: point.timestamp, total, blocked, rateLimited, challenged, avgLatency: Number(point.avg_latency_ms) || 0, p95Latency: Number(point.p95_latency_ms) || 0, label: index === visible.length - 1 ? 'Now' : timelineTick(point.timestamp) };
  });
  const line = values.map((point, index) => `${index ? 'L' : 'M'} ${point.x} ${point.y}`).join(' ');
  const first = values[0];
  const last = values[values.length - 1];
  const area = `${line} L ${last.x} ${bottom} L ${first.x} ${bottom} Z`;
  const every = Math.max(1, Math.ceil((values.length - 1) / 3));
  const labels = values.map((point, index) => (index !== 0 && index !== values.length - 1 && index % every !== 0) ? '' : `<text class="waf-dashboard-timeline-label" x="${point.x}" y="${height - 6}" text-anchor="${index === 0 ? 'start' : index === values.length - 1 ? 'end' : 'middle'}">${escapeHTML(point.label)}</text>`).join('');
  const grid = [0, .5, 1].map(fraction => {
    const y = bottom - (plotHeight * fraction);
    const label = fraction === 0 ? '0' : formatNumber(Math.round(maximum * fraction));
    return `<line class="waf-dashboard-timeline-grid" x1="${left}" y1="${y}" x2="${right}" y2="${y}" /><text class="waf-dashboard-timeline-value" x="${left - 8}" y="${y + 4}" text-anchor="end">${label}</text>`;
  }).join('');
  const pointsMarkup = values.map(point => `<g class="waf-dashboard-timeline-point"><title>${escapeHTML(`${shortTime(point.timestamp)} — ${formatNumber(point.total)} recorded decisions — ${formatNumber(point.blocked)} blocked — ${formatNumber(point.rateLimited)} rate limited — ${formatNumber(point.challenged)} challenged`)}</title><circle cx="${point.x}" cy="${point.y}" r="3" /></g>`).join('');
  return `<svg class="waf-dashboard-timeline-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Traffic Control decision activity for the selected time window">${grid}<path class="waf-dashboard-timeline-area" d="${area}" /><path class="waf-dashboard-timeline-line" d="${line}" />${pointsMarkup}${labels}</svg>`;
}

function renderControlActivityCard(options: {
  title: string;
  filterReason: string;
  items?: TrafficBreakdownItem[];
  empty: string;
  itemFilter?: TrafficBreakdownFilter;
}): string {
  return `<div class="waf-dashboard-detail-panel">
    <h4 class="is-filterable"${filterAttributes('reason', options.filterReason, `${options.title} activity`)}>${escapeHTML(options.title)}</h4>
    ${renderBreakdown(options.items, options.empty, options.itemFilter)}
  </div>`;
}

function renderControlActivity(dashboard: TrafficDashboardPayload): string {
  const breakdowns = dashboard.breakdowns || {};

  return [
    renderControlActivityCard({
      title: 'Blacklist Matches', filterReason: 'blacklist',
      items: breakdowns.blacklist_reasons, empty: 'No blacklist matches in this window.',
      itemFilter: { key: 'rule_id', value: item => item.key || item.label }
    }),
    renderControlActivityCard({
      title: 'Trust Score Bands', filterReason: 'reputation',
      items: breakdowns.reputation_scores, empty: 'No reputation actions in this window.',
      itemFilter: { key: 'reason', value: item => item.key || item.label }
    }),
    renderControlActivityCard({
      title: 'Limit Triggers', filterReason: 'ratelimit',
      items: breakdowns.ratelimit_rules?.length ? breakdowns.ratelimit_rules : breakdowns.ratelimit_triggers,
      empty: 'No rate limits exceeded in this window.',
      itemFilter: { key: 'rule_id', value: item => item.key || item.label }
    }),
    renderControlActivityCard({
      title: 'Geo Policy Matches', filterReason: 'geo',
      items: breakdowns.geo_countries, empty: 'No geo policy actions in this window.',
      itemFilter: { key: 'country', value: item => item.key || item.label }
    }),
    renderControlActivityCard({
      title: 'Flood Triggers', filterReason: 'application_flood',
      items: breakdowns.application_flood_reasons, empty: 'No application flood interventions in this window.',
      itemFilter: { key: 'reason', value: item => item.key || item.label }
    }),
    renderControlActivityCard({
      title: 'Exception Use', filterReason: 'trusted_exception',
      items: breakdowns.trusted_exception_controls, empty: 'No trusted exceptions used in this window.',
      itemFilter: { key: 'rule_id', value: item => item.key || item.label }
    })
  ].join('');
}

function renderEvents(events: TrafficEventRow[] | undefined): void {
  const body = byId<HTMLTableSectionElement>('traffic-dashboard-events');
  if (!body) return;
  visibleEvents = (events || []).slice(0, 20);
  if (!visibleEvents.length) {
    body.innerHTML = '<tr><td colspan="7" class="waf-dashboard-table-empty">No Traffic Control decisions in this window.</td></tr>';
    return;
  }
  body.innerHTML = visibleEvents.map(event => {
    const request = `${event.method || 'HTTP'} ${event.path || '/'}`;
    const reason = event.rule_name || event.rule_id || event.rule_type || event.metadata?.reason || '—';
    return `<tr>
      <td>${escapeHTML(formatTime(event.timestamp))}</td>
      <td class="waf-dashboard-decision-cell"><span class="waf-dashboard-action is-filterable tone-${actionTone(event.action)}"${filterAttributes('action', event.action || '', actionLabel(event.action))}>${escapeHTML(actionLabel(event.action))}</span></td>
      <td class="waf-dashboard-request" title="${escapeHTML(request)}"><button type="button" class="waf-dashboard-table-filter"${filterAttributes('path', event.path || '', request)}>${escapeHTML(request)}</button></td>
      <td><button type="button" class="waf-dashboard-table-filter"${filterAttributes('ip', event.client_ip || '', event.client_ip || 'Source')}>${escapeHTML(event.client_ip || '—')}</button></td>
      <td class="waf-dashboard-rule" title="${escapeHTML(reason)}">${escapeHTML(reason)}</td>
      <td class="text-right">${event.latency_ms === undefined ? '—' : `${formatNumber(event.latency_ms)} ms`}</td>
      <td class="text-right"><button type="button" class="btn btn-outline btn-sm" data-traffic-dashboard-event="${escapeHTML(event.id)}">View</button></td>
    </tr>`;
  }).join('');
}

function renderEventDetail(event: TrafficEventRow): void {
  const title = byId('traffic-dashboard-drawer-title');
  const body = byId('traffic-dashboard-drawer-body');
  if (!title || !body) return;
  title.textContent = event.rule_name || event.rule_id || event.rule_type || 'Traffic decision';
  const metadata = Object.entries(event.metadata || {}).filter(([, value]) => Boolean(value));
  const rows: Array<[string, string]> = [
    ['Time', formatTime(event.timestamp)],
    ['Decision', actionLabel(event.action)],
    ['Request', `${event.method || 'HTTP'} ${event.path || '/'}`],
    ['Source', event.client_ip || '—'],
    ['Country', event.country || '—'],
    ['Status', event.status_code === undefined ? '—' : String(event.status_code)],
    ['Rule', event.rule_name || event.rule_id || '—'],
    ['Module', event.rule_type || event.metadata?.reason || '—'],
    ['Latency', event.latency_ms === undefined ? '—' : `${formatNumber(event.latency_ms)} ms`],
    ['Request ID', event.request_id || '—'],
    ['User agent', event.user_agent_family || event.user_agent || '—'],
    ...metadata.map(([key, value]) => [key.replace(/[_-]/g, ' ').replace(/\b\w/g, char => char.toUpperCase()), value] as [string, string])
  ];
  body.innerHTML = `<dl class="waf-dashboard-event-detail">${rows.map(([label, value]) => `<div><dt>${escapeHTML(label)}</dt><dd>${escapeHTML(value)}</dd></div>`).join('')}</dl>`;
}

function controlLabel(value: string | undefined): string {
  switch ((value || '').toLowerCase()) {
    case 'blacklist': return 'IP Blacklist';
    case 'reputation': return 'IP Reputation';
    case 'ratelimit': return 'Rate Limiting';
    case 'geo': return 'Geo-Blocking';
    case 'ddos':
    case 'application_flood': return 'Application Flood';
    case 'trusted_exception': return 'Trusted Exceptions';
    default: return readableLabel(value || 'No activity');
  }
}

function renderDashboard(dashboard: TrafficDashboardPayload, operations: TrafficOperations = {}): void {
  const summary = dashboard.summary || {};
  const health = dashboard.health || {};
  const policy = dashboard.policy_health || {};
  const breakdowns = dashboard.breakdowns || {};
  const total = valueNumber(summary.total_requests);
  const healthLabel = health.db_available === false ? 'Unavailable' : (health.freshness_status || 'Current').replace(/^./, char => char.toUpperCase());
  const healthDetail = (health.message && !health.message.includes('ClickHouse analytics database is not available')) ? health.message : (health.db_available === false ? 'Analytics storage is unavailable.' : health.ingestion_lag_seconds ? `${health.ingestion_lag_seconds}s ingestion lag` : 'Analytics are current.');
  const readiness = operations.module_readiness || {};
  const controlKeys = ['blacklist', 'reputation', 'ratelimit', 'geo', 'application_flood', 'trusted_exceptions'];
  const configuredReadiness = controlKeys.map(key => readiness[key]).filter(status => status && status !== 'disabled');
  const attentionCount = configuredReadiness.filter(status => status === 'degraded' || status === 'unhealthy').length;
  const readyCount = configuredReadiness.filter(status => status === 'ready').length;
  const topPath = breakdowns.paths?.find(item => item.count > 0);
  const droppedEvents = valueNumber(policy.dropped_events ?? health.dropped_events ?? summary.dropped_events) + valueNumber(valueMap(operations.telemetry).traffic_decision_drops);
  const runtimeHealth = operations.health?.status || policy.status || 'unknown';
  const runtimeMessage = operations.health?.message || policy.config_message || 'Runtime health is unavailable.';

  setText('traffic-dashboard-decisions', formatNumber(total));
  setText('traffic-dashboard-blocked', formatNumber(summary.blocked_requests));
  setText('traffic-dashboard-challenged', formatNumber(summary.challenged_requests));
  setText('traffic-dashboard-sources', formatNumber(summary.unique_source_ips));
  setText('traffic-dashboard-attention', formatNumber(attentionCount));
  setText('traffic-dashboard-decisions-note', `Recorded control events · ${summary.window || selectedWindow}`);
  setText('traffic-dashboard-blocked-note', `${formatNumber(summary.rate_limited)} additionally rate limited`);
  setText('traffic-dashboard-challenged-note', 'Sent to client verification');
  setText('traffic-dashboard-sources-note', 'Distinct sources with a decision');
  setText('traffic-dashboard-attention-note', attentionCount ? 'Review runtime readiness below' : 'Configured controls are ready');
  setText('traffic-dashboard-runtime', readableLabel(runtimeHealth));
  setText('traffic-dashboard-runtime-note', runtimeMessage);
  setText('traffic-dashboard-readiness', configuredReadiness.length ? `${readyCount} / ${configuredReadiness.length} ready` : 'Unavailable');
  setText('traffic-dashboard-readiness-note', configuredReadiness.length ? 'Configured Traffic Control features' : 'Runtime details were not returned');
  setText('traffic-dashboard-active-control', controlLabel(summary.top_reason));
  setText('traffic-dashboard-active-control-note', 'First control that made the decision');
  setText('traffic-dashboard-hotspot', topPath?.label || topPath?.key || 'No hotspot');
  setText('traffic-dashboard-hotspot-note', topPath ? `${formatNumber(topPath.count)} recorded decisions` : 'No affected path in this window');
  setText('traffic-dashboard-telemetry', formatNumber(droppedEvents));
  setText('traffic-dashboard-telemetry-note', droppedEvents ? 'Some decisions were not recorded' : `${healthLabel} · ${healthDetail}`);

  const timeline = byId('traffic-dashboard-timeline');
  if (timeline) timeline.innerHTML = renderTimeline(dashboard.timeseries);
  const controlActivity = byId('traffic-dashboard-control-activity');
  if (controlActivity) controlActivity.innerHTML = renderControlActivity(dashboard);
  const setBreakdown = (id: string, items: TrafficBreakdownItem[] | undefined, empty: string, filter?: TrafficBreakdownFilter): void => {
    const target = byId(id);
    if (target) target.innerHTML = renderBreakdown(items, empty, filter);
  };
  setBreakdown('traffic-dashboard-outcomes', breakdowns.actions, 'No decision outcomes recorded.', { key: 'action', value: item => item.key || item.label });
  setBreakdown('traffic-dashboard-paths', breakdowns.paths, 'No affected paths recorded.', { key: 'path', value: item => item.key || item.label });
  setBreakdown('traffic-dashboard-sources-list', breakdowns.ips, 'No repeated sources recorded.', { key: 'ip', value: item => item.key || item.label });
  setBreakdown('traffic-dashboard-challenges', breakdowns.challenge_strategies, 'No client challenges issued.');
  renderEvents(dashboard.events?.events);

  const rawWarning = dashboard.warnings?.[0] || '';
  const warning = (rawWarning && !rawWarning.includes('ClickHouse analytics database is not available')) ? rawWarning : '';
  setBanner(warning || '', 'warning');
}

function resetTrafficDashboardSkeletons(): void {
  const metricKeys = ['decisions', 'blocked', 'challenged', 'sources', 'attention'];
  metricKeys.forEach(key => {
    const valEl = byId(`traffic-dashboard-${key}`);
    const noteEl = byId(`traffic-dashboard-${key}-note`);
    if (valEl) valEl.innerHTML = renderMetricSkeleton();
    if (noteEl) noteEl.innerHTML = renderMetricSubSkeleton();
  });
  const timeline = byId('traffic-dashboard-timeline');
  if (timeline) timeline.innerHTML = renderChartSkeleton(16);
  const controlActivity = byId('traffic-dashboard-control-activity');
  if (controlActivity) controlActivity.innerHTML = renderProtectionCardsSkeleton(3);
  ['outcomes', 'paths', 'sources-list', 'challenges'].forEach(panel => {
    const p = byId(`traffic-dashboard-${panel}`);
    if (p) p.innerHTML = renderBreakdownSkeleton(3);
  });
  const events = byId('traffic-dashboard-events');
  if (events) events.innerHTML = renderTableSkeleton(7, 6);
}

async function loadTrafficDashboard(): Promise<void> {
  const version = ++requestVersion;
  const refresh = byId<HTMLButtonElement>('traffic-dashboard-refresh');
  const dashboardElement = byId('traffic-dashboard');
  if (refresh) {
    refresh.disabled = true;
    refresh.setAttribute('aria-busy', 'true');
  }
  dashboardElement?.classList.add('is-loading');
  if (visibleEvents.length === 0) {
    resetTrafficDashboardSkeletons();
  }
  try {
    const query = new URLSearchParams({ window: selectedWindow, interval: 'auto', limit: '25' });
    Object.entries(filters).forEach(([key, value]) => { if (value) query.set(key, value); });
    const [response, operationsResponse] = await Promise.all([
      fetch(`/api/sections/traffic_control/dashboard?${query.toString()}`, { credentials: 'same-origin', headers: { Accept: 'application/json' } }),
      fetch('/api/sections/traffic_control/operations', { credentials: 'same-origin', headers: { Accept: 'application/json' } })
    ]);
    if (response.status === 401 || operationsResponse.status === 401) {
      window.location.href = '/admin/login';
      return;
    }
    if (!response.ok) throw new Error(`Traffic analytics request failed (${response.status}).`);
    const payload = await response.json() as TrafficDashboardResponse;
    const operations = operationsResponse.ok ? await operationsResponse.json() as TrafficOperations : {};
    if (!operationsResponse.ok) {
      payload.dashboard = { ...(payload.dashboard || {}), warnings: [...(payload.dashboard?.warnings || []), 'Runtime readiness unavailable'] };
    }
    if (version !== requestVersion || !isMounted()) return;
    if (!payload.dashboard || payload.dashboard.health?.db_available === false) {
      renderDashboard(payload.dashboard || createEmptyTrafficDashboard(), operations);
    } else {
      renderDashboard(payload.dashboard, operations);
    }
  } catch (error) {
    if (version !== requestVersion || !isMounted()) return;
    console.warn('Traffic Control analytics are unavailable:', error);
    renderDashboard(createEmptyTrafficDashboard('Analytics storage is unavailable. Live decision logging is paused.'));
  } finally {
    if (version === requestVersion && isMounted()) {
      dashboardElement?.classList.remove('is-loading');
      if (refresh) {
        refresh.disabled = false;
        refresh.setAttribute('aria-busy', 'false');
      }
    }
  }
}

function bindEvents(): void {
  if (eventsBound) return;
  eventsBound = true;
  document.addEventListener('click', event => {
    if (!(event.target instanceof Element) || !isMounted()) return;
    const filterTarget = event.target.closest<HTMLElement>('[data-traffic-dashboard-filter-key][data-traffic-dashboard-filter-value]');
    if (filterTarget?.dataset.trafficDashboardFilterKey && filterTarget.dataset.trafficDashboardFilterValue) {
      event.preventDefault();
      applyFilter(filterTarget.dataset.trafficDashboardFilterKey as TrafficFilterKey, filterTarget.dataset.trafficDashboardFilterValue);
      return;
    }
    const actionTarget = event.target.closest<HTMLElement>('[data-traffic-dashboard-action]');
    if (actionTarget) {
      event.preventDefault();
      const action = actionTarget.dataset.trafficDashboardAction;
      if (action === 'clear-filters') clearFilters();
      if (action === 'remove-filter') removeFilter(actionTarget.dataset.trafficFilterKey as TrafficFilterKey | undefined);
      if (action === 'toggle-time-panel') toggleTimePanel();
      if (action === 'apply-time-preset' && actionTarget.dataset.trafficTimePreset) setWindow(actionTarget.dataset.trafficTimePreset);
      if (action === 'apply-last-range') applyLastRange();
      if (action === 'refresh') void loadTrafficDashboard();
      if (action === 'close-drawer') {
        const drawer = byId('traffic-dashboard-drawer');
        if (drawer) drawer.hidden = true;
      }
      return;
    }
    const eventButton = event.target.closest<HTMLButtonElement>('[data-traffic-dashboard-event]');
    if (eventButton?.dataset.trafficDashboardEvent) {
      const item = visibleEvents.find(candidate => candidate.id === eventButton.dataset.trafficDashboardEvent);
      const drawer = byId('traffic-dashboard-drawer');
      if (item && drawer) {
        drawer.hidden = false;
        renderEventDetail(item);
      }
    }
  });
  document.addEventListener('keydown', event => {
    if ((event.key !== 'Enter' && event.key !== ' ') || !(event.target instanceof Element) || !isMounted()) return;
    const target = event.target.closest<HTMLElement>('[data-traffic-dashboard-filter-key][data-traffic-dashboard-filter-value], [data-traffic-dashboard-action="clear-filters"]');
    if (!target || target instanceof HTMLButtonElement) return;
    event.preventDefault();
    target.click();
  });
}

export const trafficDashboardTemplate = `
  <div id="traffic-dashboard" class="operator-frame waf-dashboard-frame traffic-dashboard-frame">
    <div class="operator-frame-header waf-dashboard-page-header">
      <div class="operator-frame-title-block"><div class="operator-frame-kicker">Edge enforcement dashboard</div><h2 class="operator-frame-title">Traffic Control</h2><p class="operator-frame-subtitle">See which controls acted, where request pressure is building, and what needs operator attention.</p></div>
      <div class="operator-frame-actions waf-dashboard-header-actions" aria-label="Traffic Control dashboard controls">
        <div id="traffic-dashboard-header-time" class="waf-dashboard-header-time"></div>
        <a class="btn btn-outline btn-sm" href="#traffic-config" data-nav-target="traffic_config">Configure Traffic Control</a>
        <button id="traffic-dashboard-refresh" type="button" class="btn btn-sm security-events-refresh-button" data-traffic-dashboard-action="refresh" aria-label="Refresh Traffic Control dashboard"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 11a8 8 0 1 0 2 5.3"/><path d="M20 4v7h-7"/></svg></button>
      </div>
      <div class="waf-dashboard-command-bar is-empty" aria-label="Active Traffic Control filters"><div id="traffic-dashboard-header-filters" class="waf-dashboard-header-filters"></div></div>
    </div>

    <div class="operator-frame-body waf-dashboard-body">
      <div id="traffic-dashboard-banner" class="waf-dashboard-banner" hidden role="status"></div>
      <div class="operator-metric-strip waf-dashboard-metrics traffic-dashboard-metrics">
        <div class="operator-metric-item tone-primary is-filterable" role="button" tabindex="0" data-traffic-dashboard-action="clear-filters" aria-label="Show all Traffic Control decisions"><div class="operator-metric-label">Recorded decisions</div><div id="traffic-dashboard-decisions" class="operator-metric-value">${renderMetricSkeleton()}</div><div id="traffic-dashboard-decisions-note" class="operator-metric-sub">${renderMetricSubSkeleton()}</div></div>
        <div class="operator-metric-item tone-danger is-filterable"${filterAttributes('action', 'block', 'blocked decisions')}><div class="operator-metric-label">Blocked</div><div id="traffic-dashboard-blocked" class="operator-metric-value">${renderMetricSkeleton()}</div><div id="traffic-dashboard-blocked-note" class="operator-metric-sub">${renderMetricSubSkeleton()}</div></div>
        <div class="operator-metric-item is-filterable"${filterAttributes('action', 'challenge', 'challenged requests')}><div class="operator-metric-label">Challenged</div><div id="traffic-dashboard-challenged" class="operator-metric-value">${renderMetricSkeleton()}</div><div id="traffic-dashboard-challenged-note" class="operator-metric-sub">${renderMetricSubSkeleton()}</div></div>
        <div class="operator-metric-item"><div class="operator-metric-label">Affected sources</div><div id="traffic-dashboard-sources" class="operator-metric-value">${renderMetricSkeleton()}</div><div id="traffic-dashboard-sources-note" class="operator-metric-sub">${renderMetricSubSkeleton()}</div></div>
        <div class="operator-metric-item"><div class="operator-metric-label">Needs attention</div><div id="traffic-dashboard-attention" class="operator-metric-value">${renderMetricSkeleton()}</div><div id="traffic-dashboard-attention-note" class="operator-metric-sub">${renderMetricSubSkeleton()}</div></div>
      </div>

      <div class="waf-dashboard-primary-grid">
        <section class="operator-section waf-dashboard-panel waf-dashboard-panel--timeline"><div class="operator-section-head"><div><h3>Decision activity</h3></div></div><div id="traffic-dashboard-timeline" class="waf-dashboard-timeline-shell">${renderChartSkeleton(16)}</div></section>
        <section class="operator-section waf-dashboard-panel waf-dashboard-panel--posture"><div class="operator-section-head"><div><h3>Operator attention</h3></div></div><div class="waf-dashboard-status-list">
          <div><span>Runtime</span><strong id="traffic-dashboard-runtime">${renderTextSkeleton('70px')}</strong><small id="traffic-dashboard-runtime-note">${renderTextSkeleton('90px')}</small></div>
          <div><span>Control readiness</span><strong id="traffic-dashboard-readiness">${renderTextSkeleton('70px')}</strong><small id="traffic-dashboard-readiness-note">${renderTextSkeleton('90px')}</small></div>
          <div><span>Most active control</span><strong id="traffic-dashboard-active-control">${renderTextSkeleton('70px')}</strong><small id="traffic-dashboard-active-control-note">${renderTextSkeleton('90px')}</small></div>
          <div><span>Top affected path</span><strong id="traffic-dashboard-hotspot">${renderTextSkeleton('70px')}</strong><small id="traffic-dashboard-hotspot-note">${renderTextSkeleton('90px')}</small></div>
          <div><span>Events not recorded</span><strong id="traffic-dashboard-telemetry">${renderTextSkeleton('70px')}</strong><small id="traffic-dashboard-telemetry-note">${renderTextSkeleton('90px')}</small></div>
        </div></section>
      </div>

      <section class="operator-section waf-dashboard-section"><div class="operator-section-head"><div><h3>Control Analytics</h3></div></div><div id="traffic-dashboard-control-activity" class="waf-dashboard-rule-grid">${renderProtectionCardsSkeleton(3)}</div></section>

      <section class="operator-section waf-dashboard-section"><div class="operator-section-head"><div><h3>Investigation hotspots</h3></div></div><div class="waf-dashboard-exposure-grid">
        <div class="waf-dashboard-detail-panel"><h4>Decision outcomes</h4><div id="traffic-dashboard-outcomes">${renderBreakdownSkeleton(3)}</div></div>
        <div class="waf-dashboard-detail-panel"><h4>Affected paths</h4><div id="traffic-dashboard-paths">${renderBreakdownSkeleton(3)}</div></div>
        <div class="waf-dashboard-detail-panel"><h4>Repeated sources</h4><div id="traffic-dashboard-sources-list">${renderBreakdownSkeleton(3)}</div></div>
        <div class="waf-dashboard-detail-panel"><h4>Challenge handling</h4><div id="traffic-dashboard-challenges">${renderBreakdownSkeleton(3)}</div></div>
      </div></section>

      <section class="operator-section waf-dashboard-section waf-dashboard-events-section"><div class="operator-section-head"><div><h3>Recent traffic decisions</h3></div></div><div class="table-container waf-dashboard-table-wrap"><table class="waf-dashboard-table"><thead><tr><th>Time</th><th>Decision</th><th>Request</th><th>Client</th><th>Reason</th><th class="text-right">Latency</th><th class="text-right"><span class="sr-only">Details</span></th></tr></thead><tbody id="traffic-dashboard-events">${renderTableSkeleton(7, 6)}</tbody></table></div></section>
    </div>
    <aside id="traffic-dashboard-drawer" class="waf-dashboard-drawer" hidden aria-label="Traffic decision details"><div class="waf-dashboard-drawer-panel"><div class="waf-dashboard-drawer-head"><div><span>Traffic decision</span><h3 id="traffic-dashboard-drawer-title">Traffic decision</h3></div><button type="button" class="btn btn-outline btn-sm" data-traffic-dashboard-action="close-drawer">Close</button></div><div id="traffic-dashboard-drawer-body" class="waf-dashboard-drawer-body"></div></div></aside>
  </div>
`;

export function initTrafficDashboard(): void {
  bindEvents();
  renderHeaderTime();
  renderHeaderFilters();
  void loadTrafficDashboard();
}

export function disposeTrafficDashboard(): void {
  requestVersion += 1;
}
