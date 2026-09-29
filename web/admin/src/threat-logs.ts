import * as AdminDOM from './core/dom.js';
import * as AdminEvents from './core/events.js';
import { notify } from './core/notify.js';
import { SectionUI } from './sections/ui-components.js';

export interface ThreatLogItem {
  id: string;
  ts: number;
  timestamp: number;
  ip: string;
  country: string;
  city?: string;
  method: string;
  host: string;
  path: string;
  queryString?: string;
  statusCode: number;
  action: 'block' | 'detect' | 'allow' | string;
  blocked: boolean;
  rule: string;
  ruleId: string;
  ruleMessages: string[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  score: number;
  latencyMs: number;
  requestId: string;
  userAgent: string;
  userAgentFamily?: string;
  matchedFields?: string[];
  metadata?: Record<string, string>;
}

interface RawThreatLogPayload {
  logs?: Array<Record<string, unknown>>;
  count?: number;
  total?: number;
  next_cursor?: string;
}

interface ThreatLogsFilters {
  query: string;
  window: string;
  action: string;
  severity: string;
  category: string;
}

interface ThreatLogsState {
  bound: boolean;
  loading: boolean;
  refreshing: boolean;
  filters: ThreatLogsFilters;
  pageSize: number;
  pageIndex: number;
  logs: ThreatLogItem[];
  filteredLogs: ThreatLogItem[];
  selectedLog: ThreatLogItem | null;
}

const threatLogsPageSizes = [25, 50, 100] as const;

const threatLogsState: ThreatLogsState = {
  bound: false,
  loading: false,
  refreshing: false,
  filters: {
    query: '',
    window: '1h',
    action: 'all',
    severity: 'all',
    category: 'all'
  },
  pageSize: 25,
  pageIndex: 0,
  logs: [],
  filteredLogs: [],
  selectedLog: null
};

const countryNames: Record<string, string> = {
  US: 'United States',
  DE: 'Germany',
  NL: 'Netherlands',
  RU: 'Russia',
  CN: 'China',
  GB: 'United Kingdom',
  FR: 'France',
  CA: 'Canada',
  AU: 'Australia',
  JP: 'Japan',
  BR: 'Brazil',
  IN: 'India',
  UA: 'Ukraine',
  PL: 'Poland',
  SG: 'Singapore',
  KR: 'South Korea',
  IT: 'Italy',
  ES: 'Spain',
  SE: 'Sweden',
  CH: 'Switzerland'
};

const countryFlagSvgMap: Record<string, string> = {
  US: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="45" fill="#B22234"/><path d="M0,3.5h60M0,10.4h60M0,17.3h60M0,24.2h60M0,31.2h60M0,38.1h60" stroke="#FFF" stroke-width="3.5"/><rect width="25" height="24.2" fill="#3C3B6E"/><circle cx="5" cy="5" r="1.2" fill="#FFF"/><circle cx="12.5" cy="5" r="1.2" fill="#FFF"/><circle cx="20" cy="5" r="1.2" fill="#FFF"/><circle cx="8.75" cy="9" r="1.2" fill="#FFF"/><circle cx="16.25" cy="9" r="1.2" fill="#FFF"/><circle cx="5" cy="13" r="1.2" fill="#FFF"/><circle cx="12.5" cy="13" r="1.2" fill="#FFF"/><circle cx="20" cy="13" r="1.2" fill="#FFF"/><circle cx="8.75" cy="17" r="1.2" fill="#FFF"/><circle cx="16.25" cy="17" r="1.2" fill="#FFF"/><circle cx="5" cy="21" r="1.2" fill="#FFF"/><circle cx="12.5" cy="21" r="1.2" fill="#FFF"/><circle cx="20" cy="21" r="1.2" fill="#FFF"/></svg>`,
  DE: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="15" fill="#000"/><rect y="15" width="60" height="15" fill="#DD0000"/><rect y="30" width="60" height="15" fill="#FFCE00"/></svg>`,
  NL: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="15" fill="#AE1C28"/><rect y="15" width="60" height="15" fill="#FFF"/><rect y="30" width="60" height="15" fill="#21468B"/></svg>`,
  RU: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="15" fill="#FFF"/><rect y="15" width="60" height="15" fill="#0039A6"/><rect y="30" width="60" height="15" fill="#D52B1E"/></svg>`,
  CN: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="45" fill="#DE2910"/><polygon points="10,4 12,10 18,10 13,14 15,20 10,16 5,20 7,14 2,10 8,10" fill="#FFDE00"/></svg>`,
  IN: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="15" fill="#FF9933"/><rect y="15" width="60" height="15" fill="#FFF"/><rect y="30" width="60" height="15" fill="#138808"/><circle cx="30" cy="22.5" r="5" fill="none" stroke="#000080" stroke-width="1.2"/><circle cx="30" cy="22.5" r="1.5" fill="#000080"/></svg>`,
  GB: `<svg viewBox="0 0 60 45" width="18" height="13.5"><clipPath id="threat-gb-c"><rect width="60" height="45"/></clipPath><g clip-path="url(#threat-gb-c)"><rect width="60" height="45" fill="#012169"/><path d="M0,0 L60,45 M60,0 L0,45" stroke="#FFF" stroke-width="6"/><path d="M0,0 L60,45 M60,0 L0,45" stroke="#C8102E" stroke-width="2"/><path d="M30,0 v45 M0,22.5 h60" stroke="#FFF" stroke-width="10"/><path d="M30,0 v45 M0,22.5 h60" stroke="#C8102E" stroke-width="6"/></g></svg>`,
  FR: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="20" height="45" fill="#002395"/><rect x="20" width="20" height="45" fill="#FFF"/><rect x="40" width="20" height="45" fill="#ED2939"/></svg>`,
  IT: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="20" height="45" fill="#009246"/><rect x="20" width="20" height="45" fill="#FFF"/><rect x="40" width="20" height="45" fill="#CE2B37"/></svg>`,
  CA: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="15" height="45" fill="#FF0000"/><rect x="15" width="30" height="45" fill="#FFF"/><rect x="45" width="15" height="45" fill="#FF0000"/><path d="M30,12 l2,7 5,-3 -2,6 6,1 -5,4 3,6 -6,-2 -1,5 -1,-5 -6,2 3,-6 -5,-4 6,-1 -2,-6 5,3z" fill="#FF0000"/></svg>`,
  AU: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="45" fill="#012169"/><g transform="scale(0.5)"><rect width="60" height="45" fill="#012169"/><path d="M0,0 L60,45 M60,0 L0,45" stroke="#FFF" stroke-width="6"/><path d="M0,0 L60,45 M60,0 L0,45" stroke="#C8102E" stroke-width="2"/><path d="M30,0 v45 M0,22.5 h60" stroke="#FFF" stroke-width="10"/><path d="M30,0 v45 M0,22.5 h60" stroke="#C8102E" stroke-width="6"/></g><circle cx="45" cy="12" r="1.5" fill="#FFF"/><circle cx="52" cy="18" r="1.5" fill="#FFF"/><circle cx="45" cy="32" r="2" fill="#FFF"/><circle cx="38" cy="24" r="1.5" fill="#FFF"/><circle cx="15" cy="32" r="3" fill="#FFF"/></svg>`,
  JP: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="45" fill="#FFF"/><circle cx="30" cy="22.5" r="13.5" fill="#BC002D"/></svg>`,
  BR: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="45" fill="#009739"/><polygon points="30,5 54,22.5 30,40 6,22.5" fill="#FEDD00"/><circle cx="30" cy="22.5" r="9" fill="#012169"/><path d="M22,25 a9,9 0 0,0 16,-4" fill="none" stroke="#FFF" stroke-width="1.2"/></svg>`,
  UA: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="22.5" fill="#0057B7"/><rect y="22.5" width="60" height="22.5" fill="#FFDD00"/></svg>`,
  PL: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="22.5" fill="#FFF"/><rect y="22.5" width="60" height="22.5" fill="#DC143C"/></svg>`,
  SG: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="22.5" fill="#ED2939"/><rect y="22.5" width="60" height="22.5" fill="#FFF"/><path d="M12,5 a7,7 0 1,0 0,12.5 a6,6 0 1,1 0,-12.5" fill="#FFF"/></svg>`,
  KR: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="45" fill="#FFF"/><circle cx="30" cy="22.5" r="9" fill="#C60C30"/><path d="M30,13.5 a4.5,4.5 0 0,1 0,9 a4.5,4.5 0 0,0 0,9 a9,9 0 0,1 0,-18" fill="#003478"/></svg>`,
  ES: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="11" fill="#AA151B"/><rect y="11" width="60" height="23" fill="#F1BF00"/><rect y="34" width="60" height="11" fill="#AA151B"/></svg>`,
  SE: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="45" fill="#006AA7"/><rect x="18" width="8" height="45" fill="#FECC00"/><rect y="18.5" width="60" height="8" fill="#FECC00"/></svg>`,
  CH: `<svg viewBox="0 0 60 45" width="18" height="13.5"><rect width="60" height="45" fill="#D52B1E"/><rect x="25" y="10" width="10" height="25" fill="#FFF"/><rect x="17.5" y="17.5" width="25" height="10" fill="#FFF"/></svg>`
};

function renderCountryFlagHtml(countryCode: string, countryName: string): string {
  const code = (countryCode || '').trim().toUpperCase();
  const svg = countryFlagSvgMap[code];
  if (svg) {
    return `<span class="threat-country-flag" title="${escapeHTML(countryName)}" aria-label="${escapeHTML(countryName)}">${svg}</span>`;
  }
  if (!code || code === 'XX' || code.length !== 2) {
    return `<span class="threat-country-flag" title="${escapeHTML(countryName || 'Unknown Location')}"><span class="threat-flag-globe">🌐</span></span>`;
  }
  return `<span class="threat-country-flag" title="${escapeHTML(countryName)}"><span class="threat-flag-code">${code}</span></span>`;
}

function getCountryName(countryCode: string): string {
  if (!countryCode) return 'Unknown Location';
  const code = countryCode.toUpperCase();
  try {
    if (typeof Intl !== 'undefined' && typeof Intl.DisplayNames === 'function') {
      const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
      const name = regionNames.of(code);
      if (name && name !== code) return name;
    }
  } catch {
    // Fallback to static mapping
  }
  return countryNames[code] || code;
}

/**
 * Entry point when navigating to the Threat Logs view.
 */
export async function loadThreatLogsPage(): Promise<void> {
  bindThreatLogsInteractions();
  threatLogsState.pageIndex = 0;
  await fetchThreatLogs(true);
}

/**
 * External refresh request.
 */
export function refreshThreatLogs(): void {
  void fetchThreatLogs(false);
}

/**
 * Fetch threat logs from the API with fallback to realistic events if database is empty.
 */
async function fetchThreatLogs(showLoadingSpinner = false): Promise<void> {
  const container = AdminDOM.getById('threat-logs-container');
  if (!container) return;

  if (showLoadingSpinner) {
    threatLogsState.loading = true;
    container.innerHTML = SectionUI.renderLoading('Loading threat logs and security events...');
  } else {
    threatLogsState.refreshing = true;
  }

  try {
    const params = new URLSearchParams();
    params.set('window', threatLogsState.filters.window || '1h');
    if (threatLogsState.filters.action !== 'all') {
      params.set('type', threatLogsState.filters.action);
    }
    params.set('limit', '250');

    const response = await fetch(`/api/logs?${params.toString()}`, {
      headers: { Accept: 'application/json' }
    });

    let rawLogs: ThreatLogItem[] = [];
    if (response.ok) {
      const data = (await response.json()) as RawThreatLogPayload;
      if (Array.isArray(data.logs) && data.logs.length > 0) {
        rawLogs = data.logs.map((item, idx) => normalizeThreatLog(item, idx));
      }
    } else {
      console.warn(`Failed to fetch threat logs: HTTP ${response.status}`);
      notify('Unable to fetch threat logs from telemetry backend.', 'error');
    }

    threatLogsState.logs = rawLogs;
    applyClientFilters();
    renderThreatLogsUI(container);
  } catch (error) {
    console.error('Failed to load threat logs:', error);
    threatLogsState.logs = [];
    applyClientFilters();
    renderThreatLogsUI(container);
    notify('Failed to connect to telemetry service.', 'error');
  } finally {
    threatLogsState.loading = false;
    threatLogsState.refreshing = false;
  }
}

/**
 * Normalize whatever the backend sends into a uniform ThreatLogItem.
 */
function normalizeThreatLog(item: Record<string, unknown>, index: number): ThreatLogItem {
  const now = Math.floor(Date.now() / 1000);
  const rawTs = Number(item.ts || item.timestamp || now - (index * 42));
  const timestamp = rawTs > 1e11 ? Math.floor(rawTs / 1000) : rawTs;
  const isBlocked = Boolean(item.blocked ?? (item.action === 'block' || item.action === 'deny'));
  const action = String(item.action || (isBlocked ? 'block' : 'allow')).toLowerCase();

  const rawSev = String(item.severity || '').toLowerCase();
  let severity: 'critical' | 'high' | 'medium' | 'low' = 'medium';
  if (rawSev === 'critical' || rawSev === 'high' || rawSev === 'low') {
    severity = rawSev;
  } else if (Number(item.score || 0) >= 15) {
    severity = 'critical';
  } else if (Number(item.score || 0) >= 5) {
    severity = 'high';
  }

  const rawCategories = Array.isArray(item.categories)
    ? (item.categories as string[])
    : (typeof item.category === 'string' ? [item.category] : []);

  const category = rawCategories[0] || detectCategoryFromRule(String(item.rule || item.rule_name || ''));

  return {
    id: String(item.id || item.request_id || `log-${timestamp}-${index}`),
    ts: timestamp,
    timestamp,
    ip: String(item.ip || item.client_ip || '-'),
    country: String(item.country || 'XX').toUpperCase(),
    city: typeof item.city === 'string' && item.city ? item.city : undefined,
    method: String(item.method || '-').toUpperCase(),
    host: String(item.host || '-'),
    path: String(item.path || '/'),
    queryString: typeof item.query_string === 'string' && item.query_string ? item.query_string : undefined,
    statusCode: Number(item.status_code || 0),
    action,
    blocked: isBlocked,
    rule: String(item.rule || item.rule_name || item.rule_id || 'Security Policy Violation'),
    ruleId: String(item.rule_id || item.ruleId || '-'),
    ruleMessages: Array.isArray(item.rule_messages) ? (item.rule_messages as string[]) : [],
    severity,
    category,
    score: Number(item.score || 0),
    latencyMs: Number(item.latency_ms || 0),
    requestId: String(item.request_id || item.requestId || '-'),
    userAgent: String(item.user_agent || item.userAgent || '-'),
    userAgentFamily: typeof item.user_agent_family === 'string' && item.user_agent_family ? item.user_agent_family : undefined,
    matchedFields: Array.isArray(item.matched_fields) ? (item.matched_fields as string[]) : undefined,
    metadata: typeof item.metadata === 'object' && item.metadata !== null ? (item.metadata as Record<string, string>) : undefined
  };
}

/**
 * Filter state logic (search query, decision, severity, category).
 */
function applyClientFilters(): void {
  const query = threatLogsState.filters.query.trim().toLowerCase();
  const actionFilter = threatLogsState.filters.action;
  const sevFilter = threatLogsState.filters.severity;
  const catFilter = threatLogsState.filters.category;

  threatLogsState.filteredLogs = threatLogsState.logs.filter(log => {
    // Action filter
    if (actionFilter === 'blocked' && !log.blocked) return false;
    if (actionFilter === 'allowed' && log.blocked) return false;

    // Severity filter
    if (sevFilter !== 'all' && log.severity !== sevFilter) return false;

    // Category filter
    if (catFilter !== 'all') {
      const normalizedCat = log.category.toLowerCase().replace(/[\s_-]+/g, '');
      const targetCat = catFilter.toLowerCase().replace(/[\s_-]+/g, '');
      if (!normalizedCat.includes(targetCat)) return false;
    }

    // Text search filter
    if (query) {
      const haystack = `${log.ip} ${log.path} ${log.rule} ${log.ruleId} ${log.country} ${log.userAgent} ${log.method} ${log.category}`.toLowerCase();
      if (!haystack.includes(query)) return false;
    }

    return true;
  });

  threatLogsState.pageIndex = 0;
}

/**
 * Main UI renderer: builds the operator frame, KPI strip, filter bar, table, and pagination.
 */
function renderThreatLogsUI(container: HTMLElement): void {
  const totalCount = threatLogsState.logs.length;
  const blockedCount = threatLogsState.logs.filter(l => l.blocked).length;
  const blockRate = totalCount > 0 ? ((blockedCount / totalCount) * 100).toFixed(1) : '0.0';
  const detectedCount = totalCount - blockedCount;
  const uniqueIPs = new Set(threatLogsState.logs.map(l => l.ip)).size;

  // 4 Core KPIs in app colors (matching Security Events graphs)
  const metricStrip = SectionUI.renderOperatorMetricStrip([
    { label: 'Total Events', value: totalCount.toLocaleString(), sub: 'In selected window', tone: 'neutral' },
    { label: 'Blocked Attacks', value: `<span style="color: var(--brand-orange, #f97316)">${blockedCount.toLocaleString()}</span>`, sub: `${blockRate}% block rate`, tone: 'neutral' },
    { label: 'Monitored / Allowed', value: `<span style="color: #5f86a2">${detectedCount.toLocaleString()}</span>`, sub: 'Detection-only mode', tone: 'neutral' },
    { label: 'Unique Attackers', value: uniqueIPs.toLocaleString(), sub: 'Distinct client IPs', tone: 'neutral' }
  ], 'threat-metric-strip');

  // Table slice
  const start = threatLogsState.pageIndex * threatLogsState.pageSize;
  const pageLogs = threatLogsState.filteredLogs.slice(start, start + threatLogsState.pageSize);

  const rows = pageLogs.map(log => renderLogRow(log));

  const table = SectionUI.renderEnterpriseTable({
    columns: ['Time', 'Client IP', 'Method', 'Path', 'Status', 'Triggered Rule', 'Verdict', 'Actions'],
    rows,
    className: 'threat-log-table',
    emptyTitle: 'No threat events matching filters',
    emptyMessage: threatLogsState.logs.length === 0
      ? 'No threat events logged for the selected time window. All incoming requests conform to active security policies.'
      : 'Try clearing your search query or broadening the filter options.'
  });

  const content = `
    <div class="threat-operator-stack">
      ${metricStrip}
      ${SectionUI.renderOperatorSection('Forensic stream', `
        <div class="threat-event-surface">
          ${renderFilterToolbar()}
          ${table}
          ${renderPagination()}
        </div>
      `, {
        subtitle: 'Real-time telemetry of requests intercepted by WAF rule groups, rate limiters, and perimeter shields.',
        className: 'threat-catalog-section'
      })}
    </div>
  `;

  const headerActions = `
    <div class="threat-header-controls">
      <button type="button" class="btn btn-outline btn-sm" data-threat-action="export-csv" title="Export current filtered logs to CSV">
        <span class="threat-button-icon" aria-hidden="true">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        </span>
        Export CSV
      </button>
      <button type="button" class="btn btn-primary btn-sm" data-nav-target="waf_managed">
        <span class="threat-button-icon" aria-hidden="true">${SectionUI.icons.shield}</span>
        WAF Rules
      </button>
    </div>
  `;

  container.innerHTML = SectionUI.renderOperatorFrame({
    title: 'Threat Logs',
    kicker: 'Security',
    subtitle: 'Real-time view of blocked requests and security events.',
    actions: headerActions,
    content,
    className: 'threat-operator-frame'
  });
}

/**
 * Renders individual table rows:
 * - Flag emoji with hover tooltip displaying full country name
 * - Divided columns: Method, Path, Status
 * - Triggered Rule without ID or Category clutter
 */
function renderLogRow(log: ThreatLogItem): string[] {
  const timeStr = formatExactTime(log.timestamp);
  const relativeStr = formatRelativeTime(log.timestamp);

  const timeHtml = `
    <div class="threat-time-cell">
      <span class="threat-time-exact">${timeStr}</span>
      <span class="threat-time-relative">${relativeStr}</span>
    </div>
  `;

  const countryName = log.city ? `${log.city}, ${getCountryName(log.country)}` : getCountryName(log.country);
  const flagHtml = renderCountryFlagHtml(log.country, countryName);

  const ipHtml = `
    <div class="threat-ip-cell">
      ${flagHtml}
      <span class="threat-ip-address text-mono">${escapeHTML(log.ip)}</span>
      <button type="button" class="threat-inline-copy" data-threat-action="copy-ip" data-threat-ip="${escapeHTML(log.ip)}" title="Copy IP address">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
      </button>
    </div>
  `;

  const methodHtml = `<span class="threat-method-pill">${escapeHTML(log.method)}</span>`;

  const cleanPath = escapeHTML(log.path || '/');
  const pathHtml = `<span class="threat-path text-mono" title="${cleanPath}">${cleanPath}</span>`;

  const statusHtml = `<span class="threat-status-code">${log.statusCode}</span>`;

  // Triggered Rule without ID or category tags cluttering the cell
  const ruleHtml = `
    <div class="threat-rule-cell">
      <span class="threat-rule-name" title="${escapeHTML(log.rule)}">${escapeHTML(log.rule)}</span>
    </div>
  `;

  // Verdict: Single merged action-outcome cell with clean stacked text (no pill boxes or status dots)
  const verdictHtml = `
    <div class="threat-verdict-cell">
      <span class="threat-verdict-action ${log.blocked ? 'is-blocked' : 'is-allowed'}">${log.blocked ? 'Blocked' : 'Allowed'}</span>
      <span class="threat-verdict-sub">${capitalize(log.severity)} risk</span>
    </div>
  `;

  const actionsHtml = `
    <div class="threat-row-actions">
      <button type="button" class="btn btn-outline btn-sm threat-inspect-btn" data-threat-action="inspect" data-threat-id="${escapeHTML(log.id)}" title="Inspect detection forensics">
        <span class="threat-btn-icon" aria-hidden="true">${SectionUI.icons.eye}</span>
        Inspect
      </button>
    </div>
  `;

  return [timeHtml, ipHtml, methodHtml, pathHtml, statusHtml, ruleHtml, verdictHtml, actionsHtml];
}

/**
 * Filter toolbar with search, time window, decision, severity, and category.
 */
function renderFilterToolbar(): string {
  const { query, window: win, action, severity, category } = threatLogsState.filters;

  return `
    <div class="threat-filter-toolbar">
      <div class="threat-filter-search-box">
        <span class="threat-search-icon" aria-hidden="true">${SectionUI.icons.search}</span>
        <input type="text" id="threat-filter-search" class="settings-input threat-search-input"
               placeholder="Search IP, path, rule name, country, or user agent..."
               value="${escapeHTML(query)}" autocomplete="off" />
        ${query ? '<button type="button" class="threat-search-clear" data-threat-action="clear-search" aria-label="Clear search">&times;</button>' : ''}
      </div>

      <div class="threat-filter-dropdowns">
        <label class="threat-filter-select-group">
          <span class="threat-select-label">Time Window</span>
          <select id="threat-filter-window" class="settings-input select-sm" data-threat-filter="window">
            <option value="15m"${win === '15m' ? ' selected' : ''}>Last 15 Minutes</option>
            <option value="1h"${win === '1h' ? ' selected' : ''}>Last 1 Hour</option>
            <option value="24h"${win === '24h' ? ' selected' : ''}>Last 24 Hours</option>
            <option value="7d"${win === '7d' ? ' selected' : ''}>Last 7 Days</option>
            <option value="all"${win === 'all' ? ' selected' : ''}>All Events</option>
          </select>
        </label>

        <label class="threat-filter-select-group">
          <span class="threat-select-label">Decision</span>
          <select id="threat-filter-action" class="settings-input select-sm" data-threat-filter="action">
            <option value="all"${action === 'all' ? ' selected' : ''}>All Decisions</option>
            <option value="blocked"${action === 'blocked' ? ' selected' : ''}>Blocked Only</option>
            <option value="allowed"${action === 'allowed' ? ' selected' : ''}>Allowed / Detected</option>
          </select>
        </label>

        <label class="threat-filter-select-group">
          <span class="threat-select-label">Severity</span>
          <select id="threat-filter-severity" class="settings-input select-sm" data-threat-filter="severity">
            <option value="all"${severity === 'all' ? ' selected' : ''}>All Severities</option>
            <option value="critical"${severity === 'critical' ? ' selected' : ''}>Critical</option>
            <option value="high"${severity === 'high' ? ' selected' : ''}>High</option>
            <option value="medium"${severity === 'medium' ? ' selected' : ''}>Medium</option>
            <option value="low"${severity === 'low' ? ' selected' : ''}>Low</option>
          </select>
        </label>

        <label class="threat-filter-select-group">
          <span class="threat-select-label">Attack Category</span>
          <select id="threat-filter-category" class="settings-input select-sm" data-threat-filter="category">
            <option value="all"${category === 'all' ? ' selected' : ''}>All Categories</option>
            <option value="sql_injection"${category === 'sql_injection' ? ' selected' : ''}>SQL Injection</option>
            <option value="xss"${category === 'xss' ? ' selected' : ''}>Cross-Site Scripting</option>
            <option value="traversal"${category === 'traversal' ? ' selected' : ''}>Path Traversal</option>
            <option value="rce"${category === 'rce' ? ' selected' : ''}>Remote Code Exec</option>
            <option value="bot"${category === 'bot' ? ' selected' : ''}>Bot &amp; Crawler</option>
            <option value="rate_limit"${category === 'rate_limit' ? ' selected' : ''}>Rate Limiting</option>
            <option value="protocol"${category === 'protocol' ? ' selected' : ''}>Protocol Violation</option>
          </select>
        </label>
      </div>

      <div class="threat-filter-actions">
        <button type="button" class="btn btn-outline btn-sm" data-threat-action="clear-filters">Reset Filters</button>
      </div>
    </div>
  `;
}

/**
 * Pagination footer.
 */
function renderPagination(): string {
  const total = threatLogsState.filteredLogs.length;
  if (total === 0) return '';

  const start = (threatLogsState.pageIndex * threatLogsState.pageSize) + 1;
  const end = Math.min(start + threatLogsState.pageSize - 1, total);
  const totalPages = Math.ceil(total / threatLogsState.pageSize);
  const prevDisabled = threatLogsState.pageIndex <= 0 ? ' disabled' : '';
  const nextDisabled = threatLogsState.pageIndex >= totalPages - 1 ? ' disabled' : '';

  const sizeOptions = threatLogsPageSizes
    .map(size => `<option value="${size}"${size === threatLogsState.pageSize ? ' selected' : ''}>${size}</option>`)
    .join('');

  return `
    <nav class="threat-pagination" aria-label="Threat log pagination">
      <div class="threat-pagination-summary">
        Showing <strong>${start}–${end}</strong> of <strong>${total.toLocaleString()}</strong> events
      </div>
      <div class="threat-pagination-controls">
        <button type="button" class="btn btn-outline btn-sm" data-threat-action="prev-page"${prevDisabled}>
          Previous
        </button>
        <span class="threat-pagination-page">Page ${threatLogsState.pageIndex + 1} of ${totalPages || 1}</span>
        <button type="button" class="btn btn-outline btn-sm" data-threat-action="next-page"${nextDisabled}>
          Next
        </button>
        <label class="threat-page-size-label">
          <span>Rows</span>
          <select class="settings-input select-sm" data-threat-control="page-size" aria-label="Rows per page">
            ${sizeOptions}
          </select>
        </label>
      </div>
    </nav>
  `;
}

/**
 * Opens the deep forensic inspector modal for a given log ID.
 */
export function openThreatInspector(logId: string): void {
  const log = threatLogsState.logs.find(l => l.id === logId);
  if (!log) return;

  threatLogsState.selectedLog = log;

  const decisionTone = log.blocked ? 'danger' : 'success';
  const decisionLabel = log.blocked ? 'BLOCKED' : 'ALLOWED';
  const exactTime = new Date(log.timestamp * 1000).toUTCString();

  const matchedFieldsList = (log.matchedFields && log.matchedFields.length > 0)
    ? log.matchedFields.map(f => `<code class="threat-code-pill">${escapeHTML(f)}</code>`).join(' ')
    : '<span class="text-muted">None specified</span>';

  const ruleMessagesList = (log.ruleMessages && log.ruleMessages.length > 0)
    ? `<ul class="threat-msg-list">${log.ruleMessages.map(m => `<li>${escapeHTML(m)}</li>`).join('')}</ul>`
    : `<p class="threat-msg-text">${escapeHTML(log.rule)}</p>`;

  const jsonDump = escapeHTML(JSON.stringify(log, null, 2));

  const modalHtml = `
    <div class="threat-inspector-modal">
      <div class="threat-inspector-header">
        <div class="threat-inspector-title-area">
          <h3 class="threat-inspector-title">${escapeHTML(log.rule || 'Security Event Details')}</h3>
          <p class="threat-inspector-subtitle">
            <span class="threat-verdict-text ${log.blocked ? 'is-blocked' : 'is-allowed'}">${log.blocked ? 'Blocked' : 'Allowed'}</span>
            <span class="threat-meta-sep">&bull;</span>
            <span class="threat-meta-risk">${capitalize(log.severity)} Risk</span>
            <span class="threat-meta-sep">&bull;</span>
            <span class="threat-meta-score">Score ${log.score}</span>
            <span class="threat-meta-sep">&bull;</span>
            <span class="threat-meta-time text-mono">${exactTime}</span>
          </p>
        </div>
        <button type="button" class="threat-inspector-close modal-close" data-section-action="close-modal" aria-label="Close modal">&times;</button>
      </div>

      <div class="threat-inspector-body">
        <div class="threat-inspector-grid">
          <!-- Column 1: Client & Origin -->
          <div class="threat-inspector-card">
            <h4 class="threat-card-title">
              <span class="threat-card-icon">${SectionUI.icons.globe}</span>
              Client &amp; Origin
            </h4>
            <div class="threat-prop-list">
              <div class="threat-prop-row">
                <span class="threat-prop-label">IP Address</span>
                <span class="threat-prop-val text-mono">
                  ${escapeHTML(log.ip)}
                  <button type="button" class="threat-inline-copy" data-threat-action="copy-ip" data-threat-ip="${escapeHTML(log.ip)}" title="Copy IP">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                  </button>
                </span>
              </div>
              <div class="threat-prop-row">
                <span class="threat-prop-label">Geo Location</span>
                <span class="threat-prop-val">${renderCountryFlagHtml(log.country, log.city ? `${log.city}, ${getCountryName(log.country)}` : getCountryName(log.country))} ${escapeHTML(log.city ? `${log.city}, ${getCountryName(log.country)}` : getCountryName(log.country))}</span>
              </div>
              <div class="threat-prop-row">
                <span class="threat-prop-label">User Agent</span>
                <span class="threat-prop-val threat-ua-text text-mono" title="${escapeHTML(log.userAgent)}">${escapeHTML(log.userAgent)}</span>
              </div>
              <div class="threat-prop-row">
                <span class="threat-prop-label">Family / Bot Class</span>
                <span class="threat-prop-val">${escapeHTML(log.userAgentFamily || 'Standard Browser / Crawler')}</span>
              </div>
            </div>
          </div>

          <!-- Column 2: HTTP Target & Context -->
          <div class="threat-inspector-card">
            <h4 class="threat-card-title">
              <span class="threat-card-icon">${SectionUI.icons.route}</span>
              HTTP Request Context
            </h4>
            <div class="threat-prop-list">
              <div class="threat-prop-row">
                <span class="threat-prop-label">Method / Status</span>
                <span class="threat-prop-val">
                  <span class="threat-method-pill">${escapeHTML(log.method)}</span>
                  <span class="threat-status-code">${log.statusCode}</span>
                </span>
              </div>
              <div class="threat-prop-row">
                <span class="threat-prop-label">Host</span>
                <span class="threat-prop-val text-mono">${escapeHTML(log.host)}</span>
              </div>
              <div class="threat-prop-row">
                <span class="threat-prop-label">Request Path</span>
                <span class="threat-prop-val text-mono threat-full-path">${escapeHTML(log.path)}</span>
              </div>
              ${log.queryString ? `
              <div class="threat-prop-row">
                <span class="threat-prop-label">Query String</span>
                <span class="threat-prop-val text-mono">${escapeHTML(log.queryString)}</span>
              </div>` : ''}
              <div class="threat-prop-row">
                <span class="threat-prop-label">Processing Time</span>
                <span class="threat-prop-val">${log.latencyMs} ms</span>
              </div>
              <div class="threat-prop-row">
                <span class="threat-prop-label">Request ID</span>
                <span class="threat-prop-val text-mono">${escapeHTML(log.requestId)}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- WAF Detection & Rule Matches -->
        <div class="threat-inspector-card threat-detection-card">
          <h4 class="threat-card-title">
            <span class="threat-card-icon">${SectionUI.icons.shield}</span>
            WAF Rule &amp; Detection Breakdown
          </h4>
          <div class="threat-prop-list">
            <div class="threat-prop-row">
              <span class="threat-prop-label">Matched Rule</span>
              <span class="threat-prop-val"><strong>${escapeHTML(log.rule)}</strong> (ID: <code class="threat-code-pill">${escapeHTML(log.ruleId)}</code>)</span>
            </div>
            <div class="threat-prop-row">
              <span class="threat-prop-label">Attack Category</span>
              <span class="threat-prop-val">${escapeHTML(log.category)}</span>
            </div>
            <div class="threat-prop-row">
              <span class="threat-prop-label">Target Field / Payload</span>
              <span class="threat-prop-val">${matchedFieldsList}</span>
            </div>
            <div class="threat-prop-row">
              <span class="threat-prop-label">Detection Messages</span>
              <div class="threat-prop-val">${ruleMessagesList}</div>
            </div>
          </div>
        </div>

        <!-- Raw JSON Forensics -->
        <div class="threat-inspector-card">
          <div class="threat-json-header">
            <h4 class="threat-card-title">
              <span class="threat-card-icon">${SectionUI.icons.fileText}</span>
              Raw Event Forensics (JSON)
            </h4>
            <button type="button" class="btn btn-outline btn-sm" data-threat-action="copy-raw-json" data-threat-id="${escapeHTML(log.id)}">
              Copy JSON
            </button>
          </div>
          <pre class="threat-json-block"><code>${jsonDump}</code></pre>
        </div>
      </div>

      <div class="threat-inspector-footer">
        <button type="button" class="btn btn-outline" data-threat-action="filter-by-ip" data-threat-ip="${escapeHTML(log.ip)}">
          Filter by this IP (${escapeHTML(log.ip)})
        </button>
        <button type="button" class="btn btn-primary" data-section-action="close-modal">Close</button>
      </div>
    </div>
  `;

  SectionUI.showModal(modalHtml, { panelClass: 'modal-content threat-modal-container', closeOnBackdrop: true });
}

/**
 * Export current filtered threat logs to a downloadable CSV file.
 */
function exportThreatLogsCSV(): void {
  const logs = threatLogsState.filteredLogs;
  if (!logs.length) {
    notify('No threat logs to export', 'warning');
    return;
  }

  const headers = [
    'Timestamp',
    'DateTime_UTC',
    'Client_IP',
    'Country',
    'City',
    'Method',
    'Path',
    'Status_Code',
    'Triggered_Rule',
    'Rule_ID',
    'Severity',
    'Decision',
    'Anomaly_Score',
    'Latency_ms',
    'User_Agent'
  ];

  const escapeCSV = (val: unknown): string => {
    if (val === null || val === undefined) return '""';
    const str = String(val).replace(/"/g, '""');
    return `"${str}"`;
  };

  const rows = logs.map(l => [
    l.timestamp,
    new Date(l.timestamp).toISOString(),
    escapeCSV(l.ip),
    escapeCSV(l.country),
    escapeCSV(l.city || ''),
    escapeCSV(l.method),
    escapeCSV(l.path),
    l.statusCode,
    escapeCSV(l.rule),
    escapeCSV(l.ruleId),
    escapeCSV(l.severity),
    escapeCSV(l.blocked ? 'BLOCKED' : 'ALLOWED'),
    l.score,
    l.latencyMs,
    escapeCSV(l.userAgent)
  ].join(','));

  const csvContent = [headers.join(','), ...rows].join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', `aegis-threat-logs-${Date.now()}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);

  notify(`Exported ${logs.length} threat events to CSV`, 'success');
}

/**
 * Delegated event bindings for Threat Logs interactions.
 */
function bindThreatLogsInteractions(): void {
  if (threatLogsState.bound) return;
  threatLogsState.bound = true;

  // Click delegation
  AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-threat-action]', (event, target) => {
    event.preventDefault();
    const action = target.dataset.threatAction;

    if (action === 'export-csv') {
      exportThreatLogsCSV();
    } else if (action === 'clear-filters') {
      threatLogsState.filters = {
        query: '',
        window: '1h',
        action: 'all',
        severity: 'all',
        category: 'all'
      };
      applyClientFilters();
      const container = AdminDOM.getById('threat-logs-container');
      if (container) renderThreatLogsUI(container);
    } else if (action === 'clear-search') {
      threatLogsState.filters.query = '';
      applyClientFilters();
      const container = AdminDOM.getById('threat-logs-container');
      if (container) renderThreatLogsUI(container);
    } else if (action === 'inspect') {
      const id = target.dataset.threatId;
      if (id) openThreatInspector(id);
    } else if (action === 'copy-ip') {
      const ip = target.dataset.threatIp;
      if (ip) {
        void navigator.clipboard.writeText(ip);
        notify(`Copied IP ${ip} to clipboard`, 'success');
      }
    } else if (action === 'filter-by-ip') {
      const ip = target.dataset.threatIp;
      if (ip) {
        threatLogsState.filters.query = ip;
        SectionUI.closeModal();
        applyClientFilters();
        const container = AdminDOM.getById('threat-logs-container');
        if (container) renderThreatLogsUI(container);
        notify(`Filtered logs for IP ${ip}`, 'info');
      }
    } else if (action === 'copy-raw-json') {
      const id = target.dataset.threatId;
      const log = threatLogsState.logs.find(l => l.id === id);
      if (log) {
        void navigator.clipboard.writeText(JSON.stringify(log, null, 2));
        notify('Copied event JSON to clipboard', 'success');
      }
    } else if (action === 'prev-page') {
      if (threatLogsState.pageIndex > 0) {
        threatLogsState.pageIndex--;
        const container = AdminDOM.getById('threat-logs-container');
        if (container) renderThreatLogsUI(container);
      }
    } else if (action === 'next-page') {
      const maxPages = Math.ceil(threatLogsState.filteredLogs.length / threatLogsState.pageSize);
      if (threatLogsState.pageIndex < maxPages - 1) {
        threatLogsState.pageIndex++;
        const container = AdminDOM.getById('threat-logs-container');
        if (container) renderThreatLogsUI(container);
      }
    }
  });

  // Filter change delegation
  AdminEvents.delegateEvent<HTMLSelectElement>(document, 'change', '[data-threat-filter]', (_event, target) => {
    const filterKey = target.dataset.threatFilter as keyof ThreatLogsFilters;
    if (filterKey && filterKey in threatLogsState.filters) {
      threatLogsState.filters[filterKey] = target.value;
      if (filterKey === 'window' || filterKey === 'action') {
        // Fetch new window from API
        void fetchThreatLogs(false);
      } else {
        applyClientFilters();
        const container = AdminDOM.getById('threat-logs-container');
        if (container) renderThreatLogsUI(container);
      }
    }
  });

  // Page size change delegation
  AdminEvents.delegateEvent<HTMLSelectElement>(document, 'change', '[data-threat-control="page-size"]', (_event, target) => {
    const newSize = Number(target.value);
    if (threatLogsPageSizes.includes(newSize as typeof threatLogsPageSizes[number])) {
      threatLogsState.pageSize = newSize;
      threatLogsState.pageIndex = 0;
      const container = AdminDOM.getById('threat-logs-container');
      if (container) renderThreatLogsUI(container);
    }
  });

  // Search input debounced handler
  let searchTimeout: number | null = null;
  AdminEvents.delegateEvent<HTMLInputElement>(document, 'input', '#threat-filter-search', (_event, target) => {
    if (searchTimeout) window.clearTimeout(searchTimeout);
    searchTimeout = window.setTimeout(() => {
      threatLogsState.filters.query = target.value;
      applyClientFilters();
      const container = AdminDOM.getById('threat-logs-container');
      if (container) renderThreatLogsUI(container);
    }, 200);
  });
}



/**
 * Category detection from rule name.
 */
function detectCategoryFromRule(rule: string): string {
  const r = rule.toLowerCase();
  if (r.includes('sql') || r.includes('sqli')) return 'SQL Injection';
  if (r.includes('xss') || r.includes('script')) return 'Cross-Site Scripting';
  if (r.includes('traversal') || r.includes('path') || r.includes('../')) return 'Path Traversal';
  if (r.includes('rce') || r.includes('command') || r.includes('shell')) return 'Remote Code Exec';
  if (r.includes('bot') || r.includes('crawler') || r.includes('fingerprint')) return 'Bot & Crawler';
  if (r.includes('rate') || r.includes('flood') || r.includes('burst')) return 'Rate Limiting';
  return 'WAF Core';
}

function formatExactTime(timestamp: number): string {
  const date = new Date(timestamp * 1000);
  return date.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatRelativeTime(timestamp: number): string {
  const diffSec = Math.floor(Date.now() / 1000) - timestamp;
  if (diffSec < 10) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

function escapeHTML(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
