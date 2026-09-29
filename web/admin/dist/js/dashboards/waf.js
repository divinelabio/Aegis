import { api } from '../api.js';
import { notify } from '../core/notify.js';
import { FEATURES } from '../core/features.js';
import { renderMetricSkeleton, renderMetricSubSkeleton, renderChartSkeleton, renderBreakdownSkeleton, renderProtectionCardsSkeleton, renderTableSkeleton } from './skeletons.js';
let selectedWindow = '24h';
let eventsBound = false;
let requestVersion = 0;
let wafDashboardFilters = {};
let securitySectionAnalytics = [];
let securityDashboardEvents = [];
let selectedSecurityAnalyticsSection = '';
let wafEventsPage = 1;
let wafEventsPageSize = 20;
let selectedWAFDrawerTab = 'overview';
const escapeHTML = (value) => String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
const formatNumber = (value) => new Intl.NumberFormat('en-US').format(Math.max(0, Number(value) || 0));
const formatPercent = (value) => `${Math.max(0, Number(value) || 0).toFixed(1)}%`;
const formatTime = (timestamp) => {
    if (!timestamp)
        return '—';
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime()))
        return '—';
    return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' }).format(date);
};
const shortTime = (timestamp) => {
    if (!timestamp)
        return '';
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime()))
        return '';
    return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(date);
};
const timelineTick = (timestamp) => {
    if (!timestamp)
        return '';
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime()))
        return '';
    return new Intl.DateTimeFormat(undefined, { hour: 'numeric', hour12: true }).format(date);
};
function wafTimeRangeLabel(window = selectedWindow) {
    const labels = {
        '15m': 'Last 15 minutes',
        '1h': 'Last hour',
        '24h': 'Last 24 hours',
        '7d': 'Last 7 days',
        '30d': 'Last 30 days'
    };
    if (labels[window])
        return labels[window];
    const match = window.match(/^(\d+)(m|h)$/);
    if (!match)
        return 'Last 24 hours';
    const amount = Number(match[1]);
    if (match[2] === 'm')
        return `Last ${amount} minute${amount === 1 ? '' : 's'}`;
    if (amount % 168 === 0) {
        const weeks = amount / 168;
        return `Last ${weeks} week${weeks === 1 ? '' : 's'}`;
    }
    if (amount % 24 === 0) {
        const days = amount / 24;
        return `Last ${days} day${days === 1 ? '' : 's'}`;
    }
    return `Last ${amount} hour${amount === 1 ? '' : 's'}`;
}
function renderWAFHeaderTime() {
    const target = byId('waf-dashboard-header-time');
    if (!target)
        return;
    const label = wafTimeRangeLabel();
    const presets = [['15m', '15m'], ['1h', '1h'], ['24h', '24h'], ['7d', '7d'], ['30d', '30d']];
    target.innerHTML = `
    <div class="security-events-time-menu waf-dashboard-time-menu">
      <button type="button" id="waf-dashboard-time-trigger" class="security-time-dropdown-trigger" data-waf-dashboard-action="toggle-time-panel" aria-label="Time range: ${escapeHTML(label)}" aria-haspopup="true" aria-expanded="false" aria-controls="waf-dashboard-time-panel">
        <svg class="security-time-trigger-icon" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
        <strong>${escapeHTML(label)}</strong>
        <svg class="security-time-trigger-chevron" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>
      </button>
      <div id="waf-dashboard-time-panel" class="security-time-panel hidden">
        <div class="security-time-panel-head"><span>Time range</span><strong>${escapeHTML(label)}</strong></div>
        <div class="security-time-presets" aria-label="Quick time ranges">
          ${presets.map(([value, presetLabel]) => `<button type="button" class="security-time-preset ${selectedWindow === value ? 'is-active' : ''}" data-waf-dashboard-action="apply-time-preset" data-waf-time-preset="${value}">${presetLabel}</button>`).join('')}
        </div>
        <div class="security-time-field">
          <span>Custom last</span>
          <div class="security-time-inline">
            <input id="waf-dashboard-relative-amount" type="number" min="1" max="999" value="24" aria-label="Last amount">
            <select id="waf-dashboard-relative-unit" aria-label="Last unit">
              <option value="minutes">minutes</option>
              <option value="hours" selected>hours</option>
              <option value="days">days</option>
              <option value="weeks">weeks</option>
            </select>
            <button type="button" class="security-time-apply" data-waf-dashboard-action="apply-last-range">Apply</button>
          </div>
        </div>
      </div>
    </div>`;
}
let isFilterBuilderOpen = false;
let selectedFilterBuilderField = 'section';
function filterDisplayLabel(key, value) {
    const labels = {
        section: 'Section',
        action: 'Decision',
        category: 'Category',
        rule_id: 'Rule ID',
        rule_name: 'Rule',
        severity: 'Severity',
        ip: 'Source IP',
        country: 'Country',
        path: 'Path',
        host: 'Host',
        matched_field: 'Field',
        min_score: 'Score',
        max_score: 'Score',
        user_agent: 'User Agent',
        user_agent_family: 'UA Family',
        method: 'Method',
        status: 'Status',
        status_class: 'Status Class',
        policy: 'Policy',
        ja3: 'JA3',
        ja4: 'JA4',
        asn: 'ASN',
        request_id: 'Request ID'
    };
    const displayValue = key === 'action' ? actionLabel(value)
        : key === 'section' ? securitySectionLabel(value)
            : key === 'severity' ? value.toUpperCase()
                : value;
    return `${labels[key] || key}: ${displayValue}`;
}
function renderFilterOperators(field) {
    if (field === 'score' || field === 'status') {
        return `
      <option value="equals" selected>equals</option>
      <option value="greater_equal">is greater than or equal to</option>
      <option value="less_equal">is less than or equal to</option>
    `;
    }
    if (field === 'section' || field === 'action' || field === 'severity' || field === 'method' || field === 'status_class') {
        return `
      <option value="equals" selected>equals</option>
      <option value="in">is in</option>
    `;
    }
    return `
    <option value="equals" selected>equals</option>
    <option value="contains">contains</option>
    <option value="starts_with">starts with</option>
    <option value="ends_with">ends with</option>
    <option value="in">is in</option>
  `;
}
function renderFilterValueControl(field) {
    switch (field) {
        case 'section':
            return `
        <select id="waf-filter-value" class="security-filter-field-select" aria-label="Filter section value">
          <option value="waf_core">WAF Core</option>
          <option value="bot_protection">Bot Defense</option>
          <option value="traffic_control">Traffic Control & DDoS</option>
          <option value="http_security">App & HTTP Security</option>
          <option value="api_security">API Shield</option>
          <option value="access_control">Edge Access</option>
        </select>
      `;
        case 'action':
            return `
        <select id="waf-filter-value" class="security-filter-field-select" aria-label="Filter action value">
          <option value="block">Block</option>
          <option value="detect">Detect / Log</option>
          <option value="challenge">Challenge</option>
          <option value="ratelimit">Rate Limit</option>
          <option value="drop">Drop</option>
          <option value="deny">Deny</option>
          <option value="allow">Allow</option>
        </select>
      `;
        case 'severity':
            return `
        <select id="waf-filter-value" class="security-filter-field-select" aria-label="Filter severity value">
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
      `;
        case 'method':
            return `
        <select id="waf-filter-value" class="security-filter-field-select" aria-label="Filter HTTP method">
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
          <option value="PATCH">PATCH</option>
          <option value="HEAD">HEAD</option>
          <option value="OPTIONS">OPTIONS</option>
        </select>
      `;
        case 'status_class':
            return `
        <select id="waf-filter-value" class="security-filter-field-select" aria-label="Filter status class">
          <option value="2xx">2xx (Successful)</option>
          <option value="3xx">3xx (Redirects)</option>
          <option value="4xx">4xx (Client errors)</option>
          <option value="5xx">5xx (Server errors)</option>
        </select>
      `;
        case 'path':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="/api/v1/..." aria-label="Path filter value">`;
        case 'host':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="api.example.com" aria-label="Host filter value">`;
        case 'ip':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="192.168.1.1" aria-label="IP filter value">`;
        case 'country':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="US, FR, DE, CN..." aria-label="Country code">`;
        case 'category':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="sqli, xss, bad_bot, ddos..." aria-label="Attack class">`;
        case 'rule_id':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="e.g. 942100" aria-label="Rule ID">`;
        case 'rule_name':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="e.g. SQL Injection Attempt" aria-label="Rule name">`;
        case 'status':
            return `<input id="waf-filter-value" class="security-filter-builder-value" type="number" min="100" max="599" placeholder="403" aria-label="Status code">`;
        case 'score':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="e.g. 5, or 10-19, or 20+" aria-label="Threat score">`;
        case 'matched_field':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="ARGS:id, REQUEST_HEADERS..." aria-label="Matched field">`;
        case 'user_agent':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="Mozilla, curl, python..." aria-label="User agent">`;
        case 'user_agent_family':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="Chrome, Firefox, Safari..." aria-label="User agent family">`;
        case 'policy':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="Policy name or ID" aria-label="Policy">`;
        case 'ja3':
        case 'ja4':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="Fingerprint hash" aria-label="TLS fingerprint">`;
        case 'asn':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="e.g. AS15169" aria-label="ASN">`;
        case 'request_id':
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="Request ID trace" aria-label="Request ID">`;
        default:
            return `<input id="waf-filter-value" class="security-filter-builder-value" placeholder="Filter value" aria-label="Filter value">`;
    }
}
function renderWAFHeaderFilters() {
    const target = byId('waf-dashboard-header-filters');
    if (!target)
        return;
    const entries = [];
    Object.entries(wafDashboardFilters).forEach(([rawKey, rawValue]) => {
        const key = rawKey;
        const value = String(rawValue || '').trim();
        if (!value || key === 'min_score' || key === 'max_score')
            return;
        entries.push({ label: filterDisplayLabel(key, value), key });
    });
    const minimum = wafDashboardFilters.min_score;
    const maximum = wafDashboardFilters.max_score;
    if (minimum || maximum) {
        const label = minimum && maximum ? `${minimum}–${maximum}` : minimum ? `${minimum}+` : `≤${maximum}`;
        entries.push({ label: `Score: ${label}`, score: true });
    }
    const currentField = selectedFilterBuilderField;
    target.innerHTML = `
    <div class="security-events-filter-left" aria-label="Security event filters">
      <div class="security-events-filter-menu">
        <button type="button" id="waf-filter-trigger" class="security-filter-add-button" data-waf-dashboard-action="toggle-filter-menu" aria-haspopup="true" aria-expanded="${isFilterBuilderOpen ? 'true' : 'false'}" aria-controls="waf-filter-popover">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/></svg>
          <span>Add filter</span>
        </button>
        <div id="waf-filter-popover" class="security-filter-builder-popover ${isFilterBuilderOpen ? '' : 'hidden'}">
          <div class="security-filter-builder-title">Add Filter</div>
          <div class="security-filter-builder-row">
            <select id="waf-filter-field" class="security-filter-field-select" aria-label="Filter by">
              <optgroup label="Protection Engines & Decisions">
                <option value="section"${currentField === 'section' ? ' selected' : ''}>Protection Section</option>
                <option value="action"${currentField === 'action' ? ' selected' : ''}>Decision / Action</option>
                <option value="severity"${currentField === 'severity' ? ' selected' : ''}>Severity Level</option>
                <option value="category"${currentField === 'category' ? ' selected' : ''}>Attack Class / Category</option>
                <option value="rule_id"${currentField === 'rule_id' ? ' selected' : ''}>Rule ID</option>
                <option value="rule_name"${currentField === 'rule_name' ? ' selected' : ''}>Rule Name / Reason</option>
                <option value="policy"${currentField === 'policy' ? ' selected' : ''}>Protection Policy</option>
                <option value="score"${currentField === 'score' ? ' selected' : ''}>Anomaly / Threat Score</option>
              </optgroup>
              <optgroup label="HTTP Request & Response">
                <option value="path"${currentField === 'path' ? ' selected' : ''}>Path</option>
                <option value="host"${currentField === 'host' ? ' selected' : ''}>Host / Domain</option>
                <option value="method"${currentField === 'method' ? ' selected' : ''}>HTTP Method</option>
                <option value="status"${currentField === 'status' ? ' selected' : ''}>Status Code</option>
                <option value="status_class"${currentField === 'status_class' ? ' selected' : ''}>Status Class</option>
                <option value="matched_field"${currentField === 'matched_field' ? ' selected' : ''}>Matched Field</option>
                <option value="request_id"${currentField === 'request_id' ? ' selected' : ''}>Request ID</option>
              </optgroup>
              <optgroup label="Client & Network Identity">
                <option value="ip"${currentField === 'ip' ? ' selected' : ''}>Source IP Address</option>
                <option value="country"${currentField === 'country' ? ' selected' : ''}>Country</option>
                <option value="user_agent"${currentField === 'user_agent' ? ' selected' : ''}>User Agent</option>
                <option value="user_agent_family"${currentField === 'user_agent_family' ? ' selected' : ''}>User Agent Family</option>
                <option value="ja3"${currentField === 'ja3' ? ' selected' : ''}>JA3 Fingerprint</option>
                <option value="ja4"${currentField === 'ja4' ? ' selected' : ''}>JA4 Fingerprint</option>
                <option value="asn"${currentField === 'asn' ? ' selected' : ''}>ASN</option>
              </optgroup>
            </select>
            <select id="waf-filter-operator" class="security-filter-operator-select" aria-label="Operator">
              ${renderFilterOperators(currentField)}
            </select>
            <span id="waf-filter-value-container" class="security-filter-builder-value-shell" style="min-width: 0; width: 100%;">
              ${renderFilterValueControl(currentField)}
            </span>
          </div>
          <div class="security-filter-builder-actions">
            <button type="button" class="btn btn-sm btn-outline" data-waf-dashboard-action="cancel-filter-builder">Cancel</button>
            <button type="button" class="btn btn-sm" data-waf-dashboard-action="apply-filter-builder">Apply</button>
          </div>
        </div>
      </div>
      ${entries.length ? `
        <div class="security-active-filters" aria-label="Active security filters">
          ${entries.map(entry => `
            <span class="security-filter-chip">
              <span>${escapeHTML(entry.label)}</span>
              <button type="button" class="security-filter-chip-remove" data-waf-dashboard-action="remove-filter"${entry.key ? ` data-waf-filter-key="${entry.key}"` : ' data-waf-filter-group="score"'} aria-label="Remove ${escapeHTML(entry.label)} filter">&times;</button>
            </span>
          `).join('')}
        </div>
      ` : ''}
      ${entries.length ? '<button type="button" class="security-filter-clear-button" data-waf-dashboard-action="clear-filters">Clear all</button>' : ''}
    </div>
  `;
}
function toggleWAFFilterMenu() {
    isFilterBuilderOpen = !isFilterBuilderOpen;
    hideWAFTimePanel();
    renderWAFHeaderFilters();
    if (isFilterBuilderOpen) {
        const input = byId('waf-filter-value');
        if (input)
            input.focus();
    }
}
function hideWAFFilterBuilder() {
    if (!isFilterBuilderOpen)
        return;
    isFilterBuilderOpen = false;
    renderWAFHeaderFilters();
}
function applyWAFScoreFilter(rawValue, operator) {
    const range = rawValue.match(/^(\d+)(?:\s*[–-]\s*(\d+)|\+)$/);
    if (range) {
        wafDashboardFilters.min_score = range[1];
        if (range[2])
            wafDashboardFilters.max_score = range[2];
        else
            delete wafDashboardFilters.max_score;
        return;
    }
    const numeric = parseInt(rawValue, 10);
    if (Number.isNaN(numeric))
        return;
    if (operator === 'greater_equal') {
        wafDashboardFilters.min_score = String(numeric);
        delete wafDashboardFilters.max_score;
    }
    else if (operator === 'less_equal') {
        wafDashboardFilters.max_score = String(numeric);
        delete wafDashboardFilters.min_score;
    }
    else {
        wafDashboardFilters.min_score = String(numeric);
        wafDashboardFilters.max_score = String(numeric);
    }
}
function applyWAFFilterBuilder() {
    const fieldSelect = byId('waf-filter-field');
    const opSelect = byId('waf-filter-operator');
    const valInput = byId('waf-filter-value');
    if (!fieldSelect || !valInput)
        return;
    const field = fieldSelect.value;
    const operator = opSelect?.value || 'equals';
    const rawValue = valInput.value.trim();
    if (!rawValue)
        return;
    if (field === 'score') {
        applyWAFScoreFilter(rawValue, operator);
    }
    else {
        wafDashboardFilters[field] = normalizeDashboardFilterValue(field, rawValue, operator);
    }
    isFilterBuilderOpen = false;
    wafEventsPage = 1;
    renderWAFHeaderFilters();
    void loadWAFDashboard();
}
function normalizeDashboardFilterValue(key, value, operator = 'equals') {
    const firstValue = operator === 'in' ? value.split(',').map(item => item.trim()).filter(Boolean)[0] || value : value;
    if (key === 'action' && firstValue === 'log')
        return 'detect';
    if (key === 'country' || key === 'method')
        return firstValue.trim().toUpperCase();
    if (key === 'asn')
        return firstValue.trim().toUpperCase().startsWith('AS') ? firstValue.trim().toUpperCase() : `AS${firstValue.trim().toUpperCase()}`;
    if (key === 'status_class')
        return firstValue.trim().toLowerCase();
    return firstValue.trim();
}
function applyWAFDashboardFilter(filter, rawValue) {
    const value = rawValue.trim();
    if (!value)
        return;
    if (filter === 'section' && !isSecuritySectionEntitled(value))
        return;
    if (filter === 'score_band') {
        const range = value.match(/^(\d+)(?:\s*[–-]\s*(\d+)|\+)$/);
        if (!range)
            return;
        const minimum = range[1];
        const maximum = range[2] || '';
        const isActive = wafDashboardFilters.min_score === minimum && wafDashboardFilters.max_score === maximum;
        if (isActive) {
            delete wafDashboardFilters.min_score;
            delete wafDashboardFilters.max_score;
        }
        else {
            wafDashboardFilters = { ...wafDashboardFilters, min_score: minimum };
            if (maximum)
                wafDashboardFilters.max_score = maximum;
            else
                delete wafDashboardFilters.max_score;
        }
    }
    else {
        const normalized = normalizeDashboardFilterValue(filter, value);
        if (wafDashboardFilters[filter] === normalized)
            delete wafDashboardFilters[filter];
        else
            wafDashboardFilters = { ...wafDashboardFilters, [filter]: normalized };
    }
    wafEventsPage = 1;
    renderWAFHeaderFilters();
    void loadWAFDashboard();
}
function removeWAFDashboardFilter(key, group) {
    if (group === 'score') {
        delete wafDashboardFilters.min_score;
        delete wafDashboardFilters.max_score;
    }
    else if (key) {
        delete wafDashboardFilters[key];
    }
    wafEventsPage = 1;
    renderWAFHeaderFilters();
    void loadWAFDashboard();
}
function clearWAFDashboardFilters() {
    if (!Object.keys(wafDashboardFilters).length)
        return;
    wafDashboardFilters = {};
    wafEventsPage = 1;
    renderWAFHeaderFilters();
    void loadWAFDashboard();
}
function hideWAFTimePanel() {
    byId('waf-dashboard-time-panel')?.classList.add('hidden');
    byId('waf-dashboard-time-trigger')?.setAttribute('aria-expanded', 'false');
}
function toggleWAFTimePanel() {
    const panel = byId('waf-dashboard-time-panel');
    if (!panel)
        return;
    panel.classList.toggle('hidden');
    byId('waf-dashboard-time-trigger')?.setAttribute('aria-expanded', String(!panel.classList.contains('hidden')));
}
function applyWAFWindow(window) {
    selectedWindow = window;
    wafEventsPage = 1;
    renderWAFHeaderTime();
    void loadWAFDashboard();
}
function applyWAFLastRange() {
    const amount = Math.max(1, Math.min(999, Math.floor(Number(byId('waf-dashboard-relative-amount')?.value) || 1)));
    const unit = byId('waf-dashboard-relative-unit')?.value || 'hours';
    const windows = {
        minutes: `${amount}m`,
        hours: `${amount}h`,
        days: `${amount * 24}h`,
        weeks: `${amount * 168}h`
    };
    applyWAFWindow(windows[unit] || windows.hours);
}
function createEmptyWAFDashboard(message = '') {
    return {
        summary: {
            total_requests: 0,
            blocked_requests: 0,
            detected_requests: 0,
            block_rate: 0,
            avg_anomaly_score: 0,
            unique_source_ips: 0,
            unique_countries: 0,
            top_attack_category: 'None',
            window: selectedWindow
        },
        timeseries: [],
        protection_summary: {
            blocked_attacks: 0,
            detected_only: 0,
            rule_matches: 0,
            critical_high: 0,
            avg_anomaly_score: 0,
            max_anomaly_score: 0
        },
        attack_intelligence: {
            categories: [],
            severities: [],
            anomaly_score_bands: [],
            trend: []
        },
        rule_effectiveness: {
            top_blocking_rules: [],
            top_detect_only_rules: [],
            noisy_rules: [],
            matched_fields: []
        },
        section_analytics: [],
        breakdowns: {
            sections: [],
            actions: [],
            ips: [],
            countries: [],
            paths: [],
            hosts: []
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
        warnings: message ? [message] : []
    };
}
function eventMatchesWAFDashboardFilters(event) {
    if (wafDashboardFilters.section && event.section !== wafDashboardFilters.section)
        return false;
    const action = normalizeDashboardFilterValue('action', String(event.action || ''));
    if (wafDashboardFilters.action && action !== wafDashboardFilters.action)
        return false;
    if (wafDashboardFilters.category) {
        const cat = wafDashboardFilters.category.toLowerCase();
        const matchesCat = event.categories?.some(item => item.toLowerCase().includes(cat) || cat.includes(item.toLowerCase()));
        const matchesRule = event.rule_name?.toLowerCase().includes(cat);
        if (!matchesCat && !matchesRule)
            return false;
    }
    if (wafDashboardFilters.rule_id) {
        const rid = wafDashboardFilters.rule_id.toLowerCase();
        const erid = String(event.rule_id || '').toLowerCase();
        const matchesId = erid.includes(rid) || rid.includes(erid);
        const matchesIds = event.rule_ids?.some(item => item.toLowerCase().includes(rid) || rid.includes(item.toLowerCase()));
        const matchesName = event.rule_name?.toLowerCase().includes(rid) || rid.includes(event.rule_name?.toLowerCase() || '');
        if (!matchesId && !matchesIds && !matchesName)
            return false;
    }
    if (wafDashboardFilters.severity && !event.severities?.some(item => item.toLowerCase() === wafDashboardFilters.severity?.toLowerCase()))
        return false;
    if (wafDashboardFilters.ip && event.client_ip !== wafDashboardFilters.ip)
        return false;
    if (wafDashboardFilters.country && event.country?.toUpperCase() !== wafDashboardFilters.country.toUpperCase())
        return false;
    if (wafDashboardFilters.path) {
        const fp = wafDashboardFilters.path.toLowerCase();
        const ep = (event.path || '').toLowerCase();
        if (!ep.includes(fp) && !fp.includes(ep))
            return false;
    }
    if (wafDashboardFilters.host) {
        const fh = wafDashboardFilters.host.toLowerCase();
        const eh = (event.host || '').toLowerCase();
        if (!eh.includes(fh) && !fh.includes(eh))
            return false;
    }
    if (wafDashboardFilters.matched_field) {
        const mf = wafDashboardFilters.matched_field.toLowerCase();
        if (!event.matched_fields?.some(item => item.toLowerCase().includes(mf) || mf.includes(item.toLowerCase())))
            return false;
    }
    if (wafDashboardFilters.user_agent) {
        const ua = wafDashboardFilters.user_agent.toLowerCase();
        const eua = ((event.user_agent || '') + ' ' + (event.user_agent_family || '')).toLowerCase();
        if (!eua.includes(ua) && !ua.includes((event.user_agent_family || '').toLowerCase()))
            return false;
    }
    if (wafDashboardFilters.method && (event.method || '').toUpperCase() !== wafDashboardFilters.method.toUpperCase())
        return false;
    if (wafDashboardFilters.status && String(event.status_code || '') !== wafDashboardFilters.status)
        return false;
    if (wafDashboardFilters.policy) {
        const pol = wafDashboardFilters.policy.toLowerCase();
        const epol = (event.policy_name || event.policy_id || '').toLowerCase();
        if (!epol.includes(pol) && !pol.includes(epol))
            return false;
    }
    if (wafDashboardFilters.rule_name) {
        const rn = wafDashboardFilters.rule_name.toLowerCase();
        const ern = (event.rule_name || '').toLowerCase();
        const matchesMsg = event.rule_messages?.some(item => item.toLowerCase().includes(rn));
        if (!ern.includes(rn) && !matchesMsg)
            return false;
    }
    if (wafDashboardFilters.user_agent_family) {
        const uaf = wafDashboardFilters.user_agent_family.toLowerCase();
        const euaf = (event.user_agent_family || '').toLowerCase();
        if (!euaf.includes(uaf))
            return false;
    }
    if (wafDashboardFilters.status_class) {
        const sc = wafDashboardFilters.status_class.toLowerCase();
        const code = event.status_code || 0;
        const cClass = `${Math.floor(code / 100)}xx`;
        if (cClass !== sc)
            return false;
    }
    if (wafDashboardFilters.ja3 && event.ja3 && !event.ja3.toLowerCase().includes(wafDashboardFilters.ja3.toLowerCase()))
        return false;
    if (wafDashboardFilters.ja4 && event.ja4 && !event.ja4.toLowerCase().includes(wafDashboardFilters.ja4.toLowerCase()))
        return false;
    if (wafDashboardFilters.asn) {
        const fasn = wafDashboardFilters.asn.toUpperCase();
        const easn = (event.asn || '').toUpperCase();
        if (!easn.includes(fasn) && !fasn.includes(easn))
            return false;
    }
    if (wafDashboardFilters.request_id && event.request_id && !event.request_id.toLowerCase().includes(wafDashboardFilters.request_id.toLowerCase()))
        return false;
    const score = Number(event.anomaly_score) || 0;
    if (wafDashboardFilters.min_score && score < Number(wafDashboardFilters.min_score))
        return false;
    if (wafDashboardFilters.max_score && score > Number(wafDashboardFilters.max_score))
        return false;
    return true;
}
function byId(id) {
    const element = document.getElementById(id);
    return element instanceof HTMLElement ? element : null;
}
function isMounted() {
    return Boolean(byId('waf-dashboard'));
}
function setText(id, value) {
    const element = byId(id);
    if (element)
        element.textContent = value;
}
function setBanner(message = '', tone = 'warning') {
    const banner = byId('waf-dashboard-banner');
    if (!banner)
        return;
    banner.hidden = !message;
    banner.classList.toggle('is-danger', Boolean(message) && tone === 'danger');
    banner.textContent = message;
}
function actionLabel(value) {
    switch ((value || '').toLowerCase()) {
        case 'block': return 'Blocked';
        case 'deny': return 'Denied';
        case 'challenge': return 'Challenged';
        case 'redirect': return 'Redirected';
        case 'detect':
        case 'log': return 'Detected';
        case 'allow': return 'Allowed';
        case 'error': return 'Error';
        default: return value ? value.charAt(0).toUpperCase() + value.slice(1) : 'Observed';
    }
}
function actionTone(value) {
    switch ((value || '').toLowerCase()) {
        case 'block':
        case 'deny':
        case 'error': return 'intervened';
        case 'allow': return 'allowed';
        default: return 'observed';
    }
}
function securitySectionLabel(value) {
    switch (value) {
        case 'waf_core': return 'Application Firewall';
        case 'bot_protection': return 'Bot Protection';
        case 'traffic_control': return 'Traffic Control';
        case 'access_control': return 'Edge Access';
        case 'api_security': return 'API Security';
        case 'http_security': return 'Application Security';
        case 'security_rules': return 'Security Rules';
        default: return value ? value.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase()) : 'Security';
    }
}
function isSecuritySectionEntitled(section) {
    if (!section)
        return true;
    switch (section) {
        case 'waf_core':
        case 'traffic_control':
        case 'http_security':
            return true;
        case 'bot_protection':
            return api.hasFeature(FEATURES.BOT_PROTECTION);
        case 'api_security':
            return api.hasFeature(FEATURES.API_SECURITY);
        case 'access_control':
            return api.hasFeature(FEATURES.ACCESS_CONTROL);
        default:
            return true;
    }
}
function dashboardFilterAttributes(filter, value, label) {
    if (!filter || !value.trim())
        return '';
    return ` role="button" tabindex="0" data-waf-dashboard-filter-key="${escapeHTML(filter)}" data-waf-dashboard-filter-value="${escapeHTML(value)}" aria-label="Filter by ${escapeHTML(label)}"`;
}
function securitySectionIcon(section) {
    const icons = {
        waf_core: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>',
        bot_protection: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/></svg>',
        traffic_control: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>',
        api_security: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        http_security: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
        access_control: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>'
    };
    return icons[section] || '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
}
function renderBreakdown(items, emptyText, filter, limit = 5) {
    const visible = (items || []).filter(item => item && item.count > 0).slice(0, limit);
    if (!visible.length)
        return `<div class="waf-dashboard-empty">${escapeHTML(emptyText)}</div>`;
    const maximum = Math.max(...visible.map(item => item.count), 1);
    return `<div class="waf-dashboard-breakdown-list">${visible.map(item => {
        const width = Math.max(4, Math.round((item.count / maximum) * 100));
        const filterValue = filter?.value(item) || '';
        const label = item.label || item.key;
        return `<div class="waf-dashboard-breakdown-row${filterValue ? ' is-filterable' : ''}"${dashboardFilterAttributes(filter?.key, filterValue, label)}>
      <span class="waf-dashboard-breakdown-label" title="${escapeHTML(item.label || item.key)}">${escapeHTML(item.label || item.key)}</span>
      <span class="waf-dashboard-breakdown-track">
        <svg viewBox="0 0 100 4" preserveAspectRatio="none" role="img" aria-label="${escapeHTML(`${item.label || item.key}: ${formatNumber(item.count)}`)}">
          <rect class="waf-dashboard-breakdown-svg-track" x="0" y="0" width="100" height="4" rx="2" ry="2" />
          <rect class="waf-dashboard-breakdown-svg-fill" x="0" y="0" width="${width}" height="4" rx="2" ry="2" />
        </svg>
      </span>
      <strong>${formatNumber(item.count)}</strong>
    </div>`;
    }).join('')}</div>`;
}
function renderSecurityAnalyticsCard(title, items, emptyText, filter) {
    const normalized = (items || []).filter(item => item && item.count > 0).slice(0, 20);
    const modalPayload = encodeURIComponent(JSON.stringify(normalized.map(item => ({
        key: item.key,
        label: item.label || item.key,
        value: filter?.value(item) || item.key || item.label,
        count: item.count
    }))));
    const filterKey = filter?.key || '';
    return `
    <section class="operator-section system-health-section security-events-stat-card">
      <div class="operator-section-head">
        <div>
          <h3>${escapeHTML(title)}</h3>
        </div>
        <button type="button" class="security-stat-card-expand" data-waf-dashboard-action="open-statistics-modal" data-security-stat-title="${escapeHTML(title)}" data-security-stat-filter-key="${escapeHTML(filterKey)}" data-security-stat-items="${escapeHTML(modalPayload)}" aria-label="Open ${escapeHTML(title)} details">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        </button>
      </div>
      <div class="security-events-stat-body">
        ${renderSecurityStatRows(normalized.slice(0, 5), filter, emptyText)}
      </div>
    </section>
  `;
}
function renderSecurityStatRows(items, filter, emptyText = 'No data') {
    if (!items.length) {
        return `<div class="security-events-stat-empty">${escapeHTML(emptyText)}</div>`;
    }
    return items.map((item, index) => {
        const filterKey = filter?.key || 'rule_id';
        const filterValue = filter?.value(item) || item.key || item.label || '';
        const label = item.label || item.key;
        const filterAttrs = filterKey && filterValue
            ? ` role="button" tabindex="0" data-waf-dashboard-filter-key="${escapeHTML(filterKey)}" data-waf-dashboard-filter-value="${escapeHTML(filterValue)}" aria-label="Filter by ${escapeHTML(label)}"`
            : '';
        return `
      <div class="security-events-stat-row${filterAttrs ? ' is-filterable' : ''}"${filterAttrs}>
        <div class="security-events-stat-rank">${index + 1}</div>
        <div class="security-events-stat-copy">
          <span title="${escapeHTML(label)}">${escapeHTML(label)}</span>
        </div>
        <strong class="security-events-stat-count">${formatNumber(item.count)}</strong>
      </div>
    `;
    }).join('');
}
function renderSecuritySectionAnalytics(items) {
    const sources = (items || []).filter(source => isSecuritySectionEntitled(source.section));
    if (!sources.length)
        return '<div class="waf-dashboard-empty">No protection-section analytics recorded.</div>';
    if (wafDashboardFilters.section && sources.some(source => source.section === wafDashboardFilters.section)) {
        selectedSecurityAnalyticsSection = wafDashboardFilters.section;
    }
    const selected = sources.find(source => source.section === selectedSecurityAnalyticsSection) || sources[0];
    selectedSecurityAnalyticsSection = selected.section;
    const selectedLabel = selected.label || securitySectionLabel(selected.section);
    const selectedTabID = `waf-dashboard-section-analytics-tab-${selected.section}`;
    const panelID = 'waf-dashboard-section-analytics-panel';
    const breakdowns = selected.breakdowns || [];
    return `<div class="waf-dashboard-section-analytics">
    <div class="waf-dashboard-section-analytics-tabs" role="tablist" aria-label="Protection analytics sections">
      ${sources.map(source => {
        const label = source.label || securitySectionLabel(source.section);
        const active = source.section === selected.section;
        const tabID = `waf-dashboard-section-analytics-tab-${source.section}`;
        return `<button type="button" id="${escapeHTML(tabID)}" class="waf-dashboard-section-analytics-tab${active ? ' is-active' : ''}" role="tab" aria-selected="${active}" aria-controls="${panelID}" tabindex="${active ? '0' : '-1'}" data-waf-dashboard-action="select-section-analytics" data-waf-dashboard-section="${escapeHTML(source.section)}"><span>${escapeHTML(label)}</span></button>`;
    }).join('')}
    </div>
    <div id="${panelID}" class="waf-dashboard-section-analytics-panel" role="tabpanel" tabindex="0" aria-labelledby="${escapeHTML(selectedTabID)}" aria-label="${escapeHTML(`${selectedLabel} analytics`)}">
      <div class="security-statistics-deck security-events-statistics-deck" data-security-statistics-deck>
        <div class="security-events-stat-grid">
          ${breakdowns.map(breakdown => `
            <div class="security-statistics-card">
              ${renderSecurityAnalyticsCard(breakdown.label, breakdown.items, `No ${breakdown.label.toLowerCase()} recorded.`, securityAnalyticsFilter(breakdown.key))}
            </div>
          `).join('')}
        </div>
        ${breakdowns.length > securityStatisticsVisibleCardCount() ? `<button type="button" class="security-statistics-show-more" data-waf-dashboard-action="toggle-statistics-cards" aria-expanded="false">Show ${breakdowns.length - securityStatisticsVisibleCardCount()} more breakdowns</button>` : ''}
      </div>
    </div>
  </div>`;
}
function securityStatisticsVisibleCardCount() {
    if (window.innerWidth >= 2560)
        return 10;
    if (window.innerWidth >= 1800)
        return 8;
    return 9;
}
function securityStatisticsHiddenCardCount(deck) {
    return Math.max(0, deck.querySelectorAll('.security-statistics-card').length - securityStatisticsVisibleCardCount());
}
function toggleSecurityStatisticsCards(button) {
    const deck = button.closest('[data-security-statistics-deck]');
    if (!deck)
        return;
    const expanded = deck.classList.toggle('is-expanded');
    const hiddenCount = securityStatisticsHiddenCardCount(deck);
    button.textContent = expanded ? 'Show fewer breakdowns' : `Show ${hiddenCount} more breakdowns`;
    button.setAttribute('aria-expanded', String(expanded));
}
function syncSecurityStatisticsShowMore(deck) {
    const button = deck.querySelector('[data-waf-dashboard-action="toggle-statistics-cards"]');
    if (!button)
        return;
    const hiddenCardCount = securityStatisticsHiddenCardCount(deck);
    button.hidden = hiddenCardCount === 0;
    if (!button.hidden)
        button.textContent = `Show ${hiddenCardCount} more breakdowns`;
}
function parseStatisticModalItems(value) {
    try {
        const parsed = JSON.parse(decodeURIComponent(value));
        return Array.isArray(parsed)
            ? parsed.map(item => ({
                key: String(item.key || ''),
                label: String(item.label || item.value || item.key || '-'),
                value: String(item.value || item.key || item.label || '-'),
                count: Number(item.count || 0)
            }))
            : [];
    }
    catch {
        return [];
    }
}
function openSecurityStatisticsModal(source) {
    const modal = byId('waf-statistics-modal');
    const title = byId('waf-statistics-modal-title');
    const body = byId('waf-statistics-modal-body');
    if (!modal || !title || !body)
        return;
    const modalTitle = source.dataset.securityStatTitle || 'Details';
    const filterKey = source.dataset.securityStatFilterKey || '';
    const items = parseStatisticModalItems(source.dataset.securityStatItems || '');
    const total = items.reduce((sum, item) => sum + item.count, 0);
    const max = Math.max(...items.map(item => item.count), 0);
    title.textContent = modalTitle;
    body.innerHTML = `
    <p class="security-statistics-modal-summary">${formatNumber(total)} events &middot; ${formatNumber(items.length)} values</p>
    <div class="security-statistics-modal-list">
      ${items.length ? items.map(item => statisticModalRow(item, filterKey, total, max)).join('') : '<div class="dashboard-empty-state"><div class="dashboard-empty-title">No values found</div><div class="dashboard-empty-detail">No values were collected for this breakdown.</div></div>'}
    </div>
  `;
    modal.classList.remove('hidden');
}
function closeSecurityStatisticsModal() {
    byId('waf-statistics-modal')?.classList.add('hidden');
}
function statisticModalRow(item, filterKey, total, max) {
    const itemValue = item.value || item.key || item.label || '';
    const itemLabel = item.label || item.value || item.key || '';
    const filterButton = filterKey && itemValue !== '-'
        ? `<button type="button" class="security-statistics-modal-filter" data-waf-dashboard-filter-key="${escapeHTML(filterKey)}" data-waf-dashboard-filter-value="${escapeHTML(itemValue)}" data-waf-dashboard-action="apply-modal-filter">Filter</button>`
        : '';
    const percent = total > 0 ? (item.count / total) * 100 : 0;
    const width = max > 0 ? Math.max((item.count / max) * 100, 1) : 0;
    return `
    <div class="security-statistics-modal-row">
      <div class="security-statistics-modal-value">
        <span>${escapeHTML(itemLabel)}</span>
        <div class="security-statistics-modal-bar" style="--stat-width: ${width.toFixed(2)}%"></div>
      </div>
      <div class="security-statistics-modal-metrics">
        <strong>${formatNumber(item.count)}</strong>
        <small>${formatPercent(percent)}</small>
      </div>
      ${filterButton}
    </div>
  `;
}
function selectSecuritySectionAnalytics(section, focusTab = false) {
    if (!isSecuritySectionEntitled(section))
        return;
    if (!securitySectionAnalytics.some(source => source.section === section))
        return;
    selectedSecurityAnalyticsSection = section;
    wafEventsPage = 1;
    const target = byId('waf-dashboard-section-results');
    if (target)
        target.innerHTML = renderSecuritySectionAnalytics(securitySectionAnalytics);
    renderSelectedSecurityEvents();
    if (focusTab) {
        document.querySelectorAll('[data-waf-dashboard-action="select-section-analytics"]').forEach(tab => {
            if (tab.dataset.wafDashboardSection === section)
                tab.focus();
        });
    }
}
function securityAnalyticsFilter(key) {
    const filters = {
        // Actions & Decisions
        actions: { key: 'action', value: item => item.key || item.label },
        mitigations: { key: 'action', value: item => item.key || item.label },
        challenge_outcomes: { key: 'action', value: item => item.key || item.label },
        challenge_types: { key: 'action', value: item => item.key || item.label },
        decision_states: { key: 'action', value: item => item.key || item.label },
        evaluation_modes: { key: 'action', value: item => item.key || item.label },
        response_actions: { key: 'action', value: item => item.key || item.label },
        // Categories & Attack Classes
        categories: { key: 'category', value: item => item.label || item.key },
        attack_types: { key: 'category', value: item => item.label || item.key },
        attack_categories: { key: 'category', value: item => item.label || item.key },
        reasons: { key: 'category', value: item => item.label || item.key },
        heuristics: { key: 'category', value: item => item.label || item.key },
        violations: { key: 'category', value: item => item.label || item.key },
        validation: { key: 'category', value: item => item.label || item.key },
        authorization: { key: 'category', value: item => item.label || item.key },
        schema_types: { key: 'category', value: item => item.label || item.key },
        data_classes: { key: 'category', value: item => item.label || item.key },
        denial_reasons: { key: 'category', value: item => item.label || item.key },
        verified_bots: { key: 'category', value: item => item.label || item.key },
        verified_clients: { key: 'category', value: item => item.label || item.key },
        authentication: { key: 'category', value: item => item.label || item.key },
        // Severities
        severities: { key: 'severity', value: item => item.label || item.key },
        reputation: { key: 'severity', value: item => item.label || item.key },
        reputation_bands: { key: 'severity', value: item => item.label || item.key },
        // Rules
        rules: { key: 'rule_id', value: item => item.key || item.label },
        matched_rules: { key: 'rule_id', value: item => item.key || item.label },
        signals: { key: 'rule_id', value: item => item.key || item.label },
        behavior_signals: { key: 'rule_id', value: item => item.key || item.label },
        ja3: { key: 'rule_id', value: item => item.key || item.label },
        ja4: { key: 'rule_id', value: item => item.key || item.label },
        asn: { key: 'rule_id', value: item => item.key || item.label },
        // Policies
        policies: { key: 'policy', value: item => item.label || item.key },
        matched_policies: { key: 'policy', value: item => item.label || item.key },
        policy_revisions: { key: 'policy', value: item => item.label || item.key },
        policy_versions: { key: 'policy', value: item => item.label || item.key },
        // Paths & Operations
        paths: { key: 'path', value: item => item.key || item.label },
        operations: { key: 'path', value: item => item.key || item.label },
        protected_objects: { key: 'path', value: item => item.key || item.label },
        // Hosts
        hosts: { key: 'host', value: item => item.key || item.label },
        policy_attachments: { key: 'host', value: item => item.key || item.label },
        // Methods
        methods: { key: 'method', value: item => item.key || item.label },
        // Status
        status: { key: 'status', value: item => item.key || item.label },
        retry_after: { key: 'status', value: item => item.key || item.label },
        // IPs & Countries
        ips: { key: 'ip', value: item => item.key || item.label },
        countries: { key: 'country', value: item => item.key || item.label },
        // User Agents
        user_agents: { key: 'user_agent', value: item => item.key || item.label },
        user_agent_families: { key: 'user_agent', value: item => item.key || item.label },
        // Score Bands
        score_bands: { key: 'score_band', value: item => item.key || item.label },
        anomaly_score_bands: { key: 'score_band', value: item => item.key || item.label },
        // Matched Fields / Layers / Profiles / Modifiers
        attack_layers: { key: 'matched_field', value: item => item.label || item.key },
        attack_payload_locations: { key: 'matched_field', value: item => item.label || item.key },
        functions: { key: 'matched_field', value: item => item.key || item.label },
        header_evidence: { key: 'matched_field', value: item => item.label || item.key },
        content_types: { key: 'matched_field', value: item => item.key || item.label },
        content_length_bands: { key: 'matched_field', value: item => item.key || item.label },
        response_inspection: { key: 'matched_field', value: item => item.key || item.label },
        header_profiles: { key: 'matched_field', value: item => item.key || item.label },
        ddos_triggers: { key: 'matched_field', value: item => item.key || item.label },
        rate_limit_triggers: { key: 'matched_field', value: item => item.key || item.label },
        strategies: { key: 'matched_field', value: item => item.key || item.label },
        thresholds: { key: 'matched_field', value: item => item.key || item.label },
        modules: { key: 'matched_field', value: item => item.key || item.label },
        parameters: { key: 'matched_field', value: item => item.key || item.label },
        payload_evidence: { key: 'matched_field', value: item => item.key || item.label },
        directions: { key: 'matched_field', value: item => item.key || item.label },
        request_modifications: { key: 'matched_field', value: item => item.key || item.label },
        response_modifications: { key: 'matched_field', value: item => item.key || item.label },
        identity_providers: { key: 'matched_field', value: item => item.key || item.label },
        service_credential_types: { key: 'matched_field', value: item => item.key || item.label },
        service_credentials: { key: 'matched_field', value: item => item.key || item.label },
        decision_sources: { key: 'matched_field', value: item => item.key || item.label }
    };
    return filters[key] || { key: 'rule_id', value: item => item.key || item.label };
}
function buildBezier(coords) {
    if (!coords.length)
        return '';
    if (coords.length === 1)
        return `M ${(coords[0].x - 8).toFixed(1)} ${coords[0].y.toFixed(1)} L ${(coords[0].x + 8).toFixed(1)} ${coords[0].y.toFixed(1)}`;
    let d = `M ${coords[0].x.toFixed(1)} ${coords[0].y.toFixed(1)}`;
    for (let i = 0; i < coords.length - 1; i++) {
        const p0 = coords[Math.max(0, i - 1)];
        const p1 = coords[i];
        const p2 = coords[i + 1];
        const p3 = coords[Math.min(coords.length - 1, i + 2)];
        const cp1x = p1.x + (p2.x - p0.x) / 6;
        const cp1y = p1.y + (p2.y - p0.y) / 6;
        const cp2x = p2.x - (p3.x - p1.x) / 6;
        const cp2y = p2.y - (p3.y - p1.y) / 6;
        d += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`;
    }
    return d;
}
function renderTimeline(points) {
    let visible = (points || []).slice(-48);
    if (!visible.length)
        return '<div class="waf-dashboard-chart-empty">No request activity in this window.</div>';
    if (visible.length === 1) {
        const single = visible[0];
        const prev = {
            timestamp: single.timestamp - 3600,
            counts: { total: 0, block: 0, detect: 0, allow: 0 },
            avg_latency_ms: 0,
            p95_latency_ms: 0,
            avg_anomaly_score: 0
        };
        visible = [prev, single];
    }
    const totalFor = (point) => Math.max(0, Number(point.counts?.total || point.counts?.requests || 0));
    const rawMax = Math.max(...visible.map(totalFor), 1);
    const maximum = Math.max(10, Math.ceil(rawMax * 1.15));
    const chartWidth = 1100;
    const chartHeight = 280;
    const plotLeft = 52;
    const plotRight = 1076;
    const plotTop = 24;
    const plotBottom = 232;
    const plotHeight = plotBottom - plotTop;
    const slotWidth = visible.length > 1 ? (plotRight - plotLeft) / (visible.length - 1) : 0;
    const values = visible.map((point, index) => {
        const total = totalFor(point);
        const blocked = Math.min(total, Math.max(0, Number(point.counts?.block || point.counts?.blocked || 0)));
        const detected = Math.min(total - blocked, Math.max(0, Number(point.counts?.detect || point.counts?.detected || point.counts?.log || 0)));
        const errors = Math.max(0, Number(point.counts?.error || point.counts?.errors || 0));
        const x = visible.length === 1 ? (plotLeft + plotRight) / 2 : plotLeft + (slotWidth * index);
        const totalY = plotBottom - ((total / maximum) * plotHeight);
        const blockedY = plotBottom - ((blocked / maximum) * plotHeight);
        const detectedY = plotBottom - ((detected / maximum) * plotHeight);
        return {
            x,
            totalY,
            blockedY,
            detectedY,
            timestamp: point.timestamp,
            total,
            blocked,
            detected,
            errors,
            avgLatency: Math.max(0, Number(point.avg_latency_ms) || 0),
            p95Latency: Math.max(0, Number(point.p95_latency_ms) || 0),
            avgScore: Math.max(0, Number(point.avg_anomaly_score) || 0),
            label: index === visible.length - 1 ? 'Now' : timelineTick(point.timestamp)
        };
    });
    const firstPoint = values[0];
    const lastPoint = values[values.length - 1];
    const totalLine = buildBezier(values.map(p => ({ x: p.x, y: p.totalY })));
    const totalArea = `${totalLine} L ${lastPoint.x.toFixed(1)} ${plotBottom} L ${firstPoint.x.toFixed(1)} ${plotBottom} Z`;
    const blockedLine = buildBezier(values.map(p => ({ x: p.x, y: p.blockedY })));
    const blockedArea = `${blockedLine} L ${lastPoint.x.toFixed(1)} ${plotBottom} L ${firstPoint.x.toFixed(1)} ${plotBottom} Z`;
    const detectedLine = buildBezier(values.map(p => ({ x: p.x, y: p.detectedY })));
    const labelEvery = Math.max(1, Math.ceil((values.length - 1) / 5));
    const labels = values.map((point, index) => {
        if (index !== 0 && index !== values.length - 1 && index % labelEvery !== 0)
            return '';
        const anchor = index === 0 ? 'start' : index === values.length - 1 ? 'end' : 'middle';
        return `<text class="waf-dashboard-timeline-label" x="${point.x.toFixed(1)}" y="${plotBottom + 26}" text-anchor="${anchor}">${escapeHTML(point.label)}</text>`;
    }).join('');
    const hoverTargets = values.map(point => `
    <g class="waf-dashboard-timeline-point">
      <circle class="waf-point-total${point.total > 0 ? ' is-visible' : ''}" cx="${point.x.toFixed(1)}" cy="${point.totalY.toFixed(1)}" r="${point.total > 0 ? 5 : 3.5}" />
      ${point.blocked > 0 ? `<circle class="waf-point-blocked is-visible" cx="${point.x.toFixed(1)}" cy="${point.blockedY.toFixed(1)}" r="4.5" />` : ''}
      ${point.detected > 0 ? `<circle class="waf-point-detected is-visible" cx="${point.x.toFixed(1)}" cy="${point.detectedY.toFixed(1)}" r="4" />` : ''}
    </g>
  `).join('');
    const grid = [0, 0.25, 0.5, 0.75, 1].map(fraction => {
        const y = plotBottom - (plotHeight * fraction);
        const label = fraction === 0 ? '0' : formatNumber(Math.round(maximum * fraction));
        return `<line class="waf-dashboard-timeline-grid" x1="${plotLeft}" y1="${y.toFixed(1)}" x2="${plotRight}" y2="${y.toFixed(1)}" /><text class="waf-dashboard-timeline-value" x="${plotLeft - 10}" y="${(y + 4).toFixed(1)}" text-anchor="end">${label}</text>`;
    }).join('');
    const pointData = escapeHTML(JSON.stringify(values.map(({ x, timestamp, total, blocked, detected }) => ({ x, timestamp, total, blocked, detected }))));
    return `
    <div class="waf-dashboard-timeline-toolbar">
      <div class="waf-dashboard-timeline-legend">
        <span class="waf-timeline-legend-item"><span class="waf-timeline-swatch is-total"></span>Inspected</span>
        <span class="waf-timeline-legend-item"><span class="waf-timeline-swatch is-blocked"></span>Blocked</span>
        <span class="waf-timeline-legend-item"><span class="waf-timeline-swatch is-detected"></span>Detected</span>
      </div>
    </div>
    <svg class="waf-dashboard-timeline-svg" data-waf-timeline-points="${pointData}" viewBox="0 0 ${chartWidth} ${chartHeight}" preserveAspectRatio="none" role="img" aria-label="WAF request volume for the selected time window">
      <defs>
        <linearGradient id="waf-timeline-total-grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#5f86a2" stop-opacity="0.28" />
          <stop offset="100%" stop-color="#5f86a2" stop-opacity="0.01" />
        </linearGradient>
        <linearGradient id="waf-timeline-blocked-grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#f97316" stop-opacity="0.24" />
          <stop offset="100%" stop-color="#f97316" stop-opacity="0.01" />
        </linearGradient>
      </defs>
      ${grid}
      <path class="waf-dashboard-timeline-total-area" d="${totalArea}" />
      <path class="waf-dashboard-timeline-blocked-area" d="${blockedArea}" />
      <path class="waf-dashboard-timeline-total-line" d="${totalLine}" />
      <path class="waf-dashboard-timeline-blocked-line" d="${blockedLine}" />
      <path class="waf-dashboard-timeline-detected-line" d="${detectedLine}" />
      <line class="waf-dashboard-timeline-axis" x1="${plotLeft}" y1="${plotBottom}" x2="${plotRight}" y2="${plotBottom}" />
      <line id="waf-timeline-crosshair" class="waf-dashboard-timeline-crosshair" x1="0" y1="${plotTop}" x2="0" y2="${plotBottom}" style="display: none;" />
      ${hoverTargets}
      <rect class="waf-dashboard-timeline-hitbox" x="${plotLeft}" y="${plotTop}" width="${plotRight - plotLeft}" height="${plotHeight}" />
      ${labels}
    </svg>
    <div id="waf-dashboard-timeline-tooltip" class="waf-dashboard-timeline-tooltip" hidden></div>
  `;
}
function bindTimelineHover() {
    const chart = document.querySelector('#waf-dashboard-timeline .waf-dashboard-timeline-svg');
    const tooltip = byId('waf-dashboard-timeline-tooltip');
    const shell = byId('waf-dashboard-timeline');
    const crosshair = document.querySelector('#waf-timeline-crosshair');
    if (!chart || !tooltip || !shell)
        return;
    let points = [];
    try {
        points = JSON.parse(chart.dataset.wafTimelinePoints || '[]');
    }
    catch {
        return;
    }
    if (!points.length)
        return;
    const hideTooltip = () => {
        tooltip.hidden = true;
        if (crosshair)
            crosshair.style.display = 'none';
    };
    chart.addEventListener('pointermove', event => {
        const rect = chart.getBoundingClientRect();
        if (!rect.width)
            return;
        const chartX = ((event.clientX - rect.left) / rect.width) * 1100;
        const point = points.reduce((nearest, candidate) => Math.abs(candidate.x - chartX) < Math.abs(nearest.x - chartX) ? candidate : nearest);
        if (crosshair) {
            crosshair.setAttribute('x1', point.x.toFixed(1));
            crosshair.setAttribute('x2', point.x.toFixed(1));
            crosshair.style.display = 'block';
        }
        tooltip.innerHTML = `
      <strong>${escapeHTML(shortTime(point.timestamp))}</strong>
      <div class="waf-dashboard-timeline-tooltip-stat">
        <span><span class="waf-timeline-swatch is-total"></span>Inspected</span>
        <strong>${formatNumber(point.total)}</strong>
      </div>
      <div class="waf-dashboard-timeline-tooltip-stat">
        <span><span class="waf-timeline-swatch is-blocked"></span>Blocked</span>
        <strong>${formatNumber(point.blocked)}</strong>
      </div>
      <div class="waf-dashboard-timeline-tooltip-stat">
        <span><span class="waf-timeline-swatch is-detected"></span>Detected</span>
        <strong>${formatNumber(point.detected)}</strong>
      </div>
    `;
        tooltip.hidden = false;
        const shellRect = shell.getBoundingClientRect();
        const pointerX = event.clientX - shellRect.left;
        const pointerY = event.clientY - shellRect.top;
        const left = Math.max(8, Math.min(pointerX + 14, shell.clientWidth - tooltip.offsetWidth - 8));
        const top = Math.max(8, Math.min(pointerY - tooltip.offsetHeight - 12, shell.clientHeight - tooltip.offsetHeight - 8));
        tooltip.style.left = `${left}px`;
        tooltip.style.top = `${top}px`;
    });
    chart.addEventListener('pointerleave', hideTooltip);
}
function renderRecommendations(items) {
    const visible = (items || []).slice(0, 3);
    if (!visible.length)
        return '<div class="waf-dashboard-empty">No tuning priorities right now.</div>';
    return `<div class="waf-dashboard-recommendations">${visible.map(item => {
        const ruleID = item.rule_id || (item.title || '').match(/\\b(\\d{4,})\\b/)?.[1] || '';
        return `
    <div class="waf-dashboard-recommendation${ruleID ? ' is-filterable' : ''}"${dashboardFilterAttributes(ruleID ? 'rule_id' : undefined, ruleID, item.title || ruleID)}>
      <strong>${escapeHTML(item.title || item.rule_id || 'Review WAF signal')}</strong>
      <span>${escapeHTML(item.detail || 'Repeated WAF activity may need a closer review.')}</span>
      ${item.count ? `<small>${formatNumber(item.count)} matches</small>` : ''}
    </div>`;
    }).join('')}</div>`;
}
function closeWAFDrawer() {
    const drawer = byId('waf-dashboard-drawer');
    if (drawer) {
        drawer.classList.add('hidden');
        drawer.setAttribute('aria-hidden', 'true');
    }
}
function setWAFDrawerTab(tab) {
    selectedWAFDrawerTab = tab;
    const overviewBtn = byId('waf-drawer-tab-overview');
    const rawBtn = byId('waf-drawer-tab-raw');
    const overviewPanel = byId('waf-drawer-panel-overview');
    const rawPanel = byId('waf-drawer-panel-raw');
    if (overviewBtn && rawBtn && overviewPanel && rawPanel) {
        const isOverview = tab === 'overview';
        overviewBtn.classList.toggle('is-active', isOverview);
        overviewBtn.setAttribute('aria-selected', String(isOverview));
        rawBtn.classList.toggle('is-active', !isOverview);
        rawBtn.setAttribute('aria-selected', String(!isOverview));
        overviewPanel.classList.toggle('hidden', !isOverview);
        rawPanel.classList.toggle('hidden', isOverview);
    }
}
function drawerCardRow(label, value, mono = false) {
    return `
    <div class="security-event-row">
      <dt class="security-event-label">${escapeHTML(label)}</dt>
      <dd class="security-event-val${mono ? ' is-mono' : ''}">${escapeHTML(value)}</dd>
    </div>
  `;
}
async function copyToClipboard(text) {
    try {
        if (navigator?.clipboard?.writeText) {
            await navigator.clipboard.writeText(text);
            notify('Copied to clipboard', 'success');
        }
        else {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            notify('Copied to clipboard', 'success');
        }
    }
    catch {
        notify('Failed to copy to clipboard', 'error');
    }
}
function renderWAFEventCommandBar(event) {
    const copyActions = [];
    const filterActions = [];
    const iconGlobe = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>';
    const iconRoute = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a4.5 4.5 0 0 0 0-9H5"/><circle cx="18" cy="5" r="3"/></svg>';
    const iconFilter = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>';
    const iconShield = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
    const iconFile = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
    const btn = (action, label, icon, attrs) => {
        const attrStr = Object.entries(attrs).map(([k, v]) => `data-${k}="${escapeHTML(v)}"`).join(' ');
        return `<button type="button" class="security-event-action-btn" data-waf-dashboard-action="${action}" ${attrStr}>
      <span class="security-event-action-icon" aria-hidden="true">${icon}</span>
      <span>${escapeHTML(label)}</span>
    </button>`;
    };
    if (event.client_ip) {
        filterActions.push(btn('apply-drawer-filter', 'Filter IP', iconFilter, { wafFilterKey: 'ip', wafFilterValue: event.client_ip }));
        copyActions.push(btn('copy-drawer-value', 'Copy IP', iconGlobe, { wafCopyValue: event.client_ip }));
    }
    if (event.path) {
        filterActions.push(btn('apply-drawer-filter', 'Filter path', iconFilter, { wafFilterKey: 'path', wafFilterValue: event.path }));
        copyActions.push(btn('copy-drawer-value', 'Copy path', iconRoute, { wafCopyValue: event.path }));
    }
    if (event.rule_id) {
        filterActions.push(btn('apply-drawer-filter', 'Filter rule', iconShield, { wafFilterKey: 'rule_id', wafFilterValue: event.rule_id }));
        copyActions.push(btn('copy-drawer-value', 'Copy rule ID', iconShield, { wafCopyValue: event.rule_id }));
    }
    if (event.action) {
        filterActions.push(btn('apply-drawer-filter', 'Filter action', iconFilter, { wafFilterKey: 'action', wafFilterValue: event.action }));
    }
    if (event.categories?.[0]) {
        filterActions.push(btn('apply-drawer-filter', 'Filter category', iconFilter, { wafFilterKey: 'category', wafFilterValue: event.categories[0] }));
    }
    copyActions.push(btn('copy-drawer-value', 'Copy JSON', iconFile, { wafCopyValue: JSON.stringify(event, null, 2) }));
    return `
    <div class="security-event-workbench-actions" aria-label="Event actions">
      <div class="security-event-action-section">
        <span class="security-event-action-kicker">Filters</span>
        <div class="security-event-action-buttons">${filterActions.join('')}</div>
      </div>
      <div class="security-event-action-section">
        <span class="security-event-action-kicker">Quick Copy</span>
        <div class="security-event-action-buttons">${copyActions.join('')}</div>
      </div>
    </div>
  `;
}
function renderEventDetail(event) {
    const kicker = byId('waf-dashboard-drawer-kicker');
    const methodBadge = byId('waf-dashboard-drawer-method');
    const title = byId('waf-dashboard-drawer-title');
    const sectionSpan = byId('waf-dashboard-drawer-section');
    const timeSpan = byId('waf-dashboard-drawer-time');
    const body = byId('waf-dashboard-drawer-body');
    if (!body)
        return;
    const sectionName = securitySectionLabel(event.section);
    const method = (event.method || 'GET').toUpperCase();
    const ruleTitle = event.rule_name || event.rule_id || 'Security detection';
    if (kicker)
        kicker.textContent = `${sectionName} event`;
    if (methodBadge)
        methodBadge.textContent = method;
    if (title)
        title.textContent = ruleTitle;
    if (sectionSpan)
        sectionSpan.textContent = sectionName;
    if (timeSpan)
        timeSpan.textContent = formatTime(event.timestamp);
    const action = event.action || 'block';
    const isError = action === 'block' || action === 'deny' || (event.status_code || 0) >= 400;
    const score = Number(event.anomaly_score) || 0;
    const scoreTone = score >= 15 ? 'is-critical' : score >= 10 ? 'is-high' : score >= 5 ? 'is-medium' : '';
    const location = [event.city, event.country].filter(Boolean).join(', ') || '—';
    const responseInspection = event.response_inspection_coverage || (event.response_inspected ? (event.response_truncated ? 'Truncated' : 'Complete') : 'Not recorded');
    body.innerHTML = `
    <div class="security-event-workbench">
      <div class="security-event-workbench-tabs" role="tablist" aria-label="Event detail views">
        <button type="button" id="waf-drawer-tab-overview" class="security-event-workbench-tab${selectedWAFDrawerTab === 'overview' ? ' is-active' : ''}" role="tab" aria-selected="${selectedWAFDrawerTab === 'overview'}" aria-controls="waf-drawer-panel-overview" data-waf-dashboard-action="switch-drawer-tab" data-waf-drawer-tab="overview">
          Overview
        </button>
        <button type="button" id="waf-drawer-tab-raw" class="security-event-workbench-tab${selectedWAFDrawerTab === 'raw' ? ' is-active' : ''}" role="tab" aria-selected="${selectedWAFDrawerTab === 'raw'}" aria-controls="waf-drawer-panel-raw" data-waf-dashboard-action="switch-drawer-tab" data-waf-drawer-tab="raw">
          Raw event
        </button>
      </div>

      <div class="security-event-workbench-panels">
        <!-- OVERVIEW VIEW -->
        <div id="waf-drawer-panel-overview" class="security-event-workbench-view${selectedWAFDrawerTab === 'overview' ? '' : ' hidden'}" role="tabpanel" aria-labelledby="waf-drawer-tab-overview">
          <!-- Summary Hero Card -->
          <div class="security-event-hero-card">
            <div class="security-event-hero-status ${isError ? 'is-error' : ''}">
              <strong class="security-event-hero-code">${escapeHTML(String(event.status_code || 403))}</strong>
              <span class="security-event-hero-label">${escapeHTML(actionLabel(action))}</span>
            </div>
            <div class="security-event-hero-meta">
              <span class="security-event-method">${escapeHTML(method)}</span>
              ${score > 0 ? `<span class="waf-score-pill ${scoreTone}">Score ${score}</span>` : ''}
              ${typeof event.latency_ms === 'number' ? `<span class="security-event-hero-latency">${formatNumber(event.latency_ms)} ms</span>` : ''}
            </div>
          </div>

          <!-- Section: Request Details -->
          <section class="security-event-card">
            <div class="security-event-card-head">
              <span class="security-event-card-title">Request Details</span>
            </div>
            <div class="security-event-card-body">
              ${drawerCardRow('Host', event.host || '—', true)}
              ${drawerCardRow('Path', event.path || '—', true)}
              ${drawerCardRow('Method', method)}
              ${drawerCardRow('Request ID', event.request_id || '—', true)}
              ${drawerCardRow('User agent', event.user_agent || event.user_agent_family || '—')}
            </div>
          </section>

          <!-- Section: Threat & Detection Details -->
          <section class="security-event-card">
            <div class="security-event-card-head">
              <span class="security-event-card-title">Threat & Detection Details</span>
            </div>
            <div class="security-event-card-body">
              ${drawerCardRow('Rule ID', event.rule_id || event.rule_ids?.join(', ') || '—', true)}
              ${drawerCardRow('Rule name', event.rule_name || '—')}
              ${drawerCardRow('Rule source', event.rule_source || '—')}
              ${drawerCardRow('Category', event.categories?.join(', ') || '—')}
              ${drawerCardRow('Severity', event.severities?.join(', ') || '—')}
              ${drawerCardRow('Anomaly score', score ? String(score) : '—')}
              ${drawerCardRow('Matched fields', event.matched_fields?.join(', ') || '—', true)}
              ${drawerCardRow('Policy name', event.policy_name || event.policy_id || '—')}
            </div>
          </section>

          <!-- Section: Client & Network -->
          <section class="security-event-card">
            <div class="security-event-card-head">
              <span class="security-event-card-title">Client & Network</span>
            </div>
            <div class="security-event-card-body">
              ${drawerCardRow('Client IP', event.client_ip || '—', true)}
              ${drawerCardRow('Location', location)}
              ${drawerCardRow('Source identity', event.client_ip_source || '—')}
              ${drawerCardRow('Response inspection', responseInspection)}
              ${event.exclusion_ids?.length ? drawerCardRow('Exclusions', formatNumber(event.exclusion_ids.length)) : ''}
              ${event.reload_id ? drawerCardRow('Reload ID', event.reload_id, true) : ''}
            </div>
          </section>
        </div>

        <!-- RAW EVENT VIEW -->
        <div id="waf-drawer-panel-raw" class="security-event-workbench-view${selectedWAFDrawerTab === 'raw' ? '' : ' hidden'}" role="tabpanel" aria-labelledby="waf-drawer-tab-raw">
          <section class="security-event-card security-event-raw-card">
            <div class="security-event-card-head security-event-raw-head">
              <span class="security-event-card-title">Raw Event JSON</span>
              <button type="button" class="btn btn-sm btn-outline" data-waf-dashboard-action="copy-drawer-value" data-waf-copy-value="${escapeHTML(JSON.stringify(event, null, 2))}">
                Copy JSON
              </button>
            </div>
            <pre class="security-event-raw-body"><code>${escapeHTML(JSON.stringify(event, null, 2))}</code></pre>
          </section>
        </div>
      </div>

      <!-- Action Bar -->
      ${renderWAFEventCommandBar(event)}
    </div>
  `;
}
function renderSelectedSecurityEvents() {
    const body = byId('waf-dashboard-events');
    if (!body)
        return;
    const entitledSources = securitySectionAnalytics.filter(source => isSecuritySectionEntitled(source.section));
    const filterKeys = Object.keys(wafDashboardFilters);
    const hasActiveFilters = filterKeys.some(k => Boolean(wafDashboardFilters[k]));
    const hasSectionFilter = Boolean(wafDashboardFilters.section && isSecuritySectionEntitled(wafDashboardFilters.section));
    const activeSection = hasSectionFilter
        ? wafDashboardFilters.section
        : (isSecuritySectionEntitled(selectedSecurityAnalyticsSection) ? selectedSecurityAnalyticsSection : (entitledSources[0]?.section || ''));
    const selected = entitledSources.find(source => source.section === activeSection) || entitledSources[0];
    const section = selected?.section || activeSection;
    const label = hasSectionFilter
        ? (selected?.label || securitySectionLabel(section))
        : (hasActiveFilters ? 'matching' : (selected?.label || securitySectionLabel(section)));
    if (hasActiveFilters && !hasSectionFilter) {
        setText('waf-dashboard-events-title', 'Recent matching security events');
    }
    else {
        setText('waf-dashboard-events-title', `Recent ${label} events`);
    }
    const eventsToDisplay = hasActiveFilters
        ? securityDashboardEvents.filter(event => isSecuritySectionEntitled(event.section) && (hasSectionFilter ? event.section === activeSection : true) && eventMatchesWAFDashboardFilters(event))
        : securityDashboardEvents.filter(event => (!section || event.section === section) && isSecuritySectionEntitled(event.section));
    const total = eventsToDisplay.length;
    const totalPages = Math.max(1, Math.ceil(total / wafEventsPageSize));
    if (wafEventsPage > totalPages)
        wafEventsPage = totalPages;
    const startIdx = (wafEventsPage - 1) * wafEventsPageSize;
    const visible = eventsToDisplay.slice(startIdx, startIdx + wafEventsPageSize);
    const start = total ? startIdx + 1 : 0;
    const end = total ? Math.min(startIdx + visible.length, total) : 0;
    if (!visible.length) {
        const emptyMessage = hasActiveFilters
            ? 'No security events found matching active filters in this window.'
            : `No ${escapeHTML(label)} events in this window.`;
        body.innerHTML = `<tr><td colspan="8" class="waf-dashboard-table-empty">${emptyMessage}</td></tr>`;
        const pagination = byId('waf-dashboard-pagination');
        if (pagination)
            pagination.innerHTML = '';
        return;
    }
    body.innerHTML = visible.map(event => {
        const timeStr = formatTime(event.timestamp);
        const method = (event.method || 'GET').toUpperCase();
        const path = event.path || '/';
        const rule = event.rule_name || event.rule_id || event.rule_ids?.[0] || '—';
        const action = event.action || 'block';
        const country = (event.country || '').toUpperCase();
        const ip = event.client_ip || '—';
        const score = Number(event.anomaly_score) || 0;
        const scoreTone = score >= 15 ? 'is-critical' : score >= 10 ? 'is-high' : score >= 5 ? 'is-medium' : '';
        const rowLabel = `Open security event for ${method} ${path}`;
        return `<tr class="waf-event-row" data-waf-dashboard-event="${escapeHTML(event.id)}" tabindex="0" role="button" aria-label="${escapeHTML(rowLabel)}">
      <td><time datetime="${new Date(event.timestamp).toISOString()}">${escapeHTML(timeStr)}</time></td>
      <td><span class="security-event-method">${escapeHTML(method)}</span></td>
      <td class="waf-dashboard-request" title="${escapeHTML(path)}"><span>${escapeHTML(path)}</span></td>
      <td class="waf-dashboard-rule" title="${escapeHTML(rule)}"><span>${escapeHTML(rule)}</span></td>
      <td class="waf-dashboard-decision-cell"><span class="waf-action-pill tone-${actionTone(action)}">${escapeHTML(actionLabel(action))}</span></td>
      <td class="security-events-routing-source" title="${escapeHTML(country ? `${country} · ${ip}` : ip)}">
        <div class="security-events-source-wrap">
          ${country ? `<span class="security-events-country-tag">${escapeHTML(country)}</span>` : ''}
          <span class="security-events-ip-text">${escapeHTML(ip)}</span>
        </div>
      </td>
      <td class="text-right">${score ? `<span class="waf-score-pill ${scoreTone}">${score}</span>` : '—'}</td>
      <td class="text-right"><button type="button" class="btn btn-outline btn-sm" data-waf-dashboard-event="${escapeHTML(event.id)}">View</button></td>
    </tr>`;
    }).join('');
    const pagination = byId('waf-dashboard-pagination');
    if (pagination) {
        const previousDisabled = wafEventsPage <= 1 ? ' disabled' : '';
        const nextDisabled = wafEventsPage >= totalPages ? ' disabled' : '';
        pagination.innerHTML = `
      <span class="security-events-pagination-summary">${start ? `Showing ${start}–${end}` : 'No events'} of ${formatNumber(total)}</span>
      <span class="security-events-pagination-controls">
        <button type="button" class="btn btn-sm btn-outline" data-waf-dashboard-action="previous-events-page"${previousDisabled}>Previous</button>
        <span class="security-events-pagination-page">Page ${wafEventsPage} of ${totalPages}</span>
        <button type="button" class="btn btn-sm btn-outline" data-waf-dashboard-action="next-events-page"${nextDisabled}>Next</button>
        <label class="security-events-page-size-label">Rows per page
          <select class="security-events-page-size" data-waf-dashboard-action="change-page-size" aria-label="Rows per page">
            ${[10, 20, 50, 100].map(val => `<option value="${val}"${wafEventsPageSize === val ? ' selected' : ''}>${val}</option>`).join('')}
          </select>
        </label>
      </span>
    `;
    }
}
function renderDashboard(dashboard) {
    const summary = dashboard.summary || {};
    const protection = dashboard.protection_summary || {};
    const health = dashboard.health || {};
    const breakdowns = dashboard.breakdowns || {};
    const total = Number(summary.total_requests) || 0;
    const blocked = Number(summary.blocked_requests) || 0;
    const detected = Number(summary.detected_requests) || 0;
    const blockRate = summary.block_rate === undefined ? (total ? (blocked / total) * 100 : 0) : Number(summary.block_rate);
    const criticalHigh = Number(protection.critical_high) || 0;
    setText('waf-dashboard-total', formatNumber(total));
    setText('waf-dashboard-blocked', formatNumber(blocked));
    setText('waf-dashboard-detected', formatNumber(detected));
    setText('waf-dashboard-rate', formatPercent(blockRate));
    setText('waf-dashboard-critical', formatNumber(criticalHigh));
    setText('waf-dashboard-total-note', summary.window ? `Last ${summary.window}` : `Last ${selectedWindow}`);
    setText('waf-dashboard-blocked-note', `${formatPercent(blockRate)} rate`);
    setText('waf-dashboard-detected-note', 'Observe-only signals');
    setText('waf-dashboard-rate-note', 'Enforced blocks');
    setText('waf-dashboard-critical-note', 'Critical or high');
    const protectionSections = byId('waf-dashboard-protection-sections');
    if (protectionSections) {
        const entitledSections = (breakdowns.sections || []).filter(item => isSecuritySectionEntitled(item.key));
        protectionSections.innerHTML = renderBreakdown(entitledSections, 'No protection sections have recorded events.', { key: 'section', value: item => item.key }, 6);
    }
    const sectionResults = byId('waf-dashboard-section-results');
    securitySectionAnalytics = (dashboard.section_analytics || []).filter(source => isSecuritySectionEntitled(source.section));
    securityDashboardEvents = (dashboard.events?.events || []).filter(ev => isSecuritySectionEntitled(ev.section));
    if (wafDashboardFilters.section && !isSecuritySectionEntitled(wafDashboardFilters.section)) {
        delete wafDashboardFilters.section;
    }
    if (!isSecuritySectionEntitled(selectedSecurityAnalyticsSection)) {
        selectedSecurityAnalyticsSection = securitySectionAnalytics[0]?.section || '';
    }
    if (sectionResults)
        sectionResults.innerHTML = renderSecuritySectionAnalytics(securitySectionAnalytics);
    const timeline = byId('waf-dashboard-timeline');
    if (timeline) {
        timeline.innerHTML = renderTimeline(dashboard.timeseries);
        bindTimelineHover();
    }
    renderSelectedSecurityEvents();
    const rawWarning = dashboard.warnings?.[0] || '';
    const warning = (rawWarning && !rawWarning.includes('ClickHouse analytics database is not available') && !rawWarning.includes('Security analytics are temporarily unavailable') && !rawWarning.includes('Analytics storage is currently unavailable')) ? rawWarning : '';
    setBanner(warning, 'warning');
}
function resetWAFDashboardSkeletons() {
    const metricKeys = ['total', 'blocked', 'detected', 'rate', 'critical'];
    metricKeys.forEach(key => {
        const valEl = byId(`waf-dashboard-${key}`);
        const noteEl = byId(`waf-dashboard-${key}-note`);
        if (valEl)
            valEl.innerHTML = renderMetricSkeleton();
        if (noteEl)
            noteEl.innerHTML = renderMetricSubSkeleton();
    });
    const timeline = byId('waf-dashboard-timeline');
    if (timeline)
        timeline.innerHTML = renderChartSkeleton(16);
    const protectionSections = byId('waf-dashboard-protection-sections');
    if (protectionSections)
        protectionSections.innerHTML = renderBreakdownSkeleton(6);
    const sectionResults = byId('waf-dashboard-section-results');
    if (sectionResults)
        sectionResults.innerHTML = renderProtectionCardsSkeleton(4);
    const events = byId('waf-dashboard-events');
    if (events)
        events.innerHTML = renderTableSkeleton(8, 6);
}
async function loadWAFDashboard() {
    const version = ++requestVersion;
    const refresh = byId('waf-dashboard-refresh');
    const dashboardElement = byId('waf-dashboard');
    if (refresh) {
        refresh.disabled = true;
        refresh.setAttribute('aria-busy', 'true');
        refresh.setAttribute('aria-label', 'Refreshing Security Dashboard');
    }
    dashboardElement?.classList.add('is-loading');
    if (securityDashboardEvents.length === 0) {
        resetWAFDashboardSkeletons();
    }
    try {
        const query = new URLSearchParams({ window: selectedWindow, interval: 'auto', limit: '25' });
        Object.entries(wafDashboardFilters).forEach(([key, value]) => {
            if (value)
                query.set(key, value);
        });
        const response = await fetchWAFDashboard(query);
        if (version !== requestVersion || !isMounted())
            return;
        const dashboard = response?.dashboard;
        if (!dashboard || dashboard.health?.db_available === false) {
            renderDashboard(dashboard || createEmptyWAFDashboard());
        }
        else {
            renderDashboard(dashboard);
        }
    }
    catch (error) {
        if (version !== requestVersion || !isMounted())
            return;
        console.warn('Security analytics are unavailable:', error);
        renderDashboard(createEmptyWAFDashboard('Analytics storage is unavailable. Live decision logging is paused.'));
    }
    finally {
        if (version === requestVersion && isMounted()) {
            dashboardElement?.classList.remove('is-loading');
            if (refresh) {
                refresh.disabled = false;
                refresh.setAttribute('aria-busy', 'false');
                refresh.setAttribute('aria-label', 'Refresh Security Dashboard');
            }
        }
    }
}
async function fetchWAFDashboard(query) {
    const response = await fetch(`/api/security/dashboard?${query.toString()}`, {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' }
    });
    if (response.status === 401) {
        window.location.href = '/admin/login';
        return null;
    }
    if (!response.ok)
        return null;
    try {
        return await response.json();
    }
    catch {
        return null;
    }
}
async function openEvent(id) {
    const drawer = byId('waf-dashboard-drawer');
    const body = byId('waf-dashboard-drawer-body');
    if (!drawer || !body || !id)
        return;
    drawer.classList.remove('hidden');
    drawer.setAttribute('aria-hidden', 'false');
    body.innerHTML = '<div class="waf-dashboard-empty">Loading detection…</div>';
    const cachedEvent = securityDashboardEvents.find(event => event.id === id);
    if (cachedEvent) {
        renderEventDetail(cachedEvent);
        return;
    }
    try {
        const response = await api.get(`security/dashboard/events/${encodeURIComponent(id)}`);
        if (!isMounted())
            return;
        if (!response?.event)
            throw new Error('Detection details are unavailable.');
        renderEventDetail(response.event);
    }
    catch (error) {
        if (!isMounted())
            return;
        body.innerHTML = `<div class="waf-dashboard-empty">${escapeHTML(error instanceof Error ? error.message : 'Detection details are unavailable.')}</div>`;
    }
}
function bindEvents() {
    if (eventsBound)
        return;
    eventsBound = true;
    document.addEventListener('click', event => {
        if (!(event.target instanceof Element) || !isMounted())
            return;
        const filterTarget = event.target.closest('[data-waf-dashboard-filter-key][data-waf-dashboard-filter-value]');
        if (filterTarget?.dataset.wafDashboardFilterKey && filterTarget.dataset.wafDashboardFilterValue) {
            event.preventDefault();
            applyWAFDashboardFilter(filterTarget.dataset.wafDashboardFilterKey, filterTarget.dataset.wafDashboardFilterValue);
            return;
        }
        const toggleFilterMenu = event.target.closest('[data-waf-dashboard-action="toggle-filter-menu"]');
        if (toggleFilterMenu) {
            event.preventDefault();
            toggleWAFFilterMenu();
            return;
        }
        const cancelFilterBuilder = event.target.closest('[data-waf-dashboard-action="cancel-filter-builder"]');
        if (cancelFilterBuilder) {
            event.preventDefault();
            hideWAFFilterBuilder();
            return;
        }
        const applyFilterBuilderBtn = event.target.closest('[data-waf-dashboard-action="apply-filter-builder"]');
        if (applyFilterBuilderBtn) {
            event.preventDefault();
            applyWAFFilterBuilder();
            return;
        }
        const removeFilter = event.target.closest('[data-waf-dashboard-action="remove-filter"]');
        if (removeFilter) {
            event.preventDefault();
            removeWAFDashboardFilter(removeFilter.dataset.wafFilterKey, removeFilter.dataset.wafFilterGroup);
            return;
        }
        const clearFilters = event.target.closest('[data-waf-dashboard-action="clear-filters"]');
        if (clearFilters) {
            event.preventDefault();
            clearWAFDashboardFilters();
            return;
        }
        const timeTrigger = event.target.closest('[data-waf-dashboard-action="toggle-time-panel"]');
        if (timeTrigger) {
            event.preventDefault();
            hideWAFFilterBuilder();
            toggleWAFTimePanel();
            return;
        }
        if (isFilterBuilderOpen) {
            const popover = byId('waf-filter-popover');
            const trigger = byId('waf-filter-trigger');
            if (popover && !popover.contains(event.target) && !trigger?.contains(event.target)) {
                hideWAFFilterBuilder();
            }
        }
        const timePanel = byId('waf-dashboard-time-panel');
        if (timePanel && !timePanel.classList.contains('hidden') && !timeTrigger && !timePanel.contains(event.target)) {
            hideWAFTimePanel();
        }
        const preset = event.target.closest('[data-waf-dashboard-action="apply-time-preset"]');
        if (preset?.dataset.wafTimePreset) {
            event.preventDefault();
            applyWAFWindow(preset.dataset.wafTimePreset);
            return;
        }
        const customRange = event.target.closest('[data-waf-dashboard-action="apply-last-range"]');
        if (customRange) {
            event.preventDefault();
            applyWAFLastRange();
            return;
        }
        const sectionAnalyticsTab = event.target.closest('[data-waf-dashboard-action="select-section-analytics"]');
        if (sectionAnalyticsTab?.dataset.wafDashboardSection) {
            event.preventDefault();
            selectSecuritySectionAnalytics(sectionAnalyticsTab.dataset.wafDashboardSection, true);
            return;
        }
        const openModal = event.target.closest('[data-waf-dashboard-action="open-statistics-modal"]');
        if (openModal) {
            event.preventDefault();
            openSecurityStatisticsModal(openModal);
            return;
        }
        const closeModal = event.target.closest('[data-waf-dashboard-action="close-statistics-modal"]');
        if (closeModal) {
            event.preventDefault();
            closeSecurityStatisticsModal();
            return;
        }
        const modalFilter = event.target.closest('[data-waf-dashboard-action="apply-modal-filter"]');
        if (modalFilter?.dataset.wafDashboardFilterKey && modalFilter.dataset.wafDashboardFilterValue) {
            event.preventDefault();
            closeSecurityStatisticsModal();
            applyWAFDashboardFilter(modalFilter.dataset.wafDashboardFilterKey, modalFilter.dataset.wafDashboardFilterValue);
            return;
        }
        const toggleCards = event.target.closest('[data-waf-dashboard-action="toggle-statistics-cards"]');
        if (toggleCards) {
            event.preventDefault();
            toggleSecurityStatisticsCards(toggleCards);
            return;
        }
        if (event.target instanceof HTMLElement && event.target.id === 'waf-statistics-modal') {
            closeSecurityStatisticsModal();
            return;
        }
        const refresh = event.target.closest('[data-waf-dashboard-action="refresh"]');
        if (refresh) {
            event.preventDefault();
            void loadWAFDashboard();
            return;
        }
        const switchTab = event.target.closest('[data-waf-dashboard-action="switch-drawer-tab"]');
        if (switchTab?.dataset.wafDrawerTab) {
            event.preventDefault();
            setWAFDrawerTab(switchTab.dataset.wafDrawerTab);
            return;
        }
        const copyBtn = event.target.closest('[data-waf-dashboard-action="copy-drawer-value"]');
        if (copyBtn?.dataset.wafCopyValue) {
            event.preventDefault();
            void copyToClipboard(copyBtn.dataset.wafCopyValue);
            return;
        }
        const drawerFilter = event.target.closest('[data-waf-dashboard-action="apply-drawer-filter"]');
        if (drawerFilter?.dataset.wafFilterKey && drawerFilter.dataset.wafFilterValue) {
            event.preventDefault();
            closeWAFDrawer();
            applyWAFDashboardFilter(drawerFilter.dataset.wafFilterKey, drawerFilter.dataset.wafFilterValue);
            return;
        }
        const closeDrawer = event.target.closest('[data-waf-dashboard-action="close-drawer"]');
        if (closeDrawer) {
            event.preventDefault();
            closeWAFDrawer();
            return;
        }
        if (event.target instanceof HTMLElement && event.target.id === 'waf-dashboard-drawer') {
            closeWAFDrawer();
            return;
        }
        const prevPage = event.target.closest('[data-waf-dashboard-action="previous-events-page"]');
        if (prevPage) {
            event.preventDefault();
            if (wafEventsPage > 1) {
                wafEventsPage -= 1;
                renderSelectedSecurityEvents();
            }
            return;
        }
        const nextPage = event.target.closest('[data-waf-dashboard-action="next-events-page"]');
        if (nextPage) {
            event.preventDefault();
            wafEventsPage += 1;
            renderSelectedSecurityEvents();
            return;
        }
        const eventRow = event.target.closest('[data-waf-dashboard-event]');
        if (eventRow?.dataset.wafDashboardEvent) {
            event.preventDefault();
            void openEvent(eventRow.dataset.wafDashboardEvent);
        }
    });
    document.addEventListener('change', event => {
        if (!(event.target instanceof Element) || !isMounted())
            return;
        if (event.target.id === 'waf-filter-field') {
            const fieldSelect = event.target;
            selectedFilterBuilderField = fieldSelect.value;
            const opSelect = byId('waf-filter-operator');
            if (opSelect)
                opSelect.innerHTML = renderFilterOperators(selectedFilterBuilderField);
            const valContainer = byId('waf-filter-value-container');
            if (valContainer)
                valContainer.innerHTML = renderFilterValueControl(selectedFilterBuilderField);
            const valInput = byId('waf-filter-value');
            if (valInput)
                valInput.focus();
            return;
        }
        const pageSizeSelect = event.target.closest('[data-waf-dashboard-action="change-page-size"]');
        if (pageSizeSelect) {
            wafEventsPageSize = Number(pageSizeSelect.value) || 20;
            wafEventsPage = 1;
            renderSelectedSecurityEvents();
        }
    });
    document.addEventListener('keydown', event => {
        if (!(event.target instanceof Element) || !isMounted())
            return;
        if (event.key === 'Escape') {
            if (isFilterBuilderOpen) {
                event.preventDefault();
                hideWAFFilterBuilder();
                return;
            }
            const timePanel = byId('waf-dashboard-time-panel');
            if (timePanel && !timePanel.classList.contains('hidden')) {
                event.preventDefault();
                hideWAFTimePanel();
                return;
            }
            if (!byId('waf-dashboard-drawer')?.classList.contains('hidden')) {
                event.preventDefault();
                closeWAFDrawer();
                return;
            }
            if (!byId('waf-statistics-modal')?.classList.contains('hidden')) {
                event.preventDefault();
                closeSecurityStatisticsModal();
                return;
            }
        }
        if (event.key === 'Enter') {
            const target = event.target;
            if (target && target.id === 'waf-filter-value' && target.tagName !== 'BUTTON') {
                event.preventDefault();
                applyWAFFilterBuilder();
                return;
            }
        }
        const sectionAnalyticsTab = event.target.closest('[data-waf-dashboard-action="select-section-analytics"]');
        if (sectionAnalyticsTab && ['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
            const tabs = Array.from(document.querySelectorAll('[data-waf-dashboard-action="select-section-analytics"]'));
            const currentIndex = tabs.indexOf(sectionAnalyticsTab);
            if (currentIndex < 0 || !tabs.length)
                return;
            const nextIndex = event.key === 'Home' ? 0
                : event.key === 'End' ? tabs.length - 1
                    : (currentIndex + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
            const next = tabs[nextIndex];
            if (!next?.dataset.wafDashboardSection)
                return;
            event.preventDefault();
            selectSecuritySectionAnalytics(next.dataset.wafDashboardSection, true);
            return;
        }
        const eventRow = event.target.closest('.waf-event-row[data-waf-dashboard-event]');
        if (eventRow && (event.key === 'Enter' || event.key === ' ') && !(event.target instanceof HTMLButtonElement)) {
            event.preventDefault();
            if (eventRow.dataset.wafDashboardEvent) {
                void openEvent(eventRow.dataset.wafDashboardEvent);
            }
            return;
        }
        if (event.key !== 'Enter' && event.key !== ' ')
            return;
        const clearFilters = event.target.closest('[data-waf-dashboard-action="clear-filters"]');
        if (clearFilters && !(clearFilters instanceof HTMLButtonElement)) {
            event.preventDefault();
            clearFilters.click();
            return;
        }
        const filterTarget = event.target.closest('[data-waf-dashboard-filter-key][data-waf-dashboard-filter-value]');
        if (!filterTarget || filterTarget instanceof HTMLButtonElement)
            return;
        event.preventDefault();
        filterTarget.click();
    });
    window.addEventListener('resize', () => {
        if (!isMounted())
            return;
        document.querySelectorAll('[data-security-statistics-deck]:not(.is-expanded)').forEach(syncSecurityStatisticsShowMore);
    });
}
export const wafDashboardTemplate = `
  <div id="waf-dashboard" class="operator-frame waf-dashboard-frame security-events-frame">
    <div class="operator-frame-header waf-dashboard-page-header security-events-page-header">
      <div class="operator-frame-title-block">
        <div class="operator-frame-kicker">Security dashboard</div>
        <h2 class="operator-frame-title">Security Events</h2>
        <p class="operator-frame-subtitle">Monitor security decisions and detections across every protection section.</p>
      </div>
      <div class="waf-dashboard-command-bar security-events-command-bar" aria-label="Security dashboard controls">
        <div id="waf-dashboard-header-filters" class="security-events-header-filters"></div>
        <div class="operator-frame-actions security-events-header-actions">
          <div id="waf-dashboard-header-time" class="security-events-header-time"></div>
          <button id="waf-dashboard-refresh" type="button" class="btn btn-sm security-events-refresh-button" data-waf-dashboard-action="refresh" aria-label="Refresh Security Dashboard">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
          </button>
        </div>
      </div>
    </div>

    <div class="operator-frame-body waf-dashboard-body">
      <div id="waf-dashboard-banner" class="waf-dashboard-banner" hidden role="status"></div>

      <div class="operator-metric-strip waf-dashboard-metrics">
        <div class="operator-metric-item tone-primary is-filterable" role="button" tabindex="0" data-waf-dashboard-action="clear-filters" aria-label="Show all security events"><div class="operator-metric-label">Security events</div><div id="waf-dashboard-total" class="operator-metric-value">${renderMetricSkeleton()}</div><div id="waf-dashboard-total-note" class="operator-metric-sub">${renderMetricSubSkeleton()}</div></div>
        <div class="operator-metric-item tone-danger is-filterable"${dashboardFilterAttributes('action', 'block', 'blocked events')}><div class="operator-metric-label">Blocked</div><div id="waf-dashboard-blocked" class="operator-metric-value">${renderMetricSkeleton()}</div><div id="waf-dashboard-blocked-note" class="operator-metric-sub">${renderMetricSubSkeleton()}</div></div>
        <div class="operator-metric-item is-filterable"${dashboardFilterAttributes('action', 'detect', 'detected events')}><div class="operator-metric-label">Detected</div><div id="waf-dashboard-detected" class="operator-metric-value">${renderMetricSkeleton()}</div><div id="waf-dashboard-detected-note" class="operator-metric-sub">${renderMetricSubSkeleton()}</div></div>
        <div class="operator-metric-item is-filterable"${dashboardFilterAttributes('action', 'block', 'blocked events')}><div class="operator-metric-label">Block rate</div><div id="waf-dashboard-rate" class="operator-metric-value">${renderMetricSkeleton()}</div><div id="waf-dashboard-rate-note" class="operator-metric-sub">${renderMetricSubSkeleton()}</div></div>
        <div class="operator-metric-item is-filterable"${dashboardFilterAttributes('severity', 'high', 'critical or high severity events')}><div class="operator-metric-label">Critical / high</div><div id="waf-dashboard-critical" class="operator-metric-value">${renderMetricSkeleton()}</div><div id="waf-dashboard-critical-note" class="operator-metric-sub">${renderMetricSubSkeleton()}</div></div>
      </div>

      <div class="waf-dashboard-primary-grid">
        <section class="operator-section waf-dashboard-panel waf-dashboard-panel--timeline">
          <div class="operator-section-head"><div><h3>Threat activity</h3></div></div>
          <div id="waf-dashboard-timeline" class="waf-dashboard-timeline-shell">${renderChartSkeleton(16)}</div>
        </section>
        <section class="operator-section waf-dashboard-panel waf-dashboard-panel--posture">
          <div class="operator-section-head"><div><h3>Protection sections</h3></div></div>
          <div id="waf-dashboard-protection-sections" class="waf-dashboard-protection-shell">${renderBreakdownSkeleton(6)}</div>
        </section>
      </div>

      <section class="operator-section waf-dashboard-section">
        <div class="operator-section-head"><div><h3>Protection analytics</h3><p>Each protection section has 16 source-specific analytics cards.</p></div></div>
        <div id="waf-dashboard-section-results">${renderProtectionCardsSkeleton(4)}</div>
      </section>

      <section class="operator-section waf-dashboard-section waf-dashboard-events-section">
        <div class="operator-section-head"><div><h3 id="waf-dashboard-events-title">Recent security events</h3></div></div>
        <div class="config-table-wrap security-events-routing-table-wrap">
          <table class="config-enterprise-table security-events-routing-table" aria-label="WAF security events">
            <thead>
              <tr>
                <th>Time</th>
                <th>Method</th>
                <th>Path</th>
                <th>Rule / Reason</th>
                <th>Decision</th>
                <th>Source</th>
                <th class="text-right">Score</th>
                <th class="text-right"><span class="sr-only">Details</span></th>
              </tr>
            </thead>
            <tbody id="waf-dashboard-events">${renderTableSkeleton(8, 6)}</tbody>
          </table>
        </div>
        <nav class="security-events-pagination" id="waf-dashboard-pagination" aria-label="Security event pagination"></nav>
      </section>
    </div>

    <div id="waf-dashboard-drawer" class="security-event-drawer hidden" role="dialog" aria-modal="true" aria-labelledby="waf-dashboard-drawer-title">
      <div class="security-event-inspector-panel security-event-drawer-panel">
        <div class="security-event-inspector-header">
          <div class="security-event-workbench-heading">
            <span class="security-event-workbench-kicker" id="waf-dashboard-drawer-kicker">Security event</span>
            <div class="security-event-workbench-title">
              <span id="waf-dashboard-drawer-method" class="security-event-method">GET</span>
              <h3 id="waf-dashboard-drawer-title">Event details</h3>
            </div>
            <p>
              <span id="waf-dashboard-drawer-section">Application Firewall</span>
              <span aria-hidden="true">·</span>
              <span id="waf-dashboard-drawer-time">—</span>
            </p>
          </div>
          <button type="button" class="btn btn-sm btn-outline security-event-inspector-close" data-waf-dashboard-action="close-drawer" aria-label="Close" title="Close">
            <span>Close</span>
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        <div id="waf-dashboard-drawer-body" class="security-event-inspector-body"></div>
      </div>
    </div>

    <div id="waf-statistics-modal" class="security-statistics-modal hidden" role="dialog" aria-modal="true" aria-labelledby="waf-statistics-modal-title">
      <div class="security-statistics-modal-panel">
        <div class="security-statistics-modal-head">
          <div>
            <h3 id="waf-statistics-modal-title">Details</h3>
          </div>
          <button type="button" class="btn btn-sm btn-outline security-statistics-modal-close" data-waf-dashboard-action="close-statistics-modal">Close</button>
        </div>
        <div id="waf-statistics-modal-body" class="security-statistics-modal-body"></div>
      </div>
    </div>
  </div>
`;
const PENDING_DASHBOARD_FILTERS_KEY = 'aegis.apisec.dashboard.pendingFilters';
function consumePendingDashboardFilters() {
    const raw = window.sessionStorage.getItem(PENDING_DASHBOARD_FILTERS_KEY);
    if (raw) {
        window.sessionStorage.removeItem(PENDING_DASHBOARD_FILTERS_KEY);
        try {
            const data = JSON.parse(raw);
            if (data.window) {
                selectedWindow = data.window;
            }
            if (data.filters && typeof data.filters === 'object') {
                wafDashboardFilters = {};
                Object.entries(data.filters).forEach(([k, v]) => {
                    const val = String(v || '').trim();
                    if (!val)
                        return;
                    wafDashboardFilters[k] = normalizeDashboardFilterValue(k, val);
                });
                wafEventsPage = 1;
            }
        }
        catch (err) {
            console.warn('Failed to parse pending dashboard filters:', err);
        }
    }
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const filterKeys = [
            'section', 'action', 'category', 'rule_id', 'rule_name', 'severity',
            'ip', 'country', 'path', 'host', 'matched_field', 'min_score', 'max_score',
            'user_agent', 'user_agent_family', 'method', 'status', 'status_class',
            'policy', 'ja3', 'ja4', 'asn', 'request_id'
        ];
        filterKeys.forEach(k => {
            const val = urlParams.get(k);
            if (val) {
                wafDashboardFilters[k] = normalizeDashboardFilterValue(k, val);
                wafEventsPage = 1;
            }
        });
    }
    catch {
        // Ignore query parsing errors
    }
}
export function initWAFDashboard() {
    consumePendingDashboardFilters();
    bindEvents();
    renderWAFHeaderTime();
    renderWAFHeaderFilters();
    void loadWAFDashboard();
}
export function disposeWAFDashboard() {
    requestVersion += 1;
    closeWAFDrawer();
    closeSecurityStatisticsModal();
}
