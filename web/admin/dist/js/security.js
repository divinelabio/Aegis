import { api, getErrorMessage, parseJsonSafe } from './api.js';
import * as AdminDOM from './core/dom.js';
import { notify } from './core/notify.js';
import { SectionUI } from './sections/ui-components.js';
import { renderSecurityAnalyticsSkeleton } from './dashboards/skeletons.js';
const actionOptions = ['block', 'challenge', 'log', 'allow', 'rate_limit', 'redirect'];
const typeOptions = [
    ['waf', 'WAF'],
    ['rate_limit', 'Rate Limit'],
    ['bot', 'Bot'],
    ['geo', 'Geo Block'],
    ['ip_access', 'IP Access'],
    ['api', 'API'],
    ['http_security', 'Application Security'],
    ['access', 'Access'],
    ['custom', 'Custom Code']
];
const defaultRuleType = 'waf';
const defaultFields = [
    { name: 'http.host', label: 'Host', section: 'waf', operators: ['eq', 'contains', 'starts_with', 'ends_with'], description: 'Request host', input_type: 'text', placeholder: 'example.com' },
    { name: 'http.request.uri.path', label: 'Path', section: 'waf', operators: ['contains', 'starts_with', 'eq'], description: 'Request path', input_type: 'text', placeholder: '/admin' },
    { name: 'http.request.method', label: 'Method', section: 'waf', operators: ['eq', 'in'], description: 'HTTP method', input_type: 'select', options: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], multi: true },
    { name: 'ip.src', label: 'Client IP', section: 'geo_ip', operators: ['eq', 'in'], description: 'Client IP', input_type: 'ip', placeholder: '203.0.113.10 or 203.0.113.0/24', multi: true },
    { name: 'ip.geoip.country', label: 'Country', section: 'geo_ip', operators: ['eq', 'in'], description: 'Country code', input_type: 'country', placeholder: 'US', multi: true },
    { name: 'ip.asn', label: 'ASN', section: 'geo_ip', operators: ['eq', 'in', 'ne'], description: 'Autonomous system number', input_type: 'text', placeholder: 'AS13335', multi: true },
    { name: 'ip.reputation.score', label: 'IP Reputation', section: 'bot', operators: ['lt', 'gt', 'eq', 'ge', 'le'], description: 'IP reputation score', input_type: 'number', placeholder: '50' },
    { name: 'http.user_agent', label: 'User Agent', section: 'bot', operators: ['contains', 'eq', 'matches'], description: 'User-Agent header', input_type: 'text', placeholder: 'HeadlessChrome' },
    { name: 'http.request.headers["content-type"]', label: 'Header: Content-Type', section: 'http_security', operators: ['eq', 'contains', 'matches'], description: 'HTTP request header value', input_type: 'text', placeholder: 'application/json' },
    { name: 'http.cookie["session"]', label: 'Cookie: session', section: 'bot', operators: ['eq', 'contains', 'matches'], description: 'HTTP cookie value', input_type: 'text', placeholder: 'session-value' },
    { name: 'http.request.query["q"]', label: 'Query: q', section: 'bot', operators: ['eq', 'contains', 'matches'], description: 'HTTP query parameter value', input_type: 'text', placeholder: 'needle' },
    { name: 'aegis.bot.score', label: 'Bot Score', section: 'bot', operators: ['lt', 'gt', 'eq'], description: 'Bot score', input_type: 'number', placeholder: '30' },
    { name: 'aegis.bot.category', label: 'Bot Category', section: 'bot', operators: ['eq', 'contains', 'in'], description: 'Bot classification category', input_type: 'text', placeholder: 'suspicious' },
    { name: 'aegis.bot.verified', label: 'Verified Bot', section: 'bot', operators: ['eq', 'ne'], description: 'Verified bot identity', input_type: 'boolean', options: ['true', 'false'], placeholder: 'false' },
    { name: 'aegis.bot.headless', label: 'Headless Browser', section: 'bot', operators: ['eq', 'ne'], description: 'Headless browser signal', input_type: 'boolean', options: ['true', 'false'], placeholder: 'true' },
    { name: 'aegis.waf.score', label: 'WAF Score', section: 'waf', operators: ['lt', 'gt', 'eq', 'ge', 'le'], description: 'WAF risk score', input_type: 'number', placeholder: '50' },
    { name: 'tls.ja3', label: 'JA3', section: 'bot', operators: ['eq', 'contains'], description: 'JA3 TLS fingerprint', input_type: 'text', placeholder: 'e7d705a3286e19ea42f587b344ee6865' },
    { name: 'tls.ja4', label: 'JA4', section: 'bot', operators: ['eq', 'contains'], description: 'JA4 TLS fingerprint', input_type: 'text', placeholder: 't13d1516h2_8daaf6152771_b0da82dd1658' },
    { name: 'api.path', label: 'API Path', section: 'api', operators: ['starts_with', 'contains', 'eq'], description: 'API path', input_type: 'text', placeholder: '/api/' },
    { name: 'api.auth.valid', label: 'API Auth Valid', section: 'api', operators: ['eq', 'ne'], description: 'API authentication validity', input_type: 'boolean', options: ['true', 'false'], placeholder: 'false' },
    { name: 'tls.version', label: 'TLS Version', section: 'http_security', operators: ['eq', 'in'], description: 'TLS version', input_type: 'select', options: ['TLS1.0', 'TLS1.1', 'TLS1.2', 'TLS1.3'], multi: true },
    { name: 'access.identity.role', label: 'Access Role', section: 'access', operators: ['eq', 'in'], description: 'Access role', input_type: 'text', placeholder: 'guest' }
];
let cachedFields = defaultFields;
let builderMode = 'visual';
let activeEditorOptions = {};
let securityAnalyticsController = null;
let securityAnalyticsRequestId = 0;
let securityAnalyticsEvents = [];
let securityAnalyticsBound = false;
let securityAnalyticsCustomSince = '';
let securityAnalyticsCustomUntil = '';
let securityDrawerReturnFocus = null;
let securityEventsPage = 1;
let securityEventsCursors = [''];
let securityEventsNextCursor = '';
let securityEventsPageRequest = null;
let securityEventsTotal = 0;
const analyticsRequestTimeoutMs = 20000;
const defaultSecurityAnalyticsLimit = '20';
const countryOptions = [
    ['US', 'United States'], ['TN', 'Tunisia'], ['CA', 'Canada'], ['GB', 'United Kingdom'], ['FR', 'France'], ['DE', 'Germany'], ['IT', 'Italy'], ['ES', 'Spain'], ['NL', 'Netherlands'], ['BE', 'Belgium'],
    ['PT', 'Portugal'], ['IE', 'Ireland'], ['SE', 'Sweden'], ['NO', 'Norway'], ['DK', 'Denmark'], ['FI', 'Finland'], ['PL', 'Poland'], ['CZ', 'Czechia'], ['AT', 'Austria'], ['CH', 'Switzerland'],
    ['TR', 'Turkey'], ['MA', 'Morocco'], ['DZ', 'Algeria'], ['EG', 'Egypt'], ['ZA', 'South Africa'], ['NG', 'Nigeria'], ['AE', 'United Arab Emirates'], ['SA', 'Saudi Arabia'], ['IL', 'Israel'], ['IN', 'India'],
    ['PK', 'Pakistan'], ['BD', 'Bangladesh'], ['CN', 'China'], ['JP', 'Japan'], ['KR', 'South Korea'], ['SG', 'Singapore'], ['ID', 'Indonesia'], ['MY', 'Malaysia'], ['PH', 'Philippines'], ['VN', 'Vietnam'],
    ['TH', 'Thailand'], ['AU', 'Australia'], ['NZ', 'New Zealand'], ['BR', 'Brazil'], ['AR', 'Argentina'], ['CL', 'Chile'], ['CO', 'Colombia'], ['MX', 'Mexico'], ['RU', 'Russia'], ['UA', 'Ukraine']
];
export const securityAnalyticsView = `
  <div class="operator-frame security-events-frame">
    <div class="operator-frame-header security-events-page-header">
      <div class="operator-frame-title-block">
        <div class="operator-frame-kicker">THREAT OPERATIONS & SOC</div>
        <h2 class="operator-frame-title">Security Events & Telemetry</h2>
        <p class="operator-frame-subtitle">Cross-section attack logs, forensic traces, request inspection, client fingerprints, and mitigation telemetry.</p>
      </div>
      <div class="security-events-command-bar" aria-label="Traffic Events controls">
        <div id="security-events-header-filters" class="security-events-header-filters"></div>
        <div class="operator-frame-actions security-events-header-actions">
          <div id="security-events-header-time" class="security-events-header-time"></div>
          <button type="button" class="btn btn-sm security-events-refresh-button" data-action="refresh-security-analytics" aria-label="Refresh traffic events">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M20 11a8 8 0 1 0 2 5.3"/>
              <path d="M20 4v7h-7"/>
            </svg>
          </button>
        </div>
      </div>
    </div>
    <div class="operator-frame-body security-events-body">
    <div class="hidden" aria-hidden="true">
      <select id="analytics-window-filter"><option value="custom"></option><option value="1h"></option><option value="24h" selected></option><option value="7d"></option><option value="30d"></option></select>
      <select id="analytics-status-class-filter"><option value=""></option><option value="2xx"></option><option value="3xx"></option><option value="4xx"></option><option value="5xx"></option></select>
      <select id="analytics-method-filter"><option value=""></option><option value="GET"></option><option value="POST"></option><option value="PUT"></option><option value="PATCH"></option><option value="DELETE"></option><option value="HEAD"></option><option value="OPTIONS"></option></select>
      <select id="analytics-limit-filter"><option value="20" selected></option><option value="50"></option><option value="100"></option><option value="200"></option></select>
      <input id="analytics-country-filter">
      <input id="analytics-ip-filter">
      <input id="analytics-path-filter">
      <input id="analytics-host-filter">
      <input id="analytics-route-filter">
      <input id="analytics-upstream-filter">
      <input id="analytics-request-id-filter">
      <input id="analytics-user-agent-filter">
      <input id="analytics-ja3-filter">
      <input id="analytics-ja4-filter">
      <input id="analytics-asn-filter">
      <input id="analytics-http-version-filter">
      <input id="analytics-tls-version-filter">
      <input id="analytics-ip-version-filter">
      <input id="analytics-content-type-filter">
      <input id="analytics-status-filter">
    </div>
    <div id="security-analytics-content">${renderSecurityAnalyticsSkeleton()}</div>
    </div>
    <div id="security-event-explorer-drawer" class="security-event-drawer hidden" role="dialog" aria-modal="true" aria-hidden="true" aria-labelledby="security-event-explorer-drawer-title">
      <div class="security-event-inspector-panel security-event-drawer-panel">
        <div class="security-event-inspector-header">
          <div class="security-event-workbench-heading">
            <span class="security-event-workbench-kicker">Traffic event</span>
            <div class="security-event-workbench-title">
              <span id="security-event-explorer-drawer-method" class="security-event-method">GET</span>
              <h3 id="security-event-explorer-drawer-title">Event details</h3>
            </div>
            <p>
              <span id="security-event-explorer-drawer-section">Request</span>
              <span aria-hidden="true">·</span>
              <span id="security-event-explorer-drawer-time">—</span>
            </p>
          </div>
          <button type="button" class="btn btn-sm btn-outline security-event-inspector-close" data-security-analytics-action="close-drawer" aria-label="Close" title="Close">
            <span>Close</span>
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        <div id="security-event-explorer-drawer-body" class="security-event-inspector-body"></div>
      </div>
    </div>
    <div id="security-statistics-modal" class="security-statistics-modal hidden" role="dialog" aria-modal="true" aria-labelledby="security-statistics-modal-title">
      <div class="security-statistics-modal-panel">
        <div class="security-statistics-modal-head">
          <div>
            <h3 id="security-statistics-modal-title">Details</h3>
          </div>
          <button type="button" class="btn btn-sm btn-outline security-statistics-modal-close" data-security-analytics-action="close-statistics-modal">Close</button>
        </div>
        <div id="security-statistics-modal-body" class="security-statistics-modal-body"></div>
      </div>
    </div>
  </div>
`;
export function featurePageView(title, subtitle, endpoint) {
    return `
    <div class="view">
      <div class="panel-row">
        <div>
          <h2 class="section-title">${title}</h2>
          <p class="section-subtitle">${subtitle}</p>
        </div>
      </div>
      <div class="card">
        <div class="card-body">
          <p class="text-muted mb-16">This feature is managed by its dedicated configuration section.</p>
          <button type="button" class="btn btn-outline" data-nav-target="${endpoint}">Open Configuration</button>
        </div>
      </div>
    </div>
  `;
}
export async function initSecurityAnalytics() {
    const container = AdminDOM.getById('security-analytics-content');
    if (!container)
        return;
    securityEventsPage = 1;
    securityEventsCursors = [''];
    securityEventsNextCursor = '';
    securityEventsTotal = 0;
    securityEventsPageRequest?.abort();
    bindSecurityAnalyticsInteractions();
    ensureSecurityEventDrawerMounted();
    const requestId = ++securityAnalyticsRequestId;
    securityAnalyticsController?.abort();
    securityAnalyticsController = new AbortController();
    closeSecurityEventExplorerDrawer();
    const refreshButton = AdminDOM.query('[data-action="refresh-security-analytics"]');
    if (refreshButton) {
        refreshButton.disabled = true;
        refreshButton.setAttribute('aria-busy', 'true');
    }
    const hasExistingContent = container.children.length > 0 && !container.querySelector('.loading-block') && !container.querySelector('.skeleton');
    if (!hasExistingContent) {
        container.innerHTML = renderSecurityAnalyticsSkeleton();
    }
    else {
        container.classList.add('is-loading');
    }
    const filters = readSecurityAnalyticsFilters();
    setSecurityEventsHeaderControls(filters, renderActiveFilterChips(filters));
    const params = buildSecurityAnalyticsParams(filters);
    try {
        const model = await loadSecurityAnalytics(params, securityAnalyticsController.signal, filters);
        if (requestId !== securityAnalyticsRequestId)
            return;
        securityAnalyticsEvents = model.events;
        securityEventsNextCursor = model.nextCursor || '';
        securityEventsTotal = model.summary.total ?? model.events.length;
        container.innerHTML = renderSecurityAnalytics(model);
        setSecurityEventsHeaderControls(model.filters, renderActiveFilterChips(model.filters));
    }
    catch (error) {
        if (requestId !== securityAnalyticsRequestId)
            return;
        console.warn('Traffic analytics are unavailable:', error);
        const model = createEmptySecurityAnalyticsModel(filters, ['Traffic analytics are currently unavailable.']);
        securityAnalyticsEvents = model.events;
        securityEventsNextCursor = model.nextCursor || '';
        securityEventsTotal = model.summary.total ?? model.events.length;
        container.innerHTML = renderSecurityAnalytics(model);
        setSecurityEventsHeaderControls(model.filters, renderActiveFilterChips(model.filters));
    }
    finally {
        if (requestId === securityAnalyticsRequestId) {
            container.classList.remove('is-loading');
            if (refreshButton) {
                refreshButton.disabled = false;
                refreshButton.setAttribute('aria-busy', 'false');
            }
        }
    }
}
function readSecurityAnalyticsFilters() {
    return {
        window: AdminDOM.selectValue('analytics-window-filter', '24h'),
        statusClass: AdminDOM.selectValue('analytics-status-class-filter', ''),
        method: AdminDOM.selectValue('analytics-method-filter', ''),
        country: AdminDOM.inputValue('analytics-country-filter', '').toUpperCase(),
        ip: AdminDOM.inputValue('analytics-ip-filter', ''),
        path: AdminDOM.inputValue('analytics-path-filter', ''),
        host: AdminDOM.inputValue('analytics-host-filter', ''),
        route: AdminDOM.inputValue('analytics-route-filter', ''),
        upstream: AdminDOM.inputValue('analytics-upstream-filter', ''),
        requestId: AdminDOM.inputValue('analytics-request-id-filter', ''),
        userAgent: AdminDOM.inputValue('analytics-user-agent-filter', ''),
        ja3: AdminDOM.inputValue('analytics-ja3-filter', ''),
        ja4: AdminDOM.inputValue('analytics-ja4-filter', ''),
        asn: AdminDOM.inputValue('analytics-asn-filter', ''),
        httpVersion: AdminDOM.inputValue('analytics-http-version-filter', ''),
        tlsVersion: AdminDOM.inputValue('analytics-tls-version-filter', ''),
        ipVersion: AdminDOM.inputValue('analytics-ip-version-filter', ''),
        contentType: AdminDOM.inputValue('analytics-content-type-filter', ''),
        statusCode: AdminDOM.inputValue('analytics-status-filter', ''),
        limit: AdminDOM.selectValue('analytics-limit-filter', defaultSecurityAnalyticsLimit)
    };
}
function buildSecurityAnalyticsParams(filters) {
    const params = new URLSearchParams({
        window: filters.window === 'custom' ? '24h' : (filters.window || '24h'),
        interval: 'auto',
        limit: filters.limit || defaultSecurityAnalyticsLimit
    });
    const since = analyticsSince(filters.window);
    if (filters.statusClass)
        params.set('status_class', filters.statusClass);
    if (filters.method)
        params.set('method', filters.method);
    if (filters.country)
        params.set('country', filters.country.toUpperCase());
    if (filters.ip)
        params.set('ip', filters.ip);
    if (filters.path)
        params.set('path', filters.path);
    if (filters.host)
        params.set('host', filters.host);
    if (filters.route)
        params.set('route', filters.route);
    if (filters.upstream)
        params.set('upstream', filters.upstream);
    if (filters.requestId)
        params.set('request_id', filters.requestId);
    if (filters.userAgent)
        params.set('user_agent', filters.userAgent);
    if (filters.ja3)
        params.set('ja3', filters.ja3);
    if (filters.ja4)
        params.set('ja4', filters.ja4);
    if (filters.asn)
        params.set('asn', filters.asn);
    if (filters.httpVersion)
        params.set('http_version', filters.httpVersion);
    if (filters.tlsVersion)
        params.set('tls_version', filters.tlsVersion);
    if (filters.ipVersion)
        params.set('ip_version', filters.ipVersion);
    if (filters.contentType)
        params.set('content_type', filters.contentType);
    if (filters.statusCode)
        params.set('status', filters.statusCode);
    if (securityAnalyticsCustomSince) {
        params.set('since', securityAnalyticsCustomSince);
    }
    else if (since) {
        params.set('since', since.toISOString());
    }
    if (securityAnalyticsCustomUntil)
        params.set('until', securityAnalyticsCustomUntil);
    return params;
}
function analyticsSince(windowValue) {
    const hours = { '1h': 1, '24h': 24, '7d': 24 * 7, '30d': 24 * 30 };
    const amount = hours[windowValue] || hours['24h'];
    return new Date(Date.now() - amount * 60 * 60 * 1000);
}
async function loadSecurityAnalytics(params, signal, filters) {
    const response = await analyticsGet(`traffic-events/dashboard?${params.toString()}`, signal);
    const dashboard = response.dashboard;
    if (!dashboard)
        throw new Error('Traffic analytics are currently unavailable.');
    if (dashboard.health?.db_available === false) {
        const rawMsg = dashboard.health.message || '';
        const warnings = (rawMsg && !rawMsg.includes('ClickHouse analytics database is not available')) ? [rawMsg] : [];
        return createEmptySecurityAnalyticsModel(filters, warnings);
    }
    const sourceSummary = dashboard.summary || {};
    const summary = {
        total: Number(sourceSummary.total_requests || 0),
        avg_latency_ms: Number(sourceSummary.avg_latency_ms || 0),
        p95_latency_ms: Number(sourceSummary.p95_latency_ms || 0),
        unique_source_ips: Number(sourceSummary.unique_source_ips || 0),
        unique_countries: Number(sourceSummary.unique_countries || 0),
        total_bytes_sent: Number(sourceSummary.total_bytes_sent || 0),
        current_rps: Number(sourceSummary.current_rps || 0),
        status_2xx: Number(sourceSummary.status_2xx || 0),
        status_3xx: Number(sourceSummary.status_3xx || 0),
        status_4xx: Number(sourceSummary.status_4xx || 0),
        status_5xx: Number(sourceSummary.status_5xx || 0)
    };
    const timeline = (dashboard.timeseries || []).map(point => ({
        bucket: point.timestamp ? new Date(point.timestamp * 1000).toISOString() : '',
        counts: point.counts || {}
    }));
    const actionMix = responseClassItems(summary);
    const events = (dashboard.events?.events || []).map(normalizeTrafficEvent);
    return {
        summary,
        events,
        timeline,
        actionMix,
        breakdowns: dashboard.breakdowns || {},
        warnings: dashboard.warnings || [],
        loadedAt: new Date(),
        filters,
        nextCursor: String(dashboard.events?.next_cursor || '')
    };
}
function normalizeTrafficEvent(item) {
    const seconds = Number(item.timestamp || 0);
    const metadata = item.metadata && typeof item.metadata === 'object' ? item.metadata : {};
    return {
        id: String(item.id || item.request_id || `${seconds}-${String(item.client_ip || '')}-${String(item.path || '')}`),
        timestamp: seconds > 0 ? new Date(seconds * 1000).toISOString() : '',
        action: String(item.action || 'served'),
        client_ip: String(item.client_ip || ''),
        country: String(item.country || ''),
        host: String(item.host || metadata.host || ''),
        path: String(item.path || ''),
        method: String(item.method || ''),
        user_agent: String(item.user_agent || ''),
        response_code: Number(item.status_code || 0),
        latency_ms: Number(item.latency_ms || 0),
        request_id: String(item.request_id || ''),
        upstream: String(item.upstream || metadata.upstream || ''),
        route_name: String(item.route_name || metadata.route_name || ''),
        bytes_sent: Number(item.bytes_sent || metadata.bytes_sent || 0),
        asn: String(item.asn || metadata.asn || ''),
        asn_org: String(item.asn_org || metadata.asn_org || ''),
        ja3: String(item.ja3 || metadata.ja3 || metadata.tls_ja3 || ''),
        ja4: String(item.ja4 || metadata.ja4 || metadata.tls_ja4 || ''),
        http_version: String(item.http_version || metadata.http_version || ''),
        tls_version: String(item.tls_version || metadata.tls_version || ''),
        ip_version: String(item.ip_version || metadata.ip_version || ''),
        response_content_type: String(item.response_content_type || metadata.response_content_type || ''),
        metadata
    };
}
async function analyticsGet(endpoint, parentSignal) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), analyticsRequestTimeoutMs);
    const abort = () => controller.abort();
    parentSignal.addEventListener('abort', abort, { once: true });
    try {
        const response = await fetch(`/api/${endpoint}`, {
            headers: { Accept: 'application/json' },
            signal: controller.signal
        });
        if (!response.ok) {
            const body = await parseJsonSafe(response, {});
            throw new Error(body.message || `Request failed: ${response.status}`);
        }
        return await parseJsonSafe(response, {});
    }
    finally {
        window.clearTimeout(timeout);
        parentSignal.removeEventListener('abort', abort);
    }
}
function eventMatchesSecurityFilters(event, filters) {
    if (filters.statusClass) {
        const code = Number(event.response_code || 0);
        const sc = filters.statusClass.toLowerCase();
        if (sc === '2xx' && (code < 200 || code >= 300))
            return false;
        if (sc === '3xx' && (code < 300 || code >= 400))
            return false;
        if (sc === '4xx' && (code < 400 || code >= 500))
            return false;
        if (sc === '5xx' && (code < 500 || code >= 600))
            return false;
    }
    if (filters.method && event.method?.toUpperCase() !== filters.method.toUpperCase())
        return false;
    if (filters.country && event.country?.toUpperCase() !== filters.country.toUpperCase())
        return false;
    if (filters.ip && event.client_ip !== filters.ip)
        return false;
    if (filters.path) {
        const fp = filters.path.toLowerCase();
        const ep = (event.path || '').toLowerCase();
        if (!ep.includes(fp) && !fp.includes(ep))
            return false;
    }
    if (filters.host) {
        const fh = filters.host.toLowerCase();
        const eh = (event.host || '').toLowerCase();
        if (!eh.includes(fh) && !fh.includes(eh))
            return false;
    }
    if (filters.route) {
        const fr = filters.route.toLowerCase();
        const er = (event.route_name || '').toLowerCase();
        if (!er.includes(fr) && !fr.includes(er))
            return false;
    }
    if (filters.upstream) {
        const fu = filters.upstream.toLowerCase();
        const eu = (event.upstream || '').toLowerCase();
        if (!eu.includes(fu) && !fu.includes(eu))
            return false;
    }
    if (filters.requestId && event.request_id !== filters.requestId)
        return false;
    if (filters.userAgent) {
        const fu = filters.userAgent.toLowerCase();
        const eu = (event.user_agent || '').toLowerCase();
        if (!eu.includes(fu) && !fu.includes(eu))
            return false;
    }
    if (filters.asn) {
        const fa = filters.asn.toLowerCase();
        const ea = ((event.asn || '') + ' ' + (event.asn_org || '')).toLowerCase();
        if (!ea.includes(fa) && !fa.includes((event.asn || '').toLowerCase()))
            return false;
    }
    if (filters.statusCode && String(event.response_code) !== String(filters.statusCode))
        return false;
    if (filters.httpVersion && (event.http_version || '').toLowerCase() !== filters.httpVersion.toLowerCase())
        return false;
    if (filters.tlsVersion && (event.tls_version || '').toLowerCase() !== filters.tlsVersion.toLowerCase())
        return false;
    if (filters.ipVersion && (event.ip_version || '').toLowerCase() !== filters.ipVersion.toLowerCase())
        return false;
    if (filters.contentType) {
        const fc = filters.contentType.toLowerCase();
        const ec = (event.response_content_type || '').toLowerCase();
        if (!ec.includes(fc) && !fc.includes(ec))
            return false;
    }
    if (filters.ja3 && event.ja3 !== filters.ja3)
        return false;
    if (filters.ja4 && event.ja4 !== filters.ja4)
        return false;
    return true;
}
function createEmptySecurityAnalyticsModel(filters, warnings = ['Traffic telemetry is currently unavailable.']) {
    const emptySummary = {
        total: 0,
        status_2xx: 0,
        status_3xx: 0,
        status_4xx: 0,
        status_5xx: 0,
        avg_latency_ms: 0,
        p95_latency_ms: 0,
        unique_source_ips: 0,
        unique_countries: 0,
        total_bytes_sent: 0,
        current_rps: 0
    };
    return {
        events: [],
        summary: emptySummary,
        timeline: [],
        actionMix: responseClassItems(emptySummary),
        breakdowns: {
            ips: [],
            hosts: [],
            routes: [],
            upstreams: [],
            paths: [],
            methods: [],
            http_versions: [],
            status: [],
            content_types: [],
            user_agents: [],
            countries: [],
            ip_versions: [],
            ja3: [],
            ja4: [],
            tls_versions: [],
            asn: []
        },
        warnings,
        loadedAt: new Date(),
        filters
    };
}
function renderSecurityAnalytics(model) {
    const total = model.summary.total ?? model.events.length;
    const hasData = total > 0 || model.events.length > 0;
    const statisticsCards = renderSecurityStatisticsCards(model);
    const warningSummary = model.warnings.length ? model.warnings.slice(0, 2).join(' / ') : '';
    const timelinePoints = securityTimelineSeries(model);
    return `
    <div class="security-analytics-shell security-events-explorer security-events-operator-explorer">
      ${renderSecurityMetricStrip(model.summary)}
      ${renderSecurityAnalyticsNotice(warningSummary, 'Telemetry status')}
      ${hasData ? '' : renderSecurityTrafficEmptyNotice()}
      <div class="security-events-analysis-grid">
        <section class="operator-section system-health-section security-events-timeline-panel">
          <div class="operator-section-head">
            <div>
              <h3>Traffic overview</h3>
            </div>
          </div>
          ${renderSecurityTrafficCard(timelinePoints)}
        </section>
        ${renderSecurityActionMixChartCard(model)}
      </div>
        ${statisticsCards}
      <section class="operator-section waf-dashboard-section waf-dashboard-events-section">
        <div class="operator-section-head">
          <div>
            <h3>Request events</h3>
          </div>
        </div>
        <div id="security-events-table-region">
          ${renderSecurityEventsTableContent(model.events, model.summary.total ?? model.events.length, model.filters.limit)}
        </div>
      </section>
    </div>
  `;
}
function renderSecurityEventsTableContent(events, total, pageSize) {
    const size = securityEventsPageSize(pageSize);
    const start = events.length ? ((securityEventsPage - 1) * size) + 1 : 0;
    const end = events.length ? start + events.length - 1 : 0;
    const nextDisabled = securityEventsNextCursor ? '' : ' disabled';
    const previousDisabled = securityEventsPage === 1 ? ' disabled' : '';
    return `
    <div class="config-table-wrap security-events-routing-table-wrap">
      <table class="config-enterprise-table security-events-routing-table" aria-label="Traffic request events">
        <thead>
          <tr>
            <th>Time</th>
            <th>Method</th>
            <th>Path</th>
            <th>Host</th>
            <th>Status</th>
            <th>Source</th>
            <th class="text-right"><span class="sr-only">Details</span></th>
          </tr>
        </thead>
        <tbody>
          ${renderEventExplorerRows(events)}
        </tbody>
      </table>
    </div>

    <nav class="security-events-pagination" aria-label="Traffic event pages">
      <span class="security-events-pagination-summary">${start ? `Showing ${start}–${end}` : 'No events'}${total ? ` of ${formatCompact(total)}` : ''}</span>
      <span class="security-events-pagination-controls">
        <button type="button" class="btn btn-sm btn-outline" data-security-analytics-action="previous-events-page"${previousDisabled}>
          Previous
        </button>
        <span class="security-events-pagination-page">Page ${securityEventsPage}</span>
        <button type="button" class="btn btn-sm btn-outline" data-security-analytics-action="next-events-page"${nextDisabled}>
          Next
        </button>
        <label class="security-events-page-size-label">Rows per page
          <select id="security-events-page-size" class="security-events-page-size" aria-label="Rows per page">
            ${[20, 50, 100, 200].map(value => `<option value="${value}"${size === value ? ' selected' : ''}>${value}</option>`).join('')}
          </select>
        </label>
      </span>
    </nav>
  `;
}
function securityEventsPageSize(value) {
    const pageSize = Number(value);
    return [20, 50, 100, 200].includes(pageSize) ? pageSize : 20;
}
async function changeSecurityEventsPage(direction) {
    const previousPage = securityEventsPage;
    const targetPage = direction === 'next' ? previousPage + 1 : previousPage - 1;
    if (targetPage < 1 || (direction === 'next' && !securityEventsNextCursor))
        return;
    const cursor = direction === 'next'
        ? securityEventsNextCursor
        : (securityEventsCursors[targetPage - 1] || '');
    const region = AdminDOM.getById('security-events-table-region');
    if (!region)
        return;
    securityEventsPageRequest?.abort();
    const controller = new AbortController();
    securityEventsPageRequest = controller;
    region.classList.add('is-loading');
    try {
        const filters = readSecurityAnalyticsFilters();
        const params = buildSecurityAnalyticsParams(filters);
        if (cursor)
            params.set('cursor', cursor);
        const response = await analyticsGet(`traffic-events/events?${params.toString()}`, controller.signal);
        if (controller.signal.aborted)
            return;
        securityEventsPage = targetPage;
        securityEventsCursors[targetPage - 1] = cursor;
        securityEventsNextCursor = String(response.next_cursor || '');
        securityAnalyticsEvents = (response.events || []).map(normalizeTrafficEvent);
        region.innerHTML = renderSecurityEventsTableContent(securityAnalyticsEvents, securityEventsTotal, filters.limit);
    }
    catch (error) {
        if (!controller.signal.aborted) {
            notify(getErrorMessage(error, 'Failed to load traffic events'), 'error');
            region.innerHTML = renderSecurityEventsTableContent(securityAnalyticsEvents, securityEventsTotal, readSecurityAnalyticsFilters().limit);
        }
    }
    finally {
        if (securityEventsPageRequest === controller) {
            securityEventsPageRequest = null;
            region.classList.remove('is-loading');
        }
    }
}
function renderSecurityTrafficEmptyNotice() {
    return `
    <div class="security-events-notice" role="status">
      <strong>No traffic data available for the selected time range.</strong>
    </div>
  `;
}
function renderSecurityMetricStrip(summary) {
    const total = Number(summary.total || 0);
    const serverErrors = Number(summary.status_5xx || 0);
    return `
    <div class="operator-metric-strip security-events-metric-strip">
      ${securityMetricItem('Requests', formatCompact(total), 'In the selected range', 'primary')}
      ${securityMetricItem('Request rate', `${formatDecimal(summary.current_rps || 0)} rps`, 'Current one-minute rate')}
      ${securityMetricItem('Unique source IPs', formatCompact(summary.unique_source_ips || 0), `${formatCompact(summary.unique_countries || 0)} countries`)}
      ${securityMetricItem('Bandwidth', formatTrafficBytes(summary.total_bytes_sent || 0), 'Response bytes sent')}
      ${securityMetricItem('P95 latency', `${formatDecimal(summary.p95_latency_ms || 0)} ms`, `Average ${formatDecimal(summary.avg_latency_ms || 0)} ms`, 'info')}
      ${securityMetricItem('5xx rate', formatPercent(total ? (serverErrors / total) * 100 : 0), `${formatCompact(serverErrors)} server errors`, serverErrors ? 'danger' : '')}
    </div>
  `;
}
function securityMetricItem(label, value, sub, tone = '') {
    return `
    <div class="operator-metric-item ${tone ? `tone-${tone}` : ''}">
      <div class="operator-metric-label">${escapeHtml(label)}</div>
      <div class="operator-metric-value">${escapeHtml(value)}</div>
      ${sub ? `<div class="operator-metric-sub">${escapeHtml(sub)}</div>` : ''}
    </div>
  `;
}
function securityEventsTimeRangeLabel(filters) {
    const since = securityAnalyticsCustomSince ? formatBucket(securityAnalyticsCustomSince) : '';
    const until = securityAnalyticsCustomUntil ? formatBucket(securityAnalyticsCustomUntil) : '';
    if (since && until)
        return `${since} to ${until}`;
    if (since)
        return `Since ${since}`;
    if (until)
        return `Until ${until}`;
    const presetLabels = {
        '15m': 'Last 15 minutes',
        '1h': 'Last hour',
        '24h': 'Last 24 hours',
        '7d': 'Last 7 days',
        '30d': 'Last 30 days',
        custom: 'Custom range'
    };
    return presetLabels[filters.window] || labelForOption('analytics-window-filter', filters.window) || 'Last 24 hours';
}
function activeSecurityTimePreset(filters) {
    return securityAnalyticsCustomSince || securityAnalyticsCustomUntil ? '' : filters.window || '24h';
}
function isoToLocalDateTimeInput(value) {
    if (!value)
        return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime()))
        return '';
    const offsetMs = date.getTimezoneOffset() * 60 * 1000;
    return new Date(date.getTime() - offsetMs).toISOString().slice(0, 16);
}
function localDateTimeInputToIso(value) {
    if (!value)
        return '';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '' : date.toISOString();
}
function durationToMilliseconds(amount, unit) {
    const safeAmount = Math.max(1, Math.min(999, Math.floor(amount || 1)));
    const unitMs = {
        minutes: 60 * 1000,
        hours: 60 * 60 * 1000,
        days: 24 * 60 * 60 * 1000,
        weeks: 7 * 24 * 60 * 60 * 1000
    };
    return safeAmount * (unitMs[unit] || unitMs.hours);
}
function setSecurityAnalyticsTimeRange(sinceIso, untilIso = '') {
    securityAnalyticsCustomSince = sinceIso;
    securityAnalyticsCustomUntil = untilIso;
    setSelectValue('analytics-window-filter', 'custom');
    closeSecurityEventExplorerDrawer();
}
function setSecurityEventsHeaderControls(filters, activeFilterChips) {
    const filterTarget = AdminDOM.getById('security-events-header-filters');
    const timeTarget = AdminDOM.getById('security-events-header-time');
    if (filterTarget)
        filterTarget.innerHTML = renderSecurityHeaderFilters(filters, activeFilterChips);
    if (timeTarget)
        timeTarget.innerHTML = renderSecurityHeaderTime(filters);
}
function renderSecurityHeaderFilters(filters, activeFilterChips) {
    const activeFilterCount = countSecurityAnalyticsFilters(filters);
    return `
    <div class="security-events-filter-left" aria-label="Traffic event filters">
      <div class="security-events-filter-menu">
        <button type="button" id="security-filter-trigger" class="security-filter-add-button" data-security-analytics-action="toggle-filter-menu" aria-haspopup="true" aria-expanded="false" aria-controls="security-filter-popover">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/></svg>
          <span>Add filter</span>
        </button>
        <div id="security-filter-popover" class="security-filter-builder-popover hidden">
          <div class="security-filter-builder-title">Add Filter</div>
          <div class="security-filter-builder-row">
            <select id="security-filter-field" class="security-filter-field-select" aria-label="Filter by">
              <option value="path" selected>Path</option>
              <option value="host">Host</option>
              <option value="route">Route</option>
              <option value="upstream">Upstream</option>
              <option value="requestId">Request ID</option>
              <option value="ip">IP address</option>
              <option value="method">Method</option>
              <option value="country">Country</option>
              <option value="userAgent">User agent</option>
              <option value="ja3">JA3 fingerprint</option>
              <option value="ja4">JA4 fingerprint</option>
              <option value="asn">ASN</option>
              <option value="httpVersion">HTTP version</option>
              <option value="tlsVersion">TLS version</option>
              <option value="ipVersion">IP version</option>
              <option value="contentType">Response content type</option>
              <option value="statusCode">Status code</option>
              <option value="statusClass">Status class</option>
            </select>
            <select id="security-filter-operator" class="security-filter-operator-select" aria-label="Operator">
              <option value="equals">equals</option>
              <option value="in">is in</option>
              <option value="contains">contains</option>
              <option value="starts_with">starts with</option>
              <option value="ends_with">ends with</option>
              <option value="greater_equal">is greater than or equal to</option>
              <option value="less_equal">is less than or equal to</option>
            </select>
            <input id="security-filter-value" class="security-filter-builder-value" placeholder="/admin" aria-label="Filter value">
          </div>
          <div class="security-filter-builder-actions">
            <button type="button" class="btn btn-sm btn-outline" data-security-analytics-action="cancel-filter-builder">Cancel</button>
            <button type="button" class="btn btn-sm" data-security-analytics-action="apply-filter-builder">Apply</button>
          </div>
        </div>
      </div>
      ${activeFilterChips || ''}
      ${activeFilterCount > 0 ? '<button type="button" class="security-filter-clear-button" data-security-analytics-action="clear-filters">Clear all</button>' : ''}
    </div>
  `;
}
function renderSecurityHeaderTime(filters) {
    const activePreset = activeSecurityTimePreset(filters);
    const customSinceLocal = isoToLocalDateTimeInput(securityAnalyticsCustomSince);
    const customUntilLocal = isoToLocalDateTimeInput(securityAnalyticsCustomUntil);
    const quickPresets = [
        ['15m', '15m'],
        ['1h', '1h'],
        ['24h', '24h'],
        ['7d', '7d'],
        ['30d', '30d']
    ];
    const timeRangeLabel = securityEventsTimeRangeLabel(filters);
    return `
      <div class="security-events-time-menu">
        <button type="button" id="security-time-trigger" class="security-time-dropdown-trigger" data-security-analytics-action="toggle-time-panel" aria-label="Time range: ${escapeAttr(timeRangeLabel)}" aria-haspopup="true" aria-expanded="false" aria-controls="security-time-panel">
          <svg class="security-time-trigger-icon" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 10h18"/></svg>
          <strong>${escapeHtml(timeRangeLabel)}</strong>
          <svg class="security-time-trigger-chevron" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
        </button>
        <div id="security-time-panel" class="security-time-panel hidden">
          <div class="security-time-panel-head">
            <span>Time range</span>
            <strong>${escapeHtml(securityEventsTimeRangeLabel(filters))}</strong>
          </div>
          <div class="security-time-mode-tabs" role="group" aria-label="Time range mode">
            <button type="button" class="security-time-mode is-active" data-security-analytics-action="set-time-mode" data-security-time-mode="last">Last</button>
            <button type="button" class="security-time-mode" data-security-analytics-action="set-time-mode" data-security-time-mode="range">Custom range</button>
          </div>
          <div id="security-time-last-mode" class="security-time-mode-panel">
            <div class="security-time-presets" aria-label="Quick time ranges">
              ${quickPresets.map(([value, label]) => `
                <button type="button" class="security-time-preset ${activePreset === value ? 'is-active' : ''}" data-security-analytics-action="apply-time-preset" data-security-time-preset="${escapeAttr(value)}">${escapeHtml(label)}</button>
              `).join('')}
            </div>
            <div class="security-time-field">
              <span>Custom last</span>
              <div class="security-time-inline">
                <input id="security-events-relative-amount" type="number" min="1" max="999" value="24" aria-label="Last amount">
                <select id="security-events-relative-unit" aria-label="Last unit">
                  <option value="minutes">minutes</option>
                  <option value="hours" selected>hours</option>
                  <option value="days">days</option>
                  <option value="weeks">weeks</option>
                </select>
                <button type="button" class="security-time-apply" data-security-analytics-action="apply-last-range">Apply</button>
              </div>
            </div>
          </div>
          <div id="security-time-range-mode" class="security-time-mode-panel hidden">
            <div class="security-time-panel-grid">
              <div class="security-time-field">
                <span>From</span>
                <input id="security-events-since-control" type="datetime-local" value="${escapeAttr(customSinceLocal)}" aria-label="Start date and time">
              </div>
              <div class="security-time-field">
                <span>To</span>
                <input id="security-events-until-control" type="datetime-local" value="${escapeAttr(customUntilLocal)}" aria-label="End date and time">
              </div>
              <button type="button" class="security-time-apply security-time-apply-wide" data-security-analytics-action="apply-date-interval">Apply range</button>
            </div>
          </div>
        </div>
      </div>
  `;
}
function renderSecurityAnalyticsNotice(message, label) {
    if (!message)
        return '';
    return `
    <div class="security-events-notice" role="status">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(message)}</strong>
    </div>
  `;
}
function renderActiveFilterChips(filters) {
    const chips = [];
    const push = (label, value, key) => {
        if (!value)
            return;
        chips.push(`
      <span class="security-filter-chip">
        <strong>${escapeHtml(label)}</strong>
        <span>${escapeHtml(value)}</span>
        <button type="button" class="security-filter-chip-remove" data-security-analytics-action="remove-filter" data-security-filter-key="${escapeAttr(key)}" aria-label="Remove ${escapeAttr(label)} filter">&times;</button>
      </span>
    `);
    };
    push('Status class', filters.statusClass, 'statusClass');
    push('Method', filters.method, 'method');
    push('Country', filters.country, 'country');
    push('IP', filters.ip, 'ip');
    push('Path', filters.path, 'path');
    push('Host', filters.host, 'host');
    push('Route', filters.route, 'route');
    push('Upstream', filters.upstream, 'upstream');
    push('Request ID', filters.requestId, 'requestId');
    push('UA', filters.userAgent, 'userAgent');
    push('JA3', filters.ja3, 'ja3');
    push('JA4', filters.ja4, 'ja4');
    push('ASN', filters.asn, 'asn');
    push('HTTP', filters.httpVersion, 'httpVersion');
    push('TLS', filters.tlsVersion, 'tlsVersion');
    push('IP version', filters.ipVersion, 'ipVersion');
    push('Content type', filters.contentType, 'contentType');
    push('Status', filters.statusCode, 'statusCode');
    if (!chips.length)
        return '';
    return `<div class="security-active-filters" aria-label="Active traffic event filters">${chips.join('')}</div>`;
}
function renderSecurityTrafficCard(points) {
    return `
    <div class="security-events-chart-panel">
      <div id="security-events-timeline-chart" class="security-events-chart-canvas">
        ${renderSecurityTimelineSvg(points)}
      </div>
    </div>
  `;
}
function renderSecurityTimelineSvg(points) {
    if (!points.length)
        return '<div class="security-events-chart-fallback">No timeline data</div>';
    const chartWidth = 1100;
    const chartHeight = 320;
    const plotLeft = 52;
    const plotRight = 1080;
    const plotTop = 38;
    const plotBottom = 264;
    const plotHeight = plotBottom - plotTop;
    const plotWidth = plotRight - plotLeft;
    const maximum = Math.max(...points.map(point => point.total), 1);
    const labelEvery = Math.max(1, Math.ceil((points.length - 1) / 4));
    const gridValues = [0.25, 0.5, 0.75, 1];
    const grid = gridValues.map(fraction => {
        const y = plotBottom - (plotHeight * fraction);
        return `
      <line class="security-events-svg-grid-line" x1="${plotLeft}" y1="${y}" x2="${plotRight}" y2="${y}" />
      <text class="security-events-svg-axis-label" x="${plotLeft - 8}" y="${y + 4}" text-anchor="end">${escapeHtml(formatCompact(Math.round(maximum * fraction)))}</text>
    `;
    }).join('');
    const densityPoints = points.map((point, index) => ({
        x: points.length === 1
            ? plotLeft + (plotWidth / 2)
            : plotLeft + ((plotWidth * index) / (points.length - 1)),
        y: plotBottom - ((Math.max(0, point.total) / maximum) * plotHeight)
    }));
    const densityLine = densityPoints.length === 1
        ? `M ${densityPoints[0].x} ${densityPoints[0].y} L ${densityPoints[0].x + 0.01} ${densityPoints[0].y}`
        : densityPoints.reduce((path, point, index) => {
            if (index === 0)
                return `M ${point.x} ${point.y}`;
            const previous = densityPoints[index - 1];
            const before = densityPoints[Math.max(0, index - 2)];
            const after = densityPoints[Math.min(densityPoints.length - 1, index + 1)];
            const controlOneX = previous.x + ((point.x - before.x) / 6);
            const controlOneY = previous.y + ((point.y - before.y) / 6);
            const controlTwoX = point.x - ((after.x - previous.x) / 6);
            const controlTwoY = point.y - ((after.y - previous.y) / 6);
            return `${path} C ${controlOneX} ${controlOneY} ${controlTwoX} ${controlTwoY} ${point.x} ${point.y}`;
        }, '');
    const densityArea = `${densityLine} L ${densityPoints[densityPoints.length - 1].x} ${plotBottom} L ${densityPoints[0].x} ${plotBottom} Z`;
    const buckets = points.map((point, index) => {
        const total = Math.max(0, point.total);
        const status2xx = Math.max(0, point.status2xx);
        const status3xx = Math.max(0, point.status3xx);
        const status4xx = Math.max(0, point.status4xx);
        const status5xx = Math.max(0, point.status5xx);
        const coordinate = densityPoints[index];
        const hitboxLeft = index === 0
            ? plotLeft
            : (densityPoints[index - 1].x + coordinate.x) / 2;
        const hitboxRight = index === points.length - 1
            ? plotRight
            : (coordinate.x + densityPoints[index + 1].x) / 2;
        const tooltip = `${point.label}: ${formatCompact(total)} requests; ${formatCompact(status2xx)} 2xx; ${formatCompact(status3xx)} 3xx; ${formatCompact(status4xx)} 4xx; ${formatCompact(status5xx)} 5xx`;
        const label = index === 0 || index === points.length - 1 || index % labelEvery === 0
            ? `<text class="security-events-svg-axis-label" x="${coordinate.x}" y="${plotBottom + 26}" text-anchor="middle">${escapeHtml(point.label)}</text>`
            : '';
        const singleClass = points.length === 1 ? ' is-single-point' : '';
        return `
      <a href="#security-events-timeline-chart" class="security-events-svg-action security-events-density-bucket" data-security-analytics-action="apply-since" data-security-since="${escapeAttr(point.bucket)}" aria-label="${escapeAttr(`View events from ${point.label}`)}">
        <title>${escapeHtml(tooltip)}</title>
        <rect class="security-events-density-hitbox" x="${hitboxLeft}" y="${plotTop}" width="${hitboxRight - hitboxLeft}" height="${plotHeight}" />
        <circle class="security-events-density-point${singleClass}" cx="${coordinate.x}" cy="${coordinate.y}" r="${points.length > 32 ? 2.5 : 3.5}" />
      </a>
      ${label}
    `;
    }).join('');
    return `
    <svg class="security-events-timeline-svg" viewBox="0 0 ${chartWidth} ${chartHeight}" role="group" aria-label="Traffic request density over time. Select a point to view requests from that time.">
      <defs>
        <linearGradient id="security-events-density-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="currentColor" stop-opacity=".34" />
          <stop offset="100%" stop-color="currentColor" stop-opacity=".025" />
        </linearGradient>
      </defs>
      <line class="security-events-density-legend-swatch" x1="${plotLeft}" y1="11" x2="${plotLeft + 18}" y2="11" />
      <text class="security-events-svg-legend-label" x="${plotLeft + 26}" y="15">Request density</text>
      ${grid}
      <path class="security-events-density-area" d="${densityArea}" />
      <path class="security-events-density-line" d="${densityLine}" />
      <line class="security-events-svg-axis-line" x1="${plotLeft}" y1="${plotBottom}" x2="${plotRight}" y2="${plotBottom}" />
      ${buckets}
    </svg>
  `;
}
function securityTimelineSeries(model) {
    const grouped = new Map();
    model.timeline.forEach(item => {
        const bucket = String(item.bucket || item.timestamp || item.time || '');
        if (!bucket)
            return;
        const counts = item.counts && typeof item.counts === 'object' ? item.counts : {};
        const row = grouped.get(bucket) || { bucket, total: 0, status2xx: 0, status3xx: 0, status4xx: 0, status5xx: 0 };
        row.status2xx += Number(counts['2xx'] || 0);
        row.status3xx += Number(counts['3xx'] || 0);
        row.status4xx += Number(counts['4xx'] || 0);
        row.status5xx += Number(counts['5xx'] || 0);
        row.total = row.status2xx + row.status3xx + row.status4xx + row.status5xx;
        grouped.set(bucket, row);
    });
    const fromTimeline = normalizeSecurityTimelineBuckets(Array.from(grouped.values()), model.filters.window);
    if (fromTimeline.length)
        return fromTimeline;
    const buckets = new Map();
    model.events.forEach(event => {
        const date = new Date(event.timestamp);
        if (Number.isNaN(date.getTime()))
            return;
        snapSecurityTimelineDate(date, model.filters.window);
        const bucket = date.toISOString();
        const row = buckets.get(bucket) || { bucket, total: 0, status2xx: 0, status3xx: 0, status4xx: 0, status5xx: 0 };
        row.total += 1;
        if (event.response_code >= 500)
            row.status5xx += 1;
        else if (event.response_code >= 400)
            row.status4xx += 1;
        else if (event.response_code >= 300)
            row.status3xx += 1;
        else if (event.response_code >= 200)
            row.status2xx += 1;
        buckets.set(bucket, row);
    });
    return normalizeSecurityTimelineBuckets(Array.from(buckets.values()), model.filters.window);
}
function normalizeSecurityTimelineBuckets(items, windowValue) {
    const limit = securityTimelinePointLimit(windowValue);
    return items
        .sort((a, b) => a.bucket.localeCompare(b.bucket))
        .slice(-limit)
        .map(item => ({ ...item, label: formatTimelineBucketLabel(item.bucket, windowValue) }));
}
function securityTimelinePointLimit(windowValue) {
    if (windowValue === '1h')
        return 60;
    if (windowValue === '7d')
        return 56;
    if (windowValue === '30d')
        return 60;
    return 48;
}
function snapSecurityTimelineDate(date, windowValue) {
    if (windowValue === '1h') {
        date.setSeconds(0, 0);
    }
    else if (windowValue === '7d') {
        const hour = date.getHours();
        date.setHours(Math.floor(hour / 3) * 3, 0, 0, 0);
    }
    else if (windowValue === '30d') {
        date.setHours(0, 0, 0, 0);
    }
    else {
        date.setMinutes(0, 0, 0);
    }
}
function formatTimelineBucketLabel(value, windowValue) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime()))
        return value;
    if (windowValue === '1h')
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (windowValue === '24h')
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return date.toLocaleString([], { month: 'short', day: 'numeric' });
}
function renderSecurityStatisticsCards(model) {
    const breakdowns = model.breakdowns || {};
    const cards = [
        renderStatisticCard('Top Source IPs', breakdowns.ips || [], 'label', 'ip'),
        renderStatisticCard('Top Hosts', breakdowns.hosts || [], 'label', 'host'),
        renderStatisticCard('Top Routes', breakdowns.routes || [], 'label', 'route'),
        renderStatisticCard('Top Upstreams', breakdowns.upstreams || [], 'label', 'upstream'),
        renderStatisticCard('Top Paths', breakdowns.paths || [], 'label', 'path'),
        renderStatisticCard('Methods', breakdowns.methods || [], 'label', 'method'),
        renderStatisticCard('HTTP Version', breakdowns.http_versions || [], 'label', 'httpVersion'),
        renderStatisticCard('Status Codes', breakdowns.status || [], 'label', 'statusCode'),
        renderStatisticCard('Response Content Type', breakdowns.content_types || [], 'label', 'contentType'),
        renderStatisticCard('User Agents', breakdowns.user_agents || [], 'label', 'userAgent'),
        renderStatisticCard('Countries', breakdowns.countries || [], 'label', 'country'),
        renderStatisticCard('IP Version', breakdowns.ip_versions || [], 'label', 'ipVersion'),
        renderStatisticCard('JA3', breakdowns.ja3 || [], 'label', 'ja3'),
        renderStatisticCard('JA4', breakdowns.ja4 || [], 'label', 'ja4'),
        renderStatisticCard('TLS Version', breakdowns.tls_versions || [], 'label', 'tlsVersion'),
        renderStatisticCard('ASN', breakdowns.asn || [], 'label', 'asn')
    ];
    return `
    <div class="security-statistics-deck security-events-statistics-deck" data-security-statistics-deck>
      <div class="security-events-stat-grid">
        ${cards.map(card => `<div class="security-statistics-card">${card}</div>`).join('')}
      </div>
      ${cards.length > securityStatisticsVisibleCardCount() ? `<button type="button" class="security-statistics-show-more" data-security-analytics-action="toggle-statistics-cards" aria-expanded="false">Show ${cards.length - securityStatisticsVisibleCardCount()} more breakdowns</button>` : ''}
    </div>
  `;
}
function securityStatisticsVisibleCardCount() {
    if (window.innerWidth >= 2560)
        return 10;
    if (window.innerWidth >= 1800)
        return 8;
    return 9;
}
function renderSecurityActionMixChartCard(model) {
    const items = actionMixChartItems(model);
    const total = items.reduce((sum, item) => sum + item.count, 0);
    return `
    <section class="operator-section system-health-section security-events-stat-card security-events-action-chart-card">
      <div class="operator-section-head">
        <div>
          <h3>Response distribution</h3>
        </div>
      </div>
      <div class="security-events-action-mix-body">
        <div id="security-events-action-mix-chart" class="security-events-action-chart">
          ${renderSecurityActionMixSvg(items, total)}
        </div>
        <div class="security-events-action-legend">
          ${items.filter(item => item.count > 0).map(item => renderActionMixLegendRow(item, total)).join('') || '<div class="security-events-stat-empty">No data</div>'}
        </div>
      </div>
    </section>
  `;
}
function renderSecurityActionMixSvg(items, total) {
    const visible = items.filter(item => item.count > 0);
    if (!total || !visible.length)
        return '<div class="security-events-chart-fallback">No response data</div>';
    let offset = 0;
    const segments = visible.map(item => {
        const width = (item.count / total) * 100;
        const tooltip = `${item.label}: ${formatCompact(item.count)} events (${formatPercent((item.count / total) * 100)})`;
        const segment = `
      <a href="#security-events-action-mix-chart" class="security-events-svg-action security-events-action-segment action-${escapeAttr(item.tone)}" data-security-analytics-action="apply-filter" data-security-filter-key="statusClass" data-security-filter-value="${escapeAttr(item.key)}" aria-label="${escapeAttr(`Filter to ${item.label}`)}">
        <title>${escapeHtml(tooltip)}</title>
        <rect x="${offset}" y="10" width="${width}" height="24" />
      </a>
    `;
        offset += width;
        return segment;
    }).join('');
    return `
    <svg class="security-events-action-svg" viewBox="0 0 100 44" preserveAspectRatio="none" role="group" aria-label="Response distribution. Select a segment to filter traffic events.">
      <rect class="security-events-action-svg-track" x="0" y="10" width="100" height="24" rx="4" />
      ${segments}
    </svg>
  `;
}
function renderActionMixLegendRow(item, total) {
    const percent = total ? (item.count / total) * 100 : 0;
    return `
    <button type="button" class="security-events-action-legend-row" data-security-analytics-action="apply-filter" data-security-filter-key="statusClass" data-security-filter-value="${escapeAttr(item.key)}">
      <span class="security-events-action-swatch action-${escapeAttr(item.tone)}"></span>
      <span class="security-events-action-label">${escapeHtml(item.label)}</span>
      <strong>${formatCompact(item.count)}</strong>
      <em>${formatPercent(percent)}</em>
    </button>
  `;
}
function actionMixChartItems(model) {
    const fromAggregates = normalizeAggregateItems(model.actionMix, 'status_class');
    const fromSummary = normalizeAggregateItems(responseClassItems(model.summary), 'status_class');
    const source = fromAggregates.length ? fromAggregates : fromSummary;
    const order = ['2xx', '3xx', '4xx', '5xx'];
    return source
        .map(item => ({ key: item.value, label: responseClassLabel(item.value), count: item.count, tone: responseClassTone(item.value) }))
        .sort((a, b) => {
        const aIndex = order.indexOf(a.key);
        const bIndex = order.indexOf(b.key);
        return (aIndex === -1 ? 99 : aIndex) - (bIndex === -1 ? 99 : bIndex);
    });
}
function renderStatisticCard(title, items, valueKey, filterKey) {
    const normalized = normalizeAggregateItems(items, valueKey).slice(0, 20);
    const modalPayload = encodeURIComponent(JSON.stringify(normalized));
    return `
    <section class="operator-section system-health-section security-events-stat-card">
      <div class="operator-section-head">
        <div>
          <h3>${escapeHtml(title)}</h3>
        </div>
        <button type="button" class="security-stat-card-expand" data-security-analytics-action="open-statistics-modal" data-security-stat-title="${escapeAttr(title)}" data-security-stat-filter-key="${escapeAttr(filterKey)}" data-security-stat-items="${escapeAttr(modalPayload)}" aria-label="Open ${escapeAttr(title)} details">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M9 3H3v18h18v-6"/></svg>
        </button>
      </div>
      <div class="security-events-stat-body">
        ${renderSecurityStatRows(normalized.slice(0, 5), filterKey)}
      </div>
    </section>
  `;
}
function renderSecurityStatRows(items, filterKey) {
    if (!items.length) {
        return '<div class="security-events-stat-empty">No data</div>';
    }
    return items.map((item, index) => {
        const filterAttrs = filterKey && item.value !== '-'
            ? ` role="button" tabindex="0" data-security-analytics-action="apply-filter" data-security-filter-key="${escapeAttr(filterKey)}" data-security-filter-value="${escapeAttr(item.value)}" aria-label="Filter by ${escapeAttr(item.value)}"`
            : '';
        return `
      <div class="security-events-stat-row${filterAttrs ? ' is-filterable' : ''}"${filterAttrs}>
        <div class="security-events-stat-rank">${index + 1}</div>
        <div class="security-events-stat-copy">
          <span title="${escapeAttr(item.value)}">${escapeHtml(item.value)}</span>
        </div>
        <strong class="security-events-stat-count">${formatCompact(item.count)}</strong>
      </div>
    `;
    }).join('');
}
function normalizeAggregateItems(items, valueKey) {
    return items.map(item => ({ value: String(item[valueKey] || item.label || item.key || item.value || '-'), count: Number(item.count || 0) }));
}
function timelineAggregateItems(items) {
    return items.map(item => ({
        value: formatBucket(String(item.bucket || item.timestamp || item.time || '-')),
        count: Number(item.count || item.events || item.total || 0)
    }));
}
function aggregateEvents(events, readValue, limit = 8) {
    const counts = new Map();
    events.forEach(event => {
        const value = readValue(event).trim();
        if (!value)
            return;
        counts.set(value, (counts.get(value) || 0) + 1);
    });
    return Array.from(counts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, limit)
        .map(([value, count]) => ({ value, count }));
}
function renderSecurityAnalyticsUnavailable(message) {
    return `
    <div class="security-analytics-shell security-events-explorer security-events-operator-explorer">
      ${renderSecurityMetricStrip({})}
      ${renderSecurityAnalyticsNotice(message, 'Unavailable')}
      <section class="operator-section system-health-section security-events-empty-section">
        <div class="security-events-empty-state">
          <h3>Traffic analytics unavailable</h3>
          <p>${escapeHtml(message)}</p>
      <button type="button" class="btn btn-outline" data-action="refresh-security-analytics">Retry</button>
        </div>
      </section>
    </div>
  `;
}
function renderEventExplorerRows(events) {
    if (!events.length)
        return '<tr><td colspan="7" class="dashboard-empty-cell"><div class="dashboard-empty-state"><div class="dashboard-empty-title">No traffic requests</div><div class="dashboard-empty-detail">Adjust the filters or time range.</div><button type="button" class="btn btn-outline btn-sm" data-security-analytics-action="clear-filters">Clear filters</button></div></td></tr>';
    return events.map(event => {
        const host = event.host || '';
        const asn = event.asn || '';
        const country = (event.country || '').toUpperCase();
        const sourceContext = [country, asn].filter(Boolean).join(' · ');
        const rowLabel = `Open traffic event for ${(event.method || '-').toUpperCase()} ${event.path || '-'}`;
        return `
      <tr data-security-event-id="${escapeAttr(event.id)}" tabindex="0" aria-label="${escapeAttr(rowLabel)}">
        <td><time datetime="${escapeAttr(event.timestamp || '')}">${escapeHtml(formatEventTime(event.timestamp))}</time></td>
        <td><span class="security-event-method">${escapeHtml((event.method || '-').toUpperCase())}</span></td>
        <td class="waf-dashboard-request" title="${escapeAttr(event.path || '-')}"><span>${escapeHtml(event.path || '-')}</span></td>
        <td class="waf-dashboard-request" title="${escapeAttr(host || '-')}"><span>${escapeHtml(host || '-')}</span></td>
        <td class="waf-dashboard-decision-cell">${securityTrafficStatusDashboardBadge(event.response_code)}</td>
        <td class="security-events-routing-source" title="${escapeAttr(sourceContext || event.client_ip || '-')}">
          <div class="security-events-source-wrap">
            ${country ? `<span class="security-events-country-tag">${escapeHtml(country)}</span>` : ''}
            <span class="security-events-ip-text">${escapeHtml(event.client_ip || '-')}</span>
          </div>
        </td>
        <td class="text-right"><button type="button" class="btn btn-outline btn-sm">View</button></td>
      </tr>
    `;
    }).join('');
}
function securityTrafficStatusDashboardBadge(status) {
    if (!status)
        return '<span class="security-events-status">-</span>';
    const tone = status >= 400 ? 'is-error' : '';
    return `<span class="security-events-status ${tone}"><strong>${escapeHtml(String(status))}</strong> <span>${escapeHtml(securityStatusLabel(status))}</span></span>`;
}
function securityActionBadge(action) {
    const normalized = (action || 'allow').toLowerCase();
    const tone = normalized === 'block' || normalized === 'deny'
        ? 'danger'
        : normalized === 'challenge' || normalized === 'rate_limit'
            ? 'warning'
            : normalized === 'allow'
                ? 'success'
                : normalized === 'log' || normalized === 'detect'
                    ? 'info'
                    : 'neutral';
    return `<span class="security-action-badge tone-${tone}">${escapeHtml(actionLabel(normalized))}</span>`;
}
function securityStatusBadge(status) {
    const tone = status >= 500 ? 'danger' : status >= 400 ? 'warning' : status >= 300 ? 'info' : status >= 200 ? 'success' : 'neutral';
    return `
    <span class="security-status-plain tone-${tone}">
      <span class="security-status-dot" aria-hidden="true"></span>
      <strong>${escapeHtml(status ? String(status) : '-')}</strong>
      <span>${escapeHtml(securityStatusLabel(status))}</span>
    </span>
  `;
}
function securityStatusLabel(status) {
    const labels = {
        200: 'OK',
        201: 'Created',
        204: 'No content',
        301: 'Redirect',
        302: 'Redirect',
        304: 'Not modified',
        400: 'Bad request',
        401: 'Unauthorized',
        403: 'Forbidden',
        404: 'Not found',
        405: 'Not allowed',
        408: 'Timeout',
        409: 'Conflict',
        429: 'Rate limited',
        500: 'Server error',
        502: 'Bad gateway',
        503: 'Unavailable',
        504: 'Gateway timeout'
    };
    if (labels[status])
        return labels[status];
    if (status >= 500)
        return 'Server error';
    if (status >= 400)
        return 'Client error';
    if (status >= 300)
        return 'Redirect';
    if (status >= 200)
        return 'Successful';
    return 'No response';
}
function ensureSecurityEventDrawerMounted() {
    const existingInBody = AdminDOM.query(':scope > #security-event-explorer-drawer', document.body);
    const viewRoot = AdminDOM.getById('view-root');
    const insideView = viewRoot ? AdminDOM.query('#security-event-explorer-drawer', viewRoot) : null;
    if (existingInBody && insideView && existingInBody !== insideView) {
        insideView.remove();
        return existingInBody;
    }
    const drawer = existingInBody || insideView || AdminDOM.getById('security-event-explorer-drawer');
    if (drawer && drawer.parentElement !== document.body) {
        document.body.appendChild(drawer);
    }
    return drawer;
}
function openSecurityEventExplorerDrawer(id) {
    const drawer = ensureSecurityEventDrawerMounted();
    const body = AdminDOM.getById('security-event-explorer-drawer-body');
    const title = AdminDOM.getById('security-event-explorer-drawer-title');
    const method = AdminDOM.getById('security-event-explorer-drawer-method');
    const section = AdminDOM.getById('security-event-explorer-drawer-section');
    const time = AdminDOM.getById('security-event-explorer-drawer-time');
    const event = securityAnalyticsEvents.find(item => item.id === id);
    if (!drawer || !body || !event)
        return;
    if (drawer.parentElement !== document.body) {
        document.body.appendChild(drawer);
    }
    securityDrawerReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    drawer.classList.remove('hidden');
    drawer.setAttribute('aria-hidden', 'false');
    const methodStr = (event.method || 'GET').toUpperCase();
    const pathStr = event.path || '/';
    if (title) {
        title.textContent = pathStr;
        title.title = pathStr;
    }
    if (method) {
        method.textContent = methodStr;
        method.className = `security-event-method method-${methodStr.toLowerCase()}`;
    }
    if (section)
        section.textContent = event.route_name || event.upstream || 'Request';
    if (time)
        time.textContent = formatEventDateTime(event.timestamp);
    body.innerHTML = renderSecurityEventDetail(event);
    body.scrollTop = 0;
    const panels = body.querySelector('.security-event-workbench-panels');
    if (panels)
        panels.scrollTop = 0;
    setSecurityEventDrawerTab('overview');
    drawer.querySelector('[data-security-analytics-action="close-drawer"]')?.focus();
}
function closeSecurityEventExplorerDrawer() {
    const drawer = AdminDOM.getById('security-event-explorer-drawer');
    drawer?.classList.add('hidden');
    drawer?.setAttribute('aria-hidden', 'true');
    securityDrawerReturnFocus?.focus();
    securityDrawerReturnFocus = null;
}
function renderSecurityEventDetail(event) {
    const method = (event.method || 'GET').toUpperCase();
    const host = event.host || '';
    const path = event.path || '/';
    const sourceIdentity = [event.asn, event.asn_org].filter(Boolean).join(' · ') || '—';
    const statusLabel = event.response_code ? securityStatusLabel(event.response_code) : 'No response';
    const isError = (event.response_code || 0) >= 400;
    return `
    <div class="security-event-workbench">
      <div class="security-event-workbench-tabs" role="tablist" aria-label="Event detail views">
        <button type="button" id="security-event-tab-overview" class="security-event-workbench-tab is-active" role="tab" aria-selected="true" aria-controls="security-event-panel-overview" data-security-analytics-action="switch-drawer-tab" data-security-drawer-tab="overview">
          Overview
        </button>
        <button type="button" id="security-event-tab-raw" class="security-event-workbench-tab" role="tab" aria-selected="false" aria-controls="security-event-panel-raw" data-security-analytics-action="switch-drawer-tab" data-security-drawer-tab="raw">
          Raw event
        </button>
      </div>

      <div class="security-event-workbench-panels">
        <!-- OVERVIEW VIEW -->
        <div id="security-event-panel-overview" class="security-event-workbench-view" role="tabpanel" aria-labelledby="security-event-tab-overview" data-security-drawer-panel="overview">
          
          <!-- Summary Hero Card -->
          <div class="security-event-hero-card">
            <div class="security-event-hero-status ${isError ? 'is-error' : ''}">
              <strong class="security-event-hero-code">${escapeHtml(String(event.response_code || '—'))}</strong>
              <span class="security-event-hero-label">${escapeHtml(statusLabel)}</span>
            </div>
            <div class="security-event-hero-meta">
              <span class="security-event-method method-${escapeAttr(method.toLowerCase())}">${escapeHtml(method)}</span>
              ${typeof event.latency_ms === 'number' ? `<span class="security-event-hero-latency">${formatNumberValue(event.latency_ms)} ms</span>` : ''}
            </div>
          </div>

          <!-- Section: Request Details -->
          <section class="security-event-card">
            <div class="security-event-card-head">
              <span class="security-event-card-title">Request Details</span>
            </div>
            <div class="security-event-card-body">
              ${detailCardRow('Host', host || '—', true)}
              ${detailCardRow('Path', path || '—', true)}
              ${detailCardRow('Request ID', event.request_id || '—', true)}
              ${detailCardRow('HTTP version', event.http_version || '—')}
              ${detailCardRow('User agent', event.user_agent || '—')}
            </div>
          </section>

          <!-- Section: Client & Network -->
          <section class="security-event-card">
            <div class="security-event-card-head">
              <span class="security-event-card-title">Client & Network</span>
            </div>
            <div class="security-event-card-body">
              ${detailCardRow('Source IP', event.client_ip || '—', true)}
              ${detailCardRow('Location', event.country || '—')}
              ${detailCardRow('IP version', event.ip_version || '—')}
              ${detailCardRow('Source identity', sourceIdentity)}
              ${event.ja3 ? detailCardRow('JA3', event.ja3, true) : ''}
              ${event.ja4 ? detailCardRow('JA4', event.ja4, true) : ''}
            </div>
          </section>

          <!-- Section: Routing & Delivery -->
          <section class="security-event-card">
            <div class="security-event-card-head">
              <span class="security-event-card-title">Routing & Delivery</span>
            </div>
            <div class="security-event-card-body">
              ${detailCardRow('Route', event.route_name || '—')}
              ${detailCardRow('Upstream', event.upstream || '—')}
              ${detailCardRow('TLS version', event.tls_version || '—')}
              ${detailCardRow('Response type', event.response_content_type || '—')}
              ${detailCardRow('Latency', typeof event.latency_ms === 'number' ? `${formatNumberValue(event.latency_ms)} ms` : '—')}
            </div>
          </section>
        </div>

        <!-- RAW EVENT VIEW -->
        <div id="security-event-panel-raw" class="security-event-workbench-view hidden" role="tabpanel" aria-labelledby="security-event-tab-raw" data-security-drawer-panel="raw">
          <section class="security-event-card security-event-raw-card">
            <div class="security-event-card-head security-event-raw-head">
              <span class="security-event-card-title">Raw Event JSON</span>
              <button type="button" class="btn btn-sm btn-outline" data-security-analytics-action="copy-drawer-value" data-security-copy-value="${escapeAttr(JSON.stringify(event, null, 2))}">
                Copy JSON
              </button>
            </div>
            <pre class="security-event-raw-body"><code>${escapeHtml(JSON.stringify(event, null, 2))}</code></pre>
          </section>
        </div>
      </div>

      <!-- Action Bar -->
      ${renderEventCommandBar(event)}
    </div>
  `;
}
function detailCardRow(label, value, mono = false) {
    return `
    <div class="security-event-row">
      <dt class="security-event-label">${escapeHtml(label)}</dt>
      <dd class="security-event-val${mono ? ' is-mono' : ''}">${escapeHtml(value)}</dd>
    </div>
  `;
}
function renderEventCommandBar(event) {
    const copyActions = [];
    const filterActions = [];
    if (event.client_ip)
        copyActions.push(drawerActionButton('copy-drawer-value', 'Copy IP', SectionUI.icons.globe, { securityCopyValue: event.client_ip }));
    if (event.path)
        copyActions.push(drawerActionButton('copy-drawer-value', 'Copy path', SectionUI.icons.route, { securityCopyValue: event.path }));
    if (event.request_id)
        copyActions.push(drawerActionButton('copy-drawer-value', 'Copy ID', SectionUI.icons.arrowRight, { securityCopyValue: event.request_id }));
    copyActions.push(drawerActionButton('copy-drawer-value', 'Copy JSON', SectionUI.icons.fileText || SectionUI.icons.file, { securityCopyValue: JSON.stringify(event, null, 2) }));
    if (event.client_ip)
        filterActions.push(drawerActionButton('apply-drawer-filter', 'Filter IP', SectionUI.icons.filter, { securityFilterKey: 'ip', securityFilterValue: event.client_ip }));
    if (event.path)
        filterActions.push(drawerActionButton('apply-drawer-filter', 'Filter path', SectionUI.icons.filter, { securityFilterKey: 'path', securityFilterValue: event.path }));
    if (event.response_code)
        filterActions.push(drawerActionButton('apply-drawer-filter', 'Filter status', SectionUI.icons.filter, { securityFilterKey: 'statusCode', securityFilterValue: String(event.response_code) }));
    if (event.route_name)
        filterActions.push(drawerActionButton('apply-drawer-filter', 'Filter route', SectionUI.icons.filter, { securityFilterKey: 'route', securityFilterValue: event.route_name }));
    if (event.upstream)
        filterActions.push(drawerActionButton('apply-drawer-filter', 'Filter upstream', SectionUI.icons.filter, { securityFilterKey: 'upstream', securityFilterValue: event.upstream }));
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
function drawerActionButton(action, label, icon, data = {}, primary = false) {
    const attrs = Object.entries(data)
        .map(([key, value]) => `data-${key.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`)}="${escapeAttr(value)}"`)
        .join(' ');
    return `
    <button type="button" class="security-event-action-btn${primary ? ' is-primary' : ''}" data-security-analytics-action="${escapeAttr(action)}" ${attrs}>
      <span class="security-event-action-icon" aria-hidden="true">${icon}</span>
      <span>${escapeHtml(label)}</span>
    </button>
  `;
}
function detailRows(rows) {
    const visibleRows = rows
        .map(([label, value]) => [label, value == null ? '' : String(value).trim()])
        .filter(([, value]) => value !== '');
    if (!visibleRows.length)
        return '';
    return `<dl class="security-event-detail-rows">${visibleRows.map(([label, value]) => `
    <div>
      <dt>${escapeHtml(label)}</dt>
      <dd>${escapeHtml(value)}</dd>
    </div>
  `).join('')}</dl>`;
}
function setSecurityEventDrawerTab(tab) {
    const target = tab === 'raw' ? 'raw' : 'overview';
    document.querySelectorAll('[data-security-drawer-tab]').forEach(button => {
        const active = button.dataset.securityDrawerTab === target;
        button.classList.toggle('is-active', active);
        button.setAttribute('aria-selected', String(active));
    });
    document.querySelectorAll('[data-security-drawer-panel]').forEach(panel => {
        panel.classList.toggle('hidden', panel.dataset.securityDrawerPanel !== target);
    });
    const body = AdminDOM.getById('security-event-explorer-drawer-body');
    if (body) {
        body.scrollTop = 0;
        const panels = body.querySelector('.security-event-workbench-panels');
        if (panels)
            panels.scrollTop = 0;
    }
}
function securitySectionRoute(section) {
    const routes = {
        traffic_control: 'traffic_config',
        waf_core: 'waf_config',
        bot_protection: 'antibots_config',
        api_security: 'apisecurity_config',
        http_security: 'httpsecurity_config',
        access_control: 'access_config'
    };
    return routes[section] || '';
}
function securityEvidenceRows(event, section) {
    const matchedRows = Object.entries(event.matched_fields || {})
        .filter(([key, value]) => shouldShowGenericEvidence(key, value))
        .map(([key, value]) => [labelize(key), value]);
    const coreRows = [
        ['Rule name', event.rule_name],
        ['Rule ID', event.rule_id],
        ['Rule type', event.rule_type],
        ['Reason', eventEvidenceValue(event, ['reason', 'decision_reason', 'trigger_reason'])]
    ];
    const hasEvidence = coreRows.some(([, value]) => String(value || '').trim()) || matchedRows.length > 0;
    if (!hasEvidence)
        return '';
    return detailRows([...coreRows, ['Section', sectionLabel(section)], ...matchedRows]);
}
function shouldShowGenericEvidence(key, value) {
    if (!String(value || '').trim())
        return false;
    const normalized = key.toLowerCase();
    const suppressed = new Set([
        'asn',
        'asn_org',
        'as_org',
        'isp',
        'host',
        'http.host',
        'referrer',
        'referer',
        'http.referer',
        'http.referrer',
        'tls_ja3',
        'tls_ja4',
        'ja3',
        'ja4',
        'bot_category',
        'bot_type',
        'bot_verified',
        'bot_headless',
        'challenge_type',
        'challenge_strategy',
        'challenge_outcome',
        'reason',
        'decision_reason',
        'trigger_reason',
        'ip_reputation',
        'reputation_action'
    ]);
    return !suppressed.has(normalized);
}
function eventEvidenceValue(event, keys) {
    const fields = event.matched_fields || {};
    for (const key of keys) {
        const value = fields[key];
        if (typeof value === 'string' && value.trim())
            return value.trim();
    }
    return '';
}
function compactUserAgent(value) {
    const ua = (value || '').trim();
    if (!ua)
        return '';
    const browserMatch = ua.match(/(OPR|Edg|Chrome|Firefox|Safari)\/([\d.]+)/i);
    const osMatch = ua.match(/\(([^)]+)\)/);
    const browserMap = { opr: 'Opera', edg: 'Edge', chrome: 'Chrome', firefox: 'Firefox', safari: 'Safari' };
    const browser = browserMatch ? `${browserMap[browserMatch[1].toLowerCase()] || browserMatch[1]} ${browserMatch[2].split('.')[0]}` : '';
    const os = osMatch ? osMatch[1].split(';').slice(0, 2).join(';').trim() : '';
    return [browser, os].filter(Boolean).join(' / ') || (ua.length > 96 ? `${ua.slice(0, 93)}...` : ua);
}
async function copySecurityDrawerValue(value) {
    if (!value || !navigator.clipboard) {
        notify('Clipboard is not available in this browser', 'error');
        return;
    }
    try {
        await navigator.clipboard.writeText(value);
        notify('Copied to clipboard', 'success');
    }
    catch (error) {
        notify(getErrorMessage(error, 'Failed to copy value'), 'error');
    }
}
function openSecurityRawEvent() {
    setSecurityEventDrawerTab('raw');
    AdminDOM.getById('security-event-tab-raw')?.focus();
}
function openSecuritySectionRoute(route) {
    const router = window.router;
    if (!route || !router?.views?.[route])
        return;
    closeSecurityEventExplorerDrawer();
    router.navigate(route);
}
function applySecurityTimePreset(value) {
    if (value === '1h' || value === '24h' || value === '7d' || value === '30d') {
        securityAnalyticsCustomSince = '';
        securityAnalyticsCustomUntil = '';
        setSelectValue('analytics-window-filter', value);
        closeSecurityEventExplorerDrawer();
        return;
    }
    const amount = Number(value.slice(0, -1));
    const suffix = value.slice(-1);
    const unitMap = { m: 'minutes', h: 'hours', d: 'days', w: 'weeks' };
    const since = new Date(Date.now() - durationToMilliseconds(amount, unitMap[suffix] || 'hours')).toISOString();
    setSecurityAnalyticsTimeRange(since);
}
function applySecurityLastRange() {
    const amount = Number(AdminDOM.inputValue('security-events-relative-amount', '24'));
    const unit = AdminDOM.selectValue('security-events-relative-unit', 'hours');
    setSecurityAnalyticsTimeRange(new Date(Date.now() - durationToMilliseconds(amount, unit)).toISOString());
}
function applySecurityDateInterval() {
    const since = localDateTimeInputToIso(AdminDOM.inputValue('security-events-since-control', ''));
    const until = localDateTimeInputToIso(AdminDOM.inputValue('security-events-until-control', ''));
    if (!since && !until)
        return;
    setSecurityAnalyticsTimeRange(since, until);
}
function bindSecurityAnalyticsInteractions() {
    if (securityAnalyticsBound)
        return;
    securityAnalyticsBound = true;
    document.addEventListener('click', event => {
        if (!(event.target instanceof Element))
            return;
        const analyticsAction = event.target.closest('[data-security-analytics-action]');
        if (analyticsAction) {
            event.preventDefault();
            const action = analyticsAction.dataset.securityAnalyticsAction || '';
            if (action === 'clear-filters') {
                clearSecurityAnalyticsFilters();
                void initSecurityAnalytics();
            }
            else if (action === 'close-drawer') {
                closeSecurityEventExplorerDrawer();
            }
            else if (action === 'toggle-filter-menu') {
                hideSecurityTimePanel();
                toggleSecurityFilterMenu();
            }
            else if (action === 'cancel-filter-builder') {
                hideSecurityFilterBuilder();
            }
            else if (action === 'apply-filter-builder') {
                applySecurityFilterBuilder();
                void initSecurityAnalytics();
            }
            else if (action === 'apply-filter') {
                closeSecurityStatisticsModal();
                applySecurityAnalyticsFilter(analyticsAction.dataset.securityFilterKey || '', analyticsAction.dataset.securityFilterValue || '');
                void initSecurityAnalytics();
            }
            else if (action === 'apply-drawer-filter') {
                closeSecurityEventExplorerDrawer();
                applySecurityAnalyticsFilter(analyticsAction.dataset.securityFilterKey || '', analyticsAction.dataset.securityFilterValue || '');
                void initSecurityAnalytics();
            }
            else if (action === 'copy-drawer-value') {
                void copySecurityDrawerValue(analyticsAction.dataset.securityCopyValue || '');
            }
            else if (action === 'switch-drawer-tab') {
                setSecurityEventDrawerTab(analyticsAction.dataset.securityDrawerTab || 'overview');
            }
            else if (action === 'open-raw-event') {
                openSecurityRawEvent();
            }
            else if (action === 'open-section-route') {
                openSecuritySectionRoute(analyticsAction.dataset.securitySectionRoute || '');
            }
            else if (action === 'remove-filter') {
                removeSecurityAnalyticsFilter(analyticsAction.dataset.securityFilterKey || '');
                void initSecurityAnalytics();
            }
            else if (action === 'apply-since') {
                setSecurityAnalyticsTimeRange(analyticsAction.dataset.securitySince || '');
                void initSecurityAnalytics();
            }
            else if (action === 'toggle-time-panel') {
                hideSecurityFilterBuilder();
                toggleSecurityTimePanel();
            }
            else if (action === 'apply-time-preset') {
                applySecurityTimePreset(analyticsAction.dataset.securityTimePreset || '24h');
                hideSecurityTimePanel();
                void initSecurityAnalytics();
            }
            else if (action === 'apply-last-range') {
                applySecurityLastRange();
                hideSecurityTimePanel();
                void initSecurityAnalytics();
            }
            else if (action === 'apply-date-interval') {
                applySecurityDateInterval();
                hideSecurityTimePanel();
                void initSecurityAnalytics();
            }
            else if (action === 'set-time-mode') {
                setSecurityTimeMode(analyticsAction.dataset.securityTimeMode || 'last');
            }
            else if (action === 'toggle-statistics-cards') {
                toggleSecurityStatisticsCards(analyticsAction);
            }
            else if (action === 'open-statistics-modal') {
                openSecurityStatisticsModal(analyticsAction);
            }
            else if (action === 'close-statistics-modal') {
                closeSecurityStatisticsModal();
            }
            else if (action === 'next-events-page') {
                void changeSecurityEventsPage('next');
            }
            else if (action === 'previous-events-page') {
                void changeSecurityEventsPage('previous');
            }
            return;
        }
        const eventRow = event.target.closest('[data-security-event-id]');
        if (eventRow) {
            event.preventDefault();
            openSecurityEventExplorerDrawer(eventRow.dataset.securityEventId || '');
            return;
        }
        if (event.target instanceof HTMLElement && event.target.id === 'security-event-explorer-drawer') {
            closeSecurityEventExplorerDrawer();
        }
    });
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && !AdminDOM.getById('security-event-explorer-drawer')?.classList.contains('hidden')) {
            event.preventDefault();
            closeSecurityEventExplorerDrawer();
            return;
        }
        if (!(event.target instanceof Element))
            return;
        const svgAction = event.target.closest('.security-events-svg-action[data-security-analytics-action]');
        if (svgAction && (event.key === 'Enter' || event.key === ' ')) {
            event.preventDefault();
            svgAction.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
            return;
        }
        if (event.key !== 'Enter' && event.key !== ' ')
            return;
        const eventRow = event.target.closest('[data-security-event-id]');
        if (!eventRow || event.target !== eventRow)
            return;
        event.preventDefault();
        openSecurityEventExplorerDrawer(eventRow.dataset.securityEventId || '');
    });
    document.addEventListener('change', event => {
        if (!(event.target instanceof HTMLSelectElement))
            return;
        if (event.target.id === 'security-filter-field') {
            updateSecurityFilterBuilderForField();
        }
        else if (event.target.id === 'analytics-window-filter' || event.target.id === 'security-events-window-control') {
            if (event.target.id === 'security-events-window-control') {
                setSelectValue('analytics-window-filter', event.target.value);
            }
            securityAnalyticsCustomSince = '';
            securityAnalyticsCustomUntil = '';
            closeSecurityEventExplorerDrawer();
            void initSecurityAnalytics();
        }
        else if (event.target.id === 'security-events-page-size') {
            setSelectValue('analytics-limit-filter', event.target.value);
            closeSecurityEventExplorerDrawer();
            void initSecurityAnalytics();
        }
    });
    window.addEventListener('resize', () => {
        document.querySelectorAll('[data-security-statistics-deck]:not(.is-expanded)').forEach(syncSecurityStatisticsShowMore);
    });
}
function toggleSecurityStatisticsCards(button) {
    const deck = button.closest('[data-security-statistics-deck]');
    if (!deck)
        return;
    const expanded = deck.classList.toggle('is-expanded');
    button.textContent = expanded ? 'Show fewer breakdowns' : `Show ${securityStatisticsHiddenCardCount(deck)} more breakdowns`;
    button.setAttribute('aria-expanded', String(expanded));
}
function securityStatisticsHiddenCardCount(deck) {
    return Math.max(0, deck.querySelectorAll('.security-statistics-card').length - securityStatisticsVisibleCardCount());
}
function syncSecurityStatisticsShowMore(deck) {
    const button = deck.querySelector('[data-security-analytics-action="toggle-statistics-cards"]');
    if (!button)
        return;
    const hiddenCardCount = securityStatisticsHiddenCardCount(deck);
    button.hidden = hiddenCardCount === 0;
    if (!button.hidden)
        button.textContent = `Show ${hiddenCardCount} more breakdowns`;
}
function openSecurityStatisticsModal(source) {
    const modal = AdminDOM.getById('security-statistics-modal');
    const title = AdminDOM.getById('security-statistics-modal-title');
    const body = AdminDOM.getById('security-statistics-modal-body');
    if (!modal || !title || !body)
        return;
    const modalTitle = source.dataset.securityStatTitle || 'Details';
    const filterKey = source.dataset.securityStatFilterKey || '';
    const items = parseStatisticModalItems(source.dataset.securityStatItems || '');
    const total = items.reduce((sum, item) => sum + item.count, 0);
    const max = Math.max(...items.map(item => item.count), 0);
    title.textContent = modalTitle;
    body.innerHTML = `
    <p class="security-statistics-modal-summary">${formatCompact(total)} events &middot; ${formatCompact(items.length)} values</p>
    <div class="security-statistics-modal-list">
      ${items.length ? items.map(item => statisticModalRow(item, filterKey, total, max)).join('') : '<div class="dashboard-empty-state"><div class="dashboard-empty-title">No values found</div><div class="dashboard-empty-detail">No values were collected for this breakdown.</div></div>'}
    </div>
  `;
    modal.classList.remove('hidden');
}
function closeSecurityStatisticsModal() {
    AdminDOM.getById('security-statistics-modal')?.classList.add('hidden');
}
function parseStatisticModalItems(value) {
    try {
        const parsed = JSON.parse(decodeURIComponent(value));
        return Array.isArray(parsed)
            ? parsed.map(item => ({ value: String(item.value || '-'), count: Number(item.count || 0) }))
            : [];
    }
    catch {
        return [];
    }
}
function statisticModalRow(item, filterKey, total, max) {
    const filterButton = filterKey && item.value !== '-'
        ? `<button type="button" class="security-statistics-modal-filter" data-security-analytics-action="apply-filter" data-security-filter-key="${escapeAttr(filterKey)}" data-security-filter-value="${escapeAttr(item.value)}">Filter</button>`
        : '';
    const percent = total > 0 ? (item.count / total) * 100 : 0;
    const width = max > 0 ? Math.max((item.count / max) * 100, 1) : 0;
    return `
    <div class="security-statistics-modal-row">
      <div class="security-statistics-modal-value">
        <span>${escapeHtml(item.value)}</span>
        <div class="security-statistics-modal-bar" style="--stat-width: ${width.toFixed(2)}%"></div>
      </div>
      <div class="security-statistics-modal-metrics">
        <strong>${formatCompact(item.count)}</strong>
        <small>${formatPercent(percent)}</small>
      </div>
      ${filterButton}
    </div>
  `;
}
function clearSecurityAnalyticsFilters() {
    securityAnalyticsCustomSince = '';
    securityAnalyticsCustomUntil = '';
    setSelectValue('analytics-window-filter', '24h');
    setSelectValue('analytics-status-class-filter', '');
    setSelectValue('analytics-method-filter', '');
    setSelectValue('analytics-limit-filter', defaultSecurityAnalyticsLimit);
    [
        'analytics-country-filter',
        'analytics-ip-filter',
        'analytics-path-filter',
        'analytics-host-filter',
        'analytics-route-filter',
        'analytics-upstream-filter',
        'analytics-request-id-filter',
        'analytics-user-agent-filter',
        'analytics-ja3-filter',
        'analytics-ja4-filter',
        'analytics-asn-filter',
        'analytics-http-version-filter',
        'analytics-tls-version-filter',
        'analytics-ip-version-filter',
        'analytics-content-type-filter',
        'analytics-status-filter'
    ].forEach(id => {
        const input = AdminDOM.getById(id);
        if (input)
            input.value = '';
    });
}
function removeSecurityAnalyticsFilter(key) {
    if (!key)
        return;
    if (key === 'since' || key === 'until' || key === 'time') {
        securityAnalyticsCustomSince = '';
        securityAnalyticsCustomUntil = '';
        setSelectValue('analytics-window-filter', '24h');
        return;
    }
    if (key === 'window') {
        securityAnalyticsCustomSince = '';
        securityAnalyticsCustomUntil = '';
        setSelectValue('analytics-window-filter', '24h');
        setSelectValue('security-events-window-control', '24h');
        return;
    }
    const inputMap = {
        country: 'analytics-country-filter',
        ip: 'analytics-ip-filter',
        path: 'analytics-path-filter',
        host: 'analytics-host-filter',
        route: 'analytics-route-filter',
        upstream: 'analytics-upstream-filter',
        requestId: 'analytics-request-id-filter',
        userAgent: 'analytics-user-agent-filter',
        ja3: 'analytics-ja3-filter',
        ja4: 'analytics-ja4-filter',
        asn: 'analytics-asn-filter',
        httpVersion: 'analytics-http-version-filter',
        tlsVersion: 'analytics-tls-version-filter',
        ipVersion: 'analytics-ip-version-filter',
        contentType: 'analytics-content-type-filter',
        statusCode: 'analytics-status-filter'
    };
    const selectMap = {
        statusClass: 'analytics-status-class-filter',
        method: 'analytics-method-filter'
    };
    const selectId = selectMap[key];
    if (selectId) {
        setSelectValue(selectId, '');
        return;
    }
    const input = inputMap[key] ? AdminDOM.getById(inputMap[key]) : null;
    if (input)
        input.value = '';
}
function toggleSecurityFilterMenu() {
    const popover = AdminDOM.getById('security-filter-popover');
    if (!popover)
        return;
    popover.classList.toggle('hidden');
    const isOpen = !popover.classList.contains('hidden');
    AdminDOM.getById('security-filter-trigger')?.setAttribute('aria-expanded', String(isOpen));
    if (isOpen) {
        updateSecurityFilterBuilderForField();
        AdminDOM.getById('security-filter-field')?.focus();
    }
}
function hideSecurityFilterBuilder() {
    AdminDOM.getById('security-filter-popover')?.classList.add('hidden');
    AdminDOM.getById('security-filter-trigger')?.setAttribute('aria-expanded', 'false');
}
function toggleSecurityTimePanel() {
    const panel = AdminDOM.getById('security-time-panel');
    if (!panel)
        return;
    panel.classList.toggle('hidden');
    AdminDOM.getById('security-time-trigger')?.setAttribute('aria-expanded', String(!panel.classList.contains('hidden')));
}
function hideSecurityTimePanel() {
    AdminDOM.getById('security-time-panel')?.classList.add('hidden');
    AdminDOM.getById('security-time-trigger')?.setAttribute('aria-expanded', 'false');
}
function setSecurityTimeMode(mode) {
    const normalized = mode === 'range' ? 'range' : 'last';
    const lastPanel = AdminDOM.getById('security-time-last-mode');
    const rangePanel = AdminDOM.getById('security-time-range-mode');
    lastPanel?.classList.toggle('hidden', normalized !== 'last');
    rangePanel?.classList.toggle('hidden', normalized !== 'range');
    document.querySelectorAll('.security-time-mode').forEach(button => {
        button.classList.toggle('is-active', button.dataset.securityTimeMode === normalized);
    });
}
function updateSecurityFilterBuilderForField() {
    const field = AdminDOM.selectValue('security-filter-field', 'path');
    const operator = AdminDOM.getById('security-filter-operator');
    const value = AdminDOM.getById('security-filter-value');
    const placeholders = {
        path: '/admin',
        host: 'example.com',
        route: 'public-app',
        upstream: 'origin-primary',
        requestId: 'req-01J...',
        ip: '203.0.113.10',
        method: 'GET',
        country: 'US',
        userAgent: 'HeadlessChrome',
        ja3: 'e7d705a3286e19ea42f587b344ee6865',
        ja4: 't13d1516h2_8daaf6152771_b0da82dd1658',
        asn: 'AS13335',
        httpVersion: 'HTTP/2',
        tlsVersion: 'TLS 1.3',
        ipVersion: 'IPv6',
        contentType: 'application/json',
        statusCode: '403',
        statusClass: '4xx'
    };
    if (operator) {
        const current = operator.value;
        operator.innerHTML = securityFilterOperatorsForField(field)
            .map(item => `<option value="${escapeAttr(item.value)}"${item.disabled ? ' disabled' : ''}>${escapeHtml(item.label)}</option>`)
            .join('');
        const currentStillValid = Array.from(operator.options).some(option => option.value === current && !option.disabled);
        operator.value = currentStillValid ? current : operator.options[0]?.value || 'equals';
        operator.disabled = operator.options.length <= 1;
    }
    if (value)
        value.placeholder = placeholders[field] || 'value';
}
function securityFilterOperatorsForField(field) {
    const equality = [
        { value: 'equals', label: 'equals' },
        { value: 'in', label: 'is in' }
    ];
    const text = [
        { value: 'contains', label: 'contains' },
        { value: 'equals', label: 'equals' },
        { value: 'in', label: 'is in' },
        { value: 'starts_with', label: 'starts with' },
        { value: 'ends_with', label: 'ends with' }
    ];
    if (field === 'statusCode' || field === 'statusClass' || field === 'asn' || field === 'httpVersion' || field === 'tlsVersion' || field === 'ipVersion' || field === 'contentType')
        return equality;
    if (field === 'path' || field === 'host' || field === 'route' || field === 'upstream' || field === 'requestId' || field === 'userAgent' || field === 'ja3' || field === 'ja4')
        return text;
    return equality;
}
function applySecurityFilterBuilder() {
    const field = AdminDOM.selectValue('security-filter-field', 'path');
    const operator = AdminDOM.selectValue('security-filter-operator', 'equals');
    const rawValue = AdminDOM.inputValue('security-filter-value', '').trim();
    if (!rawValue)
        return;
    applySecurityAnalyticsFilter(field, normalizeSecurityFilterValue(field, rawValue, operator), false);
    hideSecurityFilterBuilder();
}
function normalizeSecurityFilterValue(field, value, operator = 'equals') {
    const firstValue = operator === 'in' ? value.split(',').map(item => item.trim()).filter(Boolean)[0] || value : value;
    if (field === 'method' || field === 'country')
        return firstValue.toUpperCase();
    if (field === 'asn')
        return firstValue.toUpperCase().startsWith('AS') ? firstValue.toUpperCase() : `AS${firstValue}`;
    if (field === 'ipVersion')
        return firstValue.toLowerCase() === 'ipv6' ? 'IPv6' : 'IPv4';
    if (field === 'contentType')
        return firstValue.toLowerCase();
    if (field === 'statusClass')
        return firstValue.toLowerCase();
    return firstValue;
}
function applySecurityAnalyticsFilter(key, value, toggle = true) {
    if (!key || !value)
        return;
    const inputMap = {
        country: 'analytics-country-filter',
        ip: 'analytics-ip-filter',
        path: 'analytics-path-filter',
        host: 'analytics-host-filter',
        route: 'analytics-route-filter',
        upstream: 'analytics-upstream-filter',
        requestId: 'analytics-request-id-filter',
        userAgent: 'analytics-user-agent-filter',
        ja3: 'analytics-ja3-filter',
        ja4: 'analytics-ja4-filter',
        asn: 'analytics-asn-filter',
        httpVersion: 'analytics-http-version-filter',
        tlsVersion: 'analytics-tls-version-filter',
        ipVersion: 'analytics-ip-version-filter',
        contentType: 'analytics-content-type-filter',
        statusCode: 'analytics-status-filter'
    };
    const selectMap = {
        statusClass: 'analytics-status-class-filter',
        method: 'analytics-method-filter'
    };
    if (selectMap[key]) {
        const current = AdminDOM.selectValue(selectMap[key], '');
        setSelectValue(selectMap[key], toggle && current === value ? '' : value);
        return;
    }
    const inputId = inputMap[key];
    if (!inputId)
        return;
    const input = AdminDOM.getById(inputId);
    if (input) {
        input.value = toggle && input.value === value ? '' : value;
    }
}
function setSelectValue(id, value) {
    const select = AdminDOM.getById(id);
    if (select)
        select.value = value;
}
function responseClassItems(summary) {
    return [
        { status_class: '2xx', count: Number(summary.status_2xx || 0) },
        { status_class: '3xx', count: Number(summary.status_3xx || 0) },
        { status_class: '4xx', count: Number(summary.status_4xx || 0) },
        { status_class: '5xx', count: Number(summary.status_5xx || 0) }
    ];
}
function responseClassLabel(value) {
    const labels = { '2xx': 'Successful', '3xx': 'Redirects', '4xx': 'Client errors', '5xx': 'Server errors' };
    return `${value} ${labels[value] || 'Other'}`;
}
function responseClassTone(value) {
    const tones = { '2xx': 'allow', '3xx': 'log', '4xx': 'challenge', '5xx': 'block' };
    return tones[value] || 'log';
}
function countSecurityAnalyticsFilters(filters) {
    return [
        filters.statusClass,
        filters.method,
        filters.country,
        filters.ip,
        filters.path,
        filters.host,
        filters.route,
        filters.upstream,
        filters.requestId,
        filters.userAgent,
        filters.ja3,
        filters.ja4,
        filters.asn,
        filters.httpVersion,
        filters.tlsVersion,
        filters.ipVersion,
        filters.contentType,
        filters.statusCode
    ].filter(Boolean).length;
}
function labelForOption(selectId, value) {
    const select = AdminDOM.getById(selectId);
    return select?.querySelector(`option[value="${CSS.escape(value)}"]`)?.textContent || value;
}
function formatBucket(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime()))
        return value;
    return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function formatEventTime(value) {
    if (!value)
        return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime()))
        return value;
    return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function formatEventDateTime(value) {
    if (!value)
        return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime()))
        return value;
    return date.toLocaleString();
}
function formatNumberValue(value) {
    return new Intl.NumberFormat().format(Number(value || 0));
}
function sectionLabel(value) {
    const labels = {
        waf_core: 'Application Firewall',
        bot_protection: 'Bot Protection',
        traffic_control: 'Traffic Control',
        access_control: 'Edge Access',
        api_security: 'API Security',
        http_security: 'Application Security',
        security_rules: 'Security Rules',
        bot: 'Bot Protection',
        waf: 'Application Firewall',
        api: 'API Security',
        http: 'Application Security'
    };
    return labels[value] || labelize(value);
}
function actionLabel(action) {
    const labels = {
        allow: 'Allow',
        block: 'Block',
        challenge: 'Challenge',
        log: 'Log',
        detect: 'Detect',
        rate_limit: 'Rate Limit',
        redirect: 'Redirect'
    };
    return labels[action] || labelize(action || 'unknown');
}
export function openSecurityRuleModal(rule, options = {}) {
    activeEditorOptions = options;
    const container = AdminDOM.getById(options.containerId || 'security-rules-content');
    if (!container)
        return;
    const editing = Boolean(rule?.id);
    const typeLocked = Boolean(options.lockType);
    const hideLockedType = typeLocked && Boolean(options.hideLockedType);
    const blankCreate = !editing && Boolean(options.blankCreate);
    const type = rule?.type || options.defaults?.type || defaultRuleType;
    const defaultRule = {
        name: defaultNameForType(type),
        description: '',
        enabled: true,
        priority: 100,
        type,
        section: sectionForType(type),
        phase: defaultPhaseForType(type),
        mode: 'visual',
        expression: defaultExpressionForType(type),
        action: type === 'rate_limit' ? 'rate_limit' : type === 'custom' ? 'log' : 'block'
    };
    const current = {
        ...defaultRule,
        ...(options.defaults || {}),
        ...(rule || {})
    };
    if (blankCreate) {
        current.name = '';
        current.description = '';
        current.expression = '';
    }
    const excludeGoodBots = botScopeExcluded(current, 'good');
    const excludeAICrawlers = botScopeExcluded(current, 'ai');
    builderMode = 'visual';
    const isBotEditor = (options.editorClass || '').split(/\s+/).includes('security-rule-builder-bot');
    const initialConditions = blankCreate
        ? [{ joiner: 'and', field: isBotEditor ? '' : defaultFieldForType(current.type), operator: isBotEditor ? '' : defaultOperatorForField(defaultFieldForType(current.type)), value: '' }]
        : expressionToConditions(current.expression, current.type);
    const scopeLabel = options.scopeLabel || sectionForType(current.type);
    const title = escapeHtml(options.title || (editing ? current.name || defaultNameForType(type) : 'Custom rule'));
    const eyebrow = options.eyebrow || (editing ? 'Edit custom rule' : 'Create custom rule');
    const shellClass = [
        'security-rule-builder',
        options.editorClass || '',
        isBotEditor ? 'security-rule-builder-operator' : 'card',
        'mb-16'
    ].filter(Boolean).join(' ');
    const typeControl = hideLockedType
        ? `<div class="security-rule-scope-lock">
          <span class="text-xs text-muted text-uc">Scope</span>
          <strong>${escapeHtml(scopeLabel)}</strong>
          <select id="security-rule-type" class="hidden" aria-hidden="true" tabindex="-1">${typeOptions.map(([value, label]) => `<option value="${value}" ${current.type === value ? 'selected' : ''}>${label}</option>`).join('')}</select>
        </div>`
        : `<label class="form-group">Rule type<select id="security-rule-type" ${typeLocked ? 'disabled' : ''}>${typeOptions.map(([value, label]) => `<option value="${value}" ${current.type === value ? 'selected' : ''}>${label}</option>`).join('')}</select>${typeLocked ? '<span class="text-xs text-muted mt-4">Managed by this section</span>' : ''}</label>`;
    const hiddenTypeControl = `<select id="security-rule-type" class="hidden" aria-hidden="true" tabindex="-1">${typeOptions.map(([value, label]) => `<option value="${value}" ${current.type === value ? 'selected' : ''}>${label}</option>`).join('')}</select>`;
    const descriptionControl = isBotEditor
        ? `<input id="security-rule-description" type="hidden" value="${escapeAttr(current.description || '')}">`
        : `<label class="form-group">Description<input id="security-rule-description" value="${escapeAttr(current.description || '')}" placeholder="Optional note"></label>`;
    const ruleMetaControls = isBotEditor
        ? `<div class="security-rule-priority-row">
          ${hiddenTypeControl}
          <label class="form-group">Priority<input id="security-rule-priority" type="number" min="1" value="${current.priority}"></label>
        </div>`
        : `<div class="grid-2 gap-12">
          ${typeControl}
          <label class="form-group">Priority<input id="security-rule-priority" type="number" min="1" value="${current.priority}"></label>
        </div>`;
    const previewMarkup = `
            <div class="security-rule-expression-preview security-rule-cf-preview ${isBotEditor ? 'security-rule-preview-bottom' : ''}">
              <div class="security-rule-preview-head">
                <span class="text-xs text-muted text-uc">Rule Preview</span>
                ${isBotEditor ? '' : `
                <div class="flex-row gap-8">
                  <button type="button" class="btn btn-outline btn-sm" data-action="use-expression-builder">Use rule builder</button>
                  <button type="button" class="btn btn-outline btn-sm" data-action="use-expression-editor">Edit rule</button>
                </div>`}
              </div>
              <code id="security-rule-preview">${escapeHtml(current.expression)}</code>
            </div>`;
    container.innerHTML = `
    <div class="${escapeAttr(shellClass)}">
      <div class="card-header security-rule-builder-head">
        <div>
          <div class="security-rule-eyebrow">${escapeHtml(eyebrow)}</div>
          <h3>${title}</h3>
        </div>
        ${SectionUI.renderSwitch({
        id: 'security-rule-enabled',
        checked: current.enabled
    })}
      </div>
      <form class="card-body security-rule-form security-rule-cf-form">
        <section class="security-rule-cf-section">
          <div class="security-rule-cf-step">1</div>
          <div class="security-rule-cf-content">
            <div class="security-rule-cf-title">${isBotEditor ? 'Rule details' : 'Rule name'}</div>
            <label class="form-group">Rule name<input id="security-rule-name" value="${escapeAttr(current.name)}" placeholder="${escapeAttr(defaultNameForType(type))}" required></label>
            ${descriptionControl}
            ${ruleMetaControls}
          </div>
        </section>

        <section class="security-rule-cf-section">
          <div class="security-rule-cf-step">2</div>
          <div class="security-rule-cf-content">
            <div class="security-rule-cf-title-row">
              <div>
                <div class="security-rule-cf-title">When incoming requests match</div>
              </div>
            </div>
            ${isBotEditor ? '' : previewMarkup}
            <div id="security-rule-builder-panel" class="security-rule-condition-card">
              <div class="security-rule-condition-head">
                <div>
                  <strong>Rule Builder</strong>
                </div>
                <button type="button" class="btn btn-outline btn-sm" data-action="add-security-rule-condition">Add Condition</button>
              </div>
              <div id="security-rule-conditions" class="security-rule-conditions">
                ${initialConditions.map((condition, index) => renderConditionRow(condition, index, current.type)).join('')}
              </div>
              <div class="security-rule-builder-actions ${isBotEditor ? 'hidden' : ''}">
                <button type="button" class="btn btn-outline btn-sm" data-action="apply-visual-expression">Sync rule</button>
              </div>
            </div>
            <div id="security-rule-editor-panel" class="security-rule-code-panel hidden">
              <label class="form-group security-rule-code-group">Rule Editor<textarea id="security-rule-expression" class="security-rule-code-input" rows="7" spellcheck="false" required>${escapeHtml(current.expression)}</textarea></label>
            </div>
            <div class="security-rule-validation-actions ${isBotEditor ? 'hidden' : ''}">
              <button type="button" class="btn btn-outline btn-sm" data-action="validate-security-rule">Validate rule</button>
            </div>
            <div id="security-rule-validation" class="security-rule-test-result hidden"></div>
          </div>
        </section>

        <section class="security-rule-cf-section">
          <div class="security-rule-cf-step">3</div>
          <div class="security-rule-cf-content">
            <div class="security-rule-cf-title">Then take action</div>
            <label class="form-group">Choose action<select id="security-rule-action">${actionOptions.map(action => `<option value="${action}" ${current.action === action ? 'selected' : ''}>${labelize(action)}</option>`).join('')}</select></label>
            ${renderActionParams(current)}
            ${isBotEditor ? `
            <div class="security-rule-targeting-panel">
              <div class="security-rule-pane-title">Exceptions</div>
              <div class="text-xs text-muted mb-12">Optionally exempt trusted bot categories from this rule.</div>
            <div class="security-rule-bot-scope">
              <label class="security-rule-bot-scope-item">
                <div class="security-rule-bot-scope-check">
                  <input type="checkbox" id="security-rule-apply-good-bots" ${excludeGoodBots ? 'checked' : ''}>
                  <span class="security-rule-bot-scope-box"></span>
                </div>
                <div class="security-rule-bot-scope-body">
                  <div class="security-rule-bot-scope-label">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    Exclude verified good bots
                  </div>
                  <div class="security-rule-bot-scope-hint">Googlebot, Bingbot, and other allowlisted crawlers will bypass this rule.</div>
                </div>
              </label>
              <label class="security-rule-bot-scope-item">
                <div class="security-rule-bot-scope-check">
                  <input type="checkbox" id="security-rule-apply-ai-crawlers" ${excludeAICrawlers ? 'checked' : ''}>
                  <span class="security-rule-bot-scope-box"></span>
                </div>
                <div class="security-rule-bot-scope-body">
                  <div class="security-rule-bot-scope-label">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/><circle cx="9" cy="10" r="1"/><circle cx="15" cy="10" r="1"/><path d="M9 13s1 1 3 1 3-1 3-1"/></svg>
                    Exclude AI crawlers
                  </div>
                  <div class="security-rule-bot-scope-hint">GPTBot, ClaudeBot, PerplexityBot, and other AI training crawlers will bypass this rule.</div>
                </div>
              </label>
            </div>
            </div>
            ` : ''}
          </div>
        </section>

        ${isBotEditor ? `
        <section class="security-rule-preview-section">
            <div class="security-rule-cf-title">Review rule</div>
            ${previewMarkup}
        </section>
        ` : ''}

      </form>
      <div class="card-footer security-rule-footer">
        <span class="text-muted text-xs">Rules are validated before deployment.</span>
        <div class="flex-row gap-8 justify-end">
          <button type="button" class="btn btn-outline" data-action="close-security-rule-editor">Cancel</button>
          <button type="button" class="btn btn-outline" data-action="save-security-rule" data-rule-id="${current.id || ''}" data-save-mode="draft">Save as Draft</button>
          <button type="button" class="btn btn-primary" data-action="save-security-rule" data-rule-id="${current.id || ''}">${editing ? 'Deploy changes' : 'Deploy'}</button>
        </div>
      </div>
    </div>
  `;
    updateRuleEditorState();
    if (!blankCreate) {
        syncExpressionFromConditions(false);
    }
    updateRuleBuilderModeUI();
    updateRulePreview();
}
export async function saveSecurityRule(id, draft = false) {
    const rule = readRuleFromEditor();
    if (activeEditorOptions.requireExplicitName && !rule.name.trim()) {
        notify('Add a rule name before deploying', 'error');
        return;
    }
    if (draft)
        rule.enabled = false;
    const apiBase = activeEditorOptions.apiBase || 'v2/security/bot/rules';
    const validation = await api.post(`${apiBase}/validate`, { expression: rule.expression, rule });
    if (rule.enabled && validation && !validation.valid) {
        renderValidation(validation);
        notify('Fix the rule before enabling it', 'error');
        return;
    }
    try {
        const result = id ? await api.put(`${apiBase}/${id}`, rule) : await api.post(apiBase, rule);
        if (!result)
            return;
        notify(draft ? 'Security rule saved as draft' : id ? 'Security rule deployed' : 'Security rule deployed', 'success');
        if (activeEditorOptions.onSaved) {
            await activeEditorOptions.onSaved();
            activeEditorOptions = {};
            return;
        }
    }
    catch (error) {
        notify(getErrorMessage(error, 'Failed to save security rule'), 'error');
    }
}
export async function closeSecurityRuleEditor() {
    if (activeEditorOptions.onCancel) {
        await activeEditorOptions.onCancel();
        activeEditorOptions = {};
        return;
    }
    const container = AdminDOM.getById(activeEditorOptions.containerId || 'security-rules-content');
    if (container)
        container.innerHTML = '';
    activeEditorOptions = {};
}
export function applyVisualExpression() {
    syncExpressionFromConditions(true);
}
export function addSecurityRuleCondition(condition) {
    const container = AdminDOM.getById('security-rule-conditions');
    if (!container)
        return;
    const type = AdminDOM.selectValue('security-rule-type', defaultRuleType);
    const rowCount = container.querySelectorAll('.security-rule-condition-row').length;
    const field = condition?.field ?? (isBotRuleEditor() ? '' : defaultFieldForType(type));
    const next = {
        joiner: rowCount === 0 ? 'and' : condition?.joiner || 'and',
        field,
        operator: condition?.operator || (field ? defaultOperatorForField(field) : ''),
        value: condition?.value || (field ? defaultValueForField(field, type) : '')
    };
    container.insertAdjacentHTML('beforeend', renderConditionRow(next, rowCount, type));
    syncExpressionFromConditions(true);
}
export function removeSecurityRuleCondition(index) {
    const row = AdminDOM.query(`[data-condition-index="${CSS.escape(index)}"]`);
    if (row)
        row.remove();
    reindexConditionRows();
    if (!AdminDOM.query('.security-rule-condition-row'))
        addSecurityRuleCondition();
    syncExpressionFromConditions(true);
}
export function updateSecurityRuleConditionControl(target) {
    const row = target.closest('.security-rule-condition-row');
    if (!(row instanceof HTMLElement))
        return;
    const type = AdminDOM.selectValue('security-rule-type', defaultRuleType);
    if (target instanceof HTMLInputElement && target.classList.contains('security-rule-field-search')) {
        const displayInput = target;
        const hiddenField = row.querySelector('.security-rule-condition-field');
        filterSecurityRuleFieldOptions(displayInput);
        setSecurityRuleFieldMenuOpen(displayInput.closest('.security-rule-field-dropdown'), true);
        const match = selectableFieldOptions(type, hiddenField?.value || defaultFieldForType(type))
            .find(field => field.label.toLowerCase() === displayInput.value.trim().toLowerCase() || field.name.toLowerCase() === displayInput.value.trim().toLowerCase());
        if (!match) {
            return;
        }
        displayInput.value = match.label;
        if (hiddenField)
            hiddenField.value = match.name;
        target = hiddenField || target;
    }
    const fieldSelect = row.querySelector('.security-rule-condition-field');
    const operatorSelect = row.querySelector('.security-rule-condition-operator');
    if (target === fieldSelect && fieldSelect) {
        if (operatorSelect)
            operatorSelect.innerHTML = operatorOptions(fieldSelect.value, defaultOperatorForField(fieldSelect.value));
        const valueShell = row.querySelector('.security-rule-condition-value-shell');
        const nextValue = isBotRuleEditor() ? '' : defaultValueForField(fieldSelect.value, type);
        if (valueShell)
            valueShell.innerHTML = `Value${renderValueControl(fieldSelect.value, nextValue, row.dataset.conditionIndex || '0', operatorSelect?.value || defaultOperatorForField(fieldSelect.value))}`;
    }
    else if (target === operatorSelect) {
        const fieldValue = fieldSelect?.value || (isBotRuleEditor() ? '' : defaultFieldForType(type));
        const valueShell = row.querySelector('.security-rule-condition-value-shell');
        if (valueShell)
            valueShell.innerHTML = `Value${renderValueControl(fieldValue, readSingleConditionValue(row), row.dataset.conditionIndex || '0', operatorSelect?.value || defaultOperatorForField(fieldValue))}`;
    }
    updateRulePreview();
    if ((target === fieldSelect || target === operatorSelect) && isBotRuleEditor() && !readSingleConditionValue(row).trim()) {
        syncExpressionPreviewFromConditions();
        clearRuleValidation();
        return;
    }
    syncExpressionFromConditions(true);
}
export function chooseSecurityRuleType(type) {
    const select = AdminDOM.getSelect('security-rule-type');
    if (select)
        select.value = type;
    const action = AdminDOM.getSelect('security-rule-action');
    if (action)
        action.value = type === 'rate_limit' ? 'rate_limit' : type === 'custom' ? 'log' : 'block';
    const expression = AdminDOM.getTextarea('security-rule-expression');
    if (expression)
        expression.value = defaultExpressionForType(type);
    const name = AdminDOM.getInput('security-rule-name');
    if (name && (!name.value || name.value === 'Custom rule'))
        name.value = defaultNameForType(type);
    renderConditionRows(expressionToConditions(defaultExpressionForType(type), type), type);
    updateRuleEditorState();
    syncExpressionFromConditions(false);
    updateRulePreview();
}
export async function validateSecurityRule(showToast = true) {
    const rule = readRuleFromEditor();
    const apiBase = activeEditorOptions.apiBase || 'v2/security/bot/rules';
    const response = await api.post(`${apiBase}/validate`, { expression: rule.expression, rule });
    if (!response)
        return;
    renderValidation(response);
    if (showToast)
        notify(response.valid ? 'No issues found' : 'Rule needs changes', response.valid ? 'success' : 'error');
}
export function updateRulePreview() {
    const preview = AdminDOM.getById('security-rule-preview');
    if (preview)
        preview.textContent = AdminDOM.textareaValue('security-rule-expression');
}
export function setSecurityRuleRawMode() {
    builderMode = 'raw';
    updateRuleBuilderModeUI();
}
export function useExpressionEditor() {
    builderMode = 'raw';
    updateRuleBuilderModeUI();
}
export function useExpressionBuilder() {
    const type = AdminDOM.selectValue('security-rule-type', defaultRuleType);
    renderConditionRows(expressionToConditions(AdminDOM.textareaValue('security-rule-expression'), type), type);
    syncExpressionFromConditions(false);
    builderMode = 'visual';
    updateRuleBuilderModeUI();
}
export function updateRuleEditorState() {
    const action = AdminDOM.selectValue('security-rule-action', 'log');
    AdminDOM.queryAll('.security-rule-action-panel').forEach(panel => {
        if (panel instanceof HTMLElement)
            panel.classList.toggle('hidden', panel.dataset.actionPanel !== action);
    });
}
export function insertRuleField(field) {
    const select = AdminDOM.query('.security-rule-condition-field');
    if (select)
        select.value = field;
    const display = select?.closest('.security-rule-condition-row')?.querySelector('.security-rule-field-search');
    if (display)
        display.value = fieldLabel(field);
    if (select)
        updateSecurityRuleConditionControl(select);
}
export function toggleSecurityRuleFieldMenu(target) {
    const dropdown = target.closest('.security-rule-field-dropdown');
    if (!(dropdown instanceof HTMLElement))
        return;
    setSecurityRuleFieldMenuOpen(dropdown, !dropdown.classList.contains('is-open'));
    const input = dropdown.querySelector('.security-rule-field-search');
    if (input) {
        filterSecurityRuleFieldOptions(input);
        input.focus();
        input.select();
    }
}
export function openSecurityRuleFieldMenu(target) {
    const dropdown = target.closest('.security-rule-field-dropdown');
    if (!(dropdown instanceof HTMLElement))
        return;
    const input = dropdown.querySelector('.security-rule-field-search');
    if (input)
        filterSecurityRuleFieldOptions(input);
    setSecurityRuleFieldMenuOpen(dropdown, true);
}
export function closeSecurityRuleFieldMenus() {
    AdminDOM.queryAll('.security-rule-field-dropdown.is-open').forEach(dropdown => {
        setSecurityRuleFieldMenuOpen(dropdown, false);
    });
}
export function chooseSecurityRuleField(source) {
    const dropdown = source.closest('.security-rule-field-dropdown');
    if (!(dropdown instanceof HTMLElement))
        return;
    const field = source.dataset.field || defaultFieldForType(AdminDOM.selectValue('security-rule-type', defaultRuleType));
    const input = dropdown.querySelector('.security-rule-field-search');
    const hidden = dropdown.querySelector('.security-rule-condition-field');
    if (input)
        input.value = fieldLabel(field);
    if (hidden)
        hidden.value = field;
    setSecurityRuleFieldMenuOpen(dropdown, false);
    updateSecurityRuleConditionControl(hidden || source);
}
function readRuleFromEditor() {
    const defaults = activeEditorOptions.defaults || {};
    const type = AdminDOM.selectValue('security-rule-type', defaults.type || 'custom');
    const name = AdminDOM.inputValue('security-rule-name', activeEditorOptions.requireExplicitName ? '' : defaultNameForType(type));
    const expression = applyBotScopeToExpression(AdminDOM.textareaValue('security-rule-expression'), type);
    return {
        name,
        description: AdminDOM.inputValue('security-rule-description'),
        enabled: AdminDOM.checkboxValue('security-rule-enabled', true),
        priority: AdminDOM.numberValue('security-rule-priority', 100),
        type,
        section: defaults.section || sectionForType(type),
        phase: defaults.phase || defaultPhaseForType(type),
        source: defaults.source || 'unified',
        mode: builderMode,
        expression,
        action: AdminDOM.selectValue('security-rule-action', 'log'),
        action_params: readActionParams()
    };
}
function applyBotScopeToExpression(expression, type) {
    if (type !== 'bot' || !isBotRuleEditor())
        return expression;
    const clauses = [];
    const excludeGoodBots = AdminDOM.checkboxValue('security-rule-apply-good-bots', false);
    const excludeAICrawlers = AdminDOM.checkboxValue('security-rule-apply-ai-crawlers', false);
    if (excludeGoodBots)
        clauses.push('aegis.bot.verified ne true');
    if (excludeAICrawlers)
        clauses.push('aegis.bot.category ne "ai_crawler"');
    const base = expression.trim();
    if (!clauses.length || !base)
        return base;
    const normalized = base.toLowerCase();
    const missingClauses = clauses.filter(clause => !normalized.includes(clause.toLowerCase()));
    if (!missingClauses.length)
        return base;
    return `(${base}) and ${missingClauses.join(' and ')}`;
}
function botScopeExcluded(rule, scope) {
    const legacyValue = rule[scope === 'good' ? 'apply_to_good_bots' : 'apply_to_ai_crawlers'];
    if (legacyValue === false)
        return true;
    const expression = (rule.expression || '').toLowerCase();
    return scope === 'good'
        ? expression.includes('aegis.bot.verified ne true')
        : expression.includes('aegis.bot.category ne "ai_crawler"');
}
function renderActionParams(rule) {
    const params = rule.action_params || {};
    return `
    <div class="security-rule-action-panel ${rule.action === 'block' ? '' : 'hidden'}" data-action-panel="block">
      <div class="security-rule-pane-title">Custom response</div>
      <div class="grid-3 gap-12">
        <label class="form-group">Response type<select id="security-rule-param-response-type">
          ${['default', 'text/plain', 'text/html', 'application/json', 'application/xml'].map(value => `<option value="${value}" ${params.response_type === value ? 'selected' : ''}>${value === 'default' ? 'Default block response' : value}</option>`).join('')}
        </select></label>
        <label class="form-group">Response code<input id="security-rule-param-response-code" type="number" min="400" max="499" value="${escapeAttr(params.response_code || '403')}"></label>
        <label class="form-group">Body<input id="security-rule-param-response-body" value="${escapeAttr(params.response_body || '')}" placeholder="Optional body"></label>
      </div>
    </div>
    <div class="security-rule-action-panel ${rule.action === 'rate_limit' ? '' : 'hidden'}" data-action-panel="rate_limit">
      <div class="security-rule-pane-title">Rate Limit</div>
      <div class="grid-3 gap-12">
        <label class="form-group">Rate<input id="security-rule-param-rate" type="number" min="1" value="${escapeAttr(params.rate || '60')}"></label>
        <label class="form-group">Burst<input id="security-rule-param-burst" type="number" min="1" value="${escapeAttr(params.burst || '10')}"></label>
        <label class="form-group">Window<input id="security-rule-param-window" value="${escapeAttr(params.window || '60s')}"></label>
      </div>
    </div>
    <div class="security-rule-action-panel ${rule.action === 'redirect' ? '' : 'hidden'}" data-action-panel="redirect">
      <div class="security-rule-pane-title">Redirect</div>
      <label class="form-group">Location<input id="security-rule-param-location" value="${escapeAttr(params.location || '/')}"></label>
    </div>
  `;
}
function renderValidation(response) {
    const target = AdminDOM.getById('security-rule-validation');
    if (!target)
        return;
    const issues = [...(response.errors || []).map(error => error.message), ...(response.warnings || [])];
    if (response.valid) {
        target.classList.add('hidden');
        target.innerHTML = '';
    }
    else {
        target.classList.remove('hidden');
        target.innerHTML = `<span class="text-danger">Rule needs changes</span>${issues.map(issue => `<div class="text-xs mt-8">${escapeHtml(issue)}</div>`).join('')}`;
    }
    const preview = AdminDOM.getById('security-rule-preview');
    if (preview)
        preview.textContent = response.normalized_expression || AdminDOM.textareaValue('security-rule-expression');
}
function renderConditionRows(conditions, type) {
    const container = AdminDOM.getById('security-rule-conditions');
    if (!container)
        return;
    container.innerHTML = conditions.map((condition, index) => renderConditionRow(condition, index, type)).join('');
    builderMode = 'visual';
}
function renderConditionRow(condition, index, type) {
    const field = condition.field || (isBotRuleEditor() ? '' : defaultFieldForType(type));
    const operator = condition.operator || (field ? defaultOperatorForField(field) : '');
    return `
    <div class="security-rule-condition-row" data-condition-index="${index}">
      <div class="security-rule-condition-joiner">
        ${index === 0 ? '<span class="status-pill">When</span>' : `<select class="select-sm security-rule-condition-join"><option value="and" ${condition.joiner === 'and' ? 'selected' : ''}>AND</option><option value="or" ${condition.joiner === 'or' ? 'selected' : ''}>OR</option></select>`}
      </div>
      ${renderFieldControl(type, field, index)}
      <label class="form-group security-rule-condition-operator-shell">Operator<select class="security-rule-condition-operator">${operatorOptions(field, operator)}</select></label>
      <label class="form-group security-rule-condition-value-shell">Value${renderValueControl(field, condition.value, String(index), operator)}</label>
      <button type="button" class="btn btn-outline btn-sm security-rule-condition-remove" data-action="remove-security-rule-condition" data-condition-index="${index}" aria-label="Remove condition" title="Remove condition">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v5"/><path d="M14 11v5"/></svg>
        <span>Remove</span>
      </button>
    </div>
  `;
}
function renderFieldControl(type, selectedField, _index) {
    if (isBotRuleEditor()) {
        const options = selectableFieldOptions(type, selectedField);
        return `
      <label class="form-group security-rule-field-combobox">Field
        <div class="security-rule-field-dropdown">
          <div class="security-rule-field-search-wrap">
            <input class="security-rule-field-search" value="${selectedField ? escapeAttr(fieldLabel(selectedField)) : ''}" placeholder="Choose a field" autocomplete="off" role="combobox" aria-expanded="false">
            <button type="button" class="security-rule-field-toggle" data-action="toggle-security-rule-field-menu" aria-label="Open field options">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
            </button>
          </div>
          <input type="hidden" class="security-rule-condition-field" value="${escapeAttr(selectedField)}">
          <div class="security-rule-field-menu" role="listbox">
            <div class="security-rule-field-menu-head">Select request field</div>
            ${fieldDropdownOptions(options, selectedField)}
            <div class="security-rule-field-empty hidden">No matching fields</div>
          </div>
        </div>
      </label>`;
    }
    return `<label class="form-group">Field<select class="security-rule-condition-field">${fieldOptions(type, selectedField)}</select></label>`;
}
function fieldDropdownOptions(options, selectedField) {
    const sectionLabels = {
        bot: 'Bot signals',
        geo_ip: 'Geo and IP',
        waf: 'Request',
        api: 'API',
        http_security: 'TLS and headers',
        access: 'Access'
    };
    const sectionOrder = ['bot', 'geo_ip', 'waf', 'api', 'http_security', 'access'];
    return sectionOrder
        .filter(group => options.some(field => field.section === group))
        .map(group => `
      <div class="security-rule-field-group" data-field-group="${escapeAttr(group)}">
        <div class="security-rule-field-group-label">${escapeHtml(sectionLabels[group] || labelize(group))}</div>
        ${options
        .filter(field => field.section === group)
        .map(field => `<button type="button" class="security-rule-field-option ${field.name === selectedField ? 'is-selected' : ''}" data-action="choose-security-rule-field" data-field="${escapeAttr(field.name)}" data-label="${escapeAttr(field.label)}" role="option" aria-selected="${field.name === selectedField ? 'true' : 'false'}">
            <span class="security-rule-field-option-label">${escapeHtml(field.label)}</span>
            <code>${escapeHtml(field.name)}</code>
          </button>`)
        .join('')}
      </div>`)
        .join('');
}
function setSecurityRuleFieldMenuOpen(dropdown, open) {
    if (!(dropdown instanceof HTMLElement))
        return;
    AdminDOM.queryAll('.security-rule-field-dropdown.is-open').forEach(item => {
        if (item !== dropdown)
            setSecurityRuleFieldMenuOpen(item, false);
    });
    dropdown.classList.toggle('is-open', open);
    const input = dropdown.querySelector('.security-rule-field-search');
    if (input)
        input.setAttribute('aria-expanded', open ? 'true' : 'false');
}
function filterSecurityRuleFieldOptions(input) {
    const dropdown = input.closest('.security-rule-field-dropdown');
    if (!(dropdown instanceof HTMLElement))
        return;
    const query = input.value.trim().toLowerCase();
    let visibleCount = 0;
    dropdown.querySelectorAll('.security-rule-field-option').forEach(option => {
        const haystack = `${option.dataset.label || ''} ${option.dataset.field || ''}`.toLowerCase();
        const visible = !query || haystack.includes(query);
        option.classList.toggle('hidden', !visible);
        if (visible)
            visibleCount += 1;
    });
    dropdown.querySelectorAll('.security-rule-field-group').forEach(group => {
        group.classList.toggle('hidden', !group.querySelector('.security-rule-field-option:not(.hidden)'));
    });
    dropdown.querySelector('.security-rule-field-empty')?.classList.toggle('hidden', visibleCount > 0);
}
function isBotRuleEditor() {
    return (activeEditorOptions.editorClass || '').split(/\s+/).includes('security-rule-builder-bot');
}
function fieldOptions(type, selected) {
    const selectedField = selected || defaultFieldForType(type);
    const mergedFields = selectableFieldOptions(type, selectedField);
    const sectionLabels = {
        bot: 'Bot signals',
        geo_ip: 'Geo and IP',
        waf: 'Request',
        api: 'API',
        http_security: 'TLS and headers',
        access: 'Access'
    };
    const sectionOrder = ['bot', 'geo_ip', 'waf', 'api', 'http_security', 'access'];
    return sectionOrder
        .filter(group => mergedFields.some(field => field.section === group))
        .map(group => {
        const options = mergedFields
            .filter(field => field.section === group)
            .map(field => `<option value="${escapeAttr(field.name)}" ${field.name === selectedField ? 'selected' : ''}>${escapeHtml(field.label)}</option>`)
            .join('');
        return `<optgroup label="${escapeAttr(sectionLabels[group] || labelize(group))}">${options}</optgroup>`;
    })
        .join('');
}
function selectableFieldOptions(type, selected) {
    const section = sectionForType(type);
    const selectedField = selected || defaultFieldForType(type);
    const allowedSections = activeEditorOptions.allowedFieldSections;
    const allowedNames = activeEditorOptions.allowedFieldNames;
    const fields = cachedFields.filter(field => {
        const sectionAllowed = allowedSections?.includes(field.section);
        const nameAllowed = allowedNames?.includes(field.name);
        if (sectionAllowed || nameAllowed || field.name === selectedField)
            return true;
        return field.section === section || type === 'custom';
    });
    const fallback = fieldSpec(selectedField);
    const optionFields = fields.length ? fields : cachedFields;
    return dedupeFields(fallback && !optionFields.some(field => field.name === fallback.name) ? [fallback, ...optionFields] : optionFields);
}
function dedupeFields(fields) {
    const seen = new Set();
    const result = [];
    fields.forEach(field => {
        if (seen.has(field.name))
            return;
        seen.add(field.name);
        result.push(field);
    });
    return result;
}
function operatorOptions(field, selected) {
    if (!field)
        return '<option value="" selected disabled>Select field first</option>';
    const spec = fieldSpec(field);
    const operators = spec?.operators?.length ? spec.operators : ['contains', 'eq', 'ne', 'starts_with', 'ends_with', 'matches', 'in', 'not in', 'gt', 'lt', 'ge', 'le'];
    const selectedOperator = selected || defaultOperatorForField(field);
    return operators
        .map(value => `<option value="${value}" ${value === selectedOperator ? 'selected' : ''}>${labelize(value)}</option>`)
        .join('');
}
function renderValueControl(field, rawValue, index, selectedOperator) {
    if (!field)
        return '<input class="security-rule-condition-value" value="" placeholder="Select a field first" disabled>';
    const spec = fieldSpec(field);
    const inputType = spec?.input_type || spec?.type || 'text';
    const operator = selectedOperator || AdminDOM.query(`[data-condition-index="${CSS.escape(index)}"] .security-rule-condition-operator`)?.value || defaultOperatorForField(field);
    const multi = operator === 'in' || operator === 'not in';
    const values = splitConditionValues(rawValue);
    if (inputType === 'country') {
        return `<select class="security-rule-condition-value" ${multi ? 'multiple size="5"' : ''}>${countryOptions.map(([code, label]) => `<option value="${code}" ${values.includes(code) ? 'selected' : ''}>${code} - ${escapeHtml(label)}</option>`).join('')}</select>`;
    }
    if (inputType === 'select' || inputType === 'boolean') {
        const options = spec?.options?.length ? spec.options : ['true', 'false'];
        return `<select class="security-rule-condition-value" ${multi ? 'multiple size="4"' : ''}>${options.map(option => `<option value="${escapeAttr(option)}" ${values.includes(option) ? 'selected' : ''}>${escapeHtml(option)}</option>`).join('')}</select>`;
    }
    const type = inputType === 'number' ? 'number' : 'text';
    const placeholder = spec?.placeholder || valuePlaceholder(AdminDOM.selectValue('security-rule-type', defaultRuleType));
    const hint = inputType === 'ip' ? '<div class="text-xs text-muted mt-4">Accepts a single IP, CIDR, or comma-separated list for in/not in.</div>' : field === 'tls.ja3' || field === 'tls.ja4' ? '<div class="text-xs text-muted mt-4">Paste the fingerprint exactly as observed.</div>' : '';
    return `<input class="security-rule-condition-value" type="${type}" value="${escapeAttr(rawValue)}" placeholder="${escapeAttr(placeholder)}">${hint}`;
}
function readSingleConditionValue(row) {
    const valueControl = row.querySelector('.security-rule-condition-value');
    if (valueControl instanceof HTMLSelectElement && valueControl.multiple) {
        return Array.from(valueControl.selectedOptions).map(option => option.value).join(',');
    }
    return valueControl?.value || '';
}
function readVisualConditions() {
    return AdminDOM.queryAll('.security-rule-condition-row').map((row, index) => {
        const field = row.querySelector('.security-rule-condition-field')?.value || (isBotRuleEditor() ? '' : defaultFieldForType(AdminDOM.selectValue('security-rule-type', defaultRuleType)));
        const operator = row.querySelector('.security-rule-condition-operator')?.value || (field ? defaultOperatorForField(field) : '');
        const valueControl = row.querySelector('.security-rule-condition-value');
        let value = '';
        if (valueControl instanceof HTMLSelectElement && valueControl.multiple) {
            value = Array.from(valueControl.selectedOptions).map(option => option.value).join(',');
        }
        else {
            value = valueControl?.value || '';
        }
        return {
            joiner: index === 0 ? 'and' : (row.querySelector('.security-rule-condition-join')?.value === 'or' ? 'or' : 'and'),
            field,
            operator,
            value
        };
    });
}
function syncExpressionFromConditions(showToast) {
    const textarea = AdminDOM.getTextarea('security-rule-expression');
    if (!textarea)
        return;
    const conditions = readVisualConditions();
    const invalid = clientConditionErrors(conditions);
    if (invalid.length) {
        renderClientValidation(invalid);
        if (showToast)
            notify(invalid[0], 'error');
        return;
    }
    textarea.value = conditionsToExpression(conditions);
    builderMode = 'visual';
    updateRulePreview();
    void validateSecurityRule(false);
}
function syncExpressionPreviewFromConditions() {
    const textarea = AdminDOM.getTextarea('security-rule-expression');
    if (!textarea)
        return;
    textarea.value = conditionsToExpression(readVisualConditions());
    builderMode = 'visual';
    updateRulePreview();
}
function clearRuleValidation() {
    const target = AdminDOM.getById('security-rule-validation');
    if (!target)
        return;
    target.classList.add('hidden');
    target.innerHTML = '';
}
function conditionsToExpression(conditions) {
    return conditions
        .filter(condition => condition.field && condition.operator && condition.value)
        .map((condition, index) => `${index > 0 ? `${condition.joiner} ` : ''}${condition.field} ${condition.operator} ${formatExpressionValue(condition.value, condition.operator)}`)
        .join(' ');
}
function expressionToConditions(expression, type) {
    const clean = expression.replace(/[()]/g, ' ').replace(/\s+/g, ' ').trim();
    const parts = clean.split(/\s+(and|or)\s+/i);
    const conditions = [];
    let joiner = 'and';
    for (const part of parts) {
        const lower = part.toLowerCase();
        if (lower === 'and' || lower === 'or') {
            joiner = lower;
            continue;
        }
        const match = part.match(/^(\S+)\s+(not in|starts_with|ends_with|contains|matches|eq|ne|gt|lt|ge|le|in)\s+(.+)$/i);
        if (!match)
            continue;
        conditions.push({ joiner: conditions.length ? joiner : 'and', field: match[1], operator: match[2].toLowerCase(), value: unformatExpressionValue(match[3]) });
    }
    return conditions.length ? conditions : [{ joiner: 'and', field: defaultFieldForType(type), operator: defaultOperatorForField(defaultFieldForType(type)), value: defaultValueForField(defaultFieldForType(type), type) }];
}
function readActionParams() {
    const action = AdminDOM.selectValue('security-rule-action', 'log');
    if (action === 'block')
        return {
            response_type: AdminDOM.selectValue('security-rule-param-response-type', 'default'),
            response_code: AdminDOM.inputValue('security-rule-param-response-code', '403'),
            response_body: AdminDOM.inputValue('security-rule-param-response-body', '')
        };
    if (action === 'rate_limit')
        return {
            rate: AdminDOM.inputValue('security-rule-param-rate', '60'),
            burst: AdminDOM.inputValue('security-rule-param-burst', '10'),
            window: AdminDOM.inputValue('security-rule-param-window', '60s')
        };
    if (action === 'redirect')
        return { location: AdminDOM.inputValue('security-rule-param-location', '/') };
    return undefined;
}
function updateRuleBuilderModeUI() {
    const builder = AdminDOM.getById('security-rule-builder-panel');
    const editor = AdminDOM.getById('security-rule-editor-panel');
    if (builder)
        builder.classList.toggle('hidden', builderMode === 'raw');
    if (editor)
        editor.classList.toggle('hidden', builderMode !== 'raw');
}
function defaultExpressionForType(type) {
    const defaults = {
        geo: 'ip.geoip.country eq "US"',
        ip_access: 'ip.src eq "203.0.113.10"',
        rate_limit: 'http.request.uri.path starts_with "/api/"',
        bot: 'aegis.bot.score lt 30',
        api: 'api.path starts_with "/api/"',
        waf: 'http.request.uri.path contains "/admin"',
        http_security: 'tls.version in {"TLS1.0" "TLS1.1"}',
        access: 'access.identity.role eq "guest"',
        custom: 'http.request.uri.path contains "/api/"'
    };
    return defaults[type] || defaults.custom;
}
function defaultFieldForType(type) {
    const defaults = {
        waf: 'http.request.uri.path',
        rate_limit: 'http.request.uri.path',
        bot: 'aegis.bot.score',
        geo: 'ip.geoip.country',
        ip_access: 'ip.src',
        api: 'api.path',
        http_security: 'tls.version',
        access: 'access.identity.role',
        custom: 'http.request.uri.path'
    };
    return defaults[type] || defaults.custom;
}
function defaultOperatorForField(field) {
    const spec = fieldSpec(field);
    if (spec?.input_type === 'number' || spec?.type === 'number')
        return spec.operators.includes('lt') ? 'lt' : 'eq';
    if (field === 'ip.geoip.country' || field === 'ip.src' || field === 'tls.version' || field === 'http.request.method')
        return 'in';
    if (field.includes('path'))
        return 'starts_with';
    return spec?.operators?.includes('eq') ? 'eq' : spec?.operators?.[0] || 'contains';
}
function defaultValueForField(field, type) {
    const defaults = {
        'ip.geoip.country': 'US,TN',
        'ip.src': '203.0.113.10',
        'tls.ja3': 'abc123',
        'tls.ja4': 't13d1516h2_8daaf6152771_b0da82dd1658',
        'aegis.bot.score': '30',
        'ip.reputation.score': '50',
        'http.request.method': 'GET',
        'tls.version': 'TLS1.0,TLS1.1',
        'api.auth.valid': 'false',
        'aegis.bot.verified': 'false',
        'aegis.bot.headless': 'true'
    };
    return defaults[field] || valuePlaceholder(type);
}
function defaultNameForType(type) {
    const names = {
        geo: 'Block country',
        ip_access: 'Block IP address',
        rate_limit: 'Rate limit path',
        bot: 'Challenge suspicious bot',
        api: 'Protect API path',
        waf: 'Block risky request',
        http_security: 'Audit Application Security',
        access: 'Protect access role',
        custom: 'Custom rule'
    };
    return names[type] || names.custom;
}
function defaultPhaseForType(type) {
    if (type === 'rate_limit')
        return 'rate_limit';
    if (type === 'bot')
        return 'bot';
    if (type === 'api')
        return 'api';
    if (type === 'http_security')
        return 'http_security';
    if (type === 'geo' || type === 'ip_access' || type === 'access')
        return 'access';
    return 'http_request_firewall_custom';
}
function sectionForType(type) {
    if (type === 'geo' || type === 'ip_access')
        return 'geo_ip';
    return type;
}
function formatExpressionValue(value, operator) {
    if (operator === 'in' || operator === 'not in') {
        return `{${value.split(',').map(item => formatScalar(item.trim())).join(' ')}}`;
    }
    return formatScalar(value);
}
function unformatExpressionValue(value) {
    return value
        .replace(/[{}]/g, '')
        .split(/\s+/)
        .map(item => item.trim().replace(/^["']|["']$/g, ''))
        .filter(Boolean)
        .join(',');
}
function splitConditionValues(value) {
    return value.split(',').map(item => item.trim()).filter(Boolean);
}
function fieldSpec(field) {
    const remote = cachedFields.find(spec => spec.name === field);
    const fallback = defaultFields.find(spec => spec.name === field);
    return remote && fallback ? { ...fallback, ...remote, input_type: remote.input_type || fallback.input_type, options: remote.options?.length ? remote.options : fallback.options, placeholder: remote.placeholder || fallback.placeholder, multi: remote.multi || fallback.multi } : remote || fallback;
}
function clientConditionErrors(conditions) {
    const errors = [];
    for (const condition of conditions) {
        if (!condition.field && !condition.operator && !condition.value.trim())
            continue;
        if (!condition.field) {
            errors.push('Choose a field');
            continue;
        }
        if (!condition.operator) {
            errors.push(`${fieldLabel(condition.field)} needs an operator`);
            continue;
        }
        const values = splitConditionValues(condition.value);
        if (!condition.value.trim()) {
            errors.push(`${fieldLabel(condition.field)} needs a value`);
            continue;
        }
        if (condition.field === 'ip.src') {
            for (const value of values) {
                if (!isLikelyIpOrCidr(value))
                    errors.push(`Invalid IP/CIDR value: ${value}`);
            }
        }
        if (condition.field === 'ip.geoip.country') {
            for (const value of values) {
                if (!/^[A-Za-z]{2}$/.test(value))
                    errors.push(`Invalid country code: ${value}`);
            }
        }
    }
    return errors;
}
function isLikelyIpOrCidr(value) {
    const ipPart = value.split('/')[0];
    const octets = ipPart.split('.');
    if (octets.length !== 4 || !octets.every(octet => /^\d{1,3}$/.test(octet) && Number(octet) >= 0 && Number(octet) <= 255))
        return false;
    if (!value.includes('/'))
        return true;
    const mask = Number(value.split('/')[1]);
    return Number.isInteger(mask) && mask >= 0 && mask <= 32;
}
function renderClientValidation(errors) {
    const target = AdminDOM.getById('security-rule-validation');
    if (!target)
        return;
    target.classList.remove('hidden');
    target.innerHTML = `<span class="text-danger">Condition needs changes</span>${errors.map(error => `<div class="text-xs mt-8">${escapeHtml(error)}</div>`).join('')}`;
}
function fieldLabel(field) {
    return fieldSpec(field)?.label || labelize(field);
}
function reindexConditionRows() {
    AdminDOM.queryAll('.security-rule-condition-row').forEach((row, index) => {
        row.dataset.conditionIndex = String(index);
        const remove = row.querySelector('[data-action="remove-security-rule-condition"]');
        if (remove)
            remove.dataset.conditionIndex = String(index);
        const joiner = row.querySelector('.security-rule-condition-joiner');
        if (joiner && index === 0)
            joiner.innerHTML = '<span class="status-pill">When</span>';
        if (joiner && index > 0 && !joiner.querySelector('select'))
            joiner.innerHTML = '<select class="select-sm security-rule-condition-join"><option value="and">AND</option><option value="or">OR</option></select>';
    });
}
function formatScalar(value) {
    if (/^-?\d+(\.\d+)?$/.test(value) || value === 'true' || value === 'false')
        return value;
    return `"${value.replace(/"/g, '\\"')}"`;
}
function valuePlaceholder(type) {
    const placeholders = {
        geo: 'US or TN',
        ip_access: '203.0.113.10',
        rate_limit: '/api/',
        bot: '30',
        api: '/v1/payments',
        waf: '/admin',
        http_security: 'TLS1.2',
        access: 'admin',
        custom: '/api/'
    };
    return placeholders[type] || placeholders.custom;
}
function labelize(value) {
    return value.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
}
function formatCompact(value) {
    const formatted = new Intl.NumberFormat('en-US', {
        notation: 'compact',
        maximumFractionDigits: 1
    }).format(value || 0);
    return formatted.replace(/([KMBT])$/i, match => match.toUpperCase());
}
function formatPercent(value) {
    return `${formatDecimal(value)}%`;
}
function formatDecimal(value) {
    return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value || 0);
}
function formatTrafficBytes(value) {
    const bytes = Math.max(0, Number(value) || 0);
    if (bytes < 1024)
        return `${Math.round(bytes)} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let amount = bytes / 1024;
    let index = 0;
    while (amount >= 1024 && index < units.length - 1) {
        amount /= 1024;
        index += 1;
    }
    return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: amount >= 100 ? 0 : 1 }).format(amount)} ${units[index]}`;
}
function escapeHtml(value) {
    return String(value || '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char] || char);
}
function escapeAttr(value) {
    return escapeHtml(value).replace(/"/g, '&quot;');
}
