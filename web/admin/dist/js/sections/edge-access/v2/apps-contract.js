import { api } from '../../../api.js';
import { EDGE_ACCESS_ENDPOINTS } from './endpoints.js';
const ROOT = EDGE_ACCESS_ENDPOINTS.protectedApps;
function isRecord(value) { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function text(value) { return typeof value === 'string' ? value : ''; }
function integer(value) { return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : 0; }
function strings(value) { return Array.isArray(value) ? value.filter((item) => typeof item === 'string') : []; }
function normalizePage(value) {
    if (!isRecord(value))
        return { returned: 0, page_size: 50 };
    return { returned: integer(value.returned), page_size: integer(value.page_size) || 50, next_cursor: text(value.next_cursor) || undefined };
}
function normalizeRoute(value) {
    if (!isRecord(value) || !text(value.id) || typeof value.enabled !== 'boolean')
        return undefined;
    return { id: text(value.id), name: text(value.name), hosts: strings(value.hosts), paths: strings(value.paths), enabled: value.enabled, priority: integer(value.priority), origin_url: text(value.origin_url) || undefined, upstream: text(value.upstream) || undefined };
}
function normalizeTrustSource(value) {
    if (!isRecord(value) || (value.channel !== 'browser_session' && value.channel !== 'bearer_jwt' && value.channel !== 'api_key' && value.channel !== 'mtls'))
        return null;
    const reference = value.reference_mode === 'explicit' ? value.reference_mode : undefined;
    return { channel: value.channel, reference_mode: reference, oidc_provider_id: text(value.oidc_provider_id) || undefined, jwt_issuer_url: text(value.jwt_issuer_url) || undefined, jwt_audience: text(value.jwt_audience) || undefined };
}
export function normalizeAppV2(value) {
    if (!isRecord(value) || !text(value.id) || !text(value.name) || !text(value.route_id) || (value.default_action !== 'allow' && value.default_action !== 'deny'))
        return null;
    if (value.authorization_mode !== 'policy_attachments')
        return null;
    if (value.deployment_state !== 'draft' && value.deployment_state !== 'deployed' && value.deployment_state !== 'disabled')
        return null;
    const health = isRecord(value.access_health) ? value.access_health : {};
    if (health.state !== 'draft' && health.state !== 'deny_only' && health.state !== 'active' && health.state !== 'update_available' && health.state !== 'disabled' && health.state !== 'error')
        return null;
    if (typeof value.enabled !== 'boolean')
        return null;
    const sources = Array.isArray(value.accepted_trust_sources) ? value.accepted_trust_sources.flatMap(source => {
        const normalized = normalizeTrustSource(source);
        return normalized ? [normalized] : [];
    }) : [];
    return {
        id: text(value.id), revision: integer(value.revision), name: text(value.name), route_id: text(value.route_id), route: normalizeRoute(value.route),
        auth_method: text(value.auth_method) || undefined, default_action: value.default_action, authorization_mode: value.authorization_mode, deployment_state: value.deployment_state,
        accepted_trust_sources: sources, access_health: { state: health.state, reason_codes: strings(health.reason_codes) }, enabled: value.enabled,
        created_at: text(value.created_at) || undefined, updated_at: text(value.updated_at) || undefined
    };
}
export function normalizeAppCatalogItem(value) {
    if (!isRecord(value))
        return null;
    const app = normalizeAppV2(value.protected_app);
    const summary = isRecord(value.access_summary) ? value.access_summary : null;
    if (!app || !summary)
        return null;
    return { protected_app: app, public_addresses: strings(value.public_addresses), access_summary: { candidate_policy_count: integer(summary.candidate_policy_count), active_policy_count: integer(summary.active_policy_count), active_allow_count: integer(summary.active_allow_count), active_deployment_id: text(summary.active_deployment_id) || undefined } };
}
export function normalizeAppHistoryEvent(value) {
    if (!isRecord(value) || !text(value.id) || !text(value.protected_app_id) || !text(value.change_type))
        return null;
    return { id: text(value.id), protected_app_id: text(value.protected_app_id), change_type: text(value.change_type), actor: text(value.actor) || undefined, revision: integer(value.revision) || undefined, deployment_id: text(value.deployment_id) || undefined, attachment_id: text(value.attachment_id) || undefined, detail: text(value.detail) || undefined, timestamp: text(value.timestamp) || undefined };
}
function normalizeError(error) {
    return error ? { status: error.status, code: error.code, message: error.message, details: isRecord(error.details) ? error.details : undefined } : null;
}
async function request(endpoint, method, body, normalize) {
    const response = await api.requestResult(endpoint, method, body);
    if (response.error)
        return { data: null, error: normalizeError(response.error) };
    const data = normalize(response.data);
    return data ? { data, error: null } : { data: null, error: { status: 0, code: 'malformed_response', message: 'The Apps service returned an invalid response.' } };
}
function query(input) {
    const params = new URLSearchParams();
    if (input.q)
        params.set('q', input.q);
    if (input.status)
        params.set('status', input.status);
    if (input.trust_channel)
        params.set('trust_channel', input.trust_channel);
    if (input.no_active_allow)
        params.set('no_active_allow', 'true');
    if (input.cursor)
        params.set('cursor', input.cursor);
    const value = params.toString();
    return value ? `?${value}` : '';
}
function catalogResponse(value) {
    if (!isRecord(value) || value.success !== true || !Array.isArray(value.apps))
        return null;
    return { apps: value.apps.flatMap(item => { const normalized = normalizeAppCatalogItem(item); return normalized ? [normalized] : []; }), page: normalizePage(value.page) };
}
function detailResponse(value) { return isRecord(value) && value.success === true ? normalizeAppCatalogItem(value.app) : null; }
function historyResponse(value) {
    if (!isRecord(value) || value.success !== true || !Array.isArray(value.events))
        return null;
    return { events: value.events.flatMap(item => { const normalized = normalizeAppHistoryEvent(item); return normalized ? [normalized] : []; }), page: normalizePage(value.page) };
}
function mutationResponse(value) { return isRecord(value) && value.success === true ? normalizeAppV2(value.protected_app) : null; }
function routeOptions(value) {
    const routes = Array.isArray(value) ? value : isRecord(value) && Array.isArray(value.routes) ? value.routes : null;
    if (!routes)
        return null;
    return routes.flatMap(route => {
        if (!isRecord(route) || !text(route.id) || !text(route.name) || typeof route.enabled !== 'boolean')
            return [];
        const hosts = strings(isRecord(route.match) ? route.match.hosts : route.hosts);
        const paths = strings(isRecord(route.match) ? route.match.paths : route.paths);
        return [{ id: text(route.id), name: text(route.name), hosts, paths, enabled: route.enabled, priority: integer(route.priority), origin_url: text(route.origin_url) || text(route.upstream), upstream: text(route.upstream) || undefined }];
    });
}
function impactResponse(value) {
    if (!isRecord(value) || value.success !== true || !text(value.candidate_fingerprint) || typeof value.valid !== 'boolean')
        return null;
    return { candidate_fingerprint: text(value.candidate_fingerprint), valid: value.valid, broad_public_bypass: value.broad_public_bypass === true, confirmation_token: text(value.confirmation_token) || undefined, issues: strings(value.issues) };
}
function decisionsResponse(value) {
    if (!isRecord(value) || value.success !== true || !Array.isArray(value.decisions))
        return null;
    return value.decisions.flatMap(decision => {
        if (!isRecord(decision) || !text(decision.id) || !text(decision.result))
            return [];
        return [{ id: text(decision.id), timestamp: text(decision.timestamp) || undefined, result: text(decision.result), method: text(decision.method) || undefined, path: text(decision.path) || undefined, reason_code: text(decision.reason_code) || undefined }];
    });
}
export const appsV2Api = {
    list(queryInput = {}) { return request(`${ROOT}/catalog${query(queryInput)}`, 'GET', undefined, catalogResponse); },
    get(id) { return request(`${ROOT}/${encodeURIComponent(id)}`, 'GET', undefined, detailResponse); },
    listHistory(id, cursor) { return request(`${ROOT}/${encodeURIComponent(id)}/history${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`, 'GET', undefined, historyResponse); },
    listRoutes() { return request(EDGE_ACCESS_ENDPOINTS.routes, 'GET', undefined, routeOptions); },
    recentDecisions(id) { return request(`${EDGE_ACCESS_ENDPOINTS.activityDecisions}?protected_app_id=${encodeURIComponent(id)}&limit=5`, 'GET', undefined, decisionsResponse); },
    create(input) { return request(ROOT, 'POST', input, mutationResponse); },
    createWithRoute(route, protectedApp) { return request(`${ROOT}/create-with-route`, 'POST', { route, protected_app: protectedApp }, mutationResponse); },
    update(id, input) { return request(`${ROOT}/${encodeURIComponent(id)}`, 'PUT', input, mutationResponse); },
    delete(id, revision) { return request(`${ROOT}/${encodeURIComponent(id)}`, 'DELETE', { revision, cascade_confirmed: true }, value => isRecord(value) && value.success === true ? { deleted: true } : null); },
    impact(id) { return request(`${EDGE_ACCESS_ENDPOINTS.root}/policy-impact`, 'POST', { protected_app_id: id }, impactResponse); },
    deploy(id, candidateFingerprint, confirmationToken) {
        return request(`${ROOT}/${encodeURIComponent(id)}/policy-deployments`, 'POST', {
            candidate_fingerprint: candidateFingerprint,
            impact_confirmation_token: confirmationToken,
            acknowledge_review: true
        }, mutationResponse);
    },
    rollback(id, deploymentID) { return request(`${ROOT}/${encodeURIComponent(id)}/policy-deployments/${encodeURIComponent(deploymentID)}/rollback`, 'POST', {}, mutationResponse); }
};
export async function loadAppsForRouting() {
    const apps = [];
    const seenCursors = new Set();
    let cursor;
    do {
        const result = await appsV2Api.list({ cursor });
        if (!result.data)
            throw new Error(result.error?.message || 'Protected applications could not be loaded.');
        apps.push(...result.data.apps.map(item => item.protected_app));
        cursor = result.data.page.next_cursor;
        if (cursor) {
            if (seenCursors.has(cursor))
                throw new Error('Protected application pagination returned a repeated cursor.');
            seenCursors.add(cursor);
        }
    } while (cursor);
    return apps;
}
export async function findAppByRoute(routeID) {
    const apps = await loadAppsForRouting();
    return apps.find(app => app.route_id === routeID) || null;
}
