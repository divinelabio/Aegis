import { api } from '../../../api.js';
import { EDGE_ACCESS_ENDPOINTS } from './endpoints.js';

const ROOT = EDGE_ACCESS_ENDPOINTS.protectedApps;

export type AppAccessHealth = 'draft' | 'deny_only' | 'active' | 'update_available' | 'disabled' | 'error';
export type AppTrustChannel = 'browser_session' | 'bearer_jwt' | 'api_key' | 'mtls';
export type AppSubpage = 'overview' | 'access-policies';

export interface AppV2Error { status: number; code?: string; message: string; details?: Record<string, unknown>; }
export interface AppV2Result<T> { data: T | null; error: AppV2Error | null; }
export interface AppV2Page { returned: number; page_size: number; next_cursor?: string; }

export interface AppRouteSummary {
  id: string; name: string; hosts: string[]; paths: string[]; enabled: boolean; priority: number; origin_url?: string; upstream?: string;
}

export interface AppTrustSource {
  channel: AppTrustChannel;
  reference_mode?: 'explicit';
  oidc_provider_id?: string;
  jwt_issuer_url?: string;
  jwt_audience?: string;
}

export interface AppV2 {
  id: string; revision: number; name: string; route_id: string; route?: AppRouteSummary;
  auth_method?: string; default_action: 'allow' | 'deny';
  authorization_mode: 'policy_attachments';
  deployment_state: 'draft' | 'deployed' | 'disabled';
  accepted_trust_sources: AppTrustSource[];
  access_health: { state: AppAccessHealth; reason_codes: string[] };
  enabled: boolean; created_at?: string; updated_at?: string;
}

export interface AppAccessSummary {
  candidate_policy_count: number; active_policy_count: number; active_allow_count: number; active_deployment_id?: string;
}

export interface AppCatalogItem { protected_app: AppV2; public_addresses: string[]; access_summary: AppAccessSummary; }
export interface AppHistoryEvent {
  id: string; protected_app_id: string; change_type: string; actor?: string; revision?: number; deployment_id?: string; attachment_id?: string; detail?: string; timestamp?: string;
}
export interface AppRecentDecision { id: string; timestamp?: string; result: string; method?: string; path?: string; reason_code?: string; }
export interface AppRouteOption { id: string; name: string; hosts: string[]; paths: string[]; enabled: boolean; priority: number; origin_url: string; upstream?: string; }

export interface AppCatalogQuery { q?: string; status?: AppAccessHealth; trust_channel?: AppTrustChannel; no_active_allow?: boolean; cursor?: string; }
export interface AppV2Input {
  revision?: number; name: string; route_id?: string; auth_method?: string; default_action: 'allow' | 'deny';
  authorization_mode: 'policy_attachments'; deployment_state: 'draft' | 'deployed' | 'disabled'; accepted_trust_sources: AppTrustSource[];
}
export interface AppRouteShortcutInput { name: string; hosts: string[]; paths: string[]; origin_url: string; priority?: number; enabled: false; }

interface AppPolicyImpact { candidate_fingerprint: string; valid: boolean; broad_public_bypass: boolean; confirmation_token?: string; issues: string[]; }

function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function text(value: unknown): string { return typeof value === 'string' ? value : ''; }
function integer(value: unknown): number { return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : 0; }
function strings(value: unknown): string[] { return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []; }

function normalizePage(value: unknown): AppV2Page {
  if (!isRecord(value)) return { returned: 0, page_size: 50 };
  return { returned: integer(value.returned), page_size: integer(value.page_size) || 50, next_cursor: text(value.next_cursor) || undefined };
}

function normalizeRoute(value: unknown): AppRouteSummary | undefined {
  if (!isRecord(value) || !text(value.id) || typeof value.enabled !== 'boolean') return undefined;
  return { id: text(value.id), name: text(value.name), hosts: strings(value.hosts), paths: strings(value.paths), enabled: value.enabled, priority: integer(value.priority), origin_url: text(value.origin_url) || undefined, upstream: text(value.upstream) || undefined };
}

function normalizeTrustSource(value: unknown): AppTrustSource | null {
  if (!isRecord(value) || (value.channel !== 'browser_session' && value.channel !== 'bearer_jwt' && value.channel !== 'api_key' && value.channel !== 'mtls')) return null;
  const reference = value.reference_mode === 'explicit' ? value.reference_mode : undefined;
  return { channel: value.channel, reference_mode: reference, oidc_provider_id: text(value.oidc_provider_id) || undefined, jwt_issuer_url: text(value.jwt_issuer_url) || undefined, jwt_audience: text(value.jwt_audience) || undefined };
}

export function normalizeAppV2(value: unknown): AppV2 | null {
  if (!isRecord(value) || !text(value.id) || !text(value.name) || !text(value.route_id) || (value.default_action !== 'allow' && value.default_action !== 'deny')) return null;
  if (value.authorization_mode !== 'policy_attachments') return null;
  if (value.deployment_state !== 'draft' && value.deployment_state !== 'deployed' && value.deployment_state !== 'disabled') return null;
  const health = isRecord(value.access_health) ? value.access_health : {};
  if (health.state !== 'draft' && health.state !== 'deny_only' && health.state !== 'active' && health.state !== 'update_available' && health.state !== 'disabled' && health.state !== 'error') return null;
  if (typeof value.enabled !== 'boolean') return null;
  const sources = Array.isArray(value.accepted_trust_sources) ? value.accepted_trust_sources.flatMap(source => {
    const normalized = normalizeTrustSource(source); return normalized ? [normalized] : [];
  }) : [];
  return {
    id: text(value.id), revision: integer(value.revision), name: text(value.name), route_id: text(value.route_id), route: normalizeRoute(value.route),
    auth_method: text(value.auth_method) || undefined, default_action: value.default_action, authorization_mode: value.authorization_mode, deployment_state: value.deployment_state,
    accepted_trust_sources: sources, access_health: { state: health.state, reason_codes: strings(health.reason_codes) }, enabled: value.enabled,
    created_at: text(value.created_at) || undefined, updated_at: text(value.updated_at) || undefined
  };
}

export function normalizeAppCatalogItem(value: unknown): AppCatalogItem | null {
  if (!isRecord(value)) return null;
  const app = normalizeAppV2(value.protected_app);
  const summary = isRecord(value.access_summary) ? value.access_summary : null;
  if (!app || !summary) return null;
  return { protected_app: app, public_addresses: strings(value.public_addresses), access_summary: { candidate_policy_count: integer(summary.candidate_policy_count), active_policy_count: integer(summary.active_policy_count), active_allow_count: integer(summary.active_allow_count), active_deployment_id: text(summary.active_deployment_id) || undefined } };
}

export function normalizeAppHistoryEvent(value: unknown): AppHistoryEvent | null {
  if (!isRecord(value) || !text(value.id) || !text(value.protected_app_id) || !text(value.change_type)) return null;
  return { id: text(value.id), protected_app_id: text(value.protected_app_id), change_type: text(value.change_type), actor: text(value.actor) || undefined, revision: integer(value.revision) || undefined, deployment_id: text(value.deployment_id) || undefined, attachment_id: text(value.attachment_id) || undefined, detail: text(value.detail) || undefined, timestamp: text(value.timestamp) || undefined };
}

function normalizeError(error: { status: number; code?: string; message: string; details?: unknown } | null): AppV2Error | null {
  return error ? { status: error.status, code: error.code, message: error.message, details: isRecord(error.details) ? error.details : undefined } : null;
}

async function request<T>(endpoint: string, method: string, body: unknown, normalize: (value: unknown) => T | null): Promise<AppV2Result<T>> {
  const response = await api.requestResult<unknown>(endpoint, method, body);
  if (response.error) return { data: null, error: normalizeError(response.error) };
  const data = normalize(response.data);
  return data ? { data, error: null } : { data: null, error: { status: 0, code: 'malformed_response', message: 'The Apps service returned an invalid response.' } };
}

function query(input: AppCatalogQuery): string {
  const params = new URLSearchParams();
  if (input.q) params.set('q', input.q);
  if (input.status) params.set('status', input.status);
  if (input.trust_channel) params.set('trust_channel', input.trust_channel);
  if (input.no_active_allow) params.set('no_active_allow', 'true');
  if (input.cursor) params.set('cursor', input.cursor);
  const value = params.toString(); return value ? `?${value}` : '';
}

function catalogResponse(value: unknown): { apps: AppCatalogItem[]; page: AppV2Page } | null {
  if (!isRecord(value) || value.success !== true || !Array.isArray(value.apps)) return null;
  return { apps: value.apps.flatMap(item => { const normalized = normalizeAppCatalogItem(item); return normalized ? [normalized] : []; }), page: normalizePage(value.page) };
}

function detailResponse(value: unknown): AppCatalogItem | null { return isRecord(value) && value.success === true ? normalizeAppCatalogItem(value.app) : null; }
function historyResponse(value: unknown): { events: AppHistoryEvent[]; page: AppV2Page } | null {
  if (!isRecord(value) || value.success !== true || !Array.isArray(value.events)) return null;
  return { events: value.events.flatMap(item => { const normalized = normalizeAppHistoryEvent(item); return normalized ? [normalized] : []; }), page: normalizePage(value.page) };
}
function mutationResponse(value: unknown): AppV2 | null { return isRecord(value) && value.success === true ? normalizeAppV2(value.protected_app) : null; }
function routeOptions(value: unknown): AppRouteOption[] | null {
  const routes = Array.isArray(value) ? value : isRecord(value) && Array.isArray(value.routes) ? value.routes : null;
  if (!routes) return null;
  return routes.flatMap(route => {
    if (!isRecord(route) || !text(route.id) || !text(route.name) || typeof route.enabled !== 'boolean') return [];
    const hosts = strings(isRecord(route.match) ? route.match.hosts : route.hosts); const paths = strings(isRecord(route.match) ? route.match.paths : route.paths);
    return [{ id: text(route.id), name: text(route.name), hosts, paths, enabled: route.enabled, priority: integer(route.priority), origin_url: text(route.origin_url) || text(route.upstream), upstream: text(route.upstream) || undefined }];
  });
}
function impactResponse(value: unknown): AppPolicyImpact | null {
  if (!isRecord(value) || value.success !== true || !text(value.candidate_fingerprint) || typeof value.valid !== 'boolean') return null;
  return { candidate_fingerprint: text(value.candidate_fingerprint), valid: value.valid, broad_public_bypass: value.broad_public_bypass === true, confirmation_token: text(value.confirmation_token) || undefined, issues: strings(value.issues) };
}
function decisionsResponse(value: unknown): AppRecentDecision[] | null {
  if (!isRecord(value) || value.success !== true || !Array.isArray(value.decisions)) return null;
  return value.decisions.flatMap(decision => {
    if (!isRecord(decision) || !text(decision.id) || !text(decision.result)) return [];
    return [{ id: text(decision.id), timestamp: text(decision.timestamp) || undefined, result: text(decision.result), method: text(decision.method) || undefined, path: text(decision.path) || undefined, reason_code: text(decision.reason_code) || undefined }];
  });
}

export const appsV2Api = {
  list(queryInput: AppCatalogQuery = {}) { return request(`${ROOT}/catalog${query(queryInput)}`, 'GET', undefined, catalogResponse); },
  get(id: string) { return request(`${ROOT}/${encodeURIComponent(id)}`, 'GET', undefined, detailResponse); },
  listHistory(id: string, cursor?: string) { return request(`${ROOT}/${encodeURIComponent(id)}/history${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`, 'GET', undefined, historyResponse); },
  listRoutes() { return request(EDGE_ACCESS_ENDPOINTS.routes, 'GET', undefined, routeOptions); },

  recentDecisions(id: string) { return request(`${EDGE_ACCESS_ENDPOINTS.activityDecisions}?protected_app_id=${encodeURIComponent(id)}&limit=5`, 'GET', undefined, decisionsResponse); },
  create(input: AppV2Input) { return request(ROOT, 'POST', input, mutationResponse); },
  createWithRoute(route: AppRouteShortcutInput, protectedApp: AppV2Input) { return request(`${ROOT}/create-with-route`, 'POST', { route, protected_app: protectedApp }, mutationResponse); },
  update(id: string, input: AppV2Input) { return request(`${ROOT}/${encodeURIComponent(id)}`, 'PUT', input, mutationResponse); },
  delete(id: string, revision: number) { return request(`${ROOT}/${encodeURIComponent(id)}`, 'DELETE', { revision, cascade_confirmed: true }, value => isRecord(value) && value.success === true ? { deleted: true } : null); },
  impact(id: string) { return request(`${EDGE_ACCESS_ENDPOINTS.root}/policy-impact`, 'POST', { protected_app_id: id }, impactResponse); },
  deploy(id: string, candidateFingerprint: string, confirmationToken?: string) {
    return request(`${ROOT}/${encodeURIComponent(id)}/policy-deployments`, 'POST', {
      candidate_fingerprint: candidateFingerprint,
      impact_confirmation_token: confirmationToken,
      acknowledge_review: true
    }, mutationResponse);
  },
  rollback(id: string, deploymentID: string) { return request(`${ROOT}/${encodeURIComponent(id)}/policy-deployments/${encodeURIComponent(deploymentID)}/rollback`, 'POST', {}, mutationResponse); }
};

export async function loadAppsForRouting(): Promise<AppV2[]> {
  const apps: AppV2[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;

  do {
    const result = await appsV2Api.list({ cursor });
    if (!result.data) throw new Error(result.error?.message || 'Protected applications could not be loaded.');
    apps.push(...result.data.apps.map(item => item.protected_app));
    cursor = result.data.page.next_cursor;
    if (cursor) {
      if (seenCursors.has(cursor)) throw new Error('Protected application pagination returned a repeated cursor.');
      seenCursors.add(cursor);
    }
  } while (cursor);

  return apps;
}

export async function findAppByRoute(routeID: string): Promise<AppV2 | null> {
  const apps = await loadAppsForRouting();
  return apps.find(app => app.route_id === routeID) || null;
}
