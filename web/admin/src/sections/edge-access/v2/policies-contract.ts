import { api } from '../../../api.js';
import { EDGE_ACCESS_ENDPOINTS } from './endpoints.js';

const ROOT = EDGE_ACCESS_ENDPOINTS.root;

export type PolicyDecision = 'allow' | 'deny' | 'public_bypass';
export type PolicyVersionState = 'draft' | 'published';
export type PolicyAttachmentState = 'active' | 'disabled';
export type PolicyAuthChannel = 'oidc' | 'jwt' | 'api_key' | 'mtls';
export interface PolicyV2Error { status: number; code?: string; message: string; details?: Record<string, unknown>; }
export interface PolicyV2Result<T> { data: T | null; error: PolicyV2Error | null; }
export interface PolicyV2Page { returned: number; page_size: number; next_cursor?: string; }
export interface PolicyClaim { name: string; operator?: 'exists' | 'eq' | 'neq' | 'in' | 'contains'; values?: string[]; }
export interface PolicyPrincipals { any_authenticated: boolean; roles: string[]; groups: string[]; permissions: string[]; service_identity_ids: string[]; claims: PolicyClaim[]; }
export interface PolicyRequirements { mfa_satisfied: boolean; source_cidrs: string[]; trusted_device: boolean; countries: string[]; }
export interface Policy { id: string; revision: number; name: string; description?: string; archived: boolean; created_at?: string; updated_at?: string; }
export interface PolicyVersion { policy_id: string; version: number; revision: number; state: PolicyVersionState; decision: PolicyDecision; principals: PolicyPrincipals; requirements: PolicyRequirements; created_at?: string; updated_at?: string; published_at?: string; }
export interface PolicyAttachment { id: string; revision: number; policy_id: string; policy_version: number; protected_app_id: string; path: string; methods: string[]; auth_channels: PolicyAuthChannel[]; deployment_state: PolicyAttachmentState; enabled: boolean; created_at?: string; updated_at?: string; }
export interface PolicyWorkspaceApp { id: string; name: string; route_id: string; public_addresses: string[]; access_health: string; active_policy_count: number; candidate_policy_count: number; last_policy_change?: string; }
export interface PolicyWorkspaceAttachment { attachment: PolicyAttachment; policy_name: string; policy_description?: string; decision: PolicyDecision; principals: PolicyPrincipals; requirements: PolicyRequirements; deployed: boolean; update_available: boolean; }
export interface PolicyWorkspaceLibraryItem { policy: Policy; latest_published_version?: number; latest_published_decision?: PolicyDecision; attachment_count: number; protected_app_ids: string[]; update_available_count: number; }
export interface DecisionExplorerRecord { id: string; timestamp: string; route_id?: string; protected_app_id?: string; protected_app_name?: string; public_addresses: string[]; host?: string; path?: string; method?: string; result: string; status_code?: number; evaluation_mode?: string; auth_channel?: string; identity_type?: string; identity_id?: string; identity_email?: string; policy_attachment_id?: string; policy_id?: string; policy_version?: number; reason_code?: string; reason?: string; failed_requirement?: string; matched_conditions: string[]; explanation_available: boolean; }
export interface DecisionTraceStep { stage: string; outcome: string; detail: string; attachment_id?: string; policy_id?: string; policy_version?: number; }
export interface DecisionExplanation { available: boolean; reason: string; steps: string[]; trace: DecisionTraceStep[]; }
export interface DecisionExplorerDetail { decision: DecisionExplorerRecord; explanation: DecisionExplanation; }
export interface PolicyDraftInput { revision?: number; decision: PolicyDecision; principals: PolicyPrincipals; requirements: PolicyRequirements; }
export interface PolicyAttachmentInput { policy_id: string; policy_version: number; protected_app_id: string; path: string; methods: string[]; auth_channels: PolicyAuthChannel[]; deployment_state: PolicyAttachmentState; enabled: boolean; }

function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function text(value: unknown): string { return typeof value === 'string' ? value : ''; }
function number(value: unknown): number { return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : 0; }
function strings(value: unknown): string[] { return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : []; }
function page(value: unknown): PolicyV2Page { return isRecord(value) ? { returned: number(value.returned), page_size: number(value.page_size) || 50, next_cursor: text(value.next_cursor) || undefined } : { returned: 0, page_size: 50 }; }
function authChannels(value: unknown): PolicyAuthChannel[] { return strings(value).filter((value): value is PolicyAuthChannel => value === 'oidc' || value === 'jwt' || value === 'api_key' || value === 'mtls'); }

function claim(value: unknown): PolicyClaim | null {
  if (!isRecord(value) || !text(value.name)) return null;
  const operator = value.operator === 'exists' || value.operator === 'eq' || value.operator === 'neq' || value.operator === 'in' || value.operator === 'contains' ? value.operator : undefined;
  return { name: text(value.name), operator, values: strings(value.values) };
}
function principals(value: unknown): PolicyPrincipals {
  const record = isRecord(value) ? value : {};
  return { any_authenticated: record.any_authenticated === true, roles: strings(record.roles), groups: strings(record.groups), permissions: strings(record.permissions), service_identity_ids: strings(record.service_identity_ids), claims: Array.isArray(record.claims) ? record.claims.flatMap(item => { const parsed = claim(item); return parsed ? [parsed] : []; }) : [] };
}
function requirements(value: unknown): PolicyRequirements {
  const record = isRecord(value) ? value : {};
  return { mfa_satisfied: record.mfa_satisfied === true, source_cidrs: strings(record.source_cidrs), trusted_device: record.trusted_device === true, countries: strings(record.countries) };
}

export function normalizePolicy(value: unknown): Policy | null {
  if (!isRecord(value) || !text(value.id) || !text(value.name) || typeof value.archived !== 'boolean') return null;
  return { id: text(value.id), revision: number(value.revision), name: text(value.name), description: text(value.description) || undefined, archived: value.archived, created_at: text(value.created_at) || undefined, updated_at: text(value.updated_at) || undefined };
}
export function normalizePolicyVersion(value: unknown): PolicyVersion | null {
  if (!isRecord(value) || !text(value.policy_id) || number(value.version) < 1 || (value.state !== 'draft' && value.state !== 'published') || (value.decision !== 'allow' && value.decision !== 'deny' && value.decision !== 'public_bypass')) return null;
  return { policy_id: text(value.policy_id), version: number(value.version), revision: number(value.revision), state: value.state, decision: value.decision, principals: principals(value.principals), requirements: requirements(value.requirements), created_at: text(value.created_at) || undefined, updated_at: text(value.updated_at) || undefined, published_at: text(value.published_at) || undefined };
}
export function normalizePolicyAttachment(value: unknown): PolicyAttachment | null {
  if (!isRecord(value) || !text(value.id) || !text(value.policy_id) || !text(value.protected_app_id) || !text(value.path) || typeof value.enabled !== 'boolean') return null;
  if (value.deployment_state !== 'active' && value.deployment_state !== 'disabled') return null;
  return { id: text(value.id), revision: number(value.revision), policy_id: text(value.policy_id), policy_version: number(value.policy_version), protected_app_id: text(value.protected_app_id), path: text(value.path), methods: strings(value.methods), auth_channels: authChannels(value.auth_channels), deployment_state: value.deployment_state, enabled: value.enabled, created_at: text(value.created_at) || undefined, updated_at: text(value.updated_at) || undefined };
}
function workspaceApp(value: unknown): PolicyWorkspaceApp | null {
  if (!isRecord(value) || !text(value.id) || !text(value.name) || !text(value.route_id) || !isRecord(value.access_health) || !text(value.access_health.state)) return null;
  return { id: text(value.id), name: text(value.name), route_id: text(value.route_id), public_addresses: strings(value.public_addresses), access_health: text(value.access_health.state), active_policy_count: number(value.active_policy_count), candidate_policy_count: number(value.candidate_policy_count), last_policy_change: text(value.last_policy_change) || undefined };
}
function workspaceAttachment(value: unknown): PolicyWorkspaceAttachment | null {
  if (!isRecord(value) || !text(value.policy_name) || (value.decision !== 'allow' && value.decision !== 'deny' && value.decision !== 'public_bypass') || typeof value.deployed !== 'boolean' || typeof value.update_available !== 'boolean') return null;
  const attachment = normalizePolicyAttachment(value.attachment); if (!attachment) return null;
  return { attachment, policy_name: text(value.policy_name), policy_description: text(value.policy_description) || undefined, decision: value.decision, principals: principals(value.principals), requirements: requirements(value.requirements), deployed: value.deployed, update_available: value.update_available };
}
function libraryItem(value: unknown): PolicyWorkspaceLibraryItem | null {
  if (!isRecord(value)) return null; const policy = normalizePolicy(value.policy); if (!policy) return null;
  const decision = value.latest_published_decision === 'allow' || value.latest_published_decision === 'deny' || value.latest_published_decision === 'public_bypass' ? value.latest_published_decision : undefined;
  return { policy, latest_published_version: number(value.latest_published_version) || undefined, latest_published_decision: decision, attachment_count: number(value.attachment_count), protected_app_ids: strings(value.protected_app_ids), update_available_count: number(value.update_available_count) };
}
export function normalizeDecisionExplorerRecord(value: unknown): DecisionExplorerRecord | null {
  if (!isRecord(value) || !text(value.id) || !text(value.timestamp) || !text(value.result) || typeof value.explanation_available !== 'boolean') return null;
  return { id: text(value.id), timestamp: text(value.timestamp), route_id: text(value.route_id) || undefined, protected_app_id: text(value.protected_app_id) || undefined, protected_app_name: text(value.protected_app_name) || undefined, public_addresses: strings(value.public_addresses), host: text(value.host) || undefined, path: text(value.path) || undefined, method: text(value.method) || undefined, result: text(value.result), status_code: number(value.status_code) || undefined, evaluation_mode: text(value.evaluation_mode) || undefined, auth_channel: text(value.auth_channel) || undefined, identity_type: text(value.identity_type) || undefined, identity_id: text(value.identity_id) || undefined, identity_email: text(value.identity_email) || undefined, policy_attachment_id: text(value.policy_attachment_id) || undefined, policy_id: text(value.policy_id) || undefined, policy_version: number(value.policy_version) || undefined, reason_code: text(value.reason_code) || undefined, reason: text(value.reason) || undefined, failed_requirement: text(value.failed_requirement) || undefined, matched_conditions: strings(value.matched_conditions), explanation_available: value.explanation_available };
}
function decisionTrace(value: unknown): DecisionTraceStep[] { return Array.isArray(value) ? value.flatMap(item => isRecord(item) && text(item.stage) && text(item.outcome) && text(item.detail) ? [{ stage: text(item.stage), outcome: text(item.outcome), detail: text(item.detail), attachment_id: text(item.attachment_id) || undefined, policy_id: text(item.policy_id) || undefined, policy_version: number(item.policy_version) || undefined }] : []) : []; }
function error(value: { status: number; code?: string; message: string; details?: unknown } | null): PolicyV2Error | null { return value ? { status: value.status, code: value.code, message: value.message, details: isRecord(value.details) ? value.details : undefined } : null; }
async function request<T>(endpoint: string, method: string, body: unknown, normalize: (value: unknown) => T | null): Promise<PolicyV2Result<T>> {
  const response = await api.requestResult<unknown>(endpoint, method, body);
  if (response.error) return { data: null, error: error(response.error) };
  const data = normalize(response.data); return data ? { data, error: null } : { data: null, error: { status: 0, code: 'malformed_response', message: 'The Policy service returned an invalid response.' } };
}
function query(values: Record<string, string | number | boolean | undefined>): string { const params = new URLSearchParams(); Object.entries(values).forEach(([key, value]) => { if (value !== undefined && String(value).trim()) params.set(key, String(value)); }); const value = params.toString(); return value ? `?${value}` : ''; }

function appsResponse(value: unknown): { apps: PolicyWorkspaceApp[]; page: PolicyV2Page } | null { return isRecord(value) && value.success === true && Array.isArray(value.apps) ? { apps: value.apps.flatMap(item => { const parsed = workspaceApp(item); return parsed ? [parsed] : []; }), page: page(value.page) } : null; }
function appResponse(value: unknown): { app: PolicyWorkspaceApp; attachments: PolicyWorkspaceAttachment[]; page: PolicyV2Page } | null { if (!isRecord(value) || value.success !== true || !Array.isArray(value.attachments)) return null; const app = workspaceApp(value.app); return app ? { app, attachments: value.attachments.flatMap(item => { const parsed = workspaceAttachment(item); return parsed ? [parsed] : []; }), page: page(value.page) } : null; }
function libraryResponse(value: unknown): { policies: PolicyWorkspaceLibraryItem[]; page: PolicyV2Page } | null { return isRecord(value) && value.success === true && Array.isArray(value.policies) ? { policies: value.policies.flatMap(item => { const parsed = libraryItem(item); return parsed ? [parsed] : []; }), page: page(value.page) } : null; }
function policyResponse(value: unknown): Policy | null { return isRecord(value) && value.success === true ? normalizePolicy(value.policy) : null; }
function versionResponse(value: unknown): PolicyVersion | null { return isRecord(value) && value.success === true ? normalizePolicyVersion(value.policy_version) : null; }
function versionsResponse(value: unknown): PolicyVersion[] | null { return isRecord(value) && value.success === true && Array.isArray(value.versions) ? value.versions.flatMap(item => { const parsed = normalizePolicyVersion(item); return parsed ? [parsed] : []; }) : null; }
function attachmentResponse(value: unknown): PolicyAttachment | null { return isRecord(value) && value.success === true ? normalizePolicyAttachment(value.attachment) : null; }
function decisionsResponse(value: unknown): { decisions: DecisionExplorerRecord[]; page: PolicyV2Page } | null { return isRecord(value) && value.success === true && Array.isArray(value.decisions) ? { decisions: value.decisions.flatMap(item => { const parsed = normalizeDecisionExplorerRecord(item); return parsed ? [parsed] : []; }), page: page(value.page) } : null; }
function decisionDetailResponse(value: unknown): DecisionExplorerDetail | null { if (!isRecord(value) || value.success !== true || !isRecord(value.explanation)) return null; const decision = normalizeDecisionExplorerRecord(value.decision); if (!decision || typeof value.explanation.available !== 'boolean') return null; return { decision, explanation: { available: value.explanation.available, reason: text(value.explanation.reason), steps: strings(value.explanation.steps), trace: decisionTrace(value.explanation.trace) } }; }

export const policiesV2Api = {
  apps(input: { q?: string; status?: string; cursor?: string } = {}) { return request(`${ROOT}/policy-workspace/apps${query(input)}`, 'GET', undefined, appsResponse); },
  app(id: string, cursor?: string) { return request(`${ROOT}/policy-workspace/apps/${encodeURIComponent(id)}${query({ cursor })}`, 'GET', undefined, appResponse); },
  library(input: { q?: string; decision?: PolicyDecision; status?: 'active' | 'archived'; protected_app_id?: string; cursor?: string } = {}) { return request(`${ROOT}/policy-workspace/library${query(input)}`, 'GET', undefined, libraryResponse); },
  getPolicy(id: string) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}`, 'GET', undefined, policyResponse); },
  createPolicy(input: { name: string; description?: string }) { return request(`${ROOT}/access-policies`, 'POST', input, policyResponse); },
  updatePolicy(id: string, input: Policy) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}`, 'PUT', input, policyResponse); },
  versions(id: string) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}/versions`, 'GET', undefined, versionsResponse); },
  createDraft(id: string, input: PolicyDraftInput) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}/versions`, 'POST', input, versionResponse); },
  updateDraft(id: string, version: number, input: PolicyDraftInput) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}/versions/${version}`, 'PUT', input, versionResponse); },
  publish(id: string, version: number, revision: number) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}/versions/${version}/publish`, 'POST', { revision }, versionResponse); },
  createAttachment(input: PolicyAttachmentInput) { return request(`${ROOT}/policy-attachments`, 'POST', input, attachmentResponse); },
  updateAttachment(id: string, input: { revision: number; path: string; methods: string[]; auth_channels: PolicyAuthChannel[]; deployment_state: PolicyAttachmentState }) { return request(`${ROOT}/policy-attachments/${encodeURIComponent(id)}`, 'PUT', input, attachmentResponse); },
  upgradeAttachment(id: string, revision: number, policyVersion: number) { return request(`${ROOT}/policy-attachments/${encodeURIComponent(id)}/upgrade`, 'POST', { revision, policy_version: policyVersion }, attachmentResponse); },
  detachAttachment(id: string, revision: number) { return request(`${ROOT}/policy-attachments/${encodeURIComponent(id)}`, 'DELETE', { revision }, value => isRecord(value) && value.success === true ? { detached: value.detached === true } : null); },
  decisions(input: Record<string, string | number | undefined> = {}) { return request(`${ROOT}/decision-explorer${query(input)}`, 'GET', undefined, decisionsResponse); },
  decision(id: string) { return request(`${ROOT}/decision-explorer/${encodeURIComponent(id)}`, 'GET', undefined, decisionDetailResponse); }
};
