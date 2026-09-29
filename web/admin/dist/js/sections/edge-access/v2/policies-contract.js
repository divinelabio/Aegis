import { api } from '../../../api.js';
import { EDGE_ACCESS_ENDPOINTS } from './endpoints.js';
const ROOT = EDGE_ACCESS_ENDPOINTS.root;
function isRecord(value) { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function text(value) { return typeof value === 'string' ? value : ''; }
function number(value) { return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : 0; }
function strings(value) { return Array.isArray(value) ? value.filter((entry) => typeof entry === 'string') : []; }
function page(value) { return isRecord(value) ? { returned: number(value.returned), page_size: number(value.page_size) || 50, next_cursor: text(value.next_cursor) || undefined } : { returned: 0, page_size: 50 }; }
function authChannels(value) { return strings(value).filter((value) => value === 'oidc' || value === 'jwt' || value === 'api_key' || value === 'mtls'); }
function claim(value) {
    if (!isRecord(value) || !text(value.name))
        return null;
    const operator = value.operator === 'exists' || value.operator === 'eq' || value.operator === 'neq' || value.operator === 'in' || value.operator === 'contains' ? value.operator : undefined;
    return { name: text(value.name), operator, values: strings(value.values) };
}
function principals(value) {
    const record = isRecord(value) ? value : {};
    return { any_authenticated: record.any_authenticated === true, roles: strings(record.roles), groups: strings(record.groups), permissions: strings(record.permissions), service_identity_ids: strings(record.service_identity_ids), claims: Array.isArray(record.claims) ? record.claims.flatMap(item => { const parsed = claim(item); return parsed ? [parsed] : []; }) : [] };
}
function requirements(value) {
    const record = isRecord(value) ? value : {};
    return { mfa_satisfied: record.mfa_satisfied === true, source_cidrs: strings(record.source_cidrs), trusted_device: record.trusted_device === true, countries: strings(record.countries) };
}
export function normalizePolicy(value) {
    if (!isRecord(value) || !text(value.id) || !text(value.name) || typeof value.archived !== 'boolean')
        return null;
    return { id: text(value.id), revision: number(value.revision), name: text(value.name), description: text(value.description) || undefined, archived: value.archived, created_at: text(value.created_at) || undefined, updated_at: text(value.updated_at) || undefined };
}
export function normalizePolicyVersion(value) {
    if (!isRecord(value) || !text(value.policy_id) || number(value.version) < 1 || (value.state !== 'draft' && value.state !== 'published') || (value.decision !== 'allow' && value.decision !== 'deny' && value.decision !== 'public_bypass'))
        return null;
    return { policy_id: text(value.policy_id), version: number(value.version), revision: number(value.revision), state: value.state, decision: value.decision, principals: principals(value.principals), requirements: requirements(value.requirements), created_at: text(value.created_at) || undefined, updated_at: text(value.updated_at) || undefined, published_at: text(value.published_at) || undefined };
}
export function normalizePolicyAttachment(value) {
    if (!isRecord(value) || !text(value.id) || !text(value.policy_id) || !text(value.protected_app_id) || !text(value.path) || typeof value.enabled !== 'boolean')
        return null;
    if (value.deployment_state !== 'active' && value.deployment_state !== 'disabled')
        return null;
    return { id: text(value.id), revision: number(value.revision), policy_id: text(value.policy_id), policy_version: number(value.policy_version), protected_app_id: text(value.protected_app_id), path: text(value.path), methods: strings(value.methods), auth_channels: authChannels(value.auth_channels), deployment_state: value.deployment_state, enabled: value.enabled, created_at: text(value.created_at) || undefined, updated_at: text(value.updated_at) || undefined };
}
function workspaceApp(value) {
    if (!isRecord(value) || !text(value.id) || !text(value.name) || !text(value.route_id) || !isRecord(value.access_health) || !text(value.access_health.state))
        return null;
    return { id: text(value.id), name: text(value.name), route_id: text(value.route_id), public_addresses: strings(value.public_addresses), access_health: text(value.access_health.state), active_policy_count: number(value.active_policy_count), candidate_policy_count: number(value.candidate_policy_count), last_policy_change: text(value.last_policy_change) || undefined };
}
function workspaceAttachment(value) {
    if (!isRecord(value) || !text(value.policy_name) || (value.decision !== 'allow' && value.decision !== 'deny' && value.decision !== 'public_bypass') || typeof value.deployed !== 'boolean' || typeof value.update_available !== 'boolean')
        return null;
    const attachment = normalizePolicyAttachment(value.attachment);
    if (!attachment)
        return null;
    return { attachment, policy_name: text(value.policy_name), policy_description: text(value.policy_description) || undefined, decision: value.decision, principals: principals(value.principals), requirements: requirements(value.requirements), deployed: value.deployed, update_available: value.update_available };
}
function libraryItem(value) {
    if (!isRecord(value))
        return null;
    const policy = normalizePolicy(value.policy);
    if (!policy)
        return null;
    const decision = value.latest_published_decision === 'allow' || value.latest_published_decision === 'deny' || value.latest_published_decision === 'public_bypass' ? value.latest_published_decision : undefined;
    return { policy, latest_published_version: number(value.latest_published_version) || undefined, latest_published_decision: decision, attachment_count: number(value.attachment_count), protected_app_ids: strings(value.protected_app_ids), update_available_count: number(value.update_available_count) };
}
export function normalizeDecisionExplorerRecord(value) {
    if (!isRecord(value) || !text(value.id) || !text(value.timestamp) || !text(value.result) || typeof value.explanation_available !== 'boolean')
        return null;
    return { id: text(value.id), timestamp: text(value.timestamp), route_id: text(value.route_id) || undefined, protected_app_id: text(value.protected_app_id) || undefined, protected_app_name: text(value.protected_app_name) || undefined, public_addresses: strings(value.public_addresses), host: text(value.host) || undefined, path: text(value.path) || undefined, method: text(value.method) || undefined, result: text(value.result), status_code: number(value.status_code) || undefined, evaluation_mode: text(value.evaluation_mode) || undefined, auth_channel: text(value.auth_channel) || undefined, identity_type: text(value.identity_type) || undefined, identity_id: text(value.identity_id) || undefined, identity_email: text(value.identity_email) || undefined, policy_attachment_id: text(value.policy_attachment_id) || undefined, policy_id: text(value.policy_id) || undefined, policy_version: number(value.policy_version) || undefined, reason_code: text(value.reason_code) || undefined, reason: text(value.reason) || undefined, failed_requirement: text(value.failed_requirement) || undefined, matched_conditions: strings(value.matched_conditions), explanation_available: value.explanation_available };
}
function decisionTrace(value) { return Array.isArray(value) ? value.flatMap(item => isRecord(item) && text(item.stage) && text(item.outcome) && text(item.detail) ? [{ stage: text(item.stage), outcome: text(item.outcome), detail: text(item.detail), attachment_id: text(item.attachment_id) || undefined, policy_id: text(item.policy_id) || undefined, policy_version: number(item.policy_version) || undefined }] : []) : []; }
function error(value) { return value ? { status: value.status, code: value.code, message: value.message, details: isRecord(value.details) ? value.details : undefined } : null; }
async function request(endpoint, method, body, normalize) {
    const response = await api.requestResult(endpoint, method, body);
    if (response.error)
        return { data: null, error: error(response.error) };
    const data = normalize(response.data);
    return data ? { data, error: null } : { data: null, error: { status: 0, code: 'malformed_response', message: 'The Policy service returned an invalid response.' } };
}
function query(values) { const params = new URLSearchParams(); Object.entries(values).forEach(([key, value]) => { if (value !== undefined && String(value).trim())
    params.set(key, String(value)); }); const value = params.toString(); return value ? `?${value}` : ''; }
function appsResponse(value) { return isRecord(value) && value.success === true && Array.isArray(value.apps) ? { apps: value.apps.flatMap(item => { const parsed = workspaceApp(item); return parsed ? [parsed] : []; }), page: page(value.page) } : null; }
function appResponse(value) { if (!isRecord(value) || value.success !== true || !Array.isArray(value.attachments))
    return null; const app = workspaceApp(value.app); return app ? { app, attachments: value.attachments.flatMap(item => { const parsed = workspaceAttachment(item); return parsed ? [parsed] : []; }), page: page(value.page) } : null; }
function libraryResponse(value) { return isRecord(value) && value.success === true && Array.isArray(value.policies) ? { policies: value.policies.flatMap(item => { const parsed = libraryItem(item); return parsed ? [parsed] : []; }), page: page(value.page) } : null; }
function policyResponse(value) { return isRecord(value) && value.success === true ? normalizePolicy(value.policy) : null; }
function versionResponse(value) { return isRecord(value) && value.success === true ? normalizePolicyVersion(value.policy_version) : null; }
function versionsResponse(value) { return isRecord(value) && value.success === true && Array.isArray(value.versions) ? value.versions.flatMap(item => { const parsed = normalizePolicyVersion(item); return parsed ? [parsed] : []; }) : null; }
function attachmentResponse(value) { return isRecord(value) && value.success === true ? normalizePolicyAttachment(value.attachment) : null; }
function decisionsResponse(value) { return isRecord(value) && value.success === true && Array.isArray(value.decisions) ? { decisions: value.decisions.flatMap(item => { const parsed = normalizeDecisionExplorerRecord(item); return parsed ? [parsed] : []; }), page: page(value.page) } : null; }
function decisionDetailResponse(value) { if (!isRecord(value) || value.success !== true || !isRecord(value.explanation))
    return null; const decision = normalizeDecisionExplorerRecord(value.decision); if (!decision || typeof value.explanation.available !== 'boolean')
    return null; return { decision, explanation: { available: value.explanation.available, reason: text(value.explanation.reason), steps: strings(value.explanation.steps), trace: decisionTrace(value.explanation.trace) } }; }
export const policiesV2Api = {
    apps(input = {}) { return request(`${ROOT}/policy-workspace/apps${query(input)}`, 'GET', undefined, appsResponse); },
    app(id, cursor) { return request(`${ROOT}/policy-workspace/apps/${encodeURIComponent(id)}${query({ cursor })}`, 'GET', undefined, appResponse); },
    library(input = {}) { return request(`${ROOT}/policy-workspace/library${query(input)}`, 'GET', undefined, libraryResponse); },
    getPolicy(id) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}`, 'GET', undefined, policyResponse); },
    createPolicy(input) { return request(`${ROOT}/access-policies`, 'POST', input, policyResponse); },
    updatePolicy(id, input) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}`, 'PUT', input, policyResponse); },
    versions(id) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}/versions`, 'GET', undefined, versionsResponse); },
    createDraft(id, input) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}/versions`, 'POST', input, versionResponse); },
    updateDraft(id, version, input) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}/versions/${version}`, 'PUT', input, versionResponse); },
    publish(id, version, revision) { return request(`${ROOT}/access-policies/${encodeURIComponent(id)}/versions/${version}/publish`, 'POST', { revision }, versionResponse); },
    createAttachment(input) { return request(`${ROOT}/policy-attachments`, 'POST', input, attachmentResponse); },
    updateAttachment(id, input) { return request(`${ROOT}/policy-attachments/${encodeURIComponent(id)}`, 'PUT', input, attachmentResponse); },
    upgradeAttachment(id, revision, policyVersion) { return request(`${ROOT}/policy-attachments/${encodeURIComponent(id)}/upgrade`, 'POST', { revision, policy_version: policyVersion }, attachmentResponse); },
    detachAttachment(id, revision) { return request(`${ROOT}/policy-attachments/${encodeURIComponent(id)}`, 'DELETE', { revision }, value => isRecord(value) && value.success === true ? { detached: value.detached === true } : null); },
    decisions(input = {}) { return request(`${ROOT}/decision-explorer${query(input)}`, 'GET', undefined, decisionsResponse); },
    decision(id) { return request(`${ROOT}/decision-explorer/${encodeURIComponent(id)}`, 'GET', undefined, decisionDetailResponse); }
};
