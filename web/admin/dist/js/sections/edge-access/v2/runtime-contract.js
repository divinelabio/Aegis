import { api } from '../../../api.js';
import { EDGE_ACCESS_ENDPOINTS } from './endpoints.js';
const ROOT = EDGE_ACCESS_ENDPOINTS.root;
function isRecord(value) { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function text(value) { return typeof value === 'string' ? value : ''; }
function error(value) { return value ? { status: value.status, code: value.code, message: value.message } : null; }
async function request(endpoint, method, body, normalize) {
    const response = await api.requestResult(endpoint, method, body);
    if (response.error)
        return { data: null, error: error(response.error) };
    const data = normalize(response.data);
    return data ? { data, error: null } : { data: null, error: { status: 0, code: 'malformed_response', message: 'The Edge runtime service returned an invalid response.' } };
}
function settings(value) {
    if (!isRecord(value) || value.success !== true || !isRecord(value.settings))
        return null;
    const current = value.settings;
    if (typeof current.enabled !== 'boolean'
        || !isRecord(current.authentication)
        || !isRecord(current.authorization)
        || !isRecord(current.session_cookie)
        || !isRecord(current.identity_headers)
        || !isRecord(current.identity_trust)
        || !isRecord(current.activity)
        || !isRecord(current.audit)) {
        return null;
    }
    return current;
}
function reload(value) {
    if (!isRecord(value)
        || value.success !== true
        || typeof value.revision !== 'number'
        || typeof value.loaded_revision !== 'number'
        || typeof value.shared_storage !== 'boolean') {
        return null;
    }
    return {
        success: true,
        revision: value.revision,
        loaded_revision: value.loaded_revision,
        shared_storage: value.shared_storage,
        last_reload_at: text(value.last_reload_at) || undefined,
        last_reload_error: text(value.last_reload_error) || undefined,
        message: text(value.message) || undefined
    };
}
export const edgeRuntimeV2Api = {
    settings() { return request(`${ROOT}/settings`, 'GET', undefined, settings); },
    updateSettings(input) { return request(`${ROOT}/settings`, 'PUT', input, settings); },
    reloadStatus() { return request(`${ROOT}/reload/status`, 'GET', undefined, reload); },
    reload() { return request(`${ROOT}/reload`, 'POST', {}, reload); }
};
