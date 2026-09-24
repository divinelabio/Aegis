import { api } from '../../api.js';
import { API_SECURITY_CONFIG_ENDPOINT, API_SECURITY_DASHBOARD_ENDPOINT, API_SECURITY_INVENTORY_ENDPOINT, API_SECURITY_SCHEMA_UPLOAD_ENDPOINT, API_SECURITY_STATS_ENDPOINT } from './constants.js';
export function loadAPISecurityConfig() {
    return api.get(API_SECURITY_CONFIG_ENDPOINT);
}
export function loadAPISecurityStats() {
    return api.get(API_SECURITY_STATS_ENDPOINT);
}
export function loadAPISecurityDashboard() {
    return api.get(API_SECURITY_DASHBOARD_ENDPOINT);
}
export function loadAPISecurityInventory(query = {}) {
    const params = new URLSearchParams();
    Object.entries(query).forEach(([key, value]) => {
        if (value !== undefined && value !== '')
            params.set(key, String(value));
    });
    const suffix = params.size ? `?${params.toString()}` : '';
    return api.get(`${API_SECURITY_INVENTORY_ENDPOINT}${suffix}`);
}
export function uploadAPISecuritySchema(payload) {
    return api.post(API_SECURITY_SCHEMA_UPLOAD_ENDPOINT, payload);
}
