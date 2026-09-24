import { api } from '../../api.js';
import {
    API_SECURITY_CONFIG_ENDPOINT,
    API_SECURITY_DASHBOARD_ENDPOINT,
    API_SECURITY_INVENTORY_ENDPOINT,
    API_SECURITY_SCHEMA_UPLOAD_ENDPOINT,
    API_SECURITY_STATS_ENDPOINT
} from './constants.js';
import type { APISecuritySchemaUploadPayload } from './types.js';

export function loadAPISecurityConfig<T = unknown>(): Promise<T | null> {
    return api.get<T>(API_SECURITY_CONFIG_ENDPOINT);
}

export function loadAPISecurityStats<T = unknown>(): Promise<T | null> {
    return api.get<T>(API_SECURITY_STATS_ENDPOINT);
}

export function loadAPISecurityDashboard<T = unknown>(): Promise<T | null> {
    return api.get<T>(API_SECURITY_DASHBOARD_ENDPOINT);
}

export function loadAPISecurityInventory<T = unknown>(query: Record<string, string | number | undefined> = {}): Promise<T | null> {
    const params = new URLSearchParams();
    Object.entries(query).forEach(([key, value]) => {
        if (value !== undefined && value !== '') params.set(key, String(value));
    });
    const suffix = params.size ? `?${params.toString()}` : '';
    return api.get<T>(`${API_SECURITY_INVENTORY_ENDPOINT}${suffix}`);
}

export function uploadAPISecuritySchema(payload: APISecuritySchemaUploadPayload): Promise<unknown> {
    return api.post(API_SECURITY_SCHEMA_UPLOAD_ENDPOINT, payload);
}
