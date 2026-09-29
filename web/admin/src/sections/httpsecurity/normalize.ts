import { api } from '../../api.js';
import { FEATURES } from '../../core/features.js';
import {
    HTTPSEC_ADVANCED_CONFIG_ROOTS,
    HTTPSEC_BASIC_CONFIG_ROOTS,
    HTTPSEC_FALLBACK_CAPABILITIES,
    HTTPSEC_ROOT_CAPABILITY
} from './constants.js';
import type { HTTPSecurityCapabilities, HTTPSecurityCapability, HTTPSecurityFunctionInfo } from './types.js';

export function cloneHTTPSecurityValue<T>(value: T): T {
    if (value == null || typeof value !== 'object') return value;
    return JSON.parse(JSON.stringify(value));
}

export function getHTTPSecurityCapability(capabilities: HTTPSecurityCapabilities | null | undefined, id: string): HTTPSecurityCapability | null {
    return capabilities?.[id] || HTTPSEC_FALLBACK_CAPABILITIES[id] || null;
}

export function isHTTPSecurityConfigurable(capabilities: HTTPSecurityCapabilities | null | undefined, id: string): boolean {
    if (id === 'request_body_guard' && !api.hasFeature(FEATURES.WAF_BODY_GUARD)) {
        return false;
    }
    if (id === 'upload_protection' && !api.hasFeature(FEATURES.WAF_UPLOAD)) {
        return false;
    }
    const capability = getHTTPSecurityCapability(capabilities, id);
    return capability?.status === 'available' && capability?.config_supported === true;
}

export function normalizeHTTPSecurityCapability(info: HTTPSecurityFunctionInfo): HTTPSecurityCapability {
    const fallback = HTTPSEC_FALLBACK_CAPABILITIES[info?.id] || {};
    const capability = { ...fallback, ...(info?.capability || {}) } as HTTPSecurityCapability;
    if (!capability.status) capability.status = info?.enabled === false ? 'unsupported' : 'available';
    capability.config_supported = capability.config_supported === true;
    capability.runtime_implemented = capability.runtime_implemented === true;
    capability.toggle_supported = capability.toggle_supported === true;
    return capability;
}

export function buildHTTPSecuritySavePayload(config: Record<string, unknown>, capabilities: HTTPSecurityCapabilities): Record<string, unknown> {
    const source = cloneHTTPSecurityValue(config) || {};
    const payload: Record<string, unknown> = {};
    for (const key of HTTPSEC_BASIC_CONFIG_ROOTS) {
        if (Object.prototype.hasOwnProperty.call(source, key)) payload[key] = source[key];
    }
    for (const key of HTTPSEC_ADVANCED_CONFIG_ROOTS) {
        const capabilityID = HTTPSEC_ROOT_CAPABILITY[key];
        if (Object.prototype.hasOwnProperty.call(source, key) && isHTTPSecurityConfigurable(capabilities, capabilityID)) {
            payload[key] = source[key];
        }
    }
    return payload;
}

export function normalizeHTTPSecurityExtension(value: unknown): string {
    const raw = String(value || '').trim().toLowerCase();
    if (!raw) return '';
    const withDot = raw.startsWith('.') ? raw : `.${raw}`;
    return withDot.replace(/\s+/g, '');
}

export function normalizeHTTPSecurityExtensionList(values: unknown): string[] {
    if (!Array.isArray(values)) return [];
    return [...new Set(values.map(normalizeHTTPSecurityExtension).filter(Boolean))];
}
