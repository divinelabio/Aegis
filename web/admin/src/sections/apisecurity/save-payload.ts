import { API_SECURITY_FUNCTION_CONFIG_KEYS, SUPPORTED_CONFIG_KEYS } from './constants.js';
import { cloneAPISecurityValue, normalizeAPISecurityConfigShape } from './normalizers.js';
import type {
    APISecurityFunctionConfigKey,
    APISecuritySavePayload,
    APISecurityState
} from './types.js';

export function isAPISecurityFunctionConfigKey(value: string): value is APISecurityFunctionConfigKey {
    return API_SECURITY_FUNCTION_CONFIG_KEYS.includes(value as APISecurityFunctionConfigKey);
}

export function getAPISecurityFunctionSettingsMirrorPath(path: string): string {
    const [root, ...rest] = path.split('.');
    if (!root || rest.length === 0) return '';
    if (!isAPISecurityFunctionConfigKey(root)) return '';
    return `function_settings.${root}.${rest.join('.')}`;
}

export function setAPISecurityConfigValue(config: APISecurityState, path: string, value: unknown): void {
    const parts = path.split('.').filter(Boolean);
    if (parts.length === 0) return;
    let current: Record<string, unknown> = config;
    parts.slice(0, -1).forEach(part => {
        if (typeof current[part] !== 'object' || current[part] === null) {
            current[part] = {};
        }
        current = current[part] as Record<string, unknown>;
    });
    current[parts[parts.length - 1]] = value;
}

export function buildAPISecuritySavePayload(config: APISecurityState, sectionEnabled: boolean): APISecuritySavePayload {
    const normalized = normalizeAPISecurityConfigShape(config);
    const settings: APISecurityState = {};

    SUPPORTED_CONFIG_KEYS.forEach(key => {
        const value = normalized[key];
        if (value !== undefined) {
            (settings as Record<string, unknown>)[key] = cloneAPISecurityValue(value);
        }
    });

    return {
        enabled: sectionEnabled,
        settings
    };
}
