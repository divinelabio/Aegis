import { API_SECURITY_FUNCTION_CONFIG_KEYS, SUPPORTED_CONFIG_KEYS } from './constants.js';
import { cloneAPISecurityValue, normalizeAPISecurityConfigShape } from './normalizers.js';
export function isAPISecurityFunctionConfigKey(value) {
    return API_SECURITY_FUNCTION_CONFIG_KEYS.includes(value);
}
export function getAPISecurityFunctionSettingsMirrorPath(path) {
    const [root, ...rest] = path.split('.');
    if (!root || rest.length === 0)
        return '';
    if (!isAPISecurityFunctionConfigKey(root))
        return '';
    return `function_settings.${root}.${rest.join('.')}`;
}
export function setAPISecurityConfigValue(config, path, value) {
    const parts = path.split('.').filter(Boolean);
    if (parts.length === 0)
        return;
    let current = config;
    parts.slice(0, -1).forEach(part => {
        if (typeof current[part] !== 'object' || current[part] === null) {
            current[part] = {};
        }
        current = current[part];
    });
    current[parts[parts.length - 1]] = value;
}
export function buildAPISecuritySavePayload(config, sectionEnabled) {
    const normalized = normalizeAPISecurityConfigShape(config);
    const settings = {};
    SUPPORTED_CONFIG_KEYS.forEach(key => {
        const value = normalized[key];
        if (value !== undefined) {
            settings[key] = cloneAPISecurityValue(value);
        }
    });
    return {
        enabled: sectionEnabled,
        settings
    };
}
