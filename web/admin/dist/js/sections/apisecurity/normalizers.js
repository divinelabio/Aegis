export function cloneAPISecurityValue(value) {
    if (value === undefined)
        return value;
    return JSON.parse(JSON.stringify(value));
}
export function normalizeAPISecurityMode(value, fallback = 'detect') {
    return String(value || '').trim().toLowerCase() === 'block' ? 'block' : fallback;
}
export function normalizeAPISecurityConfigShape(input) {
    const config = cloneAPISecurityValue(input || {});
    config.enabled_functions = { ...(config.enabled_functions || {}) };
    config.function_settings = { ...(config.function_settings || {}) };
    config.inventory_metadata = { ...(config.inventory_metadata || {}) };
    config.dashboard_views = Array.isArray(config.dashboard_views) ? config.dashboard_views : [];
    config.alert_rules = Array.isArray(config.alert_rules) ? config.alert_rules : [];
    removeAPISecurityLegacyIdentitySettings(config.bfla, ['role_header']);
    removeAPISecurityLegacyIdentitySettings(config.bola, ['user_id_header', 'user_roles_header', 'tenant_header', 'learning_mode', 'learning_days']);
    removeAPISecurityLegacyIdentitySettings(config.function_settings.bfla, ['role_header']);
    removeAPISecurityLegacyIdentitySettings(config.function_settings.bola, ['user_id_header', 'user_roles_header', 'tenant_header', 'learning_mode', 'learning_days']);
    return config;
}
function removeAPISecurityLegacyIdentitySettings(value, keys) {
    if (typeof value !== 'object' || value === null)
        return;
    const settings = value;
    keys.forEach(key => delete settings[key]);
}
