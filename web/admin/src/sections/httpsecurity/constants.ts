import type { HTTPSecurityCapability, HTTPSecurityProfile } from './types.js';

export const HTTP_SECURITY_EFFECTIVE_STATE_ENDPOINT = 'sections/http_security/effective-state';

export const HTTPSEC_TABS = [
    { id: 'overview', name: 'Overview', icon: 'shield' },
    { id: 'request_policy', name: 'Request Policy', icon: 'sliders' },
    { id: 'payload_protection', name: 'Payload Protection', icon: 'activity' },
    { id: 'upload_security', name: 'Upload Security', icon: 'upload' },
    { id: 'response_protection', name: 'Response Protection', icon: 'shield' }
];

export const HTTPSEC_ROOT_CAPABILITY: Record<string, string> = {
    upload_limit: 'upload_limit',
    extension_filter: 'extension_filter',
    method_enforcer: 'method_enforcer',
    host_validator: 'host_validator',
    content_type_validator: 'content_type_validator',
    request_size_guard: 'request_size_guard',
    request_body_guard: 'request_body_guard',
    upload_protection: 'upload_protection',
    security_headers: 'security_headers',
    security_txt: 'security_txt',
    header_manager: 'header_manager',
    info_hiding: 'info_hiding',
    cookie_hardener: 'cookie_hardener',
    https_redirect: 'https_redirect',
    gzip: 'gzip',
    html_injector: 'html_injector'
};

export const HTTPSEC_BASIC_CONFIG_ROOTS = [
    'enabled',
    'protection_level',
    'upload_limit',
    'extension_filter',
    'method_enforcer',
    'host_validator',
    'content_type_validator',
    'request_size_guard',
    'security_headers',
    'info_hiding',
    'cookie_hardener',
    'gzip'
];

export const HTTPSEC_ADVANCED_CONFIG_ROOTS = [
    'header_manager',
    'https_redirect',
    'html_injector',
    'request_body_guard',
    'upload_protection'
];

export const HTTPSEC_FALLBACK_CAPABILITIES: Record<string, HTTPSecurityCapability> = {
    upload_limit: { area: 'payload', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['upload_limit'] },
    extension_filter: { area: 'upload', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['extension_filter'] },
    method_enforcer: { area: 'request', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['method_enforcer'] },
    host_validator: { area: 'request', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['host_validator'] },
    content_type_validator: { area: 'request', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['content_type_validator'] },
    request_size_guard: { area: 'request', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['request_size_guard'] },
    request_body_guard: { area: 'payload', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['request_body_guard'] },
    upload_protection: { area: 'upload', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['upload_protection'] },
    security_headers: { area: 'response', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['security_headers'] },
    security_txt: { area: 'response', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: false, config_keys: ['security_txt.contact'] },
    header_manager: { area: 'response', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['header_manager'] },
    info_hiding: { area: 'response', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['info_hiding'] },
    cookie_hardener: { area: 'response', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['cookie_hardener'] },
    https_redirect: { area: 'response', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['https_redirect'] },
    gzip: { area: 'optimization', status: 'available', config_supported: true, runtime_implemented: true, toggle_supported: true, config_keys: ['gzip'] },
    html_injector: { area: 'optimization', status: 'not_implemented', config_supported: false, runtime_implemented: false, toggle_supported: false, config_keys: ['html_injector'] }
};

export const HTTPSEC_METHOD_PROFILES: Record<string, HTTPSecurityProfile & { mode?: string; methods?: string[] }> = {
    recommended: { id: 'recommended', label: 'Recommended', note: 'Risky methods blocked', mode: 'blocklist', methods: ['TRACE', 'TRACK', 'CONNECT', 'DEBUG'] },
    api_strict: { id: 'api_strict', label: 'API strict', note: 'Common API methods only', mode: 'allowlist', methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] },
    read_only: { id: 'read_only', label: 'Read-only', note: 'Safe read methods only', mode: 'allowlist', methods: ['GET', 'HEAD', 'OPTIONS'] },
    custom: { id: 'custom', label: 'Custom', note: 'Exact method selection' }
};

export const HTTPSEC_CONTENT_TYPE_PROFILES: Record<string, HTTPSecurityProfile & { enabled: boolean; requiredOn: string[] }> = {
    off: { id: 'off', label: 'Off', note: 'Not required', enabled: false, requiredOn: [] },
    writes: { id: 'writes', label: 'Writes', note: 'POST, PUT, PATCH', enabled: true, requiredOn: ['POST', 'PUT', 'PATCH'] },
    strict_writes: { id: 'strict_writes', label: 'Strict writes', note: 'Includes DELETE', enabled: true, requiredOn: ['POST', 'PUT', 'PATCH', 'DELETE'] },
    custom: { id: 'custom', label: 'Custom', note: 'Exact method selection', enabled: true, requiredOn: [] }
};

export const HTTPSEC_BOUNDARY_PROFILES: Record<string, HTTPSecurityProfile & Record<string, number | string>> = {
    relaxed: { id: 'relaxed', label: 'Relaxed', note: 'Broad compatibility', max_url_length: 4096, max_query_length: 4096, max_header_count: 100, max_single_header_size: 16384 },
    balanced: { id: 'balanced', label: 'Balanced', note: 'Recommended default', max_url_length: 2048, max_query_length: 2048, max_header_count: 50, max_single_header_size: 8192 },
    strict: { id: 'strict', label: 'Strict', note: 'Tighter public profile', max_url_length: 1024, max_query_length: 1024, max_header_count: 32, max_single_header_size: 4096 },
    custom: { id: 'custom', label: 'Custom', note: 'Exact request envelope' }
};

export const HTTPSEC_PAYLOAD_PROFILES: Record<string, HTTPSecurityProfile> = {
    size_only: { id: 'size_only', label: 'Size only', note: 'Body limit only' },
    monitor: { id: 'monitor', label: 'Monitor', note: 'Detect structured abuse' },
    block_obvious: { id: 'block_obvious', label: 'Block obvious abuse', note: 'Block high-confidence findings' },
    custom: { id: 'custom', label: 'Custom', note: 'Expert parser tuning' }
};

export const HTTPSEC_PAYLOAD_INSPECTION_PROFILES: Record<string, HTTPSecurityProfile & { maxFindings: number; jsonDepth: number; jsonKeys: number; formParameters: number; multipartParts: number }> = {
    relaxed: { id: 'relaxed', label: 'Relaxed', note: 'Higher limits for compatible integrations', maxFindings: 200, jsonDepth: 48, jsonKeys: 5000, formParameters: 2000, multipartParts: 200 },
    balanced: { id: 'balanced', label: 'Balanced', note: 'Recommended protection for most applications', maxFindings: 100, jsonDepth: 32, jsonKeys: 2000, formParameters: 1000, multipartParts: 100 },
    strict: { id: 'strict', label: 'Strict', note: 'Tighter limits for public endpoints', maxFindings: 25, jsonDepth: 16, jsonKeys: 500, formParameters: 250, multipartParts: 40 },
    custom: { id: 'custom', label: 'Custom', note: 'Configure detailed inspection controls', maxFindings: 0, jsonDepth: 0, jsonKeys: 0, formParameters: 0, multipartParts: 0 }
};

export const HTTPSEC_UPLOAD_PROFILES: Record<string, HTTPSecurityProfile> = {
    basic_extension_filter: { id: 'basic_extension_filter', label: 'Basic filter', note: 'Block dangerous extensions' },
    strict_file_validation: { id: 'strict_file_validation', label: 'Inspect only', note: 'Inspect file content without blocking' },
    custom: { id: 'custom', label: 'Custom', note: 'Expert upload tuning' }
};

export const HTTPSEC_RESPONSE_PROFILES: Record<string, HTTPSecurityProfile> = {
    baseline: { id: 'baseline', label: 'Baseline', note: 'Recommended browser safety' },
    strict_browser: { id: 'strict_browser', label: 'Strict browser', note: 'Tighter modern browser policy' },
    compatibility: { id: 'compatibility', label: 'Compatibility', note: 'Legacy-friendly defaults' },
    custom: { id: 'custom', label: 'Custom', note: 'Exact header policy' }
};

export const HTTPSEC_COOKIE_PROFILES: Record<string, HTTPSecurityProfile> = {
    balanced: { id: 'balanced', label: 'Balanced', note: 'Secure, HttpOnly, Lax' },
    strict: { id: 'strict', label: 'Strict', note: 'Secure, HttpOnly, Strict' },
    preserve: { id: 'preserve', label: 'Preserve', note: 'Do not rewrite cookies' },
    custom: { id: 'custom', label: 'Custom', note: 'Exact cookie flags' }
};

export const HTTPSEC_EXTENSION_GROUPS: Record<string, { label: string; values: string[] }> = {
    dangerous: { label: 'Dangerous', values: ['.exe', '.dll', '.bat', '.cmd', '.sh', '.php', '.jsp', '.aspx', '.jar', '.ps1'] },
    images: { label: 'Images', values: ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'] },
    documents: { label: 'Documents', values: ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'] },
    archives: { label: 'Archives', values: ['.zip', '.rar', '.7z', '.tar', '.gz'] },
    office: { label: 'Office', values: ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf'] }
};

export const HTTPSEC_CSP_DIRECTIVES = ['default-src', 'script-src', 'style-src', 'img-src', 'connect-src', 'frame-ancestors'];
export const HTTPSEC_PERMISSION_FEATURES = ['camera', 'microphone', 'geolocation', 'payment', 'usb', 'fullscreen', 'autoplay'];
