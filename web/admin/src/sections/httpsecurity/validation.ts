import { HTTPSEC_CSP_DIRECTIVES, HTTPSEC_PERMISSION_FEATURES } from './constants.js';
import { normalizeHTTPSecurityExtensionList } from './normalize.js';
import type { HTTPSecurityValidationResult } from './types.js';

export const HTTPSEC_HEADER_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
export const HTTPSEC_EXTENSION_PATTERN = /^\.[a-z0-9][a-z0-9._+-]{0,31}$/;

export function isValidHTTPSecurityHeaderName(value: unknown): boolean {
    const text = String(value || '').trim();
    return text.length > 0 && HTTPSEC_HEADER_NAME_PATTERN.test(text);
}

export function isValidHTTPSecurityExtension(value: unknown): boolean {
    return HTTPSEC_EXTENSION_PATTERN.test(String(value || '').trim().toLowerCase());
}

export function parseHTTPSecurityCSP(value: unknown): Record<string, string[]> {
    const result: Record<string, string[]> = {};
    String(value || '').split(';').forEach((part) => {
        const tokens = part.trim().split(/\s+/).filter(Boolean);
        if (!tokens.length) return;
        const [directive, ...sources] = tokens;
        result[directive] = sources;
    });
    return result;
}

export function serializeHTTPSecurityCSP(map: Record<string, string[]>): string {
    return HTTPSEC_CSP_DIRECTIVES
        .filter((directive) => Array.isArray(map[directive]) && map[directive].length > 0)
        .map((directive) => `${directive} ${map[directive].join(' ')}`)
        .join('; ');
}

export function applyHTTPSecurityCSPPreset(preset: string, current = ''): string {
    if (preset === 'strict') {
        return "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";
    }
    if (preset === 'compatibility') {
        return "default-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'self'";
    }
    if (current && preset === 'baseline-preserve') return current;
    return "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'";
}

export function parseHTTPSecurityPermissionsPolicy(value: unknown): Record<string, string> {
    const result: Record<string, string> = {};
    String(value || '').split(',').forEach((part) => {
        const [rawFeature, rawAllow] = part.split('=');
        const feature = String(rawFeature || '').trim();
        const allow = String(rawAllow || '').trim();
        if (!feature) return;
        result[feature] = allow || '()';
    });
    return result;
}

export function serializeHTTPSecurityPermissionsPolicy(map: Record<string, string>): string {
    return HTTPSEC_PERMISSION_FEATURES
        .filter((feature) => map[feature])
        .map((feature) => `${feature}=${map[feature]}`)
        .join(', ');
}

export function applyHTTPSecurityPermissionsPreset(preset: string): string {
    if (preset === 'compatibility') {
        return 'camera=(), microphone=(), geolocation=(self), payment=(self), usb=(), fullscreen=(self), autoplay=(self)';
    }
    if (preset === 'strict') {
        return 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(), autoplay=()';
    }
    return 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(self), autoplay=()';
}

export function validateHTTPSecurityConfig(config: Record<string, unknown>): HTTPSecurityValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const headerManager = config.header_manager as Record<string, unknown> | undefined;
    const addMaps = [
        ['request', headerManager?.add_request_headers],
        ['response', headerManager?.add_response_headers]
    ] as const;
    for (const [label, map] of addMaps) {
        if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
        const seen = new Set<string>();
        for (const key of Object.keys(map)) {
            if (!isValidHTTPSecurityHeaderName(key)) errors.push(`Invalid ${label} header name: ${key}`);
            const lower = key.toLowerCase();
            if (seen.has(lower)) errors.push(`Duplicate ${label} header name: ${key}`);
            seen.add(lower);
        }
    }
    for (const [label, list] of [
        ['removed request', headerManager?.remove_request_headers],
        ['removed response', headerManager?.remove_response_headers],
        ['hidden response', (config.info_hiding as Record<string, unknown> | undefined)?.strip_headers]
    ] as const) {
        if (!Array.isArray(list)) continue;
        for (const name of list) {
            if (!isValidHTTPSecurityHeaderName(name)) errors.push(`Invalid ${label} header name: ${name}`);
        }
    }
    for (const [label, list] of [
        ['blocked upload', (config.extension_filter as Record<string, unknown> | undefined)?.blocked_extensions],
        ['blocked upload', (config.upload_protection as Record<string, unknown> | undefined)?.blocked_extensions],
        ['allowed upload', (config.upload_protection as Record<string, unknown> | undefined)?.allowed_extensions]
    ] as const) {
        for (const ext of normalizeHTTPSecurityExtensionList(list)) {
            if (!isValidHTTPSecurityExtension(ext)) errors.push(`Invalid ${label} extension: ${ext}`);
        }
    }
    const cookie = config.cookie_hardener as Record<string, unknown> | undefined;
    if (cookie?.force_samesite === 'None' && cookie?.force_secure !== true) {
        warnings.push('SameSite=None cookies should also force Secure.');
    }
    const securityHeaders = config.security_headers as Record<string, unknown> | undefined;
    const csp = String(securityHeaders?.csp || '');
    if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
        warnings.push('CSP contains unsafe inline/eval sources.');
    }
    if (csp && !parseHTTPSecurityCSP(csp)['default-src']) {
        warnings.push('CSP does not define default-src.');
    }
    const permissions = String(securityHeaders?.permissions_policy || '');
    if (permissions.includes('*')) warnings.push('Permissions Policy grants a wildcard capability.');
    return { errors, warnings };
}
