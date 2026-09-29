import { HTTPSEC_FALLBACK_CAPABILITIES } from './constants.js';
import { buildHTTPSecuritySavePayload, cloneHTTPSecurityValue, isHTTPSecurityConfigurable } from './normalize.js';
const EDITION_LABELS = {
    community: 'Community',
    professional: 'Professional',
    enterprise: 'Enterprise',
    commercial: 'Commercial',
    unknown: 'Unknown'
};
function sectionValue(config, key) {
    return cloneHTTPSecurityValue(config[key] ?? {});
}
function optionalSectionValue(config, capabilities, key, capabilityID) {
    if (!isHTTPSecurityConfigurable(capabilities, capabilityID)) {
        return undefined;
    }
    if (!Object.prototype.hasOwnProperty.call(config, key)) {
        return undefined;
    }
    return sectionValue(config, key);
}
function normalizeEdition(edition) {
    if (edition && typeof edition === 'object') {
        const record = edition;
        const id = normalizeEditionID(record.id || record.tier || record.name);
        return {
            id,
            label: String(record.label || EDITION_LABELS[id])
        };
    }
    const id = normalizeEditionID(edition);
    return { id, label: EDITION_LABELS[id] };
}
function normalizeEditionID(value) {
    const raw = String(value || '').trim().toLowerCase();
    if (raw === 'community' || raw === 'professional' || raw === 'enterprise' || raw === 'commercial') {
        return raw;
    }
    return 'unknown';
}
function assignIfDefined(target, key, value) {
    if (value !== undefined)
        target[key] = cloneHTTPSecurityValue(value);
}
export function createHTTPSecurityViewModel(config, capabilities, securityTxtContact, edition = 'unknown') {
    const source = cloneHTTPSecurityValue(config || {});
    const mergedCapabilities = {
        ...HTTPSEC_FALLBACK_CAPABILITIES,
        ...(capabilities || {})
    };
    return {
        edition: normalizeEdition(edition),
        capabilities: mergedCapabilities,
        requestPolicy: {
            hostValidator: sectionValue(source, 'host_validator'),
            methodEnforcer: sectionValue(source, 'method_enforcer'),
            contentTypeValidator: sectionValue(source, 'content_type_validator'),
            requestSizeGuard: sectionValue(source, 'request_size_guard'),
            headerManager: optionalSectionValue(source, mergedCapabilities, 'header_manager', 'header_manager')
        },
        payloadProtection: {
            uploadLimit: sectionValue(source, 'upload_limit'),
            requestBodyGuard: optionalSectionValue(source, mergedCapabilities, 'request_body_guard', 'request_body_guard')
        },
        uploadSecurity: {
            extensionFilter: sectionValue(source, 'extension_filter'),
            uploadProtection: optionalSectionValue(source, mergedCapabilities, 'upload_protection', 'upload_protection')
        },
        responseProtection: {
            securityHeaders: sectionValue(source, 'security_headers'),
            infoHiding: sectionValue(source, 'info_hiding'),
            cookieHardener: sectionValue(source, 'cookie_hardener'),
            headerManager: optionalSectionValue(source, mergedCapabilities, 'header_manager', 'header_manager'),
            securityTxt: {
                contact: String(securityTxtContact || '')
            }
        },
        optimization: {
            gzip: sectionValue(source, 'gzip'),
            htmlInjector: optionalSectionValue(source, mergedCapabilities, 'html_injector', 'html_injector')
        }
    };
}
export function buildHTTPSecurityConfigFromViewModel(model) {
    const config = {};
    assignIfDefined(config, 'host_validator', model.requestPolicy.hostValidator);
    assignIfDefined(config, 'method_enforcer', model.requestPolicy.methodEnforcer);
    assignIfDefined(config, 'content_type_validator', model.requestPolicy.contentTypeValidator);
    assignIfDefined(config, 'request_size_guard', model.requestPolicy.requestSizeGuard);
    assignIfDefined(config, 'upload_limit', model.payloadProtection.uploadLimit);
    assignIfDefined(config, 'extension_filter', model.uploadSecurity.extensionFilter);
    assignIfDefined(config, 'security_headers', model.responseProtection.securityHeaders);
    assignIfDefined(config, 'info_hiding', model.responseProtection.infoHiding);
    assignIfDefined(config, 'cookie_hardener', model.responseProtection.cookieHardener);
    assignIfDefined(config, 'gzip', model.optimization.gzip);
    assignIfDefined(config, 'header_manager', model.requestPolicy.headerManager ?? model.responseProtection.headerManager);
    assignIfDefined(config, 'request_body_guard', model.payloadProtection.requestBodyGuard);
    assignIfDefined(config, 'upload_protection', model.uploadSecurity.uploadProtection);
    assignIfDefined(config, 'html_injector', model.optimization.htmlInjector);
    return config;
}
export function buildHTTPSecuritySavePayloadFromViewModel(model) {
    return buildHTTPSecuritySavePayload(buildHTTPSecurityConfigFromViewModel(model), model.capabilities);
}
