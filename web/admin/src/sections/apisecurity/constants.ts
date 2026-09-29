import type {
    APISecurityFunctionConfigKey,
    APISecurityPolicyCatalogEntry
} from './types.js';

export const API_SECURITY_CONFIG_ENDPOINT = 'sections/api_security/config';
export const API_SECURITY_LIFECYCLE_ENDPOINT = 'sections/api_security/lifecycle';
export const API_SECURITY_STATS_ENDPOINT = 'sections/api_security/stats';
export const API_SECURITY_INVENTORY_ENDPOINT = 'sections/api_security/inventory';
export const API_SECURITY_SCHEMA_UPLOAD_ENDPOINT = 'sections/api_security/schemas';
export const API_SECURITY_DASHBOARD_ENDPOINT = 'sections/api_security/analytics/dashboard?window=24h&limit=5';

export const APISEC_DASHBOARD_PENDING_FILTERS_KEY = 'aegis.apisec.dashboard.pendingFilters';
export const APISEC_CONFIG_PENDING_FOCUS_KEY = 'aegis.apisec.config.pendingFocus';

export const SUPPORTED_CONFIG_KEYS = [
    'discovery',
    'validation',
    'injection',
    'ssrf',
    'payload_abuse',
    'graphql',
    'auth_tokens',
    'automation_abuse',
    'data_exposure',
    'bfla',
    'mass_assignment',
    'bola',
    'inventory_metadata',
    'dashboard_views',
    'alert_rules',
    'setup_workflow'
] as const;

export type APISecuritySupportedConfigKey = typeof SUPPORTED_CONFIG_KEYS[number];

export const API_SECURITY_FUNCTION_CONFIG_KEYS: APISecurityFunctionConfigKey[] = [
    'discovery',
    'validation',
    'injection',
    'ssrf',
    'payload_abuse',
    'graphql',
    'auth_tokens',
    'automation_abuse',
    'data_exposure',
    'bfla',
    'mass_assignment',
    'bola'
];

export const API_SECURITY_POLICY_CATALOG: APISecurityPolicyCatalogEntry[] = [
    {
        id: 'runtime',
        title: 'Runtime Blocking',
        operatorLabel: 'Runtime attacks',
        description: 'Stops high-confidence injection, SSRF, and abusive payloads.',
        icon: 'shield',
        summaryKey: 'runtime_blocking',
        functions: ['injection', 'ssrf', 'payload_abuse'],
        advancedGroup: 'runtime',
        setupTarget: 'surface',
        profileKey: 'runtime'
    },
    {
        id: 'contract',
        title: 'Contract Enforcement',
        operatorLabel: 'Schema policy',
        description: 'Validates API traffic against attached OpenAPI and GraphQL schemas.',
        icon: 'fileText',
        summaryKey: 'contract_enforcement',
        functions: ['validation'],
        advancedGroup: 'contract',
        setupTarget: 'schemas',
        profileKey: 'contract'
    },
    {
        id: 'authorization',
        title: 'API Authorization',
        operatorLabel: 'Operation and object access',
        description: 'Protects API operations, objects, tenants, and request fields after Edge Access establishes identity.',
        icon: 'lock',
        summaryKey: 'authorization',
        functions: ['bfla', 'mass_assignment', 'bola'],
        advancedGroup: 'authorization',
        setupTarget: 'identity',
        profileKey: 'authorization'
    },
    {
        id: 'graphql',
        title: 'GraphQL Protection',
        operatorLabel: 'GraphQL APIs',
        description: 'Protects GraphQL endpoints from introspection and expensive queries.',
        icon: 'code',
        summaryKey: 'graphql',
        functions: ['graphql'],
        advancedGroup: 'graphql',
        setupTarget: 'surface',
        profileKey: 'graphql'
    },
    {
        id: 'abuse',
        title: 'Abuse And Automation',
        operatorLabel: 'Automation abuse',
        description: 'Detects credential attacks, probing, enumeration, and scraping bursts.',
        icon: 'alert',
        summaryKey: 'abuse_automation',
        functions: ['automation_abuse'],
        advancedGroup: 'abuse',
        setupTarget: 'surface',
        profileKey: 'automation'
    },
    {
        id: 'data',
        title: 'Data Exposure',
        operatorLabel: 'Sensitive data',
        description: 'Detects sensitive request data and response leaks.',
        icon: 'database',
        summaryKey: 'data_exposure',
        functions: ['data_exposure'],
        advancedGroup: 'data',
        setupTarget: 'surface',
        profileKey: 'data'
    }
];

export const API_SECURITY_SCOPE_PICKER_PATHS = new Set([
    'discovery.paths',
    'graphql.paths',
    'auth_tokens.protected_paths',
    'auth_tokens.excluded_paths',
    'automation_abuse.login_paths',
    'automation_abuse.otp_paths',
    'automation_abuse.monitored_paths',
    'data_exposure.excluded_paths',
    'bola.isolated_paths'
]);

export const API_SECURITY_STRING_LIST_PATHS = new Set([
    ...API_SECURITY_SCOPE_PICKER_PATHS,
    'auth_tokens.required_claims',
    'automation_abuse.identifier_fields',
    'mass_assignment.protected_fields'
]);
