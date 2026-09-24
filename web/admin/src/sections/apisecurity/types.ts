export type APISecurityPolicyId =
    | 'runtime'
    | 'contract'
    | 'authorization'
    | 'graphql'
    | 'abuse'
    | 'data';

export type APISecurityTabId = 'overview' | 'inventory' | APISecurityPolicyId | 'settings';
export type APISecurityUtilitySurfaceId = 'setup' | 'advanced';
export type APISecuritySurfaceId = APISecurityTabId | APISecurityUtilitySurfaceId;
export type APISecurityWizardId = 'schema' | 'identity' | 'data' | '';
export type APISecuritySurfaceChoice = 'all' | 'schema_backed' | 'host' | 'selected' | 'manual';

export type APISecurityProfileKey = 'runtime' | 'contract' | 'authorization' | 'graphql' | 'automation' | 'data';
export type APISecurityProfileValue = 'default' | 'strict' | 'monitor' | 'custom';

export type APISecurityFunctionConfigKey =
    | 'discovery'
    | 'validation'
    | 'injection'
    | 'ssrf'
    | 'payload_abuse'
    | 'graphql'
    | 'auth_tokens'
    | 'automation_abuse'
    | 'data_exposure'
    | 'bfla'
    | 'mass_assignment'
    | 'bola';

export interface APISecurityTab {
    id: APISecurityTabId;
    name: string;
    icon: string;
}

export interface APISecurityPolicyCatalogEntry {
    id: APISecurityPolicyId;
    title: string;
    operatorLabel: string;
    description: string;
    icon: string;
    summaryKey: string;
    functions: APISecurityFunctionConfigKey[];
    advancedGroup: APISecurityPolicyId | 'discovery';
    setupTarget?: string;
    profileKey?: APISecurityProfileKey;
}

export interface APISecurityModuleConfig {
    enabled?: boolean;
    mode?: string;
    [key: string]: unknown;
}

export interface APISecurityAuthTokenIssuer {
    name?: string;
    issuer?: string;
    audiences?: string[];
    allowed_algorithms?: string[];
    jwks_url?: string;
}

export interface APISecurityBolaOwnershipRule {
    name?: string;
    resource_pattern?: string;
    owner_id_param?: string;
    owner_id_claim?: string;
    allowed_roles?: string[];
}

export interface APISecurityBFLARule {
    name?: string;
    methods?: string[];
    path_pattern?: string;
    required_roles?: string[];
    required_claim?: string;
}

export interface APISecurityMassAssignmentPathRule {
    path_pattern?: string;
    methods?: string[];
    protected_fields?: string[];
}

export interface APISecurityInventoryMetadata {
    triage?: string;
    criticality?: string;
    environment?: string;
    owner?: string;
    service?: string;
    tags?: string[];
    notes?: string;
}

export interface APISecurityState {
    [key: string]: unknown;
    data_dir?: string;
    protection_level?: number;
    mode?: string;
    log_threshold?: number;
    challenge_threshold?: number;
    block_threshold?: number;
    discovery?: APISecurityModuleConfig;
    validation?: APISecurityModuleConfig;
    injection?: APISecurityModuleConfig;
    ssrf?: APISecurityModuleConfig;
    payload_abuse?: APISecurityModuleConfig;
    graphql?: APISecurityModuleConfig;
    auth_tokens?: APISecurityModuleConfig & { issuers?: APISecurityAuthTokenIssuer[] };
    automation_abuse?: APISecurityModuleConfig;
    data_exposure?: APISecurityModuleConfig;
    bfla?: APISecurityModuleConfig & { rules?: APISecurityBFLARule[] };
    mass_assignment?: APISecurityModuleConfig & { path_rules?: APISecurityMassAssignmentPathRule[] };
    bola?: APISecurityModuleConfig & { ownership_rules?: APISecurityBolaOwnershipRule[] };
    inventory_metadata?: Record<string, APISecurityInventoryMetadata>;
    dashboard_views?: unknown[];
    alert_rules?: unknown[];
    setup_workflow?: unknown;
    enabled_functions?: Partial<Record<APISecurityFunctionConfigKey, boolean>>;
    function_settings?: Partial<Record<APISecurityFunctionConfigKey, APISecurityModuleConfig>>;
}

export interface APISecurityConfigResponse {
    enabled?: boolean;
    settings?: APISecurityState;
    [key: string]: unknown;
}

export interface APISecurityMutationResponse {
    success?: boolean;
    state?: 'active';
    active_revision?: string;
    config?: APISecurityConfigResponse;
    settings?: APISecurityState;
    [key: string]: unknown;
}

export interface APISecurityStats {
    threats_blocked?: number;
    requests_analyzed?: number;
    alerts_24h?: number;
    total_requests?: number;
    blocked_requests?: number;
    [key: string]: unknown;
}

export interface APISecurityDashboardPayload {
    summary?: Record<string, number>;
    inventory?: Record<string, number>;
    breakdowns?: Record<string, unknown[]>;
    module_summary?: Record<string, unknown>;
    events?: Record<string, unknown>;
}

export interface APISecurityDashboardResponse {
    dashboard?: APISecurityDashboardPayload;
    [key: string]: unknown;
}

export interface APISecurityEndpoint {
    method?: string;
    path?: string;
    host?: string;
    schema_status?: string;
    schema_type?: string;
    is_active?: boolean;
    metadata?: Record<string, unknown>;
    [key: string]: unknown;
}

export interface APISecuritySchemaUploadPayload {
    method: string;
    path: string;
    host: string;
    type: string;
    content: string;
}

export type APISecuritySettingCategory =
    | 'discovery'
    | 'inventory_classification'
    | 'schemas'
    | 'identity_auth_detection'
    | 'runtime'
    | 'authorization'
    | 'graphql'
    | 'abuse'
    | 'data_exposure'
    | 'exceptions'
    | 'integrations_reports';

export type APISecuritySettingControlType =
    | 'toggle'
    | 'segmented'
    | 'select'
    | 'number'
    | 'chip-list'
    | 'path-list'
    | 'endpoint-picker'
    | 'rule-table'
    | 'schema-upload'
    | 'readonly';

export interface APISecuritySettingDefinition {
    id: string;
    category: APISecuritySettingCategory;
    label: string;
    description: string;
    configPath: string;
    functionSettingsMirrorPath?: string;
    controlType: APISecuritySettingControlType;
    defaultValue?: unknown;
    profileOwnership?: APISecurityProfileKey;
    riskLevel?: 'low' | 'medium' | 'high';
    visibleWhen?: string;
    validation?: string;
    saveBehavior: 'settings' | 'settings-and-function-mirror' | 'readonly' | 'external-api';
}

export interface APISecuritySavePayload {
    enabled: boolean;
    settings: APISecurityState;
}
