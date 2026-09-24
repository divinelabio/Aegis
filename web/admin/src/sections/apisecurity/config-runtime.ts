// API Security Configuration - Runtime-backed Phase 1 shell

import { api } from '../../api.js';
import * as AdminEvents from '../../core/events.js';
import { SectionUI } from '../ui-components.js';
import * as AdminDOM from '../../core/dom.js';
import { renderAPISecuritySaveButtons } from '../apisecurity-render-helpers.js';
import { showSectionToast } from '../section-toast-helpers.js';
import { escapeSectionHtml } from '../section-runtime-helpers.js';
import { FEATURES, renderUpgradeBanner } from '../../core/features.js';
import { router } from '../../router.js';
import {
    loadAPISecurityConfig,
    loadAPISecurityDashboard,
    loadAPISecurityInventory,
    loadAPISecurityStats,
    uploadAPISecuritySchema
} from './api.js';
import { API_SECURITY_CONFIG_ENDPOINT } from './constants.js';
import { renderAPISecurityMetricStrip } from './components/metric-strip.js';
import { API_SECURITY_SETTINGS_REGISTRY, getAPISecuritySettingsByCategory } from './registry/settings-registry.js';
import type { APISecuritySettingCategory, APISecuritySettingDefinition } from './types.js';

const APISEC_DASHBOARD_PENDING_FILTERS_KEY = 'aegis.apisec.dashboard.pendingFilters';
const APISEC_CONFIG_PENDING_FOCUS_KEY = 'aegis.apisec.config.pendingFocus';
const APISEC_INVENTORY_SAVED_VIEWS_KEY = 'aegis.apisec.inventory.savedViews.v1';
const APISEC_INVENTORY_RECENT_FILTERS_KEY = 'aegis.apisec.inventory.recentFilters.v1';
const APISEC_PENDING_SCHEMA_PREFILL_KEY = 'aegis.apisec.pendingSchemaPrefill';

type APISecurityPolicyId =

    | 'runtime'
    | 'contract'
    | 'authorization'
    | 'graphql'
    | 'abuse'
    | 'data';

type APISecurityTabId = 'overview' | 'inventory' | APISecurityPolicyId | 'settings';
type APISecuritySurfaceId = APISecurityTabId;
type APISecurityWizardId = 'schema' | 'identity' | 'data' | '';
type APISecuritySurfaceChoice = 'all' | 'schema_backed' | 'host' | 'selected' | 'manual';
type APISecurityPolicyEditorTab = 'basics' | 'scope' | 'detections' | 'exceptions';
type APISecurityInventoryColumnId = 'method' | 'traffic' | 'schema' | 'posture' | 'last_seen' | 'findings';
type APISecurityInventoryColumnVisibility = Record<APISecurityInventoryColumnId, boolean>;
type APISecurityInventoryGroupBy = 'none' | 'host' | 'method' | 'schema' | 'posture' | 'service' | 'owner';

interface APISecurityInventorySavedView {
    id: string;
    name: string;
    filters: APISecurityInventoryFilters;
    columns: APISecurityInventoryColumnVisibility;
    groupBy: APISecurityInventoryGroupBy;
    created_at: string;
    updated_at: string;
}

interface APISecurityInventoryRecentFilter {
    id: string;
    label: string;
    filters: APISecurityInventoryFilters;
    used_at: string;
}

interface APISecurityTab {
    id: APISecurityTabId;
    name: string;
    icon: string;
}

interface APISecurityPolicyCatalogEntry {
    id: APISecurityPolicyId;
    title: string;
    operatorLabel: string;
    description: string;
    icon: string;
    summaryKey: string;
    functions: string[];
    settingsGroup: APISecurityPolicyId | 'discovery';
    setupTarget?: string;
    profileKey?: APISecurityProfileKey;
}

interface APISecurityModuleConfig {
    enabled?: boolean;
    mode?: string;
    [key: string]: unknown;
}

interface APISecurityInjectionConfig extends APISecurityModuleConfig {
    sqli?: boolean;
    nosqli?: boolean;
    cmdi?: boolean;
    xss?: boolean;
    sensitivity?: string;
}

interface APISecuritySSRFConfig extends APISecurityModuleConfig {
    block_private_networks?: boolean;
    block_cloud_metadata?: boolean;
}

interface APISecurityPayloadAbuseConfig extends APISecurityModuleConfig {
    sensitivity?: string;
}

interface APISecurityAutomationAbuseConfig extends APISecurityModuleConfig {
    sensitivity?: string;
    enable_credential_stuffing?: boolean;
    enable_otp_bruteforce?: boolean;
    enable_forced_browsing?: boolean;
    enable_user_enumeration?: boolean;
    enable_object_enumeration?: boolean;
    enable_scraping?: boolean;
    login_paths?: string[];
    otp_paths?: string[];
    monitored_paths?: string[];
    identifier_fields?: string[];
}

interface APISecurityDataExposureConfig extends APISecurityModuleConfig {
    sensitivity?: string;
    inspect_requests?: boolean;
    inspect_responses?: boolean;
    response_handling?: string;
    detect_secrets?: boolean;
    detect_tokens?: boolean;
    detect_payment_data?: boolean;
    detect_pii?: boolean;
    detect_debug_data?: boolean;
    detect_internal_data?: boolean;
    excluded_paths?: string[];
}

interface APISecurityGraphQLConfig extends APISecurityModuleConfig {
    paths?: string[];
    max_depth?: number;
    max_aliases?: number;
    max_batch_size?: number;
    max_complexity?: number;
    block_introspection?: boolean;
}

interface APISecurityValidationConfig extends APISecurityModuleConfig {
    block_unknown_endpoints?: boolean;
    block_invalid_methods?: boolean;
    block_invalid_content_types?: boolean;
    strict_mode?: boolean;
    allow_unknown_fields?: boolean;
    schema_formats?: string[];
    validate_responses?: boolean;
}

interface APISecurityDiscoveryConfig extends APISecurityModuleConfig {
    paths?: string[];
    interval?: string;
    index_headers?: string[];
    detect_shadow_apis?: boolean;
    detect_zombie_apis?: boolean;
    zombie_inactivity_days?: number;
    auto_classify?: boolean;
}

interface APISecurityBolaConfig extends APISecurityModuleConfig {
    enable_ownership?: boolean;
    enable_tenant?: boolean;
    enable_idor?: boolean;
    strict_mode?: boolean;
    isolated_paths?: string[];
    ownership_rules?: APISecurityBolaOwnershipRule[];
}

interface APISecurityBolaOwnershipRule {
    name?: string;
    resource_pattern?: string;
    owner_id_param?: string;
    owner_id_claim?: string;
    allowed_roles?: string[];
}

interface APISecurityAuthTokenConfig extends APISecurityModuleConfig {
    protected_paths?: string[];
    excluded_paths?: string[];
    required_claims?: string[];
    require_signature?: boolean;
    issuers?: APISecurityAuthTokenIssuer[];
}

interface APISecurityAuthTokenIssuer {
    name?: string;
    issuer?: string;
    audiences?: string[];
    allowed_algorithms?: string[];
    jwks_url?: string;
}

interface APISecurityBFLAConfig extends APISecurityModuleConfig {
    rules?: APISecurityBFLARule[];
}

interface APISecurityBFLARule {
    name?: string;
    methods?: string[];
    path_pattern?: string;
    allowed_roles?: string[];
    required_claim_key?: string;
    required_claim_values?: string[];
}

interface APISecurityMassAssignmentConfig extends APISecurityModuleConfig {
    protected_fields?: string[];
    path_rules?: APISecurityMassAssignmentPathRule[];
}

interface APISecurityMassAssignmentPathRule {
    path_pattern?: string;
    fields?: string[];
}

interface APISecurityInventoryMetadata {
    owner?: string;
    service?: string;
    environment?: string;
    criticality?: string;
    triage_state?: string;
    tags?: string[];
    notes?: string;
    updated_at?: string;
}

interface APISecurityDashboardViewFilters {
    section?: string;
    action?: string;
    module?: string;
    function?: string;
    threat_type?: string;
    severity?: string;
    mode?: string;
    direction?: string;
    data_class?: string;
    response_action?: string;
    path?: string;
    method?: string;
    host?: string;
    ip?: string;
    status?: string;
    user_agent?: string;
    rule_id?: string;
    request_id?: string;
}

interface APISecurityDashboardView {
    id?: string;
    name?: string;
    window?: string;
    filters?: APISecurityDashboardViewFilters;
    created_at?: string;
    updated_at?: string;
}

interface APISecurityMonitoringRule {
    id?: string;
    name?: string;
    enabled?: boolean;
    rule_type?: string;
    module?: string;
    function?: string;
    threat_type?: string;
    severity?: string;
    action?: string;
    data_class?: string;
    response_action?: string;
    threshold?: number;
    window?: string;
    group_by?: string;
    description?: string;
    created_at?: string;
    updated_at?: string;
}

interface APISecuritySetupWorkflow {
    dismissed?: boolean;
    completed_steps?: string[];
    last_step?: string;
    updated_at?: string;
}

interface APISecurityState {
    enabled?: boolean;
    data_dir?: string;
    protection_level?: number;
    mode?: string;
    log_threshold?: number;
    challenge_threshold?: number;
    block_threshold?: number;
    discovery?: APISecurityDiscoveryConfig;
    validation?: APISecurityValidationConfig;
    injection?: APISecurityInjectionConfig;
    ssrf?: APISecuritySSRFConfig;
    payload_abuse?: APISecurityPayloadAbuseConfig;
    graphql?: APISecurityGraphQLConfig;
    auth_tokens?: APISecurityAuthTokenConfig;
    automation_abuse?: APISecurityAutomationAbuseConfig;
    data_exposure?: APISecurityDataExposureConfig;
    bfla?: APISecurityBFLAConfig;
    mass_assignment?: APISecurityMassAssignmentConfig;
    bola?: APISecurityBolaConfig;
    inventory_metadata?: Record<string, APISecurityInventoryMetadata>;
    dashboard_views?: APISecurityDashboardView[];
    alert_rules?: APISecurityMonitoringRule[];
    setup_workflow?: APISecuritySetupWorkflow;
    enabled_functions?: Record<string, boolean>;
    function_settings?: Record<string, Record<string, unknown>>;
    [key: string]: unknown;
}

interface APISecurityStats {
    threats_blocked?: number;
    requests_analyzed?: number;
    alerts_24h?: number;
    blocked_requests?: number;
    total_requests?: number;
    allowed_requests?: number;
    validated_apis?: number;
    custom?: Record<string, unknown>;
    [key: string]: unknown;
}

interface APISecurityConfigResponse {
    enabled?: boolean;
    settings?: APISecurityState;
    [key: string]: unknown;
}

interface APISecurityConfigMutation {
    success?: boolean;
    state?: 'active';
    [key: string]: unknown;
}

interface APISecuritySummary {
    total_requests?: number;
    blocked_threats?: number;
    detected_threats?: number;
    allowed_requests?: number;
    schema_validation_failures?: number;
    top_threat_type?: string;
    window?: string;
}

interface APISecurityInventoryCoverage {
    total_endpoints?: number;
    active_endpoints?: number;
    endpoints_with_schema?: number;
    endpoints_without_schema?: number;
    schema_coverage?: number;
    openapi_schemas?: number;
    graphql_schemas?: number;
}

interface APISecurityBreakdownItem {
    key?: string;
    label?: string;
    count?: number;
    blocked?: number;
    detected?: number;
    percent?: number;
    block_rate?: number;
    last_seen?: number;
}

interface APISecurityModuleSummary {
    findings?: number;
    blocks?: number;
    detects?: number;
    top_threat_type?: string;
    top_endpoint?: string;
    last_seen?: number;
    functions?: string[];
}

interface APISecurityEventRow {
    id?: string;
    timestamp?: number;
    action?: string;
    function?: string;
    threat_type?: string;
    severity?: string;
    client_ip?: string;
    method?: string;
    host?: string;
    path?: string;
    payload_snippet?: string;
    rule_name?: string;
    mode?: string;
    reason?: string;
    direction?: string;
    data_class?: string;
    response_action?: string;
    operation_name?: string;
    operation_type?: string;
    claim_name?: string;
    protected_field?: string;
    count?: number;
    threshold?: number;
    window_seconds?: number;
}

interface APISecurityEventsPage {
    events?: APISecurityEventRow[];
    count?: number;
    next_cursor?: string;
}

interface APISecurityDashboardPayload {
    summary?: APISecuritySummary;
    inventory?: APISecurityInventoryCoverage;
    breakdowns?: Record<string, APISecurityBreakdownItem[]>;
    module_summary?: Record<string, APISecurityModuleSummary>;
    events?: APISecurityEventsPage;
    warnings?: string[];
}

interface APISecurityDashboardResponse {
    success?: boolean;
    dashboard?: APISecurityDashboardPayload;
}

interface APISecurityEndpoint {
    id?: string;
    path?: string;
    method?: string;
    host?: string;
    first_seen?: string;
    last_seen?: string;
    is_active?: boolean;
    schema_status?: string;
    schema_type?: string;
    risk_status?: string;
    last_finding?: string;
    metadata?: Record<string, string>;
}

interface APISecurityInventoryPage {
    returned?: number;
    limit?: number;
    offset?: number;
    has_more?: boolean;
    next_offset?: number;
}

interface APISecurityInventoryResponse {
    endpoints?: APISecurityEndpoint[];
    page?: APISecurityInventoryPage;
}

interface APISecurityEndpointPosture {
    endpoint: APISecurityEndpoint;
    key: string;
    metadata: APISecurityInventoryMetadata;
    riskReasons: string[];
    riskScore: number;
    recentFindings: APISecurityEventRow[];
    endpointFindingCount: number;
    schemaMissing: boolean;
    isShadow: boolean;
    isZombie: boolean;
    hasSensitiveData: boolean;
    hasAuthorizationFindings: boolean;
    hasAutomationFindings: boolean;
    hasRepeatedFindings: boolean;
}

interface APISecurityInventoryFilters {
    search: string;
    host: string;
    method: string;
    schema: string;
    risk: string;
    active: string;
}

interface APISecurityScopePickerFilters {
    search: string;
    host: string;
    method: string;
    schema: string;
    risk: string;
    active: string;
}

interface APISecurityScopePickerTarget {
    path: string;
    title: string;
    mode: 'include' | 'exclude';
    tab: APISecuritySurfaceId;
}

interface APISecurityBlockingReviewTarget {
    moduleKey: string;
    functionKey: string;
    title: string;
    modePath: string;
    enabledPath?: string;
    tab: APISecuritySurfaceId;
}

type APISecurityProfileKey = 'runtime' | 'contract' | 'authorization' | 'graphql' | 'automation' | 'data';
type APISecurityProfileValue = 'default' | 'strict' | 'monitor' | 'custom';
type APISecurityNestedListKind = 'bola-rule' | 'auth-issuer' | 'bfla-rule' | 'mass-rule';
type APISecurityAuthorizationControl = 'function' | 'object' | 'fields' | '';
type APISecurityGraphQLControl = 'limits' | 'schema' | '';

interface APISecurityPolicyModeConfirmTarget {
    policyId: APISecurityPolicyId;
    mode: 'block';
    enableOnConfirm?: boolean;
    profileKey?: APISecurityProfileKey;
    profileValue?: APISecurityProfileValue;
}

interface APISecurityPolicyViewModel {
    policy: APISecurityPolicyCatalogEntry;
    enabled: boolean;
    mode: string;
    profile: APISecurityProfileValue;
    surfaceSummary: string;
    surfaceDetail: string;
}

interface APISecurityPolicyRow {
    title: string;
    description: string;
    icon: string;
    enabled: boolean;
    enabledPath?: string;
    mode?: string;
    modePath?: string;
    statePath?: string;
    stateKind?: 'boolean';
    status?: string;
    findings?: number;
    blocks?: number;
    extra?: string;
}

interface APISecurityStringListEditorOptions {
    placeholder?: string;
    addLabel?: string;
    emptyLabel?: string;
    inventory?: APISecurityEndpoint[];
    inventoryFilter?: (endpoint: APISecurityEndpoint) => boolean;
    suggestions?: string[];
    variant?: 'path' | 'chip' | 'text';
}


type APISecurityConfigRuntime = {
    containerId: string;
    currentTab: APISecurityTabId;
    config: APISecurityState;
    sectionEnabled: boolean;
    stats: APISecurityStats;
    dashboard: APISecurityDashboardPayload;
    inventory: APISecurityEndpoint[];
    inventoryPage: APISecurityInventoryPage;
    inventoryFilters: APISecurityInventoryFilters;
    inventoryFilterMenuOpen: boolean;
    inventoryViewMenuOpen: boolean;
    inventoryColumns: APISecurityInventoryColumnVisibility;
    inventoryGroupBy: APISecurityInventoryGroupBy;
    inventorySavedViews: APISecurityInventorySavedView[];
    inventoryRecentFilters: APISecurityInventoryRecentFilter[];
    scopePickerTarget: APISecurityScopePickerTarget | null;
    scopePickerFilters: APISecurityScopePickerFilters;
    scopePickerSelectedPaths: string[];
    scopePickerChoice: APISecuritySurfaceChoice;
    scopePickerHost: string;
    blockingReviewTarget: APISecurityBlockingReviewTarget | null;
    policyModeConfirmTarget: APISecurityPolicyModeConfirmTarget | null;
    selectedPolicyId: APISecurityPolicyId | '';
    selectedPolicyEditorTab: APISecurityPolicyEditorTab;
    selectedAuthorizationControl: APISecurityAuthorizationControl;
    selectedGraphQLControl: APISecurityGraphQLControl;
    selectedInventoryEndpointKey: string;
    selectedSettingsCategory: APISecuritySettingCategory;
    settingsEditorCategory: APISecuritySettingCategory | '';
    settingsSearch: string;
    changedSettings: string[];
    schemaPrefillEndpointKey: string;
    expandedBFLARuleIndex: number;
    expandedBolaRuleIndex: number;
    expandedMassRuleIndex: number;
    setupFocus: string;
    activeWizard: APISecurityWizardId;
    wizardStep: number;
    wizardSurfaceTarget: string;
    wizardSelectedPaths: string[];
    wizardPendingProfile: APISecurityProfileValue | '';
    wizardPendingMode: string;
    overviewLoading: boolean;
    overviewError: string;
    tabs: APISecurityTab[];
    icons: Record<string, string>;
    init(containerId?: string): Promise<void>;
    loadConfig(): Promise<void>;
    loadStats(): Promise<void>;
    loadOverviewData(): Promise<void>;
    loadMoreInventory(): Promise<void>;
    render(): void;
    switchTab(id: string): void;
    openPolicyDetail(id: string): void;
    closePolicyDetail(): void;
    switchPolicyEditorTab(id: string): void;
    openAuthorizationControl(id: string): void;
    closeAuthorizationControl(): void;
    openGraphQLControl(id: string): void;
    closeGraphQLControl(): void;
    focusSetup(id: string): void;
    openWizard(id: string, step?: number): void;
    closeWizard(): void;
    setWizardStep(step: number): void;
    applySchemaWizard(): Promise<void>;
    applyIdentityWizard(): void;
    applyDataWizard(): void;
    renderTabContent(): string;
    renderOverview(): string;
    renderPolicyDetail(id: APISecurityPolicyId): string;
    renderSettings(): string;
    renderInventory(): string;
    updateField(path: string, value: unknown): void;
    requestConfigFieldUpdate(path: string, value: unknown, renderAfterUpdate?: boolean): void;
    switchSettingsCategory(id: string): void;
    openSettingsCategory(id: string): void;
    closeSettingsCategory(): void;
    updateSettingsSearch(value: string): void;
    setPolicyEnabled(id: string, enabled: boolean): void;
    setPolicyFunctionState(enabledPath: string, modePath: string, state: string): void;
    setPolicyBooleanState(path: string, state: string): void;
    confirmPolicyMode(): void;
    cancelPolicyMode(): void;
    addStringListItem(path: string, value: string): void;
    updateStringListItem(path: string, index: number, value: string): void;
    removeStringListItem(path: string, index: number): void;
    addNestedListItem(kind: APISecurityNestedListKind, parentIndex: number, field: string, value: string): void;
    updateNestedListItem(kind: APISecurityNestedListKind, parentIndex: number, field: string, itemIndex: number, value: string): void;
    removeNestedListItem(kind: APISecurityNestedListKind, parentIndex: number, field: string, itemIndex: number): void;
    updateInventoryFilter(key: string, value: string): void;
    toggleInventoryFilterMenu(): void;
    toggleInventoryViewMenu(): void;
    toggleInventoryColumn(column: string): void;
    setInventoryGroupBy(value: string): void;
    saveInventoryView(name: string): void;
    applyInventoryView(id: string): void;
    deleteInventoryView(id: string): void;
    applyInventoryRecentFilter(id: string): void;
    applyGraphQLPreset(preset: string): void;
    clearInventoryFilter(key: string): void;
    clearInventoryFilters(): void;
    openScopePicker(path: string, title: string, mode: string, tab: string): void;
    closeScopePicker(): void;
    updateScopePickerFilter(key: string, value: string): void;
    updateScopePickerHost(value: string): void;
    toggleScopePickerPath(path: string, selected: boolean): void;
    applyScopePickerChoice(choice: string): void;
    applyScopePickerSelection(): void;
    applyManualScopePath(path: string): void;
    openBlockingReview(moduleKey: string, functionKey: string, title: string, modePath: string, tab: string): void;
    closeBlockingReview(): void;
    confirmBlockMode(): void;
    openInventoryEndpoint(key: string): void;
    closeInventoryEndpoint(): void;
    setInventoryTriageState(key: string, state: string): void;
    updateInventoryMetadataField(key: string, field: string, value: unknown): void;
    prefillSchemaFromEndpoint(key: string): void;
    updateBolaRule(index: number, field: string, value: unknown): void;
    toggleBolaRuleEditor(index: number): void;
    addBolaRule(): void;
    removeBolaRule(index: number): void;
    updateAuthIssuer(index: number, field: string, value: unknown): void;
    addAuthIssuer(): void;
    removeAuthIssuer(index: number): void;
    updateBFLARule(index: number, field: string, value: unknown): void;
    toggleBFLARuleEditor(index: number): void;
    addBFLARule(): void;
    removeBFLARule(index: number): void;
    updateMassAssignmentPathRule(index: number, field: string, value: unknown): void;
    toggleMassRuleEditor(index: number): void;
    addMassAssignmentPathRule(): void;
    removeMassAssignmentPathRule(index: number): void;
    uploadSchema(): Promise<boolean>;
    saveConfig(): Promise<void>;
    applyProfile(key: string, value: string): void;
};

const SUPPORTED_CONFIG_KEYS = [
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


const API_SECURITY_POLICY_CATALOG: APISecurityPolicyCatalogEntry[] = [
    {
        id: 'runtime',
        title: 'Runtime Blocking',
        operatorLabel: 'Runtime attacks',
        description: 'Stops high-confidence injection, SSRF, and abusive payloads.',
        icon: 'shield',
        summaryKey: 'runtime_blocking',
        functions: ['injection', 'ssrf', 'payload_abuse'],
        settingsGroup: 'runtime',
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
        settingsGroup: 'contract',
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
        settingsGroup: 'authorization',
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
        settingsGroup: 'graphql',
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
        settingsGroup: 'abuse',
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
        settingsGroup: 'data',
        setupTarget: 'surface',
        profileKey: 'data'
    }
];

const APISecurityConfig: APISecurityConfigRuntime = {
    containerId: 'apisecurity-config-content',
    currentTab: 'overview',
    config: getDefaultAPISecurityConfig(),
    sectionEnabled: true,
    stats: { threats_blocked: 0, requests_analyzed: 0, alerts_24h: 0 },
    dashboard: {},
    inventory: [],
    inventoryPage: { returned: 0, limit: 100, offset: 0, has_more: false, next_offset: 0 },
    inventoryFilters: getDefaultAPISecurityInventoryFilters(),
    inventoryFilterMenuOpen: false,
    inventoryViewMenuOpen: false,
    inventoryColumns: getDefaultAPISecurityInventoryColumns(),
    inventoryGroupBy: 'none',
    inventorySavedViews: [],
    inventoryRecentFilters: [],
    scopePickerTarget: null,
    scopePickerFilters: { search: '', host: 'all', method: 'all', schema: 'all', risk: 'all', active: 'all' },
    scopePickerSelectedPaths: [],
    scopePickerChoice: 'selected',
    scopePickerHost: '',
    blockingReviewTarget: null,
    policyModeConfirmTarget: null,
    selectedPolicyId: '',
    selectedPolicyEditorTab: 'basics',
    selectedAuthorizationControl: '',
    selectedGraphQLControl: '',
    selectedInventoryEndpointKey: '',
    selectedSettingsCategory: 'discovery',
    settingsEditorCategory: '',
    settingsSearch: '',
    changedSettings: [],
    schemaPrefillEndpointKey: '',
    expandedBFLARuleIndex: 0,
    expandedBolaRuleIndex: 0,
    expandedMassRuleIndex: 0,
    setupFocus: '',
    activeWizard: '',
    wizardStep: 1,
    wizardSurfaceTarget: '',
    wizardSelectedPaths: [],
    wizardPendingProfile: '',
    wizardPendingMode: '',
    overviewLoading: false,
    overviewError: '',

    tabs: [
        { id: 'overview', name: 'Overview', icon: 'activity' },
        { id: 'inventory', name: 'API Inventory', icon: 'list' },
        { id: 'runtime', name: 'Runtime', icon: 'shield' },
        { id: 'contract', name: 'Contracts', icon: 'fileText' },
        { id: 'authorization', name: 'Authorization', icon: 'lock' },
        { id: 'graphql', name: 'GraphQL', icon: 'code' },
        { id: 'abuse', name: 'Automation', icon: 'alert' },
        { id: 'data', name: 'Data Exposure', icon: 'database' },
        { id: 'settings', name: 'Settings', icon: 'sliders' }
    ],

    icons: {
        activity: SectionUI.icons.activity,
        alert: SectionUI.icons.alertTriangle,
        code: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        database: SectionUI.icons.database,
        fileText: SectionUI.icons.fileText,
        list: SectionUI.icons.list,
        lock: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
        shield: SectionUI.icons.shield,
        sliders: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>',
        zap: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>'
    },

    async init(containerId?: string): Promise<void> {
        ensureAPISecurityBindings();
        this.containerId = containerId || 'apisecurity-config-content';
        this.inventorySavedViews = loadAPISecurityInventorySavedViews();
        this.inventoryRecentFilters = loadAPISecurityInventoryRecentFilters();
        if (this.config && Object.keys(this.config).length > 0) {
            consumeAPISecurityConfigFocus(this);
            this.render();
            void Promise.all([this.loadConfig(), this.loadStats(), this.loadOverviewData()]).then(() => this.render());
            return;
        }
        await this.loadConfig();
        await this.loadStats();
        await this.loadOverviewData();
        consumeAPISecurityConfigFocus(this);
        this.render();
    },

    async loadConfig(): Promise<void> {
        try {
            const data = await loadAPISecurityConfig<APISecurityConfigResponse>();
            if (!data) throw new Error('Failed to load config');
            this.config = normalizeAPISecurityConfig(data.settings || (data as APISecurityState));
            this.sectionEnabled = data.enabled !== false;
            this.changedSettings = [];
        } catch (error) {
            console.error('Config load error', error);
            this.config = getDefaultAPISecurityConfig();
            this.sectionEnabled = true;
            this.changedSettings = [];
        }
    },

    async loadStats(): Promise<void> {
        try {
            const data = await loadAPISecurityStats<APISecurityStats>();
            if (data) this.stats = data;
        } catch (e) {
            console.error('Failed to load stats:', e);
        }
    },

    async loadOverviewData(): Promise<void> {
        this.overviewLoading = true;
        this.overviewError = '';

        try {
            const [dashboardResponse, inventoryResponse] = await Promise.all([
                loadAPISecurityDashboard<APISecurityDashboardResponse>(),
                loadAPISecurityInventory<APISecurityInventoryResponse>({ limit: 100 })
            ]);

            this.dashboard = dashboardResponse?.dashboard || {};
            this.inventory = Array.isArray(inventoryResponse?.endpoints) ? inventoryResponse.endpoints : [];
            this.inventoryPage = inventoryResponse?.page || { returned: this.inventory.length, limit: 100, offset: 0, has_more: false, next_offset: this.inventory.length };

            if (!dashboardResponse?.dashboard) {
                this.overviewError = 'API Security analytics are currently unavailable.';
            }
        } catch (error) {
            console.error('Failed to load API Security overview:', error);
            this.dashboard = {};
            this.inventory = [];
            this.inventoryPage = { returned: 0, limit: 100, offset: 0, has_more: false, next_offset: 0 };
            this.overviewError = 'API Security overview data could not be loaded.';
        } finally {
            this.overviewLoading = false;
        }
    },

    render(): void {
        const container = AdminDOM.getById(this.containerId);
        if (!container) return;

        if (!api.hasFeature(FEATURES.API_SECURITY)) {
            container.innerHTML = renderUpgradeBanner('enterprise', 'API Security');
            return;
        }

        const consoleMetaMap: Record<string, { title: string; kicker: string; subtitle: string; actions?: string }> = {
            overview: {
                title: 'Overview',
                kicker: 'API Shield',
                subtitle: 'Monitor discovered endpoints, schema coverage, anomalous transactions, and runtime API posture.',
                actions: `
                    <div class="header-action-group" style="display: flex; align-items: center; gap: 8px;">
                        <button type="button" class="btn btn-outline btn-sm" data-nav-target="api_inventory" data-api-security-action="switch-tab" data-api-tab="inventory">Endpoint Inventory</button>
                        ${SectionUI.renderSwitch({
                            checked: this.sectionEnabled,
                            attrs: 'title="Enable or disable API Security" data-api-section-enabled="true" aria-label="Enable API Security"'
                        })}
                    </div>
                `
            },
            contract: {
                title: 'Contracts',
                kicker: 'API Shield',
                subtitle: 'Validate incoming and outgoing payloads against OpenAPI specifications, JSON schemas, and parameter contracts.',
                actions: '<button type="button" class="btn btn-primary btn-sm" data-api-security-action="open-schema-modal">+ Upload Schema</button>'
            },
            authorization: {
                title: 'Authorization',
                kicker: 'API Shield',
                subtitle: 'Mitigate Broken Object Level Authorization (BOLA), mass assignment, and unauthorized endpoint manipulation.',
                actions: '<button type="button" class="btn btn-outline btn-sm" data-nav-target="access_config">Edge Access Identity</button>'
            },
            inventory: {
                title: 'API Inventory',
                kicker: 'API Shield',
                subtitle: 'Continuous discovery of active API surfaces, shadow routes, parameters, and authentication methods.'
            },
            runtime: {
                title: 'Runtime Inspection',
                kicker: 'API Shield',
                subtitle: 'Live HTTP payload inspection, content-type enforcement, and parameter boundary validation.'
            },
            graphql: {
                title: 'GraphQL',
                kicker: 'API Shield',
                subtitle: 'Enforce maximum query depth, field-level authorization, introspection blocking, and batch limit defense.'
            },
            abuse: {
                title: 'Abuse Defense',
                kicker: 'API Shield',
                subtitle: 'Token bucket rate limits, API key brute-force defense, and automated credential abuse mitigations.'
            },
            data: {
                title: 'Data Leak Protection',
                kicker: 'API Shield',
                subtitle: 'Detect and redact PII, authorization tokens, API keys, and sensitive database records in API responses.'
            },
            settings: {
                title: 'Settings',
                kicker: 'API Shield',
                subtitle: 'Configure engine inspection depth, timeout limits, telemetry retention, and enforcement logging.'
            }
        };

        const currentMeta = consoleMetaMap[this.currentTab] || consoleMetaMap.overview;

        container.innerHTML = SectionUI.renderOperatorFrame({
            title: currentMeta.title,
            kicker: currentMeta.kicker,
            subtitle: currentMeta.subtitle,
            actions: currentMeta.actions,
            tabs: [],
            activeTab: this.currentTab,
            content: `<div id="apisecurity-tab-content">${this.renderTabContent()}${renderAPISecurityModeFieldConfirm(this.blockingReviewTarget, this.dashboard)}</div>`,
            className: 'apisecurity-operator-frame'
        });
    },

    switchTab(id: string): void {
        if (!this.tabs.some(tab => tab.id === id)) return;
        this.currentTab = id as APISecurityTabId;
        this.selectedPolicyId = isAPISecurityPolicyId(this.currentTab) ? this.currentTab : '';
        this.selectedPolicyEditorTab = 'basics';
        this.selectedAuthorizationControl = '';
        this.selectedGraphQLControl = '';
        const pendingPrefill = window.sessionStorage.getItem(APISEC_PENDING_SCHEMA_PREFILL_KEY);
        if (id === 'contract' && (pendingPrefill || this.schemaPrefillEndpointKey)) {
            this.activeWizard = 'schema';
            this.wizardStep = 1;
            this.setupFocus = 'schema';
            if (pendingPrefill) {
                this.schemaPrefillEndpointKey = pendingPrefill;
                this.selectedInventoryEndpointKey = pendingPrefill;
                window.sessionStorage.removeItem(APISEC_PENDING_SCHEMA_PREFILL_KEY);
            }
        } else {
            this.activeWizard = '';
        }
        if (this.currentTab !== 'settings') {
            this.settingsSearch = '';
            this.settingsEditorCategory = '';
        }
        if (this.currentTab !== 'inventory') {
            this.inventoryFilterMenuOpen = false;
            this.inventoryViewMenuOpen = false;
        }
        this.scopePickerTarget = null;
        this.blockingReviewTarget = null;
        this.policyModeConfirmTarget = null;
        this.render();

        const targetMap: Record<string, string> = {
            overview: 'apisecurity_config',
            contract: 'api_schema',
            authorization: 'api_owasp',
            inventory: 'api_inventory',
            graphql: 'api_graphql'
        };
        const activeNavTarget = targetMap[id];
        if (activeNavTarget) {
            AdminDOM.queryAll<HTMLElement>('.nav-link').forEach(el => el.classList.remove('active'));
            const matchedLink = AdminDOM.query<HTMLElement>(`.nav-link[data-nav-target="${activeNavTarget}"]`);
            if (matchedLink) matchedLink.classList.add('active');
        }
    },

    openPolicyDetail(id: string): void {
        if (!isAPISecurityPolicyId(id)) return;
        this.currentTab = id;
        this.selectedPolicyId = id;
        this.selectedPolicyEditorTab = 'basics';
        this.selectedAuthorizationControl = '';
        this.selectedGraphQLControl = '';
        this.scopePickerTarget = null;
        this.blockingReviewTarget = null;
        this.policyModeConfirmTarget = null;
        this.render();
    },

    closePolicyDetail(): void {
        this.currentTab = 'overview';
        this.selectedPolicyId = '';
        this.selectedPolicyEditorTab = 'basics';
        this.selectedAuthorizationControl = '';
        this.selectedGraphQLControl = '';
        this.activeWizard = '';
        this.scopePickerTarget = null;
        this.blockingReviewTarget = null;
        this.policyModeConfirmTarget = null;
        this.render();
    },

    switchPolicyEditorTab(id: string): void {
        const tab = normalizeAPISecurityPolicyEditorTab(id);
        this.selectedPolicyEditorTab = tab;
        this.scopePickerTarget = null;
        this.blockingReviewTarget = null;
        this.policyModeConfirmTarget = null;
        this.render();
    },

    openAuthorizationControl(id: string): void {
        if (!['function', 'object', 'fields'].includes(id)) return;
        this.selectedAuthorizationControl = id as APISecurityAuthorizationControl;
        this.render();
    },

    closeAuthorizationControl(): void {
        this.selectedAuthorizationControl = '';
        this.render();
    },

    openGraphQLControl(id: string): void {
        if (!['limits', 'schema'].includes(id)) return;
        this.selectedGraphQLControl = id as APISecurityGraphQLControl;
        this.render();
    },

    closeGraphQLControl(): void {
        this.selectedGraphQLControl = '';
        this.render();
    },

    focusSetup(id: string): void {
        this.setupFocus = String(id || '').trim();
        this.scopePickerTarget = null;
        this.blockingReviewTarget = null;
        this.policyModeConfirmTarget = null;
        if (['schemas', 'schema'].includes(this.setupFocus)) this.openWizard('schema');
        else if (this.setupFocus === 'identity') this.openWizard('identity');
        else if (this.setupFocus === 'data') this.openWizard('data');
        else {
            this.currentTab = 'runtime';
            this.selectedPolicyId = this.selectedPolicyId || 'runtime';
            this.activeWizard = '';
            this.render();
        }
    },

    openWizard(id: string, step = 1): void {
        const wizard = normalizeAPISecurityWizardId(id);
        if (!wizard) return;
        const policyId = getAPISecurityPolicyIdForWizard(wizard, this.selectedPolicyId);
        this.currentTab = policyId;
        this.selectedPolicyId = policyId;
        this.activeWizard = wizard;
        this.wizardStep = Math.max(1, Math.min(Number(step) || 1, getAPISecurityWizardMaxStep(wizard)));
        this.setupFocus = wizard;
        this.scopePickerTarget = null;
        this.blockingReviewTarget = null;
        this.policyModeConfirmTarget = null;
        this.render();
    },

    closeWizard(): void {
        this.activeWizard = '';
        this.wizardStep = 1;
        this.wizardSurfaceTarget = '';
        this.wizardSelectedPaths = [];
        this.wizardPendingProfile = '';
        this.wizardPendingMode = '';
        this.scopePickerTarget = null;
        this.render();
    },

    setWizardStep(step: number): void {
        if (!this.activeWizard) return;
        this.wizardStep = Math.max(1, Math.min(Number(step) || 1, getAPISecurityWizardMaxStep(this.activeWizard)));
        this.render();
    },

    async applySchemaWizard(): Promise<void> {
        const modeInput = AdminDOM.getById<HTMLSelectElement>('apisecurity-schema-wizard-mode');
        const mode = normalizeAPISecurityMode(modeInput?.value || this.config.validation?.mode || 'detect');
        this.updateField('validation.enabled', true);
        const uploaded = await this.uploadSchema();
        if (!uploaded) return;
        this.activeWizard = '';
        this.wizardStep = 1;
        SectionUI.markSaveActionBarDirty('data-api-security-action');
        this.requestConfigFieldUpdate('validation.mode', mode, true);
    },

    applyIdentityWizard(): void {
        const issuerNameInput = AdminDOM.getById<HTMLInputElement>('apisecurity-identity-issuer-name');
        const issuerInput = AdminDOM.getById<HTMLInputElement>('apisecurity-identity-issuer');
        const audienceInput = AdminDOM.getById<HTMLInputElement>('apisecurity-identity-audiences');
        const jwksInput = AdminDOM.getById<HTMLInputElement>('apisecurity-identity-jwks');
        const requireInput = AdminDOM.getById<HTMLInputElement>('apisecurity-identity-require-token');
        const modeInput = AdminDOM.getById<HTMLSelectElement>('apisecurity-identity-mode');
        const mode = normalizeAPISecurityMode(modeInput?.value || this.config.auth_tokens?.mode || 'detect');
        const issuer = String(issuerInput?.value || '').trim();
        const jwksURL = String(jwksInput?.value || '').trim();
        const existingIssuers = normalizeAuthTokenIssuers(this.config.auth_tokens?.issuers);
        const currentMode = normalizeAPISecurityMode(this.config.auth_tokens?.mode || 'detect');
        const nextIssuer: APISecurityAuthTokenIssuer = {
            name: String(issuerNameInput?.value || '').trim() || (issuer ? 'Primary issuer' : ''),
            issuer,
            audiences: normalizeStringList(audienceInput?.value || [], []),
            allowed_algorithms: existingIssuers[0]?.allowed_algorithms?.length ? existingIssuers[0].allowed_algorithms : ['RS256'],
            jwks_url: jwksURL
        };
        this.config.auth_tokens = {
            ...(this.config.auth_tokens || {}),
            enabled: true,
            mode: mode === 'block' ? currentMode : mode,
            require_signature: jwksURL ? true : this.config.auth_tokens?.require_signature === true,
            protected_paths: requireInput?.checked === false ? [] : normalizeStringList(this.config.auth_tokens?.protected_paths || [], []),
            issuers: issuer || jwksURL ? [nextIssuer, ...existingIssuers.slice(1)] : existingIssuers
        };
        this.config = normalizeAPISecurityConfig(this.config);
        this.activeWizard = '';
        this.wizardStep = 1;
        SectionUI.markSaveActionBarDirty('data-api-security-action');
        this.requestConfigFieldUpdate('auth_tokens.mode', mode, true);
    },

    applyDataWizard(): void {
        const modeInput = AdminDOM.getById<HTMLSelectElement>('apisecurity-data-wizard-mode');
        const action = String(modeInput?.value || 'detect');
        const mode = action === 'detect' ? 'detect' : 'block';
        const currentMode = normalizeAPISecurityMode(this.config.data_exposure?.mode || 'detect');
        this.config.data_exposure = {
            ...(this.config.data_exposure || {}),
            enabled: true,
            mode: mode === 'block' ? currentMode : mode,
            response_handling: action === 'redact' ? 'redact' : 'block'
        };
        this.config = normalizeAPISecurityConfig(this.config);
        this.activeWizard = '';
        this.wizardStep = 1;
        SectionUI.markSaveActionBarDirty('data-api-security-action');
        this.requestConfigFieldUpdate('data_exposure.mode', mode, true);
    },

    renderTabContent(): string {
        if (isAPISecurityPolicyId(this.currentTab)) {
            return this.renderPolicyDetail(this.currentTab);
        }
        switch (this.currentTab) {
            case 'overview': return this.renderOverview();
            case 'inventory': return this.renderInventory();
            case 'settings': return this.renderSettings();
            default: return '';
        }
    },

    renderOverview(): string {
        const coverage = getOverviewCoverage(this.dashboard, this.inventory);
        const enabledPolicies = API_SECURITY_POLICY_CATALOG.filter(policy => getAPISecurityPolicyState(this.config, policy.id).enabled).length;
        const inspectedRequests = this.dashboard.summary?.total_requests ?? getStatNumber(this.stats, 'requests_analyzed', 'total_requests');
        const detectedThreats = this.dashboard.summary?.detected_threats ?? 0;
        const blockedThreats = this.dashboard.summary?.blocked_threats ?? getStatNumber(this.stats, 'threats_blocked', 'blocked_requests');
        const policyTone = enabledPolicies === API_SECURITY_POLICY_CATALOG.length ? 'success' : enabledPolicies > 0 ? 'warning' : 'neutral';
        const metrics = renderAPISecurityMetricStrip([
            { label: 'API requests inspected', value: formatAPINumber(inspectedRequests), sub: 'Dashboard analytics window', tone: 'neutral' },
            { label: 'Threats detected', value: formatAPINumber(detectedThreats), sub: 'Detected by API Security', tone: detectedThreats > 0 ? 'warning' : 'neutral' },
            { label: 'Threats blocked', value: formatAPINumber(blockedThreats), sub: 'Stopped by policy', tone: blockedThreats > 0 ? 'danger' : 'neutral' },
            { label: 'Active policies', value: `${enabledPolicies}/${API_SECURITY_POLICY_CATALOG.length}`, sub: `${formatPercent(coverage.schema_coverage)} schema coverage`, tone: policyTone }
        ], 'apisecurity-overview-kpis');
        const moduleRows = API_SECURITY_POLICY_CATALOG
            .map(policy => {
                const state = getAPISecurityPolicyState(this.config, policy.id);
                const tone = state.enabled ? (state.mode === 'block' ? 'danger' : 'success') : 'neutral';
                const arrow = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>';
                return SectionUI.renderOperatorControlRow({
                    title: getAPISecurityPolicyDisplayTitle(policy.id),
                    description: getAPISecurityPolicyCardDescription(policy.id),
                    icon: this.icons[policy.icon],
                    enabled: state.enabled,
                    actions: arrow,
                    className: 'apisecurity-module-row',
                    attrs: `role="button" tabindex="0" data-api-security-action="open-policy-detail" data-api-policy-id="${policy.id}"`
                });
            })
            .join('');

        return `
            <div class="apisecurity-overview-stack">
                ${this.overviewLoading ? `<div class="dashboard-notice info"><strong>Loading API Security data...</strong></div>` : ''}
                ${this.overviewError ? `<div class="dashboard-notice warning"><strong>API Security data unavailable:</strong> ${escapeSectionHtml(this.overviewError)}</div>` : ''}
                ${SectionUI.renderOperatorSection('Protection statistics', metrics, { subtitle: 'Coverage and live API Security posture across inventory, schemas, and policies.' })}
                ${SectionUI.renderOperatorSection('Security policies', `<div class="operator-control-list apisecurity-module-list">${moduleRows}</div>`, {
                    subtitle: 'Open each policy area to tune scope, detections, exceptions, and rollout.'
                })}
            </div>
        `;
    },

    renderPolicyDetail(id: APISecurityPolicyId): string {
        const policy = getAPISecurityPolicyCatalogEntry(id);
        if (!policy) return this.renderOverview();
        return `
            <div class="apisecurity-config-stack apisecurity-policy-detail-stack">
                ${renderAPISecurityPolicyDetailHeader(policy, this.config, this.dashboard, this.inventory, this.icons)}
                ${renderAPISecurityPolicyEditor(policy, this.selectedPolicyEditorTab, this.config, this.inventory, this.icons, this.setupFocus, this.schemaPrefillEndpointKey, this.activeWizard, this.wizardStep)}
                ${renderAPISecurityScopePicker(this.scopePickerTarget && this.scopePickerTarget.tab === policy.id ? this.scopePickerTarget : null, this.scopePickerFilters, this.scopePickerSelectedPaths, this.inventory, this.scopePickerChoice, this.scopePickerHost)}
                ${renderAPISecurityPolicyModeConfirm(this.policyModeConfirmTarget, this.config)}
            </div>
            ${renderAPISecuritySaveButtons()}
        `;
    },

    renderSettings(): string {
        const search = this.settingsSearch.trim();
        const categories = getAPISecuritySettingsWorkbenchCategories(this.config);
        const activeEditor = this.settingsEditorCategory ? normalizeAPISecuritySettingCategory(this.settingsEditorCategory) : '';
        if (activeEditor) {
            return `
                <div class="apisecurity-config-stack apisecurity-settings-stack">
                    ${renderAPISecuritySettingsCategoryPage(activeEditor, this.config, this.inventory, this.icons, this.schemaPrefillEndpointKey, this.activeWizard, this.wizardStep)}
                    ${renderAPISecurityScopePicker(this.scopePickerTarget?.tab === 'settings' ? this.scopePickerTarget : null, this.scopePickerFilters, this.scopePickerSelectedPaths, this.inventory, this.scopePickerChoice, this.scopePickerHost)}
                </div>
                ${renderAPISecuritySaveButtons()}
            `;
        }
        const header = `
            <div class="apisecurity-settings-toolbar">
                <input type="search" value="${escapeSectionHtml(this.settingsSearch)}" placeholder="Search settings" data-api-settings-search>
            </div>
        `;
        return `
            <div class="apisecurity-config-stack apisecurity-settings-stack">
                ${SectionUI.renderOperatorSection('Settings', `
                    ${header}
                    ${renderAPISecuritySettingsOverview(categories, this.icons)}
                    ${search ? renderAPISecuritySettingsSearchResults(this.config, this.inventory, search) : ''}
                `, {
                    subtitle: 'Choose an area, make the change, and close the editor.'
                })}
                ${renderAPISecurityScopePicker(this.scopePickerTarget?.tab === 'settings' ? this.scopePickerTarget : null, this.scopePickerFilters, this.scopePickerSelectedPaths, this.inventory, this.scopePickerChoice, this.scopePickerHost)}
            </div>
            ${renderAPISecuritySaveButtons()}
        `;
    },

    renderInventory(): string {
        const coverage = getOverviewCoverage(this.dashboard, this.inventory);
        const posture = getInventoryEndpointPosture(this.config, this.dashboard, this.inventory);
        const postureCounts = getInventoryPostureCounts(posture);
        const filteredPosture = getFilteredInventoryPosture(posture, this.inventoryFilters);
        const selectedPosture = posture.find(item => item.key === this.selectedInventoryEndpointKey) || null;
        const metrics = renderInventorySummaryMetrics(coverage, postureCounts);
        const endpointTable = this.inventoryGroupBy === 'none'
            ? renderInventoryEndpointTable(filteredPosture, this.selectedInventoryEndpointKey, this.inventoryColumns)
            : renderGroupedInventoryEndpointTables(filteredPosture, this.selectedInventoryEndpointKey, this.inventoryColumns, this.inventoryGroupBy);

        return `
            <div class="apisecurity-config-stack apisecurity-inventory-stack">
                ${SectionUI.renderOperatorSection('Endpoint inventory', `
                    <div class="apisecurity-inventory-console">
                        ${metrics}
                        <section class="apisecurity-inventory-surface" aria-label="Discovered API inventory">
                            ${renderInventoryToolbar(this.inventory, this.inventoryFilters, this.inventoryFilterMenuOpen, this.inventoryViewMenuOpen, this.inventoryColumns, this.inventoryGroupBy, this.inventorySavedViews, this.inventoryRecentFilters, filteredPosture.length, posture.length)}
                            ${this.inventoryPage.has_more ? `<div class="section-action-row apisecurity-inventory-page-note"><span class="operator-toolbar-note">Loaded ${formatAPINumber(this.inventory.length)} endpoints in stable inventory order.</span><button class="btn btn-secondary btn-sm" type="button" data-api-security-action="load-more-inventory">Load more</button></div>` : ''}
                            <div class="apisecurity-inventory-workspace ${selectedPosture ? 'has-selection' : ''}">
                                <div class="apisecurity-inventory-table-pane">
                                    ${endpointTable}
                                    ${SectionUI.renderTableScrollHint()}
                                </div>
                                ${renderInventoryEndpointDetail(selectedPosture, this.config, this.dashboard, this.inventory)}
                            </div>
                        </section>
                    </div>
                `, {
                    subtitle: 'Discovered API surface, schema state, and endpoint posture.'
                })}
                ${renderAPISecurityScopePicker(this.scopePickerTarget?.tab === 'inventory' ? this.scopePickerTarget : null, this.scopePickerFilters, this.scopePickerSelectedPaths, this.inventory, this.scopePickerChoice, this.scopePickerHost)}
            </div>
            ${renderAPISecuritySaveButtons()}
        `;
    },

    updateField(path: string, value: unknown): void {
        const parts = path.split('.');
        if (parts.length === 0) return;

        let obj: Record<string, unknown> = this.config as Record<string, unknown>;
        for (let i = 0; i < parts.length - 1; i++) {
            const key = parts[i];
            const current = obj[key];
            if (typeof current !== 'object' || current === null || Array.isArray(current)) {
                obj[key] = {};
            }
            obj = obj[key] as Record<string, unknown>;
        }
        obj[parts[parts.length - 1] || path] = value;
        syncAPISecurityMirroredConfigValue(this.config, path, value);
        this.config = normalizeAPISecurityConfig(this.config);
        this.changedSettings = addChangedSettingPath(this.changedSettings, path);
    },

    requestConfigFieldUpdate(path: string, value: unknown, renderAfterUpdate = false): void {
        const normalizedPath = String(path || '').trim();
        if (!normalizedPath) return;

        const blockTarget = buildAPISecurityModeFieldConfirmTarget(
            this.config,
            normalizedPath,
            value,
            this.currentTab,
            this.selectedPolicyId
        );
        if (blockTarget) {
            this.blockingReviewTarget = blockTarget;
            this.policyModeConfirmTarget = null;
            this.scopePickerTarget = null;
            this.render();
            return;
        }

        this.updateField(normalizedPath, value);
        this.blockingReviewTarget = null;
        if (renderAfterUpdate) this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    switchSettingsCategory(id: string): void {
        this.selectedSettingsCategory = normalizeAPISecuritySettingCategory(id);
        this.settingsSearch = '';
        this.settingsEditorCategory = this.selectedSettingsCategory;
        this.scopePickerTarget = null;
        this.render();
    },

    openSettingsCategory(id: string): void {
        this.selectedSettingsCategory = normalizeAPISecuritySettingCategory(id);
        this.settingsEditorCategory = this.selectedSettingsCategory;
        this.settingsSearch = '';
        this.scopePickerTarget = null;
        this.blockingReviewTarget = null;
        this.render();
    },

    closeSettingsCategory(): void {
        this.settingsEditorCategory = '';
        this.activeWizard = '';
        this.scopePickerTarget = null;
        this.render();
    },

    updateSettingsSearch(value: string): void {
        this.settingsSearch = String(value || '').trim();
        this.render();
    },

    setPolicyEnabled(id: string, enabled: boolean): void {
        if (!isAPISecurityPolicyId(id)) return;
        this.config = applyAPISecurityPolicyEnabled(this.config, id, enabled);
        this.policyModeConfirmTarget = null;
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    setPolicyFunctionState(enabledPath: string, modePath: string, state: string): void {
        const enabledField = String(enabledPath || '').trim();
        const modeField = String(modePath || '').trim();
        const normalized = String(state || '').trim().toLowerCase();
        if (!enabledField || !modeField || !['disable', 'detect', 'block'].includes(normalized)) return;
        if (normalized === 'disable') {
            this.requestConfigFieldUpdate(enabledField, false, true);
            return;
        }
        this.updateField(enabledField, true);
        this.requestConfigFieldUpdate(modeField, normalized, true);
    },

    setPolicyBooleanState(path: string, state: string): void {
        const field = String(path || '').trim();
        const normalized = String(state || '').trim().toLowerCase();
        if (!field || !['disable', 'block'].includes(normalized)) return;
        this.requestConfigFieldUpdate(field, normalized === 'block', true);
    },

    confirmPolicyMode(): void {
        const target = this.policyModeConfirmTarget;
        if (!target) return;
        if (target.profileKey && target.profileValue) {
            this.config = applyAPISecurityProfile(this.config, target.profileKey, target.profileValue);
        } else {
            if (target.enableOnConfirm) {
                this.config = applyAPISecurityPolicyEnabled(this.config, target.policyId, true);
            }
            this.config = applyAPISecurityPolicyMode(this.config, target.policyId, target.mode);
        }
        this.policyModeConfirmTarget = null;
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    cancelPolicyMode(): void {
        this.policyModeConfirmTarget = null;
        this.render();
    },

    applyProfile(key: string, value: string): void {
        if (value !== 'default' && value !== 'strict' && value !== 'monitor') return;
        const profileKey = key as APISecurityProfileKey;
        const profileValue = value as APISecurityProfileValue;
        const policyId = getAPISecurityPolicyIdForProfileKey(profileKey);
        if (policyId && deriveAPISecurityProfile(this.config, profileKey) === profileValue) return;
        if (policyId && profileValue === 'strict' && shouldConfirmAPISecurityProfileBlock(this.config, policyId, profileKey, profileValue)) {
            this.policyModeConfirmTarget = { policyId, mode: 'block', profileKey, profileValue };
            this.render();
            return;
        }
        this.config = applyAPISecurityProfile(this.config, profileKey, profileValue);
        this.policyModeConfirmTarget = null;
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    addStringListItem(path: string, value: string): void {
        const normalizedPath = normalizeAPISecurityStringListPath(path);
        const item = String(value || '').trim();
        if (!normalizedPath || !item) return;
        const current = getAPISecurityStringListAtPath(this.config, normalizedPath);
        this.config = setAPISecurityStringListAtPath(this.config, normalizedPath, mergeAPISecurityStringLists(current, [item]));
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    updateStringListItem(path: string, index: number, value: string): void {
        const normalizedPath = normalizeAPISecurityStringListPath(path);
        if (!normalizedPath || index < 0) return;
        const current = getAPISecurityStringListAtPath(this.config, normalizedPath);
        if (index >= current.length) return;
        current[index] = String(value || '').trim();
        this.config = setAPISecurityStringListAtPath(this.config, normalizedPath, current);
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    removeStringListItem(path: string, index: number): void {
        const normalizedPath = normalizeAPISecurityStringListPath(path);
        if (!normalizedPath || index < 0) return;
        const current = getAPISecurityStringListAtPath(this.config, normalizedPath);
        if (index >= current.length) return;
        current.splice(index, 1);
        this.config = setAPISecurityStringListAtPath(this.config, normalizedPath, current);
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    addNestedListItem(kind: APISecurityNestedListKind, parentIndex: number, field: string, value: string): void {
        const item = String(value || '').trim();
        if (!item) return;
        const current = getAPISecurityNestedStringList(this.config, kind, parentIndex, field);
        applyAPISecurityNestedStringList(this, kind, parentIndex, field, mergeAPISecurityStringLists(current, [item]));
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    updateNestedListItem(kind: APISecurityNestedListKind, parentIndex: number, field: string, itemIndex: number, value: string): void {
        if (itemIndex < 0) return;
        const current = getAPISecurityNestedStringList(this.config, kind, parentIndex, field);
        if (itemIndex >= current.length) return;
        current[itemIndex] = String(value || '').trim();
        applyAPISecurityNestedStringList(this, kind, parentIndex, field, current);
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    removeNestedListItem(kind: APISecurityNestedListKind, parentIndex: number, field: string, itemIndex: number): void {
        if (itemIndex < 0) return;
        const current = getAPISecurityNestedStringList(this.config, kind, parentIndex, field);
        if (itemIndex >= current.length) return;
        current.splice(itemIndex, 1);
        applyAPISecurityNestedStringList(this, kind, parentIndex, field, current);
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    updateInventoryFilter(key: string, value: string): void {
        if (!Object.prototype.hasOwnProperty.call(this.inventoryFilters, key)) return;
        const nextValue = key === 'search' ? value : (value || 'all');
        const activeElement = document.activeElement instanceof HTMLInputElement ? document.activeElement : null;
        const restoreSearchFocus = key === 'search' && activeElement?.matches('[data-api-inventory-filter="search"]');
        const selectionStart = activeElement?.selectionStart ?? nextValue.length;
        const selectionEnd = activeElement?.selectionEnd ?? nextValue.length;
        this.inventoryFilters = {
            ...this.inventoryFilters,
            [key]: nextValue
        };
        this.inventoryRecentFilters = rememberAPISecurityInventoryRecentFilter(this.inventoryFilters, this.inventoryRecentFilters);
        if (key !== 'search') this.inventoryFilterMenuOpen = false;
        this.render();
        if (restoreSearchFocus) {
            window.setTimeout(() => {
                const input = document.querySelector<HTMLInputElement>('[data-api-inventory-filter="search"]');
                if (!input) return;
                input.focus();
                input.setSelectionRange(selectionStart, selectionEnd);
            }, 0);
        }
    },

    async loadMoreInventory(): Promise<void> {
        if (!this.inventoryPage.has_more) return;
        const limit = Math.max(1, Math.min(Number(this.inventoryPage.limit) || 100, 200));
        const offset = Math.max(0, Number(this.inventoryPage.next_offset) || this.inventory.length);
        try {
            const response = await loadAPISecurityInventory<APISecurityInventoryResponse>({ limit, offset });
            const nextEndpoints = Array.isArray(response?.endpoints) ? response.endpoints : [];
            const known = new Set(this.inventory.map(endpoint => endpoint.id || getInventoryEndpointKey(endpoint)));
            const additions = nextEndpoints.filter(endpoint => {
                const key = endpoint.id || getInventoryEndpointKey(endpoint);
                if (known.has(key)) return false;
                known.add(key);
                return true;
            });
            this.inventory = [...this.inventory, ...additions];
            this.inventoryPage = response?.page || { returned: 0, limit, offset, has_more: false, next_offset: offset };
            this.render();
        } catch (error) {
            console.error('Failed to load more API inventory:', error);
            showSectionToast('Failed to load more inventory endpoints', 'error');
        }
    },

    toggleInventoryFilterMenu(): void {
        this.inventoryFilterMenuOpen = !this.inventoryFilterMenuOpen;
        if (this.inventoryFilterMenuOpen) this.inventoryViewMenuOpen = false;
        this.render();
    },

    toggleInventoryViewMenu(): void {
        this.inventoryViewMenuOpen = !this.inventoryViewMenuOpen;
        if (this.inventoryViewMenuOpen) this.inventoryFilterMenuOpen = false;
        this.render();
    },

    toggleInventoryColumn(column: string): void {
        if (!isAPISecurityInventoryColumnId(column)) return;
        const visibleCount = APISecurityInventoryColumnIds.filter(id => this.inventoryColumns[id]).length;
        if (this.inventoryColumns[column] && visibleCount <= 1) {
            showSectionToast('Keep at least one inventory detail column visible', 'warning');
            return;
        }
        this.inventoryColumns = {
            ...this.inventoryColumns,
            [column]: !this.inventoryColumns[column]
        };
        this.render();
    },

    setInventoryGroupBy(value: string): void {
        this.inventoryGroupBy = normalizeAPISecurityInventoryGroupBy(value);
        this.inventoryViewMenuOpen = false;
        this.render();
    },

    saveInventoryView(name: string): void {
        const normalizedName = String(name || '').trim() || buildAPISecurityInventoryViewName(this.inventoryFilters, this.inventoryGroupBy);
        this.inventorySavedViews = saveAPISecurityInventoryView(
            this.inventorySavedViews,
            normalizedName,
            this.inventoryFilters,
            this.inventoryColumns,
            this.inventoryGroupBy
        );
        this.inventoryViewMenuOpen = true;
        this.render();
        showSectionToast('Inventory view saved in this browser', 'success');
    },

    applyInventoryView(id: string): void {
        const view = this.inventorySavedViews.find(item => item.id === id);
        if (!view) return;
        this.inventoryFilters = normalizeAPISecurityInventoryFilters(view.filters);
        this.inventoryColumns = normalizeAPISecurityInventoryColumns(view.columns);
        this.inventoryGroupBy = normalizeAPISecurityInventoryGroupBy(view.groupBy);
        this.inventoryFilterMenuOpen = false;
        this.inventoryViewMenuOpen = false;
        this.inventoryRecentFilters = rememberAPISecurityInventoryRecentFilter(this.inventoryFilters, this.inventoryRecentFilters);
        this.render();
    },

    deleteInventoryView(id: string): void {
        this.inventorySavedViews = deleteAPISecurityInventoryView(this.inventorySavedViews, id);
        this.inventoryViewMenuOpen = true;
        this.render();
    },

    applyInventoryRecentFilter(id: string): void {
        const recent = this.inventoryRecentFilters.find(item => item.id === id);
        if (!recent) return;
        this.inventoryFilters = normalizeAPISecurityInventoryFilters(recent.filters);
        this.inventoryFilterMenuOpen = false;
        this.inventoryViewMenuOpen = false;
        this.inventoryRecentFilters = rememberAPISecurityInventoryRecentFilter(this.inventoryFilters, this.inventoryRecentFilters);
        this.render();
    },

    applyGraphQLPreset(preset: string): void {
        const limits = getGraphQLPresetLimits(preset);
        if (!limits) return;
        Object.entries(limits).forEach(([path, value]) => this.updateField(path, value));
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    clearInventoryFilter(key: string): void {
        if (!Object.prototype.hasOwnProperty.call(this.inventoryFilters, key)) return;
        this.inventoryFilters = {
            ...this.inventoryFilters,
            [key]: key === 'search' ? '' : 'all'
        };
        this.inventoryRecentFilters = rememberAPISecurityInventoryRecentFilter(this.inventoryFilters, this.inventoryRecentFilters);
        this.render();
    },

    clearInventoryFilters(): void {
        this.inventoryFilters = getDefaultAPISecurityInventoryFilters();
        this.inventoryFilterMenuOpen = false;
        this.inventoryRecentFilters = rememberAPISecurityInventoryRecentFilter(this.inventoryFilters, this.inventoryRecentFilters);
        this.render();
    },

    openScopePicker(path: string, title: string, mode: string, tab: string): void {
        if (!isSupportedAPISecurityScopePath(path)) return;
        const targetTab = normalizeAPISecuritySurfaceId(tab, getAPISecuritySurfaceIdForScopePath(path));
        if (isAPISecurityPolicyId(targetTab)) {
            this.currentTab = targetTab;
            this.selectedPolicyId = targetTab;
        } else if (isAPISecurityTabId(targetTab)) {
            this.currentTab = targetTab;
            this.selectedPolicyId = '';
        } else {
            this.currentTab = 'inventory';
            this.selectedPolicyId = '';
        }
        this.scopePickerTarget = {
            path,
            title: title || 'Manage Scope',
            mode: mode === 'exclude' ? 'exclude' : 'include',
            tab: targetTab
        };
        this.scopePickerFilters = { search: '', host: 'all', method: 'all', schema: 'all', risk: 'all', active: 'all' };
        this.scopePickerSelectedPaths = [];
        this.scopePickerChoice = 'selected';
        this.scopePickerHost = '';
        this.blockingReviewTarget = null;
        this.policyModeConfirmTarget = null;
        this.render();
    },

    closeScopePicker(): void {
        this.scopePickerTarget = null;
        this.scopePickerSelectedPaths = [];
        this.scopePickerChoice = 'selected';
        this.scopePickerHost = '';
        this.render();
    },

    updateScopePickerFilter(key: string, value: string): void {
        if (!Object.prototype.hasOwnProperty.call(this.scopePickerFilters, key)) return;
        this.scopePickerFilters = {
            ...this.scopePickerFilters,
            [key]: value
        };
        this.render();
    },

    updateScopePickerHost(value: string): void {
        this.scopePickerHost = String(value || '').trim();
        this.scopePickerChoice = 'host';
        this.render();
    },

    toggleScopePickerPath(path: string, selected: boolean): void {
        const normalizedPath = String(path || '').trim();
        if (!normalizedPath) return;
        const current = this.scopePickerSelectedPaths.filter(Boolean);
        this.scopePickerSelectedPaths = selected
            ? mergeAPISecurityStringLists(current, [normalizedPath])
            : current.filter(item => item !== normalizedPath);
        this.scopePickerChoice = 'selected';
        this.render();
    },

    applyScopePickerChoice(choice: string): void {
        if (!this.scopePickerTarget) return;
        const normalizedChoice = normalizeAPISecuritySurfaceChoice(choice);
        if (normalizedChoice === 'manual') {
            showSectionToast('Enter an exact path below to add it to this policy', 'info');
            return;
        }
        const paths = getSurfaceChoicePaths(this.inventory, normalizedChoice, this.scopePickerHost);
        if (!paths.length) {
            showSectionToast('No matching API paths found for this surface', 'warning');
            return;
        }
        const currentPaths = getAPISecurityStringListAtPath(this.config, this.scopePickerTarget.path);
        this.updateField(this.scopePickerTarget.path, mergeAPISecurityStringLists(currentPaths, paths));
        this.scopePickerTarget = null;
        this.scopePickerSelectedPaths = [];
        this.scopePickerChoice = 'selected';
        this.scopePickerHost = '';
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    applyScopePickerSelection(): void {
        if (!this.scopePickerTarget || this.scopePickerSelectedPaths.length === 0) {
            this.closeScopePicker();
            return;
        }
        const selectedInInventoryOrder = getSelectedScopePathsInInventoryOrder(this.inventory, this.scopePickerSelectedPaths);
        const currentPaths = getAPISecurityStringListAtPath(this.config, this.scopePickerTarget.path);
        this.updateField(this.scopePickerTarget.path, mergeAPISecurityStringLists(currentPaths, selectedInInventoryOrder));
        this.scopePickerTarget = null;
        this.scopePickerSelectedPaths = [];
        this.scopePickerChoice = 'selected';
        this.scopePickerHost = '';
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    applyManualScopePath(path: string): void {
        if (!this.scopePickerTarget) return;
        const normalizedPath = String(path || '').trim();
        if (!normalizedPath.startsWith('/')) {
            showSectionToast('Enter a path starting with /', 'warning');
            return;
        }
        const currentPaths = getAPISecurityStringListAtPath(this.config, this.scopePickerTarget.path);
        this.updateField(this.scopePickerTarget.path, mergeAPISecurityStringLists(currentPaths, [normalizedPath]));
        this.scopePickerTarget = null;
        this.scopePickerSelectedPaths = [];
        this.scopePickerChoice = 'selected';
        this.scopePickerHost = '';
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    openBlockingReview(moduleKey: string, functionKey: string, title: string, modePath: string, tab: string): void {
        if (!modePath) return;
        const targetTab = normalizeAPISecuritySurfaceId(tab, getAPISecuritySurfaceIdForScopePath(modePath));
        if (isAPISecurityPolicyId(targetTab)) {
            this.currentTab = targetTab;
            this.selectedPolicyId = targetTab;
        } else if (isAPISecurityTabId(targetTab)) {
            this.currentTab = targetTab;
            this.selectedPolicyId = '';
        } else {
            this.currentTab = 'runtime';
            this.selectedPolicyId = 'runtime';
        }
        this.blockingReviewTarget = {
            moduleKey,
            functionKey,
            title: title || labelizeAPIInventoryValue(functionKey),
            modePath,
            tab: targetTab
        };
        this.scopePickerTarget = null;
        this.policyModeConfirmTarget = null;
        this.render();
    },

    closeBlockingReview(): void {
        this.blockingReviewTarget = null;
        this.render();
    },

    confirmBlockMode(): void {
        if (!this.blockingReviewTarget) return;
        if (this.blockingReviewTarget.enabledPath) {
            this.updateField(this.blockingReviewTarget.enabledPath, true);
        }
        this.updateField(this.blockingReviewTarget.modePath, 'block');
        this.blockingReviewTarget = null;
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    openInventoryEndpoint(key: string): void {
        const normalizedKey = normalizeInventoryEndpointKey(key);
        if (!normalizedKey) return;
        this.currentTab = 'inventory';
        this.selectedInventoryEndpointKey = normalizedKey;
        this.render();
    },

    closeInventoryEndpoint(): void {
        this.selectedInventoryEndpointKey = '';
        this.render();
    },

    setInventoryTriageState(key: string, state: string): void {
        this.updateInventoryMetadataField(key, 'triage_state', state);
    },

    updateInventoryMetadataField(key: string, field: string, value: unknown): void {
        const endpointKey = normalizeInventoryEndpointKey(key);
        if (!endpointKey) return;
        const current = {
            ...getInventoryMetadataByKey(this.config, endpointKey)
        };
        if (field === 'tags') {
            current.tags = uniqueStringList(normalizeStringList(value, []));
        } else if (field === 'criticality') {
            current.criticality = normalizeInventoryCriticality(value);
        } else if (field === 'environment') {
            current.environment = normalizeInventoryEnvironment(value);
        } else if (field === 'triage_state') {
            current.triage_state = normalizeInventoryTriageState(value);
        } else if (field === 'owner' || field === 'service' || field === 'notes') {
            current[field] = String(value || '').trim();
        } else {
            return;
        }
        current.updated_at = new Date().toISOString();
        this.config.inventory_metadata = {
            ...(this.config.inventory_metadata || {}),
            [endpointKey]: current
        };
        this.config = normalizeAPISecurityConfig(this.config);
        this.selectedInventoryEndpointKey = endpointKey;
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    prefillSchemaFromEndpoint(key: string): void {
        const endpointKey = normalizeInventoryEndpointKey(key);
        if (!endpointKey) return;
        window.sessionStorage.setItem(APISEC_PENDING_SCHEMA_PREFILL_KEY, endpointKey);
        this.schemaPrefillEndpointKey = endpointKey;
        this.selectedInventoryEndpointKey = endpointKey;
        this.activeWizard = 'schema';
        this.wizardStep = 1;
        this.setupFocus = 'schema';
        if (typeof router !== 'undefined' && router.navigate) {
            router.navigate('api_schema');
        } else {
            this.switchTab('contract');
            if (window.location.pathname !== '/admin/api-schema') {
                window.history.pushState({}, '', '/admin/api-schema');
            }
        }
        setTimeout(() => {
            const drawer = document.querySelector('.apisecurity-wizard-drawer');
            if (drawer) {
                drawer.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            const textarea = AdminDOM.getById<HTMLTextAreaElement>('apisecurity-schema-content');
            if (textarea) {
                textarea.focus();
            }
        }, 120);
    },

    updateBolaRule(index: number, field: string, value: unknown): void {
        const rules = normalizeBolaOwnershipRules(this.config.bola?.ownership_rules);
        while (rules.length <= index) {
            rules.push({ name: '', resource_pattern: '', owner_id_param: 'id', allowed_roles: [] });
        }
        const rule = { ...rules[index] };
        if (field === 'allowed_roles') {
            rule.allowed_roles = normalizeStringList(value, []);
        } else if (field === 'name' || field === 'resource_pattern' || field === 'owner_id_param' || field === 'owner_id_claim') {
            rule[field] = String(value || '').trim();
        }
        rules[index] = rule;
        this.config.bola = {
            ...(this.config.bola || {}),
            ownership_rules: normalizeBolaOwnershipRules(rules)
        };
        setAPISecurityConfigValue(this.config, 'function_settings.bola.ownership_rules', normalizeBolaOwnershipRules(rules));
        this.config = normalizeAPISecurityConfig(this.config);
    },

    toggleBolaRuleEditor(index: number): void {
        this.expandedBolaRuleIndex = this.expandedBolaRuleIndex === index ? -1 : index;
        this.render();
    },

    addBolaRule(): void {
        const rules = normalizeBolaOwnershipRules(this.config.bola?.ownership_rules);
        rules.push({ name: '', resource_pattern: '', owner_id_param: 'id', allowed_roles: [] });
        this.config.bola = {
            ...(this.config.bola || {}),
            ownership_rules: rules
        };
        setAPISecurityConfigValue(this.config, 'function_settings.bola.ownership_rules', rules);
        this.expandedBolaRuleIndex = rules.length - 1;
        this.render();
        revealAPISecurityRule(`bola:${rules.length - 1}`);
    },

    removeBolaRule(index: number): void {
        const rules = normalizeBolaOwnershipRules(this.config.bola?.ownership_rules);
        rules.splice(index, 1);
        this.config.bola = {
            ...(this.config.bola || {}),
            ownership_rules: rules
        };
        setAPISecurityConfigValue(this.config, 'function_settings.bola.ownership_rules', rules);
        this.config = normalizeAPISecurityConfig(this.config);
        if (rules.length === 0) {
            this.expandedBolaRuleIndex = -1;
        } else if (this.expandedBolaRuleIndex >= rules.length) {
            this.expandedBolaRuleIndex = rules.length - 1;
        } else if (index < this.expandedBolaRuleIndex) {
            this.expandedBolaRuleIndex -= 1;
        }
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    updateAuthIssuer(index: number, field: string, value: unknown): void {
        const issuers = normalizeAuthTokenIssuers(this.config.auth_tokens?.issuers);
        while (issuers.length <= index) {
            issuers.push({ name: '', issuer: '', audiences: [], allowed_algorithms: ['RS256'], jwks_url: '' });
        }
        const issuer = { ...issuers[index] };
        if (field === 'audiences' || field === 'allowed_algorithms') {
            issuer[field] = normalizeStringList(value, []);
        } else if (field === 'name' || field === 'issuer' || field === 'jwks_url') {
            issuer[field] = String(value || '').trim();
        }
        issuers[index] = issuer;
        this.config.auth_tokens = {
            ...(this.config.auth_tokens || {}),
            issuers: normalizeAuthTokenIssuers(issuers)
        };
        setAPISecurityConfigValue(this.config, 'function_settings.auth_tokens.issuers', normalizeAuthTokenIssuers(issuers));
        this.config = normalizeAPISecurityConfig(this.config);
    },

    addAuthIssuer(): void {
        const issuers = normalizeAuthTokenIssuers(this.config.auth_tokens?.issuers);
        issuers.push({ name: '', issuer: '', audiences: [], allowed_algorithms: ['RS256'], jwks_url: '' });
        this.config.auth_tokens = {
            ...(this.config.auth_tokens || {}),
            issuers
        };
        setAPISecurityConfigValue(this.config, 'function_settings.auth_tokens.issuers', issuers);
        this.render();
    },

    removeAuthIssuer(index: number): void {
        const issuers = normalizeAuthTokenIssuers(this.config.auth_tokens?.issuers);
        issuers.splice(index, 1);
        this.config.auth_tokens = {
            ...(this.config.auth_tokens || {}),
            issuers
        };
        setAPISecurityConfigValue(this.config, 'function_settings.auth_tokens.issuers', issuers);
        this.config = normalizeAPISecurityConfig(this.config);
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    updateBFLARule(index: number, field: string, value: unknown): void {
        const rules = normalizeBFLARules(this.config.bfla?.rules);
        while (rules.length <= index) {
            rules.push({ name: '', methods: [], path_pattern: '', allowed_roles: [], required_claim_key: '', required_claim_values: [] });
        }
        const rule = { ...rules[index] };
        if (field === 'methods') {
            rule.methods = normalizeStringList(value, []).map(method => method.toUpperCase());
        } else if (field === 'allowed_roles' || field === 'required_claim_values') {
            rule[field] = normalizeStringList(value, []);
        } else if (field === 'name' || field === 'path_pattern' || field === 'required_claim_key') {
            rule[field] = String(value || '').trim();
        }
        rules[index] = rule;
        this.config.bfla = {
            ...(this.config.bfla || {}),
            rules: normalizeBFLARules(rules)
        };
        setAPISecurityConfigValue(this.config, 'function_settings.bfla.rules', normalizeBFLARules(rules));
        this.config = normalizeAPISecurityConfig(this.config);
    },

    toggleBFLARuleEditor(index: number): void {
        this.expandedBFLARuleIndex = this.expandedBFLARuleIndex === index ? -1 : index;
        this.render();
    },

    addBFLARule(): void {
        const rules = normalizeBFLARules(this.config.bfla?.rules);
        rules.push({ name: '', methods: [], path_pattern: '', allowed_roles: [], required_claim_key: '', required_claim_values: [] });
        this.config.bfla = {
            ...(this.config.bfla || {}),
            rules
        };
        setAPISecurityConfigValue(this.config, 'function_settings.bfla.rules', rules);
        this.expandedBFLARuleIndex = rules.length - 1;
        this.render();
        revealAPISecurityRule(`bfla:${rules.length - 1}`);
    },

    removeBFLARule(index: number): void {
        const rules = normalizeBFLARules(this.config.bfla?.rules);
        rules.splice(index, 1);
        this.config.bfla = {
            ...(this.config.bfla || {}),
            rules
        };
        setAPISecurityConfigValue(this.config, 'function_settings.bfla.rules', rules);
        this.config = normalizeAPISecurityConfig(this.config);
        if (rules.length === 0) {
            this.expandedBFLARuleIndex = -1;
        } else if (this.expandedBFLARuleIndex >= rules.length) {
            this.expandedBFLARuleIndex = rules.length - 1;
        } else if (index < this.expandedBFLARuleIndex) {
            this.expandedBFLARuleIndex -= 1;
        }
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    updateMassAssignmentPathRule(index: number, field: string, value: unknown): void {
        const rules = normalizeMassAssignmentPathRules(this.config.mass_assignment?.path_rules);
        while (rules.length <= index) {
            rules.push({ path_pattern: '', fields: [] });
        }
        const rule = { ...rules[index] };
        if (field === 'fields') {
            rule.fields = normalizeStringList(value, []);
        } else if (field === 'path_pattern') {
            rule.path_pattern = String(value || '').trim();
        }
        rules[index] = rule;
        this.config.mass_assignment = {
            ...(this.config.mass_assignment || {}),
            path_rules: normalizeMassAssignmentPathRules(rules)
        };
        setAPISecurityConfigValue(this.config, 'function_settings.mass_assignment.path_rules', normalizeMassAssignmentPathRules(rules));
        this.config = normalizeAPISecurityConfig(this.config);
    },

    toggleMassRuleEditor(index: number): void {
        this.expandedMassRuleIndex = this.expandedMassRuleIndex === index ? -1 : index;
        this.render();
    },

    addMassAssignmentPathRule(): void {
        const rules = normalizeMassAssignmentPathRules(this.config.mass_assignment?.path_rules);
        rules.push({ path_pattern: '', fields: [] });
        this.config.mass_assignment = {
            ...(this.config.mass_assignment || {}),
            path_rules: rules
        };
        setAPISecurityConfigValue(this.config, 'function_settings.mass_assignment.path_rules', rules);
        this.expandedMassRuleIndex = rules.length - 1;
        this.render();
        revealAPISecurityRule(`mass:${rules.length - 1}`);
    },

    removeMassAssignmentPathRule(index: number): void {
        const rules = normalizeMassAssignmentPathRules(this.config.mass_assignment?.path_rules);
        rules.splice(index, 1);
        this.config.mass_assignment = {
            ...(this.config.mass_assignment || {}),
            path_rules: rules
        };
        setAPISecurityConfigValue(this.config, 'function_settings.mass_assignment.path_rules', rules);
        this.config = normalizeAPISecurityConfig(this.config);
        if (rules.length === 0) {
            this.expandedMassRuleIndex = -1;
        } else if (this.expandedMassRuleIndex >= rules.length) {
            this.expandedMassRuleIndex = rules.length - 1;
        } else if (index < this.expandedMassRuleIndex) {
            this.expandedMassRuleIndex -= 1;
        }
        this.render();
        SectionUI.markSaveActionBarDirty('data-api-security-action');
    },

    async uploadSchema(): Promise<boolean> {
        const endpointSelect = AdminDOM.getById<HTMLSelectElement>('apisecurity-schema-endpoint');
        const methodInput = AdminDOM.getById<HTMLInputElement>('apisecurity-schema-method');
        const pathInput = AdminDOM.getById<HTMLInputElement>('apisecurity-schema-path');
        const hostInput = AdminDOM.getById<HTMLInputElement>('apisecurity-schema-host');
        const typeInput = AdminDOM.getById<HTMLSelectElement>('apisecurity-schema-type');
        const contentInput = AdminDOM.getById<HTMLTextAreaElement>('apisecurity-schema-content');
        const selectedEndpoint = endpointSelect?.value !== '' ? this.inventory[Number(endpointSelect?.value)] : null;
        const payload = {
            method: String(selectedEndpoint?.method || methodInput?.value || '').trim().toUpperCase(),
            path: String(selectedEndpoint?.path || pathInput?.value || '').trim(),
            host: String(selectedEndpoint?.host || hostInput?.value || '').trim(),
            type: String(typeInput?.value || 'openapi').trim(),
            content: String(contentInput?.value || '').trim()
        };

        if (!payload.method || !payload.path || !payload.content) {
            showSectionToast('Method, path, and schema content are required', 'warning');
            return false;
        }

        const result = await uploadAPISecuritySchema(payload);
        if (result === false) {
            showSectionToast('Failed to upload API schema', 'error');
            return false;
        }
        showSectionToast('API schema uploaded', 'success');
        this.schemaPrefillEndpointKey = '';
        this.activeWizard = '';
        window.sessionStorage.removeItem(APISEC_PENDING_SCHEMA_PREFILL_KEY);
        await this.loadOverviewData();
        this.render();
        return true;
    },

    async saveConfig(): Promise<void> {
        this.config = normalizeAPISecurityConfig(this.config);
        const payload = buildAPISecuritySavePayload(this.config, this.sectionEnabled);
        const result = await api.requestResult<APISecurityConfigMutation>(API_SECURITY_CONFIG_ENDPOINT, 'PUT', payload);
        if (result.error || !result.data || result.data.success === false) {
            const message = formatAPISecuritySaveFailure(result.error);
            showSectionToast(message, 'error');
            return;
        }
        this.changedSettings = [];
        await Promise.all([this.loadConfig(), this.loadStats()]);
        SectionUI.markSaveActionBarClean('data-api-security-action');
        showSectionToast('API Security changes applied.', 'success');
        this.render();
    }
};

let apiSecurityBindingsInitialized = false;

function getDefaultAPISecurityConfig(): APISecurityState {
    return normalizeAPISecurityConfig({
        dashboard_views: [],
        alert_rules: [],
        setup_workflow: {
            dismissed: false,
            completed_steps: [],
            last_step: 'discover',
            updated_at: ''
        },
        discovery: {
            enabled: true,
            paths: ['/api/*', '/v1/*', '/v2/*', '/graphql'],
            interval: '5m',
            index_headers: ['Content-Type', 'X-API-Version'],
            detect_shadow_apis: true,
            detect_zombie_apis: true,
            zombie_inactivity_days: 30,
            auto_classify: true
        },
        validation: {
            enabled: true,
            mode: 'block',
            block_unknown_endpoints: false,
            block_invalid_methods: true,
            block_invalid_content_types: true,
            strict_mode: false,
            allow_unknown_fields: true,
            schema_formats: ['openapi', 'graphql', 'json-schema'],
            validate_responses: false
        },
        injection: {
            enabled: true,
            mode: 'block',
            sqli: true,
            nosqli: true,
            cmdi: true,
            xss: true,
            sensitivity: 'medium'
        },
        ssrf: {
            enabled: true,
            mode: 'detect',
            block_private_networks: true,
            block_cloud_metadata: true
        },
        payload_abuse: {
            enabled: true,
            mode: 'detect',
            sensitivity: 'balanced'
        },
        graphql: {
            enabled: true,
            mode: 'detect',
            paths: defaultGraphQLPaths(),
            max_depth: 15,
            max_aliases: 25,
            max_batch_size: 5,
            max_complexity: 500,
            block_introspection: true
        },
        auth_tokens: {
            enabled: true,
            mode: 'detect',
            protected_paths: [],
            excluded_paths: [],
            required_claims: ['sub'],
            require_signature: false,
            issuers: []
        },
        automation_abuse: {
            enabled: true,
            mode: 'detect',
            sensitivity: 'balanced',
            enable_credential_stuffing: true,
            enable_otp_bruteforce: true,
            enable_forced_browsing: true,
            enable_user_enumeration: true,
            enable_object_enumeration: true,
            enable_scraping: true,
            login_paths: defaultAutomationLoginPaths(),
            otp_paths: defaultAutomationOTPPaths(),
            monitored_paths: defaultAutomationMonitoredPaths(),
            identifier_fields: defaultAutomationIdentifierFields()
        },
        data_exposure: {
            enabled: true,
            mode: 'detect',
            sensitivity: 'balanced',
            inspect_requests: true,
            inspect_responses: true,
            response_handling: 'block',
            detect_secrets: true,
            detect_tokens: true,
            detect_payment_data: true,
            detect_pii: true,
            detect_debug_data: true,
            detect_internal_data: true,
            excluded_paths: []
        },
        bfla: {
            enabled: true,
            mode: 'detect',
            rules: []
        },
        mass_assignment: {
            enabled: true,
            mode: 'detect',
            protected_fields: defaultMassAssignmentFields(),
            path_rules: []
        },
        inventory_metadata: {},
        bola: {
            enabled: true,
            mode: 'detect',
            enable_ownership: false,
            enable_tenant: false,
            enable_idor: true,
            strict_mode: false,
            isolated_paths: [],
            ownership_rules: []
        },
        enabled_functions: {
            discovery: true,
            validation: true,
            injection: true,
            ssrf: true,
            payload_abuse: true,
            graphql: true,
            auth_tokens: true,
            automation_abuse: true,
            data_exposure: true,
            bfla: true,
            mass_assignment: true,
            bola: true
        },
        function_settings: {
            injection: {
                mode: 'block',
                sqli: true,
                nosqli: true,
                cmdi: true,
                xss: true,
                sensitivity: 'medium'
            },
            ssrf: {
                mode: 'detect',
                block_private_networks: true,
                block_cloud_metadata: true
            },
            payload_abuse: {
                mode: 'detect',
                sensitivity: 'balanced'
            },
            graphql: {
                mode: 'detect',
                paths: defaultGraphQLPaths(),
                max_depth: 15,
                max_aliases: 25,
                max_batch_size: 5,
                max_complexity: 500,
                block_introspection: true
            },
            auth_tokens: {
                mode: 'detect',
                protected_paths: [],
                excluded_paths: [],
                required_claims: ['sub'],
                require_signature: false,
                issuers: []
            },
            automation_abuse: {
                mode: 'detect',
                sensitivity: 'balanced',
                enable_credential_stuffing: true,
                enable_otp_bruteforce: true,
                enable_forced_browsing: true,
                enable_user_enumeration: true,
                enable_object_enumeration: true,
                enable_scraping: true,
                login_paths: defaultAutomationLoginPaths(),
                otp_paths: defaultAutomationOTPPaths(),
                monitored_paths: defaultAutomationMonitoredPaths(),
                identifier_fields: defaultAutomationIdentifierFields()
            },
            data_exposure: {
                mode: 'detect',
                sensitivity: 'balanced',
                inspect_requests: true,
                inspect_responses: true,
                response_handling: 'block',
                detect_secrets: true,
                detect_tokens: true,
                detect_payment_data: true,
                detect_pii: true,
                detect_debug_data: true,
                detect_internal_data: true,
                excluded_paths: []
            },
            bfla: {
                mode: 'detect',
                rules: []
            },
            mass_assignment: {
                mode: 'detect',
                protected_fields: defaultMassAssignmentFields(),
                path_rules: []
            },
            validation: {
                mode: 'block',
                block_unknown_endpoints: false,
                block_invalid_methods: true,
                block_invalid_content_types: true
            },
            discovery: {
                paths: ['/api/*', '/v1/*', '/v2/*', '/graphql'],
                interval: '5m',
                index_headers: ['Content-Type', 'X-API-Version'],
                detect_shadow_apis: true,
                detect_zombie_apis: true,
                zombie_inactivity_days: 30,
                auto_classify: true
            },
            bola: {
                mode: 'detect',
                enable_ownership: false,
                enable_tenant: false,
                enable_idor: true,
                strict_mode: false,
                isolated_paths: [],
                ownership_rules: []
            }
        }
    });
}

function normalizeAPISecurityConfig(input: APISecurityState | null | undefined): APISecurityState {
    const cfg: APISecurityState = { ...(input || {}) };
    const enabledFunctions = { ...(cfg.enabled_functions || {}) };
    const functionSettings = { ...(cfg.function_settings || {}) };
    const injectionSettings = { ...(functionSettings.injection || {}) };
    const ssrfSettings = { ...(functionSettings.ssrf || {}) };
    const payloadSettings = { ...(functionSettings.payload_abuse || {}) };
    const graphQLSettings = { ...(functionSettings.graphql || {}) };
    const authTokenSettings = { ...(functionSettings.auth_tokens || {}) };
    const automationSettings = { ...(functionSettings.automation_abuse || {}) };
    const dataExposureSettings = { ...(functionSettings.data_exposure || {}) };
    const bflaSettings = { ...(functionSettings.bfla || {}) };
    const massAssignmentSettings = { ...(functionSettings.mass_assignment || {}) };
    const validationSettings = { ...(functionSettings.validation || {}) };
    const discoverySettings = { ...(functionSettings.discovery || {}) };
    const bolaSettings = { ...(functionSettings.bola || {}) };

    const injection: APISecurityInjectionConfig = {
        ...(cfg.injection || {}),
        ...injectionSettings
    };
    injection.enabled = enabledFunctions.injection ?? injection.enabled ?? true;
    injection.sqli = asBoolean(injection.sqli, true);
    injection.nosqli = asBoolean(injection.nosqli, true);
    injection.cmdi = asBoolean(injection.cmdi, true);
    injection.xss = asBoolean(injection.xss, true);
    injection.sensitivity = normalizeSensitivity(injection.sensitivity);
    injection.mode = normalizeAPISecurityMode(injection.mode || cfg.mode || 'block');

    const ssrf: APISecuritySSRFConfig = {
        ...(cfg.ssrf || {}),
        ...ssrfSettings
    };
    ssrf.enabled = enabledFunctions.ssrf ?? ssrf.enabled ?? true;
    ssrf.mode = normalizeAPISecurityMode(ssrf.mode || 'detect');
    ssrf.block_private_networks = asBoolean(ssrf.block_private_networks, true);
    ssrf.block_cloud_metadata = asBoolean(ssrf.block_cloud_metadata, true);

    const payloadAbuse: APISecurityPayloadAbuseConfig = {
        ...(cfg.payload_abuse || {}),
        ...payloadSettings
    };
    payloadAbuse.enabled = enabledFunctions.payload_abuse ?? payloadAbuse.enabled ?? true;
    payloadAbuse.mode = normalizeAPISecurityMode(payloadAbuse.mode || 'detect');
    payloadAbuse.sensitivity = normalizePayloadSensitivity(payloadAbuse.sensitivity);

    const graphQL: APISecurityGraphQLConfig = {
        ...(cfg.graphql || {}),
        ...graphQLSettings
    };
    graphQL.enabled = enabledFunctions.graphql ?? graphQL.enabled ?? true;
    graphQL.mode = normalizeBolaMode(graphQL.mode || 'detect');
    graphQL.paths = normalizeStringList(graphQL.paths, defaultGraphQLPaths());
    graphQL.max_depth = normalizePositiveInteger(graphQL.max_depth, 15);
    graphQL.max_aliases = normalizePositiveInteger(graphQL.max_aliases, 25);
    graphQL.max_batch_size = normalizePositiveInteger(graphQL.max_batch_size, 5);
    graphQL.max_complexity = normalizePositiveInteger(graphQL.max_complexity, 500);
    graphQL.block_introspection = asBoolean(graphQL.block_introspection, true);

    const authTokens: APISecurityAuthTokenConfig = {
        ...(cfg.auth_tokens || {}),
        ...authTokenSettings
    };
    authTokens.enabled = enabledFunctions.auth_tokens ?? authTokens.enabled ?? true;
    authTokens.mode = normalizeBolaMode(authTokens.mode || 'detect');
    authTokens.protected_paths = normalizeStringList(authTokens.protected_paths, []);
    authTokens.excluded_paths = normalizeStringList(authTokens.excluded_paths, []);
    authTokens.required_claims = normalizeStringList(authTokens.required_claims, ['sub']);
    authTokens.require_signature = asBoolean(authTokens.require_signature, false);
    authTokens.issuers = normalizeAuthTokenIssuers(authTokens.issuers);

    const automationAbuse: APISecurityAutomationAbuseConfig = {
        ...(cfg.automation_abuse || {}),
        ...automationSettings
    };
    automationAbuse.enabled = enabledFunctions.automation_abuse ?? automationAbuse.enabled ?? true;
    automationAbuse.mode = normalizeBolaMode(automationAbuse.mode || 'detect');
    automationAbuse.sensitivity = normalizeAutomationSensitivity(automationAbuse.sensitivity);
    automationAbuse.enable_credential_stuffing = asBoolean(automationAbuse.enable_credential_stuffing, true);
    automationAbuse.enable_otp_bruteforce = asBoolean(automationAbuse.enable_otp_bruteforce, true);
    automationAbuse.enable_forced_browsing = asBoolean(automationAbuse.enable_forced_browsing, true);
    automationAbuse.enable_user_enumeration = asBoolean(automationAbuse.enable_user_enumeration, true);
    automationAbuse.enable_object_enumeration = asBoolean(automationAbuse.enable_object_enumeration, true);
    automationAbuse.enable_scraping = asBoolean(automationAbuse.enable_scraping, true);
    automationAbuse.login_paths = normalizeStringList(automationAbuse.login_paths, defaultAutomationLoginPaths());
    automationAbuse.otp_paths = normalizeStringList(automationAbuse.otp_paths, defaultAutomationOTPPaths());
    automationAbuse.monitored_paths = normalizeStringList(automationAbuse.monitored_paths, defaultAutomationMonitoredPaths());
    automationAbuse.identifier_fields = normalizeStringList(automationAbuse.identifier_fields, defaultAutomationIdentifierFields());

    const dataExposure: APISecurityDataExposureConfig = {
        ...(cfg.data_exposure || {}),
        ...dataExposureSettings
    };
    dataExposure.enabled = enabledFunctions.data_exposure ?? dataExposure.enabled ?? true;
    dataExposure.mode = normalizeBolaMode(dataExposure.mode || 'detect');
    dataExposure.sensitivity = normalizeDataExposureSensitivity(dataExposure.sensitivity);
    dataExposure.inspect_requests = asBoolean(dataExposure.inspect_requests, true);
    dataExposure.inspect_responses = asBoolean(dataExposure.inspect_responses, true);
    dataExposure.response_handling = normalizeDataExposureResponseHandling(dataExposure.response_handling);
    dataExposure.detect_secrets = asBoolean(dataExposure.detect_secrets, true);
    dataExposure.detect_tokens = asBoolean(dataExposure.detect_tokens, true);
    dataExposure.detect_payment_data = asBoolean(dataExposure.detect_payment_data, true);
    dataExposure.detect_pii = asBoolean(dataExposure.detect_pii, true);
    dataExposure.detect_debug_data = asBoolean(dataExposure.detect_debug_data, true);
    dataExposure.detect_internal_data = asBoolean(dataExposure.detect_internal_data, true);
    dataExposure.excluded_paths = normalizeStringList(dataExposure.excluded_paths, []);

    const bfla: APISecurityBFLAConfig = {
        ...(cfg.bfla || {}),
        ...bflaSettings
    };
    bfla.enabled = enabledFunctions.bfla ?? bfla.enabled ?? true;
    bfla.mode = normalizeBolaMode(bfla.mode || 'detect');
    bfla.rules = normalizeBFLARules(bfla.rules);
    delete (bfla as Record<string, unknown>).role_header;

    const massAssignment: APISecurityMassAssignmentConfig = {
        ...(cfg.mass_assignment || {}),
        ...massAssignmentSettings
    };
    massAssignment.enabled = enabledFunctions.mass_assignment ?? massAssignment.enabled ?? true;
    massAssignment.mode = normalizeBolaMode(massAssignment.mode || 'detect');
    massAssignment.protected_fields = normalizeStringList(massAssignment.protected_fields, defaultMassAssignmentFields());
    massAssignment.path_rules = normalizeMassAssignmentPathRules(massAssignment.path_rules);

    const validation: APISecurityValidationConfig = {
        ...(cfg.validation || {}),
        ...validationSettings
    };
    validation.enabled = enabledFunctions.validation ?? validation.enabled ?? true;
    validation.mode = normalizeAPISecurityMode(validation.mode || cfg.mode || 'block');
    validation.block_unknown_endpoints = asBoolean(validation.block_unknown_endpoints, false);
    validation.block_invalid_methods = asBoolean(validation.block_invalid_methods, true);
    validation.block_invalid_content_types = asBoolean(validation.block_invalid_content_types, true);
    validation.validate_responses = asBoolean(validation.validate_responses, false);

    const discovery: APISecurityDiscoveryConfig = {
        ...(cfg.discovery || {}),
        ...discoverySettings
    };
    discovery.enabled = enabledFunctions.discovery ?? discovery.enabled ?? true;
    discovery.paths = normalizeStringList(discovery.paths, ['/api/*', '/v1/*', '/v2/*', '/graphql']);
    discovery.interval = typeof discovery.interval === 'string' && discovery.interval.trim() ? discovery.interval.trim() : '5m';
    discovery.index_headers = normalizeStringList(discovery.index_headers, ['Content-Type', 'X-API-Version']);
    discovery.detect_shadow_apis = asBoolean(discovery.detect_shadow_apis, true);
    discovery.detect_zombie_apis = asBoolean(discovery.detect_zombie_apis, true);
    discovery.zombie_inactivity_days = normalizePositiveInteger(discovery.zombie_inactivity_days, 30);
    discovery.auto_classify = asBoolean(discovery.auto_classify, true);

    const bola: APISecurityBolaConfig = {
        ...(cfg.bola || {}),
        ...bolaSettings
    };
    bola.enabled = enabledFunctions.bola ?? bola.enabled ?? true;
    bola.mode = normalizeBolaMode(bola.mode || 'detect');
    bola.enable_ownership = asBoolean(bola.enable_ownership, false);
    bola.enable_tenant = asBoolean(bola.enable_tenant, false);
    bola.enable_idor = asBoolean(bola.enable_idor, true);
    bola.strict_mode = asBoolean(bola.strict_mode, false);
    bola.isolated_paths = normalizeStringList(bola.isolated_paths, []);
    bola.ownership_rules = normalizeBolaOwnershipRules(bola.ownership_rules);
    for (const legacyPath of ['user_id_header', 'user_roles_header', 'tenant_header', 'learning_mode', 'learning_days']) {
        delete (bola as Record<string, unknown>)[legacyPath];
    }

    enabledFunctions.injection = injection.enabled !== false;
    enabledFunctions.ssrf = ssrf.enabled !== false;
    enabledFunctions.payload_abuse = payloadAbuse.enabled !== false;
    enabledFunctions.graphql = graphQL.enabled !== false;
    enabledFunctions.auth_tokens = authTokens.enabled !== false;
    enabledFunctions.automation_abuse = automationAbuse.enabled !== false;
    enabledFunctions.data_exposure = dataExposure.enabled !== false;
    enabledFunctions.bfla = bfla.enabled !== false;
    enabledFunctions.mass_assignment = massAssignment.enabled !== false;
    enabledFunctions.validation = validation.enabled !== false;
    enabledFunctions.discovery = discovery.enabled !== false;
    enabledFunctions.bola = bola.enabled !== false;
    functionSettings.injection = {
        ...injectionSettings,
        sqli: injection.sqli !== false,
        nosqli: injection.nosqli !== false,
        cmdi: injection.cmdi !== false,
        xss: injection.xss !== false,
        sensitivity: injection.sensitivity,
        mode: injection.mode
    };
    functionSettings.ssrf = {
        ...ssrfSettings,
        mode: ssrf.mode,
        block_private_networks: ssrf.block_private_networks !== false,
        block_cloud_metadata: ssrf.block_cloud_metadata !== false
    };
    functionSettings.payload_abuse = {
        ...payloadSettings,
        mode: payloadAbuse.mode,
        sensitivity: payloadAbuse.sensitivity
    };
    functionSettings.graphql = {
        ...graphQLSettings,
        mode: graphQL.mode,
        paths: graphQL.paths,
        max_depth: graphQL.max_depth,
        max_aliases: graphQL.max_aliases,
        max_batch_size: graphQL.max_batch_size,
        max_complexity: graphQL.max_complexity,
        block_introspection: graphQL.block_introspection !== false
    };
    functionSettings.auth_tokens = {
        ...authTokenSettings,
        mode: authTokens.mode,
        protected_paths: authTokens.protected_paths,
        excluded_paths: authTokens.excluded_paths,
        required_claims: authTokens.required_claims,
        require_signature: authTokens.require_signature === true,
        issuers: authTokens.issuers
    };
    functionSettings.automation_abuse = {
        ...automationSettings,
        mode: automationAbuse.mode,
        sensitivity: automationAbuse.sensitivity,
        enable_credential_stuffing: automationAbuse.enable_credential_stuffing !== false,
        enable_otp_bruteforce: automationAbuse.enable_otp_bruteforce !== false,
        enable_forced_browsing: automationAbuse.enable_forced_browsing !== false,
        enable_user_enumeration: automationAbuse.enable_user_enumeration !== false,
        enable_object_enumeration: automationAbuse.enable_object_enumeration !== false,
        enable_scraping: automationAbuse.enable_scraping !== false,
        login_paths: automationAbuse.login_paths,
        otp_paths: automationAbuse.otp_paths,
        monitored_paths: automationAbuse.monitored_paths,
        identifier_fields: automationAbuse.identifier_fields
    };
    functionSettings.data_exposure = {
        ...dataExposureSettings,
        mode: dataExposure.mode,
        sensitivity: dataExposure.sensitivity,
        inspect_requests: dataExposure.inspect_requests !== false,
        inspect_responses: dataExposure.inspect_responses !== false,
        response_handling: dataExposure.response_handling,
        detect_secrets: dataExposure.detect_secrets !== false,
        detect_tokens: dataExposure.detect_tokens !== false,
        detect_payment_data: dataExposure.detect_payment_data !== false,
        detect_pii: dataExposure.detect_pii !== false,
        detect_debug_data: dataExposure.detect_debug_data !== false,
        detect_internal_data: dataExposure.detect_internal_data !== false,
        excluded_paths: dataExposure.excluded_paths
    };
    const bflaFunctionSettings = {
        ...bflaSettings,
        mode: bfla.mode,
        rules: bfla.rules
    };
    delete (bflaFunctionSettings as Record<string, unknown>).role_header;
    functionSettings.bfla = bflaFunctionSettings;
    functionSettings.mass_assignment = {
        ...massAssignmentSettings,
        mode: massAssignment.mode,
        protected_fields: massAssignment.protected_fields,
        path_rules: massAssignment.path_rules
    };
    functionSettings.validation = {
        ...validationSettings,
        mode: validation.mode,
        block_unknown_endpoints: validation.block_unknown_endpoints === true,
        block_invalid_methods: validation.block_invalid_methods !== false,
        block_invalid_content_types: validation.block_invalid_content_types !== false,
        validate_responses: validation.validate_responses === true
    };
    functionSettings.discovery = {
        ...discoverySettings,
        paths: discovery.paths,
        interval: discovery.interval,
        index_headers: discovery.index_headers,
        detect_shadow_apis: discovery.detect_shadow_apis !== false,
        detect_zombie_apis: discovery.detect_zombie_apis !== false,
        zombie_inactivity_days: discovery.zombie_inactivity_days,
        auto_classify: discovery.auto_classify !== false
    };
    const bolaFunctionSettings = {
        ...bolaSettings,
        mode: bola.mode,
        enable_ownership: bola.enable_ownership === true,
        enable_tenant: bola.enable_tenant === true,
        enable_idor: bola.enable_idor !== false,
        strict_mode: bola.strict_mode === true,
        isolated_paths: bola.isolated_paths,
        ownership_rules: bola.ownership_rules
    };
    for (const legacyPath of ['user_id_header', 'user_roles_header', 'tenant_header', 'learning_mode', 'learning_days']) {
        delete (bolaFunctionSettings as Record<string, unknown>)[legacyPath];
    }
    functionSettings.bola = bolaFunctionSettings;

    cfg.injection = injection;
    cfg.ssrf = ssrf;
    cfg.payload_abuse = payloadAbuse;
    cfg.graphql = graphQL;
    cfg.auth_tokens = authTokens;
    cfg.automation_abuse = automationAbuse;
    cfg.data_exposure = dataExposure;
    cfg.bfla = bfla;
    cfg.mass_assignment = massAssignment;
    cfg.validation = validation;
    cfg.discovery = discovery;
    cfg.bola = bola;
    cfg.inventory_metadata = normalizeInventoryMetadata(cfg.inventory_metadata);
    cfg.dashboard_views = normalizeDashboardViews(cfg.dashboard_views);
    cfg.alert_rules = normalizeMonitoringRules(cfg.alert_rules);
    cfg.setup_workflow = normalizeSetupWorkflow(cfg.setup_workflow);
    cfg.enabled_functions = enabledFunctions;
    cfg.function_settings = functionSettings;

    return cfg;
}

function buildAPISecuritySavePayload(config: APISecurityState, sectionEnabled: boolean): { enabled: boolean; settings: APISecurityState } {
    const normalized = normalizeAPISecurityConfig(config);
    const settings: APISecurityState = {};

    SUPPORTED_CONFIG_KEYS.forEach((key: string) => {
        const value = (normalized as Record<string, unknown>)[key];
        if (value !== undefined) {
            (settings as Record<string, unknown>)[key] = cloneConfigValue(value);
        }
    });

    return {
        enabled: sectionEnabled,
        settings
    };
}

function formatAPISecuritySaveFailure(error: ApiRequestFailure | null): string {
    const message = String(error?.message || 'Could not apply the API Security changes.').trim();
    const details: unknown[] = Array.isArray(error?.details) ? error.details : [];
    const detailMessage = details
        .map((detail: unknown): string => {
            if (typeof detail === 'string') return detail.trim();
            if (detail && typeof detail === 'object' && 'message' in detail && typeof (detail as { message?: unknown }).message === 'string') {
                return String((detail as { message: string }).message).trim();
            }
            return '';
        })
        .find((detail: string) => Boolean(detail) && detail !== message);

    return detailMessage ? `${message} Cause: ${detailMessage}` : message;
}

function cloneConfigValue(value: unknown): unknown {
    if (value === undefined) return undefined;
    return JSON.parse(JSON.stringify(value)) as unknown;
}

function getInjectionConfig(config: APISecurityState): APISecurityInjectionConfig {
    return config.injection || {};
}

function getSSRFConfig(config: APISecurityState): APISecuritySSRFConfig {
    return config.ssrf || {};
}

function getPayloadAbuseConfig(config: APISecurityState): APISecurityPayloadAbuseConfig {
    return config.payload_abuse || {};
}

function getGraphQLConfig(config: APISecurityState): APISecurityGraphQLConfig {
    return config.graphql || {};
}

function getAutomationAbuseConfig(config: APISecurityState): APISecurityAutomationAbuseConfig {
    return config.automation_abuse || {};
}

function getDataExposureConfig(config: APISecurityState): APISecurityDataExposureConfig {
    return config.data_exposure || {};
}

function getValidationConfig(config: APISecurityState): APISecurityValidationConfig {
    return config.validation || {};
}

function asBoolean(value: unknown, fallback: boolean): boolean {
    return typeof value === 'boolean' ? value : fallback;
}

function normalizeSensitivity(value: unknown): string {
    return value === 'low' || value === 'medium' || value === 'high' ? value : 'medium';
}

function normalizePayloadSensitivity(value: unknown): string {
    return String(value || '').trim().toLowerCase() === 'strict' ? 'strict' : 'balanced';
}

function normalizeAutomationSensitivity(value: unknown): string {
    return String(value || '').trim().toLowerCase() === 'strict' ? 'strict' : 'balanced';
}

function normalizeDataExposureSensitivity(value: unknown): string {
    return String(value || '').trim().toLowerCase() === 'strict' ? 'strict' : 'balanced';
}

function normalizeDataExposureResponseHandling(value: unknown): string {
    return String(value || '').trim().toLowerCase() === 'redact' ? 'redact' : 'block';
}

function normalizeStringList(value: unknown, fallback: string[]): string[] {
    if (Array.isArray(value)) {
        const result = value.map(item => String(item || '').trim()).filter(Boolean);
        return result.length ? result : [...fallback];
    }
    if (typeof value === 'string') {
        const result = value.split(',').map(item => item.trim()).filter(Boolean);
        return result.length ? result : [...fallback];
    }
    return [...fallback];
}

function normalizeInventoryMetadata(value: unknown): Record<string, APISecurityInventoryMetadata> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return {};
    const result: Record<string, APISecurityInventoryMetadata> = {};
    Object.entries(value as Record<string, unknown>).forEach(([key, rawValue]) => {
        const endpointKey = normalizeInventoryEndpointKey(key);
        if (!endpointKey || typeof rawValue !== 'object' || rawValue === null || Array.isArray(rawValue)) return;
        const raw = rawValue as Record<string, unknown>;
        const owner = String(raw.owner || '').trim();
        const service = String(raw.service || '').trim();
        const environment = normalizeInventoryEnvironment(raw.environment);
        const criticality = normalizeInventoryCriticality(raw.criticality);
        const triageState = normalizeInventoryTriageState(raw.triage_state);
        const tags = uniqueStringList(normalizeStringList(raw.tags, []));
        const notes = String(raw.notes || '').trim();
        const updatedAt = String(raw.updated_at || '').trim();
        const hasData = owner || service || tags.length || notes || triageState || updatedAt || String(raw.environment || '').trim() || String(raw.criticality || '').trim();
        if (!hasData) return;
        result[endpointKey] = {
            owner,
            service,
            environment,
            criticality,
            triage_state: triageState,
            tags,
            notes,
            updated_at: updatedAt
        };
    });
    return result;
}

function normalizeDashboardViews(value: unknown): APISecurityDashboardView[] {
    if (!Array.isArray(value)) return [];
    const seen = new Set<string>();
    return value.slice(0, 20).map(item => {
        const raw = (typeof item === 'object' && item !== null) ? item as Record<string, unknown> : {};
        const name = String(raw.name || '').trim() || 'API Security view';
        const id = uniqueWorkflowId(String(raw.id || name), 'view', seen);
        return {
            id,
            name,
            window: normalizeDashboardWindow(raw.window),
            filters: normalizeDashboardViewFilters(raw.filters),
            created_at: String(raw.created_at || '').trim(),
            updated_at: String(raw.updated_at || '').trim()
        };
    });
}

function normalizeDashboardViewFilters(value: unknown): APISecurityDashboardViewFilters {
    const raw = (typeof value === 'object' && value !== null && !Array.isArray(value)) ? value as Record<string, unknown> : {};
    return {
        section: lowerTrim(raw.section),
        action: lowerTrim(raw.action),
        module: lowerTrim(raw.module),
        function: lowerTrim(raw.function),
        threat_type: lowerTrim(raw.threat_type),
        severity: lowerTrim(raw.severity),
        mode: lowerTrim(raw.mode),
        direction: lowerTrim(raw.direction),
        data_class: lowerTrim(raw.data_class),
        response_action: lowerTrim(raw.response_action),
        path: String(raw.path || '').trim(),
        method: String(raw.method || '').trim().toUpperCase(),
        host: lowerTrim(raw.host),
        ip: String(raw.ip || '').trim(),
        status: String(raw.status || '').trim(),
        user_agent: String(raw.user_agent || '').trim(),
        rule_id: String(raw.rule_id || '').trim(),
        request_id: String(raw.request_id || '').trim()
    };
}

function normalizeMonitoringRules(value: unknown): APISecurityMonitoringRule[] {
    if (!Array.isArray(value)) return [];
    const seen = new Set<string>();
    return value.slice(0, 25).map(item => {
        const raw = (typeof item === 'object' && item !== null) ? item as Record<string, unknown> : {};
        const name = String(raw.name || '').trim() || 'API Security monitoring rule';
        const id = uniqueWorkflowId(String(raw.id || name), 'rule', seen);
        const threshold = Number.parseInt(String(raw.threshold ?? '1'), 10);
        return {
            id,
            name,
            enabled: raw.enabled !== false,
            rule_type: normalizeMonitoringRuleType(raw.rule_type),
            module: lowerTrim(raw.module),
            function: lowerTrim(raw.function),
            threat_type: lowerTrim(raw.threat_type),
            severity: lowerTrim(raw.severity),
            action: lowerTrim(raw.action),
            data_class: lowerTrim(raw.data_class),
            response_action: lowerTrim(raw.response_action),
            threshold: Number.isFinite(threshold) && threshold > 0 ? threshold : 1,
            window: normalizeDashboardWindow(raw.window),
            group_by: normalizeMonitoringGroupBy(raw.group_by),
            description: String(raw.description || '').trim(),
            created_at: String(raw.created_at || '').trim(),
            updated_at: String(raw.updated_at || '').trim()
        };
    });
}

function normalizeSetupWorkflow(value: unknown): APISecuritySetupWorkflow {
    const raw = (typeof value === 'object' && value !== null && !Array.isArray(value)) ? value as Record<string, unknown> : {};
    const steps = normalizeStringList(raw.completed_steps, []).filter(isAPISecuritySetupStep);
    return {
        dismissed: raw.dismissed === true,
        completed_steps: uniqueStringList(steps),
        last_step: isAPISecuritySetupStep(String(raw.last_step || '').trim()) ? String(raw.last_step || '').trim() : 'discover',
        updated_at: String(raw.updated_at || '').trim()
    };
}

function isAPISecuritySetupStep(value: string): boolean {
    return ['discover', 'schemas', 'identity', 'detect', 'findings', 'blocking'].includes(String(value || '').trim());
}

function normalizeDashboardWindow(value: unknown): string {
    const text = String(value || '').trim().toLowerCase();
    return ['1h', '24h', '7d', '30d'].includes(text) ? text : '24h';
}

function normalizeMonitoringRuleType(value: unknown): string {
    const text = String(value || '').trim().toLowerCase();
    return ['block_spike', 'critical_findings', 'new_shadow_api', 'sensitive_response_exposure', 'authorization_abuse_repeat', 'schema_coverage_drop'].includes(text) ? text : 'critical_findings';
}

function normalizeMonitoringGroupBy(value: unknown): string {
    const text = String(value || '').trim().toLowerCase();
    return ['endpoint', 'source_ip', 'module', 'threat_type', 'data_class', 'none'].includes(text) ? text : 'endpoint';
}

function uniqueWorkflowId(value: string, fallback: string, seen: Set<string>): string {
    const base = slugWorkflowId(value) || fallback;
    let id = base;
    let index = 2;
    while (seen.has(id)) {
        id = `${base}-${index}`;
        index += 1;
    }
    seen.add(id);
    return id;
}

function slugWorkflowId(value: string): string {
    return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

function lowerTrim(value: unknown): string {
    return String(value || '').trim().toLowerCase();
}

function normalizeInventoryEndpointKey(value: string): string {
    return String(value || '').trim().toLowerCase();
}

function getInventoryEndpointKey(endpoint: APISecurityEndpoint): string {
    const id = String(endpoint.id || '').trim();
    if (id) return normalizeInventoryEndpointKey(id);
    return normalizeInventoryEndpointKey([
        String(endpoint.method || 'GET').toUpperCase(),
        String(endpoint.host || ''),
        String(endpoint.path || '/')
    ].join('|'));
}

function normalizeInventoryEnvironment(value: unknown): string {
    const text = String(value || '').trim().toLowerCase();
    return text || 'unknown';
}

function normalizeInventoryCriticality(value: unknown): string {
    const text = String(value || '').trim().toLowerCase();
    return ['low', 'medium', 'high', 'critical'].includes(text) ? text : 'medium';
}

function normalizeInventoryTriageState(value: unknown): string {
    const text = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
    return ['new', 'in_review', 'accepted', 'ignored', 'needs_schema', 'deprecated'].includes(text) ? text : '';
}

function uniqueStringList(values: string[]): string[] {
    const seen = new Set<string>();
    return values.filter(value => {
        if (seen.has(value)) return false;
        seen.add(value);
        return true;
    });
}

function normalizeBolaOwnershipRules(value: unknown): APISecurityBolaOwnershipRule[] {
    if (!Array.isArray(value)) return [];
    return value
        .map(item => {
            const raw = (typeof item === 'object' && item !== null) ? item as Record<string, unknown> : {};
            const allowedRoles = normalizeStringList(raw.allowed_roles, []);
            return {
                name: String(raw.name || '').trim(),
                resource_pattern: String(raw.resource_pattern || '').trim(),
                owner_id_param: String(raw.owner_id_param || '').trim() || 'id',
                owner_id_claim: String(raw.owner_id_claim || '').trim(),
                allowed_roles: allowedRoles
            };
        });
}

function normalizeAuthTokenIssuers(value: unknown): APISecurityAuthTokenIssuer[] {
    if (!Array.isArray(value)) return [];
    return value
        .map(item => {
            const raw = (typeof item === 'object' && item !== null) ? item as Record<string, unknown> : {};
            return {
                name: String(raw.name || '').trim(),
                issuer: String(raw.issuer || raw.issuer_url || '').trim(),
                audiences: normalizeStringList(raw.audiences, []),
                allowed_algorithms: normalizeStringList(raw.allowed_algorithms, []),
                jwks_url: String(raw.jwks_url || '').trim()
            };
        })
        .filter(issuer => Boolean(issuer.name || issuer.issuer || issuer.audiences?.length || issuer.allowed_algorithms?.length || issuer.jwks_url));
}

function normalizeBFLARules(value: unknown): APISecurityBFLARule[] {
    if (!Array.isArray(value)) return [];
    return value
        .map(item => {
            const raw = (typeof item === 'object' && item !== null) ? item as Record<string, unknown> : {};
            return {
                name: String(raw.name || '').trim(),
                methods: normalizeStringList(raw.methods, []).map(method => method.toUpperCase()),
                path_pattern: String(raw.path_pattern || '').trim(),
                allowed_roles: normalizeStringList(raw.allowed_roles, []),
                required_claim_key: String(raw.required_claim_key || '').trim(),
                required_claim_values: normalizeStringList(raw.required_claim_values, [])
            };
        });
}

function normalizeMassAssignmentPathRules(value: unknown): APISecurityMassAssignmentPathRule[] {
    if (!Array.isArray(value)) return [];
    return value
        .map(item => {
            const raw = (typeof item === 'object' && item !== null) ? item as Record<string, unknown> : {};
            return {
                path_pattern: String(raw.path_pattern || '').trim(),
                fields: normalizeStringList(raw.fields, [])
            };
        });
}

function defaultMassAssignmentFields(): string[] {
    return ['role', 'roles', 'is_admin', 'admin', 'tenant_id', 'owner_id', 'balance', 'status', 'permissions', 'scopes'];
}

function defaultGraphQLPaths(): string[] {
    return ['/graphql', '/api/graphql'];
}

function getGraphQLPresetLimits(preset: string): Record<string, number | boolean> | null {
    if (preset === 'strict') {
        return {
            'graphql.max_depth': 10,
            'graphql.max_aliases': 10,
            'graphql.max_batch_size': 3,
            'graphql.max_complexity': 250,
            'graphql.block_introspection': true
        };
    }
    if (preset === 'relaxed') {
        return {
            'graphql.max_depth': 20,
            'graphql.max_aliases': 40,
            'graphql.max_batch_size': 10,
            'graphql.max_complexity': 1000,
            'graphql.block_introspection': false
        };
    }
    if (preset === 'standard') {
        return {
            'graphql.max_depth': 15,
            'graphql.max_aliases': 25,
            'graphql.max_batch_size': 5,
            'graphql.max_complexity': 500,
            'graphql.block_introspection': true
        };
    }
    return null;
}

function getGraphQLLimitPreset(graphql: APISecurityGraphQLConfig): 'standard' | 'strict' | 'relaxed' | 'custom' {
    const entries = Object.entries({
        standard: getGraphQLPresetLimits('standard') || {},
        strict: getGraphQLPresetLimits('strict') || {},
        relaxed: getGraphQLPresetLimits('relaxed') || {}
    }) as Array<['standard' | 'strict' | 'relaxed', Record<string, number | boolean>]>;
    const current: Record<string, number | boolean> = {
        'graphql.max_depth': Number(graphql.max_depth || 15),
        'graphql.max_aliases': Number(graphql.max_aliases || 25),
        'graphql.max_batch_size': Number(graphql.max_batch_size || 5),
        'graphql.max_complexity': Number(graphql.max_complexity || 500),
        'graphql.block_introspection': graphql.block_introspection !== false
    };
    return entries.find(([, limits]) => Object.entries(limits).every(([path, value]) => current[path] === value))?.[0] || 'custom';
}

function getGraphQLPresetDescription(preset: string): string {
    if (preset === 'strict') return 'Lower depth, aliases, batch, and complexity.';
    if (preset === 'relaxed') return 'Higher limits while monitoring onboarding traffic.';
    return 'Balanced production limits with introspection blocked.';
}

function defaultAutomationLoginPaths(): string[] {
    return ['/login', '/auth/login', '/api/auth/login', '/sessions', '/token'];
}

function defaultAutomationOTPPaths(): string[] {
    return ['/otp', '/mfa', '/2fa', '/verify'];
}

function defaultAutomationMonitoredPaths(): string[] {
    return ['*'];
}

function defaultAutomationIdentifierFields(): string[] {
    return ['username', 'email', 'phone', 'account', 'login', 'user', 'user_id', 'id'];
}

function normalizePositiveInteger(value: unknown, fallback: number): number {
    const parsed = Number.parseInt(String(value || ''), 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function normalizeAPISecurityMode(value: unknown): string {
    const mode = String(value || '').trim().toLowerCase();
    if (mode === 'detect' || mode === 'detection' || mode === 'log' || mode === 'logging') return 'detect';
    if (mode === 'block' || mode === 'blocking') return 'block';
    return 'block';
}

function revealAPISecurityRule(ruleId: string): void {
    window.requestAnimationFrame(() => {
        const rule = document.querySelector<HTMLElement>(`[data-api-rule-card="${ruleId}"]`);
        if (!rule) return;
        rule.scrollIntoView({ behavior: 'smooth', block: 'center' });
        rule.querySelector<HTMLInputElement>('input:not([type="hidden"])')?.focus({ preventScroll: true });
    });
}

function normalizeBolaMode(value: unknown): string {
    const mode = String(value || '').trim().toLowerCase();
    if (mode === 'block' || mode === 'blocking') return 'block';
    if (mode === 'detect' || mode === 'detection' || mode === 'log' || mode === 'logging') return 'detect';
    return 'detect';
}

function getStatNumber(stats: APISecurityStats, key: string, fallbackKey?: string): number {
    const direct = stats[key];
    if (typeof direct === 'number') return direct;
    const custom = stats.custom?.[key];
    if (typeof custom === 'number') return custom;
    if (fallbackKey) return getStatNumber(stats, fallbackKey);
    return 0;
}

function formatAPINumber(value: number): string {
    if (!Number.isFinite(value)) return '0';
    if (value >= 1000000) return `${(value / 1000000).toFixed(2)}M`;
    if (value >= 1000) return `${(value / 1000).toFixed(1)}k`;
    return value.toString();
}

function formatPercent(value: number): string {
    if (!Number.isFinite(value)) return '0%';
    return `${value.toFixed(value % 1 === 0 ? 0 : 1)}%`;
}

function getOverviewCoverage(dashboard: APISecurityDashboardPayload, inventory: APISecurityEndpoint[]): Required<APISecurityInventoryCoverage> {
    const coverage = dashboard.inventory || {};
    const totalFallback = inventory.length;
    const activeFallback = inventory.filter(endpoint => endpoint.is_active !== false).length;

    return {
        total_endpoints: coverage.total_endpoints ?? totalFallback,
        active_endpoints: coverage.active_endpoints ?? activeFallback,
        endpoints_with_schema: coverage.endpoints_with_schema ?? 0,
        endpoints_without_schema: coverage.endpoints_without_schema ?? Math.max(activeFallback - (coverage.endpoints_with_schema ?? 0), 0),
        schema_coverage: coverage.schema_coverage ?? 0,
        openapi_schemas: coverage.openapi_schemas ?? 0,
        graphql_schemas: coverage.graphql_schemas ?? 0
    };
}

function getBreakdownItems(dashboard: APISecurityDashboardPayload, key: string): APISecurityBreakdownItem[] {
    const items = dashboard.breakdowns?.[key];
    return Array.isArray(items) ? items : [];
}








function isAPIEventFinding(event: APISecurityEventRow): boolean {
    const action = String(event.action || '').toLowerCase();
    return action === 'block' || action === 'detect';
}




































function isAuthorizationFunction(value: string): boolean {
    const key = String(value || '').toLowerCase();
    return ['bola', 'auth_tokens', 'bfla', 'mass_assignment'].includes(key);
}


function getEndpointSchemaStatus(endpoint: APISecurityEndpoint): string {
    return String(endpoint.schema_status || endpoint.metadata?.schema_status || 'unknown').toLowerCase();
}

function getEndpointRiskStatus(endpoint: APISecurityEndpoint): string {
    const direct = String(endpoint.risk_status || endpoint.metadata?.risk_status || '').toLowerCase();
    if (direct === 'shadow' || direct === 'zombie' || direct === 'normal') return direct;
    if (endpoint.is_active === false) return 'zombie';
    if (getEndpointSchemaStatus(endpoint) === 'missing') return 'shadow';
    return 'normal';
}

function getInventoryMetadataByKey(config: APISecurityState, key: string): APISecurityInventoryMetadata {
    const metadata = normalizeInventoryMetadata(config.inventory_metadata || {});
    const stored = metadata[normalizeInventoryEndpointKey(key)] || {};
    return {
        owner: stored.owner || '',
        service: stored.service || '',
        environment: stored.environment || 'unknown',
        criticality: stored.criticality || 'medium',
        triage_state: stored.triage_state || '',
        tags: Array.isArray(stored.tags) ? stored.tags : [],
        notes: stored.notes || '',
        updated_at: stored.updated_at || ''
    };
}

function getInventoryEndpointPosture(config: APISecurityState, dashboard: APISecurityDashboardPayload, inventory: APISecurityEndpoint[]): APISecurityEndpointPosture[] {
    const zombieDays = Number(config.discovery?.zombie_inactivity_days || 30);
    return inventory.map(endpoint => {
        const key = getInventoryEndpointKey(endpoint);
        const schema = getEndpointSchemaStatus(endpoint);
        const risk = getEndpointRiskStatus(endpoint);
        const recentFindings = getEndpointRecentFindings(dashboard, endpoint);
        const endpointFindingCount = getEndpointFindingCount(dashboard, endpoint, recentFindings);
        const schemaMissing = schema === 'missing';
        const isShadow = risk === 'shadow' || (endpoint.is_active !== false && schemaMissing);
        const isZombie = risk === 'zombie' || endpoint.is_active === false || isEndpointStale(endpoint, zombieDays);
        const hasSensitiveData = recentFindings.some(event => String(event.function || '').toLowerCase() === 'data_exposure');
        const hasAuthorizationFindings = recentFindings.some(event => isAuthorizationFunction(String(event.function || '')));
        const hasAutomationFindings = recentFindings.some(event => String(event.function || '').toLowerCase() === 'automation_abuse');
        const hasRepeatedFindings = endpointFindingCount >= 3;
        const riskReasons: string[] = [];
        if (hasSensitiveData && schemaMissing) riskReasons.push('Sensitive data with no schema');
        if (hasAuthorizationFindings) riskReasons.push('Authorization findings');
        if (isShadow) riskReasons.push('Shadow API');
        if (hasRepeatedFindings) riskReasons.push('Repeated findings');
        if (hasAutomationFindings) riskReasons.push('Automation findings');
        if (isZombie) riskReasons.push('Zombie API');
        if (schemaMissing && !isShadow) riskReasons.push('Missing schema');
        if (!riskReasons.length && endpoint.last_finding) riskReasons.push(labelizeAPIInventoryValue(endpoint.last_finding));
        return {
            endpoint,
            key,
            metadata: getInventoryMetadataByKey(config, key),
            riskReasons: uniqueStringList(riskReasons),
            riskScore: getEndpointRiskScore({ schemaMissing, isShadow, isZombie, hasSensitiveData, hasAuthorizationFindings, hasAutomationFindings, hasRepeatedFindings }),
            recentFindings,
            endpointFindingCount,
            schemaMissing,
            isShadow,
            isZombie,
            hasSensitiveData,
            hasAuthorizationFindings,
            hasAutomationFindings,
            hasRepeatedFindings
        };
    });
}

function getEndpointRiskScore(flags: Pick<APISecurityEndpointPosture, 'schemaMissing' | 'isShadow' | 'isZombie' | 'hasSensitiveData' | 'hasAuthorizationFindings' | 'hasAutomationFindings' | 'hasRepeatedFindings'>): number {
    let score = 0;
    if (flags.hasSensitiveData && flags.schemaMissing) score = Math.max(score, 100);
    if (flags.hasAuthorizationFindings) score = Math.max(score, 90);
    if (flags.isShadow) score = Math.max(score, 80);
    if (flags.hasRepeatedFindings) score = Math.max(score, 70);
    if (flags.hasAutomationFindings) score = Math.max(score, 60);
    if (flags.isZombie) score = Math.max(score, 50);
    if (flags.schemaMissing) score = Math.max(score, 40);
    return score;
}

function getEndpointRecentFindings(dashboard: APISecurityDashboardPayload, endpoint: APISecurityEndpoint): APISecurityEventRow[] {
    const path = String(endpoint.path || '');
    const method = String(endpoint.method || '').toUpperCase();
    const host = String(endpoint.host || '');
    return (dashboard.events?.events || [])
        .filter(isAPIEventFinding)
        .filter(event => {
            if (path && event.path !== path) return false;
            if (method && event.method && String(event.method).toUpperCase() !== method) return false;
            if (host && event.host && event.host !== host) return false;
            return true;
        })
        .slice(0, 5);
}

function getEndpointFindingCount(dashboard: APISecurityDashboardPayload, endpoint: APISecurityEndpoint, recentFindings: APISecurityEventRow[]): number {
    const path = String(endpoint.path || '');
    const item = getBreakdownItems(dashboard, 'endpoints').find(entry => {
        const label = String(entry.label || '');
        const key = String(entry.key || '');
        return label === path || key.endsWith(`:${path}`) || key.includes(`:${path}:`) || key.includes(path);
    });
    return item?.count || recentFindings.length;
}

function isEndpointStale(endpoint: APISecurityEndpoint, days: number): boolean {
    if (!endpoint.last_seen) return false;
    const lastSeen = Date.parse(endpoint.last_seen);
    if (!Number.isFinite(lastSeen)) return false;
    return Date.now() - lastSeen > Math.max(days, 1) * 24 * 60 * 60 * 1000;
}

function getInventoryPostureCounts(posture: APISecurityEndpointPosture[]): { sensitive: number; repeated: number; missing: number; shadow: number; zombie: number; review: number } {
    return posture.reduce((acc, item) => {
        if (item.schemaMissing) acc.missing += 1;
        if (item.isShadow) acc.shadow += 1;
        if (item.isZombie) acc.zombie += 1;
        if (item.hasSensitiveData) acc.sensitive += 1;
        if (item.hasRepeatedFindings) acc.repeated += 1;
        if (item.riskScore > 0 && !['accepted', 'ignored', 'deprecated'].includes(item.metadata.triage_state || '')) acc.review += 1;
        return acc;
    }, { sensitive: 0, repeated: 0, missing: 0, shadow: 0, zombie: 0, review: 0 });
}

function renderInventorySummaryMetrics(coverage: Required<APISecurityInventoryCoverage>, counts: { sensitive: number; repeated: number; missing: number; shadow: number; zombie: number; review: number }): string {
    const missingSchemas = Math.max(counts.missing, coverage.endpoints_without_schema || 0);
    return renderAPISecurityMetricStrip([
        { label: 'Total endpoints', value: formatAPINumber(coverage.total_endpoints), sub: 'Discovered API surface', tone: 'neutral' },
        { label: 'Missing schema', value: formatAPINumber(missingSchemas), sub: 'Need contract coverage', tone: missingSchemas > 0 ? 'warning' : 'neutral' },
        { label: 'Shadow APIs', value: formatAPINumber(counts.shadow), sub: 'Unmanaged active endpoints', tone: counts.shadow > 0 ? 'warning' : 'neutral' },
        { label: 'Needs review', value: formatAPINumber(counts.review), sub: 'Open triage work', tone: counts.review > 0 ? 'warning' : 'success' }
    ], 'apisecurity-inventory-kpis');
}

const APISecurityInventoryColumnIds: APISecurityInventoryColumnId[] = ['method', 'traffic', 'schema', 'posture', 'last_seen', 'findings'];

function getDefaultAPISecurityInventoryFilters(): APISecurityInventoryFilters {
    return { search: '', host: 'all', method: 'all', schema: 'all', risk: 'all', active: 'all' };
}

function getDefaultAPISecurityInventoryColumns(): APISecurityInventoryColumnVisibility {
    return { method: true, traffic: true, schema: true, posture: true, last_seen: true, findings: true };
}

function normalizeAPISecurityInventoryFilters(value: unknown): APISecurityInventoryFilters {
    const input = typeof value === 'object' && value !== null ? value as Partial<Record<keyof APISecurityInventoryFilters, unknown>> : {};
    const defaults = getDefaultAPISecurityInventoryFilters();
    return {
        search: String(input.search ?? defaults.search),
        host: String(input.host ?? defaults.host) || 'all',
        method: String(input.method ?? defaults.method) || 'all',
        schema: String(input.schema ?? defaults.schema) || 'all',
        risk: String(input.risk ?? defaults.risk) || 'all',
        active: String(input.active ?? defaults.active) || 'all'
    };
}

function normalizeAPISecurityInventoryColumns(value: unknown): APISecurityInventoryColumnVisibility {
    const input = typeof value === 'object' && value !== null ? value as Partial<Record<APISecurityInventoryColumnId, unknown>> : {};
    const defaults = getDefaultAPISecurityInventoryColumns();
    const next = APISecurityInventoryColumnIds.reduce((acc, column) => {
        acc[column] = input[column] === undefined ? defaults[column] : input[column] !== false;
        return acc;
    }, {} as APISecurityInventoryColumnVisibility);
    if (!APISecurityInventoryColumnIds.some(column => next[column])) next.traffic = true;
    return next;
}

function loadAPISecurityInventorySavedViews(): APISecurityInventorySavedView[] {
    return readAPISecurityLocalJSON<APISecurityInventorySavedView[]>(APISEC_INVENTORY_SAVED_VIEWS_KEY, [])
        .map(normalizeAPISecurityInventorySavedView)
        .filter((view): view is APISecurityInventorySavedView => Boolean(view))
        .slice(0, 12);
}

function loadAPISecurityInventoryRecentFilters(): APISecurityInventoryRecentFilter[] {
    return readAPISecurityLocalJSON<APISecurityInventoryRecentFilter[]>(APISEC_INVENTORY_RECENT_FILTERS_KEY, [])
        .map(normalizeAPISecurityInventoryRecentFilter)
        .filter((filter): filter is APISecurityInventoryRecentFilter => Boolean(filter))
        .slice(0, 8);
}

function readAPISecurityLocalJSON<T>(key: string, fallback: T): T {
    try {
        const raw = window.localStorage.getItem(key);
        if (!raw) return fallback;
        return JSON.parse(raw) as T;
    } catch {
        return fallback;
    }
}

function writeAPISecurityLocalJSON(key: string, value: unknown): void {
    try {
        window.localStorage.setItem(key, JSON.stringify(value));
    } catch {
        // Browser-local views are optional; config saving must not depend on localStorage.
    }
}

function normalizeAPISecurityInventorySavedView(value: unknown): APISecurityInventorySavedView | null {
    if (typeof value !== 'object' || value === null) return null;
    const input = value as Partial<APISecurityInventorySavedView>;
    const id = String(input.id || '').trim();
    const name = String(input.name || '').trim();
    if (!id || !name) return null;
    return {
        id,
        name,
        filters: normalizeAPISecurityInventoryFilters(input.filters),
        columns: normalizeAPISecurityInventoryColumns(input.columns),
        groupBy: normalizeAPISecurityInventoryGroupBy(input.groupBy),
        created_at: String(input.created_at || input.updated_at || new Date().toISOString()),
        updated_at: String(input.updated_at || input.created_at || new Date().toISOString())
    };
}

function normalizeAPISecurityInventoryRecentFilter(value: unknown): APISecurityInventoryRecentFilter | null {
    if (typeof value !== 'object' || value === null) return null;
    const input = value as Partial<APISecurityInventoryRecentFilter>;
    const filters = normalizeAPISecurityInventoryFilters(input.filters);
    if (getActiveInventoryFilterCount(filters) === 0) return null;
    return {
        id: String(input.id || buildAPISecurityInventoryFilterId(filters)),
        label: String(input.label || formatAPISecurityInventoryFilterLabel(filters)),
        filters,
        used_at: String(input.used_at || new Date().toISOString())
    };
}

function saveAPISecurityInventoryView(
    views: APISecurityInventorySavedView[],
    name: string,
    filters: APISecurityInventoryFilters,
    columns: APISecurityInventoryColumnVisibility,
    groupBy: APISecurityInventoryGroupBy
): APISecurityInventorySavedView[] {
    const now = new Date().toISOString();
    const id = `view-${slugifyAPISecurityLocalName(name)}-${Date.now().toString(36)}`;
    const next = [
        {
            id,
            name,
            filters: normalizeAPISecurityInventoryFilters(filters),
            columns: normalizeAPISecurityInventoryColumns(columns),
            groupBy: normalizeAPISecurityInventoryGroupBy(groupBy),
            created_at: now,
            updated_at: now
        },
        ...views
    ].slice(0, 12);
    writeAPISecurityLocalJSON(APISEC_INVENTORY_SAVED_VIEWS_KEY, next);
    return next;
}

function deleteAPISecurityInventoryView(views: APISecurityInventorySavedView[], id: string): APISecurityInventorySavedView[] {
    const next = views.filter(view => view.id !== id);
    writeAPISecurityLocalJSON(APISEC_INVENTORY_SAVED_VIEWS_KEY, next);
    return next;
}

function rememberAPISecurityInventoryRecentFilter(filters: APISecurityInventoryFilters, current: APISecurityInventoryRecentFilter[]): APISecurityInventoryRecentFilter[] {
    const normalized = normalizeAPISecurityInventoryFilters(filters);
    if (getActiveInventoryFilterCount(normalized) === 0) return current;
    const now = new Date().toISOString();
    const id = buildAPISecurityInventoryFilterId(normalized);
    const next = [
        { id, label: formatAPISecurityInventoryFilterLabel(normalized), filters: normalized, used_at: now },
        ...current.filter(item => item.id !== id)
    ].slice(0, 8);
    writeAPISecurityLocalJSON(APISEC_INVENTORY_RECENT_FILTERS_KEY, next);
    return next;
}

function buildAPISecurityInventoryFilterId(filters: APISecurityInventoryFilters): string {
    return btoa(unescape(encodeURIComponent(JSON.stringify(normalizeAPISecurityInventoryFilters(filters))))).replace(/=+$/g, '').slice(0, 80);
}

function buildAPISecurityInventoryViewName(filters: APISecurityInventoryFilters, groupBy: APISecurityInventoryGroupBy): string {
    const label = formatAPISecurityInventoryFilterLabel(filters);
    return groupBy === 'none' ? label : `${label} by ${labelizeAPIInventoryValue(groupBy)}`;
}

function formatAPISecurityInventoryViewSummary(filters: APISecurityInventoryFilters, groupBy: APISecurityInventoryGroupBy): string {
    const filterLabel = formatAPISecurityInventoryFilterLabel(filters);
    return groupBy === 'none' ? filterLabel : `${filterLabel} / grouped by ${labelizeAPIInventoryValue(groupBy)}`;
}

function formatAPISecurityInventoryFilterLabel(filters: APISecurityInventoryFilters): string {
    const active = (Object.keys(filters) as Array<keyof APISecurityInventoryFilters>)
        .filter(key => key === 'search' ? Boolean(String(filters[key] || '').trim()) : Boolean(filters[key] && filters[key] !== 'all'))
        .map(key => `${getInventoryFilterLabel(key)}: ${getInventoryFilterDisplayValue(key, filters[key])}`);
    return active.length ? active.join(', ') : 'All endpoints';
}

function slugifyAPISecurityLocalName(value: string): string {
    return String(value || 'view').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32) || 'view';
}

function renderInventoryToolbar(
    inventory: APISecurityEndpoint[],
    filters: APISecurityInventoryFilters,
    filterMenuOpen: boolean,
    viewMenuOpen: boolean,
    columns: APISecurityInventoryColumnVisibility,
    groupBy: APISecurityInventoryGroupBy,
    savedViews: APISecurityInventorySavedView[],
    recentFilters: APISecurityInventoryRecentFilter[],
    filteredCount: number,
    totalCount: number
): string {
    const hosts = uniqueInventoryValues(inventory.map(endpoint => endpoint.host || '').filter(Boolean));
    const methods = uniqueInventoryValues(inventory.map(endpoint => endpoint.method || '').filter(Boolean));
    const activeCount = getActiveInventoryFilterCount(filters);
    const viewSummary = groupBy === 'none'
        ? `${APISecurityInventoryColumnIds.filter(column => columns[column]).length + 2} columns`
        : `Grouped by ${labelizeAPIInventoryValue(groupBy)}`;
    const countLabel = filteredCount === totalCount
        ? `${formatAPINumber(totalCount)} endpoint${totalCount === 1 ? '' : 's'} discovered`
        : `${formatAPINumber(filteredCount)} matching endpoint${filteredCount === 1 ? '' : 's'} of ${formatAPINumber(totalCount)}`;
    return `
        <div class="apisecurity-inventory-console-head">
            <div>
                <div class="apisecurity-inventory-eyebrow">API inventory</div>
                <h4>Discovered endpoints</h4>
                <p>Review observed API routes, contract coverage, and endpoint posture from inspected traffic.</p>
            </div>
            <div class="apisecurity-inventory-head-actions">
                <div class="apisecurity-inventory-filter-menu">
                    <button class="operator-btn operator-btn-secondary" type="button" data-api-security-action="toggle-inventory-filter-menu" aria-expanded="${filterMenuOpen ? 'true' : 'false'}">Add filter</button>
                    ${filterMenuOpen ? renderInventoryAddFilterMenu(hosts, methods, filters) : ''}
                </div>
                <div class="apisecurity-inventory-filter-menu">
                    <button class="operator-btn operator-btn-primary" type="button" data-api-security-action="toggle-inventory-view-menu" aria-expanded="${viewMenuOpen ? 'true' : 'false'}">View</button>
                    ${viewMenuOpen ? renderInventoryViewMenu(columns, groupBy, savedViews, recentFilters, filters) : ''}
                </div>
            </div>
        </div>
        <div class="apisecurity-inventory-toolbar">
            <div class="apisecurity-inventory-count" role="status" aria-live="polite">
                <strong>${formatAPINumber(filteredCount)}</strong>
                <span>${escapeSectionHtml(countLabel)}</span>
                <span class="apisecurity-inventory-view-summary">${escapeSectionHtml(viewSummary)}</span>
            </div>
            <div class="apisecurity-inventory-tools">
                ${activeCount > 0 ? `<button class="operator-btn operator-btn-secondary btn-xs" type="button" data-api-security-action="clear-inventory-filters">Clear filters</button>` : ''}
                <label class="apisecurity-inventory-search">
                    <span class="apisecurity-inventory-search-icon" aria-hidden="true">${SectionUI.icons.search || ''}</span>
                    <input class="input" type="search" value="${escapeSectionHtml(filters.search || '')}" aria-label="Search API inventory" placeholder="Search method, path, or host" data-api-inventory-filter="search">
                </label>
            </div>
        </div>
        ${renderInventoryFilterChips(filters)}
    `;
}

function renderInventoryViewMenu(
    columns: APISecurityInventoryColumnVisibility,
    groupBy: APISecurityInventoryGroupBy,
    savedViews: APISecurityInventorySavedView[],
    recentFilters: APISecurityInventoryRecentFilter[],
    filters: APISecurityInventoryFilters
): string {
    const groupOptions: Array<{ value: APISecurityInventoryGroupBy; label: string }> = [
        { value: 'none', label: 'No grouping' },
        { value: 'host', label: 'Host' },
        { value: 'method', label: 'Method' },
        { value: 'schema', label: 'Schema' },
        { value: 'posture', label: 'Posture' },
        { value: 'service', label: 'Service' },
        { value: 'owner', label: 'Owner' }
    ];
    const suggestedName = buildAPISecurityInventoryViewName(filters, groupBy);
    return `
        <div class="apisecurity-inventory-filter-popover apisecurity-inventory-view-popover" role="dialog" aria-label="Configure inventory view">
            <div class="apisecurity-inventory-view-layout">
                <label class="bot-overview-field apisecurity-inventory-filter-field">
                    <span>Group by</span>
                    <select data-api-inventory-group-by>
                        ${groupOptions.map(option => `<option value="${option.value}" ${groupBy === option.value ? 'selected' : ''}>${escapeSectionHtml(option.label)}</option>`).join('')}
                    </select>
                </label>
                <fieldset class="apisecurity-inventory-view-columns">
                    <legend>Columns</legend>
                    <div class="apisecurity-inventory-view-column-grid">
                        ${APISecurityInventoryColumnIds.map(column => `
                            <label class="apisecurity-inventory-column-option">
                                <input type="checkbox" ${columns[column] ? 'checked' : ''} data-api-security-action="toggle-inventory-column" data-api-inventory-column="${column}">
                                <span>${escapeSectionHtml(getInventoryColumnLabel(column))}</span>
                            </label>
                        `).join('')}
                    </div>
                </fieldset>
            </div>
            <div class="apisecurity-inventory-view-save">
                <label class="bot-overview-field apisecurity-inventory-filter-field">
                    <span>Save view</span>
                    <span class="apisecurity-inventory-view-save-row">
                        <input value="${escapeSectionHtml(suggestedName)}" data-api-inventory-view-name placeholder="View name">
                        <button class="btn btn-primary btn-sm" type="button" data-api-security-action="save-inventory-view">Save current</button>
                    </span>
                </label>
            </div>
            <div class="apisecurity-inventory-local-views">
                <strong class="apisecurity-inventory-view-section-title">Saved views</strong>
                ${savedViews.length ? savedViews.map(view => `
                    <div class="apisecurity-inventory-local-view">
                        <button class="link-button text-left" type="button" data-api-security-action="apply-inventory-view" data-api-inventory-view-id="${escapeSectionHtml(view.id)}">
                            <strong>${escapeSectionHtml(view.name)}</strong>
                            <small>${escapeSectionHtml(formatAPISecurityInventoryViewSummary(view.filters, view.groupBy))}</small>
                        </button>
                        <button class="btn btn-ghost btn-xs" type="button" data-api-security-action="delete-inventory-view" data-api-inventory-view-id="${escapeSectionHtml(view.id)}">Remove</button>
                    </div>
                `).join('') : '<div class="apisecurity-inventory-view-empty">No saved views in this browser.</div>'}
            </div>
            <div class="apisecurity-inventory-local-views">
                <strong class="apisecurity-inventory-view-section-title">Recent filters</strong>
                ${recentFilters.length ? recentFilters.map(recent => `
                    <button class="apisecurity-inventory-recent-filter" type="button" data-api-security-action="apply-inventory-recent-filter" data-api-inventory-recent-filter-id="${escapeSectionHtml(recent.id)}">
                        <strong>${escapeSectionHtml(recent.label)}</strong>
                        <small>${escapeSectionHtml(formatAPIDate(recent.used_at))}</small>
                    </button>
                `).join('') : '<div class="apisecurity-inventory-view-empty">Recent filters appear after filtering inventory.</div>'}
            </div>
        </div>
    `;
}

function renderInventoryAddFilterMenu(hosts: string[], methods: string[], filters: APISecurityInventoryFilters): string {
    return `
        <div class="apisecurity-inventory-filter-popover">
            ${renderInventorySelectFilter('Host', 'host', filters.host, hosts)}
            ${renderInventorySelectFilter('Method', 'method', filters.method, methods)}
            ${renderInventorySelectFilter('Schema', 'schema', filters.schema, ['covered', 'missing', 'unknown'])}
            ${renderInventorySelectFilter('Posture', 'risk', filters.risk, ['normal', 'shadow', 'zombie', 'review', 'sensitive'])}
            ${renderInventorySelectFilter('Traffic state', 'active', filters.active, ['active', 'inactive'])}
        </div>
    `;
}

function renderInventorySelectFilter(label: string, key: keyof APISecurityInventoryFilters, value: string, options: string[]): string {
    return `
        <label class="bot-overview-field apisecurity-inventory-filter-field">
            <span>${escapeSectionHtml(label)}</span>
            <select data-api-inventory-filter="${key}">
                <option value="all" ${!value || value === 'all' ? 'selected' : ''}>All</option>
                ${options.map(option => `<option value="${escapeSectionHtml(option)}" ${value === option ? 'selected' : ''}>${escapeSectionHtml(labelizeAPIInventoryValue(option))}</option>`).join('')}
            </select>
        </label>
    `;
}

function renderInventoryFilterChips(filters: APISecurityInventoryFilters): string {
    const chips = (Object.keys(filters) as Array<keyof APISecurityInventoryFilters>)
        .filter(key => key === 'search' ? Boolean(String(filters[key] || '').trim()) : Boolean(filters[key] && filters[key] !== 'all'))
        .map(key => `
            <span class="apisecurity-inventory-filter-chip">
                <strong>${escapeSectionHtml(getInventoryFilterLabel(key))}</strong>
                ${escapeSectionHtml(getInventoryFilterDisplayValue(key, filters[key]))}
                <button type="button" data-api-security-action="clear-inventory-filter" data-api-inventory-filter-key="${key}" aria-label="Remove ${escapeSectionHtml(getInventoryFilterLabel(key))} filter">x</button>
            </span>
        `);
    if (!chips.length) return '';
    return `
        <div class="apisecurity-inventory-filter-chips">
            <span class="operator-toolbar-note">Active filters</span>
            ${chips.join('')}
        </div>
    `;
}

function getActiveInventoryFilterCount(filters: APISecurityInventoryFilters): number {
    return (Object.keys(filters) as Array<keyof APISecurityInventoryFilters>)
        .filter(key => key === 'search' ? Boolean(String(filters[key] || '').trim()) : Boolean(filters[key] && filters[key] !== 'all')).length;
}

function getInventoryFilterLabel(key: keyof APISecurityInventoryFilters): string {
    switch (key) {
        case 'search': return 'Search';
        case 'host': return 'Host';
        case 'method': return 'Method';
        case 'schema': return 'Schema';
        case 'risk': return 'Posture';
        case 'active': return 'Traffic';
        default: return labelizeAPIInventoryValue(String(key));
    }
}

function getInventoryFilterDisplayValue(key: keyof APISecurityInventoryFilters, value: string): string {
    if (key === 'search') return value;
    return labelizeAPIInventoryValue(value);
}

function getFilteredInventoryPosture(posture: APISecurityEndpointPosture[], filters: APISecurityInventoryFilters): APISecurityEndpointPosture[] {
    const search = String(filters.search || '').trim().toLowerCase();
    return posture.filter(item => {
        const endpoint = item.endpoint;
        const host = endpoint.host || '';
        const method = endpoint.method || '';
        const schema = getEndpointSchemaStatus(endpoint);
        const active = endpoint.is_active !== false ? 'active' : 'inactive';
        const searchable = `${method} ${endpoint.path || ''} ${host}`.toLowerCase();
        return (!search || searchable.includes(search)) &&
            (!filters.host || filters.host === 'all' || host === filters.host) &&
            (!filters.method || filters.method === 'all' || method === filters.method) &&
            (!filters.schema || filters.schema === 'all' || schema === filters.schema) &&
            inventoryPostureMatchesFilter(item, filters.risk) &&
            (!filters.active || filters.active === 'all' || active === filters.active);
    });
}

function renderGroupedInventoryEndpointTables(
    posture: APISecurityEndpointPosture[],
    selectedKey: string,
    columns: APISecurityInventoryColumnVisibility,
    groupBy: APISecurityInventoryGroupBy
): string {
    if (!posture.length) return renderInventoryEndpointTable(posture, selectedKey, columns);
    const groups = new Map<string, APISecurityEndpointPosture[]>();
    posture.forEach(item => {
        const key = getInventoryGroupValue(item, groupBy);
        const bucket = groups.get(key) || [];
        bucket.push(item);
        groups.set(key, bucket);
    });
    return `
        <div class="apisecurity-inventory-grouped-table">
            ${Array.from(groups.entries()).map(([group, items]) => `
                <div class="apisecurity-inventory-group">
                    <div class="apisecurity-inventory-group-head">
                        <strong>${escapeSectionHtml(group)}</strong>
                        <span class="operator-toolbar-note">${formatAPINumber(items.length)} endpoint${items.length === 1 ? '' : 's'}</span>
                    </div>
                    ${renderInventoryEndpointTable(items, selectedKey, columns)}
                </div>
            `).join('')}
        </div>
    `;
}

function getAPIMethodTone(method?: string): string {
    const m = String(method || '').toUpperCase().trim();
    if (m === 'GET') return 'get';
    if (m === 'POST') return 'post';
    if (m === 'PUT') return 'put';
    if (m === 'PATCH') return 'patch';
    if (m === 'DELETE') return 'delete';
    return 'default';
}

function renderInventoryEndpointTable(
    posture: APISecurityEndpointPosture[],
    selectedKey = '',
    columns: APISecurityInventoryColumnVisibility = { method: true, traffic: true, schema: true, posture: true, last_seen: true, findings: true }
): string {
    const columnDefinitions: Array<{ id: 'api' | APISecurityInventoryColumnId | 'actions'; label: string; visible: boolean }> = [
        { id: 'api', label: 'Endpoint', visible: true },
        { id: 'method', label: 'Method', visible: columns.method !== false },
        { id: 'traffic', label: 'Traffic', visible: columns.traffic !== false },
        { id: 'schema', label: 'Schema', visible: columns.schema !== false },
        { id: 'posture', label: 'Posture', visible: columns.posture !== false },
        { id: 'last_seen', label: 'Last seen', visible: columns.last_seen !== false },
        { id: 'findings', label: 'Findings', visible: columns.findings !== false },
        { id: 'actions', label: 'Actions', visible: true }
    ];
    const visibleColumns = columnDefinitions.filter(column => column.visible);
    return `<div class="routing-table-surface apisecurity-inventory-table-surface">${SectionUI.renderEnterpriseTable({
        columns: visibleColumns.map(column => column.label),
        rows: posture.map(item => {
            const endpoint = item.endpoint;
            const selected = item.key === normalizeInventoryEndpointKey(selectedKey);
            const methodTone = getAPIMethodTone(endpoint.method);
            const cells: Record<string, string> = {
                api: `<button class="link-button text-left apisecurity-api-cell routing-route-main ${selected ? 'is-selected' : ''}" type="button" data-api-security-action="open-inventory-endpoint" data-api-endpoint-key="${escapeSectionHtml(item.key)}" aria-pressed="${selected ? 'true' : 'false'}">
                        <span class="routing-route-icon" aria-hidden="true">${SectionUI.icons.globe || '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>'}</span>
                        <span class="routing-route-copy apisecurity-endpoint-copy">
                            <strong class="apisecurity-endpoint-path">${escapeSectionHtml(endpoint.path || '/')}</strong>
                            <small class="apisecurity-endpoint-host text-note">${escapeSectionHtml(endpoint.host || 'All hosts')}</small>
                        </span>
                    </button>`,
                method: `<span class="apisecurity-method-badge apisecurity-method-${methodTone}">${escapeSectionHtml(endpoint.method || 'GET')}</span>`,
                traffic: renderInventoryTrafficCell(endpoint),
                schema: renderInventorySchemaCell(endpoint),
                posture: renderInventoryPostureCell(item),
                last_seen: renderInventoryLastSeenCell(endpoint),
                findings: renderInventoryFindingsCell(item),
                actions: renderInventoryTableActions(item)
            };
            return visibleColumns.map(column => cells[column.id] || '');
        }),
        emptyTitle: 'No discovered endpoints yet',
        emptyMessage: 'Inventory will populate when API traffic is inspected.',
        className: `routing-rule-table apisecurity-inventory-table apisecurity-inventory-table--${visibleColumns.length}`
    })}</div>`;
}

function getInventoryGroupValue(item: APISecurityEndpointPosture, groupBy: APISecurityInventoryGroupBy): string {
    const endpoint = item.endpoint;
    if (groupBy === 'host') return endpoint.host || 'Unknown host';
    if (groupBy === 'method') return endpoint.method || 'Unknown method';
    if (groupBy === 'schema') return labelizeAPIInventoryValue(getEndpointSchemaStatus(endpoint));
    if (groupBy === 'posture') return getInventoryPostureLabel(item);
    if (groupBy === 'service') return item.metadata.service || 'Unassigned service';
    if (groupBy === 'owner') return item.metadata.owner || 'Unassigned owner';
    return 'All endpoints';
}

function getInventoryColumnLabel(column: APISecurityInventoryColumnId): string {
    switch (column) {
        case 'method': return 'Method';
        case 'traffic': return 'Traffic';
        case 'schema': return 'Schema';
        case 'posture': return 'Posture';
        case 'last_seen': return 'Last seen';
        case 'findings': return 'Findings';
        default: return labelizeAPIInventoryValue(column);
    }
}

function isAPISecurityInventoryColumnId(value: unknown): value is APISecurityInventoryColumnId {
    return APISecurityInventoryColumnIds.includes(String(value || '') as APISecurityInventoryColumnId);
}

function normalizeAPISecurityInventoryGroupBy(value: unknown): APISecurityInventoryGroupBy {
    const normalized = String(value || '').trim();
    return ['none', 'host', 'method', 'schema', 'posture', 'service', 'owner'].includes(normalized)
        ? normalized as APISecurityInventoryGroupBy
        : 'none';
}

function renderInventoryTrafficCell(endpoint: APISecurityEndpoint): string {
    const active = endpoint.is_active !== false;
    return `<strong>${active ? 'Active' : 'Inactive'}</strong>`;
}

function renderInventoryLastSeenCell(endpoint: APISecurityEndpoint): string {
    if (!endpoint.last_seen) {
        return '<span class="routing-empty-value">—</span>';
    }
    return `<span class="text-note apisecurity-last-seen-date">${escapeSectionHtml(formatAPIDate(endpoint.last_seen))}</span>`;
}

function formatAPISchemaType(type?: string): string {
    const raw = String(type || '').trim().toLowerCase();
    if (raw === 'openapi' || raw === 'swagger') return 'OpenAPI';
    if (raw === 'graphql') return 'GraphQL';
    if (raw === 'grpc' || raw === 'proto' || raw === 'protobuf') return 'gRPC';
    if (!raw) return '';
    return raw.charAt(0).toUpperCase() + raw.slice(1);
}

function renderInventorySchemaCell(endpoint: APISecurityEndpoint): string {
    const schema = getEndpointSchemaStatus(endpoint);
    const baseLabel = labelizeAPIInventoryValue(schema);
    const schemaType = formatAPISchemaType(endpoint.schema_type);
    const label = schema === 'covered' && schemaType ? `${baseLabel} - ${schemaType}` : baseLabel;
    return `<strong>${escapeSectionHtml(label)}</strong>`;
}

function renderInventoryPostureCell(item: APISecurityEndpointPosture): string {
    const postureLabel = getInventoryPostureLabel(item);
    return `<strong>${escapeSectionHtml(postureLabel)}</strong>`;
}

function renderInventoryFindingsCell(item: APISecurityEndpointPosture): string {
    const count = item.endpointFindingCount || 0;
    if (count > 0) {
        return SectionUI.renderStatusPill(`${formatAPINumber(count)} ${count === 1 ? 'issue' : 'issues'}`, count > 5 ? 'danger' : 'warning');
    }
    return '<span class="routing-empty-value">0 issues</span>';
}

function renderInventoryTableActions(item: APISecurityEndpointPosture): string {
    const endpoint = item.endpoint;
    const schema = getEndpointSchemaStatus(endpoint);
    const endpointLabel = `${endpoint.method || 'API'} ${endpoint.path || '/'}`;
    const actions = SectionUI.renderActionMenu({
        id: `apisecurity-inventory-actions-${encodeURIComponent(item.key)}`,
        label: 'Actions',
        ariaLabel: `Actions for ${endpointLabel}`,
        items: [
            {
                label: 'Review',
                attrs: `data-api-security-action="open-inventory-endpoint" data-api-endpoint-key="${escapeSectionHtml(item.key)}"`
            },
            {
                label: schema === 'covered' ? 'Update schema' : 'Attach schema',
                attrs: `data-api-security-action="prefill-schema-endpoint" data-api-endpoint-key="${escapeSectionHtml(item.key)}"`
            },
            {
                label: 'Investigate',
                attrs: `data-api-security-action="investigate-dashboard" data-dashboard-section="api_security" data-dashboard-path="${escapeSectionHtml(endpoint.path || '')}" data-dashboard-method="${escapeSectionHtml(endpoint.method || '')}" data-dashboard-host="${endpoint.host && endpoint.host !== 'All hosts' ? escapeSectionHtml(endpoint.host) : ''}"`
            }
        ],
        className: 'apisecurity-inventory-table-actions'
    });
    return `<div class="operator-control-actions routing-row-actions apisecurity-table-actions">${actions}</div>`;
}

function inventoryPostureMatchesFilter(item: APISecurityEndpointPosture, filter: string): boolean {
    if (!filter || filter === 'all') return true;
    switch (filter) {
        case 'sensitive': return item.hasSensitiveData;
        case 'shadow': return item.isShadow;
        case 'zombie': return item.isZombie;
        case 'review': return item.riskScore > 0 && !['accepted', 'ignored', 'deprecated'].includes(item.metadata.triage_state || '');
        case 'normal': return getInventoryPostureFilterValue(item) === 'normal';
        default: return getInventoryPostureFilterValue(item) === filter;
    }
}

function getInventoryPostureFilterValue(item: APISecurityEndpointPosture): string {
    if (item.hasSensitiveData) return 'sensitive';
    if (item.isShadow) return 'shadow';
    if (item.isZombie) return 'zombie';
    if (item.riskScore > 0) return 'review';
    return 'normal';
}

function getInventoryPostureLabel(item: APISecurityEndpointPosture): string {
    const value = getInventoryPostureFilterValue(item);
    if (value === 'review') return 'Needs review';
    return labelizeAPIInventoryValue(value);
}

function getInventoryPostureTone(item: APISecurityEndpointPosture): string {
    const value = getInventoryPostureFilterValue(item);
    if (value === 'sensitive') return 'danger';
    if (value === 'shadow' || value === 'review') return 'warning';
    if (value === 'zombie') return 'neutral';
    return 'success';
}

function renderInventoryEndpointDetail(
    item: APISecurityEndpointPosture | null,
    config: APISecurityState,
    dashboard: APISecurityDashboardPayload,
    inventory: APISecurityEndpoint[]
): string {
    if (!item) return '';
    const endpoint = item.endpoint;
    const metadata = item.metadata;
    const triage = getInventoryTriageState(item);
    const schema = getEndpointSchemaStatus(endpoint);
    const active = endpoint.is_active !== false;
    const schemaTone = schema === 'covered' ? 'success' : schema === 'missing' ? 'warning' : 'neutral';
    const policyCoverage = API_SECURITY_POLICY_CATALOG.map(policy => {
        const surface = getAPISecurityPolicySurfaceSummary(policy.id, config, dashboard, inventory);
        const state = getAPISecurityPolicyState(config, policy.id);
        return `
            <div class="apisecurity-endpoint-policy">
                <span>${escapeSectionHtml(getAPISecurityPolicyDisplayTitle(policy.id))}</span>
                <strong>${escapeSectionHtml(surface.summary)}</strong>
                <small>${escapeSectionHtml(surface.detail)} / ${escapeSectionHtml(state.enabled ? 'Enabled' : 'Off')}</small>
            </div>
        `;
    }).join('');

    return `
        <aside class="apisecurity-endpoint-detail" aria-label="Selected endpoint detail">
            <div class="apisecurity-endpoint-detail-head">
                <div class="apisecurity-endpoint-title">
                    <strong>${escapeSectionHtml(endpoint.method || 'GET')} ${escapeSectionHtml(endpoint.path || '/')}</strong>
                    <span>${escapeSectionHtml(endpoint.host || 'unknown host')}</span>
                </div>
            </div>
            <div class="apisecurity-endpoint-actions">
                <button class="btn btn-secondary btn-sm" type="button" data-api-security-action="prefill-schema-endpoint" data-api-endpoint-key="${escapeSectionHtml(item.key)}">${schema === 'covered' ? 'Update Schema' : 'Attach Schema'}</button>
                <button class="btn btn-secondary btn-sm" type="button" data-api-security-action="investigate-dashboard" data-dashboard-section="api_security" data-dashboard-path="${escapeSectionHtml(endpoint.path || '')}" data-dashboard-method="${escapeSectionHtml(endpoint.method || '')}" data-dashboard-host="${endpoint.host && endpoint.host !== 'All hosts' ? escapeSectionHtml(endpoint.host) : ''}">Investigate</button>
                <button class="btn btn-secondary btn-sm" type="button" data-api-security-action="close-inventory-endpoint">Close</button>
            </div>
            <div class="apisecurity-endpoint-detail-section">
                <div class="apisecurity-endpoint-section-title">Endpoint summary</div>
                <div class="apisecurity-endpoint-fact-grid">
                    ${renderInventoryEndpointFact('Last seen', formatAPIDate(endpoint.last_seen))}
                    ${renderInventoryEndpointFact('Findings', formatAPINumber(item.endpointFindingCount))}
                    ${renderInventoryEndpointFact('Schema type', endpoint.schema_type || 'Not attached')}
                    ${renderInventoryEndpointFact('Environment', labelizeAPIInventoryValue(metadata.environment || 'unknown'))}
                </div>
                <div class="apisecurity-scope-chip-row">${renderRiskReasonChips(item.riskReasons)}</div>
            </div>
            <div class="apisecurity-endpoint-detail-section">
                <div class="apisecurity-endpoint-section-title">Policy coverage</div>
                <div class="apisecurity-endpoint-policy-grid">${policyCoverage}</div>
            </div>
            <div class="apisecurity-endpoint-detail-section">
                <div class="apisecurity-endpoint-section-title">Ownership</div>
                <div class="apisecurity-field-grid apisecurity-field-grid-wide">
                    <label class="bot-overview-field">
                        <span>Environment</span>
                        <input value="${escapeSectionHtml(metadata.environment || 'unknown')}" data-api-endpoint-key="${escapeSectionHtml(item.key)}" data-api-inventory-meta-field="environment" data-api-value-type="string">
                    </label>
                    <label class="bot-overview-field">
                        <span>Criticality</span>
                        <select data-api-endpoint-key="${escapeSectionHtml(item.key)}" data-api-inventory-meta-field="criticality" data-api-value-type="string">
                            ${['low', 'medium', 'high', 'critical'].map(value => `<option value="${value}" ${normalizeInventoryCriticality(metadata.criticality) === value ? 'selected' : ''}>${labelizeAPIInventoryValue(value)}</option>`).join('')}
                        </select>
                    </label>
                    <label class="bot-overview-field">
                        <span>Triage</span>
                        <select data-api-endpoint-key="${escapeSectionHtml(item.key)}" data-api-inventory-meta-field="triage_state" data-api-value-type="string">
                            ${['new', 'in_review', 'accepted', 'ignored', 'needs_schema', 'deprecated'].map(value => `<option value="${value}" ${triage === value ? 'selected' : ''}>${labelizeAPIInventoryValue(value)}</option>`).join('')}
                        </select>
                    </label>
                    <label class="bot-overview-field">
                        <span>Owner</span>
                        <input value="${escapeSectionHtml(metadata.owner || '')}" data-api-endpoint-key="${escapeSectionHtml(item.key)}" data-api-inventory-meta-field="owner" data-api-value-type="string">
                    </label>
                    <label class="bot-overview-field">
                        <span>Service</span>
                        <input value="${escapeSectionHtml(metadata.service || '')}" data-api-endpoint-key="${escapeSectionHtml(item.key)}" data-api-inventory-meta-field="service" data-api-value-type="string">
                    </label>
                    <label class="bot-overview-field">
                        <span>Tags</span>
                        <input value="${escapeSectionHtml((metadata.tags || []).join(', '))}" data-api-endpoint-key="${escapeSectionHtml(item.key)}" data-api-inventory-meta-field="tags" data-api-value-type="string">
                    </label>
                </div>
                <label class="bot-overview-field mt-16">
                    <span>Notes</span>
                    <textarea rows="3" data-api-endpoint-key="${escapeSectionHtml(item.key)}" data-api-inventory-meta-field="notes" data-api-value-type="string">${escapeSectionHtml(metadata.notes || '')}</textarea>
                </label>
            </div>
        </aside>
    `;
}

function renderInventoryEndpointFact(label: string, value: string): string {
    return `
        <div class="apisecurity-endpoint-fact">
            <span>${escapeSectionHtml(label)}</span>
            <strong>${escapeSectionHtml(value)}</strong>
        </div>
    `;
}

const API_SECURITY_SETTINGS_CATEGORIES: Array<{ id: APISecuritySettingCategory; label: string }> = [
    { id: 'discovery', label: 'Discovery' },
    { id: 'inventory_classification', label: 'Inventory Classification' },
    { id: 'schemas', label: 'Schemas' },
    { id: 'identity_auth_detection', label: 'Identity/Auth Detection' },
    { id: 'runtime', label: 'Runtime' },
    { id: 'authorization', label: 'Authorization' },
    { id: 'graphql', label: 'GraphQL' },
    { id: 'abuse', label: 'Abuse' },
    { id: 'data_exposure', label: 'Data Exposure' },
    { id: 'exceptions', label: 'Exceptions' },
    { id: 'integrations_reports', label: 'Integrations/Reports' }
];

const API_SECURITY_POLICY_OWNED_SETTING_CATEGORIES = new Set<APISecuritySettingCategory>([
    'runtime',
    'authorization',
    'graphql',
    'abuse',
    'data_exposure'
]);

const API_SECURITY_DELEGATED_SETTING_CATEGORIES = new Set<APISecuritySettingCategory>([
    'identity_auth_detection'
]);

function getAPISecuritySettingsWorkbenchCategories(config: APISecurityState): Array<{ id: APISecuritySettingCategory; label: string; count: number }> {
    return API_SECURITY_SETTINGS_CATEGORIES
        .filter(category => !API_SECURITY_POLICY_OWNED_SETTING_CATEGORIES.has(category.id))
        .filter(category => !API_SECURITY_DELEGATED_SETTING_CATEGORIES.has(category.id))
        .filter(category => category.id !== 'integrations_reports' || hasAPISecurityIntegrationReportConfig(config))
        .map(category => ({
            ...category,
            count: getAPISecuritySettingsByCategory(category.id).length
        }));
}

function hasAPISecurityIntegrationReportConfig(config: APISecurityState): boolean {
    return Array.isArray(config.dashboard_views) || Array.isArray(config.alert_rules);
}

function renderAPISecuritySettingsOverview(
    categories: Array<{ id: APISecuritySettingCategory; label: string; count: number }>,
    icons: Record<string, string>
): string {
    const grouped = [
        {
            title: 'Setup',
            description: 'Traffic discovery, inventory, schemas, and identity.',
            ids: ['discovery', 'inventory_classification', 'schemas', 'identity_auth_detection'] as APISecuritySettingCategory[]
        },
        {
            title: 'Operations',
            description: 'Exceptions and reporting configuration.',
            ids: ['exceptions', 'integrations_reports'] as APISecuritySettingCategory[]
        }
    ];
    const byId = new Map(categories.map(category => [category.id, category]));
    return `
        <div class="apisecurity-settings-overview-groups">
            ${grouped.map(group => {
        const items = group.ids
            .map(id => byId.get(id))
            .filter((category): category is { id: APISecuritySettingCategory; label: string; count: number } => Boolean(category));
        if (!items.length) return '';
        return `
            <div class="apisecurity-settings-area-group">
                <div class="apisecurity-settings-group-head">
                    <strong>${escapeSectionHtml(group.title)}</strong>
                    <span>${escapeSectionHtml(group.description)}</span>
                </div>
                <div class="operator-control-list apisecurity-settings-group-list">
                    ${items.map(category => renderAPISecuritySettingsAreaCard(category, icons)).join('')}
                </div>
            </div>
        `;
    }).join('')}
        </div>
    `;
}

function renderAPISecuritySettingsAreaCard(
    category: { id: APISecuritySettingCategory; label: string; count: number },
    icons: Record<string, string>
): string {
    const meta = getAPISecuritySettingsAreaMeta(category.id, icons);
    return SectionUI.renderOperatorControlRow({
        title: escapeSectionHtml(meta.title),
        description: escapeSectionHtml(meta.description),
        icon: meta.icon,
        enabled: true,
        actions: '<span class="apisecurity-settings-area-arrow" aria-hidden="true">&rsaquo;</span>',
        className: 'apisecurity-settings-area-row apisecurity-settings-area-row-clickable',
        attrs: `role="button" tabindex="0" data-api-security-action="open-settings-category" data-api-settings-category="${escapeSectionHtml(category.id)}"`
    });
}

function getAPISecuritySettingsAreaMeta(category: APISecuritySettingCategory, icons: Record<string, string>): { title: string; description: string; icon: string } {
    const fallback = getAPISecuritySettingCategoryLabel(category);
    const map: Partial<Record<APISecuritySettingCategory, { title: string; description: string; icon: string }>> = {
        discovery: { title: 'Discovery', description: 'Choose which API traffic becomes inventory.', icon: icons.list },
        inventory_classification: { title: 'Inventory', description: 'Classify endpoints for owners and triage.', icon: icons.activity },
        schemas: { title: 'Schemas', description: 'Attach contracts and tune validation behavior.', icon: icons.fileText },
        identity_auth_detection: { title: 'Identity', description: 'Token issuers, protected paths, and claims.', icon: icons.lock },
        runtime: { title: 'Runtime Protection', description: 'Injection, SSRF, and payload controls.', icon: icons.zap },
        authorization: { title: 'Authorization', description: 'Object access, roles, and protected fields.', icon: icons.shield },
        graphql: { title: 'GraphQL', description: 'Limits and endpoint coverage for GraphQL APIs.', icon: icons.code },
        abuse: { title: 'Abuse', description: 'Credential attacks, probing, and scraping.', icon: icons.alert },
        data_exposure: { title: 'Data Exposure', description: 'Sensitive data detection and response handling.', icon: icons.database },
        exceptions: { title: 'Exceptions', description: 'Exclude paths from API Security checks.', icon: icons.shield },
        integrations_reports: { title: 'Reports', description: 'Saved dashboard views and alert rules.', icon: icons.activity }
    };
    return map[category] || { title: fallback, description: 'API Security settings backed by the existing config.', icon: icons.sliders };
}


function renderAPISecuritySettingsCategoryPage(
    category: APISecuritySettingCategory | '',
    config: APISecurityState,
    inventory: APISecurityEndpoint[],
    icons: Record<string, string>,
    schemaPrefillEndpointKey: string,
    activeWizard: APISecurityWizardId,
    wizardStep: number
): string {
    if (!category) return '';
    const normalized = normalizeAPISecuritySettingCategory(category);
    const meta = getAPISecuritySettingsAreaMeta(normalized, icons);
    const content = renderAPISecuritySettingsCategoryContent(normalized, config, inventory, icons, schemaPrefillEndpointKey, activeWizard, wizardStep);
    return `
        <section class="apisecurity-settings-page">
            <div class="operator-control-list apisecurity-settings-page-header">
                ${SectionUI.renderOperatorControlRow({
                    title: escapeSectionHtml(meta.title),
                    description: escapeSectionHtml(meta.description),
                    icon: meta.icon,
                    enabled: true,
                    actions: SectionUI.renderOperatorBackButton({
                        label: 'Back to Settings',
                        attrs: 'data-api-security-action="close-settings-category"'
                    })
                })}
            </div>
            <div class="apisecurity-settings-page-body">
                ${content}
            </div>
        </section>
    `;
}

function normalizeAPISecuritySettingCategory(value: unknown): APISecuritySettingCategory {
    const text = String(value || '').trim();
    if (API_SECURITY_POLICY_OWNED_SETTING_CATEGORIES.has(text as APISecuritySettingCategory)
        || API_SECURITY_DELEGATED_SETTING_CATEGORIES.has(text as APISecuritySettingCategory)) return 'discovery';
    return API_SECURITY_SETTINGS_CATEGORIES.some(category => category.id === text)
        ? text as APISecuritySettingCategory
        : 'discovery';
}

function renderAPISecuritySettingsCategoryContent(
    category: APISecuritySettingCategory,
    config: APISecurityState,
    inventory: APISecurityEndpoint[],
    icons: Record<string, string>,
    schemaPrefillEndpointKey: string,
    activeWizard: APISecurityWizardId,
    wizardStep: number
): string {
    if (category === 'discovery') {
        return renderAPISecurityControlSection('Discovery controls', 'Choose which traffic is discovered and how stale APIs are flagged.', icons.list, getAPISecuritySettingsGroupContent('discovery', config, inventory, icons), true);
    }
    if (category === 'inventory_classification') {
        return renderAPISecurityControlSection('Inventory classification', 'Keep classification lightweight until inventory metadata is ready.', icons.activity, renderAPISecurityRegistryRows(getAPISecuritySettingsByCategory(category), config, inventory, true), true);
    }
    if (category === 'schemas') {
        return `
            ${renderAPISecurityControlSection('Contract behavior', 'Schema enforcement settings used by contract protection.', icons.fileText, getAPISecuritySettingsGroupContent('contract', config, inventory, icons), true)}
            ${renderAPISecurityControlSection('Attach schema', 'Paste an OpenAPI or GraphQL contract for the selected endpoint.', icons.fileText, renderAPISecuritySchemaUploadForm(inventory, schemaPrefillEndpointKey))}
            ${activeWizard === 'schema' ? renderAPISecurityWizardDrawer(activeWizard, wizardStep, config, inventory, 'schema', schemaPrefillEndpointKey) : ''}
        `;
    }
    if (category === 'runtime') {
        return renderRuntimePolicyConfiguration(config, icons);
    }
    if (category === 'authorization') {
        return renderAuthorizationPolicyConfiguration(config, inventory, icons);
    }
    if (category === 'graphql') {
        return renderGraphQLPolicyConfiguration(config, inventory, icons);
    }
    if (category === 'abuse') {
        return renderAbusePolicyConfiguration(config, inventory, icons);
    }
    if (category === 'data_exposure') {
        return `
            ${renderDataExposurePolicyConfiguration(config, inventory, icons)}
            ${activeWizard === 'data' ? renderAPISecurityWizardDrawer(activeWizard, wizardStep, config, inventory, 'data', schemaPrefillEndpointKey) : ''}
        `;
    }
    if (category === 'exceptions') {
        return renderAPISecuritySettingsExceptions(config, inventory, icons);
    }
    return renderAPISecuritySettingsIntegrationsReports(config, icons);
}

function renderAPISecuritySettingsSearchResults(config: APISecurityState, inventory: APISecurityEndpoint[], search: string): string {
    const query = search.toLowerCase();
    const matches = API_SECURITY_SETTINGS_REGISTRY
        .filter(setting => !API_SECURITY_POLICY_OWNED_SETTING_CATEGORIES.has(setting.category))
        .filter(setting => !API_SECURITY_DELEGATED_SETTING_CATEGORIES.has(setting.category))
        .filter(setting => [
        setting.label,
        setting.description,
        setting.configPath,
        getAPISecuritySettingCategoryLabel(setting.category)
    ].some(value => String(value || '').toLowerCase().includes(query)));
    return `
        <div class="apisecurity-settings-search-panel">
            <div class="apisecurity-settings-group-head">
                <strong>Search results</strong>
                <span>${matches.length ? `${formatAPINumber(matches.length)} matching settings` : 'No matching settings'}</span>
            </div>
            ${matches.length
        ? renderAPISecurityRegistryRows(matches, config, inventory, false)
        : renderAPISecurityEmptySettingsState('No settings match the current search.')}
        </div>
    `;
}

function renderAPISecurityRegistryRows(
    settings: APISecuritySettingDefinition[],
    config: APISecurityState,
    inventory: APISecurityEndpoint[],
    compact: boolean
): string {
    if (!settings.length) return '';
    return `<div class="operator-control-list apisecurity-settings-list ${compact ? 'is-compact' : ''}">
        ${settings.map(setting => renderAPISecurityRegistrySettingRow(setting, config, inventory)).join('')}
    </div>`;
}

function renderAPISecurityRegistrySettingRow(
    setting: APISecuritySettingDefinition,
    config: APISecurityState,
    inventory: APISecurityEndpoint[]
): string {
    const value = getAPISecurityConfigValue(config, setting.configPath);
    const control = renderAPISecurityRegistryControl(setting, value, inventory);
    const usesBlockControl = setting.controlType === 'chip-list' || setting.controlType === 'path-list' || setting.controlType === 'endpoint-picker';
    const actions = usesBlockControl ? '' : control;
    const content = usesBlockControl ? `<div class="apisecurity-setting-block-control">${control}</div>` : '';
    return `
        <div class="operator-control-row apisecurity-setting-row">
            <div class="operator-control-main">
                <span class="operator-control-copy">
                    <span class="operator-control-title">${escapeSectionHtml(setting.label)}</span>
                    <span class="operator-control-desc">${escapeSectionHtml(setting.description)}</span>
                </span>
            </div>
            ${actions ? `<div class="operator-control-actions apisecurity-setting-actions">${actions}</div>` : ''}
            ${content}
        </div>
    `;
}

function renderAPISecurityRegistryControl(setting: APISecuritySettingDefinition, value: unknown, inventory: APISecurityEndpoint[]): string {
    if (setting.controlType === 'toggle') {
        return `<label class="section-switch"><input type="checkbox" ${value !== false ? 'checked' : ''} data-api-path="${escapeSectionHtml(setting.configPath)}" data-api-value-type="checkbox" data-api-render="true"><span class="switch-slider"></span></label>`;
    }
    if (setting.controlType === 'number') {
        return `<input class="apisecurity-setting-number" type="number" min="0" value="${escapeSectionHtml(String(value ?? setting.defaultValue ?? 0))}" data-api-path="${escapeSectionHtml(setting.configPath)}" data-api-value-type="number" data-api-render="true">`;
    }
    if (setting.controlType === 'segmented') {
        const current = String(value ?? setting.defaultValue ?? 'detect');
        return `<div class="apisecurity-inline-segmented">
            ${['detect', 'block'].map(option => `
                <button
                    class="${current === option ? 'is-active' : ''}"
                    type="button"
                    data-api-security-action="set-config-field"
                    data-api-path="${escapeSectionHtml(setting.configPath)}"
                    data-api-value="${option}"
                    data-api-value-type="string"
                >${option === 'detect' ? 'Monitor' : 'Block'}</button>
            `).join('')}
        </div>`;
    }
    if (setting.controlType === 'select') {
        const options = getAPISecuritySettingSelectOptions(setting.configPath, value, setting.defaultValue);
        return `<select class="apisecurity-inline-select" data-api-path="${escapeSectionHtml(setting.configPath)}" data-api-value-type="string" data-api-render="true">
            ${options.map(option => `<option value="${escapeSectionHtml(option)}" ${String(value ?? setting.defaultValue ?? '') === option ? 'selected' : ''}>${escapeSectionHtml(labelizeAPIInventoryValue(option))}</option>`).join('')}
        </select>`;
    }
    if (setting.controlType === 'chip-list') {
        return renderAPISecurityChipListEditor(setting.label, setting.configPath, normalizeStringList(value, normalizeStringList(setting.defaultValue, [])), {
            placeholder: 'value',
            addLabel: 'Add'
        });
    }
    if (setting.controlType === 'path-list' || setting.controlType === 'endpoint-picker') {
        return renderAPISecurityPathListEditor(setting.label, setting.configPath, normalizeStringList(value, normalizeStringList(setting.defaultValue, [])), inventory, {
            placeholder: '/api/*'
        });
    }
    if (setting.controlType === 'rule-table') {
        const count = Array.isArray(value) ? value.length : 0;
        return `<span class="config-status-pill tone-neutral">${formatAPINumber(count)} configured</span>`;
    }
    return `<span class="config-status-pill tone-neutral">${escapeSectionHtml(formatAPISecuritySettingValue(value ?? setting.defaultValue))}</span>`;
}

function renderAPISecuritySettingsExceptions(config: APISecurityState, inventory: APISecurityEndpoint[], icons: Record<string, string>): string {
    return `
        ${renderAPISecurityControlSection('Authorization exceptions', 'Paths excluded from token validation.', icons.lock, renderAPISecurityPathListEditor('Token validation exclusions', 'auth_tokens.excluded_paths', config.auth_tokens?.excluded_paths || [], inventory, {
            placeholder: '/api/public/*'
        }))}
        ${renderAPISecurityControlSection('Data exposure exceptions', 'Paths excluded from sensitive data inspection.', icons.database, renderAPISecurityPathListEditor('Data exposure exclusions', 'data_exposure.excluded_paths', getDataExposureConfig(config).excluded_paths || [], inventory, {
            placeholder: '/api/public/*'
        }))}
    `;
}

function renderAPISecuritySettingsIntegrationsReports(config: APISecurityState, icons: Record<string, string>): string {
    return renderAPISecurityControlSection('Integrations and reports', 'Saved dashboard views and alert rules stored with API Security.', icons.activity, `
            ${SectionUI.renderOperatorControlRow({
        title: 'Dashboard views',
        description: 'Saved dashboard views are preserved in the existing API Security config shape.',
        icon: SectionUI.icons.activity,
        enabled: Array.isArray(config.dashboard_views) && config.dashboard_views.length > 0
    })}
            ${SectionUI.renderOperatorControlRow({
        title: 'Alert rules',
        description: 'Stored rule definitions only. This installation does not deliver notifications from these rules.',
        icon: SectionUI.icons.alertTriangle,
        enabled: Array.isArray(config.alert_rules) && config.alert_rules.length > 0
    })}
    `, true);
}


function renderAPISecurityEmptySettingsState(message: string): string {
    return `<div class="section-empty-state compact"><div class="section-empty-title">${escapeSectionHtml(message)}</div></div>`;
}

function getAPISecuritySettingCategoryLabel(category: APISecuritySettingCategory): string {
    return API_SECURITY_SETTINGS_CATEGORIES.find(item => item.id === category)?.label || labelizeAPIInventoryValue(category);
}

function getAPISecurityConfigValue(config: APISecurityState, path: string): unknown {
    return path.split('.').reduce<unknown>((current, part) => {
        if (typeof current !== 'object' || current === null) return undefined;
        return (current as Record<string, unknown>)[part];
    }, config);
}

function getAPISecuritySettingSelectOptions(path: string, value: unknown, fallback: unknown): string[] {
    const current = String(value ?? fallback ?? '').trim();
    const base = path.endsWith('.interval') ? ['1m', '5m', '15m', '30m', '1h']
        : path.endsWith('.sensitivity') ? ['low', 'medium', 'high', 'balanced', 'strict']
            : path.endsWith('response_handling') ? ['block', 'redact']
                : path.includes('header') ? ['X-User-ID', 'X-User-Roles', 'X-Tenant-ID', 'Authorization']
                    : ['detect', 'block'];
    return current && !base.includes(current) ? [current, ...base] : base;
}

function formatAPISecuritySettingValue(value: unknown): string {
    if (Array.isArray(value)) return `${value.length} configured`;
    if (typeof value === 'boolean') return value ? 'On' : 'Off';
    if (value === undefined || value === null || value === '') return 'Not configured';
    return String(value);
}

function addChangedSettingPath(paths: string[], path: string): string[] {
    const normalized = String(path || '').trim();
    if (!normalized) return paths;
    return paths.includes(normalized) ? paths : [...paths, normalized];
}



function getInventoryTriageState(item: APISecurityEndpointPosture): string {
    return item.metadata.triage_state || (item.riskScore > 0 ? 'new' : '');
}

function renderRiskReasonChips(reasons: string[]): string {
    if (!reasons.length) return '<span class="apisecurity-scope-chip is-muted">No risk signals</span>';
    return reasons.slice(0, 4).map(reason => `<span class="apisecurity-scope-chip">${escapeSectionHtml(reason)}</span>`).join('');
}

function getTriageTone(value: string): string {
    switch (value) {
        case 'needs_schema':
        case 'in_review':
        case 'new':
            return 'warning';
        case 'deprecated':
            return 'danger';
        case 'accepted':
            return 'success';
        default:
            return 'neutral';
    }
}

function getCriticalityTone(value: string): string {
    switch (normalizeInventoryCriticality(value)) {
        case 'critical':
            return 'danger';
        case 'high':
            return 'warning';
        case 'medium':
            return 'info';
        case 'low':
            return 'neutral';
        default:
            return 'info';
    }
}

function uniqueInventoryValues(values: string[]): string[] {
    return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function labelizeAPIInventoryValue(value: string): string {
    return String(value || 'unknown')
        .replace(/[_-]+/g, ' ')
        .replace(/\b\w/g, char => char.toUpperCase());
}

function formatAPISecurityModeField(path: string): string {
    return String(path || 'mode')
        .split('.')
        .map(part => labelizeAPIInventoryValue(part))
        .join(' ');
}

function formatAPIDate(value?: string): string {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function renderAPISecurityStringListEditor(
    title: string,
    path: string,
    values: string[],
    options: APISecurityStringListEditorOptions = {}
): string {
    const normalizedPath = normalizeAPISecurityStringListPath(path);
    const items = normalizeStringList(values, []);
    const variant = options.variant || 'text';
    const rows = items.length
        ? items.map((item, index) => `
            <div class="apisecurity-structured-row">
                <input value="${escapeSectionHtml(item)}" placeholder="${escapeSectionHtml(options.placeholder || 'Value')}" data-api-string-list-path="${escapeSectionHtml(normalizedPath)}" data-api-string-list-index="${index}">
                <button class="btn btn-secondary btn-sm" type="button" data-api-security-action="remove-string-list-item" data-api-string-list-path="${escapeSectionHtml(normalizedPath)}" data-api-string-list-index="${index}">Remove</button>
            </div>
        `).join('')
        : `<div class="section-empty-state compact"><div class="section-empty-title">${escapeSectionHtml(options.emptyLabel || 'No entries configured')}</div></div>`;
    const inventoryOptions = getAPISecurityStringListInventoryOptions(options.inventory || [], options.inventoryFilter);
    const suggestions = mergeAPISecurityStringLists(options.suggestions || [], inventoryOptions);
    const picker = suggestions.length
        ? `<select data-api-string-list-picker="${escapeSectionHtml(normalizedPath)}">
                <option value="">Add from list</option>
                ${suggestions.map(value => `<option value="${escapeSectionHtml(value)}">${escapeSectionHtml(value)}</option>`).join('')}
            </select>`
        : '';
    return `
        <div class="apisecurity-structured-editor apisecurity-structured-editor-${variant}" data-api-string-list-editor="${escapeSectionHtml(normalizedPath)}">
            <div class="apisecurity-structured-editor-head">
                <span>${escapeSectionHtml(title)}</span>
                <small>${formatAPINumber(items.length)} configured</small>
            </div>
            <div class="apisecurity-structured-list">${rows}</div>
            <div class="apisecurity-structured-add">
                ${picker}
                <input value="" placeholder="${escapeSectionHtml(options.placeholder || 'Add value')}" data-api-string-list-new="${escapeSectionHtml(normalizedPath)}">
                <button class="btn btn-primary btn-sm" type="button" data-api-security-action="add-string-list-item" data-api-string-list-path="${escapeSectionHtml(normalizedPath)}">${escapeSectionHtml(options.addLabel || 'Add')}</button>
            </div>
        </div>
    `;
}

function renderAPISecurityPathListEditor(
    title: string,
    path: string,
    values: string[],
    inventory: APISecurityEndpoint[],
    options: APISecurityStringListEditorOptions = {}
): string {
    return renderAPISecurityStringListEditor(title, path, values, {
        ...options,
        placeholder: options.placeholder || '/api/example',
        addLabel: options.addLabel || 'Add path',
        emptyLabel: options.emptyLabel || 'No paths configured',
        inventory,
        variant: 'path'
    });
}

function renderAPISecurityChipListEditor(
    title: string,
    path: string,
    values: string[],
    options: APISecurityStringListEditorOptions = {}
): string {
    return renderAPISecurityStringListEditor(title, path, values, {
        ...options,
        placeholder: options.placeholder || 'value',
        addLabel: options.addLabel || 'Add value',
        emptyLabel: options.emptyLabel || 'No values configured',
        variant: 'chip'
    });
}


function getAPISecurityStringListInventoryOptions(inventory: APISecurityEndpoint[], filter?: (endpoint: APISecurityEndpoint) => boolean): string[] {
    const endpoints = filter ? inventory.filter(filter) : inventory;
    return mergeAPISecurityStringLists([], endpoints.map(endpoint => endpoint.path || '').filter(Boolean));
}

function renderRuleEndpointPreview(pattern: string, inventory: APISecurityEndpoint[], methods: string[] = []): string {
    const normalizedPattern = String(pattern || '').trim();
    if (!normalizedPattern) {
        return `<div class="apisecurity-rule-preview"><span class="text-note">Endpoint preview appears after a path pattern is entered.</span></div>`;
    }
    const allowedMethods = new Set(normalizeStringList(methods, []).map(method => method.toUpperCase()));
    const allMatches = inventory
        .filter(endpoint => allowedMethods.size === 0 || allowedMethods.has(String(endpoint.method || '').toUpperCase()))
        .filter(endpoint => apiPathMatchesPattern(String(endpoint.path || ''), normalizedPattern));
    const matches = allMatches.slice(0, 4);
    const extra = Math.max(0, allMatches.length - matches.length);
    return `
        <div class="apisecurity-rule-preview">
            <div class="apisecurity-structured-editor-head">
                <span>Endpoint preview</span>
                <small>${formatAPINumber(matches.length + extra)} match${matches.length + extra === 1 ? '' : 'es'}</small>
            </div>
            <div class="apisecurity-scope-chip-row">
                ${matches.length
        ? matches.map(endpoint => `<span class="apisecurity-scope-chip">${escapeSectionHtml([endpoint.method || 'GET', endpoint.path || '/'].join(' '))}</span>`).join('')
        : '<span class="apisecurity-scope-chip is-muted">No inventory matches</span>'}
                ${extra > 0 ? `<span class="apisecurity-scope-chip is-muted">+${formatAPINumber(extra)} more</span>` : ''}
            </div>
        </div>
    `;
}

function apiPathMatchesPattern(path: string, pattern: string): boolean {
    const normalizedPath = String(path || '/');
    const normalizedPattern = String(pattern || '').trim();
    if (!normalizedPattern) return false;
    if (normalizedPattern === normalizedPath) return true;
    const escaped = normalizedPattern
        .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
        .replace(/\\\{[^}]+\\\}/g, '[^/]+')
        .replace(/\*/g, '.*');
    return new RegExp(`^${escaped}$`).test(normalizedPath);
}

function renderBolaOwnershipRules(rules: APISecurityBolaOwnershipRule[], inventory: APISecurityEndpoint[] = []): string {
    if (rules.length === 0) {
        return `
            <div class="apisecurity-function-empty">
                <strong>No ownership rules yet</strong>
                <span>Add a rule to connect a resource identifier to the authenticated caller.</span>
                <button class="operator-btn operator-btn-primary" type="button" data-api-security-action="add-bola-rule">Add first rule</button>
            </div>
        `;
    }
    const expandedIndex = Math.min(Math.max(APISecurityConfig.expandedBolaRuleIndex, -1), rules.length - 1);
    const rows = rules.map((rule, index) => {
        const roles = rule.allowed_roles || [];
        const expanded = expandedIndex === index;
        return `
            <article class="apisecurity-function-rule ${expanded ? 'is-expanded' : ''}" data-api-rule-card="bola:${index}">
                <div class="apisecurity-function-rule-summary">
                    <button class="apisecurity-function-rule-toggle apisecurity-object-rule-toggle" type="button" aria-expanded="${expanded ? 'true' : 'false'}" data-api-security-action="toggle-bola-rule-editor" data-api-bola-rule-index="${index}">
                        <span class="apisecurity-function-rule-number">${formatAPINumber(index + 1).padStart(2, '0')}</span>
                        <span class="apisecurity-function-rule-identity">
                            <strong>${escapeSectionHtml(rule.name || 'Untitled ownership rule')}</strong>
                            <span class="apisecurity-function-rule-path">${escapeSectionHtml(rule.resource_pattern || 'Resource path not configured')}</span>
                        </span>
                        <span class="apisecurity-object-owner-key">Owner: ${escapeSectionHtml(rule.owner_id_param || 'id')}</span>
                        <span class="apisecurity-function-rule-roles">${formatAPINumber(roles.length)} bypass role${roles.length === 1 ? '' : 's'}</span>
                        <span class="config-status-pill tone-${isBolaRuleReady(rule) ? 'success' : 'warning'}">${isBolaRuleReady(rule) ? 'Ready' : 'Needs setup'}</span>
                        <span class="apisecurity-function-rule-chevron" aria-hidden="true">&rsaquo;</span>
                    </button>
                    <button class="operator-btn operator-btn-danger operator-btn-xs" type="button" data-api-security-action="remove-bola-rule" data-api-bola-rule-index="${index}">Remove</button>
                </div>
                ${expanded ? `
                    <div class="apisecurity-function-rule-editor">
                        <div class="apisecurity-function-editor-section">
                            <div class="apisecurity-function-editor-heading">
                                <strong>Protected resource</strong>
                                <span>Identify the resource path and the parameter that contains its owner ID.</span>
                            </div>
                            <div class="apisecurity-object-rule-grid">
                                <label><span>Rule name</span><input aria-label="Ownership rule ${index + 1} name" value="${escapeSectionHtml(rule.name || '')}" placeholder="Account ownership" data-api-bola-rule-index="${index}" data-api-bola-rule-field="name"></label>
                                <label><span>Resource path</span><input aria-label="Ownership rule ${index + 1} resource path" value="${escapeSectionHtml(rule.resource_pattern || '')}" placeholder="/api/accounts/{id}" data-api-bola-rule-index="${index}" data-api-bola-rule-field="resource_pattern"></label>
                                <label><span>Owner ID parameter</span><input aria-label="Ownership rule ${index + 1} owner ID parameter" value="${escapeSectionHtml(rule.owner_id_param || 'id')}" placeholder="id" data-api-bola-rule-index="${index}" data-api-bola-rule-field="owner_id_param"></label>
                            </div>
                        </div>
                        <div class="apisecurity-function-editor-section">
                            <div class="apisecurity-function-editor-heading">
                                <strong>Privileged roles</strong>
                                <span>Roles allowed to access the resource without an ownership match.</span>
                            </div>
                            ${renderAuthorizationCompactValueEditor('bola-rule', 'Bypass roles', 'allowed_roles', index, roles, {
                                placeholder: 'custom-role',
                                suggestions: ['admin', 'owner', 'support'],
                                addLabel: 'Add role',
                                emptyLabel: 'No bypass roles configured.'
                            })}
                        </div>
                        ${renderRuleEndpointPreview(rule.resource_pattern || '', inventory)}
                    </div>
                ` : ''}
            </article>
        `;
    }).join('');
    return `<div class="apisecurity-function-rule-list">${rows}</div>`;
}

function isBolaRuleReady(rule: APISecurityBolaOwnershipRule): boolean {
    return Boolean(rule.name && rule.resource_pattern && rule.owner_id_param);
}


function renderBFLARuleRows(rules: APISecurityBFLARule[], inventory: APISecurityEndpoint[] = []): string {
    if (rules.length === 0) {
        return `
            <div class="apisecurity-function-empty">
                <strong>No authorization rules yet</strong>
                <span>Add a rule to restrict an API operation by method, path, role, or claim.</span>
                <button class="operator-btn operator-btn-primary" type="button" data-api-security-action="add-bfla-rule">Add first rule</button>
            </div>
        `;
    }
    const expandedIndex = Math.min(Math.max(APISecurityConfig.expandedBFLARuleIndex, -1), rules.length - 1);
    const rows = rules.map((rule, index) => {
        const methods = rule.methods || [];
        const roles = rule.allowed_roles || [];
        const claimValues = rule.required_claim_values || [];
        const expanded = expandedIndex === index;
        return `
            <article class="apisecurity-function-rule ${expanded ? 'is-expanded' : ''}" data-api-rule-card="bfla:${index}">
                <div class="apisecurity-function-rule-summary">
                    <button
                        class="apisecurity-function-rule-toggle"
                        type="button"
                        aria-expanded="${expanded ? 'true' : 'false'}"
                        data-api-security-action="toggle-bfla-rule-editor"
                        data-api-bfla-rule-index="${index}"
                    >
                        <span class="apisecurity-function-rule-number">${formatAPINumber(index + 1).padStart(2, '0')}</span>
                        <span class="apisecurity-function-rule-identity">
                            <strong>${escapeSectionHtml(rule.name || 'Untitled rule')}</strong>
                            <span class="apisecurity-function-rule-path">${escapeSectionHtml(rule.path_pattern || 'Path not configured')}</span>
                        </span>
                        <span class="apisecurity-function-rule-methods">
                            ${methods.length
        ? methods.slice(0, 3).map(method => `<span>${escapeSectionHtml(method)}</span>`).join('')
        : '<span class="is-empty">No methods</span>'}
                            ${methods.length > 3 ? `<span>+${formatAPINumber(methods.length - 3)}</span>` : ''}
                        </span>
                        <span class="apisecurity-function-rule-roles">${formatAPINumber(roles.length)} role${roles.length === 1 ? '' : 's'}</span>
                        <span class="config-status-pill tone-${isBFLARuleReady(rule) ? 'success' : 'warning'}">${isBFLARuleReady(rule) ? 'Ready' : 'Needs setup'}</span>
                        <span class="apisecurity-function-rule-chevron" aria-hidden="true">&rsaquo;</span>
                    </button>
                    <button class="operator-btn operator-btn-danger operator-btn-xs" type="button" data-api-security-action="remove-bfla-rule" data-api-bfla-rule-index="${index}">Remove</button>
                </div>
                ${expanded ? `
                    <div class="apisecurity-function-rule-editor">
                        <div class="apisecurity-function-editor-section">
                            <div class="apisecurity-function-editor-heading">
                                <strong>Protected operation</strong>
                                <span>Name the rule and select the route it applies to.</span>
                            </div>
                            <div class="apisecurity-function-operation-grid">
                                <label>
                                    <span>Rule name</span>
                                    <input aria-label="Rule ${index + 1} name" value="${escapeSectionHtml(rule.name || '')}" placeholder="Admin user access" data-api-bfla-rule-index="${index}" data-api-bfla-rule-field="name">
                                </label>
                                <label>
                                    <span>Path pattern</span>
                                    <input aria-label="Rule ${index + 1} path pattern" value="${escapeSectionHtml(rule.path_pattern || '')}" placeholder="/api/admin/{id}" data-api-bfla-rule-index="${index}" data-api-bfla-rule-field="path_pattern">
                                </label>
                                ${renderBFLACompactValueEditor('Methods', 'methods', index, methods, {
                                    suggestions: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
                                    emptyLabel: 'Select at least one method.'
                                })}
                            </div>
                        </div>
                        <div class="apisecurity-function-editor-section">
                            <div class="apisecurity-function-editor-heading">
                                <strong>Who may call it</strong>
                                <span>Allow common roles or add a role used by your application.</span>
                            </div>
                            ${renderBFLACompactValueEditor('Allowed roles', 'allowed_roles', index, roles, {
                                placeholder: 'custom-role',
                                suggestions: ['admin', 'owner', 'support'],
                                addLabel: 'Add role',
                                emptyLabel: 'Select or add at least one role.'
                            })}
                        </div>
                        <details class="apisecurity-function-claim" ${(rule.required_claim_key || claimValues.length) ? 'open' : ''}>
                            <summary>
                                <span><strong>Additional claim requirement</strong><small>Optional</small></span>
                                <span>Require a trusted claim in addition to an allowed role.</span>
                            </summary>
                            <div class="apisecurity-function-claim-grid">
                                <label>
                                    <span>Claim key</span>
                                    <input aria-label="Rule ${index + 1} required claim key" value="${escapeSectionHtml(rule.required_claim_key || '')}" placeholder="scope" data-api-bfla-rule-index="${index}" data-api-bfla-rule-field="required_claim_key">
                                </label>
                                ${renderBFLACompactValueEditor('Accepted values', 'required_claim_values', index, claimValues, {
                                    placeholder: 'users:write',
                                    addLabel: 'Add value',
                                    emptyLabel: 'Add a value when a claim key is configured.'
                                })}
                            </div>
                        </details>
                        ${renderRuleEndpointPreview(rule.path_pattern || '', inventory, methods)}
                    </div>
                ` : ''}
            </article>
        `;
    }).join('');
    return `<div class="apisecurity-function-rule-list">${rows}</div>`;
}

function isBFLARuleReady(rule: APISecurityBFLARule): boolean {
    const hasCallerRequirement = (rule.allowed_roles || []).length > 0
        || (Boolean(rule.required_claim_key) && (rule.required_claim_values || []).length > 0);
    return Boolean(rule.name && rule.path_pattern && (rule.methods || []).length > 0 && hasCallerRequirement);
}

function renderBFLACompactValueEditor(
    title: string,
    field: string,
    parentIndex: number,
    values: string[],
    options: APISecurityStringListEditorOptions = {}
): string {
    return renderAuthorizationCompactValueEditor('bfla-rule', title, field, parentIndex, values, options);
}

function renderAuthorizationCompactValueEditor(
    kind: APISecurityNestedListKind,
    title: string,
    field: string,
    parentIndex: number,
    values: string[],
    options: APISecurityStringListEditorOptions = {}
): string {
    const items = normalizeStringList(values, []);
    const suggestions = normalizeStringList(options.suggestions || [], []);
    const suggestionKeys = new Set(suggestions.map(value => value.toLowerCase()));
    const customItems = items
        .map((item, index) => ({ item, index }))
        .filter(({ item }) => !suggestionKeys.has(item.toLowerCase()));
    const allowCustom = !(kind === 'bfla-rule' && field === 'methods');
    return `
        <div class="apisecurity-auth-value-editor" data-api-nested-list-editor="${kind}:${parentIndex}:${escapeSectionHtml(field)}">
            <div class="apisecurity-auth-value-head">
                <span>${escapeSectionHtml(title)}</span>
                <small>${formatAPINumber(items.length)} selected</small>
            </div>
            ${suggestions.length ? `
                <div class="apisecurity-auth-quick-options" role="group" aria-label="${escapeSectionHtml(title)}">
                    ${suggestions.map(value => {
        const itemIndex = items.findIndex(item => item.toLowerCase() === value.toLowerCase());
        const active = itemIndex >= 0;
        return `
                        <button
                            class="apisecurity-auth-quick-option ${active ? 'is-active' : ''}"
                            type="button"
                            aria-pressed="${active ? 'true' : 'false'}"
                            data-api-security-action="toggle-nested-list-value"
                            data-api-nested-list-kind="${kind}"
                            data-api-nested-list-parent-index="${parentIndex}"
                            data-api-nested-list-field="${escapeSectionHtml(field)}"
                            data-api-nested-list-value="${escapeSectionHtml(value)}"
                            data-api-nested-list-index="${itemIndex}"
                        >${escapeSectionHtml(value)}</button>
                    `;
    }).join('')}
                </div>
            ` : ''}
            ${customItems.length ? `
                <div class="apisecurity-auth-value-chips">
                    ${customItems.map(({ item, index }) => `
                    <span class="apisecurity-auth-value-chip">
                        ${escapeSectionHtml(item)}
                        <button type="button" aria-label="Remove ${escapeSectionHtml(item)}" data-api-security-action="remove-nested-list-item" data-api-nested-list-kind="${kind}" data-api-nested-list-parent-index="${parentIndex}" data-api-nested-list-field="${escapeSectionHtml(field)}" data-api-nested-list-index="${index}">&times;</button>
                    </span>
                    `).join('')}
                </div>
            ` : ''}
            ${items.length === 0 ? `<span class="apisecurity-auth-value-empty">${escapeSectionHtml(options.emptyLabel || 'None selected.')}</span>` : ''}
            ${allowCustom ? `
                <div class="apisecurity-auth-value-add">
                    <input aria-label="New ${escapeSectionHtml(title)} value" value="" placeholder="${escapeSectionHtml(options.placeholder || 'Add value')}" data-api-nested-list-new="${kind}:${parentIndex}:${escapeSectionHtml(field)}">
                    <button class="btn btn-primary btn-sm" type="button" data-api-security-action="add-nested-list-item" data-api-nested-list-kind="${kind}" data-api-nested-list-parent-index="${parentIndex}" data-api-nested-list-field="${escapeSectionHtml(field)}">${escapeSectionHtml(options.addLabel || 'Add')}</button>
                </div>
            ` : ''}
        </div>
    `;
}

function renderAuthorizationStringValueEditor(
    title: string,
    path: string,
    values: string[],
    options: APISecurityStringListEditorOptions = {}
): string {
    const items = normalizeStringList(values, []);
    const suggestions = normalizeStringList(options.suggestions || [], []);
    const suggestionKeys = new Set(suggestions.map(value => value.toLowerCase()));
    const customItems = items
        .map((item, index) => ({ item, index }))
        .filter(({ item }) => !suggestionKeys.has(item.toLowerCase()));
    return `
        <div class="apisecurity-auth-value-editor" data-api-string-list-editor="${escapeSectionHtml(path)}">
            <div class="apisecurity-auth-value-head">
                <span>${escapeSectionHtml(title)}</span>
                <small>${formatAPINumber(items.length)} selected</small>
            </div>
            <div class="apisecurity-auth-quick-options" role="group" aria-label="${escapeSectionHtml(title)}">
                ${suggestions.map(value => {
        const itemIndex = items.findIndex(item => item.toLowerCase() === value.toLowerCase());
        const active = itemIndex >= 0;
        return `
                    <button class="apisecurity-auth-quick-option ${active ? 'is-active' : ''}" type="button" aria-pressed="${active ? 'true' : 'false'}" data-api-security-action="toggle-string-list-value" data-api-string-list-path="${escapeSectionHtml(path)}" data-api-string-list-value="${escapeSectionHtml(value)}" data-api-string-list-index="${itemIndex}">${escapeSectionHtml(value)}</button>
                `;
    }).join('')}
            </div>
            ${customItems.length ? `
                <div class="apisecurity-auth-value-chips">
                    ${customItems.map(({ item, index }) => `
                        <span class="apisecurity-auth-value-chip">${escapeSectionHtml(item)}<button type="button" aria-label="Remove ${escapeSectionHtml(item)}" data-api-security-action="remove-string-list-item" data-api-string-list-path="${escapeSectionHtml(path)}" data-api-string-list-index="${index}">&times;</button></span>
                    `).join('')}
                </div>
            ` : ''}
            ${items.length === 0 ? `<span class="apisecurity-auth-value-empty">${escapeSectionHtml(options.emptyLabel || 'None selected.')}</span>` : ''}
            <div class="apisecurity-auth-value-add">
                <input aria-label="New ${escapeSectionHtml(title)} value" value="" placeholder="${escapeSectionHtml(options.placeholder || 'Add value')}" data-api-string-list-new="${escapeSectionHtml(path)}">
                <button class="btn btn-primary btn-sm" type="button" data-api-security-action="add-string-list-item" data-api-string-list-path="${escapeSectionHtml(path)}">${escapeSectionHtml(options.addLabel || 'Add')}</button>
            </div>
        </div>
    `;
}


function renderMassAssignmentPathRuleRows(rules: APISecurityMassAssignmentPathRule[], inventory: APISecurityEndpoint[] = []): string {
    if (rules.length === 0) {
        return `
            <div class="apisecurity-function-empty">
                <strong>No path-specific rules</strong>
                <span>The default protected fields apply globally. Add a path rule when an endpoint needs a narrower field set.</span>
                <button class="operator-btn operator-btn-primary" type="button" data-api-security-action="add-mass-rule">Add first path rule</button>
            </div>
        `;
    }
    const expandedIndex = Math.min(Math.max(APISecurityConfig.expandedMassRuleIndex, -1), rules.length - 1);
    const rows = rules.map((rule, index) => {
        const fields = rule.fields || [];
        const expanded = expandedIndex === index;
        return `
            <article class="apisecurity-function-rule ${expanded ? 'is-expanded' : ''}" data-api-rule-card="mass:${index}">
                <div class="apisecurity-function-rule-summary">
                    <button class="apisecurity-function-rule-toggle apisecurity-mass-rule-toggle" type="button" aria-expanded="${expanded ? 'true' : 'false'}" data-api-security-action="toggle-mass-rule-editor" data-api-mass-rule-index="${index}">
                        <span class="apisecurity-function-rule-number">${formatAPINumber(index + 1).padStart(2, '0')}</span>
                        <span class="apisecurity-function-rule-identity">
                            <strong>${escapeSectionHtml(rule.path_pattern || 'Path not configured')}</strong>
                            <span class="apisecurity-function-rule-path">Path-specific protected fields</span>
                        </span>
                        <span class="apisecurity-mass-field-summary">${formatAPINumber(fields.length)} field${fields.length === 1 ? '' : 's'}</span>
                        <span class="config-status-pill tone-${isMassAssignmentRuleReady(rule) ? 'success' : 'warning'}">${isMassAssignmentRuleReady(rule) ? 'Ready' : 'Needs setup'}</span>
                        <span class="apisecurity-function-rule-chevron" aria-hidden="true">&rsaquo;</span>
                    </button>
                    <button class="operator-btn operator-btn-danger operator-btn-xs" type="button" data-api-security-action="remove-mass-rule" data-api-mass-rule-index="${index}">Remove</button>
                </div>
                ${expanded ? `
                    <div class="apisecurity-function-rule-editor">
                        <div class="apisecurity-function-editor-section">
                            <div class="apisecurity-function-editor-heading">
                                <strong>Endpoint scope</strong>
                                <span>Choose the write endpoint that needs its own protected-field set.</span>
                            </div>
                            <div class="apisecurity-mass-path-field">
                                <label><span>Path pattern</span><input aria-label="Protected field rule ${index + 1} path pattern" value="${escapeSectionHtml(rule.path_pattern || '')}" placeholder="/api/accounts/{id}" data-api-mass-rule-index="${index}" data-api-mass-rule-field="path_pattern"></label>
                            </div>
                        </div>
                        <div class="apisecurity-function-editor-section">
                            <div class="apisecurity-function-editor-heading">
                                <strong>Fields protected on this path</strong>
                                <span>This list replaces the defaults for requests matching the path.</span>
                            </div>
                            ${renderAuthorizationCompactValueEditor('mass-rule', 'Protected fields', 'fields', index, fields, {
                                placeholder: 'server_owned_field',
                                suggestions: ['role', 'is_admin', 'permissions', 'plan', 'balance', 'credit_limit'],
                                addLabel: 'Add field',
                                emptyLabel: 'Select or add at least one field.'
                            })}
                        </div>
                        ${renderRuleEndpointPreview(rule.path_pattern || '', inventory)}
                    </div>
                ` : ''}
            </article>
        `;
    }).join('');
    return `<div class="apisecurity-function-rule-list">${rows}</div>`;
}

function isMassAssignmentRuleReady(rule: APISecurityMassAssignmentPathRule): boolean {
    return Boolean(rule.path_pattern && (rule.fields || []).length > 0);
}

function isAPISecurityPolicyId(value: unknown): value is APISecurityPolicyId {
    return ['runtime', 'contract', 'authorization', 'graphql', 'abuse', 'data'].includes(String(value || ''));
}

function isAPISecuritySurfaceId(value: unknown): value is APISecuritySurfaceId {
    return isAPISecurityTabId(value) || isAPISecurityPolicyId(value);
}

function normalizeAPISecuritySurfaceId(value: unknown, fallback: APISecuritySurfaceId): APISecuritySurfaceId {
    return isAPISecuritySurfaceId(value) ? value : fallback;
}

function getAPISecurityPolicyIdForWizard(wizard: APISecurityWizardId, fallback: APISecurityPolicyId | ''): APISecurityPolicyId {
    if (wizard === 'schema') return 'contract';
    if (wizard === 'identity') return 'authorization';
    if (wizard === 'data') return 'data';
    return fallback || 'runtime';
}

function getAPISecuritySurfaceIdForScopePath(path: string): APISecuritySurfaceId {
    if (path === 'discovery.paths') return 'inventory';
    if (path.startsWith('graphql.')) return 'graphql';
    if (path.startsWith('auth_tokens.') || path.startsWith('bola.')) return 'authorization';
    if (path.startsWith('automation_abuse.')) return 'abuse';
    if (path.startsWith('data_exposure.')) return 'data';
    return 'inventory';
}


function getAPISecurityPolicyCatalogEntry(id: APISecurityPolicyId): APISecurityPolicyCatalogEntry | null {
    return API_SECURITY_POLICY_CATALOG.find(policy => policy.id === id) || null;
}

function getAPISecurityPolicyState(config: APISecurityState, id: APISecurityPolicyId): {
    enabled: boolean;
    mode: string;
    profile?: APISecurityProfileValue;
    status: string;
    detail: string;
} {
    if (id === 'runtime') {
        const injection = getInjectionConfig(config);
        const ssrf = getSSRFConfig(config);
        const payload = getPayloadAbuseConfig(config);
        const modes = [injection.mode || 'block', ssrf.mode || 'detect', payload.mode || 'detect'].map(normalizeAPISecurityMode);
        const enabledCount = [injection.enabled, ssrf.enabled, payload.enabled].filter(value => value !== false).length;
        return {
            enabled: enabledCount > 0,
            mode: modes.includes('block') ? 'block' : 'detect',
            profile: deriveAPISecurityProfile(config, 'runtime'),
            status: enabledCount > 0 ? `${enabledCount}/3 active` : 'Off',
            detail: modes.includes('block') ? 'Blocking enabled' : 'Detect mode'
        };
    }
    if (id === 'contract') {
        const validation = getValidationConfig(config);
        const mode = normalizeAPISecurityMode(validation.mode || 'block');
        return {
            enabled: validation.enabled !== false,
            mode,
            profile: deriveAPISecurityProfile(config, 'contract'),
            status: validation.enabled !== false ? labelizeAPIInventoryValue(mode) : 'Off',
            detail: validation.block_unknown_endpoints ? 'Unknown APIs enforced' : 'Schema-backed APIs'
        };
    }
    if (id === 'authorization') {
        const bfla = config.bfla || {};
        const massAssignment = config.mass_assignment || {};
        const bola = config.bola || {};
        const enabledCount = [bfla.enabled, massAssignment.enabled, bola.enabled].filter(value => value !== false).length;
        const modes = [bfla.mode || 'detect', massAssignment.mode || 'detect', bola.mode || 'detect'].map(value => normalizeAPISecurityMode(String(value)));
        return {
            enabled: enabledCount > 0,
            mode: modes.includes('block') ? 'block' : 'detect',
            profile: deriveAPISecurityProfile(config, 'authorization'),
            status: enabledCount > 0 ? `${enabledCount}/3 active` : 'Off',
            detail: modes.includes('block') ? 'Blocking enabled' : 'Detect mode'
        };
    }
    if (id === 'graphql') {
        const graphql = getGraphQLConfig(config);
        const mode = normalizeAPISecurityMode(graphql.mode || 'detect');
        return {
            enabled: graphql.enabled !== false,
            mode,
            profile: deriveAPISecurityProfile(config, 'graphql'),
            status: graphql.enabled !== false ? labelizeAPIInventoryValue(mode) : 'Off',
            detail: graphql.block_introspection !== false ? 'Introspection protected' : 'Introspection allowed'
        };
    }
    if (id === 'abuse') {
        const automation = getAutomationAbuseConfig(config);
        const mode = normalizeAPISecurityMode(automation.mode || 'detect');
        return {
            enabled: automation.enabled !== false,
            mode,
            profile: deriveAPISecurityProfile(config, 'automation'),
            status: automation.enabled !== false ? labelizeAPIInventoryValue(mode) : 'Off',
            detail: `${labelizeAPIInventoryValue(normalizeAutomationSensitivity(automation.sensitivity))} sensitivity`
        };
    }
    const dataExposure = getDataExposureConfig(config);
    const mode = normalizeAPISecurityMode(dataExposure.mode || 'detect');
    const responseHandling = normalizeDataExposureResponseHandling(dataExposure.response_handling);
    return {
        enabled: dataExposure.enabled !== false,
        mode,
        profile: deriveAPISecurityProfile(config, 'data'),
        status: dataExposure.enabled !== false ? labelizeAPIInventoryValue(mode) : 'Off',
        detail: mode === 'block' ? `Responses ${labelizeAPIInventoryValue(responseHandling)}` : 'Detect mode'
    };
}

function formatAPISecurityProfileLabel(profile: APISecurityProfileValue): string {
    if (profile === 'default') return 'Standard';
    if (profile === 'strict') return 'Strict';
    if (profile === 'monitor') return 'Monitor only';
    return 'Custom';
}

function getAPISecurityPolicyCardDescription(id: APISecurityPolicyId): string {
    switch (id) {
        case 'runtime': return 'Stops injection, SSRF, and abusive payloads.';
        case 'contract': return 'Enforces schemas and API contract behavior.';
        case 'authorization': return 'Protects API operations, objects, tenants, and request fields using trusted Edge Access identity.';
        case 'graphql': return 'Protects GraphQL endpoints from unsafe query patterns.';
        case 'abuse': return 'Detects automation, probing, enumeration, and scraping.';
        case 'data': return 'Detects sensitive data and response exposure.';
        default: return 'API Security policy.';
    }
}

function getAPISecurityPolicyDisplayTitle(id: APISecurityPolicyId): string {
    switch (id) {
        case 'runtime': return 'Runtime Protection';
        case 'abuse': return 'Abuse Protection';
        case 'data': return 'Data Exposure Protection';
        default: return getAPISecurityPolicyCatalogEntry(id)?.title || 'API Security policy';
    }
}



function renderAPISecurityPolicyEnabledToggle(id: APISecurityPolicyId, enabled: boolean): string {
    return `
        <label class="section-switch" aria-label="${escapeSectionHtml(getAPISecurityPolicyDisplayTitle(id))} enabled">
            <input type="checkbox" ${enabled ? 'checked' : ''} data-api-policy-enabled="${id}">
            <span class="switch-slider"></span>
        </label>
    `;
}

function buildAPISecurityPolicyViewModel(
    policy: APISecurityPolicyCatalogEntry,
    config: APISecurityState,
    dashboard: APISecurityDashboardPayload,
    inventory: APISecurityEndpoint[]
): APISecurityPolicyViewModel {
    const state = getAPISecurityPolicyState(config, policy.id);
    const surface = getAPISecurityPolicySurfaceSummary(policy.id, config, dashboard, inventory);
    return {
        policy,
        enabled: state.enabled,
        mode: state.mode,
        profile: state.profile || (policy.profileKey ? deriveAPISecurityProfile(config, policy.profileKey) : 'custom'),
        surfaceSummary: surface.summary,
        surfaceDetail: surface.detail
    };
}

function renderAPISecurityPolicyEditor(
    policy: APISecurityPolicyCatalogEntry,
    activeTab: APISecurityPolicyEditorTab,
    config: APISecurityState,
    inventory: APISecurityEndpoint[],
    icons: Record<string, string>,
    setupFocus: string,
    schemaPrefillEndpointKey: string,
    activeWizard: APISecurityWizardId,
    wizardStep: number
): string {
    void activeTab;
    const ownsSettings = doesAPISecurityPolicyOwnSettings(policy.id);
    const scopeContent = policy.id === 'runtime' || (ownsSettings && policy.id !== 'contract')
        ? ''
        : renderAPISecurityPolicyScopeContent(policy, config, inventory, icons);
    const setupPanel = renderAPISecurityPolicySetupPanel(policy.id, config, inventory, setupFocus, schemaPrefillEndpointKey, activeWizard, wizardStep);
    const exceptionContent = ownsSettings ? '' : renderAPISecurityPolicyExceptions(policy.id, config, inventory, icons);
    const configurationContent = ownsSettings
        ? renderAPISecurityPolicyPrimaryConfiguration(policy.id, config, inventory, icons)
        : SectionUI.renderOperatorSection('Configuration', getAPISecuritySettingsGroupContent(policy.settingsGroup, config, inventory, icons), {
            subtitle: 'Backed by existing API Security settings.'
        });
    const editorContent = policy.id === 'contract'
        ? (activeWizard === 'schema'
            ? `${setupPanel}${configurationContent}${exceptionContent}`
            : `${configurationContent}${scopeContent}${setupPanel}${exceptionContent}`)
        : `${scopeContent}${setupPanel}${configurationContent}${exceptionContent}`;
    return `
        <div class="apisecurity-policy-editor-panel apisecurity-policy-single-page">
            ${editorContent}
        </div>
    `;
}

function doesAPISecurityPolicyOwnSettings(policyId: APISecurityPolicyId): boolean {
    return policyId === 'runtime'
        || policyId === 'contract'
        || policyId === 'authorization'
        || policyId === 'graphql'
        || policyId === 'abuse'
        || policyId === 'data';
}

function renderAPISecurityPolicyDetailHeader(
    _policy: APISecurityPolicyCatalogEntry,
    _config: APISecurityState,
    _dashboard: APISecurityDashboardPayload,
    _inventory: APISecurityEndpoint[],
    _icons: Record<string, string>
): string {
    return '';
}

function renderAPISecurityPolicyScopeContent(
    policy: APISecurityPolicyCatalogEntry,
    config: APISecurityState,
    inventory: APISecurityEndpoint[],
    icons: Record<string, string>
): string {
    if (policy.id === 'contract') {
        return renderAPISecurityControlSection(
            'Schema attachment',
            'Attach OpenAPI or GraphQL contracts using the existing schema upload endpoint.',
            icons.fileText,
            renderAPISecuritySchemaUploadForm(inventory, '')
        );
    }
    if (policy.id === 'authorization') {
        const authTokens = config.auth_tokens || {};
        const bola = config.bola || {};
        return `
            ${SectionUI.renderOperatorSection('Authorization surface', `
                ${renderAPISecurityPathListEditor('Protected API paths', 'auth_tokens.protected_paths', authTokens.protected_paths || [], inventory, {
                    placeholder: '/api/private/*'
                })}
                ${renderAPISecurityPathListEditor('Excluded API paths', 'auth_tokens.excluded_paths', authTokens.excluded_paths || [], inventory, {
                    placeholder: '/api/public/*'
                })}
                ${renderAPISecurityPathListEditor('Isolated object paths', 'bola.isolated_paths', bola.isolated_paths || [], inventory, {
                    placeholder: '/api/tenants/{tenant_id}'
                })}
            `, {
                subtitle: 'Select the API surfaces that require token, function, field, or object access checks.'
            })}
        `;
    }
    if (policy.id === 'graphql') {
        const graphql = getGraphQLConfig(config);
        return SectionUI.renderOperatorSection('GraphQL surface', renderAPISecurityPathListEditor('GraphQL paths', 'graphql.paths', graphql.paths || defaultGraphQLPaths(), inventory, {
            placeholder: '/graphql',
            inventoryFilter: endpoint => String(endpoint.path || '').toLowerCase().includes('graphql')
        }), {
            subtitle: 'Endpoint paths inspected by GraphQL protection.'
        });
    }
    if (policy.id === 'abuse') {
        const automation = getAutomationAbuseConfig(config);
        return SectionUI.renderOperatorSection('Abuse surfaces', `
            ${renderAPISecurityPathListEditor('Login paths', 'automation_abuse.login_paths', automation.login_paths || defaultAutomationLoginPaths(), inventory, { placeholder: '/api/login' })}
            ${renderAPISecurityPathListEditor('OTP paths', 'automation_abuse.otp_paths', automation.otp_paths || defaultAutomationOTPPaths(), inventory, { placeholder: '/api/mfa/verify' })}
            ${renderAPISecurityPathListEditor('Monitored paths', 'automation_abuse.monitored_paths', automation.monitored_paths || defaultAutomationMonitoredPaths(), inventory, { placeholder: '/api/*' })}
        `, {
            subtitle: 'Surfaces used by abuse and automation counters.'
        });
    }
    if (policy.id === 'data') {
        const dataExposure = getDataExposureConfig(config);
        return SectionUI.renderOperatorSection('Data exposure scope', renderAPISecurityPathListEditor('Excluded paths', 'data_exposure.excluded_paths', dataExposure.excluded_paths || [], inventory, {
            placeholder: '/api/public/*'
        }), {
            subtitle: 'APIs excluded from request and response data exposure inspection.'
        });
    }
    return SectionUI.renderOperatorSection('Runtime surface', `<div class="section-empty-state compact"><div class="section-empty-title">All discovered APIs</div></div>`, {
        subtitle: 'Runtime protection applies across the discovered API estate.'
    });
}

function renderAPISecurityPolicyExceptions(
    policyId: APISecurityPolicyId,
    config: APISecurityState,
    inventory: APISecurityEndpoint[],
    icons: Record<string, string>
): string {
    void icons;
    if (policyId === 'authorization') {
        const authTokens = config.auth_tokens || {};
        return SectionUI.renderOperatorSection('Authorization exceptions', renderAPISecurityPathListEditor('Token validation exclusions', 'auth_tokens.excluded_paths', authTokens.excluded_paths || [], inventory, {
            placeholder: '/api/public/*'
        }), {
            subtitle: 'Existing token validation exclusions.'
        });
    }
    if (policyId === 'data') {
        const dataExposure = getDataExposureConfig(config);
        return SectionUI.renderOperatorSection('Data exposure exceptions', renderAPISecurityPathListEditor('Excluded paths', 'data_exposure.excluded_paths', dataExposure.excluded_paths || [], inventory, {
            placeholder: '/api/public/*'
        }), {
            subtitle: 'Existing data exposure exclusions.'
        });
    }
    return '';
}


function renderAPISecurityPolicyModeConfirm(target: APISecurityPolicyModeConfirmTarget | null, config: APISecurityState): string {
    if (!target) return '';
    const policy = getAPISecurityPolicyCatalogEntry(target.policyId);
    if (!policy) return '';
    const paths = getAPISecurityPolicyModePaths(target.policyId);
    const pendingProfile = target.profileValue ? `${formatAPISecurityProfileLabel(target.profileValue)} profile` : 'Block mode';
    const currentMode = getAPISecurityPolicyModeSummary(config, target.policyId);
    return `
        <div class="section-modal-overlay section-modal-overlay-padded is-open is-visible" role="presentation">
            <div class="section-modal-panel section-confirm-modal apisecurity-block-confirm-modal" role="dialog" aria-modal="true" aria-label="Confirm block mode">
                <div class="section-modal-head">
                    <div><h2 class="section-modal-title">Confirm Block mode</h2><p class="section-modal-sub">${escapeSectionHtml(getAPISecurityPolicyDisplayTitle(policy.id))}</p></div>
                    <button class="section-confirm-close" type="button" aria-label="Close" data-api-security-action="cancel-policy-mode">${SectionUI.icons.x || '&times;'}</button>
                </div>
                <div class="section-modal-body"><p>Switching to ${escapeSectionHtml(pendingProfile)} updates ${paths.length} existing mode setting${paths.length === 1 ? '' : 's'} from ${escapeSectionHtml(currentMode)} to Block. Save is still required.</p></div>
                <div class="section-modal-footer">
                    <button class="btn btn-secondary btn-sm" type="button" data-api-security-action="cancel-policy-mode">Cancel</button>
                    <button class="btn btn-primary btn-sm" type="button" data-api-security-action="confirm-policy-mode">Confirm Block</button>
                </div>
            </div>
        </div>
    `;
}

function renderAPISecurityModeFieldConfirm(target: APISecurityBlockingReviewTarget | null, _dashboard: APISecurityDashboardPayload): string {
    if (!target) return '';
    const modeField = formatAPISecurityModeField(target.modePath);
    return `
        <div class="section-modal-overlay section-modal-overlay-padded is-open is-visible" role="presentation">
            <div class="section-modal-panel section-confirm-modal apisecurity-block-confirm-modal" role="dialog" aria-modal="true" aria-label="Confirm block mode">
                <div class="section-modal-head">
                    <div><h2 class="section-modal-title">Confirm Block mode</h2><p class="section-modal-sub">${escapeSectionHtml(target.title)}</p></div>
                    <button class="section-confirm-close" type="button" aria-label="Close" data-api-security-action="close-block-review">${SectionUI.icons.x || '&times;'}</button>
                </div>
                <div class="section-modal-body"><p>Switching ${escapeSectionHtml(modeField)} to Block applies enforcement to matching requests. Save is still required.</p></div>
                <div class="section-modal-footer">
                    <button class="btn btn-secondary btn-sm" type="button" data-api-security-action="close-block-review">Cancel</button>
                    <button class="btn btn-primary btn-sm" type="button" data-api-security-action="confirm-block-mode">Confirm Block</button>
                </div>
            </div>
        </div>
    `;
}

function getAPISecurityPolicySurfaceSummary(
    id: APISecurityPolicyId,
    config: APISecurityState,
    dashboard: APISecurityDashboardPayload,
    inventory: APISecurityEndpoint[]
): { summary: string; detail: string } {
    if (id === 'runtime') {
        const paths = normalizeStringList(config.discovery?.paths, ['/api/*', '/v1/*', '/v2/*', '/graphql']);
        return {
            summary: 'All discovered APIs',
            detail: formatAPISecurityPathSummary(paths, 'Discovery paths are not configured')
        };
    }
    if (id === 'contract') {
        const coverage = getOverviewCoverage(dashboard, inventory);
        if (coverage.endpoints_with_schema > 0) {
            return {
                summary: `${formatAPINumber(coverage.endpoints_with_schema)} schema-backed APIs`,
                detail: `${formatPercent(coverage.schema_coverage)} schema coverage`
            };
        }
        return {
            summary: 'Not configured',
            detail: 'Attach schemas to enable contract coverage'
        };
    }
    if (id === 'authorization') {
        const ruleCount = normalizeBFLARules(config.bfla?.rules).length
            + normalizeBolaOwnershipRules(config.bola?.ownership_rules).length
            + normalizeMassAssignmentPathRules(config.mass_assignment?.path_rules).length;
        return ruleCount > 0
            ? { summary: `${formatAPINumber(ruleCount)} API authorization ${ruleCount === 1 ? 'rule' : 'rules'}`, detail: 'Uses trusted identity from Edge Access' }
            : { summary: 'Edge Access identity', detail: 'Add function, object, tenant, or protected-field rules' };
    }
    if (id === 'graphql') {
        const paths = normalizeStringList(getGraphQLConfig(config).paths, defaultGraphQLPaths());
        return paths.length
            ? { summary: `${formatAPINumber(paths.length)} GraphQL paths`, detail: formatAPISecurityPathSummary(paths, 'GraphQL APIs') }
            : { summary: 'Not configured', detail: 'Choose GraphQL API paths' };
    }
    if (id === 'abuse') {
        const paths = normalizeStringList(getAutomationAbuseConfig(config).monitored_paths, defaultAutomationMonitoredPaths());
        const allApis = paths.includes('*');
        return {
            summary: allApis ? 'All APIs' : `${formatAPINumber(paths.length)} monitored paths`,
            detail: formatAPISecurityPathSummary(paths, 'Monitored API paths')
        };
    }
    const excluded = normalizeStringList(getDataExposureConfig(config).excluded_paths, []);
    return excluded.length
        ? { summary: `All APIs except ${formatAPINumber(excluded.length)} exclusions`, detail: formatAPISecurityPathSummary(excluded, 'Excluded API paths') }
        : { summary: 'All APIs', detail: 'No exclusions configured' };
}

function formatAPISecurityPathSummary(paths: string[], fallback: string): string {
    const cleaned = paths.map(path => String(path || '').trim()).filter(Boolean);
    if (!cleaned.length) return fallback;
    if (cleaned.includes('*')) return 'All API paths';
    const visible = cleaned.slice(0, 3).join(', ');
    const remaining = cleaned.length - 3;
    return remaining > 0 ? `${visible} +${remaining} more` : visible;
}

function getAPISecurityPolicyFunctionKeys(id: APISecurityPolicyId): string[] {
    return getAPISecurityPolicyCatalogEntry(id)?.functions || [];
}

function isAPISecurityFunctionConfigKey(key: string): boolean {
    return key === 'discovery' || API_SECURITY_POLICY_CATALOG.some(policy => policy.functions.includes(key));
}

function getAPISecurityPolicyModePaths(id: APISecurityPolicyId): string[] {
    return getAPISecurityPolicyFunctionKeys(id).map(key => `${key}.mode`);
}

function getAPISecurityPolicyIdForFunctionKey(functionKey: string): APISecurityPolicyId | null {
    return API_SECURITY_POLICY_CATALOG.find(policy => policy.functions.includes(functionKey))?.id || null;
}

function getAPISecurityPolicyFunctionMode(config: APISecurityState, functionKey: string): string {
    const settings = config.function_settings?.[functionKey] || {};
    const moduleConfig = (config as Record<string, unknown>)[functionKey];
    const moduleMode = typeof moduleConfig === 'object' && moduleConfig !== null
        ? (moduleConfig as APISecurityModuleConfig).mode
        : undefined;
    return normalizeAPISecurityMode(settings.mode || moduleMode || 'detect');
}

function buildAPISecurityModeFieldConfirmTarget(
    config: APISecurityState,
    path: string,
    value: unknown,
    currentTab: APISecurityTabId,
    selectedPolicyId: APISecurityPolicyId | ''
): APISecurityBlockingReviewTarget | null {
    if (normalizeAPISecurityMode(value) !== 'block') return null;
    const parts = String(path || '').split('.').filter(Boolean);
    if (parts.length !== 2 || parts[1] !== 'mode') return null;

    const functionKey = parts[0];
    if (!isAPISecurityFunctionConfigKey(functionKey)) return null;
    if (getAPISecurityPolicyFunctionMode(config, functionKey) === 'block') return null;

    const policyId = getAPISecurityPolicyIdForFunctionKey(functionKey);
    const targetTab = isAPISecurityPolicyId(currentTab) && selectedPolicyId ? selectedPolicyId : currentTab;
    return {
        moduleKey: policyId || functionKey,
        functionKey,
        title: `${formatAPISecurityModeField(path)} block review`,
        modePath: path,
        tab: targetTab
    };
}

function getAPISecurityPolicyModeSummary(config: APISecurityState, id: APISecurityPolicyId): string {
    const modes = getAPISecurityPolicyFunctionKeys(id).map(key => getAPISecurityPolicyFunctionMode(config, key));
    if (modes.length && modes.every(mode => mode === 'block')) return 'Block';
    if (modes.length && modes.every(mode => mode === 'detect')) return 'Monitor';
    return 'Mixed';
}

function syncAPISecurityMirroredConfigValue(config: APISecurityState, path: string, value: unknown): void {
    const [root, ...rest] = String(path || '').split('.').filter(Boolean);
    if (!root || rest.length === 0 || !isAPISecurityFunctionConfigKey(root)) return;
    if (rest.length === 1 && rest[0] === 'enabled') {
        setAPISecurityConfigValue(config, `enabled_functions.${root}`, Boolean(value));
        return;
    }
    setAPISecurityConfigValue(config, `function_settings.${root}.${rest.join('.')}`, cloneConfigValue(value));
}

function setAPISecurityConfigValue(config: APISecurityState, path: string, value: unknown): void {
    const parts = path.split('.').filter(Boolean);
    if (!parts.length) return;
    let obj: Record<string, unknown> = config as Record<string, unknown>;
    for (let index = 0; index < parts.length - 1; index++) {
        const key = parts[index];
        const current = obj[key];
        if (typeof current !== 'object' || current === null || Array.isArray(current)) {
            obj[key] = {};
        }
        obj = obj[key] as Record<string, unknown>;
    }
    obj[parts[parts.length - 1]] = value;
}

function getAPISecurityNestedStringList(config: APISecurityState, kind: APISecurityNestedListKind, parentIndex: number, field: string): string[] {
    if (kind === 'bola-rule' && field === 'allowed_roles') {
        return normalizeStringList(normalizeBolaOwnershipRules(config.bola?.ownership_rules)[parentIndex]?.allowed_roles, []);
    }
    if (kind === 'auth-issuer' && (field === 'audiences' || field === 'allowed_algorithms')) {
        return normalizeStringList(normalizeAuthTokenIssuers(config.auth_tokens?.issuers)[parentIndex]?.[field], field === 'allowed_algorithms' ? ['RS256'] : []);
    }
    if (kind === 'bfla-rule' && (field === 'methods' || field === 'allowed_roles' || field === 'required_claim_values')) {
        return normalizeStringList(normalizeBFLARules(config.bfla?.rules)[parentIndex]?.[field], []);
    }
    if (kind === 'mass-rule' && field === 'fields') {
        return normalizeStringList(normalizeMassAssignmentPathRules(config.mass_assignment?.path_rules)[parentIndex]?.fields, []);
    }
    return [];
}

function applyAPISecurityNestedStringList(
    runtime: APISecurityConfigRuntime,
    kind: APISecurityNestedListKind,
    parentIndex: number,
    field: string,
    values: string[]
): void {
    const list = normalizeStringList(values, []);
    if (kind === 'bola-rule' && field === 'allowed_roles') {
        runtime.updateBolaRule(parentIndex, field, list);
    } else if (kind === 'auth-issuer' && (field === 'audiences' || field === 'allowed_algorithms')) {
        runtime.updateAuthIssuer(parentIndex, field, list.length ? list : (field === 'allowed_algorithms' ? ['RS256'] : []));
    } else if (kind === 'bfla-rule' && (field === 'methods' || field === 'allowed_roles' || field === 'required_claim_values')) {
        runtime.updateBFLARule(parentIndex, field, field === 'methods' ? list.map(method => method.toUpperCase()) : list);
    } else if (kind === 'mass-rule' && field === 'fields') {
        runtime.updateMassAssignmentPathRule(parentIndex, field, list);
    }
}

function applyAPISecurityPolicyEnabled(config: APISecurityState, id: APISecurityPolicyId, enabled: boolean): APISecurityState {
    const next = normalizeAPISecurityConfig(config);
    getAPISecurityPolicyFunctionKeys(id).forEach(key => {
        setAPISecurityConfigValue(next, `${key}.enabled`, enabled);
        setAPISecurityConfigValue(next, `enabled_functions.${key}`, enabled);
    });
    return normalizeAPISecurityConfig(next);
}

function applyAPISecurityPolicyMode(config: APISecurityState, id: APISecurityPolicyId, mode: 'detect' | 'block'): APISecurityState {
    const next = normalizeAPISecurityConfig(config);
    getAPISecurityPolicyFunctionKeys(id).forEach(key => {
        setAPISecurityConfigValue(next, `${key}.mode`, mode);
        setAPISecurityConfigValue(next, `function_settings.${key}.mode`, mode);
    });
    return normalizeAPISecurityConfig(next);
}

function getAPISecurityPolicyIdForProfileKey(key: APISecurityProfileKey): APISecurityPolicyId | null {
    const policy = API_SECURITY_POLICY_CATALOG.find(entry => entry.profileKey === key);
    return policy?.id || null;
}

function shouldConfirmAPISecurityProfileBlock(
    config: APISecurityState,
    policyId: APISecurityPolicyId,
    profileKey: APISecurityProfileKey,
    profileValue: APISecurityProfileValue
): boolean {
    if (profileValue !== 'strict') return false;
    const current = getAPISecurityPolicyState(config, policyId).mode;
    if (current === 'block') return false;
    const preview = applyAPISecurityProfile(config, profileKey, profileValue);
    return getAPISecurityPolicyState(preview, policyId).mode === 'block';
}

function renderAPISecurityPolicySetupPanel(
    policyId: APISecurityPolicyId,
    config: APISecurityState,
    inventory: APISecurityEndpoint[],
    setupFocus: string,
    schemaPrefillEndpointKey: string,
    activeWizard: APISecurityWizardId,
    wizardStep: number
): string {
    if (!activeWizard) return '';
    const targetPolicy = getAPISecurityPolicyIdForWizard(activeWizard, policyId);
    if (targetPolicy !== policyId) return '';
    return renderAPISecurityWizardDrawer(
        activeWizard,
        wizardStep,
        config,
        inventory,
        setupFocus,
        schemaPrefillEndpointKey
    );
}

function getAPISecuritySettingsGroupContent(
    group: APISecurityPolicyCatalogEntry['settingsGroup'],
    config: APISecurityState,
    inventory: APISecurityEndpoint[],
    icons: Record<string, string>
): string {
    switch (group) {
        case 'runtime': return renderRuntimeDetectionControls(config, icons);
        case 'contract': return renderContractDetectionControls();
        case 'authorization': return renderAuthorizationDetectionControls(config, icons);
        case 'graphql': return renderGraphQLDetectionControls();
        case 'abuse': return renderAbuseDetectionControls(config, icons);
        case 'data': return renderDataExposureDetectionControls(config, icons);
        case 'discovery': return renderDiscoverySettingsControls(config, icons, inventory);
        default: return '';
    }
}

function getAPISecurityPolicyRows(id: APISecurityPolicyId, config: APISecurityState, icons: Record<string, string>): APISecurityPolicyRow[] {
    if (id === 'runtime') {
        const injection = getInjectionConfig(config);
        const ssrf = getSSRFConfig(config);
        const payload = getPayloadAbuseConfig(config);
        return [
            { title: 'Injection Protection', description: 'Runtime attack payloads.', icon: icons.zap, enabled: injection.enabled !== false, enabledPath: 'injection.enabled', mode: injection.mode || 'block', modePath: 'injection.mode' },
            { title: 'SSRF Protection', description: 'Unsafe URL and IP targets.', icon: icons.shield, enabled: ssrf.enabled !== false, enabledPath: 'ssrf.enabled', mode: ssrf.mode || 'detect', modePath: 'ssrf.mode' },
            { title: 'Payload Abuse Protection', description: 'Malformed or abusive payloads.', icon: icons.alert, enabled: payload.enabled !== false, enabledPath: 'payload_abuse.enabled', mode: payload.mode || 'detect', modePath: 'payload_abuse.mode' }
        ];
    }
    if (id === 'contract') {
        const validation = getValidationConfig(config);
        return [
            { title: 'Schema Enforcement', description: 'Attached API contracts.', icon: icons.fileText, enabled: validation.enabled !== false, enabledPath: 'validation.enabled', mode: validation.mode || 'block', modePath: 'validation.mode' },
            { title: 'Invalid Method Policy', description: 'Reject methods that are not allowed by attached contracts.', icon: icons.alert, enabled: validation.block_invalid_methods !== false, statePath: 'validation.block_invalid_methods', stateKind: 'boolean' },
            { title: 'Invalid Content Type Policy', description: 'Reject request content types not allowed by attached contracts.', icon: icons.fileText, enabled: validation.block_invalid_content_types !== false, statePath: 'validation.block_invalid_content_types', stateKind: 'boolean' },
            { title: 'Response Contract Validation', description: 'Validate complete JSON responses against declared OpenAPI response contracts. Streams, compressed, and oversized responses remain explicitly uninspected.', icon: icons.activity, enabled: validation.validate_responses === true, statePath: 'validation.validate_responses', stateKind: 'boolean' }
        ];
    }
    if (id === 'authorization') {
        const bfla = config.bfla || {};
        const massAssignment = config.mass_assignment || {};
        const bola = config.bola || {};
        return [
            { title: 'Function Authorization', description: 'Role and claim rules for API operations.', icon: icons.alert, enabled: bfla.enabled !== false, enabledPath: 'bfla.enabled', mode: String(bfla.mode || 'detect'), modePath: 'bfla.mode' },
            { title: 'Object And Tenant Authorization', description: 'Ownership, tenant isolation, and IDOR protection.', icon: icons.lock, enabled: bola.enabled !== false, enabledPath: 'bola.enabled', mode: String(bola.mode || 'detect'), modePath: 'bola.mode' },
            { title: 'Protected Request Fields', description: 'Mass-assignment protection for client-controlled fields.', icon: icons.database, enabled: massAssignment.enabled !== false, enabledPath: 'mass_assignment.enabled', mode: String(massAssignment.mode || 'detect'), modePath: 'mass_assignment.mode' }
        ];
    }
    if (id === 'graphql') {
        const graphql = getGraphQLConfig(config);
        return [
            { title: 'GraphQL Attack Policy', description: 'Unsafe query behavior.', icon: icons.code, enabled: graphql.enabled !== false, enabledPath: 'graphql.enabled', mode: graphql.mode || 'detect', modePath: 'graphql.mode', extra: graphql.block_introspection !== false ? 'Introspection protected' : 'Introspection allowed' }
        ];
    }
    if (id === 'abuse') {
        const automation = getAutomationAbuseConfig(config);
        return [
            { title: 'Automation Abuse Protection', description: 'Automated abuse patterns.', icon: icons.alert, enabled: automation.enabled !== false, enabledPath: 'automation_abuse.enabled', mode: automation.mode || 'detect', modePath: 'automation_abuse.mode' }
        ];
    }
    const dataExposure = getDataExposureConfig(config);
    return [
        { title: 'Data Exposure Protection', description: 'Sensitive data exposure.', icon: icons.database, enabled: dataExposure.enabled !== false, enabledPath: 'data_exposure.enabled', mode: dataExposure.mode || 'detect', modePath: 'data_exposure.mode' }
    ];
}

function renderAPISecurityPolicyPrimaryConfiguration(
    id: APISecurityPolicyId,
    config: APISecurityState,
    inventory: APISecurityEndpoint[],
    icons: Record<string, string>
): string {
    if (id === 'runtime') return renderRuntimePolicyConfiguration(config, icons);
    if (id === 'contract') return renderContractPolicyConfiguration(config, icons);
    if (id === 'authorization') return renderAuthorizationPolicyConfiguration(config, inventory, icons);
    if (id === 'graphql') return renderGraphQLPolicyConfiguration(config, inventory, icons);
    if (id === 'abuse') return renderAbusePolicyConfiguration(config, inventory, icons);
    return renderDataExposurePolicyConfiguration(config, inventory, icons);
}


function renderAPISecurityControlSection(title: string, description: string, icon: string, content: string, flush = false): string {
    return `
        <div class="operator-control-list apisecurity-config-section-shell">
            ${SectionUI.renderOperatorControlRow({ title, description, icon, enabled: true, actions: '' })}
            <div class="apisecurity-config-section-body${flush ? ' is-flush' : ''}">${content}</div>
        </div>
    `;
}

function renderRuntimePolicyConfiguration(config: APISecurityState, icons: Record<string, string>): string {
    const injection = getInjectionConfig(config);
    const payload = getPayloadAbuseConfig(config);
    return `
        ${renderAPISecurityControlSection(
            'Protection modules',
            'Enable, monitor, or block the runtime protections that make up this policy.',
            icons.shield,
            getAPISecurityPolicyRows('runtime', config, icons).map(renderAPISecurityPolicyRow).join(''),
            true
        )}
        ${renderAPISecurityControlSection('Sensitivity', 'Routine runtime tuning. Detailed settings keep individual detector branches.', icons.sliders, `
            <div class="apisecurity-field-grid apisecurity-field-grid-wide">
                <label class="bot-overview-field">
                    <span>Injection Sensitivity</span>
                    <select data-api-path="injection.sensitivity" data-api-value-type="string" data-api-render="true">
                        <option value="low" ${injection.sensitivity === 'low' ? 'selected' : ''}>Low</option>
                        <option value="medium" ${injection.sensitivity === 'medium' ? 'selected' : ''}>Medium</option>
                        <option value="high" ${injection.sensitivity === 'high' ? 'selected' : ''}>High</option>
                    </select>
                </label>
                <label class="bot-overview-field">
                    <span>Payload Sensitivity</span>
                    <select data-api-path="payload_abuse.sensitivity" data-api-value-type="string" data-api-render="true">
                        <option value="balanced" ${normalizePayloadSensitivity(payload.sensitivity) === 'balanced' ? 'selected' : ''}>Balanced</option>
                        <option value="strict" ${normalizePayloadSensitivity(payload.sensitivity) === 'strict' ? 'selected' : ''}>Strict</option>
                    </select>
                </label>
            </div>
        `)}
    `;
}

function renderContractPolicyConfiguration(config: APISecurityState, icons: Record<string, string>): string {
    return renderAPISecurityControlSection(
        'Contract controls',
        'Choose how attached schemas are validated and which contract violations are blocked.',
        icons.fileText,
        getAPISecurityPolicyRows('contract', config, icons).map(renderAPISecurityPolicyRow).join(''),
        true
    );
}

function renderAuthorizationPolicyConfiguration(
    config: APISecurityState,
    inventory: APISecurityEndpoint[],
    icons: Record<string, string>
): string {
    const bola = config.bola || {};
    const bfla = config.bfla || {};
    const massAssignment = config.mass_assignment || {};
    const selectedControl = APISecurityConfig.selectedAuthorizationControl;
    if (!selectedControl) {
        return renderAuthorizationControlList(bfla, bola, massAssignment, icons);
    }
    const detail = selectedControl === 'function'
        ? { title: 'Function authorization', subtitle: 'Method and path actions with role and claim allow rules.', content: renderBFLAPolicySettings(bfla, inventory) }
        : selectedControl === 'object'
            ? { title: 'Object and tenant authorization', subtitle: 'Map identity injected by Edge Access into ownership, tenant-isolation, and IDOR controls.', content: renderObjectAuthorizationPolicySettings(bola, inventory) }
            : { title: 'Protected request fields', subtitle: 'Prevent clients from changing sensitive fields through mass assignment.', content: renderMassAssignmentPolicySettings(massAssignment, inventory) };
    return `
        <div class="apisecurity-authorization-detail-nav">
            ${SectionUI.renderOperatorBackButton({
                label: 'Back to authorization controls',
                attrs: 'data-api-security-action="close-authorization-control"'
            })}
        </div>
        ${detail.content}
    `;
}

function renderAuthorizationControlList(
    bfla: APISecurityBFLAConfig,
    bola: APISecurityBolaConfig,
    massAssignment: APISecurityMassAssignmentConfig,
    icons: Record<string, string>
): string {
    const controls = [
        { id: 'function', title: 'Function authorization', description: 'Method and path actions with role and claim allow rules.', icon: icons.lock, enabled: bfla.enabled !== false, mode: bfla.mode || 'detect' },
        { id: 'object', title: 'Object and tenant authorization', description: 'Ownership, tenant isolation, and IDOR controls using trusted identity.', icon: icons.shield, enabled: bola.enabled !== false, mode: bola.mode || 'detect' },
        { id: 'fields', title: 'Protected request fields', description: 'Prevent mass assignment of fields that should remain under server control.', icon: icons.database, enabled: massAssignment.enabled !== false, mode: massAssignment.mode || 'detect' }
    ];
    return `
        <div class="operator-control-list apisecurity-primary-policy-list apisecurity-authorization-control-list">
            ${controls.map(control => SectionUI.renderOperatorControlRow({
                title: control.title,
                description: control.description,
                icon: control.icon,
                enabled: control.enabled,
                actions: '<span class="apisecurity-authorization-list-arrow" aria-hidden="true">&rsaquo;</span>',
                className: 'apisecurity-module-row apisecurity-authorization-control-row',
                attrs: `role="button" tabindex="0" data-api-security-action="open-authorization-control" data-api-authorization-control="${control.id}"`
            })).join('')}
        </div>
    `;
}

function renderPolicyStateControl(title: string, enabled: boolean, mode: string, enabledPath: string, modePath: string): string {
    const normalizedMode = normalizeAPISecurityMode(mode) as 'detect' | 'block';
    return `
        <select class="apisecurity-inline-select apisecurity-policy-mode-select" aria-label="${escapeSectionHtml(title)} mode" data-api-policy-function-state="true" data-api-enabled-path="${escapeSectionHtml(enabledPath)}" data-api-mode-path="${escapeSectionHtml(modePath)}">
            <option value="disable" ${!enabled ? 'selected' : ''}>Disable</option>
            <option value="detect" ${enabled && normalizedMode === 'detect' ? 'selected' : ''}>Monitor</option>
            <option value="block" ${enabled && normalizedMode === 'block' ? 'selected' : ''}>Block</option>
        </select>
    `;
}

function renderBFLAPolicySettings(config: APISecurityBFLAConfig, inventory: APISecurityEndpoint[] = []): string {
    const rules = normalizeBFLARules(config.rules);
    return `
        <div class="apisecurity-function-console">
            <div class="apisecurity-function-console-head">
                <div>
                    <span class="apisecurity-function-eyebrow">Operation access</span>
                    <h3>Authorization rules</h3>
                    <p>Decide which roles and claims may call protected API operations.</p>
                </div>
                <div class="apisecurity-function-console-actions">
                    ${renderPolicyStateControl('Function authorization', config.enabled !== false, String(config.mode || 'detect'), 'bfla.enabled', 'bfla.mode')}
                    <button class="operator-btn operator-btn-primary" type="button" data-api-security-action="add-bfla-rule">
                        <span aria-hidden="true">+</span> Add rule
                    </button>
                </div>
            </div>
            <div class="apisecurity-function-context">
                <strong>Verified identity required</strong>
                <p>Role and claim rules use only claims from a signature-verified JWT. Inbound identity headers are ignored.</p>
                <span class="config-status-pill tone-neutral">${formatAPINumber(rules.length)} rule${rules.length === 1 ? '' : 's'}</span>
            </div>
            ${renderBFLARuleRows(rules, inventory)}
        </div>
    `;
}

function renderObjectAuthorizationPolicySettings(config: APISecurityBolaConfig, inventory: APISecurityEndpoint[] = []): string {
    const rules = normalizeBolaOwnershipRules(config.ownership_rules);
    const isolatedPaths = Array.isArray(config.isolated_paths) ? config.isolated_paths : [];
    return `
        <div class="apisecurity-function-console apisecurity-object-console">
            <div class="apisecurity-function-console-head">
                <div>
                    <span class="apisecurity-function-eyebrow">Resource access</span>
                    <h3>Ownership and tenant rules</h3>
                    <p>Bind protected resources to the authenticated caller and tenant.</p>
                </div>
                <div class="apisecurity-function-console-actions">
                    ${renderPolicyStateControl('Object and tenant authorization', config.enabled !== false, String(config.mode || 'detect'), 'bola.enabled', 'bola.mode')}
                    <button class="operator-btn operator-btn-primary" type="button" data-api-security-action="add-bola-rule">
                        <span aria-hidden="true">+</span> Add ownership rule
                    </button>
                </div>
            </div>
            <div class="apisecurity-object-context">
                <div class="apisecurity-function-editor-heading">
                    <strong>Verified token identity only</strong>
                    <p>Ownership uses the verified subject or configured owner claim. Tenant routes must include <code>{tenant_id}</code>; inbound identity headers are ignored.</p>
                </div>
            </div>
            <details class="apisecurity-authorization-scope" ${isolatedPaths.length ? 'open' : ''}>
                <summary>
                    <strong>Tenant-isolated paths</strong>
                </summary>
                ${renderAPISecurityPathListEditor('Path patterns', 'bola.isolated_paths', isolatedPaths, inventory, {
                    placeholder: '/api/tenants/{tenant_id}'
                })}
            </details>
            ${renderBolaOwnershipRules(rules, inventory)}
        </div>
    `;
}

function renderMassAssignmentPolicySettings(config: APISecurityMassAssignmentConfig, inventory: APISecurityEndpoint[] = []): string {
    const protectedFields = config.protected_fields || defaultMassAssignmentFields();
    const rules = normalizeMassAssignmentPathRules(config.path_rules);
    return `
        <div class="apisecurity-function-console apisecurity-protected-fields-console">
            <div class="apisecurity-function-console-head">
                <div>
                    <span class="apisecurity-function-eyebrow">Write protection</span>
                    <h3>Protected field rules</h3>
                    <p>Stop clients from writing fields that should remain under server control.</p>
                </div>
                <div class="apisecurity-function-console-actions">
                    ${renderPolicyStateControl('Protected request fields', config.enabled !== false, String(config.mode || 'detect'), 'mass_assignment.enabled', 'mass_assignment.mode')}
                    <button class="operator-btn operator-btn-primary" type="button" data-api-security-action="add-mass-rule">
                        <span aria-hidden="true">+</span> Add path rule
                    </button>
                </div>
            </div>
            <div class="apisecurity-protected-defaults">
                <div class="apisecurity-function-editor-heading">
                    <strong>Default protected fields</strong>
                    <span>Applied to write requests unless a path rule defines a narrower field set.</span>
                </div>
                ${renderAuthorizationStringValueEditor('Protected fields', 'mass_assignment.protected_fields', protectedFields, {
                    placeholder: 'server_owned_field',
                    suggestions: ['role', 'is_admin', 'permissions', 'plan', 'balance', 'credit_limit'],
                    addLabel: 'Add field',
                    emptyLabel: 'Select or add at least one protected field.'
                })}
            </div>
            ${renderMassAssignmentPathRuleRows(rules, inventory)}
        </div>
    `;
}


function renderGraphQLPolicyConfiguration(config: APISecurityState, _inventory: APISecurityEndpoint[], icons: Record<string, string>): string {
    const graphql = getGraphQLConfig(config);
    const selectedControl = APISecurityConfig.selectedGraphQLControl;
    if (!selectedControl) return renderGraphQLControlList(graphql, icons);

    const detail = selectedControl === 'limits'
            ? {
                title: 'Query execution limits',
                subtitle: 'Choose a production baseline, then set precise limits for depth, aliases, batching, and complexity.',
                content: renderGraphQLLimitsConfiguration(graphql, icons)
            }
            : {
                title: 'Schema exposure',
                subtitle: 'Control whether clients can enumerate your GraphQL schema through introspection.',
                content: renderGraphQLSchemaConfiguration(graphql, icons)
            };

    return `
        <div class="apisecurity-authorization-detail-nav">
            ${SectionUI.renderOperatorBackButton({
                label: 'Back to GraphQL protection',
                attrs: 'data-api-security-action="close-graphql-control"'
            })}
        </div>
        ${detail.content}
    `;
}

function renderGraphQLScopeTable(paths: string[], showToolbar = true): string {
    const normalizedPaths = normalizeStringList(paths, []);
    const hasConfiguredPaths = normalizedPaths.length > 0;
    const scopeActionLabel = hasConfiguredPaths ? 'Edit paths' : 'Add GraphQL paths';
    return `
        <div class="operator-table-panel apisecurity-graphql-scope-table">
            ${showToolbar ? `<div class="operator-table-toolbar">
                <div class="operator-toolbar-group">
                    <span class="operator-toolbar-note">${formatAPINumber(normalizedPaths.length)} path${normalizedPaths.length === 1 ? '' : 's'} protected</span>
                </div>
                <button class="btn btn-primary btn-sm" type="button" data-api-security-action="open-scope-picker" data-api-scope-path="graphql.paths" data-api-scope-title="GraphQL API scope" data-api-scope-mode="include" data-api-tab="graphql">${scopeActionLabel}</button>
            </div>` : ''}
            ${SectionUI.renderEnterpriseTable({
                columns: ['GraphQL path', 'Policy coverage', 'Actions'],
                rows: normalizedPaths.map((path, index) => [
                    `<span class="text-main text-small">${escapeSectionHtml(path)}</span>`,
                    '<span class="config-status-pill tone-primary">Protected</span>',
                    `<button class="btn btn-secondary btn-sm" type="button" data-api-security-action="remove-string-list-item" data-api-string-list-path="graphql.paths" data-api-string-list-index="${index}">Remove</button>`
                ]),
                emptyTitle: 'No GraphQL paths configured',
                emptyMessage: 'Select Add GraphQL paths to choose endpoints for this policy.',
                className: 'apisecurity-action-table'
            })}
        </div>
    `;
}

function renderGraphQLControlList(graphql: APISecurityGraphQLConfig, icons: Record<string, string>): string {
    const paths = normalizeStringList(graphql.paths, defaultGraphQLPaths());
    const activePreset = getGraphQLLimitPreset(graphql);
    const arrow = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>';
    const controls = [
        { id: 'limits', title: 'Query execution limits', description: `${activePreset === 'custom' ? 'Custom limits' : `${labelizeAPIInventoryValue(activePreset)} profile`} · Depth ${formatAPINumber(Number(graphql.max_depth || 15))} · Complexity ${formatAPINumber(Number(graphql.max_complexity || 500))}.`, icon: icons.sliders },
        { id: 'schema', title: 'Schema exposure', description: graphql.block_introspection !== false ? 'Schema introspection is blocked to prevent unauthorized API enumeration.' : 'Schema introspection is enabled for development and exploration.', icon: icons.shield }
    ];
    return `
        <div class="operator-control-list apisecurity-primary-policy-list apisecurity-graphql-control-list">
            ${SectionUI.renderOperatorControlRow({ title: 'GraphQL request policy', description: 'Choose whether GraphQL requests exceeding depth or complexity limits are logged (Detect) or rejected (Block).', icon: icons.code, enabled: graphql.enabled !== false, actions: renderPolicyStateControl('GraphQL protection', graphql.enabled !== false, String(graphql.mode || 'detect'), 'graphql.enabled', 'graphql.mode') })}
            ${controls.map(control => SectionUI.renderOperatorControlRow({ title: control.title, description: control.description, icon: control.icon, enabled: true, actions: arrow, className: 'apisecurity-module-row apisecurity-authorization-control-row', attrs: `role="button" tabindex="0" data-api-security-action="open-graphql-control" data-api-graphql-control="${control.id}"` })).join('')}
        </div>
        <div class="operator-control-list apisecurity-graphql-paths-shell">
            ${SectionUI.renderOperatorControlRow({ title: 'Configured GraphQL paths', description: 'Every endpoint protected by this policy.', icon: icons.list, enabled: true, actions: `<span class="operator-toolbar-note">${formatAPINumber(paths.length)} protected path${paths.length === 1 ? '' : 's'}</span><button class="btn btn-primary btn-sm" type="button" data-api-security-action="open-scope-picker" data-api-scope-path="graphql.paths" data-api-scope-title="GraphQL API scope" data-api-scope-mode="include" data-api-tab="graphql">${paths.length ? 'Edit paths' : 'Add GraphQL paths'}</button>` })}
            ${renderGraphQLScopeTable(paths, false)}
        </div>
    `;
}

function renderGraphQLLimitsConfiguration(graphql: APISecurityGraphQLConfig, icons: Record<string, string>): string {
    const activePreset = getGraphQLLimitPreset(graphql);
    const presets = [{ id: 'strict', visual: 'privacy' }, { id: 'standard', visual: 'balanced' }, { id: 'relaxed', visual: 'maximum' }];
    return `
        <div class="operator-control-list apisecurity-graphql-limits-shell">
            ${SectionUI.renderOperatorControlRow({
                title: 'Limit profile',
                description: 'Choose a baseline, then fine-tune depth, aliases, batching, and complexity when needed.',
                icon: icons.sliders,
                enabled: true
            })}
            <div class="apisecurity-graphql-limits-shell-body">
                <div class="section-fp-grid" role="group" aria-label="GraphQL limit profiles">
            ${presets.map(({ id, visual }) => {
                const active = activePreset === id;
                return `
                    <button class="section-fp-card ${visual} ${active ? 'active' : ''}" type="button" data-api-security-action="apply-graphql-preset" data-api-graphql-preset="${id}" aria-pressed="${active ? 'true' : 'false'}">
                        ${active ? '<span class="section-fp-check" aria-hidden="true">&check;</span>' : ''}
                        <span class="section-fp-icon-wrap" aria-hidden="true">${icons.sliders}</span>
                        <span class="section-fp-title">${escapeSectionHtml(labelizeAPIInventoryValue(id))}</span>
                        <span class="section-fp-sub">${escapeSectionHtml(getGraphQLPresetDescription(id))}</span>
                    </button>
                `;
            }).join('')}
                </div>
                <div class="apisecurity-field-grid apisecurity-field-grid-wide mt-16">
            <label class="bot-overview-field"><span>Maximum depth</span><input aria-label="Maximum GraphQL query depth" type="number" min="1" value="${escapeSectionHtml(String(graphql.max_depth || 15))}" data-api-path="graphql.max_depth" data-api-value-type="number"></label>
            <label class="bot-overview-field"><span>Maximum aliases</span><input aria-label="Maximum GraphQL aliases" type="number" min="1" value="${escapeSectionHtml(String(graphql.max_aliases || 25))}" data-api-path="graphql.max_aliases" data-api-value-type="number"></label>
            <label class="bot-overview-field"><span>Maximum batch size</span><input aria-label="Maximum GraphQL batch size" type="number" min="1" value="${escapeSectionHtml(String(graphql.max_batch_size || 5))}" data-api-path="graphql.max_batch_size" data-api-value-type="number"></label>
            <label class="bot-overview-field"><span>Maximum complexity</span><input aria-label="Maximum GraphQL complexity" type="number" min="1" value="${escapeSectionHtml(String(graphql.max_complexity || 500))}" data-api-path="graphql.max_complexity" data-api-value-type="number"></label>
                </div>
            </div>
        </div>
    `;
}

function renderGraphQLSchemaConfiguration(graphql: APISecurityGraphQLConfig, icons: Record<string, string>): string {
    const introspectionBlocked = graphql.block_introspection !== false;
    return `
        <div class="operator-control-list apisecurity-graphql-schema-shell">
            ${SectionUI.renderOperatorControlRow({
                title: 'Introspection access',
                description: 'Choose whether clients can enumerate the GraphQL schema.',
                icon: icons.shield,
                enabled: true
            })}
            <div class="apisecurity-graphql-schema-shell-body">
                <div class="edge-access-v2-provider-template-grid apisecurity-graphql-schema-grid" role="group" aria-label="GraphQL introspection access">
                <button class="edge-access-v2-provider-template ${introspectionBlocked ? 'is-selected' : ''}" type="button" data-api-security-action="set-config-field" data-api-path="graphql.block_introspection" data-api-value="true" data-api-value-type="checkbox" aria-pressed="${introspectionBlocked ? 'true' : 'false'}">
                    <span class="edge-access-v2-provider-mark apisecurity-graphql-schema-mark" aria-hidden="true">${icons.shield}</span>
                    <span class="edge-access-v2-provider-template-copy"><strong>Block introspection</strong><span>Reject schema enumeration requests.</span><small>Recommended for production</small></span>
                    <span class="edge-access-v2-provider-template-check" aria-hidden="true">${SectionUI.icons.check}</span>
                </button>
                <button class="edge-access-v2-provider-template ${!introspectionBlocked ? 'is-selected' : ''}" type="button" data-api-security-action="set-config-field" data-api-path="graphql.block_introspection" data-api-value="false" data-api-value-type="checkbox" aria-pressed="${!introspectionBlocked ? 'true' : 'false'}">
                    <span class="edge-access-v2-provider-mark apisecurity-graphql-schema-mark" aria-hidden="true">${icons.code}</span>
                    <span class="edge-access-v2-provider-template-copy"><strong>Allow introspection</strong><span>Permit schema enumeration for clients.</span><small>Use only when required</small></span>
                    <span class="edge-access-v2-provider-template-check" aria-hidden="true">${SectionUI.icons.check}</span>
                </button>
                </div>
            </div>
        </div>
    `;
}

function renderAPISecurityListTableSection(
    title: string,
    description: string,
    icon: string,
    path: string,
    values: string[],
    options: APISecurityStringListEditorOptions & { kind: 'path' | 'identifier' }
): string {
    const normalizedPath = normalizeAPISecurityStringListPath(path);
    const items = normalizeStringList(values, []);
    const suggestions = mergeAPISecurityStringLists(
        options.suggestions || [],
        getAPISecurityStringListInventoryOptions(options.inventory || [], options.inventoryFilter)
    );
    const isPath = options.kind === 'path';
    const valueLabel = isPath ? 'Path pattern' : 'Identifier field';
    const detailLabel = isPath ? 'Abuse coverage' : 'Request identity';
    const emptyTitle = isPath ? 'No path patterns configured' : 'No identifier fields configured';
    const emptyMessage = isPath
        ? 'Add a path pattern to include this API surface in abuse protection.'
        : 'Add an identifier field used to group abuse activity.';
    const toolbar = `
        <div class="operator-table-toolbar apisecurity-list-table-toolbar">
            <div class="operator-toolbar-group">
                <span class="operator-toolbar-note">${formatAPINumber(items.length)} configured</span>
            </div>
            <div class="apisecurity-structured-add">
                ${suggestions.length ? `<select aria-label="${escapeSectionHtml(`Add ${title} from list`)}" data-api-string-list-picker="${escapeSectionHtml(normalizedPath)}"><option value="">Add from list</option>${suggestions.map(value => `<option value="${escapeSectionHtml(value)}">${escapeSectionHtml(value)}</option>`).join('')}</select>` : ''}
                <input aria-label="${escapeSectionHtml(`Add ${title}`)}" value="" placeholder="${escapeSectionHtml(options.placeholder || 'Add value')}" data-api-string-list-new="${escapeSectionHtml(normalizedPath)}">
                <button class="btn btn-primary btn-sm" type="button" data-api-security-action="add-string-list-item" data-api-string-list-path="${escapeSectionHtml(normalizedPath)}">${escapeSectionHtml(options.addLabel || 'Add')}</button>
            </div>
        </div>`;
    return renderAPISecurityControlSection(title, description, icon, `
        <div class="operator-table-panel apisecurity-list-table-section">
            ${toolbar}
            ${SectionUI.renderEnterpriseTable({
                columns: [valueLabel, detailLabel, 'Actions'],
                rows: items.map((item, index) => [
                    `<input class="apisecurity-list-table-input" aria-label="${escapeSectionHtml(`${valueLabel} ${index + 1}`)}" value="${escapeSectionHtml(item)}" placeholder="${escapeSectionHtml(options.placeholder || 'Value')}" data-api-string-list-path="${escapeSectionHtml(normalizedPath)}" data-api-string-list-index="${index}">`,
                    `<span class="text-note">${isPath ? 'Included in abuse checks' : 'Groups related activity'}</span>`,
                    `<button class="btn btn-secondary btn-sm" type="button" data-api-security-action="remove-string-list-item" data-api-string-list-path="${escapeSectionHtml(normalizedPath)}" data-api-string-list-index="${index}">Remove</button>`
                ]),
                emptyTitle,
                emptyMessage,
                className: 'apisecurity-action-table'
            })}
        </div>
    `);
}

function renderAbusePolicyConfiguration(config: APISecurityState, inventory: APISecurityEndpoint[], icons: Record<string, string>): string {
    const automation = getAutomationAbuseConfig(config);
    return `
        <div class="operator-control-list apisecurity-config-section-shell apisecurity-primary-policy-list">
            ${getAPISecurityPolicyRows('abuse', config, icons).map(renderAPISecurityPolicyRow).join('')}
            ${SectionUI.renderOperatorControlRow({
                title: 'Behavior',
                description: 'Set the baseline sensitivity used by abuse detection.',
                icon: icons.sliders,
                enabled: true,
                actions: ''
            })}
            <div class="apisecurity-config-section-body">
                <div class="apisecurity-field-grid apisecurity-field-grid-wide">
                    <label class="bot-overview-field"><span>Sensitivity</span><select data-api-path="automation_abuse.sensitivity" data-api-value-type="string" data-api-render="true"><option value="balanced" ${normalizeAutomationSensitivity(automation.sensitivity) === 'balanced' ? 'selected' : ''}>Balanced</option><option value="strict" ${normalizeAutomationSensitivity(automation.sensitivity) === 'strict' ? 'selected' : ''}>Strict</option></select></label>
                </div>
            </div>
        </div>
        ${renderAPISecurityListTableSection('Login path patterns', 'Paths where sign-in attempts are evaluated for abuse.', icons.lock, 'automation_abuse.login_paths', automation.login_paths || defaultAutomationLoginPaths(), { kind: 'path', placeholder: '/api/login', addLabel: 'Add path', inventory })}
        ${renderAPISecurityListTableSection('OTP path patterns', 'Paths where one-time passcode attempts are evaluated for abuse.', icons.shield, 'automation_abuse.otp_paths', automation.otp_paths || defaultAutomationOTPPaths(), { kind: 'path', placeholder: '/api/mfa/verify', addLabel: 'Add path', inventory })}
        ${renderAPISecurityListTableSection('Monitored path patterns', 'Additional API paths included in abuse detection.', icons.list, 'automation_abuse.monitored_paths', automation.monitored_paths || defaultAutomationMonitoredPaths(), { kind: 'path', placeholder: '/api/*', addLabel: 'Add path', inventory })}
        ${renderAPISecurityListTableSection('Identifier fields', 'Request fields used to group related abuse activity.', icons.database, 'automation_abuse.identifier_fields', automation.identifier_fields || defaultAutomationIdentifierFields(), { kind: 'identifier', placeholder: 'email', addLabel: 'Add field', suggestions: ['email', 'username', 'user_id', 'account_id', 'phone'] })}
    `;
}

function renderDataExposurePolicyConfiguration(config: APISecurityState, inventory: APISecurityEndpoint[], icons: Record<string, string>): string {
    const dataExposure = getDataExposureConfig(config);
    return `
        <div class="operator-control-list apisecurity-primary-policy-list apisecurity-data-exposure-primary-list">
            ${getAPISecurityPolicyRows('data', config, icons).map(renderAPISecurityPolicyRow).join('')}
            ${renderAPISecurityToggleSettingRow('Inspect Requests', 'data_exposure.inspect_requests', dataExposure.inspect_requests !== false, icons.fileText, 'Inspect request payloads for sensitive data.')}
            ${renderAPISecurityToggleSettingRow('Inspect Responses', 'data_exposure.inspect_responses', dataExposure.inspect_responses !== false, icons.activity, 'Inspect response payloads for sensitive data.')}
        </div>
        ${renderAPISecurityControlSection('Response handling', 'Set the detection sensitivity, then choose how sensitive response data is handled.', icons.alert, `
            <div class="apisecurity-field-grid apisecurity-field-grid-wide">
                <label class="bot-overview-field"><span>Sensitivity</span><select data-api-path="data_exposure.sensitivity" data-api-value-type="string" data-api-render="true"><option value="balanced" ${normalizeDataExposureSensitivity(dataExposure.sensitivity) === 'balanced' ? 'selected' : ''}>Balanced</option><option value="strict" ${normalizeDataExposureSensitivity(dataExposure.sensitivity) === 'strict' ? 'selected' : ''}>Strict</option></select></label>
                <label class="bot-overview-field"><span>Response Handling</span><select data-api-path="data_exposure.response_handling" data-api-value-type="string" data-api-render="true"><option value="block" ${normalizeDataExposureResponseHandling(dataExposure.response_handling) === 'block' ? 'selected' : ''}>Block response</option><option value="redact" ${normalizeDataExposureResponseHandling(dataExposure.response_handling) === 'redact' ? 'selected' : ''}>Redact response</option></select></label>
            </div>
            ${renderAPISecurityPathListEditor('Excluded Path Patterns', 'data_exposure.excluded_paths', dataExposure.excluded_paths || [], inventory, {
        placeholder: '/api/public/*'
    })}
        `)}
    `;
}

function renderAPISecurityWizardDrawer(
    activeWizard: APISecurityWizardId,
    wizardStep: number,
    config: APISecurityState,
    inventory: APISecurityEndpoint[],
    setupFocus: string,
    schemaPrefillEndpointKey: string
): string {
    if (!activeWizard) return '';
    const title = {
        schema: 'Attach Schema',
        identity: 'Identity setup',
        data: 'Data exposure setup'
    }[activeWizard];
    const content = activeWizard === 'schema'
        ? renderSchemaWizardContent(config, inventory, schemaPrefillEndpointKey, wizardStep)
        : activeWizard === 'identity'
            ? renderIdentityWizardContent(config, wizardStep)
            : renderDataExposureWizardContent(config, wizardStep);
    return SectionUI.renderOperatorSection(title, `
        <div class="apisecurity-wizard-drawer" data-api-wizard-active="${activeWizard}">
            <div class="apisecurity-wizard-head">
                ${renderAPISecurityWizardSteps(activeWizard, wizardStep)}
                <button class="btn btn-secondary btn-sm" type="button" data-api-security-action="close-wizard">Close</button>
            </div>
            ${content}
        </div>
    `, {
        subtitle: setupFocus ? 'Guided setup writes existing API Security configuration fields.' : 'Guided setup writes existing API Security configuration fields.'
    });
}

function renderAPISecurityWizardSteps(activeWizard: APISecurityWizardId, currentStep: number): string {
    const max = getAPISecurityWizardMaxStep(activeWizard);
    if (max <= 1) return '<div class="apisecurity-chip-row"><span class="apisecurity-chip is-active">Ready</span></div>';
    const labels = activeWizard === 'schema'
        ? ['Endpoint', 'Schema', 'Action']
        : activeWizard === 'identity'
            ? ['Surface', 'Issuer', 'Action']
            : ['Action', 'Handling'];
    return `<div class="apisecurity-chip-row">${labels.map((label, index) => {
        const step = index + 1;
        return `<button class="apisecurity-chip ${step === currentStep ? 'is-active' : ''}" type="button" data-api-security-action="set-wizard-step" data-api-wizard-step="${step}">${escapeSectionHtml(label)}</button>`;
    }).join('')}</div>`;
}

function renderSchemaWizardContent(config: APISecurityState, inventory: APISecurityEndpoint[], schemaPrefillEndpointKey: string, wizardStep: number): string {
    const validation = getValidationConfig(config);
    return `
        ${wizardStep === 1 ? `<div class="section-empty-state"><div class="section-empty-title">Choose an endpoint</div><div class="section-empty-sub">Pick a discovered endpoint or keep manual endpoint details for this schema.</div></div>` : ''}
        ${renderAPISecuritySchemaUploadForm(inventory, schemaPrefillEndpointKey)}
        <div class="apisecurity-field-grid mt-16">
            <label class="bot-overview-field">
                <span>Schema Action</span>
                <select id="apisecurity-schema-wizard-mode">
                    <option value="detect" ${normalizeAPISecurityMode(validation.mode || 'detect') === 'detect' ? 'selected' : ''}>Monitor mismatches</option>
                    <option value="block" ${normalizeAPISecurityMode(validation.mode || 'detect') === 'block' ? 'selected' : ''}>Block mismatches</option>
                </select>
            </label>
        </div>
        <div class="section-action-row mt-16">
            <button class="btn btn-primary" type="button" data-api-security-action="apply-schema-wizard">Apply Schema Setup</button>
        </div>
    `;
}

function renderIdentityWizardContent(config: APISecurityState, wizardStep: number): string {
    const authTokens = config.auth_tokens || {};
    const issuer = normalizeAuthTokenIssuers(authTokens.issuers)[0] || {};
    return `
        ${wizardStep === 1 ? renderAPISecurityPathListEditor('Protected API Surface', 'auth_tokens.protected_paths', authTokens.protected_paths || [], [], {
        placeholder: '/api/private/*'
    }) : ''}
        <div class="apisecurity-field-grid apisecurity-field-grid-wide mt-16">
            <label class="bot-overview-field">
                <span>Issuer Name</span>
                <input id="apisecurity-identity-issuer-name" value="${escapeSectionHtml(issuer.name || '')}" placeholder="Primary issuer">
            </label>
            <label class="bot-overview-field">
                <span>Issuer URL</span>
                <input id="apisecurity-identity-issuer" value="${escapeSectionHtml(issuer.issuer || '')}" placeholder="https://issuer.example">
            </label>
            <label class="bot-overview-field">
                <span>Audience</span>
                <input id="apisecurity-identity-audiences" value="${escapeSectionHtml((issuer.audiences || []).join(', '))}" placeholder="api">
            </label>
            <label class="bot-overview-field">
                <span>JWKS URL</span>
                <input id="apisecurity-identity-jwks" value="${escapeSectionHtml(issuer.jwks_url || '')}" placeholder="https://issuer.example/.well-known/jwks.json">
            </label>
            <label class="bot-overview-field">
                <span>Token Presence</span>
                <label class="section-switch"><input id="apisecurity-identity-require-token" type="checkbox" ${(authTokens.protected_paths || []).length ? 'checked' : ''}><span class="switch-slider"></span></label>
            </label>
            <label class="bot-overview-field">
                <span>Action</span>
                <select id="apisecurity-identity-mode">
                    <option value="detect" ${normalizeAPISecurityMode(authTokens.mode || 'detect') === 'detect' ? 'selected' : ''}>Monitor</option>
                    <option value="block" ${normalizeAPISecurityMode(authTokens.mode || 'detect') === 'block' ? 'selected' : ''}>Block</option>
                </select>
            </label>
        </div>
        <div class="section-action-row mt-16">
            <button class="btn btn-primary" type="button" data-api-security-action="apply-identity-wizard">Apply Identity Setup</button>
        </div>
    `;
}

function renderDataExposureWizardContent(config: APISecurityState, wizardStep: number): string {
    const dataExposure = getDataExposureConfig(config);
    const action = normalizeAPISecurityMode(dataExposure.mode || 'detect') === 'detect'
        ? 'detect'
        : normalizeDataExposureResponseHandling(dataExposure.response_handling) === 'redact' ? 'redact' : 'block';
    return `
        ${wizardStep === 1 ? `<div class="section-empty-state"><div class="section-empty-title">Choose response handling</div><div class="section-empty-sub">Detector classes stay enabled by default. Detailed tuning is available in Settings and Detections.</div></div>` : ''}
        <div class="apisecurity-field-grid">
            <label class="bot-overview-field">
                <span>Data Action</span>
                <select id="apisecurity-data-wizard-mode">
                    <option value="detect" ${action === 'detect' ? 'selected' : ''}>Monitor sensitive data</option>
                    <option value="block" ${action === 'block' ? 'selected' : ''}>Block sensitive responses</option>
                    <option value="redact" ${action === 'redact' ? 'selected' : ''}>Redact sensitive responses</option>
                </select>
            </label>
        </div>
        <div class="section-action-row mt-16">
            <button class="btn btn-primary" type="button" data-api-security-action="apply-data-wizard">Apply Data Setup</button>
        </div>
    `;
}

function renderAPISecuritySchemaUploadForm(inventory: APISecurityEndpoint[], schemaPrefillEndpointKey: string): string {
    const prefillIndex = schemaPrefillEndpointKey
        ? inventory.findIndex(endpoint => {
            const k = getInventoryEndpointKey(endpoint);
            if (k === schemaPrefillEndpointKey) return true;
            if (endpoint.id && normalizeInventoryEndpointKey(endpoint.id) === schemaPrefillEndpointKey) return true;
            const parts = schemaPrefillEndpointKey.split('|');
            if (parts.length >= 3) {
                const [m, h, p] = parts;
                if ((endpoint.method || 'GET').toLowerCase() === m.toLowerCase() &&
                    (endpoint.path || '/').toLowerCase() === p.toLowerCase() &&
                    (!h || (endpoint.host || '').toLowerCase() === h.toLowerCase())) {
                    return true;
                }
            }
            return false;
        })
        : -1;
    const prefill = prefillIndex >= 0 ? inventory[prefillIndex] : null;
    const endpointOptions = inventory
        .map((endpoint, index) => `<option value="${index}" ${index === prefillIndex ? 'selected' : ''}>${escapeSectionHtml([endpoint.method || 'GET', endpoint.path || '/', endpoint.host || ''].filter(Boolean).join(' '))}</option>`)
        .join('');
    const rawSchemaType = String(prefill?.schema_type || '').toLowerCase();
    const isGraphQL = rawSchemaType.includes('graphql') || String(prefill?.path || '').toLowerCase().includes('graphql');
    const selectedSchemaType = isGraphQL ? 'graphql' : 'openapi';
    const isCovered = prefill ? getEndpointSchemaStatus(prefill) === 'covered' : false;

    return `
        ${prefill ? `
            <div class="apisecurity-target-banner mb-16" style="padding: 10px 14px; background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 6px; display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <span class="apisecurity-method-badge apisecurity-method-${getAPIMethodTone(prefill.method)}">${escapeSectionHtml(prefill.method || 'GET')}</span>
                    <strong style="margin-left: 8px;">${escapeSectionHtml(prefill.path || '/')}</strong>
                    <span class="text-note" style="margin-left: 8px;">${escapeSectionHtml(prefill.host || 'All hosts')}</span>
                </div>
            </div>
        ` : ''}
        <div class="apisecurity-field-grid apisecurity-field-grid-wide">
            <label class="bot-overview-field">
                <span>Attach or replace target</span>
                <select id="apisecurity-schema-endpoint">
                    <option value="" ${prefillIndex < 0 ? 'selected' : ''}>Manual endpoint - enter details below</option>
                    ${endpointOptions}
                </select>
            </label>
            <label class="bot-overview-field">
                <span>Method</span>
                <input id="apisecurity-schema-method" value="${escapeSectionHtml(prefill?.method || 'GET')}" placeholder="GET" ${prefill ? 'readonly' : ''}>
            </label>
            <label class="bot-overview-field">
                <span>Path</span>
                <input id="apisecurity-schema-path" value="${escapeSectionHtml(prefill?.path || '')}" placeholder="/api/users" ${prefill ? 'readonly' : ''}>
            </label>
            <label class="bot-overview-field">
                <span>Host</span>
                <input id="apisecurity-schema-host" value="${escapeSectionHtml(prefill?.host || '')}" placeholder="app.example.test" ${prefill ? 'readonly' : ''}>
            </label>
            <label class="bot-overview-field">
                <span>Schema Type</span>
                <select id="apisecurity-schema-type">
                    <option value="openapi" ${selectedSchemaType === 'openapi' ? 'selected' : ''}>OpenAPI</option>
                    <option value="graphql" ${selectedSchemaType === 'graphql' ? 'selected' : ''}>GraphQL</option>
                </select>
            </label>
        </div>
        <label class="bot-overview-field mt-16">
            <span>Schema Content</span>
            <textarea id="apisecurity-schema-content" rows="6" placeholder="Paste OpenAPI JSON/YAML or GraphQL schema"></textarea>
        </label>
        <div class="apisecurity-schema-actions">
            <button class="btn btn-primary btn-sm" type="button" data-api-security-action="upload-schema">
                ${SectionUI.icons.upload}
                <span>Upload Schema</span>
            </button>
        </div>
    `;
}

function renderNoAdditionalSettingsControls(): string {
    return `<div class="section-empty-state"><div class="section-empty-title">No additional controls</div><div class="section-empty-sub">Routine configuration for this policy is available above.</div></div>`;
}

function renderRuntimeDetectionControls(config: APISecurityState, icons: Record<string, string>): string {
    const injection = getInjectionConfig(config);
    const ssrf = getSSRFConfig(config);
    const vectorRows = [
        ['SQL Injection', 'injection.sqli', injection.sqli !== false],
        ['NoSQL Injection', 'injection.nosqli', injection.nosqli !== false],
        ['Command Injection', 'injection.cmdi', injection.cmdi !== false],
        ['XSS Detection', 'injection.xss', injection.xss !== false]
    ].map(([title, path, enabled]) => renderAPISecurityToggleSettingRow(String(title), String(path), Boolean(enabled), icons.zap)).join('');
    return `
        ${SectionUI.renderOperatorSection('Injection vectors', `<div class="operator-control-list">${vectorRows}</div>`)}
        ${SectionUI.renderOperatorSection('SSRF coverage', `<div class="operator-control-list">
            ${renderAPISecurityToggleSettingRow('Private And Internal Target Coverage', 'ssrf.block_private_networks', ssrf.block_private_networks !== false, icons.lock)}
            ${renderAPISecurityToggleSettingRow('Cloud Metadata Targets', 'ssrf.block_cloud_metadata', ssrf.block_cloud_metadata !== false, icons.database)}
        </div>`)}
    `;
}

function renderContractDetectionControls(): string {
    return renderNoAdditionalSettingsControls();
}

function renderAuthorizationDetectionControls(config: APISecurityState, icons: Record<string, string>): string {
    const bola = config.bola || {};
    const bolaRows = `
        ${renderAPISecurityToggleSettingRow('Ownership Enforcement', 'bola.enable_ownership', bola.enable_ownership === true, icons.lock)}
        ${renderAPISecurityToggleSettingRow('Tenant Isolation', 'bola.enable_tenant', bola.enable_tenant === true, icons.shield)}
        ${renderAPISecurityToggleSettingRow('IDOR Enumeration Detection', 'bola.enable_idor', bola.enable_idor !== false, icons.alert)}
        ${renderAPISecurityToggleSettingRow('Strict Tenant Mode', 'bola.strict_mode', bola.strict_mode === true, icons.fileText)}
    `;
    return `
        ${SectionUI.renderOperatorSection('BOLA detector switches', `<div class="operator-control-list">${bolaRows}</div>`, {
            subtitle: 'Low-level object access detector branches.'
        })}
    `;
}

function renderGraphQLDetectionControls(): string {
    return renderNoAdditionalSettingsControls();
}

function renderAbuseDetectionControls(config: APISecurityState, icons: Record<string, string>): string {
    const automation = getAutomationAbuseConfig(config);
    const detectorRows = `
        ${renderAPISecurityToggleSettingRow('Credential Stuffing', 'automation_abuse.enable_credential_stuffing', automation.enable_credential_stuffing !== false, icons.lock)}
        ${renderAPISecurityToggleSettingRow('OTP Brute Force', 'automation_abuse.enable_otp_bruteforce', automation.enable_otp_bruteforce !== false, icons.shield)}
        ${renderAPISecurityToggleSettingRow('Forced Browsing', 'automation_abuse.enable_forced_browsing', automation.enable_forced_browsing !== false, icons.alert)}
        ${renderAPISecurityToggleSettingRow('User And Account Enumeration', 'automation_abuse.enable_user_enumeration', automation.enable_user_enumeration !== false, icons.activity)}
        ${renderAPISecurityToggleSettingRow('Object ID Enumeration', 'automation_abuse.enable_object_enumeration', automation.enable_object_enumeration !== false, icons.fileText)}
        ${renderAPISecurityToggleSettingRow('Scraping And Expensive Query Abuse', 'automation_abuse.enable_scraping', automation.enable_scraping !== false, icons.database)}
    `;
    return `
        ${SectionUI.renderOperatorSection('Behavior detectors', `<div class="operator-control-list">${detectorRows}</div>`)}
    `;
}

function renderDataExposureDetectionControls(config: APISecurityState, icons: Record<string, string>): string {
    const dataExposure = getDataExposureConfig(config);
    const detectorRows = `
        ${renderAPISecurityToggleSettingRow('Secret Exposure', 'data_exposure.detect_secrets', dataExposure.detect_secrets !== false, icons.lock)}
        ${renderAPISecurityToggleSettingRow('Token Exposure', 'data_exposure.detect_tokens', dataExposure.detect_tokens !== false, icons.shield)}
        ${renderAPISecurityToggleSettingRow('Payment Data', 'data_exposure.detect_payment_data', dataExposure.detect_payment_data !== false, icons.database)}
        ${renderAPISecurityToggleSettingRow('PII Exposure', 'data_exposure.detect_pii', dataExposure.detect_pii !== false, icons.activity)}
        ${renderAPISecurityToggleSettingRow('Debug Data Exposure', 'data_exposure.detect_debug_data', dataExposure.detect_debug_data !== false, icons.fileText)}
        ${renderAPISecurityToggleSettingRow('Internal Data Exposure', 'data_exposure.detect_internal_data', dataExposure.detect_internal_data !== false, icons.list)}
    `;
    return `
        ${SectionUI.renderOperatorSection('Exposure detectors', `<div class="operator-control-list">${detectorRows}</div>`)}
    `;
}

function renderDiscoverySettingsControls(config: APISecurityState, icons: Record<string, string>, inventory: APISecurityEndpoint[]): string {
    const discovery = config.discovery || {};
    const paths = Array.isArray(discovery.paths) ? discovery.paths : [];
    return `
        <div class="operator-control-list">
            ${renderAPISecurityToggleSettingRow('Endpoint Discovery', 'discovery.enabled', discovery.enabled !== false, icons.list)}
            ${renderAPISecurityToggleSettingRow('Shadow API Detection', 'discovery.detect_shadow_apis', discovery.detect_shadow_apis !== false, icons.alert)}
            ${renderAPISecurityToggleSettingRow('Zombie API Detection', 'discovery.detect_zombie_apis', discovery.detect_zombie_apis !== false, icons.fileText)}
        </div>
        <div class="apisecurity-field-grid mt-16">
            <label class="bot-overview-field"><span>Zombie Inactivity Days</span><input type="number" min="1" max="365" value="${Number(discovery.zombie_inactivity_days || 30)}" data-api-path="discovery.zombie_inactivity_days" data-api-value-type="number" data-api-render="true"></label>
        </div>
        ${renderAPISecurityPathListEditor('API Path Patterns', 'discovery.paths', paths, inventory, {
            placeholder: '/api/*'
        })}
    `;
}

function renderAPISecurityToggleSettingRow(title: string, path: string, enabled: boolean, icon: string, description = 'Enable or disable this protection.'): string {
    return SectionUI.renderOperatorControlRow({
        title,
        description,
        icon,
        enabled,
        actions: `<label class="section-switch apisecurity-setting-switch">
                <input type="checkbox" aria-label="${escapeSectionHtml(title)}" ${enabled ? 'checked' : ''} data-api-path="${escapeSectionHtml(path)}" data-api-value-type="checkbox" data-api-render="true">
                <span class="switch-slider"></span>
            </label>`
    });
}


function renderAPISecurityPolicyRow(row: APISecurityPolicyRow): string {
    const mode = normalizeAPISecurityMode(row.mode || 'detect') as 'detect' | 'block';
    const stateControl = row.modePath && row.enabledPath
        ? `
            ${row.modePath ? `
                <select class="apisecurity-inline-select apisecurity-policy-mode-select" aria-label="${escapeSectionHtml(row.title)} mode" data-api-policy-function-state="true" data-api-enabled-path="${escapeSectionHtml(row.enabledPath)}" data-api-mode-path="${escapeSectionHtml(row.modePath)}">
                    <option value="disable" ${!row.enabled ? 'selected' : ''}>Disable</option>
                    <option value="detect" ${row.enabled && mode === 'detect' ? 'selected' : ''}>Monitor</option>
                    <option value="block" ${row.enabled && mode === 'block' ? 'selected' : ''}>Block</option>
                </select>
            ` : ''}
        `
        : row.statePath && row.stateKind === 'boolean'
            ? `
                <select class="apisecurity-inline-select apisecurity-policy-mode-select" aria-label="${escapeSectionHtml(row.title)} state" data-api-policy-boolean-state="true" data-api-state-path="${escapeSectionHtml(row.statePath)}">
                    <option value="disable" ${!row.enabled ? 'selected' : ''}>Disable</option>
                    <option value="block" ${row.enabled ? 'selected' : ''}>Block</option>
                </select>
            `
        : `<span class="config-status-pill tone-neutral">${escapeSectionHtml(row.status || 'Configured')}</span>`;
    const signalContent = row.findings !== undefined || row.blocks !== undefined || row.extra
        ? `<div class="flex align-center gap-8 text-xs text-note">
            ${row.findings !== undefined ? `<span>${formatAPINumber(row.findings)} findings</span>` : ''}
            ${row.blocks !== undefined ? `<span>${formatAPINumber(row.blocks)} blocks</span>` : ''}
            ${row.extra ? `<span>${escapeSectionHtml(row.extra)}</span>` : ''}
        </div>`
        : '';

    return SectionUI.renderOperatorControlRow({
        title: row.title,
        description: row.description,
        icon: row.icon,
        enabled: row.enabled,
        actions: stateControl,
        content: signalContent
    });
}





function renderAPISecurityScopePicker(
    target: APISecurityScopePickerTarget | null,
    filters: APISecurityScopePickerFilters,
    selectedPaths: string[],
    inventory: APISecurityEndpoint[],
    choice: APISecuritySurfaceChoice = 'selected',
    selectedHost: string = ''
): string {
    if (!target) return '';

    const hosts = getScopePickerOptions(inventory, endpoint => endpoint.host || '');
    const methods = getScopePickerOptions(inventory, endpoint => endpoint.method || '');
    const schemas = getScopePickerOptions(inventory, endpoint => endpoint.schema_status || 'unknown');
    const risks = getScopePickerOptions(inventory, endpoint => endpoint.risk_status || 'normal');
    const filtered = getFilteredScopePickerEndpoints(inventory, filters);
    const selectedSet = new Set(selectedPaths);
    const selectedCount = selectedPaths.length;
    const selectedChoice = normalizeAPISecuritySurfaceChoice(choice);
    const allCount = getSurfaceChoicePaths(inventory, 'all', '').length;
    const schemaBackedCount = getSurfaceChoicePaths(inventory, 'schema_backed', '').length;
    const selectedHostCount = selectedHost ? getSurfaceChoicePaths(inventory, 'host', selectedHost).length : 0;
    const manualPathEntry = `
        <div class="apisecurity-scope-manual-entry">
            <label class="bot-overview-field">
                <span>Add exact path</span>
                <input id="apisecurity-scope-manual-path" placeholder="/graphql" autocomplete="off">
            </label>
            <button class="btn btn-primary btn-sm" type="button" data-api-security-action="apply-manual-scope-path">Add path</button>
        </div>
    `;
    const surfaceChoices = `
        <div class="apisecurity-surface-choice-grid">
            <button class="apisecurity-surface-choice ${selectedChoice === 'all' ? 'is-active' : ''}" type="button" data-api-security-action="apply-surface-choice" data-api-surface-choice="all">
                <strong>All discovered APIs</strong>
                <span>${formatAPINumber(allCount)} paths</span>
            </button>
            <button class="apisecurity-surface-choice ${selectedChoice === 'schema_backed' ? 'is-active' : ''}" type="button" data-api-security-action="apply-surface-choice" data-api-surface-choice="schema_backed">
                <strong>Schema-backed APIs</strong>
                <span>${formatAPINumber(schemaBackedCount)} paths</span>
            </button>
            <div class="apisecurity-surface-choice ${selectedChoice === 'host' ? 'is-active' : ''}">
                <strong>Selected host</strong>
                <label class="bot-overview-field">
                    <span>Host</span>
                    <select data-api-surface-host>
                        <option value="">Choose host</option>
                        ${hosts.map(host => `<option value="${escapeSectionHtml(host)}" ${selectedHost === host ? 'selected' : ''}>${escapeSectionHtml(host)}</option>`).join('')}
                    </select>
                </label>
                <button class="btn btn-primary btn-sm" type="button" data-api-security-action="apply-surface-choice" data-api-surface-choice="host" ${!selectedHost ? 'disabled' : ''}>Add ${formatAPINumber(selectedHostCount)} paths</button>
            </div>
            <button class="apisecurity-surface-choice ${selectedChoice === 'selected' ? 'is-active' : ''}" type="button" data-api-security-action="apply-scope-picker" ${selectedCount === 0 ? 'disabled' : ''}>
                <strong>Selected endpoints</strong>
                <span>${formatAPINumber(selectedCount)} selected</span>
            </button>
        </div>
    `;
    const rows = filtered.map(endpoint => {
        const path = endpoint.path || '/';
        const checked = selectedSet.has(path);
        return [
            `<label class="apisecurity-scope-option"><input type="checkbox" ${checked ? 'checked' : ''} data-api-scope-path-option="${escapeSectionHtml(path)}"><span>${escapeSectionHtml(path)}</span></label>`,
            escapeSectionHtml(endpoint.method || '-'),
            escapeSectionHtml(endpoint.host || '-'),
            escapeSectionHtml(labelizeAPIInventoryValue(endpoint.schema_status || 'unknown')),
            escapeSectionHtml(labelizeAPIInventoryValue(endpoint.risk_status || 'normal')),
            `<span class="config-status-pill tone-${endpoint.is_active === false ? 'neutral' : 'success'}">${endpoint.is_active === false ? 'Inactive' : 'Active'}</span>`
        ];
    });
    const content = inventory.length
        ? `
            <div class="apisecurity-scope-picker">
                <div class="apisecurity-scope-picker-head">
                    <div>
                        <strong>${escapeSectionHtml(target.title)}</strong>
                        <span>${target.mode === 'exclude' ? 'Choose APIs to exclude from this policy.' : 'Choose the API surface for this policy.'}</span>
                    </div>
                    <div class="section-action-row">
                        <button class="btn btn-secondary btn-sm" type="button" data-api-security-action="close-scope-picker">Close</button>
                    </div>
                </div>
                ${surfaceChoices}
                <div class="apisecurity-scope-filter-grid">
                    <label class="bot-overview-field">
                        <span>Search</span>
                        <input value="${escapeSectionHtml(filters.search)}" data-api-scope-filter="search" placeholder="/api/users">
                    </label>
                    ${renderScopePickerSelect('Host', 'host', filters.host, hosts)}
                    ${renderScopePickerSelect('Method', 'method', filters.method, methods)}
                    ${renderScopePickerSelect('Schema', 'schema', filters.schema, schemas)}
                    ${renderScopePickerSelect('Risk', 'risk', filters.risk, risks)}
                    ${renderScopePickerSelect('State', 'active', filters.active, ['active', 'inactive'])}
                </div>
                ${manualPathEntry}
                ${SectionUI.renderEnterpriseTable({
                    columns: ['Path', 'Method', 'Host', 'Schema', 'Risk', 'State'],
                    rows,
                    emptyTitle: 'No endpoints match these filters',
                    emptyMessage: 'Adjust the filters or add wildcard paths in Settings.',
                    className: 'apisecurity-scope-picker-table'
                })}
            </div>
        `
        : `
            <div class="apisecurity-scope-picker">
                <div class="section-empty-state">
                    <div class="section-empty-title">No discovered endpoints yet</div>
                    <div class="section-empty-sub">Add the exact GraphQL endpoint path below. Discovered endpoints will appear here when inventory data is available.</div>
                </div>
                ${manualPathEntry}
                <div class="section-action-row mt-16"><button class="btn btn-secondary btn-sm" type="button" data-api-security-action="close-scope-picker">Close</button></div>
            </div>
        `;

    return SectionUI.renderOperatorSection('Scope picker', content, {
        subtitle: 'Inventory-backed endpoint selection. Host and method are only filters; the saved value is the endpoint path.'
    });
}

function renderScopePickerSelect(label: string, key: keyof APISecurityScopePickerFilters, value: string, options: string[]): string {
    return `
        <label class="bot-overview-field">
            <span>${escapeSectionHtml(label)}</span>
            <select data-api-scope-filter="${key}">
                <option value="all" ${value === 'all' || value === '' ? 'selected' : ''}>All</option>
                ${options.map(option => `<option value="${escapeSectionHtml(option)}" ${value === option ? 'selected' : ''}>${escapeSectionHtml(labelizeAPIInventoryValue(option))}</option>`).join('')}
            </select>
        </label>
    `;
}




function deriveAPISecurityProfile(config: APISecurityState, key: APISecurityProfileKey): APISecurityProfileValue {
    const normalized = normalizeAPISecurityConfig(config);
    if (key === 'runtime') {
        const injection = getInjectionConfig(normalized);
        const ssrf = getSSRFConfig(normalized);
        const payload = getPayloadAbuseConfig(normalized);
        const allVectorsOn = [injection.sqli, injection.nosqli, injection.cmdi, injection.xss].every(value => value !== false);
        const ssrfDefaults = ssrf.block_private_networks !== false && ssrf.block_cloud_metadata !== false;
        if (allVectorsOn && ssrfDefaults && injection.sensitivity === 'medium' && normalizePayloadSensitivity(payload.sensitivity) === 'balanced') return 'default';
        if (allVectorsOn && ssrfDefaults && injection.sensitivity === 'high' && normalizePayloadSensitivity(payload.sensitivity) === 'strict') return 'strict';
    }
    if (key === 'graphql') {
        const graphql = getGraphQLConfig(normalized);
        if (graphql.enabled !== false && normalizeAPISecurityMode(String(graphql.mode || 'detect')) === 'detect' && graphql.block_introspection === false) return 'monitor';
        if (graphql.max_depth === 15 && graphql.max_aliases === 25 && graphql.max_batch_size === 5 && graphql.max_complexity === 500 && graphql.block_introspection !== false) return 'default';
        if (graphql.max_depth === 10 && graphql.max_aliases === 10 && graphql.max_batch_size === 3 && graphql.max_complexity === 250 && graphql.block_introspection !== false) return 'strict';
    }
    if (key === 'contract') {
        const validation = getValidationConfig(normalized);
        const enabled = validation.enabled !== false;
        const mode = normalizeAPISecurityMode(validation.mode || 'detect');
        const methodAndContentTypeOn = validation.block_invalid_methods !== false && validation.block_invalid_content_types !== false;
        if (enabled && mode === 'detect' && validation.block_unknown_endpoints === false && validation.block_invalid_methods === false && validation.block_invalid_content_types === false) return 'monitor';
        if (enabled && mode === 'detect' && methodAndContentTypeOn && validation.block_unknown_endpoints !== true) return 'default';
        if (enabled && mode === 'block' && methodAndContentTypeOn && validation.block_unknown_endpoints === true) return 'strict';
    }
    if (key === 'authorization') {
        const bfla = normalized.bfla || {};
        const massAssignment = normalized.mass_assignment || {};
        const bola = normalized.bola || {};
        const groups = [bfla, massAssignment, bola];
        const allEnabled = groups.every(group => group.enabled !== false);
        const modes = groups.map(group => normalizeAPISecurityMode(String(group.mode || 'detect')));
        if (allEnabled && modes.every(mode => mode === 'detect')) return 'default';
        if (allEnabled && modes.every(mode => mode === 'block')) return 'strict';
    }
    if (key === 'automation') {
        return normalizeAutomationSensitivity(getAutomationAbuseConfig(normalized).sensitivity) === 'strict' ? 'strict' : 'default';
    }
    if (key === 'data') {
        return normalizeDataExposureSensitivity(getDataExposureConfig(normalized).sensitivity) === 'strict' ? 'strict' : 'default';
    }
    return 'custom';
}

function applyAPISecurityMonitorProfile(config: APISecurityState, key: APISecurityProfileKey): APISecurityState {
    const next = normalizeAPISecurityConfig(config);
    const policyId = getAPISecurityPolicyIdForProfileKey(key);
    if (policyId) {
        getAPISecurityPolicyFunctionKeys(policyId).forEach(functionKey => {
            setAPISecurityConfigValue(next, `${functionKey}.enabled`, true);
            setAPISecurityConfigValue(next, `${functionKey}.mode`, 'detect');
            setAPISecurityConfigValue(next, `enabled_functions.${functionKey}`, true);
            setAPISecurityConfigValue(next, `function_settings.${functionKey}.mode`, 'detect');
        });
    }
    if (key === 'contract') {
        next.validation = {
            ...(next.validation || {}),
            enabled: true,
            mode: 'detect',
            block_unknown_endpoints: false,
            block_invalid_methods: false,
            block_invalid_content_types: false
        };
        setAPISecurityConfigValue(next, 'function_settings.validation.block_unknown_endpoints', false);
        setAPISecurityConfigValue(next, 'function_settings.validation.block_invalid_methods', false);
        setAPISecurityConfigValue(next, 'function_settings.validation.block_invalid_content_types', false);
    }
    if (key === 'graphql') {
        next.graphql = {
            ...(next.graphql || {}),
            enabled: true,
            mode: 'detect',
            block_introspection: false
        };
        setAPISecurityConfigValue(next, 'function_settings.graphql.block_introspection', false);
    }
    if (key === 'authorization') {
        next.bfla = { ...(next.bfla || {}), enabled: true, mode: 'detect' };
        next.mass_assignment = { ...(next.mass_assignment || {}), enabled: true, mode: 'detect' };
        next.bola = { ...(next.bola || {}), enabled: true, mode: 'detect' };
    }
    if (key === 'runtime') {
        next.injection = { ...(next.injection || {}), enabled: true, mode: 'detect' };
        next.ssrf = { ...(next.ssrf || {}), enabled: true, mode: 'detect' };
        next.payload_abuse = { ...(next.payload_abuse || {}), enabled: true, mode: 'detect' };
    }
    if (key === 'automation') {
        next.automation_abuse = { ...(next.automation_abuse || {}), enabled: true, mode: 'detect' };
    }
    if (key === 'data') {
        next.data_exposure = { ...(next.data_exposure || {}), enabled: true, mode: 'detect' };
    }
    return normalizeAPISecurityConfig(next);
}

function applyAPISecurityProfile(config: APISecurityState, key: APISecurityProfileKey, value: APISecurityProfileValue): APISecurityState {
    const next = normalizeAPISecurityConfig(config);
    if (value === 'custom') return next;
    if (value === 'monitor') return applyAPISecurityMonitorProfile(next, key);
    if (key === 'runtime') {
        next.injection = {
            ...(next.injection || {}),
            sqli: true,
            nosqli: true,
            cmdi: true,
            xss: true,
            sensitivity: value === 'strict' ? 'high' : 'medium'
        };
        setAPISecurityConfigValue(next, 'function_settings.injection.sqli', true);
        setAPISecurityConfigValue(next, 'function_settings.injection.nosqli', true);
        setAPISecurityConfigValue(next, 'function_settings.injection.cmdi', true);
        setAPISecurityConfigValue(next, 'function_settings.injection.xss', true);
        setAPISecurityConfigValue(next, 'function_settings.injection.sensitivity', value === 'strict' ? 'high' : 'medium');
        next.ssrf = {
            ...(next.ssrf || {}),
            block_private_networks: true,
            block_cloud_metadata: true
        };
        setAPISecurityConfigValue(next, 'function_settings.ssrf.block_private_networks', true);
        setAPISecurityConfigValue(next, 'function_settings.ssrf.block_cloud_metadata', true);
        next.payload_abuse = {
            ...(next.payload_abuse || {}),
            sensitivity: value === 'strict' ? 'strict' : 'balanced'
        };
        setAPISecurityConfigValue(next, 'function_settings.payload_abuse.sensitivity', value === 'strict' ? 'strict' : 'balanced');
    }
    if (key === 'graphql') {
        next.graphql = {
            ...(next.graphql || {}),
            max_depth: value === 'strict' ? 10 : 15,
            max_aliases: value === 'strict' ? 10 : 25,
            max_batch_size: value === 'strict' ? 3 : 5,
            max_complexity: value === 'strict' ? 250 : 500,
            block_introspection: true
        };
        setAPISecurityConfigValue(next, 'function_settings.graphql.max_depth', value === 'strict' ? 10 : 15);
        setAPISecurityConfigValue(next, 'function_settings.graphql.max_aliases', value === 'strict' ? 10 : 25);
        setAPISecurityConfigValue(next, 'function_settings.graphql.max_batch_size', value === 'strict' ? 3 : 5);
        setAPISecurityConfigValue(next, 'function_settings.graphql.max_complexity', value === 'strict' ? 250 : 500);
        setAPISecurityConfigValue(next, 'function_settings.graphql.block_introspection', true);
    }
    if (key === 'contract') {
        next.validation = {
            ...(next.validation || {}),
            enabled: true,
            mode: value === 'strict' ? 'block' : 'detect',
            block_unknown_endpoints: value === 'strict',
            block_invalid_methods: true,
            block_invalid_content_types: true
        };
        setAPISecurityConfigValue(next, 'enabled_functions.validation', true);
        setAPISecurityConfigValue(next, 'function_settings.validation.mode', value === 'strict' ? 'block' : 'detect');
        setAPISecurityConfigValue(next, 'function_settings.validation.block_unknown_endpoints', value === 'strict');
        setAPISecurityConfigValue(next, 'function_settings.validation.block_invalid_methods', true);
        setAPISecurityConfigValue(next, 'function_settings.validation.block_invalid_content_types', true);
    }
    if (key === 'authorization') {
        const mode = value === 'strict' ? 'block' : 'detect';
        next.bfla = {
            ...(next.bfla || {}),
            enabled: true,
            mode
        };
        setAPISecurityConfigValue(next, 'enabled_functions.bfla', true);
        setAPISecurityConfigValue(next, 'function_settings.bfla.mode', mode);
        next.mass_assignment = {
            ...(next.mass_assignment || {}),
            enabled: true,
            mode
        };
        setAPISecurityConfigValue(next, 'enabled_functions.mass_assignment', true);
        setAPISecurityConfigValue(next, 'function_settings.mass_assignment.mode', mode);
        next.bola = {
            ...(next.bola || {}),
            enabled: true,
            mode
        };
        setAPISecurityConfigValue(next, 'enabled_functions.bola', true);
        setAPISecurityConfigValue(next, 'function_settings.bola.mode', mode);
    }
    if (key === 'automation') {
        next.automation_abuse = {
            ...(next.automation_abuse || {}),
            sensitivity: value === 'strict' ? 'strict' : 'balanced'
        };
        setAPISecurityConfigValue(next, 'function_settings.automation_abuse.sensitivity', value === 'strict' ? 'strict' : 'balanced');
    }
    if (key === 'data') {
        next.data_exposure = {
            ...(next.data_exposure || {}),
            sensitivity: value === 'strict' ? 'strict' : 'balanced'
        };
        setAPISecurityConfigValue(next, 'function_settings.data_exposure.sensitivity', value === 'strict' ? 'strict' : 'balanced');
    }
    return normalizeAPISecurityConfig(next);
}

const API_SECURITY_SCOPE_PICKER_PATHS = new Set([
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

const API_SECURITY_STRING_LIST_PATHS = new Set([
    ...API_SECURITY_SCOPE_PICKER_PATHS,
    'auth_tokens.required_claims',
    'automation_abuse.identifier_fields',
    'mass_assignment.protected_fields'
]);

function normalizeAPISecurityStringListPath(path: string): string {
    const normalizedPath = String(path || '').trim();
    return API_SECURITY_STRING_LIST_PATHS.has(normalizedPath) ? normalizedPath : '';
}

function isSupportedAPISecurityScopePath(path: string): boolean {
    return API_SECURITY_SCOPE_PICKER_PATHS.has(path);
}

function getAPISecurityStringListAtPath(config: APISecurityState, path: string): string[] {
    const value = path.split('.').reduce<unknown>((current, part) => {
        if (typeof current !== 'object' || current === null) return undefined;
        return (current as Record<string, unknown>)[part];
    }, config);
    return normalizeStringList(value, []);
}

function getAPISecurityFunctionSettingsMirrorPath(path: string): string {
    const [root, ...rest] = path.split('.');
    if (!root || rest.length === 0) return '';
    if (!isAPISecurityFunctionConfigKey(root)) return '';
    return `function_settings.${root}.${rest.join('.')}`;
}

function setAPISecurityStringListAtPath(config: APISecurityState, path: string, items: string[]): APISecurityState {
    const normalizedPath = normalizeAPISecurityStringListPath(path);
    if (!normalizedPath) return normalizeAPISecurityConfig(config);
    const next = normalizeAPISecurityConfig(config);
    const list = normalizeStringList(items, []);
    setAPISecurityConfigValue(next, normalizedPath, list);
    const mirrorPath = getAPISecurityFunctionSettingsMirrorPath(normalizedPath);
    if (mirrorPath) setAPISecurityConfigValue(next, mirrorPath, list);
    return normalizeAPISecurityConfig(next);
}

function mergeAPISecurityStringLists(primary: string[], secondary: string[]): string[] {
    const seen = new Set<string>();
    return [...primary, ...secondary]
        .map(item => String(item || '').trim())
        .filter(Boolean)
        .filter(item => {
            if (seen.has(item)) return false;
            seen.add(item);
            return true;
        });
}

function normalizeAPISecurityWizardId(value: unknown): APISecurityWizardId {
    const id = String(value || '').trim();
    if (id === 'schema' || id === 'identity' || id === 'data') return id;
    return '';
}

function getAPISecurityWizardMaxStep(wizard: APISecurityWizardId): number {
    if (wizard === 'schema' || wizard === 'identity') return 3;
    if (wizard === 'data') return 2;
    return 1;
}

function normalizeAPISecuritySurfaceChoice(value: unknown): APISecuritySurfaceChoice {
    const choice = String(value || '').trim();
    if (choice === 'all' || choice === 'schema_backed' || choice === 'host' || choice === 'manual') return choice;
    return 'selected';
}

function getSurfaceChoicePaths(inventory: APISecurityEndpoint[], choice: APISecuritySurfaceChoice, host: string): string[] {
    const selectedHost = String(host || '').trim();
    let endpoints = inventory;
    if (choice === 'schema_backed') {
        endpoints = inventory.filter(endpoint => getEndpointSchemaStatus(endpoint) === 'covered');
    } else if (choice === 'host') {
        endpoints = selectedHost ? inventory.filter(endpoint => String(endpoint.host || '') === selectedHost) : [];
    } else if (choice !== 'all') {
        endpoints = [];
    }
    return mergeAPISecurityStringLists([], endpoints.map(endpoint => endpoint.path || '').filter(Boolean));
}

function getSelectedScopePathsInInventoryOrder(inventory: APISecurityEndpoint[], selectedPaths: string[]): string[] {
    const selected = new Set(selectedPaths);
    const ordered = mergeAPISecurityStringLists(
        inventory.map(endpoint => endpoint.path || '').filter(path => selected.has(path)),
        []
    );
    const missingFromInventory = selectedPaths.filter(path => !ordered.includes(path));
    return mergeAPISecurityStringLists(ordered, missingFromInventory);
}

function getScopePickerOptions(inventory: APISecurityEndpoint[], read: (endpoint: APISecurityEndpoint) => string): string[] {
    return mergeAPISecurityStringLists([], inventory.map(read).filter(Boolean)).sort((a, b) => a.localeCompare(b));
}

function getFilteredScopePickerEndpoints(inventory: APISecurityEndpoint[], filters: APISecurityScopePickerFilters): APISecurityEndpoint[] {
    const search = String(filters.search || '').trim().toLowerCase();
    return inventory.filter(endpoint => {
        const path = endpoint.path || '';
        const method = endpoint.method || '';
        const host = endpoint.host || '';
        const schema = endpoint.schema_status || 'unknown';
        const risk = endpoint.risk_status || 'normal';
        const active = endpoint.is_active === false ? 'inactive' : 'active';
        if (search && ![path, method, host, schema, risk].some(value => value.toLowerCase().includes(search))) return false;
        if (filters.host && filters.host !== 'all' && host !== filters.host) return false;
        if (filters.method && filters.method !== 'all' && method !== filters.method) return false;
        if (filters.schema && filters.schema !== 'all' && schema !== filters.schema) return false;
        if (filters.risk && filters.risk !== 'all' && risk !== filters.risk) return false;
        if (filters.active && filters.active !== 'all' && active !== filters.active) return false;
        return true;
    });
}









function parseAPISecurityValue(
    element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
): unknown {
    const type = element.dataset.apiValueType || 'string';

    if (type === 'checkbox' && element instanceof HTMLInputElement) {
        return element.checked;
    }

    if (type === 'number') {
        const parsed = Number.parseInt(element.value, 10);
        return Number.isFinite(parsed) ? parsed : 0;
    }

    if (type === 'csv') {
        return element.value.split(',').map((part) => part.trim()).filter(Boolean);
    }

    return element.value;
}

function parseAPISecurityDatasetValue(value: string, type: string): unknown {
    if (type === 'checkbox') return value === 'true';
    if (type === 'number') {
        const parsed = Number.parseInt(value, 10);
        return Number.isFinite(parsed) ? parsed : 0;
    }
    return value;
}

function openAPISecurityDashboardInvestigation(target: HTMLElement): void {
    const rawHost = target.dataset.dashboardHost || '';
    const host = (rawHost === 'All hosts' || rawHost === 'unknown host') ? '' : rawHost;
    const filters: Record<string, string> = {};

    const addIfPresent = (key: string, value?: string) => {
        const val = String(value || '').trim();
        if (val && val !== 'all') {
            filters[key] = val;
        }
    };

    addIfPresent('section', target.dataset.dashboardSection || 'api_security');
    addIfPresent('path', target.dataset.dashboardPath);
    addIfPresent('method', target.dataset.dashboardMethod);
    addIfPresent('host', host);
    addIfPresent('action', target.dataset.dashboardAction);
    addIfPresent('module', target.dataset.dashboardModule);
    addIfPresent('function', target.dataset.dashboardFunction);
    addIfPresent('threat_type', target.dataset.dashboardThreat);
    addIfPresent('severity', target.dataset.dashboardSeverity);
    addIfPresent('mode', target.dataset.dashboardMode);
    addIfPresent('direction', target.dataset.dashboardDirection);
    addIfPresent('data_class', target.dataset.dashboardDataClass);
    addIfPresent('response_action', target.dataset.dashboardResponseAction);
    addIfPresent('ip', target.dataset.dashboardIp);
    addIfPresent('status', target.dataset.dashboardStatus);
    addIfPresent('rule_id', target.dataset.dashboardRule);
    addIfPresent('request_id', target.dataset.dashboardRequest);

    window.sessionStorage.setItem(APISEC_DASHBOARD_PENDING_FILTERS_KEY, JSON.stringify({
        window: '24h',
        filters
    }));
    router.dashboardTab = 'security';
    router.navigate('dashboard');
}

function consumeAPISecurityConfigFocus(runtime: APISecurityConfigRuntime): void {
    const raw = window.sessionStorage.getItem(APISEC_CONFIG_PENDING_FOCUS_KEY);
    if (!raw) return;
    window.sessionStorage.removeItem(APISEC_CONFIG_PENDING_FOCUS_KEY);
    try {
        const focus = JSON.parse(raw) as { tab?: string; method?: string; host?: string; path?: string };
        if (isAPISecurityTabId(focus.tab)) {
            runtime.currentTab = focus.tab;
            runtime.selectedPolicyId = isAPISecurityPolicyId(focus.tab) ? focus.tab : '';
        } else if (isAPISecurityPolicyId(focus.tab)) {
            runtime.currentTab = focus.tab;
            runtime.selectedPolicyId = focus.tab;
        }
        if (focus.path) {
            const method = String(focus.method || '').toUpperCase();
            const host = String(focus.host || '').toLowerCase();
            const path = String(focus.path || '');
            const endpoint = runtime.inventory.find(item => {
                const methodMatch = !method || String(item.method || '').toUpperCase() === method;
                const hostMatch = !host || String(item.host || '').toLowerCase() === host;
                return methodMatch && hostMatch && String(item.path || '') === path;
            });
            if (endpoint) {
                runtime.selectedInventoryEndpointKey = getInventoryEndpointKey(endpoint);
            }
        }
    } catch {
        // Ignore malformed focus state from another session.
    }
}

function isAPISecurityTabId(value: unknown): value is APISecurityTabId {
    return ['overview', 'inventory', 'runtime', 'contract', 'authorization', 'graphql', 'abuse', 'data', 'settings'].includes(String(value || ''));
}

function normalizeAPISecurityPolicyEditorTab(value: unknown): APISecurityPolicyEditorTab {
    const tab = String(value || '').trim();
    return ['basics', 'scope', 'detections', 'exceptions'].includes(tab)
        ? tab as APISecurityPolicyEditorTab
        : 'basics';
}

function ensureAPISecurityBindings(): void {
    if (apiSecurityBindingsInitialized) return;
    apiSecurityBindingsInitialized = true;

    AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-api-security-action]', (_event, target) => {
        const action = target.dataset.apiSecurityAction;
        const tabId = target.dataset.apiTab;

        switch (action) {
            case 'switch-tab':
                if (tabId) APISecurityConfig.switchTab(tabId);
                break;
            case 'switch-settings-category':
                APISecurityConfig.switchSettingsCategory(target.dataset.apiSettingsCategory || '');
                break;
            case 'open-settings-category':
                APISecurityConfig.openSettingsCategory(target.dataset.apiSettingsCategory || '');
                break;
            case 'close-settings-category':
                APISecurityConfig.closeSettingsCategory();
                break;
            case 'open-edge-access':
                router.navigate('access_config');
                break;
            case 'switch-policy-editor-tab':
                APISecurityConfig.switchPolicyEditorTab(target.dataset.apiPolicyEditorTab || '');
                break;
            case 'open-authorization-control':
                APISecurityConfig.openAuthorizationControl(target.dataset.apiAuthorizationControl || '');
                break;
            case 'close-authorization-control':
                APISecurityConfig.closeAuthorizationControl();
                break;
            case 'open-graphql-control':
                APISecurityConfig.openGraphQLControl(target.dataset.apiGraphqlControl || '');
                break;
            case 'close-graphql-control':
                APISecurityConfig.closeGraphQLControl();
                break;
            case 'set-config-field':
                APISecurityConfig.requestConfigFieldUpdate(
                    target.dataset.apiPath || '',
                    parseAPISecurityDatasetValue(target.dataset.apiValue || '', target.dataset.apiValueType || 'string'),
                    true
                );
                break;
            case 'open-policy-detail':
                APISecurityConfig.openPolicyDetail(target.dataset.apiPolicyId || '');
                break;
            case 'close-policy-detail':
                APISecurityConfig.closePolicyDetail();
                break;
            case 'confirm-policy-mode':
                APISecurityConfig.confirmPolicyMode();
                break;
            case 'cancel-policy-mode':
                APISecurityConfig.cancelPolicyMode();
                break;
            case 'focus-setup':
                APISecurityConfig.focusSetup(target.dataset.apiSetupFocus || '');
                break;
            case 'open-wizard':
                APISecurityConfig.openWizard(target.dataset.apiWizard || '');
                break;
            case 'close-wizard':
                APISecurityConfig.closeWizard();
                break;
            case 'set-wizard-step':
                APISecurityConfig.setWizardStep(Number(target.dataset.apiWizardStep || 1));
                break;
            case 'apply-schema-wizard':
                void APISecurityConfig.applySchemaWizard();
                break;
            case 'apply-identity-wizard':
                APISecurityConfig.applyIdentityWizard();
                break;
            case 'apply-data-wizard':
                APISecurityConfig.applyDataWizard();
                break;
            case 'reset':
                void APISecurityConfig.loadConfig()
                    .then(() => APISecurityConfig.render())
                    .finally(() => SectionUI.markSaveActionBarClean('data-api-security-action'));
                break;
            case 'save':
                void APISecurityConfig.saveConfig();
                break;
            case 'upload-schema':
                void APISecurityConfig.uploadSchema();
                break;
            case 'open-scope-picker':
                APISecurityConfig.openScopePicker(
                    target.dataset.apiScopePath || '',
                    target.dataset.apiScopeTitle || '',
                    target.dataset.apiScopeMode || 'include',
                    target.dataset.apiTab || ''
                );
                break;
            case 'close-scope-picker':
                APISecurityConfig.closeScopePicker();
                break;
            case 'apply-scope-picker':
                APISecurityConfig.applyScopePickerSelection();
                break;
            case 'apply-manual-scope-path': {
                const input = AdminDOM.getById<HTMLInputElement>('apisecurity-scope-manual-path');
                APISecurityConfig.applyManualScopePath(input?.value || '');
                break;
            }
            case 'apply-surface-choice':
                APISecurityConfig.applyScopePickerChoice(target.dataset.apiSurfaceChoice || 'selected');
                break;
            case 'open-block-review':
                APISecurityConfig.openBlockingReview(
                    target.dataset.apiModuleKey || '',
                    target.dataset.apiFunctionKey || '',
                    target.dataset.apiReviewTitle || '',
                    target.dataset.apiModePath || '',
                    target.dataset.apiTab || ''
                );
                break;
            case 'close-block-review':
                APISecurityConfig.closeBlockingReview();
                break;
            case 'confirm-block-mode':
                APISecurityConfig.confirmBlockMode();
                break;
            case 'open-inventory-endpoint':
                APISecurityConfig.openInventoryEndpoint(target.dataset.apiEndpointKey || '');
                break;
            case 'load-more-inventory':
                void APISecurityConfig.loadMoreInventory();
                break;
            case 'close-inventory-endpoint':
                APISecurityConfig.closeInventoryEndpoint();
                break;
            case 'set-inventory-triage':
                APISecurityConfig.setInventoryTriageState(target.dataset.apiEndpointKey || '', target.dataset.apiTriageState || '');
                break;
            case 'prefill-schema-endpoint':
                APISecurityConfig.prefillSchemaFromEndpoint(target.dataset.apiEndpointKey || '');
                break;
            case 'toggle-inventory-filter-menu':
                APISecurityConfig.toggleInventoryFilterMenu();
                break;
            case 'toggle-inventory-view-menu':
                APISecurityConfig.toggleInventoryViewMenu();
                break;
            case 'save-inventory-view': {
                const menu = target.closest<HTMLElement>('.apisecurity-inventory-view-popover');
                const input = menu?.querySelector<HTMLInputElement>('[data-api-inventory-view-name]');
                APISecurityConfig.saveInventoryView(input?.value || '');
                break;
            }
            case 'apply-inventory-view':
                APISecurityConfig.applyInventoryView(target.dataset.apiInventoryViewId || '');
                break;
            case 'delete-inventory-view':
                APISecurityConfig.deleteInventoryView(target.dataset.apiInventoryViewId || '');
                break;
            case 'apply-inventory-recent-filter':
                APISecurityConfig.applyInventoryRecentFilter(target.dataset.apiInventoryRecentFilterId || '');
                break;
            case 'apply-graphql-preset':
                APISecurityConfig.applyGraphQLPreset(target.dataset.apiGraphqlPreset || '');
                break;
            case 'toggle-inventory-column':
                APISecurityConfig.toggleInventoryColumn(target.dataset.apiInventoryColumn || '');
                break;
            case 'clear-inventory-filter':
                APISecurityConfig.clearInventoryFilter(target.dataset.apiInventoryFilterKey || '');
                break;
            case 'clear-inventory-filters':
                APISecurityConfig.clearInventoryFilters();
                break;
            case 'add-string-list-item': {
                const path = target.dataset.apiStringListPath || '';
                const editor = target.closest<HTMLElement>('[data-api-string-list-editor]');
                const input = editor?.querySelector<HTMLInputElement>('[data-api-string-list-new]');
                APISecurityConfig.addStringListItem(path, input?.value || '');
                break;
            }
            case 'remove-string-list-item':
                APISecurityConfig.removeStringListItem(target.dataset.apiStringListPath || '', Number(target.dataset.apiStringListIndex || 0));
                break;
            case 'toggle-string-list-value': {
                const path = target.dataset.apiStringListPath || '';
                const itemIndex = Number(target.dataset.apiStringListIndex ?? -1);
                if (itemIndex >= 0) {
                    APISecurityConfig.removeStringListItem(path, itemIndex);
                } else {
                    APISecurityConfig.addStringListItem(path, target.dataset.apiStringListValue || '');
                }
                break;
            }
            case 'add-nested-list-item': {
                const editor = target.closest<HTMLElement>('[data-api-nested-list-editor]');
                const input = editor?.querySelector<HTMLInputElement>('[data-api-nested-list-new]');
                APISecurityConfig.addNestedListItem(
                    target.dataset.apiNestedListKind as APISecurityNestedListKind,
                    Number(target.dataset.apiNestedListParentIndex || 0),
                    target.dataset.apiNestedListField || '',
                    input?.value || ''
                );
                break;
            }
            case 'remove-nested-list-item':
                APISecurityConfig.removeNestedListItem(
                    target.dataset.apiNestedListKind as APISecurityNestedListKind,
                    Number(target.dataset.apiNestedListParentIndex || 0),
                    target.dataset.apiNestedListField || '',
                    Number(target.dataset.apiNestedListIndex || 0)
                );
                break;
            case 'toggle-nested-list-value': {
                const itemIndex = Number(target.dataset.apiNestedListIndex ?? -1);
                const parentIndex = Number(target.dataset.apiNestedListParentIndex || 0);
                const field = target.dataset.apiNestedListField || '';
                const kind = target.dataset.apiNestedListKind as APISecurityNestedListKind;
                if (itemIndex >= 0) {
                    APISecurityConfig.removeNestedListItem(kind, parentIndex, field, itemIndex);
                } else {
                    APISecurityConfig.addNestedListItem(kind, parentIndex, field, target.dataset.apiNestedListValue || '');
                }
                break;
            }
            case 'investigate-dashboard':
                openAPISecurityDashboardInvestigation(target);
                break;
            case 'add-bola-rule':
                APISecurityConfig.addBolaRule();
                SectionUI.markSaveActionBarDirty('data-api-security-action');
                break;
            case 'toggle-bola-rule-editor':
                APISecurityConfig.toggleBolaRuleEditor(Number(target.dataset.apiBolaRuleIndex || 0));
                break;
            case 'remove-bola-rule':
                APISecurityConfig.removeBolaRule(Number(target.dataset.apiBolaRuleIndex || 0));
                break;
            case 'add-auth-issuer':
                APISecurityConfig.addAuthIssuer();
                SectionUI.markSaveActionBarDirty('data-api-security-action');
                break;
            case 'remove-auth-issuer':
                APISecurityConfig.removeAuthIssuer(Number(target.dataset.apiAuthIssuerIndex || 0));
                break;
            case 'add-bfla-rule':
                APISecurityConfig.addBFLARule();
                SectionUI.markSaveActionBarDirty('data-api-security-action');
                break;
            case 'toggle-bfla-rule-editor':
                APISecurityConfig.toggleBFLARuleEditor(Number(target.dataset.apiBflaRuleIndex || 0));
                break;
            case 'remove-bfla-rule':
                APISecurityConfig.removeBFLARule(Number(target.dataset.apiBflaRuleIndex || 0));
                break;
            case 'add-mass-rule':
                APISecurityConfig.addMassAssignmentPathRule();
                SectionUI.markSaveActionBarDirty('data-api-security-action');
                break;
            case 'toggle-mass-rule-editor':
                APISecurityConfig.toggleMassRuleEditor(Number(target.dataset.apiMassRuleIndex || 0));
                break;
            case 'remove-mass-rule':
                APISecurityConfig.removeMassAssignmentPathRule(Number(target.dataset.apiMassRuleIndex || 0));
                break;
            default:
                break;
        }
    });

    AdminEvents.delegateEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(
        document,
        'change',
        '[data-api-path]',
        (_event, target) => {
            const path = target.dataset.apiPath;
            if (!path) return;

            APISecurityConfig.requestConfigFieldUpdate(path, parseAPISecurityValue(target), target.dataset.apiRender === 'true');
        }
    );

    AdminEvents.delegateEvent<HTMLSelectElement>(
        document,
        'change',
        '#apisecurity-schema-endpoint',
        (_event, target) => {
            const endpoint = target.value === '' ? null : APISecurityConfig.inventory[Number(target.value)] || null;
            const methodInput = AdminDOM.getById<HTMLInputElement>('apisecurity-schema-method');
            const pathInput = AdminDOM.getById<HTMLInputElement>('apisecurity-schema-path');
            const hostInput = AdminDOM.getById<HTMLInputElement>('apisecurity-schema-host');
            const typeInput = AdminDOM.getById<HTMLSelectElement>('apisecurity-schema-type');
            if (!methodInput || !pathInput || !hostInput) return;

            methodInput.value = endpoint?.method || 'GET';
            pathInput.value = endpoint?.path || '';
            hostInput.value = endpoint?.host || '';
            methodInput.readOnly = Boolean(endpoint);
            pathInput.readOnly = Boolean(endpoint);
            hostInput.readOnly = Boolean(endpoint);

            if (typeInput && endpoint) {
                const rawSchemaType = String(endpoint.schema_type || '').toLowerCase();
                const isGraphQL = rawSchemaType.includes('graphql') || String(endpoint.path || '').toLowerCase().includes('graphql');
                typeInput.value = isGraphQL ? 'graphql' : 'openapi';
            }
        }
    );

    AdminEvents.delegateEvent<HTMLSelectElement>(
        document,
        'change',
        '[data-api-policy-function-state]',
        (_event, target) => {
            APISecurityConfig.setPolicyFunctionState(
                target.dataset.apiEnabledPath || '',
                target.dataset.apiModePath || '',
                target.value
            );
        }
    );

    AdminEvents.delegateEvent<HTMLSelectElement>(
        document,
        'change',
        '[data-api-policy-boolean-state]',
        (_event, target) => {
            APISecurityConfig.setPolicyBooleanState(
                target.dataset.apiStatePath || '',
                target.value
            );
        }
    );


    AdminEvents.delegateEvent<HTMLInputElement>(
        document,
        'change',
        '[data-api-string-list-index]',
        (_event, target) => {
            APISecurityConfig.updateStringListItem(
                target.dataset.apiStringListPath || '',
                Number(target.dataset.apiStringListIndex || 0),
                target.value
            );
        }
    );

    AdminEvents.delegateEvent<HTMLSelectElement>(
        document,
        'change',
        '[data-api-string-list-picker]',
        (_event, target) => {
            if (!target.value) return;
            APISecurityConfig.addStringListItem(target.dataset.apiStringListPicker || '', target.value);
        }
    );

    AdminEvents.delegateEvent<HTMLSelectElement>(
        document,
        'change',
        '[data-api-nested-list-picker]',
        (_event, target) => {
            if (!target.value) return;
            APISecurityConfig.addNestedListItem(
                target.dataset.apiNestedListKind as APISecurityNestedListKind,
                Number(target.dataset.apiNestedListParentIndex || 0),
                target.dataset.apiNestedListField || '',
                target.value
            );
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement>(
        document,
        'change',
        '[data-api-nested-list-index]',
        (_event, target) => {
            APISecurityConfig.updateNestedListItem(
                target.dataset.apiNestedListKind as APISecurityNestedListKind,
                Number(target.dataset.apiNestedListParentIndex || 0),
                target.dataset.apiNestedListField || '',
                Number(target.dataset.apiNestedListIndex || 0),
                target.value
            );
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement>(
        document,
        'change',
        '[data-api-policy-enabled]',
        (_event, target) => {
            APISecurityConfig.setPolicyEnabled(target.dataset.apiPolicyEnabled || '', target.checked);
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement>(
        document,
        'change',
        '[data-api-section-enabled]',
        (_event, target) => {
            APISecurityConfig.sectionEnabled = target.checked;
            APISecurityConfig.render();
            SectionUI.markSaveActionBarDirty('data-api-security-action');
        }
    );


    AdminEvents.delegateEvent<HTMLElement>(document, 'keydown', '[data-api-security-action="switch-tab"]', (event, target) => {
        if (!(event instanceof KeyboardEvent)) return;
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        const tabId = target.dataset.apiTab;
        if (tabId) APISecurityConfig.switchTab(tabId);
    });

    AdminEvents.delegateEvent<HTMLElement>(document, 'keydown', '[data-api-security-action="open-policy-detail"]', (event, target) => {
        if (!(event instanceof KeyboardEvent)) return;
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        APISecurityConfig.openPolicyDetail(target.dataset.apiPolicyId || '');
    });

    AdminEvents.delegateEvent<HTMLElement>(document, 'keydown', '[data-api-security-action="open-settings-category"]', (event, target) => {
        if (!(event instanceof KeyboardEvent)) return;
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        APISecurityConfig.openSettingsCategory(target.dataset.apiSettingsCategory || '');
    });

    AdminEvents.delegateEvent<HTMLElement>(document, 'keydown', '[data-api-security-action="open-authorization-control"]', (event, target) => {
        if (!(event instanceof KeyboardEvent)) return;
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        APISecurityConfig.openAuthorizationControl(target.dataset.apiAuthorizationControl || '');
    });

    AdminEvents.delegateEvent<HTMLElement>(document, 'keydown', '[data-api-security-action="open-graphql-control"]', (event, target) => {
        if (!(event instanceof KeyboardEvent)) return;
        if (target instanceof HTMLButtonElement) return;
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        APISecurityConfig.openGraphQLControl(target.dataset.apiGraphqlControl || '');
    });

    AdminEvents.delegateEvent<HTMLInputElement | HTMLSelectElement>(
        document,
        'change',
        '[data-api-scope-filter]',
        (_event, target) => {
            const key = target.dataset.apiScopeFilter;
            if (!key) return;
            APISecurityConfig.updateScopePickerFilter(key, target.value);
        }
    );

    AdminEvents.delegateEvent<HTMLSelectElement>(
        document,
        'change',
        '[data-api-surface-host]',
        (_event, target) => {
            APISecurityConfig.updateScopePickerHost(target.value);
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement>(
        document,
        'change',
        '[data-api-scope-path-option]',
        (_event, target) => {
            APISecurityConfig.toggleScopePickerPath(target.dataset.apiScopePathOption || '', target.checked);
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(
        document,
        'change',
        '[data-api-inventory-meta-field]',
        (_event, target) => {
            APISecurityConfig.updateInventoryMetadataField(
                target.dataset.apiEndpointKey || '',
                target.dataset.apiInventoryMetaField || '',
                parseAPISecurityValue(target)
            );
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement | HTMLSelectElement>(
        document,
        'change',
        '[data-api-inventory-filter]',
        (_event, target) => {
            const key = target.dataset.apiInventoryFilter;
            if (!key) return;
            APISecurityConfig.updateInventoryFilter(key, target.value);
        }
    );

    AdminEvents.delegateEvent<HTMLSelectElement>(
        document,
        'change',
        '[data-api-inventory-group-by]',
        (_event, target) => {
            APISecurityConfig.setInventoryGroupBy(target.value);
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement>(
        document,
        'input',
        '[data-api-inventory-filter="search"]',
        (_event, target) => {
            APISecurityConfig.updateInventoryFilter('search', target.value);
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement>(
        document,
        'input',
        '[data-api-settings-search]',
        (_event, target) => {
            APISecurityConfig.updateSettingsSearch(target.value);
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement>(
        document,
        'change',
        '[data-api-bola-rule-field]',
        (_event, target) => {
            const index = Number(target.dataset.apiBolaRuleIndex || 0);
            const field = target.dataset.apiBolaRuleField;
            if (!field) return;
            APISecurityConfig.updateBolaRule(index, field, parseAPISecurityValue(target));
            SectionUI.markSaveActionBarDirty('data-api-security-action');
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement>(
        document,
        'change',
        '[data-api-auth-issuer-field]',
        (_event, target) => {
            const index = Number(target.dataset.apiAuthIssuerIndex || 0);
            const field = target.dataset.apiAuthIssuerField;
            if (!field) return;
            APISecurityConfig.updateAuthIssuer(index, field, parseAPISecurityValue(target));
            SectionUI.markSaveActionBarDirty('data-api-security-action');
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement>(
        document,
        'change',
        '[data-api-bfla-rule-field]',
        (_event, target) => {
            const index = Number(target.dataset.apiBflaRuleIndex || 0);
            const field = target.dataset.apiBflaRuleField;
            if (!field) return;
            APISecurityConfig.updateBFLARule(index, field, parseAPISecurityValue(target));
            SectionUI.markSaveActionBarDirty('data-api-security-action');
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement>(
        document,
        'change',
        '[data-api-mass-rule-field]',
        (_event, target) => {
            const index = Number(target.dataset.apiMassRuleIndex || 0);
            const field = target.dataset.apiMassRuleField;
            if (!field) return;
            APISecurityConfig.updateMassAssignmentPathRule(index, field, parseAPISecurityValue(target));
            SectionUI.markSaveActionBarDirty('data-api-security-action');
        }
    );
}

const APISecurityConfigState = {
    get containerId(): string { return APISecurityConfig.containerId; },
    set containerId(value: string) { APISecurityConfig.containerId = value; },
    get currentTab(): APISecurityTabId { return APISecurityConfig.currentTab; },
    set currentTab(value: APISecurityTabId) { APISecurityConfig.currentTab = value; },
    get selectedSettingsCategory(): APISecuritySettingCategory { return APISecurityConfig.selectedSettingsCategory; },
    set selectedSettingsCategory(value: APISecuritySettingCategory) { APISecurityConfig.selectedSettingsCategory = value; },
    get settingsSearch(): string { return APISecurityConfig.settingsSearch; },
    set settingsSearch(value: string) { APISecurityConfig.settingsSearch = value; },
    get changedSettings(): string[] { return APISecurityConfig.changedSettings; },
    set changedSettings(value: string[]) { APISecurityConfig.changedSettings = value; },
    get selectedPolicyEditorTab(): APISecurityPolicyEditorTab { return APISecurityConfig.selectedPolicyEditorTab; },
    set selectedPolicyEditorTab(value: APISecurityPolicyEditorTab) { APISecurityConfig.selectedPolicyEditorTab = value; },
    get config(): APISecurityState { return APISecurityConfig.config; },
    set config(value: APISecurityState) { APISecurityConfig.config = normalizeAPISecurityConfig(value); },
    get sectionEnabled(): boolean { return APISecurityConfig.sectionEnabled; },
    set sectionEnabled(value: boolean) { APISecurityConfig.sectionEnabled = value; },
    get stats(): APISecurityStats { return APISecurityConfig.stats; },
    set stats(value: APISecurityStats) { APISecurityConfig.stats = value; },
    get dashboard(): APISecurityDashboardPayload { return APISecurityConfig.dashboard; },
    set dashboard(value: APISecurityDashboardPayload) { APISecurityConfig.dashboard = value; },
    get inventory(): APISecurityEndpoint[] { return APISecurityConfig.inventory; },
    set inventory(value: APISecurityEndpoint[]) { APISecurityConfig.inventory = value; },
    get overviewLoading(): boolean { return APISecurityConfig.overviewLoading; },
    set overviewLoading(value: boolean) { APISecurityConfig.overviewLoading = value; },
    get overviewError(): string { return APISecurityConfig.overviewError; },
    set overviewError(value: string) { APISecurityConfig.overviewError = value; },
    get tabs(): APISecurityTab[] { return APISecurityConfig.tabs; },
    set tabs(value: APISecurityTab[]) { APISecurityConfig.tabs = value; },
    get icons(): Record<string, string> { return APISecurityConfig.icons; },
    set icons(value: Record<string, string>) { APISecurityConfig.icons = value; }
};

const APISecurityConfigService = {
    init: (containerId?: string): Promise<void> => APISecurityConfig.init(containerId),
    loadConfig: (): Promise<void> => APISecurityConfig.loadConfig(),
    loadStats: (): Promise<void> => APISecurityConfig.loadStats(),
    loadOverviewData: (): Promise<void> => APISecurityConfig.loadOverviewData(),
    saveConfig: (): Promise<void> => APISecurityConfig.saveConfig()
};

const APISecurityConfigView = {
    render: (): void => APISecurityConfig.render(),
    renderTabContent: (): string => APISecurityConfig.renderTabContent(),
    renderOverview: (): string => APISecurityConfig.renderOverview(),
    renderInventory: (): string => APISecurityConfig.renderInventory(),
    renderSettings: (): string => APISecurityConfig.renderSettings(),
    renderSaveButtons: renderAPISecuritySaveButtons,
    showToast: showSectionToast
};

const APISecurityConfigController = {
    switchTab: (id: string): void => APISecurityConfig.switchTab(id),
    switchSettingsCategory: (id: string): void => APISecurityConfig.switchSettingsCategory(id),
    updateSettingsSearch: (value: string): void => APISecurityConfig.updateSettingsSearch(value),
    switchPolicyEditorTab: (id: string): void => APISecurityConfig.switchPolicyEditorTab(id),
    updateField: (path: string, value: unknown): void => APISecurityConfig.updateField(path, value),
    requestConfigFieldUpdate: (path: string, value: unknown, renderAfterUpdate?: boolean): void => APISecurityConfig.requestConfigFieldUpdate(path, value, renderAfterUpdate),
    updateInventoryFilter: (key: string, value: string): void => APISecurityConfig.updateInventoryFilter(key, value),
    updateBolaRule: (index: number, field: string, value: unknown): void => APISecurityConfig.updateBolaRule(index, field, value),
    addBolaRule: (): void => APISecurityConfig.addBolaRule(),
    removeBolaRule: (index: number): void => APISecurityConfig.removeBolaRule(index),
    updateAuthIssuer: (index: number, field: string, value: unknown): void => APISecurityConfig.updateAuthIssuer(index, field, value),
    addAuthIssuer: (): void => APISecurityConfig.addAuthIssuer(),
    removeAuthIssuer: (index: number): void => APISecurityConfig.removeAuthIssuer(index),
    updateBFLARule: (index: number, field: string, value: unknown): void => APISecurityConfig.updateBFLARule(index, field, value),
    addBFLARule: (): void => APISecurityConfig.addBFLARule(),
    removeBFLARule: (index: number): void => APISecurityConfig.removeBFLARule(index),
    updateMassAssignmentPathRule: (index: number, field: string, value: unknown): void => APISecurityConfig.updateMassAssignmentPathRule(index, field, value),
    addMassAssignmentPathRule: (): void => APISecurityConfig.addMassAssignmentPathRule(),
    removeMassAssignmentPathRule: (index: number): void => APISecurityConfig.removeMassAssignmentPathRule(index),
    uploadSchema: (): Promise<boolean> => APISecurityConfig.uploadSchema()
};

const apiSecurityServiceMethods = new Set<keyof typeof APISecurityConfigService>([
    'init',
    'loadConfig',
    'loadStats',
    'loadOverviewData',
    'saveConfig'
]);

const apiSecurityViewMethods = new Set<keyof typeof APISecurityConfigView>([
    'render',
    'renderTabContent',
    'renderOverview',
    'renderInventory',
    'renderSettings',
    'renderSaveButtons',
    'showToast'
]);

export const APISecurityConfigFacade = new Proxy({} as APISecurityConfigRuntime & { state: typeof APISecurityConfigState }, {
    get(_target, prop: string | symbol): unknown {
        if (prop === 'state') return APISecurityConfigState;
        if (typeof prop !== 'string') return undefined;

        if (apiSecurityServiceMethods.has(prop as keyof typeof APISecurityConfigService)) {
            return APISecurityConfigService[prop as keyof typeof APISecurityConfigService];
        }
        if (apiSecurityViewMethods.has(prop as keyof typeof APISecurityConfigView)) {
            return APISecurityConfigView[prop as keyof typeof APISecurityConfigView];
        }
        if (prop in APISecurityConfigController) {
            return APISecurityConfigController[prop as keyof typeof APISecurityConfigController];
        }

        const value = APISecurityConfig[prop as keyof APISecurityConfigRuntime];
        return typeof value === 'function' ? value.bind(APISecurityConfig) : value;
    },
    set(_target, prop: string | symbol, value: unknown): boolean {
        if (typeof prop === 'string' && prop in APISecurityConfig) {
            (APISecurityConfig as Record<string, unknown>)[prop] = value;
            return true;
        }
        return false;
    }
});
