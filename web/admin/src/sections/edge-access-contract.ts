// Edge Access contract types for the stable access_control API namespace.

export type EdgeAccessAuthMethod = 'public' | 'api_key' | 'jwt' | 'oidc' | 'mtls';
export type EdgeAccessAuthSupport = 'ready' | 'setup_only' | 'future';
export type EdgeAccessAction = 'allow' | 'deny';
export type ProtectedAppStatus = 'enabled' | 'disabled' | 'misconfigured';
export type AccessDecisionResult = 'allow' | 'deny' | 'redirect' | 'requires_auth' | 'preview_only';
export type IdentityHeaderSource = 'subject' | 'email' | 'roles' | 'groups' | 'provider' | 'claim';

export interface EdgeSupportStatus {
    status: EdgeAccessAuthSupport;
    reason?: string;
}

export interface AccessClaimRequirement {
    name: string;
    operator?: '' | 'exists' | 'eq' | 'neq' | 'in' | 'contains';
    values?: string[];
}

export interface IdentityHeaderMapping {
    header_name: string;
    source: IdentityHeaderSource;
    claim?: string;
    format?: string;
}

export interface IdentityHeaderConfig {
    enabled: boolean;
    overwrite_existing: boolean;
    headers?: IdentityHeaderMapping[];
}

export interface EdgeAccessRouteSummary {
    id: string;
    name?: string;
    hosts?: string[];
    paths?: string[];
    enabled: boolean;
    priority: number;
    origin_url?: string;
    upstream?: string;
}

export interface EdgeAccessWarning {
    code: string;
    message: string;
}

export interface ProtectedApp {
    id: string;
    name: string;
    route_id: string;
    route?: EdgeAccessRouteSummary;
    auth_method: EdgeAccessAuthMethod;
    allowed_roles?: string[];
    allowed_groups?: string[];
    required_claims?: AccessClaimRequirement[];
    policy_id?: string;
    default_action: EdgeAccessAction;
    identity_headers: IdentityHeaderConfig;
    enabled: boolean;
    status: ProtectedAppStatus;
    status_reason?: string;
    created_at?: string;
    updated_at?: string;
}

export interface ProtectedAppInput {
    id?: string;
    name: string;
    route_id?: string;
    auth_method: EdgeAccessAuthMethod;
    allowed_roles?: string[];
    allowed_groups?: string[];
    required_claims?: AccessClaimRequirement[];
    policy_id?: string;
    default_action?: EdgeAccessAction;
    identity_headers?: IdentityHeaderConfig;
    enabled: boolean;
}

export interface ProtectedAppListResponse {
    success: boolean;
    protected_apps: ProtectedApp[];
    routes_source: '/api/routes';
}

export interface ProtectedAppMutationResponse {
    success: boolean;
    error?: string;
    message?: string;
    protected_app?: ProtectedApp;
    warnings?: EdgeAccessWarning[];
    contract_only?: boolean;
    next_phase_hint?: string;
}

export interface ProtectedAppRouteCreateRequest {
    name: string;
    hosts: string[];
    paths: string[];
    origin_url: string;
    priority?: number;
    enabled: boolean;
}

export interface CreateProtectedAppWithRouteRequest {
    route: ProtectedAppRouteCreateRequest;
    protected_app: ProtectedAppInput;
}

export interface CreateProtectedAppWithRouteResponse {
    success: boolean;
    route_id?: string;
    protected_app?: ProtectedApp;
    warnings?: EdgeAccessWarning[];
    contract_only?: boolean;
    error?: string;
    message?: string;
}

export interface EdgeJWTIssuer {
    name: string;
    issuer_url: string;
    jwks_url?: string;
    audience?: string;
    algorithms?: string[];
    claims_mapping?: Record<string, string>;
    secret_key?: string;
}

export interface EdgeJWTConfig {
    enabled: boolean;
    issuers: EdgeJWTIssuer[];
    header_name?: string;
    token_prefix?: string;
    required_claims?: string[];
}

export interface EdgeOIDCProvider {
    issuer: string;
    client_id: string;
    client_secret?: string;
    redirect_url?: string;
    scopes?: string[];
    claim_map?: Record<string, string>;
}

export interface EdgeOIDCConfig {
    enabled: boolean;
    providers: Record<string, EdgeOIDCProvider>;
}

export interface IdentityClaimMapping {
    subject?: string;
    email?: string;
    roles?: string;
    groups?: string;
}

export interface IdentityTrustConfig {
    jwt: EdgeJWTConfig;
    oidc: EdgeOIDCConfig;
    claim_mapping: IdentityClaimMapping;
    oidc_support: EdgeSupportStatus;
    mtls_support: EdgeSupportStatus;
}

export type IdentityTrustTestStatus = 'passed' | 'warning' | 'failed';

export interface IdentityTrustTestCheck {
    id: string;
    label: string;
    status: IdentityTrustTestStatus;
    message: string;
}

export interface IdentityTrustTestResponse {
    success: boolean;
    status: IdentityTrustTestStatus;
    checks: IdentityTrustTestCheck[];
    warnings?: EdgeAccessWarning[];
}

export interface IdentityTrustJWTTestRequest {
    issuer: EdgeJWTIssuer;
    fetch_jwks?: boolean;
}

export interface IdentityTrustOIDCTestRequest {
    provider_key: string;
    provider: EdgeOIDCProvider;
    fetch_discovery?: boolean;
}

export interface ServiceCredential {
    id: string;
    name: string;
    type: 'api_key' | 'mtls_client_certificate';
    roles?: string[];
    groups?: string[];
    protected_app_ids?: string[];
    key_prefix?: string;
    fingerprint?: string;
    subject?: string;
    sans?: string[];
    issuer?: string;
    serial_number?: string;
    status: string;
    expires_at?: string;
    last_used_at?: string;
    usage_count?: number;
    created_at?: string;
    updated_at?: string;
    revoked_at?: string;
    not_before?: string;
    not_after?: string;
    revoked?: boolean;
}

export interface AccessDecisionPreviewRequest {
    host?: string;
    path?: string;
    method?: string;
    route_id?: string;
    protected_app_id?: string;
    auth_method?: EdgeAccessAuthMethod;
    roles?: string[];
    groups?: string[];
    claims?: Record<string, string>;
    protected_app?: ProtectedAppInput;
}

export interface AccessDecisionPreview {
    result: AccessDecisionResult;
    action: EdgeAccessAction;
    reason?: string;
    protected_app_id?: string;
    route_id?: string;
    description: string;
    identity_headers?: IdentityHeaderMapping[];
}

export interface EdgeAuthenticationSettings {
    methods: EdgeAccessAuthMethod[];
}

export interface EdgeAuthorizationSettings {
    default_action: EdgeAccessAction;
}

export interface EdgeSessionCookieSettings {
    name: string;
    secure: boolean;
    http_only: boolean;
    same_site: string;
    token_ttl?: string;
    idle_timeout?: string;
    max_sessions: number;
    bind_to_ip: boolean;
    bind_to_user_agent: boolean;
}

export interface EdgeActivitySettings {
    retention_days: number;
    max_decision_records: number;
}

export interface EdgeAuditSettings {
    retention_days: number;
    export_max_records: number;
}

export interface EdgeAccessSettings {
    enabled: boolean;
    authentication: EdgeAuthenticationSettings;
    authorization: EdgeAuthorizationSettings;
    session_cookie: EdgeSessionCookieSettings;
    identity_headers: IdentityHeaderConfig;
    identity_trust: IdentityTrustConfig;
    activity: EdgeActivitySettings;
    audit: EdgeAuditSettings;
}

export interface EdgeAccessSettingsResponse {
    success: boolean;
    settings: EdgeAccessSettings;
}

export interface AccessDecisionRecord {
    id: string;
    timestamp: string;
    route_id?: string;
    protected_app_id?: string;
    service_credential_id?: string;
    service_credential_type?: string;
    service_credential_fingerprint?: string;
    auth_method?: EdgeAccessAuthMethod | string;
    identity_type?: string;
    identity_id?: string;
    identity_email?: string;
    identity_name?: string;
    ip?: string;
    user_agent?: string;
    method?: string;
    host?: string;
    path?: string;
    action?: string;
    status_code?: number;
    result: string;
    reason?: string;
    evaluation_mode?: 'policy_attachments';
    policy_deployment_id?: string;
    policy_attachment_id?: string;
    policy_id?: string;
    policy_version?: number;
    reason_code?: string;
    failed_requirement?: string;
    metadata?: Record<string, string>;
}

export interface AccessDecisionActivityResponse {
    success: boolean;
    decisions: AccessDecisionRecord[];
}

export interface ActivitySessionRecord {
    id: string;
    user_id: string;
    identity_email?: string;
    ip_address?: string;
    user_agent?: string;
    created_at: string;
    expires_at: string;
    last_active_at: string;
    expiry_status?: string;
    metadata?: Record<string, string>;
}

export interface ActivitySessionsResponse {
    success: boolean;
    sessions: ActivitySessionRecord[];
    active_count: number;
}

export interface RetentionClassStatus {
    supported: boolean;
    enabled: boolean;
    retention_days: number;
    limit?: number;
    last_cleanup_at?: string;
    last_deleted?: number;
    last_result?: string;
    message?: string;
    next_cleanup_at?: string;
}

export interface RetentionStatusResponse {
    success: boolean;
    activity: RetentionClassStatus;
    audit: RetentionClassStatus;
}

export interface RetentionRunResponse extends RetentionStatusResponse {
    deleted: number;
    error?: string;
    message?: string;
}

export interface ReloadStatusResponse {
    success: boolean;
    revision: number;
    loaded_revision: number;
    shared_storage: boolean;
    last_reload_at?: string;
    last_reload_error?: string;
    message?: string;
}

export interface ReloadMutationResponse extends ReloadStatusResponse {
    reloaded: boolean;
    error?: string;
}

export interface ActivityAuditEvent {
    id: string;
    timestamp: string;
    action: string;
    identity_type?: string;
    identity_id?: string;
    identity_name?: string;
    ip?: string;
    user_agent?: string;
    path?: string;
    method?: string;
    result: string;
    reason?: string;
    metadata?: Record<string, string>;
}

export interface ActivityAuditResponse {
    success: boolean;
    events: ActivityAuditEvent[];
}

export interface EdgeAccessErrorResponse {
    success: false;
    error: string;
    code?: string;
    message: string;
    details?: Record<string, unknown>;
    contract_version: string;
}

export type PolicyDecision = 'allow' | 'deny' | 'public_bypass';
export type PolicyVersionState = 'draft' | 'published';
export type PolicyAttachmentDeploymentState = 'active' | 'disabled';

export interface AccessPolicyContract {
    id: string;
    revision: number;
    name: string;
    description?: string;
    archived: boolean;
    created_at?: string;
    updated_at?: string;
}

export interface AccessPolicyVersionContract {
    policy_id: string;
    version: number;
    revision: number;
    state: PolicyVersionState;
    decision: PolicyDecision;
    principals: PolicyPrincipalsContract;
    requirements: PolicyRequirementsContract;
    created_at?: string;
    updated_at?: string;
    published_at?: string;
}

export interface PolicyPrincipalsContract {
    any_authenticated?: boolean;
    roles?: string[];
    groups?: string[];
    permissions?: string[];
    service_identity_ids?: string[];
    claims?: AccessClaimRequirement[];
}

export interface PolicyRequirementsContract {
    mfa_satisfied?: boolean;
    trusted_device?: boolean;
    source_cidrs?: string[];
    countries?: string[];
    time_windows?: Array<{ timezone: string; days?: string[]; start: string; end: string }>;
}

export interface PolicyAttachmentContract {
    id: string;
    revision: number;
    policy_id: string;
    policy_version: number;
    protected_app_id: string;
    path: string;
    methods?: string[];
    auth_channels?: string[];
    deployment_state: PolicyAttachmentDeploymentState;
    enabled: boolean;
    created_at?: string;
    updated_at?: string;
}

export interface PolicyPage {
    returned: number;
    page_size: number;
    next_cursor?: string;
}

export interface PolicyListQuery {
    q?: string;
    status?: 'active' | 'archived';
    decision?: PolicyDecision;
    protected_app_id?: string;
    page_size?: number;
    cursor?: string;
}

export interface PolicyAttachmentUpdateInput {
    revision: number;
    path: string;
    methods?: string[];
    auth_channels?: string[];
    deployment_state: PolicyAttachmentDeploymentState;
}

export interface PolicyAttachmentUpgradeInput { revision: number; policy_version: number; }
export interface PolicyVersionPublishInput { revision: number; }
export interface PolicyVersionDraftInput {
    decision: PolicyDecision;
    principals?: PolicyPrincipalsContract;
    requirements?: PolicyRequirementsContract;
    revision?: number;
}
export interface PolicyAttachmentCreateInput {
    id?: string;
    policy_id: string;
    policy_version: number;
    protected_app_id: string;
    path: string;
    methods?: string[];
    auth_channels?: string[];
    deployment_state?: PolicyAttachmentDeploymentState;
    enabled: boolean;
}
export interface PolicyAttachmentListQuery {
    policy_id?: string;
    protected_app_id?: string;
    status?: PolicyAttachmentDeploymentState;
    page_size?: number;
    cursor?: string;
}

export interface PolicyRuntimeCapabilitiesContract {
    mfa_satisfied: boolean;
    source_cidrs: boolean;
    trusted_device: boolean;
    countries: boolean;
    time_windows: boolean;
}

export interface PolicyEvaluationResultContract {
    result: 'allow' | 'deny' | 'requires_auth';
    reason_code: string;
    reason: string;
    attachment_id?: string;
    policy_id?: string;
    policy_version?: number;
    matched_conditions?: string[];
    failed_requirement?: string;
    eligible_channels?: string[];
}

export interface PolicySimulationInput {
    protected_app_id: string;
    source?: 'candidate' | 'deployed';
    path: string;
    method: string;
    auth_channel?: string;
    source_ip?: string;
    identity?: { id?: string; type?: string; roles?: string[]; groups?: string[]; claims?: Record<string, string>; service_credential_id?: string; mfa_verified?: boolean };
}

export interface AppPolicyDeploymentContract {
    id: string;
    protected_app_id: string;
    authorization_mode: 'policy_attachments';
    candidate_fingerprint?: string;
    route_id: string;
    active: boolean;
    created_at?: string;
    updated_at?: string;
}

export interface PolicyDeploymentInput {
    candidate_fingerprint: string;
    impact_confirmation_token?: string;
    shadow_review: { review_id?: string; session_id?: string; acknowledge_zero_samples?: boolean; acknowledge_mismatches?: boolean };
}

export interface PolicyShadowReviewInput {
    session_id: string;
    acknowledge_zero_samples?: boolean;
    acknowledge_mismatches?: boolean;
}

export interface OrganizationDenyGuardrailInput {
    id?: string;
    revision?: number;
    policy_id: string;
    policy_version: number;
    path: string;
    methods?: string[];
    enabled: boolean;
}

export interface EdgeAccessRouteOption {
    id: string;
    name?: string;
    hosts?: string[];
    paths?: string[];
    enabled?: boolean;
}
