export interface UpstreamTarget {
  url: string;
  weight?: number;
  healthy?: boolean;
}

export interface UpstreamHealthCheck {
  enabled?: boolean;
  interval?: string;
  timeout?: string;
  path?: string;
  method?: string;
  expected_statuses?: number[];
  healthy_threshold?: number;
  unhealthy_threshold?: number;
}

export interface UpstreamSticky {
  enabled?: boolean;
  cookie?: string;
  ttl?: string;
}

export interface UpstreamTargetRuntimeStatus {
  url: string;
  healthy: boolean;
  health_check_enabled: boolean;
  active_connections?: number;
  consecutive_failures?: number;
  consecutive_successes?: number;
  last_check?: string;
  last_latency_ms?: number;
  last_status_code?: number;
  last_error?: string;
}

export interface UpstreamGroupRuntimeStatus {
  name: string;
  targets: UpstreamTargetRuntimeStatus[];
}

export type UpstreamStrategy = 'round_robin' | 'weighted_rr' | 'least_conn' | 'ip_hash';

export interface OriginPool {
  id: string;
  name: string;
  strategy: UpstreamStrategy | string;
  targets: UpstreamTarget[];
  health_check?: UpstreamHealthCheck;
  sticky?: UpstreamSticky;
}

export interface CircuitBreakerConfig {
  threshold: number;
  timeout: string;
}

export interface StickySecretStatus {
  configured: boolean;
  migration_required: boolean;
  yaml_cleanup_pending: boolean;
  revision: number;
}

export interface RouteBackend {
  url: string;
  weight?: number;
}

export interface RouteRecord {
  id?: string;
  name?: string;
  priority?: number;
  hosts?: string[];
  paths?: string[];
  match?: {
    hosts?: string[];
    paths?: string[];
    methods?: string[];
    headers?: Record<string, string[]>;
    query?: Record<string, string[]>;
    source_cidrs?: string[];
  };
  action?: {
    upstream?: string;
    backends?: RouteBackend[];
    strategy?: string;
    strip_prefix?: string;
    rewrite_path?: string;
    preserve_host?: boolean;
    timeout?: string;
    retries?: number;
  };
  backends?: RouteBackend[];
  load_balance?: string;
  strip_prefix?: string;
  enabled?: boolean;
  security?: {
    waf_core?: boolean;
    traffic_control?: boolean;
    http_security?: boolean;
    bot_protection?: boolean;
    api_security?: boolean;
    access_control?: boolean;
    country?: RouteCountryPolicy;
  };
}

export interface RouteCountryPolicy {
  enabled?: boolean;
  allow_countries?: string[];
  block_countries?: string[];
  groups?: string[];
  exceptions?: string[];
}

export interface RouteTestRequest {
  method?: string;
  url?: string;
  host?: string;
  remote_addr?: string;
  headers?: Record<string, string>;
}

export interface RouteTestResponse {
  matched: boolean;
  client_info?: {
    ip?: string;
    client_ip?: string;
    source?: string;
    trusted_proxy?: boolean;
    is_trusted?: boolean;
    immediate_peer?: string;
    original_host?: string;
    original_proto?: string;
    proxy_hops?: number;
  };
  request?: {
    method: string;
    host: string;
    path: string;
    query?: string;
  };
  route?: RouteRecord;
  upstream?: string;
  sections?: Record<string, any>;
  delivery?: {
    named_upstream?: string;
    strategy?: string;
    backend_count?: number;
    strip_prefix?: string;
    rewrite_path?: string;
    preserve_host?: boolean;
    timeout?: string;
    retries?: number;
  };
}

export type AppAccessHealth = 'draft' | 'deny_only' | 'active' | 'update_available' | 'disabled' | 'error';

export interface AppV2 {
  id: string;
  revision?: number;
  name: string;
  route_id: string;
  route?: any;
  auth_method?: string;
  default_action?: 'allow' | 'deny';
  authorization_mode?: string;
  deployment_state?: 'draft' | 'deployed' | 'disabled';
  accepted_trust_sources?: Array<{
    channel: string;
    reference_mode?: string;
    oidc_provider_id?: string;
    jwt_issuer_url?: string;
    jwt_audience?: string;
  }>;
  access_health?: {
    state: AppAccessHealth;
    reason_codes: string[];
  };
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export type DeploymentMode = 'standalone' | 'behind_proxy' | 'sidecar' | 'kubernetes_ingress';
export type ProxyProvider = 'nginx' | 'traefik' | 'apache' | 'caddy';

export interface TrustedProxySettings {
  enabled: boolean;
  cidrs: string[];
  real_ip_headers: string[];
  proto_header: string;
  host_header: string;
  forwarded_header: boolean;
  recursive: boolean;
  source_urls?: string[];
  source_files?: string[];
  source_root?: string;
  combined_list?: string;
}

export interface InfrastructureSettings {
  mode: DeploymentMode;
  proxy_provider: ProxyProvider;
  public_base_url: string;
  aegis_address: string;
  trusted_proxies: TrustedProxySettings;
}

export interface ProxySettingsResponse {
  settings: InfrastructureSettings;
  runtime?: {
    applied: boolean;
    restart_required: boolean;
    revision: string;
  };
  trusted_list?: {
    path: string;
    exists: boolean;
    entries: number;
    updated_at?: string;
    configured_sources: number;
    error?: string;
  };
}

export interface ProxyGuideResponse {
  provider: string;
  title?: string;
  subtitle?: string;
  steps?: string[];
  template?: string;
}

export interface CertificateRecord {
  id?: string;
  domain?: string;
  cn?: string;
  issuer?: string;
  valid?: boolean;
  status?: string;
  source?: string;
  managed?: boolean;
  active?: boolean;
  deletable?: boolean;
  auto_renew?: boolean;
  days_remaining?: number;
  renew_at?: string;
  type?: string;
  key_size?: number;
  not_before?: string;
  not_after?: string;
  fingerprint?: string;
  sans?: string[];
}

export interface TLSConfigState {
  enabled: boolean;
  auto: boolean;
  domains: string[];
  email: string;
  provider?: string;
  challenge?: string;
  listener_mode?: 'http' | 'https';
}

export interface WafCoreConfig {
  enabled: boolean;
  mode: 'prevention' | 'detection';
  paranoia_level: number;
  inbound_anomaly_threshold: number;
  outbound_anomaly_threshold: number;
  response_inspection?: boolean;
  health?: {
    status: string;
    message: string;
    details?: Record<string, any>;
  };
}

export interface CrsRuleGroup {
  id: string;
  file_name: string;
  name: string;
  description: string;
  category: 'protocol' | 'attack' | 'lfi_rfi' | 'sqli' | 'xss' | 'scanner';
  rule_count: number;
  paranoia_level: number;
  enabled: boolean;
}

export interface WAFRuleTarget {
  zone: string;
  field?: string;
  patterns?: string[];
  negate?: boolean;
  operator?: string;
  transforms?: string[];
  [key: string]: unknown;
}

export interface WAFCustomRule {
  schema_version?: number;
  id: string;
  name: string;
  enabled?: boolean;
  severity?: 'critical' | 'high' | 'medium' | 'low' | string;
  message?: string;
  score?: number;
  tags?: string[];
  targets?: WAFRuleTarget[];
  filename?: string;
  valid?: boolean;
  validation_errors?: string[];
  [key: string]: unknown;
}

export interface WAFRuleDetailResponse {
  rule: WAFCustomRule;
  valid?: boolean;
  validation_errors?: string[];
}

export type CustomWafRule = WAFCustomRule;

export interface WAFProfile {
  id: string;
  name: string;
  description?: string;
  priority?: number;
  paranoia_level?: number;
  anomaly_threshold?: number;
  enforcement_mode?: 'blocking' | 'detection' | string;
  builtin?: boolean;
  rule_groups?: Record<string, string>;
  paths?: string[] | null;
  methods?: string[] | null;
  content_types?: string[] | null;
  exclusions?: any[] | null;
}

export interface WAFManagedRuleFile {
  name: string;
  enabled?: boolean;
  group?: string;
  category?: 'request' | 'response' | 'other' | string;
  status?: 'healthy' | 'warning' | 'error' | 'disabled' | string;
  health_message?: string;
  rule_count?: number;
  action_count?: number;
  directive_count?: number;
  file_size_bytes?: number;
  modified_at?: string;
  parse_error?: string;
}

export interface WAFLeakPattern {
  id: string;
  name: string;
  category?: string;
  pattern?: string;
  severity?: string;
  action?: 'detect' | 'redact' | 'block' | 'allow' | string;
  enabled?: boolean;
  confidence?: number;
}

export interface WAFLeakAllowlistEntry {
  id: string;
  reason?: string;
  category?: string;
  host?: string;
  path?: string;
  content_type?: string;
  expires_at?: string;
  created_at?: string;
  enabled?: boolean;
}

export interface WAFLeakProtectionConfig {
  enabled?: boolean;
  mode?: 'detect' | 'redact' | 'block' | 'allow' | string;
  default_action?: 'detect' | 'redact' | 'block' | 'allow' | string;
  max_body_size?: number;
  inspect_content_types?: string[];
  skip_content_types?: string[];
  redaction_enabled?: boolean;
  block_status_code?: number;
  replacement_body?: string;
  rules?: Record<string, string>;
  categories?: Record<string, string>;
  custom_patterns?: WAFLeakPattern[];
  allowlist?: WAFLeakAllowlistEntry[];
}

export interface WAFConfigDashboardStats {
  total_requests?: number;
  blocked_requests?: number;
  allowed_requests?: number;
  logged_requests?: number;
  sqli_blocked?: number;
  xss_blocked?: number;
  path_traversal_blocked?: number;
  rce_blocked?: number;
  lfi_blocked?: number;
  rfi_blocked?: number;
  other_blocked?: number;
  avg_inspection_time_ms?: number;
  total_rules?: number;
  active_rules?: number;
  started_at?: string;
  updated_at?: string;
  engine?: {
    categories?: Record<string, number>;
    total_blocked?: number;
    total_inspections?: number;
    total_logged?: number;
    total_passed?: number;
  };
}

export interface WAFHealth {
  status?: string;
  message?: string;
  enabled?: boolean;
  mode?: string;
  engine_initialized?: boolean;
  active_revision?: string;
  crs?: {
    version?: string;
    release_channel?: string;
    rule_files_loaded?: number;
    rule_files_available?: number;
    data_files?: number;
    seclang_directives?: number;
    unique_rule_ids?: number;
    verified?: boolean;
  };
  reload?: {
    status?: string;
    last_reload_id?: string;
    last_success_at?: string;
    last_failure_at?: string;
    fail_open?: boolean;
    failure_mode?: string;
  };
  rules?: {
    active_exclusions?: number;
    crs_directives_loaded?: number;
    crs_files_loaded?: number;
    crs_rules_loaded?: number;
    custom_rules_loaded?: number;
    exclusions?: number;
  };
  telemetry?: {
    db_available?: boolean;
    dropped_events?: number;
    freshness_status?: string;
    message?: string;
  };
}

export interface WAFSectionConfig {
  enabled?: boolean;
  mode?: 'blocking' | 'detection' | 'off' | string;
  rule_strictness?: number;
  anomaly_threshold?: number;
  outbound_anomaly_threshold?: number;
  active_profile_id?: string;
  active_policy_id?: string;
  failure_mode?: 'fail_open' | 'fail_closed' | 'service_unavailable' | string;
  max_request_body_size?: number;
  max_response_body_size?: number;
  response_inspection?: boolean;
  crs_enabled?: boolean;
  crs_paranoia_level?: number;
  custom_rules_enabled?: boolean;
  excluded_paths?: string[];
  rule_groups?: Record<string, string>;
  leak_protection?: WAFLeakProtectionConfig;
  request_body_guard?: any;
  upload_protection?: any;
  [key: string]: any;
}

export interface RateLimitPolicy {
  id: string;
  name: string;
  description?: string;
  key_by: 'client_ip' | 'session_cookie' | 'header' | 'api_key';
  header_name?: string;
  rate: number; // requests/sec
  burst: number;
  action: 'rate_limit_429' | 'challenge' | 'block';
  enabled: boolean;
}

export interface BotDefenseConfig {
  enabled?: boolean;
  mode: 'off' | 'permissive' | 'balanced' | 'strict' | 'custom';
  allow_good_bots: boolean;
  challenge_unknown: boolean;
  block_bad_bots: boolean;
  captcha_provider: 'recaptcha_v2' | 'recaptcha_v3' | 'turnstile' | 'friendlycaptcha' | 'hcaptcha';
  site_key: string;
  secret_key: string;
  score_threshold?: number;
}

export type AntibotStrictness = 'low' | 'balanced' | 'high' | 'under_attack';
export type AntibotResponseMode = 'log' | 'challenge' | 'block';

export interface AntibotRuleCondition {
  field?: string;
  operator?: string;
  value?: string | number | boolean | null;
}

export interface AntibotRule {
  id?: string;
  name: string;
  description?: string;
  enabled: boolean;
  action: 'allow' | 'block' | 'challenge' | 'log';
  priority: number;
  expression?: string;
  conditions?: AntibotRuleCondition[];
  apply_to_good_bots?: boolean;
  apply_to_ai_crawlers?: boolean;
  type?: string;
  section?: string;
  phase?: string;
  mode?: string;
  [key: string]: any;
}

export interface AntibotWhitelistConfig {
  ips?: string[];
  paths?: string[];
  methods?: string[];
  headers?: string[];
  user_agents?: string[];
}

export interface AntibotClassificationConfig {
  enabled?: boolean;
  treat_unknown_as_bot?: boolean;
  allow_good_bots?: boolean;
  block_bad_bots?: boolean;
  verify_search_engines?: boolean;
  good_bot_rules?: Record<string, { action: string; verify_dns?: boolean }>;
}

export interface AntibotAICrawlersConfig {
  enabled?: boolean;
  rules?: Record<string, { action: string; verify_dns?: boolean }>;
}

export interface AntibotFullConfig {
  enabled?: boolean;
  mode?: string;
  strictness?: AntibotStrictness;
  response_mode?: AntibotResponseMode;
  enforcement_mode?: string;
  risk_profile?: string;
  scoring_profile?: string;
  auto_thresholds_enabled?: boolean;
  behavioral?: {
    enabled?: boolean;
  };
  detection?: {
    enabled?: boolean;
    mode?: string;
    block_threshold?: number;
    challenge_threshold?: number;
    block_datacenters?: boolean;
  };
  classification?: AntibotClassificationConfig;
  ai_crawlers?: AntibotAICrawlersConfig;
  whitelist?: AntibotWhitelistConfig;
  anti_evasion?: {
    fp_rotation_detection?: boolean;
    credential_stuffing?: boolean;
    session_anomaly?: boolean;
    rate_pattern_analysis?: boolean;
    max_fps_per_ip?: number;
  };
  tls?: {
    enabled?: boolean;
    header_order_enabled?: boolean;
    ja3_enabled?: boolean;
    ja4_enabled?: boolean;
    mismatch_action?: string;
  };
  challenge_ladder?: {
    enabled?: boolean;
    js_challenge_enabled?: boolean;
    managed_challenge_enabled?: boolean;
    interactive_enabled?: boolean;
    cooldown_seconds?: number;
    failure_action?: string;
  };
  managed_thresholds?: {
    observe?: number;
    challenge?: number;
    block?: number;
    repeat_offender?: number;
  };
  [key: string]: any;
}

export interface SecurityEventItem {
  id: string;
  timestamp: string | number;
  client_ip: string;
  country?: string;
  city?: string;
  method: string;
  host: string;
  path: string;
  query_string?: string;
  action: 'BLOCK' | 'CHALLENGE' | 'ALLOW' | 'LOG' | string;
  blocked?: boolean;
  rule_name?: string;
  rule_id?: string;
  rule_type?: string;
  section?: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  score?: number;
  category?: string;
  user_agent?: string;
  user_agent_family?: string;
  payload?: string;
  matched_fields?: string[];
  rule_messages?: string[];
  status_code: number;
  latency_ms?: number;
  bytes_sent?: number;
  upstream?: string;
  route_name?: string;
  request_id?: string;
  asn?: string;
  asn_org?: string;
  ja3?: string;
  ja4?: string;
  http_version?: string;
  tls_version?: string;
  ip_version?: string;
  response_content_type?: string;
  metadata?: Record<string, string>;
}

export interface TrafficEventsSummary {
  total_requests: number;
  blocked_requests?: number;
  allowed_requests?: number;
  challenged_requests?: number;
  rate_limited?: number;
  error_requests?: number;
  block_rate?: number;
  status_2xx: number;
  status_3xx: number;
  status_4xx: number;
  status_5xx: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  unique_source_ips: number;
  unique_countries: number;
  total_bytes_sent: number;
  current_rps: number;
  top_reason?: string;
  active_bans?: number;
  active_connections?: number;
  dropped_events?: number;
  window?: string;
}

export interface TrafficEventsTimeseriesPoint {
  timestamp: number;
  counts?: Record<string, number>;
  avg_latency_ms?: number;
  p95_latency_ms?: number;
}

export interface TrafficEventsBreakdownItem {
  label?: string;
  key?: string;
  value?: string;
  count: number;
  blocked?: number;
  challenged?: number;
  rate_limited?: number;
  block_rate?: number;
  percent?: number;
  last_seen?: number;
  avg_latency_ms?: number;
}

export interface TrafficOperations {
  health?: { status?: string; message?: string };
  revision?: Record<string, unknown>;
  modules?: Record<string, unknown>;
  state?: Record<string, unknown>;
  telemetry?: Record<string, unknown>;
  freshness?: Record<string, unknown>;
  module_readiness?: Record<string, string>;
  decision_logs?: Record<string, number>;
}

export interface TrafficEventsDashboardData {
  summary: TrafficEventsSummary;
  timeseries: TrafficEventsTimeseriesPoint[];
  breakdowns: Record<string, TrafficEventsBreakdownItem[]>;
  events: {
    events: SecurityEventItem[];
    count?: number;
    next_cursor?: string;
  };
  health?: {
    db_available?: boolean;
    ingestion_lag_seconds?: number;
    dropped_events?: number;
    freshness_status?: string;
    message?: string;
  };
  policy_health?: {
    status?: string;
    enabled_state?: string;
    protection_level?: number;
    dropped_events?: number;
    config_message?: string;
  };
  operations?: TrafficOperations;
  warnings?: string[];
}

export interface SecurityDashboardSummary {
  total_requests: number;
  blocked_requests: number;
  detected_requests: number;
  allowed_requests: number;
  error_requests: number;
  block_rate: number;
  detection_rate: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  avg_anomaly_score: number;
  max_anomaly_score: number;
  unique_source_ips: number;
  unique_countries: number;
  top_attack_category: string;
  dropped_events?: number;
  window?: string;
}

export interface SecurityDashboardTimeseriesPoint {
  timestamp: number;
  counts?: {
    total?: number;
    requests?: number;
    block?: number;
    blocked?: number;
    detect?: number;
    detected?: number;
    allow?: number;
    allowed?: number;
    error?: number;
  };
  avg_latency_ms?: number;
  p95_latency_ms?: number;
  avg_anomaly_score?: number;
}

export interface SecuritySectionBreakdownItem {
  key: string;
  label: string;
  count: number;
  blocked?: number;
  detected?: number;
  percent?: number;
  avg_score?: number;
  value?: string;
}

export interface SecuritySectionBreakdown {
  key: string;
  label: string;
  items?: SecuritySectionBreakdownItem[];
}

export interface SecuritySectionAnalytics {
  section: string;
  label: string;
  breakdowns?: SecuritySectionBreakdown[];
}

export interface SecurityProtectionSummary {
  blocked_attacks?: number;
  detected_only?: number;
  rule_matches?: number;
  critical_high?: number;
  avg_anomaly_score?: number;
  max_anomaly_score?: number;
  enforced_block_rate?: number;
  top_attack_category?: string;
  window?: string;
}

export interface SecurityDashboardData {
  summary: SecurityDashboardSummary;
  timeseries: SecurityDashboardTimeseriesPoint[];
  protection_summary?: SecurityProtectionSummary;
  attack_intelligence?: {
    categories?: SecuritySectionBreakdownItem[];
    severities?: SecuritySectionBreakdownItem[];
    anomaly_score_bands?: SecuritySectionBreakdownItem[];
    trend?: SecurityDashboardTimeseriesPoint[];
  };
  rule_effectiveness?: {
    top_blocking_rules?: SecuritySectionBreakdownItem[];
    top_detect_only_rules?: SecuritySectionBreakdownItem[];
    noisy_rules?: SecuritySectionBreakdownItem[];
    matched_fields?: SecuritySectionBreakdownItem[];
  };
  section_analytics: SecuritySectionAnalytics[];
  breakdowns?: Record<string, SecuritySectionBreakdownItem[]>;
  events: {
    events: SecurityEventItem[];
    count?: number;
    next_cursor?: string;
  };
  health?: {
    db_available?: boolean;
    last_event_timestamp?: number;
    ingestion_lag_seconds?: number;
    dropped_events?: number;
    freshness_status?: string;
    message?: string;
  };
  warnings?: string[];
}

export interface TrafficStats {
  total_requests: number;
  blocked_requests: number;
  challenges_issued: number;
  p95_latency_ms: number;
  status_2xx: number;
  status_3xx: number;
  status_4xx: number;
  status_5xx: number;
}

export interface CaptchaModuleConfig {
  enabled?: boolean;
  provider_name?: 'recaptcha_v2' | 'recaptcha_v3' | 'turnstile' | 'hcaptcha' | 'mtcaptcha' | 'friendlycaptcha';
  site_key?: string;
  secret_key_ref?: string;
  secret_key_configured?: boolean;
  secret_key_migration_required?: boolean;
  score_threshold?: number;
  [key: string]: unknown;
}

export type InteractiveVerificationMethod = 'hold' | 'click' | 'slide' | 'sequence' | 'match';

export interface ChallengeModuleConfig {
  enabled?: boolean;
  theme?: string;
  custom_title?: string;
  custom_message?: string;
  mode?: string;
  preset?: string;
  invisible_enabled?: boolean;
  managed_enabled?: boolean;
  interactive_enabled?: boolean;
  interactive_style?: InteractiveVerificationMethod;
  captcha_enabled?: boolean;
  escalation_policy?: string;
  cooldown_seconds?: number;
  max_failures?: number;
  failure_action?: string;
  cookie_ttl?: number;
  [key: string]: unknown;
}

export interface ErrorPageTemplate {
  id: string;
  name: string;
  html: string;
  source?: 'built-in' | 'custom';
}

export interface ErrorPagesModuleConfig {
  enabled?: boolean;
  theme?: 'auto' | 'light' | 'dark';
  active_template_id?: string;
  templates?: ErrorPageTemplate[];
  page_403?: string;
  page_404?: string;
  page_503?: string;
  [key: string]: unknown;
}

export interface AegisModule {
  id: string;
  name: string;
  description: string;
  category: 'delivery' | 'security' | 'traffic' | 'observability';
  enabled: boolean;
  edition: 'community' | 'enterprise';
  status: 'active' | 'disabled' | 'locked';
}

export interface SystemSettings {
  http_port?: number;
  admin_port?: number;
  admin_host?: string;
  prometheus_enabled?: boolean;
  prometheus_path?: string;
  prometheus_token?: string;
  request_logging?: boolean;
}

export interface AuditEntry {
  id?: string;
  user_id?: string;
  username?: string;
  actor_role_id?: string;
  action?: string;
  resource?: string;
  details?: string;
  metadata?: string;
  ip_address?: string;
  peer_ip_address?: string;
  ip_address_source?: string;
  created_at?: string;
}

export interface AuditLogsMeta {
  count?: number;
  next_cursor?: string;
  write_successes_total?: number;
  write_failures_total?: number;
  last_write_success_at?: string;
  last_write_failure_at?: string;
  last_write_outcome?: 'success' | 'failure';
  retention?: {
    enabled?: boolean;
    retention_days?: number;
    runs_total?: number;
    failures_total?: number;
    last_run_at?: string;
    last_failure_at?: string;
    last_deleted?: number;
  };
}

export interface AuditLogsResponse {
  data: AuditEntry[];
  meta?: AuditLogsMeta;
}

export interface AuditQueryParams {
  limit?: number;
  cursor?: string;
  action?: string;
  actor?: string;
  from?: string;
  to?: string;
}

export interface WAFExclusion {
  id: string;
  rule_id?: string;
  rule_group?: string;
  paths?: string[];
  params?: string[];
  ips?: string[];
  reason?: string;
  description?: string;
  path_pattern?: string;
  methods?: string[];
  comment?: string;
  created_at?: string;
  expires_at?: string;
  enabled?: boolean;
}

export type NavItemKey =
  | 'security-events'
  | 'traffic-events'
  | 'threat-logs'
  | 'waf-overview'
  | 'waf-rulesets'
  | 'waf-custom'
  | 'waf-exclusions'
  | 'waf-leak'
  | 'waf-leak-protection'
  | 'traffic-control'
  | 'traffic-overview'
  | 'traffic-ratelimit'
  | 'traffic-blacklist'
  | 'traffic-reputation'
  | 'traffic-geo'
  | 'traffic-ddos'
  | 'traffic-priority'
  | 'app-security'
  | 'app-security-overview'
  | 'app-security-request'
  | 'app-security-payload'
  | 'app-security-upload'
  | 'app-security-response'
  | 'bot-overview'
  | 'bot-managed'
  | 'bot-rules'
  | 'bot-classification'
  | 'bot-ai'
  | 'bot-exceptions'
  | 'api-security'
  | 'api-inventory'
  | 'api-contracts'
  | 'api-authorization'
  | 'api-graphql'
  | 'edge-access'
  | 'access-apps'
  | 'access-policies'
  | 'access-identity'
  | 'access-roles'
  | 'access-decisions'
  | 'access-runtime'
  | 'proxy-settings'
  | 'routing'
  | 'origins'
  | 'ssl'
  | 'modules'
  | 'settings'
  | 'audit'
  | 'profile'
  | 'users'
  | 'login'
  | 'request-reset'
  | 'reset-password';

export interface UserSession {
  status: string;
  username: string;
  id: string;
  role_id?: string;
  role_name?: string;
  permissions?: string[];
  edition?: string;
  active_features?: string[];
  csrf_token?: string;
}

export interface LoginResult {
  success: boolean;
  mfaRequired?: boolean;
  error?: string;
  user?: UserSession;
}

export interface PermissionRecord {
  id: string;
  slug: string;
  description: string;
}

export interface RoleRecord {
  id: string;
  name: string;
  description: string;
  permissions?: PermissionRecord[];
  is_builtin?: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface UserRecord {
  id: string;
  username: string;
  email: string;
  role_id: string;
  role?: RoleRecord;
  mfa_enabled?: boolean;
  is_active: boolean;
  last_login_at?: string;
  failed_login_attempts?: number;
  locked_until?: string;
  created_at?: string;
  updated_at?: string;
}

export interface UserPayload {
  id?: string;
  username: string;
  email: string;
  role_id: string;
  password?: string;
  is_active?: boolean;
}

export interface RolePayload {
  id?: string;
  name: string;
  description: string;
  permissions: string[];
}

export interface UsersListResponse {
  data: UserRecord[];
  meta: {
    page: number;
    limit: number;
    total: number;
    total_pages: number;
  };
}

export interface RolesListResponse {
  data: RoleRecord[];
}

export interface PermissionsListResponse {
  data: PermissionRecord[];
}

export interface ProfileDetails {
  id?: number | string;
  username?: string;
  email?: string;
  role_id?: number | string;
  role_name?: string;
  mfa_enabled?: boolean;
  created_at?: string;
}

export interface MFASecretData {
  secret?: string;
  qr_image?: string;
}

export interface TrafficGeoConfig {
  enabled?: boolean;
  mode?: 'blocklist' | 'allowlist';
  db_path?: string;
  auto_update?: boolean;
  update_interval?: string;
  update_url?: string;
  countries?: string[];
  regions?: string[];
  groups?: string[];
  allow_countries?: string[];
  block_countries?: string[];
  exceptions?: string[];
  unknown_action?: 'allow' | 'block' | 'challenge';
  cache_ttl?: string;
}

export interface TrafficGeoStatus {
  enabled?: boolean;
  mode?: string;
  db_path?: string;
  db_loaded?: boolean;
  lookup_mode?: string;
  auto_update?: boolean;
  unknown_action?: 'allow' | 'block' | 'challenge';
  countries?: number;
  regions?: number;
  exceptions?: number;
  last_loaded_at?: string;
  last_error?: string;
  provider?: string;
  database?: {
    path?: string;
    loaded?: boolean;
    database_type?: string;
    loaded_at?: string;
    last_error?: string;
    cache_entries?: number;
    cache_hits?: number;
    cache_misses?: number;
  };
}

export interface IPBlacklistEntry {
  id: string;
  target: string;
  type: 'ip' | 'cidr';
  note: string;
  created_at: string;
  expires_at?: string;
  active: boolean;
}

export interface IPBlacklistConfig {
  enabled: boolean;
  ips: string[];
  cidrs: string[];
  entries: Array<{
    target: string;
    note?: string;
    expires_at?: string;
  }>;
  total_count?: number;
}

export interface BlockedIPStatus {
  blocked: Array<{
    ip: string;
    reason: string;
    created_at: string;
    expires_at?: string;
  }>;
  cidrs: Array<{
    cidr: string;
    reason: string;
    created_at: string;
    expires_at?: string;
  }>;
  count: number;
}

export interface TrafficTrustedException {
  id: string;
  targets: string[];
  controls?: Array<'flood' | 'rate' | 'geo' | 'reputation' | string>;
  hosts?: string[];
  methods?: string[];
  path?: string;
  path_match?: 'exact' | 'prefix' | 'glob';
  expires_at?: string;
  note?: string;
}

export interface LicenseSnapshot {
  build_tier: string;
  licensed_tier: string;
  effective_tier: string;
  status: string;
  features: string[];
  activation_id?: string;
  expires_at?: string;
  offline_until?: string;
  subscription_end?: string;
  last_refresh?: string;
  last_error?: string;
  upgrade?: {
    required?: boolean;
    available?: boolean;
    reason?: string;
    state?: string;
    target_tier?: string;
    target_version?: string;
    minimum_updater_version?: string;
  };
}

export interface StorageRuntimeStatus {
  driver: string;
  configured: boolean;
  environment_locked: boolean;
  active: boolean;
  available: boolean;
  mode?: 'required' | 'optional' | 'disabled';
  retention_days?: number;
  restart_required: boolean;
}

export interface StorageStatusResponse {
  control: StorageRuntimeStatus;
  analytics: StorageRuntimeStatus;
}

export interface SetupStatusResponse {
  status: string;
  completed: boolean;
  setup_required: boolean;
  user_count: number;
  storage: StorageStatusResponse;
}

export interface SetupBootstrapResponse {
  status: string;
  config: Record<string, any>;
  users: UserRecord[];
  roles: RoleRecord[];
  modules: Record<string, string>;
}

export interface SetupFirstAdminRequest {
  username: string;
  email: string;
  password: string;
}

export interface SetupFirstAdminResponse {
  status: string;
  id: string;
  username: string;
  role_id: string;
  csrf_token: string;
  permissions: string[];
}

export interface SetupCompleteResponse {
  status: string;
  completed: boolean;
}

export interface PostgreSQLPreflightRequest {
  host: string;
  port: number;
  database: string;
  username: string;
  password?: string;
  ssl_mode: string;
}

export interface PostgreSQLControlPendingRequest {
  host: string;
  port: number;
  database: string;
  username: string;
  password_secret_ref: string;
  ssl_mode: string;
}

export interface ClickHousePreflightRequest {
  host: string;
  port: number;
  database: string;
  username: string;
  password?: string;
  secure: boolean;
}

export interface ClickHouseAnalyticsPendingRequest {
  mode: 'required' | 'optional' | 'disabled';
  driver?: 'postgresql' | 'clickhouse';
  host: string;
  port: number;
  database: string;
  username: string;
  password_secret_ref: string;
  secure: boolean;
  retention_days?: number;
}

export interface UpstreamSettings {
  target?: string;
  max_idle_conns?: number;
  max_idle_conns_per_host?: number;
  max_conns_per_host?: number;
  idle_timeout?: string;
  tls_timeout?: string;
  health_check_concurrency?: number;
  insecure_skip_verify?: boolean;
}

export interface TelemetrySettings {
  prometheus_enabled?: boolean;
  prometheus_path?: string;
  prometheus_token?: string;
  request_logging?: boolean;
}

export interface SystemUpdateStatus {
  current_version: string;
  latest_version?: string;
  update_available: boolean;
  notify?: boolean;
  severity?: 'critical' | 'recommended' | 'info';
  release_date?: string;
  title?: string;
  highlights?: string[];
  download_url?: string;
  changelog_url?: string;
  channel?: string;
  target_tier?: string;
  error?: string;
}

export interface EdgeAccessSettings {
  enabled: boolean;
  authentication: {
    methods?: string[];
    [key: string]: any;
  };
  authorization: {
    default_action: 'allow' | 'deny';
    [key: string]: any;
  };
  session_cookie: {
    token_ttl?: string;
    idle_timeout?: string;
    max_sessions: number;
    name?: string;
    secure?: boolean;
    http_only?: boolean;
    same_site?: string;
    bind_to_ip?: boolean;
    bind_to_user_agent?: boolean;
  };
  identity_headers: {
    enabled: boolean;
    overwrite_existing: boolean;
    headers?: any[];
  };
  activity: {
    retention_days: number;
    max_decision_records?: number;
  };
  audit: {
    retention_days: number;
    export_max_records?: number;
  };
  identity_trust?: Record<string, any>;
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

export interface AppSecurityRouteCoverage {
  protected: number;
  total: number;
  percentage: number;
  known: boolean;
}

export interface AppSecurityFunctionStatus {
  id: string;
  configured_mode: string;
  effective_mode: string;
  status: 'active' | 'disabled' | 'unavailable' | 'excluded' | 'degraded';
  reason?: string;
}

export interface AppSecurityEffectiveState {
  section_enabled: boolean;
  configured_state: 'ENFORCE' | 'OFF';
  effective_state: 'ENFORCING' | 'MONITORING' | 'PARTIALLY_ENFORCED' | 'DISABLED' | 'NOT_ATTACHED' | 'UNAVAILABLE' | string;
  reason: string;
  route_coverage: AppSecurityRouteCoverage;
  functions: AppSecurityFunctionStatus[];
  runtime?: {
    initialized: boolean;
    middleware_installed: boolean;
    runtime_only: boolean;
  };
}

export interface AppSecurityUploadLimitConfig {
  enabled: boolean;
  max_body_size: string;
}

export interface AppSecurityExtensionFilterConfig {
  enabled: boolean;
  blocked_extensions: string[];
}

export interface AppSecurityMethodEnforcerConfig {
  enabled: boolean;
  mode: 'blocklist' | 'allowlist';
  blocked_methods?: string[];
  allowed_methods?: string[];
}

export interface AppSecurityContentTypeValidatorConfig {
  enabled: boolean;
  required_on: string[];
}

export interface AppSecurityRequestSizeGuardConfig {
  enabled: boolean;
  max_url_length: number;
  max_header_count: number;
  max_single_header_size: number;
  max_query_length: number;
}

export interface AppSecuritySecurityHeadersConfig {
  enabled: boolean;
  hsts: string;
  x_frame_options: string;
  x_content_type_opts?: string;
  x_content_type_options?: string;
  referrer_policy: string;
  csp?: string;
  permissions_policy?: string;
}

export interface AppSecuritySecurityTxtConfig {
  contact?: string;
}

export interface AppSecurityInfoHidingConfig {
  enabled: boolean;
  strip_headers: string[];
}

export interface AppSecurityCookieHardenerConfig {
  enabled: boolean;
  force_secure: boolean;
  force_httponly: boolean;
  force_samesite: string;
}

export interface AppSecurityHTTPSRedirectConfig {
  enabled: boolean;
  status_code: number;
}

export interface AppSecurityGzipConfig {
  enabled: boolean;
  min_size: number;
  content_types: string[];
  level: number;
}

export interface AppSecurityHostValidatorConfig {
  enabled: boolean;
  allowed_hosts: string[];
}

export interface AppSecurityHeaderManagerConfig {
  enabled: boolean;
  add_request_headers: Record<string, string>;
  remove_request_headers: string[];
  add_response_headers?: Record<string, string>;
  remove_response_headers?: string[];
}

export interface AppSecurityJsonGuardConfig {
  enabled?: boolean;
  max_depth?: number;
  max_keys?: number;
  max_array_length?: number;
  max_string_length?: number;
}

export interface AppSecurityXmlGuardConfig {
  enabled?: boolean;
  max_depth?: number;
  max_elements?: number;
  max_attributes?: number;
  max_text_length?: number;
  block_doctype?: boolean;
  block_external_entities?: boolean;
}

export interface AppSecurityFormGuardConfig {
  enabled?: boolean;
  max_parameters?: number;
  max_parameter_name_length?: number;
  max_parameter_value_length?: number;
}

export interface AppSecurityMultipartGuardConfig {
  enabled?: boolean;
  max_parts?: number;
  max_field_count?: number;
  max_field_name_length?: number;
  max_field_value_length?: number;
}

export interface AppSecurityEncodingGuardConfig {
  enabled?: boolean;
  max_decoding_passes?: number;
  reject_invalid_utf8?: boolean;
  detect_mixed_encoding?: boolean;
}

export interface AppSecurityGraphqlGuardConfig {
  enabled?: boolean;
  max_depth?: number;
  max_aliases?: number;
  max_fields?: number;
  max_fragments?: number;
  max_batched_operations?: number;
  block_introspection?: boolean;
  require_operation_name?: boolean;
}

export interface AppSecurityRequestBodyGuardConfig {
  enabled: boolean;
  mode?: 'detect' | 'block' | string;
  max_findings?: number;
  max_body_size?: number;
  json?: AppSecurityJsonGuardConfig;
  xml?: AppSecurityXmlGuardConfig;
  form?: AppSecurityFormGuardConfig;
  multipart?: AppSecurityMultipartGuardConfig;
  encoding?: AppSecurityEncodingGuardConfig;
  graphql?: AppSecurityGraphqlGuardConfig;
}

export interface AppSecurityContentRulesConfig {
  detect_executable_bytes?: boolean;
  detect_server_side_code?: boolean;
  detect_macro_documents?: boolean;
  detect_svg_script?: boolean;
  detect_html_upload?: boolean;
  detect_pdf_exploits?: boolean;
  detect_high_entropy?: boolean;
}

export interface AppSecurityArchivePolicyConfig {
  enabled?: boolean;
  max_compression_ratio?: number;
  max_expanded_size?: number;
  max_entries?: number;
  block_nested_archives?: boolean;
  block_encrypted_archives?: boolean;
  block_traversal_paths?: boolean;
}

export interface AppSecurityUploadProtectionConfig {
  enabled: boolean;
  mode?: 'detect' | 'block' | 'allow' | string;
  max_files?: number;
  max_file_size?: number;
  max_total_upload_size?: number;
  max_filename_length?: number;
  mime_policy?: 'validate' | 'allow' | string;
  blocked_extensions?: string[];
  allowed_extensions?: string[];
  inspect_first_bytes?: number;
  content_rules?: AppSecurityContentRulesConfig;
  archive_policy?: AppSecurityArchivePolicyConfig;
}

export interface AppSecurityConfig {
  enabled: boolean;
  protection_level?: number;
  upload_limit?: AppSecurityUploadLimitConfig;
  request_body_guard?: AppSecurityRequestBodyGuardConfig;
  extension_filter?: AppSecurityExtensionFilterConfig;
  upload_protection?: AppSecurityUploadProtectionConfig;
  method_enforcer?: AppSecurityMethodEnforcerConfig;
  host_validator?: AppSecurityHostValidatorConfig;
  content_type_validator?: AppSecurityContentTypeValidatorConfig;
  request_size_guard?: AppSecurityRequestSizeGuardConfig;
  security_headers?: AppSecuritySecurityHeadersConfig;
  header_manager?: AppSecurityHeaderManagerConfig;
  https_redirect?: AppSecurityHTTPSRedirectConfig;
  info_hiding?: AppSecurityInfoHidingConfig;
  cookie_hardener?: AppSecurityCookieHardenerConfig;
  security_txt?: AppSecuritySecurityTxtConfig;
  gzip?: AppSecurityGzipConfig;
  [key: string]: any;
}

export interface AppSecurityStats {
  total: number;
  blocked: number;
  allowed: number;
  compressed: number;
}

export interface AlertItem {
  id: string;
  level: 'critical' | 'warning' | 'info' | string;
  title: string;
  message: string;
  created_at: string;
  read: boolean;
  source?: string;
  route?: string;
  action_label?: string;
  unresolved: boolean;
  meta?: Record<string, any>;
}

export interface AlertsResponse {
  alerts: AlertItem[];
  unread_count: number;
}

