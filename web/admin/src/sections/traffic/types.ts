/**
 * Traffic Control Types and Interfaces
 * Shared data structures for traffic control.
 */

export type TrafficTabId = 'overview' | 'blacklist' | 'reputation' | 'ratelimit' | 'geo' | 'ddos' | 'priority';

export interface TrafficTab {
    id: TrafficTabId;
    name: string;
    icon: string;
}

export interface TrafficStats {
    total_requests?: number;
    blocked_requests?: number;
    active_connections?: number;
    in_flight_requests?: number;
    custom?: {
        active_connections?: number;
        in_flight_requests?: number;
        [key: string]: unknown;
    };
    [key: string]: unknown;
}

export interface TrafficBlacklistEntry {
    target: string;
    expires_at?: string | null;
    note?: string;
    [key: string]: unknown;
}

export interface TrafficBlacklistConfig {
    enabled?: boolean;
    ips?: string[];
    cidrs?: string[];
    entries?: TrafficBlacklistEntry[];
    [key: string]: unknown;
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
    exceptions?: string[];
    allow_countries?: string[];
    block_countries?: string[];
    groups?: string[];
    unknown_action?: 'allow' | 'block' | 'challenge';
    cache_ttl?: string;
    [key: string]: unknown;
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
    fail_open?: boolean;
    provider?: string;
    attribution_url?: string;
    policy?: {
        enabled?: boolean;
        allow_countries?: string[];
        block_countries?: string[];
        groups?: string[];
        exceptions?: number;
        fail_open?: boolean;
    };
    database?: {
        path?: string;
        loaded?: boolean;
        generation?: string;
        database_type?: string;
        loaded_at?: string;
        last_error?: string;
        cache_entries?: number;
        cache_hits?: number;
        cache_misses?: number;
        unknown?: number;
    };
    [key: string]: unknown;
}

export interface TrafficReputationProviderConfig {
    enabled?: boolean;
    api_key?: string;
    api_key_configured?: boolean;
    clear_api_key?: boolean;
    confidence_score?: number;
    source?: string;
    sync_interval?: string;
    timeout?: string;
    [key: string]: unknown;
}

export interface TrafficReputationPolicyRule {
    id: string;
    score_threshold?: number;
    action?: 'allow' | 'monitor' | 'challenge' | 'block';
    categories?: string[];
    enabled?: boolean;
    [key: string]: unknown;
}

export interface TrafficReputationRule {
    id: string;
    ip_or_cidr: string;
    action: 'allow' | 'block' | 'challenge' | 'bypass' | string;
    score?: number;
    comment?: string;
    created_at?: string;
}

export interface TrafficReputationConfig {
    enabled?: boolean;
    mode?: string;
    threshold?: number;
    block_threshold?: number;
    challenge_threshold?: number;
    strict_score_threshold?: number;
    block_datacenter?: boolean;
    block_tor?: boolean;
    cache_ttl?: string;
    sensitivity?: number | string;
    action?: string;
    rules?: TrafficReputationRule[];
    allowed_ips?: string[];
    blocked_ips?: string[];
    providers?: Record<string, TrafficReputationProviderConfig>;
    policy_rules?: TrafficReputationPolicyRule[];
    cti?: {
        enabled?: boolean;
        url?: string;
        api_key?: string;
        min_score?: number;
    };
    [key: string]: unknown;
}

export interface FeedStatusData {
    last_attempt?: string;
    last_success?: string;
    last_error?: string;
    entry_count?: number;
    checksum?: string;
    next_attempt?: string;
    attempts?: number;
    successes?: number;
    failures?: number;
}

export interface UnifiedThreatIndicator {
    indicator: string;
    type: 'ip' | 'cidr';
    category: string;
    severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
    score?: number;
    confidence?: string;
    threat_name?: string;
    malware_family?: string;
    threat_actor?: string;
    mitre_tactics?: string[];
    action?: string;
    source?: string;
    source_name?: string;
    status?: 'active' | 'disabled' | string;
}

export interface UnifiedThreatFeedData {
    status?: 'ok' | 'degraded' | 'error';
    total_indicators?: number;
    sources?: Record<string, {
        enabled?: boolean;
        source?: string;
        url?: string;
        entry_count?: number;
        status?: FeedStatusData;
    }>;
    indicators?: UnifiedThreatIndicator[];
    cti?: {
        enabled?: boolean;
        url?: string;
        indicators?: UnifiedThreatIndicator[];
        entry_count?: number;
        status?: FeedStatusData;
    };
}

export interface ThreatFeedPaginationState {
    page: number;
    pageSize: number;
    search: string;
    sourceFilter: string;
    severityFilter?: string;
    sortBy?: 'indicator' | 'score' | 'severity' | 'category' | 'protocol' | 'confidence';
    sortOrder?: 'asc' | 'desc';
}

export interface TrafficPathOverride {
    id: string;
    name?: string;
    priority?: number;
    hosts?: string[];
    methods?: string[];
    pattern: string;
    match?: 'exact' | 'prefix' | 'glob';
    rate: number;
    burst: number;
    window: string;
    action?: 'block' | 'challenge' | 'dry_run' | string;
    algorithm?: 'token_bucket' | 'fixed_window' | 'sliding_window' | string;
    key_by?: 'ip' | 'ip_ua' | 'cookie' | 'token' | string;
    bypass_static?: boolean;
    dry_run?: boolean;
    verified_grace_multiplier?: number;
    enabled?: boolean;
    [key: string]: unknown;
}

export interface TrafficRateLimitRule {
    id: string;
    path_pattern?: string;
    methods?: string[];
    rate?: number;
    burst?: number;
    window?: string;
    action?: 'drop' | 'reject' | 'delay' | 'challenge' | 'block' | string;
    enabled?: boolean;
    [key: string]: unknown;
}

export interface TrafficRateLimitConfig {
    enabled?: boolean;
    default_rate?: number;
    default_burst?: number;
    window?: string;
    algorithm?: 'token_bucket' | 'fixed_window' | 'sliding_window' | string;
    strategy?: 'token_bucket' | 'leaky_bucket' | 'sliding_window' | string;
    key_by?: string;
    key_header?: string;
    action?: string;
    bypass_static?: boolean;
    bypass_known_bots?: boolean;
    verified_grace_multiplier?: number;
    dry_run?: boolean;
    max_states?: number;
    state_idle_ttl?: string;
    path_overrides?: TrafficPathOverride[];
    rules?: TrafficRateLimitRule[];
    [key: string]: unknown;
}

export interface TrafficDDoSConfig {
    enabled?: boolean;
    max_rps?: number;
    max_connections?: number;
    burst_multiplier?: number;
    action?: string;
    auto_ban?: boolean;
    ban_duration?: number;
    objects?: Array<{
        id: string;
        hosts?: string[];
        methods?: string[];
        path?: string;
        path_match?: string;
        max_rps?: number;
        max_concurrency?: number;
        burst_multiplier?: number;
        action?: string;
        auto_ban?: boolean;
        ban_duration?: number;
        verified_grace_multiplier?: number;
    }>;
    syn_flood_protection?: boolean;
    slowloris_protection?: boolean;
    http_flood_threshold?: number;
    http_flood_window?: string;
    challenge_threshold?: number;
    auto_mitigation?: boolean;
    in_flight_limit?: number;
    burst_tolerance?: number;
    [key: string]: unknown;
}

export interface TrafficTrustedException {
    id: string;
    name?: string;
    source_ips?: string[];
    paths?: string[];
    bypass_rate_limiting?: boolean;
    bypass_ddos?: boolean;
    bypass_geo?: boolean;
    bypass_reputation?: boolean;
    bandwidth_priority?: 'normal' | 'high' | 'critical';
    enabled?: boolean;
    [key: string]: unknown;
}

export interface TrafficSectionConfig {
    enabled?: boolean;
    blacklist?: TrafficBlacklistConfig;
    reputation?: TrafficReputationConfig;
    rate_limit?: TrafficRateLimitConfig;
    geo?: TrafficGeoConfig;
    ddos?: TrafficDDoSConfig;
    trusted_exceptions?: TrafficTrustedException[];
    [key: string]: unknown;
}
