/**
 * WAF Types & Interfaces
 * Shared data structures across Community and Pro WAF modules.
 */

export type WAFTabId = 'overview' | 'leak_protection' | 'managed' | 'custom' | 'exclusions';
export type WAFRulesView = 'main' | 'managed' | 'editor';
export type WAFExclusionScope = 'all' | 'global' | 'rule' | 'active' | 'inactive';
export type WAFManagedRuleStatusFilter = 'all' | 'enabled' | 'disabled' | 'warning' | 'error';
export type WAFLeakProtectionPage = '' | 'advanced' | 'credentials' | 'debug' | 'files' | 'custom_detectors' | 'allowlist';

export interface WAFTab {
    id: WAFTabId;
    name: string;
    icon: string;
}

export interface WAFAttackStat {
    type: string;
    count: number;
    [key: string]: unknown;
}

export interface WAFConfigHistoryPoint {
    timestamp?: string;
    total_requests: number;
    blocked_requests: number;
    [key: string]: unknown;
}

export interface WAFConfigDashboardStats {
    total_requests?: number;
    blocked_requests?: number;
    avg_inspection_ms?: number;
    attack_types?: WAFAttackStat[];
    history?: WAFConfigHistoryPoint[];
    [key: string]: unknown;
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
    [key: string]: unknown;
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
    schema_version: number;
    id: string;
    name: string;
    enabled?: boolean;
    severity?: string;
    message?: string;
    score?: number;
    tags?: string[];
    targets?: WAFRuleTarget[];
    filename?: string;
    valid?: boolean;
    validation_errors?: string[];
    [key: string]: unknown;
}

export interface WAFProfile {
    id: string;
    name: string;
    description?: string;
    icon?: string;
    paranoia_level?: number;
    anomaly_threshold?: number;
    enforcement_mode?: 'blocking' | 'detection' | string;
    builtin?: boolean;
    [key: string]: unknown;
}

export interface WAFExclusion {
    id: string;
    rule_id?: string;
    rule_group?: string;
    path_pattern?: string;
    methods?: string[];
    comment?: string;
    created_at?: string;
    expires_at?: string;
    enabled?: boolean;
    [key: string]: unknown;
}

export interface WAFLeakPattern {
    id: string;
    name: string;
    category?: string;
    pattern?: string;
    action?: string;
    enabled?: boolean;
    [key: string]: unknown;
}

export interface WAFLeakAllowlistEntry {
    id: string;
    reason?: string;
    category?: string;
    host?: string;
    path?: string;
    content_type?: string;
    [key: string]: unknown;
}

export interface WAFLeakProtectionConfig {
    enabled?: boolean;
    mode?: string;
    default_action?: string;
    max_body_size?: number;
    custom_patterns?: WAFLeakPattern[];
    allowlist?: WAFLeakAllowlistEntry[];
    categories?: Record<string, string>;
    inspect_content_types?: string[];
    skip_content_types?: string[];
    [key: string]: unknown;
}

export interface WAFSectionConfig {
    enabled?: boolean;
    mode?: 'blocking' | 'detection' | 'off' | string;
    strictness?: number;
    active_profile_id?: string;
    managed_rules?: Record<string, boolean>;
    custom_rules?: WAFCustomRule[];
    exclusions?: WAFExclusion[];
    leak_protection?: WAFLeakProtectionConfig;
    [key: string]: unknown;
}
