import type { NavItemKey } from '../types';

/* * * Backend Feature IDs matching Aegis-main/internal/edition/types.go */

// Core / Community Tier Features
export const FEATURE_PROXY_CORE = 'proxy.core';
export const FEATURE_PROXY_TLS = 'proxy.tls';
export const FEATURE_PROXY_ROUTING = 'proxy.routing';
export const FEATURE_PROXY_LOAD_BALANCING = 'proxy.load_balancing';
export const FEATURE_WAF_CORE = 'waf.core';
export const FEATURE_WAF_CUSTOM_RULES = 'waf.custom_rules';
export const FEATURE_WAF_UPLOAD_PROTECTION = 'waf.upload_protection';
export const FEATURE_HTTP_SECURITY_BASIC = 'http_security.basic';
export const FEATURE_HTTP_SECURITY_ADVANCED = 'http_security.advanced';
export const FEATURE_TRAFFIC_BLACKLIST = 'traffic.blacklist';
export const FEATURE_TRAFFIC_RATE_LIMIT = 'traffic.rate_limit';
export const FEATURE_TRAFFIC_CONNECTION_STATS = 'traffic.connection_stats';
export const FEATURE_TRAFFIC_GEO = 'traffic.geo';
export const FEATURE_ADMIN_SINGLE_USER = 'admin.single_user';
export const FEATURE_ADMIN_MFA = 'admin.mfa';
export const FEATURE_ANALYTICS_BASIC = 'analytics.basic';

// Professional Tier Features
export const FEATURE_WAF_LEAK_PROTECTION = 'waf.leak_protection';
export const FEATURE_WAF_BODY_GUARD = 'waf.body_guard';
export const FEATURE_WAF_ADVANCED_POLICY = 'waf.advanced_policy';
export const FEATURE_TRAFFIC_DDOS = 'traffic.ddos';
export const FEATURE_TRAFFIC_PRIORITY = 'traffic.priority';
export const FEATURE_TRAFFIC_REPUTATION = 'traffic.reputation';
export const FEATURE_BOT_ALL = 'bot.all';

// Enterprise Tier Features
export const FEATURE_API_SECURITY_ALL = 'api_security.all';
export const FEATURE_ACCESS_CONTROL_ALL = 'access_control.all';
export const FEATURE_ADMIN_MULTI_USER = 'admin.multi_user';
export const FEATURE_ADMIN_RBAC = 'admin.rbac';
export const FEATURE_ADMIN_AUDIT = 'admin.audit';
export const FEATURE_ANALYTICS_ADVANCED = 'analytics.advanced';

/* * * Unified feature dictionary for convenient lookup */
export const FEATURES = {
  // Community / Core
  PROXY_CORE: FEATURE_PROXY_CORE,
  PROXY_TLS: FEATURE_PROXY_TLS,
  PROXY_ROUTING: FEATURE_PROXY_ROUTING,
  PROXY_LOAD_BALANCING: FEATURE_PROXY_LOAD_BALANCING,
  WAF_CORE: FEATURE_WAF_CORE,
  WAF_CUSTOM_RULES: FEATURE_WAF_CUSTOM_RULES,
  WAF_UPLOAD_PROTECTION: FEATURE_WAF_UPLOAD_PROTECTION,
  HTTP_SECURITY_BASIC: FEATURE_HTTP_SECURITY_BASIC,
  HTTP_SECURITY_ADVANCED: FEATURE_HTTP_SECURITY_ADVANCED,
  TRAFFIC_BLACKLIST: FEATURE_TRAFFIC_BLACKLIST,
  TRAFFIC_RATE_LIMIT: FEATURE_TRAFFIC_RATE_LIMIT,
  TRAFFIC_CONNECTION_STATS: FEATURE_TRAFFIC_CONNECTION_STATS,
  TRAFFIC_GEO: FEATURE_TRAFFIC_GEO,
  ADMIN_SINGLE_USER: FEATURE_ADMIN_SINGLE_USER,
  ADMIN_MFA: FEATURE_ADMIN_MFA,
  ANALYTICS_BASIC: FEATURE_ANALYTICS_BASIC,

  // Professional
  WAF_LEAK_PROTECTION: FEATURE_WAF_LEAK_PROTECTION,
  WAF_BODY_GUARD: FEATURE_WAF_BODY_GUARD,
  WAF_ADVANCED_POLICY: FEATURE_WAF_ADVANCED_POLICY,
  TRAFFIC_DDOS: FEATURE_TRAFFIC_DDOS,
  TRAFFIC_PRIORITY: FEATURE_TRAFFIC_PRIORITY,
  TRAFFIC_REPUTATION: FEATURE_TRAFFIC_REPUTATION,
  BOT_ALL: FEATURE_BOT_ALL,

  // Enterprise
  API_SECURITY_ALL: FEATURE_API_SECURITY_ALL,
  ACCESS_CONTROL_ALL: FEATURE_ACCESS_CONTROL_ALL,
  ADMIN_MULTI_USER: FEATURE_ADMIN_MULTI_USER,
  ADMIN_RBAC: FEATURE_ADMIN_RBAC,
  ADMIN_AUDIT: FEATURE_ADMIN_AUDIT,
  ANALYTICS_ADVANCED: FEATURE_ANALYTICS_ADVANCED,
} as const;

export type FeatureID = (typeof FEATURES)[keyof typeof FEATURES];
export type EditionTier = 'community' | 'professional' | 'enterprise';

/* * * Features included by default in each edition tier */
export const COMMUNITY_FEATURES: readonly string[] = [
  FEATURE_PROXY_CORE,
  FEATURE_PROXY_TLS,
  FEATURE_PROXY_ROUTING,
  FEATURE_PROXY_LOAD_BALANCING,
  FEATURE_WAF_CORE,
  FEATURE_WAF_CUSTOM_RULES,
  FEATURE_WAF_UPLOAD_PROTECTION,
  FEATURE_HTTP_SECURITY_BASIC,
  FEATURE_HTTP_SECURITY_ADVANCED,
  FEATURE_TRAFFIC_BLACKLIST,
  FEATURE_TRAFFIC_RATE_LIMIT,
  FEATURE_TRAFFIC_CONNECTION_STATS,
  FEATURE_TRAFFIC_GEO,
  FEATURE_ADMIN_SINGLE_USER,
  FEATURE_ADMIN_MFA,
  FEATURE_ANALYTICS_BASIC,
];

export const PROFESSIONAL_FEATURES: readonly string[] = [
  ...COMMUNITY_FEATURES,
  FEATURE_WAF_LEAK_PROTECTION,
  FEATURE_WAF_BODY_GUARD,
  FEATURE_WAF_ADVANCED_POLICY,
  FEATURE_TRAFFIC_DDOS,
  FEATURE_TRAFFIC_PRIORITY,
  FEATURE_TRAFFIC_REPUTATION,
  FEATURE_BOT_ALL,
];

export const ENTERPRISE_FEATURES: readonly string[] = [
  ...PROFESSIONAL_FEATURES,
  FEATURE_API_SECURITY_ALL,
  FEATURE_ACCESS_CONTROL_ALL,
  FEATURE_ADMIN_MULTI_USER,
  FEATURE_ADMIN_RBAC,
  FEATURE_ADMIN_AUDIT,
  FEATURE_ANALYTICS_ADVANCED,
];

/* * * Returns default feature list for a given tier */
export function getFeaturesForTier(tier?: string): readonly string[] {
  const normalized = (tier || '').toLowerCase().trim();
  switch (normalized) {
    case 'enterprise':
      return ENTERPRISE_FEATURES;
    case 'professional':
    case 'pro':
      return PROFESSIONAL_FEATURES;
    case 'community':
    default:
      return COMMUNITY_FEATURES;
  }
}

/* * * Route-to-Feature gating map * Maps NavItemKey routes to their required backend feature ID. * Routes without an entry in this map are accessible across all tiers. */
export const ROUTE_FEATURE_MAP: Partial<Record<NavItemKey, string>> = {
  // WAF Leak Protection (Professional)
  'waf-leak': FEATURE_WAF_LEAK_PROTECTION,
  'waf-leak-protection': FEATURE_WAF_LEAK_PROTECTION,

  // Traffic DDoS, Priority, Reputation (Professional)
  'traffic-ddos': FEATURE_TRAFFIC_DDOS,
  'traffic-priority': FEATURE_TRAFFIC_PRIORITY,
  'traffic-reputation': FEATURE_TRAFFIC_REPUTATION,

  // Bot Defense Suite (Professional)
  'bot-overview': FEATURE_BOT_ALL,
  'bot-managed': FEATURE_BOT_ALL,
  'bot-rules': FEATURE_BOT_ALL,
  'bot-classification': FEATURE_BOT_ALL,
  'bot-ai': FEATURE_BOT_ALL,
  'bot-exceptions': FEATURE_BOT_ALL,

  // API Security Suite (Enterprise)
  'api-security': FEATURE_API_SECURITY_ALL,
  'api-inventory': FEATURE_API_SECURITY_ALL,
  'api-contracts': FEATURE_API_SECURITY_ALL,
  'api-authorization': FEATURE_API_SECURITY_ALL,
  'api-graphql': FEATURE_API_SECURITY_ALL,

  // Edge Access Control (Enterprise)
  'edge-access': FEATURE_ACCESS_CONTROL_ALL,
  'access-apps': FEATURE_ACCESS_CONTROL_ALL,
  'access-policies': FEATURE_ACCESS_CONTROL_ALL,
  'access-identity': FEATURE_ACCESS_CONTROL_ALL,
  'access-roles': FEATURE_ACCESS_CONTROL_ALL,
  'access-decisions': FEATURE_ACCESS_CONTROL_ALL,
  'access-runtime': FEATURE_ACCESS_CONTROL_ALL,

  'audit': FEATURE_ADMIN_AUDIT,
  'users': FEATURE_ADMIN_MULTI_USER,
};

/* * * Returns the required backend feature ID for a navigation route, if any. */
export function getRequiredFeatureForRoute(navKey: NavItemKey): string | undefined {
  return ROUTE_FEATURE_MAP[navKey];
}

/* * * Helper to determine if a route is permitted given a feature evaluation function. */
export function isRouteEntitled(
  navKey: NavItemKey,
  hasFeature: (featureId?: string) => boolean
): boolean {
  const requiredFeature = getRequiredFeatureForRoute(navKey);
  return hasFeature(requiredFeature);
}

/* * * Returns the minimum tier required for a given feature ID. */
export function getRequiredTierForFeature(featureId: string): EditionTier {
  if (COMMUNITY_FEATURES.includes(featureId)) {
    return 'community';
  }
  if (PROFESSIONAL_FEATURES.includes(featureId)) {
    return 'professional';
  }
  return 'enterprise';
}

export { useAuth, useEntitlements } from '../context/AuthContext';

