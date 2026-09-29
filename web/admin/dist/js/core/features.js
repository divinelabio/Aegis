/**
 * Feature gate constants and upgrade banner renderer.
 * FeatureID strings mirror aegis/internal/edition/types.go exactly.
 * Source of truth: web/admin/src/core/features.ts
 * Runtime output: web/admin/dist/js/core/features.js
 */
// FeatureID constants — must stay in sync with edition/types.go
export const FEATURES = {
    // Proxy
    PROXY_CORE: 'proxy.core',
    TLS: 'proxy.tls',
    ROUTING: 'proxy.routing',
    LOAD_BALANCING: 'proxy.load_balancing',
    // WAF
    WAF_CORE: 'waf.core',
    WAF_CUSTOM_RULES: 'waf.custom_rules',
    WAF_LEAK_PROTECTION: 'waf.leak_protection',
    WAF_UPLOAD: 'waf.upload_protection',
    WAF_BODY_GUARD: 'waf.body_guard',
    WAF_ADVANCED_POLICY: 'waf.advanced_policy',
    // HTTP Security
    HTTP_SECURITY: 'http_security.basic',
    HTTP_ADVANCED: 'http_security.advanced',
    // Traffic
    TRAFFIC_BLACKLIST: 'traffic.blacklist',
    TRAFFIC_RATE_LIMIT: 'traffic.rate_limit',
    TRAFFIC_CONN_STATS: 'traffic.connection_stats',
    TRAFFIC_GEO: 'traffic.geo',
    TRAFFIC_REPUTATION: 'traffic.reputation',
    TRAFFIC_APPLICATION_FLOOD: 'traffic.ddos',
    TRAFFIC_TRUSTED_EXCEPTIONS: 'traffic.priority',
    // Bot
    BOT_PROTECTION: 'bot.all',
    // API Security
    API_SECURITY: 'api_security.all',
    // Access Control
    ACCESS_CONTROL: 'access_control.all',
    // Admin
    ADMIN_SINGLE_USER: 'admin.single_user',
    ADMIN_MFA: 'admin.mfa',
    ADMIN_MULTI_USER: 'admin.multi_user',
    ADMIN_RBAC: 'admin.rbac',
    ADMIN_AUDIT: 'admin.audit',
    // Analytics
    ANALYTICS_BASIC: 'analytics.basic',
    ANALYTICS_ADVANCED: 'analytics.advanced',
};
const TIER_LABELS = {
    professional: 'Pro',
    enterprise: 'Enterprise',
};
const TIER_COLORS = {
    professional: 'var(--primary)',
    enterprise: 'var(--color-purple, #8b5cf6)',
};
const TIER_ICON = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
/**
 * Renders a locked-feature upgrade banner to embed inside a tab panel.
 * @param requiredTier  'professional' | 'enterprise'
 * @param featureName   Human-readable feature name for display
 */
export function renderUpgradeBanner(requiredTier, featureName) {
    const label = TIER_LABELS[requiredTier] ?? requiredTier;
    const color = TIER_COLORS[requiredTier] ?? 'var(--primary)';
    return `
    <div class="upgrade-banner">
      <div class="upgrade-banner-icon" style="color:${color}">
        ${TIER_ICON}
      </div>
      <div class="upgrade-banner-body">
        <div class="upgrade-banner-title">${featureName} is not enabled</div>
        <div class="upgrade-banner-sub">
          This feature requires a licence key with ${label} capabilities.
        </div>
      </div>
      <div class="upgrade-banner-badge" style="background:${color}15;color:${color};border-color:${color}40">
        ${TIER_ICON} ${label}
      </div>
    </div>
  `;
}
/**
 * Renders a locked tab button — same visual as normal tabs but with a lock badge.
 * Drop-in replacement for the tab button HTML in sections.
 */
