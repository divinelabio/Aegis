/**
 * Minimal admin router
 * Source of truth: web/admin/src/router.ts
 * Runtime output: web/admin/dist/js/router.js
 */
import { api } from './api.js';
import { FEATURES } from './core/features.js';
import { loadAuditLogsPage } from './audit.js';
import { loadPoliciesTable } from './categories.js';
import * as AdminDOM from './core/dom.js';
import { switchDashboardTab } from './dashboards/index.js';
import { CaptchaConfig } from './modules/captcha-config.js';
import { ChallengeConfig } from './modules/challenge-config.js';
import { loadProfilePage } from './profile.js';
import { loadProxySettingsPage } from './proxy-settings.js';
import { initRuleEditor } from './rule-editor.js';
import { loadRoutesTable } from './routes.js';
import { HTTPSecurityConfigFacade } from './sections/httpsecurity-config.js';
import { AccessControlConfigFacade } from './sections/access-config.js';
import { TrafficConfigFacade } from './sections/traffic-config.js';
import { WAFConfigFacade } from './sections/waf-config.js';
import { APISecurityConfigFacade } from './sections/apisecurity-config.js';
import { AntibotsConfigFacade } from './sections/antibots-config.js';
import { loadSettingsPage, selectSettingsTab } from './settings.js';
import { loadSSLPage } from './ssl.js';
import { loadUpstreamsPage } from './upstreams.js';
import { loadUsersPage } from './users.js';
import { ModuleDashboard } from './modules/dashboard.js';
import { ReputationConfig } from './modules/reputation-config.js';
import { featurePageView, initSecurityAnalytics, securityAnalyticsView } from './security.js';
import { loadThreatLogsPage, refreshThreatLogs } from './threat-logs.js';
export const router = {
    current: 'security_analytics',
    dashboardTab: 'security',
    navigateToRuleEditor(filePath) {
        this.navigate('rule_editor');
        void initRuleEditor(filePath);
    },
    views: {
        dashboard: `
            <div class="view">
                <div id="dashboard-content"></div>
            </div>
    `,
        security_analytics: securityAnalyticsView,
        attack_map: `
            <div class="view view-operator">
                <div id="traffic-config-content"><div class="loading-block">Loading Attack Map &amp; Geo...</div></div>
            </div>
        `,
        waf_managed: `
            <div class="view view-operator">
                <div id="waf-config-content"><div class="loading-block">Loading Managed Rulesets...</div></div>
            </div>
        `,
        waf_custom: `
            <div class="view view-operator">
                <div id="waf-config-content"><div class="loading-block">Loading Custom Rules Engine...</div></div>
            </div>
        `,
        waf_exclusions: `
            <div class="view view-operator">
                <div id="waf-config-content"><div class="loading-block">Loading Rule Exclusions...</div></div>
            </div>
        `,
        waf_body_guard: `
            <div class="view view-operator">
                <div id="waf-config-content"><div class="loading-block">Loading Body &amp; Upload Guard...</div></div>
            </div>
        `,
        dlp_redaction: `
            <div class="view view-operator">
                <div id="waf-config-content"><div class="loading-block">Loading Masking &amp; Redaction...</div></div>
            </div>
        `,
        traffic_access_geo: `
            <div class="view view-operator">
                <div id="traffic-config-content"><div class="loading-block">Loading Access Lists &amp; GeoIP...</div></div>
            </div>
        `,
        bot_fingerprinting: `
            <div class="view view-operator">
                <div id="antibots-config-content"><div class="loading-block">Loading Client Fingerprinting...</div></div>
            </div>
        `,
        api_jwt: `
            <div class="view view-operator">
                <div id="apisecurity-config-content"><div class="loading-block">Loading Token &amp; JWT Guard...</div></div>
            </div>
        `,
        api_graphql: `
            <div class="view view-operator">
                <div id="apisecurity-config-content"><div class="loading-block">Loading GraphQL Protection...</div></div>
            </div>
        `,
        access_idp: `
            <div class="view view-operator">
                <div id="access-config-content"><div class="loading-block">Loading Identity Providers...</div></div>
            </div>
        `,
        access_mtls: `
            <div class="view view-operator">
                <div id="access-config-content"><div class="loading-block">Loading Mutual TLS...</div></div>
            </div>
        `,
        access_sessions: `
            <div class="view view-operator">
                <div id="access-config-content"><div class="loading-block">Loading Active Sessions...</div></div>
            </div>
        `,
        bot_management: featurePageView('Bot Management', 'Manage bot scoring, challenges, known bots, and fingerprinting during the unified migration.', 'antibots_config'),
        ddos_protection: featurePageView('DDoS Protection', 'Operate rate limits, traffic throttling, and IP controls in Traffic Control.', 'traffic_config'),
        api_shield: featurePageView('API Shield', 'Centralize API schema, BOLA, and GraphQL controls while preserving API Security configuration.', 'apisecurity_config'),
        waf_config: `
            <div class="view view-operator">
                <div id="waf-config-content"><div class="loading-block">Loading...</div></div>
            </div>
        `,
        dlp_config: `
            <div class="view view-operator">
                <div id="waf-config-content"><div class="loading-block">Loading Data Leak Protection...</div></div>
            </div>
        `,
        antibots_config: `
            <div class="view view-operator">
                <div id="antibots-config-content"><div class="loading-block">Loading...</div></div>
            </div>
        `,
        bot_classification: `
            <div class="view view-operator">
                <div id="antibots-config-content"><div class="loading-block">Loading Bot Classification...</div></div>
            </div>
        `,
        traffic_config: `
            <div class="view view-operator">
                <div id="traffic-config-content"><div class="loading-block">Loading...</div></div>
            </div>
        `,
        ddos_config: `
            <div class="view view-operator">
                <div id="traffic-config-content"><div class="loading-block">Loading DDoS Shield...</div></div>
            </div>
        `,
        ratelimit_config: `
            <div class="view view-operator">
                <div id="traffic-config-content"><div class="loading-block">Loading Rate Limiting...</div></div>
            </div>
        `,
        threat_intel: `
            <div class="view view-operator">
                <div id="traffic-config-content"><div class="loading-block">Loading Threat Intelligence...</div></div>
            </div>
        `,
        access_config: `
            <div class="view view-operator">
                <div id="access-config-content"><div class="loading-block">Loading Edge Access...</div></div>
            </div>
        `,
        access_apps: `
            <div class="view view-operator">
                <div id="access-config-content"><div class="loading-block">Loading Protected Applications...</div></div>
            </div>
        `,
        access_policies: `
            <div class="view view-operator">
                <div id="access-config-content"><div class="loading-block">Loading Access Policies...</div></div>
            </div>
        `,
        access_identity: `
            <div class="view view-operator">
                <div id="access-config-content"><div class="loading-block">Loading Identity Providers...</div></div>
            </div>
        `,
        access_roles: `
            <div class="view view-operator">
                <div id="access-config-content"><div class="loading-block">Loading Roles & Scopes...</div></div>
            </div>
        `,
        access_decisions: `
            <div class="view view-operator">
                <div id="access-config-content"><div class="loading-block">Loading Access Decisions...</div></div>
            </div>
        `,
        access_settings: `
            <div class="view view-operator">
                <div id="access-config-content"><div class="loading-block">Loading Settings...</div></div>
            </div>
        `,
        apisecurity_config: `
            <div class="view view-operator">
                <div id="apisecurity-config-content"><div class="loading-block">Loading API Security...</div></div>
            </div>
        `,
        api_schema: `
            <div class="view view-operator">
                <div id="apisecurity-config-content"><div class="loading-block">Loading API Schema & Contracts...</div></div>
            </div>
        `,
        api_owasp: `
            <div class="view view-operator">
                <div id="apisecurity-config-content"><div class="loading-block">Loading OWASP API Defense...</div></div>
            </div>
        `,
        api_inventory: `
            <div class="view view-operator">
                <div id="apisecurity-config-content"><div class="loading-block">Loading API Inventory...</div></div>
            </div>
        `,
        httpsecurity_config: `
            <div class="view view-operator">
                <div id="httpsecurity-config-content"><div class="loading-block">Loading...</div></div>
            </div>
        `,
        httpsec_request: `
            <div class="view view-operator">
                <div id="httpsecurity-config-content"><div class="loading-block">Loading Request Policy...</div></div>
            </div>
        `,
        httpsec_payload: `
            <div class="view view-operator">
                <div id="httpsecurity-config-content"><div class="loading-block">Loading Payload Protection...</div></div>
            </div>
        `,
        httpsec_upload: `
            <div class="view view-operator">
                <div id="httpsecurity-config-content"><div class="loading-block">Loading Upload Security...</div></div>
            </div>
        `,
        httpsec_response: `
            <div class="view view-operator">
                <div id="httpsecurity-config-content"><div class="loading-block">Loading Response Protection...</div></div>
            </div>
        `,
        traffic_geo: `
            <div class="view view-operator">
                <div id="traffic-config-content"><div class="loading-block">Loading Geo-Blocking...</div></div>
            </div>
        `,
        traffic_priority: `
            <div class="view view-operator">
                <div id="traffic-config-content"><div class="loading-block">Loading Trusted Exceptions...</div></div>
            </div>
        `,
        traffic_blacklist: `
            <div class="view view-operator">
                <div id="traffic-config-content"><div class="loading-block">Loading IP Blacklist...</div></div>
            </div>
        `,
        bot_rules: `
            <div class="view view-operator">
                <div id="antibots-config-content"><div class="loading-block">Loading Custom Rules...</div></div>
            </div>
        `,
        bot_ai: `
            <div class="view view-operator">
                <div id="antibots-config-content"><div class="loading-block">Loading AI Crawlers...</div></div>
            </div>
        `,
        bot_exceptions: `
            <div class="view view-operator">
                <div id="antibots-config-content"><div class="loading-block">Loading Exceptions...</div></div>
            </div>
        `,
        waf: `
            <div class="view">
                <div id="policies-container">Loading...</div>
            </div>
        `,
        modules: `
            <div class="view pt-32">
                <div id="modules-dashboard">Loading...</div>
            </div>
        `,
        module_captcha: `
            <div class="view view-operator">
                <div id="captcha-config-content">Loading...</div>
            </div>
        `,
        module_challenge: `
            <div class="view view-operator">
                <div id="challenge-config-content"><div class="loading-block">Loading Smart Challenge...</div></div>
            </div>
        `,
        routes: `
            <div class="view view-operator">
                <div id="routes-container"><div class="loading-block">Loading routes...</div></div>
            </div>
        `,
        proxy_settings: `
            <div class="view view-operator">
                <div id="proxy-settings-container"><div class="loading-block">Loading proxy settings...</div></div>
            </div>
        `,
        settings: `
            <div class="view view-operator">
                <div id="settings-container"><div class="loading-block">Loading settings...</div></div>
            </div>
        `,
        users: `
            <div class="view view-operator">
                <div id="users-container"><div class="loading-block">Loading users...</div></div>
            </div>
        `,
        profile: `
            <div class="view view-operator">
                <div id="profile-container"><div class="loading-block">Loading profile...</div></div>
            </div>
        `,
        audit: `
            <div class="view view-operator">
                <div id="audit-logs-container"></div>
            </div>
        `,
        logs: `
            <div class="view view-operator">
                <div style="display:none"><button type="button" class="btn btn-outline" data-action="refresh-threat-logs">Refresh</button></div>
                <div id="threat-logs-container"><div class="loading-block">Loading threat logs...</div></div>
            </div>
        `,
        upstream: `
            <div class="view view-operator">
                <div id="upstream-container"><div class="loading-block">Loading origins...</div></div>
            </div>
        `,
        ssl: `
            <div class="view view-operator">
                <div id="ssl-container"><div class="loading-block">Loading certificates...</div></div>
            </div>
        `,
        rule_editor: `
            <div id="content"></div>
        `,
        module_reputation: `
            <div class="view view-operator">
                <div id="reputation-config-content"><div class="loading-block">Loading Reputation Manager...</div></div>
            </div>
        `,
        login: `
            <div class="view">
                <div class="auth-shell auth-inline-shell">
                    <section class="auth-panel auth-panel-form">
                        <div class="auth-brand-lockup">
                            <img src="/images/logo.svg" alt="Aegis" class="brand-logo-img">
                            <div>
                                <div class="auth-brand-name">AEGIS</div>
                                <div class="auth-brand-tag">Security Console</div>
                            </div>
                        </div>
                        <h1>Sign in to the Security Console</h1>
                        <p class="subtitle">Administrative sign-in for security, traffic, and policy operations.</p>
                        <form id="loginForm" data-action="handle-login">
                            <div class="form-group">
                                <label>Username</label>
                                <div class="input-wrapper">
                                    <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                                        <circle cx="12" cy="7" r="4"></circle>
                                    </svg>
                                    <input type="text" id="username" placeholder="Enter your username" required autofocus>
                                </div>
                            </div>
                            <div class="form-group">
                                <label>Password</label>
                                <div class="input-wrapper">
                                    <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                                    </svg>
                                    <input type="password" id="password" placeholder="••••••••" required>
                                </div>
                            </div>
                            <div class="remember-row">
                                <label class="remember-me">
                                    <input type="checkbox" id="rememberMe">
                                    Remember me
                                </label>
                                <a href="/admin/request-reset" class="forgot-pass">Forgot password?</a>
                            </div>
                            <button type="submit" class="btn btn-primary">Sign In</button>
                        </form>
                        <div class="footer">v2.1.0 · Aegis Security Platform</div>
                    </section>
                    <section class="auth-panel auth-panel-visual" aria-hidden="true">
                        <div class="auth-visual-grid"></div>
                        <div class="auth-visual-copy">
                            <div class="auth-visual-kicker">Threat Intelligence Glass</div>
                            <h2>Live security posture, built for operators.</h2>
                            <p>Dark glass surfaces, monospace telemetry, and focused controls for confident response.</p>
                        </div>
                    </section>
                </div>
            </div>
        `
    },
    navigate(target, sourceLink, options = {}) {
        const previous = this.current;
        const routeAliases = {
            bot_management: 'antibots_config',
            ddos_protection: 'traffic_config',
            api_shield: 'apisecurity_config',
            about: 'dashboard'
        };
        if (target === 'module_error_pages') {
            selectSettingsTab('appearance');
            target = 'settings';
        }
        target = routeAliases[target] || target;
        const routeFeatureRequirements = {
            security_analytics: FEATURES.ANALYTICS_BASIC,
            module_reputation: FEATURES.TRAFFIC_REPUTATION,
            threat_intel: FEATURES.TRAFFIC_REPUTATION,
            ddos_config: FEATURES.TRAFFIC_APPLICATION_FLOOD,
            traffic_priority: FEATURES.TRAFFIC_TRUSTED_EXCEPTIONS,
            dlp_config: FEATURES.WAF_LEAK_PROTECTION,
            dlp_redaction: FEATURES.WAF_LEAK_PROTECTION,
            waf_body_guard: FEATURES.WAF_BODY_GUARD,
            httpsec_body_guard: FEATURES.WAF_BODY_GUARD,
            httpsec_upload: FEATURES.WAF_UPLOAD,
            antibots_config: FEATURES.BOT_PROTECTION,
            bot_fingerprinting: FEATURES.BOT_PROTECTION,
            bot_rules: FEATURES.BOT_PROTECTION,
            bot_classification: FEATURES.BOT_PROTECTION,
            bot_ai: FEATURES.BOT_PROTECTION,
            bot_exceptions: FEATURES.BOT_PROTECTION,
            apisecurity_config: FEATURES.API_SECURITY,
            api_inventory: FEATURES.API_SECURITY,
            api_schema: FEATURES.API_SECURITY,
            api_owasp: FEATURES.API_SECURITY,
            api_graphql: FEATURES.API_SECURITY,
            access_config: FEATURES.ACCESS_CONTROL,
            access_apps: FEATURES.ACCESS_CONTROL,
            access_policies: FEATURES.ACCESS_CONTROL,
            access_identity: FEATURES.ACCESS_CONTROL,
            access_roles: FEATURES.ACCESS_CONTROL,
            access_decisions: FEATURES.ACCESS_CONTROL,
            access_settings: FEATURES.ACCESS_CONTROL,
            users: FEATURES.ADMIN_MULTI_USER,
            audit: FEATURES.ADMIN_AUDIT,
        };
        const reqFeature = routeFeatureRequirements[target];
        if (reqFeature && !api.hasFeature(reqFeature)) {
            if (['dlp_config', 'dlp_redaction', 'waf_body_guard'].includes(target)) {
                target = 'waf_config';
            }
            else if (['threat_intel', 'ddos_config', 'traffic_priority'].includes(target)) {
                target = 'traffic_config';
            }
            else if (['httpsec_body_guard', 'httpsec_upload'].includes(target)) {
                target = 'httpsecurity_config';
            }
            else if (target === 'module_reputation') {
                target = 'modules';
            }
            else {
                target = 'dashboard';
            }
        }
        const routePaths = {
            dashboard: '/admin/dashboard',
            security_analytics: '/admin/analytics/security',
            attack_map: '/admin/attack-map',
            waf: '/admin/waf',
            waf_config: '/admin/waf-config',
            waf_managed: '/admin/waf/managed',
            waf_custom: '/admin/waf/custom',
            waf_exclusions: '/admin/waf/exclusions',
            waf_body_guard: '/admin/waf/body-guard',
            dlp_config: '/admin/dlp-config',
            dlp_redaction: '/admin/dlp/redaction',
            traffic_config: '/admin/traffic-config',
            ddos_config: '/admin/ddos-config',
            ratelimit_config: '/admin/ratelimit-config',
            traffic_access_geo: '/admin/traffic/access-geo',
            traffic_blacklist: '/admin/traffic/blacklist',
            traffic_geo: '/admin/traffic/geo',
            traffic_priority: '/admin/traffic/priority',
            threat_intel: '/admin/threat-intel',
            httpsecurity_config: '/admin/httpsecurity-config',
            httpsec_request: '/admin/httpsecurity/request-policy',
            httpsec_payload: '/admin/httpsecurity/payload-protection',
            httpsec_upload: '/admin/httpsecurity/upload-security',
            httpsec_response: '/admin/httpsecurity/response-protection',
            antibots_config: '/admin/antibots-config',
            bot_classification: '/admin/bot/classification',
            bot_fingerprinting: '/admin/bot/fingerprinting',
            bot_rules: '/admin/bot/rules',
            bot_ai: '/admin/bot/ai-crawlers',
            bot_exceptions: '/admin/bot/exceptions',
            apisecurity_config: '/admin/apisecurity-config',
            api_schema: '/admin/api-schema',
            api_owasp: '/admin/api-owasp',
            api_inventory: '/admin/api-inventory',
            api_jwt: '/admin/api/jwt',
            api_graphql: '/admin/api/graphql',
            access_config: '/admin/access-config',
            access_apps: '/admin/access/apps',
            access_policies: '/admin/access/policies',
            access_identity: '/admin/access/identity',
            access_roles: '/admin/access/roles',
            access_decisions: '/admin/access/decisions',
            access_settings: '/admin/access/settings',
            access_idp: '/admin/access/idp',
            access_mtls: '/admin/access/mtls',
            access_sessions: '/admin/access/sessions',
            proxy_settings: '/admin/proxy-settings',
            routes: '/admin/routing',
            upstream: '/admin/upstreams',
            ssl: '/admin/ssl',
            modules: '/admin/modules',
            module_captcha: '/admin/modules/captcha',
            module_challenge: '/admin/modules/challenge',
            module_reputation: '/admin/modules/reputation',
            users: '/admin/users',
            profile: '/admin/profile',
            audit: '/admin/audit',
            settings: '/admin/settings',
            logs: '/admin/logs',
            rule_editor: '/admin/rule-editor'
        };
        let nextPath = routePaths[target];
        if (target === 'dashboard') {
            if (!this.dashboardTab || this.dashboardTab === 'overview') {
                this.dashboardTab = 'security';
            }
            nextPath = `${nextPath}?tab=${encodeURIComponent(this.dashboardTab)}`;
        }
        if (nextPath && `${window.location.pathname}${window.location.search}` !== nextPath) {
            const method = options.replace ? 'replaceState' : 'pushState';
            window.history[method]({}, '', nextPath);
        }
        try {
            window.sessionStorage.setItem('aegis-last-target', target);
            if (target === 'dashboard' && this.dashboardTab) {
                window.sessionStorage.setItem('aegis-last-dashboard-tab', this.dashboardTab);
            }
        }
        catch {
            // Storage unavailable in restricted context
        }
        this.current = target;
        if (target === 'login') {
            document.body.classList.add('auth-layout');
        }
        else {
            document.body.classList.remove('auth-layout');
        }
        if (target !== 'security_analytics') {
            const securityDrawer = AdminDOM.getById('security-event-explorer-drawer');
            if (securityDrawer) {
                securityDrawer.classList.add('hidden');
                securityDrawer.setAttribute('aria-hidden', 'true');
            }
        }
        const viewGroupMap = {
            waf_config: { group: 'waf', containerId: 'waf-config-content' },
            waf_managed: { group: 'waf', containerId: 'waf-config-content' },
            waf_custom: { group: 'waf', containerId: 'waf-config-content' },
            waf_exclusions: { group: 'waf', containerId: 'waf-config-content' },
            waf_body_guard: { group: 'waf', containerId: 'waf-config-content' },
            dlp_config: { group: 'waf', containerId: 'waf-config-content' },
            dlp_redaction: { group: 'waf', containerId: 'waf-config-content' },
            traffic_config: { group: 'traffic', containerId: 'traffic-config-content' },
            ddos_config: { group: 'traffic', containerId: 'traffic-config-content' },
            ratelimit_config: { group: 'traffic', containerId: 'traffic-config-content' },
            traffic_access_geo: { group: 'traffic', containerId: 'traffic-config-content' },
            traffic_blacklist: { group: 'traffic', containerId: 'traffic-config-content' },
            traffic_geo: { group: 'traffic', containerId: 'traffic-config-content' },
            traffic_priority: { group: 'traffic', containerId: 'traffic-config-content' },
            threat_intel: { group: 'traffic', containerId: 'traffic-config-content' },
            attack_map: { group: 'traffic', containerId: 'traffic-config-content' },
            apisecurity_config: { group: 'apisecurity', containerId: 'apisecurity-config-content' },
            api_schema: { group: 'apisecurity', containerId: 'apisecurity-config-content' },
            api_owasp: { group: 'apisecurity', containerId: 'apisecurity-config-content' },
            api_inventory: { group: 'apisecurity', containerId: 'apisecurity-config-content' },
            api_graphql: { group: 'apisecurity', containerId: 'apisecurity-config-content' },
            api_jwt: { group: 'apisecurity', containerId: 'apisecurity-config-content' },
            antibots_config: { group: 'antibots', containerId: 'antibots-config-content' },
            bot_classification: { group: 'antibots', containerId: 'antibots-config-content' },
            bot_fingerprinting: { group: 'antibots', containerId: 'antibots-config-content' },
            bot_rules: { group: 'antibots', containerId: 'antibots-config-content' },
            bot_ai: { group: 'antibots', containerId: 'antibots-config-content' },
            bot_exceptions: { group: 'antibots', containerId: 'antibots-config-content' },
            httpsecurity_config: { group: 'httpsecurity', containerId: 'httpsecurity-config-content' },
            httpsec_request: { group: 'httpsecurity', containerId: 'httpsecurity-config-content' },
            httpsec_payload: { group: 'httpsecurity', containerId: 'httpsecurity-config-content' },
            httpsec_upload: { group: 'httpsecurity', containerId: 'httpsecurity-config-content' },
            httpsec_response: { group: 'httpsecurity', containerId: 'httpsecurity-config-content' },
            access_config: { group: 'access', containerId: 'access-config-content' },
            access_apps: { group: 'access', containerId: 'access-config-content' },
            access_policies: { group: 'access', containerId: 'access-config-content' },
            access_identity: { group: 'access', containerId: 'access-config-content' },
            access_roles: { group: 'access', containerId: 'access-config-content' },
            access_decisions: { group: 'access', containerId: 'access-config-content' },
            access_settings: { group: 'access', containerId: 'access-config-content' },
            access_idp: { group: 'access', containerId: 'access-config-content' },
            access_mtls: { group: 'access', containerId: 'access-config-content' },
            access_sessions: { group: 'access', containerId: 'access-config-content' },
        };
        const currentGroup = viewGroupMap[target];
        const prevGroup = previous ? viewGroupMap[previous] : null;
        const canReuseView = Boolean(currentGroup &&
            prevGroup &&
            currentGroup.group === prevGroup.group &&
            AdminDOM.getById(currentGroup.containerId));
        if (!canReuseView) {
            const viewRoot = AdminDOM.getById('view-root');
            if (viewRoot) {
                viewRoot.innerHTML = this.views[target] || '<div class="view-placeholder">404</div>';
            }
        }
        const titleEl = AdminDOM.getById('page-title');
        if (titleEl) {
            const titles = {
                dashboard: 'Overview',
                security_analytics: 'Traffic Events',
                attack_map: 'Attack Map',
                waf_config: 'Overview',
                waf_managed: 'Managed Rulesets',
                waf_custom: 'Custom Rules',
                waf_exclusions: 'Exclusions',
                waf_body_guard: 'Payload Protection',
                bot_management: 'Bot Defense',
                ddos_protection: 'Application Flood',
                api_shield: 'API Shield',
                waf: 'Application Firewall',
                dlp_config: 'Leak Protection',
                dlp_redaction: 'Masking & Redaction',
                antibots_config: 'Overview',
                bot_classification: 'Classification',
                bot_fingerprinting: 'Managed Protection',
                bot_rules: 'Custom Rules',
                bot_ai: 'AI Crawlers',
                bot_exceptions: 'Exceptions',
                traffic_config: 'Overview',
                ddos_config: 'Application Flood',
                ratelimit_config: 'Rate Limiting',
                traffic_access_geo: 'IP Blacklist',
                traffic_blacklist: 'IP Blacklist',
                traffic_geo: 'Geo-Blocking',
                traffic_priority: 'Trusted Exceptions',
                threat_intel: 'IP Reputation',
                access_config: 'Overview',
                access_apps: 'Apps',
                access_policies: 'Access Policies',
                access_identity: 'Identity',
                access_roles: 'Roles',
                access_decisions: 'Decisions',
                access_settings: 'Settings',
                access_idp: 'Identity Providers',
                access_mtls: 'Mutual TLS',
                access_sessions: 'Active Sessions',
                modules: 'Modules',
                module_captcha: 'CAPTCHA',
                module_challenge: 'Smart Challenge',
                module_reputation: 'IP Reputation',
                routes: 'Routing',
                proxy_settings: 'Proxy Settings',
                settings: 'Settings',
                logs: 'Threat Logs',
                upstream: 'Origins',
                ssl: 'SSL Certificates',
                login: 'Login',
                profile: 'Profile',
                audit: 'Audit Logs',
                users: 'Users',
                rule_editor: 'Rule Editor',
                apisecurity_config: 'Overview',
                api_schema: 'Contracts',
                api_owasp: 'Authorization',
                api_inventory: 'API Inventory',
                api_jwt: 'JWT Guard',
                api_graphql: 'GraphQL',
                httpsecurity_config: 'Overview',
                httpsec_request: 'Request Policy',
                httpsec_payload: 'Payload Protection',
                httpsec_upload: 'Upload Security',
                httpsec_response: 'Response Protection'
            };
            titleEl.innerText = titles[target] || target.charAt(0).toUpperCase() + target.slice(1);
        }
        AdminDOM.queryAll('.nav-link').forEach(element => element.classList.remove('active'));
        AdminDOM.queryAll('.nav-domain-group').forEach(element => element.classList.remove('has-active-child'));
        const activeEvent = globalThis.event;
        const clickedLink = sourceLink instanceof Element
            ? sourceLink.closest('.nav-link')
            : activeEvent?.target instanceof Element
                ? activeEvent.target.closest('.nav-link')
                : null;
        let activeLinkElement = null;
        if (clickedLink instanceof HTMLElement) {
            clickedLink.classList.add('active');
            activeLinkElement = clickedLink;
        }
        else {
            let targetLink = AdminDOM.query(`.nav-link[data-nav-target="${target}"]`);
            if (target === 'dashboard') {
                const tab = (this.dashboardTab && this.dashboardTab !== 'overview') ? this.dashboardTab : 'security';
                const specificDashboardLink = AdminDOM.query(`.nav-link[data-nav-target="dashboard"][data-dashboard-tab="${tab}"]`);
                if (specificDashboardLink instanceof HTMLElement) {
                    targetLink = specificDashboardLink;
                }
            }
            if (targetLink instanceof HTMLElement) {
                targetLink.classList.add('active');
                activeLinkElement = targetLink;
            }
        }
        if (activeLinkElement) {
            const parentDomainGroup = activeLinkElement.closest('.nav-domain-group');
            if (parentDomainGroup instanceof HTMLElement) {
                AdminDOM.queryAll('.nav-domain-group').forEach(group => {
                    if (group !== parentDomainGroup && group instanceof HTMLElement) {
                        group.classList.remove('is-open');
                        const h = group.querySelector('.nav-domain-header');
                        if (h instanceof HTMLElement) {
                            h.setAttribute('aria-expanded', 'false');
                        }
                    }
                });
                parentDomainGroup.classList.add('is-open', 'has-active-child');
                const header = parentDomainGroup.querySelector('.nav-domain-header');
                if (header instanceof HTMLElement) {
                    header.setAttribute('aria-expanded', 'true');
                }
            }
        }
        if (target === 'dashboard') {
            const tabToSwitch = (this.dashboardTab && this.dashboardTab !== 'overview') ? this.dashboardTab : 'security';
            window.setTimeout(() => {
                switchDashboardTab(tabToSwitch);
            }, 50);
        }
        if (target === 'security_analytics')
            void initSecurityAnalytics();
        if (target === 'attack_map') {
            TrafficConfigFacade.currentTab = 'geo';
            if (canReuseView) {
                TrafficConfigFacade.switchTab('geo');
            }
            else {
                void TrafficConfigFacade.init().then(() => {
                    TrafficConfigFacade.switchTab('geo');
                });
            }
        }
        if (target === 'waf')
            void loadPoliciesTable();
        if (target === 'waf_config') {
            WAFConfigFacade.currentTab = 'overview';
            if (canReuseView) {
                WAFConfigFacade.switchTab('overview');
            }
            else {
                void WAFConfigFacade.init().then(() => {
                    WAFConfigFacade.switchTab('overview');
                });
            }
        }
        if (target === 'waf_managed') {
            WAFConfigFacade.currentTab = 'managed';
            if (canReuseView) {
                WAFConfigFacade.switchTab('managed');
            }
            else {
                void WAFConfigFacade.init().then(() => {
                    WAFConfigFacade.switchTab('managed');
                });
            }
        }
        if (target === 'waf_custom') {
            WAFConfigFacade.currentTab = 'custom';
            if (canReuseView) {
                WAFConfigFacade.switchTab('custom');
            }
            else {
                void WAFConfigFacade.init().then(() => {
                    WAFConfigFacade.switchTab('custom');
                });
            }
        }
        if (target === 'waf_exclusions') {
            WAFConfigFacade.currentTab = 'exclusions';
            if (canReuseView) {
                WAFConfigFacade.switchTab('exclusions');
            }
            else {
                void WAFConfigFacade.init().then(() => {
                    WAFConfigFacade.switchTab('exclusions');
                });
            }
        }
        if (target === 'waf_body_guard') {
            WAFConfigFacade.currentTab = 'overview';
            if (canReuseView) {
                WAFConfigFacade.switchTab('overview');
            }
            else {
                void WAFConfigFacade.init().then(() => {
                    WAFConfigFacade.switchTab('overview');
                });
            }
        }
        if (target === 'dlp_config') {
            WAFConfigFacade.currentTab = 'leak_protection';
            if (canReuseView) {
                WAFConfigFacade.switchTab('leak_protection');
            }
            else {
                void WAFConfigFacade.init().then(() => {
                    WAFConfigFacade.switchTab('leak_protection');
                });
            }
        }
        if (target === 'dlp_redaction') {
            WAFConfigFacade.currentTab = 'leak_protection';
            if (canReuseView) {
                WAFConfigFacade.switchTab('leak_protection');
                WAFConfigFacade.leakProtectionPage = 'advanced';
                WAFConfigFacade.render();
            }
            else {
                void WAFConfigFacade.init().then(() => {
                    WAFConfigFacade.switchTab('leak_protection');
                    WAFConfigFacade.leakProtectionPage = 'advanced';
                    WAFConfigFacade.render();
                });
            }
        }
        if (target === 'traffic_config') {
            TrafficConfigFacade.currentTab = 'overview';
            if (canReuseView) {
                TrafficConfigFacade.switchTab('overview');
            }
            else {
                void TrafficConfigFacade.init().then(() => {
                    TrafficConfigFacade.switchTab('overview');
                });
            }
        }
        if (target === 'ddos_config') {
            TrafficConfigFacade.currentTab = 'ddos';
            if (canReuseView) {
                TrafficConfigFacade.switchTab('ddos');
            }
            else {
                void TrafficConfigFacade.init().then(() => {
                    TrafficConfigFacade.switchTab('ddos');
                });
            }
        }
        if (target === 'ratelimit_config') {
            TrafficConfigFacade.currentTab = 'ratelimit';
            if (canReuseView) {
                TrafficConfigFacade.switchTab('ratelimit');
            }
            else {
                void TrafficConfigFacade.init().then(() => {
                    TrafficConfigFacade.switchTab('ratelimit');
                });
            }
        }
        if (target === 'traffic_access_geo' || target === 'traffic_blacklist') {
            TrafficConfigFacade.currentTab = 'blacklist';
            if (canReuseView) {
                TrafficConfigFacade.switchTab('blacklist');
            }
            else {
                void TrafficConfigFacade.init().then(() => {
                    TrafficConfigFacade.switchTab('blacklist');
                });
            }
        }
        if (target === 'traffic_geo') {
            TrafficConfigFacade.currentTab = 'geo';
            if (canReuseView) {
                TrafficConfigFacade.switchTab('geo');
            }
            else {
                void TrafficConfigFacade.init().then(() => {
                    TrafficConfigFacade.switchTab('geo');
                });
            }
        }
        if (target === 'traffic_priority') {
            TrafficConfigFacade.currentTab = 'priority';
            if (canReuseView) {
                TrafficConfigFacade.switchTab('priority');
            }
            else {
                void TrafficConfigFacade.init().then(() => {
                    TrafficConfigFacade.switchTab('priority');
                });
            }
        }
        if (target === 'threat_intel') {
            TrafficConfigFacade.currentTab = 'reputation';
            if (canReuseView) {
                TrafficConfigFacade.switchTab('reputation');
            }
            else {
                void TrafficConfigFacade.init().then(() => {
                    TrafficConfigFacade.switchTab('reputation');
                });
            }
        }
        if (target === 'module_reputation')
            void ReputationConfig.init();
        const httpsecTabs = {
            httpsecurity_config: 'overview',
            httpsec_request: 'request_policy',
            httpsec_payload: 'payload_protection',
            httpsec_upload: 'upload_security',
            httpsec_response: 'response_protection',
        };
        if (httpsecTabs[target]) {
            const tab = httpsecTabs[target];
            if (canReuseView) {
                HTTPSecurityConfigFacade.switchTab(tab);
            }
            else {
                void HTTPSecurityConfigFacade.init().then(() => {
                    HTTPSecurityConfigFacade.switchTab(tab);
                });
            }
        }
        const apisecTabs = {
            apisecurity_config: 'overview',
            api_schema: 'contract',
            api_owasp: 'authorization',
            api_inventory: 'inventory',
            api_graphql: 'graphql',
            api_jwt: 'authorization',
            api_shield: 'overview',
        };
        if (apisecTabs[target]) {
            const tab = apisecTabs[target];
            if (canReuseView) {
                APISecurityConfigFacade.switchTab(tab);
            }
            else {
                void APISecurityConfigFacade.init().then(() => {
                    APISecurityConfigFacade.switchTab(tab);
                });
            }
        }
        const antibotTabs = {
            antibots_config: 'overview',
            bot_classification: 'classification',
            bot_fingerprinting: 'managed',
            bot_rules: 'rules',
            bot_ai: 'ai',
            bot_exceptions: 'exceptions',
            bot_management: 'overview',
        };
        if (antibotTabs[target]) {
            const tab = antibotTabs[target];
            if (canReuseView) {
                AntibotsConfigFacade.switchTab(tab);
            }
            else {
                void AntibotsConfigFacade.init().then(() => {
                    AntibotsConfigFacade.switchTab(tab);
                });
            }
        }
        const accessTabs = {
            access_config: 'apps',
            access_apps: 'apps',
            access_policies: 'policies',
            access_identity: 'identity',
            access_idp: 'identity',
            access_roles: 'roles',
            access_decisions: 'decisions',
            access_settings: 'runtime',
            access_mtls: 'identity',
            access_sessions: 'decisions',
        };
        if (accessTabs[target]) {
            const tab = accessTabs[target];
            if (canReuseView) {
                AccessControlConfigFacade.switchTab(tab);
            }
            else {
                void AccessControlConfigFacade.init().then(() => {
                    AccessControlConfigFacade.switchTab(tab);
                });
            }
        }
        if (target === 'modules') {
            const container = AdminDOM.getById('modules-dashboard');
            if (container)
                container.innerHTML = String(ModuleDashboard.render() || '');
        }
        if (target === 'module_captcha')
            void CaptchaConfig.init();
        if (target === 'module_challenge')
            void ChallengeConfig.init();
        if (target === 'routes')
            void loadRoutesTable();
        if (target === 'proxy_settings')
            void loadProxySettingsPage();
        if (target === 'settings')
            void loadSettingsPage();
        if (target === 'logs')
            void loadThreatLogsPage();
        if (target === 'upstream')
            void loadUpstreamsPage();
        if (target === 'ssl')
            void loadSSLPage();
        if (target === 'users')
            void loadUsersPage();
        if (target === 'profile')
            void loadProfilePage();
        if (target === 'audit')
            void loadAuditLogsPage();
    }
};
globalThis.router = router;
export { refreshThreatLogs };
