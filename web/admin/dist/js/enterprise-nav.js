/**
 * Adds paid configuration sections to the shared admin sidebar.
 *
 * The links are created only after the authenticated modules endpoint confirms
 * that the running edition exposes the corresponding section.
 */
import * as AdminDOM from './core/dom.js';
const ENTERPRISE_NAV_ITEMS = [
    {
        target: 'antibots_config',
        label: 'Bot Protection',
        module: 'bot_protection',
        permission: 'waf:read',
        icon: `
      <path d="M8 9V7a4 4 0 0 1 8 0v2"/>
      <rect x="5" y="9" width="14" height="11" rx="3"/>
      <path d="M9 14h.01M15 14h.01M9 17h6M3 12h2M19 12h2M3 17h2M19 17h2"/>
    `
    },
    {
        target: 'apisecurity_config',
        label: 'API Security',
        module: 'api_security',
        permission: 'waf:read',
        icon: `
      <path d="M8 9 4 12l4 3M16 9l4 3-4 3M14 5l-4 14"/>
    `
    },
    {
        target: 'access_config',
        label: 'Edge Access',
        module: 'access_control',
        permission: 'system:config',
        icon: `
      <circle cx="9" cy="8" r="3"/>
      <path d="M3.5 19a5.5 5.5 0 0 1 11 0M16 11l2 2 4-4M18 13v6"/>
    `
    }
];
function buildNavItem(item) {
    const link = document.createElement('a');
    link.className = 'nav-link enterprise-nav-item';
    link.href = '#';
    link.dataset.navTarget = item.target;
    link.dataset.permission = item.permission;
    link.innerHTML = `
    <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">${item.icon}</svg>
    ${item.label}
  `;
    return link;
}
async function loadEnterpriseNavigation() {
    const appSecurityLink = AdminDOM.query('.nav-link[data-nav-target="httpsecurity_config"]');
    if (!appSecurityLink)
        return;
    try {
        const setupResponse = await fetch('/api/setup/status', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
        if (setupResponse.ok) {
            const setup = (await setupResponse.json());
            if (setup.setup_required && setup.user_count === 0)
                return;
        }
        const [modulesResponse, sessionResponse] = await Promise.all([
            fetch('/api/modules', { credentials: 'same-origin', headers: { Accept: 'application/json' } }),
            fetch('/api/verify_session', { credentials: 'same-origin', headers: { Accept: 'application/json' } })
        ]);
        if (!modulesResponse.ok || !sessionResponse.ok)
            return;
        const modules = (await modulesResponse.json());
        const session = (await sessionResponse.json());
        const tier = (modules.license_tier || 'community').trim().toLowerCase();
        const permissions = new Set(session.permissions || []);
        if (tier === 'community') {
            AdminDOM.queryAll('.enterprise-nav-item').forEach(el => el.classList.add('hidden'));
            return;
        }
        AdminDOM.queryAll('.enterprise-nav-item').forEach(el => el.classList.remove('hidden'));
        let insertionPoint = appSecurityLink;
        ENTERPRISE_NAV_ITEMS.forEach(item => {
            if (!modules[item.module] || !permissions.has(item.permission))
                return;
            if (AdminDOM.query(`[data-nav-target="${item.target}"]`))
                return;
            const link = buildNavItem(item);
            insertionPoint.after(link);
            insertionPoint = link;
        });
    }
    catch (error) {
        console.warn('[Aegis] Paid navigation could not be loaded:', error);
    }
}
document.addEventListener('DOMContentLoaded', () => {
    void loadEnterpriseNavigation();
});
document.addEventListener('aegis:license-changed', () => {
    void loadEnterpriseNavigation();
});
