import * as AdminDOM from '../core/dom.js';
import { loadSystemDashboard, systemTemplate } from './system.js';
import { disposeTrafficDashboard, initTrafficDashboard, trafficDashboardTemplate } from './traffic.js';
import { disposeWAFDashboard, initWAFDashboard, wafDashboardTemplate } from './waf.js';
/**
 * Dashboard entrypoint.
 *
 * Each restored dashboard owns its layout while sharing the application's
 * operator-frame language and navigation shell.
 */
export function switchDashboardTab(tab = 'security') {
    const container = AdminDOM.getById('dashboard-content');
    if (!container)
        return;
    disposeWAFDashboard();
    disposeTrafficDashboard();
    const normalizedTab = tab === 'system' || tab === 'traffic' ? tab : 'security';
    const pageTitle = AdminDOM.getById('page-title');
    const pageView = container.closest('.view');
    if (normalizedTab === 'system') {
        pageView?.classList.add('view-operator');
        container.innerHTML = systemTemplate;
        container.setAttribute('aria-label', 'Infrastructure dashboard');
        if (pageTitle)
            pageTitle.textContent = 'System Health & Engine Telemetry';
        loadSystemDashboard();
        return;
    }
    if (normalizedTab === 'traffic') {
        pageView?.classList.add('view-operator');
        container.innerHTML = trafficDashboardTemplate;
        container.setAttribute('aria-label', 'Traffic Control dashboard');
        if (pageTitle)
            pageTitle.textContent = 'Traffic Control Dashboard';
        initTrafficDashboard();
        return;
    }
    pageView?.classList.add('view-operator');
    container.innerHTML = wafDashboardTemplate;
    container.setAttribute('aria-label', 'Security Dashboard');
    if (pageTitle)
        pageTitle.textContent = 'Security Dashboard';
    initWAFDashboard();
}
