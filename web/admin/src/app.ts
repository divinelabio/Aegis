/**
 * Main admin app bootstrap
 * Source of truth: web/admin/src/app.ts
 * Runtime output: web/admin/dist/js/app.js
 */

import { api } from './api.js';
import { loadAuditLogsPage } from './audit.js';
import { refreshAlerts, toggleAlertDropdown } from './alerts.js';
import * as AdminDOM from './core/dom.js';
import { router, refreshThreatLogs } from './router.js';
import {
  applyVisualExpression,
  addSecurityRuleCondition,
  closeSecurityRuleEditor,
  initSecurityAnalytics,
  saveSecurityRule,
  chooseSecurityRuleType,
  updateRulePreview,
  updateRuleEditorState,
  validateSecurityRule,
  chooseSecurityRuleField,
  closeSecurityRuleFieldMenus,
  insertRuleField,
  removeSecurityRuleCondition,
  openSecurityRuleFieldMenu,
  toggleSecurityRuleFieldMenu,
  updateSecurityRuleConditionControl,
  setSecurityRuleRawMode,
  useExpressionBuilder,
  useExpressionEditor
} from './security.js';
import { WAFConfigFacade } from './sections/waf-config.js';
import { SectionUI } from './sections/ui-components.js';
import { selectSettingsTab } from './settings.js';
import { notify } from './core/notify.js';
import { showUploadCertModal } from './ssl.js';
import { openOriginEditor } from './upstreams.js';
import { maybeShowSetupWizard } from './setup-wizard.js';
import { initSystemUpdateChecker } from './system-update.js';

interface ModulesResponse {
  license_tier?: string;
}

type AdminTheme = 'light' | 'dark';

const THEME_STORAGE_KEY = 'aegis-admin-theme';

const routeMap: Record<string, string> = {
  '/': 'security_analytics',
  '/admin': 'security_analytics',
  '/admin/dashboard': 'dashboard',
  '/admin/overview': 'security_analytics',
  '/admin/analytics/security': 'security_analytics',
  '/admin/analytics/traffic': 'security_analytics',
  '/admin/traffic-events': 'security_analytics',
  '/admin/login': 'login',
  '/admin/waf': 'waf',
  '/admin/rules': 'waf',
  '/admin/attack-map': 'attack_map',
  '/admin/waf-config': 'waf_config',
  '/admin/waf/config': 'waf_config',
  '/admin/waf-core': 'waf_config',
  '/admin/waf/managed': 'waf_managed',
  '/admin/waf-managed': 'waf_managed',
  '/admin/waf/custom': 'waf_custom',
  '/admin/waf-custom': 'waf_custom',
  '/admin/waf/exclusions': 'waf_exclusions',
  '/admin/waf-exclusions': 'waf_exclusions',
  '/admin/waf/body-guard': 'waf_body_guard',
  '/admin/waf-body-guard': 'waf_body_guard',
  '/admin/dlp-config': 'dlp_config',
  '/admin/dlp': 'dlp_config',
  '/admin/dlp/redaction': 'dlp_redaction',
  '/admin/dlp-redaction': 'dlp_redaction',
  '/admin/data-protection': 'dlp_config',
  '/admin/traffic-config': 'traffic_config',
  '/admin/traffic-control': 'traffic_config',
  '/admin/traffic': 'traffic_config',
  '/admin/traffic/access-geo': 'traffic_access_geo',
  '/admin/traffic-access-geo': 'traffic_access_geo',
  '/admin/ddos-config': 'ddos_config',
  '/admin/ddos': 'ddos_config',
  '/admin/ratelimit-config': 'ratelimit_config',
  '/admin/ratelimit': 'ratelimit_config',
  '/admin/rate-limiting': 'ratelimit_config',
  '/admin/threat-intel': 'threat_intel',
  '/admin/threat-intelligence': 'threat_intel',
  '/admin/httpsecurity-config': 'httpsecurity_config',
  '/admin/http-security': 'httpsecurity_config',
  '/admin/app-security': 'httpsecurity_config',
  '/admin/antibots-config': 'antibots_config',
  '/admin/bot-protection': 'antibots_config',
  '/admin/antibots': 'antibots_config',
  '/admin/bot/fingerprinting': 'bot_fingerprinting',
  '/admin/bot-fingerprinting': 'bot_fingerprinting',
  '/admin/bot-challenges': 'module_challenge',
  '/admin/challenges': 'module_challenge',
  '/admin/apisecurity-config': 'apisecurity_config',
  '/admin/api-security': 'apisecurity_config',
  '/admin/apisecurity': 'apisecurity_config',
  '/admin/api-schema': 'api_schema',
  '/admin/api-contracts': 'api_schema',
  '/admin/api-owasp': 'api_owasp',
  '/admin/api/jwt': 'api_jwt',
  '/admin/api-jwt': 'api_jwt',
  '/admin/api/graphql': 'api_graphql',
  '/admin/api-graphql': 'api_graphql',
  '/admin/api-inventory': 'api_inventory',
  '/admin/access-config': 'access_config',
  '/admin/access-control': 'access_config',
  '/admin/access/apps': 'access_apps',
  '/admin/access-apps': 'access_apps',
  '/admin/access/policies': 'access_policies',
  '/admin/access-policies': 'access_policies',
  '/admin/access/identity': 'access_identity',
  '/admin/access-identity': 'access_identity',
  '/admin/access/roles': 'access_roles',
  '/admin/access-roles': 'access_roles',
  '/admin/access/decisions': 'access_decisions',
  '/admin/access-decisions': 'access_decisions',
  '/admin/access/settings': 'access_settings',
  '/admin/access-settings': 'access_settings',
  '/admin/access/idp': 'access_identity',
  '/admin/access-idp': 'access_identity',
  '/admin/access/mtls': 'access_settings',
  '/admin/access-mtls': 'access_settings',
  '/admin/access/sessions': 'access_decisions',
  '/admin/access-sessions': 'access_decisions',
  '/admin/edge-access': 'access_config',
  '/admin/logs': 'logs',
  '/admin/threat-logs': 'logs',
  '/admin/settings': 'settings',
  '/admin/config': 'settings',
  '/admin/proxy': 'proxy_settings',
  '/admin/proxy-settings': 'proxy_settings',
  '/admin/edge': 'proxy_settings',
  '/admin/infrastructure': 'proxy_settings',
  '/admin/routing': 'routes',
  '/admin/routes': 'routes',
  '/admin/upstreams': 'upstream',
  '/admin/upstream': 'upstream',
  '/admin/origins': 'upstream',
  '/admin/ssl': 'ssl',
  '/admin/certificates': 'ssl',
  '/admin/modules': 'modules',
  '/admin/modules/dashboard': 'modules',
  '/admin/modules/captcha': 'module_captcha',
  '/admin/captcha': 'module_captcha',
  '/admin/modules/challenge': 'module_challenge',
  '/admin/challenge': 'module_challenge',
  '/admin/modules/reputation': 'module_reputation',
  '/admin/reputation': 'module_reputation',
  '/admin/users': 'users',
  '/admin/user-management': 'users',
  '/admin/profile': 'profile',
  '/admin/account': 'profile',
  '/admin/audit': 'audit',
  '/admin/audit-logs': 'audit',
  '/admin/about': 'dashboard',
  '/admin/rule-editor': 'rule_editor'
};

function invokeShellAction(action: string): void {
  if (action === 'open-upgrade' || action === 'open-license') {
    selectSettingsTab('license');
    router.navigate('settings');
    return;
  }

  if (action === 'logout') {
    closeAccountMenu();
    logout();
    return;
  }

  if (action === 'toggle-account-menu') {
    toggleAccountMenu();
    return;
  }

  if (action === 'toggle-theme') {
    toggleThemeFromMenu();
    return;
  }

  if (action === 'toggle-alert-dropdown') {
    toggleAlertDropdown();
    return;
  }

  if (action === 'refresh-threat-logs') {
    refreshThreatLogs();
    return;
  }

  if (action === 'show-add-upstream-editor') {
    openOriginEditor();
    return;
  }

  if (action === 'show-upload-cert-modal') {
    showUploadCertModal();
    return;
  }

  if (action === 'refresh-audit-logs') {
    void loadAuditLogsPage();
    return;
  }

  if (action === 'refresh-security-analytics') {
    void initSecurityAnalytics();
    return;
  }

  if (action === 'apply-visual-expression') {
    applyVisualExpression();
    return;
  }

  if (action === 'add-security-rule-condition') {
    addSecurityRuleCondition();
    return;
  }

  if (action === 'remove-security-rule-condition') {
    const activeEvent = globalThis.event;
    const source = activeEvent?.target instanceof Element ? activeEvent.target.closest('[data-condition-index]') : null;
    if (source instanceof HTMLElement) removeSecurityRuleCondition(source.dataset.conditionIndex || '');
    return;
  }

  if (action === 'use-expression-editor') {
    useExpressionEditor();
    return;
  }

  if (action === 'use-expression-builder') {
    useExpressionBuilder();
    return;
  }

  if (action === 'choose-security-rule-type') {
    const activeEvent = globalThis.event;
    const source = activeEvent?.target instanceof Element ? activeEvent.target.closest('[data-rule-type]') : null;
    if (source instanceof HTMLElement) chooseSecurityRuleType(source.dataset.ruleType || 'custom');
    return;
  }

  if (action === 'validate-security-rule') {
    void validateSecurityRule();
    return;
  }

  if (action === 'insert-rule-field') {
    const activeEvent = globalThis.event;
    const source = activeEvent?.target instanceof Element ? activeEvent.target.closest('[data-field]') : null;
    if (source instanceof HTMLElement) insertRuleField(source.dataset.field || '');
    return;
  }

  if (action === 'toggle-security-rule-field-menu') {
    const activeEvent = globalThis.event;
    if (activeEvent?.target instanceof Element) toggleSecurityRuleFieldMenu(activeEvent.target);
    return;
  }

  if (action === 'choose-security-rule-field') {
    const activeEvent = globalThis.event;
    const source = activeEvent?.target instanceof Element ? activeEvent.target.closest('[data-field]') : null;
    if (source instanceof HTMLElement) chooseSecurityRuleField(source);
    return;
  }

  if (action === 'save-security-rule') {
    const activeEvent = globalThis.event;
    const source = activeEvent?.target instanceof Element ? activeEvent.target.closest('[data-rule-id]') : null;
    if (source instanceof HTMLElement) void saveSecurityRule(source.dataset.ruleId || undefined, source.dataset.saveMode === 'draft');
    return;
  }

  if (action === 'close-security-rule-editor') {
    void closeSecurityRuleEditor();
    return;
  }

}

function bindSidebarQuickSearch(): void {
  const searchInput = AdminDOM.getById<HTMLInputElement>('sidebar-quick-search');
  if (!searchInput) return;

  const searchBox = AdminDOM.query('.sidebar-search-box');
  if (searchBox instanceof HTMLElement) {
    searchBox.addEventListener('click', (event) => {
      if (event.target !== searchInput) {
        searchInput.focus();
      }
    });
  }

  const handleSearch = () => {
    const rawQuery = searchInput.value.trim().toLowerCase();
    const navMenu = AdminDOM.query('.nav-menu');
    if (!navMenu) return;

    const domainGroups = navMenu.querySelectorAll<HTMLElement>('.nav-domain-group');
    const topLinks = navMenu.querySelectorAll<HTMLElement>('.nav-menu > .nav-link');
    const categoryLabels = navMenu.querySelectorAll<HTMLElement>('.nav-category-label');

    if (!rawQuery) {
      domainGroups.forEach(group => {
        if (group.classList.contains('hidden')) return;
        group.style.display = '';
        const childLinks = group.querySelectorAll<HTMLElement>('.nav-sub-link');
        childLinks.forEach(link => {
          if (!link.classList.contains('hidden')) {
            link.style.display = '';
          }
        });
        const hasActive = group.classList.contains('has-active-child');
        group.classList.toggle('is-open', hasActive);
        const header = group.querySelector('.nav-domain-header');
        if (header instanceof HTMLElement) {
          header.setAttribute('aria-expanded', hasActive ? 'true' : 'false');
        }
      });
      topLinks.forEach(link => {
        if (!link.classList.contains('hidden')) {
          link.style.display = '';
        }
      });
      categoryLabels.forEach(cat => {
        if (!cat.classList.contains('hidden')) {
          cat.style.display = '';
        }
      });
      return;
    }

    topLinks.forEach(link => {
      if (link.classList.contains('hidden')) {
        link.style.display = 'none';
        return;
      }
      const text = link.textContent?.trim().toLowerCase() || '';
      const matches = text.includes(rawQuery);
      link.style.display = matches ? '' : 'none';
    });

    domainGroups.forEach(group => {
      if (group.classList.contains('hidden')) {
        group.style.display = 'none';
        return;
      }
      const groupTitleEl = group.querySelector('.nav-domain-title');
      const groupTitle = groupTitleEl?.textContent?.trim().toLowerCase() || '';
      const groupMatches = groupTitle.includes(rawQuery);

      const subLinks = group.querySelectorAll<HTMLElement>('.nav-sub-link');
      let matchingSublinksCount = 0;

      subLinks.forEach(link => {
        if (link.classList.contains('hidden')) {
          link.style.display = 'none';
          return;
        }
        const linkText = link.textContent?.trim().toLowerCase() || '';
        const linkMatches = groupMatches || linkText.includes(rawQuery);
        link.style.display = linkMatches ? '' : 'none';
        if (linkMatches) matchingSublinksCount++;
      });

      if (groupMatches || matchingSublinksCount > 0) {
        group.style.display = '';
        group.classList.add('is-open');
        const header = group.querySelector('.nav-domain-header');
        if (header instanceof HTMLElement) {
          header.setAttribute('aria-expanded', 'true');
        }
      } else {
        group.style.display = 'none';
        group.classList.remove('is-open');
        const header = group.querySelector('.nav-domain-header');
        if (header instanceof HTMLElement) {
          header.setAttribute('aria-expanded', 'false');
        }
      }
    });

    categoryLabels.forEach(cat => {
      if (cat.classList.contains('hidden')) {
        cat.style.display = 'none';
        return;
      }
      let sibling = cat.nextElementSibling;
      let hasVisibleChild = false;
      while (sibling && !sibling.classList.contains('nav-category-label') && !sibling.classList.contains('nav-group-label')) {
        if (sibling instanceof HTMLElement && !sibling.classList.contains('hidden') && sibling.style.display !== 'none') {
          hasVisibleChild = true;
          break;
        }
        sibling = sibling.nextElementSibling;
      }
      cat.style.display = hasVisibleChild ? '' : 'none';
    });
  };

  const clearBtn = AdminDOM.getById<HTMLButtonElement>('sidebar-search-clear');
  const updateClearBtn = () => {
    if (!clearBtn) return;
    clearBtn.classList.toggle('hidden', !searchInput.value);
  };

  if (clearBtn) {
    clearBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      searchInput.value = '';
      updateClearBtn();
      handleSearch();
      searchInput.focus();
    });
  }

  searchInput.addEventListener('input', () => {
    updateClearBtn();
    handleSearch();
  });

  searchInput.addEventListener('keydown', (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      searchInput.value = '';
      updateClearBtn();
      handleSearch();
      searchInput.blur();
    }
  });
}

function bindShellInteractions(): void {
  bindSidebarQuickSearch();
  const appRoot = AdminDOM.getById('app');
  if (!appRoot) return;

  appRoot.addEventListener('click', event => {
    if (!(event.target instanceof Element)) return;

    if (event.target instanceof HTMLInputElement && event.target.classList.contains('security-rule-field-search')) {
      openSecurityRuleFieldMenu(event.target);
      return;
    }

    const domainHeader = event.target.closest('.nav-domain-header');
    if (domainHeader instanceof HTMLElement) {
      event.preventDefault();
      const domainGroup = domainHeader.closest('.nav-domain-group');
      if (domainGroup instanceof HTMLElement) {
        const willBeOpen = !domainGroup.classList.contains('is-open');
        if (willBeOpen) {
          AdminDOM.queryAll('.nav-domain-group').forEach(otherGroup => {
            if (otherGroup !== domainGroup && otherGroup instanceof HTMLElement) {
              otherGroup.classList.remove('is-open');
              const otherHeader = otherGroup.querySelector('.nav-domain-header');
              if (otherHeader instanceof HTMLElement) {
                otherHeader.setAttribute('aria-expanded', 'false');
              }
            }
          });
        }
        domainGroup.classList.toggle('is-open', willBeOpen);
        domainHeader.setAttribute('aria-expanded', willBeOpen ? 'true' : 'false');
      }
      return;
    }

    const navTargetElement = event.target.closest('[data-nav-target]');
    if (navTargetElement instanceof HTMLElement) {
      event.preventDefault();
      closeAccountMenu();

      const navTarget = navTargetElement.dataset.navTarget;
      if (!navTarget) return;

      const dashboardTab = navTargetElement.dataset.dashboardTab;
      if (dashboardTab) {
        router.dashboardTab = dashboardTab;
      }

      if (navTargetElement.dataset.navPostAction === 'license') {
        selectSettingsTab('license');
      }

      router.navigate(navTarget, navTargetElement);

      if (navTargetElement.dataset.navPostAction === 'waf-rules') {
        window.setTimeout(() => {
          WAFConfigFacade.switchTab('custom');
        }, 200);
      }
      return;
    }

    const actionElement = event.target.closest('[data-action]');
    if (actionElement instanceof HTMLElement) {
      const action = actionElement.dataset.action;
      if (action === 'toggle-theme' && actionElement instanceof HTMLInputElement) return;
      event.preventDefault();
      if (action) invokeShellAction(action);
    } else if (!event.target.closest('.security-rule-field-dropdown')) {
      closeSecurityRuleFieldMenus();
    }
  });

  appRoot.addEventListener('change', event => {
    if (!(event.target instanceof Element)) return;

    if (event.target.id === 'security-rule-type' && event.target instanceof HTMLSelectElement) {
      chooseSecurityRuleType(event.target.value);
      return;
    }

    if (event.target.id === 'security-rule-enabled' || event.target.id === 'security-rule-action') {
      updateRuleEditorState();
    }

    if (event.target.closest('.security-rule-condition-row')) {
      updateSecurityRuleConditionControl(event.target);
      return;
    }

    if (event.target instanceof HTMLInputElement && event.target.dataset.action === 'toggle-theme') {
      toggleThemeFromMenu();
      return;
    }

    const actionElement = event.target.closest('[data-action]');
    if (!(actionElement instanceof HTMLElement)) return;

    const action = actionElement.dataset.action;
    if (action) invokeShellAction(action);
  });

  appRoot.addEventListener('click', event => {
    if (!(event.target instanceof Element)) return;
    if (event.target.closest('.top-account')) return;
    closeAccountMenu();
  });

  appRoot.addEventListener('input', event => {
    if (!(event.target instanceof Element)) return;
    if (event.target.id === 'security-rule-expression') {
      setSecurityRuleRawMode();
      updateRulePreview();
      void validateSecurityRule(false);
    }
    if (event.target.closest('.security-rule-condition-row')) {
      updateSecurityRuleConditionControl(event.target);
    }
  });

  appRoot.addEventListener('submit', event => {
    if (!(event.target instanceof Element)) return;

    const form = event.target.closest('form[data-action="handle-login"]');
    if (!(form instanceof HTMLFormElement)) return;

    void handleLogin(event as SubmitEvent);
  });

  window.addEventListener('popstate', () => {
    const popUrl = new URL(window.location.href);
    const popPath = popUrl.pathname === '/' ? '/' : popUrl.pathname.replace(/\/$/, '');
    const popTab = popUrl.searchParams.get('tab');
    if (popTab) {
      if (popPath.includes('dashboard') || !popPath.includes('settings')) {
        router.dashboardTab = popTab;
      }
      if (popPath.includes('settings')) {
        selectSettingsTab(popTab);
      }
    }
    let popTarget = routeMap[popPath] || 'security_analytics';
    if (popPath.startsWith('/admin/modules/')) {
      const sub = popPath.replace('/admin/modules/', '');
      if (sub === 'captcha') popTarget = 'module_captcha';
      else if (sub === 'challenge') popTarget = 'module_challenge';
      else if (sub === 'reputation') popTarget = 'module_reputation';
      else popTarget = 'modules';
    }
    router.navigate(popTarget, null, { replace: true });
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  applyTheme(getStoredTheme());
  bindShellInteractions();
  document.addEventListener('aegis:license-changed', () => void updatePlanSummary());

  const loader = AdminDOM.getById('global-loader');
  const appRoot = AdminDOM.getById('app');
  const url = new URL(window.location.href);
  const path = url.pathname === '/' ? '/' : url.pathname.replace(/\/$/, '');
  const tabParam = url.searchParams.get('tab');

  if (tabParam) {
    if (path.includes('dashboard') || !path.includes('settings')) {
      router.dashboardTab = tabParam === 'overview' ? 'security' : tabParam;
    }
    if (path.includes('settings')) {
      selectSettingsTab(tabParam);
    }
  } else {
    try {
      const lastDashboardTab = window.sessionStorage.getItem('aegis-last-dashboard-tab');
      if (lastDashboardTab) {
        router.dashboardTab = lastDashboardTab === 'overview' ? 'security' : lastDashboardTab;
      }
    } catch {
      // Storage unavailable
    }
  }

  if (await maybeShowSetupWizard({ firstRunOnly: true })) {
    if (loader) loader.classList.add('hidden');
    if (appRoot) appRoot.classList.remove('hidden');
    return;
  }

  let target = routeMap[path];
  if (!target) {
    if (path.startsWith('/admin/modules/')) {
      const sub = path.replace('/admin/modules/', '');
      if (sub === 'captcha') target = 'module_captcha';
      else if (sub === 'challenge') target = 'module_challenge';
      else if (sub === 'reputation') target = 'module_reputation';
      else if (sub === 'error-pages' || sub === 'error_pages' || sub === 'appearance') target = 'module_error_pages';
      else target = 'modules';
    } else {
      try {
        const lastTarget = window.sessionStorage.getItem('aegis-last-target');
        if (lastTarget && (routeMap['/admin/' + lastTarget] || routeMap[lastTarget])) {
          target = lastTarget;
        }
      } catch {
        // Storage unavailable
      }
      if (!target) target = 'security_analytics';
    }
  }

  if (path === '/admin/login') {
    if (loader) loader.classList.add('hidden');
    if (appRoot) appRoot.classList.remove('hidden');
    router.navigate('login');
    return;
  }

  api.checkSession()
    .then(async isValid => {
      if (!isValid) {
      console.log('[Aegis] Session inactive, redirecting to login');
      if (loader) loader.classList.add('hidden');
      const redirect = encodeURIComponent(window.location.pathname + window.location.search);
      window.location.href = `/admin/login?redirect=${redirect}`;
      return;
      }

      console.log('[Aegis] Session verified, CSRF token loaded');
      if (await maybeShowSetupWizard()) {
        if (loader) loader.classList.add('hidden');
        if (appRoot) appRoot.classList.remove('hidden');
        return;
      }
      if (loader) loader.classList.add('hidden');
      if (appRoot) appRoot.classList.remove('hidden');
      syncThemeMenuState();

      try {
        router.navigate(target);
      } catch (error) {
        console.error('[Aegis] Route bootstrap failed:', error);
        notify('The requested section failed to load. You can still navigate the panel.', 'warning');
      }

      updateSidebarPermissions();
      void updatePlanSummary();
      refreshAlerts();
      void initSystemUpdateChecker();
      const user = api.currentUser;
      if (user) {
        const nameEl = AdminDOM.query('.user-name');
        const roleEl = AdminDOM.query('.user-role');
        if (nameEl instanceof HTMLElement) nameEl.textContent = user.username;
        if (roleEl instanceof HTMLElement) roleEl.textContent = 'Active User';
      }
    })
    .catch(error => {
      console.error('Session check error', error);
      window.location.href = '/admin/login';
    });
});

async function updatePlanSummary(): Promise<void> {
  const planLabel = AdminDOM.getById('top-plan-label');
  const planName = AdminDOM.getById('current-plan-name');
  const upgradeButton = AdminDOM.getById('plan-upgrade-button');

  try {
    const response = await fetch('/api/modules', { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error(`Plan request failed with status ${response.status}`);

    const modules = (await response.json()) as ModulesResponse;
    const normalizedTier = (modules.license_tier || 'community').trim().toLowerCase();

    if (normalizedTier === 'professional' || normalizedTier === 'pro') {
      if (planLabel) {
        planLabel.textContent = 'Plan';
        planLabel.classList.remove('hidden');
      }
      if (planName) {
        planName.textContent = 'Pro';
      }
      if (upgradeButton) upgradeButton.classList.add('hidden');
    } else if (normalizedTier === 'enterprise') {
      if (planLabel) {
        planLabel.textContent = 'Plan';
        planLabel.classList.remove('hidden');
      }
      if (planName) {
        planName.textContent = 'Enterprise';
      }
      if (upgradeButton) upgradeButton.classList.add('hidden');
    } else {
      if (planLabel) {
        planLabel.textContent = '';
        planLabel.classList.add('hidden');
      }
      if (planName) {
        planName.textContent = 'Community Edition';
      }
      if (upgradeButton) upgradeButton.classList.remove('hidden');
    }
  } catch (error) {
    console.warn('[Aegis] Could not load current plan:', error);
    if (planName) planName.textContent = 'Unavailable';
    if (upgradeButton) upgradeButton.classList.add('hidden');
  }
}

async function handleLogin(event: SubmitEvent): Promise<void> {
  event.preventDefault();

  const username = AdminDOM.inputValue('username');
  const password = AdminDOM.inputValue('password');
  const result = await api.login(username, password);

  if (result.success) {
    notify('Login successful', 'success');
    window.setTimeout(() => {
      window.location.href = '/admin/analytics/security';
    }, 500);
    return;
  }

  notify(result.error || 'Invalid credentials', 'error');
}

function logout(): void {
  SectionUI.openConfirmModal(
    'Confirm Logout',
    'Are you sure you want to log out of your session?',
    'Logout',
    'var(--primary)',
    () => {
      SectionUI.closeModal();
      void api.logout();
    }
  );
}

function getStoredTheme(): AdminTheme {
  try {
    return window.localStorage.getItem(THEME_STORAGE_KEY) === 'light' ? 'light' : 'dark';
  } catch {
    return 'dark';
  }
}

function applyTheme(theme: AdminTheme): void {
  document.documentElement.dataset.theme = theme === 'dark' ? 'dark' : 'light';
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Storage can be unavailable in restricted browser contexts.
  }
  syncThemeMenuState();
}

function toggleThemeFromMenu(): void {
  const input = AdminDOM.getById<HTMLInputElement>('admin-theme-switch');
  const nextTheme: AdminTheme = input?.checked ? 'dark' : 'light';
  applyTheme(nextTheme);
}

function syncThemeMenuState(): void {
  const theme: AdminTheme = document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
  const input = AdminDOM.getById<HTMLInputElement>('admin-theme-switch');
  const label = AdminDOM.getById('theme-state-label');

  if (input) {
    input.checked = theme === 'dark';
    input.setAttribute('aria-checked', theme === 'dark' ? 'true' : 'false');
  }

  if (label) label.textContent = theme === 'dark' ? 'Dark' : 'Light';
}

function toggleAccountMenu(): void {
  const menu = AdminDOM.getById('account-menu');
  const trigger = AdminDOM.query('.top-account-trigger');
  if (!(menu instanceof HTMLElement)) return;
  const willOpen = menu.classList.contains('hidden');
  menu.classList.toggle('hidden', !willOpen);
  if (willOpen) syncThemeMenuState();
  if (trigger instanceof HTMLElement) {
    trigger.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
  }
}

function closeAccountMenu(): void {
  const menu = AdminDOM.getById('account-menu');
  const trigger = AdminDOM.query('.top-account-trigger');
  if (menu instanceof HTMLElement) menu.classList.add('hidden');
  if (trigger instanceof HTMLElement) trigger.setAttribute('aria-expanded', 'false');
}

function updateSidebarPermissions(): void {
  if (!api.currentUser) return;

  AdminDOM.queryAll('[data-permission], [data-features]').forEach(link => {
    if (!(link instanceof HTMLElement)) return;
    if (link.classList.contains('nav-domain-group') || link.classList.contains('nav-category-label') || link.classList.contains('nav-group-label')) {
      return;
    }
    const requiredPerm = link.dataset.permission;
    const requiredFeatures = (link.dataset.features || '')
      .split(/\s+/)
      .map(feature => feature.trim())
      .filter(Boolean);
    const permissionAllowed = !requiredPerm || api.hasPermission(requiredPerm);
    const featuresAllowed = requiredFeatures.every(feature => api.hasFeature(feature));
    link.classList.toggle('hidden', !permissionAllowed || !featuresAllowed);
  });

  AdminDOM.queryAll('.nav-domain-group').forEach(group => {
    if (!(group instanceof HTMLElement)) return;
    const requiredPerm = group.dataset.permission;
    const requiredFeatures = (group.dataset.features || '')
      .split(/\s+/)
      .map(feature => feature.trim())
      .filter(Boolean);
    const permissionAllowed = !requiredPerm || api.hasPermission(requiredPerm);
    const featuresAllowed = requiredFeatures.every(feature => api.hasFeature(feature));
    if (!permissionAllowed || !featuresAllowed) {
      group.classList.add('hidden');
      return;
    }
    const links = group.querySelectorAll('.nav-link');
    const hasVisibleChildren = Array.from(links).some(link => !link.classList.contains('hidden'));
    group.classList.toggle('hidden', !hasVisibleChildren);
  });

  AdminDOM.queryAll('.nav-category-label, .nav-group-label').forEach(label => {
    if (!(label instanceof HTMLElement)) return;

    let sibling = label.nextElementSibling;
    let hasVisibleChildren = false;

    while (sibling && !sibling.classList.contains('nav-category-label') && !sibling.classList.contains('nav-group-label')) {
      if (sibling instanceof HTMLElement && !sibling.classList.contains('hidden')) {
        if (sibling.classList.contains('nav-link')) {
          hasVisibleChildren = true;
          break;
        }
        if (sibling.classList.contains('nav-domain-group')) {
          const links = sibling.querySelectorAll('.nav-link');
          const groupHasVisible = Array.from(links).some(link => !link.classList.contains('hidden'));
          if (groupHasVisible) {
            hasVisibleChildren = true;
            break;
          }
        }
      }
      sibling = sibling.nextElementSibling;
    }

    const requiredPermission = label.dataset.permission;
    if (requiredPermission && !api.hasPermission(requiredPermission)) {
      label.classList.add('hidden');
    } else if (!hasVisibleChildren) {
      label.classList.add('hidden');
    } else {
      label.classList.remove('hidden');
    }
  });
}
