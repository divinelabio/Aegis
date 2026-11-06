import React, { useState, useEffect, useCallback, useRef, lazy, Suspense } from 'react';
import { Theme, Loading } from '@carbon/react';
import { Shell } from './components/layout/Shell';
import { apiService } from './services/api';
import { AuthProvider, useAuth } from './context/AuthContext';
import { FeatureLockedView } from './components/common';
import { isRouteEntitled } from './utils/features';
import type { NavItemKey } from './types';

// Lazy-loaded route components for optimized initial bundle loading
const OriginsPage = lazy(() => import('./pages/OriginsPage').then((m) => ({ default: m.OriginsPage })));
const RoutingPage = lazy(() => import('./pages/RoutingPage').then((m) => ({ default: m.RoutingPage })));
const ProxySettingsPage = lazy(() => import('./pages/ProxySettingsPage').then((m) => ({ default: m.ProxySettingsPage })));
const SslPage = lazy(() => import('./pages/SslPage').then((m) => ({ default: m.SslPage })));
const WafOverviewPage = lazy(() => import('./pages/WafOverviewPage').then((m) => ({ default: m.WafOverviewPage })));
const WafRulesPage = lazy(() => import('./pages/WafRulesPage').then((m) => ({ default: m.WafRulesPage })));
const WafCustomPage = lazy(() => import('./pages/WafCustomPage').then((m) => ({ default: m.WafCustomPage })));
const WafExclusionsPage = lazy(() => import('./pages/WafExclusionsPage').then((m) => ({ default: m.WafExclusionsPage })));
const WafLeakProtectionPage = lazy(() => import('./pages/WafLeakProtectionPage').then((m) => ({ default: m.WafLeakProtectionPage })));
const AppSecurityOverviewPage = lazy(() => import('./pages/AppSecurityOverviewPage').then((m) => ({ default: m.AppSecurityOverviewPage })));
const AppSecurityRequestPage = lazy(() => import('./pages/AppSecurityRequestPage').then((m) => ({ default: m.AppSecurityRequestPage })));
const AppSecurityPayloadPage = lazy(() => import('./pages/AppSecurityPayloadPage').then((m) => ({ default: m.AppSecurityPayloadPage })));
const AppSecurityUploadPage = lazy(() => import('./pages/AppSecurityUploadPage').then((m) => ({ default: m.AppSecurityUploadPage })));
const AppSecurityResponsePage = lazy(() => import('./pages/AppSecurityResponsePage').then((m) => ({ default: m.AppSecurityResponsePage })));
const RateLimitingPage = lazy(() => import('./pages/RateLimitingPage').then((m) => ({ default: m.RateLimitingPage })));
const BotOverviewPage = lazy(() => import('./pages/BotOverviewPage').then((m) => ({ default: m.BotOverviewPage })));
const BotManagedPage = lazy(() => import('./pages/BotManagedPage').then((m) => ({ default: m.BotManagedPage })));
const BotRulesPage = lazy(() => import('./pages/BotRulesPage').then((m) => ({ default: m.BotRulesPage })));
const BotClassificationPage = lazy(() => import('./pages/BotClassificationPage').then((m) => ({ default: m.BotClassificationPage })));
const BotAiPage = lazy(() => import('./pages/BotAiPage').then((m) => ({ default: m.BotAiPage })));
const BotExceptionsPage = lazy(() => import('./pages/BotExceptionsPage').then((m) => ({ default: m.BotExceptionsPage })));
const SecurityEventsPage = lazy(() => import('./pages/SecurityEventsPage').then((m) => ({ default: m.SecurityEventsPage })));
const TrafficEventsPage = lazy(() => import('./pages/TrafficEventsPage').then((m) => ({ default: m.TrafficEventsPage })));
const ThreatLogsPage = lazy(() => import('./pages/ThreatLogsPage').then((m) => ({ default: m.ThreatLogsPage })));
const TrafficControlOverviewPage = lazy(() => import('./pages/TrafficControlOverviewPage').then((m) => ({ default: m.TrafficControlOverviewPage })));
const IpBlacklistPage = lazy(() => import('./pages/IpBlacklistPage').then((m) => ({ default: m.IpBlacklistPage })));
const GeoBlockingPage = lazy(() => import('./pages/GeoBlockingPage').then((m) => ({ default: m.GeoBlockingPage })));
const IpReputationPage = lazy(() => import('./pages/IpReputationPage').then((m) => ({ default: m.IpReputationPage })));
const TrustedExceptionsPage = lazy(() => import('./pages/TrustedExceptionsPage').then((m) => ({ default: m.TrustedExceptionsPage })));
const ApplicationFloodPage = lazy(() => import('./pages/ApplicationFloodPage').then((m) => ({ default: m.ApplicationFloodPage })));
const ApiSecurityPage = lazy(() => import('./pages/ApiSecurityPage').then((m) => ({ default: m.ApiSecurityPage })));
const EdgeAccessPage = lazy(() => import('./pages/EdgeAccessPage').then((m) => ({ default: m.EdgeAccessPage })));
const ModulesPage = lazy(() => import('./pages/ModulesPage').then((m) => ({ default: m.ModulesPage })));
const AuditLogsPage = lazy(() => import('./pages/AuditLogsPage').then((m) => ({ default: m.AuditLogsPage })));
const SettingsPage = lazy(() => import('./pages/SettingsPage').then((m) => ({ default: m.SettingsPage })));
const ProfilePage = lazy(() => import('./pages/ProfilePage').then((m) => ({ default: m.ProfilePage })));
const UsersPage = lazy(() => import('./pages/UsersPage').then((m) => ({ default: m.UsersPage })));
const SetupWizardPage = lazy(() => import('./pages/SetupWizardPage').then((m) => ({ default: m.SetupWizardPage })));

// Route loaders map for instant prefetching on hover / idle
export const ROUTE_LOADERS: Partial<Record<NavItemKey, () => Promise<any>>> = {
  'origins': () => import('./pages/OriginsPage'),
  'routing': () => import('./pages/RoutingPage'),
  'proxy-settings': () => import('./pages/ProxySettingsPage'),
  'ssl': () => import('./pages/SslPage'),
  'waf-overview': () => import('./pages/WafOverviewPage'),
  'waf-rulesets': () => import('./pages/WafRulesPage'),
  'waf-custom': () => import('./pages/WafCustomPage'),
  'waf-exclusions': () => import('./pages/WafExclusionsPage'),
  'waf-leak': () => import('./pages/WafLeakProtectionPage'),
  'app-security': () => import('./pages/AppSecurityOverviewPage'),
  'app-security-request': () => import('./pages/AppSecurityRequestPage'),
  'app-security-payload': () => import('./pages/AppSecurityPayloadPage'),
  'app-security-upload': () => import('./pages/AppSecurityUploadPage'),
  'app-security-response': () => import('./pages/AppSecurityResponsePage'),
  'traffic-control': () => import('./pages/TrafficControlOverviewPage'),
  'traffic-ratelimit': () => import('./pages/RateLimitingPage'),
  'traffic-blacklist': () => import('./pages/IpBlacklistPage'),
  'traffic-geo': () => import('./pages/GeoBlockingPage'),
  'traffic-reputation': () => import('./pages/IpReputationPage'),
  'traffic-priority': () => import('./pages/TrustedExceptionsPage'),
  'traffic-ddos': () => import('./pages/ApplicationFloodPage'),
  'bot-overview': () => import('./pages/BotOverviewPage'),
  'bot-managed': () => import('./pages/BotManagedPage'),
  'bot-rules': () => import('./pages/BotRulesPage'),
  'bot-classification': () => import('./pages/BotClassificationPage'),
  'bot-ai': () => import('./pages/BotAiPage'),
  'bot-exceptions': () => import('./pages/BotExceptionsPage'),
  'security-events': () => import('./pages/SecurityEventsPage'),
  'traffic-events': () => import('./pages/TrafficEventsPage'),
  'threat-logs': () => import('./pages/ThreatLogsPage'),
  'api-security': () => import('./pages/ApiSecurityPage'),
  'edge-access': () => import('./pages/EdgeAccessPage'),
  'modules': () => import('./pages/ModulesPage'),
  'audit': () => import('./pages/AuditLogsPage'),
  'settings': () => import('./pages/SettingsPage'),
  'profile': () => import('./pages/ProfilePage'),
  'users': () => import('./pages/UsersPage'),
};

export const prefetchRoute = (key: NavItemKey) => {
  const baseKey = key.startsWith('access-') ? 'edge-access' : key.startsWith('api-') ? 'api-security' : key;
  const loader = ROUTE_LOADERS[baseKey as NavItemKey];
  if (loader) {
    try {
      void loader();
    } catch {
    }
  }
};

const LoginPage = lazy(() => import('./pages/auth/LoginPage').then((m) => ({ default: m.LoginPage })));
const ResetRequestPage = lazy(() => import('./pages/auth/ResetRequestPage').then((m) => ({ default: m.ResetRequestPage })));
const ResetConfirmPage = lazy(() => import('./pages/auth/ResetConfirmPage').then((m) => ({ default: m.ResetConfirmPage })));

const SectionLoadingFallback: React.FC = () => (
  <div className="aegis-loading-screen" aria-live="polite">
    <Loading description="Loading section..." withOverlay={false} />
  </div>
);

const AppContent: React.FC = () => {
  const { isAuthenticated, hasFeature, refreshSession } = useAuth();

  const normalizeNav = (raw: string): NavItemKey => {
    let hash = raw.replace(/^#\/?/, '').toLowerCase();
    const qIndex = hash.indexOf('?');
    if (qIndex !== -1) {
      hash = hash.slice(0, qIndex);
    }

    const aliasMap: Record<string, NavItemKey> = {
      'dashboard': 'security-events',
      'security': 'security-events',
      'security_analytics': 'traffic-events',
      'traffic': 'traffic-events',
      'apisecurity-config': 'api-security',
      'api_security': 'api-security',
      'api-shield': 'api-security',
      'api_inventory': 'api-inventory',
      'api_schema': 'api-contracts',
      'api-contracts': 'api-contracts',
      'api_owasp': 'api-authorization',
      'api_jwt': 'api-authorization',
      'api-authorization': 'api-authorization',
      'api_graphql': 'api-graphql',
      'api-graphql': 'api-graphql',
      'waf-leak': 'waf-leak',
      'waf-leak-protection': 'waf-leak',
      'dlp_config': 'waf-leak',
      'bot-rule-create': 'bot-rules',
      'bot-rules-new': 'bot-rules',
      'bot-rule-edit': 'bot-rules',
      'module_reputation': 'modules',
      'modules-reputation': 'modules',
      'reputation': 'modules',
      'module_captcha': 'modules',
      'module_challenge': 'modules',
      'module_error_pages': 'modules',
      'modules-captcha': 'modules',
      'modules-challenge': 'modules',
      'modules-errorpages': 'modules',
      'error-pages': 'modules',
      'errorpages': 'modules',
      'error_pages': 'modules',
      'bot-challenges': 'modules',
      'challenges': 'modules',
      'captcha': 'modules',
      'audit-logs': 'audit',
      'audit_logs': 'audit',
      'audit-trail': 'audit',
      'audit_trail': 'audit',
      'profile': 'profile',
      'my-profile': 'profile',
      'user-profile': 'profile',
      'users': 'users',
      'operators': 'users',
      'roles': 'users',
      'user-management': 'users',
      'users-management': 'users',
      'access-management': 'users',
      'login': 'login',
      'signin': 'login',
      'sign-in': 'login',
      'auth': 'login',
      'request-reset': 'request-reset',
      'forgot-password': 'request-reset',
      'reset-request': 'request-reset',
      'reset-password': 'reset-password',
      'reset-confirm': 'reset-password',
      'app-security': 'app-security',
      'app-security-overview': 'app-security',
      'app_security': 'app-security',
      'waf_config': 'waf-overview',
      'antibots_config': 'bot-overview',
      'traffic_config': 'traffic-control',
      'access_config': 'edge-access',
      'apisecurity_config': 'api-security',
      'httpsecurity_config': 'app-security',
    };
    if (aliasMap[hash]) return aliasMap[hash];

    const validNavs: NavItemKey[] = [
      'security-events', 'traffic-events', 'threat-logs',
      'origins', 'routing', 'proxy-settings', 'ssl',
      'waf-overview', 'waf-rulesets', 'waf-custom', 'waf-exclusions', 'waf-leak', 'waf-leak-protection',
      'traffic-control', 'traffic-overview', 'traffic-ratelimit',
      'traffic-blacklist', 'traffic-geo', 'traffic-reputation', 'traffic-ddos', 'traffic-priority',
      'app-security', 'app-security-overview', 'app-security-request', 'app-security-payload', 'app-security-upload', 'app-security-response',
      'bot-overview', 'bot-managed', 'bot-rules', 'bot-classification', 'bot-ai', 'bot-exceptions',
      'api-security', 'api-inventory', 'api-contracts', 'api-authorization', 'api-graphql',
      'edge-access', 'access-apps', 'access-policies', 'access-identity', 'access-roles', 'access-decisions', 'access-runtime',
      'modules', 'settings', 'settings-license' as any, 'audit', 'profile', 'users',
      'login', 'request-reset', 'reset-password',
    ];
    if (hash === 'app-security' || hash === 'app-security-overview') return 'app-security';
    if (hash.startsWith('app-security-') && validNavs.includes(hash as NavItemKey)) return hash as NavItemKey;
    if (hash.startsWith('bot-') && validNavs.includes(hash as NavItemKey)) return hash as NavItemKey;
    if (hash.startsWith('api-') && validNavs.includes(hash as NavItemKey)) return hash as NavItemKey;
    if (hash.startsWith('access-') && validNavs.includes(hash as NavItemKey)) return hash as NavItemKey;
    if (validNavs.includes(hash as NavItemKey)) return hash as NavItemKey;
    return 'security-events';
  };

  const getInitialNav = (): NavItemKey => {
    const pathname = window.location.pathname.toLowerCase();
    if (pathname.includes('reset-confirm')) {
      return 'reset-password';
    }
    if (pathname.includes('request-reset')) {
      return 'request-reset';
    }
    return normalizeNav(window.location.hash);
  };

  const getInitialTheme = (): 'g100' | 'g10' => {
    try {
      const stored = window.localStorage.getItem('aegis-admin-theme');
      if (stored === 'light') return 'g10';
      return 'g100';     } catch {
      return 'g100';
    }
  };

  const [activeNav, setActiveNav] = useState<NavItemKey>(getInitialNav);
  const [theme, setTheme] = useState<'g100' | 'g10'>(getInitialTheme);
  const [licenseTier, setLicenseTier] = useState<string>('community');
  const [setupRequired, setSetupRequired] = useState<boolean>(false);
  const [checkingSetup, setCheckingSetup] = useState<boolean>(!isAuthenticated);

  useEffect(() => {
    if (isAuthenticated) {
      setCheckingSetup(false);
      return;
    }
    let isMounted = true;
    const checkSetup = async () => {
      try {
        const res = await apiService.getSetupStatus();
        if (isMounted && res && res.setup_required && res.user_count === 0) {
          setSetupRequired(true);
        }
      } catch {
      } finally {
        if (isMounted) {
          setCheckingSetup(false);
        }
      }
    };
    checkSetup();
    return () => {
      isMounted = false;
    };
  }, [isAuthenticated]);

  useEffect(() => {
    if (!isAuthenticated) return;
    const fetchTier = async () => {
      try {
        const lic = await apiService.getLicense();
        if (lic?.effective_tier) {
          setLicenseTier(lic.effective_tier.toLowerCase());
        } else if (lic?.licensed_tier) {
          setLicenseTier(lic.licensed_tier.toLowerCase());
        }
      } catch {
      }
    };
    fetchTier();

    const handleLicenseChanged = () => {
      fetchTier();
    };
    window.addEventListener('aegis:license-changed', handleLicenseChanged);
    return () => window.removeEventListener('aegis:license-changed', handleLicenseChanged);
  }, [isAuthenticated]);

  useEffect(() => {
    if (!isAuthenticated) return;
    // Background idle warmup of all primary route bundles so subsequent clicks are instantaneous
    const timer = setTimeout(() => {
      const keys = Object.keys(ROUTE_LOADERS) as NavItemKey[];
      let idx = 0;
      const step = () => {
        if (idx < keys.length) {
          prefetchRoute(keys[idx++]);
          if (typeof (window as any).requestIdleCallback === 'function') {
            (window as any).requestIdleCallback(step);
          } else {
            setTimeout(step, 60);
          }
        }
      };
      if (typeof (window as any).requestIdleCallback === 'function') {
        (window as any).requestIdleCallback(step);
      } else {
        setTimeout(step, 100);
      }
    }, 600);
    return () => clearTimeout(timer);
  }, [isAuthenticated]);

  const isManualNavRef = useRef<boolean>(false);

  const handleSelectNav = useCallback((key: NavItemKey) => {
    const targetHash = `#${key}`;
    if (window.location.hash !== targetHash) {
      isManualNavRef.current = true;
      window.location.hash = targetHash;
    }
    // Instant tab activation for immediate, snappy feedback
    setActiveNav(key);

    // Asynchronous scroll reset to avoid forced synchronous layout reflow
    requestAnimationFrame(() => {
      const mainEl = document.getElementById('aegis-main-content');
      if (mainEl && mainEl.scrollTop > 0) {
        mainEl.scrollTop = 0;
      }
    });
  }, []);

  useEffect(() => {
    const handleHashChange = () => {
      if (isManualNavRef.current) {
        isManualNavRef.current = false;
        return;
      }
      const normalized = normalizeNav(window.location.hash);
      if (normalized) {
        setActiveNav(normalized);
        requestAnimationFrame(() => {
          const mainEl = document.getElementById('aegis-main-content');
          if (mainEl && mainEl.scrollTop > 0) {
            mainEl.scrollTop = 0;
          }
        });
      }
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  // Idle background prefetching for instant route transitions
  useEffect(() => {
    if (!isAuthenticated) return;
    const popularRoutes: NavItemKey[] = [
      'traffic-events', 'threat-logs', 'waf-overview', 'waf-rulesets',
      'traffic-control', 'origins', 'routing', 'edge-access', 'api-security'
    ];
    const timer = setTimeout(() => {
      popularRoutes.forEach((r) => prefetchRoute(r));
    }, 1200);
    return () => clearTimeout(timer);
  }, [isAuthenticated]);

  useEffect(() => {
    if (isAuthenticated && activeNav === 'login') {
      handleSelectNav('security-events');
    }
  }, [isAuthenticated, activeNav, handleSelectNav]);

  useEffect(() => {
    try {
      document.documentElement.dataset.theme = theme === 'g10' ? 'light' : 'dark';
    } catch {
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => {
      const next = prev === 'g100' ? 'g10' : 'g100';
      try {
        window.localStorage.setItem('aegis-admin-theme', next === 'g10' ? 'light' : 'dark');
        document.documentElement.dataset.theme = next === 'g10' ? 'light' : 'dark';
      } catch {
      }
      return next;
    });
  };

  if (activeNav === 'request-reset') {
    return (
      <Suspense fallback={null}>
        <Theme theme={theme}>
          <ResetRequestPage />
        </Theme>
      </Suspense>
    );
  }

  if (activeNav === 'reset-password') {
    return (
      <Suspense fallback={null}>
        <Theme theme={theme}>
          <ResetConfirmPage />
        </Theme>
      </Suspense>
    );
  }

  if (!isAuthenticated) {
    if (checkingSetup) {
      return (
        <Theme theme={theme}>
          <SectionLoadingFallback />
        </Theme>
      );
    }

    if (setupRequired) {
      return (
        <Suspense fallback={<SectionLoadingFallback />}>
          <Theme theme={theme}>
            <SetupWizardPage
              onComplete={async () => {
                setSetupRequired(false);
                await refreshSession();
                handleSelectNav('security-events');
              }}
            />
          </Theme>
        </Suspense>
      );
    }

    return (
      <Suspense fallback={null}>
        <Theme theme={theme}>
          <LoginPage
            onSuccess={() => {
              const currentHash = normalizeNav(window.location.hash);
              const targetNav =
                currentHash && !['login', 'request-reset', 'reset-password'].includes(currentHash)
                  ? currentHash
                  : activeNav && !['login', 'request-reset', 'reset-password'].includes(activeNav)
                  ? activeNav
                  : 'security-events';
              handleSelectNav(targetNav);
            }}
          />
        </Theme>
      </Suspense>
    );
  }

  const effectiveNav: NavItemKey = activeNav === 'login' ? 'security-events' : activeNav;

  const renderContent = () => {
    if (!isRouteEntitled(effectiveNav, hasFeature)) {
      return <FeatureLockedView navKey={effectiveNav} onNavigate={handleSelectNav} />;
    }

    let content: React.ReactNode;
    switch (effectiveNav) {
      case 'security-events':
        content = <SecurityEventsPage onNavigate={handleSelectNav} />;
        break;
      case 'traffic-events':
        content = <TrafficEventsPage onNavigate={handleSelectNav} />;
        break;
      case 'threat-logs':
        content = <ThreatLogsPage onNavigate={handleSelectNav} />;
        break;

      case 'origins':
        content = <OriginsPage />;
        break;
      case 'routing':
        content = <RoutingPage onNavigate={handleSelectNav} />;
        break;
      case 'proxy-settings':
        content = <ProxySettingsPage />;
        break;
      case 'ssl':
        content = <SslPage />;
        break;

      case 'waf-overview':
        content = <WafOverviewPage onNavigate={handleSelectNav} />;
        break;
      case 'waf-rulesets':
        content = <WafRulesPage />;
        break;
      case 'waf-custom':
        content = <WafCustomPage />;
        break;
      case 'waf-leak':
      case 'waf-leak-protection':
        content = <WafLeakProtectionPage />;
        break;
      case 'waf-exclusions':
        content = <WafExclusionsPage />;
        break;

      case 'traffic-control':
      case 'traffic-overview':
        content = <TrafficControlOverviewPage onNavigate={handleSelectNav} />;
        break;
      case 'traffic-ratelimit':
        content = <RateLimitingPage />;
        break;
      case 'traffic-blacklist':
        content = <IpBlacklistPage />;
        break;
      case 'traffic-geo':
        content = <GeoBlockingPage />;
        break;
      case 'traffic-reputation':
        content = <IpReputationPage />;
        break;
      case 'traffic-priority':
        content = <TrustedExceptionsPage />;
        break;
      case 'traffic-ddos':
        content = <ApplicationFloodPage />;
        break;

      case 'app-security':
      case 'app-security-overview':
        content = <AppSecurityOverviewPage onNavigate={handleSelectNav} />;
        break;
      case 'app-security-request':
        content = <AppSecurityRequestPage onNavigate={handleSelectNav} />;
        break;
      case 'app-security-payload':
        content = <AppSecurityPayloadPage onNavigate={handleSelectNav} />;
        break;
      case 'app-security-upload':
        content = <AppSecurityUploadPage onNavigate={handleSelectNav} />;
        break;
      case 'app-security-response':
        content = <AppSecurityResponsePage onNavigate={handleSelectNav} />;
        break;

      case 'bot-overview':
        content = <BotOverviewPage onNavigate={handleSelectNav} />;
        break;
      case 'bot-managed':
        content = <BotManagedPage onNavigate={handleSelectNav} />;
        break;
      case 'bot-rules':
        content = <BotRulesPage />;
        break;
      case 'bot-classification':
        content = <BotClassificationPage />;
        break;
      case 'bot-ai':
        content = <BotAiPage />;
        break;
      case 'bot-exceptions':
        content = <BotExceptionsPage />;
        break;

      case 'api-security':
      case 'api-inventory':
      case 'api-contracts':
      case 'api-authorization':
      case 'api-graphql':
        content = <ApiSecurityPage activeNavKey={activeNav} onNavigate={handleSelectNav} />;
        break;

      case 'edge-access':
      case 'access-apps':
      case 'access-policies':
      case 'access-identity':
      case 'access-roles':
      case 'access-decisions':
      case 'access-runtime':
        content = <EdgeAccessPage activeNavKey={activeNav} onNavigate={handleSelectNav} />;
        break;

      case 'modules':
        content = <ModulesPage onNavigate={handleSelectNav} />;
        break;
      case 'audit':
        content = <AuditLogsPage />;
        break;
      case 'settings':
        content = <SettingsPage />;
        break;

      case 'profile':
        content = <ProfilePage />;
        break;

      case 'users':
        content = <UsersPage />;
        break;

      default:
        content = <SecurityEventsPage onNavigate={handleSelectNav} />;
    }

    const getModuleKey = (nav: NavItemKey): string => {
      if (nav.startsWith('access-') || nav === 'edge-access') return 'edge-access-module';
      if (nav.startsWith('api-')) return 'api-shield-module';
      if (nav === 'traffic-overview') return 'traffic-control';
      if (nav === 'waf-leak-protection') return 'waf-leak';
      if (nav === 'users') return 'user-management';
      return nav;
    };
    const moduleKey = getModuleKey(effectiveNav);

    return (
      <Suspense fallback={<SectionLoadingFallback />}>
        <div key={effectiveNav} className="aegis-page-transition" data-module={moduleKey}>
          {content}
        </div>
      </Suspense>
    );
  };

  return (
    <Shell
      activeNav={effectiveNav}
      onSelectNav={handleSelectNav}
      onPreloadNav={prefetchRoute}
      theme={theme}
      onToggleTheme={toggleTheme}
      licenseTier={licenseTier}
    >
      {renderContent()}
    </Shell>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};

export default App;
