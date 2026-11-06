import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Button,
  InlineNotification,
} from '@carbon/react';
import {
  Security,
  SettingsAdjust,
  Activity,
  Upload,
  Network_3,
  WarningAlt,
} from '@carbon/icons-react';
import {
  PageHeader,
  MetricStrip,
  KpiCard,
  SectionCard,
  StatusToggle,
  HeaderSwitcher,
  SaveActionBar,
} from '../components/common';
import { apiService } from '../services/api';
import type {
  NavItemKey,
  AppSecurityEffectiveState,
  AppSecurityConfig,
  AppSecurityStats,
} from '../types';

interface AppSecurityOverviewPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

export const AppSecurityOverviewPage: React.FC<AppSecurityOverviewPageProps> = ({ onNavigate }) => {
  const [_loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [effectiveState, setEffectiveState] = useState<AppSecurityEffectiveState | null>(null);
  const [serverConfig, setServerConfig] = useState<AppSecurityConfig>({ enabled: true });
  const [stats, setStats] = useState<AppSecurityStats>({ total: 0, blocked: 0, allowed: 0, compressed: 0 });

  const [enabled, setEnabled] = useState<boolean>(true);

  const [httpsRedirect, setHttpsRedirect] = useState<boolean>(false);
  const [infoHiding, setInfoHiding] = useState<boolean>(true);
  const [cookieHardener, setCookieHardener] = useState<boolean>(true);
  const [gzipEnabled, setGzipEnabled] = useState<boolean>(true);

  const handleNavigate = (key: NavItemKey) => {
    if (onNavigate) {
      onNavigate(key);
    } else {
      window.location.hash = `#${key}`;
    }
  };

  const loadData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [effRes, cfgRes, statsRes] = await Promise.allSettled([
        apiService.getAppSecurityEffectiveState(),
        apiService.getAppSecurityConfig(),
        apiService.getAppSecurityStats(),
      ]);

      let effData: AppSecurityEffectiveState | null = null;
      let cfgData: AppSecurityConfig | null = null;
      let statsData: AppSecurityStats = { total: 0, blocked: 0, allowed: 0, compressed: 0 };

      if (effRes.status === 'fulfilled' && effRes.value) {
        effData = effRes.value;
        setEffectiveState(effData);
      }

      if (cfgRes.status === 'fulfilled' && cfgRes.value) {
        cfgData = cfgRes.value;
        setServerConfig(cfgData);
      }

      if (statsRes.status === 'fulfilled' && statsRes.value) {
        statsData = statsRes.value;
        setStats(statsData);
      }

      const isGloballyEnabled = cfgData
        ? cfgData.enabled !== false
        : effData
          ? effData.section_enabled !== false
          : true;

      setEnabled(isGloballyEnabled);

      if (cfgData) {
        setHttpsRedirect(Boolean(cfgData.https_redirect?.enabled));
        setInfoHiding(cfgData.info_hiding ? cfgData.info_hiding.enabled !== false : true);
        setCookieHardener(cfgData.cookie_hardener ? cfgData.cookie_hardener.enabled !== false : true);
        setGzipEnabled(cfgData.gzip ? cfgData.gzip.enabled !== false : true);
      }
    } catch (err: any) {
      console.error('[AppSecurityOverviewPage] Error loading data:', err);
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleMasterToggle = async (next: boolean) => {
    setEnabled(next);
    try {
      const res = await apiService.saveAppSecurityConfig({ enabled: next });
      if (res.success) {
        setNotification({
          type: 'success',
          message: `Application Security engine ${next ? 'enabled' : 'disabled'}.`,
        });
        await loadData(true);
      } else {
        throw new Error(res.error || 'Failed to update engine status.');
      }
    } catch (err: any) {
      setEnabled(!next);
      setNotification({
        type: 'error',
        message: err?.message || 'Failed to update engine status.',
      });
    }
  };

  const isDirty = useMemo(() => {
    const origHttps = Boolean(serverConfig.https_redirect?.enabled);
    const origInfo = serverConfig.info_hiding ? serverConfig.info_hiding.enabled !== false : true;
    const origCookie = serverConfig.cookie_hardener ? serverConfig.cookie_hardener.enabled !== false : true;
    const origGzip = serverConfig.gzip ? serverConfig.gzip.enabled !== false : true;

    return (
      httpsRedirect !== origHttps ||
      infoHiding !== origInfo ||
      cookieHardener !== origCookie ||
      gzipEnabled !== origGzip
    );
  }, [serverConfig, httpsRedirect, infoHiding, cookieHardener, gzipEnabled]);

  const handleReset = () => {
    setHttpsRedirect(Boolean(serverConfig.https_redirect?.enabled));
    setInfoHiding(serverConfig.info_hiding ? serverConfig.info_hiding.enabled !== false : true);
    setCookieHardener(serverConfig.cookie_hardener ? serverConfig.cookie_hardener.enabled !== false : true);
    setGzipEnabled(serverConfig.gzip ? serverConfig.gzip.enabled !== false : true);
  };

  const handleSave = async () => {
    setSaving(true);
    setNotification(null);
    try {
      const updates: Partial<AppSecurityConfig> = {
        https_redirect: {
          enabled: httpsRedirect,
          status_code: serverConfig.https_redirect?.status_code || 301,
        },
        info_hiding: {
          enabled: infoHiding,
          strip_headers: serverConfig.info_hiding?.strip_headers || ['Server', 'X-Powered-By', 'X-AspNet-Version'],
        },
        cookie_hardener: {
          enabled: cookieHardener,
          force_secure: serverConfig.cookie_hardener?.force_secure !== false,
          force_httponly: serverConfig.cookie_hardener?.force_httponly !== false,
          force_samesite: serverConfig.cookie_hardener?.force_samesite || 'Lax',
        },
        gzip: {
          enabled: gzipEnabled,
          min_size: serverConfig.gzip?.min_size || 1024,
          content_types: serverConfig.gzip?.content_types || [
            'text/html',
            'text/css',
            'application/javascript',
            'application/json',
            'text/xml',
          ],
          level: serverConfig.gzip?.level || 6,
        },
      };

      const res = await apiService.saveAppSecurityConfig(updates);
      if (!res.success) {
        throw new Error(res.error || 'Server returned an error saving configuration.');
      }

      setNotification({
        type: 'success',
        message: 'Transport hardening configuration saved successfully.',
      });
      await loadData(true);
    } catch (err: any) {
      console.error('[AppSecurityOverviewPage] Save error:', err);
      setNotification({
        type: 'error',
        message: err?.message || 'Failed to save configuration.',
      });
    } finally {
      setSaving(false);
    }
  };

  const formatNumber = (num: number): string => {
    if (!Number.isFinite(num)) return '0';
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}k`;
    return num.toLocaleString();
  };

  const coverage = effectiveState?.route_coverage || {
    protected: 0,
    total: 0,
    percentage: 0,
    known: false,
  };

  const { activeModulesCount, activeControlsCount } = useMemo(() => {
    if (!enabled) {
      return { activeModulesCount: 0, activeControlsCount: 0 };
    }

    if (effectiveState?.functions && Array.isArray(effectiveState.functions) && effectiveState.functions.length > 0) {
      const securityFns = effectiveState.functions.filter(
        (f) => f.status !== 'excluded' && f.status !== 'unavailable'
      );
      const activeControls = securityFns.filter((f) => f.status === 'active').length;

      const isAreaActive = (fnIds: string[]) =>
        effectiveState.functions.some((f) => fnIds.includes(f.id) && f.status === 'active');

      const reqActive = isAreaActive(['method_enforcer', 'host_validator', 'content_type_validator', 'request_size_guard', 'header_manager']);
      const payActive = isAreaActive(['upload_limit', 'request_body_guard']);
      const uplActive = isAreaActive(['extension_filter', 'upload_protection']);
      const resActive = isAreaActive(['security_headers', 'info_hiding', 'cookie_hardener', 'https_redirect']);

      const activeModules = [reqActive, payActive, uplActive, resActive].filter(Boolean).length;

      return {
        activeModulesCount: activeModules,
        activeControlsCount: activeControls,
      };
    }

    const hasReq = Boolean(
      serverConfig.method_enforcer?.enabled !== false ||
      serverConfig.host_validator?.enabled ||
      serverConfig.request_size_guard?.enabled !== false ||
      serverConfig.content_type_validator?.enabled !== false
    );
    const hasPay = Boolean(
      serverConfig.upload_limit?.enabled !== false ||
      serverConfig.request_body_guard?.enabled !== false
    );
    const hasUpl = Boolean(
      serverConfig.extension_filter?.enabled !== false ||
      serverConfig.upload_protection?.enabled !== false
    );
    const hasRes = Boolean(
      serverConfig.security_headers?.enabled !== false ||
      serverConfig.info_hiding?.enabled !== false ||
      serverConfig.cookie_hardener?.enabled !== false ||
      serverConfig.https_redirect?.enabled
    );

    const activeModules = [hasReq, hasPay, hasUpl, hasRes].filter(Boolean).length;

    let activeControls = 0;
    if (serverConfig.method_enforcer?.enabled !== false) activeControls++;
    if (serverConfig.host_validator?.enabled) activeControls++;
    if (serverConfig.request_size_guard?.enabled !== false) activeControls++;
    if (serverConfig.content_type_validator?.enabled !== false) activeControls++;
    if (serverConfig.upload_limit?.enabled !== false) activeControls++;
    if (serverConfig.request_body_guard?.enabled !== false) activeControls++;
    if (serverConfig.extension_filter?.enabled !== false) activeControls++;
    if (serverConfig.upload_protection?.enabled !== false) activeControls++;
    if (serverConfig.security_headers?.enabled !== false) activeControls++;
    if (serverConfig.info_hiding?.enabled !== false) activeControls++;
    if (serverConfig.cookie_hardener?.enabled !== false) activeControls++;
    if (serverConfig.https_redirect?.enabled) activeControls++;

    return {
      activeModulesCount: activeModules,
      activeControlsCount: activeControls,
    };
  }, [enabled, effectiveState, serverConfig]);

  const modules = [
    {
      id: 'request',
      title: 'Request Policy',
      description: 'HTTP method restrictions, host validation, and request boundaries.',
      icon: SettingsAdjust,
      navKey: 'app-security-request' as NavItemKey,
    },
    {
      id: 'payload',
      title: 'Payload Protection',
      description: 'Body size limits and structured payload inspection (JSON, XML, Form).',
      icon: Activity,
      navKey: 'app-security-payload' as NavItemKey,
    },
    {
      id: 'upload',
      title: 'Upload Security',
      description: 'Extension blocklists, MIME verification, and binary inspection.',
      icon: Upload,
      navKey: 'app-security-upload' as NavItemKey,
    },
    {
      id: 'response',
      title: 'Response Protection',
      description: 'Browser security headers, CSP, cookie attributes, and cloaking.',
      icon: Security,
      navKey: 'app-security-response' as NavItemKey,
    },
  ];

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Application security"
        title="Overview"
        icon={Security}
        action={
          <HeaderSwitcher
            id="app-security-master-switch"
            toggled={enabled}
            onToggle={handleMasterToggle}
            ariaLabel="Application Security Global Engine Enable"
          />
        }
      />

      {notification && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind={notification.type}
            title={notification.type === 'success' ? 'Success' : notification.type === 'error' ? 'Notice' : 'Information'}
            subtitle={notification.message}
            onClose={() => setNotification(null)}
          />
        </div>
      )}

      {!enabled && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind="warning"
            title="Protection Paused"
            subtitle="Application Security is disabled. Traffic bypasses request policies, upload guards, and response security headers."
            lowContrast
          />
        </div>
      )}

      {enabled && effectiveState?.effective_state === 'NOT_ATTACHED' && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind="warning"
            title="Policy Unattached"
            subtitle={effectiveState.reason || 'Security controls are enabled but not attached to any active routes.'}
            lowContrast
          />
        </div>
      )}

      <div style={{ marginBottom: '32px' }}>
        <MetricStrip columns={4}>
          <KpiCard
            label="Active Controls"
            value={!enabled ? '0 of 4 active' : `${activeModulesCount} of 4 active`}
            subtext={
              !enabled
                ? 'Protection engine disabled'
                : activeModulesCount === 4
                  ? 'All security functions active'
                  : `${activeControlsCount} control rules active`
            }
            icon={Security}
            status={!enabled ? 'warning' : activeModulesCount === 4 ? 'success' : 'default'}
          />
          <KpiCard
            label="Protected Routes"
            value={`${coverage.protected} of ${coverage.total}`}
            subtext={`${coverage.percentage}% effective coverage`}
            icon={Network_3}
          />
          <KpiCard
            label="Total Requests"
            value={formatNumber(stats.total)}
            subtext="Processed requests"
            icon={Activity}
          />
          <KpiCard
            label="Blocked Findings"
            value={formatNumber(stats.blocked)}
            subtext="Requests blocked"
            icon={WarningAlt}
          />
        </MetricStrip>
      </div>

      <SectionCard
        title="Security functions"
        padded={false}
      >
        {modules.map((mod, index) => {
          const IconComponent = mod.icon;
          const isLast = index === modules.length - 1;

          return (
            <div
              key={mod.id}
              onClick={() => handleNavigate(mod.navKey)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '16px 24px',
                borderBottom: isLast ? 'none' : '1px solid var(--cds-border-subtle)',
                cursor: 'pointer',
                transition: 'background-color 0.15s ease',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--cds-layer-hover, rgba(141, 141, 141, 0.12))';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '80%' }}>
                <IconComponent size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '2px' }}>
                    {mod.title}
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    {mod.description}
                  </div>
                </div>
              </div>
              <Button
                kind="ghost"
                size="sm"
                onClick={(e) => {
                  e.stopPropagation();
                  handleNavigate(mod.navKey);
                }}
              >
                Manage
              </Button>
            </div>
          );
        })}
      </SectionCard>

      <SectionCard
        title="Transport & Delivery"
        padded={true}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '16px',
            width: '100%',
          }}
        >
          <div
            style={{
              background: 'var(--cds-layer-02)',
              border: '1px solid var(--cds-border-subtle)',
              padding: '16px 20px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              minHeight: '100px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px' }}>
              <div>
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                  HTTPS Redirection
                </div>
                <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '4px 0 0' }}>
                  Redirect HTTP requests to HTTPS.
                </p>
              </div>
              <StatusToggle
                id="toggle-https-redirect"
                toggled={httpsRedirect}
                onToggle={(val) => setHttpsRedirect(val)}
                hideLabel
                size="sm"
                ariaLabel="Enable HTTPS Redirection"
              />
            </div>
          </div>

          <div
            style={{
              background: 'var(--cds-layer-02)',
              border: '1px solid var(--cds-border-subtle)',
              padding: '16px 20px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              minHeight: '100px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px' }}>
              <div>
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                  Server Cloaking
                </div>
                <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '4px 0 0' }}>
                  Strip Server and runtime version headers from responses.
                </p>
              </div>
              <StatusToggle
                id="toggle-info-hiding"
                toggled={infoHiding}
                onToggle={(val) => setInfoHiding(val)}
                hideLabel
                size="sm"
                ariaLabel="Enable Server Cloaking"
              />
            </div>
          </div>

          <div
            style={{
              background: 'var(--cds-layer-02)',
              border: '1px solid var(--cds-border-subtle)',
              padding: '16px 20px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              minHeight: '100px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px' }}>
              <div>
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                  Cookie Hardening
                </div>
                <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '4px 0 0' }}>
                  Enforce Secure, HttpOnly, and SameSite flags on Set-Cookie.
                </p>
              </div>
              <StatusToggle
                id="toggle-cookie-hardener"
                toggled={cookieHardener}
                onToggle={(val) => setCookieHardener(val)}
                hideLabel
                size="sm"
                ariaLabel="Enable Cookie Hardening"
              />
            </div>
          </div>

          <div
            style={{
              background: 'var(--cds-layer-02)',
              border: '1px solid var(--cds-border-subtle)',
              padding: '16px 20px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              minHeight: '100px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px' }}>
              <div>
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                  Gzip Compression
                </div>
                <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '4px 0 0' }}>
                  Compress text, script, stylesheet, and JSON responses.
                </p>
              </div>
              <StatusToggle
                id="toggle-gzip"
                toggled={gzipEnabled}
                onToggle={(val) => setGzipEnabled(val)}
                hideLabel
                size="sm"
                ariaLabel="Enable Gzip Compression"
              />
            </div>
          </div>
        </div>
      </SectionCard>

      <SaveActionBar
        isDirty={isDirty}
        isSaving={saving}
        onReset={handleReset}
        onSave={handleSave}
        message="You have unsaved changes in transport hardening"
      />
    </div>
  );
};

export default AppSecurityOverviewPage;
