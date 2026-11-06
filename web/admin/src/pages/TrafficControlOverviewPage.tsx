import React, { useState, useEffect, useCallback } from 'react';
import {
  Button,
  InlineNotification,
} from '@carbon/react';
import {
  Misuse,
  Time,
  Security,
  Globe,
  DataStructured,
  Star,
  Activity,
  Network_3,
} from '@carbon/icons-react';
import {
  PageHeader,
  MetricStrip,
  KpiCard,
  SectionCard,
  HeaderSwitcher,
} from '../components/common';
import type { NavItemKey } from '../types';
import { apiService } from '../services/api';

interface TrafficControlOverviewPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

export const TrafficControlOverviewPage: React.FC<TrafficControlOverviewPageProps> = ({
  onNavigate,
}) => {
  const [engineEnabled, setEngineEnabled] = useState<boolean>(true);
  const [savingEngine, setSavingEngine] = useState<boolean>(false);
  const [defaultRate, setDefaultRate] = useState<number>(60);
  const [rateWindow, setRateWindow] = useState<string>('1m');
  const [inFlightRequests, setInFlightRequests] = useState<number>(0);
  const [engineHealthMsg, setEngineHealthMsg] = useState<string>('Enforcing edge quotas');
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const handleNavigate = (key: NavItemKey) => {
    if (onNavigate) {
      onNavigate(key);
    } else {
      window.location.hash = `#${key}`;
    }
  };

  const [modules, setModules] = useState([
    {
      id: 'blacklist',
      title: 'IP Blacklist',
      description: 'Block traffic from specific IP addresses or CIDR subnets.',
      icon: Misuse,
      enabled: false,
      available: true,
      readiness: undefined as string | undefined,
      navKey: 'traffic-blacklist' as NavItemKey,
    },
    {
      id: 'ratelimit',
      title: 'Rate Limiting',
      description: 'Throttle request volume and enforce burst allowances.',
      icon: Time,
      enabled: true,
      available: true,
      readiness: undefined as string | undefined,
      navKey: 'traffic-ratelimit' as NavItemKey,
    },
    {
      id: 'ddos',
      title: 'Application Flood Protection',
      description: 'Mitigate volumetric HTTP floods and connection spikes.',
      icon: Security,
      enabled: false,
      available: true,
      readiness: undefined as string | undefined,
      navKey: 'traffic-ddos' as NavItemKey,
    },
    {
      id: 'geo',
      title: 'Geo-Blocking',
      description: 'Allow or restrict requests by country and region.',
      icon: Globe,
      enabled: false,
      available: true,
      readiness: undefined as string | undefined,
      navKey: 'traffic-geo' as NavItemKey,
    },
    {
      id: 'reputation',
      title: 'IP Reputation Policy',
      description: 'Score client risk using live threat intelligence feeds.',
      icon: DataStructured,
      enabled: false,
      available: true,
      readiness: undefined as string | undefined,
      navKey: 'traffic-reputation' as NavItemKey,
    },
    {
      id: 'priority',
      title: 'Trusted Exceptions',
      description: 'Bypass rate and flood policies for trusted clients.',
      icon: Star,
      enabled: false,
      available: true,
      readiness: undefined as string | undefined,
      navKey: 'traffic-priority' as NavItemKey,
    },
  ]);

  const availableModules = modules.filter((m) => m.available !== false);
  const modulesActive = availableModules.filter((m) => m.enabled).length;
  const modulesTotal = availableModules.length;
  const coveragePct = modulesTotal > 0 ? Math.round((modulesActive / modulesTotal) * 100) : 0;

  const loadAll = useCallback(async () => {
    try {
      const [fullConfig, stats, ops, caps] = await Promise.all([
        apiService.getTrafficControlFullConfig(),
        apiService.getTrafficControlStats(),
        apiService.getTrafficControlOperations(),
        apiService.getTrafficControlCapabilities(),
      ]);

      if (stats) {
        const inflight = Number(
          stats.in_flight_requests ??
            stats.custom?.in_flight_requests ??
            stats.active_connections ??
            stats.custom?.active_connections ??
            0
        );
        setInFlightRequests(Number.isFinite(inflight) ? inflight : 0);
      }

      if (ops?.health?.message) {
        setEngineHealthMsg(ops.health.message);
      }

      if (fullConfig) {
        setEngineEnabled(fullConfig.enabled !== false);
        const rl = fullConfig.ratelimit || fullConfig.rate_limit || {};
        if (rl.default_rate) setDefaultRate(Number(rl.default_rate) || 60);
        if (rl.window) setRateWindow(String(rl.window));

        const bl = fullConfig.blacklist || {};
        const blTotal =
          (Array.isArray(bl.ips) ? bl.ips.length : 0) +
          (Array.isArray(bl.cidrs) ? bl.cidrs.length : 0) +
          (Array.isArray(bl.entries) ? bl.entries.length : 0);
        const blEnabled =
          bl.enabled !== undefined ? Boolean(bl.enabled) : blTotal > 0;

        const flood = fullConfig.application_flood || fullConfig.ddos || {};
        const geo = fullConfig.geo || {};
        const rep = fullConfig.reputation || {};
        const exceptions = Array.isArray(fullConfig.trusted_exceptions)
          ? fullConfig.trusted_exceptions
          : [];

        const feat = caps?.features || {};
        const readiness = ops?.module_readiness || {};

        setModules([
          {
            id: 'blacklist',
            title: 'IP Blacklist',
            description: 'Block traffic from specific IP addresses or CIDR subnets.',
            icon: Misuse,
            enabled: blEnabled,
            available: feat.blacklist?.available !== false,
            readiness: readiness.blacklist,
            navKey: 'traffic-blacklist',
          },
          {
            id: 'ratelimit',
            title: 'Rate Limiting',
            description: 'Throttle request volume and enforce burst allowances.',
            icon: Time,
            enabled: rl.enabled !== false,
            available: feat.ratelimit?.available !== false,
            readiness: readiness.ratelimit,
            navKey: 'traffic-ratelimit',
          },
          {
            id: 'ddos',
            title: 'Application Flood Protection',
            description: 'Mitigate volumetric HTTP floods and connection spikes.',
            icon: Security,
            enabled: Boolean(flood.enabled),
            available: feat.application_flood?.available !== false,
            readiness: readiness.application_flood,
            navKey: 'traffic-ddos',
          },
          {
            id: 'geo',
            title: 'Geo-Blocking',
            description: 'Allow or restrict requests by country and region.',
            icon: Globe,
            enabled: Boolean(geo.enabled),
            available: feat.geo?.available !== false,
            readiness: readiness.geo,
            navKey: 'traffic-geo',
          },
          {
            id: 'reputation',
            title: 'IP Reputation Policy',
            description: 'Score client risk using live threat intelligence feeds.',
            icon: DataStructured,
            enabled: Boolean(rep.enabled),
            available: feat.reputation?.available !== false,
            readiness: readiness.reputation,
            navKey: 'traffic-reputation',
          },
          {
            id: 'priority',
            title: 'Trusted Exceptions',
            description: 'Bypass rate and flood policies for trusted clients.',
            icon: Star,
            enabled: exceptions.length > 0,
            available: feat.trusted_exceptions?.available !== false,
            readiness: readiness.trusted_exceptions,
            navKey: 'traffic-priority',
          },
        ]);
      }
    } catch (err) {
      console.warn('Failed to load Traffic Control overview:', err);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const handleToggleEngine = async (checked: boolean) => {
    const previous = engineEnabled;
    setEngineEnabled(checked);
    setSavingEngine(true);
    try {
      const ok = await apiService.saveTrafficControlFullConfig({ enabled: checked }, 'full');
      if (ok) {
        setNotification({
          kind: checked ? 'success' : 'info',
          message: checked
            ? 'Traffic Control engine enabled'
            : 'Traffic Control engine bypassed (standby mode)',
        });
      } else {
        setEngineEnabled(previous);
        setNotification({
          kind: 'error',
          message: 'Failed to update Traffic Control engine status',
        });
      }
    } catch {
      setEngineEnabled(previous);
      setNotification({
        kind: 'error',
        message: 'Failed to update Traffic Control engine status',
      });
    } finally {
      setSavingEngine(false);
    }
  };

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Traffic control"
        title="Overview"
        icon={Activity}
        action={
          <HeaderSwitcher
            id="traffic-master-switch"
            toggled={engineEnabled}
            onToggle={handleToggleEngine}
            disabled={savingEngine}
            ariaLabel="Toggle Traffic Control Master Engine"
          />
        }
      />

      {notification && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      <div style={{ marginBottom: '32px' }}>
        <MetricStrip columns={4}>
          <KpiCard
            label="Protection Mode"
            value={engineEnabled ? 'Active' : 'Off'}
            subtext={engineEnabled ? engineHealthMsg : 'Bypassed'}
            icon={Security}
          />
          <KpiCard
            label="Active Modules"
            value={`${modulesActive} of ${modulesTotal}`}
            subtext={`${coveragePct}% coverage`}
            icon={Activity}
          />
          <KpiCard
            label="Default Rate"
            value={`${defaultRate} req/${rateWindow}`}
            subtext="Global rate limit"
            icon={Time}
            onClick={() => handleNavigate('traffic-ratelimit')}
          />
          <KpiCard
            label="In-Flight Requests"
            value={inFlightRequests.toLocaleString()}
            subtext="Active concurrent requests"
            icon={Network_3}
            onClick={() => handleNavigate('traffic-ddos')}
          />
        </MetricStrip>
      </div>

      <SectionCard
        title="Protection modules"
        padded={false}
      >
        {availableModules.map((mod, index) => {
          const IconComponent = mod.icon;
          const isLast = index === availableModules.length - 1;

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
    </div>
  );
};

export default TrafficControlOverviewPage;
