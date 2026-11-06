import React, { useState, useEffect } from 'react';
import {
  Button,
  InlineNotification,
} from '@carbon/react';
import {
  Bot,
  Activity,
  List,
  Tag as TagIcon,
  Filter,
} from '@carbon/icons-react';
import {
  PageHeader,
  MetricStrip,
  KpiCard,
  SectionCard,
  HeaderSwitcher,
} from '../components/common';
import { apiService } from '../services/api';
import type { NavItemKey } from '../types';

interface BotOverviewPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

export const BotOverviewPage: React.FC<BotOverviewPageProps> = ({ onNavigate }) => {
  const [_loading, setLoading] = useState<boolean>(true);
  const [enabled, setEnabled] = useState<boolean>(true);
  const [responseMode, setResponseMode] = useState<string>('challenge');
  const [rawConfig, setRawConfig] = useState<any>(null);
  const [stats, setStats] = useState<any>(null);
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

  const loadData = async () => {
    setLoading(true);
    try {
      const [cfgRes, statsRes] = await Promise.allSettled([
        apiService.getAntibotConfig(),
        apiService.getBotStats(),
      ]);

      if (cfgRes.status === 'fulfilled' && cfgRes.value) {
        const cfg = cfgRes.value;
        setRawConfig(cfg);
        setEnabled(cfg.enabled !== false);
        if (cfg.response_mode) setResponseMode(cfg.response_mode);
      }
      if (statsRes.status === 'fulfilled' && statsRes.value) {
        setStats(statsRes.value);
      }
    } catch {
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleToggleEngine = async (next: boolean) => {
    const prevEnabled = enabled;
    setEnabled(next);
    try {
      const base = rawConfig || (await apiService.getAntibotConfig()) || {};
      const updated = { ...base, enabled: next };
      const res = await apiService.saveAntibotConfig(updated);
      if (res && res.success === false) {
        setEnabled(prevEnabled);
        setNotification({
          kind: 'error',
          message: res.error || 'Failed to update engine status.',
        });
        return;
      }
      setRawConfig(updated);
      setNotification({
        kind: 'success',
        message: `Bot Protection engine ${next ? 'enabled' : 'disabled'}.`,
      });
    } catch (err: any) {
      setEnabled(prevEnabled);
      setNotification({
        kind: 'error',
        message: err?.message || 'Failed to update engine status.',
      });
    }
  };

  const totalObserved = Number(stats?.total_requests ?? stats?.allowed_requests ?? 0);
  const totalBlocked = Number(stats?.blocked_requests ?? 0);
  const totalChallenged = Number(stats?.custom?.challenged_requests ?? 0);

  const getProtectionModeLabel = () => {
    if (!enabled) return 'Off';
    if (responseMode === 'block') return 'Blocking';
    if (responseMode === 'log') return 'Detection';
    return 'Challenge';
  };

  const getProtectionModeSubtext = () => {
    if (!enabled) return 'Bypassed';
    if (responseMode === 'block') return 'Enforcing drops';
    if (responseMode === 'log') return 'Observation only';
    return 'Managed challenge';
  };

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Bot defense"
        title="Overview"
        icon={Bot}
        action={
          <HeaderSwitcher
            id="bot-master-switch"
            toggled={enabled}
            onToggle={handleToggleEngine}
            ariaLabel="Bot Global Engine Enable"
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
        <div style={{ marginBottom: '16px' }}>
          <h2
            style={{
              fontSize: '16px',
              fontWeight: 600,
              color: 'var(--cds-text-primary)',
              margin: '0 0 4px 0',
            }}
          >
            Protection statistics
          </h2>
          <p
            style={{
              fontSize: '13px',
              color: 'var(--cds-text-secondary)',
              margin: 0,
            }}
          >
            Live client inspection activity, mitigation signals, and challenge states.
          </p>
        </div>

        <MetricStrip columns={4}>
          <KpiCard
            label="Protection Mode"
            value={getProtectionModeLabel()}
            subtext={getProtectionModeSubtext()}
            status="default"
          />
          <KpiCard
            label="Clients Inspected"
            value={totalObserved.toLocaleString()}
            subtext="Observed request sessions"
            status="default"
          />
          <KpiCard
            label="Blocked Threats"
            value={totalBlocked.toLocaleString()}
            subtext="Immediate edge drop"
            status="default"
          />
          <KpiCard
            label="Active Challenges"
            value={totalChallenged.toLocaleString()}
            subtext="PoW & verification flows"
            status="default"
          />
        </MetricStrip>
      </div>

      <SectionCard
        title="Bot Protection Modules"
        padded={false}
      >
        <div
          onClick={() => handleNavigate('bot-managed')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '20px 24px',
            borderBottom: '1px solid var(--cds-border-subtle)',
            cursor: 'pointer',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <Activity size={20} style={{ color: 'var(--cds-interactive)' }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Managed Protection
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                TLS fingerprinting, behavioral heuristics, and progressive challenge ladders.
              </div>
            </div>
          </div>
          <Button
            kind="ghost"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              handleNavigate('bot-managed');
            }}
          >
            Manage
          </Button>
        </div>

        <div
          onClick={() => handleNavigate('bot-classification')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '20px 24px',
            borderBottom: '1px solid var(--cds-border-subtle)',
            cursor: 'pointer',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <TagIcon size={20} style={{ color: 'var(--cds-interactive)' }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Verified Bots
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                FCrDNS validation for search crawlers and verified services.
              </div>
            </div>
          </div>
          <Button
            kind="ghost"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              handleNavigate('bot-classification');
            }}
          >
            Manage
          </Button>
        </div>

        <div
          onClick={() => handleNavigate('bot-ai')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '20px 24px',
            borderBottom: '1px solid var(--cds-border-subtle)',
            cursor: 'pointer',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <Bot size={20} style={{ color: 'var(--cds-interactive)' }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                AI Crawlers
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Access rules for AI crawlers and automated model training bots.
              </div>
            </div>
          </div>
          <Button
            kind="ghost"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              handleNavigate('bot-ai');
            }}
          >
            Manage
          </Button>
        </div>

        <div
          onClick={() => handleNavigate('bot-rules')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '20px 24px',
            borderBottom: '1px solid var(--cds-border-subtle)',
            cursor: 'pointer',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <List size={20} style={{ color: 'var(--cds-interactive)' }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Custom Rules
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Wire-speed match expressions evaluated before heuristic scoring.
              </div>
            </div>
          </div>
          <Button
            kind="ghost"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              handleNavigate('bot-rules');
            }}
          >
            Manage
          </Button>
        </div>

        <div
          onClick={() => handleNavigate('bot-exceptions')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '20px 24px',
            cursor: 'pointer',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <Filter size={20} style={{ color: 'var(--cds-interactive)' }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Exceptions
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Path, IP, and header bypasses for trusted services and monitoring agents.
              </div>
            </div>
          </div>
          <Button
            kind="ghost"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              handleNavigate('bot-exceptions');
            }}
          >
            Manage
          </Button>
        </div>
      </SectionCard>
    </div>
  );
};

export default BotOverviewPage;
