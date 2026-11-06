import React, { useState, useEffect } from 'react';
import {
  Select,
  SelectItem,
  Button,
  InlineNotification,
} from '@carbon/react';
import {
  Activity,
  List,
  Security,
  ArrowRight,
  Renew,
  SettingsAdjust,
} from '@carbon/icons-react';
import {
  PageHeader,
  SectionCard,
  HeaderSwitcher,
  SaveActionBar,
} from '../components/common';
import { apiService } from '../services/api';
import type {
  AntibotFullConfig,
  AntibotStrictness,
  AntibotResponseMode,
  AntibotRule,
  NavItemKey,
} from '../types';
import './BotManagedPage.scss';

interface BotManagedPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

export const BotManagedPage: React.FC<BotManagedPageProps> = ({ onNavigate }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [isEngineToggling, setIsEngineToggling] = useState<boolean>(false);
  const [isDirty, setIsDirty] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [engineEnabled, setEngineEnabled] = useState<boolean>(true);
  const [strictness, setStrictness] = useState<AntibotStrictness>('balanced');
  const [responseMode, setResponseMode] = useState<AntibotResponseMode>('challenge');
  const [_rules, setRules] = useState<AntibotRule[]>([]);
  const [initialConfig, setInitialConfig] = useState<AntibotFullConfig | null>(null);

  const markDirty = () => setIsDirty(true);

  const loadData = async (showNotification = false) => {
    setLoading(true);
    try {
      const [cfgRes, rulesRes] = await Promise.allSettled([
        apiService.getAntibotConfig(),
        apiService.getBotProtectionRules(),
      ]);

      if (cfgRes.status === 'fulfilled' && cfgRes.value) {
        const cfg = cfgRes.value;
        setInitialConfig(cfg);
        const resolvedEngine = cfg.enabled !== false && cfg.detection?.enabled !== false;
        const resolvedStrictness = (cfg.strictness || cfg.mode || 'balanced') as AntibotStrictness;
        const resolvedResponseMode = (cfg.response_mode || 'challenge') as AntibotResponseMode;
        setEngineEnabled(resolvedEngine);
        setStrictness(resolvedStrictness);
        setResponseMode(resolvedResponseMode);
      }

      if (rulesRes.status === 'fulfilled' && Array.isArray(rulesRes.value)) {
        setRules(rulesRes.value);
      }

      setIsDirty(false);
      if (showNotification) {
        setNotification({ kind: 'info', message: 'Bot protection configuration refreshed.' });
      }
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load bot protection configuration.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleToggleEngine = async (next: boolean) => {
    setIsEngineToggling(true);
    const prev = engineEnabled;
    setEngineEnabled(next);
    try {
      const base = initialConfig || (await apiService.getAntibotConfig()) || {};
      const updated = {
        ...base,
        enabled: next,
        detection: {
          ...(base.detection || {}),
          enabled: next,
        },
      };
      const res = await apiService.saveAntibotConfig(updated);
      if (res && res.success === false) {
        setEngineEnabled(prev);
        setNotification({
          kind: 'error',
          message: res.error || 'Failed to update engine status.',
        });
        return;
      }
      setInitialConfig(updated);
      setNotification({
        kind: 'success',
        message: `Bot Protection engine ${next ? 'enabled' : 'disabled'}.`,
      });
    } catch (err: any) {
      setEngineEnabled(prev);
      setNotification({
        kind: 'error',
        message: err?.message || 'Failed to update engine status.',
      });
    } finally {
      setIsEngineToggling(false);
    }
  };

  const handleSelectStrictness = (mode: AntibotStrictness) => {
    if (mode !== strictness) {
      setStrictness(mode);
      markDirty();
    }
  };

  const handleSelectResponseMode = (mode: AntibotResponseMode) => {
    if (mode !== responseMode) {
      setResponseMode(mode);
      markDirty();
    }
  };

  const handleReset = () => {
    if (initialConfig) {
      const isEng = initialConfig.enabled !== false && initialConfig.detection?.enabled !== false;
      setEngineEnabled(isEng);
      setStrictness((initialConfig.strictness || initialConfig.mode || 'balanced') as AntibotStrictness);
      setResponseMode((initialConfig.response_mode || 'challenge') as AntibotResponseMode);
    }
    setIsDirty(false);
    setNotification({ kind: 'info', message: 'Pending changes reverted.' });
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const modeValue =
        strictness === 'low'
          ? 'permissive'
          : strictness === 'high' || strictness === 'under_attack'
          ? 'strict'
          : 'balanced';

      let managedThresholds = initialConfig?.managed_thresholds;
      if (strictness === 'high' || strictness === 'under_attack') {
        managedThresholds = {
          ...(managedThresholds || {}),
          observe: 15,
          challenge: 40,
          block: 70,
          repeat_offender: 2,
        };
      } else if (strictness === 'low') {
        managedThresholds = {
          ...(managedThresholds || {}),
          observe: 30,
          challenge: 65,
          block: 90,
          repeat_offender: 4,
        };
      } else {
        managedThresholds = {
          ...(managedThresholds || {}),
          observe: 20,
          challenge: 55,
          block: 85,
          repeat_offender: 3,
        };
      }

      const payload: Partial<AntibotFullConfig> = {
        ...(initialConfig || {}),
        enabled: engineEnabled,
        strictness,
        mode: modeValue,
        response_mode: responseMode,
        managed_thresholds: managedThresholds,
        detection: {
          ...(initialConfig?.detection || {}),
          enabled: engineEnabled,
          mode: modeValue,
        },
      };

      const res = await apiService.saveAntibotConfig(payload);
      if (res && res.success === false) {
        setNotification({
          kind: 'error',
          message: res.error || 'Failed to save managed protection settings.',
        });
        return;
      }
      setInitialConfig({ ...(initialConfig || {}), ...payload } as AntibotFullConfig);
      setIsDirty(false);
      setNotification({
        kind: 'success',
        message: 'Managed bot protection settings saved successfully.',
      });
    } catch (err: any) {
      setNotification({
        kind: 'error',
        message: err?.message || 'Failed to save managed protection settings.',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <main className="bot-managed-page" id="main-content">
      <PageHeader
        kicker="Bot defense"
        title="Managed Protection"
        icon={Activity}
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Button
              kind="ghost"
              size="sm"
              renderIcon={Renew}
              disabled={loading}
              onClick={() => loadData(true)}
            >
              Refresh
            </Button>
            <HeaderSwitcher
              id="bot-managed-engine-toggle"
              ariaLabel="Bot Engine Status"
              toggled={engineEnabled}
              onToggle={handleToggleEngine}
              disabled={isEngineToggling}
            />
          </div>
        }
      />

      {notification && (
        <InlineNotification
          kind={notification.kind}
          title={notification.message}
          onCloseButtonClick={() => setNotification(null)}
          className="cds--spacing-bottom-06"
        />
      )}

      <SectionCard
        kicker="MANAGED SCORING"
        title="Managed protection"
        padded={false}
      >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '20px 24px',
                borderBottom: '1px solid var(--cds-border-subtle)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '70%' }}>
                <SettingsAdjust size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                <div>
                  <div
                    style={{
                      fontWeight: 600,
                      fontSize: '14px',
                      color: 'var(--cds-text-primary)',
                      marginBottom: '4px',
                    }}
                  >
                    Strictness
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    Adjust score thresholds for automated detection and challenge triggers.
                  </div>
                </div>
              </div>
              <div style={{ width: '220px' }}>
                <Select
                  id="select-strictness"
                  hideLabel
                  labelText="Strictness"
                  size="sm"
                  value={strictness}
                  onChange={(e) => handleSelectStrictness(e.target.value as AntibotStrictness)}
                >
                  <SelectItem value="low" text="Low (Permissive)" />
                  <SelectItem value="balanced" text="Balanced (Recommended)" />
                  <SelectItem value="high" text="High (Strict)" />
                  <SelectItem value="under_attack" text="Under attack (Emergency)" />
                </Select>
              </div>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '20px 24px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '70%' }}>
                <Security size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                <div>
                  <div
                    style={{
                      fontWeight: 600,
                      fontSize: '14px',
                      color: 'var(--cds-text-primary)',
                      marginBottom: '4px',
                    }}
                  >
                    Response mode
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    Action taken when traffic exceeds the threat score threshold.
                  </div>
                </div>
              </div>
              <div style={{ width: '220px' }}>
                <Select
                  id="select-response-mode"
                  hideLabel
                  labelText="Response mode"
                  size="sm"
                  value={responseMode}
                  onChange={(e) => handleSelectResponseMode(e.target.value as AntibotResponseMode)}
                >
                  <SelectItem value="log" text="Log only" />
                  <SelectItem value="challenge" text="Challenge" />
                  <SelectItem value="block" text="Block (HTTP 403)" />
                </Select>
              </div>
            </div>
          </SectionCard>

          <SectionCard
            kicker="CHALLENGE & RULES"
            title="Rules & Challenges"
            padded={false}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '20px 24px',
                borderBottom: '1px solid var(--cds-border-subtle)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '70%' }}>
                <List size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                <div>
                  <div
                    style={{
                      fontWeight: 600,
                      fontSize: '14px',
                      color: 'var(--cds-text-primary)',
                      marginBottom: '4px',
                    }}
                  >
                    Custom rules
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    Define granular match expressions by IP, ASN, country, or user-agent.
                  </div>
                </div>
              </div>
              <Button
                kind="tertiary"
                size="sm"
                onClick={() =>
                  onNavigate ? onNavigate('bot-rules') : (window.location.hash = '#bot-rules')
                }
              >
                Manage rules
              </Button>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '20px 24px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '70%' }}>
                <Security size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                <div>
                  <div
                    style={{
                      fontWeight: 600,
                      fontSize: '14px',
                      color: 'var(--cds-text-primary)',
                      marginBottom: '4px',
                    }}
                  >
                    Smart Challenge
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    Configure challenge difficulty, captcha providers, and verification timeouts.
                  </div>
                </div>
              </div>
              <Button
                kind="ghost"
                size="sm"
                renderIcon={ArrowRight}
                onClick={() => {
                  window.location.hash = '#modules-challenge';
                  if (onNavigate) {
                    onNavigate('modules');
                  }
                }}
              >
                Open Smart Challenge
              </Button>
            </div>
          </SectionCard>

      <SaveActionBar
        isDirty={isDirty}
        isSaving={saving}
        onReset={handleReset}
        onSave={handleSave}
      />
    </main>
  );
};
