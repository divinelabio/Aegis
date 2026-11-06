import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Select,
  SelectItem,
  Button,
  NumberInput,
  InlineNotification,
} from '@carbon/react';
import {
  Firewall,
  Security,
  Layers,
  SettingsAdjust,
  Activity,
  Folder,
  List,
  Filter,
  Document,
  WarningAlt,
} from '@carbon/icons-react';
import {
  PageHeader,
  SectionCard,
  StatusToggle,
  HeaderSwitcher,
  MetricStrip,
  KpiCard,
  SaveActionBar,
} from '../components/common';
import { apiService } from '../services/api';
import type { NavItemKey, WAFSectionConfig, WAFProfile, WAFConfigDashboardStats, WAFHealth } from '../types';

interface WafOverviewPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

export const WafOverviewPage: React.FC<WafOverviewPageProps> = ({ onNavigate }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [serverConfig, setServerConfig] = useState<WAFSectionConfig>({});
  const [health, setHealth] = useState<WAFHealth>({});
  const [stats, setStats] = useState<WAFConfigDashboardStats | null>(null);
  const [profiles, setProfiles] = useState<WAFProfile[]>([]);

  const [activeManagedRules, setActiveManagedRules] = useState<number>(0);
  const [activeCustomRules, setActiveCustomRules] = useState<number>(0);
  const [activeExclusions, setActiveExclusions] = useState<number>(0);

  const [wafEnabled, setWafEnabled] = useState<boolean>(true);
  const [mode, setMode] = useState<string>('blocking');
  const [lastEnabledMode, setLastEnabledMode] = useState<string>('blocking');
  const [profile, setProfile] = useState<string>('custom');
  const [sensitivity, setSensitivity] = useState<string>('1');
  const [anomalyThreshold, setAnomalyThreshold] = useState<number>(5);
  const [failureMode, setFailureMode] = useState<string>('fail_open');
  const [requestBodyLimit, setRequestBodyLimit] = useState<number>(10);
  const [responseInspection, setResponseInspection] = useState<boolean>(true);
  const [responseBodyLimit, setResponseBodyLimit] = useState<number>(1);

  const handleNavigate = (key: NavItemKey) => {
    if (onNavigate) {
      onNavigate(key);
    } else {
      window.location.hash = `#${key}`;
    }
  };

  const isExclusionExpired = (e: any): boolean => {
    if (!e?.expires_at) return false;
    const ts = Date.parse(e.expires_at);
    if (!ts) return false;
    return Date.now() > ts;
  };

  const loadData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [fullCfg, statsData, profilesData, crsFiles, customRules, exclusions] = await Promise.all([
        apiService.getWafFullConfig(),
        apiService.getWafStats(),
        apiService.getWafProfiles(),
        apiService.getWafCrsFiles(),
        apiService.getCustomRules(),
        apiService.getExclusions(),
      ]);

      const cfg = fullCfg.config || {};
      setServerConfig(cfg);
      setHealth(fullCfg.health || {});
      setStats(statsData);
      setProfiles(profilesData || []);

      setActiveManagedRules((crsFiles || []).filter((f) => f.enabled !== false).length);
      setActiveCustomRules((customRules || []).filter((r) => r.enabled !== false).length);
      setActiveExclusions((exclusions || []).filter((e) => e.enabled !== false && !isExclusionExpired(e)).length);

      if (!silent) {
        const isEnabled = cfg.enabled !== false && cfg.mode !== 'off';
        const currentMode = isEnabled ? (cfg.mode === 'detection' ? 'detection' : 'blocking') : 'off';
        setWafEnabled(isEnabled);
        setMode(currentMode);
        if (currentMode === 'blocking' || currentMode === 'detection') {
          setLastEnabledMode(currentMode);
        }
        setProfile(cfg.active_profile_id || cfg.active_policy_id || 'custom');
        setSensitivity(String(cfg.rule_strictness || cfg.crs_paranoia_level || cfg.engine?.paranoia_level || 1));
        setAnomalyThreshold(cfg.anomaly_threshold || cfg.engine?.anomaly_threshold || 5);
        setFailureMode(cfg.failure_mode || 'fail_open');

        const reqBytes = typeof cfg.max_request_body_size === 'number' && cfg.max_request_body_size > 0
          ? cfg.max_request_body_size
          : (cfg.validation?.max_body_size || 10485760);
        setRequestBodyLimit(Math.round((reqBytes / 1048576) * 10) / 10);

        setResponseInspection(cfg.response_inspection !== false);
        const respBytes = typeof cfg.max_response_body_size === 'number' && cfg.max_response_body_size > 0
          ? cfg.max_response_body_size
          : 1048576;
        setResponseBodyLimit(Math.round((respBytes / 1048576) * 10) / 10);
      }
    } catch (err: any) {
      console.error('[WafOverviewPage] Failed to load data:', err);
      if (!silent) {
        setNotification({
          type: 'error',
          message: err?.message || 'Failed to load Application Firewall configuration.',
        });
      }
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      loadData(true);
    }, 30000);
    return () => clearInterval(interval);
  }, [loadData]);

  const isDirty = useMemo(() => {
    if (loading) return false;
    const initialEnabled = serverConfig.enabled !== false && serverConfig.mode !== 'off';
    const initialMode = initialEnabled ? (serverConfig.mode === 'detection' ? 'detection' : 'blocking') : 'off';
    const initialProfile = serverConfig.active_profile_id || serverConfig.active_policy_id || 'custom';
    const initialSensitivity = String(serverConfig.rule_strictness || serverConfig.crs_paranoia_level || serverConfig.engine?.paranoia_level || 1);
    const initialThreshold = serverConfig.anomaly_threshold || serverConfig.engine?.anomaly_threshold || 5;
    const initialFailureMode = serverConfig.failure_mode || 'fail_open';
    const initialReqLimit = Math.round(((serverConfig.max_request_body_size || serverConfig.validation?.max_body_size || 10485760) / 1048576) * 10) / 10;
    const initialRespInspect = serverConfig.response_inspection !== false;
    const initialRespLimit = Math.round(((serverConfig.max_response_body_size || 1048576) / 1048576) * 10) / 10;

    return (
      wafEnabled !== initialEnabled ||
      mode !== initialMode ||
      profile !== initialProfile ||
      sensitivity !== initialSensitivity ||
      anomalyThreshold !== initialThreshold ||
      failureMode !== initialFailureMode ||
      requestBodyLimit !== initialReqLimit ||
      responseInspection !== initialRespInspect ||
      responseBodyLimit !== initialRespLimit
    );
  }, [
    loading,
    serverConfig,
    wafEnabled,
    mode,
    profile,
    sensitivity,
    anomalyThreshold,
    failureMode,
    requestBodyLimit,
    responseInspection,
    responseBodyLimit,
  ]);

  const handleReset = () => {
    const isEnabled = serverConfig.enabled !== false && serverConfig.mode !== 'off';
    const initMode = isEnabled ? (serverConfig.mode === 'detection' ? 'detection' : 'blocking') : 'off';
    setWafEnabled(isEnabled);
    setMode(initMode);
    if (initMode === 'blocking' || initMode === 'detection') {
      setLastEnabledMode(initMode);
    }
    setProfile(serverConfig.active_profile_id || serverConfig.active_policy_id || 'custom');
    setSensitivity(String(serverConfig.rule_strictness || serverConfig.crs_paranoia_level || serverConfig.engine?.paranoia_level || 1));
    setAnomalyThreshold(serverConfig.anomaly_threshold || serverConfig.engine?.anomaly_threshold || 5);
    setFailureMode(serverConfig.failure_mode || 'fail_open');
    const reqBytes = typeof serverConfig.max_request_body_size === 'number' && serverConfig.max_request_body_size > 0
      ? serverConfig.max_request_body_size
      : (serverConfig.validation?.max_body_size || 10485760);
    setRequestBodyLimit(Math.round((reqBytes / 1048576) * 10) / 10);
    setResponseInspection(serverConfig.response_inspection !== false);
    const respBytes = typeof serverConfig.max_response_body_size === 'number' && serverConfig.max_response_body_size > 0
      ? serverConfig.max_response_body_size
      : 1048576;
    setResponseBodyLimit(Math.round((respBytes / 1048576) * 10) / 10);
    setNotification(null);
  };

  const handleMasterToggle = (checked: boolean) => {
    setWafEnabled(checked);
    if (!checked) {
      if (mode === 'blocking' || mode === 'detection') {
        setLastEnabledMode(mode);
      }
      setMode('off');
    } else {
      setMode(lastEnabledMode || 'blocking');
    }
  };

  const handleModeChange = (newMode: string) => {
    setMode(newMode);
    if (newMode === 'off') {
      setWafEnabled(false);
    } else {
      setWafEnabled(true);
      setLastEnabledMode(newMode);
    }
  };

  const handleProfileChange = (selectedProfileId: string) => {
    setProfile(selectedProfileId);
    if (selectedProfileId === 'custom' || !selectedProfileId) return;
    const matched = profiles.find((p) => p.id === selectedProfileId);
    if (matched) {
      if (matched.enforcement_mode === 'blocking' || matched.enforcement_mode === 'detection') {
        setMode(matched.enforcement_mode);
        setWafEnabled(true);
        setLastEnabledMode(matched.enforcement_mode);
      }
      const pLevel = matched.paranoia_level ?? (matched as any).rule_strictness ?? (matched as any).strictness ?? (matched as any).paranoiaLevel;
      if (pLevel) {
        setSensitivity(String(pLevel));
      }
      const aThresh = matched.anomaly_threshold ?? (matched as any).threshold ?? (matched as any).anomalyThreshold ?? (matched as any).score_threshold;
      if (aThresh) {
        setAnomalyThreshold(Number(aThresh));
      }
      if (typeof (matched as any).response_inspection === 'boolean') {
        setResponseInspection((matched as any).response_inspection);
      }
      setNotification({
        type: 'info',
        message: `Applied recommended settings for ${matched.name}`,
      });
    }
  };

  const handleSensitivityChange = (newVal: string) => {
    setSensitivity(newVal);
    if (profile !== 'custom') setProfile('custom');
  };

  const handleThresholdChange = (newVal: number) => {
    setAnomalyThreshold(newVal);
    if (profile !== 'custom') setProfile('custom');
  };

  const handleSave = async () => {
    setSaving(true);
    setNotification(null);
    try {
      const effectiveMode = wafEnabled ? (mode === 'off' ? 'blocking' : mode) : 'off';
      const reqBytes = Math.round(Number(requestBodyLimit) * 1048576);
      const respBytes = Math.round(Number(responseBodyLimit) * 1048576);
      const numSensitivity = Number(sensitivity);
      const numThreshold = Number(anomalyThreshold);

      const updates: Partial<WAFSectionConfig> = {
        enabled: wafEnabled && effectiveMode !== 'off',
        mode: effectiveMode,
        active_profile_id: profile === 'custom' ? '' : profile,
        active_policy_id: profile === 'custom' ? '' : profile,
        rule_strictness: numSensitivity,
        crs_paranoia_level: numSensitivity,
        anomaly_threshold: numThreshold,
        failure_mode: failureMode,
        max_request_body_size: reqBytes,
        max_response_body_size: respBytes,
        response_inspection: responseInspection,
      };

      const res = await apiService.saveWafFullConfig(updates, serverConfig);
      if (!res.success) {
        throw new Error(res.error || 'Server returned an error saving configuration.');
      }
      setNotification({
        type: 'success',
        message: 'Application Firewall configuration saved successfully.',
      });
      await loadData(false);
    } catch (err: any) {
      console.error('[WafOverviewPage] Save error:', err);
      setNotification({
        type: 'error',
        message: err?.message || 'Failed to save configuration.',
      });
    } finally {
      setSaving(false);
    }
  };

  const totalReq = stats?.total_requests || 0;
  const blockedReq = stats?.blocked_requests || 0;
  const blockRate = totalReq > 0 ? (blockedReq / totalReq) * 100 : 0;
  const loadedRules = activeManagedRules + activeCustomRules;
  const activeProfileObj = profiles.find((p) => p.id === profile);
  const isHighParanoia = Number(sensitivity) >= 3;
  const isHighProfileDeviation = Boolean(
    activeProfileObj && Number(sensitivity) > (activeProfileObj.paranoia_level || 1) + 1,
  );
  const isReloadFailed = health?.reload?.status === 'failed' || health?.status === 'degraded' || health?.status === 'error';
  const telemetryDetails = (health as any)?.details?.telemetry || health?.telemetry;
  const telemetryWarning =
    telemetryDetails?.dropped_events && telemetryDetails.dropped_events > 0
      ? `${telemetryDetails.dropped_events} recent WAF events could not be recorded. Traffic protection remains active.`
      : telemetryDetails?.db_available === false
        ? telemetryDetails?.message || 'WAF event history is temporarily unavailable. Traffic protection remains active.'
        : '';

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Application firewall"
        title="Overview"
        icon={Firewall}
        action={
          <HeaderSwitcher
            toggled={wafEnabled}
            onToggle={handleMasterToggle}
            ariaLabel="WAF engine enablement"
          />
        }
      />

      {notification && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind={notification.type}
            title={notification.type === 'success' ? 'Success' : 'Notice'}
            subtitle={notification.message}
            onClose={() => setNotification(null)}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      {isReloadFailed && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind="warning"
            title="WAF Engine Warning"
            subtitle={health?.message || 'The latest protection update was not applied. Your previous settings remain active.'}
            lowContrast
          />
        </div>
      )}

      {telemetryWarning && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind="warning"
            title="WAF Telemetry Notice"
            subtitle={telemetryWarning}
            lowContrast
          />
        </div>
      )}

      <MetricStrip columns={4}>
        <KpiCard
          label="Protection Mode"
          value={wafEnabled ? (mode === 'blocking' ? 'Blocking' : mode === 'detection' ? 'Detection' : 'Off') : 'Off'}
          subtext={
            wafEnabled
              ? mode === 'blocking'
                ? 'Enforcing matches'
                : mode === 'detection'
                ? 'Observation only'
                : 'Inspection bypassed'
              : 'Engine disabled'
          }
          icon={Security}
        />
        <KpiCard
          label="Requests Inspected"
          value={totalReq.toLocaleString()}
          subtext="Last 24 hours"
          icon={Activity}
        />
        <KpiCard
          label="Requests Blocked"
          value={blockedReq.toLocaleString()}
          subtext={`${blockRate.toFixed(1)}% block rate`}
          icon={Firewall}
        />
        <KpiCard
          label="Loaded Rules"
          value={loadedRules.toLocaleString()}
          subtext={isReloadFailed ? 'Update failed - previous settings active' : `${activeManagedRules} managed, ${activeCustomRules} custom`}
          icon={Folder}
          onClick={() => handleNavigate('waf-rulesets')}
        />
      </MetricStrip>

      <SectionCard
        title="Protection configuration"
        padded={false}
      >
        {(isHighParanoia || isHighProfileDeviation) && (
          <div
            style={{
              padding: '12px 24px',
              backgroundColor: 'var(--cds-layer-02)',
              borderBottom: '1px solid var(--cds-border-subtle)',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
            }}
          >
            <WarningAlt size={18} style={{ color: 'var(--cds-support-warning, #f1c21b)', flexShrink: 0 }} />
            <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
              <strong style={{ color: 'var(--cds-text-primary)' }}>
                {sensitivity === '4' ? 'Paranoid mode (PL4)' : 'Strict mode (PL3)'}:
              </strong>{' '}
              {isHighProfileDeviation && activeProfileObj
                ? `Sensitivity is significantly higher than recommended for ${activeProfileObj.name}. `
                : ''}
              Higher sensitivity inspects more deeply but increases false-positive risk. Test application flows and review exceptions before production enforcement.
            </div>
          </div>
        )}

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
            <Security size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Protection mode
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Active enforcement action for matched threats.
              </div>
            </div>
          </div>
          <div style={{ width: '180px' }}>
            <Select
              id="select-mode"
              hideLabel
              labelText="Protection mode"
              size="sm"
              value={mode}
              onChange={(e) => handleModeChange(e.target.value)}
            >
              <SelectItem value="blocking" text="Block" />
              <SelectItem value="detection" text="Detect" />
              <SelectItem value="off" text="Off" />
            </Select>
          </div>
        </div>

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
            <Layers size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Protection profile
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Preset sensitivity and scoring baseline.
              </div>
            </div>
          </div>
          <div style={{ width: '220px' }}>
            <Select
              id="select-profile"
              hideLabel
              labelText="Protection profile"
              size="sm"
              value={profile}
              onChange={(e) => handleProfileChange(e.target.value)}
            >
              <SelectItem value="custom" text="Custom Profile" />
              {profiles.map((p) => (
                <SelectItem key={p.id} value={p.id} text={p.name} />
              ))}
            </Select>
          </div>
        </div>

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
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Rule sensitivity
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                OWASP Paranoia Level (PL). Higher levels inspect deeper but increase false-positive risk.
              </div>
            </div>
          </div>
          <div style={{ width: '180px' }}>
            <Select
              id="select-sensitivity"
              hideLabel
              labelText="Rule sensitivity"
              size="sm"
              value={sensitivity}
              onChange={(e) => handleSensitivityChange(e.target.value)}
            >
              <SelectItem value="1" text="Standard (PL1)" />
              <SelectItem value="2" text="Balanced (PL2)" />
              <SelectItem value="3" text="Strict (PL3)" />
              <SelectItem value="4" text="Paranoid (PL4)" />
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
            <Activity size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Anomaly threshold
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Cumulative threat score required to trigger blocking. Lower scores are stricter.
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <NumberInput
              id="input-anomaly"
              hideLabel
              label="Anomaly threshold"
              size="sm"
              min={1}
              max={20}
              value={anomalyThreshold}
              onChange={(_evt, state) => handleThresholdChange(Number(state.value))}
              style={{ width: '100px' }}
            />
            <span
              style={{
                fontSize: '12px',
                color: 'var(--cds-text-secondary)',
                fontFamily: 'var(--cds-font-mono, monospace)',
              }}
            >
              score
            </span>
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title="Advanced settings"
        padded={false}
        collapsible
        defaultExpanded={false}
      >
        <div
          onClick={() => handleNavigate('waf-rulesets')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '20px 24px',
            borderBottom: '1px solid var(--cds-border-subtle)',
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <Folder size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
            <div>
              <div style={{ marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                  Managed rules
                </span>
                <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', fontWeight: 400 }}>
                  ({activeManagedRules} active)
                </span>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                OWASP Core Rule Set (CRS)
              </div>
            </div>
          </div>
          <Button
            kind="ghost"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              handleNavigate('waf-rulesets');
            }}
          >
            Manage
          </Button>
        </div>

        <div
          onClick={() => handleNavigate('waf-custom')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '20px 24px',
            borderBottom: '1px solid var(--cds-border-subtle)',
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <List size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
            <div>
              <div style={{ marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                  Custom rules
                </span>
                <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', fontWeight: 400 }}>
                  ({activeCustomRules} active)
                </span>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Custom pattern matching and scoring rules
              </div>
            </div>
          </div>
          <Button
            kind="ghost"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              handleNavigate('waf-custom');
            }}
          >
            Manage
          </Button>
        </div>

        <div
          onClick={() => handleNavigate('waf-exclusions')}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '20px 24px',
            borderBottom: '1px solid var(--cds-border-subtle)',
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <Filter size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
            <div>
              <div style={{ marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                  Exclusions
                </span>
                <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', fontWeight: 400 }}>
                  ({activeExclusions} active)
                </span>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Path, parameter, and IP bypass rules
              </div>
            </div>
          </div>
          <Button
            kind="ghost"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              handleNavigate('waf-exclusions');
            }}
          >
            Manage
          </Button>
        </div>

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
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Inspection failure behavior
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Action when inspection times out or encounters engine errors.
              </div>
            </div>
          </div>
          <div style={{ width: '220px' }}>
            <Select
              id="select-failure-mode"
              hideLabel
              labelText="Inspection failure behavior"
              size="sm"
              value={failureMode}
              onChange={(e) => setFailureMode(e.target.value)}
            >
              <SelectItem value="fail_open" text="Continue traffic (Fail Open)" />
              <SelectItem value="fail_closed" text="Block request (Fail Closed)" />
              <SelectItem value="service_unavailable" text="Show service unavailable" />
            </Select>
          </div>
        </div>

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
            <Document size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Request body inspection limit
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Maximum request payload scanned for threats.
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <NumberInput
              id="input-req-body"
              hideLabel
              label="Request body inspection limit"
              size="sm"
              min={0.5}
              max={64}
              step={0.5}
              value={requestBodyLimit}
              onChange={(_evt, state) => setRequestBodyLimit(Number(state.value))}
              style={{ width: '100px' }}
            />
            <span
              style={{
                fontSize: '12px',
                color: 'var(--cds-text-secondary)',
                fontFamily: 'var(--cds-font-mono, monospace)',
              }}
            >
              MiB
            </span>
          </div>
        </div>

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
            <Document size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Outbound response inspection
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Scan upstream server responses for leaks and stack traces.
              </div>
            </div>
          </div>
          <StatusToggle
            id="waf-response-inspection-toggle"
            toggled={responseInspection}
            onToggle={(checked) => setResponseInspection(checked)}
            hideLabel
            size="sm"
            ariaLabel="Outbound response inspection"
          />
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
            <Document size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                Response body inspection limit
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Maximum response payload scanned for leakage.
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <NumberInput
              id="input-resp-body"
              hideLabel
              label="Response body inspection limit"
              size="sm"
              min={0.5}
              max={64}
              step={0.5}
              value={responseBodyLimit}
              onChange={(_evt, state) => {
                const val = Number(state.value);
                setResponseBodyLimit(val);
                if (val > 0 && !responseInspection) {
                  setResponseInspection(true);
                }
              }}
              style={{ width: '100px' }}
            />
            <span
              style={{
                fontSize: '12px',
                color: 'var(--cds-text-secondary)',
                fontFamily: 'var(--cds-font-mono, monospace)',
              }}
            >
              MiB
            </span>
          </div>
        </div>
      </SectionCard>

      <SaveActionBar
        isDirty={isDirty}
        isSaving={saving}
        onReset={handleReset}
        onSave={handleSave}
      />
    </div>
  );
};
