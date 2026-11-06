import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Tabs,
  TabList,
  Tab,
  TabPanels,
  TabPanel,
  TextInput,
  Checkbox,
  NumberInput,
  Button,
  Tag,
  InlineNotification,
  ContentSwitcher,
  Switch,
} from '@carbon/react';
import {
  SettingsAdjust,
  Globe,
  Activity,
  Document,
  TrashCan,
  Add,
  ArrowLeft,
  Security,
  Application,
  Locked,
  Unlocked,
} from '@carbon/icons-react';
import {
  PageHeader,
  SectionCard,
  StatusToggle,
  SaveActionBar,
  RadioCardGroup,
} from '../components/common';
import { apiService } from '../services/api';
import type {
  NavItemKey,
  AppSecurityConfig,
} from '../types';

interface AppSecurityRequestPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

const ALL_HTTP_METHODS = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
  'TRACE',
  'TRACK',
  'CONNECT',
  'DEBUG',
];

const WRITE_HTTP_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

const METHOD_PRESETS = {
  recommended: {
    id: 'recommended',
    title: 'Recommended',
    desc: 'Block debugging and tracing methods (TRACE, TRACK, CONNECT, DEBUG).',
    icon: Security,
    mode: 'blocklist' as const,
    methods: ['TRACE', 'TRACK', 'CONNECT', 'DEBUG'],
  },
  api_strict: {
    id: 'api_strict',
    title: 'API strict',
    desc: 'Allow standard REST methods (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).',
    icon: Application,
    mode: 'allowlist' as const,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
  },
  read_only: {
    id: 'read_only',
    title: 'Read-only',
    desc: 'Allow GET, HEAD, and OPTIONS only.',
    icon: Document,
    mode: 'allowlist' as const,
    methods: ['GET', 'HEAD', 'OPTIONS'],
  },
  custom: {
    id: 'custom',
    title: 'Custom',
    desc: 'Configure specific allowed or blocked methods.',
    icon: SettingsAdjust,
  },
};

const BOUNDARY_PRESETS = {
  balanced: {
    id: 'balanced',
    title: 'Balanced',
    desc: 'URL: 2 KB · Query: 2 KB · Headers: 50 · Header size: 8 KB',
    icon: Activity,
    max_url_length: 2048,
    max_query_length: 2048,
    max_header_count: 50,
    max_single_header_size: 8192,
  },
  relaxed: {
    id: 'relaxed',
    title: 'Relaxed',
    desc: 'URL: 4 KB · Query: 4 KB · Headers: 100 · Header size: 16 KB',
    icon: Globe,
    max_url_length: 4096,
    max_query_length: 4096,
    max_header_count: 100,
    max_single_header_size: 16384,
  },
  strict: {
    id: 'strict',
    title: 'Strict',
    desc: 'URL: 1 KB · Query: 1 KB · Headers: 32 · Header size: 4 KB',
    icon: Security,
    max_url_length: 1024,
    max_query_length: 1024,
    max_header_count: 32,
    max_single_header_size: 4096,
  },
  custom: {
    id: 'custom',
    title: 'Custom',
    desc: 'Custom limits for URL, query string, and headers.',
    icon: SettingsAdjust,
  },
};

const CONTENT_TYPE_PRESETS = {
  writes: {
    id: 'writes',
    title: 'Mutations (recommended)',
    desc: 'Require Content-Type on POST, PUT, and PATCH.',
    icon: Document,
    requiredOn: ['POST', 'PUT', 'PATCH'],
  },
  strict_writes: {
    id: 'strict_writes',
    title: 'All mutations (strict)',
    desc: 'Require Content-Type on POST, PUT, PATCH, and DELETE.',
    icon: Security,
    requiredOn: ['POST', 'PUT', 'PATCH', 'DELETE'],
  },
  off: {
    id: 'off',
    title: 'Disabled',
    desc: 'Do not require Content-Type headers.',
    icon: Unlocked,
    requiredOn: [],
  },
  custom: {
    id: 'custom',
    title: 'Custom',
    desc: 'Select specific methods that require Content-Type.',
    icon: SettingsAdjust,
    requiredOn: [],
  },
};

export const AppSecurityRequestPage: React.FC<AppSecurityRequestPageProps> = ({ onNavigate }) => {
  const [_loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [serverConfig, setServerConfig] = useState<AppSecurityConfig>({ enabled: true });

  const [hvEnabled, setHvEnabled] = useState<boolean>(false);
  const [allowedHosts, setAllowedHosts] = useState<string[]>([]);
  const [newHostInput, setNewHostInput] = useState<string>('');
  const [hostInputError, setHostInputError] = useState<string>('');

  const [meEnabled, setMeEnabled] = useState<boolean>(true);
  const [methodPreset, setMethodPreset] = useState<string>('recommended');
  const [methodMode, setMethodMode] = useState<'blocklist' | 'allowlist'>('blocklist');
  const [selectedMethods, setSelectedMethods] = useState<string[]>(['TRACE', 'TRACK', 'CONNECT', 'DEBUG']);

  const [rsgEnabled, setRsgEnabled] = useState<boolean>(true);
  const [boundaryPreset, setBoundaryPreset] = useState<string>('balanced');
  const [maxUrlLength, setMaxUrlLength] = useState<number>(2048);
  const [maxQueryLength, setMaxQueryLength] = useState<number>(2048);
  const [maxHeaderCount, setMaxHeaderCount] = useState<number>(50);
  const [maxSingleHeaderSize, setMaxSingleHeaderSize] = useState<number>(8192);

  const [ctvEnabled, setCtvEnabled] = useState<boolean>(true);
  const [contentPreset, setContentPreset] = useState<string>('writes');
  const [ctvRequiredOn, setCtvRequiredOn] = useState<string[]>(['POST', 'PUT', 'PATCH']);

  const [hmEnabled, setHmEnabled] = useState<boolean>(false);
  const [addRequestHeaders, setAddRequestHeaders] = useState<Record<string, string>>({});
  const [removeRequestHeaders, setRemoveRequestHeaders] = useState<string[]>([]);
  const [newAddHeaderName, setNewAddHeaderName] = useState<string>('');
  const [newAddHeaderValue, setNewAddHeaderValue] = useState<string>('');
  const [newRemoveHeaderName, setNewRemoveHeaderName] = useState<string>('');
  const [headerError, setHeaderError] = useState<string>('');

  const handleNavigate = (key: NavItemKey) => {
    if (onNavigate) {
      onNavigate(key);
    } else {
      window.location.hash = `#${key}`;
    }
  };

  // Helper to compare array contents regardless of order
  const arraysEqual = (a?: string[], b?: string[]) => {
    const arrA = a || [];
    const arrB = b || [];
    if (arrA.length !== arrB.length) return false;
    const sortedA = [...arrA].sort();
    const sortedB = [...arrB].sort();
    return sortedA.every((val, idx) => val === sortedB[idx]);
  };

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const cfg = await apiService.getAppSecurityConfig();
      if (cfg) {
        setServerConfig(cfg);

        const hv = cfg.host_validator || { enabled: false, allowed_hosts: [] };
        setHvEnabled(Boolean(hv.enabled));
        setAllowedHosts(Array.isArray(hv.allowed_hosts) ? [...hv.allowed_hosts] : []);

        const me = cfg.method_enforcer || { enabled: true, mode: 'blocklist', blocked_methods: ['TRACE', 'TRACK', 'CONNECT', 'DEBUG'] };
        setMeEnabled(me.enabled !== false);
        const mMode = me.mode === 'allowlist' ? 'allowlist' : 'blocklist';
        setMethodMode(mMode);
        const methods = mMode === 'allowlist' ? (me.allowed_methods || []) : (me.blocked_methods || []);
        setSelectedMethods([...methods]);

        if (mMode === 'blocklist' && arraysEqual(methods, METHOD_PRESETS.recommended.methods)) {
          setMethodPreset('recommended');
        } else if (mMode === 'allowlist' && arraysEqual(methods, METHOD_PRESETS.api_strict.methods)) {
          setMethodPreset('api_strict');
        } else if (mMode === 'allowlist' && arraysEqual(methods, METHOD_PRESETS.read_only.methods)) {
          setMethodPreset('read_only');
        } else {
          setMethodPreset('custom');
        }

        const rsg = cfg.request_size_guard || {
          enabled: true,
          max_url_length: 2048,
          max_query_length: 2048,
          max_header_count: 50,
          max_single_header_size: 8192,
        };
        setRsgEnabled(rsg.enabled !== false);
        const urlL = rsg.max_url_length || 2048;
        const qL = rsg.max_query_length || 2048;
        const hC = rsg.max_header_count || 50;
        const sS = rsg.max_single_header_size || 8192;
        setMaxUrlLength(urlL);
        setMaxQueryLength(qL);
        setMaxHeaderCount(hC);
        setMaxSingleHeaderSize(sS);

        if (
          urlL === BOUNDARY_PRESETS.balanced.max_url_length &&
          qL === BOUNDARY_PRESETS.balanced.max_query_length &&
          hC === BOUNDARY_PRESETS.balanced.max_header_count &&
          sS === BOUNDARY_PRESETS.balanced.max_single_header_size
        ) {
          setBoundaryPreset('balanced');
        } else if (
          urlL === BOUNDARY_PRESETS.relaxed.max_url_length &&
          qL === BOUNDARY_PRESETS.relaxed.max_query_length &&
          hC === BOUNDARY_PRESETS.relaxed.max_header_count &&
          sS === BOUNDARY_PRESETS.relaxed.max_single_header_size
        ) {
          setBoundaryPreset('relaxed');
        } else if (
          urlL === BOUNDARY_PRESETS.strict.max_url_length &&
          qL === BOUNDARY_PRESETS.strict.max_query_length &&
          hC === BOUNDARY_PRESETS.strict.max_header_count &&
          sS === BOUNDARY_PRESETS.strict.max_single_header_size
        ) {
          setBoundaryPreset('strict');
        } else {
          setBoundaryPreset('custom');
        }

        const ctv = cfg.content_type_validator || { enabled: true, required_on: ['POST', 'PUT', 'PATCH'] };
        const isCtvOn = ctv.enabled !== false;
        setCtvEnabled(isCtvOn);
        const ctvReq = Array.isArray(ctv.required_on) ? [...ctv.required_on] : [];
        setCtvRequiredOn(ctvReq);

        if (!isCtvOn || ctvReq.length === 0) {
          setContentPreset('off');
        } else if (arraysEqual(ctvReq, CONTENT_TYPE_PRESETS.writes.requiredOn)) {
          setContentPreset('writes');
        } else if (arraysEqual(ctvReq, CONTENT_TYPE_PRESETS.strict_writes.requiredOn)) {
          setContentPreset('strict_writes');
        } else {
          setContentPreset('custom');
        }

        const hm = cfg.header_manager || { enabled: false, add_request_headers: {}, remove_request_headers: [] };
        setHmEnabled(Boolean(hm.enabled));
        setAddRequestHeaders(hm.add_request_headers ? { ...hm.add_request_headers } : {});
        setRemoveRequestHeaders(Array.isArray(hm.remove_request_headers) ? [...hm.remove_request_headers] : []);
      }
    } catch (err: any) {
      console.error('[AppSecurityRequestPage] Load error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSelectMethodPreset = (presetId: string) => {
    setMethodPreset(presetId);
    if (presetId === 'recommended') {
      setMethodMode('blocklist');
      setSelectedMethods([...METHOD_PRESETS.recommended.methods]);
    } else if (presetId === 'api_strict') {
      setMethodMode('allowlist');
      setSelectedMethods([...METHOD_PRESETS.api_strict.methods]);
    } else if (presetId === 'read_only') {
      setMethodMode('allowlist');
      setSelectedMethods([...METHOD_PRESETS.read_only.methods]);
    }
  };

  const handleToggleMethod = (method: string) => {
    setMethodPreset('custom');
    setSelectedMethods((prev) =>
      prev.includes(method) ? prev.filter((m) => m !== method) : [...prev, method],
    );
  };

  const handleSelectBoundaryPreset = (presetId: string) => {
    setBoundaryPreset(presetId);
    if (presetId === 'balanced') {
      setMaxUrlLength(BOUNDARY_PRESETS.balanced.max_url_length);
      setMaxQueryLength(BOUNDARY_PRESETS.balanced.max_query_length);
      setMaxHeaderCount(BOUNDARY_PRESETS.balanced.max_header_count);
      setMaxSingleHeaderSize(BOUNDARY_PRESETS.balanced.max_single_header_size);
    } else if (presetId === 'relaxed') {
      setMaxUrlLength(BOUNDARY_PRESETS.relaxed.max_url_length);
      setMaxQueryLength(BOUNDARY_PRESETS.relaxed.max_query_length);
      setMaxHeaderCount(BOUNDARY_PRESETS.relaxed.max_header_count);
      setMaxSingleHeaderSize(BOUNDARY_PRESETS.relaxed.max_single_header_size);
    } else if (presetId === 'strict') {
      setMaxUrlLength(BOUNDARY_PRESETS.strict.max_url_length);
      setMaxQueryLength(BOUNDARY_PRESETS.strict.max_query_length);
      setMaxHeaderCount(BOUNDARY_PRESETS.strict.max_header_count);
      setMaxSingleHeaderSize(BOUNDARY_PRESETS.strict.max_single_header_size);
    }
  };

  const handleSelectContentPreset = (presetId: string) => {
    setContentPreset(presetId);
    if (presetId === 'writes') {
      setCtvEnabled(true);
      setCtvRequiredOn([...CONTENT_TYPE_PRESETS.writes.requiredOn]);
    } else if (presetId === 'strict_writes') {
      setCtvEnabled(true);
      setCtvRequiredOn([...CONTENT_TYPE_PRESETS.strict_writes.requiredOn]);
    } else if (presetId === 'off') {
      setCtvEnabled(false);
      setCtvRequiredOn([]);
    }
  };

  const handleToggleContentMethod = (method: string) => {
    setContentPreset('custom');
    setCtvRequiredOn((prev) =>
      prev.includes(method) ? prev.filter((m) => m !== method) : [...prev, method],
    );
  };

  const handleAddHost = () => {
    setHostInputError('');
    const trimmed = newHostInput.trim().toLowerCase();
    if (!trimmed) return;

    if (allowedHosts.includes(trimmed)) {
      setHostInputError(`Domain "${trimmed}" is already added.`);
      return;
    }

    setAllowedHosts((prev) => [...prev, trimmed]);
    setNewHostInput('');
  };

  const handleRemoveHost = (host: string) => {
    setAllowedHosts((prev) => prev.filter((h) => h !== host));
  };

  const handleAddHeaderMap = () => {
    setHeaderError('');
    const name = newAddHeaderName.trim();
    const value = newAddHeaderValue.trim();
    if (!name) {
      setHeaderError('Header name is required.');
      return;
    }
    const tokenRegex = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
    if (!tokenRegex.test(name)) {
      setHeaderError('Invalid HTTP header name syntax.');
      return;
    }
    setAddRequestHeaders((prev) => ({
      ...prev,
      [name]: value,
    }));
    setNewAddHeaderName('');
    setNewAddHeaderValue('');
  };

  const handleRemoveHeaderMap = (name: string) => {
    setAddRequestHeaders((prev) => {
      const copy = { ...prev };
      delete copy[name];
      return copy;
    });
  };

  const handleAddRemoveHeader = () => {
    setHeaderError('');
    const name = newRemoveHeaderName.trim();
    if (!name) return;
    const tokenRegex = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
    if (!tokenRegex.test(name)) {
      setHeaderError('Invalid HTTP header name syntax.');
      return;
    }
    if (removeRequestHeaders.includes(name)) {
      setHeaderError(`Header "${name}" is already in the strip list.`);
      return;
    }
    setRemoveRequestHeaders((prev) => [...prev, name]);
    setNewRemoveHeaderName('');
  };

  const handleRemoveRemoveHeader = (name: string) => {
    setRemoveRequestHeaders((prev) => prev.filter((h) => h !== name));
  };

  const isDirty = useMemo(() => {
    const origHv = serverConfig.host_validator || { enabled: false, allowed_hosts: [] };
    const origMe = serverConfig.method_enforcer || { enabled: true, mode: 'blocklist', blocked_methods: ['TRACE', 'TRACK', 'CONNECT', 'DEBUG'] };
    const origRsg = serverConfig.request_size_guard || { enabled: true, max_url_length: 2048, max_query_length: 2048, max_header_count: 50, max_single_header_size: 8192 };
    const origCtv = serverConfig.content_type_validator || { enabled: true, required_on: ['POST', 'PUT', 'PATCH'] };
    const origHm = serverConfig.header_manager || { enabled: false, add_request_headers: {}, remove_request_headers: [] };

    if (hvEnabled !== Boolean(origHv.enabled)) return true;
    if (!arraysEqual(allowedHosts, origHv.allowed_hosts)) return true;

    if (meEnabled !== (origMe.enabled !== false)) return true;
    if (methodMode !== (origMe.mode === 'allowlist' ? 'allowlist' : 'blocklist')) return true;
    const origMethods = origMe.mode === 'allowlist' ? (origMe.allowed_methods || []) : (origMe.blocked_methods || []);
    if (!arraysEqual(selectedMethods, origMethods)) return true;

    if (rsgEnabled !== (origRsg.enabled !== false)) return true;
    if (maxUrlLength !== (origRsg.max_url_length || 2048)) return true;
    if (maxQueryLength !== (origRsg.max_query_length || 2048)) return true;
    if (maxHeaderCount !== (origRsg.max_header_count || 50)) return true;
    if (maxSingleHeaderSize !== (origRsg.max_single_header_size || 8192)) return true;

    if (ctvEnabled !== (origCtv.enabled !== false)) return true;
    if (!arraysEqual(ctvRequiredOn, origCtv.required_on)) return true;

    if (hmEnabled !== Boolean(origHm.enabled)) return true;
    if (JSON.stringify(addRequestHeaders) !== JSON.stringify(origHm.add_request_headers || {})) return true;
    if (!arraysEqual(removeRequestHeaders, origHm.remove_request_headers)) return true;

    return false;
  }, [
    serverConfig,
    hvEnabled,
    allowedHosts,
    meEnabled,
    methodMode,
    selectedMethods,
    rsgEnabled,
    maxUrlLength,
    maxQueryLength,
    maxHeaderCount,
    maxSingleHeaderSize,
    ctvEnabled,
    ctvRequiredOn,
    hmEnabled,
    addRequestHeaders,
    removeRequestHeaders,
  ]);

  const handleReset = () => {
    loadData();
  };

  const handleSave = async () => {
    setSaving(true);
    setNotification(null);
    try {
      const updates: Partial<AppSecurityConfig> = {
        host_validator: {
          enabled: hvEnabled,
          allowed_hosts: allowedHosts,
        },
        method_enforcer: {
          enabled: meEnabled,
          mode: methodMode,
          blocked_methods: methodMode === 'blocklist' ? selectedMethods : [],
          allowed_methods: methodMode === 'allowlist' ? selectedMethods : [],
        },
        request_size_guard: {
          enabled: rsgEnabled,
          max_url_length: maxUrlLength,
          max_query_length: maxQueryLength,
          max_header_count: maxHeaderCount,
          max_single_header_size: maxSingleHeaderSize,
        },
        content_type_validator: {
          enabled: ctvEnabled,
          required_on: ctvRequiredOn,
        },
        header_manager: {
          enabled: hmEnabled,
          add_request_headers: addRequestHeaders,
          remove_request_headers: removeRequestHeaders,
          add_response_headers: serverConfig.header_manager?.add_response_headers || {},
          remove_response_headers: serverConfig.header_manager?.remove_response_headers || [],
        },
      };

      const res = await apiService.saveAppSecurityConfig(updates);
      if (!res.success) {
        throw new Error(res.error || 'Server returned an error saving request policy.');
      }

      setNotification({
        type: 'success',
        message: 'Request policy configuration updated successfully.',
      });
      await loadData();
    } catch (err: any) {
      console.error('[AppSecurityRequestPage] Save error:', err);
      setNotification({
        type: 'error',
        message: err?.message || 'Failed to save request policy configuration.',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        title="Request policy"
        icon={SettingsAdjust}
        action={
          <Button
            kind="ghost"
            size="sm"
            renderIcon={ArrowLeft}
            onClick={() => handleNavigate('app-security')}
          >
            Back to Overview
          </Button>
        }
      />

      {notification && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind={notification.type}
            title={notification.type === 'success' ? 'Success' : notification.type === 'error' ? 'Error' : 'Notice'}
            subtitle={notification.message}
            onClose={() => setNotification(null)}
          />
        </div>
      )}

      <Tabs>
          <TabList aria-label="Request Policy Configuration Areas" contained>
            <Tab renderIcon={SettingsAdjust}>HTTP methods</Tab>
            <Tab renderIcon={Globe}>Host validation</Tab>
            <Tab renderIcon={Activity}>Request boundaries</Tab>
            <Tab renderIcon={Document}>Content-Type</Tab>
            <Tab renderIcon={Security}>Upstream headers</Tab>
          </TabList>

          <TabPanels>
            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="HTTP methods"
                action={
                  <StatusToggle
                    id="toggle-method-enforcer"
                    toggled={meEnabled}
                    onToggle={(val) => setMeEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle HTTP methods"
                  />
                }
              >
                <div style={{ marginBottom: '24px' }}>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '13px',
                      fontWeight: 600,
                      color: 'var(--cds-text-primary)',
                      marginBottom: '12px',
                    }}
                  >
                    Profile
                  </label>
                  <RadioCardGroup
                    name="method-preset-group"
                    valueSelected={methodPreset}
                    onChange={(val) => handleSelectMethodPreset(val)}
                    options={Object.values(METHOD_PRESETS).map((p) => ({
                      value: p.id,
                      title: p.title,
                      description: p.desc,
                      icon: p.icon,
                    }))}
                  />
                </div>

                {methodPreset === 'custom' && (
                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '20px',
                      marginTop: '16px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
                      <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                        Custom methods ({selectedMethods.length})
                      </strong>

                      <ContentSwitcher
                        selectedIndex={methodMode === 'blocklist' ? 0 : 1}
                        onChange={(idx) => setMethodMode(idx.name === 'blocklist' ? 'blocklist' : 'allowlist')}
                      >
                        <Switch name="blocklist" text="Block selected" />
                        <Switch name="allowlist" text="Allow selected" />
                      </ContentSwitcher>
                    </div>

                    <div
                      style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
                        gap: '8px',
                        marginTop: '12px',
                      }}
                    >
                      {ALL_HTTP_METHODS.map((method) => {
                        const isChecked = selectedMethods.includes(method);
                        return (
                          <div
                            key={method}
                            onClick={() => handleToggleMethod(method)}
                            style={{
                              padding: '10px 14px',
                              background: isChecked ? 'var(--cds-layer-selected-02)' : 'var(--cds-layer-01)',
                              border: `1px solid ${isChecked ? 'var(--cds-border-interactive)' : 'var(--cds-border-subtle)'}`,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              userSelect: 'none',
                              transition: 'all 0.15s ease',
                            }}
                          >
                            <span style={{ fontWeight: 600, fontSize: '13px', color: isChecked ? 'var(--cds-text-primary)' : 'var(--cds-text-secondary)' }}>
                              {method}
                            </span>
                            <Checkbox
                              id={`check-method-${method}`}
                              labelText={`Allow HTTP ${method} method`}
                              hideLabel
                              checked={isChecked}
                              onChange={() => {}}
                            />
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </SectionCard>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Host validation"
                action={
                  <StatusToggle
                    id="toggle-host-validator"
                    toggled={hvEnabled}
                    onToggle={(val) => setHvEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle Host validation"
                  />
                }
              >
                <div style={{ marginBottom: '24px' }}>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '13px',
                      fontWeight: 600,
                      color: 'var(--cds-text-primary)',
                      marginBottom: '12px',
                    }}
                  >
                    Mode
                  </label>
                  <RadioCardGroup
                    name="host-mode-group"
                    valueSelected={hvEnabled ? 'strict' : 'open'}
                    onChange={(val) => setHvEnabled(val === 'strict')}
                    options={[
                      {
                        value: 'open',
                        title: 'Permissive (all hosts)',
                        description: 'Accept any incoming Host header.',
                        icon: Unlocked,
                      },
                      {
                        value: 'strict',
                        title: 'Strict (allowlist)',
                        description: 'Allow only configured domains. Reject all others with 403 Forbidden.',
                        icon: Locked,
                      },
                    ]}
                  />
                </div>

                {hvEnabled && (
                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '20px',
                      marginTop: '16px',
                    }}
                  >
                    <div style={{ marginBottom: '16px' }}>
                      <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                        Authorized domains ({allowedHosts.length})
                      </strong>
                    </div>

                    <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', maxWidth: '600px' }}>
                      <TextInput
                        id="input-new-domain"
                        labelText="New authorized domain"
                        hideLabel
                        placeholder="Domain or IP (e.g. api.example.com)"
                        value={newHostInput}
                        onChange={(e) => setNewHostInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault();
                            handleAddHost();
                          }
                        }}
                      />
                      <Button
                        size="md"
                        renderIcon={Add}
                        onClick={handleAddHost}
                      >
                        Add domain
                      </Button>
                    </div>

                    {hostInputError && (
                      <p style={{ color: 'var(--cds-text-error)', fontSize: '12px', margin: '-8px 0 12px 0' }}>
                        {hostInputError}
                      </p>
                    )}

                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', minHeight: '36px', alignItems: 'center' }}>
                      {allowedHosts.length > 0 ? (
                        allowedHosts.map((host) => (
                          <Tag
                            key={host}
                            type="blue"
                            filter
                            onClose={() => handleRemoveHost(host)}
                          >
                            {host}
                          </Tag>
                        ))
                      ) : (
                        <span style={{ fontSize: '13px', color: 'var(--cds-text-helper)' }}>
                          No authorized domains configured.
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </SectionCard>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Request boundaries"
                action={
                  <StatusToggle
                    id="toggle-request-size-guard"
                    toggled={rsgEnabled}
                    onToggle={(val) => setRsgEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle Request boundaries"
                  />
                }
              >
                <div style={{ marginBottom: '24px' }}>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '13px',
                      fontWeight: 600,
                      color: 'var(--cds-text-primary)',
                      marginBottom: '12px',
                    }}
                  >
                    Profile
                  </label>
                  <RadioCardGroup
                    name="boundary-preset-group"
                    valueSelected={boundaryPreset}
                    onChange={(val) => handleSelectBoundaryPreset(val)}
                    options={Object.values(BOUNDARY_PRESETS).map((p) => ({
                      value: p.id,
                      title: p.title,
                      description: p.desc,
                      icon: p.icon,
                    }))}
                  />
                </div>

                <div
                  style={{
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '20px',
                    marginTop: '16px',
                  }}
                >
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                      gap: '16px',
                    }}
                  >
                    <NumberInput
                      id="input-max-url-length"
                      label="Max URL length (bytes)"
                      min={128}
                      max={65536}
                      step={128}
                      value={maxUrlLength}
                      onChange={(_e, { value }) => {
                        setMaxUrlLength(Number(value) || 2048);
                        setBoundaryPreset('custom');
                      }}
                    />

                    <NumberInput
                      id="input-max-query-length"
                      label="Max query length (bytes)"
                      min={64}
                      max={32768}
                      step={64}
                      value={maxQueryLength}
                      onChange={(_e, { value }) => {
                        setMaxQueryLength(Number(value) || 2048);
                        setBoundaryPreset('custom');
                      }}
                    />

                    <NumberInput
                      id="input-max-header-count"
                      label="Max header count"
                      min={5}
                      max={200}
                      step={5}
                      value={maxHeaderCount}
                      onChange={(_e, { value }) => {
                        setMaxHeaderCount(Number(value) || 50);
                        setBoundaryPreset('custom');
                      }}
                    />

                    <NumberInput
                      id="input-max-single-header-size"
                      label="Max single header size (bytes)"
                      min={256}
                      max={65536}
                      step={256}
                      value={maxSingleHeaderSize}
                      onChange={(_e, { value }) => {
                        setMaxSingleHeaderSize(Number(value) || 8192);
                        setBoundaryPreset('custom');
                      }}
                    />
                  </div>
                </div>
              </SectionCard>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Content-Type enforcement"
                action={
                  <StatusToggle
                    id="toggle-content-type-validator"
                    toggled={ctvEnabled}
                    onToggle={(val) => setCtvEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle Content-Type enforcement"
                  />
                }
              >
                <div style={{ marginBottom: '24px' }}>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '13px',
                      fontWeight: 600,
                      color: 'var(--cds-text-primary)',
                      marginBottom: '12px',
                    }}
                  >
                    Profile
                  </label>
                  <RadioCardGroup
                    name="content-type-preset-group"
                    valueSelected={contentPreset}
                    onChange={(val) => handleSelectContentPreset(val)}
                    options={Object.values(CONTENT_TYPE_PRESETS).map((p) => ({
                      value: p.id,
                      title: p.title,
                      description: p.desc,
                      icon: p.icon,
                    }))}
                  />
                </div>

                {contentPreset === 'custom' && (
                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '20px',
                      marginTop: '16px',
                    }}
                  >
                    <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)', display: 'block', marginBottom: '16px' }}>
                      Required methods
                    </strong>

                    <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                      {WRITE_HTTP_METHODS.map((method) => {
                        const isChecked = ctvRequiredOn.includes(method);
                        return (
                          <div
                            key={method}
                            onClick={() => handleToggleContentMethod(method)}
                            style={{
                              padding: '10px 18px',
                              background: isChecked ? 'var(--cds-layer-selected-02)' : 'var(--cds-layer-01)',
                              border: `1px solid ${isChecked ? 'var(--cds-border-interactive)' : 'var(--cds-border-subtle)'}`,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '12px',
                              userSelect: 'none',
                            }}
                          >
                            <span style={{ fontWeight: 600, fontSize: '13px', color: isChecked ? 'var(--cds-text-primary)' : 'var(--cds-text-secondary)' }}>
                              {method}
                            </span>
                            <Checkbox
                              id={`check-ctv-${method}`}
                              labelText={`Require Content-Type on ${method}`}
                              hideLabel
                              checked={isChecked}
                              onChange={() => {}}
                            />
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </SectionCard>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Upstream headers"
                action={
                  <StatusToggle
                    id="toggle-header-manager"
                    toggled={hmEnabled}
                    onToggle={(val) => setHmEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle upstream headers"
                  />
                }
              >
                {headerError && (
                  <div style={{ marginBottom: '16px' }}>
                    <InlineNotification
                      kind="error"
                      title="Invalid header"
                      subtitle={headerError}
                      onClose={() => setHeaderError('')}
                    />
                  </div>
                )}

                <div
                  style={{
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '20px',
                    marginBottom: '20px',
                  }}
                >
                  <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                    Add request headers ({Object.keys(addRequestHeaders).length})
                  </strong>

                  <div style={{ display: 'flex', gap: '8px', margin: '16px 0', flexWrap: 'wrap', alignItems: 'flex-end' }}>
                    <div style={{ width: '220px' }}>
                      <TextInput
                        id="input-add-header-name"
                        labelText="Header name"
                        placeholder="e.g. X-Forwarded-Client"
                        value={newAddHeaderName}
                        onChange={(e) => setNewAddHeaderName(e.target.value)}
                      />
                    </div>
                    <div style={{ width: '260px' }}>
                      <TextInput
                        id="input-add-header-val"
                        labelText="Header value"
                        placeholder="e.g. Aegis-Gateway"
                        value={newAddHeaderValue}
                        onChange={(e) => setNewAddHeaderValue(e.target.value)}
                      />
                    </div>
                    <Button
                      size="md"
                      renderIcon={Add}
                      onClick={handleAddHeaderMap}
                    >
                      Add header
                    </Button>
                  </div>

                  {Object.keys(addRequestHeaders).length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {Object.entries(addRequestHeaders).map(([k, v]) => (
                        <div
                          key={k}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '8px 12px',
                            background: 'var(--cds-layer-01)',
                            border: '1px solid var(--cds-border-subtle)',
                          }}
                        >
                          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                            <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--cds-text-primary)', fontFamily: 'monospace' }}>
                              {k}:
                            </span>
                            <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', fontFamily: 'monospace' }}>
                              {v}
                            </span>
                          </div>
                          <Button
                            kind="ghost"
                            size="sm"
                            hasIconOnly
                            renderIcon={TrashCan}
                            iconDescription="Remove header"
                            onClick={() => handleRemoveHeaderMap(k)}
                          />
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span style={{ fontSize: '13px', color: 'var(--cds-text-helper)' }}>
                      No headers configured.
                    </span>
                  )}
                </div>

                <div
                  style={{
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '20px',
                  }}
                >
                  <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                    Strip request headers ({removeRequestHeaders.length})
                  </strong>

                  <div style={{ display: 'flex', gap: '8px', margin: '16px 0', maxWidth: '500px' }}>
                    <TextInput
                      id="input-remove-header-name"
                      labelText="Header name"
                      hideLabel
                      placeholder="e.g. X-Powered-By or Proxy-Connection"
                      value={newRemoveHeaderName}
                      onChange={(e) => setNewRemoveHeaderName(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault();
                          handleAddRemoveHeader();
                        }
                      }}
                    />
                    <Button
                      size="md"
                      renderIcon={Add}
                      onClick={handleAddRemoveHeader}
                    >
                      Strip header
                    </Button>
                  </div>

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', minHeight: '36px', alignItems: 'center' }}>
                    {removeRequestHeaders.length > 0 ? (
                      removeRequestHeaders.map((hdr) => (
                        <Tag
                          key={hdr}
                          type="red"
                          filter
                          onClose={() => handleRemoveRemoveHeader(hdr)}
                        >
                          {hdr}
                        </Tag>
                      ))
                    ) : (
                      <span style={{ fontSize: '13px', color: 'var(--cds-text-helper)' }}>
                        No headers configured for removal.
                      </span>
                    )}
                  </div>
                </div>
              </SectionCard>
            </TabPanel>
          </TabPanels>
        </Tabs>

      <SaveActionBar
        isDirty={isDirty}
        isSaving={saving}
        onReset={handleReset}
        onSave={handleSave}
        message="You have unsaved changes"
      />
    </div>
  );
};

export default AppSecurityRequestPage;
