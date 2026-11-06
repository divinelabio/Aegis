import React, { useEffect, useState, useMemo } from 'react';
import {
  Button,
  Select,
  SelectItem,
  Toggle,
  NumberInput,
  TextInput,
  TextArea,
  Tag,
  InlineNotification,
  Loading,
  Breadcrumb,
  BreadcrumbItem,
} from '@carbon/react';
import {
  Security,
  View,
  SettingsAdjust,
  Document,
  ChevronRight,
  ArrowLeft,
  Add,
  TrashCan,
  DataBase,
  Globe,
  Code,
} from '@carbon/icons-react';
import type {
  WAFSectionConfig,
  WAFLeakProtectionConfig,
  WAFLeakPattern,
  WAFLeakAllowlistEntry,
} from '../types';
import { apiService } from '../services/api';
import {
  PageHeader,
  SectionCard,
  SaveActionBar,
} from '../components/common';

interface ControlRowProps {
  title: string;
  description?: string;
  icon?: React.ComponentType<{ size?: number; style?: React.CSSProperties }>;
  action?: React.ReactNode;
  noBorder?: boolean;
}

const ControlRow: React.FC<ControlRowProps> = ({
  title,
  description,
  icon: Icon,
  action,
  noBorder,
}) => (
  <div
    style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: '16px',
      padding: '16px 0',
      borderBottom: noBorder ? 'none' : '1px solid var(--cds-border-subtle)',
    }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '72%' }}>
      {Icon && (
        <Icon size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
      )}
      <div>
        <div
          style={{
            fontWeight: 600,
            fontSize: '14px',
            color: 'var(--cds-text-primary)',
            marginBottom: description ? '4px' : 0,
          }}
        >
          {title}
        </div>
        {description && (
          <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
            {description}
          </div>
        )}
      </div>
    </div>
    {action && <div style={{ flexShrink: 0 }}>{action}</div>}
  </div>
);

type LeakSubPage =
  | ''
  | 'advanced'
  | 'credentials'
  | 'debug'
  | 'files'
  | 'custom_detectors'
  | 'allowlist';

interface LeakMimeGroup {
  id: string;
  title: string;
  description: string;
  mimeTypes: string[];
  icon: React.ComponentType<{ size?: number; style?: React.CSSProperties }>;
}

const LEAK_MIME_GROUPS: LeakMimeGroup[] = [
  {
    id: 'json_api',
    title: 'REST & JSON APIs',
    description:
      'Scans JSON payloads and API error objects.',
    mimeTypes: ['application/json', 'application/problem+json'],
    icon: DataBase,
  },
  {
    id: 'web_pages',
    title: 'Web Pages & HTML',
    description:
      'Scans HTML views, stack traces, and plain text responses.',
    mimeTypes: ['text/html', 'text/plain'],
    icon: Globe,
  },
  {
    id: 'xml_soap',
    title: 'XML & SOAP Services',
    description:
      'Scans XML feeds and SOAP payloads.',
    mimeTypes: ['text/xml', 'application/xml'],
    icon: Document,
  },
  {
    id: 'scripts',
    title: 'JavaScript & Scripts',
    description:
      'Scans generated JavaScript files for embedded keys.',
    mimeTypes: ['application/javascript', 'text/javascript'],
    icon: Code,
  },
];

interface LeakCategoryGroup {
  id: 'credentials' | 'debug' | 'files';
  title: string;
  description: string;
  items: Array<{ category: string; title: string }>;
}

const LEAK_CATEGORY_GROUPS: LeakCategoryGroup[] = [
  {
    id: 'credentials',
    title: 'Credentials and tokens',
    description: '6 categories',
    items: [
      { category: 'private_key', title: 'Private keys' },
      { category: 'cloud_secret', title: 'Cloud credentials' },
      { category: 'api_token', title: 'API tokens' },
      { category: 'jwt', title: 'JWTs' },
      { category: 'env_file', title: 'Environment dumps' },
      { category: 'db_connection', title: 'Database connections' },
    ],
  },
  {
    id: 'debug',
    title: 'Debug and source exposure',
    description: '4 categories',
    items: [
      { category: 'stack_trace', title: 'Stack traces' },
      { category: 'debug_page', title: 'Debug pages' },
      { category: 'source_code', title: 'Source code' },
      { category: 'internal_network', title: 'Internal network details' },
    ],
  },
  {
    id: 'files',
    title: 'Browsable files',
    description: '2 categories',
    items: [
      { category: 'directory_listing', title: 'Directory listings' },
      { category: 'backup_config', title: 'Backup and config files' },
    ],
  },
];

const ACTION_OPTIONS = [
  { value: 'allow', label: 'Bypass inspection' },
  { value: 'detect', label: 'Monitor only' },
  { value: 'redact', label: 'Redact matches' },
  { value: 'block', label: 'Block responses' },
];

const DEFAULT_LEAK_CONFIG: Required<
  Pick<
    WAFLeakProtectionConfig,
    | 'enabled'
    | 'mode'
    | 'default_action'
    | 'max_body_size'
    | 'inspect_content_types'
    | 'skip_content_types'
    | 'redaction_enabled'
    | 'block_status_code'
    | 'replacement_body'
    | 'rules'
    | 'custom_patterns'
    | 'allowlist'
  >
> = {
  enabled: true,
  mode: 'detect',
  default_action: 'detect',
  max_body_size: 1048576,
  inspect_content_types: [
    'text/html',
    'text/plain',
    'application/json',
    'application/javascript',
    'text/xml',
    'application/xml',
  ],
  skip_content_types: [
    'image/*',
    'video/*',
    'audio/*',
    'font/*',
    'application/octet-stream',
    'application/pdf',
  ],
  redaction_enabled: true,
  block_status_code: 403,
  replacement_body: 'Response blocked by Aegis Leak Protection',
  rules: {},
  custom_patterns: [],
  allowlist: [],
};

function normalizeLeakAction(raw: unknown, fallback = 'detect'): string {
  if (typeof raw !== 'string') return fallback;
  if (raw === 'monitoring') return 'detect';
  if (raw === 'blocking') return 'block';
  if (raw === 'off') return 'allow';
  return ['allow', 'detect', 'redact', 'block'].includes(raw) ? raw : fallback;
}

function normalizeLeakConfig(raw?: WAFLeakProtectionConfig): WAFLeakProtectionConfig {
  const src = raw || {};
  const rulesSource = src.rules || src.categories || {};
  const rules: Record<string, string> = {};
  Object.entries(rulesSource).forEach(([k, v]) => {
    if (v) {
      rules[k] = normalizeLeakAction(v);
    }
  });

  const mode = normalizeLeakAction(src.mode ?? src.default_action, 'detect');
  const defaultAction = normalizeLeakAction(src.default_action ?? src.mode, mode);

  return {
    enabled: src.enabled !== undefined ? Boolean(src.enabled) : DEFAULT_LEAK_CONFIG.enabled,
    mode,
    default_action: defaultAction,
    max_body_size:
      typeof src.max_body_size === 'number' && src.max_body_size > 0
        ? src.max_body_size
        : DEFAULT_LEAK_CONFIG.max_body_size,
    inspect_content_types: Array.isArray(src.inspect_content_types)
      ? [...src.inspect_content_types]
      : [...DEFAULT_LEAK_CONFIG.inspect_content_types],
    skip_content_types: Array.isArray(src.skip_content_types)
      ? [...src.skip_content_types]
      : [...DEFAULT_LEAK_CONFIG.skip_content_types],
    redaction_enabled:
      src.redaction_enabled !== undefined
        ? Boolean(src.redaction_enabled)
        : DEFAULT_LEAK_CONFIG.redaction_enabled,
    block_status_code:
      typeof src.block_status_code === 'number' &&
      src.block_status_code >= 400 &&
      src.block_status_code <= 599
        ? src.block_status_code
        : DEFAULT_LEAK_CONFIG.block_status_code,
    replacement_body:
      typeof src.replacement_body === 'string'
        ? src.replacement_body
        : DEFAULT_LEAK_CONFIG.replacement_body,
    rules,
    custom_patterns: Array.isArray(src.custom_patterns)
      ? src.custom_patterns.map((p) => ({ ...p }))
      : [],
    allowlist: Array.isArray(src.allowlist)
      ? src.allowlist.map((a) => ({ ...a }))
      : [],
  };
}

export const WafLeakProtectionPage: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [subPage, setSubPage] = useState<LeakSubPage>('');
  const [serverConfig, setServerConfig] = useState<WAFSectionConfig | null>(null);
  const [leakConfig, setLeakConfig] = useState<WAFLeakProtectionConfig>(() =>
    normalizeLeakConfig(undefined)
  );
  const [savedLeakConfig, setSavedLeakConfig] = useState<WAFLeakProtectionConfig>(() =>
    normalizeLeakConfig(undefined)
  );
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info' | 'warning';
    title: string;
    subtitle?: string;
  } | null>(null);

  const [detectorName, setDetectorName] = useState<string>('');
  const [detectorPattern, setDetectorPattern] = useState<string>('');
  const [detectorCategory, setDetectorCategory] = useState<string>('custom');
  const [detectorAction, setDetectorAction] = useState<string>('');

  const [allowHost, setAllowHost] = useState<string>('');
  const [allowPath, setAllowPath] = useState<string>('');
  const [allowContentType, setAllowContentType] = useState<string>('');
  const [allowCategory, setAllowCategory] = useState<string>('');
  const [allowReason, setAllowReason] = useState<string>('');
  const [allowExpires, setAllowExpires] = useState<string>('');

  const [inspectMimeInput, setInspectMimeInput] = useState<string>('');
  const [skipMimeInput, setSkipMimeInput] = useState<string>('');

  const loadConfig = async () => {
    setLoading(true);
    try {
      const fullRes = await apiService.getWafFullConfig();
      const cfg = fullRes?.config || null;
      setServerConfig(cfg);
      const normalized = normalizeLeakConfig(cfg?.leak_protection);
      setLeakConfig(normalized);
      setSavedLeakConfig(normalizeLeakConfig(cfg?.leak_protection));
    } catch {
      setNotification({
        kind: 'error',
        title: 'Failed to load Leak Protection configuration',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadConfig();
  }, []);

  const isDirty = useMemo(() => {
    return JSON.stringify(leakConfig) !== JSON.stringify(savedLeakConfig);
  }, [leakConfig, savedLeakConfig]);

  const maxBodyMib = useMemo(() => {
    const bytes = leakConfig.max_body_size || DEFAULT_LEAK_CONFIG.max_body_size;
    return Math.round((bytes / (1024 * 1024)) * 10) / 10;
  }, [leakConfig.max_body_size]);

  const activeGroupCount = useMemo(() => {
    const inspectList = leakConfig.inspect_content_types || [];
    return LEAK_MIME_GROUPS.filter((group) =>
      inspectList.some((m) =>
        group.mimeTypes.some((gm) => gm.toLowerCase() === m.toLowerCase())
      )
    ).length;
  }, [leakConfig.inspect_content_types]);

  const exceptionCount = useMemo(() => {
    const rulesCount = Object.keys(leakConfig.rules || {}).length;
    const patternsCount = (leakConfig.custom_patterns || []).length;
    const allowlistCount = (leakConfig.allowlist || []).length;
    return rulesCount + patternsCount + allowlistCount;
  }, [leakConfig.rules, leakConfig.custom_patterns, leakConfig.allowlist]);

  const advancedSummary = useMemo(() => {
    return `${activeGroupCount} of ${LEAK_MIME_GROUPS.length} response categories enabled${
      exceptionCount
        ? ` · ${exceptionCount} exception${exceptionCount === 1 ? '' : 's'}`
        : ''
    }`;
  }, [activeGroupCount, exceptionCount]);

  const handleToggleMimeGroup = (groupId: string, enabled: boolean) => {
    const group = LEAK_MIME_GROUPS.find((g) => g.id === groupId);
    if (!group) return;
    let current = [...(leakConfig.inspect_content_types || [])];
    if (enabled) {
      for (const mime of group.mimeTypes) {
        if (!current.some((m) => m.toLowerCase() === mime.toLowerCase())) {
          current.push(mime);
        }
      }
    } else {
      current = current.filter(
        (m) => !group.mimeTypes.some((gm) => gm.toLowerCase() === m.toLowerCase())
      );
    }
    setLeakConfig((prev) => ({
      ...prev,
      inspect_content_types: current,
    }));
  };

  const handleAddMime = (scope: 'inspect' | 'skip') => {
    const raw = (scope === 'inspect' ? inspectMimeInput : skipMimeInput)
      .trim()
      .toLowerCase();
    if (!/^[^/\s]+\/[^/\s]+$/.test(raw)) {
      setNotification({
        kind: 'warning',
        title: 'Invalid MIME type',
        subtitle: 'Enter a MIME type such as application/json or image/*',
      });
      return;
    }
    const field =
      scope === 'inspect' ? 'inspect_content_types' : 'skip_content_types';
    const current = [...(leakConfig[field] || [])];
    if (current.some((v) => v.toLowerCase() === raw)) {
      setNotification({
        kind: 'info',
        title: 'MIME type already configured',
      });
      return;
    }
    setLeakConfig((prev) => ({
      ...prev,
      [field]: [...current, raw],
    }));
    if (scope === 'inspect') setInspectMimeInput('');
    else setSkipMimeInput('');
  };

  const handleRemoveMime = (scope: 'inspect' | 'skip', mimeType: string) => {
    const field =
      scope === 'inspect' ? 'inspect_content_types' : 'skip_content_types';
    setLeakConfig((prev) => ({
      ...prev,
      [field]: (prev[field] || []).filter(
        (v) => v.toLowerCase() !== mimeType.toLowerCase()
      ),
    }));
  };

  const handleCategoryActionChange = (category: string, action: string) => {
    setLeakConfig((prev) => {
      const nextRules = { ...(prev.rules || {}) };
      if (!action) {
        delete nextRules[category];
      } else {
        nextRules[category] = action;
      }
      return {
        ...prev,
        rules: nextRules,
      };
    });
  };

  const handleAddPattern = () => {
    const name = detectorName.trim();
    const pattern = detectorPattern.trim();
    const category = detectorCategory.trim() || 'custom';
    const action = detectorAction.trim();

    if (!name || !pattern) {
      setNotification({
        kind: 'warning',
        title: 'Missing detector details',
        subtitle: 'Provide a detector name and regular expression.',
      });
      return;
    }

    const newPattern: WAFLeakPattern = {
      id: 'leak.custom.' + Date.now().toString(36),
      name,
      pattern,
      category,
      severity: 'medium',
      action,
      enabled: true,
      confidence: 75,
    };

    setLeakConfig((prev) => ({
      ...prev,
      custom_patterns: [...(prev.custom_patterns || []), newPattern],
    }));
    setDetectorName('');
    setDetectorPattern('');
    setDetectorCategory('custom');
    setDetectorAction('');
  };

  const handleRemovePattern = (id: string) => {
    setLeakConfig((prev) => ({
      ...prev,
      custom_patterns: (prev.custom_patterns || []).filter((p) => p.id !== id),
    }));
  };

  const handleAddAllowlist = () => {
    const host = allowHost.trim();
    const path = allowPath.trim();
    const contentType = allowContentType.trim();
    const category = allowCategory.trim();
    const reason = allowReason.trim();
    const expiryValue = allowExpires.trim();

    if (!host && !path && !contentType) {
      setNotification({
        kind: 'warning',
        title: 'Unbounded allowlist exception',
        subtitle: 'Bound the exception to a host, path, or content type.',
      });
      return;
    }
    if (!reason) {
      setNotification({
        kind: 'warning',
        title: 'Reason required',
        subtitle: 'Add a reason before staging an allowlist exception.',
      });
      return;
    }

    let expiresAt = '';
    if (expiryValue) {
      const expiry = new Date(expiryValue + 'T00:00:00.000Z');
      if (Number.isNaN(expiry.getTime())) {
        setNotification({
          kind: 'warning',
          title: 'Invalid expiry date',
          subtitle: 'Enter a valid allowlist expiry date.',
        });
        return;
      }
      expiresAt = expiry.toISOString();
    }

    const newEntry: WAFLeakAllowlistEntry = {
      id: 'leak.allowlist.' + Date.now().toString(36),
      enabled: true,
      category,
      host,
      path,
      content_type: contentType,
      expires_at: expiresAt,
      reason,
    };

    setLeakConfig((prev) => ({
      ...prev,
      allowlist: [...(prev.allowlist || []), newEntry],
    }));
    setAllowHost('');
    setAllowPath('');
    setAllowContentType('');
    setAllowCategory('');
    setAllowReason('');
    setAllowExpires('');
  };

  const handleRemoveAllowlist = (id: string) => {
    setLeakConfig((prev) => ({
      ...prev,
      allowlist: (prev.allowlist || []).filter((a) => a.id !== id),
    }));
  };

  const handleSave = async () => {
    setSaving(true);
    setNotification(null);
    try {
      const updates: WAFSectionConfig = {
        ...(serverConfig || {}),
        leak_protection: leakConfig,
      };
      const result = await apiService.saveWafFullConfig(updates, serverConfig || undefined);
      if (result.success) {
        await loadConfig();
        setNotification({
          kind: 'success',
          title: 'Leak Protection configuration saved',
          subtitle: 'Outbound secret inspection settings have been updated.',
        });
      } else {
        setNotification({
          kind: 'error',
          title: 'Failed to save Leak Protection configuration',
          subtitle: result.error || 'Verify your settings and try again.',
        });
      }
    } catch {
      setNotification({
        kind: 'error',
        title: 'Error saving Leak Protection configuration',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleDiscard = () => {
    setLeakConfig(normalizeLeakConfig(savedLeakConfig));
    setNotification(null);
  };

  const selectedCategoryGroup = LEAK_CATEGORY_GROUPS.find(
    (g) => g.id === subPage
  );
  const isAdvancedChildPage =
    Boolean(selectedCategoryGroup) ||
    subPage === 'custom_detectors' ||
    subPage === 'allowlist';

  const mode = normalizeLeakAction(leakConfig.mode, 'detect');
  const defaultAction = normalizeLeakAction(leakConfig.default_action, mode);

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px', width: '100%' }}>
        <Loading withOverlay={false} description="Loading leak protection..." />
      </div>
    );
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '24px',
        padding: '32px',
        width: '100%',
        boxSizing: 'border-box',
      }}
    >
      {subPage !== '' && (
        <Breadcrumb noTrailingSlash style={{ marginBottom: '-8px' }}>
          <BreadcrumbItem
            href="#waf-leak"
            onClick={(e: React.MouseEvent) => {
              e.preventDefault();
              setSubPage('');
            }}
          >
            Leak protection
          </BreadcrumbItem>
          {isAdvancedChildPage && (
            <BreadcrumbItem
              href="#waf-leak-advanced"
              onClick={(e: React.MouseEvent) => {
                e.preventDefault();
                setSubPage('advanced');
              }}
            >
              Advanced settings
            </BreadcrumbItem>
          )}
          <BreadcrumbItem isCurrentPage>
            {selectedCategoryGroup
              ? selectedCategoryGroup.title
              : subPage === 'custom_detectors'
              ? 'Custom detectors'
              : subPage === 'allowlist'
              ? 'Allowlist exceptions'
              : 'Advanced settings'}
          </BreadcrumbItem>
        </Breadcrumb>
      )}

      <PageHeader
        kicker="Application firewall"
        title="Leak protection"
        icon={View}
        action={
          subPage !== '' ? (
            <Button
              kind="ghost"
              size="sm"
              renderIcon={ArrowLeft}
              onClick={() =>
                setSubPage(isAdvancedChildPage ? 'advanced' : '')
              }
            >
              {isAdvancedChildPage
                ? 'Back to Advanced settings'
                : 'Back to Leak Protection'}
            </Button>
          ) : undefined
        }
      />

      {notification && (
        <InlineNotification
          kind={notification.kind}
          title={notification.title}
          subtitle={notification.subtitle}
          onCloseButtonClick={() => setNotification(null)}
          lowContrast
        />
      )}

      {subPage === '' && (
        <>
          <SectionCard
            title="Leak protection"
          >
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <ControlRow
                title="Inspect responses for exposed secrets"
                description="Scan outbound application responses to detect and prevent data leakage."
                icon={View}
                action={
                  <Toggle
                    id="waf-leak-enabled-toggle"
                    labelText=""
                    hideLabel
                    toggled={Boolean(leakConfig.enabled)}
                    onToggle={(checked: boolean) => setLeakConfig((prev) => ({ ...prev, enabled: checked }))
                    }
                  />
                }
              />
              <ControlRow
                title="Response action"
                description="Action taken when sensitive data or credentials are detected."
                icon={Security}
                noBorder
                action={
                  <div style={{ minWidth: '220px' }}>
                    <Select
                      id="waf-leak-mode-select"
                      labelText="Leak mitigation mode"
                      hideLabel
                      size="sm"
                      value={mode}
                      onChange={(e) => {
                        const nextMode = e.target.value;
                        setLeakConfig((prev) => ({
                          ...prev,
                          mode: nextMode,
                          default_action: nextMode,
                        }));
                      }}
                    >
                      {ACTION_OPTIONS.map((opt) => (
                        <SelectItem
                          key={opt.value}
                          value={opt.value}
                          text={opt.label}
                        />
                      ))}
                    </Select>
                  </div>
                }
              />
            </div>
          </SectionCard>

          <SectionCard
            title="Inspection coverage"
            description="Configure payload thresholds and targeted response types."
          >
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <ControlRow
                title="Maximum response size"
                description="Payload limit for outbound scanning. Larger payloads bypass inspection."
                icon={Document}
                action={
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      width: '160px',
                    }}
                  >
                    <NumberInput
                      id="waf-leak-max-body-size"
                      label="Maximum response size"
                      hideLabel
                      size="sm"
                      min={0.5}
                      max={64}
                      step={0.5}
                      value={maxBodyMib}
                      onChange={(_e: any, { value }: { value: string | number }) => {
                        const num = Number(value);
                        if (Number.isFinite(num) && num >= 0.5 && num <= 64) {
                          setLeakConfig((prev) => ({
                            ...prev,
                            max_body_size: Math.round(num * 1024 * 1024),
                          }));
                        }
                      }}
                    />
                    <span
                      style={{
                        fontSize: '0.75rem',
                        color: 'var(--cds-text-secondary)',
                      }}
                    >
                      MiB
                    </span>
                  </div>
                }
              />
              <ControlRow
                title="Advanced settings"
                description={advancedSummary}
                icon={SettingsAdjust}
                noBorder
                action={
                  <Button
                    kind="ghost"
                    size="sm"
                    renderIcon={ChevronRight}
                    onClick={() => setSubPage('advanced')}
                  >
                    Configure
                  </Button>
                }
              />
            </div>
          </SectionCard>
        </>
      )}

      {subPage === 'advanced' && (
        <>
          <SectionCard
            title="Advanced settings"
          >
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {LEAK_MIME_GROUPS.map((group, idx) => {
                const isGroupEnabled = (
                  leakConfig.inspect_content_types || []
                ).some((m) =>
                  group.mimeTypes.some(
                    (gm) => gm.toLowerCase() === m.toLowerCase()
                  )
                );
                return (
                  <ControlRow
                    key={group.id}
                    title={group.title}
                    description={group.description}
                    icon={group.icon}
                    noBorder={
                      idx === LEAK_MIME_GROUPS.length - 1 &&
                      mode !== 'redact' &&
                      defaultAction !== 'redact' &&
                      mode !== 'block' &&
                      defaultAction !== 'block'
                    }
                    action={
                      <Toggle
                        id={`waf-leak-mime-group-${group.id}`}
                        labelText=""
                        hideLabel
                        toggled={isGroupEnabled}
                        onToggle={(checked: boolean) => handleToggleMimeGroup(group.id, checked)
                        }
                      />
                    }
                  />
                );
              })}

              {(mode === 'redact' || defaultAction === 'redact') && (
                <ControlRow
                  title="Replace detected values"
                  description="Mask matched secrets with [REDACTED] before delivery."
                  icon={View}
                  noBorder={mode !== 'block' && defaultAction !== 'block'}
                  action={
                    <Toggle
                      id="waf-leak-redaction-enabled"
                      labelText=""
                      hideLabel
                      toggled={Boolean(leakConfig.redaction_enabled)}
                      onToggle={(checked: boolean) => setLeakConfig((prev) => ({
                          ...prev,
                          redaction_enabled: checked,
                        }))
                      }
                    />
                  }
                />
              )}

              {(mode === 'block' || defaultAction === 'block') && (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                    gap: '16px',
                    padding: '16px 0',
                  }}
                >
                  <div>
                    <NumberInput
                      id="waf-leak-block-status"
                      label="Block response status (HTTP)"
                      min={400}
                      max={599}
                      step={1}
                      value={leakConfig.block_status_code || 403}
                      onChange={(_e: any, { value }: { value: string | number }) => {
                        const code = Number(value);
                        if (Number.isFinite(code) && code >= 400 && code <= 599) {
                          setLeakConfig((prev) => ({
                            ...prev,
                            block_status_code: Math.round(code),
                          }));
                        }
                      }}
                    />
                  </div>
                  <div>
                    <TextArea
                      id="waf-leak-replacement-body"
                      labelText="Blocked response body"
                      helperText="Response message returned to clients when a response is blocked."
                      rows={3}
                      value={leakConfig.replacement_body || ''}
                      onChange={(e) =>
                        setLeakConfig((prev) => ({
                          ...prev,
                          replacement_body: e.target.value,
                        }))
                      }
                    />
                  </div>
                </div>
              )}
            </div>
          </SectionCard>

          <SectionCard
            title="Custom MIME coverage"
          >
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                gap: '24px',
              }}
            >
              <div>
                <div
                  style={{
                    fontSize: '0.875rem',
                    fontWeight: 600,
                    marginBottom: '8px',
                  }}
                >
                  Inspected Content-Types
                </div>
                <div
                  style={{
                    display: 'flex',
                    gap: '8px',
                    marginBottom: '12px',
                  }}
                >
                  <TextInput
                    id="waf-leak-inspect-mime-input"
                    labelText="New MIME type to inspect"
                    hideLabel
                    size="sm"
                    placeholder="e.g. application/vnd.api+json"
                    value={inspectMimeInput}
                    onChange={(e) => setInspectMimeInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        handleAddMime('inspect');
                      }
                    }}
                  />
                  <Button
                    kind="secondary"
                    size="sm"
                    renderIcon={Add}
                    onClick={() => handleAddMime('inspect')}
                  >
                    Add
                  </Button>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {(leakConfig.inspect_content_types || []).map((mime) => (
                    <Tag
                      key={mime}
                      type="blue"
                      size="sm"
                      filter
                      onClose={() => handleRemoveMime('inspect', mime)}
                    >
                      {mime}
                    </Tag>
                  ))}
                </div>
              </div>

              <div>
                <div
                  style={{
                    fontSize: '0.875rem',
                    fontWeight: 600,
                    marginBottom: '8px',
                  }}
                >
                  Skipped Content-Types
                </div>
                <div
                  style={{
                    display: 'flex',
                    gap: '8px',
                    marginBottom: '12px',
                  }}
                >
                  <TextInput
                    id="waf-leak-skip-mime-input"
                    labelText="New MIME type to bypass"
                    hideLabel
                    size="sm"
                    placeholder="e.g. image/* or application/pdf"
                    value={skipMimeInput}
                    onChange={(e) => setSkipMimeInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        handleAddMime('skip');
                      }
                    }}
                  />
                  <Button
                    kind="secondary"
                    size="sm"
                    renderIcon={Add}
                    onClick={() => handleAddMime('skip')}
                  >
                    Add
                  </Button>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {(leakConfig.skip_content_types || []).map((mime) => (
                    <Tag
                      key={mime}
                      type="cool-gray"
                      size="sm"
                      filter
                      onClose={() => handleRemoveMime('skip', mime)}
                    >
                      {mime}
                    </Tag>
                  ))}
                </div>
              </div>
            </div>
          </SectionCard>

          <SectionCard
            title="Detection category exceptions"
            description="Override default action for specific secret types."
          >
            {mode === 'block' ? (
              <p
                style={{
                  margin: 0,
                  fontSize: '0.875rem',
                  color: 'var(--cds-text-secondary)',
                }}
              >
                Block applies to every finding.
              </p>
            ) : mode === 'allow' ? (
              <p
                style={{
                  margin: 0,
                  fontSize: '0.875rem',
                  color: 'var(--cds-text-secondary)',
                }}
              >
                Select Monitor, Redact, or Block to use exceptions.
              </p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {LEAK_CATEGORY_GROUPS.map((group, idx) => {
                  const rulesObj = leakConfig.rules || {};
                  const configuredCount = group.items.filter((item) =>
                    Boolean(rulesObj[item.category])
                  ).length;
                  return (
                    <ControlRow
                      key={group.id}
                      title={group.title}
                      description={
                        configuredCount > 0
                          ? `${group.description} · ${configuredCount} override${
                              configuredCount === 1 ? '' : 's'
                            }`
                          : group.description
                      }
                      icon={Security}
                      noBorder={idx === LEAK_CATEGORY_GROUPS.length - 1}
                      action={
                        <Button
                          kind="ghost"
                          size="sm"
                          renderIcon={ChevronRight}
                          onClick={() => setSubPage(group.id)}
                        >
                          Configure
                        </Button>
                      }
                    />
                  );
                })}
              </div>
            )}
          </SectionCard>

          <SectionCard
            title="Custom detectors & Allowlist"
            description="Regex detectors and scoped suppression rules."
          >
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <ControlRow
                title="Custom detectors"
                description={`${(leakConfig.custom_patterns || []).length} configured`}
                icon={Code}
                action={
                  <Button
                    kind="ghost"
                    size="sm"
                    renderIcon={ChevronRight}
                    onClick={() => setSubPage('custom_detectors')}
                  >
                    Manage
                  </Button>
                }
              />
              <ControlRow
                title="Allowlist exceptions"
                description={`${(leakConfig.allowlist || []).length} configured`}
                icon={View}
                noBorder
                action={
                  <Button
                    kind="ghost"
                    size="sm"
                    renderIcon={ChevronRight}
                    onClick={() => setSubPage('allowlist')}
                  >
                    Manage
                  </Button>
                }
              />
            </div>
          </SectionCard>
        </>
      )}

      {selectedCategoryGroup && (
        <SectionCard
          title={selectedCategoryGroup.title}
          description="Choose the response for each detection category."
        >
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {selectedCategoryGroup.items.map((item, idx) => {
              const currentVal = (leakConfig.rules || {})[item.category] || '';
              return (
                <ControlRow
                  key={item.category}
                  title={item.title}
                  icon={Security}
                  noBorder={idx === selectedCategoryGroup.items.length - 1}
                  action={
                    <div style={{ minWidth: '220px' }}>
                      <Select
                        id={`waf-leak-cat-${item.category}`}
                        labelText="Leak category sensitivity action"
                        hideLabel
                        size="sm"
                        value={currentVal}
                        onChange={(e) =>
                          handleCategoryActionChange(
                            item.category,
                            e.target.value
                          )
                        }
                      >
                        <SelectItem value="" text="Use policy default" />
                        {ACTION_OPTIONS.map((opt) => (
                          <SelectItem
                            key={opt.value}
                            value={opt.value}
                            text={opt.label}
                          />
                        ))}
                      </Select>
                    </div>
                  }
                />
              );
            })}
          </div>
        </SectionCard>
      )}

      {subPage === 'custom_detectors' && (
        <SectionCard
          title="Custom detectors"
          description="Add narrowly scoped detectors when the built-in categories are not enough."
        >
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: '12px',
              alignItems: 'end',
              marginBottom: '20px',
            }}
          >
            <TextInput
              id="firewall-leak-pattern-name"
              labelText="Name"
              placeholder="e.g. Internal API key"
              size="sm"
              value={detectorName}
              onChange={(e) => setDetectorName(e.target.value)}
            />
            <TextInput
              id="firewall-leak-pattern-expression"
              labelText="Pattern (Regular expression)"
              placeholder="e.g. (?i)aegis_secret_[a-z0-9]{32}"
              size="sm"
              value={detectorPattern}
              onChange={(e) => setDetectorPattern(e.target.value)}
            />
            <TextInput
              id="firewall-leak-pattern-category"
              labelText="Category"
              placeholder="custom"
              size="sm"
              value={detectorCategory}
              onChange={(e) => setDetectorCategory(e.target.value)}
            />
            <Select
              id="firewall-leak-pattern-action"
              labelText="Response"
              size="sm"
              value={detectorAction}
              onChange={(e) => setDetectorAction(e.target.value)}
            >
              <SelectItem value="" text="Policy default" />
              <SelectItem value="detect" text="Monitor only" />
              <SelectItem value="redact" text="Redact matches" />
              <SelectItem value="block" text="Block responses" />
            </Select>
            <div>
              <Button
                kind="secondary"
                size="sm"
                renderIcon={Add}
                onClick={handleAddPattern}
              >
                Add detector
              </Button>
            </div>
          </div>

          {(leakConfig.custom_patterns || []).length === 0 ? (
            <p
              style={{
                margin: 0,
                fontSize: '0.875rem',
                color: 'var(--cds-text-secondary)',
              }}
            >
              No custom detectors are staged.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {(leakConfig.custom_patterns || []).map((pattern, idx) => (
                <ControlRow
                  key={pattern.id}
                  title={pattern.name || pattern.id}
                  description={`${pattern.category || 'custom'} · ${
                    pattern.action || 'policy default'
                  } · ${
                    pattern.enabled === false ? 'disabled' : 'enabled'
                  } · /${pattern.pattern}/`}
                  icon={Code}
                  noBorder={
                    idx === (leakConfig.custom_patterns || []).length - 1
                  }
                  action={
                    <Button
                      kind="ghost"
                      size="sm"
                      renderIcon={TrashCan}
                      onClick={() => handleRemovePattern(pattern.id)}
                    >
                      Remove
                    </Button>
                  }
                />
              ))}
            </div>
          )}
        </SectionCard>
      )}

      {subPage === 'allowlist' && (
        <SectionCard
          title="Allowlist exceptions"
          description="Suppress leak detection on specific hosts, paths, or content types."
        >
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
              gap: '12px',
              alignItems: 'end',
              marginBottom: '20px',
            }}
          >
            <TextInput
              id="firewall-leak-allowlist-host"
              labelText="Host"
              placeholder="Optional"
              size="sm"
              value={allowHost}
              onChange={(e) => setAllowHost(e.target.value)}
            />
            <TextInput
              id="firewall-leak-allowlist-path"
              labelText="Path"
              placeholder="e.g. /health"
              size="sm"
              value={allowPath}
              onChange={(e) => setAllowPath(e.target.value)}
            />
            <TextInput
              id="firewall-leak-allowlist-content-type"
              labelText="Content type"
              placeholder="Optional"
              size="sm"
              value={allowContentType}
              onChange={(e) => setAllowContentType(e.target.value)}
            />
            <TextInput
              id="firewall-leak-allowlist-category"
              labelText="Category"
              placeholder="Optional"
              size="sm"
              value={allowCategory}
              onChange={(e) => setAllowCategory(e.target.value)}
            />
            <TextInput
              id="firewall-leak-allowlist-reason"
              labelText="Reason"
              placeholder="Required"
              size="sm"
              value={allowReason}
              onChange={(e) => setAllowReason(e.target.value)}
            />
            <TextInput
              id="firewall-leak-allowlist-expires"
              type="date"
              labelText="Expires"
              size="sm"
              value={allowExpires}
              onChange={(e) => setAllowExpires(e.target.value)}
            />
            <div>
              <Button
                kind="secondary"
                size="sm"
                renderIcon={Add}
                onClick={handleAddAllowlist}
              >
                Add exception
              </Button>
            </div>
          </div>

          {(leakConfig.allowlist || []).length === 0 ? (
            <p
              style={{
                margin: 0,
                fontSize: '0.875rem',
                color: 'var(--cds-text-secondary)',
              }}
            >
              No allowlist exceptions are staged.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {(leakConfig.allowlist || []).map((entry, idx) => (
                <ControlRow
                  key={entry.id}
                  title={entry.reason || entry.id}
                  description={[
                    entry.category || 'any category',
                    entry.host || 'any host',
                    entry.path || 'any path',
                    entry.content_type || 'any content type',
                    entry.expires_at
                      ? `expires ${new Date(entry.expires_at).toLocaleDateString()}`
                      : null,
                  ]
                    .filter(Boolean)
                    .join(' · ')}
                  icon={View}
                  noBorder={idx === (leakConfig.allowlist || []).length - 1}
                  action={
                    <Button
                      kind="ghost"
                      size="sm"
                      renderIcon={TrashCan}
                      onClick={() => handleRemoveAllowlist(entry.id)}
                    >
                      Remove
                    </Button>
                  }
                />
              ))}
            </div>
          )}
        </SectionCard>
      )}

      <SaveActionBar
        isDirty={isDirty}
        isSaving={saving}
        onSave={handleSave}
        onReset={handleDiscard}
      />
    </div>
  );
};

export default WafLeakProtectionPage;
