import React, { useState, useEffect } from 'react';
import {
  Tile,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Button,
  Tag,
  Select,
  SelectItem,
  TextInput,
  InlineNotification,
  DataTableSkeleton,
  NumberInput,
  Slider,
  TileGroup,
  RadioTile,
  Layer,
} from '@carbon/react';
import { Add, Flash, ArrowLeft, Time, Misuse, Security, View } from '@carbon/icons-react';
import { PageHeader, SectionCard, StatusToggle, KpiCard, MetricStrip } from '../components/common';
import { apiService } from '../services/api';

export interface RateLimitRule {
  id: string;
  name?: string;
  pattern: string;
  match: 'glob' | 'prefix' | 'exact';
  priority: number;
  methods: string[];
  hosts: string[];
  rate: number;
  burst: number;
  window: string;
  action: 'block' | 'challenge' | 'dry_run';
  algorithm: 'token_bucket' | 'sliding_window' | 'fixed_window';
  key_by: 'ip' | 'ip_ua' | 'cookie' | 'token';
  bypass_static: boolean;
  dry_run: boolean;
  verified_grace_multiplier: number;
}

export const RateLimitingPage: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [config, setConfig] = useState<any>({
    enabled: true,
    default_rate: 60,
    default_burst: 20,
    window: '1m',
    algorithm: 'token_bucket',
    key_by: 'ip',
    action: 'block',
  });
  const [rules, setRules] = useState<RateLimitRule[]>([]);
  const [viewMode, setViewMode] = useState<'table' | 'editor'>('table');
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [notification, setNotification] = useState<{ kind: 'success' | 'error' | 'info'; message: string } | null>(null);

  const [formName, setFormName] = useState('');
  const [formPattern, setFormPattern] = useState('');
  const [formMatch, setFormMatch] = useState<'glob' | 'prefix' | 'exact'>('glob');
  const [formPriority, setFormPriority] = useState<number>(100);
  const [formMethods, setFormMethods] = useState('');
  const [formHosts, setFormHosts] = useState('');
  const [formRate, setFormRate] = useState<number>(60);
  const [formBurst, setFormBurst] = useState<number>(10);
  const [formWindow, setFormWindow] = useState('1m');
  const [formAction, setFormAction] = useState<'block' | 'challenge' | 'dry_run'>('block');
  const [formAlgorithm, setFormAlgorithm] = useState<'token_bucket' | 'sliding_window' | 'fixed_window'>('token_bucket');
  const [formKeyBy, setFormKeyBy] = useState<'ip' | 'ip_ua' | 'cookie' | 'token'>('ip');
  const [formBypassStatic, setFormBypassStatic] = useState(true);
  const [formGrace, setFormGrace] = useState<number>(2);

  const loadData = async () => {
    setLoading(true);
    try {
      const cfg = await apiService.getRateLimitConfig();
      setConfig(cfg);
      setRules(cfg.path_overrides || []);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load rate limiting config' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const openAddRule = () => {
    setEditingIndex(null);
    setFormName('');
    setFormPattern('');
    setFormMatch('glob');
    setFormPriority(100);
    setFormMethods('');
    setFormHosts('');
    setFormRate(60);
    setFormBurst(10);
    setFormWindow('1m');
    setFormAction('block');
    setFormAlgorithm('token_bucket');
    setFormKeyBy('ip');
    setFormBypassStatic(true);
    setFormGrace(2);
    setViewMode('editor');
  };

  const openEditRule = (idx: number) => {
    const r = rules[idx];
    if (!r) return;
    setEditingIndex(idx);
    setFormName(r.name || '');
    setFormPattern(r.pattern || '');
    setFormMatch(r.match || 'glob');
    setFormPriority(r.priority ?? 100);
    setFormMethods(Array.isArray(r.methods) ? r.methods.join(', ') : '');
    setFormHosts(Array.isArray(r.hosts) ? r.hosts.join(', ') : '');
    setFormRate(r.rate || 60);
    setFormBurst(r.burst || 10);
    setFormWindow(r.window || '1m');
    setFormAction(r.action || (r.dry_run ? 'dry_run' : 'block'));
    setFormAlgorithm(r.algorithm || 'token_bucket');
    setFormKeyBy(r.key_by || 'ip');
    setFormBypassStatic(r.bypass_static !== false);
    setFormGrace(r.verified_grace_multiplier || 2);
    setViewMode('editor');
  };

  const cancelEditor = () => {
    setViewMode('table');
    setEditingIndex(null);
  };

  const handleSaveRule = async () => {
    const pattern = formPattern.trim();
    if (!pattern.startsWith('/')) {
      setNotification({ kind: 'error', message: 'Target path pattern must start with "/" (e.g. /api/*).' });
      return;
    }
    if (!Number.isFinite(formRate) || formRate < 1) {
      setNotification({ kind: 'error', message: 'Request allowance must be at least 1.' });
      return;
    }
    if (!Number.isFinite(formBurst) || formBurst < 0) {
      setNotification({ kind: 'error', message: 'Burst headroom cannot be negative.' });
      return;
    }

    const splitValues = (str: string, norm: (s: string) => string) =>
      str.split(',').map((s) => norm(s.trim())).filter(Boolean);

    const isEdit = editingIndex !== null;
    const ruleId = isEdit && rules[editingIndex]?.id ? rules[editingIndex].id : `rule-${Date.now().toString(36)}`;

    const rulePayload: RateLimitRule = {
      id: ruleId,
      name: formName.trim() || undefined,
      pattern,
      match: formMatch,
      priority: Number(formPriority) || 100,
      methods: splitValues(formMethods, (s) => s.toUpperCase()),
      hosts: splitValues(formHosts, (s) => s.toLowerCase()),
      rate: Number(formRate),
      burst: Number(formBurst),
      window: formWindow,
      action: formAction,
      algorithm: formAlgorithm,
      key_by: formKeyBy,
      bypass_static: formBypassStatic,
      dry_run: formAction === 'dry_run',
      verified_grace_multiplier: Number(formGrace) || 2,
    };

    const nextRules = [...rules];
    if (isEdit && editingIndex !== null) {
      nextRules[editingIndex] = rulePayload;
    } else {
      nextRules.push(rulePayload);
    }

    const nextConfig = { ...config, path_overrides: nextRules };
    const ok = await apiService.saveRateLimitConfig(nextConfig);
    if (ok) {
      setConfig(nextConfig);
      setRules(nextRules);
      setViewMode('table');
      setEditingIndex(null);
      setNotification({
        kind: 'success',
        message: isEdit ? `Rate limit rule for ${pattern} updated.` : `Rate limit rule for ${pattern} created.`,
      });
    } else {
      setNotification({ kind: 'error', message: 'Failed to persist rate limit rule.' });
    }
  };

  const removeRule = async (idx: number) => {
    const targetRule = rules[idx];
    if (!targetRule) return;
    const nextRules = rules.filter((_, i) => i !== idx);
    const nextConfig = { ...config, path_overrides: nextRules };
    const ok = await apiService.saveRateLimitConfig(nextConfig);
    if (ok) {
      setConfig(nextConfig);
      setRules(nextRules);
      setNotification({ kind: 'info', message: `Rule for ${targetRule.pattern} removed.` });
    } else {
      setNotification({ kind: 'error', message: 'Failed to remove rate limit rule.' });
    }
  };

  const totalRules = rules.length;
  const blockCount = rules.filter((r) => r.action === 'block' || (!r.action && !r.dry_run)).length;
  const challengeCount = rules.filter((r) => r.action === 'challenge').length;
  const dryRunCount = rules.filter((r) => r.action === 'dry_run' || r.dry_run).length;

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      {viewMode === 'table' ? (
        <PageHeader
          title="Rate limiting"
          icon={Flash}
          action={
            <Button kind="primary" renderIcon={Add} onClick={openAddRule}>
              New rule
            </Button>
          }
        />
      ) : (
        <PageHeader
          title={editingIndex !== null ? 'Edit rule' : 'New rule'}
          icon={Flash}
          action={
            <div style={{ display: 'flex', gap: '8px' }}>
              <Button kind="secondary" onClick={cancelEditor}>
                Cancel
              </Button>
              <Button kind="primary" onClick={handleSaveRule}>
                {editingIndex !== null ? 'Update rule' : 'Save rule'}
              </Button>
            </div>
          }
        />
      )}

      {notification && (
        <div style={{ marginBottom: '20px' }}>
          <InlineNotification
            kind={notification.kind}
            subtitle={notification.message}
            onClose={() => setNotification(null)}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      {viewMode === 'table' ? (
        <>
          <MetricStrip minColWidth="180px">
            <KpiCard
              label="Engine Status"
              value={config?.enabled !== false ? 'Active' : 'Bypassed'}
              subtext={config?.enabled !== false ? 'Pure rule-driven' : 'Traffic throttling bypassed'}
              status={config?.enabled !== false ? 'success' : 'default'}
            />
            <KpiCard
              label="Active Rules"
              value={totalRules}
              subtext="Route-specific policies"
              status={totalRules > 0 ? 'info' : 'default'}
            />
            <KpiCard
              label="Enforcing Rules"
              value={blockCount + challengeCount}
              subtext={`${blockCount} block, ${challengeCount} challenge`}
              status={blockCount + challengeCount > 0 ? 'warning' : 'default'}
            />
            <KpiCard
              label="Dry Run Rules"
              value={dryRunCount}
              subtext="Evaluation without drop"
              status={dryRunCount > 0 ? 'info' : 'default'}
            />
          </MetricStrip>

          <Tile style={{ padding: 0 }}>
          {totalRules > 0 && (
            <div
              style={{
                padding: '14px 24px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                borderBottom: '1px solid var(--cds-border-subtle, #393939)',
                flexWrap: 'wrap',
                gap: '12px',
              }}
            >
              <div style={{ display: 'flex', gap: '16px', fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                <span>
                  <strong>{totalRules}</strong> {totalRules === 1 ? 'rule' : 'rules'}
                </span>
                {blockCount > 0 && (
                  <span>
                    <strong>{blockCount}</strong> block
                  </span>
                )}
                {challengeCount > 0 && (
                  <span>
                    <strong>{challengeCount}</strong> challenge
                  </span>
                )}
                {dryRunCount > 0 && (
                  <span>
                    <strong>{dryRunCount}</strong> dry run
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontSize: '12px', color: 'var(--cds-text-helper)' }}>
                  Evaluated in priority order.
                </span>
                <Button kind="primary" size="sm" renderIcon={Add} onClick={openAddRule}>
                  New rule
                </Button>
              </div>
            </div>
          )}

          {loading ? (
            <DataTableSkeleton columnCount={7} rowCount={6} showHeader={false} showToolbar={false} />
          ) : (
            <Table size="md" aria-label="Rate Limiting Policies">
              <TableHead>
                <TableRow>
                  <TableHeader>Target Route</TableHeader>
                  <TableHeader>Scope & Match</TableHeader>
                  <TableHeader>Rate & Burst</TableHeader>
                  <TableHeader>Mitigation</TableHeader>
                  <TableHeader>Engine Tuning</TableHeader>
                  <TableHeader>Priority</TableHeader>
                  <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
                </TableRow>
              </TableHead>
              <TableBody>
                {rules.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} style={{ textAlign: 'center', padding: '48px 16px' }}>
                      <Time size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
                      <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px' }}>
                        No rate limit rules defined
                      </div>
                      <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                        Add a rule to limit request rates for specific routes.
                      </div>
                      <Button kind="tertiary" size="sm" renderIcon={Add} onClick={openAddRule}>
                        New rule
                      </Button>
                    </TableCell>
                  </TableRow>
                ) : (
                  rules.map((rule, idx) => {
                    const matchType = (rule.match || 'glob').toUpperCase();
                    const actionTone = rule.action === 'challenge' ? 'purple' : rule.action === 'dry_run' || rule.dry_run ? 'blue' : 'red';
                    const actionLabel = rule.action === 'challenge' ? 'Smart Challenge' : rule.action === 'dry_run' || rule.dry_run ? 'Observe Only' : 'Strict Block (429)';
                    const algoLabel = rule.algorithm === 'sliding_window' ? 'Sliding Window' : rule.algorithm === 'fixed_window' ? 'Fixed Window' : 'Token Bucket';
                    const keyLabel = rule.key_by === 'ip_ua' ? 'IP+UA' : rule.key_by === 'cookie' ? 'Cookie' : rule.key_by === 'token' ? 'Token' : 'IP';

                    return (
                      <TableRow key={rule.id || idx}>
                        <TableCell>
                          <div style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontWeight: 700, fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                            {rule.pattern}
                          </div>
                          {rule.name && (
                            <div style={{ fontSize: '11px', color: 'var(--cds-text-helper)', marginTop: '2px' }}>
                              {rule.name}
                            </div>
                          )}
                        </TableCell>
                        <TableCell>
                          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', alignItems: 'center' }}>
                            <Tag type="cool-gray" size="sm">
                              {matchType}
                            </Tag>
                            {Array.isArray(rule.methods) && rule.methods.length > 0 ? (
                              rule.methods.map((m) => (
                                <Tag key={m} type="cool-gray" size="sm">
                                  {m}
                                </Tag>
                              ))
                            ) : (
                              <Tag type="cool-gray" size="sm">
                                ALL
                              </Tag>
                            )}
                          </div>
                          {Array.isArray(rule.hosts) && rule.hosts.length > 0 && (
                            <div style={{ fontSize: '11px', color: 'var(--cds-text-helper)', marginTop: '2px', fontFamily: 'monospace' }}>
                              {rule.hosts.join(', ')}
                            </div>
                          )}
                        </TableCell>
                        <TableCell>
                          <div>
                            <strong style={{ fontFamily: 'monospace', fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                              {rule.rate}
                            </strong>{' '}
                            <span style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>
                              req / {rule.window || '1m'}
                            </span>
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--cds-text-helper)', fontFamily: 'monospace' }}>
                            +{rule.burst} burst req
                          </div>
                        </TableCell>
                        <TableCell>
                          <Tag type={actionTone as any} size="sm">
                            {actionLabel}
                          </Tag>
                        </TableCell>
                        <TableCell>
                          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                            {algoLabel}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--cds-text-helper)', fontFamily: 'monospace' }}>
                            Key: {keyLabel}
                            {rule.bypass_static ? ' • No Static' : ''}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Tag type="cool-gray" size="sm">
                            #{rule.priority ?? 100}
                          </Tag>
                        </TableCell>
                        <TableCell style={{ textAlign: 'right' }}>
                          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '4px' }}>
                            <Button kind="ghost" size="sm" onClick={() => openEditRule(idx)}>
                              Edit
                            </Button>
                            <Button kind="danger--ghost" size="sm" onClick={() => removeRule(idx)}>
                              Delete
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          )}
        </Tile>
        </>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <Button kind="ghost" size="sm" renderIcon={ArrowLeft} onClick={cancelEditor}>
              Back to rules
            </Button>
          </div>

          <SectionCard title="Route & match">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '16px' }}>
              <TextInput
                id="rl-rule-name"
                labelText="Rule name (optional)"
                placeholder="e.g. Login rate limit"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
              />
              <TextInput
                id="rl-rule-pattern"
                labelText="Path pattern"
                placeholder="/api/v1/auth/*"
                value={formPattern}
                onChange={(e) => setFormPattern(e.target.value)}
                style={{ fontFamily: 'var(--cds-font-family-mono, monospace)' }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '16px' }}>
              <Select
                id="rl-rule-match"
                labelText="Match type"
                value={formMatch}
                onChange={(e) => setFormMatch(e.target.value as any)}
              >
                <SelectItem value="glob" text="Glob (*)" />
                <SelectItem value="prefix" text="Prefix" />
                <SelectItem value="exact" text="Exact" />
              </Select>
              <NumberInput
                id="rl-rule-priority"
                label="Priority"
                helperText="Lower numbers evaluate first"
                placeholder="100"
                value={formPriority}
                onChange={(_e, { value }) => setFormPriority(Number(value) || 100)}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
              <TextInput
                id="rl-rule-methods"
                labelText="HTTP methods"
                placeholder="POST, PUT (blank for all)"
                value={formMethods}
                onChange={(e) => setFormMethods(e.target.value)}
                style={{ fontFamily: 'var(--cds-font-family-mono, monospace)' }}
              />
              <TextInput
                id="rl-rule-hosts"
                labelText="Hosts (optional)"
                placeholder="api.example.com (blank for all)"
                value={formHosts}
                onChange={(e) => setFormHosts(e.target.value)}
                style={{ fontFamily: 'var(--cds-font-family-mono, monospace)' }}
              />
            </div>
          </SectionCard>

          <SectionCard title="Rate & burst">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '24px' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>Request rate</strong>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <NumberInput
                      id="form-rate-input"
                      min={1}
                      max={100000}
                      step={10}
                      value={formRate}
                      onChange={(_e, { value }) => setFormRate(Number(value) || 1)}
                      hideLabel
                      label="Request rate"
                      size="sm"
                      style={{ width: '120px' }}
                    />
                    <Select
                      id="form-window-select"
                      value={formWindow}
                      onChange={(e) => setFormWindow(e.target.value)}
                      hideLabel
                      labelText="Window"
                      size="sm"
                      inline
                      style={{ minWidth: '90px' }}
                    >
                      <SelectItem value="1s" text="/ sec" />
                      <SelectItem value="1m" text="/ min" />
                      <SelectItem value="1h" text="/ hr" />
                    </Select>
                  </div>
                </div>
                <Slider
                  id="form-rate-slider"
                  min={1}
                  max={5000}
                  step={10}
                  value={Math.min(formRate, 5000)}
                  onChange={({ value }) => setFormRate(value)}
                  hideTextInput
                  labelText="Request rate slider"
                  hideLabel
                />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>Burst capacity</strong>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <NumberInput
                      id="form-burst-input"
                      min={0}
                      max={5000}
                      step={5}
                      value={formBurst}
                      onChange={(_e, { value }) => setFormBurst(Number(value) || 0)}
                      hideLabel
                      label="Burst capacity"
                      size="sm"
                      style={{ width: '120px' }}
                    />
                    <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>requests</span>
                  </div>
                </div>
                <Slider
                  id="form-burst-slider"
                  min={0}
                  max={1000}
                  step={5}
                  value={Math.min(formBurst, 1000)}
                  onChange={({ value }) => setFormBurst(value)}
                  hideTextInput
                  labelText="Burst capacity slider"
                  hideLabel
                />
              </div>
            </div>
          </SectionCard>

          <SectionCard title="Action & tuning">
            <div style={{ marginBottom: '20px' }}>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cds-text-primary)', marginBottom: '10px' }}>
                Action
              </div>
              <TileGroup
                name="rl-form-action"
                legend=""
                valueSelected={formAction}
                onChange={(val) => setFormAction(val as 'block' | 'challenge' | 'dry_run')}
                style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}
              >
                <RadioTile id="rl-act-block" value="block">
                  <div style={{ padding: '0.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <Misuse size={18} style={{ color: 'var(--cds-support-error, #da1e28)', flexShrink: 0 }} />
                      <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                        Block (429)
                      </strong>
                    </div>
                    <small style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', display: 'block' }}>
                      Drop requests with HTTP 429.
                    </small>
                  </div>
                </RadioTile>

                <RadioTile id="rl-act-challenge" value="challenge">
                  <div style={{ padding: '0.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <Security size={18} style={{ color: 'var(--cds-support-warning, #f1c21b)', flexShrink: 0 }} />
                      <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                        Challenge
                      </strong>
                    </div>
                    <small style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', display: 'block' }}>
                      Require verification challenge.
                    </small>
                  </div>
                </RadioTile>

                <RadioTile id="rl-act-dryrun" value="dry_run">
                  <div style={{ padding: '0.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <View size={18} style={{ color: 'var(--cds-support-info, #4589ff)', flexShrink: 0 }} />
                      <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                        Observe (dry run)
                      </strong>
                    </div>
                    <small style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', display: 'block' }}>
                      Log violations without blocking.
                    </small>
                  </div>
                </RadioTile>
              </TileGroup>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '16px' }}>
              <Select
                id="rl-rule-algorithm"
                labelText="Algorithm"
                value={formAlgorithm}
                onChange={(e) => setFormAlgorithm(e.target.value as any)}
              >
                <SelectItem value="token_bucket" text="Token bucket" />
                <SelectItem value="sliding_window" text="Sliding window" />
                <SelectItem value="fixed_window" text="Fixed window" />
              </Select>
              <Select
                id="rl-rule-key-by"
                labelText="Client key"
                value={formKeyBy}
                onChange={(e) => setFormKeyBy(e.target.value as any)}
              >
                <SelectItem value="ip" text="IP address" />
                <SelectItem value="ip_ua" text="IP + User-Agent" />
                <SelectItem value="cookie" text="Session cookie (session_id)" />
                <SelectItem value="token" text="Bearer token" />
              </Select>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', alignItems: 'center' }}>
              <StatusToggle
                id="rl-rule-bypass-static"
                label="Bypass static assets"
                description="Exclude images, CSS, and JS from rate limits."
                toggled={formBypassStatic}
                onToggle={(val) => setFormBypassStatic(val)}
              />

              <Layer>
                <Tile
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '14px 16px',
                  }}
                >
                  <div>
                    <strong style={{ fontSize: '13px', display: 'block', color: 'var(--cds-text-primary)' }}>
                      Verified client grace
                    </strong>
                    <span style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>
                      Multiplier for verified bots and authenticated users.
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <NumberInput
                      id="form-grace-input"
                      min={1}
                      max={5}
                      step={0.5}
                      value={formGrace}
                      onChange={(_e, { value }) => setFormGrace(Number(value) || 1)}
                      hideLabel
                      label="Verified client grace"
                      size="sm"
                      style={{ width: '100px' }}
                    />
                    <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>&times; rate</span>
                  </div>
                </Tile>
              </Layer>
            </div>
          </SectionCard>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '8px' }}>
            <Button kind="secondary" onClick={cancelEditor}>
              Cancel
            </Button>
            <Button kind="primary" onClick={handleSaveRule}>
              {editingIndex !== null ? 'Update rule' : 'Save rule'}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};

export default RateLimitingPage;
