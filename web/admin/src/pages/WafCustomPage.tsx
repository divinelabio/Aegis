import React, { useEffect, useState, useMemo } from 'react';
import {
  DataTable,
  TableContainer,
  TableToolbar,
  TableToolbarContent,
  TableToolbarSearch,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Button,
  Tag,
  Toggle,
  Modal,
  TextInput,
  Select,
  SelectItem,
  NumberInput,
  Checkbox,
  InlineNotification,
  DataTableSkeleton,
  Tile,
  CodeSnippet,
  Breadcrumb,
  BreadcrumbItem,
} from '@carbon/react';
import {
  Add,
  TrashCan,
  Renew,
  Edit,
  Security,
  ArrowLeft,
  Checkmark,
  CheckmarkOutline,
  Code,
  Filter,
} from '@carbon/icons-react';
import type { WAFCustomRule, WAFRuleTarget } from '../types';
import { apiService } from '../services/api';
import { PageHeader, SectionCard, MetricStrip, KpiCard } from '../components/common';

const TRANSFORM_OPTIONS = [
  'lowercase',
  'url_decode',
  'html_entity_decode',
  'base64_decode',
  'hex_decode',
  'remove_comments',
  'remove_whitespace',
  'compress_whitespace',
  'normalize_path',
];

interface ConditionDraft {
  zone: string;
  operator: string;
  field: string;
  pattern: string;
  negate: boolean;
  transforms: string[];
}

export function formatRuleExpression(rule: WAFCustomRule): string {
  if (rule.targets && rule.targets.length > 0) {
    const parts = rule.targets.map((target) => {
      const zone = target.field ? `${target.zone}:${target.field}` : target.zone;
      const op = target.operator || '@rx';
      const patterns =
        target.patterns && target.patterns.length > 0
          ? target.patterns.map((p) => `"${p}"`).join(', ')
          : '""';
      return `${target.negate ? 'NOT ' : ''}${zone} ${op} ${patterns}`.trim();
    });
    return parts.join(' | ');
  }
  return rule.message || 'No expression';
}

export function generateRulePreview(
  id: string,
  message: string,
  score: number,
  conditions: ConditionDraft[]
): string {
  const validConditions = conditions.filter((c) => c.pattern.trim().length > 0);
  if (validConditions.length === 0) {
    return '# Add conditions above with a match pattern to preview this rule';
  }

  const operatorLabels: Record<string, string> = {
    '@rx': 'matches regex',
    '@streq': 'equals',
    '@contains': 'contains',
    '@ipMatch': 'matches IP/CIDR',
  };

  const lines = validConditions.map((condition, index) => {
    let zoneName = condition.zone.toUpperCase();
    if (zoneName === 'HEADERS') zoneName = 'REQUEST_HEADERS';
    else if (zoneName === 'BODY') zoneName = 'REQUEST_BODY';
    else if (zoneName === 'URI') zoneName = 'REQUEST_URI';
    else if (zoneName === 'PATH') zoneName = 'URL_PATH';
    else if (zoneName === 'METHOD') zoneName = 'REQUEST_METHOD';
    else if (zoneName === 'CLIENT_IP') zoneName = 'REMOTE_ADDR';
    else if (zoneName === 'ARGS') zoneName = 'ARGS';
    else if (zoneName === 'COOKIES') zoneName = 'REQUEST_COOKIES';

    if (condition.field.trim()) {
      zoneName += `:${condition.field.trim()}`;
    }

    const transformText =
      condition.transforms.length > 0 ? ` after ${condition.transforms.join(' → ')}` : '';

    return `${index + 1}. ${condition.negate ? 'NOT ' : ''}${zoneName} ${
      operatorLabels[condition.operator] || condition.operator
    } ${JSON.stringify(condition.pattern)}${transformText}`;
  });

  return [
    `Rule ${id || '100001'}: ${message || 'Custom Rule'}`,
    'Evaluation: match when ANY condition below succeeds.',
    ...lines,
    `On match: add ${score} to the request anomaly score.`,
  ].join('\n');
}

export const WafCustomPage: React.FC = () => {
  const [viewMode, setViewMode] = useState<'list' | 'editor'>('list');

  const [rules, setRules] = useState<WAFCustomRule[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<
    'all' | 'critical' | 'high' | 'medium' | 'low' | 'active' | 'inactive'
  >('all');
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState<boolean>(false);
  const [ruleToDelete, setRuleToDelete] = useState<WAFCustomRule | null>(null);

  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [editingValid, setEditingValid] = useState<boolean>(true);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [formId, setFormId] = useState<string>('');
  const [formName, setFormName] = useState<string>('');
  const [formSeverity, setFormSeverity] = useState<string>('medium');
  const [formMessage, setFormMessage] = useState<string>('');
  const [formScore, setFormScore] = useState<number>(25);
  const [formTags, setFormTags] = useState<string>('custom, local');
  const [conditions, setConditions] = useState<ConditionDraft[]>([]);

  const loadData = async () => {
    setLoading(true);
    try {
      const customRules = await apiService.getCustomRules();
      const normalized = (customRules || []).map((r, idx) => ({
        ...r,
        id: r.id ? String(r.id) : `10000${idx + 1}`,
      }));
      setRules(normalized);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load custom rules' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleOpenCreate = () => {
    const existingIds = rules
      .map((r) => Number.parseInt(r.id, 10))
      .filter((n) => Number.isFinite(n) && n >= 100000);
    const nextId = existingIds.length > 0 ? String(Math.max(...existingIds) + 1) : '100001';

    setEditingRuleId(null);
    setEditingValid(true);
    setValidationErrors([]);
    setFormId(nextId);
    setFormName('');
    setFormSeverity('medium');
    setFormMessage('');
    setFormScore(25);
    setFormTags('custom, local');
    setConditions([
      {
        zone: 'headers',
        operator: '@rx',
        field: 'User-Agent',
        pattern: '',
        negate: false,
        transforms: [],
      },
    ]);
    setViewMode('editor');
  };

  const handleOpenEdit = async (ruleId: string) => {
    setLoading(true);
    try {
      const detail = await apiService.getCustomRule(ruleId);
      const rule = detail?.rule || rules.find((r) => r.id === ruleId);
      if (!rule) {
        setNotification({ kind: 'error', message: 'Unable to load rule definition' });
        return;
      }

      setEditingRuleId(rule.id);
      setEditingValid(detail?.valid ?? (rule.valid !== false));
      setValidationErrors(detail?.validation_errors || rule.validation_errors || []);
      setFormId(rule.id);
      setFormName(rule.name || '');
      setFormSeverity(rule.severity || 'medium');
      setFormMessage(rule.message || '');
      setFormScore(Number(rule.score) || 25);
      setFormTags((rule.tags || ['custom', 'local']).join(', '));

      if (rule.targets && rule.targets.length > 0) {
        const rows: ConditionDraft[] = [];
        rule.targets.forEach((t) => {
          const patterns = t.patterns && t.patterns.length > 0 ? t.patterns : [''];
          patterns.forEach((p) => {
            rows.push({
              zone: t.zone || 'headers',
              operator: t.operator || '@rx',
              field: t.field || '',
              pattern: p,
              negate: t.negate || false,
              transforms: Array.isArray(t.transforms) ? [...t.transforms] : [],
            });
          });
        });
        setConditions(rows);
      } else {
        setConditions([
          {
            zone: 'headers',
            operator: '@rx',
            field: '',
            pattern: '',
            negate: false,
            transforms: [],
          },
        ]);
      }

      setViewMode('editor');
    } catch {
      setNotification({ kind: 'error', message: 'Failed to open rule editor' });
    } finally {
      setLoading(false);
    }
  };

  const handleAddCondition = () => {
    setConditions((prev) => [
      ...prev,
      {
        zone: 'headers',
        operator: '@rx',
        field: '',
        pattern: '',
        negate: false,
        transforms: [],
      },
    ]);
  };

  const handleRemoveCondition = (index: number) => {
    setConditions((prev) => prev.filter((_, i) => i !== index));
  };

  const handleUpdateCondition = (index: number, updates: Partial<ConditionDraft>) => {
    setConditions((prev) =>
      prev.map((c, i) => (i === index ? { ...c, ...updates } : c))
    );
  };

  const handleToggleTransform = (index: number, transform: string) => {
    setConditions((prev) =>
      prev.map((c, i) => {
        if (i !== index) return c;
        const exists = c.transforms.includes(transform);
        const next = exists
          ? c.transforms.filter((t) => t !== transform)
          : [...c.transforms, transform];
        return { ...c, transforms: next };
      })
    );
  };

  const handleSaveRule = async () => {
    const id = formId.trim();
    const name = formName.trim();
    const score = Number(formScore);

    if (!id || !name) {
      setNotification({ kind: 'error', message: 'Rule ID and name are required' });
      return;
    }
    if (!Number.isFinite(score) || score < 1 || score > 1000) {
      setNotification({ kind: 'error', message: 'Anomaly score must be between 1 and 1000' });
      return;
    }

    const validConditions = conditions.filter((c) => c.pattern.trim().length > 0);
    if (validConditions.length === 0) {
      setNotification({ kind: 'error', message: 'At least one condition with a pattern is required' });
      return;
    }

    const targets: WAFRuleTarget[] = validConditions.map((c) => ({
      zone: c.zone,
      operator: c.operator || '@rx',
      field: ['headers', 'args', 'cookies'].includes(c.zone) && c.field.trim() ? c.field.trim() : undefined,
      patterns: [c.pattern.trim()],
      negate: c.negate || false,
      transforms: c.transforms.length > 0 ? c.transforms : undefined,
    }));

    const tags = formTags
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);

    const isEdit = !!editingRuleId;
    const payload: WAFCustomRule = {
      schema_version: 1,
      id,
      name,
      message: formMessage.trim() || name,
      severity: formSeverity,
      score,
      enabled: isEdit ? rules.find((r) => r.id === id)?.enabled !== false : true,
      tags: tags.length > 0 ? tags : ['custom', 'local'],
      targets,
      valid: true,
    };

    setSaving(true);
    const res = await apiService.saveCustomRule(payload, isEdit);
    setSaving(false);

    if (res.success) {
      setNotification({
        kind: 'success',
        message: isEdit ? `Rule "${name}" updated successfully` : `Rule "${name}" created successfully`,
      });
      setViewMode('list');
      await loadData();
    } else {
      setNotification({
        kind: 'error',
        message: res.error || `Failed to ${isEdit ? 'update' : 'create'} rule`,
      });
    }
  };

  const handleToggleRule = async (rule: WAFCustomRule, enabled: boolean) => {
    const prevRules = [...rules];
    setRules((prev) => prev.map((r) => (r.id === rule.id ? { ...r, enabled } : r)));

    const res = await apiService.toggleCustomRule(rule.id, enabled);
    if (res.success) {
      setNotification({
        kind: 'success',
        message: `Rule "${rule.name || rule.id}" ${enabled ? 'enabled' : 'disabled'}`,
      });
    } else {
      setRules(prevRules);
      setNotification({
        kind: 'error',
        message: res.error || `Failed to update status for rule "${rule.name || rule.id}"`,
      });
    }
  };

  const openDeleteConfirm = (rule: WAFCustomRule) => {
    setRuleToDelete(rule);
    setDeleteConfirmOpen(true);
  };

  const handleDeleteRule = async () => {
    if (!ruleToDelete) return;
    const res = await apiService.deleteCustomRule(ruleToDelete.id);
    if (res.success) {
      setRules((prev) => prev.filter((r) => r.id !== ruleToDelete.id));
      setNotification({
        kind: 'success',
        message: `Rule "${ruleToDelete.name || ruleToDelete.id}" deleted successfully`,
      });
    } else {
      setNotification({
        kind: 'error',
        message: res.error || `Failed to delete rule "${ruleToDelete.name || ruleToDelete.id}"`,
      });
    }
    setDeleteConfirmOpen(false);
    setRuleToDelete(null);
  };

  const getSeverityBadge = (severity?: string) => {
    switch ((severity || '').toLowerCase()) {
      case 'critical':
        return <Tag type="red" size="sm">Critical</Tag>;
      case 'high':
        return <Tag type="warm-gray" size="sm">High</Tag>;
      case 'low':
        return <Tag type="cool-gray" size="sm">Low</Tag>;
      case 'medium':
      default:
        return <Tag type="cyan" size="sm">Medium</Tag>;
    }
  };

  const getPatternPlaceholder = (zone: string, op: string) => {
    if (op === '@ipMatch' || zone === 'client_ip') {
      return 'IP or CIDR (e.g. 192.168.1.0/24)';
    }
    if (op === '@streq') {
      return 'Exact string match';
    }
    if (op === '@contains') {
      return 'Substring to match';
    }
    return 'Regex pattern (e.g. (?i)badbot)';
  };

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      const isEnabled = r.enabled !== false;
      const severity = (r.severity || 'medium').toLowerCase();

      if (severityFilter === 'active' && !isEnabled) return false;
      if (severityFilter === 'inactive' && isEnabled) return false;
      if (
        (severityFilter === 'critical' ||
          severityFilter === 'high' ||
          severityFilter === 'medium' ||
          severityFilter === 'low') &&
        severity !== severityFilter
      ) {
        return false;
      }

      const q = searchQuery.trim().toLowerCase();
      if (!q) return true;

      if ((r.name || '').toLowerCase().includes(q)) return true;
      if ((r.id || '').toLowerCase().includes(q)) return true;
      if ((r.message || '').toLowerCase().includes(q)) return true;
      if ((r.severity || '').toLowerCase().includes(q)) return true;
      if (String(r.score ?? '').includes(q)) return true;

      if (Array.isArray(r.tags) && r.tags.some((t) => (t || '').toLowerCase().includes(q))) return true;

      if (Array.isArray(r.targets)) {
        for (const target of r.targets) {
          if ((target.zone || '').toLowerCase().includes(q)) return true;
          if ((target.field || '').toLowerCase().includes(q)) return true;
          if ((target.operator || '').toLowerCase().includes(q)) return true;
          if (Array.isArray(target.patterns) && target.patterns.some((p) => (p || '').toLowerCase().includes(q))) return true;
          if (Array.isArray(target.transforms) && target.transforms.some((tx) => (tx || '').toLowerCase().includes(q))) return true;
        }
      }

      const expr = formatRuleExpression(r).toLowerCase();
      if (expr.includes(q)) return true;

      return false;
    });
  }, [rules, searchQuery, severityFilter]);

  const activeCount = rules.filter((r) => r.enabled !== false).length;
  const inactiveCount = rules.length - activeCount;
  const highSeverityCount = rules.filter((r) => {
    const sev = (r.severity || '').toLowerCase();
    return sev === 'critical' || sev === 'high';
  }).length;

  const headers = [
    { key: 'name', header: 'Rule name & ID' },
    { key: 'expression', header: 'Target expression' },
    { key: 'severity', header: 'Severity' },
    { key: 'score', header: 'Score' },
    { key: 'status', header: 'Status' },
    { key: 'actions', header: 'Actions' },
  ];

  const rulesMap = useMemo(() => {
    const map = new Map<string, WAFCustomRule>();
    rules.forEach((r) => {
      map.set(r.id, r);
    });
    return map;
  }, [rules]);

  const tableRows = useMemo(() => {
    return filteredRules.map((r) => ({
      id: r.id,
      name: r.name,
      expression: formatRuleExpression(r),
      severity: r.severity || 'medium',
      score: r.score ?? '-',
      enabled: r.enabled !== false,
    }));
  }, [filteredRules]);

  const previewText = useMemo(() => {
    return generateRulePreview(formId, formMessage || formName, formScore, conditions);
  }, [formId, formMessage, formName, formScore, conditions]);

  if (viewMode === 'editor') {
    const isEdit = !!editingRuleId;

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px', width: '100%', boxSizing: 'border-box' }}>
        <Breadcrumb noTrailingSlash style={{ marginBottom: '-8px' }}>
          <BreadcrumbItem
            href="#waf-custom"
            onClick={(e: any) => {
              e.preventDefault();
              setViewMode('list');
            }}
          >
            Custom rules
          </BreadcrumbItem>
          <BreadcrumbItem isCurrentPage>
            {isEdit ? 'Edit rule' : 'Create rule'}
          </BreadcrumbItem>
        </Breadcrumb>

        <PageHeader
          kicker="Application firewall"
          title={isEdit ? 'Edit custom rule' : 'Create custom rule'}
          icon={Security}
          action={
            <div style={{ display: 'flex', gap: '8px' }}>
              <Button
                kind="ghost"
                size="md"
                renderIcon={ArrowLeft}
                onClick={() => setViewMode('list')}
              >
                Back to rules
              </Button>
            </div>
          }
        />

        {notification && (
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        )}

        <SectionCard
          title="Rule identity"
        >
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: '16px',
              marginBottom: '16px',
            }}
          >
            <TextInput
              id="cr-id"
              labelText="Rule ID"
              placeholder="100001"
              value={formId}
              readOnly={isEdit}
              onChange={(e) => setFormId(e.target.value)}
              helperText={isEdit ? 'Rule ID is immutable once saved' : undefined}
              required
            />
            <TextInput
              id="cr-name"
              labelText="Rule name"
              placeholder="e.g. Block malicious user agents"
              value={formName}
              onChange={(e) => setFormName(e.target.value)}
              required
            />
            <Select
              id="cr-sev"
              labelText="Severity"
              value={formSeverity}
              onChange={(e) => setFormSeverity(e.target.value)}
            >
              <SelectItem value="critical" text="Critical" />
              <SelectItem value="high" text="High" />
              <SelectItem value="medium" text="Medium" />
              <SelectItem value="low" text="Low" />
            </Select>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: '16px',
              marginBottom: '20px',
            }}
          >
            <TextInput
              id="cr-msg"
              labelText="Log message"
              placeholder="e.g. Malicious User Agent Detected"
              value={formMessage}
              onChange={(e) => setFormMessage(e.target.value)}
            />
            <NumberInput
              id="cr-score"
              label="Anomaly score"
              min={1}
              max={1000}
              step={5}
              value={formScore}
              onChange={(_e: any, { value }: any) => setFormScore(Number(value) || 25)}
              helperText="Points added to anomaly score on match (1–1000)"
            />
            <TextInput
              id="cr-tags"
              labelText="Tags"
              placeholder="custom, account-protection"
              value={formTags}
              onChange={(e) => setFormTags(e.target.value)}
            />
          </div>

          {!editingValid && (
            <div style={{ marginTop: '16px' }}>
              <InlineNotification
                kind="warning"
                title="This stored rule is inactive until repaired"
                subtitle={validationErrors.length > 0 ? validationErrors.join('; ') : 'Invalid rule definition'}
              />
            </div>
          )}
        </SectionCard>

        <SectionCard
          title="Match conditions"
          description="Evaluates when any condition matches (OR logic)."
          action={
            <Button
              kind="tertiary"
              size="sm"
              renderIcon={Add}
              onClick={handleAddCondition}
            >
              Add condition
            </Button>
          }
        >
          {conditions.length === 0 ? (
            <div
              style={{
                textAlign: 'center',
                padding: '36px 16px',
                border: '1px dashed var(--cds-border-subtle)',
                color: 'var(--cds-text-secondary)',
                fontSize: '13px',
              }}
            >
              Add a condition to define what this rule should match.
              <div style={{ marginTop: '12px' }}>
                <Button kind="tertiary" size="sm" renderIcon={Add} onClick={handleAddCondition}>
                  Add condition
                </Button>
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {conditions.map((cond, idx) => {
                const needsField = ['headers', 'args', 'cookies'].includes(cond.zone);

                return (
                  <Tile
                    key={idx}
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      borderRadius: 0,
                      padding: '20px',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        marginBottom: '16px',
                        borderBottom: '1px solid var(--cds-border-subtle)',
                        paddingBottom: '12px',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                          Condition {idx + 1}
                        </span>
                        {cond.negate && <Tag type="red" size="sm">NOT</Tag>}
                      </div>
                      {conditions.length > 1 && (
                        <Button
                          kind="ghost"
                          size="sm"
                          hasIconOnly
                          renderIcon={TrashCan}
                          iconDescription="Remove condition"
                          onClick={() => handleRemoveCondition(idx)}
                        />
                      )}
                    </div>

                    <div
                      style={{
                        display: 'grid',
                        gridTemplateColumns: needsField
                          ? 'repeat(auto-fit, minmax(200px, 1fr))'
                          : 'repeat(auto-fit, minmax(220px, 1fr))',
                        gap: '16px',
                        alignItems: 'flex-start',
                        marginBottom: '16px',
                      }}
                    >
                      <Select
                        id={`cond-zone-${idx}`}
                        labelText="Zone"
                        value={cond.zone}
                        onChange={(e) => handleUpdateCondition(idx, { zone: e.target.value })}
                      >
                        <SelectItem value="headers" text="Headers" />
                        <SelectItem value="args" text="Query params" />
                        <SelectItem value="cookies" text="Cookies" />
                        <SelectItem value="body" text="Request body" />
                        <SelectItem value="uri" text="Request URI" />
                        <SelectItem value="path" text="URL path" />
                        <SelectItem value="method" text="Method" />
                        <SelectItem value="client_ip" text="Client IP" />
                      </Select>

                      {needsField && (
                        <TextInput
                          id={`cond-field-${idx}`}
                          labelText="Field name"
                          placeholder={
                            cond.zone === 'headers'
                              ? 'e.g. User-Agent'
                              : cond.zone === 'cookies'
                              ? 'e.g. session_id'
                              : 'e.g. query_param'
                          }
                          value={cond.field}
                          onChange={(e) => handleUpdateCondition(idx, { field: e.target.value })}
                        />
                      )}

                      <Select
                        id={`cond-op-${idx}`}
                        labelText="Operator"
                        value={cond.operator}
                        onChange={(e) => handleUpdateCondition(idx, { operator: e.target.value })}
                      >
                        <SelectItem value="@rx" text="Regex (@rx)" />
                        <SelectItem value="@streq" text="Equals (@streq)" />
                        <SelectItem value="@contains" text="Contains (@contains)" />
                        <SelectItem value="@ipMatch" text="IP Match (@ipMatch)" />
                      </Select>

                      <TextInput
                        id={`cond-pattern-${idx}`}
                        labelText="Pattern"
                        placeholder={getPatternPlaceholder(cond.zone, cond.operator)}
                        value={cond.pattern}
                        onChange={(e) => handleUpdateCondition(idx, { pattern: e.target.value })}
                        required
                      />
                    </div>

                    <div style={{ marginBottom: '16px' }}>
                      <Checkbox
                        id={`cond-negate-${idx}`}
                        labelText="Negate match (invert condition to NOT)"
                        checked={cond.negate}
                        onChange={(_e, { checked }) => handleUpdateCondition(idx, { negate: checked })}
                      />
                    </div>

                    <div>
                      <div
                        style={{
                          fontSize: '12px',
                          fontWeight: 600,
                          color: 'var(--cds-text-secondary)',
                          marginBottom: '8px',
                        }}
                      >
                        Transforms
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                        {TRANSFORM_OPTIONS.map((tx) => {
                          const isActive = cond.transforms.includes(tx);
                          return (
                            <Tag
                              key={tx}
                              type={isActive ? 'blue' : 'cool-gray'}
                              size="md"
                              style={{ cursor: 'pointer', userSelect: 'none', margin: 0 }}
                              onClick={() => handleToggleTransform(idx, tx)}
                            >
                              {isActive ? '✓ ' : ''}{tx.replace(/_/g, ' ')}
                            </Tag>
                          );
                        })}
                      </div>
                    </div>
                  </Tile>
                );
              })}
            </div>
          )}
        </SectionCard>

        <SectionCard
          title="Rule preview"
          description="Generated evaluation syntax for engine inspection and debugging."
        >
          <CodeSnippet type="multi" feedback="Copied to clipboard">
            {previewText}
          </CodeSnippet>
        </SectionCard>

        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '12px',
            paddingTop: '20px',
            borderTop: '1px solid var(--cds-border-subtle)',
          }}
        >
          <Button
            kind="secondary"
            size="md"
            onClick={() => setViewMode('list')}
            disabled={saving}
          >
            Cancel
          </Button>
          <Button
            kind="primary"
            size="md"
            renderIcon={Checkmark}
            onClick={handleSaveRule}
            disabled={saving}
          >
            {isEdit ? 'Save changes' : 'Create rule'}
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: '32px' }}>
      <PageHeader
        kicker="Application firewall"
        title="Custom rules"
        icon={Security}
        action={
          <Button kind="primary" renderIcon={Add} size="md" onClick={handleOpenCreate}>
            Create rule
          </Button>
        }
      />

      {notification && (
        <div style={{ marginBottom: '16px' }}>
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      <MetricStrip columns={4}>
        <KpiCard
          label="Total Custom Rules"
          value={rules.length.toLocaleString()}
          subtext={`${activeCount} active · ${inactiveCount} disabled`}
          icon={Code}
        />
        <KpiCard
          label="Active Protections"
          value={activeCount.toLocaleString()}
          subtext="Enforcing in real-time"
          icon={CheckmarkOutline}
        />
        <KpiCard
          label="High Severity"
          value={highSeverityCount.toLocaleString()}
          subtext="Critical & high impact"
          icon={Security}
        />
        <KpiCard
          label="Filtered View"
          value={filteredRules.length.toLocaleString()}
          subtext={
            severityFilter !== 'all'
              ? `Filter: ${severityFilter}`
              : searchQuery
              ? `Matching "${searchQuery}"`
              : 'Showing all rules'
          }
          icon={Filter}
        />
      </MetricStrip>

      {loading ? (
        <DataTableSkeleton headers={headers} rowCount={6} columnCount={headers.length} />
      ) : (
        <DataTable rows={tableRows} headers={headers}>
          {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
            <TableContainer
              title="Configured Custom Rules"
              description="Application-specific inspection rules, anomaly scoring, and target conditions."
            >
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    placeholder="Search custom rules..."
                    value={searchQuery}
                    onChange={(e: any, val?: string) => {
                      setSearchQuery(val ?? e?.target?.value ?? '');
                    }}
                    onClear={() => setSearchQuery('')}
                  />
                  <div style={{ width: '180px', marginRight: '8px' }}>
                    <Select
                      id="custom-rule-severity-filter"
                      labelText="Filter rules by severity"
                      hideLabel
                      size="md"
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value as any)}
                    >
                      <SelectItem value="all" text="All Severities" />
                      <SelectItem value="critical" text="Critical" />
                      <SelectItem value="high" text="High" />
                      <SelectItem value="medium" text="Medium" />
                      <SelectItem value="low" text="Low" />
                      <SelectItem value="active" text="Active Only" />
                      <SelectItem value="inactive" text="Inactive Only" />
                    </Select>
                  </div>
                  <Button
                    kind="ghost"
                    hasIconOnly
                    renderIcon={Renew}
                    iconDescription="Refresh"
                    onClick={loadData}
                  />
                </TableToolbarContent>
              </TableToolbar>

              <Table {...getTableProps()} size="md" aria-label="WAF custom rules table">
                <TableHead>
                  <TableRow>
                    {headers.map((header) => {
                      const { key, ...props } = getHeaderProps({ header });
                      return (
                        <TableHeader key={key} {...props}>
                          {header.header}
                        </TableHeader>
                      );
                    })}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {rows.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={headers.length} style={{ textAlign: 'center', padding: '48px 16px' }}>
                        <Security size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
                        <div
                          style={{
                            fontWeight: 600,
                            fontSize: '14px',
                            marginBottom: '4px',
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          {rules.length === 0
                            ? 'No custom rules configured'
                            : 'No matching custom rules found'}
                        </div>
                        <div
                          style={{
                            color: 'var(--cds-text-secondary)',
                            fontSize: '13px',
                            marginBottom: '16px',
                            maxWidth: '440px',
                            margin: '0 auto 16px',
                          }}
                        >
                          {rules.length === 0
                            ? 'Create a custom rule to inspect request headers, URI paths, parameters, or payloads.'
                            : 'No custom rules match the current search query or filter. Try clearing filters or adjust your search.'}
                        </div>
                        {rules.length === 0 ? (
                          <Button kind="primary" size="sm" renderIcon={Add} onClick={handleOpenCreate}>
                            Create rule
                          </Button>
                        ) : (
                          <div style={{ display: 'inline-flex', gap: '8px' }}>
                            <Button
                              kind="tertiary"
                              size="sm"
                              onClick={() => {
                                setSearchQuery('');
                                setSeverityFilter('all');
                              }}
                            >
                              Clear filters
                            </Button>
                            <Button kind="primary" size="sm" renderIcon={Add} onClick={handleOpenCreate}>
                              Create rule
                            </Button>
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  ) : (
                    rows.map((row) => {
                      const raw = rulesMap.get(row.id) || rules.find((r) => r.id === row.id);
                      if (!raw) return null;
                      const { key, ...rowProps } = getRowProps({ row });
                      const isEnabled = raw.enabled !== false;
                      const isValid = raw.valid !== false;

                      return (
                        <TableRow key={key} {...rowProps}>
                          <TableCell>
                            <div style={{ fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                              {raw.name}
                            </div>
                            <div
                              style={{
                                fontSize: '12px',
                                color: 'var(--cds-text-secondary)',
                                fontFamily: 'var(--cds-code-01, monospace)',
                                marginTop: '2px',
                              }}
                            >
                              {raw.id}
                            </div>
                          </TableCell>

                          <TableCell style={{ maxWidth: '420px' }}>
                            <code
                              style={{
                                fontSize: '12px',
                                fontFamily: 'var(--cds-code-01, monospace)',
                                padding: '3px 8px',
                                backgroundColor: 'var(--cds-layer-02)',
                                border: '1px solid var(--cds-border-subtle)',
                                borderRadius: 0,
                                wordBreak: 'break-all',
                                display: 'inline-block',
                                color: 'var(--cds-text-primary)',
                              }}
                            >
                              {formatRuleExpression(raw)}
                            </code>
                          </TableCell>

                          <TableCell>{getSeverityBadge(raw.severity)}</TableCell>

                          <TableCell>
                            <span style={{ fontFamily: 'var(--cds-code-01, monospace)', fontWeight: 600, fontSize: '13px' }}>
                              {raw.score ?? 25}
                            </span>
                          </TableCell>

                          <TableCell>
                            <Toggle
                              id={`toggle-custom-rule-${raw.id}`}
                              size="sm"
                              labelText=""
                              hideLabel
                              toggled={isEnabled}
                              disabled={!isValid}
                              onToggle={(c) => handleToggleRule(raw, c)}
                              aria-label={`${isEnabled ? 'Disable' : 'Enable'} ${raw.name || raw.id}`}
                              title={isValid ? undefined : 'Repair this rule before enabling it'}
                            />
                          </TableCell>

                          <TableCell>
                            <div style={{ display: 'flex', gap: '4px' }}>
                              <Button
                                kind="ghost"
                                size="sm"
                                hasIconOnly
                                renderIcon={Edit}
                                iconDescription="Edit rule"
                                onClick={() => handleOpenEdit(raw.id)}
                              />
                              <Button
                                kind="danger--ghost"
                                size="sm"
                                hasIconOnly
                                renderIcon={TrashCan}
                                iconDescription="Delete rule"
                                onClick={() => openDeleteConfirm(raw)}
                              />
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </DataTable>
      )}

      <Modal
        danger
        open={deleteConfirmOpen}
        modalHeading="Delete custom rule"
        primaryButtonText="Delete rule"
        secondaryButtonText="Cancel"
        onRequestClose={() => setDeleteConfirmOpen(false)}
        onRequestSubmit={handleDeleteRule}
      >
        <p style={{ padding: '16px 0', lineHeight: 1.5 }}>
          Delete rule <strong>{ruleToDelete?.id}</strong> ({ruleToDelete?.name})? This rule will immediately stop filtering incoming traffic.
        </p>
      </Modal>

    </div>
  );
};
