import React, { useState, useEffect, useMemo } from 'react';
import {
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Button,
  Search,
  Tag,
  Modal,
  TextInput,
  Select,
  SelectItem,
  SelectItemGroup,
  NumberInput,
  Checkbox,
  InlineNotification,
  IconButton,
  ContentSwitcher,
  Switch,
  CodeSnippet,
  Toggle,
  TextArea,
} from '@carbon/react';
import {
  List,
  Add,
  TrashCan,
  Edit,
  ChevronUp,
  ChevronDown,
  ChevronRight,
  Checkmark,
  ArrowLeft,
  Security,
  MisuseOutline,
  CheckmarkOutline,
  View,
} from '@carbon/icons-react';
import {
  PageHeader,
  SectionCard,
  StatusToggle,
  RadioCardGroup,
  type RadioCardOption,
} from '../components/common';
import { apiService } from '../services/api';
import type { AntibotRule, AntibotRuleCondition, NavItemKey } from '../types';

interface BotRulesPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

interface BuilderCondition {
  id: string;
  joiner: 'and' | 'or';
  field: string;
  fieldKey?: string;
  operator: string;
  value: string;
}

export interface FieldSpec {
  name: string;
  label: string;
  category: string;
  operators: string[];
  inputType: 'text' | 'number' | 'boolean' | 'select';
  options?: string[];
  placeholder?: string;
  needsKey?: boolean;
}

export const FIELD_CATEGORIES: Array<{
  category: string;
  fields: FieldSpec[];
}> = [
  {
    category: 'IP & Geolocation',
    fields: [
      { name: 'ip.src', label: 'Client IP Address', category: 'IP & Geolocation', operators: ['eq', 'ne', 'in'], inputType: 'text', placeholder: '198.51.100.1 or 203.0.113.0/24' },
      { name: 'ip.geoip.country', label: 'Country Code (ISO-2)', category: 'IP & Geolocation', operators: ['eq', 'ne', 'in'], inputType: 'text', placeholder: 'US, CN, RU, FR' },
      { name: 'ip.asn', label: 'Autonomous System (ASN)', category: 'IP & Geolocation', operators: ['eq', 'ne', 'in'], inputType: 'text', placeholder: 'AS13335' },
      { name: 'ip.reputation.score', label: 'IP Threat Score (0-100)', category: 'IP & Geolocation', operators: ['lt', 'gt', 'eq', 'ge', 'le'], inputType: 'number', placeholder: '50' },
    ],
  },
  {
    category: 'HTTP Request Attributes',
    fields: [
      { name: 'http.host', label: 'Hostname / Host Header', category: 'HTTP Request Attributes', operators: ['eq', 'ne', 'contains', 'starts_with', 'ends_with'], inputType: 'text', placeholder: 'api.example.com' },
      { name: 'http.request.uri.path', label: 'URI Request Path', category: 'HTTP Request Attributes', operators: ['contains', 'starts_with', 'ends_with', 'eq'], inputType: 'text', placeholder: '/api/v1/auth' },
      { name: 'http.request.method', label: 'HTTP Request Method', category: 'HTTP Request Attributes', operators: ['eq', 'ne', 'in'], inputType: 'select', options: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'] },
      { name: 'http.request.headers', label: 'HTTP Header by Name', category: 'HTTP Request Attributes', operators: ['eq', 'ne', 'contains', 'matches'], inputType: 'text', needsKey: true, placeholder: 'Header value' },
      { name: 'http.request.query', label: 'URL Query Parameter', category: 'HTTP Request Attributes', operators: ['eq', 'ne', 'contains', 'matches'], inputType: 'text', needsKey: true, placeholder: 'Query parameter value' },
      { name: 'http.cookie', label: 'Cookie by Name', category: 'HTTP Request Attributes', operators: ['eq', 'ne', 'contains', 'matches'], inputType: 'text', needsKey: true, placeholder: 'Cookie value' },
    ],
  },
  {
    category: 'Bot Signals & Detection',
    fields: [
      { name: 'aegis.bot.score', label: 'Bot Threat Score (0-100)', category: 'Bot Signals & Detection', operators: ['lt', 'gt', 'eq', 'ge', 'le'], inputType: 'number', placeholder: '30' },
      { name: 'http.user_agent', label: 'User Agent String', category: 'Bot Signals & Detection', operators: ['contains', 'eq', 'ne', 'matches'], inputType: 'text', placeholder: 'HeadlessChrome, python-requests, Scrapy' },
      { name: 'aegis.bot.category', label: 'Bot Category Tag', category: 'Bot Signals & Detection', operators: ['eq', 'ne', 'contains', 'in'], inputType: 'text', placeholder: 'scrapers, crawlers, scanners' },
      { name: 'aegis.bot.verified', label: 'FCrDNS Verified Bot Status', category: 'Bot Signals & Detection', operators: ['eq', 'ne'], inputType: 'boolean', options: ['true', 'false'] },
      { name: 'aegis.bot.headless', label: 'Headless Browser Detected', category: 'Bot Signals & Detection', operators: ['eq', 'ne'], inputType: 'boolean', options: ['true', 'false'] },
    ],
  },
  {
    category: 'Fingerprinting & Edge Signals',
    fields: [
      { name: 'tls.ja3', label: 'TLS JA3 Fingerprint Hash', category: 'Fingerprinting & Edge Signals', operators: ['eq', 'ne', 'contains'], inputType: 'text', placeholder: 'e7d705a3286e19ea42f587b344ee6865' },
      { name: 'tls.ja4', label: 'TLS JA4 Fingerprint String', category: 'Fingerprinting & Edge Signals', operators: ['eq', 'ne', 'contains'], inputType: 'text', placeholder: 't13d1516h2_8daaf6152771_b0da82dd1658' },
    ],
  },
];

const FIELD_DEFINITIONS: FieldSpec[] = FIELD_CATEGORIES.flatMap((c) => c.fields);

const OPERATOR_LABELS: Record<string, string> = {
  eq: 'equals (==)',
  ne: 'does not equal (!=)',
  contains: 'contains',
  not_contains: 'does not contain',
  starts_with: 'starts with',
  ends_with: 'ends with',
  matches: 'matches regex (~)',
  lt: 'less than (<)',
  gt: 'greater than (>)',
  ge: 'greater or equal (>=)',
  le: 'less or equal (<=)',
  in: 'is in set (in)',
};

const BOT_RULE_ACTION_OPTIONS: RadioCardOption[] = [
  {
    value: 'block',
    title: 'Block',
    description: 'Drop matching requests immediately.',
    icon: MisuseOutline,
  },
  {
    value: 'challenge',
    title: 'Managed Challenge',
    description: 'Issue an interactive or cryptographic verification challenge.',
    icon: Security,
  },
  {
    value: 'allow',
    title: 'Allow',
    description: 'Bypass bot mitigation engines for matching requests.',
    icon: CheckmarkOutline,
  },
  {
    value: 'log',
    title: 'Log Only',
    description: 'Log matches without altering traffic.',
    icon: View,
  },
];

export const BotRulesPage: React.FC<BotRulesPageProps> = () => {
  const [_loading, setLoading] = useState<boolean>(true);
  const [rules, setRules] = useState<AntibotRule[]>([]);
  const [ruleSearch, setRuleSearch] = useState<string>('');
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const isHashCreate = typeof window !== 'undefined' && (window.location.hash === '#bot-rule-create' || window.location.hash === '#bot-rules-new');
  const [viewMode, setViewMode] = useState<'list' | 'editor'>(isHashCreate ? 'editor' : 'list');

  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [formName, setFormName] = useState<string>('');
  const [formPriority, setFormPriority] = useState<number>(100);
  const [formEnabled, setFormEnabled] = useState<boolean>(true);
  const [formAction, setFormAction] = useState<string>('block');
  const [builderTab, setBuilderTab] = useState<'visual' | 'raw'>('visual');
  const [conditions, setConditions] = useState<BuilderCondition[]>([]);
  const [rawExpression, setRawExpression] = useState<string>('');
  const [excludeGoodBots, setExcludeGoodBots] = useState<boolean>(false);
  const [excludeAiCrawlers, setExcludeAiCrawlers] = useState<boolean>(false);
  const [inspectorOpen, setInspectorOpen] = useState<boolean>(false);
  const [deleteTarget, setDeleteTarget] = useState<AntibotRule | null>(null);

  const [expressionValid, setExpressionValid] = useState<boolean | null>(null);
  const [expressionError, setExpressionError] = useState<string | null>(null);
  const [isValidatingExpr, setIsValidatingExpr] = useState<boolean>(false);

  const validateExpr = async (expr: string) => {
    const trimmed = expr.trim();
    if (!trimmed) {
      setExpressionValid(null);
      setExpressionError(null);
      return;
    }
    setIsValidatingExpr(true);
    try {
      const res = await apiService.validateBotExpression(trimmed);
      if (res.valid) {
        setExpressionValid(true);
        setExpressionError(null);
      } else {
        setExpressionValid(false);
        setExpressionError(res.error || (res.errors && res.errors[0]?.message) || 'Invalid expression syntax');
      }
    } catch (err: any) {
      setExpressionValid(false);
      setExpressionError(err?.message || 'Validation request failed');
    } finally {
      setIsValidatingExpr(false);
    }
  };

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await apiService.getBotProtectionRules();
      if (Array.isArray(data)) {
        setRules(data);
      }
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Failed to load bot rules.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const totalRules = rules.length;
  const enabledRules = rules.filter((r) => r.enabled !== false).length;
  const disabledRules = totalRules - enabledRules;
  const totalMatchers = rules.reduce(
    (acc, r) => acc + (r.conditions?.length || 0) + (r.expression ? 1 : 0),
    0
  );

  const filteredRules = useMemo(() => {
    const q = ruleSearch.trim().toLowerCase();
    if (!q) return rules;
    return rules.filter(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        (r.expression && r.expression.toLowerCase().includes(q)) ||
        String(r.action).toLowerCase().includes(q) ||
        (r.conditions &&
          r.conditions.some(
            (c) =>
              c.field?.toLowerCase().includes(q) ||
              c.operator?.toLowerCase().includes(q) ||
              String(c.value ?? '').toLowerCase().includes(q)
          ))
    );
  }, [rules, ruleSearch]);

  const handleToggleRule = async (rule: AntibotRule) => {
    const nextEnabled = rule.enabled === false;
    const updated = { ...rule, enabled: nextEnabled };
    const prevRules = rules;
    setRules((prev) => prev.map((r) => (r.id === rule.id ? updated : r)));
    try {
      const res = await apiService.saveBotRule(updated);
      if (res && res.success === false) {
        setRules(prevRules);
        setNotification({
          kind: 'error',
          message: res.error || 'Failed to update rule status.',
        });
        return;
      }
      setNotification({
        kind: 'success',
        message: `Rule "${rule.name}" ${nextEnabled ? 'enabled' : 'disabled'}.`,
      });
    } catch (err: any) {
      setRules(prevRules);
      setNotification({ kind: 'error', message: err?.message || 'Failed to update rule status.' });
    }
  };

  const handleMoveRule = async (index: number, direction: -1 | 1) => {
    const target = index + direction;
    if (target < 0 || target >= rules.length) return;
    const prevRules = rules;
    const reordered = [...rules];
    const [moved] = reordered.splice(index, 1);
    reordered.splice(target, 0, moved);
    setRules(reordered);
    try {
      const ids = reordered.map((r) => r.id).filter(Boolean) as string[];
      if (ids.length > 0) {
        const res = await apiService.reorderBotRules(ids);
        if (res && res.success === false) {
          setRules(prevRules);
          setNotification({ kind: 'error', message: res.error || 'Failed to update rule priorities.' });
          return;
        }
      }
    } catch (err: any) {
      setRules(prevRules);
      setNotification({ kind: 'error', message: err?.message || 'Failed to update rule priorities.' });
    }
  };

  const computedLiveExpression = useMemo(() => {
    if (builderTab === 'raw') {
      return rawExpression.trim();
    }
    if (conditions.length === 0) return 'true';
    return conditions
      .map((c, idx) => {
        let fieldName = c.field;
        if (c.fieldKey && (c.field === 'http.request.headers' || c.field === 'http.cookie' || c.field === 'http.request.query')) {
          fieldName = `${c.field}["${c.fieldKey.toLowerCase()}"]`;
        }
        const op = c.operator;
        const val = c.value;
        const isNumeric = ['aegis.bot.score', 'ip.reputation.score', 'aegis.waf.score'].includes(c.field);
        const formattedVal = isNumeric || val === 'true' || val === 'false' ? val : `"${val}"`;
        const clause = `${fieldName} ${op} ${formattedVal}`;
        return idx === 0 ? clause : `${c.joiner} ${clause}`;
      })
      .join(' ');
  }, [builderTab, rawExpression, conditions]);

  const openCreateRulePage = () => {
    setEditingRuleId(null);
    setFormName('');
    setFormPriority((rules.length + 1) * 10);
    setFormEnabled(true);
    setFormAction('block');
    setBuilderTab('visual');
    setConditions([
      {
        id: `cond_${Date.now()}`,
        joiner: 'and',
        field: 'aegis.bot.score',
        operator: 'lt',
        value: '30',
      },
    ]);
    setRawExpression('aegis.bot.score lt 30');
    setExcludeGoodBots(false);
    setExcludeAiCrawlers(false);
    setInspectorOpen(false);
    setViewMode('editor');
    window.location.hash = '#bot-rule-create';
  };

  const openEditRulePage = (rule: AntibotRule) => {
    setEditingRuleId(rule.id || null);
    setFormName(rule.name || '');
    setFormPriority(Number(rule.priority) || 100);
    setFormEnabled(rule.enabled !== false);
    setFormAction(String(rule.action || 'block'));
    setExcludeGoodBots(rule.apply_to_good_bots === false);
    setExcludeAiCrawlers(rule.apply_to_ai_crawlers === false);
    setInspectorOpen(false);

    if (rule.conditions && rule.conditions.length > 0) {
      setConditions(
        rule.conditions.map((c, idx) => ({
          id: `cond_${idx}_${Date.now()}`,
          joiner: ((c as any).joiner as 'and' | 'or') || 'and',
          field: c.field || 'http.user_agent',
          fieldKey: (c as any).key || '',
          operator: c.operator || 'contains',
          value: String(c.value ?? ''),
        }))
      );
      setBuilderTab('visual');
    } else {
      setRawExpression(rule.expression || '');
      setBuilderTab('raw');
      setConditions([]);
    }

    setViewMode('editor');
    window.location.hash = '#bot-rule-edit';
  };

  const handleCancelEditor = () => {
    setViewMode('list');
    window.location.hash = '#bot-rules';
  };

  const handleAddCondition = () => {
    setConditions((prev) => [
      ...prev,
      {
        id: `cond_${Date.now()}`,
        joiner: 'and',
        field: 'http.user_agent',
        operator: 'contains',
        value: '',
      },
    ]);
  };

  const handleRemoveCondition = (id: string) => {
    setConditions((prev) => prev.filter((c) => c.id !== id));
  };

  const handleUpdateCondition = (id: string, updates: Partial<BuilderCondition>) => {
    setConditions((prev) =>
      prev.map((c) => {
        if (c.id !== id) return c;
        const next = { ...c, ...updates };
        if (updates.field && updates.field !== c.field) {
          const spec = FIELD_DEFINITIONS.find((f) => f.name === updates.field);
          if (spec && !spec.operators.includes(next.operator)) {
            next.operator = spec.operators[0];
          }
          if (spec?.inputType === 'boolean') {
            next.value = 'true';
          }
        }
        return next;
      })
    );
  };

  const handleSaveRule = async () => {
    if (!formName.trim()) return;

    const expressionToSave = builderTab === 'raw' ? rawExpression.trim() : computedLiveExpression;

    const targetConditions: AntibotRuleCondition[] =
      builderTab === 'visual'
        ? conditions.map((c) => ({
            field: c.fieldKey ? `${c.field}["${c.fieldKey}"]` : c.field,
            operator: c.operator,
            value: c.value,
            joiner: c.joiner,
          }))
        : [];

    const targetRule: AntibotRule = {
      ...(editingRuleId ? { id: editingRuleId } : {}),
      name: formName.trim(),
      action: formAction as any,
      priority: formPriority,
      expression: expressionToSave,
      conditions: targetConditions.length > 0 ? targetConditions : undefined,
      enabled: formEnabled,
      type: 'bot',
      section: 'bot',
      phase: 'bot',
      apply_to_good_bots: !excludeGoodBots,
      apply_to_ai_crawlers: !excludeAiCrawlers,
    };

    try {
      const res = await apiService.saveBotRule(targetRule);
      if (res && res.success === false) {
        setNotification({
          kind: 'error',
          message: res.error || 'Failed to deploy bot rule.',
        });
        return;
      }
      await loadData();
      setViewMode('list');
      window.location.hash = '#bot-rules';
      setNotification({
        kind: 'success',
        message: `Bot rule "${targetRule.name}" deployed successfully.`,
      });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Failed to deploy bot rule.' });
    }
  };

  const handleDeleteRule = async () => {
    if (!deleteTarget?.id) return;
    const id = deleteTarget.id;
    const prevRules = rules;
    setRules((prev) => prev.filter((r) => r.id !== id));
    try {
      const res = await apiService.deleteBotRule(id);
      if (res && res.success === false) {
        setRules(prevRules);
        setNotification({ kind: 'error', message: res.error || 'Failed to delete bot rule.' });
        return;
      }
      setDeleteTarget(null);
      setNotification({
        kind: 'success',
        message: 'Bot rule removed.',
      });
    } catch (err: any) {
      setRules(prevRules);
      setNotification({ kind: 'error', message: err?.message || 'Failed to delete bot rule.' });
    }
  };

  const getActionTagType = (action: string) => {
    switch (action.toLowerCase()) {
      case 'block': return 'red';
      case 'challenge': return 'purple';
      case 'allow': return 'green';
      default: return 'cool-gray';
    }
  };

  if (viewMode === 'editor') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
        <div>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={ArrowLeft}
            onClick={handleCancelEditor}
          >
            Back to custom bot rules
          </Button>
        </div>

        {notification && (
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        )}

        <SectionCard
          title={editingRuleId ? `Edit ${formName || 'custom bot rule'}` : 'Create custom bot rule'}
          action={
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <Toggle
                id="bot-rule-form-enabled"
                labelText=""
                hideLabel
                toggled={formEnabled}
                onToggle={(toggled) => setFormEnabled(toggled)}
                size="md"
                aria-label="Rule status"
              />
            </div>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
            <div>
              <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                Rule details
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px', maxWidth: '720px', alignItems: 'start' }}>
                <TextInput
                  id="bot-rule-name"
                  labelText="Rule name"
                  placeholder="e.g. Block Aggressive Scraping & Headless Bots"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  required
                  autoComplete="off"
                />

                <NumberInput
                  id="bot-rule-priority"
                  label="Priority (lower evaluates first)"
                  min={1}
                  max={1000}
                  step={10}
                  value={formPriority}
                  onChange={(_e, { value }) => setFormPriority(Number(value) || 100)}
                />
              </div>
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '4px' }}>
                <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                  Traffic match criteria
                </div>
                <ContentSwitcher
                  selectedIndex={builderTab === 'visual' ? 0 : 1}
                  size="sm"
                  style={{ maxWidth: '280px' }}
                  onChange={(item) => {
                    if (item.name === 'raw') {
                      setRawExpression(computedLiveExpression);
                      setBuilderTab('raw');
                    } else {
                      setBuilderTab('visual');
                    }
                  }}
                >
                  <Switch name="visual" text="Visual Builder" />
                  <Switch name="raw" text="Expression Editor" />
                </ContentSwitcher>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', marginBottom: '16px' }}>
                Match incoming traffic by request attributes, fingerprints, or expression syntax.
              </div>

              {builderTab === 'visual' ? (
                <div style={{ border: '1px solid var(--cds-border-subtle)', background: 'var(--cds-layer-01)' }}>
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '96px 2.2fr 1.6fr 2.4fr 40px',
                      gap: '12px',
                      padding: '10px 16px',
                      background: 'var(--cds-layer-02)',
                      borderBottom: '1px solid var(--cds-border-subtle)',
                      fontSize: '11px',
                      fontWeight: 600,
                      color: 'var(--cds-text-secondary)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      alignItems: 'center',
                    }}
                  >
                    <div>Logic</div>
                    <div>Attribute / Field</div>
                    <div>Operator</div>
                    <div>Value / Pattern</div>
                    <div style={{ textAlign: 'center' }}>Remove</div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    {conditions.map((cond, index) => {
                      const currentSpec = FIELD_DEFINITIONS.find((f) => f.name === cond.field) || FIELD_DEFINITIONS[0];
                      const operators = currentSpec.operators;

                      return (
                        <div
                          key={cond.id}
                          style={{
                            display: 'grid',
                            gridTemplateColumns: '96px 2.2fr 1.6fr 2.4fr 40px',
                            gap: '12px',
                            padding: '12px 16px',
                            alignItems: 'center',
                            borderBottom: index < conditions.length - 1 ? '1px solid var(--cds-border-subtle)' : 'none',
                            background: 'var(--cds-layer-01)',
                          }}
                        >
                          <div>
                            {index === 0 ? (
                              <Tag type="cool-gray" size="sm" style={{ margin: 0, fontWeight: 700, letterSpacing: '0.05em', width: '100%', textAlign: 'center', justifyContent: 'center' }}>
                                WHEN
                              </Tag>
                            ) : (
                              <Select
                                id={`join-${cond.id}`}
                                labelText="Condition join operator"
                                hideLabel
                                size="sm"
                                value={cond.joiner}
                                onChange={(e) => handleUpdateCondition(cond.id, { joiner: e.target.value as 'and' | 'or' })}
                              >
                                <SelectItem value="and" text="AND" />
                                <SelectItem value="or" text="OR" />
                              </Select>
                            )}
                          </div>

                          <div>
                            <Select
                              id={`field-${cond.id}`}
                              labelText="Condition inspect field"
                              hideLabel
                              size="sm"
                              value={cond.field}
                              onChange={(e) => handleUpdateCondition(cond.id, { field: e.target.value })}
                            >
                              {FIELD_CATEGORIES.map((cat) => (
                                <SelectItemGroup key={cat.category} label={cat.category}>
                                  {cat.fields.map((f) => (
                                    <SelectItem key={f.name} value={f.name} text={`${f.label} (${f.name})`} />
                                  ))}
                                </SelectItemGroup>
                              ))}
                            </Select>
                            {currentSpec.needsKey && (
                              <TextInput
                                id={`key-${cond.id}`}
                                labelText={`Key ${cond.id}`}
                                hideLabel
                                placeholder="Key (e.g. User-Agent, X-Api-Key)"
                                size="sm"
                                value={cond.fieldKey || ''}
                                onChange={(e) => handleUpdateCondition(cond.id, { fieldKey: e.target.value })}
                                style={{ marginTop: '6px' }}
                              />
                            )}
                          </div>

                          <div>
                            <Select
                              id={`op-${cond.id}`}
                              labelText="Condition evaluation operator"
                              hideLabel
                              size="sm"
                              value={cond.operator}
                              onChange={(e) => handleUpdateCondition(cond.id, { operator: e.target.value })}
                            >
                              {operators.map((op) => (
                                <SelectItem key={op} value={op} text={OPERATOR_LABELS[op] || op} />
                              ))}
                            </Select>
                          </div>

                          <div>
                            {currentSpec.inputType === 'boolean' ? (
                              <Select
                                id={`val-${cond.id}`}
                                labelText="Condition target pattern value"
                                hideLabel
                                size="sm"
                                value={cond.value}
                                onChange={(e) => handleUpdateCondition(cond.id, { value: e.target.value })}
                              >
                                <SelectItem value="true" text="true (True / Present)" />
                                <SelectItem value="false" text="false (False / Absent)" />
                              </Select>
                            ) : currentSpec.inputType === 'select' && currentSpec.options ? (
                              <Select
                                id={`val-${cond.id}`}
                                labelText="Condition target pattern value"
                                hideLabel
                                size="sm"
                                value={cond.value}
                                onChange={(e) => handleUpdateCondition(cond.id, { value: e.target.value })}
                              >
                                {currentSpec.options.map((opt) => (
                                  <SelectItem key={opt} value={opt} text={opt} />
                                ))}
                              </Select>
                            ) : currentSpec.inputType === 'number' ? (
                              <TextInput
                                id={`val-${cond.id}`}
                                labelText="Condition target pattern value"
                                hideLabel
                                type="number"
                                placeholder={currentSpec.placeholder || 'Value'}
                                size="sm"
                                value={cond.value}
                                onChange={(e) => handleUpdateCondition(cond.id, { value: e.target.value })}
                              />
                            ) : (
                              <TextInput
                                id={`val-${cond.id}`}
                                labelText="Condition target pattern value"
                                hideLabel
                                placeholder={currentSpec.placeholder || 'Value'}
                                size="sm"
                                value={cond.value}
                                onChange={(e) => handleUpdateCondition(cond.id, { value: e.target.value })}
                              />
                            )}
                          </div>

                          <div style={{ display: 'flex', justifyContent: 'center' }}>
                            <IconButton
                              kind="ghost"
                              size="sm"
                              label="Remove condition"
                              align="left"
                              onClick={() => handleRemoveCondition(cond.id)}
                              disabled={conditions.length <= 1}
                            >
                              <TrashCan size={16} />
                            </IconButton>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  <div
                    style={{
                      padding: '12px 16px',
                      background: 'var(--cds-layer-02)',
                      borderTop: '1px solid var(--cds-border-subtle)',
                      display: 'flex',
                      alignItems: 'center',
                    }}
                  >
                    <Button
                      kind="ghost"
                      size="sm"
                      renderIcon={Add}
                      onClick={handleAddCondition}
                    >
                      Add condition
                    </Button>
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <TextArea
                    id="raw-expression-input"
                    labelText="Wire Expression"
                    helperText="Expressions follow Wireshark syntax: (field operator value) joined by 'and' or 'or'."
                    rows={4}
                    value={rawExpression}
                    onChange={(e) => {
                      setRawExpression(e.target.value);
                      if (expressionValid !== null) {
                        validateExpr(e.target.value);
                      }
                    }}
                    onBlur={() => validateExpr(rawExpression)}
                    style={{ fontFamily: 'var(--cds-font-mono, monospace)' }}
                  />

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <Button
                      kind="ghost"
                      size="sm"
                      onClick={() => validateExpr(rawExpression)}
                      disabled={isValidatingExpr || !rawExpression.trim()}
                    >
                      {isValidatingExpr ? 'Validating...' : 'Validate Expression'}
                    </Button>
                    {expressionValid === true && (
                      <Tag type="green" size="sm">
                        Expression Syntax Valid
                      </Tag>
                    )}
                    {expressionValid === false && (
                      <Tag type="red" size="sm">
                        Invalid Expression: {expressionError}
                      </Tag>
                    )}
                  </div>

                  <div
                    style={{
                      padding: '12px 16px',
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      fontSize: '12px',
                      color: 'var(--cds-text-secondary)',
                    }}
                  >
                    <div style={{ fontWeight: 600, color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                      Syntax Examples:
                    </div>
                    <div style={{ fontFamily: 'var(--cds-font-mono, monospace)', marginTop: '2px' }}>
                      • <code>aegis.bot.score lt 30 and http.user_agent contains &quot;curl&quot;</code>
                    </div>
                    <div style={{ fontFamily: 'var(--cds-font-mono, monospace)', marginTop: '2px' }}>
                      • <code>ip.geoip.country in {`{"CN", "RU"}`} and aegis.bot.headless eq true</code>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div>
              <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                Choose an action
              </div>
              <RadioCardGroup
                name="bot-rule-action-group"
                valueSelected={formAction}
                onChange={(val) => setFormAction(val)}
                options={BOT_RULE_ACTION_OPTIONS}
                minColumnWidth="230px"
              />
            </div>

            <div>
              <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                Exemptions
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', maxWidth: '640px' }}>
                <Checkbox
                  id="rule-exclude-good-bots"
                  labelText="Bypass verified search engines and good bots"
                  checked={excludeGoodBots}
                  onChange={(_e, { checked }) => setExcludeGoodBots(checked)}
                />
                <Checkbox
                  id="rule-exclude-ai-crawlers"
                  labelText="Bypass generative AI crawlers"
                  checked={excludeAiCrawlers}
                  onChange={(_e, { checked }) => setExcludeAiCrawlers(checked)}
                />
              </div>
            </div>

            <div style={{ borderTop: '1px solid var(--cds-border-subtle)', paddingTop: '16px' }}>
              <button
                type="button"
                onClick={() => setInspectorOpen(!inspectorOpen)}
                style={{
                  background: 'none',
                  border: 'none',
                  padding: 0,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  color: 'var(--cds-text-primary)',
                  fontSize: '13px',
                  fontWeight: 600,
                }}
              >
                {inspectorOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                <span>Rule preview & wire expression</span>
                <span style={{ fontSize: '12px', fontWeight: 400, color: 'var(--cds-text-secondary)' }}>
                  (Live expression generated from criteria)
                </span>
              </button>

              {inspectorOpen && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '16px', maxWidth: '800px' }}>
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                      gap: '12px',
                      padding: '16px',
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Action
                      </div>
                      <div style={{ marginTop: '4px' }}>
                        <Tag type={getActionTagType(formAction)} size="sm" style={{ margin: 0, textTransform: 'uppercase' }}>
                          {formAction}
                        </Tag>
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Priority
                      </div>
                      <div style={{ fontSize: '13px', fontWeight: 600, marginTop: '4px', color: 'var(--cds-text-primary)' }}>
                        #{formPriority}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Criteria
                      </div>
                      <div style={{ fontSize: '13px', fontWeight: 600, marginTop: '4px', color: 'var(--cds-text-primary)' }}>
                        {builderTab === 'visual' ? `${conditions.length} condition(s)` : 'Expression Editor'}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Status
                      </div>
                      <div style={{ marginTop: '4px' }}>
                        <Tag type={formEnabled ? 'green' : 'cool-gray'} size="sm" style={{ margin: 0 }}>
                          {formEnabled ? 'ACTIVE' : 'DISABLED'}
                        </Tag>
                      </div>
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-secondary)', marginBottom: '6px' }}>
                      Compiled Wire Expression
                    </div>
                    <CodeSnippet type="multi" feedback="Copied to clipboard">
                      {computedLiveExpression}
                    </CodeSnippet>
                  </div>
                </div>
              )}
            </div>

            <div style={{ display: 'flex', gap: '12px', paddingTop: '20px', borderTop: '1px solid var(--cds-border-subtle)' }}>
              <Button
                kind="primary"
                renderIcon={Checkmark}
                onClick={handleSaveRule}
                disabled={!formName.trim()}
              >
                {editingRuleId ? 'Deploy Changes' : 'Deploy Rule'}
              </Button>
              <Button
                kind="ghost"
                onClick={handleCancelEditor}
              >
                Cancel
              </Button>
            </div>
          </div>
        </SectionCard>
      </div>
    );
  }

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Bot defense"
        title="Custom rules"
        icon={List}
        action={
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <div style={{ width: '260px' }}>
              <Search
                id="search-rules"
                labelText="Search bot protection rules"
                placeholder="Filter rules..."
                value={ruleSearch}
                onChange={(e) => setRuleSearch(e.target.value)}
                size="sm"
              />
            </div>
            <Button
              kind="primary"
              size="md"
              renderIcon={Add}
              onClick={openCreateRulePage}
              style={{ borderRadius: 0 }}
            >
              Create Rule
            </Button>
          </div>
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

      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '12px 16px',
          background: 'var(--cds-layer-01)',
          border: '1px solid var(--cds-border-subtle)',
          marginBottom: '16px',
          fontSize: '13px',
          color: 'var(--cds-text-secondary)',
        }}
      >
        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
          <span>
            <strong style={{ color: 'var(--cds-text-primary)' }}>{totalRules}</strong> {totalRules === 1 ? 'rule' : 'rules'}
          </span>
          <span style={{ color: 'var(--cds-border-strong)' }}>|</span>
          <span>
            <strong style={{ color: 'var(--cds-support-success)' }}>{enabledRules}</strong> enabled
          </span>
          <span style={{ color: 'var(--cds-border-strong)' }}>|</span>
          <span>
            <strong style={{ color: 'var(--cds-text-muted, #8d8d8d)' }}>{disabledRules}</strong> disabled
          </span>
          <span style={{ color: 'var(--cds-border-strong)' }}>|</span>
          <span>
            <strong style={{ color: 'var(--cds-text-primary)' }}>{totalMatchers}</strong> total matchers
          </span>
        </div>
        <div style={{ fontSize: '12px' }}>
          Evaluated in priority order
        </div>
      </div>

      <div style={{ border: '1px solid var(--cds-border-subtle)', background: 'var(--cds-layer-01)' }}>
        <Table aria-label="Custom Bot Rules Table" size="md">
          <TableHead>
            <TableRow>
              <TableHeader style={{ width: '280px' }}>Rule</TableHeader>
              <TableHeader>Match</TableHeader>
              <TableHeader style={{ width: '130px' }}>Action</TableHeader>
              <TableHeader style={{ width: '110px' }}>Priority</TableHeader>
              <TableHeader style={{ width: '100px' }}>Enabled</TableHeader>
              <TableHeader style={{ textAlign: 'right', width: '110px' }}>Actions</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredRules.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} style={{ textAlign: 'center', padding: '48px 16px' }}>
                  <List size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
                  <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px', color: 'var(--cds-text-primary)' }}>
                    {ruleSearch ? 'No matching rules' : 'No custom rules'}
                  </div>
                  <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                    {ruleSearch
                      ? 'No rules match the current query.'
                      : 'Create a rule to allow, challenge, log, or block matching bot traffic.'}
                  </div>
                  {!ruleSearch && (
                    <Button
                      kind="primary"
                      size="sm"
                      renderIcon={Add}
                      onClick={openCreateRulePage}
                      style={{ borderRadius: 0 }}
                    >
                      Create First Rule
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ) : (
              filteredRules.map((rule, idx) => {
                const isFirst = idx === 0;
                const isLast = idx === filteredRules.length - 1;
                const actionStr = String(rule.action || 'block').toLowerCase();
                const matchCount = (rule.conditions || []).length + (rule.expression ? 1 : 0);

                return (
                  <TableRow key={rule.id || idx}>
                    <TableCell>
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                        <List size={18} style={{ color: 'var(--cds-interactive)', flexShrink: 0, marginTop: '2px' }} />
                        <div>
                          <div>
                            <button
                              type="button"
                              onClick={() => openEditRulePage(rule)}
                              style={{
                                background: 'none',
                                border: 'none',
                                padding: 0,
                                fontWeight: 600,
                                fontSize: '14px',
                                color: 'var(--cds-link-primary, #ff9d57)',
                                cursor: 'pointer',
                                textAlign: 'left',
                              }}
                            >
                              {rule.name || `Rule ${idx + 1}`}
                            </button>
                          </div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px', alignItems: 'center' }}>
                            <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                              {matchCount === 1 ? '1 match condition' : `${matchCount} match conditions`}
                            </span>
                            {rule.apply_to_good_bots === false && (
                              <Tag type="outline" size="sm" style={{ margin: 0, fontSize: '11px' }}>
                                Skip good bots
                              </Tag>
                            )}
                            {rule.apply_to_ai_crawlers === false && (
                              <Tag type="outline" size="sm" style={{ margin: 0, fontSize: '11px' }}>
                                Skip AI crawlers
                              </Tag>
                            )}
                          </div>
                        </div>
                      </div>
                    </TableCell>

                    <TableCell>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                        {rule.conditions && rule.conditions.length > 0 ? (
                          rule.conditions.map((c, cIdx) => (
                            <span
                              key={cIdx}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                background: 'var(--cds-layer-02)',
                                border: '1px solid var(--cds-border-subtle)',
                                padding: '2px 8px',
                                fontSize: '12px',
                                fontFamily: 'var(--cds-font-family-mono, monospace)',
                              }}
                            >
                              <strong style={{ color: 'var(--cds-text-primary)' }}>{c.field}</strong>
                              <span style={{ color: 'var(--cds-text-secondary)' }}>{c.operator}</span>
                              <span style={{ color: 'var(--cds-interactive)' }}>{c.value}</span>
                            </span>
                          ))
                        ) : rule.expression ? (
                          <span
                            style={{
                              display: 'inline-block',
                              background: 'var(--cds-layer-02)',
                              border: '1px solid var(--cds-border-subtle)',
                              padding: '2px 8px',
                              fontSize: '12px',
                              fontFamily: 'var(--cds-font-family-mono, monospace)',
                              color: 'var(--cds-text-primary)',
                              maxWidth: '460px',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {rule.expression}
                          </span>
                        ) : (
                          <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                            No match criteria
                          </span>
                        )}
                      </div>
                    </TableCell>

                    <TableCell>
                      <Tag
                        type={getActionTagType(actionStr)}
                        size="md"
                        style={{ margin: 0, textTransform: 'capitalize' }}
                      >
                        {actionStr}
                      </Tag>
                    </TableCell>

                    <TableCell>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <button
                          type="button"
                          disabled={isFirst}
                          onClick={() => handleMoveRule(idx, -1)}
                          aria-label="Move rule higher"
                          style={{
                            background: 'none',
                            border: '1px solid var(--cds-border-subtle)',
                            cursor: isFirst ? 'not-allowed' : 'pointer',
                            opacity: isFirst ? 0.3 : 1,
                            padding: '2px 4px',
                            display: 'inline-flex',
                            alignItems: 'center',
                          }}
                        >
                          <ChevronUp size={14} />
                        </button>
                        <span style={{ fontWeight: 600, fontSize: '13px', minWidth: '22px', textAlign: 'center' }}>
                          {idx + 1}
                        </span>
                        <button
                          type="button"
                          disabled={isLast}
                          onClick={() => handleMoveRule(idx, 1)}
                          aria-label="Move rule lower"
                          style={{
                            background: 'none',
                            border: '1px solid var(--cds-border-subtle)',
                            cursor: isLast ? 'not-allowed' : 'pointer',
                            opacity: isLast ? 0.3 : 1,
                            padding: '2px 4px',
                            display: 'inline-flex',
                            alignItems: 'center',
                          }}
                        >
                          <ChevronDown size={14} />
                        </button>
                      </div>
                    </TableCell>

                    <TableCell>
                      <StatusToggle
                        id={`toggle-rule-${rule.id || idx}`}
                        toggled={rule.enabled !== false}
                        onToggle={() => handleToggleRule(rule)}
                        size="sm"
                        ariaLabel={`Toggle status for ${rule.name}`}
                      />
                    </TableCell>

                    <TableCell style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '4px' }}>
                        <IconButton
                          kind="ghost"
                          size="sm"
                          label="Edit rule"
                          onClick={() => openEditRulePage(rule)}
                        >
                          <Edit size={16} />
                        </IconButton>
                        <IconButton
                          kind="ghost"
                          size="sm"
                          label="Delete rule"
                          onClick={() => setDeleteTarget(rule)}
                        >
                          <TrashCan size={16} style={{ color: 'var(--cds-support-error)' }} />
                        </IconButton>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>

      <Modal
        open={Boolean(deleteTarget)}
        danger
        modalHeading="Delete Custom Rule"
        primaryButtonText="Delete"
        secondaryButtonText="Cancel"
        onRequestClose={() => setDeleteTarget(null)}
        onRequestSubmit={handleDeleteRule}
      >
        <p>
          Are you sure you want to delete the custom bot rule <strong>&quot;{deleteTarget?.name}&quot;</strong>?
          This action takes effect immediately upon deployment.
        </p>
      </Modal>
    </div>
  );
};

export default BotRulesPage;
