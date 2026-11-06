import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Tabs,
  TabList,
  Tab,
  TabPanels,
  TabPanel,
  NumberInput,
  Button,
  InlineNotification,
  Toggle,
} from '@carbon/react';
import {
  SettingsAdjust,
  Code,
  Document,
  Security,
  Activity,
  ArrowLeft,
  ArrowRight,
  View,
  Misuse,
  Flash,
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
  AppSecurityRequestBodyGuardConfig,
  AppSecurityUploadLimitConfig,
} from '../types';

interface AppSecurityPayloadPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

const INSPECTION_PRESETS = {
  balanced: {
    id: 'balanced',
    title: 'Balanced',
    desc: 'Recommended balance between inspection depth and performance.',
    icon: Activity,
    maxFindings: 100,
    jsonDepth: 32,
    jsonKeys: 2000,
    formParameters: 1000,
    multipartParts: 100,
  },
  relaxed: {
    id: 'relaxed',
    title: 'Relaxed',
    desc: 'Higher limits for large payloads and data ingestion.',
    icon: Flash,
    maxFindings: 200,
    jsonDepth: 48,
    jsonKeys: 5000,
    formParameters: 2000,
    multipartParts: 200,
  },
  strict: {
    id: 'strict',
    title: 'Strict',
    desc: 'Tighter thresholds for exposed public endpoints.',
    icon: Security,
    maxFindings: 25,
    jsonDepth: 16,
    jsonKeys: 500,
    formParameters: 250,
    multipartParts: 40,
  },
  custom: {
    id: 'custom',
    title: 'Custom',
    desc: 'Custom parser thresholds and limits.',
    icon: SettingsAdjust,
    maxFindings: 100,
    jsonDepth: 32,
    jsonKeys: 2000,
    formParameters: 1000,
    multipartParts: 100,
  },
};

const COMMON_BODY_LIMITS = [1, 5, 10, 25, 50, 100];

export const AppSecurityPayloadPage: React.FC<AppSecurityPayloadPageProps> = ({ onNavigate }) => {
  const [_loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [serverConfig, setServerConfig] = useState<AppSecurityConfig>({ enabled: true });

  const [rbgEnabled, setRbgEnabled] = useState<boolean>(true);
  const [enforcementMode, setEnforcementMode] = useState<'detect' | 'block'>('detect');
  const [inspectionPreset, setInspectionPreset] = useState<string>('balanced');
  const [maxFindings, setMaxFindings] = useState<number>(100);

  const [limitEnabled, setLimitEnabled] = useState<boolean>(true);
  const [maxBodySizeMb, setMaxBodySizeMb] = useState<number>(10);

  const [jsonEnabled, setJsonEnabled] = useState<boolean>(true);
  const [jsonMaxDepth, setJsonMaxDepth] = useState<number>(32);
  const [jsonMaxKeys, setJsonMaxKeys] = useState<number>(2000);
  const [jsonMaxArrayLength, setJsonMaxArrayLength] = useState<number>(1000);
  const [jsonMaxStringLength, setJsonMaxStringLength] = useState<number>(65536);

  const [xmlEnabled, setXmlEnabled] = useState<boolean>(true);
  const [xmlMaxDepth, setXmlMaxDepth] = useState<number>(32);
  const [xmlMaxElements, setXmlMaxElements] = useState<number>(5000);
  const [xmlMaxAttributes, setXmlMaxAttributes] = useState<number>(1000);
  const [xmlMaxTextLength, setXmlMaxTextLength] = useState<number>(65536);
  const [xmlBlockDoctype, setXmlBlockDoctype] = useState<boolean>(true);
  const [xmlBlockExternalEntities, setXmlBlockExternalEntities] = useState<boolean>(true);

  const [formEnabled, setFormEnabled] = useState<boolean>(true);
  const [formMaxParams, setFormMaxParams] = useState<number>(1000);
  const [formMaxNameLength, setFormMaxNameLength] = useState<number>(256);
  const [formMaxValueLength, setFormMaxValueLength] = useState<number>(65536);

  const [multipartEnabled, setMultipartEnabled] = useState<boolean>(true);
  const [multipartMaxParts, setMultipartMaxParts] = useState<number>(100);
  const [multipartMaxFieldCount, setMultipartMaxFieldCount] = useState<number>(80);
  const [multipartMaxFieldNameLength, setMultipartMaxFieldNameLength] = useState<number>(256);
  const [multipartMaxFieldValueLength, setMultipartMaxFieldValueLength] = useState<number>(65536);

  const [encodingEnabled, setEncodingEnabled] = useState<boolean>(true);
  const [encodingMaxPasses, setEncodingMaxPasses] = useState<number>(2);
  const [encodingRejectInvalidUtf8, setEncodingRejectInvalidUtf8] = useState<boolean>(true);
  const [encodingDetectMixed, setEncodingDetectMixed] = useState<boolean>(true);

  const [graphqlEnabled, setGraphqlEnabled] = useState<boolean>(true);
  const [graphqlMaxDepth, setGraphqlMaxDepth] = useState<number>(12);
  const [graphqlMaxAliases, setGraphqlMaxAliases] = useState<number>(20);
  const [graphqlMaxFields, setGraphqlMaxFields] = useState<number>(250);
  const [graphqlMaxFragments, setGraphqlMaxFragments] = useState<number>(25);
  const [graphqlMaxBatchedOps, setGraphqlMaxBatchedOps] = useState<number>(5);
  const [graphqlBlockIntrospection, setGraphqlBlockIntrospection] = useState<boolean>(false);
  const [graphqlRequireOperationName, setGraphqlRequireOperationName] = useState<boolean>(false);

  const handleNavigate = (key: NavItemKey) => {
    if (onNavigate) {
      onNavigate(key);
    } else {
      window.location.hash = `#${key}`;
    }
  };

  const parseSizeMb = (sizeStr?: string): number => {
    if (!sizeStr) return 10;
    const raw = String(sizeStr).trim().toUpperCase();
    const num = parseInt(raw, 10);
    if (!Number.isFinite(num) || num <= 0) return 10;
    return raw.includes('GB') ? num * 1024 : num;
  };

  const detectInspectionPreset = (
    findings: number,
    jDepth: number,
    jKeys: number,
    fParams: number,
    mParts: number
  ): string => {
    for (const [key, p] of Object.entries(INSPECTION_PRESETS)) {
      if (key === 'custom') continue;
      if (
        findings === p.maxFindings &&
        jDepth === p.jsonDepth &&
        jKeys === p.jsonKeys &&
        fParams === p.formParameters &&
        mParts === p.multipartParts
      ) {
        return key;
      }
    }
    return 'custom';
  };

  const populateFromConfig = useCallback((cfg: AppSecurityConfig) => {
    const rbg = cfg.request_body_guard || ({} as AppSecurityRequestBodyGuardConfig);
    const isRbgEnabled = rbg.enabled !== false;
    setRbgEnabled(isRbgEnabled);
    setEnforcementMode(rbg.mode === 'block' ? 'block' : 'detect');

    const findings = rbg.max_findings ?? 100;
    setMaxFindings(findings);

    const limit = cfg.upload_limit || ({} as AppSecurityUploadLimitConfig);
    setLimitEnabled(limit.enabled !== false);
    setMaxBodySizeMb(parseSizeMb(limit.max_body_size));

    const json = rbg.json || {};
    setJsonEnabled(json.enabled !== false);
    const jDepth = json.max_depth ?? 32;
    const jKeys = json.max_keys ?? 2000;
    setJsonMaxDepth(jDepth);
    setJsonMaxKeys(jKeys);
    setJsonMaxArrayLength(json.max_array_length ?? 1000);
    setJsonMaxStringLength(json.max_string_length ?? 65536);

    const xml = rbg.xml || {};
    setXmlEnabled(xml.enabled !== false);
    setXmlMaxDepth(xml.max_depth ?? 32);
    setXmlMaxElements(xml.max_elements ?? 5000);
    setXmlMaxAttributes(xml.max_attributes ?? 1000);
    setXmlMaxTextLength(xml.max_text_length ?? 65536);
    setXmlBlockDoctype(xml.block_doctype !== false);
    setXmlBlockExternalEntities(xml.block_external_entities !== false);

    const form = rbg.form || {};
    setFormEnabled(form.enabled !== false);
    const fParams = form.max_parameters ?? 1000;
    setFormMaxParams(fParams);
    setFormMaxNameLength(form.max_parameter_name_length ?? 256);
    setFormMaxValueLength(form.max_parameter_value_length ?? 65536);

    const multipart = rbg.multipart || {};
    setMultipartEnabled(multipart.enabled !== false);
    const mParts = multipart.max_parts ?? 100;
    setMultipartMaxParts(mParts);
    setMultipartMaxFieldCount(multipart.max_field_count ?? 80);
    setMultipartMaxFieldNameLength(multipart.max_field_name_length ?? 256);
    setMultipartMaxFieldValueLength(multipart.max_field_value_length ?? 65536);

    const enc = rbg.encoding || {};
    setEncodingEnabled(enc.enabled !== false);
    setEncodingMaxPasses(enc.max_decoding_passes ?? 2);
    setEncodingRejectInvalidUtf8(enc.reject_invalid_utf8 !== false);
    setEncodingDetectMixed(enc.detect_mixed_encoding !== false);

    const gql = rbg.graphql || {};
    setGraphqlEnabled(gql.enabled !== false);
    setGraphqlMaxDepth(gql.max_depth ?? 12);
    setGraphqlMaxAliases(gql.max_aliases ?? 20);
    setGraphqlMaxFields(gql.max_fields ?? 250);
    setGraphqlMaxFragments(gql.max_fragments ?? 25);
    setGraphqlMaxBatchedOps(gql.max_batched_operations ?? 5);
    setGraphqlBlockIntrospection(gql.block_introspection === true);
    setGraphqlRequireOperationName(gql.require_operation_name === true);

    setInspectionPreset(detectInspectionPreset(findings, jDepth, jKeys, fParams, mParts));
  }, []);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const cfg = await apiService.getAppSecurityConfig();
      if (cfg) {
        setServerConfig(cfg);
        populateFromConfig(cfg);
      }
    } catch (e: any) {
      setNotification({
        type: 'error',
        message: e?.message || 'Failed to load Application Security configuration',
      });
    } finally {
      setLoading(false);
    }
  }, [populateFromConfig]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSelectInspectionPreset = (presetKey: string) => {
    setInspectionPreset(presetKey);
    const preset = (INSPECTION_PRESETS as any)[presetKey];
    if (preset && presetKey !== 'custom') {
      setMaxFindings(preset.maxFindings);
      setJsonMaxDepth(preset.jsonDepth);
      setJsonMaxKeys(preset.jsonKeys);
      setFormMaxParams(preset.formParameters);
      setMultipartMaxParts(preset.multipartParts);
    }
  };

  const isDirty = useMemo(() => {
    const origRbg = serverConfig.request_body_guard || ({} as AppSecurityRequestBodyGuardConfig);
    const origLimit = serverConfig.upload_limit || ({} as AppSecurityUploadLimitConfig);
    const origJson = origRbg.json || {};
    const origXml = origRbg.xml || {};
    const origForm = origRbg.form || {};
    const origMultipart = origRbg.multipart || {};
    const origEnc = origRbg.encoding || {};
    const origGql = origRbg.graphql || {};

    if (rbgEnabled !== (origRbg.enabled !== false)) return true;
    if (enforcementMode !== (origRbg.mode === 'block' ? 'block' : 'detect')) return true;
    if (maxFindings !== (origRbg.max_findings ?? 100)) return true;

    if (limitEnabled !== (origLimit.enabled !== false)) return true;
    if (maxBodySizeMb !== parseSizeMb(origLimit.max_body_size)) return true;

    if (jsonEnabled !== (origJson.enabled !== false)) return true;
    if (jsonMaxDepth !== (origJson.max_depth ?? 32)) return true;
    if (jsonMaxKeys !== (origJson.max_keys ?? 2000)) return true;
    if (jsonMaxArrayLength !== (origJson.max_array_length ?? 1000)) return true;
    if (jsonMaxStringLength !== (origJson.max_string_length ?? 65536)) return true;

    if (xmlEnabled !== (origXml.enabled !== false)) return true;
    if (xmlMaxDepth !== (origXml.max_depth ?? 32)) return true;
    if (xmlMaxElements !== (origXml.max_elements ?? 5000)) return true;
    if (xmlMaxAttributes !== (origXml.max_attributes ?? 1000)) return true;
    if (xmlMaxTextLength !== (origXml.max_text_length ?? 65536)) return true;
    if (xmlBlockDoctype !== (origXml.block_doctype !== false)) return true;
    if (xmlBlockExternalEntities !== (origXml.block_external_entities !== false)) return true;

    if (formEnabled !== (origForm.enabled !== false)) return true;
    if (formMaxParams !== (origForm.max_parameters ?? 1000)) return true;
    if (formMaxNameLength !== (origForm.max_parameter_name_length ?? 256)) return true;
    if (formMaxValueLength !== (origForm.max_parameter_value_length ?? 65536)) return true;

    if (multipartEnabled !== (origMultipart.enabled !== false)) return true;
    if (multipartMaxParts !== (origMultipart.max_parts ?? 100)) return true;
    if (multipartMaxFieldCount !== (origMultipart.max_field_count ?? 80)) return true;
    if (multipartMaxFieldNameLength !== (origMultipart.max_field_name_length ?? 256)) return true;
    if (multipartMaxFieldValueLength !== (origMultipart.max_field_value_length ?? 65536)) return true;

    if (encodingEnabled !== (origEnc.enabled !== false)) return true;
    if (encodingMaxPasses !== (origEnc.max_decoding_passes ?? 2)) return true;
    if (encodingRejectInvalidUtf8 !== (origEnc.reject_invalid_utf8 !== false)) return true;
    if (encodingDetectMixed !== (origEnc.detect_mixed_encoding !== false)) return true;

    if (graphqlEnabled !== (origGql.enabled !== false)) return true;
    if (graphqlMaxDepth !== (origGql.max_depth ?? 12)) return true;
    if (graphqlMaxAliases !== (origGql.max_aliases ?? 20)) return true;
    if (graphqlMaxFields !== (origGql.max_fields ?? 250)) return true;
    if (graphqlMaxFragments !== (origGql.max_fragments ?? 25)) return true;
    if (graphqlMaxBatchedOps !== (origGql.max_batched_operations ?? 5)) return true;
    if (graphqlBlockIntrospection !== (origGql.block_introspection === true)) return true;
    if (graphqlRequireOperationName !== (origGql.require_operation_name === true)) return true;

    return false;
  }, [
    serverConfig,
    rbgEnabled,
    enforcementMode,
    maxFindings,
    limitEnabled,
    maxBodySizeMb,
    jsonEnabled,
    jsonMaxDepth,
    jsonMaxKeys,
    jsonMaxArrayLength,
    jsonMaxStringLength,
    xmlEnabled,
    xmlMaxDepth,
    xmlMaxElements,
    xmlMaxAttributes,
    xmlMaxTextLength,
    xmlBlockDoctype,
    xmlBlockExternalEntities,
    formEnabled,
    formMaxParams,
    formMaxNameLength,
    formMaxValueLength,
    multipartEnabled,
    multipartMaxParts,
    multipartMaxFieldCount,
    multipartMaxFieldNameLength,
    multipartMaxFieldValueLength,
    encodingEnabled,
    encodingMaxPasses,
    encodingRejectInvalidUtf8,
    encodingDetectMixed,
    graphqlEnabled,
    graphqlMaxDepth,
    graphqlMaxAliases,
    graphqlMaxFields,
    graphqlMaxFragments,
    graphqlMaxBatchedOps,
    graphqlBlockIntrospection,
    graphqlRequireOperationName,
  ]);

  const handleReset = () => {
    populateFromConfig(serverConfig);
    setNotification(null);
  };

  const handleSave = async () => {
    setSaving(true);
    setNotification(null);

    try {
      const payload: Partial<AppSecurityConfig> = {
        upload_limit: {
          enabled: limitEnabled,
          max_body_size: `${maxBodySizeMb}MB`,
        },
        request_body_guard: {
          enabled: rbgEnabled,
          mode: enforcementMode,
          max_findings: maxFindings,
          max_body_size: maxBodySizeMb * 1024 * 1024,
          json: {
            enabled: jsonEnabled,
            max_depth: jsonMaxDepth,
            max_keys: jsonMaxKeys,
            max_array_length: jsonMaxArrayLength,
            max_string_length: jsonMaxStringLength,
          },
          xml: {
            enabled: xmlEnabled,
            max_depth: xmlMaxDepth,
            max_elements: xmlMaxElements,
            max_attributes: xmlMaxAttributes,
            max_text_length: xmlMaxTextLength,
            block_doctype: xmlBlockDoctype,
            block_external_entities: xmlBlockExternalEntities,
          },
          form: {
            enabled: formEnabled,
            max_parameters: formMaxParams,
            max_parameter_name_length: formMaxNameLength,
            max_parameter_value_length: formMaxValueLength,
          },
          multipart: {
            enabled: multipartEnabled,
            max_parts: multipartMaxParts,
            max_field_count: multipartMaxFieldCount,
            max_field_name_length: multipartMaxFieldNameLength,
            max_field_value_length: multipartMaxFieldValueLength,
          },
          encoding: {
            enabled: encodingEnabled,
            max_decoding_passes: encodingMaxPasses,
            reject_invalid_utf8: encodingRejectInvalidUtf8,
            detect_mixed_encoding: encodingDetectMixed,
          },
          graphql: {
            enabled: graphqlEnabled,
            max_depth: graphqlMaxDepth,
            max_aliases: graphqlMaxAliases,
            max_fields: graphqlMaxFields,
            max_fragments: graphqlMaxFragments,
            max_batched_operations: graphqlMaxBatchedOps,
            block_introspection: graphqlBlockIntrospection,
            require_operation_name: graphqlRequireOperationName,
          },
        },
      };

      const res = await apiService.saveAppSecurityConfig(payload);
      if (!res.success) {
        throw new Error(res.error || 'Server returned an error saving payload protection settings.');
      }

      setNotification({
        type: 'success',
        message: 'Payload protection settings saved successfully.',
      });
      await loadData();
    } catch (e: any) {
      setNotification({
        type: 'error',
        message: e?.message || 'Failed to save payload protection settings',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        title="Payload protection"
        icon={Activity}
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
          <TabList aria-label="Payload Protection Configuration Areas" contained>
            <Tab renderIcon={SettingsAdjust}>Body size & inspection</Tab>
            <Tab renderIcon={Code}>JSON & XML</Tab>
            <Tab renderIcon={Document}>Form & multipart</Tab>
            <Tab renderIcon={Security}>Encoding</Tab>
            <Tab renderIcon={Activity}>GraphQL</Tab>
          </TabList>

          <TabPanels>
            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Payload inspection"
                action={
                  <StatusToggle
                    id="toggle-request-body-guard"
                    toggled={rbgEnabled}
                    onToggle={(val) => setRbgEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle payload inspection"
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
                    name="enforcement-mode-group"
                    valueSelected={enforcementMode}
                    onChange={(val) => setEnforcementMode(val === 'block' ? 'block' : 'detect')}
                    options={[
                      {
                        value: 'detect',
                        title: 'Monitor',
                        description: 'Log payload anomalies without blocking requests.',
                        icon: View,
                      },
                      {
                        value: 'block',
                        title: 'Block',
                        description: 'Block requests with malformed or malicious payloads.',
                        icon: Misuse,
                      },
                    ]}
                  />
                </div>

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
                    name="inspection-preset-group"
                    valueSelected={inspectionPreset}
                    onChange={(val) => handleSelectInspectionPreset(val)}
                    options={Object.values(INSPECTION_PRESETS).map((p) => ({
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
                    maxWidth: '360px',
                  }}
                >
                  <NumberInput
                    id="input-max-findings"
                    label="Max findings per request"
                    min={1}
                    max={1000}
                    step={1}
                    value={maxFindings}
                    onChange={(_e, { value }) => {
                      setMaxFindings(Number(value) || 100);
                      setInspectionPreset('custom');
                    }}
                  />
                </div>
              </SectionCard>

              <div style={{ marginTop: '24px' }}>
                <SectionCard
                  title="Request body size limit"
                  action={
                    <StatusToggle
                      id="toggle-upload-limit"
                      toggled={limitEnabled}
                      onToggle={(val) => setLimitEnabled(val)}
                      hideLabel
                      size="sm"
                      ariaLabel="Toggle request body size limit"
                    />
                  }
                >
                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '20px',
                    }}
                  >
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '600px' }}>
                      <NumberInput
                        id="input-body-size-mb"
                        label="Max request body size (MB)"
                        min={1}
                        max={4096}
                        step={1}
                        value={maxBodySizeMb}
                        onChange={(_e, { value }) => setMaxBodySizeMb(Number(value) || 10)}
                      />

                      <div>
                        <span
                          style={{
                            display: 'block',
                            fontSize: '12px',
                            fontWeight: 600,
                            color: 'var(--cds-text-secondary)',
                            marginBottom: '8px',
                          }}
                        >
                          Presets
                        </span>
                        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                          {COMMON_BODY_LIMITS.map((size) => {
                            const isSelected = maxBodySizeMb === size;
                            return (
                              <Button
                                key={size}
                                size="sm"
                                kind={isSelected ? 'primary' : 'tertiary'}
                                onClick={() => setMaxBodySizeMb(size)}
                              >
                                {size} MB
                              </Button>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  </div>
                </SectionCard>
              </div>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="JSON parser"
                action={
                  <StatusToggle
                    id="toggle-json-guard"
                    toggled={jsonEnabled}
                    onToggle={(val) => setJsonEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle JSON guard"
                  />
                }
              >
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                    gap: '20px',
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '20px',
                  }}
                >
                  <NumberInput
                    id="input-json-max-depth"
                    label="Max nesting depth"
                    min={1}
                    max={256}
                    step={1}
                    value={jsonMaxDepth}
                    onChange={(_e, { value }) => {
                      setJsonMaxDepth(Number(value) || 32);
                      setInspectionPreset('custom');
                    }}
                  />
                  <NumberInput
                    id="input-json-max-keys"
                    label="Max object keys"
                    min={1}
                    max={50000}
                    step={50}
                    value={jsonMaxKeys}
                    onChange={(_e, { value }) => {
                      setJsonMaxKeys(Number(value) || 2000);
                      setInspectionPreset('custom');
                    }}
                  />
                  <NumberInput
                    id="input-json-max-array-length"
                    label="Max array elements"
                    min={1}
                    max={25000}
                    step={50}
                    value={jsonMaxArrayLength}
                    onChange={(_e, { value }) => setJsonMaxArrayLength(Number(value) || 1000)}
                  />
                  <NumberInput
                    id="input-json-max-string-length"
                    label="Max string length (bytes)"
                    min={256}
                    max={10485760}
                    step={1024}
                    value={jsonMaxStringLength}
                    onChange={(_e, { value }) => setJsonMaxStringLength(Number(value) || 65536)}
                  />
                </div>
              </SectionCard>

              <div style={{ marginTop: '24px' }}>
                <SectionCard
                  title="XML parser"
                  action={
                    <StatusToggle
                      id="toggle-xml-guard"
                      toggled={xmlEnabled}
                      onToggle={(val) => setXmlEnabled(val)}
                      hideLabel
                      size="sm"
                      ariaLabel="Toggle XML guard"
                    />
                  }
                >
                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '20px',
                    }}
                  >
                    <div
                      style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                        gap: '20px',
                        marginBottom: '20px',
                      }}
                    >
                      <NumberInput
                        id="input-xml-max-depth"
                        label="Max element depth"
                        min={1}
                        max={256}
                        step={1}
                        value={xmlMaxDepth}
                        onChange={(_e, { value }) => setXmlMaxDepth(Number(value) || 32)}
                      />
                      <NumberInput
                        id="input-xml-max-elements"
                        label="Max total elements"
                        min={1}
                        max={50000}
                        step={100}
                        value={xmlMaxElements}
                        onChange={(_e, { value }) => setXmlMaxElements(Number(value) || 5000)}
                      />
                      <NumberInput
                        id="input-xml-max-attributes"
                        label="Max attributes"
                        min={1}
                        max={10000}
                        step={50}
                        value={xmlMaxAttributes}
                        onChange={(_e, { value }) => setXmlMaxAttributes(Number(value) || 1000)}
                      />
                      <NumberInput
                        id="input-xml-max-text-length"
                        label="Max text node length (bytes)"
                        min={256}
                        max={10485760}
                        step={1024}
                        value={xmlMaxTextLength}
                        onChange={(_e, { value }) => setXmlMaxTextLength(Number(value) || 65536)}
                      />
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '600px' }}>
                        <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                          Block DOCTYPE declarations
                        </strong>
                        <Toggle
                          id="toggle-xml-block-doctype"
                          labelText=""
                          hideLabel
                          toggled={xmlBlockDoctype}
                          onToggle={(val) => setXmlBlockDoctype(val)}
                          size="sm"
                        />
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '600px' }}>
                        <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                          Block external entity expansion
                        </strong>
                        <Toggle
                          id="toggle-xml-block-external"
                          labelText=""
                          hideLabel
                          toggled={xmlBlockExternalEntities}
                          onToggle={(val) => setXmlBlockExternalEntities(val)}
                          size="sm"
                        />
                      </div>
                    </div>
                  </div>
                </SectionCard>
              </div>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Form parser"
                action={
                  <StatusToggle
                    id="toggle-form-guard"
                    toggled={formEnabled}
                    onToggle={(val) => setFormEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle form guard"
                  />
                }
              >
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                    gap: '20px',
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '20px',
                  }}
                >
                  <NumberInput
                    id="input-form-max-parameters"
                    label="Max form parameters"
                    min={1}
                    max={20000}
                    step={50}
                    value={formMaxParams}
                    onChange={(_e, { value }) => {
                      setFormMaxParams(Number(value) || 1000);
                      setInspectionPreset('custom');
                    }}
                  />
                  <NumberInput
                    id="input-form-max-name-length"
                    label="Max parameter name length (bytes)"
                    min={16}
                    max={4096}
                    step={16}
                    value={formMaxNameLength}
                    onChange={(_e, { value }) => setFormMaxNameLength(Number(value) || 256)}
                  />
                  <NumberInput
                    id="input-form-max-val-length"
                    label="Max parameter value length (bytes)"
                    min={256}
                    max={10485760}
                    step={1024}
                    value={formMaxValueLength}
                    onChange={(_e, { value }) => setFormMaxValueLength(Number(value) || 65536)}
                  />
                </div>
              </SectionCard>

              <div style={{ marginTop: '24px' }}>
                <SectionCard
                  title="Multipart parser"
                  action={
                    <StatusToggle
                      id="toggle-multipart-guard"
                      toggled={multipartEnabled}
                      onToggle={(val) => setMultipartEnabled(val)}
                      hideLabel
                      size="sm"
                      ariaLabel="Toggle multipart guard"
                    />
                  }
                >
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                      gap: '20px',
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '20px',
                    }}
                  >
                    <NumberInput
                      id="input-multipart-max-parts"
                      label="Max total MIME parts"
                      min={1}
                      max={1000}
                      step={10}
                      value={multipartMaxParts}
                      onChange={(_e, { value }) => {
                        setMultipartMaxParts(Number(value) || 100);
                        setInspectionPreset('custom');
                      }}
                    />
                    <NumberInput
                      id="input-multipart-max-fields"
                      label="Max non-file fields"
                      min={1}
                      max={500}
                      step={5}
                      value={multipartMaxFieldCount}
                      onChange={(_e, { value }) => setMultipartMaxFieldCount(Number(value) || 80)}
                    />
                    <NumberInput
                      id="input-multipart-max-field-name"
                      label="Max field name length (bytes)"
                      min={16}
                      max={4096}
                      step={16}
                      value={multipartMaxFieldNameLength}
                      onChange={(_e, { value }) => setMultipartMaxFieldNameLength(Number(value) || 256)}
                    />
                    <NumberInput
                      id="input-multipart-max-field-val"
                      label="Max field value length (bytes)"
                      min={256}
                      max={10485760}
                      step={1024}
                      value={multipartMaxFieldValueLength}
                      onChange={(_e, { value }) => setMultipartMaxFieldValueLength(Number(value) || 65536)}
                    />
                  </div>
                </SectionCard>
              </div>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Encoding"
                action={
                  <StatusToggle
                    id="toggle-encoding-guard"
                    toggled={encodingEnabled}
                    onToggle={(val) => setEncodingEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle encoding guard"
                  />
                }
              >
                <div
                  style={{
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '20px',
                  }}
                >
                  <div style={{ maxWidth: '360px', marginBottom: '24px' }}>
                    <NumberInput
                      id="input-encoding-max-passes"
                      label="Max recursive decoding passes"
                      min={1}
                      max={5}
                      step={1}
                      value={encodingMaxPasses}
                      onChange={(_e, { value }) => setEncodingMaxPasses(Number(value) || 2)}
                    />
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '600px' }}>
                      <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                        Reject invalid UTF-8 sequences
                      </strong>
                      <Toggle
                        id="toggle-reject-invalid-utf8"
                        labelText=""
                        hideLabel
                        toggled={encodingRejectInvalidUtf8}
                        onToggle={(val) => setEncodingRejectInvalidUtf8(val)}
                        size="sm"
                      />
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '600px' }}>
                      <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                        Detect mixed encoding schemes
                      </strong>
                      <Toggle
                        id="toggle-detect-mixed-encoding"
                        labelText=""
                        hideLabel
                        toggled={encodingDetectMixed}
                        onToggle={(val) => setEncodingDetectMixed(val)}
                        size="sm"
                      />
                    </div>
                  </div>
                </div>
              </SectionCard>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="GraphQL limits"
                action={
                  <StatusToggle
                    id="toggle-graphql-guard"
                    toggled={graphqlEnabled}
                    onToggle={(val) => setGraphqlEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle GraphQL guard"
                  />
                }
              >
                <div
                  style={{
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '20px',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      flexWrap: 'wrap',
                      gap: '12px',
                      padding: '12px 16px',
                      marginBottom: '20px',
                      background: 'var(--cds-layer-01)',
                      borderLeft: '4px solid var(--cds-support-info)',
                    }}
                  >
                    <div style={{ flex: '1 1 300px' }}>
                      <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)', display: 'block', marginBottom: '2px' }}>
                        API Shield GraphQL protection
                      </strong>
                      <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', lineHeight: 1.4 }}>
                        GraphQL AST inspection and schema enforcement are configured under API Shield.
                      </span>
                    </div>
                    <Button
                      kind="tertiary"
                      size="sm"
                      renderIcon={ArrowRight}
                      onClick={() => handleNavigate('api-graphql')}
                    >
                      Open API Shield
                    </Button>
                  </div>

                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                      gap: '20px',
                      marginBottom: '20px',
                    }}
                  >
                    <NumberInput
                      id="input-gql-max-depth"
                      label="Max selection depth"
                      min={1}
                      max={64}
                      step={1}
                      value={graphqlMaxDepth}
                      onChange={(_e, { value }) => setGraphqlMaxDepth(Number(value) || 12)}
                    />
                    <NumberInput
                      id="input-gql-max-aliases"
                      label="Max field aliases"
                      min={1}
                      max={200}
                      step={5}
                      value={graphqlMaxAliases}
                      onChange={(_e, { value }) => setGraphqlMaxAliases(Number(value) || 20)}
                    />
                    <NumberInput
                      id="input-gql-max-fields"
                      label="Max total fields"
                      min={1}
                      max={2000}
                      step={25}
                      value={graphqlMaxFields}
                      onChange={(_e, { value }) => setGraphqlMaxFields(Number(value) || 250)}
                    />
                    <NumberInput
                      id="input-gql-max-fragments"
                      label="Max fragment spreads"
                      min={1}
                      max={100}
                      step={5}
                      value={graphqlMaxFragments}
                      onChange={(_e, { value }) => setGraphqlMaxFragments(Number(value) || 25)}
                    />
                    <NumberInput
                      id="input-gql-max-batched-ops"
                      label="Max batched operations"
                      min={1}
                      max={50}
                      step={1}
                      value={graphqlMaxBatchedOps}
                      onChange={(_e, { value }) => setGraphqlMaxBatchedOps(Number(value) || 5)}
                    />
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '600px' }}>
                      <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                        Block introspection queries
                      </strong>
                      <Toggle
                        id="toggle-gql-block-introspection"
                        labelText=""
                        hideLabel
                        toggled={graphqlBlockIntrospection}
                        onToggle={(val) => setGraphqlBlockIntrospection(val)}
                        size="sm"
                      />
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '600px' }}>
                      <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                        Require operation name
                      </strong>
                      <Toggle
                        id="toggle-gql-require-operation-name"
                        labelText=""
                        hideLabel
                        toggled={graphqlRequireOperationName}
                        onToggle={(val) => setGraphqlRequireOperationName(val)}
                        size="sm"
                      />
                    </div>
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

export default AppSecurityPayloadPage;
