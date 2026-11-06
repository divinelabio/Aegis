import React, { useState, useEffect, useMemo } from 'react';
import {
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Button,
  Tag,
  Search,
  Select,
  SelectItem,
  TextInput,
  TextArea,
  NumberInput,
  Modal,
  InlineNotification,
  TileGroup,
  RadioTile,
} from '@carbon/react';
import {
  Activity,
  List,
  Security,
  Document,
  Locked,
  Code,
  WarningAlt,
  DataBase,
  Application,
  Add,
  TrashCan,
  Upload,
  ChevronRight,
  ChevronDown,
  ArrowLeft,
  SettingsAdjust,
  Layers,
} from '@carbon/icons-react';
import {
  PageHeader,
  MetricStrip,
  KpiCard,
  SectionCard,
  HeaderSwitcher,
  SaveActionBar,
} from '../components/common';
import { apiService } from '../services/api';
import type { NavItemKey } from '../types';

interface ApiSecurityPageProps {
  activeNavKey?: NavItemKey;
  onNavigate?: (key: NavItemKey) => void;
}

export interface APISecurityAuthTokenIssuer {
  name: string;
  issuer: string;
  audiences: string[];
  allowed_algorithms: string[];
  jwks_url: string;
}

export interface APISecurityBolaOwnershipRule {
  name: string;
  resource_pattern: string;
  owner_id_param: string;
  owner_id_claim?: string;
  allowed_roles: string[];
}

export interface APISecurityBFLARule {
  name: string;
  methods: string[];
  path_pattern: string;
  allowed_roles: string[];
  required_claim_key?: string;
  required_claim_values?: string[];
}

export interface APISecurityMassAssignmentPathRule {
  path_pattern: string;
  fields: string[];
}

export interface APISecurityEndpoint {
  id: string;
  key: string;
  path: string;
  method: string;
  host: string;
  first_seen?: string;
  last_seen?: string;
  is_active: boolean;
  schema_status: 'covered' | 'missing' | 'drifted' | string;
  schema_type?: 'openapi' | 'graphql' | string;
  risk_status: 'shadow' | 'zombie' | 'normal' | 'sensitive' | 'review' | 'high' | 'medium' | 'low' | 'safe' | string;
  service?: string;
  owner?: string;
  environment?: string;
  triage_state?: 'active' | 'review' | 'ignored' | string;
  criticality?: 'low' | 'medium' | 'high' | 'critical' | string;
  notes?: string;
}

export const getRiskTagType = (riskStatus?: string): 'red' | 'magenta' | 'warm-gray' | 'green' | 'cool-gray' => {
  switch (riskStatus?.toLowerCase()) {
    case 'zombie':
      return 'red';
    case 'shadow':
      return 'magenta';
    case 'sensitive':
      return 'warm-gray';
    case 'normal':
      return 'green';
    default:
      return 'cool-gray';
  }
};

export interface RegisteredContractSpec {
  id: string;
  name: string;
  host: string;
  format: string;
  version: string;
  endpointsCovered: number;
  status: string;
}

export const ApiSecurityPage: React.FC<ApiSecurityPageProps> = ({ activeNavKey, onNavigate }) => {
  const [subPolicy, setSubPolicy] = useState<'runtime' | 'abuse' | 'data' | null>(null);

  const [_loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [isDirty, setIsDirty] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [rawConfig, setRawConfig] = useState<any>(null);
  const [enabled, setEnabled] = useState<boolean>(true);
  const [_protectionLevel, setProtectionLevel] = useState<number>(3);

  const [injectionState, setInjectionState] = useState<'disable' | 'detect' | 'block'>('block');
  const [injectionSensitivity, setInjectionSensitivity] = useState<'low' | 'medium' | 'high'>('medium');
  const [ssrfState, setSsrfState] = useState<'disable' | 'detect' | 'block'>('detect');
  const [payloadState, setPayloadState] = useState<'disable' | 'detect' | 'block'>('detect');
  const [payloadSensitivity, setPayloadSensitivity] = useState<'balanced' | 'strict'>('balanced');

  const [schemaEnforcementState, setSchemaEnforcementState] = useState<'disable' | 'detect' | 'block'>('block');
  const [invalidMethodPolicy, setInvalidMethodPolicy] = useState<'disable' | 'block'>('block');
  const [invalidContentTypePolicy, setInvalidContentTypePolicy] = useState<'disable' | 'block'>('block');
  const [responseContractValidation, setResponseContractValidation] = useState<'disable' | 'block'>('disable');
  const [unknownEndpointsPolicy, setUnknownEndpointsPolicy] = useState<'disable' | 'block'>('disable');
  const [registeredSpecs, setRegisteredSpecs] = useState<RegisteredContractSpec[]>([]);

  const [selectedAuthControl, setSelectedAuthControl] = useState<'function' | 'object' | 'fields' | 'tokens' | null>(null);
  const [functionAuthState, setFunctionAuthState] = useState<'disable' | 'detect' | 'block'>('detect');
  const [objectAuthState, setObjectAuthState] = useState<'disable' | 'detect' | 'block'>('detect');
  const [massFieldsState, setMassFieldsState] = useState<'disable' | 'detect' | 'block'>('detect');
  const [tokenValidationState, setTokenValidationState] = useState<'disable' | 'detect' | 'block'>('detect');
  const [requiredClaims, setRequiredClaims] = useState<string>('sub, exp, iss');
  const [tokenProtectedPaths, setTokenProtectedPaths] = useState<string>('/api/v1/secure/*');
  const [tokenExcludedPaths, setTokenExcludedPaths] = useState<string>('/api/v1/auth/login, /api/v1/health');
  const [isolatedPaths, setIsolatedPaths] = useState<string[]>([]);
  const [newIsolatedPath, setNewIsolatedPath] = useState<string>('');
  const [massFields, setMassFields] = useState<string[]>([
    'roles', 'admin', 'tenant_id', 'owner_id', 'status', 'scopes', 'role', 'is_admin', 'permissions', 'balance'
  ]);
  const [newFieldInput, setNewFieldInput] = useState<string>('');
  const [expandedBflaIndex, setExpandedBflaIndex] = useState<number | null>(0);
  const [expandedBolaIndex, setExpandedBolaIndex] = useState<number | null>(null);
  const [expandedMassIndex, setExpandedMassIndex] = useState<number | null>(null);
  const [newBflaRoleInputs, setNewBflaRoleInputs] = useState<Record<number, string>>({});
  const [newBflaClaimValInputs, setNewBflaClaimValInputs] = useState<Record<number, string>>({});
  const [newBolaRoleInputs, setNewBolaRoleInputs] = useState<Record<number, string>>({});
  const [newMassRuleFieldInputs, setNewMassRuleFieldInputs] = useState<Record<number, string>>({});
  const [authIssuers, setAuthIssuers] = useState<APISecurityAuthTokenIssuer[]>([]);
  const [bolaRules, setBolaRules] = useState<APISecurityBolaOwnershipRule[]>([]);
  const [bflaRules, setBflaRules] = useState<APISecurityBFLARule[]>([]);
  const [massPathRules, setMassPathRules] = useState<APISecurityMassAssignmentPathRule[]>([]);

  const [selectedGraphQLControl, setSelectedGraphQLControl] = useState<'limits' | 'schema' | null>(null);
  const [graphqlState, setGraphqlState] = useState<'disable' | 'detect' | 'block'>('block');
  const [graphqlIntrospectionPolicy, setGraphqlIntrospectionPolicy] = useState<'disable' | 'block'>('block');
  const [graphqlMaxDepth, setGraphqlMaxDepth] = useState<number>(15);
  const [graphqlMaxAliases, setGraphqlMaxAliases] = useState<number>(25);
  const [graphqlMaxBatchSize, setGraphqlMaxBatchSize] = useState<number>(5);
  const [graphqlMaxComplexity, setGraphqlMaxComplexity] = useState<number>(500);
  const [graphqlPaths, setGraphqlPaths] = useState<string[]>(['/graphql', '/api/graphql']);
  const [isPathModalOpen, setIsPathModalOpen] = useState(false);
  const [newGraphqlPath, setNewGraphqlPath] = useState('');

  const getGraphQLLimitPreset = (): 'strict' | 'standard' | 'relaxed' | 'custom' => {
    if (
      graphqlMaxDepth === 10 &&
      graphqlMaxAliases === 10 &&
      graphqlMaxBatchSize === 3 &&
      graphqlMaxComplexity === 250 &&
      graphqlIntrospectionPolicy === 'block'
    ) {
      return 'strict';
    }
    if (
      graphqlMaxDepth === 15 &&
      graphqlMaxAliases === 25 &&
      graphqlMaxBatchSize === 5 &&
      graphqlMaxComplexity === 500 &&
      graphqlIntrospectionPolicy === 'block'
    ) {
      return 'standard';
    }
    if (
      graphqlMaxDepth === 20 &&
      graphqlMaxAliases === 40 &&
      graphqlMaxBatchSize === 10 &&
      graphqlMaxComplexity === 1000 &&
      graphqlIntrospectionPolicy === 'disable'
    ) {
      return 'relaxed';
    }
    return 'custom';
  };

  const applyGraphQLPreset = (preset: 'strict' | 'standard' | 'relaxed') => {
    if (preset === 'strict') {
      setGraphqlMaxDepth(10);
      setGraphqlMaxAliases(10);
      setGraphqlMaxBatchSize(3);
      setGraphqlMaxComplexity(250);
      setGraphqlIntrospectionPolicy('block');
    } else if (preset === 'standard') {
      setGraphqlMaxDepth(15);
      setGraphqlMaxAliases(25);
      setGraphqlMaxBatchSize(5);
      setGraphqlMaxComplexity(500);
      setGraphqlIntrospectionPolicy('block');
    } else if (preset === 'relaxed') {
      setGraphqlMaxDepth(20);
      setGraphqlMaxAliases(40);
      setGraphqlMaxBatchSize(10);
      setGraphqlMaxComplexity(1000);
      setGraphqlIntrospectionPolicy('disable');
    }
    markDirty();
  };

  const [credentialStuffingState, setCredentialStuffingState] = useState<'disable' | 'detect' | 'block'>('block');
  const [otpBruteforceState, setOtpBruteforceState] = useState<'disable' | 'detect' | 'block'>('block');
  const [forcedBrowsingState, setForcedBrowsingState] = useState<'disable' | 'detect' | 'block'>('block');
  const [userEnumerationState, setUserEnumerationState] = useState<'disable' | 'detect' | 'block'>('block');
  const [objectEnumerationState, setObjectEnumerationState] = useState<'disable' | 'detect' | 'block'>('detect');
  const [scrapingState, setScrapingState] = useState<'disable' | 'detect' | 'block'>('detect');
  const [automationSensitivity, setAutomationSensitivity] = useState<'balanced' | 'strict'>('balanced');

  const [responseLeakHandling, setResponseLeakHandling] = useState<'redact' | 'block' | 'disable'>('block');
  const [piiState, setPiiState] = useState<'disable' | 'detect' | 'block'>('block');
  const [secretsState, setSecretsState] = useState<'disable' | 'detect' | 'block'>('block');
  const [tokensState, setTokensState] = useState<'disable' | 'detect' | 'block'>('block');
  const [paymentDataState, setPaymentDataState] = useState<'disable' | 'detect' | 'block'>('block');
  const [debugDataState, setDebugDataState] = useState<'disable' | 'detect' | 'block'>('block');
  const [internalDataState, setInternalDataState] = useState<'disable' | 'detect' | 'block'>('detect');

  const [inventory, setInventory] = useState<APISecurityEndpoint[]>([]);
  const [inventorySearch, setInventorySearch] = useState<string>('');
  const [methodFilter, setMethodFilter] = useState<string>('ALL');
  const [schemaFilter, setSchemaFilter] = useState<string>('ALL');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [selectedEndpoint, setSelectedEndpoint] = useState<APISecurityEndpoint | null>(null);

  const [schemaModalOpen, setSchemaModalOpen] = useState<boolean>(false);
  const [uploadTarget, setUploadTarget] = useState<string>('manual');
  const [uploadMethod, setUploadMethod] = useState<string>('GET');
  const [uploadHost, setUploadHost] = useState<string>('app.example.test');
  const [uploadPath, setUploadPath] = useState<string>('/api/users');
  const [uploadType, setUploadType] = useState<'openapi' | 'graphql'>('openapi');
  const [uploadContent, setUploadContent] = useState<string>('');
  const [uploadSubmitting, setUploadSubmitting] = useState<boolean>(false);

  const [bolaModalOpen, setBolaModalOpen] = useState<boolean>(false);
  const [newBolaName, setNewBolaName] = useState<string>('');
  const [newBolaPattern, setNewBolaPattern] = useState<string>('');
  const [newBolaParam, setNewBolaParam] = useState<string>('user_id');
  const [newBolaClaim, setNewBolaClaim] = useState<string>('sub');
  const [newBolaRoles, setNewBolaRoles] = useState<string>('admin');

  const [bflaModalOpen, setBflaModalOpen] = useState<boolean>(false);
  const [newBflaName, setNewBflaName] = useState<string>('');
  const [newBflaMethods, setNewBflaMethods] = useState<string>('POST, PUT, DELETE');
  const [newBflaPattern, setNewBflaPattern] = useState<string>('');
  const [newBflaRoles, setNewBflaRoles] = useState<string>('admin');

  const [massModalOpen, setMassModalOpen] = useState<boolean>(false);
  const [newMassPattern, setNewMassPattern] = useState<string>('');
  const [newMassFields, setNewMassFields] = useState<string>('role, is_admin, tier');

  const [issuerModalOpen, setIssuerModalOpen] = useState<boolean>(false);
  const [newIssuerName, setNewIssuerName] = useState<string>('');
  const [newIssuerUrl, setNewIssuerUrl] = useState<string>('');
  const [newIssuerAudiences, setNewIssuerAudiences] = useState<string>('');
  const [newIssuerAlgorithms, setNewIssuerAlgorithms] = useState<string>('RS256');
  const [newIssuerJwks, setNewIssuerJwks] = useState<string>('');

  const [apiStats, setApiStats] = useState<any>(null);
  const [apiDashboard, setApiDashboard] = useState<any>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const cfg = await apiService.getApiSecurityConfig();
      if (cfg) {
        setRawConfig(cfg);
        const root = (cfg.config && typeof cfg.config === 'object') ? cfg.config : cfg;
        const s = (root.settings && typeof root.settings === 'object') ? root.settings : root;

        setEnabled(root.enabled !== false);
        setProtectionLevel(root.protection_level ?? 3);

        const inj = s.injection || {};
        setInjectionState(!inj.enabled ? 'disable' : inj.mode === 'block' ? 'block' : 'detect');
        setInjectionSensitivity(inj.sensitivity || 'medium');

        const ss = s.ssrf || {};
        setSsrfState(!ss.enabled ? 'disable' : ss.mode === 'block' ? 'block' : 'detect');

        const pa = s.payload_abuse || {};
        setPayloadState(!pa.enabled ? 'disable' : pa.mode === 'block' ? 'block' : 'detect');
        setPayloadSensitivity(pa.sensitivity === 'strict' ? 'strict' : 'balanced');

        const val = s.validation || {};
        setSchemaEnforcementState(!val.enabled ? 'disable' : val.mode === 'block' ? 'block' : 'detect');
        setInvalidMethodPolicy(val.block_invalid_methods !== false ? 'block' : 'disable');
        setInvalidContentTypePolicy(val.block_invalid_content_types !== false ? 'block' : 'disable');
        setResponseContractValidation(val.validate_responses === true ? 'block' : 'disable');
        setUnknownEndpointsPolicy(val.block_unknown_endpoints === true ? 'block' : 'disable');

        const tok = s.auth_tokens || {};
        setTokenValidationState(!tok.enabled ? 'disable' : tok.mode === 'block' ? 'block' : 'detect');
        if (Array.isArray(tok.required_claims)) {
          setRequiredClaims(tok.required_claims.join(', '));
        }
        if (Array.isArray(tok.protected_paths)) {
          setTokenProtectedPaths(tok.protected_paths.join(', '));
        }
        if (Array.isArray(tok.excluded_paths)) {
          setTokenExcludedPaths(tok.excluded_paths.join(', '));
        }
        if (Array.isArray(tok.issuers)) {
          setAuthIssuers(tok.issuers);
        }

        const bo = s.bola || {};
        setObjectAuthState(!bo.enabled ? 'disable' : bo.mode === 'block' ? 'block' : 'detect');
        if (Array.isArray(bo.ownership_rules)) {
          setBolaRules(bo.ownership_rules);
        }
        if (Array.isArray(bo.isolated_paths)) {
          setIsolatedPaths(bo.isolated_paths);
        }

        const bf = s.bfla || {};
        setFunctionAuthState(!bf.enabled ? 'disable' : bf.mode === 'block' ? 'block' : 'detect');
        if (Array.isArray(bf.rules)) {
          setBflaRules(bf.rules);
        }

        const ma = s.mass_assignment || {};
        setMassFieldsState(!ma.enabled ? 'disable' : ma.mode === 'block' ? 'block' : 'detect');
        if (Array.isArray(ma.protected_fields) && ma.protected_fields.length > 0) {
          setMassFields(ma.protected_fields);
        }
        if (Array.isArray(ma.path_rules)) {
          setMassPathRules(ma.path_rules);
        }

        const gql = s.graphql || {};
        setGraphqlState(!gql.enabled ? 'disable' : gql.mode === 'block' ? 'block' : 'detect');
        setGraphqlIntrospectionPolicy(gql.block_introspection !== false ? 'block' : 'disable');
        setGraphqlMaxDepth(gql.max_depth ?? 15);
        setGraphqlMaxAliases(gql.max_aliases ?? 25);
        setGraphqlMaxBatchSize(gql.max_batch_size ?? 5);
        setGraphqlMaxComplexity(gql.max_complexity ?? 500);
        if (Array.isArray(gql.paths) && gql.paths.length > 0) {
          setGraphqlPaths(gql.paths);
        } else {
          setGraphqlPaths(['/graphql', '/api/graphql']);
        }

        const auto = s.automation_abuse || {};
        setCredentialStuffingState(auto.enable_credential_stuffing !== false ? 'block' : 'disable');
        setOtpBruteforceState(auto.enable_otp_bruteforce !== false ? 'block' : 'disable');
        setForcedBrowsingState(auto.enable_forced_browsing !== false ? 'block' : 'disable');
        setUserEnumerationState(auto.enable_user_enumeration !== false ? 'block' : 'disable');
        setObjectEnumerationState(auto.enable_object_enumeration !== false ? 'detect' : 'disable');
        setScrapingState(auto.enable_scraping !== false ? 'detect' : 'disable');
        setAutomationSensitivity(auto.sensitivity === 'strict' ? 'strict' : 'balanced');

        const de = s.data_exposure || {};
        setResponseLeakHandling(de.response_handling === 'redact' ? 'redact' : de.response_handling === 'block' ? 'block' : 'disable');
        setPiiState(de.detect_pii !== false ? 'block' : 'disable');
        setSecretsState(de.detect_secrets !== false ? 'block' : 'disable');
        setTokensState(de.detect_tokens !== false ? 'block' : 'disable');
        setPaymentDataState(de.detect_payment_data !== false ? 'block' : 'disable');
        setDebugDataState(de.detect_debug_data !== false ? 'block' : 'disable');
        setInternalDataState(de.detect_internal_data !== false ? 'detect' : 'disable');
      }

      try {
        const invRes = await apiService.getApiSecurityInventory();
        const endpoints: APISecurityEndpoint[] | null = Array.isArray(invRes)
          ? invRes
          : Array.isArray(invRes?.endpoints)
          ? invRes.endpoints
          : Array.isArray(invRes?.items)
          ? invRes.items
          : null;
        if (endpoints !== null) {
          setInventory(endpoints);
          const activeSchemas: RegisteredContractSpec[] = [];
          const seenSpecs = new Set<string>();
          for (const ep of endpoints) {
            if (ep.schema_status === 'covered') {
              const specKey = `${ep.host}-${ep.schema_type || 'openapi'}`;
              if (!seenSpecs.has(specKey)) {
                seenSpecs.add(specKey);
                activeSchemas.push({
                  id: `spec-${activeSchemas.length + 1}`,
                  name: `${(ep.schema_type || 'openapi').toUpperCase()} Specification (${ep.host})`,
                  host: ep.host,
                  format: ep.schema_type === 'graphql' ? 'GraphQL SDL' : 'OpenAPI 3.x',
                  version: 'v1.0.0',
                  endpointsCovered: endpoints.filter((e) => e.host === ep.host && e.schema_status === 'covered').length,
                  status: 'ACTIVE ENFORCING',
                });
              }
            }
          }
          if (activeSchemas.length > 0) {
            setRegisteredSpecs(activeSchemas);
          }
        }
      } catch {
      }

      try {
        const [statsRes, dashRes] = await Promise.all([
          apiService.getApiSecurityStats().catch(() => null),
          apiService.getApiSecurityAnalytics('24h').catch(() => null),
        ]);
        if (statsRes) setApiStats(statsRes);
        if (dashRes) setApiDashboard(dashRes);
      } catch {
      }

      setIsDirty(false);
    } catch {
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const markDirty = () => setIsDirty(true);

  const parseList = (str: string): string[] =>
    str
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

  const handleSave = async () => {
    setSaving(true);
    try {
      const settingsPayload: Record<string, any> = {
        ...(rawConfig?.settings || {}),
        injection: {
          ...(rawConfig?.settings?.injection || {}),
          enabled: injectionState !== 'disable',
          mode: injectionState === 'block' ? 'block' : 'detect',
          sensitivity: injectionSensitivity,
        },
        ssrf: {
          ...(rawConfig?.settings?.ssrf || {}),
          enabled: ssrfState !== 'disable',
          mode: ssrfState === 'block' ? 'block' : 'detect',
        },
        payload_abuse: {
          ...(rawConfig?.settings?.payload_abuse || {}),
          enabled: payloadState !== 'disable',
          mode: payloadState === 'block' ? 'block' : 'detect',
          sensitivity: payloadSensitivity,
        },
        validation: {
          ...(rawConfig?.settings?.validation || {}),
          enabled: schemaEnforcementState !== 'disable',
          mode: schemaEnforcementState === 'block' ? 'block' : 'detect',
          block_invalid_methods: invalidMethodPolicy === 'block',
          block_invalid_content_types: invalidContentTypePolicy === 'block',
          validate_responses: responseContractValidation === 'block',
          block_unknown_endpoints: unknownEndpointsPolicy === 'block',
        },
        auth_tokens: {
          ...(rawConfig?.settings?.auth_tokens || {}),
          enabled: tokenValidationState !== 'disable',
          mode: tokenValidationState === 'block' ? 'block' : 'detect',
          required_claims: parseList(requiredClaims),
          protected_paths: parseList(tokenProtectedPaths),
          excluded_paths: parseList(tokenExcludedPaths),
          require_signature: authIssuers.length > 0,
          issuers: authIssuers,
        },
        bola: {
          ...(rawConfig?.settings?.bola || {}),
          enabled: objectAuthState !== 'disable',
          mode: objectAuthState === 'block' ? 'block' : 'detect',
          enable_ownership: bolaRules.length > 0,
          enable_tenant: isolatedPaths.length > 0,
          ownership_rules: bolaRules,
          isolated_paths: isolatedPaths,
        },
        bfla: {
          ...(rawConfig?.settings?.bfla || {}),
          enabled: functionAuthState !== 'disable',
          mode: functionAuthState === 'block' ? 'block' : 'detect',
          rules: bflaRules,
        },
        mass_assignment: {
          ...(rawConfig?.settings?.mass_assignment || {}),
          enabled: massFieldsState !== 'disable',
          mode: massFieldsState === 'block' ? 'block' : 'detect',
          protected_fields: massFields,
          path_rules: massPathRules,
        },
        graphql: {
          ...(rawConfig?.settings?.graphql || {}),
          enabled: graphqlState !== 'disable',
          mode: graphqlState === 'block' ? 'block' : 'detect',
          block_introspection: graphqlIntrospectionPolicy === 'block',
          max_depth: graphqlMaxDepth,
          max_aliases: graphqlMaxAliases,
          max_batch_size: graphqlMaxBatchSize,
          max_complexity: graphqlMaxComplexity,
          paths: graphqlPaths,
        },
        automation_abuse: {
          ...(rawConfig?.settings?.automation_abuse || {}),
          enabled: true,
          mode: 'detect',
          enable_credential_stuffing: credentialStuffingState !== 'disable',
          enable_otp_bruteforce: otpBruteforceState !== 'disable',
          enable_forced_browsing: forcedBrowsingState !== 'disable',
          enable_user_enumeration: userEnumerationState !== 'disable',
          enable_object_enumeration: objectEnumerationState !== 'disable',
          enable_scraping: scrapingState !== 'disable',
          sensitivity: automationSensitivity,
        },
        data_exposure: {
          ...(rawConfig?.settings?.data_exposure || {}),
          enabled: true,
          mode: 'detect',
          response_handling: responseLeakHandling === 'redact' ? 'redact' : 'block',
          inspect_responses: responseLeakHandling !== 'disable',
          detect_pii: piiState !== 'disable',
          detect_secrets: secretsState !== 'disable',
          detect_tokens: tokensState !== 'disable',
          detect_payment_data: paymentDataState !== 'disable',
          detect_debug_data: debugDataState !== 'disable',
          detect_internal_data: internalDataState !== 'disable',
        },
      };

      const mergedConfig = {
        enabled,
        settings: settingsPayload,
      };

      const res = await apiService.saveApiSecurityConfig(mergedConfig);
      if (res.success) {
        setRawConfig(res.data?.config || mergedConfig);
        setIsDirty(false);
        setNotification({
          kind: 'success',
          message: 'API Security configuration deployed successfully across edge proxies.',
        });
      } else {
        setNotification({
          kind: 'error',
          message: `Failed to deploy API Security configuration: ${res.error || 'Check backend logs.'}`,
        });
      }
    } catch {
      setNotification({
        kind: 'error',
        message: 'Network error communicating with Aegis control-plane.',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleUploadSchema = async () => {
    if (!uploadContent.trim()) {
      setNotification({ kind: 'error', message: 'Schema content cannot be empty.' });
      return;
    }
    setUploadSubmitting(true);
    try {
      const res = await apiService.uploadApiSecuritySchema({
        host: uploadHost,
        path: uploadPath,
        method: uploadMethod || 'GET',
        type: uploadType,
        content: uploadContent,
      });
      if (res.success) {
        setSchemaModalOpen(false);
        setRegisteredSpecs((prev) => [
          ...prev,
          {
            id: `spec-${Date.now()}`,
            name: `${uploadType === 'openapi' ? 'OpenAPI Contract' : 'GraphQL SDL'} (${uploadPath})`,
            host: uploadHost,
            format: uploadType === 'openapi' ? 'OpenAPI 3.1' : 'GraphQL SDL',
            version: 'v1.0.0',
            endpointsCovered: 1,
            status: 'ACTIVE ENFORCING',
          },
        ]);
        setUploadContent('');
        setNotification({
          kind: 'success',
          message: `Schema successfully attached and compiled for ${uploadHost}${uploadPath}.`,
        });
      } else {
        setNotification({
          kind: 'error',
          message: `Schema upload rejected: ${res.error || 'Ensure valid OpenAPI or GraphQL SDL syntax.'}`,
        });
      }
    } catch {
      setNotification({ kind: 'error', message: 'Failed to upload schema.' });
    } finally {
      setUploadSubmitting(false);
    }
  };

  const filteredInventory = useMemo(() => {
    return inventory.filter((ep) => {
      if (!ep) return false;
      const q = inventorySearch.trim().toLowerCase();
      if (q) {
        const path = (ep.path || '').toLowerCase();
        const host = (ep.host || '').toLowerCase();
        const service = (ep.service || '').toLowerCase();
        const owner = (ep.owner || '').toLowerCase();
        const env = (ep.environment || '').toLowerCase();
        const crit = (ep.criticality || '').toLowerCase();
        const triage = (ep.triage_state || '').toLowerCase();
        const notes = (ep.notes || '').toLowerCase();
        if (
          !path.includes(q) &&
          !host.includes(q) &&
          !service.includes(q) &&
          !owner.includes(q) &&
          !env.includes(q) &&
          !crit.includes(q) &&
          !triage.includes(q) &&
          !notes.includes(q)
        ) {
          return false;
        }
      }
      if (methodFilter !== 'ALL' && (ep.method || '').toUpperCase() !== methodFilter) {
        return false;
      }
      if (schemaFilter !== 'ALL' && ep.schema_status !== schemaFilter) {
        return false;
      }
      if (riskFilter !== 'ALL' && ep.risk_status !== riskFilter) {
        return false;
      }
      return true;
    });
  }, [inventory, inventorySearch, methodFilter, schemaFilter, riskFilter]);

  const totalEndpoints = inventory.length;
  const activeEndpoints = inventory.filter((e) => e?.is_active).length;
  const coveredEndpoints = inventory.filter((e) => e?.schema_status === 'covered').length;
  const shadowEndpoints = inventory.filter((e) => e?.schema_status === 'missing').length;
  const schemaCoveragePercent = totalEndpoints > 0 ? Math.round((coveredEndpoints / totalEndpoints) * 100) : 0;

  const activePolicyCount = useMemo(() => {
    let count = 0;
    if (injectionState !== 'disable' || ssrfState !== 'disable' || payloadState !== 'disable') count++;
    if (schemaEnforcementState !== 'disable') count++;
    if (tokenValidationState !== 'disable' || objectAuthState !== 'disable' || functionAuthState !== 'disable' || massFieldsState !== 'disable') count++;
    if (graphqlState !== 'disable') count++;
    if (
      credentialStuffingState !== 'disable' ||
      otpBruteforceState !== 'disable' ||
      forcedBrowsingState !== 'disable' ||
      userEnumerationState !== 'disable' ||
      objectEnumerationState !== 'disable' ||
      scrapingState !== 'disable'
    ) count++;
    if (
      piiState !== 'disable' ||
      secretsState !== 'disable' ||
      tokensState !== 'disable' ||
      paymentDataState !== 'disable' ||
      debugDataState !== 'disable' ||
      internalDataState !== 'disable'
    ) count++;
    return count;
  }, [
    injectionState, ssrfState, payloadState,
    schemaEnforcementState,
    tokenValidationState, objectAuthState, functionAuthState, massFieldsState,
    graphqlState,
    credentialStuffingState, otpBruteforceState, forcedBrowsingState, userEnumerationState, objectEnumerationState, scrapingState,
    piiState, secretsState, tokensState, paymentDataState, debugDataState, internalDataState
  ]);

  const requestsInspectedValue = useMemo(() => {
    const raw = apiStats?.requests_analyzed ?? apiStats?.total_requests ?? apiDashboard?.dashboard?.summary?.total_requests ?? apiDashboard?.summary?.total_requests;
    return typeof raw === 'number' ? raw.toLocaleString() : '0';
  }, [apiStats, apiDashboard]);

  const threatsDetectedValue = useMemo(() => {
    const raw = apiStats?.alerts_24h ?? apiDashboard?.dashboard?.summary?.threats_detected ?? apiDashboard?.summary?.threats_detected;
    return typeof raw === 'number' ? raw.toLocaleString() : '0';
  }, [apiStats, apiDashboard]);

  const threatsBlockedValue = useMemo(() => {
    const raw = apiStats?.threats_blocked ?? apiStats?.blocked_requests ?? apiDashboard?.dashboard?.summary?.threats_blocked ?? apiDashboard?.summary?.threats_blocked;
    return typeof raw === 'number' ? raw.toLocaleString() : '0';
  }, [apiStats, apiDashboard]);

  const renderControlRow = (
    title: string,
    desc: string,
    control: React.ReactNode,
    icon?: React.ComponentType<{ size?: number; style?: React.CSSProperties }>,
    isLast: boolean = false
  ) => {
    const IconComponent = icon;
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '20px 24px',
          borderBottom: isLast ? 'none' : '1px solid var(--cds-border-subtle)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
          {IconComponent && <IconComponent size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />}
          <div>
            <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
              {title}
            </div>
            <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', lineHeight: 1.4 }}>
              {desc}
            </div>
          </div>
        </div>
        <div style={{ width: '180px', flexShrink: 0, display: 'flex', justifyContent: 'flex-end' }}>
          {control}
        </div>
      </div>
    );
  };

  const renderOverviewView = () => {
    return (
      <>
        <PageHeader
          kicker="API security"
          title="Overview"
          icon={Application}
          action={
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <Button
                kind="tertiary"
                size="sm"
                onClick={() => onNavigate && onNavigate('api-inventory')}
              >
                Endpoint Inventory
              </Button>
              <HeaderSwitcher
                id="api-security-master-toggle"
                toggled={enabled}
                onToggle={(checked) => {
                  setEnabled(checked);
                  markDirty();
                }}
                ariaLabel="Toggle Master API Security Engine"
              />
            </div>
          }
        />

        <div style={{ marginBottom: '32px' }}>
          <div style={{ marginBottom: '16px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--cds-text-primary)', margin: '0 0 4px 0' }}>
              Protection statistics
            </h2>
            <p style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', margin: 0 }}>
              Coverage and live API Security posture across inventory, schemas, and policies.
            </p>
          </div>

          <MetricStrip columns={4}>
            <KpiCard
              label="API Requests Inspected"
              value={requestsInspectedValue}
              subtext="Dashboard analytics window"
              status="default"
              icon={Activity}
            />
            <KpiCard
              label="Threats Detected"
              value={threatsDetectedValue}
              subtext="Detected by API Security"
              status="default"
              icon={WarningAlt}
            />
            <KpiCard
              label="Threats Blocked"
              value={threatsBlockedValue}
              subtext="Stopped by policy"
              status="default"
              icon={Security}
            />
            <KpiCard
              label="Active Policies"
              value={`${activePolicyCount}/6`}
              subtext={`${schemaCoveragePercent}% schema coverage`}
              status="default"
              icon={Document}
              onClick={() => onNavigate && onNavigate('api-contracts')}
            />
          </MetricStrip>
        </div>

        <SectionCard
          title="Security policies"
          padded={false}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '20px 24px',
              borderBottom: '1px solid var(--cds-border-subtle)',
              cursor: 'pointer',
            }}
            onClick={() => setSubPolicy('runtime')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
              <Security size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                  Runtime Protection
                </div>
                <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  Stops injection, SSRF, and abusive payloads.
                </div>
              </div>
            </div>
            <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '20px 24px',
              borderBottom: '1px solid var(--cds-border-subtle)',
              cursor: 'pointer',
            }}
            onClick={() => onNavigate && onNavigate('api-contracts')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
              <Document size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                  Contract Enforcement
                </div>
                <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  Enforces schemas and API contract behavior.
                </div>
              </div>
            </div>
            <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '20px 24px',
              borderBottom: '1px solid var(--cds-border-subtle)',
              cursor: 'pointer',
            }}
            onClick={() => onNavigate && onNavigate('api-authorization')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
              <Locked size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                  API Authorization
                </div>
                <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  Protects API operations, objects, tenants, and request fields using trusted Edge Access identity.
                </div>
              </div>
            </div>
            <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '20px 24px',
              borderBottom: '1px solid var(--cds-border-subtle)',
              cursor: 'pointer',
            }}
            onClick={() => onNavigate && onNavigate('api-graphql')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
              <Code size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                  GraphQL Protection
                </div>
                <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  Protects GraphQL endpoints from unsafe query patterns.
                </div>
              </div>
            </div>
            <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '20px 24px',
              borderBottom: '1px solid var(--cds-border-subtle)',
              cursor: 'pointer',
            }}
            onClick={() => setSubPolicy('abuse')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
              <WarningAlt size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                  Abuse Protection
                </div>
                <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  Detects automation, probing, enumeration, and scraping.
                </div>
              </div>
            </div>
            <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '20px 24px',
              cursor: 'pointer',
            }}
            onClick={() => setSubPolicy('data')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
              <DataBase size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                  Data Exposure Protection
                </div>
                <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  Detects sensitive data and response exposure.
                </div>
              </div>
            </div>
            <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
          </div>
        </SectionCard>
      </>
    );
  };

  const renderContractsView = () => {
    return (
      <>
        <PageHeader
          kicker="API security"
          title="Contracts"
          icon={Document}
          action={
            <Button
              kind="primary"
              size="sm"
              renderIcon={Upload}
              onClick={() => setSchemaModalOpen(true)}
            >
              + Upload Schema
            </Button>
          }
        />

        <div style={{ marginBottom: '32px' }}>
          <SectionCard
            title="Contract controls"
            padded={false}
          >
            {renderControlRow(
              'Schema Enforcement',
              'Enforce parameter and body validation against attached schemas.',
              <Select
                id="contract-schema-enforce"
                hideLabel
                labelText="Schema Enforcement"
                size="sm"
                value={schemaEnforcementState}
                onChange={(e) => {
                  setSchemaEnforcementState(e.target.value as any);
                  markDirty();
                }}
              >
                <SelectItem value="disable" text="Disable" />
                <SelectItem value="detect" text="Monitor" />
                <SelectItem value="block" text="Block" />
              </Select>,
              Document
            )}

            {renderControlRow(
              'Invalid Method Policy',
              'Block HTTP methods not permitted by the schema.',
              <Select
                id="contract-method-policy"
                hideLabel
                labelText="Invalid Method Policy"
                size="sm"
                value={invalidMethodPolicy}
                onChange={(e) => {
                  setInvalidMethodPolicy(e.target.value as any);
                  markDirty();
                }}
              >
                <SelectItem value="disable" text="Disable" />
                <SelectItem value="block" text="Block" />
              </Select>,
              WarningAlt
            )}

            {renderControlRow(
              'Invalid Content Type Policy',
              'Block Content-Types not declared in the schema.',
              <Select
                id="contract-content-type-policy"
                hideLabel
                labelText="Invalid Content Type Policy"
                size="sm"
                value={invalidContentTypePolicy}
                onChange={(e) => {
                  setInvalidContentTypePolicy(e.target.value as any);
                  markDirty();
                }}
              >
                <SelectItem value="disable" text="Disable" />
                <SelectItem value="block" text="Block" />
              </Select>,
              Document
            )}

            {renderControlRow(
              'Response Contract Validation',
              'Validate JSON response payloads against declared OpenAPI response contracts.',
              <Select
                id="contract-resp-val"
                hideLabel
                labelText="Response Contract Validation"
                size="sm"
                value={responseContractValidation}
                onChange={(e) => {
                  setResponseContractValidation(e.target.value as any);
                  markDirty();
                }}
              >
                <SelectItem value="disable" text="Disable" />
                <SelectItem value="block" text="Block" />
              </Select>,
              Activity
            )}

            {renderControlRow(
              'Shadow API Policy',
              'Reject requests to endpoints not declared in any registered schema.',
              <Select
                id="contract-unknown-policy"
                hideLabel
                labelText="Shadow API Policy"
                size="sm"
                value={unknownEndpointsPolicy}
                onChange={(e) => {
                  setUnknownEndpointsPolicy(e.target.value as any);
                  markDirty();
                }}
              >
                <SelectItem value="disable" text="Disable" />
                <SelectItem value="block" text="Block" />
              </Select>,
              WarningAlt,
              true
            )}
          </SectionCard>
        </div>

        <div style={{ marginBottom: '32px' }}>
          <SectionCard
            title="Schema attachment"
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                <Select
                  id="attach-target-select"
                  labelText="ATTACH OR REPLACE TARGET"
                  value={uploadTarget}
                  onChange={(e) => {
                    const val = e.target.value;
                    setUploadTarget(val);
                    if (val !== 'manual') {
                      const ep = inventory.find((item) => item.key === val);
                      if (ep) {
                        setUploadPath(ep.path);
                        setUploadHost(ep.host);
                        setUploadMethod(ep.method);
                      }
                    }
                  }}
                >
                  <SelectItem value="manual" text="Manual endpoint - enter details below" />
                  {inventory.map((ep) => (
                    <SelectItem key={ep.key} value={ep.key} text={`${ep.method} ${ep.path} (${ep.host})`} />
                  ))}
                </Select>

                <Select
                  id="attach-method-select"
                  labelText="METHOD"
                  value={uploadMethod}
                  onChange={(e) => setUploadMethod(e.target.value)}
                >
                  <SelectItem value="GET" text="GET" />
                  <SelectItem value="POST" text="POST" />
                  <SelectItem value="PUT" text="PUT" />
                  <SelectItem value="DELETE" text="DELETE" />
                  <SelectItem value="PATCH" text="PATCH" />
                  <SelectItem value="ALL" text="ALL (Wildcard)" />
                </Select>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                <TextInput
                  id="attach-path-input"
                  labelText="PATH"
                  placeholder="/api/users"
                  value={uploadPath}
                  onChange={(e) => setUploadPath(e.target.value)}
                />
                <TextInput
                  id="attach-host-input"
                  labelText="HOST"
                  placeholder="app.example.test"
                  value={uploadHost}
                  onChange={(e) => setUploadHost(e.target.value)}
                />
              </div>

              <div>
                <Select
                  id="attach-type-select"
                  labelText="SCHEMA TYPE"
                  value={uploadType}
                  onChange={(e) => setUploadType(e.target.value as any)}
                >
                  <SelectItem value="openapi" text="OpenAPI 3.x (JSON / YAML)" />
                  <SelectItem value="graphql" text="GraphQL SDL (Schema Definition Language)" />
                </Select>
              </div>

              <div>
                <TextArea
                  id="attach-content-input"
                  labelText="SCHEMA CONTENT"
                  placeholder="Paste OpenAPI JSON/YAML or GraphQL schema here..."
                  rows={8}
                  value={uploadContent}
                  onChange={(e) => setUploadContent(e.target.value)}
                  style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontSize: '12px' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: '8px' }}>
                <Button
                  kind="primary"
                  size="md"
                  renderIcon={Upload}
                  disabled={uploadSubmitting}
                  onClick={handleUploadSchema}
                >
                  {uploadSubmitting ? 'Uploading...' : 'Upload Schema'}
                </Button>
              </div>
            </div>
          </SectionCard>
        </div>

        <SectionCard
          title="Registered Specifications & Contracts"
          padded={false}
        >
          <Table aria-label="Registered Specifications and Contracts">
            <TableHead>
              <TableRow>
                <TableHeader>Specification</TableHeader>
                <TableHeader>Host / Scope</TableHeader>
                <TableHeader>Format</TableHeader>
                <TableHeader>Version</TableHeader>
                <TableHeader>Endpoints Covered</TableHeader>
                <TableHeader>Status</TableHeader>
                <TableHeader>Actions</TableHeader>
              </TableRow>
            </TableHead>
            <TableBody>
              {registeredSpecs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} style={{ textAlign: 'center', padding: '36px 16px' }}>
                    <Document size={24} style={{ marginBottom: '8px', color: 'var(--cds-icon-secondary)' }} />
                    <div style={{ fontWeight: 600, color: 'var(--cds-text-primary)' }}>No contracts registered</div>
                    <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>Upload an OpenAPI specification or GraphQL SDL above.</div>
                  </TableCell>
                </TableRow>
              ) : (
                registeredSpecs.map((spec) => (
                  <TableRow key={spec.id}>
                    <TableCell style={{ fontWeight: 600 }}>{spec.name}</TableCell>
                    <TableCell style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontSize: '12px' }}>
                      {spec.host}
                    </TableCell>
                    <TableCell>
                      <Tag type={spec.format.includes('OpenAPI') ? 'teal' : 'purple'} size="sm">
                        {spec.format}
                      </Tag>
                    </TableCell>
                    <TableCell>{spec.version}</TableCell>
                    <TableCell>{spec.endpointsCovered} endpoints</TableCell>
                    <TableCell>
                      <Tag type="green" size="sm">{spec.status}</Tag>
                    </TableCell>
                    <TableCell>
                      <Button
                        kind="ghost"
                        size="sm"
                        hasIconOnly
                        renderIcon={TrashCan}
                        iconDescription="Remove Specification"
                        onClick={() => {
                          setRegisteredSpecs((prev) => prev.filter((s) => s.id !== spec.id));
                          markDirty();
                        }}
                      />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </SectionCard>
      </>
    );
  };

  const renderInventoryView = () => {
    return (
      <>
        <PageHeader
          kicker="API security"
          title="API Inventory"
          icon={List}
          action={
            <Button
              kind="primary"
              size="sm"
              renderIcon={Upload}
              onClick={() => setSchemaModalOpen(true)}
            >
              Upload schema
            </Button>
          }
        />

        <div style={{ marginBottom: '24px' }}>
          <MetricStrip columns={4}>
            <KpiCard
              label="Discovered endpoints"
              value={totalEndpoints}
              subtext="Total discovered"
              status="default"
            />
            <KpiCard
              label="Active endpoints"
              value={activeEndpoints}
              subtext="Routing traffic"
              status="default"
            />
            <KpiCard
              label="Schema coverage"
              value={`${schemaCoveragePercent}%`}
              subtext={`${coveredEndpoints} covered`}
              status="default"
            />
            <KpiCard
              label="Undocumented endpoints"
              value={shadowEndpoints}
              subtext={shadowEndpoints > 0 ? 'Missing schemas' : 'None'}
              status="default"
            />
          </MetricStrip>
        </div>

        <SectionCard
          title="Discovered endpoints"
          padded={false}
        >
          <div
            style={{
              padding: '16px 24px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: '16px',
              borderBottom: '1px solid var(--cds-border-subtle)',
              flexWrap: 'wrap',
            }}
          >
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flex: '1 1 320px' }}>
              <Search
                size="md"
                labelText="Search endpoints"
                placeholder="Search by path, host, or service..."
                value={inventorySearch}
                onChange={(e) => setInventorySearch(e.target.value)}
              />
            </div>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <div style={{ width: '130px' }}>
                <Select
                  id="inv-filter-method"
                  size="md"
                  hideLabel
                  labelText="Method"
                  value={methodFilter}
                  onChange={(e) => setMethodFilter(e.target.value)}
                >
                  <SelectItem value="ALL" text="All methods" />
                  <SelectItem value="GET" text="GET" />
                  <SelectItem value="POST" text="POST" />
                  <SelectItem value="PUT" text="PUT" />
                  <SelectItem value="DELETE" text="DELETE" />
                </Select>
              </div>
              <div style={{ width: '150px' }}>
                <Select
                  id="inv-filter-schema"
                  size="md"
                  hideLabel
                  labelText="Schema"
                  value={schemaFilter}
                  onChange={(e) => setSchemaFilter(e.target.value)}
                >
                  <SelectItem value="ALL" text="All schemas" />
                  <SelectItem value="covered" text="Covered" />
                  <SelectItem value="missing" text="Missing" />
                  <SelectItem value="drifted" text="Drifted" />
                </Select>
              </div>
              <div style={{ width: '160px' }}>
                <Select
                  id="inv-filter-risk"
                  size="md"
                  hideLabel
                  labelText="Risk"
                  value={riskFilter}
                  onChange={(e) => setRiskFilter(e.target.value)}
                >
                  <SelectItem value="ALL" text="All risks" />
                  <SelectItem value="shadow" text="Shadow API" />
                  <SelectItem value="zombie" text="Zombie API" />
                  <SelectItem value="normal" text="Normal (Active)" />
                  <SelectItem value="sensitive" text="Sensitive" />
                  <SelectItem value="review" text="In Review" />
                </Select>
              </div>
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <Table aria-label="Discovered API Endpoints">
              <TableHead>
                <TableRow>
                  <TableHeader>Method</TableHeader>
                  <TableHeader>Endpoint</TableHeader>
                  <TableHeader>Host</TableHeader>
                  <TableHeader>Service</TableHeader>
                  <TableHeader>Schema status</TableHeader>
                  <TableHeader>Risk</TableHeader>
                  <TableHeader>Last seen</TableHeader>
                  <TableHeader>Actions</TableHeader>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredInventory.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} style={{ textAlign: 'center', padding: '48px 16px' }}>
                      <List size={32} style={{ marginBottom: '8px', color: 'var(--cds-icon-secondary)' }} />
                      <div style={{ fontWeight: 600, marginBottom: '4px', color: 'var(--cds-text-primary)' }}>
                        No endpoints match your filters
                      </div>
                      <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                        Adjust search term, method, schema coverage, or risk status filters.
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredInventory.map((ep) => (
                    <TableRow key={ep.id}>
                      <TableCell>
                        <Tag type="outline" size="sm">
                          {ep.method || 'GET'}
                        </Tag>
                      </TableCell>
                      <TableCell style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontWeight: 600, fontSize: '13px' }}>
                        {ep.path || ''}
                      </TableCell>
                      <TableCell style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                        {ep.host || ''}
                      </TableCell>
                      <TableCell>
                        <div style={{ fontSize: '13px' }}>{ep.service || '-'}</div>
                        {ep.owner && <div style={{ fontSize: '11px', color: 'var(--cds-text-helper)' }}>{ep.owner}</div>}
                      </TableCell>
                      <TableCell>
                        <Tag
                          type={
                            ep.schema_status === 'covered'
                              ? 'green'
                              : ep.schema_status === 'missing'
                              ? 'red'
                              : 'cool-gray'
                          }
                          size="sm"
                        >
                          {ep.schema_status || 'missing'}
                        </Tag>
                      </TableCell>
                      <TableCell>
                        <Tag
                          type={getRiskTagType(ep.risk_status)}
                          size="sm"
                        >
                          {ep.risk_status || 'normal'}
                        </Tag>
                      </TableCell>
                      <TableCell style={{ fontSize: '12px', color: 'var(--cds-text-helper)' }}>
                        {ep.last_seen || '-'}
                      </TableCell>
                      <TableCell>
                        <Button kind="ghost" size="sm" onClick={() => setSelectedEndpoint(ep)}>
                          Inspect
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </SectionCard>
      </>
    );
  };

  const renderAuthorizationView = () => {
    if (selectedAuthControl === 'tokens') {
      return (
        <>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={ArrowLeft}
            onClick={() => setSelectedAuthControl(null)}
            style={{ marginBottom: '16px' }}
          >
            Back to authorization controls
          </Button>

          <PageHeader
            kicker="API security"
            title="Token validation & issuers"
            icon={Locked}
            action={
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '130px' }}>
                  <Select
                    id="auth-token-state-detail"
                    hideLabel
                    labelText="Token Validation Policy"
                    size="sm"
                    value={tokenValidationState}
                    onChange={(e) => {
                      setTokenValidationState(e.target.value as any);
                      markDirty();
                    }}
                  >
                    <SelectItem value="disable" text="Disable" />
                    <SelectItem value="detect" text="Monitor" />
                    <SelectItem value="block" text="Block" />
                  </Select>
                </div>
                <Button
                  kind="primary"
                  size="sm"
                  renderIcon={Add}
                  onClick={() => setIssuerModalOpen(true)}
                >
                  + Add issuer
                </Button>
              </div>
            }
          />

          <SectionCard
            title="Token verification scope"
            description="Configure which paths require valid identity tokens and which claims are required."
          >
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
              <TextInput
                id="token-protected-paths"
                labelText="Protected API paths"
                helperText="Comma-separated paths requiring verified tokens (e.g. /api/v1/*)"
                value={tokenProtectedPaths}
                onChange={(e) => {
                  setTokenProtectedPaths(e.target.value);
                  markDirty();
                }}
              />
              <TextInput
                id="token-excluded-paths"
                labelText="Excluded paths"
                helperText="Paths that bypass token checks (e.g. /api/v1/auth/login, /health)"
                value={tokenExcludedPaths}
                onChange={(e) => {
                  setTokenExcludedPaths(e.target.value);
                  markDirty();
                }}
              />
              <TextInput
                id="token-required-claims"
                labelText="Required claims"
                helperText="Comma-separated claim keys required in valid tokens (e.g. sub, exp, iss)"
                value={requiredClaims}
                onChange={(e) => {
                  setRequiredClaims(e.target.value);
                  markDirty();
                }}
              />
            </div>
          </SectionCard>

          <div style={{ marginTop: '24px' }}>
            <SectionCard
              title="Trusted JWKS token issuers"
              description="Cryptographic identity providers used to verify JWT signatures."
              padded={false}
              action={
                <Button
                  kind="primary"
                  size="sm"
                  renderIcon={Add}
                  onClick={() => setIssuerModalOpen(true)}
                >
                  + Add issuer
                </Button>
              }
            >
              {authIssuers.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '48px 24px' }}>
                  <Locked size={32} style={{ marginBottom: '12px', color: 'var(--cds-icon-secondary)' }} />
                  <div style={{ fontWeight: 600, fontSize: '15px', color: 'var(--cds-text-primary)', marginBottom: '6px' }}>
                    No trusted token issuers registered
                  </div>
                  <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '20px' }}>
                    Register a JWKS endpoint (e.g. Okta, Auth0, Keycloak) to verify cryptographically signed tokens.
                  </div>
                  <Button
                    kind="primary"
                    size="sm"
                    renderIcon={Add}
                    onClick={() => setIssuerModalOpen(true)}
                  >
                    Register issuer
                  </Button>
                </div>
              ) : (
                <Table aria-label="Trusted token issuers">
                  <TableHead>
                    <TableRow>
                      <TableHeader>Issuer Name</TableHeader>
                      <TableHeader>Issuer URL</TableHeader>
                      <TableHeader>JWKS Endpoint</TableHeader>
                      <TableHeader>Algorithms</TableHeader>
                      <TableHeader style={{ width: '80px', textAlign: 'center' }}>Actions</TableHeader>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {authIssuers.map((iss, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <strong>{iss.name}</strong>
                        </TableCell>
                        <TableCell style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontSize: '12px' }}>
                          {iss.issuer}
                        </TableCell>
                        <TableCell style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontSize: '12px' }}>
                          {iss.jwks_url || '—'}
                        </TableCell>
                        <TableCell>
                          {(iss.allowed_algorithms || ['RS256']).map((alg, aIdx) => (
                            <Tag key={aIdx} type="cool-gray" size="sm">
                              {alg}
                            </Tag>
                          ))}
                        </TableCell>
                        <TableCell style={{ textAlign: 'center' }}>
                          <Button
                            kind="ghost"
                            size="sm"
                            hasIconOnly
                            renderIcon={TrashCan}
                            iconDescription="Delete issuer"
                            onClick={() => {
                              setAuthIssuers((prev) => prev.filter((_, i) => i !== idx));
                              markDirty();
                            }}
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </SectionCard>
          </div>
        </>
      );
    }

    if (selectedAuthControl === 'function') {
      return (
        <>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={ArrowLeft}
            onClick={() => setSelectedAuthControl(null)}
            style={{ marginBottom: '16px' }}
          >
            Back to authorization controls
          </Button>

          <PageHeader
            kicker="API security"
            title="Authorization rules"
            icon={Locked}
            action={
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '130px' }}>
                  <Select
                    id="auth-bfla-state-detail"
                    hideLabel
                    labelText="Function Authorization"
                    size="sm"
                    value={functionAuthState}
                    onChange={(e) => {
                      setFunctionAuthState(e.target.value as any);
                      markDirty();
                    }}
                  >
                    <SelectItem value="disable" text="Disable" />
                    <SelectItem value="detect" text="Monitor" />
                    <SelectItem value="block" text="Block" />
                  </Select>
                </div>
                <Button
                  kind="primary"
                  size="sm"
                  renderIcon={Add}
                  onClick={() => {
                    setBflaRules((prev) => [
                      ...prev,
                      { name: '', methods: [], path_pattern: '', allowed_roles: [], required_claim_key: '', required_claim_values: [] },
                    ]);
                    setExpandedBflaIndex(bflaRules.length);
                    markDirty();
                  }}
                >
                  + Add rule
                </Button>
              </div>
            }
          />

          <div
            style={{
              padding: '12px 16px',
              background: 'var(--cds-layer-01)',
              border: '1px solid var(--cds-border-subtle)',
              marginBottom: '20px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                Verified identity required:
              </span>
              <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                Role and claim rules use only claims from a signature-verified JWT. Inbound identity headers are ignored.
              </span>
            </div>
            <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', fontFamily: 'var(--cds-font-family-mono, monospace)' }}>
              {bflaRules.length} {bflaRules.length === 1 ? 'rule' : 'rules'}
            </span>
          </div>

          {bflaRules.length === 0 ? (
            <SectionCard padded={false}>
              <div style={{ textAlign: 'center', padding: '48px 24px' }}>
                <Locked size={32} style={{ marginBottom: '12px', color: 'var(--cds-icon-secondary)' }} />
                <div style={{ fontWeight: 600, fontSize: '15px', color: 'var(--cds-text-primary)', marginBottom: '6px' }}>
                  No authorization rules configured
                </div>
                <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '20px' }}>
                  Add a rule to restrict API operations by HTTP method, path pattern, role, or claim.
                </div>
                <Button
                  kind="primary"
                  size="sm"
                  renderIcon={Add}
                  onClick={() => {
                    setBflaRules([
                      { name: '', methods: [], path_pattern: '', allowed_roles: [], required_claim_key: '', required_claim_values: [] },
                    ]);
                    setExpandedBflaIndex(0);
                    markDirty();
                  }}
                >
                  Add rule
                </Button>
              </div>
            </SectionCard>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '24px' }}>
              {bflaRules.map((rule, idx) => {
                const isExpanded = expandedBflaIndex === idx;
                const allMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
                const commonRoles = ['admin', 'owner', 'support'];

                return (
                  <div
                    key={idx}
                    style={{
                      border: '1px solid var(--cds-border-subtle)',
                      background: 'var(--cds-layer-01)',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '12px 16px',
                        background: 'var(--cds-layer-02)',
                        borderBottom: isExpanded ? '1px solid var(--cds-border-subtle)' : 'none',
                        cursor: 'pointer',
                      }}
                      onClick={() => setExpandedBflaIndex(isExpanded ? null : idx)}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flex: 1, minWidth: 0 }}>
                        <span
                          style={{
                            fontFamily: 'var(--cds-font-family-mono, monospace)',
                            color: 'var(--cds-text-secondary)',
                            fontWeight: 600,
                            fontSize: '13px',
                            width: '24px',
                          }}
                        >
                          {String(idx + 1).padStart(2, '0')}
                        </span>
                        <div style={{ display: 'flex', flexDirection: 'column', minWidth: '220px' }}>
                          <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                            {rule.name || 'Untitled rule'}
                          </strong>
                          <span
                            style={{
                              fontSize: '12px',
                              fontFamily: 'var(--cds-font-family-mono, monospace)',
                              color: 'var(--cds-text-secondary)',
                              marginTop: '2px',
                            }}
                          >
                            {rule.path_pattern || 'Path not configured'}
                          </span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                          <span style={{ fontFamily: 'var(--cds-font-family-mono, monospace)' }}>
                            {rule.methods && rule.methods.length > 0 ? rule.methods.join(', ') : 'ALL METHODS'}
                          </span>
                          <span>·</span>
                          <span>
                            {rule.allowed_roles && rule.allowed_roles.length > 0
                              ? `${rule.allowed_roles.length} role${rule.allowed_roles.length === 1 ? '' : 's'}`
                              : 'All roles'}
                          </span>
                          {rule.required_claim_key && (
                            <>
                              <span>·</span>
                              <span style={{ fontFamily: 'var(--cds-font-family-mono, monospace)' }}>
                                claim: {rule.required_claim_key}
                              </span>
                            </>
                          )}
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }} onClick={(e) => e.stopPropagation()}>
                        <Button
                          kind="ghost"
                          size="sm"
                          hasIconOnly
                          renderIcon={isExpanded ? ChevronDown : ChevronRight}
                          iconDescription="Toggle rule editor"
                          onClick={() => setExpandedBflaIndex(isExpanded ? null : idx)}
                        />
                        <Button
                          kind="danger--ghost"
                          size="sm"
                          hasIconOnly
                          renderIcon={TrashCan}
                          iconDescription="Remove rule"
                          onClick={() => {
                            setBflaRules((prev) => prev.filter((_, i) => i !== idx));
                            if (expandedBflaIndex === idx) setExpandedBflaIndex(null);
                            markDirty();
                          }}
                        />
                      </div>
                    </div>

                    {isExpanded && (
                      <div style={{ padding: '24px 20px', background: 'var(--cds-layer-01)' }}>
                        <div style={{ marginBottom: '24px' }}>
                          <div style={{ marginBottom: '14px' }}>
                            <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>Protected operation</strong>
                            <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                              Specify the operation name and route pattern.
                            </div>
                          </div>

                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '16px' }}>
                            <TextInput
                              id={`bfla-name-${idx}`}
                              labelText="Rule name"
                              placeholder="e.g. Admin user access"
                              value={rule.name}
                              onChange={(e) => {
                                const val = e.target.value;
                                setBflaRules((prev) => {
                                  const next = [...prev];
                                  next[idx] = { ...next[idx], name: val };
                                  return next;
                                });
                                markDirty();
                              }}
                            />
                            <TextInput
                              id={`bfla-pattern-${idx}`}
                              labelText="Path pattern"
                              placeholder="e.g. /api/admin/{id}"
                              value={rule.path_pattern}
                              onChange={(e) => {
                                const val = e.target.value;
                                setBflaRules((prev) => {
                                  const next = [...prev];
                                  next[idx] = { ...next[idx], path_pattern: val };
                                  return next;
                                });
                                markDirty();
                              }}
                            />
                          </div>

                          <div>
                            <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-primary)', marginBottom: '8px' }}>
                              Allowed HTTP Methods
                            </div>
                            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                              {allMethods.map((m) => {
                                const active = rule.methods.includes(m);
                                return (
                                  <Button
                                    key={m}
                                    size="sm"
                                    kind={active ? 'primary' : 'ghost'}
                                    onClick={() => {
                                      const nextMethods = active
                                        ? rule.methods.filter((x) => x !== m)
                                        : [...rule.methods, m];
                                      setBflaRules((prev) => {
                                        const next = [...prev];
                                        next[idx] = { ...next[idx], methods: nextMethods };
                                        return next;
                                      });
                                      markDirty();
                                    }}
                                    style={{ minHeight: '30px', padding: '0 12px', fontSize: '12px', fontWeight: active ? 600 : 400 }}
                                  >
                                    {m}
                                  </Button>
                                );
                              })}
                            </div>
                            <div style={{ fontSize: '11px', color: 'var(--cds-text-helper)', marginTop: '6px' }}>
                              Leave all unselected to match any incoming HTTP method.
                            </div>
                          </div>
                        </div>

                        <div style={{ marginBottom: '24px', paddingTop: '20px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                          <div style={{ marginBottom: '14px' }}>
                            <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>Allowed roles</strong>
                            <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                              Users must possess at least one of these roles in their verified token to call this endpoint.
                            </div>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
                            <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>Suggested roles:</span>
                            {commonRoles.map((r) => {
                              const isAdded = rule.allowed_roles.includes(r);
                              return (
                                <Button
                                  key={r}
                                  size="sm"
                                  kind="ghost"
                                  disabled={isAdded}
                                  onClick={() => {
                                    if (!isAdded) {
                                      setBflaRules((prev) => {
                                        const next = [...prev];
                                        next[idx] = { ...next[idx], allowed_roles: [...next[idx].allowed_roles, r] };
                                        return next;
                                      });
                                      markDirty();
                                    }
                                  }}
                                  style={{ minHeight: '26px', padding: '0 8px', fontSize: '11px' }}
                                >
                                  {isAdded ? `✓ ${r}` : `+ ${r}`}
                                </Button>
                              );
                            })}
                          </div>

                          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center', minHeight: '32px', marginBottom: '14px' }}>
                            {rule.allowed_roles.length === 0 ? (
                              <span style={{ fontSize: '12px', color: 'var(--cds-text-helper)', fontStyle: 'italic' }}>
                                No specific roles required (all authenticated callers allowed).
                              </span>
                            ) : (
                              rule.allowed_roles.map((r, rIdx) => (
                                <Tag
                                  key={rIdx}
                                  type="cool-gray"
                                  size="md"
                                  filter
                                  onClose={() => {
                                    setBflaRules((prev) => {
                                      const next = [...prev];
                                      next[idx] = {
                                        ...next[idx],
                                        allowed_roles: next[idx].allowed_roles.filter((x) => x !== r),
                                      };
                                      return next;
                                    });
                                    markDirty();
                                  }}
                                >
                                  {r}
                                </Tag>
                              ))
                            )}
                          </div>

                          <div style={{ display: 'flex', gap: '8px', maxWidth: '380px' }}>
                            <TextInput
                              id={`custom-role-${idx}`}
                              hideLabel
                              labelText="Custom Role"
                              placeholder="Add role name (e.g. billing-admin)"
                              size="sm"
                              value={newBflaRoleInputs[idx] || ''}
                              onChange={(e) =>
                                setNewBflaRoleInputs((prev) => ({ ...prev, [idx]: e.target.value }))
                              }
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                  e.preventDefault();
                                  const val = (newBflaRoleInputs[idx] || '').trim();
                                  if (val && !rule.allowed_roles.includes(val)) {
                                    setBflaRules((prev) => {
                                      const next = [...prev];
                                      next[idx] = { ...next[idx], allowed_roles: [...next[idx].allowed_roles, val] };
                                      return next;
                                    });
                                    setNewBflaRoleInputs((prev) => ({ ...prev, [idx]: '' }));
                                    markDirty();
                                  }
                                }
                              }}
                            />
                            <Button
                              kind="secondary"
                              size="sm"
                              onClick={() => {
                                const val = (newBflaRoleInputs[idx] || '').trim();
                                if (val && !rule.allowed_roles.includes(val)) {
                                  setBflaRules((prev) => {
                                    const next = [...prev];
                                    next[idx] = { ...next[idx], allowed_roles: [...next[idx].allowed_roles, val] };
                                    return next;
                                  });
                                  setNewBflaRoleInputs((prev) => ({ ...prev, [idx]: '' }));
                                  markDirty();
                                }
                              }}
                            >
                              Add role
                            </Button>
                          </div>
                        </div>

                        <div style={{ paddingTop: '20px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                          <div style={{ marginBottom: '14px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                                Additional claim requirement
                              </strong>
                              <span style={{ fontSize: '12px', color: 'var(--cds-text-helper)' }}>(optional)</span>
                            </div>
                            <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                              Require a specific JWT claim and accepted values in addition to an allowed role.
                            </div>
                          </div>

                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
                            <TextInput
                              id={`bfla-claim-key-${idx}`}
                              labelText="Claim key"
                              placeholder="e.g. scope or permissions"
                              value={rule.required_claim_key || ''}
                              onChange={(e) => {
                                const val = e.target.value;
                                setBflaRules((prev) => {
                                  const next = [...prev];
                                  next[idx] = { ...next[idx], required_claim_key: val };
                                  return next;
                                });
                                markDirty();
                              }}
                            />
                            <div>
                              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-primary)', marginBottom: '8px' }}>
                                Accepted values
                              </div>
                              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '10px', minHeight: '28px' }}>
                                {(rule.required_claim_values || []).length === 0 ? (
                                  <span style={{ fontSize: '12px', color: 'var(--cds-text-helper)', fontStyle: 'italic' }}>
                                    No value restrictions.
                                  </span>
                                ) : (
                                  (rule.required_claim_values || []).map((val, vIdx) => (
                                    <Tag
                                      key={vIdx}
                                      type="cool-gray"
                                      size="sm"
                                      filter
                                      onClose={() => {
                                        setBflaRules((prev) => {
                                          const next = [...prev];
                                          next[idx] = {
                                            ...next[idx],
                                            required_claim_values: (next[idx].required_claim_values || []).filter((_, i) => i !== vIdx),
                                          };
                                          return next;
                                        });
                                        markDirty();
                                      }}
                                    >
                                      {val}
                                    </Tag>
                                  ))
                                )}
                              </div>
                              <div style={{ display: 'flex', gap: '8px' }}>
                                <TextInput
                                  id={`bfla-claim-val-${idx}`}
                                  hideLabel
                                  labelText="Claim Value"
                                  placeholder="e.g. users:write"
                                  size="sm"
                                  value={newBflaClaimValInputs[idx] || ''}
                                  onChange={(e) =>
                                    setNewBflaClaimValInputs((prev) => ({ ...prev, [idx]: e.target.value }))
                                  }
                                  onKeyDown={(e) => {
                                    if (e.key === 'Enter') {
                                      e.preventDefault();
                                      const val = (newBflaClaimValInputs[idx] || '').trim();
                                      if (val) {
                                        setBflaRules((prev) => {
                                          const next = [...prev];
                                          const current = next[idx].required_claim_values || [];
                                          next[idx] = { ...next[idx], required_claim_values: [...current, val] };
                                          return next;
                                        });
                                        setNewBflaClaimValInputs((prev) => ({ ...prev, [idx]: '' }));
                                        markDirty();
                                      }
                                    }
                                  }}
                                />
                                <Button
                                  kind="secondary"
                                  size="sm"
                                  onClick={() => {
                                    const val = (newBflaClaimValInputs[idx] || '').trim();
                                    if (val) {
                                      setBflaRules((prev) => {
                                        const next = [...prev];
                                        const current = next[idx].required_claim_values || [];
                                        next[idx] = { ...next[idx], required_claim_values: [...current, val] };
                                        return next;
                                      });
                                      setNewBflaClaimValInputs((prev) => ({ ...prev, [idx]: '' }));
                                      markDirty();
                                    }
                                  }}
                                >
                                  Add value
                                </Button>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </>
      );
    }

    if (selectedAuthControl === 'object') {
      const commonRoles = ['admin', 'owner', 'support'];

      return (
        <>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={ArrowLeft}
            onClick={() => setSelectedAuthControl(null)}
            style={{ marginBottom: '16px' }}
          >
            Back to authorization controls
          </Button>

          <PageHeader
            kicker="API security"
            title="Ownership and tenant rules"
            icon={Security}
            action={
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '130px' }}>
                  <Select
                    id="auth-bola-state-detail"
                    hideLabel
                    labelText="Object Authorization"
                    size="sm"
                    value={objectAuthState}
                    onChange={(e) => {
                      setObjectAuthState(e.target.value as any);
                      markDirty();
                    }}
                  >
                    <SelectItem value="disable" text="Disable" />
                    <SelectItem value="detect" text="Monitor" />
                    <SelectItem value="block" text="Block" />
                  </Select>
                </div>
                <Button
                  kind="primary"
                  size="sm"
                  renderIcon={Add}
                  onClick={() => {
                    setBolaRules((prev) => [
                      ...prev,
                      { name: '', resource_pattern: '', owner_id_param: 'id', allowed_roles: [] },
                    ]);
                    setExpandedBolaIndex(bolaRules.length);
                    markDirty();
                  }}
                >
                  + Add ownership rule
                </Button>
              </div>
            }
          />

          <div
            style={{
              padding: '12px 16px',
              background: 'var(--cds-layer-01)',
              border: '1px solid var(--cds-border-subtle)',
              marginBottom: '20px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                Verified token identity only:
              </span>
              <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                Ownership uses the verified subject or configured owner claim. Tenant routes must include <code>{'{tenant_id}'}</code>; inbound identity headers are ignored.
              </span>
            </div>
            <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', fontFamily: 'var(--cds-font-family-mono, monospace)' }}>
              {bolaRules.length} {bolaRules.length === 1 ? 'rule' : 'rules'}
            </span>
          </div>

          <div style={{ marginBottom: '24px' }}>
            <SectionCard
              title="Tenant-isolated paths"
              description="Routes where multi-tenant isolation boundaries are strictly enforced."
            >
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '16px' }}>
                {isolatedPaths.map((p, idx) => (
                  <Tag
                    key={idx}
                    type="cool-gray"
                    size="sm"
                    filter
                    onClose={() => {
                      setIsolatedPaths((prev) => prev.filter((_, i) => i !== idx));
                      markDirty();
                    }}
                  >
                    {p}
                  </Tag>
                ))}
              </div>
              <div style={{ display: 'flex', gap: '8px', maxWidth: '440px' }}>
                <TextInput
                  id="add-isolated-path"
                  hideLabel
                  labelText="Tenant Path"
                  placeholder="/api/tenants/{tenant_id}"
                  size="sm"
                  value={newIsolatedPath}
                  onChange={(e) => setNewIsolatedPath(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      if (newIsolatedPath.trim()) {
                        setIsolatedPaths((prev) => [...prev, newIsolatedPath.trim()]);
                        setNewIsolatedPath('');
                        markDirty();
                      }
                    }
                  }}
                />
                <Button
                  kind="secondary"
                  size="sm"
                  onClick={() => {
                    if (newIsolatedPath.trim()) {
                      setIsolatedPaths((prev) => [...prev, newIsolatedPath.trim()]);
                      setNewIsolatedPath('');
                      markDirty();
                    }
                  }}
                >
                  Add path
                </Button>
              </div>
            </SectionCard>
          </div>

          {bolaRules.length === 0 ? (
            <SectionCard padded={false}>
              <div style={{ textAlign: 'center', padding: '48px 24px' }}>
                <Security size={32} style={{ marginBottom: '12px', color: 'var(--cds-icon-secondary)' }} />
                <div style={{ fontWeight: 600, fontSize: '15px', color: 'var(--cds-text-primary)', marginBottom: '6px' }}>
                  No ownership rules yet
                </div>
                <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '20px' }}>
                  Add a rule to connect a resource identifier to the authenticated caller.
                </div>
                <Button
                  kind="primary"
                  size="sm"
                  renderIcon={Add}
                  onClick={() => {
                    setBolaRules([
                      { name: '', resource_pattern: '', owner_id_param: 'id', allowed_roles: [] },
                    ]);
                    setExpandedBolaIndex(0);
                    markDirty();
                  }}
                >
                  Add first rule
                </Button>
              </div>
            </SectionCard>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '24px' }}>
              {bolaRules.map((rule, idx) => {
                const isExpanded = expandedBolaIndex === idx;

                return (
                  <div
                    key={idx}
                    style={{
                      border: '1px solid var(--cds-border-subtle)',
                      background: 'var(--cds-layer-01)',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '12px 16px',
                        background: 'var(--cds-layer-02)',
                        borderBottom: isExpanded ? '1px solid var(--cds-border-subtle)' : 'none',
                        cursor: 'pointer',
                      }}
                      onClick={() => setExpandedBolaIndex(isExpanded ? null : idx)}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flex: 1, minWidth: 0 }}>
                        <span
                          style={{
                            fontFamily: 'var(--cds-font-family-mono, monospace)',
                            color: 'var(--cds-text-secondary)',
                            fontWeight: 600,
                            fontSize: '13px',
                            width: '24px',
                          }}
                        >
                          {String(idx + 1).padStart(2, '0')}
                        </span>
                        <div style={{ display: 'flex', flexDirection: 'column', minWidth: '220px' }}>
                          <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                            {rule.name || 'Untitled ownership rule'}
                          </strong>
                          <span
                            style={{
                              fontSize: '12px',
                              fontFamily: 'var(--cds-font-family-mono, monospace)',
                              color: 'var(--cds-text-secondary)',
                              marginTop: '2px',
                            }}
                          >
                            {rule.resource_pattern || 'Resource path not configured'}
                          </span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                          <span style={{ fontFamily: 'var(--cds-font-family-mono, monospace)' }}>
                            param: {rule.owner_id_param || 'id'}
                          </span>
                          <span>·</span>
                          <span>
                            {rule.allowed_roles.length > 0
                              ? `${rule.allowed_roles.length} bypass role${rule.allowed_roles.length === 1 ? '' : 's'}`
                              : 'No bypass roles'}
                          </span>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }} onClick={(e) => e.stopPropagation()}>
                        <Button
                          kind="ghost"
                          size="sm"
                          hasIconOnly
                          renderIcon={isExpanded ? ChevronDown : ChevronRight}
                          iconDescription="Toggle editor"
                          onClick={() => setExpandedBolaIndex(isExpanded ? null : idx)}
                        />
                        <Button
                          kind="danger--ghost"
                          size="sm"
                          hasIconOnly
                          renderIcon={TrashCan}
                          iconDescription="Remove rule"
                          onClick={() => {
                            setBolaRules((prev) => prev.filter((_, i) => i !== idx));
                            if (expandedBolaIndex === idx) setExpandedBolaIndex(null);
                            markDirty();
                          }}
                        />
                      </div>
                    </div>

                    {isExpanded && (
                      <div style={{ padding: '24px 20px', background: 'var(--cds-layer-01)' }}>
                        <div style={{ marginBottom: '24px' }}>
                          <div style={{ marginBottom: '14px' }}>
                            <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>Protected resource</strong>
                            <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                              Identify the resource path and the parameter that contains its owner ID.
                            </div>
                          </div>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
                            <TextInput
                              id={`bola-name-${idx}`}
                              labelText="Rule name"
                              placeholder="e.g. Account ownership"
                              value={rule.name}
                              onChange={(e) => {
                                const val = e.target.value;
                                setBolaRules((prev) => {
                                  const next = [...prev];
                                  next[idx] = { ...next[idx], name: val };
                                  return next;
                                });
                                markDirty();
                              }}
                            />
                            <TextInput
                              id={`bola-resource-${idx}`}
                              labelText="Resource path"
                              placeholder="e.g. /api/accounts/{id}"
                              value={rule.resource_pattern}
                              onChange={(e) => {
                                const val = e.target.value;
                                setBolaRules((prev) => {
                                  const next = [...prev];
                                  next[idx] = { ...next[idx], resource_pattern: val };
                                  return next;
                                });
                                markDirty();
                              }}
                            />
                            <TextInput
                              id={`bola-owner-id-${idx}`}
                              labelText="Owner ID parameter"
                              placeholder="id"
                              value={rule.owner_id_param || 'id'}
                              onChange={(e) => {
                                const val = e.target.value;
                                setBolaRules((prev) => {
                                  const next = [...prev];
                                  next[idx] = { ...next[idx], owner_id_param: val };
                                  return next;
                                });
                                markDirty();
                              }}
                            />
                          </div>
                        </div>

                        <div style={{ paddingTop: '20px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                          <div style={{ marginBottom: '14px' }}>
                            <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>Privileged bypass roles</strong>
                            <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                              Roles allowed to access the resource without requiring an ownership match.
                            </div>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
                            <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>Suggested roles:</span>
                            {commonRoles.map((r) => {
                              const isAdded = rule.allowed_roles.includes(r);
                              return (
                                <Button
                                  key={r}
                                  size="sm"
                                  kind="ghost"
                                  disabled={isAdded}
                                  onClick={() => {
                                    if (!isAdded) {
                                      setBolaRules((prev) => {
                                        const next = [...prev];
                                        next[idx] = { ...next[idx], allowed_roles: [...next[idx].allowed_roles, r] };
                                        return next;
                                      });
                                      markDirty();
                                    }
                                  }}
                                  style={{ minHeight: '26px', padding: '0 8px', fontSize: '11px' }}
                                >
                                  {isAdded ? `✓ ${r}` : `+ ${r}`}
                                </Button>
                              );
                            })}
                          </div>
                          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center', minHeight: '32px', marginBottom: '14px' }}>
                            {rule.allowed_roles.length === 0 ? (
                              <span style={{ fontSize: '12px', color: 'var(--cds-text-helper)', fontStyle: 'italic' }}>
                                No bypass roles configured (strict caller ownership required).
                              </span>
                            ) : (
                              rule.allowed_roles.map((r, rIdx) => (
                                <Tag
                                  key={rIdx}
                                  type="cool-gray"
                                  size="md"
                                  filter
                                  onClose={() => {
                                    setBolaRules((prev) => {
                                      const next = [...prev];
                                      next[idx] = {
                                        ...next[idx],
                                        allowed_roles: next[idx].allowed_roles.filter((x) => x !== r),
                                      };
                                      return next;
                                    });
                                    markDirty();
                                  }}
                                >
                                  {r}
                                </Tag>
                              ))
                            )}
                          </div>
                          <div style={{ display: 'flex', gap: '8px', maxWidth: '380px' }}>
                            <TextInput
                              id={`custom-bypass-role-${idx}`}
                              hideLabel
                              labelText="Bypass Role"
                              placeholder="Add role name (e.g. audit-service)"
                              size="sm"
                              value={newBolaRoleInputs[idx] || ''}
                              onChange={(e) =>
                                setNewBolaRoleInputs((prev) => ({ ...prev, [idx]: e.target.value }))
                              }
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                  e.preventDefault();
                                  const val = (newBolaRoleInputs[idx] || '').trim();
                                  if (val && !rule.allowed_roles.includes(val)) {
                                    setBolaRules((prev) => {
                                      const next = [...prev];
                                      next[idx] = { ...next[idx], allowed_roles: [...next[idx].allowed_roles, val] };
                                      return next;
                                    });
                                    setNewBolaRoleInputs((prev) => ({ ...prev, [idx]: '' }));
                                    markDirty();
                                  }
                                }
                              }}
                            />
                            <Button
                              kind="secondary"
                              size="sm"
                              onClick={() => {
                                const val = (newBolaRoleInputs[idx] || '').trim();
                                if (val && !rule.allowed_roles.includes(val)) {
                                  setBolaRules((prev) => {
                                    const next = [...prev];
                                    next[idx] = { ...next[idx], allowed_roles: [...next[idx].allowed_roles, val] };
                                    return next;
                                  });
                                  setNewBolaRoleInputs((prev) => ({ ...prev, [idx]: '' }));
                                  markDirty();
                                }
                              }}
                            >
                              Add role
                            </Button>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </>
      );
    }

    if (selectedAuthControl === 'fields') {
      const defaultSuggestions = ['role', 'is_admin', 'permissions', 'plan', 'balance', 'credit_limit'];

      return (
        <>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={ArrowLeft}
            onClick={() => setSelectedAuthControl(null)}
            style={{ marginBottom: '16px' }}
          >
            Back to authorization controls
          </Button>

          <PageHeader
            kicker="API security"
            title="Protected field rules"
            icon={DataBase}
            action={
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '130px' }}>
                  <Select
                    id="auth-mass-state-detail"
                    hideLabel
                    labelText="Protected Fields State"
                    size="sm"
                    value={massFieldsState}
                    onChange={(e) => {
                      setMassFieldsState(e.target.value as any);
                      markDirty();
                    }}
                  >
                    <SelectItem value="disable" text="Disable" />
                    <SelectItem value="detect" text="Monitor" />
                    <SelectItem value="block" text="Block" />
                  </Select>
                </div>
                <Button
                  kind="primary"
                  size="sm"
                  renderIcon={Add}
                  onClick={() => {
                    setMassPathRules((prev) => [
                      ...prev,
                      { path_pattern: '', fields: [] },
                    ]);
                    setExpandedMassIndex(massPathRules.length);
                    markDirty();
                  }}
                >
                  + Add path rule
                </Button>
              </div>
            }
          />

          <SectionCard
            title="Default protected fields"
            description="Applied to write requests unless a path rule defines a narrower field set."
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>Suggested fields:</span>
              {defaultSuggestions.map((f) => {
                const isAdded = massFields.includes(f);
                return (
                  <Button
                    key={f}
                    size="sm"
                    kind="ghost"
                    disabled={isAdded}
                    onClick={() => {
                      if (!isAdded) {
                        setMassFields((prev) => [...prev, f]);
                        markDirty();
                      }
                    }}
                    style={{ minHeight: '26px', padding: '0 8px', fontSize: '11px' }}
                  >
                    {isAdded ? `✓ ${f}` : `+ ${f}`}
                  </Button>
                );
              })}
            </div>

            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center', minHeight: '32px', marginBottom: '14px' }}>
              {massFields.length === 0 ? (
                <span style={{ fontSize: '12px', color: 'var(--cds-text-helper)', fontStyle: 'italic' }}>
                  No default protected fields configured.
                </span>
              ) : (
                massFields.map((field, idx) => (
                  <Tag
                    key={idx}
                    type="cool-gray"
                    size="md"
                    filter
                    onClose={() => {
                      setMassFields((prev) => prev.filter((_, i) => i !== idx));
                      markDirty();
                    }}
                  >
                    {field}
                  </Tag>
                ))
              )}
            </div>

            <div style={{ display: 'flex', gap: '8px', maxWidth: '380px' }}>
              <TextInput
                id="add-mass-field"
                hideLabel
                labelText="Custom Field"
                placeholder="Add field name (e.g. balance)"
                size="sm"
                value={newFieldInput}
                onChange={(e) => setNewFieldInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    const val = newFieldInput.trim();
                    if (val && !massFields.includes(val)) {
                      setMassFields((prev) => [...prev, val]);
                      setNewFieldInput('');
                      markDirty();
                    }
                  }
                }}
              />
              <Button
                kind="secondary"
                size="sm"
                onClick={() => {
                  const val = newFieldInput.trim();
                  if (val && !massFields.includes(val)) {
                    setMassFields((prev) => [...prev, val]);
                    setNewFieldInput('');
                    markDirty();
                  }
                }}
              >
                Add field
              </Button>
            </div>
          </SectionCard>

          <div style={{ marginTop: '24px' }}>
            {massPathRules.length === 0 ? (
              <SectionCard padded={false}>
                <div style={{ textAlign: 'center', padding: '48px 24px' }}>
                  <DataBase size={32} style={{ marginBottom: '12px', color: 'var(--cds-icon-secondary)' }} />
                  <div style={{ fontWeight: 600, fontSize: '15px', color: 'var(--cds-text-primary)', marginBottom: '6px' }}>
                    No path-specific rules
                  </div>
                  <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '20px' }}>
                    The default protected fields apply globally. Add a path rule when an endpoint needs a narrower field set.
                  </div>
                  <Button
                    kind="primary"
                    size="sm"
                    renderIcon={Add}
                    onClick={() => {
                      setMassPathRules([
                        { path_pattern: '', fields: [] },
                      ]);
                      setExpandedMassIndex(0);
                      markDirty();
                    }}
                  >
                    Add first path rule
                  </Button>
                </div>
              </SectionCard>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {massPathRules.map((rule, idx) => {
                  const isExpanded = expandedMassIndex === idx;

                  return (
                    <div
                      key={idx}
                      style={{
                        border: '1px solid var(--cds-border-subtle)',
                        background: 'var(--cds-layer-01)',
                        overflow: 'hidden',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '12px 16px',
                          background: 'var(--cds-layer-02)',
                          borderBottom: isExpanded ? '1px solid var(--cds-border-subtle)' : 'none',
                          cursor: 'pointer',
                        }}
                        onClick={() => setExpandedMassIndex(isExpanded ? null : idx)}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flex: 1, minWidth: 0 }}>
                          <span
                            style={{
                              fontFamily: 'var(--cds-font-family-mono, monospace)',
                              color: 'var(--cds-text-secondary)',
                              fontWeight: 600,
                              fontSize: '13px',
                              width: '24px',
                            }}
                          >
                            {String(idx + 1).padStart(2, '0')}
                          </span>
                          <div style={{ display: 'flex', flexDirection: 'column', minWidth: '220px' }}>
                            <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                              {rule.path_pattern || 'Untitled path rule'}
                            </strong>
                            <span
                              style={{
                                fontSize: '12px',
                                fontFamily: 'var(--cds-font-family-mono, monospace)',
                                color: 'var(--cds-text-secondary)',
                                marginTop: '2px',
                              }}
                            >
                              {rule.path_pattern || 'Path not configured'}
                            </span>
                          </div>
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                            {rule.fields.length} protected field{rule.fields.length === 1 ? '' : 's'}
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }} onClick={(e) => e.stopPropagation()}>
                          <Button
                            kind="ghost"
                            size="sm"
                            hasIconOnly
                            renderIcon={isExpanded ? ChevronDown : ChevronRight}
                            iconDescription="Toggle editor"
                            onClick={() => setExpandedMassIndex(isExpanded ? null : idx)}
                          />
                          <Button
                            kind="danger--ghost"
                            size="sm"
                            hasIconOnly
                            renderIcon={TrashCan}
                            iconDescription="Remove rule"
                            onClick={() => {
                              setMassPathRules((prev) => prev.filter((_, i) => i !== idx));
                              if (expandedMassIndex === idx) setExpandedMassIndex(null);
                              markDirty();
                            }}
                          />
                        </div>
                      </div>

                      {isExpanded && (
                        <div style={{ padding: '24px 20px', background: 'var(--cds-layer-01)' }}>
                          <div style={{ marginBottom: '24px' }}>
                            <div style={{ marginBottom: '14px' }}>
                              <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>Endpoint scope</strong>
                              <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                                Choose the write endpoint that needs its own protected-field set.
                              </div>
                            </div>
                            <TextInput
                              id={`mass-path-pattern-${idx}`}
                              labelText="Path pattern"
                              placeholder="e.g. /api/accounts/{id}"
                              value={rule.path_pattern}
                              onChange={(e) => {
                                const val = e.target.value;
                                setMassPathRules((prev) => {
                                  const next = [...prev];
                                  next[idx] = { ...next[idx], path_pattern: val };
                                  return next;
                                });
                                markDirty();
                              }}
                            />
                          </div>

                          <div style={{ paddingTop: '20px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                            <div style={{ marginBottom: '14px' }}>
                              <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>Fields protected on this path</strong>
                              <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                                This list replaces the defaults for requests matching this path.
                              </div>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
                              <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>Suggested fields:</span>
                              {defaultSuggestions.map((f) => {
                                const isAdded = rule.fields.includes(f);
                                return (
                                  <Button
                                    key={f}
                                    size="sm"
                                    kind="ghost"
                                    disabled={isAdded}
                                    onClick={() => {
                                      if (!isAdded) {
                                        setMassPathRules((prev) => {
                                          const next = [...prev];
                                          next[idx] = { ...next[idx], fields: [...next[idx].fields, f] };
                                          return next;
                                        });
                                        markDirty();
                                      }
                                    }}
                                    style={{ minHeight: '26px', padding: '0 8px', fontSize: '11px' }}
                                  >
                                    {isAdded ? `✓ ${f}` : `+ ${f}`}
                                  </Button>
                                );
                              })}
                            </div>
                            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center', minHeight: '32px', marginBottom: '14px' }}>
                              {rule.fields.length === 0 ? (
                                <span style={{ fontSize: '12px', color: 'var(--cds-text-helper)', fontStyle: 'italic' }}>
                                  No path fields configured.
                                </span>
                              ) : (
                                rule.fields.map((f, fIdx) => (
                                  <Tag
                                    key={fIdx}
                                    type="cool-gray"
                                    size="md"
                                    filter
                                    onClose={() => {
                                      setMassPathRules((prev) => {
                                        const next = [...prev];
                                        next[idx] = {
                                          ...next[idx],
                                          fields: next[idx].fields.filter((x) => x !== f),
                                        };
                                        return next;
                                      });
                                      markDirty();
                                    }}
                                  >
                                    {f}
                                  </Tag>
                                ))
                              )}
                            </div>
                            <div style={{ display: 'flex', gap: '8px', maxWidth: '380px' }}>
                              <TextInput
                                id={`custom-path-field-${idx}`}
                                hideLabel
                                labelText="Path Field"
                                placeholder="Add field name (e.g. permissions)"
                                size="sm"
                                value={newMassRuleFieldInputs[idx] || ''}
                                onChange={(e) =>
                                  setNewMassRuleFieldInputs((prev) => ({ ...prev, [idx]: e.target.value }))
                                }
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter') {
                                    e.preventDefault();
                                    const val = (newMassRuleFieldInputs[idx] || '').trim();
                                    if (val && !rule.fields.includes(val)) {
                                      setMassPathRules((prev) => {
                                        const next = [...prev];
                                        next[idx] = { ...next[idx], fields: [...next[idx].fields, val] };
                                        return next;
                                      });
                                      setNewMassRuleFieldInputs((prev) => ({ ...prev, [idx]: '' }));
                                      markDirty();
                                    }
                                  }
                                }}
                              />
                              <Button
                                kind="secondary"
                                size="sm"
                                onClick={() => {
                                  const val = (newMassRuleFieldInputs[idx] || '').trim();
                                  if (val && !rule.fields.includes(val)) {
                                    setMassPathRules((prev) => {
                                      const next = [...prev];
                                      next[idx] = { ...next[idx], fields: [...next[idx].fields, val] };
                                      return next;
                                    });
                                    setNewMassRuleFieldInputs((prev) => ({ ...prev, [idx]: '' }));
                                    markDirty();
                                  }
                                }}
                              >
                                Add field
                              </Button>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      );
    }

    return (
      <>
        <PageHeader
          kicker="API security"
          title="Authorization"
          icon={Locked}
          action={
            <Button
              kind="tertiary"
              size="sm"
              onClick={() => onNavigate && onNavigate('edge-access')}
            >
              Edge Access Identity
            </Button>
          }
        />

        <SectionCard padded={false}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '20px 24px',
              borderBottom: '1px solid var(--cds-border-subtle)',
              cursor: 'pointer',
              transition: 'background-color 0.15s ease',
            }}
            onClick={() => {
              setSelectedAuthControl('function');
              setExpandedBflaIndex(bflaRules.length > 0 ? 0 : null);
            }}
            onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--cds-layer-hover, var(--cds-layer-02))')}
            onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
              <Locked size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                  Function authorization
                </div>
                <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  Method and path actions with role and claim allow rules.
                </div>
              </div>
            </div>
            <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '20px 24px',
              borderBottom: '1px solid var(--cds-border-subtle)',
              cursor: 'pointer',
              transition: 'background-color 0.15s ease',
            }}
            onClick={() => {
              setSelectedAuthControl('object');
              setExpandedBolaIndex(bolaRules.length > 0 ? 0 : null);
            }}
            onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--cds-layer-hover, var(--cds-layer-02))')}
            onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
              <Security size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                  Object and tenant authorization
                </div>
                <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  Ownership, tenant isolation, and IDOR controls using trusted identity.
                </div>
              </div>
            </div>
            <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '20px 24px',
              borderBottom: '1px solid var(--cds-border-subtle)',
              cursor: 'pointer',
              transition: 'background-color 0.15s ease',
            }}
            onClick={() => {
              setSelectedAuthControl('fields');
              setExpandedMassIndex(massPathRules.length > 0 ? 0 : null);
            }}
            onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--cds-layer-hover, var(--cds-layer-02))')}
            onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
              <DataBase size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                  Protected request fields
                </div>
                <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  Prevent mass assignment of fields that should remain under server control.
                </div>
              </div>
            </div>
            <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '20px 24px',
              cursor: 'pointer',
              transition: 'background-color 0.15s ease',
            }}
            onClick={() => setSelectedAuthControl('tokens')}
            onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--cds-layer-hover, var(--cds-layer-02))')}
            onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
              <Locked size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                  Identity & Token Verification
                </div>
                <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  Validate JWT tokens, verify signatures against JWKS endpoints, and enforce token issuers.
                </div>
              </div>
            </div>
            <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
          </div>
        </SectionCard>
      </>
    );
  };

  const renderGraphQLView = () => {
    const activePreset = getGraphQLLimitPreset();

    if (selectedGraphQLControl === 'limits') {
      const presets = [
        {
          id: 'strict',
          title: 'Strict',
          description: 'Lower depth, aliases, batch, and complexity.',
        },
        {
          id: 'standard',
          title: 'Standard',
          description: 'Balanced production limits with introspection blocked.',
        },
        {
          id: 'relaxed',
          title: 'Relaxed',
          description: 'Higher limits while monitoring onboarding traffic.',
        },
      ] as const;

      return (
        <>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={ArrowLeft}
            onClick={() => setSelectedGraphQLControl(null)}
            style={{ marginBottom: '16px' }}
          >
            Back to GraphQL protection
          </Button>

          <PageHeader
            kicker="API security"
            title="Query execution limits"
            icon={SettingsAdjust}
          />

          <SectionCard
            title="Limit profile"
          >
            <div style={{ marginBottom: '28px' }}>
              <TileGroup
                name="gql-limits-preset"
                legend=""
                valueSelected={activePreset}
                onChange={(val) => applyGraphQLPreset(val as any)}
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                  gap: '16px',
                }}
              >
                {presets.map((p) => (
                  <RadioTile key={p.id} id={`preset-${p.id}`} value={p.id}>
                    <div style={{ padding: '4px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                        <SettingsAdjust size={16} style={{ color: 'var(--cds-interactive)' }} />
                        <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                          {p.title}
                        </strong>
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', lineHeight: 1.4 }}>
                        {p.description}
                      </div>
                    </div>
                  </RadioTile>
                ))}
              </TileGroup>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: '20px',
                paddingTop: '20px',
                borderTop: '1px solid var(--cds-border-subtle)',
              }}
            >
              <NumberInput
                id="gql-depth"
                label="Maximum depth"
                size="md"
                min={1}
                max={100}
                value={graphqlMaxDepth}
                onChange={(_, { value }) => {
                  setGraphqlMaxDepth(Number(value) || 15);
                  markDirty();
                }}
              />
              <NumberInput
                id="gql-aliases"
                label="Maximum aliases"
                size="md"
                min={1}
                max={200}
                value={graphqlMaxAliases}
                onChange={(_, { value }) => {
                  setGraphqlMaxAliases(Number(value) || 25);
                  markDirty();
                }}
              />
              <NumberInput
                id="gql-batch"
                label="Maximum batch size"
                size="md"
                min={1}
                max={50}
                value={graphqlMaxBatchSize}
                onChange={(_, { value }) => {
                  setGraphqlMaxBatchSize(Number(value) || 5);
                  markDirty();
                }}
              />
              <NumberInput
                id="gql-complexity"
                label="Maximum complexity"
                size="md"
                min={10}
                max={10000}
                value={graphqlMaxComplexity}
                onChange={(_, { value }) => {
                  setGraphqlMaxComplexity(Number(value) || 500);
                  markDirty();
                }}
              />
            </div>
          </SectionCard>
        </>
      );
    }

    if (selectedGraphQLControl === 'schema') {
      return (
        <>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={ArrowLeft}
            onClick={() => setSelectedGraphQLControl(null)}
            style={{ marginBottom: '16px' }}
          >
            Back to GraphQL protection
          </Button>

          <PageHeader
            kicker="API security"
            title="Schema exposure"
            icon={Security}
          />

          <SectionCard
            title="Introspection access"
            description="Choose whether clients can enumerate the GraphQL schema."
          >
            <TileGroup
              name="gql-introspection-mode"
              legend=""
              valueSelected={graphqlIntrospectionPolicy}
              onChange={(val) => {
                setGraphqlIntrospectionPolicy(val as any);
                markDirty();
              }}
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                gap: '16px',
              }}
            >
              <RadioTile id="gql-intro-block" value="block">
                <div style={{ padding: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Security size={18} style={{ color: 'var(--cds-support-success, #42be65)' }} />
                      <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                        Block introspection
                      </strong>
                    </div>
                    <Tag type="green" size="sm">Recommended</Tag>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', lineHeight: 1.4 }}>
                    Reject schema enumeration requests to prevent unauthorized API reconnaissance.
                  </div>
                </div>
              </RadioTile>

              <RadioTile id="gql-intro-allow" value="disable">
                <div style={{ padding: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Code size={18} style={{ color: 'var(--cds-support-warning, #f1c21b)' }} />
                      <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                        Allow introspection
                      </strong>
                    </div>
                    <Tag type="warm-gray" size="sm">Development only</Tag>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', lineHeight: 1.4 }}>
                    Permit schema enumeration for clients, developer tools, and public documentation.
                  </div>
                </div>
              </RadioTile>
            </TileGroup>
          </SectionCard>
        </>
      );
    }

    const presetLabel = activePreset === 'custom' ? 'Custom limits' : `${activePreset.charAt(0).toUpperCase() + activePreset.slice(1)} profile`;

    return (
      <>
        <PageHeader
          kicker="API security"
          title="GraphQL"
          icon={Code}
        />

        <MetricStrip minColWidth="220px">
          <KpiCard
            label="GraphQL Request Policy"
            value={graphqlState.toUpperCase()}
            subtext="Query violation enforcement"
            status="default"
          />
          <KpiCard
            label="Execution Profile"
            value={presetLabel}
            subtext={`Depth ${graphqlMaxDepth} · Complexity ${graphqlMaxComplexity}`}
            status="default"
          />
          <KpiCard
            label="Schema Introspection"
            value={graphqlIntrospectionPolicy === 'block' ? 'Blocked' : 'Exposed'}
            subtext={graphqlIntrospectionPolicy === 'block' ? 'Schema enumeration denied' : 'Introspection queries allowed'}
            status="default"
          />
          <KpiCard
            label="Protected Endpoints"
            value={`${graphqlPaths.length} Paths`}
            subtext="Configured GraphQL routes"
            status="default"
          />
        </MetricStrip>

        <div style={{ marginBottom: '24px' }}>
          <SectionCard
            title="GraphQL request policy"
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
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
                <Code size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                    GraphQL request policy
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    Choose whether GraphQL requests exceeding depth or complexity limits are logged (Detect) or rejected (Block).
                  </div>
                </div>
              </div>
              <div style={{ width: '180px', flexShrink: 0 }}>
                <Select
                  id="gql-request-policy"
                  hideLabel
                  labelText="GraphQL request policy"
                  size="sm"
                  value={graphqlState}
                  onChange={(e) => {
                    setGraphqlState(e.target.value as any);
                    markDirty();
                  }}
                >
                  <SelectItem value="disable" text="Disable" />
                  <SelectItem value="detect" text="Monitor" />
                  <SelectItem value="block" text="Block" />
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
                cursor: 'pointer',
                transition: 'background-color 0.15s ease',
              }}
              onClick={() => setSelectedGraphQLControl('limits')}
              onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--cds-layer-hover, var(--cds-layer-02))')}
              onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
                <SettingsAdjust size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                    Query execution limits
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    {presetLabel} · Depth {graphqlMaxDepth} · Complexity {graphqlMaxComplexity}.
                  </div>
                </div>
              </div>
              <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '20px 24px',
                cursor: 'pointer',
                transition: 'background-color 0.15s ease',
              }}
              onClick={() => setSelectedGraphQLControl('schema')}
              onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--cds-layer-hover, var(--cds-layer-02))')}
              onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
                <Security size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                    Schema exposure
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    {graphqlIntrospectionPolicy === 'block'
                      ? 'Schema introspection is blocked to prevent unauthorized API enumeration.'
                      : 'Schema introspection is enabled for development and exploration.'}
                  </div>
                </div>
              </div>
              <ChevronRight size={20} style={{ color: 'var(--cds-icon-secondary)' }} />
            </div>
          </SectionCard>
        </div>

        <SectionCard
          title="Configured GraphQL paths"
          description="Every endpoint protected by this policy."
          action={
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                {graphqlPaths.length} protected path{graphqlPaths.length === 1 ? '' : 's'}
              </span>
              <Button
                kind="primary"
                size="sm"
                onClick={() => setIsPathModalOpen(true)}
              >
                {graphqlPaths.length ? 'Edit paths' : 'Add GraphQL paths'}
              </Button>
            </div>
          }
          padded={false}
        >
          {graphqlPaths.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '48px 24px' }}>
              <List size={32} style={{ marginBottom: '12px', color: 'var(--cds-icon-secondary)' }} />
              <div style={{ fontWeight: 600, fontSize: '15px', color: 'var(--cds-text-primary)', marginBottom: '6px' }}>
                No GraphQL paths configured
              </div>
              <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '20px' }}>
                Select Add GraphQL paths to choose endpoints for this policy.
              </div>
              <Button
                kind="primary"
                size="sm"
                onClick={() => setIsPathModalOpen(true)}
              >
                Add GraphQL paths
              </Button>
            </div>
          ) : (
            <Table aria-label="Configured GraphQL paths">
              <TableHead>
                <TableRow>
                  <TableHeader>GraphQL Path</TableHeader>
                  <TableHeader>Policy Coverage</TableHeader>
                  <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
                </TableRow>
              </TableHead>
              <TableBody>
                {graphqlPaths.map((p, idx) => (
                  <TableRow key={idx}>
                    <TableCell style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                      {p}
                    </TableCell>
                    <TableCell>
                      <Tag type="blue" size="sm">
                        Protected
                      </Tag>
                    </TableCell>
                    <TableCell style={{ textAlign: 'right' }}>
                      <Button
                        kind="danger--ghost"
                        size="sm"
                        hasIconOnly
                        renderIcon={TrashCan}
                        iconDescription="Remove path"
                        onClick={() => {
                          setGraphqlPaths((prev) => prev.filter((_, i) => i !== idx));
                          markDirty();
                        }}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </SectionCard>

        <Modal
          open={isPathModalOpen}
          onRequestClose={() => {
            setIsPathModalOpen(false);
            setNewGraphqlPath('');
          }}
          modalHeading="Configured GraphQL Paths"
          primaryButtonText="Done"
          onRequestSubmit={() => {
            setIsPathModalOpen(false);
            setNewGraphqlPath('');
          }}
          size="md"
        >
          <div style={{ marginBottom: '20px' }}>
            <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', marginBottom: '16px' }}>
              Add or remove endpoint paths that will be subject to GraphQL depth, complexity, and introspection defenses.
            </div>

            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-primary)', marginBottom: '8px' }}>
                Common endpoint suggestions:
              </div>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {['/graphql', '/api/graphql', '/v1/graphql', '/v2/graphql'].map((sug) => {
                  const alreadyAdded = graphqlPaths.includes(sug);
                  return (
                    <Button
                      key={sug}
                      kind={alreadyAdded ? 'ghost' : 'tertiary'}
                      size="sm"
                      disabled={alreadyAdded}
                      onClick={() => {
                        if (!alreadyAdded) {
                          setGraphqlPaths((prev) => [...prev, sug]);
                          markDirty();
                        }
                      }}
                    >
                      {alreadyAdded ? `${sug} (Added)` : `+ ${sug}`}
                    </Button>
                  );
                })}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-end', marginBottom: '24px' }}>
              <TextInput
                id="modal-add-graphql-path"
                labelText="Custom GraphQL Route Path"
                placeholder="/custom/graphql"
                value={newGraphqlPath}
                onChange={(e) => setNewGraphqlPath(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    if (newGraphqlPath.trim() && !graphqlPaths.includes(newGraphqlPath.trim())) {
                      setGraphqlPaths((prev) => [...prev, newGraphqlPath.trim()]);
                      setNewGraphqlPath('');
                      markDirty();
                    }
                  }
                }}
              />
              <Button
                kind="secondary"
                size="md"
                onClick={() => {
                  if (newGraphqlPath.trim() && !graphqlPaths.includes(newGraphqlPath.trim())) {
                    setGraphqlPaths((prev) => [...prev, newGraphqlPath.trim()]);
                    setNewGraphqlPath('');
                    markDirty();
                  }
                }}
              >
                Add Path
              </Button>
            </div>

            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-primary)', marginBottom: '8px' }}>
                Currently configured ({graphqlPaths.length}):
              </div>
              {graphqlPaths.length === 0 ? (
                <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', fontStyle: 'italic' }}>
                  No paths configured yet.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {graphqlPaths.map((p, idx) => (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 12px',
                        background: 'var(--cds-layer-02)',
                        border: '1px solid var(--cds-border-subtle)',
                      }}
                    >
                      <span style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontSize: '13px', fontWeight: 600 }}>
                        {p}
                      </span>
                      <Button
                        kind="danger--ghost"
                        size="sm"
                        hasIconOnly
                        renderIcon={TrashCan}
                        iconDescription="Remove path"
                        onClick={() => {
                          setGraphqlPaths((prev) => prev.filter((_, i) => i !== idx));
                          markDirty();
                        }}
                      />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </Modal>
      </>
    );
  };

  const renderRuntimeView = () => {
    return (
      <>
        <PageHeader
          kicker="API security"
          title="Runtime Inspection"
          icon={Security}
          action={
            <Button
              kind="ghost"
              size="sm"
              renderIcon={ArrowLeft}
              onClick={() => setSubPolicy(null)}
            >
              Back to Overview
            </Button>
          }
        />

        <div style={{ marginBottom: '32px' }}>
          <SectionCard
            title="Protection modules"
            padded={false}
          >
            {renderControlRow(
              'Injection Protection',
              'Runtime attack payloads including SQLi, NoSQLi, CMDi, and XSS.',
              <Select
                id="runtime-inj-state"
                hideLabel
                labelText="Injection Protection"
                size="sm"
                value={injectionState}
                onChange={(e) => {
                  setInjectionState(e.target.value as any);
                  markDirty();
                }}
              >
                <SelectItem value="disable" text="Disable" />
                <SelectItem value="detect" text="Monitor" />
                <SelectItem value="block" text="Block" />
              </Select>,
              Security
            )}

            {renderControlRow(
              'SSRF Protection',
              'Unsafe URL and IP targets, private networks (RFC 1918), and cloud metadata.',
              <Select
                id="runtime-ssrf-state"
                hideLabel
                labelText="SSRF Protection"
                size="sm"
                value={ssrfState}
                onChange={(e) => {
                  setSsrfState(e.target.value as any);
                  markDirty();
                }}
              >
                <SelectItem value="disable" text="Disable" />
                <SelectItem value="detect" text="Monitor" />
                <SelectItem value="block" text="Block" />
              </Select>,
              Security
            )}

            {renderControlRow(
              'Payload Abuse Protection',
              'Malformed or abusive payloads, JSON nesting bombs, and chunked buffer exhaustion.',
              <Select
                id="runtime-payload-state"
                hideLabel
                labelText="Payload Abuse Protection"
                size="sm"
                value={payloadState}
                onChange={(e) => {
                  setPayloadState(e.target.value as any);
                  markDirty();
                }}
              >
                <SelectItem value="disable" text="Disable" />
                <SelectItem value="detect" text="Monitor" />
                <SelectItem value="block" text="Block" />
              </Select>,
              WarningAlt,
              true
            )}
          </SectionCard>
        </div>

        <SectionCard
          title="Sensitivity"
          padded={false}
        >
          {renderControlRow(
            'Injection Sensitivity',
            'Algorithmic detection sensitivity for runtime injection attacks.',
            <Select
              id="runtime-inj-sens"
              hideLabel
              labelText="Injection Sensitivity"
              size="sm"
              value={injectionSensitivity}
              onChange={(e) => {
                setInjectionSensitivity(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="low" text="Low (PL1)" />
              <SelectItem value="medium" text="Medium (PL2)" />
              <SelectItem value="high" text="High (PL3)" />
            </Select>,
            SettingsAdjust
          )}

          {renderControlRow(
            'Payload Sensitivity',
            'Detection sensitivity and maximum payload buffer thresholds.',
            <Select
              id="runtime-pay-sens"
              hideLabel
              labelText="Payload Sensitivity"
              size="sm"
              value={payloadSensitivity}
              onChange={(e) => {
                setPayloadSensitivity(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="balanced" text="Balanced" />
              <SelectItem value="strict" text="Strict" />
            </Select>,
            Layers,
            true
          )}
        </SectionCard>
      </>
    );
  };

  const renderAbuseView = () => {
    return (
      <>
        <PageHeader
          kicker="API security"
          title="Abuse Defense"
          icon={WarningAlt}
          action={
            <Button
              kind="ghost"
              size="sm"
              renderIcon={ArrowLeft}
              onClick={() => setSubPolicy(null)}
            >
              Back to Overview
            </Button>
          }
        />

        <SectionCard
          title="Automation controls"
          padded={false}
        >
          {renderControlRow(
            'Credential Stuffing Defense',
            'Mitigate automated credential testing against authentication routes.',
            <Select
              id="abuse-cred-state"
              hideLabel
              labelText="Credential Stuffing"
              size="sm"
              value={credentialStuffingState}
              onChange={(e) => {
                setCredentialStuffingState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            WarningAlt
          )}

          {renderControlRow(
            'OTP Brute Force Mitigation',
            'Detects rapid verification attempts against one-time codes.',
            <Select
              id="abuse-otp-state"
              hideLabel
              labelText="OTP Brute Force"
              size="sm"
              value={otpBruteforceState}
              onChange={(e) => {
                setOtpBruteforceState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            WarningAlt
          )}

          {renderControlRow(
            'Forced Browsing & Path Probing',
            'Identifies directory brute-forcing, file probing, and wordlist traversals.',
            <Select
              id="abuse-forced-state"
              hideLabel
              labelText="Forced Browsing"
              size="sm"
              value={forcedBrowsingState}
              onChange={(e) => {
                setForcedBrowsingState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            Security
          )}

          {renderControlRow(
            'User & Account Enumeration',
            'Detects timing and error pattern probing for valid accounts.',
            <Select
              id="abuse-user-enum-state"
              hideLabel
              labelText="User Enumeration"
              size="sm"
              value={userEnumerationState}
              onChange={(e) => {
                setUserEnumerationState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            Locked
          )}

          {renderControlRow(
            'Object ID Sequence Enumeration',
            'Flags incremental numeric or sequential UUID walk patterns.',
            <Select
              id="abuse-obj-enum-state"
              hideLabel
              labelText="Object Enumeration"
              size="sm"
              value={objectEnumerationState}
              onChange={(e) => {
                setObjectEnumerationState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            DataBase
          )}

          {renderControlRow(
            'High-Volume Data Scraping Guard',
            'Detects distributed harvesting of catalog, product, and pricing APIs.',
            <Select
              id="abuse-scraping-state"
              hideLabel
              labelText="Scraping Guard"
              size="sm"
              value={scrapingState}
              onChange={(e) => {
                setScrapingState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            Activity
          )}

          {renderControlRow(
            'Detection Sensitivity',
            'Algorithmic sensitivity for behavioral automation scoring.',
            <Select
              id="abuse-sens"
              hideLabel
              labelText="Sensitivity"
              size="sm"
              value={automationSensitivity}
              onChange={(e) => {
                setAutomationSensitivity(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="balanced" text="Balanced" />
              <SelectItem value="strict" text="Strict" />
            </Select>,
            SettingsAdjust,
            true
          )}
        </SectionCard>
      </>
    );
  };

  const renderDataExposureView = () => {
    return (
      <>
        <PageHeader
          kicker="API security"
          title="Data Leak Protection"
          icon={DataBase}
          action={
            <Button
              kind="ghost"
              size="sm"
              renderIcon={ArrowLeft}
              onClick={() => setSubPolicy(null)}
            >
              Back to Overview
            </Button>
          }
        />

        <SectionCard
          title="Data exposure controls"
          padded={false}
        >
          {renderControlRow(
            'Response Leak Handling',
            'Action taken when sensitive outbound server data is detected.',
            <Select
              id="de-leak-handling"
              hideLabel
              labelText="Leak Handling"
              size="sm"
              value={responseLeakHandling}
              onChange={(e) => {
                setResponseLeakHandling(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="block" text="Block Connection" />
              <SelectItem value="redact" text="Redact in Transit" />
              <SelectItem value="disable" text="Disable" />
            </Select>,
            Security
          )}

          {renderControlRow(
            'Personally Identifiable Information (PII)',
            'SSNs, national IDs, email addresses, and phone numbers in response bodies.',
            <Select
              id="de-pii-state"
              hideLabel
              labelText="PII Detection"
              size="sm"
              value={piiState}
              onChange={(e) => {
                setPiiState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            DataBase
          )}

          {renderControlRow(
            'Secrets & API Keys',
            'AWS, GitHub, Stripe keys, PEM private keys, and API tokens.',
            <Select
              id="de-secrets-state"
              hideLabel
              labelText="Secrets Detection"
              size="sm"
              value={secretsState}
              onChange={(e) => {
                setSecretsState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            Locked
          )}

          {renderControlRow(
            'Auth Tokens in Responses',
            'Accidental JWTs or session cookies rendered in output data.',
            <Select
              id="de-tokens-state"
              hideLabel
              labelText="Token Detection"
              size="sm"
              value={tokensState}
              onChange={(e) => {
                setTokensState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            Locked
          )}

          {renderControlRow(
            'Payment & Financial Data (PCI DSS)',
            'Credit card numbers, CVVs, IBAN, and bank account records.',
            <Select
              id="de-payment-state"
              hideLabel
              labelText="Payment Data Detection"
              size="sm"
              value={paymentDataState}
              onChange={(e) => {
                setPaymentDataState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            Document
          )}

          {renderControlRow(
            'Debug Error Dumps & Stack Traces',
            'Internal database exceptions, Go panics, and framework trace logs.',
            <Select
              id="de-debug-state"
              hideLabel
              labelText="Debug Data Detection"
              size="sm"
              value={debugDataState}
              onChange={(e) => {
                setDebugDataState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            WarningAlt
          )}

          {renderControlRow(
            'Internal Server IP & Hostname Leaks',
            'Headers and bodies exposing internal origin IP addresses.',
            <Select
              id="de-internal-state"
              hideLabel
              labelText="Internal IP Detection"
              size="sm"
              value={internalDataState}
              onChange={(e) => {
                setInternalDataState(e.target.value as any);
                markDirty();
              }}
            >
              <SelectItem value="disable" text="Disable" />
              <SelectItem value="detect" text="Monitor" />
              <SelectItem value="block" text="Block" />
            </Select>,
            Activity,
            true
          )}
        </SectionCard>
      </>
    );
  };

  const renderCurrentView = () => {
    switch (activeNavKey) {
      case 'api-inventory':
        return renderInventoryView();
      case 'api-contracts':
        return renderContractsView();
      case 'api-authorization':
        return renderAuthorizationView();
      case 'api-graphql':
        return renderGraphQLView();
      default: {
        if (subPolicy === 'runtime') return renderRuntimeView();
        if (subPolicy === 'abuse') return renderAbuseView();
        if (subPolicy === 'data') return renderDataExposureView();
        return renderOverviewView();
      }
    }
  };

  return (
    <div style={{ padding: '32px 32px 100px', width: '100%', boxSizing: 'border-box' }}>
      {notification && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      {renderCurrentView()}

      <Modal
        open={schemaModalOpen}
        modalHeading="Upload OpenAPI or GraphQL Schema"
        primaryButtonText={uploadSubmitting ? 'Compiling...' : 'Attach & Compile Schema'}
        secondaryButtonText="Cancel"
        onRequestClose={() => setSchemaModalOpen(false)}
        onRequestSubmit={handleUploadSchema}
        primaryButtonDisabled={uploadSubmitting}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '16px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 120px', gap: '16px' }}>
            <TextInput
              id="modal-upload-host"
              labelText="Host Domain"
              placeholder="api.example.com"
              value={uploadHost}
              onChange={(e) => setUploadHost(e.target.value)}
            />
            <TextInput
              id="modal-upload-path"
              labelText="Base Route Prefix"
              placeholder="/api/v1"
              value={uploadPath}
              onChange={(e) => setUploadPath(e.target.value)}
            />
            <Select
              id="modal-upload-method"
              labelText="Method"
              value={uploadMethod}
              onChange={(e) => setUploadMethod(e.target.value)}
            >
              <SelectItem value="GET" text="GET" />
              <SelectItem value="POST" text="POST" />
              <SelectItem value="PUT" text="PUT" />
              <SelectItem value="DELETE" text="DELETE" />
              <SelectItem value="PATCH" text="PATCH" />
              <SelectItem value="ALL" text="ALL" />
            </Select>
          </div>

          <Select
            id="modal-upload-type"
            labelText="Schema Format Specification"
            value={uploadType}
            onChange={(e) => setUploadType(e.target.value as any)}
          >
            <SelectItem value="openapi" text="OpenAPI 3.0 / 3.1 (JSON or YAML)" />
            <SelectItem value="graphql" text="GraphQL SDL (Schema Definition Language)" />
          </Select>

          <TextArea
            id="modal-upload-content"
            labelText="Schema Definition Content"
            placeholder="Paste your OpenAPI 3.0 JSON / YAML or GraphQL SDL schema here..."
            rows={10}
            value={uploadContent}
            onChange={(e) => setUploadContent(e.target.value)}
            style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontSize: '12px' }}
          />
        </div>
      </Modal>

      {selectedEndpoint && (
        <Modal
          open={Boolean(selectedEndpoint)}
          modalHeading={`Endpoint details: ${selectedEndpoint.method || ''} ${selectedEndpoint.path || ''}`}
          primaryButtonText="Close"
          onRequestClose={() => setSelectedEndpoint(null)}
          onRequestSubmit={() => setSelectedEndpoint(null)}
          passiveModal
        >
          <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <Tag type="outline" size="sm">{selectedEndpoint.method || 'GET'}</Tag>
              <Tag type={selectedEndpoint.schema_status === 'covered' ? 'green' : 'cool-gray'} size="sm">
                {selectedEndpoint.schema_status || 'missing'}
              </Tag>
              <Tag type={getRiskTagType(selectedEndpoint.risk_status)} size="sm">
                {selectedEndpoint.risk_status || 'normal'}
              </Tag>
            </div>

            <div style={{ background: 'var(--cds-layer-01)', padding: '16px', border: '1px solid var(--cds-border-subtle)' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '13px' }}>
                <div><strong>Host:</strong> {selectedEndpoint.host || '-'}</div>
                <div><strong>Service:</strong> {selectedEndpoint.service || '-'}</div>
                <div><strong>Owner:</strong> {selectedEndpoint.owner || '-'}</div>
                <div><strong>Environment:</strong> {selectedEndpoint.environment || '-'}</div>
                <div><strong>First observed:</strong> {selectedEndpoint.first_seen || '-'}</div>
                <div><strong>Last observed:</strong> {selectedEndpoint.last_seen || '-'}</div>
                <div><strong>Criticality:</strong> {selectedEndpoint.criticality || '-'}</div>
                <div><strong>Triage:</strong> {selectedEndpoint.triage_state || '-'}</div>
              </div>
            </div>

            {selectedEndpoint.notes && (
              <p style={{ margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                {selectedEndpoint.notes}
              </p>
            )}

            <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
              <Button
                kind="primary"
                size="sm"
                onClick={() => {
                  setUploadHost(selectedEndpoint.host || '');
                  setUploadPath(selectedEndpoint.path || '');
                  setUploadMethod(selectedEndpoint.method || 'GET');
                  setUploadTarget(selectedEndpoint.key || 'manual');
                  setSelectedEndpoint(null);
                  onNavigate && onNavigate('api-contracts');
                }}
              >
                Attach schema
              </Button>
            </div>
          </div>
        </Modal>
      )}

      <Modal
        open={bolaModalOpen}
        modalHeading="Add BOLA Ownership Rule"
        primaryButtonText="Add Rule"
        secondaryButtonText="Cancel"
        onRequestClose={() => setBolaModalOpen(false)}
        onRequestSubmit={() => {
          if (!newBolaName.trim() || !newBolaPattern.trim()) return;
          setBolaRules((prev) => [
            ...prev,
            {
              name: newBolaName.trim(),
              resource_pattern: newBolaPattern.trim(),
              owner_id_param: newBolaParam.trim(),
              owner_id_claim: newBolaClaim.trim(),
              allowed_roles: parseList(newBolaRoles),
            },
          ]);
          setBolaModalOpen(false);
          setNewBolaName('');
          setNewBolaPattern('');
          markDirty();
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '16px' }}>
          <TextInput
            id="bola-name"
            labelText="Rule Name"
            placeholder="e.g. Account Data Isolation"
            value={newBolaName}
            onChange={(e) => setNewBolaName(e.target.value)}
          />
          <TextInput
            id="bola-pattern"
            labelText="Resource Path Pattern"
            placeholder="e.g. /api/v1/accounts/{account_id}/*"
            value={newBolaPattern}
            onChange={(e) => setNewBolaPattern(e.target.value)}
          />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            <TextInput
              id="bola-param"
              labelText="Owner URL Parameter"
              placeholder="account_id"
              value={newBolaParam}
              onChange={(e) => setNewBolaParam(e.target.value)}
            />
            <TextInput
              id="bola-claim"
              labelText="Token Match Claim"
              placeholder="aid or sub"
              value={newBolaClaim}
              onChange={(e) => setNewBolaClaim(e.target.value)}
            />
          </div>
          <TextInput
            id="bola-roles"
            labelText="Exempt / Bypass Roles (comma-separated)"
            placeholder="admin, secops"
            value={newBolaRoles}
            onChange={(e) => setNewBolaRoles(e.target.value)}
          />
        </div>
      </Modal>

      <Modal
        open={bflaModalOpen}
        modalHeading="Add BFLA Function Authorization Rule"
        primaryButtonText="Add Rule"
        secondaryButtonText="Cancel"
        onRequestClose={() => setBflaModalOpen(false)}
        onRequestSubmit={() => {
          if (!newBflaName.trim() || !newBflaPattern.trim()) return;
          setBflaRules((prev) => [
            ...prev,
            {
              name: newBflaName.trim(),
              methods: parseList(newBflaMethods).map((m) => m.toUpperCase()),
              path_pattern: newBflaPattern.trim(),
              allowed_roles: parseList(newBflaRoles),
            },
          ]);
          setBflaModalOpen(false);
          setNewBflaName('');
          setNewBflaPattern('');
          markDirty();
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '16px' }}>
          <TextInput
            id="bfla-name"
            labelText="Rule Name"
            placeholder="e.g. Sensitive API Mutations"
            value={newBflaName}
            onChange={(e) => setNewBflaName(e.target.value)}
          />
          <TextInput
            id="bfla-methods"
            labelText="HTTP Methods (comma-separated)"
            placeholder="POST, PUT, DELETE"
            value={newBflaMethods}
            onChange={(e) => setNewBflaMethods(e.target.value)}
          />
          <TextInput
            id="bfla-pattern"
            labelText="Path Pattern"
            placeholder="/api/v1/finance/*"
            value={newBflaPattern}
            onChange={(e) => setNewBflaPattern(e.target.value)}
          />
          <TextInput
            id="bfla-roles"
            labelText="Authorized Roles (comma-separated)"
            placeholder="finance_admin, compliance"
            value={newBflaRoles}
            onChange={(e) => setNewBflaRoles(e.target.value)}
          />
        </div>
      </Modal>

      <Modal
        open={issuerModalOpen}
        modalHeading="Register Trusted JWKS Issuer"
        primaryButtonText="Add Issuer"
        secondaryButtonText="Cancel"
        onRequestClose={() => setIssuerModalOpen(false)}
        onRequestSubmit={() => {
          if (!newIssuerName.trim() || !newIssuerUrl.trim()) return;
          setAuthIssuers((prev) => [
            ...prev,
            {
              name: newIssuerName.trim(),
              issuer: newIssuerUrl.trim(),
              audiences: parseList(newIssuerAudiences),
              allowed_algorithms: parseList(newIssuerAlgorithms),
              jwks_url: newIssuerJwks.trim() || `${newIssuerUrl.trim()}/.well-known/jwks.json`,
            },
          ]);
          setIssuerModalOpen(false);
          setNewIssuerName('');
          setNewIssuerUrl('');
          setNewIssuerAudiences('');
          setNewIssuerJwks('');
          markDirty();
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '16px' }}>
          <TextInput
            id="issuer-name"
            labelText="Issuer Name"
            placeholder="e.g. Okta Production IdP"
            value={newIssuerName}
            onChange={(e) => setNewIssuerName(e.target.value)}
          />
          <TextInput
            id="issuer-url"
            labelText="Issuer URL"
            placeholder="https://identity.company.com/"
            value={newIssuerUrl}
            onChange={(e) => setNewIssuerUrl(e.target.value)}
          />
          <TextInput
            id="issuer-jwks"
            labelText="JWKS Endpoint URL"
            placeholder="https://identity.company.com/.well-known/jwks.json"
            value={newIssuerJwks}
            onChange={(e) => setNewIssuerJwks(e.target.value)}
          />
          <TextInput
            id="issuer-audiences"
            labelText="Expected Audiences (comma-separated)"
            placeholder="https://api.example.com"
            value={newIssuerAudiences}
            onChange={(e) => setNewIssuerAudiences(e.target.value)}
          />
          <TextInput
            id="issuer-algorithms"
            labelText="Allowed Algorithms (comma-separated)"
            placeholder="RS256, ES256"
            value={newIssuerAlgorithms}
            onChange={(e) => setNewIssuerAlgorithms(e.target.value)}
          />
        </div>
      </Modal>

      <Modal
        open={massModalOpen}
        modalHeading="Add Mass Assignment Path Rule"
        primaryButtonText="Add Rule"
        secondaryButtonText="Cancel"
        onRequestClose={() => setMassModalOpen(false)}
        onRequestSubmit={() => {
          if (!newMassPattern.trim()) return;
          setMassPathRules((prev) => [
            ...prev,
            {
              path_pattern: newMassPattern.trim(),
              fields: parseList(newMassFields),
            },
          ]);
          setMassModalOpen(false);
          setNewMassPattern('');
          setNewMassFields('role, is_admin, tier');
          markDirty();
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '16px' }}>
          <TextInput
            id="mass-pattern-input"
            labelText="Path Pattern"
            placeholder="/api/v1/users/*"
            value={newMassPattern}
            onChange={(e) => setNewMassPattern(e.target.value)}
          />
          <TextInput
            id="mass-fields-input"
            labelText="Protected Fields (comma-separated)"
            placeholder="role, is_admin, tier"
            value={newMassFields}
            onChange={(e) => setNewMassFields(e.target.value)}
          />
        </div>
      </Modal>

      <SaveActionBar
        isDirty={isDirty}
        onSave={handleSave}
        onReset={() => {
          loadData();
          setIsDirty(false);
        }}
        isSaving={saving}
      />
    </div>
  );
};
