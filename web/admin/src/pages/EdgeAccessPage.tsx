import React, { useState, useEffect, useMemo } from 'react';
import {
  TextInput,
  TextArea,
  NumberInput,
  Select,
  SelectItem,
  Button,
  Tag,
  Modal,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  TableContainer,
  TableToolbar,
  TableToolbarContent,
  TableToolbarSearch,
  Pagination,
  InlineNotification,
  Checkbox,
  Breadcrumb,
  BreadcrumbItem,
  OverflowMenu,
  OverflowMenuItem,
} from '@carbon/react';
import {
  UserAvatar,
  Document,
  Security,
  Activity,
  Add,
  Renew,
  Globe,
  ArrowLeft,
  Checkmark,
  CheckmarkFilled,
  Undo,
  Network_3,
  Key,
  ChevronDown,
  ChevronRight,
  Unlocked,
  Tag as TagIcon,
  Close,
  Filter,
  Locked,
  Application,
  Time,
  Layers,
} from '@carbon/icons-react';
import {
  PageHeader,
  MetricStrip,
  KpiCard,
  SectionCard,
  StatusToggle,
  HeaderSwitcher,
  SaveActionBar,
} from '../components/common';
import { apiService } from '../services/api';
import type { NavItemKey, RouteRecord } from '../types';

export type AppAccessHealth = 'draft' | 'deny_only' | 'active' | 'update_available' | 'disabled' | 'error';
export type AppTrustChannel = 'browser_session' | 'bearer_jwt' | 'api_key' | 'mtls';

export interface AppRouteSummary {
  id: string;
  name: string;
  hosts: string[];
  paths: string[];
  enabled: boolean;
  priority: number;
  origin_url?: string;
  upstream?: string;
}

export interface AppTrustSource {
  channel: AppTrustChannel;
  reference_mode?: 'explicit';
  oidc_provider_id?: string;
  jwt_issuer_url?: string;
  jwt_audience?: string;
}

export interface AppV2 {
  id: string;
  revision: number;
  name: string;
  route_id: string;
  route?: AppRouteSummary;
  auth_method?: string;
  default_action: 'allow' | 'deny';
  authorization_mode: 'policy_attachments';
  deployment_state: 'draft' | 'deployed' | 'disabled';
  accepted_trust_sources: AppTrustSource[];
  access_health: {
    state: AppAccessHealth;
    reason_codes: string[];
  };
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface AppAccessSummary {
  candidate_policy_count: number;
  active_policy_count: number;
  active_allow_count: number;
  active_deployment_id?: string;
}

export interface AppCatalogItem {
  protected_app: AppV2;
  public_addresses: string[];
  access_summary: AppAccessSummary;
}

export interface AppAttachedPolicy {
  attachmentId: string;
  policyId: string;
  policyName: string;
  version: number;
  decision: 'allow' | 'deny' | 'public_bypass';
  path: string;
  methods: string[];
  principalsSummary: string;
  deployed: boolean;
  updateAvailable: boolean;
}

export interface AccessPolicy {
  id: string;
  name: string;
  description: string;
  version: number;
  decision: 'allow' | 'deny' | 'public_bypass';
  principals: {
    any_authenticated: boolean;
    roles: string[];
    groups: string[];
    claims: Array<{ name: string; operator: string; values: string[] }>;
    permissions?: string[];
    service_identity_ids?: string[];
  };
  requirements: {
    mfa_satisfied: boolean;
    trusted_device: boolean;
    source_cidrs: string[];
    countries: string[];
  };
  attachment_count: number;
  protected_app_ids?: string[];
  update_available_count?: number;
  archived?: boolean;
  updated_at: string;
}

export interface IdentityClaimMapping {
  subject: string;
  email: string;
  roles: string;
  groups: string;
}

export interface IdentityValidationCheck {
  id: string;
  label: string;
  status: 'passed' | 'warning' | 'failed';
  message: string;
}

export interface IdentityProviderValidation {
  status: 'valid' | 'warning' | 'failed' | 'not_validated';
  checked_at?: string;
  checks: IdentityValidationCheck[];
}

export interface IdentityProvider {
  id: string;
  provider_id?: string;
  name: string;
  type: 'oidc' | 'jwt';
  preset?: string;
  issuer: string;
  client_id?: string;
  client_secret?: string;
  redirect_url?: string;
  audience?: string;
  jwks_url?: string;
  secret_key?: string;
  scopes: string[];
  algorithms?: string[];
  identity_mapping?: IdentityClaimMapping;
  validation?: IdentityProviderValidation;
  usage?: { protected_app_ids: string[] };
  status: 'valid' | 'warning' | 'failed';
  status_message?: string;
  apps_count?: number;
}

export interface ServiceIdentity {
  id: string;
  revision?: number;
  name: string;
  type: 'api_key' | 'mtls';
  key_prefix?: string;
  fingerprint?: string;
  roles: string[];
  groups?: string[];
  status: 'active' | 'revoked' | 'expired' | string;
  expires_at?: string;
  last_used_at?: string;
  usage_count?: number;
  created_at?: string;
  updated_at?: string;
  revoked?: boolean;
}

export interface ProviderTemplate {
  id: string;
  name: string;
  description: string;
  type: 'oidc' | 'jwt';
  namePlaceholder: string;
  issuerPlaceholder: string;
}

export const PROVIDER_TEMPLATES: ProviderTemplate[] = [
  { id: 'entra', name: 'Microsoft Entra ID', description: 'Workforce sign-in with an Entra tenant and OpenID Connect.', type: 'oidc', namePlaceholder: 'Corporate Microsoft Entra', issuerPlaceholder: 'https://login.microsoftonline.com/{tenant-id}/v2.0' },
  { id: 'okta', name: 'Okta', description: 'Connect an Okta authorization server for workforce access.', type: 'oidc', namePlaceholder: 'Corporate Okta', issuerPlaceholder: 'https://company.okta.com/oauth2/default' },
  { id: 'auth0', name: 'Auth0', description: 'Use an Auth0 tenant for browser and application identities.', type: 'oidc', namePlaceholder: 'Production Auth0', issuerPlaceholder: 'https://tenant.auth0.com/' },
  { id: 'google', name: 'Google Workspace', description: 'Authenticate managed Google Workspace users through OIDC.', type: 'oidc', namePlaceholder: 'Google Workspace', issuerPlaceholder: 'https://accounts.google.com' },
  { id: 'keycloak', name: 'Keycloak', description: 'Connect a self-managed Keycloak realm for workforce sign-in.', type: 'oidc', namePlaceholder: 'Corporate Keycloak', issuerPlaceholder: 'https://identity.example.com/realms/{realm}' },
  { id: 'oidc', name: 'Generic OIDC', description: 'Connect any standards-compliant OpenID Connect provider.', type: 'oidc', namePlaceholder: 'Corporate identity provider', issuerPlaceholder: 'https://identity.example.com' },
  { id: 'entra-jwt', name: 'Microsoft Entra API', description: 'Verify access tokens issued for a Microsoft Entra application.', type: 'jwt', namePlaceholder: 'Microsoft Entra API', issuerPlaceholder: 'https://login.microsoftonline.com/{tenant-id}/v2.0' },
  { id: 'okta-jwt', name: 'Okta API', description: 'Validate API access tokens from an Okta authorization server.', type: 'jwt', namePlaceholder: 'Okta API issuer', issuerPlaceholder: 'https://company.okta.com/oauth2/default' },
  { id: 'auth0-jwt', name: 'Auth0 API', description: 'Verify machine and API tokens issued by an Auth0 tenant.', type: 'jwt', namePlaceholder: 'Auth0 production API', issuerPlaceholder: 'https://tenant.auth0.com/' },
  { id: 'cognito-jwt', name: 'Amazon Cognito', description: 'Validate access and ID tokens from an Amazon Cognito user pool.', type: 'jwt', namePlaceholder: 'Production Cognito pool', issuerPlaceholder: 'https://cognito-idp.{region}.amazonaws.com/{user-pool-id}' },
  { id: 'keycloak-jwt', name: 'Keycloak API', description: 'Verify API and service tokens issued by a Keycloak realm.', type: 'jwt', namePlaceholder: 'Keycloak API issuer', issuerPlaceholder: 'https://identity.example.com/realms/{realm}' },
  { id: 'jwt', name: 'Generic JWT issuer', description: 'Verify bearer tokens using JWKS or write-only key material.', type: 'jwt', namePlaceholder: 'Production API issuer', issuerPlaceholder: 'https://tokens.example.com' },
];

export function normalizeAccessPolicy(raw: any): AccessPolicy {
  if (!raw) {
    return {
      id: `pol-${Date.now()}`,
      name: 'Unnamed Policy',
      description: '',
      version: 1,
      decision: 'allow',
      principals: {
        any_authenticated: true,
        roles: [],
        groups: [],
        claims: [],
        permissions: [],
        service_identity_ids: [],
      },
      requirements: {
        mfa_satisfied: false,
        trusted_device: false,
        source_cidrs: [],
        countries: [],
      },
      attachment_count: 0,
      protected_app_ids: [],
      update_available_count: 0,
      archived: false,
      updated_at: new Date().toISOString(),
    };
  }

  const base = raw.policy && typeof raw.policy === 'object' ? raw.policy : raw;
  const principals = raw.principals || base.principals || {};
  const requirements = raw.requirements || base.requirements || {};

  return {
    id: base.id || raw.id || `pol-${Date.now()}`,
    name: base.name || raw.name || 'Unnamed Policy',
    description: base.description || raw.description || '',
    version: raw.latest_published_version || base.version || raw.version || 1,
    decision: (raw.latest_published_decision || base.decision || raw.decision || 'allow') as 'allow' | 'deny' | 'public_bypass',
    principals: {
      any_authenticated: principals.any_authenticated ?? true,
      roles: Array.isArray(principals.roles) ? principals.roles : [],
      groups: Array.isArray(principals.groups) ? principals.groups : [],
      claims: Array.isArray(principals.claims) ? principals.claims : [],
      permissions: Array.isArray(principals.permissions) ? principals.permissions : [],
      service_identity_ids: Array.isArray(principals.service_identity_ids) ? principals.service_identity_ids : [],
    },
    requirements: {
      mfa_satisfied: Boolean(requirements.mfa_satisfied),
      trusted_device: Boolean(requirements.trusted_device),
      source_cidrs: Array.isArray(requirements.source_cidrs) ? requirements.source_cidrs : [],
      countries: Array.isArray(requirements.countries) ? requirements.countries : [],
    },
    attachment_count: typeof raw.attachment_count === 'number'
      ? raw.attachment_count
      : (Array.isArray(raw.protected_app_ids) ? raw.protected_app_ids.length : 0),
    protected_app_ids: Array.isArray(raw.protected_app_ids)
      ? raw.protected_app_ids
      : (Array.isArray(base.protected_app_ids) ? base.protected_app_ids : []),
    update_available_count: typeof raw.update_available_count === 'number' ? raw.update_available_count : 0,
    archived: Boolean(base.archived ?? raw.archived),
    updated_at: base.updated_at || raw.updated_at || new Date().toISOString(),
  };
}

export function detectProviderBrand(provider: { name: string; issuer: string; type: string; preset?: string }): string {
  if (provider.preset) return provider.preset;
  const source = `${provider.name} ${provider.issuer}`.toLowerCase();
  if (provider.type === 'jwt') {
    if (source.includes('cognito') || source.includes('amazonaws')) return 'cognito-jwt';
    if (source.includes('keycloak')) return 'keycloak-jwt';
    if (source.includes('microsoft') || source.includes('entra') || source.includes('login.microsoftonline')) return 'entra-jwt';
    if (source.includes('okta')) return 'okta-jwt';
    if (source.includes('auth0')) return 'auth0-jwt';
    return 'jwt';
  }
  if (source.includes('microsoft') || source.includes('entra') || source.includes('login.microsoftonline')) return 'entra';
  if (source.includes('okta')) return 'okta';
  if (source.includes('auth0')) return 'auth0';
  if (source.includes('google') || source.includes('accounts.google')) return 'google';
  if (source.includes('keycloak')) return 'keycloak';
  return 'oidc';
}

export function renderProviderBrandMark(brand: string, name: string): React.ReactElement {
  if (brand === 'entra' || brand === 'entra-jwt') {
    return (
      <div
        aria-label={`${name} icon`}
        style={{
          width: '28px',
          height: '28px',
          display: 'grid',
          gridTemplateColumns: 'repeat(2, 1fr)',
          gap: '2px',
          padding: '5px',
          background: 'var(--cds-layer-02, #262626)',
          borderRadius: '4px',
          border: '1px solid var(--cds-border-subtle)',
          flexShrink: 0,
        }}
      >
        <span style={{ background: '#f25022', borderRadius: '1px' }} />
        <span style={{ background: '#7fba00', borderRadius: '1px' }} />
        <span style={{ background: '#00a4ef', borderRadius: '1px' }} />
        <span style={{ background: '#ffb900', borderRadius: '1px' }} />
      </div>
    );
  }
  if (brand === 'okta' || brand === 'okta-jwt') {
    return (
      <div
        aria-label={`${name} icon`}
        style={{
          width: '28px',
          height: '28px',
          borderRadius: '4px',
          background: 'var(--cds-layer-02, #262626)',
          border: '1px solid var(--cds-border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 700,
          fontSize: '14px',
          color: '#007dc1',
          flexShrink: 0,
        }}
      >
        O
      </div>
    );
  }
  if (brand === 'auth0' || brand === 'auth0-jwt') {
    return (
      <div
        aria-label={`${name} icon`}
        style={{
          width: '28px',
          height: '28px',
          borderRadius: '4px',
          background: 'var(--cds-layer-02, #262626)',
          border: '1px solid var(--cds-border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 700,
          fontSize: '11px',
          color: '#eb5424',
          flexShrink: 0,
        }}
      >
        A0
      </div>
    );
  }
  if (brand === 'google') {
    return (
      <div
        aria-label={`${name} icon`}
        style={{
          width: '28px',
          height: '28px',
          borderRadius: '4px',
          background: 'var(--cds-layer-02, #262626)',
          border: '1px solid var(--cds-border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 700,
          fontSize: '14px',
          color: '#4285f4',
          flexShrink: 0,
        }}
      >
        G
      </div>
    );
  }
  if (brand === 'keycloak' || brand === 'keycloak-jwt') {
    return (
      <div
        aria-label={`${name} icon`}
        style={{
          width: '28px',
          height: '28px',
          borderRadius: '4px',
          background: 'var(--cds-layer-02, #262626)',
          border: '1px solid var(--cds-border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 700,
          fontSize: '14px',
          color: '#4db6ac',
          flexShrink: 0,
        }}
      >
        K
      </div>
    );
  }
  if (brand === 'cognito-jwt') {
    return (
      <div
        aria-label={`${name} icon`}
        style={{
          width: '28px',
          height: '28px',
          borderRadius: '4px',
          background: 'var(--cds-layer-02, #262626)',
          border: '1px solid var(--cds-border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 700,
          fontSize: '9px',
          color: '#ff9900',
          flexShrink: 0,
        }}
      >
        AWS
      </div>
    );
  }
  if (brand === 'jwt' || brand === 'api_key') {
    return (
      <div
        aria-label={`${name} icon`}
        style={{
          width: '28px',
          height: '28px',
          borderRadius: '4px',
          background: 'var(--cds-layer-02, #262626)',
          border: '1px solid var(--cds-border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--cds-icon-primary)',
          flexShrink: 0,
        }}
      >
        <Key size={16} />
      </div>
    );
  }
  if (brand === 'mtls') {
    return (
      <div
        aria-label={`${name} icon`}
        style={{
          width: '28px',
          height: '28px',
          borderRadius: '4px',
          background: 'var(--cds-layer-02, #262626)',
          border: '1px solid var(--cds-border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--cds-icon-primary)',
          flexShrink: 0,
        }}
      >
        <Security size={16} />
      </div>
    );
  }
  return (
    <div
      aria-label={`${name} icon`}
      style={{
        width: '28px',
        height: '28px',
        borderRadius: '4px',
        background: 'var(--cds-layer-02, #262626)',
        border: '1px solid var(--cds-border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'var(--cds-icon-primary)',
        flexShrink: 0,
      }}
    >
      <Globe size={16} />
    </div>
  );
}

export interface AccessRole {
  id: string;
  name: string;
  description: string;
  is_builtin: boolean;
  permissions: string[];
  inherits: string[];
  assigned_apps_count: number;
}

export interface DecisionTraceStep {
  stage: string;
  outcome: string;
  detail: string;
  attachment_id?: string;
  policy_id?: string;
  policy_version?: number;
}

export interface DecisionExplanation {
  available: boolean;
  reason: string;
  steps: string[];
  trace: DecisionTraceStep[];
}

export interface DecisionRecord {
  id: string;
  timestamp: string;
  route_id?: string;
  protected_app_id?: string;
  protected_app_name?: string;
  public_addresses?: string[];
  host: string;
  path: string;
  method?: string;
  result: 'allow' | 'deny' | 'requires_auth' | string;
  status_code?: number;
  evaluation_mode?: string;
  auth_channel?: string;
  identity_type?: string;
  identity_id?: string;
  identity_email?: string;
  client_ip?: string;
  client_country?: string;
  policy_attachment_id?: string;
  policy_id?: string;
  policy_version?: number;
  reason_code?: string;
  reason?: string;
  failed_requirement?: string;
  matched_conditions?: string[];
  explanation_available?: boolean;
  matched_policy?: string;
  trace_steps?: DecisionTraceStep[];
  explanation?: DecisionExplanation;
}

const mapBackendAttachmentToUI = (att: any, policiesList: AccessPolicy[]): AppAttachedPolicy => {
  const pol = policiesList.find((p) => p.id === (att.policy_id || att.policyId));
  const currentVersion = pol?.version ?? att.policy_version ?? att.version ?? 1;
  const attachedVersion = att.policy_version ?? att.version ?? 1;
  const decision = pol?.decision ?? att.decision ?? 'allow';
  const principalsSummary = pol?.decision === 'public_bypass'
    ? 'Identity not required'
    : pol?.principals?.any_authenticated
    ? 'Any authenticated identity'
    : (Array.isArray(pol?.principals?.roles) && pol.principals.roles.length > 0)
    ? `Roles: ${pol.principals.roles.join(', ')}`
    : 'All authenticated';

  return {
    attachmentId: att.id || att.attachmentId || `att-${Date.now()}`,
    policyId: att.policy_id || att.policyId,
    policyName: pol?.name || att.policy_name || att.policyName || att.policy_id || 'Policy',
    version: attachedVersion,
    decision,
    path: att.path || '/*',
    methods: att.methods && att.methods.length > 0 && att.methods[0] !== 'ALL' ? att.methods : ['*'],
    principalsSummary,
    deployed: att.deployment_state === 'active' || att.deployed === true,
    updateAvailable: currentVersion > attachedVersion,
  };
};

const parseMethodsInput = (val: string): string[] => {
  const trimmed = (val || '').trim();
  if (!trimmed || trimmed === 'ALL' || trimmed === '*') {
    return ['*'];
  }
  const list = trimmed
    .split(',')
    .map((m) => m.trim().toUpperCase())
    .map((m) => (m === 'ALL' ? '*' : m))
    .filter(Boolean);
  if (list.includes('*')) {
    return ['*'];
  }
  return list.length > 0 ? list : ['*'];
};

interface EdgeAccessPageProps {
  activeNavKey?: NavItemKey;
  onNavigate?: (key: NavItemKey) => void;
}

export const EdgeAccessPage: React.FC<EdgeAccessPageProps> = ({ activeNavKey, onNavigate }) => {
  const [localNav, setLocalNav] = useState<NavItemKey>(activeNavKey || 'edge-access');
  const [_loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [reloadingEngine, setReloadingEngine] = useState<boolean>(false);
  const [testingProvider, setTestingProvider] = useState<boolean>(false);
  const [isDirty, setIsDirty] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  useEffect(() => {
    if (activeNavKey) {
      setLocalNav(activeNavKey);
    }
  }, [activeNavKey]);

  const currentView = useMemo<'overview' | 'apps' | 'policies' | 'identity' | 'roles' | 'decisions' | 'runtime'>(() => {
    switch (localNav) {
      case 'edge-access':
        return 'overview';
      case 'access-apps':
        return 'apps';
      case 'access-policies':
        return 'policies';
      case 'access-identity':
        return 'identity';
      case 'access-roles':
        return 'roles';
      case 'access-decisions':
        return 'decisions';
      case 'access-runtime':
        return 'runtime';
      default:
        return 'overview';
    }
  }, [localNav]);

  useEffect(() => {
    if (currentView !== 'apps' && currentView !== 'overview') {
      setSelectedAppId(null);
      setCreatingApp(false);
      setManagingPolicies(false);
    }
    if (currentView !== 'policies') {
      setPolicyMode('list');
      setEditingPolicyId(null);
    }
    if (currentView !== 'identity') {
      setIdentityMode('list');
      setEditingProviderId(null);
    }
    if (currentView !== 'roles') {
      setRoleMode('list');
      setEditingRoleId(null);
    }
  }, [currentView]);

  const goToView = (navKey: NavItemKey) => {
    if (onNavigate) {
      onNavigate(navKey);
    } else {
      setLocalNav(navKey);
    }
  };

  const [enabled, setEnabled] = useState<boolean>(true);
  const [authEnabled, setAuthEnabled] = useState<boolean>(true);
  const [apiKeyEnabled, setApiKeyEnabled] = useState<boolean>(true);
  const [apiKeyHeader, setApiKeyHeader] = useState<string>('X-API-Key');
  const [jwtEnabled, setJwtEnabled] = useState<boolean>(true);
  const [jwtHeader, setJwtHeader] = useState<string>('Authorization');
  const [jwtPrefix, setJwtPrefix] = useState<string>('Bearer');
  const [oidcEnabled, setOidcEnabled] = useState<boolean>(true);

  const [sessionEnabled, setSessionEnabled] = useState<boolean>(true);
  const [tokenTtl, setTokenTtl] = useState<string>('24h');
  const [idleTimeout, setIdleTimeout] = useState<string>('30m');
  const [maxSessions, setMaxSessions] = useState<number>(5);
  const [bindToIp, setBindToIp] = useState<boolean>(false);
  const [bindToUa, setBindToUa] = useState<boolean>(false);
  const [cookieName, setCookieName] = useState<string>('aegis_session');
  const [cookieSecure, setCookieSecure] = useState<boolean>(true);
  const [cookieHttpOnly, setCookieHttpOnly] = useState<boolean>(true);
  const [cookieSameSite, setCookieSameSite] = useState<'lax' | 'strict' | 'none'>('lax');

  const [identityHeadersEnabled, setIdentityHeadersEnabled] = useState<boolean>(true);
  const [overwriteHeaders, setOverwriteHeaders] = useState<boolean>(true);

  const [catalogItems, setCatalogItems] = useState<AppCatalogItem[]>([]);
  const [availableRoutes, setAvailableRoutes] = useState<RouteRecord[]>([]);
  const [policies, setPolicies] = useState<AccessPolicy[]>([]);
  const [attachedPoliciesMap, setAttachedPoliciesMap] = useState<Record<string, AppAttachedPolicy[]>>({});
  const [idps, setIdps] = useState<IdentityProvider[]>([]);
  const [identityRevision, setIdentityRevision] = useState<number>(1);
  const [serviceIdentities, setServiceIdentities] = useState<ServiceIdentity[]>([]);
  const [roles, setRoles] = useState<AccessRole[]>([]);
  const [decisions, setDecisions] = useState<DecisionRecord[]>([]);
  const [rawConfig, setRawConfig] = useState<any>(null);

  const [creatingApp, setCreatingApp] = useState<boolean>(false);
  const [selectedAppId, setSelectedAppId] = useState<string | null>(null);
  const [managingPolicies, setManagingPolicies] = useState<boolean>(false);
  const [appSearch, setAppSearch] = useState<string>('');
  const [appStatusFilter, setAppStatusFilter] = useState<string>('');
  const [catalogPage, setCatalogPage] = useState<number>(1);
  const [catalogPageSize, setCatalogPageSize] = useState<number>(10);

  const [newAppName, setNewAppName] = useState<string>('');
  const [newAppRouteMode, setNewAppRouteMode] = useState<'existing' | 'new'>('existing');
  const [newAppRouteId, setNewAppRouteId] = useState<string>('');
  const [newAppRouteName, setNewAppRouteName] = useState<string>('');
  const [newAppRouteHost, setNewAppRouteHost] = useState<string>('');
  const [newAppOriginUrl, setNewAppOriginUrl] = useState<string>('');
  const [newAppRoutePath, setNewAppRoutePath] = useState<string>('/*');
  const [newAppRoutePriority, setNewAppRoutePriority] = useState<number>(100);
  const [newAppAdvancedRouteOpen, setNewAppAdvancedRouteOpen] = useState<boolean>(false);
  const [newAppTrustBrowser, setNewAppTrustBrowser] = useState<boolean>(true);
  const [newAppOidcProviderId, setNewAppOidcProviderId] = useState<string>('idp-entra');
  const [newAppTrustJwt, setNewAppTrustJwt] = useState<boolean>(false);
  const [newAppJwtProviderId, setNewAppJwtProviderId] = useState<string>('idp-auth0');
  const [newAppApiKey, setNewAppApiKey] = useState<boolean>(false);
  const [newAppMtls, setNewAppMtls] = useState<boolean>(false);

  const [confirmDialog, setConfirmDialog] = useState<{
    open: boolean;
    title: string;
    message: string;
    confirmLabel: string;
    danger?: boolean;
    onConfirm: () => void;
  }>({
    open: false,
    title: '',
    message: '',
    confirmLabel: '',
    onConfirm: () => {},
  });

  const [changeAttachmentModal, setChangeAttachmentModal] = useState<{
    open: boolean;
    attachment: AppAttachedPolicy | null;
    path: string;
    methods: string;
    enabled: boolean;
  }>({
    open: false,
    attachment: null,
    path: '/*',
    methods: '',
    enabled: true,
  });

  const [policyMode, setPolicyMode] = useState<'list' | 'new' | 'edit'>('list');
  const [editingPolicyId, setEditingPolicyId] = useState<string | null>(null);
  const [policySearch, setPolicySearch] = useState<string>('');
  const [policyStatusFilter, setPolicyStatusFilter] = useState<string>('');
  const [policyPage, setPolicyPage] = useState<number>(1);
  const [policyPageSize, setPolicyPageSize] = useState<number>(10);

  const [policyFormName, setPolicyFormName] = useState<string>('');
  const [policyFormDesc, setPolicyFormDesc] = useState<string>('');
  const [policyFormDecision, setPolicyFormDecision] = useState<'allow' | 'deny' | 'public_bypass'>('allow');
  const [policyFormIdentityMode, setPolicyFormIdentityMode] = useState<'any' | 'specific'>('any');
  const [policyFormGroups, setPolicyFormGroups] = useState<string>('');
  const [policyFormRoles, setPolicyFormRoles] = useState<string[]>([]);
  const [policyFormPermissions, setPolicyFormPermissions] = useState<string>('');
  const [policyFormServiceIdentities, setPolicyFormServiceIdentities] = useState<string>('');
  const [policyFormClaims, setPolicyFormClaims] = useState<string>('[]');
  const [policyFormMfa, setPolicyFormMfa] = useState<boolean>(false);
  const [policyFormCidrs, setPolicyFormCidrs] = useState<string>('');
  const [policyAdvancedIdentityOpen, setPolicyAdvancedIdentityOpen] = useState<boolean>(false);

  const [libraryAttachModal, setLibraryAttachModal] = useState<{
    open: boolean;
    policy: AccessPolicy | null;
    appId: string;
  }>({
    open: false,
    policy: null,
    appId: '',
  });

  const [identityMode, setIdentityMode] = useState<'list' | 'new' | 'edit'>('list');
  const [editingProviderId, setEditingProviderId] = useState<string | null>(null);
  const [identitySearch, setIdentitySearch] = useState<string>('');
  const [identityPage, setIdentityPage] = useState<number>(1);
  const [identityPageSize, setIdentityPageSize] = useState<number>(10);

  const [idpFormType, setIdpFormType] = useState<'oidc' | 'jwt' | 'api_key' | 'mtls' | ''>('oidc');
  const [idpFormPreset, setIdpFormPreset] = useState<string>('entra');
  const [idpFormId, setIdpFormId] = useState<string>('corporate-sso');
  const [idpFormName, setIdpFormName] = useState<string>('Corporate Microsoft Entra');
  const [idpFormIssuer, setIdpFormIssuer] = useState<string>('https://login.microsoftonline.com/{tenant-id}/v2.0');
  const [idpFormClientId, setIdpFormClientId] = useState<string>('');
  const [idpFormClientSecret, setIdpFormClientSecret] = useState<string>('');
  const [idpFormRedirectUrl, setIdpFormRedirectUrl] = useState<string>('https://app.example.com/auth/callback');
  const [idpFormScopes, setIdpFormScopes] = useState<string>('openid, profile, email');
  const [idpFormAudience, setIdpFormAudience] = useState<string>('api://edge-access');
  const [idpFormAlgorithms, setIdpFormAlgorithms] = useState<string>('RS256');
  const [idpFormJwksUrl, setIdpFormJwksUrl] = useState<string>('');
  const [idpFormSecretKey, setIdpFormSecretKey] = useState<string>('');
  const [idpAdvancedOpen, setIdpAdvancedOpen] = useState<boolean>(false);
  const [idpFormMachineName, setIdpFormMachineName] = useState<string>('');
  const [idpFormMachineExpiresIn, setIdpFormMachineExpiresIn] = useState<string>('');
  const [idpFormMachineGroups, setIdpFormMachineGroups] = useState<string>('');
  const [idpFormMachineCertPem, setIdpFormMachineCertPem] = useState<string>('');
  const [idpFormMachineRoles, setIdpFormMachineRoles] = useState<string[]>([]);

  const [validationModal, setValidationModal] = useState<{
    open: boolean;
    provider: IdentityProvider | null;
  }>({
    open: false,
    provider: null,
  });

  const [deleteProviderModal, setDeleteProviderModal] = useState<{
    open: boolean;
    provider: IdentityProvider | null;
  }>({
    open: false,
    provider: null,
  });

  const [claimMappingModal, setClaimMappingModal] = useState<{
    open: boolean;
    provider: IdentityProvider | null;
    subject: string;
    email: string;
    roles: string;
    groups: string;
    testClaimsJson: string;
    previewText: string | null;
  }>({
    open: false,
    provider: null,
    subject: 'sub',
    email: 'email',
    roles: 'roles',
    groups: 'groups',
    testClaimsJson: '{\n  "sub": "user_7482",\n  "email": "alice.secops@corp.internal",\n  "roles": ["admin", "sec-ops"],\n  "groups": ["engineering", "security"]\n}',
    previewText: null,
  });

  const [editServiceIdentityModal, setEditServiceIdentityModal] = useState<{
    open: boolean;
    identity: ServiceIdentity | null;
    name: string;
    roles: string[];
    groups: string;
    expiresIn: string;
    certPem: string;
  }>({
    open: false,
    identity: null,
    name: '',
    roles: [],
    groups: '',
    expiresIn: '',
    certPem: '',
  });

  const [usageModal, setUsageModal] = useState<{
    open: boolean;
    identity: ServiceIdentity | null;
    apps: string[];
    versions: string[];
    deployments: string[];
  }>({
    open: false,
    identity: null,
    apps: [],
    versions: [],
    deployments: [],
  });

  const [rotateServiceModal, setRotateServiceModal] = useState<{
    open: boolean;
    identity: ServiceIdentity | null;
  }>({
    open: false,
    identity: null,
  });

  const [revokeServiceModal, setRevokeServiceModal] = useState<{
    open: boolean;
    identity: ServiceIdentity | null;
    dependencies: string[];
  }>({
    open: false,
    identity: null,
    dependencies: [],
  });

  const [oneTimeSecretModal, setOneTimeSecretModal] = useState<{
    open: boolean;
    secret: string;
    warning: string;
  }>({
    open: false,
    secret: '',
    warning: '',
  });

  const [roleSearch, setRoleSearch] = useState<string>('');

  const [decisionSearch, setDecisionSearch] = useState<string>('');
  const [decisionResultFilter, setDecisionResultFilter] = useState<string>('');
  const [decisionHostnameFilter, setDecisionHostnameFilter] = useState<string>('');
  const [decisionIdentityFilter, setDecisionIdentityFilter] = useState<string>('');
  const [decisionChannelFilter, setDecisionChannelFilter] = useState<string>('');
  const [decisionAttachmentFilter, setDecisionAttachmentFilter] = useState<string>('');
  const [decisionVersionFilter, setDecisionVersionFilter] = useState<string>('');
  const [decisionFromFilter, setDecisionFromFilter] = useState<string>('');
  const [decisionToFilter, setDecisionToFilter] = useState<string>('');
  const [showAdvancedDecisionFilters, setShowAdvancedDecisionFilters] = useState<boolean>(false);
  const [decisionPage, setDecisionPage] = useState<number>(1);
  const [decisionPageSize, setDecisionPageSize] = useState<number>(10);
  const [decisionExplanationModal, setDecisionExplanationModal] = useState<{
    open: boolean;
    decision: DecisionRecord | null;
    loading: boolean;
  }>({
    open: false,
    decision: null,
    loading: false,
  });

  const activeAdvancedFilterCount = useMemo(() => {
    let count = 0;
    if (decisionHostnameFilter.trim()) count++;
    if (decisionIdentityFilter.trim()) count++;
    if (decisionAttachmentFilter.trim()) count++;
    if (decisionVersionFilter.trim()) count++;
    if (decisionFromFilter) count++;
    if (decisionToFilter) count++;
    return count;
  }, [
    decisionHostnameFilter,
    decisionIdentityFilter,
    decisionAttachmentFilter,
    decisionVersionFilter,
    decisionFromFilter,
    decisionToFilter,
  ]);

  const hasActiveDecisionFilters = Boolean(
    decisionSearch.trim() ||
    decisionResultFilter ||
    decisionHostnameFilter.trim() ||
    decisionIdentityFilter.trim() ||
    decisionChannelFilter ||
    decisionAttachmentFilter.trim() ||
    decisionVersionFilter.trim() ||
    decisionFromFilter ||
    decisionToFilter
  );

  const resetDecisionFilters = () => {
    setDecisionSearch('');
    setDecisionResultFilter('');
    setDecisionHostnameFilter('');
    setDecisionIdentityFilter('');
    setDecisionChannelFilter('');
    setDecisionAttachmentFilter('');
    setDecisionVersionFilter('');
    setDecisionFromFilter('');
    setDecisionToFilter('');
    setDecisionPage(1);
  };

  const [attachPolicyModalOpen, setAttachPolicyModalOpen] = useState<boolean>(false);
  const [attachPolicyId, setAttachPolicyId] = useState<string>('pol-portal-auth');
  const [attachPolicyPath, setAttachPolicyPath] = useState<string>('/*');
  const [attachPolicyMethods, setAttachPolicyMethods] = useState<string>('');

  const [rolePage, setRolePage] = useState<number>(1);
  const [rolePageSize, setRolePageSize] = useState<number>(10);
  const [roleMode, setRoleMode] = useState<'list' | 'new' | 'edit'>('list');
  const [editingRoleId, setEditingRoleId] = useState<string | null>(null);
  const [roleFormId, setRoleFormId] = useState<string>('');
  const [roleFormName, setRoleFormName] = useState<string>('');
  const [roleFormDesc, setRoleFormDesc] = useState<string>('');
  const [roleFormPermissions, setRoleFormPermissions] = useState<string>('');
  const [roleFormInherits, setRoleFormInherits] = useState<string[]>([]);
  const [deleteRoleModal, setDeleteRoleModal] = useState<{ open: boolean; role: AccessRole | null }>({
    open: false,
    role: null,
  });

  const markDirty = () => setIsDirty(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const [cfg, appsRes, routesRes, polRes, attRes, idpRes, svcRes, rolesRes, decRes] = await Promise.all([
        apiService.getEdgeAccessConfig(),
        apiService.getEdgeAccessApps(),
        apiService.getRoutes(),
        apiService.getEdgeAccessPolicies(),
        apiService.getEdgeAccessPolicyAttachments(),
        apiService.getEdgeAccessIdentityProviders(),
        apiService.getEdgeAccessServiceIdentities(),
        apiService.getEdgeAccessRoles(),
        apiService.getEdgeAccessDecisions(50),
      ]);

      if (cfg) {
        setRawConfig(cfg);
        setEnabled(cfg.enabled ?? true);
        if (cfg.authentication) {
          setAuthEnabled(cfg.authentication.enabled ?? true);
          setApiKeyEnabled(
            cfg.authentication.api_key?.enabled ??
            (Array.isArray(cfg.authentication.methods) ? cfg.authentication.methods.includes('api_key') : true)
          );
          setApiKeyHeader(cfg.authentication.api_key_header || cfg.authentication.api_key?.header || 'X-API-Key');
          setJwtEnabled(
            cfg.authentication.jwt?.enabled ??
            (Array.isArray(cfg.authentication.methods) ? cfg.authentication.methods.includes('jwt') : true)
          );
          setJwtHeader(cfg.authentication.jwt?.header_name || cfg.authentication.jwt?.header || 'Authorization');
          setJwtPrefix(cfg.authentication.jwt?.token_prefix || cfg.authentication.jwt?.prefix || 'Bearer');
          setOidcEnabled(
            cfg.authentication.oidc?.enabled ??
            (Array.isArray(cfg.authentication.methods) ? cfg.authentication.methods.includes('oidc') : true)
          );
        }
        const sess = cfg.session_cookie || cfg.sessions;
        if (sess) {
          setSessionEnabled(sess.enabled ?? true);
          setTokenTtl(sess.token_ttl || '24h');
          setIdleTimeout(sess.idle_timeout || '30m');
          setMaxSessions(sess.max_sessions || 5);
          setBindToIp(sess.bind_to_ip ?? false);
          setBindToUa(sess.bind_to_user_agent ?? false);
          setCookieName(sess.name || sess.cookie_name || 'aegis_session');
          setCookieSecure(sess.secure ?? sess.cookie_secure ?? true);
          setCookieHttpOnly(sess.http_only ?? sess.cookie_http_only ?? true);
          setCookieSameSite(sess.same_site || sess.cookie_same_site || 'lax');
        }
        if (cfg.identity_headers) {
          setIdentityHeadersEnabled(cfg.identity_headers.enabled ?? true);
          setOverwriteHeaders(cfg.identity_headers.overwrite_existing ?? cfg.identity_headers.overwrite ?? true);
        }
      }

      if (appsRes?.apps && Array.isArray(appsRes.apps)) {
        setCatalogItems(appsRes.apps);
      } else if (Array.isArray(appsRes)) {
        setCatalogItems(appsRes);
      } else {
        setCatalogItems([]);
      }

      if (routesRes && Array.isArray(routesRes)) {
        setAvailableRoutes(routesRes);
        if (routesRes.length > 0 && !newAppRouteId) {
          setNewAppRouteId(routesRes[0].id || '');
        }
      }

      let loadedPolicies: AccessPolicy[] = [];
      const rawPolicyList = Array.isArray(polRes)
        ? polRes
        : (polRes?.policies && Array.isArray(polRes.policies) ? polRes.policies : null);
      if (rawPolicyList) {
        loadedPolicies = rawPolicyList.map(normalizeAccessPolicy);
        setPolicies(loadedPolicies);
      } else {
        setPolicies([]);
      }

      const rawAttachments: any[] = attRes?.attachments || (Array.isArray(attRes) ? attRes : []);
      const nextMap: Record<string, AppAttachedPolicy[]> = {};
      rawAttachments.forEach((att: any) => {
        const appId = att.protected_app_id || att.protectedAppId;
        if (!appId) return;
        if (!nextMap[appId]) nextMap[appId] = [];
        nextMap[appId].push(mapBackendAttachmentToUI(att, loadedPolicies));
      });
      setAttachedPoliciesMap(nextMap);

      if (idpRes?.providers && Array.isArray(idpRes.providers)) {
        setIdps(idpRes.providers);
      } else {
        setIdps([]);
      }
      if (idpRes?.identity_revision) {
        setIdentityRevision(idpRes.identity_revision);
      }

      if (svcRes?.identities && Array.isArray(svcRes.identities)) {
        setServiceIdentities(svcRes.identities);
      } else if (Array.isArray(svcRes)) {
        setServiceIdentities(svcRes);
      } else {
        setServiceIdentities([]);
      }

      if (rolesRes?.roles && Array.isArray(rolesRes.roles)) {
        setRoles(rolesRes.roles);
      } else if (Array.isArray(rolesRes)) {
        setRoles(rolesRes);
      } else {
        setRoles([]);
      }

      if (decRes?.decisions && Array.isArray(decRes.decisions)) {
        setDecisions(decRes.decisions);
      } else if (Array.isArray(decRes)) {
        setDecisions(decRes);
      } else {
        setDecisions([]);
      }
    } catch (err) {
      console.warn('Edge Access load error:', err);
      setNotification({ kind: 'error', message: 'Failed to load Edge Access data from server.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      const sessionCookieObj = {
        name: cookieName,
        secure: cookieSecure,
        http_only: cookieHttpOnly,
        same_site: cookieSameSite,
        token_ttl: tokenTtl,
        idle_timeout: idleTimeout,
        max_sessions: maxSessions,
        bind_to_ip: bindToIp,
        bind_to_user_agent: bindToUa,
      };
      const rawMethods: string[] = Array.isArray(rawConfig?.authentication?.methods)
        ? rawConfig.authentication.methods
        : ['api_key'];
      const methodsSet = new Set<string>(rawMethods);
      if (apiKeyEnabled) {
        methodsSet.add('api_key');
      } else {
        methodsSet.delete('api_key');
      }
      if (jwtEnabled) {
        methodsSet.add('jwt');
      } else {
        methodsSet.delete('jwt');
      }
      if (oidcEnabled) {
        methodsSet.add('oidc');
      } else {
        methodsSet.delete('oidc');
      }
      const syncMethods = Array.from(methodsSet);

      const merged = {
        ...(rawConfig || {}),
        enabled,
        authentication: {
          ...(rawConfig?.authentication || {}),
          enabled: authEnabled,
          methods: syncMethods,
          api_key_header: apiKeyHeader,
          api_key: {
            ...(rawConfig?.authentication?.api_key || {}),
            enabled: apiKeyEnabled,
            header: apiKeyHeader,
          },
          jwt: {
            ...(rawConfig?.authentication?.jwt || {}),
            enabled: jwtEnabled,
            header: jwtHeader,
            header_name: jwtHeader,
            prefix: jwtPrefix,
            token_prefix: jwtPrefix,
          },
          oidc: {
            ...(rawConfig?.authentication?.oidc || {}),
            enabled: oidcEnabled,
          },
        },
        sessions: {
          ...(rawConfig?.sessions || {}),
          enabled: sessionEnabled,
          token_ttl: tokenTtl,
          idle_timeout: idleTimeout,
          max_sessions: maxSessions,
          bind_to_ip: bindToIp,
          bind_to_user_agent: bindToUa,
          cookie_name: cookieName,
          cookie_secure: cookieSecure,
          cookie_http_only: cookieHttpOnly,
          cookie_same_site: cookieSameSite,
        },
        session_cookie: {
          ...(rawConfig?.session_cookie || {}),
          ...sessionCookieObj,
        },
        identity_headers: {
          ...(rawConfig?.identity_headers || {}),
          enabled: identityHeadersEnabled,
          overwrite: overwriteHeaders,
          overwrite_existing: overwriteHeaders,
        },
      };

      const ok = await apiService.saveEdgeAccessConfig(merged);
      if (ok) {
        setRawConfig(merged);
        setIsDirty(false);
        setNotification({ kind: 'success', message: 'Edge access configuration saved.' });
      } else {
        setNotification({ kind: 'error', message: 'Failed to save edge access configuration.' });
      }
    } catch {
      setNotification({ kind: 'error', message: 'Network error saving configuration.' });
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    loadData();
    setNotification({ kind: 'info', message: 'Pending changes reverted to active configuration.' });
  };

  const handleReloadEngine = async () => {
    setReloadingEngine(true);
    try {
      const res = await apiService.reloadEdgeAccess();
      if (res?.success) {
        setNotification({
          kind: 'success',
          message: res.message || `Edge Access runtime reloaded successfully (revision ${res.revision || res.loaded_revision || 'active'}).`,
        });
        await loadData();
      } else {
        setNotification({
          kind: 'error',
          message: res?.last_reload_error || res?.message || 'Failed to reload Edge Access runtime.',
        });
      }
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error triggering runtime reload.' });
    } finally {
      setReloadingEngine(false);
    }
  };

  const handleTestProvider = async () => {
    setTestingProvider(true);
    try {
      if (idpFormType === 'jwt') {
        const res = await apiService.testEdgeAccessJwtIssuer({
          issuer: {
            name: idpFormName.trim(),
            issuer_url: idpFormIssuer.trim(),
            jwks_url: idpFormJwksUrl.trim() || undefined,
            audience: idpFormAudience.trim() || undefined,
            secret_key: idpFormSecretKey.trim() || undefined,
            algorithms: idpFormAlgorithms.split(',').map((a) => a.trim()).filter(Boolean),
          },
          fetch_jwks: true,
        });
        if (res.success && res.data) {
          const testStatus = res.data.status;
          if (testStatus === 'passed') {
            setNotification({ kind: 'success', message: 'JWT issuer verification succeeded.' });
          } else if (testStatus === 'warning') {
            const warningCheck = res.data.checks?.find((c: any) => c.status === 'warning');
            setNotification({ kind: 'info', message: warningCheck ? `Warning: ${warningCheck.message}` : 'JWT issuer verified with warnings.' });
          } else {
            const failCheck = res.data.checks?.find((c: any) => c.status === 'failed');
            setNotification({ kind: 'error', message: failCheck ? `Validation failed: ${failCheck.message}` : 'JWT issuer validation failed.' });
          }
        } else {
          setNotification({ kind: 'error', message: res.error || 'Failed to test JWT issuer.' });
        }
      } else {
        const res = await apiService.testEdgeAccessOidcProvider({
          provider_key: idpFormId.trim() || 'oidc-test',
          provider: {
            name: idpFormName.trim(),
            issuer: idpFormIssuer.trim(),
            client_id: idpFormClientId.trim() || undefined,
            client_secret: idpFormClientSecret.trim() || undefined,
            redirect_url: idpFormRedirectUrl.trim() || undefined,
            scopes: idpFormScopes.split(',').map((s) => s.trim()).filter(Boolean),
          },
          fetch_discovery: true,
        });
        if (res.success && res.data) {
          const testStatus = res.data.status;
          if (testStatus === 'passed') {
            setNotification({ kind: 'success', message: 'OIDC discovery and provider test succeeded.' });
          } else if (testStatus === 'warning') {
            const warningCheck = res.data.checks?.find((c: any) => c.status === 'warning');
            setNotification({ kind: 'info', message: warningCheck ? `Warning: ${warningCheck.message}` : 'OIDC provider verified with warnings.' });
          } else {
            const failCheck = res.data.checks?.find((c: any) => c.status === 'failed');
            setNotification({ kind: 'error', message: failCheck ? `Validation failed: ${failCheck.message}` : 'OIDC provider discovery failed.' });
          }
        } else {
          setNotification({ kind: 'error', message: res.error || 'Failed to test OIDC provider.' });
        }
      }
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Error testing identity provider connection.' });
    } finally {
      setTestingProvider(false);
    }
  };

  const handleCreateApp = async (deployDirectly = false) => {
    if (!newAppName.trim()) {
      setNotification({ kind: 'error', message: 'An App name is required.' });
      return;
    }

    if (newAppRouteMode === 'new') {
      if (!newAppRouteName.trim() || !newAppRouteHost.trim() || !newAppOriginUrl.trim()) {
        setNotification({ kind: 'error', message: 'Route name, public hostname, and origin URL are required to create a new route.' });
        return;
      }
    } else if (!newAppRouteId) {
      setNotification({ kind: 'error', message: 'Select a canonical Route.' });
      return;
    }

    const acceptedSources: AppTrustSource[] = [];
    if (newAppTrustBrowser) {
      acceptedSources.push({
        channel: 'browser_session',
        reference_mode: 'explicit',
        oidc_provider_id: newAppOidcProviderId || undefined,
      });
    }
    if (newAppTrustJwt) {
      acceptedSources.push({
        channel: 'bearer_jwt',
        reference_mode: 'explicit',
        jwt_issuer_url: newAppJwtProviderId ? idps.find(i => i.id === newAppJwtProviderId)?.issuer : undefined,
      });
    }
    if (newAppApiKey) {
      acceptedSources.push({ channel: 'api_key' });
    }
    if (newAppMtls) {
      acceptedSources.push({ channel: 'mtls' });
    }

    const selectedRoute = availableRoutes.find(r => r.id === newAppRouteId);

    const appPayload: any = {
      name: newAppName.trim(),
      default_action: 'deny',
      authorization_mode: 'policy_attachments',
      deployment_state: 'draft',
      accepted_trust_sources: acceptedSources,
    };
    if (newAppRouteMode === 'existing') {
      appPayload.route_id = newAppRouteId;
    }

    let createdApp: AppV2 | null = null;
    let createdRouteId = newAppRouteId;

    try {
      if (newAppRouteMode === 'new') {
        const res = await apiService.createEdgeAccessAppWithRoute(
          {
            name: newAppRouteName.trim(),
            hosts: [newAppRouteHost.trim()],
            paths: [newAppRoutePath.trim() || '/*'],
            origin_url: newAppOriginUrl.trim(),
            priority: newAppRoutePriority || 100,
            enabled: false,
          },
          appPayload
        );
        if (!res.success) {
          setNotification({ kind: 'error', message: res.error || 'Failed to create application with route.' });
          return;
        }
        createdApp = res.data?.protected_app || res.data;
        if (res.route_id) createdRouteId = res.route_id;
      } else {
        const res = await apiService.createEdgeAccessApp(appPayload);
        if (!res.success) {
          setNotification({ kind: 'error', message: res.error || 'Failed to create application.' });
          return;
        }
        createdApp = res.data?.protected_app || res.data;
      }
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error creating application.' });
      return;
    }

    if (!createdApp) {
      setNotification({ kind: 'error', message: 'Failed to create application on server.' });
      return;
    }

    const appId = createdApp.id;
    const newAddresses = newAppRouteMode === 'existing' && selectedRoute
      ? (selectedRoute.hosts || []).map(h => `${h}${(selectedRoute.paths && selectedRoute.paths[0]) || '/*'}`)
      : [`${newAppRouteHost.trim()}${newAppRoutePath.trim() || '/*'}`];

    const newItem: AppCatalogItem = {
      protected_app: {
        ...createdApp,
        route_id: createdApp.route_id || createdRouteId,
        route: createdApp.route || (newAppRouteMode === 'existing' && selectedRoute
          ? {
              id: selectedRoute.id || newAppRouteId,
              name: selectedRoute.name || newAppRouteId,
              hosts: selectedRoute.hosts || ['*'],
              paths: selectedRoute.paths || ['/*'],
              enabled: selectedRoute.enabled !== false,
              priority: selectedRoute.priority || 100,
              origin_url: selectedRoute.action?.upstream,
            }
          : {
              id: `rt-${appId}`,
              name: newAppRouteName.trim(),
              hosts: [newAppRouteHost.trim()],
              paths: [newAppRoutePath.trim() || '/*'],
              enabled: false,
              priority: newAppRoutePriority || 100,
              origin_url: newAppOriginUrl.trim(),
            }),
      },
      public_addresses: newAddresses,
      access_summary: {
        candidate_policy_count: 0,
        active_policy_count: 0,
        active_allow_count: 0,
      },
    };

    setCatalogItems([newItem, ...catalogItems]);
    setCreatingApp(false);
    setSelectedAppId(appId);
    setManagingPolicies(false);
    markDirty();

    setNewAppName('');
    setNewAppRouteMode('existing');
    setNewAppRouteName('');
    setNewAppRouteHost('');
    setNewAppOriginUrl('');
    setNewAppRoutePath('/*');
    setNewAppRoutePriority(100);

    setNotification({
      kind: 'success',
      message: 'Application saved.',
    });

    if (deployDirectly) {
      setConfirmDialog({
        open: true,
        title: 'Review policy deployment',
        message: "Confirm that you reviewed this candidate's policy impact before deployment. Candidate changes invalidate this confirmation.",
        confirmLabel: 'Acknowledge and deploy',
        danger: false,
        onConfirm: () => handleDeployApp(appId),
      });
    }
  };

  const handleDeployApp = async (appId: string) => {
    try {
      const res = await apiService.deployEdgeAccessApp(appId);
      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to deploy application.' });
        return;
      }
      const deployedApp = res.data?.protected_app || res.data;
      setCatalogItems(catalogItems.map(item => {
        if (item.protected_app.id !== appId) return item;
        return {
          ...item,
          protected_app: {
            ...item.protected_app,
            ...(deployedApp || {}),
            deployment_state: 'deployed',
            access_health: { state: 'active', reason_codes: [] },
          },
          access_summary: {
            ...item.access_summary,
            active_policy_count: Math.max(1, item.access_summary.candidate_policy_count),
            active_allow_count: Math.max(1, item.access_summary.candidate_policy_count),
            active_deployment_id: deployedApp?.active_deployment_id || `dep-${Date.now()}`,
          },
        };
      }));

      markDirty();
      setNotification({ kind: 'success', message: 'Application deployed successfully.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error deploying application.' });
    }
  };

  const handleRollbackApp = async (appId: string, deploymentId?: string) => {
    try {
      if (!deploymentId) {
        setNotification({ kind: 'error', message: 'No target deployment ID specified for rollback.' });
        return;
      }
      const res = await apiService.rollbackEdgeAccessApp(appId, deploymentId);
      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to rollback application.' });
        return;
      }
      await loadData();
      setNotification({ kind: 'info', message: 'Deployment rolled back to previous version.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error rolling back application.' });
    }
  };

  const handleDisableApp = async (appId: string) => {
    try {
      const targetApp = catalogItems.find(i => i.protected_app.id === appId)?.protected_app;
      if (targetApp) {
        await apiService.updateEdgeAccessApp(appId, { ...targetApp, deployment_state: 'disabled' });
      }
    } catch {
    }
    setCatalogItems(catalogItems.map(item => {
      if (item.protected_app.id !== appId) return item;
      return {
        ...item,
        protected_app: {
          ...item.protected_app,
          deployment_state: 'disabled',
          access_health: { state: 'disabled', reason_codes: ['OPERATOR_DISABLED'] },
        },
      };
    }));
    markDirty();
    setNotification({ kind: 'info', message: 'Application disabled.' });
  };

  const handleDeleteApp = async (appId: string, revision = 1) => {
    try {
      const targetApp = catalogItems.find(i => i.protected_app.id === appId)?.protected_app;
      const rev = targetApp?.revision ?? revision;
      const res = await apiService.deleteEdgeAccessApp(appId, rev);
      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to delete application.' });
        return;
      }
      setCatalogItems(catalogItems.filter(item => item.protected_app.id !== appId));
      if (selectedAppId === appId) {
        setSelectedAppId(null);
        setManagingPolicies(false);
      }
      markDirty();
      setNotification({ kind: 'info', message: 'Application removed.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error deleting application.' });
    }
  };

  const filteredCatalogItems = useMemo(() => {
    const q = appSearch.trim().toLowerCase();
    return catalogItems.filter((item) => {
      const app = item.protected_app;
      if (appStatusFilter && app.access_health.state !== appStatusFilter) {
        return false;
      }
      if (!q) return true;
      return (
        app.name.toLowerCase().includes(q) ||
        (app.route?.name && app.route.name.toLowerCase().includes(q)) ||
        item.public_addresses.some((addr) => addr.toLowerCase().includes(q)) ||
        (app.route?.hosts && app.route.hosts.some((h) => h.toLowerCase().includes(q)))
      );
    });
  }, [catalogItems, appSearch, appStatusFilter]);

  const paginatedCatalogItems = useMemo(() => {
    const start = (catalogPage - 1) * catalogPageSize;
    return filteredCatalogItems.slice(start, start + catalogPageSize);
  }, [filteredCatalogItems, catalogPage, catalogPageSize]);

  const selectedAppItem = useMemo(() => {
    if (!selectedAppId) return null;
    return catalogItems.find(item => item.protected_app.id === selectedAppId) || null;
  }, [catalogItems, selectedAppId]);

  const renderAppStatusPill = (health: AppAccessHealth) => {
    switch (health) {
      case 'active':
        return <Tag type="green" size="sm">Active</Tag>;
      case 'draft':
        return <Tag type="cool-gray" size="sm">Draft</Tag>;
      case 'deny_only':
        return <Tag type="warm-gray" size="sm">Deny-only</Tag>;
      case 'update_available':
        return <Tag type="blue" size="sm">Update available</Tag>;
      case 'disabled':
        return <Tag type="red" size="sm">Disabled</Tag>;
      case 'error':
        return <Tag type="magenta" size="sm">Error</Tag>;
      default:
        return <Tag type="gray" size="sm">{health}</Tag>;
    }
  };

  const filteredPolicies = useMemo(() => {
    const q = policySearch.trim().toLowerCase();
    return policies.filter((p) => {
      if (policyStatusFilter === 'active' && p.archived) return false;
      if (policyStatusFilter === 'archived' && !p.archived) return false;
      if (!q) return true;
      const name = p.name || '';
      const desc = p.description || '';
      return (
        name.toLowerCase().includes(q) ||
        desc.toLowerCase().includes(q)
      );
    });
  }, [policies, policySearch, policyStatusFilter]);

  const paginatedPolicies = useMemo(() => {
    const start = (policyPage - 1) * policyPageSize;
    return filteredPolicies.slice(start, start + policyPageSize);
  }, [filteredPolicies, policyPage, policyPageSize]);

  const filteredRoles = useMemo(() => {
    const q = roleSearch.trim().toLowerCase();
    return roles
      .filter((r) => {
        if (!q) return true;
        return r.name.toLowerCase().includes(q) || r.description.toLowerCase().includes(q);
      })
      .sort((left, right) => Number(right.is_builtin) - Number(left.is_builtin) || left.name.localeCompare(right.name));
  }, [roles, roleSearch]);

  const paginatedRoles = useMemo(() => {
    const start = (rolePage - 1) * rolePageSize;
    return filteredRoles.slice(start, start + rolePageSize);
  }, [filteredRoles, rolePage, rolePageSize]);

  const filteredDecisions = useMemo(() => {
    const q = decisionSearch.trim().toLowerCase();
    const hostname = decisionHostnameFilter.trim().toLowerCase();
    const identity = decisionIdentityFilter.trim().toLowerCase();
    const attachment = decisionAttachmentFilter.trim().toLowerCase();
    const version = decisionVersionFilter.trim();
    const fromTime = decisionFromFilter ? new Date(decisionFromFilter).getTime() : null;
    const toTime = decisionToFilter ? new Date(decisionToFilter).getTime() : null;

    return decisions.filter((d) => {
      if (decisionResultFilter && d.result.toLowerCase() !== decisionResultFilter.toLowerCase()) {
        return false;
      }

      if (decisionChannelFilter) {
        const dChannel = (d.auth_channel || '').toLowerCase();
        if (decisionChannelFilter === 'public') {
          if (!dChannel.includes('public') && !dChannel.includes('none')) return false;
        } else if (decisionChannelFilter === 'oidc') {
          if (!dChannel.includes('oidc') && !dChannel.includes('browser')) return false;
        } else if (decisionChannelFilter === 'jwt') {
          if (!dChannel.includes('jwt') && !dChannel.includes('bearer')) return false;
        } else if (decisionChannelFilter === 'api_key') {
          if (!dChannel.includes('api_key') && !dChannel.includes('key')) return false;
        } else if (decisionChannelFilter === 'mtls') {
          if (!dChannel.includes('mtls')) return false;
        } else {
          if (!dChannel.includes(decisionChannelFilter.toLowerCase())) return false;
        }
      }

      if (hostname && !(d.host || '').toLowerCase().includes(hostname)) {
        return false;
      }

      if (identity) {
        const idMatch = (d.identity_id || '').toLowerCase().includes(identity);
        const emailMatch = (d.identity_email || '').toLowerCase().includes(identity);
        if (!idMatch && !emailMatch) return false;
      }

      if (attachment && !(d.policy_attachment_id || '').toLowerCase().includes(attachment)) {
        return false;
      }

      if (version && String(d.policy_version ?? '') !== version) {
        return false;
      }

      if (fromTime || toTime) {
        const dTime = new Date(d.timestamp).getTime();
        if (!isNaN(dTime)) {
          if (fromTime && dTime < fromTime) return false;
          if (toTime && dTime > toTime) return false;
        }
      }

      if (q) {
        const targetReq = `${d.host || ''}${d.path || ''}`.toLowerCase();
        const reasonStr = `${d.reason_code || ''} ${d.reason || ''}`.toLowerCase();
        const appStr = `${d.protected_app_name || ''} ${d.protected_app_id || ''} ${d.route_id || ''}`.toLowerCase();
        const idStr = `${d.identity_id || ''} ${d.identity_email || ''}`.toLowerCase();
        const methodStr = (d.method || '').toLowerCase();
        const ipStr = (d.client_ip || '').toLowerCase();
        if (
          !targetReq.includes(q) &&
          !reasonStr.includes(q) &&
          !appStr.includes(q) &&
          !idStr.includes(q) &&
          !methodStr.includes(q) &&
          !ipStr.includes(q)
        ) {
          return false;
        }
      }

      return true;
    });
  }, [
    decisions,
    decisionSearch,
    decisionResultFilter,
    decisionHostnameFilter,
    decisionIdentityFilter,
    decisionChannelFilter,
    decisionAttachmentFilter,
    decisionVersionFilter,
    decisionFromFilter,
    decisionToFilter,
  ]);

  const paginatedDecisions = useMemo(() => {
    const start = (decisionPage - 1) * decisionPageSize;
    return filteredDecisions.slice(start, start + decisionPageSize);
  }, [filteredDecisions, decisionPage, decisionPageSize]);

  const handleOpenDecisionExplanation = async (decision: DecisionRecord) => {
    setDecisionExplanationModal({
      open: true,
      decision,
      loading: !decision.explanation && !decision.trace_steps,
    });
    if (!decision.explanation && !decision.trace_steps) {
      try {
        const detail = await apiService.getEdgeAccessDecisionDetail(decision.id);
        if (detail) {
          setDecisionExplanationModal((prev) => ({
            ...prev,
            decision: {
              ...decision,
              explanation: detail.explanation || decision.explanation,
              trace_steps: detail.trace_steps || detail.trace || decision.trace_steps,
            },
            loading: false,
          }));
        } else {
          setDecisionExplanationModal((prev) => ({ ...prev, loading: false }));
        }
      } catch {
        setDecisionExplanationModal((prev) => ({ ...prev, loading: false }));
      }
    }
  };

  const handleAttachPolicySubmit = async () => {
    if (!selectedAppId) return;
    const pol = policies.find(p => p.id === attachPolicyId);
    if (!pol) {
      setNotification({ kind: 'error', message: 'Choose a published Policy.' });
      return;
    }

    const currentAttachments = attachedPoliciesMap[selectedAppId] || [];
    const methodsList = parseMethodsInput(attachPolicyMethods);
    const isPublicBypass = pol.decision === 'public_bypass';
    const authChannels = isPublicBypass ? [] : ['oidc', 'jwt'];
    const principalsSummary = isPublicBypass
      ? 'Identity not required'
      : pol.principals?.any_authenticated
      ? 'Any authenticated identity'
      : (Array.isArray(pol.principals?.roles) && pol.principals.roles.length > 0)
      ? `Roles: ${pol.principals.roles.join(', ')}`
      : 'All authenticated';

    try {
      const res = await apiService.attachEdgeAccessPolicy({
        policy_id: pol.id,
        policy_version: pol.version,
        protected_app_id: selectedAppId,
        path: attachPolicyPath.trim() || '/*',
        methods: methodsList,
        auth_channels: authChannels,
        deployment_state: 'active',
        enabled: true,
      });

      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to attach policy.' });
        return;
      }

      const createdAtt = res.data;
      const newAtt: AppAttachedPolicy = {
        attachmentId: createdAtt?.id || `att-${Date.now()}`,
        policyId: pol.id,
        policyName: pol.name,
        version: pol.version,
        decision: pol.decision,
        path: attachPolicyPath.trim() || '/*',
        methods: methodsList,
        principalsSummary,
        deployed: true,
        updateAvailable: false,
      };

      setAttachedPoliciesMap({
        ...attachedPoliciesMap,
        [selectedAppId]: [...currentAttachments, newAtt],
      });

      setAttachPolicyModalOpen(false);
      setAttachPolicyPath('/*');
      setAttachPolicyMethods('');
      markDirty();
      setNotification({ kind: 'success', message: 'Policy attached as candidate configuration. Review deployment from the App.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error attaching policy.' });
    }
  };

  const handleDetachPolicy = async (attachmentId: string) => {
    if (!selectedAppId) return;
    try {
      const res = await apiService.detachEdgeAccessPolicy(attachmentId);
      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to detach policy.' });
        return;
      }
      const currentAttachments = attachedPoliciesMap[selectedAppId] || [];
      setAttachedPoliciesMap({
        ...attachedPoliciesMap,
        [selectedAppId]: currentAttachments.filter(a => a.attachmentId !== attachmentId),
      });
      markDirty();
      setNotification({ kind: 'info', message: 'Policy detached.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error detaching policy.' });
    }
  };

  const handleOpenPolicyEditor = async (policy?: AccessPolicy) => {
    if (policy) {
      setPolicyMode('edit');
      setEditingPolicyId(policy.id);
      setPolicyFormName(policy.name || '');
      setPolicyFormDesc(policy.description || '');
      setPolicyFormDecision(policy.decision || 'allow');
      setPolicyFormIdentityMode(policy.principals?.any_authenticated ? 'any' : 'specific');
      setPolicyFormGroups((policy.principals?.groups || []).join(', '));
      setPolicyFormRoles(policy.principals?.roles || []);
      setPolicyFormPermissions((policy.principals?.permissions || []).join(', '));
      setPolicyFormServiceIdentities((policy.principals?.service_identity_ids || []).join(', '));
      setPolicyFormClaims(JSON.stringify(policy.principals?.claims || [], null, 2));
      setPolicyFormMfa(Boolean(policy.requirements?.mfa_satisfied));
      setPolicyFormCidrs((policy.requirements?.source_cidrs || []).join(', '));
      setPolicyAdvancedIdentityOpen(
        Boolean(
          (policy.principals?.permissions && policy.principals.permissions.length > 0) ||
          (policy.principals?.service_identity_ids && policy.principals.service_identity_ids.length > 0) ||
          (policy.principals?.claims && policy.principals.claims.length > 0)
        )
      );

      try {
        const versionsRes = await apiService.getEdgeAccessPolicyVersions(policy.id);
        const versionsList = Array.isArray(versionsRes)
          ? versionsRes
          : (versionsRes?.versions && Array.isArray(versionsRes.versions) ? versionsRes.versions : []);
        if (versionsList.length > 0) {
          const draftVer = versionsList.find((v: any) => v.state === 'draft') || versionsList[versionsList.length - 1];
          if (draftVer) {
            if (draftVer.decision) setPolicyFormDecision(draftVer.decision);
            if (draftVer.principals) {
              setPolicyFormIdentityMode(draftVer.principals.any_authenticated ? 'any' : 'specific');
              if (Array.isArray(draftVer.principals.groups)) setPolicyFormGroups(draftVer.principals.groups.join(', '));
              if (Array.isArray(draftVer.principals.roles)) setPolicyFormRoles(draftVer.principals.roles);
              if (Array.isArray(draftVer.principals.permissions)) setPolicyFormPermissions(draftVer.principals.permissions.join(', '));
              if (Array.isArray(draftVer.principals.service_identity_ids)) setPolicyFormServiceIdentities(draftVer.principals.service_identity_ids.join(', '));
              if (Array.isArray(draftVer.principals.claims)) setPolicyFormClaims(JSON.stringify(draftVer.principals.claims, null, 2));
            }
            if (draftVer.requirements) {
              setPolicyFormMfa(Boolean(draftVer.requirements.mfa_satisfied));
              if (Array.isArray(draftVer.requirements.source_cidrs)) setPolicyFormCidrs(draftVer.requirements.source_cidrs.join(', '));
            }
          }
        }
      } catch (err) {
        console.warn('Could not fetch policy versions, using cached policy definition:', err);
      }
    } else {
      setPolicyMode('new');
      setEditingPolicyId(null);
      setPolicyFormName('');
      setPolicyFormDesc('');
      setPolicyFormDecision('allow');
      setPolicyFormIdentityMode('any');
      setPolicyFormGroups('');
      setPolicyFormRoles([]);
      setPolicyFormPermissions('');
      setPolicyFormServiceIdentities('');
      setPolicyFormClaims('[]');
      setPolicyFormMfa(false);
      setPolicyFormCidrs('');
      setPolicyAdvancedIdentityOpen(false);
    }
  };

  const handleSavePolicyDraft = async (publish = false) => {
    if (!policyFormName.trim()) {
      setNotification({ kind: 'error', message: 'A Policy name is required.' });
      return;
    }

    let parsedClaims: Array<{ name: string; operator: string; values: string[] }> = [];
    if (policyFormClaims.trim()) {
      try {
        const val = JSON.parse(policyFormClaims.trim());
        if (Array.isArray(val)) parsedClaims = val;
      } catch {
        setNotification({ kind: 'error', message: 'Claim conditions must be a valid JSON array.' });
        return;
      }
    }

    const groupsList = policyFormGroups.split(',').map((g) => g.trim()).filter(Boolean);
    const permsList = policyFormPermissions.split(',').map((p) => p.trim()).filter(Boolean);
    const svcsList = policyFormServiceIdentities.split(',').map((s) => s.trim()).filter(Boolean);
    const cidrsList = policyFormCidrs.split(',').map((c) => c.trim()).filter(Boolean);

    const draftPrincipals = {
      any_authenticated: policyFormDecision === 'public_bypass' ? false : policyFormIdentityMode === 'any',
      roles: policyFormDecision === 'public_bypass' || policyFormIdentityMode === 'any' ? [] : policyFormRoles,
      groups: policyFormDecision === 'public_bypass' || policyFormIdentityMode === 'any' ? [] : groupsList,
      permissions: policyFormDecision === 'public_bypass' || policyFormIdentityMode === 'any' ? [] : permsList,
      service_identity_ids: policyFormDecision === 'public_bypass' || policyFormIdentityMode === 'any' ? [] : svcsList,
      claims: policyFormDecision === 'public_bypass' || policyFormIdentityMode === 'any' ? [] : parsedClaims,
    };
    const draftRequirements = {
      mfa_satisfied: policyFormMfa,
      trusted_device: false,
      source_cidrs: cidrsList,
      countries: [],
    };

    if (policyMode === 'new') {
      try {
        const polRes = await apiService.createEdgeAccessPolicy({
          name: policyFormName.trim(),
          description: policyFormDesc.trim(),
        });
        if (!polRes.success) {
          setNotification({ kind: 'error', message: polRes.error || 'Failed to create policy.' });
          return;
        }
        const createdPolicyId = polRes.data?.id || polRes.data?.policy?.id;
        if (!createdPolicyId) {
          setNotification({ kind: 'error', message: 'Server did not return a valid policy ID.' });
          return;
        }

        const draftRes = await apiService.createEdgeAccessPolicyDraft(createdPolicyId, {
          decision: policyFormDecision,
          principals: draftPrincipals,
          requirements: draftRequirements,
        });
        if (!draftRes.success) {
          setNotification({ kind: 'error', message: draftRes.error || 'Failed to save policy draft.' });
          return;
        }

        if (publish) {
          const pubRes = await apiService.publishEdgeAccessPolicyVersion(createdPolicyId, 1, 1);
          if (!pubRes.success) {
            setNotification({ kind: 'error', message: pubRes.error || 'Failed to publish policy version.' });
            return;
          }
        }

        const newPol: AccessPolicy = {
          id: createdPolicyId,
          name: policyFormName.trim(),
          description: policyFormDesc.trim(),
          version: 1,
          decision: policyFormDecision,
          principals: draftPrincipals,
          requirements: draftRequirements,
          attachment_count: 0,
          protected_app_ids: [],
          update_available_count: 0,
          archived: false,
          updated_at: new Date().toISOString(),
        };

        setPolicies([newPol, ...policies]);
        setPolicyMode('list');
        setEditingPolicyId(null);
        markDirty();
        setNotification({
          kind: 'success',
          message: publish ? 'Published Policy Version v1. Attachments remain pinned until explicitly upgraded.' : 'Policy draft saved.',
        });
      } catch (err: any) {
        setNotification({ kind: 'error', message: err?.message || 'Network error saving policy.' });
      }
    } else if (editingPolicyId) {
      const existing = policies.find((p) => p.id === editingPolicyId);
      const nextVersion = publish ? ((existing?.version ?? 1) + 1) : (existing?.version ?? 1);

      try {
        const updateRes = await apiService.updateEdgeAccessPolicy(editingPolicyId, {
          name: policyFormName.trim(),
          description: policyFormDesc.trim(),
        });
        if (!updateRes.success) {
          setNotification({ kind: 'error', message: updateRes.error || 'Failed to update policy metadata.' });
          return;
        }

        const draftRes = await apiService.createEdgeAccessPolicyDraft(editingPolicyId, {
          decision: policyFormDecision,
          principals: draftPrincipals,
          requirements: draftRequirements,
        });
        if (!draftRes.success) {
          setNotification({ kind: 'error', message: draftRes.error || 'Failed to save policy draft.' });
          return;
        }

        if (publish) {
          const pubRes = await apiService.publishEdgeAccessPolicyVersion(editingPolicyId, nextVersion, 1);
          if (!pubRes.success) {
            setNotification({ kind: 'error', message: pubRes.error || 'Failed to publish policy version.' });
            return;
          }
        }

        setPolicies(
          policies.map((p) => {
            if (p.id !== editingPolicyId) return p;
            return {
              ...p,
              name: policyFormName.trim(),
              description: policyFormDesc.trim(),
              version: nextVersion,
              decision: policyFormDecision,
              principals: draftPrincipals,
              requirements: draftRequirements,
              updated_at: new Date().toISOString(),
            };
          })
        );

        if (publish) {
          const nextMap = { ...attachedPoliciesMap };
          let anyUpdated = false;
          Object.keys(nextMap).forEach((appId) => {
            nextMap[appId] = nextMap[appId].map((att) => {
              if (att.policyId === editingPolicyId && att.version < nextVersion) {
                anyUpdated = true;
                return { ...att, updateAvailable: true };
              }
              return att;
            });
          });
          if (anyUpdated) {
            setAttachedPoliciesMap(nextMap);
          }
        }

        setPolicyMode('list');
        setEditingPolicyId(null);
        markDirty();
        setNotification({
          kind: 'success',
          message: publish ? `Published Policy Version v${nextVersion}. Attachments remain pinned until explicitly upgraded.` : 'Policy draft saved.',
        });
      } catch (err: any) {
        setNotification({ kind: 'error', message: err?.message || 'Network error saving policy.' });
      }
    }
  };

  const handleArchivePolicyConfirm = (pol: AccessPolicy) => {
    const attachedApps = pol.protected_app_ids?.length || pol.attachment_count || 0;
    if (attachedApps > 0) {
      setNotification({
        kind: 'error',
        message: `Cannot archive policy "${pol.name}": it is currently attached to ${attachedApps} application(s). Detach it first.`
      });
      return;
    }

    setConfirmDialog({
      open: true,
      title: 'Archive policy',
      message: `Archive "${pol.name}"? Active Attachments must be detached first, and immutable Version history will remain available.`,
      confirmLabel: 'Archive policy',
      danger: true,
      onConfirm: async () => {
        try {
          const res = await apiService.archiveEdgeAccessPolicy(pol.id);
          if (!res.success) {
            setNotification({ kind: 'error', message: res.error || 'Failed to archive policy.' });
            return;
          }
          setPolicies(
            policies.map((p) => (p.id === pol.id ? { ...p, archived: true } : p))
          );
          markDirty();
          setNotification({ kind: 'success', message: 'Policy archived.' });
        } catch (err: any) {
          setNotification({ kind: 'error', message: err?.message || 'Network error archiving policy.' });
        }
      },
    });
  };

  const handleLibraryPolicyAttachSubmit = async () => {
    if (!libraryAttachModal.policy || !libraryAttachModal.appId) {
      setNotification({ kind: 'error', message: 'Choose an Application before attaching a Policy.' });
      return;
    }

    const pol = libraryAttachModal.policy;
    const appId = libraryAttachModal.appId;
    const currentAttachments = attachedPoliciesMap[appId] || [];
    const isPublicBypass = pol.decision === 'public_bypass';
    const authChannels = isPublicBypass ? [] : ['oidc', 'jwt'];

    try {
      const res = await apiService.attachEdgeAccessPolicy({
        policy_id: pol.id,
        policy_version: pol.version,
        protected_app_id: appId,
        path: '/*',
        methods: ['*'],
        auth_channels: authChannels,
        deployment_state: 'active',
        enabled: true,
      });

      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to attach policy.' });
        return;
      }

      const createdAtt = res.data;
      const newAtt: AppAttachedPolicy = {
        attachmentId: createdAtt?.id || `att-${Date.now()}`,
        policyId: pol.id,
        policyName: pol.name,
        version: pol.version,
        decision: pol.decision,
        path: '/*',
        methods: ['*'],
        principalsSummary:
          isPublicBypass
            ? 'Identity not required'
            : pol.principals?.any_authenticated
            ? 'Any authenticated identity'
            : (Array.isArray(pol.principals?.roles) && pol.principals.roles.length > 0)
            ? `Roles: ${pol.principals.roles.join(', ')}`
            : 'No identity restriction',
        deployed: true,
        updateAvailable: false,
      };

      setAttachedPoliciesMap({
        ...attachedPoliciesMap,
        [appId]: [...currentAttachments, newAtt],
      });

      setPolicies(
        policies.map((p) => {
          if (p.id !== pol.id) return p;
          const currentAppIds = Array.isArray(p.protected_app_ids) ? p.protected_app_ids : [];
          const nextAppIds = currentAppIds.includes(appId) ? currentAppIds : [...currentAppIds, appId];
          return {
            ...p,
            attachment_count: (p.attachment_count ?? 0) + 1,
            protected_app_ids: nextAppIds,
          };
        })
      );

      setLibraryAttachModal({ open: false, policy: null, appId: '' });
      markDirty();
      setNotification({
        kind: 'success',
        message: 'Policy attached as candidate configuration. Review deployment from the Application.',
      });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error attaching policy.' });
    }
  };

  const handleOpenProviderEditor = (provider?: IdentityProvider) => {
    if (provider) {
      const brand = detectProviderBrand(provider);
      setEditingProviderId(provider.id || provider.provider_id || '');
      setIdpFormType(provider.type);
      setIdpFormPreset(brand);
      setIdpFormId(provider.id || provider.provider_id || '');
      setIdpFormName(provider.name);
      setIdpFormIssuer(provider.issuer);
      setIdpFormClientId(provider.client_id || '');
      setIdpFormClientSecret('');
      setIdpFormRedirectUrl(provider.redirect_url || 'https://app.example.com/auth/callback');
      setIdpFormScopes(provider.scopes?.join(', ') || 'openid, profile, email');
      setIdpFormAudience(provider.audience || 'api://edge-access');
      setIdpFormAlgorithms(provider.algorithms?.join(', ') || 'RS256');
      setIdpFormJwksUrl(provider.jwks_url || '');
      setIdpFormSecretKey(provider.secret_key || '');
      setIdpAdvancedOpen(Boolean(provider.scopes && provider.scopes.join(', ') !== 'openid, profile, email'));
      setIdentityMode('edit');
    } else {
      const defaultTemplate = PROVIDER_TEMPLATES[0];
      setEditingProviderId(null);
      setIdpFormType('oidc');
      setIdpFormPreset(defaultTemplate.id);
      setIdpFormId('corporate-sso');
      setIdpFormName(defaultTemplate.namePlaceholder);
      setIdpFormIssuer(defaultTemplate.issuerPlaceholder);
      setIdpFormClientId('');
      setIdpFormClientSecret('');
      setIdpFormRedirectUrl('https://app.example.com/auth/callback');
      setIdpFormScopes('openid, profile, email');
      setIdpFormAudience('api://edge-access');
      setIdpFormAlgorithms('RS256');
      setIdpFormJwksUrl('');
      setIdpFormSecretKey('');
      setIdpAdvancedOpen(false);
      setIdpFormMachineName('');
      setIdpFormMachineExpiresIn('');
      setIdpFormMachineGroups('');
      setIdpFormMachineCertPem('');
      setIdpFormMachineRoles([]);
      setIdentityMode('new');
    }
  };

  const handleSelectProviderPreset = (presetId: string) => {
    const tmpl = PROVIDER_TEMPLATES.find((t) => t.id === presetId);
    if (!tmpl) return;
    setIdpFormPreset(tmpl.id);
    setIdpFormType(tmpl.type);
    setIdpFormName(tmpl.namePlaceholder);
    setIdpFormIssuer(tmpl.issuerPlaceholder);
    setIdpFormId(tmpl.type === 'oidc' ? `${tmpl.id}-sso` : `${tmpl.id}-api`);
  };

  const handleSaveProvider = async () => {
    if (!idpFormName.trim() || !idpFormIssuer.trim()) {
      setNotification({ kind: 'error', message: 'Display name and Issuer URL are required.' });
      return;
    }
    const scopesList = idpFormScopes.split(',').map((s) => s.trim()).filter(Boolean);
    const algosList = idpFormAlgorithms.split(',').map((a) => a.trim()).filter(Boolean);

    const providerPayload: any = {
      id: idpFormId.trim(),
      name: idpFormName.trim(),
      type: idpFormType === 'jwt' ? 'jwt' : 'oidc',
      issuer: idpFormIssuer.trim(),
      client_id: idpFormClientId.trim() || undefined,
      client_secret: idpFormClientSecret.trim() || undefined,
      redirect_url: idpFormRedirectUrl.trim() || undefined,
      audience: idpFormAudience.trim() || undefined,
      jwks_url: idpFormJwksUrl.trim() || undefined,
      secret_key: idpFormSecretKey.trim() || undefined,
      scopes: scopesList.length > 0 ? scopesList : ['openid', 'profile', 'email'],
      algorithms: algosList.length > 0 ? algosList : ['RS256'],
      identity_revision: identityRevision,
    };

    if (identityMode === 'new') {
      try {
        const res = await apiService.createEdgeAccessIdentityProvider(providerPayload);
        if (!res.success) {
          setNotification({ kind: 'error', message: res.error || 'Failed to create identity provider.' });
          return;
        }
        if (res.identity_revision) {
          setIdentityRevision(res.identity_revision);
        }
        const createdProvider = res.data;
        const newProvider: IdentityProvider = {
          id: createdProvider?.id || idpFormId.trim(),
          provider_id: createdProvider?.id || idpFormId.trim(),
          name: createdProvider?.name || idpFormName.trim(),
          type: createdProvider?.type || (idpFormType === 'jwt' ? 'jwt' : 'oidc'),
          preset: idpFormPreset,
          issuer: createdProvider?.issuer || idpFormIssuer.trim(),
          client_id: createdProvider?.client_id || idpFormClientId.trim() || undefined,
          redirect_url: createdProvider?.redirect_url || idpFormRedirectUrl.trim() || undefined,
          audience: createdProvider?.audience || idpFormAudience.trim() || undefined,
          jwks_url: createdProvider?.jwks_url || idpFormJwksUrl.trim() || undefined,
          secret_key: createdProvider?.secret_key || idpFormSecretKey.trim() || undefined,
          scopes: createdProvider?.scopes || (scopesList.length > 0 ? scopesList : ['openid', 'profile', 'email']),
          algorithms: createdProvider?.algorithms || (algosList.length > 0 ? algosList : ['RS256']),
          identity_mapping: createdProvider?.identity_mapping || {
            subject: 'sub',
            email: 'email',
            roles: 'roles',
            groups: 'groups',
          },
          validation: createdProvider?.validation || {
            status: 'valid',
            checked_at: new Date().toISOString(),
            checks: [
              { id: 'discovery', label: 'Issuer validation', status: 'passed', message: 'Issuer endpoint reachable.' },
            ],
          },
          usage: { protected_app_ids: [] },
          status: 'valid',
          status_message: 'Configuration active',
          apps_count: 0,
        };
        setIdps([newProvider, ...idps]);
        setIdentityMode('list');
        setEditingProviderId(null);
        markDirty();
        setNotification({ kind: 'success', message: 'Identity provider saved.' });
      } catch (err: any) {
        setNotification({ kind: 'error', message: err?.message || 'Network error saving identity provider.' });
      }
    } else if (editingProviderId) {
      try {
        const res = await apiService.updateEdgeAccessIdentityProvider(editingProviderId, providerPayload);
        if (!res.success) {
          setNotification({ kind: 'error', message: res.error || 'Failed to update identity provider.' });
          return;
        }
        if (res.identity_revision) {
          setIdentityRevision(res.identity_revision);
        }
        const updatedProvider = res.data;
        setIdps(
          idps.map((p) => {
            if (p.id !== editingProviderId && p.provider_id !== editingProviderId) return p;
            return {
              ...p,
              ...(updatedProvider || {}),
              name: idpFormName.trim(),
              issuer: idpFormIssuer.trim(),
              client_id: idpFormClientId.trim() || undefined,
              redirect_url: idpFormRedirectUrl.trim() || undefined,
              audience: idpFormAudience.trim() || undefined,
              jwks_url: idpFormJwksUrl.trim() || undefined,
              secret_key: idpFormSecretKey.trim() || undefined,
              scopes: scopesList.length > 0 ? scopesList : p.scopes,
              algorithms: algosList.length > 0 ? algosList : p.algorithms,
            };
          })
        );
        setIdentityMode('list');
        setEditingProviderId(null);
        markDirty();
        setNotification({ kind: 'success', message: 'Identity provider saved.' });
      } catch (err: any) {
        setNotification({ kind: 'error', message: err?.message || 'Network error updating identity provider.' });
      }
    }
  };

  const handleSaveMachineIdentity = async () => {
    if (!idpFormMachineName.trim()) {
      setNotification({ kind: 'error', message: 'Display name is required for machine identity.' });
      return;
    }
    const isApiKey = idpFormType === 'api_key';
    const isMtls = idpFormType === 'mtls';
    if (isMtls && !idpFormMachineCertPem.trim()) {
      setNotification({ kind: 'error', message: 'Certificate PEM is required for mTLS identity.' });
      return;
    }

    const payload = {
      name: idpFormMachineName.trim(),
      roles: idpFormMachineRoles,
      groups: idpFormMachineGroups.split(',').map((g) => g.trim()).filter(Boolean),
      expires_in: idpFormMachineExpiresIn.trim() || undefined,
      expires_at: idpFormMachineExpiresIn.trim() || undefined,
      certificate_pem: isMtls ? idpFormMachineCertPem.trim() : undefined,
      cert_pem: isMtls ? idpFormMachineCertPem.trim() : undefined,
    };

    try {
      if (isApiKey) {
        const res = await apiService.createEdgeAccessApiKeyCredential(payload);
        if (!res.success) {
          setNotification({ kind: 'error', message: res.error || 'Failed to generate API Key credential.' });
          return;
        }
        const newSvc: ServiceIdentity = res.data;
        setServiceIdentities([newSvc, ...serviceIdentities]);
        setIdentityMode('list');
        markDirty();

        setOneTimeSecretModal({
          open: true,
          secret: res.secret || '',
          warning: res.warning || 'Save this secret now. It cannot be retrieved later.',
        });
      } else {
        const res = await apiService.createEdgeAccessMtlsCredential(payload);
        if (!res.success) {
          setNotification({ kind: 'error', message: res.error || 'Failed to register mTLS credential.' });
          return;
        }
        const newSvc: ServiceIdentity = res.data;
        setServiceIdentities([newSvc, ...serviceIdentities]);
        setIdentityMode('list');
        markDirty();
        setNotification({ kind: 'success', message: 'Machine identity saved.' });
      }
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error creating machine identity.' });
    }
  };

  const handleValidateProvider = async (provider: IdentityProvider) => {
    try {
      const pId = provider.id || provider.provider_id || '';
      if (!pId) return;
      const res = await apiService.validateEdgeAccessIdentityProvider(pId, identityRevision);
      const validatedData = res.success ? res.data : null;
      setValidationModal({
        open: true,
        provider: {
          ...provider,
          validation: validatedData?.validation || provider.validation || {
            status: res.success ? 'valid' : 'invalid',
            checked_at: new Date().toISOString(),
            checks: [
              { id: 'discovery', label: 'Issuer discovery', status: res.success ? 'passed' : 'failed', message: res.success ? 'Issuer endpoint verified.' : (res.error || 'Validation failed.') },
            ],
          },
        },
      });
    } catch {
      setValidationModal({
        open: true,
        provider,
      });
    }
  };

  const handleDeleteProviderConfirm = (provider: IdentityProvider) => {
    setDeleteProviderModal({
      open: true,
      provider,
    });
  };

  const handleDeleteProviderSubmit = async () => {
    if (!deleteProviderModal.provider) return;
    const pId = deleteProviderModal.provider.id || deleteProviderModal.provider.provider_id || '';
    if (!pId) return;
    try {
      const res = await apiService.deleteEdgeAccessIdentityProvider(pId, identityRevision);
      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to delete identity provider.' });
        return;
      }
      if (res.identity_revision) {
        setIdentityRevision(res.identity_revision);
      }
      setIdps(idps.filter((p) => p.id !== pId && p.provider_id !== pId));
      setDeleteProviderModal({ open: false, provider: null });
      markDirty();
      setNotification({ kind: 'success', message: 'Identity provider deleted.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error deleting identity provider.' });
    }
  };

  const handleOpenClaimMapping = (provider: IdentityProvider) => {
    setClaimMappingModal({
      open: true,
      provider,
      subject: provider.identity_mapping?.subject || 'sub',
      email: provider.identity_mapping?.email || 'email',
      roles: provider.identity_mapping?.roles || 'roles',
      groups: provider.identity_mapping?.groups || 'groups',
      testClaimsJson: '{\n  "sub": "user_7482",\n  "email": "alice.secops@corp.internal",\n  "roles": ["admin", "sec-ops"],\n  "groups": ["engineering", "security"]\n}',
      previewText: null,
    });
  };

  const handlePreviewMappingSubmit = async () => {
    try {
      const parsed = JSON.parse(claimMappingModal.testClaimsJson);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Synthetic claims must be a JSON object.');
      }
      if (claimMappingModal.provider?.id) {
        const res = await apiService.previewEdgeAccessClaimMapping(claimMappingModal.provider.id, parsed);
        if (res.success && res.data) {
          const mapping = res.data.mapped_identity || res.data;
          const preview = `Subject: ${mapping.subject || '—'}\nEmail: ${mapping.email || '—'}\nRoles: ${Array.isArray(mapping.roles) ? mapping.roles.join(', ') : (mapping.roles || '—')}\nGroups: ${Array.isArray(mapping.groups) ? mapping.groups.join(', ') : (mapping.groups || '—')}`;
          setClaimMappingModal((prev) => ({ ...prev, previewText: preview }));
          return;
        }
      }
      const subVal = parsed[claimMappingModal.subject] ?? '—';
      const emailVal = parsed[claimMappingModal.email] ?? '—';
      const rolesVal = Array.isArray(parsed[claimMappingModal.roles])
        ? parsed[claimMappingModal.roles].join(', ')
        : parsed[claimMappingModal.roles] ?? '—';
      const groupsVal = Array.isArray(parsed[claimMappingModal.groups])
        ? parsed[claimMappingModal.groups].join(', ')
        : parsed[claimMappingModal.groups] ?? '—';

      const preview = `Subject: ${subVal}\nEmail: ${emailVal}\nRoles: ${rolesVal}\nGroups: ${groupsVal}`;
      setClaimMappingModal((prev) => ({ ...prev, previewText: preview }));
    } catch {
      setNotification({ kind: 'error', message: 'Synthetic claims must be a valid JSON object.' });
    }
  };

  const handleSaveClaimMappingSubmit = async () => {
    if (!claimMappingModal.provider) return;
    const pId = claimMappingModal.provider.id || claimMappingModal.provider.provider_id || '';
    if (!pId) return;
    const mappingObj = {
      subject: claimMappingModal.subject.trim() || 'sub',
      email: claimMappingModal.email.trim() || 'email',
      roles: claimMappingModal.roles.trim() || 'roles',
      groups: claimMappingModal.groups.trim() || 'groups',
    };

    try {
      const res = await apiService.saveEdgeAccessClaimMapping(pId, identityRevision, mappingObj);
      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to save claim mapping.' });
        return;
      }
      if (res.identity_revision) {
        setIdentityRevision(res.identity_revision);
      }
      setIdps(
        idps.map((p) => {
          if (p.id !== pId && p.provider_id !== pId) return p;
          return {
            ...p,
            identity_mapping: mappingObj,
          };
        })
      );
      setClaimMappingModal({ open: false, provider: null, subject: '', email: '', roles: '', groups: '', testClaimsJson: '', previewText: null });
      markDirty();
      setNotification({ kind: 'success', message: 'Claim mapping saved.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error saving claim mapping.' });
    }
  };

  const handleShowServiceUsage = (svc: ServiceIdentity) => {
    const matchingApps = catalogItems.filter((a) =>
      a.protected_app.accepted_trust_sources.some((t) => t.channel === svc.type)
    );
    const matchingAppIds = new Set(matchingApps.map((a) => a.protected_app.id));
    const relevantAttachments = Object.entries(attachedPoliciesMap)
      .filter(([appId]) => matchingAppIds.has(appId))
      .flatMap(([, atts]) => atts);
    const computedVersions = Array.from(new Set(relevantAttachments.map((a) => `v${a.version || 1}`)));
    const computedDeployments = Array.from(new Set(relevantAttachments.map((a) => (a.deployed ? 'active-edge' : 'pending-deployment'))));

    setUsageModal({
      open: true,
      identity: svc,
      apps: matchingApps.map((a) => a.protected_app.name),
      versions: computedVersions.length > 0 ? computedVersions : policies.length > 0 ? Array.from(new Set(policies.map((p) => `v${p.version || 1}`))) : ['v1.0.0'],
      deployments: computedDeployments.length > 0 ? computedDeployments : ['active-edge'],
    });
  };

  const handleOpenEditService = (svc: ServiceIdentity) => {
    setEditServiceIdentityModal({
      open: true,
      identity: svc,
      name: svc.name,
      roles: svc.roles,
      groups: svc.groups?.join(', ') || '',
      expiresIn: svc.expires_at || '',
      certPem: '',
    });
  };

  const handleSaveEditServiceSubmit = async () => {
    if (!editServiceIdentityModal.identity) return;
    const svcId = editServiceIdentityModal.identity.id;
    const isMtls = editServiceIdentityModal.identity.type === 'mtls';
    const updatePayload: Record<string, any> = {
      name: editServiceIdentityModal.name.trim() || editServiceIdentityModal.identity.name,
      roles: editServiceIdentityModal.roles,
      groups: editServiceIdentityModal.groups.split(',').map((g) => g.trim()).filter(Boolean),
      expires_in: editServiceIdentityModal.expiresIn.trim() || undefined,
      expires_at: editServiceIdentityModal.expiresIn.trim() || undefined,
    };
    if (isMtls && editServiceIdentityModal.certPem?.trim()) {
      updatePayload.certificate_pem = editServiceIdentityModal.certPem.trim();
      updatePayload.cert_pem = editServiceIdentityModal.certPem.trim();
    }

    try {
      const res = await apiService.updateEdgeAccessServiceCredential(svcId, updatePayload);
      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to update machine identity.' });
        return;
      }
      const updatedSvc = res.data || {
        ...editServiceIdentityModal.identity,
        ...updatePayload,
        updated_at: new Date().toISOString(),
      };
      setServiceIdentities(
        serviceIdentities.map((s) => (s.id === svcId ? updatedSvc : s))
      );
      setEditServiceIdentityModal({ open: false, identity: null, name: '', roles: [], groups: '', expiresIn: '', certPem: '' });
      markDirty();
      setNotification({ kind: 'success', message: 'Machine identity saved.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error updating machine identity.' });
    }
  };

  const handleRotateServiceConfirm = (svc: ServiceIdentity) => {
    setRotateServiceModal({ open: true, identity: svc });
  };

  const handleRotateServiceSubmit = async () => {
    if (!rotateServiceModal.identity) return;
    const svcId = rotateServiceModal.identity.id;
    const isApiKey = rotateServiceModal.identity.type === 'api_key';

    try {
      const res = await apiService.rotateEdgeAccessServiceCredential(svcId);
      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to rotate service credential.' });
        return;
      }
      const rotatedSvc = res.data;
      setServiceIdentities(
        serviceIdentities.map((s) => (s.id === svcId ? { ...s, ...(rotatedSvc || {}), updated_at: new Date().toISOString() } : s))
      );
      setRotateServiceModal({ open: false, identity: null });
      markDirty();

      if (isApiKey && res.secret) {
        setOneTimeSecretModal({
          open: true,
          secret: res.secret,
          warning: res.warning || 'Save this replacement secret now. It cannot be retrieved later.',
        });
      } else {
        setNotification({ kind: 'success', message: 'Machine identity rotated.' });
      }
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error rotating machine identity.' });
    }
  };

  const handleRevokeServiceConfirm = (svc: ServiceIdentity) => {
    setRevokeServiceModal({
      open: true,
      identity: svc,
      dependencies: catalogItems.filter((a) => a.protected_app.accepted_trust_sources.some((t) => t.channel === svc.type)).map((a) => a.protected_app.name),
    });
  };

  const handleRevokeServiceSubmit = async () => {
    if (!revokeServiceModal.identity) return;
    const svcId = revokeServiceModal.identity.id;

    try {
      const res = await apiService.revokeEdgeAccessServiceCredential(svcId);
      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to revoke service credential.' });
        return;
      }
      setServiceIdentities(
        serviceIdentities.map((s) => {
          if (s.id !== svcId) return s;
          return {
            ...s,
            status: 'revoked',
            revoked: true,
            updated_at: new Date().toISOString(),
          };
        })
      );
      setRevokeServiceModal({ open: false, identity: null, dependencies: [] });
      markDirty();
      setNotification({
        kind: 'success',
        message: 'Machine identity revoked. Affected authentication now fails closed.',
      });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error revoking machine identity.' });
    }
  };

  const handleOpenRoleEditor = (role?: AccessRole) => {
    if (role) {
      if (role.is_builtin) {
        setNotification({ kind: 'error', message: 'System roles are protected and cannot be edited.' });
        return;
      }
      setEditingRoleId(role.id);
      setRoleFormId(role.id);
      setRoleFormName(role.name);
      setRoleFormDesc(role.description || '');
      setRoleFormPermissions(role.permissions.join(', '));
      setRoleFormInherits(role.inherits || []);
      setRoleMode('edit');
    } else {
      setEditingRoleId(null);
      setRoleFormId('');
      setRoleFormName('');
      setRoleFormDesc('');
      setRoleFormPermissions('');
      setRoleFormInherits([]);
      setRoleMode('new');
    }
  };

  const handleSaveRole = async () => {
    const roleId = (editingRoleId || roleFormId).trim();
    const roleName = roleFormName.trim();
    if (!roleId || !roleName) {
      setNotification({ kind: 'error', message: 'Role ID and display name are required.' });
      return;
    }

    const perms = roleFormPermissions
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);

    if (perms.length === 0) {
      setNotification({ kind: 'error', message: 'Add at least one permission.' });
      return;
    }

    if (roleFormInherits.includes(roleId)) {
      setNotification({ kind: 'error', message: 'A role cannot inherit itself.' });
      return;
    }

    // Role cycle detection matching shell.ts
    const rolesByID = new Map(roles.map((r) => [r.id, r]));
    const reachesRole = (candidateID: string, visited = new Set<string>()): boolean => {
      if (candidateID === roleId) return true;
      if (visited.has(candidateID)) return false;
      visited.add(candidateID);
      return (rolesByID.get(candidateID)?.inherits || []).some((parentID) => reachesRole(parentID, visited));
    };

    if (roleFormInherits.some((parentID) => reachesRole(parentID))) {
      setNotification({ kind: 'error', message: 'This inheritance selection would create a role cycle.' });
      return;
    }

    if (roleMode === 'new') {
      const id = roleId.toLowerCase().replace(/[^a-z0-9_-]/g, '-');
      if (roles.some((r) => r.id === id)) {
        setNotification({ kind: 'error', message: `A role with ID "${id}" already exists.` });
        return;
      }
      const newRolePayload = {
        id,
        name: roleName,
        description: roleFormDesc.trim(),
        is_builtin: false,
        permissions: perms,
        inherits: roleFormInherits,
      };

      try {
        const res = await apiService.createEdgeAccessRole(newRolePayload);
        if (!res.success) {
          setNotification({ kind: 'error', message: res.error || 'Failed to create role.' });
          return;
        }
        const newR: AccessRole = {
          ...newRolePayload,
          assigned_apps_count: 0,
        };
        setRoles([...roles, newR]);
        setRoleMode('list');
        setEditingRoleId(null);
        markDirty();
        setNotification({ kind: 'success', message: 'Role created.' });
      } catch (err: any) {
        setNotification({ kind: 'error', message: err?.message || 'Network error creating role.' });
      }
    } else if (editingRoleId) {
      const updatePayload = {
        name: roleName,
        description: roleFormDesc.trim(),
        permissions: perms,
        inherits: roleFormInherits,
      };

      try {
        const res = await apiService.updateEdgeAccessRole(editingRoleId, updatePayload);
        if (!res.success) {
          setNotification({ kind: 'error', message: res.error || 'Failed to update role.' });
          return;
        }
        setRoles(
          roles.map((r) => {
            if (r.id !== editingRoleId) return r;
            return {
              ...r,
              ...updatePayload,
            };
          })
        );
        setRoleMode('list');
        setEditingRoleId(null);
        markDirty();
        setNotification({ kind: 'success', message: 'Role updated.' });
      } catch (err: any) {
        setNotification({ kind: 'error', message: err?.message || 'Network error updating role.' });
      }
    }
  };

  const handleDeleteRoleConfirm = (role: AccessRole) => {
    if (role.is_builtin) {
      setNotification({ kind: 'error', message: 'System roles are protected and cannot be deleted.' });
      return;
    }
    setDeleteRoleModal({ open: true, role });
  };

  const handleDeleteRoleSubmit = async () => {
    if (!deleteRoleModal.role) return;
    const rId = deleteRoleModal.role.id;
    try {
      const res = await apiService.deleteEdgeAccessRole(rId);
      if (!res.success) {
        setNotification({ kind: 'error', message: res.error || 'Failed to delete role.' });
        return;
      }
      setRoles(roles.filter((r) => r.id !== rId));
      setDeleteRoleModal({ open: false, role: null });
      markDirty();
      setNotification({ kind: 'success', message: 'Role deleted.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Network error deleting role.' });
    }
  };

  const currentAppAttachedPolicies = selectedAppId ? (attachedPoliciesMap[selectedAppId] || []) : [];

  const renderManagedRolePicker = ({
    rolesList,
    selected,
    onToggle,
    label = 'Available roles',
    emptyMessage = 'No other roles are available to inherit.',
    excludeId,
  }: {
    rolesList: AccessRole[];
    selected: string[];
    onToggle: (id: string) => void;
    label?: string;
    emptyMessage?: string;
    excludeId?: string;
  }) => {
    const safeRoles = Array.isArray(rolesList) ? rolesList : [];
    const safeSelected = Array.isArray(selected) ? selected : [];
    const available = safeRoles.filter((r) => r && r.id !== excludeId);
    return (
      <fieldset style={{ border: 'none', margin: 0, padding: 0 }}>
        <legend style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cds-text-primary)', marginBottom: '10px' }}>
          {label}
        </legend>
        {available.length === 0 ? (
          <p style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', margin: 0 }}>
            {emptyMessage}
          </p>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '10px', maxWidth: '800px' }}>
            {available.map((r) => {
              const checked = safeSelected.includes(r.id);
              const perms = Array.isArray(r.permissions) ? r.permissions : [];
              const directDesc = perms.includes('*')
                ? 'Full access'
                : `${perms.length} ${perms.length === 1 ? 'permission' : 'permissions'}`;
              const inheritsCount = Array.isArray(r.inherits) ? r.inherits.length : 0;
              return (
                <div
                  key={r.id}
                  role="checkbox"
                  aria-checked={checked}
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === ' ' || e.key === 'Enter') {
                      e.preventDefault();
                      onToggle(r.id);
                    }
                  }}
                  onClick={() => onToggle(r.id)}
                  style={{
                    minHeight: '58px',
                    padding: '10px 14px',
                    border: checked
                      ? '1px solid var(--cds-interactive, #ff832b)'
                      : '1px solid var(--cds-border-subtle)',
                    background: checked
                      ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.08))'
                      : 'var(--cds-layer-01)',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '12px',
                    cursor: 'pointer',
                    borderRadius: '4px',
                    transition: 'border-color 140ms ease, background 140ms ease',
                    userSelect: 'none',
                    outline: 'none',
                  }}
                >
                  <div
                    style={{
                      width: '18px',
                      height: '18px',
                      borderRadius: '3px',
                      marginTop: '2px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                      border: checked
                        ? '1px solid var(--cds-interactive, #ff832b)'
                        : '1px solid var(--cds-border-strong, #8d8d8d)',
                      background: checked
                        ? 'var(--cds-interactive, #ff832b)'
                        : 'var(--cds-field-01, transparent)',
                      color: '#ffffff',
                      transition: 'all 0.14s ease',
                    }}
                  >
                    {checked && <Checkmark size={12} />}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <strong style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                        {r.name}
                      </strong>
                      {r.is_builtin && (
                        <Tag size="sm" type="cool-gray" style={{ margin: 0, padding: '0 6px', fontSize: '11px', height: '18px' }}>
                          System
                        </Tag>
                      )}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px', lineHeight: 1.4 }}>
                      {directDesc}
                      {inheritsCount > 0 && ` · ${inheritsCount} inherited`}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </fieldset>
    );
  };

  const renderAppsCatalogTable = () => (
    <TableContainer>
      <TableToolbar>
        <TableToolbarContent>
          <TableToolbarSearch
            persistent
            placeholder="Search applications, routes, or hostnames"
            value={appSearch}
            onChange={(e: any) => {
              setAppSearch(e.target.value || '');
              setCatalogPage(1);
            }}
          />
          <div style={{ width: '180px' }}>
            <Select
              id="filter-status-select"
              labelText="Filter status select"
              hideLabel
              value={appStatusFilter}
              onChange={(e) => {
                setAppStatusFilter(e.target.value);
                setCatalogPage(1);
              }}
              size="sm"
            >
              <SelectItem value="" text="All statuses" />
              <SelectItem value="draft" text="Draft" />
              <SelectItem value="deny_only" text="Deny-only" />
              <SelectItem value="active" text="Active" />
              <SelectItem value="update_available" text="Update available" />
              <SelectItem value="disabled" text="Disabled" />
              <SelectItem value="error" text="Error" />
            </Select>
          </div>
          <Button
            kind="ghost"
            hasIconOnly
            renderIcon={Renew}
            iconDescription="Refresh"
            onClick={loadData}
          />
          <Button
            kind="primary"
            size="sm"
            renderIcon={Network_3}
            onClick={() => {
              setCreatingApp(true);
              setSelectedAppId(null);
              setManagingPolicies(false);
            }}
          >
            Add application
          </Button>
        </TableToolbarContent>
      </TableToolbar>

      <Table size="md" useZebraStyles={false} aria-label="Protected applications table">
        <TableHead>
          <TableRow>
            <TableHeader>Application</TableHeader>
            <TableHeader>Public address</TableHeader>
            <TableHeader>Access</TableHeader>
            <TableHeader>Status</TableHeader>
            <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
          </TableRow>
        </TableHead>
        <TableBody>
          {paginatedCatalogItems.map((item) => {
            const app = item.protected_app;
            return (
              <TableRow key={app.id}>
                <TableCell style={{ fontWeight: 600 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Network_3 size={16} style={{ color: 'var(--cds-icon-primary)', flexShrink: 0 }} />
                    <Button
                      kind="ghost"
                      size="sm"
                      style={{ padding: '0 4px', fontWeight: 600, color: 'var(--cds-link-primary)' }}
                      onClick={() => {
                        setSelectedAppId(app.id);
                        setManagingPolicies(false);
                      }}
                    >
                      {app.name}
                    </Button>
                  </div>
                </TableCell>
                <TableCell>
                  {item.public_addresses.length ? (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {item.public_addresses.map((addr, idx) => (
                        <span key={idx} style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontSize: '13px' }}>
                          {addr}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span style={{ color: 'var(--cds-text-muted, var(--cds-text-secondary))', fontSize: '13px' }}>
                      Route unavailable
                    </span>
                  )}
                </TableCell>
                <TableCell>
                  <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    {item.access_summary.active_allow_count === 0
                      ? 'No active policy'
                      : item.access_summary.active_allow_count === 1
                      ? '1 active policy'
                      : `${item.access_summary.active_allow_count} active policies`}
                  </span>
                </TableCell>
                <TableCell>
                  {renderAppStatusPill(app.access_health.state)}
                </TableCell>
                <TableCell style={{ textAlign: 'right' }}>
                  <OverflowMenu flipped size="sm" ariaLabel={`Actions for ${app.name}`}>
                    <OverflowMenuItem
                      itemText="Open application"
                      onClick={() => {
                        setSelectedAppId(app.id);
                        setManagingPolicies(false);
                      }}
                    />
                    {app.deployment_state !== 'disabled' && (
                      <OverflowMenuItem
                        itemText="Manage policies"
                        onClick={() => {
                          setSelectedAppId(app.id);
                          setManagingPolicies(true);
                        }}
                      />
                    )}
                    <OverflowMenuItem
                      itemText="View decisions"
                      onClick={() => {
                        setDecisionSearch(app.route?.hosts[0] || app.name);
                        goToView('access-decisions');
                      }}
                    />
                    {app.deployment_state === 'draft' && (
                      <OverflowMenuItem
                        itemText="Deploy application"
                        onClick={() => {
                          setConfirmDialog({
                            open: true,
                            title: 'Review policy deployment',
                            message: "Confirm that you reviewed this candidate's policy impact before deployment. Candidate changes invalidate this confirmation.",
                            confirmLabel: 'Acknowledge and deploy',
                            danger: false,
                            onConfirm: () => handleDeployApp(app.id),
                          });
                        }}
                      />
                    )}
                    {app.deployment_state !== 'disabled' ? (
                      <OverflowMenuItem
                        isDelete
                        itemText="Disable application"
                        onClick={() => {
                          setConfirmDialog({
                            open: true,
                            title: 'Disable App',
                            message: `Disable "${app.name}"? Edge Access will stop using this App configuration, while the Route and reusable Policies remain unchanged.`,
                            confirmLabel: 'Disable App',
                            danger: true,
                            onConfirm: () => handleDisableApp(app.id),
                          });
                        }}
                      />
                    ) : (
                      <OverflowMenuItem
                        isDelete
                        itemText="Delete application"
                        onClick={() => {
                          setConfirmDialog({
                            open: true,
                            title: 'Delete App',
                            message: `Delete "${app.name}"? App-scoped candidate attachments and runtime snapshots are removed. The canonical Route, reusable Policies, and audit evidence are preserved.`,
                            confirmLabel: 'Delete App',
                            danger: true,
                            onConfirm: () => handleDeleteApp(app.id, app.revision),
                          });
                        }}
                      />
                    )}
                  </OverflowMenu>
                </TableCell>
              </TableRow>
            );
          })}

          {filteredCatalogItems.length === 0 && (
            <TableRow>
              <TableCell colSpan={5} style={{ textAlign: 'center', padding: '40px' }}>
                <div style={{ fontWeight: 600, fontSize: '15px', marginBottom: '6px', color: 'var(--cds-text-primary)' }}>
                  No protected applications
                </div>
                <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                  Create an application when a published Route is ready to receive access control.
                </div>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>

      <Pagination
        backwardText="Previous page"
        forwardText="Next page"
        itemsPerPageText="Items per page:"
        page={catalogPage}
        pageNumberText="Page Number"
        pageSize={catalogPageSize}
        pageSizes={[5, 10, 20, 50]}
        totalItems={filteredCatalogItems.length}
        onChange={({ page, pageSize }) => {
          if (page) setCatalogPage(page);
          if (pageSize) setCatalogPageSize(pageSize);
        }}
      />
    </TableContainer>
  );

  const renderCurrentView = () => {
    switch (currentView) {
      case 'policies': {
        if (policyMode !== 'list') {
          const editingPolicy = policies.find((p) => p.id === editingPolicyId);
          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <div>
                <Button
                  kind="ghost"
                  size="sm"
                  renderIcon={ArrowLeft}
                  onClick={() => {
                    setPolicyMode('list');
                    setEditingPolicyId(null);
                  }}
                >
                  Back to access policies
                </Button>
              </div>

              <SectionCard
                title={
                  policyMode === 'new'
                    ? 'Create policy'
                    : editingPolicy?.name
                    ? `Edit ${editingPolicy.name} draft`
                    : 'Create policy'
                }
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
                  <div>
                    <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                      Policy details
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '640px' }}>
                      <TextInput
                        id="policy-form-name"
                        labelText="Policy name"
                        placeholder="e.g. Support team access"
                        value={policyFormName}
                        onChange={(e) => setPolicyFormName(e.target.value)}
                        required
                        autoComplete="off"
                      />
                      <TextArea
                        id="policy-form-desc"
                        labelText="Description"
                        placeholder="Describe what this policy authorizes"
                        value={policyFormDesc}
                        onChange={(e) => setPolicyFormDesc(e.target.value)}
                        rows={3}
                      />
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                      Decision
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
                      <div
                        role="radio"
                        aria-checked={policyFormDecision === 'allow'}
                        tabIndex={0}
                        onKeyDown={(e) => {
                          if (e.key === ' ' || e.key === 'Enter') {
                            e.preventDefault();
                            setPolicyFormDecision('allow');
                          }
                        }}
                        onClick={() => setPolicyFormDecision('allow')}
                        style={{
                          padding: '16px',
                          border: policyFormDecision === 'allow' ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                          background: policyFormDecision === 'allow' ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '12px',
                          outline: 'none',
                        }}
                      >
                        <input
                          type="radio"
                          name="policy_decision_radio"
                          checked={policyFormDecision === 'allow'}
                          onChange={() => setPolicyFormDecision('allow')}
                          style={{ marginTop: '3px' }}
                        />
                        <Security size={20} style={{ color: 'var(--cds-icon-primary)', marginTop: '2px', flexShrink: 0 }} />
                        <div>
                          <div style={{ fontSize: '14px', fontWeight: 600 }}>Allow</div>
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                            Permit matching requests.
                          </div>
                        </div>
                      </div>

                      <div
                        role="radio"
                        aria-checked={policyFormDecision === 'deny'}
                        tabIndex={0}
                        onKeyDown={(e) => {
                          if (e.key === ' ' || e.key === 'Enter') {
                            e.preventDefault();
                            setPolicyFormDecision('deny');
                          }
                        }}
                        onClick={() => setPolicyFormDecision('deny')}
                        style={{
                          padding: '16px',
                          border: policyFormDecision === 'deny' ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                          background: policyFormDecision === 'deny' ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '12px',
                          outline: 'none',
                        }}
                      >
                        <input
                          type="radio"
                          name="policy_decision_radio"
                          checked={policyFormDecision === 'deny'}
                          onChange={() => setPolicyFormDecision('deny')}
                          style={{ marginTop: '3px' }}
                        />
                        <Security size={20} style={{ color: 'var(--cds-support-error, #da1e28)', marginTop: '2px', flexShrink: 0 }} />
                        <div>
                          <div style={{ fontSize: '14px', fontWeight: 600 }}>Deny</div>
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                            Block and deny matching requests.
                          </div>
                        </div>
                      </div>

                      <div
                        role="radio"
                        aria-checked={policyFormDecision === 'public_bypass'}
                        tabIndex={0}
                        onKeyDown={(e) => {
                          if (e.key === ' ' || e.key === 'Enter') {
                            e.preventDefault();
                            setPolicyFormDecision('public_bypass');
                          }
                        }}
                        onClick={() => setPolicyFormDecision('public_bypass')}
                        style={{
                          padding: '16px',
                          border: policyFormDecision === 'public_bypass' ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                          background: policyFormDecision === 'public_bypass' ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '12px',
                          outline: 'none',
                        }}
                      >
                        <input
                          type="radio"
                          name="policy_decision_radio"
                          checked={policyFormDecision === 'public_bypass'}
                          onChange={() => setPolicyFormDecision('public_bypass')}
                          style={{ marginTop: '3px' }}
                        />
                        <Unlocked size={20} style={{ color: 'var(--cds-icon-primary)', marginTop: '2px', flexShrink: 0 }} />
                        <div>
                          <div style={{ fontSize: '14px', fontWeight: 600 }}>Public bypass</div>
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                            Allow public access without authentication.
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                      Identity criteria
                    </div>

                    {policyFormDecision === 'public_bypass' ? (
                      <InlineNotification
                        kind="info"
                        lowContrast
                        hideCloseButton
                        subtitle="Identity criteria not evaluated for Public bypass."
                      />
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
                          <div
                            role="radio"
                            aria-checked={policyFormIdentityMode === 'any'}
                            tabIndex={0}
                            onKeyDown={(e) => {
                              if (e.key === ' ' || e.key === 'Enter') {
                                e.preventDefault();
                                setPolicyFormIdentityMode('any');
                              }
                            }}
                            onClick={() => setPolicyFormIdentityMode('any')}
                            style={{
                              padding: '16px',
                              border: policyFormIdentityMode === 'any' ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                              background: policyFormIdentityMode === 'any' ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: '12px',
                              outline: 'none',
                            }}
                          >
                            <input
                              type="radio"
                              name="policy_id_mode_radio"
                              checked={policyFormIdentityMode === 'any'}
                              onChange={() => setPolicyFormIdentityMode('any')}
                              style={{ marginTop: '3px' }}
                            />
                            <UserAvatar size={20} style={{ color: 'var(--cds-icon-primary)', marginTop: '2px', flexShrink: 0 }} />
                            <div>
                              <div style={{ fontSize: '14px', fontWeight: 600 }}>Any authenticated identity</div>
                              <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                                Permit any verified user session.
                              </div>
                            </div>
                          </div>

                          <div
                            role="radio"
                            aria-checked={policyFormIdentityMode === 'specific'}
                            tabIndex={0}
                            onKeyDown={(e) => {
                              if (e.key === ' ' || e.key === 'Enter') {
                                e.preventDefault();
                                setPolicyFormIdentityMode('specific');
                              }
                            }}
                            onClick={() => setPolicyFormIdentityMode('specific')}
                            style={{
                              padding: '16px',
                              border: policyFormIdentityMode === 'specific' ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                              background: policyFormIdentityMode === 'specific' ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: '12px',
                              outline: 'none',
                            }}
                          >
                            <input
                              type="radio"
                              name="policy_id_mode_radio"
                              checked={policyFormIdentityMode === 'specific'}
                              onChange={() => setPolicyFormIdentityMode('specific')}
                              style={{ marginTop: '3px' }}
                            />
                            <Key size={20} style={{ color: 'var(--cds-icon-primary)', marginTop: '2px', flexShrink: 0 }} />
                            <div>
                              <div style={{ fontSize: '14px', fontWeight: 600 }}>Specific identities</div>
                              <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                                Restrict to selected groups, roles, or claims.
                              </div>
                            </div>
                          </div>
                        </div>

                        {policyFormIdentityMode === 'specific' && (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', padding: '16px', backgroundColor: 'var(--cds-layer-01)', border: '1px solid var(--cds-border-subtle)', borderRadius: '4px' }}>
                            <div style={{ maxWidth: '640px' }}>
                              <TextInput
                                id="policy-form-groups"
                                labelText="Groups"
                                placeholder="e.g. operations, incident-response"
                                helperText="Comma separated"
                                value={policyFormGroups}
                                onChange={(e) => setPolicyFormGroups(e.target.value)}
                              />
                            </div>

                            <div>
                              {renderManagedRolePicker({
                                rolesList: roles,
                                selected: policyFormRoles,
                                onToggle: (id) => {
                                  if (policyFormRoles.includes(id)) {
                                    setPolicyFormRoles(policyFormRoles.filter((r) => r !== id));
                                  } else {
                                    setPolicyFormRoles([...policyFormRoles, id]);
                                  }
                                },
                                label: 'Managed roles',
                                emptyMessage: 'Create a role before assigning role-based access.',
                              })}
                            </div>

                            <div style={{ borderTop: '1px solid var(--cds-border-subtle)', paddingTop: '12px' }}>
                              <button
                                type="button"
                                onClick={() => setPolicyAdvancedIdentityOpen(!policyAdvancedIdentityOpen)}
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
                                {policyAdvancedIdentityOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                                <span>Advanced identity matching</span>
                                <span style={{ fontSize: '12px', fontWeight: 400, color: 'var(--cds-text-secondary)' }}>
                                  (permissions, service IDs, claims)
                                </span>
                              </button>

                              {policyAdvancedIdentityOpen && (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '16px', maxWidth: '640px' }}>
                                  <TextInput
                                    id="policy-form-perms"
                                    labelText="RBAC permissions"
                                    placeholder="Enter required permissions"
                                    value={policyFormPermissions}
                                    onChange={(e) => setPolicyFormPermissions(e.target.value)}
                                  />
                                  <TextInput
                                    id="policy-form-service-ids"
                                    labelText="Service identity IDs"
                                    placeholder="Enter service identity IDs"
                                    helperText="Comma separated"
                                    value={policyFormServiceIdentities}
                                    onChange={(e) => setPolicyFormServiceIdentities(e.target.value)}
                                  />
                                  <TextArea
                                    id="policy-form-claims"
                                    labelText="Claim conditions (JSON)"
                                    placeholder="Valid JSON claim conditions"
                                    helperText="JSON array of claim conditions"
                                    value={policyFormClaims}
                                    onChange={(e) => setPolicyFormClaims(e.target.value)}
                                    rows={4}
                                  />
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  <div>
                    <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                      Requirements
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '640px' }}>
                      <Checkbox
                        id="policy-form-mfa"
                        labelText="Require MFA"
                        checked={policyFormMfa}
                        onChange={(_, { checked }) => setPolicyFormMfa(checked)}
                      />
                      <TextInput
                        id="policy-form-cidrs"
                        labelText="Source CIDRs"
                        placeholder="e.g. 203.0.113.0/24, 2001:db8::/32"
                        helperText="Comma separated"
                        value={policyFormCidrs}
                        onChange={(e) => setPolicyFormCidrs(e.target.value)}
                      />
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '12px', paddingTop: '20px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                    <Button
                      kind="primary"
                      renderIcon={Document}
                      onClick={() => handleSavePolicyDraft(false)}
                    >
                      Save draft
                    </Button>
                    {policyMode === 'edit' && (
                      <Button
                        kind="secondary"
                        onClick={() => handleSavePolicyDraft(true)}
                      >
                        Review and publish
                      </Button>
                    )}
                    <Button
                      kind="ghost"
                      onClick={() => {
                        setPolicyMode('list');
                        setEditingPolicyId(null);
                      }}
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
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <PageHeader
              title="Access policies"
              icon={Document}
            />
            <TableContainer>
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    placeholder="Search policies by name or description"
                    value={policySearch}
                    onChange={(e: any) => {
                      setPolicySearch(e.target.value || '');
                      setPolicyPage(1);
                    }}
                  />
                  <div style={{ width: '180px' }}>
                    <Select
                      id="policy-status-filter"
                      labelText="Policy status filter"
                      hideLabel
                      value={policyStatusFilter}
                      onChange={(e) => {
                        setPolicyStatusFilter(e.target.value);
                        setPolicyPage(1);
                      }}
                      size="md"
                    >
                      <SelectItem value="" text="All statuses" />
                      <SelectItem value="active" text="Active" />
                      <SelectItem value="archived" text="Archived" />
                    </Select>
                  </div>
                  <Button
                    kind="primary"
                    size="sm"
                    renderIcon={Document}
                    onClick={() => handleOpenPolicyEditor()}
                  >
                    New policy
                  </Button>
                </TableToolbarContent>
              </TableToolbar>

              <Table size="md" useZebraStyles={false} aria-label="Policy library table">
                <TableHead>
                  <TableRow>
                    <TableHeader>Policy</TableHeader>
                    <TableHeader>Decision</TableHeader>
                    <TableHeader>Applications</TableHeader>
                    <TableHeader>Status</TableHeader>
                    <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedPolicies.map((pol) => {
                    const appCount = Array.isArray(pol.protected_app_ids)
                      ? pol.protected_app_ids.length
                      : (pol.attachment_count ?? 0);
                    const appsText = appCount ? `${appCount} application${appCount === 1 ? '' : 's'}` : 'Not attached';
                    const decision = pol.decision || 'allow';
                    const decisionLabel = decision === 'public_bypass'
                      ? 'Public bypass'
                      : (decision.charAt(0).toUpperCase() + decision.slice(1));

                    return (
                      <TableRow key={pol.id}>
                        <TableCell style={{ fontWeight: 600 }}>
                          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                            <Document size={16} style={{ color: 'var(--cds-icon-primary)', marginTop: '6px', flexShrink: 0 }} />
                            <div>
                              <Button
                                kind="ghost"
                                size="sm"
                                style={{ padding: '0 4px', fontWeight: 600, color: 'var(--cds-link-primary)' }}
                                onClick={() => handleOpenPolicyEditor(pol)}
                              >
                                {pol.name || 'Unnamed policy'}
                              </Button>
                              {pol.description && (
                                <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', paddingLeft: '4px', marginTop: '2px' }}>
                                  {pol.description}
                                </div>
                              )}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Tag
                            type={
                              decision === 'allow'
                                ? 'green'
                                : decision === 'deny'
                                ? 'red'
                                : 'cool-gray'
                            }
                            size="sm"
                          >
                            {decisionLabel}
                          </Tag>
                        </TableCell>
                        <TableCell>
                          <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                            {appsText}
                          </span>
                        </TableCell>
                        <TableCell>
                          {pol.archived ? (
                            <Tag type="gray" size="sm">Archived</Tag>
                          ) : pol.update_available_count ? (
                            <Tag type="blue" size="sm">
                              {pol.update_available_count} update{pol.update_available_count === 1 ? '' : 's'}
                            </Tag>
                          ) : (
                            <Tag type="green" size="sm">Current</Tag>
                          )}
                        </TableCell>
                        <TableCell style={{ textAlign: 'right' }}>
                          <OverflowMenu flipped size="sm" ariaLabel={`Actions for ${pol.name}`}>
                            {!pol.archived && (
                              <OverflowMenuItem
                                itemText="Attach policy"
                                onClick={() =>
                                  setLibraryAttachModal({
                                    open: true,
                                    policy: pol,
                                    appId: catalogItems[0]?.protected_app.id || '',
                                  })
                                }
                              />
                            )}
                            <OverflowMenuItem
                              itemText="Open policy"
                              onClick={() => handleOpenPolicyEditor(pol)}
                            />
                            <OverflowMenuItem
                              itemText="View decisions"
                              onClick={() => {
                                setDecisionSearch(pol.name);
                                goToView('access-decisions');
                              }}
                            />
                            {!pol.archived && (
                              <OverflowMenuItem
                                isDelete
                                itemText="Archive policy"
                                onClick={() => handleArchivePolicyConfirm(pol)}
                              />
                            )}
                          </OverflowMenu>
                        </TableCell>
                      </TableRow>
                    );
                  })}

                  {filteredPolicies.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} style={{ textAlign: 'center', padding: '40px' }}>
                        <div style={{ fontWeight: 600, fontSize: '15px', marginBottom: '6px', color: 'var(--cds-text-primary)' }}>
                          No reusable policies
                        </div>
                        <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                          Create a policy to reuse authorization logic across applications.
                        </div>
                        <Button
                          kind="primary"
                          size="sm"
                          renderIcon={Document}
                          onClick={() => handleOpenPolicyEditor()}
                        >
                          New policy
                        </Button>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>

              <Pagination
                backwardText="Previous page"
                forwardText="Next page"
                itemsPerPageText="Items per page:"
                page={policyPage}
                pageNumberText="Page Number"
                pageSize={policyPageSize}
                pageSizes={[5, 10, 20]}
                totalItems={filteredPolicies.length}
                onChange={({ page, pageSize }) => {
                  if (page) setPolicyPage(page);
                  if (pageSize) setPolicyPageSize(pageSize);
                }}
              />
            </TableContainer>
          </div>
        );
      }
      case 'identity': {
        type InventoryItem =
          | { kind: 'provider'; data: IdentityProvider }
          | { kind: 'machine'; data: ServiceIdentity };

        const allInventory: InventoryItem[] = [
          ...idps.map((p) => ({ kind: 'provider' as const, data: p })),
          ...serviceIdentities.map((s) => ({ kind: 'machine' as const, data: s })),
        ].sort((a, b) => a.data.name.localeCompare(b.data.name));

        const filteredInventory = allInventory.filter((item) => {
          if (!identitySearch.trim()) return true;
          const q = identitySearch.toLowerCase();
          if (item.kind === 'provider') {
            return (
              item.data.name.toLowerCase().includes(q) ||
              item.data.issuer.toLowerCase().includes(q) ||
              item.data.type.toLowerCase().includes(q)
            );
          } else {
            return (
              item.data.name.toLowerCase().includes(q) ||
              (item.data.key_prefix && item.data.key_prefix.toLowerCase().includes(q)) ||
              (item.data.fingerprint && item.data.fingerprint.toLowerCase().includes(q)) ||
              item.data.type.toLowerCase().includes(q)
            );
          }
        });

        const pagedInventory = filteredInventory.slice(
          (identityPage - 1) * identityPageSize,
          identityPage * identityPageSize
        );

        if (identityMode !== 'list') {
          const isEditing = identityMode === 'edit';
          const editingProvider = isEditing
            ? idps.find((p) => p.id === editingProviderId || p.provider_id === editingProviderId)
            : undefined;
          const currentTemplate = PROVIDER_TEMPLATES.find((t) => t.id === idpFormPreset);
          const isMachine = !isEditing && (idpFormType === 'api_key' || idpFormType === 'mtls');

          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <Button
                  kind="ghost"
                  size="sm"
                  renderIcon={ArrowLeft}
                  onClick={() => {
                    setIdentityMode('list');
                    setEditingProviderId(null);
                  }}
                >
                  Back to identity sources
                </Button>
              </div>

              <SectionCard
                title={isEditing ? `Edit ${editingProvider?.name || 'provider'}` : 'Add identity source'}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
                  {!isEditing && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                      <div>
                        <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                          Connection type
                        </div>
                      </div>

                      <div style={{ maxWidth: '400px' }}>
                        <Select
                          id="idp-type-select"
                          labelText="Identity type"
                          value={idpFormType}
                          onChange={(e) => {
                            const val = e.target.value as any;
                            setIdpFormType(val);
                            if (val === 'oidc') {
                              handleSelectProviderPreset('entra');
                            } else if (val === 'jwt') {
                              handleSelectProviderPreset('entra-jwt');
                            }
                          }}
                        >
                          <SelectItem value="" text="Choose an identity type" />
                          <SelectItem value="oidc" text="Workforce provider (OIDC)" />
                          <SelectItem value="jwt" text="Token issuer (JWT)" />
                          <SelectItem value="api_key" text="Machine identity (API key)" />
                          <SelectItem value="mtls" text="Machine identity (mTLS)" />
                        </Select>
                      </div>

                      {idpFormType === 'oidc' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '8px' }}>
                          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                            OpenID Connect providers
                          </div>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px' }}>
                            {PROVIDER_TEMPLATES.filter((t) => t.type === 'oidc').map((tmpl) => {
                              const isSelected = idpFormPreset === tmpl.id;
                              return (
                                <div
                                  key={tmpl.id}
                                  onClick={() => handleSelectProviderPreset(tmpl.id)}
                                  style={{
                                    padding: '16px',
                                    border: isSelected ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                                    background: isSelected ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                                    cursor: 'pointer',
                                    display: 'flex',
                                    gap: '12px',
                                    position: 'relative',
                                  }}
                                >
                                  {renderProviderBrandMark(tmpl.id, tmpl.name)}
                                  <div style={{ flex: 1 }}>
                                    <div style={{ fontSize: '13px', fontWeight: 600 }}>{tmpl.name}</div>
                                    <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', marginTop: '2px', lineHeight: 1.3 }}>
                                      {tmpl.description}
                                    </div>
                                    <div style={{ marginTop: '6px' }}>
                                      <Tag size="sm" type="cool-gray">OpenID Connect</Tag>
                                    </div>
                                  </div>
                                  {isSelected && (
                                    <CheckmarkFilled size={16} style={{ color: 'var(--cds-interactive, #ff832b)' }} />
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {idpFormType === 'jwt' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '8px' }}>
                          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                            JWT issuers
                          </div>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px' }}>
                            {PROVIDER_TEMPLATES.filter((t) => t.type === 'jwt').map((tmpl) => {
                              const isSelected = idpFormPreset === tmpl.id;
                              return (
                                <div
                                  key={tmpl.id}
                                  onClick={() => handleSelectProviderPreset(tmpl.id)}
                                  style={{
                                    padding: '16px',
                                    border: isSelected ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                                    background: isSelected ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                                    cursor: 'pointer',
                                    display: 'flex',
                                    gap: '12px',
                                    position: 'relative',
                                  }}
                                >
                                  {renderProviderBrandMark(tmpl.id, tmpl.name)}
                                  <div style={{ flex: 1 }}>
                                    <div style={{ fontSize: '13px', fontWeight: 600 }}>{tmpl.name}</div>
                                    <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', marginTop: '2px', lineHeight: 1.3 }}>
                                      {tmpl.description}
                                    </div>
                                    <div style={{ marginTop: '6px' }}>
                                      <Tag size="sm" type="cool-gray">Bearer token verification</Tag>
                                    </div>
                                  </div>
                                  {isSelected && (
                                    <CheckmarkFilled size={16} style={{ color: 'var(--cds-interactive, #ff832b)' }} />
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {(idpFormType === 'oidc' || idpFormType === 'jwt') && currentTemplate && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', borderTop: isEditing ? 'none' : '1px solid var(--cds-border-subtle)', paddingTop: isEditing ? '0' : '20px' }}>
                      <div>
                        <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                          {isEditing ? 'Provider configuration' : `Configure ${currentTemplate.name}`}
                        </div>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px', maxWidth: '800px' }}>
                        <TextInput
                          id="idp-form-id"
                          labelText="Provider ID"
                          placeholder={idpFormType === 'oidc' ? 'corporate-sso' : 'production-api'}
                          value={idpFormId}
                          disabled={isEditing}
                          onChange={(e) => setIdpFormId(e.target.value)}
                          required
                        />
                        <TextInput
                          id="idp-form-name"
                          labelText="Display name"
                          placeholder={currentTemplate.namePlaceholder}
                          value={idpFormName}
                          onChange={(e) => setIdpFormName(e.target.value)}
                          required
                        />
                        <div style={{ gridColumn: '1 / -1' }}>
                          <TextInput
                            id="idp-form-issuer"
                            labelText="Issuer URL"
                            placeholder={currentTemplate.issuerPlaceholder}
                            value={idpFormIssuer}
                            onChange={(e) => setIdpFormIssuer(e.target.value)}
                            required
                          />
                        </div>

                        {idpFormType === 'oidc' ? (
                          <>
                            <TextInput
                              id="idp-form-client-id"
                              labelText="Client ID"
                              placeholder="Application client ID"
                              value={idpFormClientId}
                              onChange={(e) => setIdpFormClientId(e.target.value)}
                              required
                            />
                            <TextInput
                              id="idp-form-client-secret"
                              type="password"
                              labelText="Client secret"
                              placeholder={isEditing ? 'Leave empty to keep current secret' : 'Enter client secret'}
                              value={idpFormClientSecret}
                              onChange={(e) => setIdpFormClientSecret(e.target.value)}
                            />
                            <div style={{ gridColumn: '1 / -1' }}>
                              <TextInput
                                id="idp-form-redirect-url"
                                labelText="Redirect URL"
                                placeholder="https://app.example.com/auth/callback"
                                value={idpFormRedirectUrl}
                                onChange={(e) => setIdpFormRedirectUrl(e.target.value)}
                                required
                              />
                            </div>
                          </>
                        ) : (
                          <>
                            <TextInput
                              id="idp-form-audience"
                              labelText="Audience"
                              placeholder="api://edge-access"
                              value={idpFormAudience}
                              onChange={(e) => setIdpFormAudience(e.target.value)}
                            />
                            <TextInput
                              id="idp-form-algorithms"
                              labelText="Algorithms"
                              placeholder="RS256"
                              value={idpFormAlgorithms}
                              onChange={(e) => setIdpFormAlgorithms(e.target.value)}
                            />
                            <div style={{ gridColumn: '1 / -1' }}>
                              <TextInput
                                id="idp-form-jwks-url"
                                labelText="JWKS URL"
                                placeholder={isEditing ? 'Leave empty to keep the configured URL' : 'https://issuer.example.com/.well-known/jwks.json'}
                                value={idpFormJwksUrl}
                                onChange={(e) => setIdpFormJwksUrl(e.target.value)}
                              />
                            </div>
                            <div style={{ gridColumn: '1 / -1' }}>
                              <TextArea
                                id="idp-form-secret-key"
                                labelText="Verification secret or public key"
                                placeholder={isEditing ? 'Leave empty to keep existing material' : 'Paste verification material'}
                                value={idpFormSecretKey}
                                onChange={(e) => setIdpFormSecretKey(e.target.value)}
                                rows={4}
                              />
                            </div>
                          </>
                        )}
                      </div>

                      {idpFormType === 'oidc' && (
                        <div style={{ borderTop: '1px solid var(--cds-border-subtle)', paddingTop: '12px' }}>
                          <button
                            type="button"
                            onClick={() => setIdpAdvancedOpen(!idpAdvancedOpen)}
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
                            {idpAdvancedOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                            <span>Advanced settings</span>
                            <span style={{ fontSize: '12px', fontWeight: 400, color: 'var(--cds-text-secondary)' }}>
                              (OIDC scopes)
                            </span>
                          </button>

                          {idpAdvancedOpen && (
                            <div style={{ marginTop: '16px', maxWidth: '640px' }}>
                              <TextInput
                                id="idp-form-scopes"
                                labelText="Scopes"
                                value={idpFormScopes}
                                onChange={(e) => setIdpFormScopes(e.target.value)}
                                helperText="Comma-separated scopes requested from provider."
                              />
                            </div>
                          )}
                        </div>
                      )}

                      <div style={{ display: 'flex', gap: '12px', paddingTop: '16px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                        <Button kind="primary" onClick={handleSaveProvider}>
                          {isEditing ? 'Save Changes' : 'Add provider'}
                        </Button>
                        <Button
                          kind="secondary"
                          onClick={handleTestProvider}
                          disabled={testingProvider || !idpFormIssuer.trim()}
                        >
                          {testingProvider ? 'Testing...' : 'Test connection'}
                        </Button>
                      </div>
                    </div>
                  )}

                  {isMachine && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', borderTop: '1px solid var(--cds-border-subtle)', paddingTop: '20px' }}>
                      <div>
                        <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '4px', color: 'var(--cds-text-primary)' }}>
                          {idpFormType === 'api_key' ? 'Configure API key' : 'Configure mTLS identity'}
                        </div>
                        <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                          {idpFormType === 'api_key'
                            ? 'Create a credential for an automated client or service.'
                            : 'Register a client certificate for mutual TLS authentication.'}
                        </div>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px', maxWidth: '800px' }}>
                        <TextInput
                          id="machine-name"
                          labelText="Display name"
                          placeholder={idpFormType === 'api_key' ? 'Deployment automation' : 'Production service certificate'}
                          value={idpFormMachineName}
                          onChange={(e) => setIdpFormMachineName(e.target.value)}
                          required
                        />
                        <TextInput
                          id="machine-expires"
                          labelText="Expires in"
                          placeholder="Optional, for example 90d"
                          value={idpFormMachineExpiresIn}
                          onChange={(e) => setIdpFormMachineExpiresIn(e.target.value)}
                        />
                        <div style={{ gridColumn: '1 / -1' }}>
                          <TextInput
                            id="machine-groups"
                            labelText="Groups"
                            placeholder="Comma-separated groups"
                            value={idpFormMachineGroups}
                            onChange={(e) => setIdpFormMachineGroups(e.target.value)}
                          />
                        </div>
                        {idpFormType === 'mtls' && (
                          <div style={{ gridColumn: '1 / -1' }}>
                            <TextArea
                              id="machine-cert"
                              labelText="Certificate PEM"
                              placeholder="Paste the client certificate in PEM format"
                              value={idpFormMachineCertPem}
                              onChange={(e) => setIdpFormMachineCertPem(e.target.value)}
                              rows={5}
                              required
                            />
                          </div>
                        )}
                      </div>

                      <div style={{ maxWidth: '800px' }}>
                        {renderManagedRolePicker({
                          rolesList: roles,
                          selected: idpFormMachineRoles,
                          onToggle: (id) => {
                            if (idpFormMachineRoles.includes(id)) {
                              setIdpFormMachineRoles(idpFormMachineRoles.filter((rId) => rId !== id));
                            } else {
                              setIdpFormMachineRoles([...idpFormMachineRoles, id]);
                            }
                          },
                          label: 'Assigned roles',
                          emptyMessage: 'Create a role before assigning role-based access.',
                        })}
                      </div>

                      <div style={{ display: 'flex', gap: '12px', paddingTop: '16px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                        <Button kind="primary" onClick={handleSaveMachineIdentity}>
                          Create identity
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              </SectionCard>
            </div>
          );
        }

        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <PageHeader
              title="Identity & trust"
              icon={UserAvatar}
            />
            <TableContainer>
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    placeholder="Search identity sources..."
                    value={identitySearch}
                    onChange={(e: any) => setIdentitySearch(e.target.value || '')}
                  />
                  <Button
                    kind="primary"
                    size="sm"
                    renderIcon={Add}
                    onClick={() => handleOpenProviderEditor()}
                  >
                    Add identity source
                  </Button>
                </TableToolbarContent>
              </TableToolbar>

              <Table size="md" useZebraStyles={false} aria-label="Identity sources table">
                <TableHead>
                  <TableRow>
                    <TableHeader>Identity source</TableHeader>
                    <TableHeader>Type</TableHeader>
                    <TableHeader>Status</TableHeader>
                    <TableHeader>Used by</TableHeader>
                    <TableHeader>Last activity</TableHeader>
                    <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pagedInventory.map((item) => {
                    if (item.kind === 'provider') {
                      const provider = item.data;
                      const brand = detectProviderBrand(provider);
                      const isOidc = provider.type === 'oidc';
                      const statusVal = provider.validation?.status || provider.status || 'not_validated';
                      const appsUsed = provider.usage?.protected_app_ids?.length || provider.apps_count || 0;
                      const lastChecked = provider.validation?.checked_at
                        ? new Date(provider.validation.checked_at).toLocaleString()
                        : 'Never validated';

                      return (
                        <TableRow key={provider.id || provider.provider_id}>
                          <TableCell style={{ fontWeight: 600 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                              {renderProviderBrandMark(brand, provider.name)}
                              <div>
                                <div style={{ fontSize: '14px', fontWeight: 600 }}>{provider.name}</div>
                                <div style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontSize: '11px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                                  {provider.issuer}
                                </div>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <div>
                              <div style={{ fontSize: '13px', fontWeight: 600 }}>
                                {isOidc ? 'Workforce provider' : 'Token issuer'}
                              </div>
                              <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                                {isOidc ? 'OpenID Connect' : 'JWT'}
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Tag
                              type={
                                statusVal === 'valid'
                                  ? 'green'
                                  : statusVal === 'warning'
                                  ? 'warm-gray'
                                  : statusVal === 'failed'
                                  ? 'red'
                                  : 'cool-gray'
                              }
                              size="sm"
                            >
                              {statusVal === 'valid' ? 'Valid' : statusVal === 'warning' ? 'Warning' : statusVal === 'failed' ? 'Failed' : 'Not validated'}
                            </Tag>
                          </TableCell>
                          <TableCell>
                            {appsUsed > 0 ? (
                              <span style={{ fontSize: '13px', fontWeight: 600 }}>
                                {appsUsed} {appsUsed === 1 ? 'application' : 'applications'}
                              </span>
                            ) : (
                              <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>Not assigned</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                              {lastChecked}
                            </span>
                          </TableCell>
                          <TableCell style={{ textAlign: 'right' }}>
                            <OverflowMenu flipped size="sm" ariaLabel={`Actions for ${provider.name}`}>
                              <OverflowMenuItem
                                itemText="Validate provider"
                                onClick={() => handleValidateProvider(provider)}
                              />
                              <OverflowMenuItem
                                itemText="Edit provider"
                                onClick={() => handleOpenProviderEditor(provider)}
                              />
                              <OverflowMenuItem
                                itemText="Edit claim mapping"
                                onClick={() => handleOpenClaimMapping(provider)}
                              />
                              <OverflowMenuItem
                                isDelete
                                itemText="Delete provider"
                                onClick={() => handleDeleteProviderConfirm(provider)}
                              />
                            </OverflowMenu>
                          </TableCell>
                        </TableRow>
                      );
                    } else {
                      const svc = item.data;
                      const isApiKey = svc.type === 'api_key';
                      const lastActivity = svc.updated_at || svc.created_at || svc.last_used_at;
                      const lastActivityStr = lastActivity ? new Date(lastActivity).toLocaleString() : '—';
                      const usageCount = svc.usage_count || 0;

                      return (
                        <TableRow key={svc.id}>
                          <TableCell style={{ fontWeight: 600 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                              {renderProviderBrandMark(svc.type, svc.name)}
                              <div>
                                <div style={{ fontSize: '14px', fontWeight: 600 }}>{svc.name}</div>
                                <div style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontSize: '11px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                                  {svc.key_prefix || svc.fingerprint || 'Automated client credential'}
                                </div>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <div>
                              <div style={{ fontSize: '13px', fontWeight: 600 }}>Machine identity</div>
                              <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                                {isApiKey ? 'API key' : 'mTLS certificate'}
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            {svc.revoked ? (
                              <Tag type="red" size="sm">Revoked</Tag>
                            ) : (
                              <Tag type="green" size="sm">Active</Tag>
                            )}
                          </TableCell>
                          <TableCell>
                            {usageCount > 0 ? (
                              <span style={{ fontSize: '13px', fontWeight: 600 }}>
                                {usageCount} {usageCount === 1 ? 'reference' : 'references'}
                              </span>
                            ) : (
                              <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>Not used</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                              {lastActivityStr}
                            </span>
                          </TableCell>
                          <TableCell style={{ textAlign: 'right' }}>
                            <OverflowMenu flipped size="sm" ariaLabel={`Actions for ${svc.name}`}>
                              <OverflowMenuItem
                                itemText="View usage"
                                onClick={() => handleShowServiceUsage(svc)}
                              />
                              <OverflowMenuItem
                                itemText="Edit identity"
                                onClick={() => handleOpenEditService(svc)}
                              />
                              <OverflowMenuItem
                                itemText="Rotate credential"
                                onClick={() => handleRotateServiceConfirm(svc)}
                              />
                              <OverflowMenuItem
                                isDelete
                                itemText="Revoke identity"
                                onClick={() => handleRevokeServiceConfirm(svc)}
                              />
                            </OverflowMenu>
                          </TableCell>
                        </TableRow>
                      );
                    }
                  })}

                  {filteredInventory.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} style={{ textAlign: 'center', padding: '40px' }}>
                        <div style={{ fontWeight: 600, fontSize: '15px', marginBottom: '6px', color: 'var(--cds-text-primary)' }}>
                          No identity sources
                        </div>
                        <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                          Add an OIDC provider, JWT issuer, API key, or mTLS machine identity.
                        </div>
                        <Button
                          kind="primary"
                          size="sm"
                          renderIcon={Add}
                          onClick={() => handleOpenProviderEditor()}
                        >
                          Add identity source
                        </Button>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>

              <Pagination
                backwardText="Previous page"
                forwardText="Next page"
                itemsPerPageText="Items per page:"
                page={identityPage}
                pageNumberText="Page Number"
                pageSize={identityPageSize}
                pageSizes={[5, 10, 20]}
                totalItems={filteredInventory.length}
                onChange={({ page, pageSize }) => {
                  if (page) setIdentityPage(page);
                  if (pageSize) setIdentityPageSize(pageSize);
                }}
              />
            </TableContainer>
          </div>
        );
      }
      case 'roles': {
        if (roleMode !== 'list') {
          const isEditing = roleMode === 'edit';
          const editingRole = isEditing ? roles.find((r) => r.id === editingRoleId) : null;
          const otherRoles = roles.filter((r) => r.id !== (editingRoleId || roleFormId));

          if (isEditing && (!editingRole || editingRole.is_builtin)) {
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div>
                  <Button
                    kind="ghost"
                    size="sm"
                    renderIcon={ArrowLeft}
                    onClick={() => {
                      setRoleMode('list');
                      setEditingRoleId(null);
                    }}
                  >
                    Back to roles
                  </Button>
                </div>
                <SectionCard
                  title="Role unavailable"
                  description="System roles are protected. Return to Roles and create a role instead."
                >
                  <div style={{ textAlign: 'center', padding: '32px 16px' }}>
                    <div style={{ fontWeight: 600, fontSize: '15px', marginBottom: '8px', color: 'var(--cds-text-primary)' }}>
                      This role cannot be edited
                    </div>
                    <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '20px' }}>
                      System roles are protected. Return to Roles and create a custom role instead.
                    </div>
                    <Button
                      kind="primary"
                      size="sm"
                      onClick={() => {
                        setRoleMode('list');
                        setEditingRoleId(null);
                      }}
                    >
                      Return to roles
                    </Button>
                  </div>
                </SectionCard>
              </div>
            );
          }

          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <Button
                  kind="ghost"
                  size="sm"
                  renderIcon={ArrowLeft}
                  onClick={() => {
                    setRoleMode('list');
                    setEditingRoleId(null);
                  }}
                >
                  Back to roles
                </Button>
              </div>

              <SectionCard
                title={isEditing ? `Edit ${editingRole?.name || roleFormName || 'role'}` : 'Create role'}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div>
                      <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                        Role details
                      </div>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', maxWidth: '720px' }}>
                      <TextInput
                        id="role-form-id"
                        labelText="Role ID"
                        placeholder="support_operator"
                        value={roleFormId}
                        readOnly={isEditing}
                        onChange={(e) => setRoleFormId(e.target.value)}
                        helperText={isEditing ? 'Role identifiers cannot be modified after creation.' : undefined}
                        required
                      />
                      <TextInput
                        id="role-form-name"
                        labelText="Display name"
                        placeholder="Support operator"
                        value={roleFormName}
                        onChange={(e) => setRoleFormName(e.target.value)}
                        required
                      />
                      <div style={{ gridColumn: '1 / -1' }}>
                        <TextArea
                          id="role-form-desc"
                          labelText="Description"
                          placeholder="Describe the responsibilities granted by this role"
                          value={roleFormDesc}
                          onChange={(e) => setRoleFormDesc(e.target.value)}
                          rows={3}
                        />
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div>
                      <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                        Permissions
                      </div>
                    </div>

                    <div style={{ maxWidth: '720px' }}>
                      <TextArea
                        id="role-form-permissions"
                        labelText="Permission identifiers"
                        placeholder="read:incidents, write:incidents"
                        value={roleFormPermissions}
                        onChange={(e) => setRoleFormPermissions(e.target.value)}
                        rows={4}
                        helperText="Comma separated"
                        required
                      />
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div>
                      <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                        Inherited roles
                      </div>
                    </div>

                    {renderManagedRolePicker({
                      rolesList: otherRoles,
                      selected: roleFormInherits,
                      onToggle: (id) => {
                        if (roleFormInherits.includes(id)) {
                          setRoleFormInherits(roleFormInherits.filter((rId) => rId !== id));
                        } else {
                          setRoleFormInherits([...roleFormInherits, id]);
                        }
                      },
                      label: 'Available roles',
                      emptyMessage: 'No other roles are available to inherit.',
                      excludeId: editingRoleId || roleFormId,
                    })}
                  </div>

                  <div style={{ display: 'flex', gap: '12px', paddingTop: '20px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                    <Button kind="secondary" size="md" onClick={() => setRoleMode('list')}>
                      Cancel
                    </Button>
                    <Button kind="primary" size="md" renderIcon={TagIcon} onClick={handleSaveRole}>
                      {isEditing ? 'Save changes' : 'Create role'}
                    </Button>
                  </div>
                </div>
              </SectionCard>
            </div>
          );
        }

        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <PageHeader
              title="Roles & scopes"
              icon={Locked}
            />
            <TableContainer>
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    placeholder="Search roles..."
                    value={roleSearch}
                    onChange={(e: any) => {
                      setRoleSearch(e.target.value || '');
                      setRolePage(1);
                    }}
                  />
                  <Button
                    kind="primary"
                    size="sm"
                    renderIcon={TagIcon}
                    onClick={() => handleOpenRoleEditor()}
                  >
                    Create role
                  </Button>
                </TableToolbarContent>
              </TableToolbar>

              <Table size="md" useZebraStyles={false} aria-label="Roles table">
                <TableHead>
                  <TableRow>
                    <TableHeader>Role</TableHeader>
                    <TableHeader>Access</TableHeader>
                    <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedRoles.map((r) => {
                    const directAccess = r.permissions.includes('*')
                      ? 'Full access'
                      : `${r.permissions.length} ${r.permissions.length === 1 ? 'permission' : 'permissions'}`;
                    const inheritedCount = r.inherits?.length || 0;

                    return (
                      <TableRow key={r.id}>
                        <TableCell>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>{r.name}</strong>
                              {r.is_builtin && (
                                <Tag size="sm" type="cool-gray" style={{ margin: 0, padding: '0 6px', fontSize: '11px', height: '18px' }}>
                                  System
                                </Tag>
                              )}
                            </div>
                            {r.description && (
                              <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', lineHeight: '1.45', maxWidth: '520px' }}>
                                {r.description}
                              </span>
                            )}
                            <span style={{ fontSize: '11px', fontFamily: 'var(--cds-font-mono, monospace)', color: 'var(--cds-text-helper)' }}>
                              {r.id}
                            </span>
                          </div>
                        </TableCell>

                        <TableCell>
                          <div style={{ display: 'grid', gap: '3px' }}>
                            <strong style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                              {directAccess}
                            </strong>
                            {inheritedCount > 0 ? (
                              <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                                {inheritedCount} inherited {inheritedCount === 1 ? 'role' : 'roles'}
                              </span>
                            ) : (
                              <span style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>
                                Direct permissions only
                              </span>
                            )}
                          </div>
                        </TableCell>

                        <TableCell style={{ textAlign: 'right' }}>
                          {r.is_builtin ? (
                            <span style={{ color: 'var(--cds-text-secondary)', fontSize: '14px' }} aria-label="No actions">
                              —
                            </span>
                          ) : (
                            <OverflowMenu flipped size="sm" ariaLabel={`Actions for ${r.name}`}>
                              <OverflowMenuItem
                                itemText="Edit role"
                                onClick={() => handleOpenRoleEditor(r)}
                              />
                              <OverflowMenuItem
                                isDelete
                                itemText="Delete role"
                                onClick={() => handleDeleteRoleConfirm(r)}
                              />
                            </OverflowMenu>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                  {filteredRoles.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={3} style={{ textAlign: 'center', padding: '40px' }}>
                        <div style={{ fontWeight: 600, fontSize: '15px', marginBottom: '6px', color: 'var(--cds-text-primary)' }}>
                          No roles
                        </div>
                        <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                          Create a role to define reusable permissions for identities and policies.
                        </div>
                        <Button
                          kind="primary"
                          size="sm"
                          renderIcon={TagIcon}
                          onClick={() => handleOpenRoleEditor()}
                        >
                          Add role
                        </Button>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>

              <Pagination
                backwardText="Previous page"
                forwardText="Next page"
                itemsPerPageText="Items per page:"
                page={rolePage}
                pageNumberText="Page Number"
                pageSize={rolePageSize}
                pageSizes={[5, 10, 20]}
                totalItems={filteredRoles.length}
                onChange={({ page, pageSize }) => {
                  if (page) setRolePage(page);
                  if (pageSize) setRolePageSize(pageSize);
                }}
              />
            </TableContainer>
          </div>
        );
      }
      case 'decisions':
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <PageHeader
              title="Decisions"
              icon={Activity}
              action={
                <Button
                  kind="ghost"
                  size="sm"
                  renderIcon={Renew}
                  onClick={loadData}
                >
                  Refresh
                </Button>
              }
            />
            <TableContainer>
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    placeholder="Search request, reason, app, or identity"
                    value={decisionSearch}
                    onChange={(e: any) => {
                      setDecisionSearch(e.target.value || '');
                      setDecisionPage(1);
                    }}
                  />
                  <div style={{ width: '130px' }}>
                    <Select
                      id="filter-decision-result"
                      labelText="Filter decision result"
                      hideLabel
                      value={decisionResultFilter}
                      onChange={(e) => {
                        setDecisionResultFilter(e.target.value);
                        setDecisionPage(1);
                      }}
                      size="sm"
                    >
                      <SelectItem value="" text="All results" />
                      <SelectItem value="allow" text="Allow" />
                      <SelectItem value="deny" text="Deny" />
                    </Select>
                  </div>
                  <div style={{ width: '140px' }}>
                    <Select
                      id="filter-decision-channel"
                      labelText="Filter decision channel"
                      hideLabel
                      value={decisionChannelFilter}
                      onChange={(e) => {
                        setDecisionChannelFilter(e.target.value);
                        setDecisionPage(1);
                      }}
                      size="sm"
                    >
                      <SelectItem value="" text="All channels" />
                      <SelectItem value="oidc" text="OIDC" />
                      <SelectItem value="jwt" text="JWT" />
                      <SelectItem value="api_key" text="API key" />
                      <SelectItem value="mtls" text="mTLS" />
                      <SelectItem value="public" text="Public" />
                    </Select>
                  </div>
                  <Button
                    kind={showAdvancedDecisionFilters || activeAdvancedFilterCount > 0 ? 'secondary' : 'ghost'}
                    size="sm"
                    renderIcon={Filter}
                    onClick={() => setShowAdvancedDecisionFilters(prev => !prev)}
                  >
                    Filters{activeAdvancedFilterCount > 0 ? ` (${activeAdvancedFilterCount})` : ''}
                  </Button>
                  {hasActiveDecisionFilters && (
                    <Button
                      kind="ghost"
                      size="sm"
                      renderIcon={Close}
                      onClick={resetDecisionFilters}
                    >
                      Clear
                    </Button>
                  )}
                  <Button
                    kind="ghost"
                    size="sm"
                    hasIconOnly
                    renderIcon={Renew}
                    iconDescription="Refresh decisions"
                    onClick={() => {
                      void apiService.getEdgeAccessDecisions(50).then((decRes) => {
                        if (decRes?.decisions && Array.isArray(decRes.decisions)) {
                          setDecisions(decRes.decisions);
                        }
                      });
                      setDecisionPage(1);
                    }}
                  />
                </TableToolbarContent>
              </TableToolbar>

              {showAdvancedDecisionFilters && (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
                    gap: '12px',
                    padding: '12px 16px',
                    background: 'var(--cds-layer-02)',
                    borderBottom: '1px solid var(--cds-border-subtle)',
                    alignItems: 'flex-end',
                  }}
                >
                  <TextInput
                    id="decision-filter-hostname"
                    labelText="Hostname"
                    placeholder="Hostname"
                    size="sm"
                    value={decisionHostnameFilter}
                    onChange={(e) => {
                      setDecisionHostnameFilter(e.target.value);
                      setDecisionPage(1);
                    }}
                  />
                  <TextInput
                    id="decision-filter-identity"
                    labelText="Identity"
                    placeholder="Identity"
                    size="sm"
                    value={decisionIdentityFilter}
                    onChange={(e) => {
                      setDecisionIdentityFilter(e.target.value);
                      setDecisionPage(1);
                    }}
                  />
                  <TextInput
                    id="decision-filter-attachment"
                    labelText="Attachment ID"
                    placeholder="Attachment ID"
                    size="sm"
                    value={decisionAttachmentFilter}
                    onChange={(e) => {
                      setDecisionAttachmentFilter(e.target.value);
                      setDecisionPage(1);
                    }}
                  />
                  <TextInput
                    id="decision-filter-version"
                    labelText="Policy version"
                    placeholder="Version"
                    size="sm"
                    value={decisionVersionFilter}
                    onChange={(e) => {
                      setDecisionVersionFilter(e.target.value);
                      setDecisionPage(1);
                    }}
                  />
                  <TextInput
                    id="decision-filter-from"
                    labelText="From time"
                    type="datetime-local"
                    size="sm"
                    value={decisionFromFilter}
                    onChange={(e) => {
                      setDecisionFromFilter(e.target.value);
                      setDecisionPage(1);
                    }}
                  />
                  <TextInput
                    id="decision-filter-to"
                    labelText="To time"
                    type="datetime-local"
                    size="sm"
                    value={decisionToFilter}
                    onChange={(e) => {
                      setDecisionToFilter(e.target.value);
                      setDecisionPage(1);
                    }}
                  />
                </div>
              )}

              <Table size="sm" useZebraStyles={false} aria-label="Decisions table">
                <TableHead>
                  <TableRow>
                    <TableHeader>Time</TableHeader>
                    <TableHeader>App / route</TableHeader>
                    <TableHeader>Request</TableHeader>
                    <TableHeader>Result</TableHeader>
                    <TableHeader>Identity</TableHeader>
                    <TableHeader>Reason</TableHeader>
                    <TableHeader>Policy version</TableHeader>
                    <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {paginatedDecisions.map((d) => (
                    <TableRow key={d.id}>
                      <TableCell style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', whiteSpace: 'nowrap' }}>
                        {new Date(d.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--cds-text-primary)' }}>
                          {d.protected_app_name || d.protected_app_id || d.route_id || 'Unbound'}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontSize: '12px' }}>
                          {d.host}{d.path}
                        </span>
                      </TableCell>
                      <TableCell>
                        {d.result === 'allow' ? (
                          <Tag type="green" size="sm">Allow</Tag>
                        ) : d.result === 'deny' ? (
                          <Tag type="red" size="sm">Deny</Tag>
                        ) : (
                          <Tag type="warm-gray" size="sm">{d.result}</Tag>
                        )}
                      </TableCell>
                      <TableCell>
                        <span style={{ fontSize: '13px' }}>{d.identity_id || d.identity_email || 'Unauthenticated'}</span>
                      </TableCell>
                      <TableCell style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                        {d.reason_code || '—'}
                      </TableCell>
                      <TableCell style={{ fontSize: '12px' }}>
                        {d.policy_id ? (
                          <span>{d.policy_id} v{d.policy_version ?? '—'}</span>
                        ) : (
                          <span style={{ color: 'var(--cds-text-muted)' }}>Unavailable</span>
                        )}
                      </TableCell>
                      <TableCell style={{ textAlign: 'right' }}>
                        <Button
                          kind="ghost"
                          size="sm"
                          renderIcon={Activity}
                          onClick={() => handleOpenDecisionExplanation(d)}
                        >
                          View trace
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}

                  {filteredDecisions.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={8} style={{ textAlign: 'center', padding: '48px 24px' }}>
                        <div style={{ fontWeight: 600, fontSize: '15px', color: 'var(--cds-text-primary)', marginBottom: '4px' }}>
                          No decisions
                        </div>
                        <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                          Authorization outcomes appear after protected traffic is evaluated.
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>

              <Pagination
                backwardText="Previous page"
                forwardText="Next page"
                itemsPerPageText="Items per page:"
                page={decisionPage}
                pageNumberText="Page Number"
                pageSize={decisionPageSize}
                pageSizes={[10, 15, 25, 50]}
                totalItems={filteredDecisions.length}
                onChange={({ page, pageSize }) => {
                  if (page) setDecisionPage(page);
                  if (pageSize) setDecisionPageSize(pageSize);
                }}
              />
            </TableContainer>
          </div>
        );
      case 'runtime':
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <PageHeader
              title="Runtime settings"
              icon={Renew}
            />
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <SectionCard title="Session settings">
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '20px', marginBottom: '20px' }}>
                  <TextInput
                    id="token-ttl"
                    labelText="Session token TTL"
                    value={tokenTtl}
                    onChange={(e) => { setTokenTtl(e.target.value); markDirty(); }}
                    helperText="Total session validity (e.g. 24h, 7d)"
                  />
                  <TextInput
                    id="idle-timeout"
                    labelText="Idle timeout"
                    value={idleTimeout}
                    onChange={(e) => { setIdleTimeout(e.target.value); markDirty(); }}
                    helperText="Inactivity window before re-authentication"
                  />
                  <NumberInput
                    id="max-sessions"
                    label="Max concurrent sessions"
                    value={maxSessions}
                    onChange={(_, { value }) => { setMaxSessions(Number(value) || 5); markDirty(); }}
                    min={1}
                    max={20}
                  />
                  <TextInput
                    id="cookie-name"
                    labelText="Cookie name"
                    value={cookieName}
                    onChange={(e) => { setCookieName(e.target.value); markDirty(); }}
                  />
                  <Select
                    id="cookie-same-site"
                    labelText="Cookie SameSite"
                    value={cookieSameSite}
                    onChange={(e) => { setCookieSameSite(e.target.value as 'lax' | 'strict' | 'none'); markDirty(); }}
                  >
                    <SelectItem value="lax" text="Lax (default)" />
                    <SelectItem value="strict" text="Strict" />
                    <SelectItem value="none" text="None (requires HTTPS)" />
                  </Select>
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '24px', paddingTop: '16px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                  <StatusToggle
                    id="toggle-bind-ip"
                    label="Bind to client IP"
                    toggled={bindToIp}
                    onToggle={(checked) => { setBindToIp(checked); markDirty(); }}
                    description="Invalidate session if IP changes"
                  />
                  <StatusToggle
                    id="toggle-bind-ua"
                    label="Bind to user agent"
                    toggled={bindToUa}
                    onToggle={(checked) => { setBindToUa(checked); markDirty(); }}
                    description="Invalidate session if User-Agent changes"
                  />
                  <StatusToggle
                    id="toggle-cookie-secure"
                    label="Secure cookie"
                    toggled={cookieSecure}
                    onToggle={(checked) => { setCookieSecure(checked); markDirty(); }}
                    description="Transmit only over HTTPS"
                  />
                  <StatusToggle
                    id="toggle-cookie-httponly"
                    label="HttpOnly cookie"
                    toggled={cookieHttpOnly}
                    onToggle={(checked) => { setCookieHttpOnly(checked); markDirty(); }}
                    description="Prevent client-side script access"
                  />
                </div>
              </SectionCard>

              <SectionCard title="Identity headers">
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '24px' }}>
                  <StatusToggle
                    id="toggle-identity-headers"
                    label="Inject identity headers"
                    toggled={identityHeadersEnabled}
                    onToggle={(checked) => { setIdentityHeadersEnabled(checked); markDirty(); }}
                    description="Inject X-Aegis-Identity-* headers"
                  />
                  <StatusToggle
                    id="toggle-overwrite-headers"
                    label="Sanitize client headers"
                    toggled={overwriteHeaders}
                    onToggle={(checked) => { setOverwriteHeaders(checked); markDirty(); }}
                    description="Strip untrusted inbound headers"
                  />
                </div>
              </SectionCard>

              <SectionCard title="Authentication protocols">
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '24px' }}>
                  <StatusToggle
                    id="toggle-runtime-enabled"
                    label="Edge access runtime"
                    toggled={enabled}
                    onToggle={(checked) => { setEnabled(checked); markDirty(); }}
                    description="Global protection engine"
                  />
                  <StatusToggle
                    id="toggle-auth-global"
                    label="Authentication engine"
                    toggled={authEnabled}
                    onToggle={(checked) => { setAuthEnabled(checked); markDirty(); }}
                  />
                  <StatusToggle
                    id="toggle-apikey"
                    label="API keys"
                    toggled={apiKeyEnabled}
                    onToggle={(checked) => { setApiKeyEnabled(checked); markDirty(); }}
                  />
                  <StatusToggle
                    id="toggle-jwt"
                    label="JWT tokens"
                    toggled={jwtEnabled}
                    onToggle={(checked) => { setJwtEnabled(checked); markDirty(); }}
                  />
                  <StatusToggle
                    id="toggle-oidc"
                    label="OpenID Connect"
                    toggled={oidcEnabled}
                    onToggle={(checked) => { setOidcEnabled(checked); markDirty(); }}
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '20px', marginTop: '20px', paddingTop: '16px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                  <TextInput
                    id="api-key-header"
                    labelText="API key header"
                    value={apiKeyHeader}
                    onChange={(e) => { setApiKeyHeader(e.target.value); markDirty(); }}
                    helperText="Header to extract API key (default: X-API-Key)"
                  />
                  <TextInput
                    id="jwt-header"
                    labelText="JWT header"
                    value={jwtHeader}
                    onChange={(e) => { setJwtHeader(e.target.value); markDirty(); }}
                    helperText="Header containing bearer token (default: Authorization)"
                  />
                  <TextInput
                    id="jwt-prefix"
                    labelText="JWT prefix"
                    value={jwtPrefix}
                    onChange={(e) => { setJwtPrefix(e.target.value); markDirty(); }}
                    helperText="Token scheme prefix (default: Bearer)"
                  />
                </div>
              </SectionCard>

              <SectionCard title="Engine operations">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
                  <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', maxWidth: '600px' }}>
                    Reload access state, caches, and policy snapshots without dropping in-flight traffic.
                  </div>
                  <Button
                    kind="tertiary"
                    renderIcon={Renew}
                    disabled={reloadingEngine}
                    onClick={handleReloadEngine}
                  >
                    {reloadingEngine ? 'Reloading...' : 'Hot reload engine'}
                  </Button>
                </div>
              </SectionCard>
            </div>
          </div>
        );
      case 'overview': {
        const overviewModules: Array<{
          id: string;
          title: string;
          description: string;
          icon: React.ComponentType<any>;
          navKey: NavItemKey;
        }> = [
          {
            id: 'apps',
            title: 'Protected applications',
            description: 'Service catalog, upstream routes, and identity gates.',
            icon: Network_3,
            navKey: 'access-apps',
          },
          {
            id: 'policies',
            title: 'Access policies',
            description: 'Authorization rules, RBAC claims, and device posture.',
            icon: Document,
            navKey: 'access-policies',
          },
          {
            id: 'identity',
            title: 'Identity & trust',
            description: 'Directory providers (OIDC, SAML) and machine credentials.',
            icon: UserAvatar,
            navKey: 'access-identity',
          },
          {
            id: 'roles',
            title: 'Roles & scopes',
            description: 'Role definitions, claim mappings, and permissions.',
            icon: TagIcon,
            navKey: 'access-roles',
          },
          {
            id: 'decisions',
            title: 'Decisions & audit',
            description: 'Policy evaluation events and authorization traces.',
            icon: Activity,
            navKey: 'access-decisions',
          },
          {
            id: 'runtime',
            title: 'Runtime settings',
            description: 'Token signing algorithms, cookies, and cache limits.',
            icon: Renew,
            navKey: 'access-runtime',
          },
        ];

        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
            <PageHeader
              title="Overview"
              icon={Locked}
              action={
                <HeaderSwitcher
                  id="edge-access-overview-master-switch"
                  toggled={enabled}
                  onToggle={(checked) => {
                    setEnabled(checked);
                    markDirty();
                    setNotification({
                      kind: checked ? 'success' : 'info',
                      message: checked
                        ? 'Edge Access engine enabled.'
                        : 'Edge Access engine bypassed (standby mode).',
                    });
                  }}
                  ariaLabel="Edge Access Master Engine Enable"
                />
              }
            />

            <MetricStrip columns={4}>
              <KpiCard
                label="Protection mode"
                value={enabled ? (authEnabled ? 'Enforcing' : 'Observation') : 'Off'}
                subtext={enabled ? (authEnabled ? 'Evaluating route gates' : 'Auth engine paused') : 'Global engine bypassed'}
                icon={Security}
              />
              <KpiCard
                label="Protected apps"
                value={catalogItems.length.toString()}
                subtext={`${catalogItems.filter((i) => i.protected_app.access_health.state === 'active').length} active route bindings`}
                icon={Network_3}
                onClick={() => goToView('access-apps')}
              />
              <KpiCard
                label="Reusable policies"
                value={policies.length.toString()}
                subtext={`${policies.filter((p) => p.decision === 'allow').length} allow rules`}
                icon={Document}
                onClick={() => goToView('access-policies')}
              />
              <KpiCard
                label="Identity sources"
                value={(idps.length + serviceIdentities.length).toString()}
                subtext={`${idps.length} workforce, ${serviceIdentities.length} machine`}
                icon={UserAvatar}
                onClick={() => goToView('access-identity')}
              />
            </MetricStrip>

            <SectionCard
              title="Session & security"
              padded={false}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '16px 24px',
                  borderBottom: '1px solid var(--cds-border-subtle)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
                  <Time size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '2px' }}>
                      Session validity & timeouts
                    </div>
                    <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                      Token validity ({tokenTtl}) and idle timeout ({idleTimeout}).
                    </div>
                  </div>
                </div>
                <Button
                  kind="ghost"
                  size="sm"
                  onClick={() => goToView('access-runtime')}
                >
                  Manage
                </Button>
              </div>

              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '16px 24px',
                  borderBottom: '1px solid var(--cds-border-subtle)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
                  <Security size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '2px' }}>
                      Session context binding
                    </div>
                    <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                      Bind session tokens to client IP and User-Agent.
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                  <StatusToggle
                    id="overview-bind-ip"
                    label="IP binding"
                    toggled={bindToIp}
                    onToggle={(checked) => { setBindToIp(checked); markDirty(); }}
                    size="sm"
                  />
                  <StatusToggle
                    id="overview-bind-ua"
                    label="User-Agent binding"
                    toggled={bindToUa}
                    onToggle={(checked) => { setBindToUa(checked); markDirty(); }}
                    size="sm"
                  />
                </div>
              </div>

              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '16px 24px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '75%' }}>
                  <Layers size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '2px' }}>
                      Upstream identity headers
                    </div>
                    <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                      Forward user identity, roles, and claims in X-Aegis-Identity-* headers.
                    </div>
                  </div>
                </div>
                <StatusToggle
                  id="overview-identity-headers"
                  toggled={identityHeadersEnabled}
                  onToggle={(checked) => { setIdentityHeadersEnabled(checked); markDirty(); }}
                  size="sm"
                  hideLabel
                />
              </div>
            </SectionCard>

            <SectionCard
              title="Access modules"
              padded={false}
            >
              {overviewModules.map((mod, index) => {
                const IconComponent = mod.icon;
                const isLast = index === overviewModules.length - 1;

                return (
                  <div
                    key={mod.id}
                    onClick={() => goToView(mod.navKey as NavItemKey)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '16px 24px',
                      borderBottom: isLast ? 'none' : '1px solid var(--cds-border-subtle)',
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
                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px', maxWidth: '80%' }}>
                      <IconComponent size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                      <div>
                        <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '2px' }}>
                          {mod.title}
                        </div>
                        <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                          {mod.description}
                        </div>
                      </div>
                    </div>
                    <Button
                      kind="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        goToView(mod.navKey as NavItemKey);
                      }}
                    >
                      Manage
                    </Button>
                  </div>
                );
              })}
            </SectionCard>
          </div>
        );
      }
      case 'apps':
      default:
        if (selectedAppItem) {
          if (managingPolicies) {
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Breadcrumb noTrailingSlash aria-label="Application breadcrumbs">
                    <BreadcrumbItem href="#" onClick={(e) => { e.preventDefault(); setSelectedAppId(null); setManagingPolicies(false); }}>
                      Applications
                    </BreadcrumbItem>
                    <BreadcrumbItem href="#" onClick={(e) => { e.preventDefault(); setManagingPolicies(false); }}>
                      {selectedAppItem.protected_app.name}
                    </BreadcrumbItem>
                    <BreadcrumbItem isCurrentPage>
                      Policy attachments
                    </BreadcrumbItem>
                  </Breadcrumb>

                  <Button
                    kind="primary"
                    size="sm"
                    renderIcon={Document}
                    onClick={() => setAttachPolicyModalOpen(true)}
                  >
                    Attach policy
                  </Button>
                </div>

                <TableContainer>
                  <Table size="md" useZebraStyles={false} aria-label="Attached policies table">
                    <TableHead>
                      <TableRow>
                        <TableHeader>Policy</TableHeader>
                        <TableHeader>Decision</TableHeader>
                        <TableHeader>Scope</TableHeader>
                        <TableHeader>Identity</TableHeader>
                        <TableHeader>Status</TableHeader>
                        <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {currentAppAttachedPolicies.map((att) => (
                        <TableRow key={att.attachmentId}>
                          <TableCell style={{ fontWeight: 600 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <Document size={16} style={{ color: 'var(--cds-icon-primary)', flexShrink: 0 }} />
                              <div>
                                <Button
                                  kind="ghost"
                                  size="sm"
                                  style={{ padding: '0 4px', fontWeight: 600, color: 'var(--cds-link-primary)' }}
                                  onClick={() => {
                                    setPolicySearch(att.policyName);
                                    goToView('access-policies');
                                  }}
                                >
                                  {att.policyName}
                                </Button>
                                <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', paddingLeft: '4px' }}>
                                  Version v{att.version}
                                </div>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Tag
                              type={att.decision === 'allow' ? 'green' : att.decision === 'deny' ? 'red' : 'gray'}
                              size="sm"
                            >
                              {att.decision === 'public_bypass' ? 'Public bypass' : att.decision.charAt(0).toUpperCase() + att.decision.slice(1)}
                            </Tag>
                          </TableCell>
                          <TableCell>
                            <span style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontSize: '13px' }}>
                              {att.path}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                              {att.principalsSummary}
                            </span>
                          </TableCell>
                          <TableCell>
                            {att.updateAvailable ? (
                              <Tag type="blue" size="sm">Update available</Tag>
                            ) : att.deployed ? (
                              <Tag type="green" size="sm">Deployed</Tag>
                            ) : (
                              <Tag type="warm-gray" size="sm">Review required</Tag>
                            )}
                          </TableCell>
                          <TableCell style={{ textAlign: 'right' }}>
                            <OverflowMenu flipped size="sm" ariaLabel={`Actions for ${att.policyName}`}>
                              <OverflowMenuItem
                                itemText="Open policy"
                                onClick={() => {
                                  setPolicySearch(att.policyName);
                                  goToView('access-policies');
                                }}
                              />
                              <OverflowMenuItem
                                itemText="Change attachment"
                                onClick={() => {
                                  setChangeAttachmentModal({
                                    open: true,
                                    attachment: att,
                                    path: att.path,
                                    methods: att.methods && att.methods.length > 0 && att.methods[0] !== '*' && att.methods[0] !== 'ALL' ? att.methods.join(', ') : '',
                                    enabled: att.deployed,
                                  });
                                }}
                              />
                              {att.updateAvailable && (
                                <OverflowMenuItem
                                  itemText="Upgrade attachment"
                                  onClick={() => {
                                    setConfirmDialog({
                                      open: true,
                                      title: 'Upgrade Attachment',
                                      message: `Pin this Attachment to v${att.version + 1}? It becomes candidate configuration and needs App deployment review.`,
                                      confirmLabel: 'Upgrade Attachment',
                                      danger: false,
                                      onConfirm: async () => {
                                        try {
                                          const res = await apiService.upgradeEdgeAccessPolicyAttachment(att.attachmentId, 1, att.version + 1);
                                          if (!res.success) {
                                            setNotification({ kind: 'error', message: res.error || 'Failed to upgrade attachment.' });
                                            return;
                                          }
                                          setAttachedPoliciesMap({
                                            ...attachedPoliciesMap,
                                            [selectedAppItem.protected_app.id]: currentAppAttachedPolicies.map(p =>
                                              p.attachmentId === att.attachmentId ? { ...p, updateAvailable: false, version: p.version + 1 } : p
                                            ),
                                          });
                                          markDirty();
                                          setNotification({ kind: 'success', message: 'Attachment upgrade is ready for deployment review.' });
                                        } catch (err: any) {
                                          setNotification({ kind: 'error', message: err?.message || 'Network error upgrading attachment.' });
                                        }
                                      },
                                    });
                                  }}
                                />
                              )}
                              <OverflowMenuItem
                                isDelete
                                itemText="Detach policy"
                                onClick={() => {
                                  setConfirmDialog({
                                    open: true,
                                    title: 'Detach Policy',
                                    message: 'Detach this Policy from the App? The reusable Policy and its Version history remain available.',
                                    confirmLabel: 'Detach',
                                    danger: true,
                                    onConfirm: () => handleDetachPolicy(att.attachmentId),
                                  });
                                }}
                              />
                            </OverflowMenu>
                          </TableCell>
                        </TableRow>
                      ))}

                      {currentAppAttachedPolicies.length === 0 && (
                        <TableRow>
                          <TableCell colSpan={6} style={{ textAlign: 'center', padding: '40px' }}>
                            <div style={{ fontWeight: 600, fontSize: '15px', marginBottom: '6px', color: 'var(--cds-text-primary)' }}>
                              No policies attached
                            </div>
                            <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                              Attach a published reusable policy to protect this application.
                            </div>
                            <Button
                              kind="primary"
                              size="sm"
                              renderIcon={Document}
                              onClick={() => setAttachPolicyModalOpen(true)}
                            >
                              Attach policy
                            </Button>
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </TableContainer>
              </div>
            );
          }

          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Breadcrumb noTrailingSlash aria-label="Application navigation">
                  <BreadcrumbItem href="#" onClick={(e) => { e.preventDefault(); setSelectedAppId(null); }}>
                    Applications
                  </BreadcrumbItem>
                  <BreadcrumbItem isCurrentPage>
                    {selectedAppItem.protected_app.name}
                  </BreadcrumbItem>
                </Breadcrumb>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Button
                    kind="tertiary"
                    size="sm"
                    renderIcon={Activity}
                    onClick={() => {
                      setDecisionSearch(selectedAppItem.protected_app.route?.hosts[0] || selectedAppItem.protected_app.name);
                      goToView('access-decisions');
                    }}
                  >
                    View decisions
                  </Button>

                  {selectedAppItem.protected_app.deployment_state === 'deployed' && selectedAppItem.access_summary.active_deployment_id && (
                    <Button
                      kind="secondary"
                      size="sm"
                      renderIcon={Undo}
                      onClick={() => {
                        setConfirmDialog({
                          open: true,
                          title: 'Rollback policy deployment',
                          message: 'Restore the prior immutable policy deployment for this App. Candidate policy changes and historical evidence are retained.',
                          confirmLabel: 'Rollback to prior deployment',
                          danger: false,
                          onConfirm: () => handleRollbackApp(selectedAppItem.protected_app.id, selectedAppItem.access_summary.active_deployment_id),
                        });
                      }}
                    >
                      Rollback deployment
                    </Button>
                  )}

                  <OverflowMenu flipped size="sm" ariaLabel={`Actions for ${selectedAppItem.protected_app.name}`}>
                    {selectedAppItem.protected_app.deployment_state !== 'disabled' ? (
                      <OverflowMenuItem
                        isDelete
                        itemText="Disable application"
                        onClick={() => {
                          setConfirmDialog({
                            open: true,
                            title: 'Disable App',
                            message: `Disable "${selectedAppItem.protected_app.name}"? Edge Access will stop using this App configuration, while the Route and reusable Policies remain unchanged.`,
                            confirmLabel: 'Disable App',
                            danger: true,
                            onConfirm: () => handleDisableApp(selectedAppItem.protected_app.id),
                          });
                        }}
                      />
                    ) : (
                      <OverflowMenuItem
                        isDelete
                        itemText="Delete application"
                        onClick={() => {
                          setConfirmDialog({
                            open: true,
                            title: 'Delete App',
                            message: `Delete "${selectedAppItem.protected_app.name}"? App-scoped candidate attachments and runtime snapshots are removed. The canonical Route, reusable Policies, and audit evidence are preserved.`,
                            confirmLabel: 'Delete App',
                            danger: true,
                            onConfirm: () => handleDeleteApp(selectedAppItem.protected_app.id, selectedAppItem.protected_app.revision),
                          });
                        }}
                      />
                    )}
                  </OverflowMenu>

                  {selectedAppItem.protected_app.deployment_state === 'draft' && (
                    <Button
                      kind="primary"
                      size="sm"
                      renderIcon={CheckmarkFilled}
                      onClick={() => {
                        setConfirmDialog({
                          open: true,
                          title: 'Review policy deployment',
                          message: "Confirm that you reviewed this candidate's policy impact before deployment. Candidate changes invalidate this confirmation.",
                          confirmLabel: 'Acknowledge and deploy',
                          danger: false,
                          onConfirm: () => handleDeployApp(selectedAppItem.protected_app.id),
                        });
                      }}
                    >
                      Deploy
                    </Button>
                  )}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px' }}>
                <SectionCard
                  title="Routing"
                >
                  {selectedAppItem.protected_app.route ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <Network_3 size={20} style={{ color: 'var(--cds-icon-primary)', flexShrink: 0 }} />
                        <div>
                          <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--cds-text-helper)' }}>
                            Canonical Route
                          </div>
                          <div style={{ fontSize: '15px', fontWeight: 600 }}>
                            {selectedAppItem.protected_app.route.name || selectedAppItem.protected_app.route.id}
                          </div>
                        </div>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '12px', borderTop: '1px solid var(--cds-border-subtle)', paddingTop: '16px' }}>
                        <div>
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginBottom: '2px' }}>Public address</div>
                          <div style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontSize: '13px', color: 'var(--cds-link-primary)' }}>
                            {selectedAppItem.public_addresses.join(', ') || 'Route unavailable'}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginBottom: '2px' }}>Origin</div>
                          <div style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontSize: '13px' }}>
                            {selectedAppItem.protected_app.route.origin_url || 'Not exposed'}
                          </div>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>Routing status</span>
                          <Tag type={selectedAppItem.protected_app.route.enabled ? 'green' : 'gray'} size="sm">
                            {selectedAppItem.protected_app.route.enabled ? 'Enabled' : 'Disabled'}
                          </Tag>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                      <strong>Route unavailable</strong> — The canonical Route could not be loaded from Routing.
                    </div>
                  )}
                </SectionCard>

                <SectionCard
                  title="Attached policies"
                  action={
                    <Button
                      size="sm"
                      kind="ghost"
                      renderIcon={Security}
                      onClick={() => setManagingPolicies(true)}
                    >
                      Manage policies
                    </Button>
                  }
                >
                  <Table size="sm" useZebraStyles={false} aria-label="Attached policies summary">
                    <TableHead>
                      <TableRow>
                        <TableHeader>Policy</TableHeader>
                        <TableHeader>Decision</TableHeader>
                        <TableHeader>Status</TableHeader>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {currentAppAttachedPolicies.slice(0, 3).map((pol) => (
                        <TableRow key={pol.attachmentId}>
                          <TableCell style={{ fontWeight: 600 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <Document size={14} style={{ color: 'var(--cds-icon-primary)', flexShrink: 0 }} />
                              <span>{pol.policyName}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Tag type={pol.decision === 'allow' ? 'green' : pol.decision === 'deny' ? 'red' : 'gray'} size="sm">
                              {pol.decision === 'public_bypass' ? 'Public bypass' : pol.decision.charAt(0).toUpperCase() + pol.decision.slice(1)}
                            </Tag>
                          </TableCell>
                          <TableCell>
                            <Tag type={!pol.deployed ? 'warm-gray' : pol.updateAvailable ? 'blue' : 'green'} size="sm">
                              {!pol.deployed ? 'Review required' : pol.updateAvailable ? 'Update available' : 'Active'}
                            </Tag>
                          </TableCell>
                        </TableRow>
                      ))}
                      {currentAppAttachedPolicies.length === 0 && (
                        <TableRow>
                          <TableCell colSpan={3} style={{ textAlign: 'center', padding: '24px' }}>
                            <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px' }}>No policies attached</div>
                            <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                              Use Manage policies to attach a reusable access policy.
                            </div>
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                  {currentAppAttachedPolicies.length > 3 && (
                    <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '12px', textAlign: 'center' }}>
                      Showing 3 of {currentAppAttachedPolicies.length} attached policies.
                    </div>
                  )}
                </SectionCard>
              </div>

              <SectionCard
                title="Recent decisions"
              >
                <Table size="sm" useZebraStyles={false} aria-label="Recent decisions table">
                  <TableHead>
                    <TableRow>
                      <TableHeader>Time</TableHeader>
                      <TableHeader>Method</TableHeader>
                      <TableHeader>Path</TableHeader>
                      <TableHeader>Result</TableHeader>
                      <TableHeader>Reason</TableHeader>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {decisions
                      .filter(d => !selectedAppItem.protected_app.route?.hosts[0] || d.host.includes(selectedAppItem.protected_app.route.hosts[0]) || d.path.includes(selectedAppItem.protected_app.name.toLowerCase()))
                      .slice(0, 5)
                      .map((d) => (
                        <TableRow key={d.id}>
                          <TableCell style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                            {new Date(d.timestamp).toLocaleTimeString()}
                          </TableCell>
                          <TableCell>
                            <span style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontSize: '12px', fontWeight: 600 }}>{d.method}</span>
                          </TableCell>
                          <TableCell>
                            <span style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontSize: '12px' }}>
                              {d.path}
                            </span>
                          </TableCell>
                          <TableCell>
                            <Tag type={d.result === 'allow' ? 'green' : d.result === 'deny' ? 'red' : 'warm-gray'} size="sm">
                              {d.result.toUpperCase()}
                            </Tag>
                          </TableCell>
                          <TableCell style={{ fontSize: '12px', color: 'var(--cds-text-helper)' }}>
                            {d.reason_code}
                          </TableCell>
                        </TableRow>
                      ))}
                    {decisions.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={5} style={{ textAlign: 'center', padding: '32px' }}>
                          <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px' }}>No recent decisions</div>
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                            The first five decisions for this App appear here when traffic is evaluated.
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </SectionCard>
            </div>
          );
        }

        if (creatingApp) {
          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <div>
                <Button
                  kind="ghost"
                  size="sm"
                  renderIcon={ArrowLeft}
                  onClick={() => setCreatingApp(false)}
                >
                  Back to applications
                </Button>
              </div>

              <SectionCard
                title="Create application"
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
                  <div>
                    <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                      Application details
                    </div>
                    <div style={{ maxWidth: '480px' }}>
                      <TextInput
                        id="new-app-name-input"
                        labelText="Application name"
                        placeholder="e.g. Customer portal"
                        value={newAppName}
                        onChange={(e) => setNewAppName(e.target.value)}
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                      Link route
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '20px' }}>
                      <div
                        onClick={() => setNewAppRouteMode('existing')}
                        style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '12px',
                          padding: '16px',
                          border: newAppRouteMode === 'existing' ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                          background: newAppRouteMode === 'existing' ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                          cursor: 'pointer',
                        }}
                      >
                        <input
                          type="radio"
                          name="route_mode"
                          checked={newAppRouteMode === 'existing'}
                          onChange={() => setNewAppRouteMode('existing')}
                          style={{ marginTop: '3px' }}
                        />
                        <Network_3 size={20} style={{ color: 'var(--cds-icon-primary)', marginTop: '2px', flexShrink: 0 }} />
                        <div>
                          <div style={{ fontSize: '14px', fontWeight: 600 }}>Use an existing route</div>
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '4px' }}>
                            Protect a route from Routing.
                          </div>
                        </div>
                      </div>

                      <div
                        onClick={() => setNewAppRouteMode('new')}
                        style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '12px',
                          padding: '16px',
                          border: newAppRouteMode === 'new' ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                          background: newAppRouteMode === 'new' ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                          cursor: 'pointer',
                        }}
                      >
                        <input
                          type="radio"
                          name="route_mode"
                          checked={newAppRouteMode === 'new'}
                          onChange={() => setNewAppRouteMode('new')}
                          style={{ marginTop: '3px' }}
                        />
                        <Globe size={20} style={{ color: 'var(--cds-icon-primary)', marginTop: '2px', flexShrink: 0 }} />
                        <div>
                          <div style={{ fontSize: '14px', fontWeight: 600 }}>Create a new route</div>
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '4px' }}>
                            Create a disabled route through Routing.
                          </div>
                        </div>
                      </div>
                    </div>

                    {newAppRouteMode === 'existing' ? (
                      <div style={{ maxWidth: '540px' }}>
                        <Select
                          id="select-existing-route"
                          labelText="Route to protect"
                          value={newAppRouteId}
                          onChange={(e) => setNewAppRouteId(e.target.value)}
                        >
                          <SelectItem value="" text="Select a route" />
                          {availableRoutes.map((r) => (
                            <SelectItem
                              key={r.id}
                              value={r.id || ''}
                              text={`${r.name || r.id} — ${(r.hosts || []).join(', ') || r.id}${r.enabled !== false ? '' : ' (disabled)'}`}
                            />
                          ))}
                        </Select>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '640px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '12px 16px', background: 'var(--cds-layer-02, #f4f4f4)', borderLeft: '3px solid var(--cds-interactive, #ff832b)', fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                          <Network_3 size={16} style={{ color: 'var(--cds-icon-primary)', flexShrink: 0 }} />
                          <span>Route is created with protection disabled until deployment is complete.</span>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px' }}>
                          <TextInput
                            id="new-route-name-input"
                            labelText="Route name"
                            placeholder="e.g. Customer portal route"
                            value={newAppRouteName}
                            onChange={(e) => setNewAppRouteName(e.target.value)}
                          />
                          <TextInput
                            id="new-route-host-input"
                            labelText="Public hostname"
                            placeholder="portal.example.com"
                            value={newAppRouteHost}
                            onChange={(e) => setNewAppRouteHost(e.target.value)}
                          />
                          <TextInput
                            id="new-route-origin-input"
                            labelText="Origin"
                            placeholder="https://portal.internal"
                            value={newAppOriginUrl}
                            onChange={(e) => setNewAppOriginUrl(e.target.value)}
                          />
                        </div>

                        <div style={{ border: '1px solid var(--cds-border-subtle)', padding: '12px 16px' }}>
                          <div
                            onClick={() => setNewAppAdvancedRouteOpen(!newAppAdvancedRouteOpen)}
                            style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer', fontWeight: 600, fontSize: '13px' }}
                          >
                            <span>Advanced route options</span>
                            {newAppAdvancedRouteOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                          </div>
                          {newAppAdvancedRouteOpen && (
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '16px', paddingTop: '16px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                              <TextInput
                                id="new-route-path-input"
                                labelText="Base path"
                                value={newAppRoutePath}
                                onChange={(e) => setNewAppRoutePath(e.target.value)}
                              />
                              <NumberInput
                                id="new-route-priority-input"
                                label="Priority"
                                value={newAppRoutePriority}
                                onChange={(_, { value }) => setNewAppRoutePriority(Number(value) || 100)}
                                min={1}
                                max={1000}
                              />
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  <div>
                    <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px', color: 'var(--cds-text-primary)' }}>
                      Identity sources
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
                      <div
                        style={{
                          padding: '16px',
                          border: newAppTrustBrowser ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                          background: newAppTrustBrowser ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '12px',
                        }}
                      >
                        <label style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', cursor: 'pointer' }}>
                          <input
                            type="checkbox"
                            checked={newAppTrustBrowser}
                            onChange={(e) => setNewAppTrustBrowser(e.target.checked)}
                            style={{ marginTop: '3px' }}
                          />
                          <UserAvatar size={20} style={{ color: 'var(--cds-icon-primary)', marginTop: '2px', flexShrink: 0 }} />
                          <div>
                            <div style={{ fontSize: '14px', fontWeight: 600 }}>Browser sign-in</div>
                            <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                              Verified OIDC session for browser users.
                            </div>
                          </div>
                        </label>
                        {newAppTrustBrowser && (
                          <div style={{ paddingLeft: '32px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <Select
                              id="new-app-oidc-select"
                              labelText="OIDC provider"
                              value={newAppOidcProviderId}
                              onChange={(e) => setNewAppOidcProviderId(e.target.value)}
                              size="sm"
                            >
                              <SelectItem value="" text="Select an OIDC provider" />
                              {idps.filter(i => i.type === 'oidc').map(p => (
                                <SelectItem key={p.id} value={p.id} text={`${p.name} · ${p.issuer}`} />
                              ))}
                            </Select>
                          </div>
                        )}
                      </div>

                      <div
                        style={{
                          padding: '16px',
                          border: newAppTrustJwt ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                          background: newAppTrustJwt ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '12px',
                        }}
                      >
                        <label style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', cursor: 'pointer' }}>
                          <input
                            type="checkbox"
                            checked={newAppTrustJwt}
                            onChange={(e) => setNewAppTrustJwt(e.target.checked)}
                            style={{ marginTop: '3px' }}
                          />
                          <Key size={20} style={{ color: 'var(--cds-icon-primary)', marginTop: '2px', flexShrink: 0 }} />
                          <div>
                            <div style={{ fontSize: '14px', fontWeight: 600 }}>Bearer token</div>
                            <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                              JWT validation from a configured issuer.
                            </div>
                          </div>
                        </label>
                        {newAppTrustJwt && (
                          <div style={{ paddingLeft: '32px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <Select
                              id="new-app-jwt-select"
                              labelText="JWT issuer"
                              value={newAppJwtProviderId}
                              onChange={(e) => setNewAppJwtProviderId(e.target.value)}
                              size="sm"
                            >
                              <SelectItem value="" text="Select a JWT issuer" />
                              {idps.filter(i => i.type === 'jwt').map(p => (
                                <SelectItem key={p.id} value={p.id} text={`${p.name} · ${p.issuer}`} />
                              ))}
                            </Select>
                          </div>
                        )}
                      </div>

                      <div
                        onClick={() => setNewAppApiKey(!newAppApiKey)}
                        style={{
                          padding: '16px',
                          border: newAppApiKey ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                          background: newAppApiKey ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '12px',
                          cursor: 'pointer',
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={newAppApiKey}
                          onChange={(e) => setNewAppApiKey(e.target.checked)}
                          style={{ marginTop: '3px' }}
                        />
                        <Key size={20} style={{ color: 'var(--cds-icon-primary)', marginTop: '2px', flexShrink: 0 }} />
                        <div>
                          <div style={{ fontSize: '14px', fontWeight: 600 }}>API key</div>
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                            Approved service identities with API keys.
                          </div>
                        </div>
                      </div>

                      <div
                        onClick={() => setNewAppMtls(!newAppMtls)}
                        style={{
                          padding: '16px',
                          border: newAppMtls ? '2px solid var(--cds-interactive, #ff832b)' : '1px solid var(--cds-border-subtle)',
                          background: newAppMtls ? 'var(--cds-layer-selected, rgba(15, 98, 254, 0.05))' : 'var(--cds-layer-01)',
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '12px',
                          cursor: 'pointer',
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={newAppMtls}
                          onChange={(e) => setNewAppMtls(e.target.checked)}
                          style={{ marginTop: '3px' }}
                        />
                        <Security size={20} style={{ color: 'var(--cds-icon-primary)', marginTop: '2px', flexShrink: 0 }} />
                        <div>
                          <div style={{ fontSize: '14px', fontWeight: 600 }}>mTLS certificate</div>
                          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                            Client certificate verification.
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '12px', paddingTop: '20px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                    <Button kind="primary" onClick={() => handleCreateApp(false)}>
                      Save draft
                    </Button>
                    <Button kind="secondary" onClick={() => handleCreateApp(true)}>
                      Review and deploy
                    </Button>
                  </div>
                </div>
              </SectionCard>
            </div>
          );
        }

        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <PageHeader
              title="Applications"
              icon={Application}
              action={
                <Button
                  kind="ghost"
                  size="sm"
                  renderIcon={Renew}
                  onClick={loadData}
                >
                  Refresh
                </Button>
              }
            />
            <MetricStrip columns={4}>
              <KpiCard
                label="Applications"
                value={catalogItems.length.toString()}
                subtext="Route bindings"
                status="default"
                icon={Network_3}
              />
              <KpiCard
                label="Active"
                value={catalogItems.filter((i) => i.protected_app.access_health.state === 'active').length.toString()}
                subtext="Enforcing policy"
                status="success"
                icon={CheckmarkFilled}
              />
              <KpiCard
                label="Drafts"
                value={catalogItems.filter((i) => i.protected_app.access_health.state === 'draft').length.toString()}
                subtext="Not affecting traffic"
                status="default"
                icon={Document}
              />
              <KpiCard
                label="Needs review"
                value={catalogItems.filter((i) => ['deny_only', 'update_available', 'error'].includes(i.protected_app.access_health.state)).length.toString()}
                subtext="Review before rollout"
                status="warning"
              />
            </MetricStrip>

            {renderAppsCatalogTable()}
          </div>
        );
      }
    };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      {notification && (
        <InlineNotification
          kind={notification.kind}
          title={notification.message}
          onCloseButtonClick={() => setNotification(null)}
        />
      )}

      {renderCurrentView()}

      <Modal
        open={attachPolicyModalOpen}
        modalHeading="Attach policy"
        primaryButtonText="Attach policy"
        secondaryButtonText="Cancel"
        onRequestSubmit={handleAttachPolicySubmit}
        onRequestClose={() => { setAttachPolicyModalOpen(false); setAttachPolicyPath('/*'); setAttachPolicyMethods(''); }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
          <Select
            id="modal-select-policy"
            labelText="Policy"
            value={attachPolicyId}
            onChange={(e) => setAttachPolicyId(e.target.value)}
          >
            <SelectItem value="" text="Select a published policy" />
            {policies.filter((p) => !p.archived).map((p) => (
              <SelectItem
                key={p.id}
                value={p.id}
                text={`${p.name || 'Unnamed policy'} — v${p.version || 1}`}
              />
            ))}
          </Select>

          <div
            style={{
              padding: '16px',
              backgroundColor: 'var(--cds-layer-01)',
              border: '1px solid var(--cds-border-subtle)',
              borderRadius: '4px',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600 }}>Where should this policy apply?</div>
              <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                Limit this policy to a path. Leave Methods blank to match every method.
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
              <TextInput
                id="modal-attach-path"
                labelText="Path"
                placeholder="/*"
                value={attachPolicyPath}
                onChange={(e) => setAttachPolicyPath(e.target.value)}
              />
              <TextInput
                id="modal-attach-methods"
                labelText="Methods"
                helperText="Optional"
                placeholder="All methods"
                value={attachPolicyMethods === 'ALL' ? '' : attachPolicyMethods}
                onChange={(e) => setAttachPolicyMethods(e.target.value)}
              />
            </div>
          </div>
        </div>
      </Modal>

      <Modal
        open={changeAttachmentModal.open}
        modalHeading="Change attachment"
        primaryButtonText="Save Changes"
        secondaryButtonText="Cancel"
        onRequestSubmit={async () => {
          if (!selectedAppItem || !changeAttachmentModal.attachment) return;
          const attId = changeAttachmentModal.attachment.attachmentId;
          const methodsList = parseMethodsInput(changeAttachmentModal.methods);
          const attPolicy = policies.find(p => p.id === changeAttachmentModal.attachment?.policyId);
          const isPublicBypass = attPolicy?.decision === 'public_bypass' || changeAttachmentModal.attachment?.decision === 'public_bypass';
          const authChannels = isPublicBypass ? [] : ['oidc', 'jwt'];
          try {
            const res = await apiService.updateEdgeAccessPolicyAttachment(attId, {
              revision: 1,
              path: changeAttachmentModal.path.trim() || '/*',
              methods: methodsList,
              auth_channels: authChannels,
              deployment_state: changeAttachmentModal.enabled ? 'active' : 'disabled',
            });
            if (!res.success) {
              setNotification({ kind: 'error', message: res.error || 'Failed to update policy attachment.' });
              return;
            }
            setAttachedPoliciesMap({
              ...attachedPoliciesMap,
              [selectedAppItem.protected_app.id]: (attachedPoliciesMap[selectedAppItem.protected_app.id] || []).map((a) => {
                if (a.attachmentId !== attId) return a;
                return {
                  ...a,
                  path: changeAttachmentModal.path.trim() || '/*',
                  methods: methodsList,
                  deployed: changeAttachmentModal.enabled,
                };
              }),
            });
            setChangeAttachmentModal({ open: false, attachment: null, path: '/*', methods: '', enabled: true });
            markDirty();
            setNotification({ kind: 'success', message: 'Attachment candidate updated. Deployment review is required.' });
          } catch (err: any) {
            setNotification({ kind: 'error', message: err?.message || 'Network error updating policy attachment.' });
          }
        }}
        onRequestClose={() => setChangeAttachmentModal({ open: false, attachment: null, path: '/*', methods: '', enabled: true })}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
          <p style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', margin: 0 }}>
            Update where this policy applies before the next deployment.
          </p>

          <div
            style={{
              padding: '16px',
              backgroundColor: 'var(--cds-layer-01)',
              border: '1px solid var(--cds-border-subtle)',
              borderRadius: '4px',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div style={{ fontSize: '13px', fontWeight: 600 }}>Attachment scope</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
              <TextInput
                id="modal-change-attach-path"
                labelText="Path"
                value={changeAttachmentModal.path}
                onChange={(e) => setChangeAttachmentModal({ ...changeAttachmentModal, path: e.target.value })}
              />
              <TextInput
                id="modal-change-attach-methods"
                labelText="Methods"
                helperText="Optional"
                placeholder="All methods"
                value={changeAttachmentModal.methods}
                onChange={(e) => setChangeAttachmentModal({ ...changeAttachmentModal, methods: e.target.value })}
              />
            </div>
          </div>

          <Checkbox
            id="modal-change-attach-enabled"
            labelText="Enable for the next deployment"
            helperText="Keep this attachment active when the Application is deployed."
            checked={changeAttachmentModal.enabled}
            onChange={(_, { checked }) => setChangeAttachmentModal({ ...changeAttachmentModal, enabled: checked })}
          />
        </div>
      </Modal>

      <Modal
        open={confirmDialog.open}
        modalHeading={confirmDialog.title}
        primaryButtonText={confirmDialog.confirmLabel}
        secondaryButtonText="Cancel"
        danger={confirmDialog.danger}
        onRequestSubmit={() => {
          confirmDialog.onConfirm();
          setConfirmDialog((prev) => ({ ...prev, open: false }));
        }}
        onRequestClose={() => setConfirmDialog((prev) => ({ ...prev, open: false }))}
      >
        <p style={{ paddingTop: '16px', fontSize: '14px', lineHeight: 1.5, color: 'var(--cds-text-primary)' }}>
          {confirmDialog.message}
        </p>
      </Modal>

      <Modal
        open={libraryAttachModal.open}
        modalHeading="Attach policy"
        primaryButtonText="Attach policy"
        secondaryButtonText="Cancel"
        onRequestSubmit={handleLibraryPolicyAttachSubmit}
        onRequestClose={() => setLibraryAttachModal({ open: false, policy: null, appId: '' })}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
          {libraryAttachModal.policy && (
            <p style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', margin: 0 }}>
              Attach <strong>{libraryAttachModal.policy.name}</strong> v{libraryAttachModal.policy.version} to an application.
            </p>
          )}

          <Select
            id="modal-lib-attach-app"
            labelText="Application"
            value={libraryAttachModal.appId}
            onChange={(e) => setLibraryAttachModal({ ...libraryAttachModal, appId: e.target.value })}
          >
            <SelectItem value="" text="Select an application" />
            {catalogItems.map((item) => {
              const app = item.protected_app || (item as any);
              const addr = (Array.isArray(item.public_addresses) ? item.public_addresses[0] : '') || app.route_id || '';
              return (
                <SelectItem
                  key={app.id}
                  value={app.id}
                  text={`${app.name || 'Application'}${addr ? ` — ${addr}` : ''}`}
                />
              );
            })}
          </Select>

          <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: 0, lineHeight: 1.4 }}>
            The policy will initially match all paths, methods, and authentication channels. You can narrow it later from the Application.
          </p>
        </div>
      </Modal>

      {validationModal.open && validationModal.provider && (
        <Modal
          open
          modalHeading={`Validation: ${validationModal.provider.name}`}
          primaryButtonText="Done"
          onRequestSubmit={() => setValidationModal({ open: false, provider: null })}
          onRequestClose={() => setValidationModal({ open: false, provider: null })}
          passiveModal
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>Status:</span>
              <Tag
                type={
                  validationModal.provider.validation?.status === 'valid'
                    ? 'green'
                    : validationModal.provider.validation?.status === 'warning'
                    ? 'warm-gray'
                    : 'red'
                }
                size="sm"
              >
                {validationModal.provider.validation?.status || 'Valid'}
              </Tag>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {(validationModal.provider.validation?.checks || []).map((chk) => (
                <div
                  key={chk.id}
                  style={{
                    padding: '12px',
                    border: '1px solid var(--cds-border-subtle)',
                    background: 'var(--cds-layer-01)',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                  }}
                >
                  <Tag type={chk.status === 'passed' ? 'green' : chk.status === 'warning' ? 'warm-gray' : 'red'} size="sm">
                    {chk.status.toUpperCase()}
                  </Tag>
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 600 }}>{chk.label}</div>
                    <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                      {chk.message}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Modal>
      )}

      {deleteProviderModal.open && deleteProviderModal.provider && (
        <Modal
          open
          danger
          modalHeading="Delete identity provider"
          primaryButtonText="Delete provider"
          secondaryButtonText="Cancel"
          onRequestSubmit={handleDeleteProviderSubmit}
          onRequestClose={() => setDeleteProviderModal({ open: false, provider: null })}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.5 }}>
              Deleting <strong>{deleteProviderModal.provider.name}</strong> is blocked if Apps still depend on it.
            </p>
            {deleteProviderModal.provider.usage?.protected_app_ids && deleteProviderModal.provider.usage.protected_app_ids.length > 0 ? (
              <div>
                <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: '6px' }}>Affected Apps:</div>
                <ul style={{ paddingLeft: '20px', margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  {deleteProviderModal.provider.usage.protected_app_ids.map((id) => (
                    <li key={id}>{id}</li>
                  ))}
                </ul>
              </div>
            ) : (
              <p style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', margin: 0 }}>
                No explicit App dependency is currently listed.
              </p>
            )}
          </div>
        </Modal>
      )}

      {claimMappingModal.open && claimMappingModal.provider && (
        <Modal
          open
          modalHeading={`Edit mapping: ${claimMappingModal.provider.name}`}
          primaryButtonText="Save claim mapping"
          secondaryButtonText="Cancel"
          onRequestSubmit={handleSaveClaimMappingSubmit}
          onRequestClose={() => setClaimMappingModal({ open: false, provider: null, subject: '', email: '', roles: '', groups: '', testClaimsJson: '', previewText: null })}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)', lineHeight: 1.4 }}>
              {claimMappingModal.provider.name} maps verified claims to the shared Edge identity. Use synthetic JSON only—never a real bearer token.
            </p>

            <TextInput
              id="mapping-subject"
              labelText="Subject claim"
              value={claimMappingModal.subject}
              onChange={(e) => setClaimMappingModal({ ...claimMappingModal, subject: e.target.value })}
              required
            />
            <TextInput
              id="mapping-email"
              labelText="Email claim"
              value={claimMappingModal.email}
              onChange={(e) => setClaimMappingModal({ ...claimMappingModal, email: e.target.value })}
              required
            />
            <TextInput
              id="mapping-roles"
              labelText="Roles claim"
              value={claimMappingModal.roles}
              onChange={(e) => setClaimMappingModal({ ...claimMappingModal, roles: e.target.value })}
              required
            />
            <TextInput
              id="mapping-groups"
              labelText="Groups claim"
              value={claimMappingModal.groups}
              onChange={(e) => setClaimMappingModal({ ...claimMappingModal, groups: e.target.value })}
              required
            />

            <TextArea
              id="mapping-test-claims"
              labelText="Synthetic claims JSON"
              helperText="Use non-production claim values only."
              value={claimMappingModal.testClaimsJson}
              onChange={(e) => setClaimMappingModal({ ...claimMappingModal, testClaimsJson: e.target.value })}
              rows={4}
            />

            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <Button kind="tertiary" size="sm" onClick={handlePreviewMappingSubmit}>
                Preview identity
              </Button>
            </div>

            {claimMappingModal.previewText && (
              <div
                style={{
                  padding: '12px',
                  background: 'var(--cds-layer-02, #262626)',
                  border: '1px solid var(--cds-border-subtle)',
                  fontFamily: 'var(--cds-font-mono, monospace)',
                  fontSize: '12px',
                  whiteSpace: 'pre-wrap',
                  lineHeight: 1.5,
                }}
              >
                {claimMappingModal.previewText}
              </div>
            )}
          </div>
        </Modal>
      )}

      {editServiceIdentityModal.open && editServiceIdentityModal.identity && (
        <Modal
          open
          modalHeading="Edit machine identity"
          primaryButtonText="Save identity"
          secondaryButtonText="Cancel"
          onRequestSubmit={handleSaveEditServiceSubmit}
          onRequestClose={() => setEditServiceIdentityModal({ open: false, identity: null, name: '', roles: [], groups: '', expiresIn: '', certPem: '' })}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
            <TextInput
              id="edit-svc-type"
              labelText="Identity type"
              value={editServiceIdentityModal.identity.type === 'api_key' ? 'API key' : 'mTLS certificate'}
              readOnly
            />
            <TextInput
              id="edit-svc-name"
              labelText="Name"
              value={editServiceIdentityModal.name}
              onChange={(e) => setEditServiceIdentityModal({ ...editServiceIdentityModal, name: e.target.value })}
              required
            />
            <TextInput
              id="edit-svc-groups"
              labelText="Groups"
              helperText="Comma-separated."
              value={editServiceIdentityModal.groups}
              onChange={(e) => setEditServiceIdentityModal({ ...editServiceIdentityModal, groups: e.target.value })}
            />
            <TextInput
              id="edit-svc-expires"
              labelText="Expires in"
              helperText="Optional duration."
              value={editServiceIdentityModal.expiresIn}
              onChange={(e) => setEditServiceIdentityModal({ ...editServiceIdentityModal, expiresIn: e.target.value })}
            />

            {editServiceIdentityModal.identity.type === 'mtls' && (
              <TextArea
                id="edit-svc-cert-pem"
                labelText="Certificate PEM (optional update)"
                helperText="Paste replacement certificate in PEM format to rotate."
                rows={4}
                value={editServiceIdentityModal.certPem}
                onChange={(e) => setEditServiceIdentityModal({ ...editServiceIdentityModal, certPem: e.target.value })}
              />
            )}

            <div>
              {renderManagedRolePicker({
                rolesList: roles,
                selected: editServiceIdentityModal.roles,
                onToggle: (id) => {
                  if (editServiceIdentityModal.roles.includes(id)) {
                    setEditServiceIdentityModal({
                      ...editServiceIdentityModal,
                      roles: editServiceIdentityModal.roles.filter((rId) => rId !== id),
                    });
                  } else {
                    setEditServiceIdentityModal({
                      ...editServiceIdentityModal,
                      roles: [...editServiceIdentityModal.roles, id],
                    });
                  }
                },
                label: 'Assigned roles',
                emptyMessage: 'Create a role before assigning role-based access.',
              })}
            </div>
          </div>
        </Modal>
      )}

      {usageModal.open && usageModal.identity && (
        <Modal
          open
          modalHeading="Machine identity usage"
          primaryButtonText="Done"
          onRequestSubmit={() => setUsageModal({ open: false, identity: null, apps: [], versions: [], deployments: [] })}
          onRequestClose={() => setUsageModal({ open: false, identity: null, apps: [], versions: [], deployments: [] })}
          passiveModal
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
            <div>
              <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '6px' }}>Protected Apps</div>
              {usageModal.apps.length > 0 ? (
                <ul style={{ paddingLeft: '20px', margin: 0, fontSize: '13px' }}>
                  {usageModal.apps.map((app) => (
                    <li key={app}>{app}</li>
                  ))}
                </ul>
              ) : (
                <p style={{ margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)' }}>None</p>
              )}
            </div>

            <div>
              <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '6px' }}>Policy versions</div>
              {usageModal.versions.length > 0 ? (
                <ul style={{ paddingLeft: '20px', margin: 0, fontSize: '13px' }}>
                  {usageModal.versions.map((ver) => (
                    <li key={ver}>{ver}</li>
                  ))}
                </ul>
              ) : (
                <p style={{ margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)' }}>None</p>
              )}
            </div>

            <div>
              <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '6px' }}>Active deployments</div>
              {usageModal.deployments.length > 0 ? (
                <ul style={{ paddingLeft: '20px', margin: 0, fontSize: '13px' }}>
                  {usageModal.deployments.map((dep) => (
                    <li key={dep}>{dep}</li>
                  ))}
                </ul>
              ) : (
                <p style={{ margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)' }}>None</p>
              )}
            </div>
          </div>
        </Modal>
      )}

      {rotateServiceModal.open && rotateServiceModal.identity && (
        <Modal
          open
          modalHeading="Rotate machine identity"
          primaryButtonText="Rotate identity"
          secondaryButtonText="Cancel"
          onRequestSubmit={handleRotateServiceSubmit}
          onRequestClose={() => setRotateServiceModal({ open: false, identity: null })}
        >
          <div style={{ paddingTop: '16px' }}>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.5 }}>
              A replacement credential will be created for <strong>{rotateServiceModal.identity.name}</strong>. Any new secret is shown once.
            </p>
          </div>
        </Modal>
      )}

      {revokeServiceModal.open && revokeServiceModal.identity && (
        <Modal
          open
          danger
          modalHeading="Revoke machine identity"
          primaryButtonText="Revoke identity"
          secondaryButtonText="Cancel"
          onRequestSubmit={handleRevokeServiceSubmit}
          onRequestClose={() => setRevokeServiceModal({ open: false, identity: null, dependencies: [] })}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.5 }}>
              Revocation immediately causes authentication to fail closed for <strong>{revokeServiceModal.identity.name}</strong>. Review affected resources before continuing:
            </p>
            {revokeServiceModal.dependencies.length > 0 ? (
              <ul style={{ paddingLeft: '20px', margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                {revokeServiceModal.dependencies.map((dep) => (
                  <li key={dep}>{dep}</li>
                ))}
              </ul>
            ) : (
              <p style={{ margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                No active references were reported.
              </p>
            )}
          </div>
        </Modal>
      )}

      {oneTimeSecretModal.open && (
        <Modal
          open
          modalHeading="Save the secret now"
          primaryButtonText="I saved it"
          onRequestSubmit={() => setOneTimeSecretModal({ open: false, secret: '', warning: '' })}
          onRequestClose={() => setOneTimeSecretModal({ open: false, secret: '', warning: '' })}
          passiveModal
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
            <p style={{ margin: 0, fontSize: '14px', color: 'var(--cds-support-warning, #f1c21b)', fontWeight: 600 }}>
              {oneTimeSecretModal.warning}
            </p>
            <TextArea
              id="one-time-secret"
              labelText="Secret"
              value={oneTimeSecretModal.secret}
              readOnly
              rows={3}
              helperText="Copy and store this secret in a secure password manager or vault."
            />
          </div>
        </Modal>
      )}

      {deleteRoleModal.open && deleteRoleModal.role && (
        <Modal
          open
          danger
          modalHeading="Delete role"
          primaryButtonText="Delete role"
          secondaryButtonText="Cancel"
          onRequestSubmit={handleDeleteRoleSubmit}
          onRequestClose={() => setDeleteRoleModal({ open: false, role: null })}
        >
          <div style={{ paddingTop: '16px' }}>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.5 }}>
              Delete <strong>{deleteRoleModal.role.name}</strong>? Identities or policies that still reference{' '}
              <code style={{ fontFamily: 'var(--cds-font-mono, monospace)', background: 'var(--cds-layer-02)', padding: '2px 4px' }}>
                {deleteRoleModal.role.id}
              </code>{' '}
              may stop matching.
            </p>
          </div>
        </Modal>
      )}

      {decisionExplanationModal.open && decisionExplanationModal.decision && (
        <Modal
          open
          modalHeading={`Decision Trace: ${decisionExplanationModal.decision.method || 'GET'} ${decisionExplanationModal.decision.host}${decisionExplanationModal.decision.path}`}
          primaryButtonText="Close"
          onRequestSubmit={() => setDecisionExplanationModal({ open: false, decision: null, loading: false })}
          onRequestClose={() => setDecisionExplanationModal({ open: false, decision: null, loading: false })}
          passiveModal
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>Outcome:</span>
                <Tag
                  type={
                    decisionExplanationModal.decision.result === 'allow'
                      ? 'green'
                      : decisionExplanationModal.decision.result === 'deny'
                      ? 'red'
                      : 'warm-gray'
                  }
                  size="sm"
                >
                  {decisionExplanationModal.decision.result.toUpperCase()}
                </Tag>
                {decisionExplanationModal.decision.reason_code && (
                  <Tag type="cool-gray" size="sm">
                    {decisionExplanationModal.decision.reason_code}
                  </Tag>
                )}
              </div>
              <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                {new Date(decisionExplanationModal.decision.timestamp).toLocaleString()}
              </span>
            </div>

            {decisionExplanationModal.decision.reason && (
              <p style={{ margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                {decisionExplanationModal.decision.reason}
              </p>
            )}

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                gap: '12px',
                padding: '12px',
                background: 'var(--cds-layer-01)',
                border: '1px solid var(--cds-border-subtle)',
                borderRadius: '4px',
              }}
            >
              <div>
                <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>Application</div>
                <div style={{ fontSize: '13px', fontWeight: 600 }}>
                  {decisionExplanationModal.decision.protected_app_name || decisionExplanationModal.decision.protected_app_id || 'Unbound'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>Identity / Channel</div>
                <div style={{ fontSize: '13px' }}>
                  {decisionExplanationModal.decision.identity_id || decisionExplanationModal.decision.identity_email || 'Unauthenticated'} ({decisionExplanationModal.decision.auth_channel || 'public'})
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>Client IP</div>
                <div style={{ fontSize: '13px', fontFamily: 'var(--cds-font-mono, monospace)' }}>
                  {decisionExplanationModal.decision.client_ip || '—'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>Policy Version</div>
                <div style={{ fontSize: '13px' }}>
                  {decisionExplanationModal.decision.policy_id ? `${decisionExplanationModal.decision.policy_id} v${decisionExplanationModal.decision.policy_version ?? '—'}` : 'Unavailable'}
                </div>
              </div>
            </div>

            <div>
              <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>Evaluation Trace Steps</div>
              {decisionExplanationModal.loading ? (
                <p style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>Loading trace details...</p>
              ) : ((decisionExplanationModal.decision.trace_steps && decisionExplanationModal.decision.trace_steps.length > 0) || (decisionExplanationModal.decision.explanation?.trace && decisionExplanationModal.decision.explanation.trace.length > 0)) ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {((decisionExplanationModal.decision.trace_steps || decisionExplanationModal.decision.explanation?.trace) || []).map((step, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '10px 12px',
                        border: '1px solid var(--cds-border-subtle)',
                        background: 'var(--cds-layer-01)',
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '10px',
                        borderRadius: '4px',
                      }}
                    >
                      <Tag
                        type={
                          step.outcome === 'allow' || step.outcome === 'passed' || step.outcome === 'matched'
                            ? 'green'
                            : step.outcome === 'deny' || step.outcome === 'failed'
                            ? 'red'
                            : 'warm-gray'
                        }
                        size="sm"
                      >
                        {step.stage || `Step ${idx + 1}`}
                      </Tag>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: '13px', fontWeight: 600 }}>{step.outcome.toUpperCase()}</div>
                        <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                          {step.detail}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : decisionExplanationModal.decision.explanation?.steps && decisionExplanationModal.decision.explanation.steps.length > 0 ? (
                <ul style={{ paddingLeft: '20px', margin: 0, fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  {decisionExplanationModal.decision.explanation.steps.map((st, i) => (
                    <li key={i}>{st}</li>
                  ))}
                </ul>
              ) : (
                <p style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', margin: 0 }}>
                  Detailed step-by-step trace is not recorded for this historical evaluation.
                </p>
              )}
            </div>
          </div>
        </Modal>
      )}

      <SaveActionBar
        isDirty={isDirty}
        isSaving={saving}
        onSave={handleSave}
        onReset={handleReset}
      />
    </div>
  );
};
