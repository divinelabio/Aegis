import { api } from '../../../api.js';
import { EDGE_ACCESS_ENDPOINTS } from './endpoints.js';

const ROOT = `${EDGE_ACCESS_ENDPOINTS.root}/identity`;

export type IdentityProviderType = 'oidc' | 'jwt';
export type IdentityProviderValidationStatus = 'valid' | 'warning' | 'failed' | 'not_validated';
export type ServiceIdentityType = 'api_key' | 'mtls';

export interface IdentityV2Error {
  status: number;
  code?: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface IdentityV2Result<T> {
  data: T | null;
  error: IdentityV2Error | null;
}

export interface IdentityPagination {
  returned: number;
  page_size: number;
  next_cursor?: string;
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
  status: IdentityProviderValidationStatus;
  checked_at?: string;
  checks: IdentityValidationCheck[];
}

export interface IdentityProvider {
  provider_id: string;
  type: IdentityProviderType;
  name: string;
  issuer: string;
  client_id?: string;
  redirect_url?: string;
  scopes: string[];
  audience?: string;
  algorithms: string[];
  identity_mapping: IdentityClaimMapping;
  validation: IdentityProviderValidation;
  usage: { protected_app_ids: string[] };
}

export interface IdentityProviderInput {
  identity_revision: number;
  provider_id?: string;
  type: IdentityProviderType;
  name: string;
  issuer: string;
  client_id?: string;
  client_secret?: string;
  redirect_url?: string;
  scopes?: string[];
  jwks_url?: string;
  audience?: string;
  algorithms?: string[];
  secret_key?: string;
}

export interface IdentityMappingRecord {
  provider_id: string;
  provider_name: string;
  provider_type: IdentityProviderType;
  mapping: IdentityClaimMapping;
}

export interface IdentityMappingPreview {
  subject: string;
  email: string;
  roles: string[];
  groups: string[];
  diagnostics: Array<{ field: string; message: string }>;
}

export interface ServiceIdentity {
  id: string;
  revision: number;
  name: string;
  type: ServiceIdentityType;
  roles: string[];
  groups: string[];
  key_prefix?: string;
  fingerprint?: string;
  status: string;
  expires_at?: string;
  last_used_at?: string;
  usage_count: number;
  created_at?: string;
  updated_at?: string;
  revoked: boolean;
}

export interface ServiceIdentityUsage {
  protected_app_ids: string[];
  policy_versions: string[];
  policy_deployment_ids: string[];
}

export interface ServiceIdentityInput {
  type: ServiceIdentityType;
  name: string;
  roles?: string[];
  groups?: string[];
  expires_in?: string;
  certificate_pem?: string;
}

export interface ServiceIdentityUpdateInput {
  revision: number;
  name?: string;
  roles?: string[];
  groups?: string[];
  expires_in?: string;
  certificate_pem?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function text(value: unknown): string { return typeof value === 'string' ? value : ''; }
function number(value: unknown): number { return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : 0; }
function strings(value: unknown): string[] { return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : []; }

function normalizeMapping(value: unknown): IdentityClaimMapping | null {
  if (!isRecord(value)) return null;
  const mapping = { subject: text(value.subject), email: text(value.email), roles: text(value.roles), groups: text(value.groups) };
  return mapping.subject && mapping.email && mapping.roles && mapping.groups ? mapping : null;
}

function normalizePagination(value: unknown): IdentityPagination {
  if (!isRecord(value)) return { returned: 0, page_size: 50 };
  return { returned: number(value.returned), page_size: number(value.page_size) || 50, next_cursor: text(value.next_cursor) || undefined };
}

function normalizeValidation(value: unknown): IdentityProviderValidation {
  if (!isRecord(value)) return { status: 'not_validated', checks: [] };
  const status = value.status === 'valid' || value.status === 'warning' || value.status === 'failed' ? value.status : 'not_validated';
  const checks = Array.isArray(value.checks) ? value.checks.flatMap(check => {
    if (!isRecord(check) || !text(check.id) || !text(check.label) || !text(check.message)) return [];
    const checkStatus: IdentityValidationCheck['status'] = check.status === 'passed' || check.status === 'warning' || check.status === 'failed' ? check.status : 'failed';
    return [{ id: text(check.id), label: text(check.label), status: checkStatus, message: text(check.message) }];
  }) : [];
  return { status, checked_at: text(value.checked_at) || undefined, checks };
}

export function normalizeIdentityProvider(value: unknown): IdentityProvider | null {
  if (!isRecord(value) || !text(value.provider_id) || (value.type !== 'oidc' && value.type !== 'jwt') || !text(value.name) || !text(value.issuer)) return null;
  const mapping = normalizeMapping(value.identity_mapping);
  if (!mapping) return null;
  const usage = isRecord(value.usage) ? { protected_app_ids: strings(value.usage.protected_app_ids) } : { protected_app_ids: [] };
  return {
    provider_id: text(value.provider_id), type: value.type, name: text(value.name), issuer: text(value.issuer),
    client_id: text(value.client_id) || undefined, redirect_url: text(value.redirect_url) || undefined,
    scopes: strings(value.scopes), audience: text(value.audience) || undefined, algorithms: strings(value.algorithms),
    identity_mapping: mapping, validation: normalizeValidation(value.validation), usage
  };
}

export function normalizeIdentityMapping(value: unknown): IdentityMappingRecord | null {
  if (!isRecord(value) || !text(value.provider_id) || !text(value.provider_name) || (value.provider_type !== 'oidc' && value.provider_type !== 'jwt')) return null;
  const mapping = normalizeMapping(value.mapping);
  return mapping ? { provider_id: text(value.provider_id), provider_name: text(value.provider_name), provider_type: value.provider_type, mapping } : null;
}

export function normalizeIdentityPreview(value: unknown): IdentityMappingPreview | null {
  if (!isRecord(value)) return null;
  const diagnostics = Array.isArray(value.diagnostics) ? value.diagnostics.flatMap(diagnostic => {
    if (!isRecord(diagnostic) || !text(diagnostic.field) || !text(diagnostic.message)) return [];
    return [{ field: text(diagnostic.field), message: text(diagnostic.message) }];
  }) : [];
  return { subject: text(value.subject), email: text(value.email), roles: strings(value.roles), groups: strings(value.groups), diagnostics };
}

export function normalizeServiceIdentity(value: unknown): ServiceIdentity | null {
  if (!isRecord(value) || !text(value.id) || !text(value.name) || (value.type !== 'api_key' && value.type !== 'mtls' && value.type !== 'mtls_client_certificate') || !text(value.status)) return null;
  return {
    id: text(value.id), revision: number(value.revision), name: text(value.name), type: value.type === 'mtls_client_certificate' ? 'mtls' : value.type, roles: strings(value.roles), groups: strings(value.groups),
    key_prefix: text(value.key_prefix) || undefined, fingerprint: text(value.fingerprint) || undefined, status: text(value.status),
    expires_at: text(value.expires_at) || undefined, last_used_at: text(value.last_used_at) || undefined, usage_count: number(value.usage_count),
    created_at: text(value.created_at) || undefined, updated_at: text(value.updated_at) || undefined, revoked: value.revoked === true
  };
}

function normalizeError(error: { status: number; code?: string; message: string; details?: unknown } | null): IdentityV2Error | null {
  if (!error) return null;
  return { status: error.status, code: error.code, message: error.message, details: isRecord(error.details) ? error.details : undefined };
}

async function request<T>(endpoint: string, method: string, body: unknown, normalize: (value: unknown) => T | null): Promise<IdentityV2Result<T>> {
  const response = await api.requestResult<unknown>(endpoint, method, body);
  if (response.error) return { data: null, error: normalizeError(response.error) };
  const data = normalize(response.data);
  if (!data) return { data: null, error: { status: 0, code: 'malformed_response', message: 'The Identity service returned an invalid response.' } };
  return { data, error: null };
}

function responseProvider(value: unknown): { provider: IdentityProvider; identityRevision: number } | null {
  if (!isRecord(value) || value.success !== true) return null;
  const provider = normalizeIdentityProvider(value.provider);
  return provider ? { provider, identityRevision: number(value.identity_revision) } : null;
}

function responseProviders(value: unknown): { providers: IdentityProvider[]; identityRevision: number; page: IdentityPagination } | null {
  if (!isRecord(value) || value.success !== true || !Array.isArray(value.providers)) return null;
  const providers = value.providers.flatMap(provider => {
    const normalized = normalizeIdentityProvider(provider);
    return normalized ? [normalized] : [];
  });
  return { providers, identityRevision: number(value.identity_revision), page: normalizePagination(value.page) };
}

function responseMapping(value: unknown): { mapping: IdentityMappingRecord; identityRevision: number } | null {
  if (!isRecord(value) || value.success !== true) return null;
  const mapping = normalizeIdentityMapping(value.mapping);
  return mapping ? { mapping, identityRevision: number(value.identity_revision) } : null;
}

function responseMappings(value: unknown): { mappings: IdentityMappingRecord[]; identityRevision: number; page: IdentityPagination } | null {
  if (!isRecord(value) || value.success !== true || !Array.isArray(value.mappings)) return null;
  const mappings = value.mappings.flatMap(mapping => {
    const normalized = normalizeIdentityMapping(mapping);
    return normalized ? [normalized] : [];
  });
  return { mappings, identityRevision: number(value.identity_revision), page: normalizePagination(value.page) };
}

function responsePreview(value: unknown): IdentityMappingPreview | null {
  if (!isRecord(value) || value.success !== true) return null;
  return normalizeIdentityPreview(value.identity) ? { ...normalizeIdentityPreview(value.identity)!, diagnostics: Array.isArray(value.diagnostics) ? value.diagnostics.flatMap(diagnostic => isRecord(diagnostic) && text(diagnostic.field) && text(diagnostic.message) ? [{ field: text(diagnostic.field), message: text(diagnostic.message) }] : []) : [] } : null;
}

function responseServiceIdentity(value: unknown): { credential: ServiceIdentity; secret?: string; warning?: string; usage?: ServiceIdentityUsage } | null {
  if (!isRecord(value) || value.success !== true) return null;
  const credential = normalizeServiceIdentity(value.credential);
  if (!credential) return null;
  const usageRecord = isRecord(value.usage) ? { protected_app_ids: strings(value.usage.protected_app_ids), policy_versions: strings(value.usage.policy_versions), policy_deployment_ids: strings(value.usage.policy_deployment_ids) } : undefined;
  return { credential, secret: text(value.secret) || undefined, warning: text(value.warning) || undefined, usage: usageRecord };
}

function responseServiceIdentities(value: unknown): { credentials: ServiceIdentity[]; page: IdentityPagination } | null {
  if (!isRecord(value) || value.success !== true || !Array.isArray(value.credentials)) return null;
  const credentials = value.credentials.flatMap(credential => {
    const normalized = normalizeServiceIdentity(credential);
    return normalized ? [normalized] : [];
  });
  return { credentials, page: normalizePagination(value.page) };
}

function responseUsage(value: unknown): ServiceIdentityUsage | null {
  if (!isRecord(value) || value.success !== true || !isRecord(value.usage)) return null;
  return { protected_app_ids: strings(value.usage.protected_app_ids), policy_versions: strings(value.usage.policy_versions), policy_deployment_ids: strings(value.usage.policy_deployment_ids) };
}

function pageQuery(cursor?: string): string {
  return cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
}

export const identityV2Api = {
  listProviders(cursor?: string) { return request(`${ROOT}/providers${pageQuery(cursor)}`, 'GET', undefined, responseProviders); },
  getProvider(providerID: string) { return request(`${ROOT}/providers/${encodeURIComponent(providerID)}`, 'GET', undefined, responseProvider); },
  createProvider(input: IdentityProviderInput) { return request(`${ROOT}/providers`, 'POST', input, responseProvider); },
  updateProvider(providerID: string, input: IdentityProviderInput) { return request(`${ROOT}/providers/${encodeURIComponent(providerID)}`, 'PUT', input, responseProvider); },
  validateProvider(providerID: string, identityRevision: number) { return request(`${ROOT}/providers/${encodeURIComponent(providerID)}/validate`, 'POST', { identity_revision: identityRevision }, responseProvider); },
  deleteProvider(providerID: string, identityRevision: number) { return request(`${ROOT}/providers/${encodeURIComponent(providerID)}`, 'DELETE', { identity_revision: identityRevision }, value => isRecord(value) && value.success === true ? { identityRevision: number(value.identity_revision) } : null); },
  listMappings(cursor?: string) { return request(`${ROOT}/mappings${pageQuery(cursor)}`, 'GET', undefined, responseMappings); },
  updateMapping(providerID: string, identityRevision: number, mapping: IdentityClaimMapping) { return request(`${ROOT}/mappings/${encodeURIComponent(providerID)}`, 'PUT', { identity_revision: identityRevision, mapping }, responseMapping); },
  previewMapping(providerID: string, claims: Record<string, unknown>) { return request(`${ROOT}/mappings/${encodeURIComponent(providerID)}/preview`, 'POST', { claims }, responsePreview); },
  listServiceIdentities(cursor?: string) { return request(`${ROOT}/service-identities${pageQuery(cursor)}`, 'GET', undefined, responseServiceIdentities); },
  getServiceIdentity(id: string) { return request(`${ROOT}/service-identities/${encodeURIComponent(id)}`, 'GET', undefined, responseServiceIdentity); },
  createServiceIdentity(input: ServiceIdentityInput) { return request(`${ROOT}/service-identities`, 'POST', input, responseServiceIdentity); },
  updateServiceIdentity(id: string, input: ServiceIdentityUpdateInput) { return request(`${ROOT}/service-identities/${encodeURIComponent(id)}`, 'PUT', input, responseServiceIdentity); },
  rotateServiceIdentity(id: string, revision: number) { return request(`${ROOT}/service-identities/${encodeURIComponent(id)}/rotate`, 'POST', { revision }, responseServiceIdentity); },
  revokeServiceIdentity(id: string, revision: number, confirmDependencies: boolean) { return request(`${ROOT}/service-identities/${encodeURIComponent(id)}/revoke`, 'POST', { revision, confirm_dependencies: confirmDependencies }, responseServiceIdentity); },
  getServiceIdentityUsage(id: string) { return request(`${ROOT}/service-identities/${encodeURIComponent(id)}/usage`, 'GET', undefined, responseUsage); }
};
