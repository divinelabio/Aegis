import type { PolicyRuntimeCapabilitiesContract } from '../../edge-access-contract.js';
import type { IdentityMappingRecord, IdentityProvider, IdentityPagination, ServiceIdentity } from './identity-contract.js';
import type { AppCatalogItem, AppHistoryEvent, AppRecentDecision, AppRouteOption, AppSubpage } from './apps-contract.js';
import type { DecisionExplorerDetail, DecisionExplorerRecord, Policy, PolicyAuthChannel, PolicyVersion, PolicyWorkspaceApp, PolicyWorkspaceAttachment, PolicyWorkspaceLibraryItem } from './policies-contract.js';
import type { EdgeAccessSettings, ReloadStatusResponse } from '../../edge-access-contract.js';
import type { AccessRole } from './roles-contract.js';

export type EdgeAccessV2Destination = 'apps' | 'policies' | 'identity' | 'roles' | 'decisions' | 'runtime';
export type EdgeAccessV2IdentityTab = 'providers' | 'mappings' | 'service-identities';
export type EdgeAccessV2IdentityProviderMode = 'list' | 'new' | 'edit';
export type EdgeAccessV2IdentityProviderKind = 'oidc' | 'jwt' | 'api_key' | 'mtls';
export type EdgeAccessV2IdentityProviderPreset = 'entra' | 'okta' | 'auth0' | 'google' | 'keycloak' | 'oidc' | 'entra-jwt' | 'okta-jwt' | 'auth0-jwt' | 'cognito-jwt' | 'keycloak-jwt' | 'jwt';
export type EdgeAccessV2PolicyView = 'library';
export type EdgeAccessV2PolicyMode = 'list' | 'new' | 'edit';
export type EdgeAccessV2RoleMode = 'list' | 'new' | 'edit';

export interface EdgeAccessV2Route {
  destination: EdgeAccessV2Destination;
  identityTab: EdgeAccessV2IdentityTab;
  identityProviderMode: EdgeAccessV2IdentityProviderMode;
  identityProviderID?: string;
  identityProviderKind?: EdgeAccessV2IdentityProviderKind;
  identityProviderPreset?: EdgeAccessV2IdentityProviderPreset;
  roleMode: EdgeAccessV2RoleMode;
  roleID?: string;
  appID?: string;
  appSubpage: AppSubpage;
  creatingApp: boolean;
  newAppRouteID?: string;
  policyView: EdgeAccessV2PolicyView;
  policyAppID?: string;
  policyID?: string;
  policyMode: EdgeAccessV2PolicyMode;
  policyFirstAttachment: boolean;
  decisionAppID?: string;
  decisionPolicyID?: string;
  decisionQuery?: string;
  decisionResult?: string;
  decisionIdentity?: string;
  decisionChannel?: string;
  decisionHostname?: string;
  decisionAttachmentID?: string;
  decisionPolicyVersion?: string;
  decisionFrom?: string;
  decisionTo?: string;
}

export interface EdgeAccessV2PolicyCapabilitiesState {
  loading: boolean;
  value: PolicyRuntimeCapabilitiesContract | null;
  error: string | null;
}

export interface EdgeAccessV2ResourceState<T> {
  loading: boolean;
  value: T | null;
  page: IdentityPagination | null;
  error: string | null;
}

export interface EdgeAccessV2IdentityState {
  identityRevision: number;
  providers: EdgeAccessV2ResourceState<IdentityProvider[]>;
  mappings: EdgeAccessV2ResourceState<IdentityMappingRecord[]>;
  serviceIdentities: EdgeAccessV2ResourceState<ServiceIdentity[]>;
}

export interface EdgeAccessV2RolesState {
  catalog: EdgeAccessV2ResourceState<AccessRole[]>;
}

export interface EdgeAccessV2AppsState {
  catalog: EdgeAccessV2ResourceState<AppCatalogItem[]>;
  detail: EdgeAccessV2ResourceState<AppCatalogItem>;
  history: EdgeAccessV2ResourceState<AppHistoryEvent[]>;
  decisions: EdgeAccessV2ResourceState<AppRecentDecision[]>;
  routes: EdgeAccessV2ResourceState<AppRouteOption[]>;
  filter: { q: string; status: string; trustChannel: string; noActiveAllow: boolean };
}

export interface EdgeAccessV2PoliciesState {
  apps: EdgeAccessV2ResourceState<PolicyWorkspaceApp[]>;
  appDetail: EdgeAccessV2ResourceState<{ app: PolicyWorkspaceApp; attachments: PolicyWorkspaceAttachment[] }>;
  library: EdgeAccessV2ResourceState<PolicyWorkspaceLibraryItem[]>;
  policy: EdgeAccessV2ResourceState<Policy>;
  versions: EdgeAccessV2ResourceState<PolicyVersion[]>;
  pendingFirstAttachment: { protectedAppID: string; path: string; methods: string[]; channels: PolicyAuthChannel[] } | null;
  filter: { q: string; status: string; decision: string };
}

export interface EdgeAccessV2DecisionsState {
  list: EdgeAccessV2ResourceState<DecisionExplorerRecord[]>;
  detail: EdgeAccessV2ResourceState<DecisionExplorerDetail>;
  filter: { q: string; result: string; identity: string; channel: string; hostname: string; attachmentID: string; policyVersion: string; from: string; to: string };
}

export interface EdgeAccessV2RuntimeState {
  settings: EdgeAccessV2ResourceState<EdgeAccessSettings>;
  reload: EdgeAccessV2ResourceState<ReloadStatusResponse>;
}

export interface EdgeAccessV2ShellState {
  route: EdgeAccessV2Route;
  policyCapabilities: EdgeAccessV2PolicyCapabilitiesState;
  identity: EdgeAccessV2IdentityState;
  roles: EdgeAccessV2RolesState;
  apps: EdgeAccessV2AppsState;
  policies: EdgeAccessV2PoliciesState;
  decisions: EdgeAccessV2DecisionsState;
  runtime: EdgeAccessV2RuntimeState;
}

export const EDGE_ACCESS_V2_DESTINATIONS: readonly EdgeAccessV2Destination[] = ['apps', 'policies', 'identity', 'roles', 'decisions', 'runtime'];
export const EDGE_ACCESS_V2_IDENTITY_TABS: readonly EdgeAccessV2IdentityTab[] = ['providers', 'mappings', 'service-identities'];
