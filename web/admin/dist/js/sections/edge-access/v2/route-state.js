import { EDGE_ACCESS_V2_DESTINATIONS, EDGE_ACCESS_V2_IDENTITY_TABS } from './types.js';
const VIEW_PARAM = 'ea_view';
const IDENTITY_TAB_PARAM = 'ea_identity_tab';
const IDENTITY_PROVIDER_MODE_PARAM = 'ea_identity_provider_mode';
const IDENTITY_PROVIDER_ID_PARAM = 'ea_identity_provider_id';
const IDENTITY_PROVIDER_KIND_PARAM = 'ea_identity_provider_kind';
const IDENTITY_PROVIDER_PRESET_PARAM = 'ea_identity_provider_preset';
const APP_ID_PARAM = 'ea_app_id';
const APP_TAB_PARAM = 'ea_app_tab';
const CREATE_APP_PARAM = 'ea_create_app';
const NEW_APP_ROUTE_ID_PARAM = 'ea_route_id';
const POLICY_VIEW_PARAM = 'ea_policy_view';
const POLICY_APP_ID_PARAM = 'ea_policy_app_id';
const POLICY_ID_PARAM = 'ea_policy_id';
const POLICY_MODE_PARAM = 'ea_policy_mode';
const POLICY_FIRST_ATTACHMENT_PARAM = 'ea_policy_first_attachment';
const ROLE_ID_PARAM = 'ea_role_id';
const ROLE_MODE_PARAM = 'ea_role_mode';
const DECISION_APP_ID_PARAM = 'ea_decision_app_id';
const DECISION_POLICY_ID_PARAM = 'ea_decision_policy_id';
const DECISION_QUERY_PARAM = 'ea_decision_q';
const DECISION_RESULT_PARAM = 'ea_decision_result';
const DECISION_IDENTITY_PARAM = 'ea_decision_identity';
const DECISION_CHANNEL_PARAM = 'ea_decision_channel';
const DECISION_HOSTNAME_PARAM = 'ea_decision_hostname';
const DECISION_ATTACHMENT_ID_PARAM = 'ea_decision_attachment_id';
const DECISION_POLICY_VERSION_PARAM = 'ea_decision_policy_version';
const DECISION_FROM_PARAM = 'ea_decision_from';
const DECISION_TO_PARAM = 'ea_decision_to';
const APP_SUBPAGES = ['overview', 'access-policies'];
const POLICY_VIEWS = ['library'];
const POLICY_MODES = ['list', 'new', 'edit'];
const ROLE_MODES = ['list', 'new', 'edit'];
const IDENTITY_PROVIDER_MODES = ['list', 'new', 'edit'];
const IDENTITY_PROVIDER_KINDS = ['oidc', 'jwt', 'api_key', 'mtls'];
const IDENTITY_PROVIDER_PRESETS = ['entra', 'okta', 'auth0', 'google', 'keycloak', 'oidc', 'entra-jwt', 'okta-jwt', 'auth0-jwt', 'cognito-jwt', 'keycloak-jwt', 'jwt'];
export function isEdgeAccessV2Destination(value) {
    return value !== null && EDGE_ACCESS_V2_DESTINATIONS.includes(value);
}
export function isEdgeAccessV2IdentityTab(value) {
    return value !== null && EDGE_ACCESS_V2_IDENTITY_TABS.includes(value);
}
function isIdentityProviderMode(value) {
    return value !== null && IDENTITY_PROVIDER_MODES.includes(value);
}
function isIdentityProviderPreset(value) {
    return value !== null && IDENTITY_PROVIDER_PRESETS.includes(value);
}
function isIdentityProviderKind(value) {
    return value !== null && IDENTITY_PROVIDER_KINDS.includes(value);
}
function providerPresetKind(preset) {
    return preset.endsWith('-jwt') || preset === 'jwt' ? 'jwt' : 'oidc';
}
export function isEdgeAccessV2AppSubpage(value) {
    return value !== null && APP_SUBPAGES.includes(value);
}
export function isEdgeAccessV2PolicyView(value) { return value !== null && POLICY_VIEWS.includes(value); }
export function isEdgeAccessV2PolicyMode(value) { return value !== null && POLICY_MODES.includes(value); }
export function isEdgeAccessV2RoleMode(value) { return value !== null && ROLE_MODES.includes(value); }
export function parseEdgeAccessV2Route(search) {
    const params = new URLSearchParams(search);
    const destination = params.get(VIEW_PARAM);
    const identityTab = params.get(IDENTITY_TAB_PARAM);
    const identityProviderMode = params.get(IDENTITY_PROVIDER_MODE_PARAM);
    const identityProviderKind = params.get(IDENTITY_PROVIDER_KIND_PARAM);
    const identityProviderPreset = params.get(IDENTITY_PROVIDER_PRESET_PARAM);
    const parsedProviderPreset = isIdentityProviderPreset(identityProviderPreset) ? identityProviderPreset : undefined;
    const appID = params.get(APP_ID_PARAM) || undefined;
    const creatingApp = params.get(CREATE_APP_PARAM) === '1';
    const appSubpage = params.get(APP_TAB_PARAM);
    const policyView = params.get(POLICY_VIEW_PARAM);
    const policyMode = params.get(POLICY_MODE_PARAM);
    const roleMode = params.get(ROLE_MODE_PARAM);
    return {
        destination: isEdgeAccessV2Destination(destination) ? destination : 'apps',
        identityTab: isEdgeAccessV2IdentityTab(identityTab) ? identityTab : 'providers',
        identityProviderMode: isIdentityProviderMode(identityProviderMode) ? identityProviderMode : 'list',
        identityProviderID: params.get(IDENTITY_PROVIDER_ID_PARAM) || undefined,
        identityProviderKind: isIdentityProviderKind(identityProviderKind) ? identityProviderKind : parsedProviderPreset ? providerPresetKind(parsedProviderPreset) : undefined,
        identityProviderPreset: parsedProviderPreset,
        appID: creatingApp ? undefined : appID,
        appSubpage: isEdgeAccessV2AppSubpage(appSubpage) ? appSubpage : 'overview',
        creatingApp,
        newAppRouteID: creatingApp ? params.get(NEW_APP_ROUTE_ID_PARAM) || undefined : undefined,
        policyView: isEdgeAccessV2PolicyView(policyView) ? policyView : 'library',
        policyAppID: params.get(POLICY_APP_ID_PARAM) || undefined,
        policyID: params.get(POLICY_ID_PARAM) || undefined,
        policyMode: isEdgeAccessV2PolicyMode(policyMode) ? policyMode : 'list',
        policyFirstAttachment: params.get(POLICY_FIRST_ATTACHMENT_PARAM) === '1',
        roleMode: isEdgeAccessV2RoleMode(roleMode) ? roleMode : 'list',
        roleID: params.get(ROLE_ID_PARAM) || undefined,
        decisionAppID: params.get(DECISION_APP_ID_PARAM) || undefined,
        decisionPolicyID: params.get(DECISION_POLICY_ID_PARAM) || undefined,
        decisionQuery: params.get(DECISION_QUERY_PARAM) || undefined,
        decisionResult: params.get(DECISION_RESULT_PARAM) || undefined,
        decisionIdentity: params.get(DECISION_IDENTITY_PARAM) || undefined,
        decisionChannel: params.get(DECISION_CHANNEL_PARAM) || undefined,
        decisionHostname: params.get(DECISION_HOSTNAME_PARAM) || undefined,
        decisionAttachmentID: params.get(DECISION_ATTACHMENT_ID_PARAM) || undefined,
        decisionPolicyVersion: params.get(DECISION_POLICY_VERSION_PARAM) || undefined,
        decisionFrom: params.get(DECISION_FROM_PARAM) || undefined,
        decisionTo: params.get(DECISION_TO_PARAM) || undefined
    };
}
export function serializeEdgeAccessV2Route(search, route) {
    const params = new URLSearchParams(search);
    params.set(VIEW_PARAM, route.destination);
    if (route.destination === 'identity') {
        params.set(IDENTITY_TAB_PARAM, route.identityTab);
        const providerMode = route.identityProviderMode || 'list';
        if (route.identityTab === 'providers' && providerMode !== 'list') {
            params.set(IDENTITY_PROVIDER_MODE_PARAM, providerMode);
            if (route.identityProviderID)
                params.set(IDENTITY_PROVIDER_ID_PARAM, route.identityProviderID);
            else
                params.delete(IDENTITY_PROVIDER_ID_PARAM);
            if (route.identityProviderKind)
                params.set(IDENTITY_PROVIDER_KIND_PARAM, route.identityProviderKind);
            else
                params.delete(IDENTITY_PROVIDER_KIND_PARAM);
            if (route.identityProviderPreset)
                params.set(IDENTITY_PROVIDER_PRESET_PARAM, route.identityProviderPreset);
            else
                params.delete(IDENTITY_PROVIDER_PRESET_PARAM);
        }
        else {
            params.delete(IDENTITY_PROVIDER_MODE_PARAM);
            params.delete(IDENTITY_PROVIDER_ID_PARAM);
            params.delete(IDENTITY_PROVIDER_KIND_PARAM);
            params.delete(IDENTITY_PROVIDER_PRESET_PARAM);
        }
    }
    else {
        params.delete(IDENTITY_TAB_PARAM);
        params.delete(IDENTITY_PROVIDER_MODE_PARAM);
        params.delete(IDENTITY_PROVIDER_ID_PARAM);
        params.delete(IDENTITY_PROVIDER_KIND_PARAM);
        params.delete(IDENTITY_PROVIDER_PRESET_PARAM);
    }
    if (route.destination === 'apps' && route.creatingApp) {
        params.set(CREATE_APP_PARAM, '1');
        if (route.newAppRouteID)
            params.set(NEW_APP_ROUTE_ID_PARAM, route.newAppRouteID);
        else
            params.delete(NEW_APP_ROUTE_ID_PARAM);
        params.delete(APP_ID_PARAM);
        params.delete(APP_TAB_PARAM);
    }
    else if (route.destination === 'apps' && route.appID) {
        params.set(APP_ID_PARAM, route.appID);
        params.set(APP_TAB_PARAM, route.appSubpage);
        params.delete(CREATE_APP_PARAM);
        params.delete(NEW_APP_ROUTE_ID_PARAM);
    }
    else {
        params.delete(APP_ID_PARAM);
        params.delete(APP_TAB_PARAM);
        params.delete(CREATE_APP_PARAM);
        params.delete(NEW_APP_ROUTE_ID_PARAM);
    }
    if (route.destination === 'policies') {
        params.set(POLICY_VIEW_PARAM, route.policyView);
        if (route.policyAppID)
            params.set(POLICY_APP_ID_PARAM, route.policyAppID);
        else
            params.delete(POLICY_APP_ID_PARAM);
        if (route.policyID)
            params.set(POLICY_ID_PARAM, route.policyID);
        else
            params.delete(POLICY_ID_PARAM);
        if (route.policyMode !== 'list')
            params.set(POLICY_MODE_PARAM, route.policyMode);
        else
            params.delete(POLICY_MODE_PARAM);
        if (route.policyFirstAttachment)
            params.set(POLICY_FIRST_ATTACHMENT_PARAM, '1');
        else
            params.delete(POLICY_FIRST_ATTACHMENT_PARAM);
    }
    else {
        params.delete(POLICY_VIEW_PARAM);
        params.delete(POLICY_APP_ID_PARAM);
        params.delete(POLICY_ID_PARAM);
        params.delete(POLICY_MODE_PARAM);
        params.delete(POLICY_FIRST_ATTACHMENT_PARAM);
    }
    if (route.destination === 'roles') {
        if (route.roleMode !== 'list')
            params.set(ROLE_MODE_PARAM, route.roleMode);
        else
            params.delete(ROLE_MODE_PARAM);
        if (route.roleID)
            params.set(ROLE_ID_PARAM, route.roleID);
        else
            params.delete(ROLE_ID_PARAM);
    }
    else {
        params.delete(ROLE_MODE_PARAM);
        params.delete(ROLE_ID_PARAM);
    }
    if (route.destination === 'decisions') {
        if (route.decisionAppID)
            params.set(DECISION_APP_ID_PARAM, route.decisionAppID);
        else
            params.delete(DECISION_APP_ID_PARAM);
        if (route.decisionPolicyID)
            params.set(DECISION_POLICY_ID_PARAM, route.decisionPolicyID);
        else
            params.delete(DECISION_POLICY_ID_PARAM);
        if (route.decisionQuery)
            params.set(DECISION_QUERY_PARAM, route.decisionQuery);
        else
            params.delete(DECISION_QUERY_PARAM);
        if (route.decisionResult)
            params.set(DECISION_RESULT_PARAM, route.decisionResult);
        else
            params.delete(DECISION_RESULT_PARAM);
        if (route.decisionIdentity)
            params.set(DECISION_IDENTITY_PARAM, route.decisionIdentity);
        else
            params.delete(DECISION_IDENTITY_PARAM);
        if (route.decisionChannel)
            params.set(DECISION_CHANNEL_PARAM, route.decisionChannel);
        else
            params.delete(DECISION_CHANNEL_PARAM);
        if (route.decisionHostname)
            params.set(DECISION_HOSTNAME_PARAM, route.decisionHostname);
        else
            params.delete(DECISION_HOSTNAME_PARAM);
        if (route.decisionAttachmentID)
            params.set(DECISION_ATTACHMENT_ID_PARAM, route.decisionAttachmentID);
        else
            params.delete(DECISION_ATTACHMENT_ID_PARAM);
        if (route.decisionPolicyVersion)
            params.set(DECISION_POLICY_VERSION_PARAM, route.decisionPolicyVersion);
        else
            params.delete(DECISION_POLICY_VERSION_PARAM);
        if (route.decisionFrom)
            params.set(DECISION_FROM_PARAM, route.decisionFrom);
        else
            params.delete(DECISION_FROM_PARAM);
        if (route.decisionTo)
            params.set(DECISION_TO_PARAM, route.decisionTo);
        else
            params.delete(DECISION_TO_PARAM);
    }
    else {
        params.delete(DECISION_APP_ID_PARAM);
        params.delete(DECISION_POLICY_ID_PARAM);
        params.delete(DECISION_QUERY_PARAM);
        params.delete(DECISION_RESULT_PARAM);
        params.delete(DECISION_IDENTITY_PARAM);
        params.delete(DECISION_CHANNEL_PARAM);
        params.delete(DECISION_HOSTNAME_PARAM);
        params.delete(DECISION_ATTACHMENT_ID_PARAM);
        params.delete(DECISION_POLICY_VERSION_PARAM);
        params.delete(DECISION_FROM_PARAM);
        params.delete(DECISION_TO_PARAM);
    }
    const serialized = params.toString();
    return serialized ? `?${serialized}` : '';
}
