import { SectionUI } from '../../ui-components.js';
import { escapeHTML, formatDateTime, statusTone } from '../view-helpers.js';
import { renderV2Apps } from './apps-components.js';
import { renderV2Decisions, renderV2Policies } from './policies-components.js';
import { renderV2Runtime } from './runtime-components.js';
import { renderManagedRolePicker, renderV2Roles } from './roles-components.js';
import { renderAdvancedDisclosure, renderCreateBack, renderSetupHeading } from './setup-components.js';
const configurationNavigation = [
    { destination: 'apps', label: 'Apps', icon: SectionUI.icons.route },
    { destination: 'policies', label: 'Access policies', icon: SectionUI.icons.shieldCheck },
    { destination: 'identity', label: 'Identity', icon: SectionUI.icons.users },
    { destination: 'roles', label: 'Roles', icon: SectionUI.icons.tag },
    { destination: 'decisions', label: 'Decisions', icon: SectionUI.icons.activity },
    { destination: 'runtime', label: 'Settings', icon: SectionUI.icons.settings }
];
function identityAction(label, action, attributes = '', primary = false) {
    return `<button type="button" class="btn ${primary ? 'btn-primary' : 'btn-outline'}" data-edge-access-v2-action="${action}" ${attributes}>${escapeHTML(label)}</button>`;
}
function identityLoadingOrError(loading, error, retryTab) {
    if (loading)
        return SectionUI.renderLoading('Loading identity configuration...');
    if (error)
        return `<div class="section-error" role="alert"><div class="error-message">${escapeHTML(error)}</div>${identityAction('Retry', 'retry-identity', `data-edge-access-v2-identity-tab="${retryTab}"`)}</div>`;
    return null;
}
function providerStatus(provider) {
    const status = provider.validation.status;
    const label = { valid: 'Valid', warning: 'Warning', failed: 'Failed', not_validated: 'Not validated' };
    return SectionUI.renderStatusPill(label[status] || 'Not validated', statusTone(status));
}
const providerTemplates = [
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
    { id: 'jwt', name: 'Generic JWT issuer', description: 'Verify bearer tokens using JWKS or write-only key material.', type: 'jwt', namePlaceholder: 'Production API issuer', issuerPlaceholder: 'https://tokens.example.com' }
];
const addIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>';
function providerBrand(provider) {
    const source = `${provider.name} ${provider.issuer}`.toLowerCase();
    if (provider.type === 'jwt') {
        if (source.includes('cognito') || source.includes('amazonaws'))
            return 'cognito-jwt';
        if (source.includes('keycloak'))
            return 'keycloak-jwt';
        if (source.includes('microsoft') || source.includes('entra') || source.includes('login.microsoftonline'))
            return 'entra-jwt';
        if (source.includes('okta'))
            return 'okta-jwt';
        if (source.includes('auth0'))
            return 'auth0-jwt';
        return 'jwt';
    }
    if (source.includes('microsoft') || source.includes('entra') || source.includes('login.microsoftonline'))
        return 'entra';
    if (source.includes('okta'))
        return 'okta';
    if (source.includes('auth0'))
        return 'auth0';
    if (source.includes('google') || source.includes('accounts.google'))
        return 'google';
    if (source.includes('keycloak'))
        return 'keycloak';
    return 'oidc';
}
function providerMark(brand, label) {
    const content = {
        entra: '<span class="edge-access-v2-provider-ms-grid"><i></i><i></i><i></i><i></i></span>',
        okta: '<span class="edge-access-v2-provider-letter">O</span>',
        auth0: '<span class="edge-access-v2-provider-letter">A0</span>',
        google: '<span class="edge-access-v2-provider-letter">G</span>',
        keycloak: '<span class="edge-access-v2-provider-letter">K</span>',
        oidc: SectionUI.icons.globe,
        'entra-jwt': '<span class="edge-access-v2-provider-ms-grid"><i></i><i></i><i></i><i></i></span>',
        'okta-jwt': '<span class="edge-access-v2-provider-letter">O</span>',
        'auth0-jwt': '<span class="edge-access-v2-provider-letter">A0</span>',
        'cognito-jwt': '<span class="edge-access-v2-provider-letter">AWS</span>',
        'keycloak-jwt': '<span class="edge-access-v2-provider-letter">K</span>',
        jwt: SectionUI.icons.key
    };
    return `<span class="edge-access-v2-provider-mark brand-${brand}" aria-label="${escapeHTML(label)} icon">${content[brand]}</span>`;
}
function setupField(label, name, value = '', options = {}) {
    const classes = `edge-access-v2-setup-field${options.wide ? ' edge-access-v2-setup-field--wide' : ''}`;
    const shared = `name="${escapeHTML(name)}"${options.required ? ' required' : ''}${options.readonly ? ' readonly' : ''}${options.placeholder ? ` placeholder="${escapeHTML(options.placeholder)}"` : ''}`;
    const control = options.textarea
        ? `<textarea class="input" rows="5" ${shared}>${escapeHTML(value)}</textarea>`
        : `<input class="input" type="${escapeHTML(options.type || 'text')}" value="${escapeHTML(value)}" ${shared}>`;
    return `<label class="${classes}"><span>${escapeHTML(label)}</span>${control}</label>`;
}
function renderProviderTypeSelector(selectedType) {
    return `<div class="edge-access-v2-provider-type-step">
    <label class="edge-access-v2-setup-field edge-access-v2-provider-type-field">
      <span>Identity type</span>
      <select class="input" data-edge-access-v2-provider-type-select>
        <option value="">Choose an identity type</option>
        <option value="oidc"${selectedType === 'oidc' ? ' selected' : ''}>Workforce provider (OIDC)</option>
        <option value="jwt"${selectedType === 'jwt' ? ' selected' : ''}>Token issuer (JWT)</option>
        <option value="api_key"${selectedType === 'api_key' ? ' selected' : ''}>Machine identity (API key)</option>
        <option value="mtls"${selectedType === 'mtls' ? ' selected' : ''}>Machine identity (mTLS)</option>
      </select>
    </label>
  </div>`;
}
function renderProviderSetup(state) {
    const editing = state.route.identityProviderMode === 'edit';
    const provider = editing ? (state.identity.providers.value || []).find(item => item.provider_id === state.route.identityProviderID) : undefined;
    if (editing && state.identity.providers.loading)
        return `<div class="edge-access-v2-create-shell edge-access-v2-provider-setup-shell">${renderCreateBack('Identity sources', 'Back to identity sources', 'provider-back')}${SectionUI.renderLoading('Loading provider configuration...')}</div>`;
    if (editing && !provider)
        return `<div class="edge-access-v2-create-shell edge-access-v2-provider-setup-shell">${renderCreateBack('Identity sources', 'Back to identity sources', 'provider-back')}${SectionUI.renderOperatorSection('Provider unavailable', SectionUI.renderEmptyState('Provider not found', 'Return to Identity sources and choose an available provider.', 'info'))}</div>`;
    const selectedPreset = provider ? providerBrand(provider) : state.route.identityProviderPreset;
    const template = providerTemplates.find(item => item.id === selectedPreset);
    const selectedType = provider?.type || template?.type || state.route.identityProviderKind;
    const machineType = !editing && (selectedType === 'api_key' || selectedType === 'mtls') ? selectedType : undefined;
    const defaultScopes = 'openid, profile, email';
    const configuredScopes = provider?.scopes.join(', ') || defaultScopes;
    const hasCustomScopes = Boolean(provider && configuredScopes !== defaultScopes);
    const templateCards = (providerType) => providerTemplates.filter(item => item.type === providerType).map(item => `<button type="button" class="edge-access-v2-provider-template${selectedPreset === item.id ? ' is-selected' : ''}" data-edge-access-v2-action="provider-template" data-edge-access-v2-provider-preset="${item.id}" data-edge-access-v2-provider-kind="${item.type}" aria-pressed="${selectedPreset === item.id}">
    ${providerMark(item.id, item.name)}
    <span class="edge-access-v2-provider-template-copy"><strong>${escapeHTML(item.name)}</strong><span>${escapeHTML(item.description)}</span><small>${item.type === 'oidc' ? 'OpenID Connect' : 'Bearer token verification'}</small></span>
    <span class="edge-access-v2-provider-template-check" aria-hidden="true">${SectionUI.icons.check}</span>
  </button>`).join('');
    const type = provider?.type || template?.type;
    const form = template && type ? `<section class="edge-access-v2-setup-section edge-access-v2-provider-config-section">
    ${renderSetupHeading(editing ? 'Provider configuration' : `Configure ${template.name}`, type === 'oidc' ? 'Enter the provider metadata and browser client configuration.' : 'Configure issuer verification for bearer tokens.')}
    <form class="edge-access-v2-provider-page-form" data-edge-access-v2-provider-form="true" data-edge-access-v2-provider-id="${escapeHTML(provider?.provider_id || '')}">
      <input type="hidden" name="type" value="${type}">
      <div class="edge-access-v2-provider-form-grid">
        ${setupField('Provider ID', 'provider_id', provider?.provider_id || '', { required: true, readonly: editing, placeholder: type === 'oidc' ? 'corporate-sso' : 'production-api' })}
        ${setupField('Display name', 'name', provider?.name || '', { required: true, placeholder: template.namePlaceholder })}
        ${setupField('Issuer URL', 'issuer', provider?.issuer || '', { required: true, placeholder: template.issuerPlaceholder, wide: true })}
        ${type === 'oidc' ? `
          ${setupField('Client ID', 'client_id', provider?.client_id || '', { required: true, placeholder: 'Application client ID' })}
          ${setupField('Client secret', 'client_secret', '', { type: 'password', placeholder: editing ? 'Leave empty to keep current secret' : 'Enter client secret' })}
          ${setupField('Redirect URL', 'redirect_url', provider?.redirect_url || '', { required: true, placeholder: 'https://app.example.com/auth/callback', wide: true })}
        ` : `
          ${setupField('Audience', 'audience', provider?.audience || '', { placeholder: 'api://edge-access' })}
          ${setupField('Algorithms', 'algorithms', provider?.algorithms.join(', ') || 'RS256')}
          ${setupField('JWKS URL', 'jwks_url', '', { placeholder: editing ? 'Leave empty to keep the configured URL' : 'https://issuer.example.com/.well-known/jwks.json', wide: true })}
          ${setupField('Verification secret or public key', 'secret_key', '', { textarea: true, wide: true, placeholder: editing ? 'Leave empty to keep existing material' : 'Paste verification material' })}
        `}
      </div>
      ${type === 'oidc' ? renderAdvancedDisclosure({
        title: 'Advanced settings',
        description: 'OIDC scopes',
        body: setupField('Scopes', 'scopes', configuredScopes),
        open: hasCustomScopes,
        className: 'edge-access-v2-provider-advanced'
    }) : ''}
      <footer class="edge-access-v2-create-actions"><div class="operator-control-actions">${identityAction(editing ? 'Save Changes' : 'Add provider', 'provider-save', '', true)}</div></footer>
    </form>
  </section>` : '';
    const machineForm = machineType ? `<section class="edge-access-v2-setup-section edge-access-v2-provider-config-section">
    ${renderSetupHeading(machineType === 'api_key' ? 'Configure API key' : 'Configure mTLS identity', machineType === 'api_key' ? 'Create a credential for an automated client or service.' : 'Register a client certificate for mutual TLS authentication.')}
    <form class="edge-access-v2-provider-page-form" data-edge-access-v2-machine-form="true">
      <input type="hidden" name="type" value="${machineType}">
      <div class="edge-access-v2-provider-form-grid">
        ${setupField('Display name', 'name', '', { required: true, placeholder: machineType === 'api_key' ? 'Deployment automation' : 'Production service certificate' })}
        ${setupField('Expires in', 'expires_in', '', { placeholder: 'Optional, for example 90d' })}
        ${setupField('Groups', 'groups', '', { placeholder: 'Comma-separated groups' })}
        ${machineType === 'mtls' ? setupField('Certificate PEM', 'certificate_pem', '', { required: true, textarea: true, wide: true, placeholder: 'Paste the client certificate in PEM format' }) : ''}
      </div>
      ${renderManagedRolePicker(state.roles.catalog, [], { name: 'roles', label: 'Assigned roles' })}
      <footer class="edge-access-v2-create-actions"><div class="operator-control-actions">${identityAction('Create identity', 'machine-identity-save', '', true)}</div></footer>
    </form>
  </section>` : '';
    return `<div class="edge-access-v2-create-shell edge-access-v2-provider-setup-shell">
    ${renderCreateBack('Identity sources', 'Back to identity sources', 'provider-back')}
    ${SectionUI.renderOperatorSection(editing ? `Edit ${escapeHTML(provider?.name || 'provider')}` : 'Add identity source', `
      ${editing ? '' : `<section class="edge-access-v2-setup-section edge-access-v2-provider-catalog-section">
        ${renderSetupHeading('Choose a connection', 'Select an identity type, then configure the matching connection.')}
        ${renderProviderTypeSelector(selectedType)}
        ${selectedType === 'oidc' || selectedType === 'jwt' ? `<div class="edge-access-v2-provider-type-catalog" data-edge-access-v2-provider-type-catalog>
          <div class="edge-access-v2-provider-type-options" data-edge-access-v2-provider-type-options="oidc"${selectedType === 'oidc' ? '' : ' hidden'}>
            <div class="edge-access-v2-provider-type-summary"><div><strong>OpenID Connect providers</strong><span>Browser sessions and workforce single sign-on</span></div></div>
            <div class="edge-access-v2-provider-template-grid">${templateCards('oidc')}</div>
          </div>
          <div class="edge-access-v2-provider-type-options" data-edge-access-v2-provider-type-options="jwt"${selectedType === 'jwt' ? '' : ' hidden'}>
            <div class="edge-access-v2-provider-type-summary"><div><strong>JWT issuers</strong><span>Bearer-token verification for APIs and workloads</span></div></div>
            <div class="edge-access-v2-provider-template-grid">${templateCards('jwt')}</div>
          </div>
        </div>` : ''}
      </section>`}
      ${form}
      ${machineForm}
    `, { subtitle: editing ? 'Update connection metadata and write-only credentials.' : 'Create a reusable identity source, then validate it before assigning it to applications.', className: 'edge-access-v2-new-app-section edge-access-v2-provider-editor-section' })}
  </div>`;
}
function serviceIdentityStatus(identity) {
    return SectionUI.renderStatusPill(identity.revoked ? 'Revoked' : identity.status, statusTone(identity.revoked ? 'failed' : identity.status));
}
function machineIdentityMark(identity) {
    const icon = identity.type === 'api_key' ? SectionUI.icons.key : SectionUI.icons.shieldCheck;
    return `<span class="edge-access-v2-provider-mark brand-jwt" aria-label="${escapeHTML(identity.name)} icon">${icon}</span>`;
}
function renderIdentityInventory(state) {
    const providerResource = state.identity.providers;
    const machineResource = state.identity.serviceIdentities;
    const mappingResource = state.identity.mappings;
    const actions = `<button type="button" class="btn btn-primary" data-edge-access-v2-action="identity-source-create"><span class="edge-access-v2-button-icon" aria-hidden="true">${addIcon}</span>Add identity source</button>`;
    const loading = (providerResource.loading && !providerResource.value) || (machineResource.loading && !machineResource.value);
    if (loading) {
        return SectionUI.renderOperatorSection('Identity sources', SectionUI.renderLoading('Loading identity sources...'), {
            subtitle: 'Manage workforce providers, token issuers, and machine credentials in one inventory.',
            actions,
            className: 'edge-access-v2-provider-inventory-section'
        });
    }
    const mappedProviderIDs = new Set((mappingResource.value || []).map(mapping => mapping.provider_id));
    const providerRows = (providerResource.value || []).map(provider => ({
        name: provider.name,
        cells: [
            `<div class="edge-access-v2-provider-cell">${providerMark(providerBrand(provider), provider.name)}<div><strong>${escapeHTML(provider.name)}</strong><span class="text-mono">${escapeHTML(provider.issuer)}</span></div></div>`,
            `<strong>${provider.type === 'oidc' ? 'Workforce provider' : 'Token issuer'}</strong><br><span class="text-muted">${provider.type === 'oidc' ? 'OpenID Connect' : 'JWT'}</span>`,
            providerStatus(provider),
            provider.usage.protected_app_ids.length ? `<strong>${provider.usage.protected_app_ids.length} ${provider.usage.protected_app_ids.length === 1 ? 'application' : 'applications'}</strong>` : '<span class="text-muted">Not assigned</span>',
            provider.validation.checked_at ? formatDateTime(provider.validation.checked_at) : '<span class="text-muted">Never validated</span>',
            SectionUI.renderActionMenu({
                id: `edge-access-v2-provider-actions-${provider.provider_id}`,
                ariaLabel: `Actions for ${provider.name}`,
                label: 'More',
                items: [
                    { label: 'Validate provider', attrs: `data-edge-access-v2-action="provider-validate" data-edge-access-v2-provider-id="${escapeHTML(provider.provider_id)}"` },
                    { label: 'Edit provider', attrs: `data-edge-access-v2-action="provider-edit" data-edge-access-v2-provider-id="${escapeHTML(provider.provider_id)}"` },
                    {
                        label: mappingResource.loading ? 'Loading claim mapping...' : mappingResource.error || !mappedProviderIDs.has(provider.provider_id) ? 'Claim mapping unavailable' : 'Edit claim mapping',
                        attrs: `data-edge-access-v2-action="mapping-edit" data-edge-access-v2-provider-id="${escapeHTML(provider.provider_id)}"`,
                        disabled: mappingResource.loading || Boolean(mappingResource.error) || !mappedProviderIDs.has(provider.provider_id)
                    },
                    { label: 'Delete provider', attrs: `data-edge-access-v2-action="provider-delete" data-edge-access-v2-provider-id="${escapeHTML(provider.provider_id)}"`, tone: 'danger' }
                ]
            })
        ]
    }));
    const machineRows = (machineResource.value || []).map(identity => ({
        name: identity.name,
        cells: [
            `<div class="edge-access-v2-provider-cell">${machineIdentityMark(identity)}<div><strong>${escapeHTML(identity.name)}</strong><span class="text-mono">${escapeHTML(identity.key_prefix || identity.fingerprint || 'Automated client credential')}</span></div></div>`,
            `<strong>Machine identity</strong><br><span class="text-muted">${identity.type === 'api_key' ? 'API key' : 'mTLS certificate'}</span>`,
            serviceIdentityStatus(identity),
            identity.usage_count ? `<strong>${identity.usage_count} ${identity.usage_count === 1 ? 'reference' : 'references'}</strong>` : '<span class="text-muted">Not used</span>',
            formatDateTime(identity.updated_at || identity.created_at),
            SectionUI.renderActionMenu({
                id: `edge-access-v2-machine-identity-actions-${identity.id}`,
                ariaLabel: `Actions for ${identity.name}`,
                label: 'More',
                items: [
                    { label: 'View usage', attrs: `data-edge-access-v2-action="service-identity-usage" data-edge-access-v2-service-identity-id="${escapeHTML(identity.id)}"` },
                    { label: 'Edit identity', attrs: `data-edge-access-v2-action="service-identity-edit" data-edge-access-v2-service-identity-id="${escapeHTML(identity.id)}"` },
                    { label: 'Rotate credential', attrs: `data-edge-access-v2-action="service-identity-rotate" data-edge-access-v2-service-identity-id="${escapeHTML(identity.id)}"` },
                    { label: 'Revoke identity', attrs: `data-edge-access-v2-action="service-identity-revoke" data-edge-access-v2-service-identity-id="${escapeHTML(identity.id)}"`, tone: 'danger' }
                ]
            })
        ]
    }));
    const rows = [...providerRows, ...machineRows].sort((left, right) => left.name.localeCompare(right.name)).map(item => item.cells);
    const errors = [
        providerResource.error ? identityLoadingOrError(false, providerResource.error, 'providers') : '',
        machineResource.error ? identityLoadingOrError(false, machineResource.error, 'service-identities') : '',
        mappingResource.error ? identityLoadingOrError(false, 'Claim mapping actions are temporarily unavailable.', 'mappings') : ''
    ].filter(Boolean).join('');
    const table = SectionUI.renderEnterpriseTable({
        columns: ['Identity source', 'Type', 'Status', 'Used by', 'Last activity', 'Actions'],
        rows,
        emptyTitle: 'No identity sources',
        emptyMessage: 'Add an OIDC provider, JWT issuer, API key, or mTLS machine identity.'
    });
    return SectionUI.renderOperatorSection('Identity sources', `<div class="edge-access-v2-provider-inventory">${errors}${table}</div>`, {
        subtitle: 'Manage workforce providers, token issuers, and machine credentials in one inventory.',
        actions,
        className: 'edge-access-v2-provider-inventory-section'
    });
}
function renderIdentity(state) {
    if (state.route.identityProviderMode !== 'list')
        return renderProviderSetup(state);
    return renderIdentityInventory(state);
}
function renderDestination(state) {
    switch (state.route.destination) {
        case 'policies': return renderV2Policies(state);
        case 'identity': return renderIdentity(state);
        case 'roles': return renderV2Roles(state);
        case 'decisions': return renderV2Decisions(state);
        case 'runtime': return renderV2Runtime(state);
        default: return renderV2Apps(state);
    }
}
export function renderEdgeAccessV2Shell(state) {
    const active = state.route.destination;
    const isOverview = typeof window !== 'undefined' && window.location.pathname.includes('/access-config');
    const consoleMetaMap = {
        apps: {
            title: isOverview ? 'Overview' : 'Apps',
            kicker: 'Edge Access',
            subtitle: 'Service catalog, upstream routes, and per-application identity enforcement gates.'
        },
        policies: {
            title: 'Access Policies',
            kicker: 'Edge Access',
            subtitle: 'Context-aware authorization policies, RBAC claims, device posture, and session constraints.'
        },
        identity: {
            title: 'Identity',
            kicker: 'Edge Access',
            subtitle: 'Connect workforce directory identities via OIDC, SAML 2.0, Microsoft Entra ID, Okta, and Google Workspace.'
        },
        roles: {
            title: 'Roles',
            kicker: 'Edge Access',
            subtitle: 'Role definitions, claim mappings, and attribute-based access controls across connected providers.'
        },
        decisions: {
            title: 'Decisions',
            kicker: 'Edge Access',
            subtitle: 'Real-time policy evaluation stream, authorization logs, device posture passes, and session denials.'
        },
        runtime: {
            title: 'Settings',
            kicker: 'Edge Access',
            subtitle: 'Runtime token signing algorithms, session cookies, cookie domains, and engine cache limits.'
        }
    };
    const currentMeta = consoleMetaMap[active] || consoleMetaMap.apps;
    return SectionUI.renderOperatorFrame({
        title: currentMeta.title,
        kicker: currentMeta.kicker,
        subtitle: currentMeta.subtitle,
        tabs: [],
        activeTab: active,
        content: `<div class="edge-access-v2-content">${renderDestination(state)}</div>`,
        className: 'edge-access-operator-frame edge-access-v2-shell'
    });
}
