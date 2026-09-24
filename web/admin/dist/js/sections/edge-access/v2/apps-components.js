import { SectionUI } from '../../ui-components.js';
import { escapeHTML, formatDateTime, statusTone } from '../view-helpers.js';
import { renderAttachedPolicies, renderAttachedPolicySummary } from './policies-components.js';
import { renderCreateBack, renderSetupChoiceCard, renderSetupHeading } from './setup-components.js';
function action(label, name, attributes = '', primary = false, leadingIcon = '') {
    return `<button type="button" class="btn ${primary ? 'btn-primary' : 'btn-outline'}" data-edge-access-v2-action="${name}" ${attributes}>${leadingIcon ? `<span class="edge-access-v2-button-icon" aria-hidden="true">${leadingIcon}</span>` : ''}${escapeHTML(label)}</button>`;
}
function appStatus(item) {
    const state = item.protected_app.access_health.state;
    const label = { draft: 'Draft', deny_only: 'Deny-only', active: 'Active', update_available: 'Update available', disabled: 'Disabled', error: 'Error' };
    return SectionUI.renderStatusPill(label[state] || state, statusTone(state === 'deny_only' ? 'warning' : state));
}
function addresses(item) {
    const addresses = item.public_addresses;
    return addresses.length ? addresses.map(address => `<span class="edge-access-v2-route-address">${escapeHTML(address)}</span>`).join('') : '<span class="text-muted">Route unavailable</span>';
}
function accessSummary(item) {
    const { active_allow_count: activeAllow } = item.access_summary;
    const activeLabel = activeAllow === 0
        ? 'No active policy'
        : activeAllow === 1 ? '1 active policy' : `${activeAllow} active policies`;
    return `<span class="edge-access-v2-app-policy-summary">${activeLabel}</span>`;
}
function appIdentity(item) {
    return `<div class="edge-access-v2-app-identity"><span class="edge-access-v2-app-icon" aria-hidden="true">${SectionUI.icons.route}</span><span class="edge-access-v2-app-copy"><button type="button" class="btn-link edge-access-v2-app-link" data-edge-access-v2-action="app-open" data-edge-access-v2-app-id="${escapeHTML(item.protected_app.id)}">${escapeHTML(item.protected_app.name)}</button></span></div>`;
}
function loadingOrError(loading, error, retry) {
    if (loading)
        return SectionUI.renderLoading('Loading Apps...');
    if (error)
        return `<div class="section-error" role="alert"><div class="error-message">${escapeHTML(error)}</div>${action('Retry', retry)}</div>`;
    return null;
}
function renderAppList(state) {
    const resource = state.apps.catalog;
    const pending = loadingOrError(resource.loading, resource.error, 'apps-refresh');
    const filter = state.apps.filter;
    const apps = resource.value || [];
    const controls = `<form class="edge-access-v2-app-filters edge-access-v2-app-library-filters" data-edge-access-v2-app-filters="true">
    <label class="edge-access-v2-filter-search"><span class="edge-access-v2-sr-only">Search applications</span><span class="edge-access-v2-filter-search-icon" aria-hidden="true">${SectionUI.icons.search}</span><input class="input" name="q" aria-label="Search applications" placeholder="Search applications, routes, or hostnames" value="${escapeHTML(filter.q)}"></label>
    <label class="edge-access-v2-filter-status"><span class="edge-access-v2-sr-only">Filter by status</span><select class="input" name="status" aria-label="Filter applications by status"><option value="">All statuses</option>${['draft', 'deny_only', 'active', 'update_available', 'disabled', 'error'].map(value => `<option value="${value}"${filter.status === value ? ' selected' : ''}>${escapeHTML(value.replace('_', ' '))}</option>`).join('')}</select></label>
  </form>`;
    const rows = apps.map(item => {
        const app = item.protected_app;
        const appAttrs = `data-edge-access-v2-app-id="${escapeHTML(app.id)}"`;
        const rowActions = [
            { label: 'Open application', attrs: `data-edge-access-v2-action="app-open" ${appAttrs}` },
            ...(app.deployment_state !== 'disabled'
                ? [{ label: 'Manage policies', attrs: `data-edge-access-v2-action="app-manage-policies" ${appAttrs}` }]
                : []),
            { label: 'View decisions', attrs: `data-edge-access-v2-action="app-view-decisions" ${appAttrs}` },
            ...(app.deployment_state === 'draft'
                ? [{ label: 'Deploy application', attrs: `data-edge-access-v2-action="app-deploy" ${appAttrs}` }]
                : []),
            ...(app.deployment_state === 'disabled'
                ? [{ label: 'Delete application', attrs: `data-edge-access-v2-action="app-delete" ${appAttrs}`, tone: 'danger' }]
                : [{ label: 'Disable application', attrs: `data-edge-access-v2-action="app-disable" ${appAttrs}`, tone: 'danger' }])
        ];
        return [
            appIdentity(item),
            addresses(item),
            accessSummary(item),
            appStatus(item),
            `<div class="operator-control-actions edge-access-v2-library-actions">${SectionUI.renderActionMenu({
                id: `edge-access-v2-app-library-actions-${app.id}`,
                ariaLabel: `Actions for ${app.name}`,
                label: 'More',
                items: rowActions,
                className: 'edge-access-v2-table-actions'
            })}</div>`
        ];
    });
    const tableContent = pending || SectionUI.renderEnterpriseTable({
        columns: ['Application', 'Public address', 'Access', 'Status', 'Actions'],
        rows,
        className: 'edge-access-v2-catalog-table edge-access-v2-app-library-table',
        emptyTitle: 'No protected applications',
        emptyMessage: 'Create an application when a published Route is ready to receive access control.'
    });
    const metrics = pending ? '' : SectionUI.renderOperatorMetricStrip([
        { label: 'Applications', value: apps.length, sub: 'Route bindings', tone: 'neutral' },
        { label: 'Active', value: apps.filter(item => item.protected_app.access_health.state === 'active').length, sub: 'Enforcing policy', tone: 'success' },
        { label: 'Drafts', value: apps.filter(item => item.protected_app.access_health.state === 'draft').length, sub: 'Not affecting traffic', tone: 'neutral' },
        { label: 'Needs review', value: apps.filter(item => ['deny_only', 'update_available', 'error'].includes(item.protected_app.access_health.state)).length, sub: 'Review before rollout', tone: 'warning' }
    ], 'edge-access-v2-metric-strip');
    return `<div class="edge-access-v2-catalog-stack">
    ${metrics}
    ${SectionUI.renderOperatorSection('Applications', `<div class="edge-access-v2-app-library-surface">${controls}${tableContent}${pending ? '' : SectionUI.renderTableScrollHint()}</div>`, {
        subtitle: 'Each application is bound to one Route. Route addresses and origins stay managed in Routing.',
        actions: action('New app', 'app-new', '', true, SectionUI.icons.route),
        className: 'edge-access-v2-catalog-section'
    })}
  </div>`;
}
function routeOptions(state) {
    if (state.apps.routes.loading)
        return '<option>Loading Routes…</option>';
    const routes = state.apps.routes.value || [];
    if (!routes.length)
        return '<option value="">No Routes available</option>';
    return `<option value="">Select a Route</option>${routes.map(route => `<option value="${escapeHTML(route.id)}">${escapeHTML(route.name)} — ${escapeHTML(route.hosts.join(', ') || route.id)}${route.enabled ? '' : ' (disabled)'}</option>`).join('')}`;
}
function providersFor(state, type) {
    return (state.identity.providers.value || []).filter(provider => provider.type === type);
}
function providerSelect(state, type, name, label) {
    const resource = state.identity.providers;
    const providers = providersFor(state, type);
    const unavailable = resource.loading || Boolean(resource.error) || providers.length === 0;
    const emptyLabel = resource.loading
        ? 'Loading configured providers…'
        : resource.error ? 'Provider list unavailable'
            : `No ${type === 'oidc' ? 'OIDC providers' : 'JWT issuers'} configured`;
    const options = providers.length
        ? `<option value="">${escapeHTML(label)}</option>${providers.map(provider => `<option value="${escapeHTML(provider.provider_id)}">${escapeHTML(provider.name)} &middot; ${escapeHTML(provider.issuer)}</option>`).join('')}`
        : `<option value="">${escapeHTML(emptyLabel)}</option>`;
    return `<select class="input edge-access-v2-choice-select" name="${escapeHTML(name)}" aria-label="${escapeHTML(label)}"${unavailable ? ' disabled' : ''}>${options}</select>`;
}
function providerAvailability(state, type) {
    const resource = state.identity.providers;
    const providers = providersFor(state, type);
    if (resource.loading)
        return '<p class="edge-access-v2-choice-hint">Loading configured identity providers…</p>';
    if (resource.error)
        return `<p class="edge-access-v2-choice-hint">Identity providers could not be loaded. <button type="button" class="btn-link" data-edge-access-v2-action="retry-identity" data-edge-access-v2-identity-tab="providers">Retry</button></p>`;
    if (providers.length)
        return '<p class="edge-access-v2-choice-hint">Configured in Identity. You can change this later without changing the Route.</p>';
    return `<p class="edge-access-v2-choice-hint">Create a provider first in <button type="button" class="btn-link" data-edge-access-v2-action="identity-tab" data-edge-access-v2-identity-tab="providers">Identity sources</button>.</p>`;
}
function renderNewAppExperience(state) {
    const routeError = state.apps.routes.error ? `<div class="section-warning-inline">${escapeHTML(state.apps.routes.error)}</div>` : '';
    const routeSelectDisabled = state.apps.routes.loading ? ' disabled' : '';
    const content = `<form class="edge-access-v2-new-app-form" data-edge-access-v2-app-form="new">
    ${routeError}
    <section class="edge-access-v2-setup-section">
      ${renderSetupHeading('Application details', 'Use the name your team will recognize when managing access.')}
      <label class="edge-access-v2-setup-field edge-access-v2-setup-field--wide"><span>Application name</span><input class="input" name="name" required autocomplete="off" placeholder="e.g. Customer portal"></label>
    </section>

    <section class="edge-access-v2-setup-section">
      ${renderSetupHeading('Link a Route', 'Edge Access protects a Route. Hosts, origins, and runtime enablement stay owned by Routing.')}
      <div class="edge-access-v2-choice-grid edge-access-v2-route-choice-grid">
        ${renderSetupChoiceCard({ type: 'radio', name: 'route_mode', value: 'existing', checked: true, title: 'Use an existing Route', description: 'Protect a Route that already exists in Routing.', icon: SectionUI.icons.route })}
        ${renderSetupChoiceCard({ type: 'radio', name: 'route_mode', value: 'new', title: 'Create a new Route', description: 'Use this only when the Route does not exist. It creates a disabled Route through Routing.', icon: SectionUI.icons.globe })}
      </div>
      <div class="edge-access-v2-route-panel" data-edge-access-v2-route-panel="existing">
        <label class="edge-access-v2-setup-field"><span>Route to protect</span><select class="input" name="route_id"${routeSelectDisabled}>${routeOptions(state)}</select></label>
      </div>
      <div class="edge-access-v2-route-panel" data-edge-access-v2-route-panel="new" hidden>
          <div class="edge-access-v2-route-safety"><span aria-hidden="true">${SectionUI.icons.route}</span><span>Edge Access creates the Route with protection disabled. Finish deployment here, then enable the Route from Routing.</span></div>
        <div class="edge-access-v2-route-field-grid">
          <label class="edge-access-v2-setup-field"><span>Route name</span><input class="input" name="route_name" placeholder="e.g. Customer portal route"></label>
          <label class="edge-access-v2-setup-field"><span>Public hostname</span><input class="input" name="route_host" inputmode="url" placeholder="portal.example.com"></label>
          <label class="edge-access-v2-setup-field"><span>Origin</span><input class="input" name="origin_url" type="url" placeholder="https://portal.internal"></label>
        </div>
        <details class="edge-access-v2-advanced-route-options"><summary>Advanced Route options</summary><div class="edge-access-v2-route-field-grid"><label class="edge-access-v2-setup-field"><span>Base path</span><input class="input" name="route_path" value="/*"></label><label class="edge-access-v2-setup-field"><span>Priority</span><input class="input" name="route_priority" type="number" value="100"></label></div></details>
      </div>
    </section>

    <section class="edge-access-v2-setup-section edge-access-v2-trust-setup">
      ${renderSetupHeading('Choose identity sources', 'Choose how requests can prove who they are. Leave everything off for a draft if identity setup is not ready yet.')}
      <div class="edge-access-v2-source-grid">
        <div class="edge-access-v2-source-choice edge-access-v2-choice-card">
          <label class="edge-access-v2-source-toggle"><input type="checkbox" name="trust_browser"><span class="edge-access-v2-selection-mark" aria-hidden="true">${SectionUI.icons.check}</span><span class="edge-access-v2-choice-icon" aria-hidden="true">${SectionUI.icons.users}</span><span class="edge-access-v2-choice-copy"><strong>Browser sign-in</strong><span>Use a verified OIDC session for people using a browser.</span></span></label>
          <div class="edge-access-v2-source-configuration" data-edge-access-v2-trust-panel="browser" hidden><label class="edge-access-v2-setup-field"><span>OIDC provider</span>${providerSelect(state, 'oidc', 'oidc_provider_id', 'Select an OIDC provider')}</label>${providerAvailability(state, 'oidc')}</div>
        </div>
        <div class="edge-access-v2-source-choice edge-access-v2-choice-card">
          <label class="edge-access-v2-source-toggle"><input type="checkbox" name="trust_jwt"><span class="edge-access-v2-selection-mark" aria-hidden="true">${SectionUI.icons.check}</span><span class="edge-access-v2-choice-icon" aria-hidden="true">${SectionUI.icons.key}</span><span class="edge-access-v2-choice-copy"><strong>Bearer token</strong><span>Accept JWTs from a configured issuer for API clients.</span></span></label>
          <div class="edge-access-v2-source-configuration" data-edge-access-v2-trust-panel="jwt" hidden><label class="edge-access-v2-setup-field"><span>JWT issuer</span>${providerSelect(state, 'jwt', 'jwt_provider_id', 'Select a JWT issuer')}</label>${providerAvailability(state, 'jwt')}</div>
        </div>
        <label class="edge-access-v2-source-choice edge-access-v2-choice-card edge-access-v2-source-choice--simple"><span class="edge-access-v2-source-toggle"><input type="checkbox" name="api_key"><span class="edge-access-v2-selection-mark" aria-hidden="true">${SectionUI.icons.check}</span><span class="edge-access-v2-choice-icon" aria-hidden="true">${SectionUI.icons.key}</span><span class="edge-access-v2-choice-copy"><strong>API key</strong><span>Allow approved service identities that authenticate with an API key.</span></span></span></label>
        <label class="edge-access-v2-source-choice edge-access-v2-choice-card edge-access-v2-source-choice--simple"><span class="edge-access-v2-source-toggle"><input type="checkbox" name="mtls"><span class="edge-access-v2-selection-mark" aria-hidden="true">${SectionUI.icons.check}</span><span class="edge-access-v2-choice-icon" aria-hidden="true">${SectionUI.icons.shieldCheck}</span><span class="edge-access-v2-choice-copy"><strong>mTLS certificate</strong><span>Allow approved service identities that authenticate with a client certificate.</span></span></span></label>
      </div>
    </section>

    <footer class="edge-access-v2-create-actions"><div class="operator-control-actions">${action('Save draft', 'app-save-draft', '', true)}${action('Review and deploy', 'app-save-and-deploy')}</div></footer>
  </form>`;
    const form = SectionUI.renderOperatorSection('Create application', content, {
        subtitle: 'Build the application around a Route first; access policy configuration comes after the draft is saved.',
        className: 'edge-access-v2-new-app-section'
    });
    return `<div class="edge-access-v2-create-shell edge-access-v2-new-app-shell">
    ${renderCreateBack('Apps', 'Back to applications', 'apps-back')}
    ${form}
  </div>`;
}
function renderOverview(state, item, decisions) {
    const app = item.protected_app;
    const route = app.route;
    const routeContext = route ? `
    <div class="edge-access-v2-route-overview">
      <div class="edge-access-v2-route-identity">
        <span class="edge-access-v2-overview-icon" aria-hidden="true">${SectionUI.icons.route}</span>
        <div>
          <span class="edge-access-v2-overview-eyebrow">Canonical Route</span>
          <strong>${escapeHTML(route.name || route.id)}</strong>
        </div>
      </div>
      <dl class="edge-access-v2-route-facts">
        <div>
          <dt>Public address</dt>
          <dd class="text-mono">${addresses(item)}</dd>
        </div>
        <div>
          <dt>Origin</dt>
          <dd class="text-mono">${escapeHTML(route.origin_url || 'Not exposed')}</dd>
        </div>
        <div>
          <dt>Routing status</dt>
          <dd>${SectionUI.renderStatusPill(route.enabled ? 'Enabled' : 'Disabled', route.enabled ? 'success' : 'neutral')}</dd>
        </div>
      </dl>
    </div>
  ` : `<div class="edge-access-v2-overview-message">${SectionUI.icons.alertTriangle}<div><strong>Route unavailable</strong><span>The canonical Route could not be loaded from Routing.</span></div></div>`;
    const decisionRows = (decisions || []).map(decision => [formatDateTime(decision.timestamp), escapeHTML(decision.method || '—'), `<span class="text-mono">${escapeHTML(decision.path || '—')}</span>`, escapeHTML(decision.result), escapeHTML(decision.reason_code || '—')]);
    const decisionsTable = SectionUI.renderEnterpriseTable({ columns: ['Time', 'Method', 'Path', 'Result', 'Reason'], rows: decisionRows, emptyTitle: 'No recent decisions', emptyMessage: 'The first five decisions for this App appear here when traffic is evaluated.' });
    const routeSection = SectionUI.renderOperatorSection('Routing', routeContext, {
        subtitle: 'Public exposure and origin are managed by Routing.',
        className: 'edge-access-v2-overview-card edge-access-v2-route-card'
    });
    const decisionsSection = decisionRows.length
        ? SectionUI.renderOperatorSection('Recent decisions', decisionsTable, {
            subtitle: 'Latest evaluated requests for this application.',
            className: 'edge-access-v2-overview-card edge-access-v2-decisions-section'
        })
        : '';
    return `
    <div class="edge-access-v2-app-overview">
      ${routeSection}
      ${renderAttachedPolicySummary(state)}
      ${decisionsSection}
    </div>
  `;
}
function renderPolicyAttachmentsWorkspace(state, item) {
    const app = item.protected_app;
    const appAttrs = `data-edge-access-v2-app-id="${escapeHTML(app.id)}"`;
    return SectionUI.renderResourceWorkspace({
        title: 'Manage policy attachments',
        breadcrumbLabel: escapeHTML(app.name),
        breadcrumbCurrent: 'Policy attachments',
        breadcrumbAttrs: `data-edge-access-v2-action="app-overview" ${appAttrs}`,
        metadata: 'Attach reusable policies and review how they apply to this application.',
        actions: action('Attach policy', 'policy-add-menu', `data-edge-access-v2-policy-app-id="${escapeHTML(app.id)}"`, true, SectionUI.icons.fileText),
        content: renderAttachedPolicies(state),
        className: 'edge-access-v2-app-workspace edge-access-v2-policy-attachments-workspace'
    });
}
function renderDetail(state, item) {
    if (state.route.appSubpage === 'access-policies')
        return renderPolicyAttachmentsWorkspace(state, item);
    const app = item.protected_app;
    const appAttrs = `data-edge-access-v2-app-id="${escapeHTML(app.id)}"`;
    const rollback = app.deployment_state === 'deployed' && item.access_summary.active_deployment_id
        ? action('Rollback deployment', 'app-rollback', `${appAttrs} data-edge-access-v2-deployment-id="${escapeHTML(item.access_summary.active_deployment_id)}"`)
        : '';
    const lifecycleMenu = SectionUI.renderActionMenu({
        id: `edge-access-v2-app-actions-${app.id}`,
        label: 'More',
        ariaLabel: `More actions for ${app.name}`,
        items: app.deployment_state === 'disabled'
            ? [{ label: 'Delete application', attrs: `data-edge-access-v2-action="app-delete" ${appAttrs}`, tone: 'danger' }]
            : [{ label: 'Disable application', attrs: `data-edge-access-v2-action="app-disable" ${appAttrs}`, tone: 'danger' }]
    });
    const deployAction = app.deployment_state === 'draft' ? action('Deploy', 'app-deploy', appAttrs, true) : '';
    const headerActions = `${action('View decisions', 'app-view-decisions', appAttrs)}${rollback}${lifecycleMenu}${deployAction}`;
    return SectionUI.renderResourceWorkspace({
        title: '',
        breadcrumbLabel: 'Apps',
        breadcrumbCurrent: escapeHTML(app.name),
        breadcrumbAttrs: 'data-edge-access-v2-action="apps-back"',
        actions: headerActions,
        content: renderOverview(state, item, state.apps.decisions.value),
        className: 'edge-access-v2-app-workspace edge-access-v2-app-workspace--compact-header'
    });
}
export function renderV2Apps(state) {
    if (state.route.creatingApp)
        return renderNewAppExperience(state);
    if (state.route.appID) {
        const resource = state.apps.detail;
        const pending = loadingOrError(resource.loading, resource.error, 'app-detail-retry');
        if (pending) {
            const managingPolicies = state.route.appSubpage === 'access-policies';
            return SectionUI.renderResourceWorkspace({
                title: managingPolicies ? 'Manage policy attachments' : 'Application',
                breadcrumbLabel: managingPolicies ? 'Application' : 'Apps',
                breadcrumbCurrent: managingPolicies ? 'Policy attachments' : escapeHTML(state.route.appID),
                breadcrumbAttrs: managingPolicies
                    ? `data-edge-access-v2-action="app-overview" data-edge-access-v2-app-id="${escapeHTML(state.route.appID)}"`
                    : 'data-edge-access-v2-action="apps-back"',
                metadata: 'Loading application details…',
                content: pending,
                className: 'edge-access-v2-app-workspace edge-access-v2-app-workspace--pending'
            });
        }
        if (resource.value)
            return renderDetail(state, resource.value);
        return SectionUI.renderResourceWorkspace({
            title: 'Application unavailable',
            breadcrumbLabel: 'Apps',
            breadcrumbCurrent: escapeHTML(state.route.appID),
            breadcrumbAttrs: 'data-edge-access-v2-action="apps-back"',
            metadata: 'This application could not be loaded.',
            content: SectionUI.renderEmptyState('Application unavailable', 'It may have been deleted or you may not have permission to view it.', 'shield'),
            className: 'edge-access-v2-app-workspace edge-access-v2-app-workspace--error'
        });
    }
    return renderAppList(state);
}
