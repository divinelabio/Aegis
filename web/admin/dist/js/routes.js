/**
 * Route management page
 * Source of truth: web/admin/src/routes.ts
 * Runtime output: web/admin/dist/js/routes.js
 */
import { api } from './api.js';
import { FEATURES } from './core/features.js';
import * as AdminDOM from './core/dom.js';
import * as AdminEvents from './core/events.js';
import { SectionUI } from './sections/ui-components.js';
import { notify } from './core/notify.js';
import { AccessControlConfigFacade } from './sections/access-config.js';
import { loadAppsForRouting } from './sections/edge-access/v2/apps-contract.js';
function escapeHTML(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
const routesState = {
    routesData: [],
    protectedApps: [],
    protectedAppsByRoute: new Map(),
    protectedAppsAvailable: true,
    originGroups: [],
    editingRoute: null,
    eventsBound: false
};
export async function loadRoutesTable() {
    bindRoutesEvents();
    const container = AdminDOM.getById('routes-container');
    if (!container)
        return;
    container.innerHTML = '<div class="text-center p-40 text-note">Loading routes...</div>';
    try {
        const hasAccessControl = api.hasFeature(FEATURES.ACCESS_CONTROL);
        let protectedAppsAvailable = hasAccessControl;
        const [data, protectedApps, originGroups] = await Promise.all([
            api.get('routes'),
            hasAccessControl
                ? loadAppsForRouting().catch(error => {
                    console.warn('Failed to load Edge Access Protected Apps for Routing', error);
                    protectedAppsAvailable = false;
                    return [];
                })
                : Promise.resolve([]),
            api.get('upstreams').catch(error => {
                console.warn('Failed to load Origins for Routing', error);
                return [];
            })
        ]);
        if (!data) {
            container.innerHTML = '<div class="p-20 text-danger">Routes could not be loaded. Check the admin API and try again.</div>';
            return;
        }
        routesState.routesData = Array.isArray(data) ? data : (data.routes || []);
        routesState.protectedApps = protectedApps;
        routesState.protectedAppsByRoute = new Map(protectedApps.map(app => [app.route_id, app]));
        routesState.protectedAppsAvailable = protectedAppsAvailable;
        routesState.originGroups = Array.isArray(originGroups) ? originGroups : [];
        renderRoutesTable(container);
    }
    catch (error) {
        console.error(error);
        container.innerHTML = '<div class="p-20 text-danger">Failed to load routes</div>';
    }
}
function routeHosts(route) {
    return route.match?.hosts?.length ? route.match.hosts : (route.hosts || []);
}
function routePaths(route) {
    return route.match?.paths?.length ? route.match.paths : (route.paths || []);
}
function routeBackends(route) {
    return route.action?.backends?.length ? route.action.backends : (route.backends || []);
}
function routeForWrite(route) {
    if (!route)
        return {};
    return {
        id: route.id,
        name: route.name,
        priority: route.priority,
        match: route.match,
        action: route.action,
        enabled: route.enabled,
        security: route.security
    };
}
function routeStripPrefix(route) {
    return route.action?.strip_prefix || route.strip_prefix || '';
}
const inlineStrategies = new Set(['round_robin', 'weighted_rr', 'least_conn', 'ip_hash']);
function routeInlineStrategy(route) {
    if (!route)
        return 'round_robin';
    if (route.action?.strategy && inlineStrategies.has(route.action.strategy))
        return route.action.strategy;
    if (route.load_balance && inlineStrategies.has(route.load_balance))
        return route.load_balance;
    if (route.action?.upstream && inlineStrategies.has(route.action.upstream) && routeBackends(route).length > 0) {
        return route.action.upstream;
    }
    return 'round_robin';
}
function routeNamedUpstream(route) {
    const upstream = route?.action?.upstream || '';
    return inlineStrategies.has(upstream) ? '' : upstream;
}
function formatMatcherMap(value) {
    return value && Object.keys(value).length > 0 ? JSON.stringify(value, null, 2) : '';
}
function routeDeliveryMode(route) {
    if (routeNamedUpstream(route))
        return 'origin';
    if (route && routeBackends(route).length > 0)
        return 'inline';
    return route ? 'default' : (routesState.originGroups.length > 0 ? 'origin' : 'inline');
}
function renderOriginOptions(selectedOrigin) {
    const knownOrigins = routesState.originGroups.map(origin => origin.name);
    const options = [`<option value="">Choose an Origin</option>`];
    if (selectedOrigin && !knownOrigins.includes(selectedOrigin)) {
        options.push(`<option value="${escapeHTML(selectedOrigin)}" selected>${escapeHTML(selectedOrigin)}</option>`);
    }
    options.push(...knownOrigins.map(name => `<option value="${escapeHTML(name)}"${name === selectedOrigin ? ' selected' : ''}>${escapeHTML(name)}</option>`));
    return options.join('');
}
function routeProtectedApp(route) {
    if (!route.id)
        return null;
    return routesState.protectedAppsByRoute.get(route.id) || null;
}
function routeAccessInfo(route) {
    const app = routeProtectedApp(route);
    const accessFlag = route.security?.access_control;
    if (!routesState.protectedAppsAvailable) {
        return {
            label: 'Unknown',
            tone: 'warning',
            app: null,
            description: 'Access protection status is temporarily unavailable.'
        };
    }
    if (app) {
        if (app.access_health.state === 'error' || !app.route) {
            return {
                label: 'Misconfigured',
                tone: 'danger',
                app,
                description: app.access_health.reason_codes.join(', ') || 'Protected App references a Route that Routing cannot resolve.'
            };
        }
        if (!app.enabled || app.deployment_state !== 'deployed' || route.enabled === false || accessFlag === false) {
            return {
                label: 'Disabled',
                tone: 'warning',
                app,
                description: 'Protected App exists, but route or access enforcement is disabled.'
            };
        }
        if (accessFlag === true || ['active', 'deny_only', 'update_available'].includes(app.access_health.state)) {
            return {
                label: 'Protected',
                tone: 'primary',
                app,
                description: `${app.name} enforces its deployed access policies.`
            };
        }
        return {
            label: 'Misconfigured',
            tone: 'danger',
            app,
            description: 'Protected App exists, but route access enforcement is not enabled.'
        };
    }
    if (accessFlag === true) {
        return {
            label: 'Misconfigured',
            tone: 'danger',
            app: null,
            description: 'Route has access enforcement enabled without a Protected App.'
        };
    }
    return {
        label: 'Public',
        tone: 'neutral',
        app: null,
        description: 'No Protected App is linked to this route.'
    };
}
function renderRoutingEnterpriseRows() {
    const hasAccessControl = api.hasFeature(FEATURES.ACCESS_CONTROL);
    return routesState.routesData.map((route, index) => {
        const access = routeAccessInfo(route);
        const routeID = escapeHTML(route.id || '');
        const menuID = `routing-route-actions-${encodeURIComponent(route.id || route.name || String(index))}`;
        const isEnabled = route.enabled !== false;
        const items = [
            ...(hasAccessControl ? [{ label: access.app ? 'Open App' : 'Protect', attrs: `data-action="routes-protect-access" data-route-id="${routeID}"` }] : []),
            { label: isEnabled ? 'Disable route' : 'Enable route', attrs: `data-action="routes-toggle" data-route-id="${routeID}"` },
            { label: 'Edit route', attrs: `data-action="routes-edit" data-route-id="${routeID}"` },
            { label: 'Delete route', attrs: `data-action="routes-delete" data-route-id="${routeID}"`, tone: 'danger' }
        ];
        const actions = SectionUI.renderActionMenu({
            id: menuID,
            label: 'More',
            ariaLabel: `Actions for ${route.name || 'route'}`,
            items,
            className: 'routing-row-menu'
        });
        const backends = routeBackends(route);
        const paths = routePaths(route);
        return [
            `<div class="routing-route-main">
        <span class="routing-route-icon" aria-hidden="true">${routeIcon('route')}</span>
        <span class="routing-route-copy">
          <strong>${escapeHTML(route.name || 'Unnamed route')}</strong>
          <small>${escapeHTML(routeHosts(route).join(', ') || 'All hosts')}</small>
        </span>
      </div>`,
            `<div class="routing-chip-row">
        ${(paths.length ? paths : ['/*']).map(path => `<span class="routing-path-chip">${escapeHTML(path)}</span>`).join('')}
      </div>`,
            backends.length
                ? `<div class="routing-backend-list">${backends.map(backend => `<span class="routing-backend-url" title="${escapeHTML(backend.url)}">${escapeHTML(backend.url)}</span>`).join('')}</div>`
                : route.action?.upstream
                    ? `<span class="routing-backend-url">Origin: ${escapeHTML(route.action.upstream)}</span>`
                    : '<span class="routing-empty-value">No target configured</span>',
            SectionUI.renderStatusPill(escapeHTML(route.action?.upstream || route.action?.strategy || route.load_balance || 'Inline'), 'neutral'),
            ...(hasAccessControl ? [SectionUI.renderStatusPill(access.label, access.tone)] : []),
            `<button type="button" class="routing-status-toggle-btn" data-action="routes-toggle" data-route-id="${routeID}" aria-label="${isEnabled ? 'Disable route' : 'Enable route'}" title="${isEnabled ? 'Click to disable route' : 'Click to enable route'}">
        ${SectionUI.renderStatusPill(isEnabled ? 'Enabled' : 'Disabled', isEnabled ? 'success' : 'neutral')}
      </button>`,
            `<div class="operator-control-actions routing-row-actions">${actions}</div>`
        ];
    });
}
function renderRoutesTable(container) {
    const hasAccessControl = api.hasFeature(FEATURES.ACCESS_CONTROL);
    const columns = ['Route', 'Path patterns', 'Backends', 'Origin policy', ...(hasAccessControl ? ['Access'] : []), 'Status', 'Actions'];
    const content = `
    <div class="routing-operator-stack">
      ${SectionUI.renderOperatorSection('Route rules', `
        <div class="routing-table-surface">${SectionUI.renderEnterpriseTable({
        columns,
        rows: renderRoutingEnterpriseRows(),
        className: 'routing-rule-table',
        emptyTitle: 'No routes configured',
        emptyMessage: 'Add a route to match traffic and send it to an origin.'
    })}</div>
      `, {
        subtitle: 'Hosts, path patterns, origin targets, and runtime state in priority order.',
        className: 'routing-catalog-section'
    })}
    </div>
  `;
    container.innerHTML = `
        ${SectionUI.renderOperatorFrame({
        title: 'Routing',
        kicker: 'Network',
        subtitle: 'Send matching hosts and paths to the right origin. Routes are evaluated in priority order.',
        actions: `<button type="button" class="btn btn-primary" data-action="routes-open-editor">${routeIcon('add')}Add Route</button>`,
        content,
        className: 'routing-operator-frame'
    })}
    `;
}
function renderRouteEditor(container, route = null) {
    routesState.editingRoute = route;
    const isEditing = Boolean(route?.id);
    const routeTitle = isEditing ? (route?.name || 'Edit route') : 'Add route';
    const saveLabel = isEditing ? 'Save Changes' : 'Create route';
    const hosts = route ? routeHosts(route).join(', ') : '';
    const paths = route ? routePaths(route).join(', ') : '';
    const backends = route
        ? routeBackends(route).map(backend => `${backend.url},${backend.weight || 1}`).join('\n')
        : '';
    const loadBalance = routeInlineStrategy(route);
    const namedUpstream = routeNamedUpstream(route);
    const methods = route?.match?.methods?.join(', ') || '';
    const sourceCIDRs = route?.match?.source_cidrs?.join(', ') || '';
    const headerMatchers = formatMatcherMap(route?.match?.headers);
    const queryMatchers = formatMatcherMap(route?.match?.query);
    const stripPrefix = route ? routeStripPrefix(route) : '';
    const rewritePath = route?.action?.rewrite_path || '';
    const timeout = route?.action?.timeout || '';
    const retries = route?.action?.retries ?? 0;
    const preserveHost = route?.action?.preserve_host ?? true;
    const deliveryMode = routeDeliveryMode(route);
    const pathTransform = rewritePath ? 'rewrite' : stripPrefix ? 'strip' : 'keep';
    const hasAdvancedDelivery = Boolean(pathTransform !== 'keep' || timeout || retries > 0 || !preserveHost);
    const hasAdvancedSettings = Boolean(methods || sourceCIDRs || headerMatchers || queryMatchers ||
        hasAdvancedDelivery || (route?.priority !== undefined && route.priority !== 100) ||
        (deliveryMode === 'origin' && backends));
    const hasAccessControl = api.hasFeature(FEATURES.ACCESS_CONTROL);
    const accessContext = (route && hasAccessControl) ? renderRouteAccessContext(route) : '';
    const selected = (value) => loadBalance === value ? ' selected' : '';
    const saveIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><path d="M17 21v-8H7v8"/><path d="M7 3v5h8"/></svg>';
    const content = `
      <form id="route-form" class="route-create-form">
        <input type="hidden" id="route-id" value="${escapeHTML(route?.id || '')}">

        <section class="route-create-setup-section" aria-labelledby="route-create-details-title">
          <div class="route-create-setup-heading">
            <h3 id="route-create-details-title">Route details</h3>
          </div>
          <div class="route-create-field-grid route-create-basics-grid">
            <div class="settings-field">
              <label for="route-name">Route name <span class="route-create-required">Required</span></label>
              <input type="text" id="route-name" required class="input" value="${escapeHTML(route?.name || '')}" placeholder="API backend" autocomplete="off">
            </div>
            <label class="route-create-toggle-row route-create-enable-control">
              <span>Enable route</span>
              <span class="checkbox-toggle route-enabled-switch switch">
                <input type="checkbox" id="route-enabled" ${route?.enabled !== false ? 'checked' : ''}>
                <span class="switch-slider"></span>
              </span>
            </label>
          </div>
        </section>

        <section class="route-create-setup-section" aria-labelledby="route-create-matching-title">
          <div class="route-create-setup-heading">
            <h3 id="route-create-matching-title">Traffic matching</h3>
          </div>
          <div class="route-create-field-grid route-create-field-grid--two">
            <div class="settings-field">
              <label for="route-hosts">Hosts</label>
              <input type="text" id="route-hosts" class="input" value="${escapeHTML(hosts)}" placeholder="example.com, *.example.com" autocomplete="off">
            </div>
            <div class="settings-field">
              <label for="route-paths">Path patterns</label>
              <input type="text" id="route-paths" class="input" value="${escapeHTML(paths)}" placeholder="/api/*, /v1/*" autocomplete="off">
            </div>
          </div>
        </section>

        <section class="route-create-setup-section" aria-labelledby="route-create-delivery-title">
          <div class="route-create-setup-heading">
            <h3 id="route-create-delivery-title">Destination</h3>
          </div>
          <div class="route-create-field-grid route-create-field-grid--two">
            <div class="settings-field">
              <label for="route-delivery-mode">Delivery target</label>
              <select id="route-delivery-mode" class="input">
                <option value="origin"${deliveryMode === 'origin' ? ' selected' : ''}>Named Origin</option>
                <option value="inline"${deliveryMode === 'inline' ? ' selected' : ''}>Inline backend</option>
                <option value="default"${deliveryMode === 'default' ? ' selected' : ''}>Default proxy target</option>
              </select>
            </div>
            <div id="route-origin-delivery" class="settings-field"${deliveryMode === 'origin' ? '' : ' hidden'}>
              <label for="route-upstream">Origin</label>
              <select id="route-upstream" class="input">${renderOriginOptions(namedUpstream)}</select>
            </div>
            <p id="route-default-delivery" class="route-create-default-target"${deliveryMode === 'default' ? '' : ' hidden'}>Uses the configured default proxy target.</p>
          </div>
          <div id="route-inline-delivery" class="route-create-inline-delivery"${deliveryMode === 'inline' ? '' : ' hidden'}>
            <div class="route-create-field-grid route-create-field-grid--two">
              <div class="settings-field">
                <label for="route-backends">Backend targets</label>
                <textarea id="route-backends" rows="4" class="input text-mono text-small" placeholder="http://localhost:8080&#10;http://localhost:8081,2">${escapeHTML(backends)}</textarea>
                <span class="settings-hint">One URL per line. Add a weight only when needed.</span>
              </div>
              <div class="settings-field">
                <label for="route-lb">Inline strategy</label>
                <select id="route-lb" class="input">
                  <option value="round_robin"${selected('round_robin')}>Round robin</option>
                  <option value="weighted_rr"${selected('weighted_rr')}>Weighted round robin</option>
                  <option value="least_conn"${selected('least_conn')}>Least connections</option>
                  <option value="ip_hash"${selected('ip_hash')}>IP hash</option>
                </select>
              </div>
            </div>
          </div>
        </section>

        <details id="route-advanced-settings" class="route-create-advanced route-create-advanced-settings" ${hasAdvancedSettings ? 'open' : ''}>
          <summary><span>Advanced settings</span></summary>
          <div class="route-create-advanced-body route-create-advanced-settings-body">
            <section class="route-create-advanced-group" aria-labelledby="route-advanced-matching-title">
              <h4 id="route-advanced-matching-title">Matching rules</h4>
              <div class="route-create-field-grid route-create-field-grid--two">
                <div class="settings-field">
                  <label for="route-methods">HTTP methods</label>
                  <input type="text" id="route-methods" class="input" value="${escapeHTML(methods)}" placeholder="GET, POST" autocomplete="off">
                </div>
                <div class="settings-field">
                  <label for="route-source-cidrs">Source IPs / CIDRs</label>
                  <input type="text" id="route-source-cidrs" class="input" value="${escapeHTML(sourceCIDRs)}" placeholder="10.0.0.0/8, 203.0.113.8" autocomplete="off">
                </div>
                <div class="settings-field">
                  <label for="route-headers">Header matchers</label>
                  <textarea id="route-headers" rows="4" class="input text-mono text-small" placeholder='{"X-Environment":["production"]}'>${escapeHTML(headerMatchers)}</textarea>
                </div>
                <div class="settings-field">
                  <label for="route-query">Query matchers</label>
                  <textarea id="route-query" rows="4" class="input text-mono text-small" placeholder='{"tenant":["primary"]}'>${escapeHTML(queryMatchers)}</textarea>
                </div>
              </div>
            </section>

            <details id="route-fallback-delivery" class="route-create-advanced-group route-create-subdisclosure"${deliveryMode === 'origin' ? '' : ' hidden'}${backends ? ' open' : ''}>
              <summary>Fallback backend</summary>
              <div class="route-create-field-grid route-create-field-grid--two">
                <div class="settings-field">
                  <label for="route-fallback-backends">Backend targets</label>
                  <textarea id="route-fallback-backends" rows="4" class="input text-mono text-small" placeholder="http://localhost:8080&#10;http://localhost:8081,2">${escapeHTML(backends)}</textarea>
                  <span class="settings-hint">Used only when the selected Origin has no available target.</span>
                </div>
                <div class="settings-field">
                  <label for="route-fallback-lb">Fallback strategy</label>
                  <select id="route-fallback-lb" class="input">
                    <option value="round_robin"${selected('round_robin')}>Round robin</option>
                    <option value="weighted_rr"${selected('weighted_rr')}>Weighted round robin</option>
                    <option value="least_conn"${selected('least_conn')}>Least connections</option>
                    <option value="ip_hash"${selected('ip_hash')}>IP hash</option>
                  </select>
                </div>
              </div>
            </details>

            <section class="route-create-advanced-group" aria-labelledby="route-advanced-delivery-title">
              <h4 id="route-advanced-delivery-title">Delivery behavior</h4>
              <div class="route-create-field-grid route-create-field-grid--two">
                <div class="settings-field">
                  <label for="route-path-transform">Path handling</label>
                  <select id="route-path-transform" class="input">
                    <option value="keep"${pathTransform === 'keep' ? ' selected' : ''}>Keep the incoming path</option>
                    <option value="strip"${pathTransform === 'strip' ? ' selected' : ''}>Strip a prefix</option>
                    <option value="rewrite"${pathTransform === 'rewrite' ? ' selected' : ''}>Replace the path</option>
                  </select>
                </div>
                <div id="route-strip-field" class="settings-field"${pathTransform === 'strip' ? '' : ' hidden'}>
                  <label for="route-strip">Prefix to strip</label>
                  <input type="text" id="route-strip" class="input" value="${escapeHTML(stripPrefix)}" placeholder="/api" autocomplete="off">
                </div>
                <div id="route-rewrite-field" class="settings-field"${pathTransform === 'rewrite' ? '' : ' hidden'}>
                  <label for="route-rewrite">Replacement path</label>
                  <input type="text" id="route-rewrite" class="input" value="${escapeHTML(rewritePath)}" placeholder="/internal/v1" autocomplete="off">
                </div>
                <div class="settings-field">
                  <label for="route-timeout">Route timeout</label>
                  <input type="text" id="route-timeout" class="input" value="${escapeHTML(timeout)}" placeholder="15s" autocomplete="off">
                  <span class="settings-hint">Leave blank to use the global timeout.</span>
                </div>
                <div class="settings-field">
                  <label for="route-retries">Retries</label>
                  <input type="number" id="route-retries" class="input" value="${escapeHTML(retries)}" min="0" max="5">
                </div>
              </div>
              <label class="route-create-toggle-row">
                <span>Preserve incoming Host</span>
                <span class="checkbox-toggle route-enabled-switch switch">
                  <input type="checkbox" id="route-preserve-host" ${preserveHost ? 'checked' : ''}>
                  <span class="switch-slider"></span>
                </span>
              </label>
            </section>

            <section class="route-create-advanced-group route-create-advanced-group--compact" aria-labelledby="route-advanced-route-title">
              <h4 id="route-advanced-route-title">Route priority</h4>
              <div class="route-create-field-grid route-create-field-grid--compact">
                <div class="settings-field">
                  <label for="route-priority">Priority</label>
                  <input type="number" id="route-priority" value="${escapeHTML(route?.priority ?? 100)}" min="1" max="10000" class="input">
                  <span class="settings-hint">Lower numbers are evaluated first.</span>
                </div>
              </div>
            </section>
          </div>
        </details>

        ${route && hasAccessControl ? `
          <section class="route-create-setup-section" aria-labelledby="route-create-access-title">
            <div class="route-create-setup-heading">
              <div>
                <h3 id="route-create-access-title">Edge Access</h3>
                <p>Protection attached to this route.</p>
              </div>
            </div>
            <div id="route-access-context" class="routing-edge-context">
              ${accessContext}
            </div>
          </section>
        ` : ''}

        <footer class="route-create-actions">
          <div class="operator-control-actions">
            <button type="submit" class="btn btn-primary">${saveIcon}${saveLabel}</button>
          </div>
        </footer>
      </form>
    `;
    container.innerHTML = SectionUI.renderOperatorFrame({
        title: 'Routing',
        kicker: 'Network',
        content: `
        <div class="routing-editor-create-shell">
          ${SectionUI.renderOperatorBackButton({
            label: 'Back to Routes',
            ariaLabel: 'Back to Routes',
            attrs: 'data-action="routes-close-editor"'
        })}
          ${SectionUI.renderOperatorSection(routeTitle, content, { className: 'routing-editor-create-section' })}
        </div>
      `,
        className: 'routing-operator-frame routing-editor-operator-frame'
    });
    syncRouteEditorControls();
    window.requestAnimationFrame(() => AdminDOM.getInput('route-name')?.focus());
}
function syncRouteEditorControls() {
    const deliveryMode = AdminDOM.selectValue('route-delivery-mode', 'origin');
    const originDelivery = document.getElementById('route-origin-delivery');
    const defaultDelivery = document.getElementById('route-default-delivery');
    const inlineDelivery = document.getElementById('route-inline-delivery');
    const fallbackDelivery = document.getElementById('route-fallback-delivery');
    if (originDelivery)
        originDelivery.hidden = deliveryMode !== 'origin';
    if (defaultDelivery)
        defaultDelivery.hidden = deliveryMode !== 'default';
    if (inlineDelivery)
        inlineDelivery.hidden = deliveryMode !== 'inline';
    if (fallbackDelivery)
        fallbackDelivery.hidden = deliveryMode !== 'origin';
    const pathTransform = AdminDOM.selectValue('route-path-transform', 'keep');
    const stripField = document.getElementById('route-strip-field');
    const rewriteField = document.getElementById('route-rewrite-field');
    if (stripField)
        stripField.hidden = pathTransform !== 'strip';
    if (rewriteField)
        rewriteField.hidden = pathTransform !== 'rewrite';
}
function routeIcon(name) {
    if (name === 'add') {
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14"/><path d="M5 12h14"/></svg>';
    }
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><path d="M8 6h5a3 3 0 0 1 3 3v7"/><path d="M6 8v8a2 2 0 0 0 2 2h8"/></svg>';
}
function bindRoutesEvents() {
    if (routesState.eventsBound)
        return;
    routesState.eventsBound = true;
    AdminEvents.delegateEvent(document, 'click', '#routes-container [data-action="routes-open-editor"]', event => {
        event.preventDefault();
        const container = AdminDOM.getById('routes-container');
        if (container)
            renderRouteEditor(container);
    });
    AdminEvents.delegateEvent(document, 'click', '#routes-container [data-action="routes-edit"]', (event, target) => {
        event.preventDefault();
        const routeId = target.dataset.routeId;
        if (routeId)
            editRoute(routeId);
    });
    AdminEvents.delegateEvent(document, 'click', '#routes-container [data-action="routes-delete"]', (event, target) => {
        event.preventDefault();
        const routeId = target.dataset.routeId;
        if (routeId)
            void deleteRoute(routeId);
    });
    AdminEvents.delegateEvent(document, 'click', '#routes-container [data-action="routes-protect-access"]', (event, target) => {
        event.preventDefault();
        if (!api.hasFeature(FEATURES.ACCESS_CONTROL))
            return;
        const routeId = target.dataset.routeId;
        if (routeId)
            void openEdgeAccessForRoute(routeId);
    });
    AdminEvents.delegateEvent(document, 'click', '#routes-container [data-action="routes-close-editor"]', event => {
        event.preventDefault();
        closeRouteEditor();
    });
    AdminEvents.delegateEvent(document, 'click', '#routes-container [data-action="routes-toggle"]', (event, target) => {
        event.preventDefault();
        const routeId = target.dataset.routeId;
        if (!routeId)
            return;
        const route = routesState.routesData.find(item => item.id === routeId);
        if (!route)
            return;
        void toggleRoute(routeId, route.enabled === false);
    });
    AdminEvents.delegateEvent(document, 'change', '#routes-container #route-delivery-mode, #routes-container #route-path-transform', () => {
        syncRouteEditorControls();
    });
    AdminEvents.delegateEvent(document, 'submit', '#routes-container #route-form', event => {
        void saveRoute(event);
    });
}
function closeRouteEditor() {
    routesState.editingRoute = null;
    const container = AdminDOM.getById('routes-container');
    if (container)
        renderRoutesTable(container);
}
function editRoute(id) {
    const route = routesState.routesData.find(routeItem => routeItem.id === id);
    const container = AdminDOM.getById('routes-container');
    if (route && container)
        renderRouteEditor(container, route);
}
function commaValues(value) {
    return value.split(',').map(item => item.trim()).filter(Boolean);
}
function parseMatcherMap(value, label) {
    if (!value.trim())
        return {};
    const parsed = JSON.parse(value);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
        throw new Error(`${label} must be a JSON object.`);
    }
    const normalized = {};
    for (const [name, allowed] of Object.entries(parsed)) {
        if (!Array.isArray(allowed) || !allowed.every(item => typeof item === 'string')) {
            throw new Error(`${label}.${name} must be an array of strings.`);
        }
        normalized[name] = allowed;
    }
    return normalized;
}
function parseRouteBackends(value) {
    return value
        .split('\n')
        .map(line => line.trim())
        .filter(Boolean)
        .map((line, index) => {
        const separator = line.lastIndexOf(',');
        const url = (separator >= 0 ? line.slice(0, separator) : line).trim();
        const weightText = separator >= 0 ? line.slice(separator + 1).trim() : '1';
        const weight = Number.parseInt(weightText, 10);
        if (!url || !Number.isInteger(weight) || weight < 1 || weight > 1000) {
            throw new Error(`Backend line ${index + 1} must use URL,weight with a weight from 1 to 1000.`);
        }
        return { url, weight };
    });
}
async function saveRoute(event) {
    event.preventDefault();
    try {
        const id = AdminDOM.inputValue('route-id');
        const existing = routesState.editingRoute;
        const hosts = commaValues(AdminDOM.inputValue('route-hosts'));
        const paths = commaValues(AdminDOM.inputValue('route-paths'));
        const deliveryMode = AdminDOM.selectValue('route-delivery-mode', 'origin');
        const methods = commaValues(AdminDOM.inputValue('route-methods')).map(method => method.toUpperCase());
        const sourceCIDRs = commaValues(AdminDOM.inputValue('route-source-cidrs'));
        const headers = parseMatcherMap(AdminDOM.textareaValue('route-headers'), 'Header matchers');
        const query = parseMatcherMap(AdminDOM.textareaValue('route-query'), 'Query matchers');
        const backendField = deliveryMode === 'origin' ? 'route-fallback-backends' : 'route-backends';
        const strategyField = deliveryMode === 'origin' ? 'route-fallback-lb' : 'route-lb';
        const backends = deliveryMode === 'default' ? [] : parseRouteBackends(AdminDOM.textareaValue(backendField));
        const strategy = AdminDOM.selectValue(strategyField, 'round_robin');
        const pathTransform = AdminDOM.selectValue('route-path-transform', 'keep');
        const upstream = deliveryMode === 'origin' ? AdminDOM.selectValue('route-upstream') : '';
        if (deliveryMode === 'origin' && !upstream) {
            throw new Error('Choose an Origin or select a different delivery target.');
        }
        if (deliveryMode === 'inline' && backends.length === 0) {
            throw new Error('Add at least one inline backend target.');
        }
        const route = {
            ...routeForWrite(existing),
            id: id || existing?.id,
            name: AdminDOM.inputValue('route-name'),
            priority: AdminDOM.numberValue('route-priority', 100),
            enabled: AdminDOM.checkboxValue('route-enabled', true),
            match: {
                ...(existing?.match || {}),
                hosts: hosts.length > 0 ? hosts : ['*'],
                paths: paths.length > 0 ? paths : ['/*'],
                methods,
                headers,
                query,
                source_cidrs: sourceCIDRs
            },
            action: {
                ...(existing?.action || {}),
                upstream,
                backends,
                strategy,
                strip_prefix: pathTransform === 'strip' ? AdminDOM.inputValue('route-strip') : '',
                rewrite_path: pathTransform === 'rewrite' ? AdminDOM.inputValue('route-rewrite') : '',
                preserve_host: AdminDOM.checkboxValue('route-preserve-host', true),
                timeout: AdminDOM.inputValue('route-timeout'),
                retries: AdminDOM.numberValue('route-retries', 0)
            }
        };
        const result = await api.requestResult('routes', id ? 'PUT' : 'POST', route);
        if (result.error) {
            routesShowToast(result.error.message, 'error');
            return;
        }
        routesState.editingRoute = null;
        await loadRoutesTable();
        routesShowToast(`Route ${id ? 'updated' : 'created'} successfully`, 'success');
    }
    catch (error) {
        console.error(error);
        routesShowToast('Failed to save route', 'error');
    }
}
async function toggleRoute(id, enabled) {
    const route = routesState.routesData.find(routeItem => routeItem.id === id);
    if (!route)
        return;
    const result = await api.requestResult('routes', 'PUT', { ...routeForWrite(route), enabled });
    if (result.error) {
        routesShowToast(result.error.message, 'error');
    }
    else {
        routesShowToast(`Route ${enabled ? 'enabled' : 'disabled'} successfully`, 'success');
    }
    await loadRoutesTable();
}
function renderRouteAccessContext(route) {
    const access = routeAccessInfo(route);
    const actionLabel = access.app ? 'Open App' : 'Protect';
    return `
    <div class="routing-edge-context-row">
      <span class="status-pill ${access.tone}">${escapeHTML(access.label)}</span>
      <span>${escapeHTML(access.description)}</span>
      <button type="button" class="btn btn-outline btn-xs" data-action="routes-protect-access" data-route-id="${escapeHTML(route.id || '')}">${escapeHTML(actionLabel)}</button>
    </div>
  `;
}
async function openEdgeAccessForRoute(routeId) {
    if (!api.hasFeature(FEATURES.ACCESS_CONTROL))
        return;
    const runtimeRouter = window.router;
    if (runtimeRouter && typeof runtimeRouter.navigate === 'function') {
        runtimeRouter.navigate('access_config');
    }
    await AccessControlConfigFacade.init();
    await AccessControlConfigFacade.openProtectedAppForRoute(routeId);
}
async function deleteRoute(id) {
    SectionUI.openConfirmModal('Delete Route', `Are you sure you want to delete this route (<strong>${escapeHTML(id)}</strong>)?<br>Rules are processed in priority order. Linked Edge Access routes cannot be deleted.`, 'Delete', 'var(--danger)', () => {
        void confirmDeleteRoute(id);
    });
}
async function confirmDeleteRoute(id) {
    SectionUI.closeModal();
    const result = await api.requestResult(`routes?id=${encodeURIComponent(id)}`, 'DELETE');
    if (result.error) {
        routesShowToast(result.error.message, 'error');
    }
    else {
        routesShowToast('Route deleted successfully', 'success');
    }
    await loadRoutesTable();
}
function routesShowToast(message, type = 'info') {
    notify(message, type);
}
void routesState.editingRoute;
void renderRouteEditor;
void closeRouteEditor;
void editRoute;
void saveRoute;
void toggleRoute;
void deleteRoute;
void confirmDeleteRoute;
void routesShowToast;
void openEdgeAccessForRoute;
