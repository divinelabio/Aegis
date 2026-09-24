import { api } from '../../../api.js';
import { FEATURES, renderUpgradeBanner } from '../../../core/features.js';
import * as AdminDOM from '../../../core/dom.js';
import { SectionUI } from '../../ui-components.js';
import { escapeHTML } from '../view-helpers.js';
import { loadV2PolicyCapabilities } from './api.js';
import { renderEdgeAccessV2Shell } from './components.js';
import { appsV2Api, findAppByRoute } from './apps-contract.js';
import { identityV2Api } from './identity-contract.js';
import { policiesV2Api } from './policies-contract.js';
import { rolesV2Api } from './roles-contract.js';
import { renderManagedRolePicker } from './roles-components.js';
import { edgeRuntimeV2Api } from './runtime-contract.js';
import { isEdgeAccessV2Destination, isEdgeAccessV2AppSubpage, isEdgeAccessV2IdentityTab, isEdgeAccessV2PolicyView, parseEdgeAccessV2Route, serializeEdgeAccessV2Route } from './route-state.js';
export class EdgeAccessV2Shell {
    constructor() {
        this.containerID = 'access-config-content';
        this.bound = false;
        this.state = {
            route: { destination: 'apps', identityTab: 'providers', identityProviderMode: 'list', roleMode: 'list', appSubpage: 'overview', creatingApp: false, policyView: 'library', policyMode: 'list', policyFirstAttachment: false },
            policyCapabilities: { loading: false, value: null, error: null },
            identity: {
                identityRevision: 0,
                providers: { loading: false, value: null, page: null, error: null },
                mappings: { loading: false, value: null, page: null, error: null },
                serviceIdentities: { loading: false, value: null, page: null, error: null }
            },
            roles: {
                catalog: { loading: false, value: null, page: null, error: null }
            },
            apps: {
                catalog: { loading: false, value: null, page: null, error: null },
                detail: { loading: false, value: null, page: null, error: null },
                history: { loading: false, value: null, page: null, error: null },
                decisions: { loading: false, value: null, page: null, error: null },
                routes: { loading: false, value: null, page: null, error: null },
                filter: { q: '', status: '', trustChannel: '', noActiveAllow: false }
            },
            policies: {
                apps: { loading: false, value: null, page: null, error: null },
                appDetail: { loading: false, value: null, page: null, error: null },
                library: { loading: false, value: null, page: null, error: null },
                policy: { loading: false, value: null, page: null, error: null },
                versions: { loading: false, value: null, page: null, error: null },
                pendingFirstAttachment: null,
                filter: { q: '', status: '', decision: '' }
            },
            decisions: {
                list: { loading: false, value: null, page: null, error: null },
                detail: { loading: false, value: null, page: null, error: null },
                filter: { q: '', result: '', identity: '', channel: '', hostname: '', attachmentID: '', policyVersion: '', from: '', to: '' }
            },
            runtime: {
                settings: { loading: false, value: null, page: null, error: null },
                reload: { loading: false, value: null, page: null, error: null }
            }
        };
        this.onDocumentClick = (event) => {
            if (!(event.target instanceof Element))
                return;
            const target = event.target.closest('[data-edge-access-v2-action]');
            if (!target)
                return;
            const action = target.dataset.edgeAccessV2Action;
            if (action === 'navigate') {
                const destination = target.dataset.edgeAccessV2Destination;
                if (isEdgeAccessV2Destination(destination))
                    this.navigate(destination);
                return;
            }
            if (action === 'identity-tab') {
                const identityTab = target.dataset.edgeAccessV2IdentityTab;
                if (isEdgeAccessV2IdentityTab(identityTab))
                    this.navigate('identity', identityTab);
                return;
            }
            if (action === 'app-new') {
                this.navigateApp({ appID: undefined, appSubpage: 'overview', creatingApp: true });
                return;
            }
            if (action === 'apps-back') {
                this.navigateApp({ appID: undefined, appSubpage: 'overview', creatingApp: false });
                return;
            }
            if (action === 'apps-refresh') {
                void this.loadAppCatalog(true);
                return;
            }
            const appID = target.dataset.edgeAccessV2AppId;
            const deploymentID = target.dataset.edgeAccessV2DeploymentId;
            if (action === 'app-open' && appID) {
                this.navigateApp({ appID, appSubpage: 'overview', creatingApp: false });
                return;
            }
            if (action === 'app-overview' && appID) {
                this.navigateApp({ appID, appSubpage: 'overview', creatingApp: false });
                return;
            }
            if (action === 'app-subpage') {
                const subpage = target.dataset.edgeAccessV2AppSubpage;
                if (isEdgeAccessV2AppSubpage(subpage) && this.state.route.appID)
                    this.navigateApp({ appID: this.state.route.appID, appSubpage: subpage, creatingApp: false });
                return;
            }
            if (action === 'app-save-draft') {
                void this.saveNewApp(target, false);
                return;
            }
            if (action === 'app-save-and-deploy') {
                void this.saveNewApp(target, true);
                return;
            }
            if (action === 'app-trust-reset') {
                SectionUI.markSaveActionBarClean('data-edge-access-v2-action');
                this.render();
                return;
            }
            if (action === 'app-save-trust' && appID) {
                void this.saveAppTrustSources(target, appID);
                return;
            }
            if (action === 'app-deploy' && appID) {
                void this.deployApp(appID);
                return;
            }
            if (action === 'app-rollback' && appID && deploymentID) {
                this.confirmRollbackDeployment(appID, deploymentID);
                return;
            }
            if (action === 'app-disable' && appID) {
                this.confirmDisableApp(appID);
                return;
            }
            if (action === 'app-delete' && appID) {
                this.confirmDeleteApp(appID);
                return;
            }
            if (action === 'app-manage-policies' && appID) {
                this.navigateApp({ appID, appSubpage: 'access-policies', creatingApp: false });
                return;
            }
            if (action === 'app-view-decisions' && appID) {
                this.navigateDecisions({ appID });
                return;
            }
            if (action === 'app-detail-retry' && this.state.route.appID) {
                void this.loadAppDetail(this.state.route.appID, true);
                return;
            }
            if (action === 'retry-identity') {
                const tab = target.dataset.edgeAccessV2IdentityTab;
                if (isEdgeAccessV2IdentityTab(tab))
                    void this.loadIdentityTab(tab, true);
                return;
            }
            const roleID = target.dataset.edgeAccessV2RoleId;
            if (action === 'roles-retry') {
                void this.loadRoles(true);
                return;
            }
            if (action === 'role-new') {
                this.navigateRole('new');
                return;
            }
            if (action === 'role-back') {
                this.navigateRole('list');
                return;
            }
            if (action === 'role-edit' && roleID) {
                this.navigateRole('edit', roleID);
                return;
            }
            if (action === 'role-save') {
                const form = target.closest('form[data-edge-access-v2-role-form]');
                if (form)
                    void this.saveRole(form);
                return;
            }
            if (action === 'role-delete' && roleID) {
                this.confirmDeleteRole(roleID);
                return;
            }
            if (action === 'policy-view') {
                this.state.policies.pendingFirstAttachment = null;
                const view = target.dataset.edgeAccessV2PolicyView;
                if (isEdgeAccessV2PolicyView(view))
                    this.navigatePolicy({ policyView: view, policyAppID: undefined, policyID: undefined, policyMode: 'list', policyFirstAttachment: false });
                return;
            }
            if (action === 'policy-apps-retry') {
                void this.loadPolicyApps(true);
                return;
            }
            if (action === 'policy-library-retry') {
                void this.loadPolicyLibrary(true);
                return;
            }
            if (action === 'policy-app-retry') {
                const policyAppID = this.state.route.policyAppID || this.state.route.appID;
                if (policyAppID)
                    void this.loadPolicyApp(policyAppID, true);
                return;
            }
            if (action === 'policy-filter-apps') {
                this.applyPolicyFilters(target, 'apps');
                return;
            }
            const policyAppID = target.dataset.edgeAccessV2PolicyAppId;
            const policyID = target.dataset.edgeAccessV2PolicyId;
            if (action === 'policy-open-app' && policyAppID) {
                this.state.policies.pendingFirstAttachment = null;
                this.navigatePolicy({ policyView: 'library', policyAppID, policyID: undefined, policyMode: 'list', policyFirstAttachment: false });
                return;
            }
            if (action === 'policy-back') {
                this.state.policies.pendingFirstAttachment = null;
                this.navigatePolicy({ policyView: this.state.route.policyView, policyAppID: undefined, policyID: undefined, policyMode: 'list', policyFirstAttachment: false });
                return;
            }
            if (action === 'policy-new') {
                this.state.policies.pendingFirstAttachment = null;
                this.navigatePolicy({ policyView: this.state.route.policyView, policyAppID: undefined, policyID: undefined, policyMode: 'new', policyFirstAttachment: false });
                return;
            }
            if (action === 'policy-open' && policyID) {
                this.state.policies.pendingFirstAttachment = null;
                this.navigatePolicy({ policyView: this.state.route.policyView, policyAppID: this.state.route.policyAppID, policyID, policyMode: 'edit', policyFirstAttachment: false });
                return;
            }
            if (action === 'policy-add-menu' && policyAppID) {
                void this.openPolicyAddMenu(policyAppID);
                return;
            }
            if (action === 'policy-library-attach' && policyID) {
                void this.openLibraryPolicyAttach(policyID);
                return;
            }
            if (action === 'policy-save-draft') {
                void this.savePolicyDraft(target);
                return;
            }
            if (action === 'policy-publish') {
                void this.publishPolicyDraft(target);
                return;
            }
            if (action === 'policy-archive' && policyID) {
                this.confirmArchivePolicy(policyID);
                return;
            }
            if (action === 'policy-attach-save') {
                void this.saveExistingPolicyAttachment(target);
                return;
            }
            if (action === 'policy-library-attach-save') {
                void this.saveLibraryPolicyAttachment(target);
                return;
            }
            const attachmentID = target.dataset.edgeAccessV2AttachmentId;
            if (action === 'policy-change-attachment' && attachmentID) {
                this.openAttachmentEditor(attachmentID);
                return;
            }
            if (action === 'policy-attachment-save' && attachmentID) {
                void this.saveAttachmentScope(target, attachmentID);
                return;
            }
            if (action === 'policy-upgrade-attachment' && attachmentID) {
                void this.upgradeAttachment(attachmentID);
                return;
            }
            if (action === 'policy-detach-attachment' && attachmentID) {
                this.confirmDetachAttachment(attachmentID);
                return;
            }
            if (action === 'policy-view-decisions' && policyAppID) {
                this.navigateDecisions({ appID: policyAppID });
                return;
            }
            if (action === 'policy-view-policy-decisions' && policyID) {
                this.navigateDecisions({ policyID });
                return;
            }
            if (action === 'policy-deploy-handoff' && policyAppID) {
                this.navigateApp({ appID: policyAppID, appSubpage: 'overview', creatingApp: false });
                return;
            }
            if (action === 'decisions-refresh') {
                void this.loadDecisions(true);
                return;
            }
            if (action === 'decisions-filter') {
                this.applyDecisionFilters(target);
                return;
            }
            const decisionID = target.dataset.edgeAccessV2DecisionId;
            if (action === 'decision-open' && decisionID) {
                void this.loadDecisionDetail(decisionID);
                return;
            }
            if (action === 'runtime-retry') {
                void this.loadRuntime(true);
                return;
            }
            if (action === 'runtime-save') {
                void this.saveRuntimeSettings(target);
                return;
            }
            if (action === 'runtime-reload') {
                void this.reloadRuntime();
                return;
            }
            const providerID = target.dataset.edgeAccessV2ProviderId;
            const providerPreset = target.dataset.edgeAccessV2ProviderPreset;
            const providerKind = target.dataset.edgeAccessV2ProviderKind;
            if (action === 'identity-source-create') {
                this.navigateIdentityProvider('new');
                return;
            }
            if (action === 'provider-template' && providerPreset && ['entra', 'okta', 'auth0', 'google', 'keycloak', 'oidc', 'entra-jwt', 'okta-jwt', 'auth0-jwt', 'cognito-jwt', 'keycloak-jwt', 'jwt'].includes(providerPreset)) {
                this.navigateIdentityProvider('new', undefined, providerPreset, providerKind === 'jwt' ? 'jwt' : 'oidc');
                return;
            }
            if (action === 'provider-back') {
                this.navigateIdentityProvider('list');
                return;
            }
            if (action === 'provider-edit' && providerID) {
                this.navigateIdentityProvider('edit', providerID);
                return;
            }
            if (action === 'provider-save') {
                const form = target.closest('form[data-edge-access-v2-provider-form]');
                if (form) {
                    const previousID = form.dataset.edgeAccessV2ProviderId;
                    void this.saveProvider(form, previousID ? this.findProvider(previousID) : undefined);
                }
                return;
            }
            if (action === 'provider-validate' && providerID) {
                void this.validateProvider(providerID);
                return;
            }
            if (action === 'provider-delete' && providerID) {
                void this.confirmProviderDelete(providerID);
                return;
            }
            if (action === 'mapping-edit' && providerID) {
                void this.openMappingEditor(this.findMapping(providerID));
                return;
            }
            if (action === 'machine-identity-save') {
                const form = target.closest('form[data-edge-access-v2-machine-form]');
                if (form)
                    void this.saveServiceIdentity(form, undefined, true);
                return;
            }
            const serviceIdentityID = target.dataset.edgeAccessV2ServiceIdentityId;
            if (action === 'service-identity-edit' && serviceIdentityID)
                void this.openServiceIdentityEditor(this.findServiceIdentity(serviceIdentityID));
            if (action === 'service-identity-usage' && serviceIdentityID)
                void this.showServiceIdentityUsage(serviceIdentityID);
            if (action === 'service-identity-rotate' && serviceIdentityID)
                void this.confirmServiceIdentityRotate(serviceIdentityID);
            if (action === 'service-identity-revoke' && serviceIdentityID)
                void this.confirmServiceIdentityRevoke(serviceIdentityID);
        };
        this.onDocumentChange = (event) => {
            if (!(event.target instanceof Element))
                return;
            const appFilters = event.target.closest('form[data-edge-access-v2-app-filters]');
            if (appFilters && event.target instanceof HTMLSelectElement) {
                this.applyAppFilters(appFilters);
                return;
            }
            const policyLibraryFilters = event.target.closest('form[data-edge-access-v2-policy-filters="library"]');
            if (policyLibraryFilters && event.target instanceof HTMLSelectElement) {
                this.applyPolicyFilters(policyLibraryFilters, 'library');
                return;
            }
            const providerTypeSelect = event.target.closest('[data-edge-access-v2-provider-type-select]');
            if (providerTypeSelect) {
                const providerKind = providerTypeSelect.value;
                this.navigateIdentityProvider('new', undefined, undefined, ['oidc', 'jwt', 'api_key', 'mtls'].includes(providerKind) ? providerKind : undefined);
                return;
            }
            const policyForm = event.target.closest('form[data-edge-access-v2-policy-form]');
            if (policyForm) {
                if (['decision', 'identity_mode'].includes(event.target.name))
                    this.syncPolicyEditorForm(policyForm);
                return;
            }
            const form = event.target.closest('form[data-edge-access-v2-app-form="new"], form[data-edge-access-v2-app-form="trust"]');
            if (!form)
                return;
            const control = event.target;
            if (form.dataset.edgeAccessV2AppForm === 'trust') {
                if (['trust_browser', 'trust_jwt'].includes(control.name))
                    this.syncNewAppForm(form);
                SectionUI.markSaveActionBarDirty('data-edge-access-v2-action');
                return;
            }
            if (!['route_mode', 'trust_browser', 'trust_jwt'].includes(control.name))
                return;
            this.syncNewAppForm(form);
        };
        this.onDocumentSubmit = (event) => {
            if (!(event.target instanceof HTMLFormElement))
                return;
            if (event.target.matches('form[data-edge-access-v2-policy-filters="library"]')) {
                event.preventDefault();
                this.applyPolicyFilters(event.target, 'library');
                return;
            }
            if (!event.target.matches('form[data-edge-access-v2-app-filters]'))
                return;
            event.preventDefault();
            this.applyAppFilters(event.target);
        };
        this.onPopState = () => {
            this.state.route = parseEdgeAccessV2Route(window.location.search);
            if (this.state.route.destination === 'policies' && this.state.route.policyMode === 'new')
                this.resetPolicyEditorState();
            this.syncDecisionFiltersFromRoute();
            this.syncSidebar(this.state.route.destination);
            this.render();
            void this.loadCurrentScreen();
        };
    }
    async init() {
        this.state.route = parseEdgeAccessV2Route(window.location.search);
        this.syncDecisionFiltersFromRoute();
        this.bind();
        this.render();
        await this.loadCurrentScreen();
    }
    render() {
        const container = AdminDOM.getById(this.containerID);
        if (!container)
            return;
        if (!api.hasFeature(FEATURES.ACCESS_CONTROL)) {
            container.innerHTML = renderUpgradeBanner('enterprise', 'Edge Access');
            return;
        }
        container.innerHTML = renderEdgeAccessV2Shell(this.state);
    }
    switchTab(tabID) {
        const compatibilityDestinations = {
            apps: 'apps',
            protected_apps: 'apps',
            policies: 'policies',
            access_policies: 'policies',
            identity: 'identity',
            identity_trust: 'identity',
            idp: 'identity',
            roles: 'roles',
            decisions: 'decisions',
            activity: 'decisions',
            runtime: 'runtime',
            settings: 'runtime',
            service_credentials: 'identity'
        };
        const destination = compatibilityDestinations[tabID] || (isEdgeAccessV2Destination(tabID) ? tabID : undefined);
        if (destination) {
            if (this.state.route.destination !== destination) {
                this.navigate(destination);
            }
            else {
                this.syncSidebar(destination);
                this.render();
            }
        }
    }
    updateField() {
        // Phase 6 has no V2 forms. This compatibility method intentionally has no side effect.
    }
    async saveConfig() {
        // The V2 shell owns all active Edge Access configuration through focused workflows.
    }
    async loadConfig() {
        await this.loadCurrentScreen();
    }
    async openProtectedAppForRoute(routeId) {
        try {
            const app = await findAppByRoute(routeId);
            if (app) {
                this.navigateApp({ appID: app.id, appSubpage: 'overview', creatingApp: false });
                return;
            }
            this.navigateApp({ appID: undefined, appSubpage: 'overview', creatingApp: true, newAppRouteID: routeId });
        }
        catch (error) {
            SectionUI.showToast(error instanceof Error ? error.message : 'Apps could not be loaded for this Route.', 'error');
            this.navigate('apps');
        }
    }
    async openActivityForProtectedApp(appID) {
        this.navigateDecisions({ appID });
    }
    bind() {
        if (this.bound)
            return;
        document.addEventListener('click', this.onDocumentClick);
        document.addEventListener('change', this.onDocumentChange);
        document.addEventListener('submit', this.onDocumentSubmit);
        window.addEventListener('popstate', this.onPopState);
        this.bound = true;
    }
    syncNewAppForm(form) {
        const routeMode = form.querySelector('input[name="route_mode"]:checked')?.value || 'existing';
        const existingRoutePanel = form.querySelector('[data-edge-access-v2-route-panel="existing"]');
        const newRoutePanel = form.querySelector('[data-edge-access-v2-route-panel="new"]');
        if (existingRoutePanel)
            existingRoutePanel.hidden = routeMode !== 'existing';
        if (newRoutePanel)
            newRoutePanel.hidden = routeMode !== 'new';
        const browserEnabled = form.querySelector('input[name="trust_browser"]')?.checked === true;
        const jwtEnabled = form.querySelector('input[name="trust_jwt"]')?.checked === true;
        const browserPanel = form.querySelector('[data-edge-access-v2-trust-panel="browser"]');
        const jwtPanel = form.querySelector('[data-edge-access-v2-trust-panel="jwt"]');
        if (browserPanel)
            browserPanel.hidden = !browserEnabled;
        if (jwtPanel)
            jwtPanel.hidden = !jwtEnabled;
    }
    syncPolicyEditorForm(form) {
        const publicBypass = form.querySelector('input[name="decision"]:checked')?.value === 'public_bypass';
        const specificIdentities = form.querySelector('input[name="identity_mode"]:checked')?.value === 'specific';
        const identityControls = form.querySelector('[data-edge-access-v2-policy-identity-controls]');
        const specificIdentityControls = form.querySelector('[data-edge-access-v2-policy-specific-identities]');
        const bypassNote = form.querySelector('[data-edge-access-v2-policy-bypass-note]');
        if (identityControls)
            identityControls.hidden = publicBypass;
        if (specificIdentityControls)
            specificIdentityControls.hidden = !specificIdentities;
        if (bypassNote)
            bypassNote.hidden = !publicBypass;
    }
    navigate(destination, identityTab = this.state.route.identityTab) {
        const next = { ...this.state.route, destination, identityTab: destination === 'identity' ? 'providers' : identityTab, identityProviderMode: 'list', identityProviderID: undefined, identityProviderKind: undefined, identityProviderPreset: undefined, roleMode: 'list', roleID: undefined };
        const nextSearch = serializeEdgeAccessV2Route(window.location.search, next);
        window.history.pushState({}, '', `${window.location.pathname}${nextSearch}${window.location.hash}`);
        this.state.route = next;
        this.syncSidebar(destination);
        this.render();
        void this.loadCurrentScreen();
    }
    syncSidebar(destination) {
        const isOverview = typeof window !== 'undefined' && window.location.pathname.includes('/access-config') && destination === 'apps';
        const targetMap = {
            apps: isOverview ? 'access_config' : 'access_apps',
            policies: 'access_policies',
            identity: 'access_identity',
            roles: 'access_roles',
            decisions: 'access_decisions',
            runtime: 'access_settings'
        };
        const titleMap = {
            apps: isOverview ? 'Overview' : 'Apps',
            policies: 'Access Policies',
            identity: 'Identity',
            roles: 'Roles',
            decisions: 'Decisions',
            runtime: 'Settings'
        };
        const target = targetMap[destination] || 'access_config';
        const pageTitleEl = AdminDOM.getById('page-title');
        if (pageTitleEl && titleMap[destination]) {
            pageTitleEl.innerText = titleMap[destination];
        }
        AdminDOM.queryAll('.nav-link').forEach(el => el.classList.remove('active'));
        AdminDOM.queryAll('.nav-domain-group').forEach(el => el.classList.remove('has-active-child'));
        const link = AdminDOM.query(`.nav-link[data-nav-target="${target}"]`) || AdminDOM.query(`.nav-link[data-nav-target="access_config"]`);
        if (link) {
            link.classList.add('active');
            const parent = link.closest('.nav-domain-group');
            if (parent instanceof HTMLElement) {
                AdminDOM.queryAll('.nav-domain-group').forEach(group => {
                    if (group !== parent && group instanceof HTMLElement) {
                        group.classList.remove('is-open');
                        const h = group.querySelector('.nav-domain-header');
                        if (h instanceof HTMLElement)
                            h.setAttribute('aria-expanded', 'false');
                    }
                });
                parent.classList.add('is-open', 'has-active-child');
                const header = parent.querySelector('.nav-domain-header');
                if (header instanceof HTMLElement)
                    header.setAttribute('aria-expanded', 'true');
            }
        }
    }
    navigateIdentityProvider(mode, providerID, preset, kind) {
        const next = { ...this.state.route, destination: 'identity', identityTab: 'providers', identityProviderMode: mode, identityProviderID: providerID, identityProviderKind: kind, identityProviderPreset: preset };
        const nextSearch = serializeEdgeAccessV2Route(window.location.search, next);
        window.history.pushState({}, '', `${window.location.pathname}${nextSearch}${window.location.hash}`);
        this.state.route = next;
        this.render();
        void this.loadCurrentScreen();
    }
    navigateRole(mode, roleID) {
        const next = { ...this.state.route, destination: 'roles', roleMode: mode, roleID };
        const nextSearch = serializeEdgeAccessV2Route(window.location.search, next);
        window.history.pushState({}, '', `${window.location.pathname}${nextSearch}${window.location.hash}`);
        this.state.route = next;
        this.render();
        void this.loadCurrentScreen();
    }
    navigateApp(app) {
        const next = { ...this.state.route, destination: 'apps', ...app };
        const nextSearch = serializeEdgeAccessV2Route(window.location.search, next);
        window.history.pushState({}, '', `${window.location.pathname}${nextSearch}${window.location.hash}`);
        this.state.route = next;
        this.render();
        void this.loadCurrentScreen();
    }
    navigatePolicy(nextPolicy) {
        if (nextPolicy.policyMode === 'new')
            this.resetPolicyEditorState();
        const next = { ...this.state.route, destination: 'policies', ...nextPolicy };
        const nextSearch = serializeEdgeAccessV2Route(window.location.search, next);
        window.history.pushState({}, '', `${window.location.pathname}${nextSearch}${window.location.hash}`);
        this.state.route = next;
        this.render();
        void this.loadCurrentScreen();
    }
    resetPolicyEditorState() {
        Object.assign(this.state.policies.policy, { loading: false, value: null, page: null, error: null });
        Object.assign(this.state.policies.versions, { loading: false, value: null, page: null, error: null });
    }
    syncDecisionFiltersFromRoute() {
        const route = this.state.route;
        this.state.decisions.filter = { q: route.decisionQuery || '', result: route.decisionResult || '', identity: route.decisionIdentity || '', channel: route.decisionChannel || '', hostname: route.decisionHostname || '', attachmentID: route.decisionAttachmentID || '', policyVersion: route.decisionPolicyVersion || '', from: route.decisionFrom || '', to: route.decisionTo || '' };
    }
    navigateDecisions(selection) {
        const filter = selection.filter || this.state.decisions.filter;
        const next = { ...this.state.route, destination: 'decisions', decisionAppID: selection.appID, decisionPolicyID: selection.policyID, decisionQuery: filter.q || undefined, decisionResult: filter.result || undefined, decisionIdentity: filter.identity || undefined, decisionChannel: filter.channel || undefined, decisionHostname: filter.hostname || undefined, decisionAttachmentID: filter.attachmentID || undefined, decisionPolicyVersion: filter.policyVersion || undefined, decisionFrom: filter.from || undefined, decisionTo: filter.to || undefined };
        const nextSearch = serializeEdgeAccessV2Route(window.location.search, next);
        window.history.pushState({}, '', `${window.location.pathname}${nextSearch}${window.location.hash}`);
        this.state.route = next;
        this.syncDecisionFiltersFromRoute();
        this.state.decisions.list.value = null;
        this.state.decisions.detail.value = null;
        this.render();
        void this.loadCurrentScreen();
    }
    async loadCurrentScreen() {
        if (this.state.route.destination === 'apps') {
            if (this.state.route.creatingApp) {
                await Promise.all([this.loadAppRoutes(), this.loadIdentityTab('providers')]);
                if (this.state.route.destination === 'apps' && this.state.route.creatingApp) {
                    this.render();
                    const routeSelect = document.querySelector('form[data-edge-access-v2-app-form="new"] select[name="route_id"]');
                    if (routeSelect && this.state.route.newAppRouteID)
                        routeSelect.value = this.state.route.newAppRouteID;
                }
            }
            else if (this.state.route.appID) {
                await this.loadAppDetail(this.state.route.appID);
                if (this.state.route.appSubpage === 'access-policies')
                    await this.loadPolicyApp(this.state.route.appID);
                if (this.state.route.appSubpage === 'overview')
                    await Promise.all([
                        this.loadAppDecisions(this.state.route.appID),
                        this.loadPolicyApp(this.state.route.appID)
                    ]);
            }
            else
                await this.loadAppCatalog();
            return;
        }
        if (this.state.route.destination === 'policies') {
            await this.loadPolicyCapabilities();
            if (this.state.route.policyMode !== 'list') {
                await this.loadRoles();
                if (this.state.route.policyID)
                    await this.loadPolicyEditor(this.state.route.policyID);
                return;
            }
            if (this.state.route.policyAppID)
                await this.loadPolicyApp(this.state.route.policyAppID);
            else if (this.state.route.policyView === 'library')
                await this.loadPolicyLibrary();
            else
                await this.loadPolicyApps();
            return;
        }
        if (this.state.route.destination === 'decisions') {
            await this.loadDecisions();
            return;
        }
        if (this.state.route.destination === 'runtime') {
            await this.loadRuntime();
            return;
        }
        if (this.state.route.destination === 'roles') {
            await this.loadRoles();
            return;
        }
        if (this.state.route.destination === 'identity') {
            const resources = this.state.route.identityProviderMode === 'list'
                ? ['providers', 'mappings', 'service-identities']
                : ['providers', 'mappings'];
            await Promise.all([this.loadRoles(), ...resources.map(tab => this.loadIdentityTab(tab))]);
        }
    }
    async loadRuntime(force = false) {
        const settings = this.state.runtime.settings;
        const reload = this.state.runtime.reload;
        if (!force && settings.value && reload.value)
            return;
        settings.loading = true;
        reload.loading = true;
        settings.error = null;
        reload.error = null;
        this.render();
        const [settingsResult, reloadResult] = await Promise.all([edgeRuntimeV2Api.settings(), edgeRuntimeV2Api.reloadStatus()]);
        settings.loading = false;
        reload.loading = false;
        if (settingsResult.data)
            settings.value = settingsResult.data;
        else
            settings.error = settingsResult.error?.message || 'Runtime settings could not be loaded.';
        if (reloadResult.data)
            reload.value = reloadResult.data;
        else
            reload.error = reloadResult.error?.message || 'Runtime reload status could not be loaded.';
        if (this.state.route.destination === 'runtime')
            this.render();
    }
    async saveRuntimeSettings(target) {
        const form = target.closest('form[data-edge-access-v2-runtime-form]');
        const current = this.state.runtime.settings.value;
        if (!form || !current)
            return;
        const numberValue = (name, fallback) => { const value = Number(this.formValue(form, name)); return Number.isFinite(value) && value >= 0 ? Math.floor(value) : fallback; };
        const checked = (name) => form.elements.namedItem(name)?.checked === true;
        const next = { ...current, enabled: checked('enabled'), session_cookie: { ...current.session_cookie, token_ttl: this.formValue(form, 'token_ttl'), idle_timeout: this.formValue(form, 'idle_timeout'), max_sessions: numberValue('max_sessions', current.session_cookie.max_sessions) }, identity_headers: { ...current.identity_headers, enabled: checked('identity_headers_enabled'), overwrite_existing: checked('identity_headers_overwrite') }, activity: { ...current.activity, retention_days: numberValue('activity_retention', current.activity.retention_days) }, audit: { ...current.audit, retention_days: numberValue('audit_retention', current.audit.retention_days) } };
        const result = await edgeRuntimeV2Api.updateSettings(next);
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Runtime controls could not be saved.');
            return;
        }
        this.state.runtime.settings.value = result.data;
        SectionUI.showToast('Edge runtime controls saved.', 'success');
        this.render();
    }
    async reloadRuntime() {
        const result = await edgeRuntimeV2Api.reload();
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Runtime reload failed.');
            return;
        }
        this.state.runtime.reload.value = result.data;
        SectionUI.showToast('Edge Access runtime reloaded.', 'success');
        this.render();
    }
    async loadAppCatalog(force = false) {
        const resource = this.state.apps.catalog;
        if (resource.loading || (!force && resource.value))
            return;
        resource.loading = true;
        resource.error = null;
        this.render();
        const filter = this.state.apps.filter;
        const result = await appsV2Api.list({ q: filter.q || undefined, status: filter.status || undefined, trust_channel: filter.trustChannel || undefined, no_active_allow: filter.noActiveAllow || undefined });
        resource.loading = false;
        if (result.data) {
            resource.value = result.data.apps;
            resource.page = result.data.page;
        }
        else
            resource.error = result.error?.message || 'Apps could not be loaded.';
        if (this.state.route.destination === 'apps' && !this.state.route.appID && !this.state.route.creatingApp)
            this.render();
    }
    async loadAppDetail(id, force = false) {
        const resource = this.state.apps.detail;
        if (resource.loading || (!force && resource.value?.protected_app.id === id))
            return;
        resource.loading = true;
        resource.error = null;
        this.render();
        const result = await appsV2Api.get(id);
        resource.loading = false;
        if (result.data)
            resource.value = result.data;
        else {
            resource.value = null;
            resource.error = result.error?.message || 'App details could not be loaded.';
        }
        if (this.state.route.destination === 'apps' && this.state.route.appID === id)
            this.render();
    }
    async loadAppDecisions(id, force = false) {
        const resource = this.state.apps.decisions;
        if (resource.loading || (!force && resource.value && this.state.route.appID === id))
            return;
        resource.loading = true;
        resource.error = null;
        this.render();
        const result = await appsV2Api.recentDecisions(id);
        resource.loading = false;
        if (result.data)
            resource.value = result.data;
        else
            resource.error = result.error?.message || 'Recent decisions could not be loaded.';
        if (this.state.route.destination === 'apps' && this.state.route.appID === id && this.state.route.appSubpage === 'overview')
            this.render();
    }
    async loadAppRoutes(force = false) {
        const resource = this.state.apps.routes;
        if (resource.loading || (!force && resource.value))
            return;
        resource.loading = true;
        resource.error = null;
        this.render();
        const result = await appsV2Api.listRoutes();
        resource.loading = false;
        if (result.data)
            resource.value = result.data;
        else
            resource.error = result.error?.message || 'Routes could not be loaded from Routing.';
        if (this.state.route.destination === 'apps' && this.state.route.creatingApp)
            this.render();
    }
    async loadPolicyCapabilities() {
        if (this.state.policyCapabilities.value || this.state.policyCapabilities.loading)
            return;
        this.state.policyCapabilities.loading = true;
        this.state.policyCapabilities.error = null;
        this.render();
        const capabilities = await loadV2PolicyCapabilities();
        this.state.policyCapabilities.loading = false;
        if (capabilities)
            this.state.policyCapabilities.value = capabilities;
        else
            this.state.policyCapabilities.error = 'Some policy conditions are temporarily unavailable.';
        if (this.state.route.destination === 'policies')
            this.render();
    }
    async loadPolicyApps(force = false) {
        const resource = this.state.policies.apps;
        if (resource.loading || (!force && resource.value))
            return;
        resource.loading = true;
        resource.error = null;
        this.render();
        const filter = this.state.policies.filter;
        const result = await policiesV2Api.apps({ q: filter.q || undefined, status: filter.status || undefined });
        resource.loading = false;
        if (result.data) {
            resource.value = result.data.apps;
            resource.page = result.data.page;
        }
        else
            resource.error = result.error?.message || 'Policy Apps could not be loaded.';
        if (this.state.route.destination === 'policies' && !this.state.route.policyAppID && this.state.route.policyView === 'library')
            this.render();
    }
    async loadPolicyApp(id, force = false) {
        const resource = this.state.policies.appDetail;
        if (resource.loading || (!force && resource.value?.app.id === id))
            return;
        resource.loading = true;
        resource.error = null;
        this.render();
        const result = await policiesV2Api.app(id);
        resource.loading = false;
        if (result.data) {
            resource.value = { app: result.data.app, attachments: result.data.attachments };
            resource.page = result.data.page;
        }
        else {
            resource.value = null;
            resource.error = result.error?.message || 'Policy Attachments could not be loaded.';
        }
        if ((this.state.route.destination === 'policies' && this.state.route.policyAppID === id)
            || (this.state.route.destination === 'apps' && this.state.route.appID === id && (this.state.route.appSubpage === 'access-policies' || this.state.route.appSubpage === 'overview')))
            this.render();
    }
    async loadPolicyLibrary(force = false) {
        const resource = this.state.policies.library;
        if (resource.loading || (!force && resource.value))
            return;
        resource.loading = true;
        resource.error = null;
        this.render();
        const filter = this.state.policies.filter;
        const result = await policiesV2Api.library({ q: filter.q || undefined, status: filter.status === 'active' || filter.status === 'archived' ? filter.status : undefined, decision: filter.decision || undefined });
        resource.loading = false;
        if (result.data) {
            resource.value = result.data.policies;
            resource.page = result.data.page;
        }
        else
            resource.error = result.error?.message || 'Policy library could not be loaded.';
        if (this.state.route.destination === 'policies' && this.state.route.policyView === 'library' && !this.state.route.policyID)
            this.render();
    }
    async loadPolicyEditor(id, force = false) {
        const policyResource = this.state.policies.policy;
        const versionResource = this.state.policies.versions;
        if (!force && policyResource.value?.id === id && versionResource.value)
            return;
        policyResource.loading = true;
        versionResource.loading = true;
        policyResource.error = null;
        versionResource.error = null;
        this.render();
        const [policy, versions] = await Promise.all([policiesV2Api.getPolicy(id), policiesV2Api.versions(id)]);
        policyResource.loading = false;
        versionResource.loading = false;
        if (policy.data)
            policyResource.value = policy.data;
        else
            policyResource.error = policy.error?.message || 'Policy could not be loaded.';
        if (versions.data)
            versionResource.value = versions.data;
        else
            versionResource.error = versions.error?.message || 'Policy versions could not be loaded.';
        if (this.state.route.destination === 'policies' && this.state.route.policyID === id)
            this.render();
    }
    applyPolicyFilters(target, mode) {
        const form = target.closest('form[data-edge-access-v2-policy-filters]');
        if (!form)
            return;
        const data = new FormData(form);
        this.state.policies.filter = { q: String(data.get('q') || '').trim(), status: String(data.get('status') || '').trim(), decision: String(data.get('decision') || '').trim() };
        if (mode === 'apps') {
            this.state.policies.apps.value = null;
            void this.loadPolicyApps(true);
        }
        else {
            this.state.policies.library.value = null;
            void this.loadPolicyLibrary(true);
        }
    }
    splitList(value) { return value.split(',').map(item => item.trim()).filter(Boolean); }
    policyDraftFromForm(form) {
        const decision = this.formValue(form, 'decision');
        if (decision !== 'allow' && decision !== 'deny' && decision !== 'public_bypass') {
            this.showIdentityError('Choose an Allow, Deny, or Public bypass decision.');
            return null;
        }
        const identityMode = this.formValue(form, 'identity_mode');
        if (decision !== 'public_bypass' && identityMode !== 'any' && identityMode !== 'specific') {
            this.showIdentityError('Choose who can match this policy.');
            return null;
        }
        let claims = [];
        const rawClaims = this.formValue(form, 'claims');
        if (rawClaims) {
            try {
                const parsed = JSON.parse(rawClaims);
                if (!Array.isArray(parsed) || parsed.some(item => typeof item !== 'object' || item === null || typeof item.name !== 'string'))
                    throw new Error('invalid');
                claims = parsed;
            }
            catch {
                this.showIdentityError('Claim conditions must be a JSON array with a string name.');
                return null;
            }
        }
        const mfa = form.elements.namedItem('mfa_satisfied')?.checked === true;
        const specificPrincipals = {
            any_authenticated: false,
            roles: this.formValues(form, 'roles'),
            groups: this.splitList(this.formValue(form, 'groups')),
            permissions: this.splitList(this.formValue(form, 'permissions')),
            service_identity_ids: this.splitList(this.formValue(form, 'service_identity_ids')),
            claims
        };
        if (decision !== 'public_bypass' && identityMode === 'specific' &&
            specificPrincipals.roles.length + specificPrincipals.groups.length + specificPrincipals.permissions.length +
                specificPrincipals.service_identity_ids.length + specificPrincipals.claims.length === 0) {
            this.showIdentityError('Add at least one role, group, permission, service identity, or claim condition.');
            return null;
        }
        const principals = decision === 'public_bypass'
            ? { any_authenticated: false, roles: [], groups: [], permissions: [], service_identity_ids: [], claims: [] }
            : identityMode === 'any'
                ? { any_authenticated: true, roles: [], groups: [], permissions: [], service_identity_ids: [], claims: [] }
                : specificPrincipals;
        return { decision, principals, requirements: { mfa_satisfied: mfa, source_cidrs: this.splitList(this.formValue(form, 'source_cidrs')), trusted_device: false, countries: [] } };
    }
    firstAttachmentFromForm(form) {
        const protectedAppID = this.state.route.policyFirstAttachment ? this.state.route.policyAppID || '' : '';
        if (!protectedAppID)
            return null;
        return {
            protectedAppID,
            path: this.formValue(form, 'path') || '/*',
            methods: this.splitList(this.formValue(form, 'methods')).map(method => method.toUpperCase()),
            channels: Array.from(form.elements.namedItem('auth_channels')?.selectedOptions || []).map(option => option.value).filter((value) => value === 'oidc' || value === 'jwt' || value === 'api_key' || value === 'mtls')
        };
    }
    async savePolicyDraft(target) {
        const form = target.closest('form[data-edge-access-v2-policy-form]');
        if (!form)
            return null;
        const input = this.policyDraftFromForm(form);
        if (!input)
            return null;
        const pendingFirstAttachment = this.firstAttachmentFromForm(form);
        if (pendingFirstAttachment)
            this.state.policies.pendingFirstAttachment = pendingFirstAttachment;
        const name = this.formValue(form, 'name');
        if (!name) {
            this.showIdentityError('A Policy name is required.');
            return null;
        }
        const description = this.formValue(form, 'description');
        let policy = this.state.policies.policy.value;
        if (!policy) {
            const created = await policiesV2Api.createPolicy({ name, description: description || undefined });
            if (!created.data) {
                this.showIdentityError(created.error?.message || 'Policy could not be created.');
                return null;
            }
            policy = created.data;
            this.state.policies.policy.value = policy;
            const createdDraft = await policiesV2Api.createDraft(policy.id, input);
            if (!createdDraft.data) {
                this.showIdentityError(createdDraft.error?.message || 'Policy draft could not be created.');
                return null;
            }
            this.state.policies.versions.value = [createdDraft.data];
            this.navigatePolicy({ policyView: this.state.route.policyView, policyAppID: this.state.route.policyAppID, policyID: policy.id, policyMode: 'edit', policyFirstAttachment: this.state.route.policyFirstAttachment });
            SectionUI.showToast('Policy saved.', 'success');
            return createdDraft.data;
        }
        if (policy.name !== name || (policy.description || '') !== description) {
            const updatedPolicy = await policiesV2Api.updatePolicy(policy.id, { ...policy, name, description: description || undefined });
            if (!updatedPolicy.data) {
                this.showIdentityError(updatedPolicy.error?.message || 'Policy metadata could not be saved.');
                return null;
            }
            policy = updatedPolicy.data;
            this.state.policies.policy.value = policy;
        }
        let draft = (this.state.policies.versions.value || []).find(version => version.state === 'draft');
        if (!draft) {
            const createdDraft = await policiesV2Api.createDraft(policy.id, input);
            if (!createdDraft.data) {
                this.showIdentityError(createdDraft.error?.message || 'A new Policy draft could not be created.');
                return null;
            }
            draft = createdDraft.data;
            this.state.policies.versions.value = [...(this.state.policies.versions.value || []), draft];
        }
        else {
            const updatedDraft = await policiesV2Api.updateDraft(policy.id, draft.version, { ...input, revision: draft.revision });
            if (!updatedDraft.data) {
                this.showIdentityError(updatedDraft.error?.message || 'Policy draft could not be saved.');
                return null;
            }
            draft = updatedDraft.data;
            this.state.policies.versions.value = (this.state.policies.versions.value || []).map(version => version.version === draft?.version ? draft : version);
        }
        SectionUI.showToast('Policy saved.', 'success');
        this.render();
        return draft;
    }
    async publishPolicyDraft(target) {
        const shouldCreateFirstAttachment = this.state.route.policyFirstAttachment && Boolean(this.state.route.policyAppID);
        const form = target.closest('form[data-edge-access-v2-policy-form]');
        const currentFirstAttachment = form ? this.firstAttachmentFromForm(form) : null;
        const pendingFirstAttachment = this.state.policies.pendingFirstAttachment?.protectedAppID === this.state.route.policyAppID ? this.state.policies.pendingFirstAttachment : null;
        const firstAttachment = currentFirstAttachment || pendingFirstAttachment;
        const draft = await this.savePolicyDraft(target);
        const policy = this.state.policies.policy.value;
        if (!draft || !policy)
            return;
        const published = await policiesV2Api.publish(policy.id, draft.version, draft.revision);
        if (!published.data) {
            this.showIdentityError(published.error?.message || 'Policy Version could not be published.');
            return;
        }
        this.state.policies.versions.value = (this.state.policies.versions.value || []).map(version => version.version === published.data?.version ? published.data : version);
        if (shouldCreateFirstAttachment && this.state.route.policyAppID) {
            if (!firstAttachment) {
                this.showIdentityError('The initial Attachment scope is no longer available. Reopen the Policy and attach the published Version.');
                return;
            }
            const attachment = await policiesV2Api.createAttachment({ policy_id: policy.id, policy_version: published.data.version, protected_app_id: firstAttachment.protectedAppID, path: firstAttachment.path, methods: firstAttachment.methods, auth_channels: firstAttachment.channels, deployment_state: 'active', enabled: true });
            if (!attachment.data) {
                this.showIdentityError(`Policy Version published, but its first Attachment needs attention: ${attachment.error?.message || 'Attachment could not be created.'}`);
                return;
            }
            SectionUI.showToast('Policy published and Attachment prepared. Complete deployment from the App.', 'success');
            // The App attachment projection was loaded before publication. Invalidate
            // it before returning so the newly pinned candidate is not hidden behind
            // a same-App cache hit.
            this.state.policies.appDetail.value = null;
            this.state.policies.pendingFirstAttachment = null;
            const protectedAppID = this.state.route.policyAppID;
            if (protectedAppID)
                this.navigateApp({ appID: protectedAppID, appSubpage: 'access-policies', creatingApp: false });
            else
                this.navigatePolicy({ policyView: 'library', policyAppID: undefined, policyID: undefined, policyMode: 'list', policyFirstAttachment: false });
            return;
        }
        SectionUI.showToast(`Published Policy Version v${published.data.version}. Attachments remain pinned until explicitly upgraded.`, 'success');
        this.state.policies.library.value = null;
        // Version publication can make a pinned Attachment upgradeable. Clear the
        // projection so returning to the App reads its current update status.
        this.state.policies.appDetail.value = null;
        this.render();
    }
    async openPolicyAddMenu(appID) {
        await this.loadPolicyLibrary();
        const options = this.state.policies.library.value || [];
        const select = options.filter(item => item.latest_published_version).map(item => `<option value="${escapeHTML(item.policy.id)}">${escapeHTML(item.policy.name)} — v${item.latest_published_version}</option>`).join('');
        SectionUI.showModal(`
      <div class="section-modal-head">
        <h3 class="section-modal-title">Attach policy</h3>
        <button type="button" class="section-modal-close" data-section-action="close-modal" aria-label="Close dialog">&times;</button>
      </div>
      <form class="section-modal-form" data-edge-access-v2-policy-attach="true">
        <div class="section-modal-body section-modal-stack-body">
          <input type="hidden" name="protected_app_id" value="${escapeHTML(appID)}">
          <div class="section-form-group">
            <label class="section-form-label" for="edge-access-v2-attach-policy-id">Policy</label>
            <select id="edge-access-v2-attach-policy-id" class="section-input w-100" name="policy_id">
              <option value="">Select a published policy</option>${select}
            </select>
          </div>
          <div class="section-panel-soft section-panel-soft--stacked">
            <div class="section-form-label">Where should this policy apply?</div>
            <p class="section-modal-note">Limit this policy to a path. Leave Methods blank to match every method.</p>
            <div class="grid-2">
              <div class="section-form-group">
                <label class="section-form-label" for="edge-access-v2-attach-path">Path</label>
                <input id="edge-access-v2-attach-path" class="section-input w-100" name="path" value="/*">
              </div>
              <div class="section-form-group">
                <label class="section-form-label" for="edge-access-v2-attach-methods">Methods <span class="text-note text-11">Optional</span></label>
                <input id="edge-access-v2-attach-methods" class="section-input w-100" name="methods" placeholder="All methods">
              </div>
            </div>
          </div>
        </div>
        <div class="section-modal-footer">
          <button class="operator-btn operator-btn-secondary" type="button" data-section-action="close-modal">Cancel</button>
          <button class="operator-btn operator-btn-primary" type="button" data-edge-access-v2-action="policy-attach-save">Attach policy</button>
        </div>
      </form>
    `, { panelClass: 'modal-content section-modal-panel-md flow-operator-modal' });
    }
    async saveExistingPolicyAttachment(target) {
        const form = target.closest('form[data-edge-access-v2-policy-attach]');
        if (!form)
            return;
        const policyID = this.formValue(form, 'policy_id');
        const appID = this.formValue(form, 'protected_app_id');
        if (!policyID || !appID) {
            this.showIdentityError('Choose a published Policy.');
            return;
        }
        const library = this.state.policies.library.value?.find(item => item.policy.id === policyID);
        if (!library?.latest_published_version) {
            this.showIdentityError('The selected Policy has no published Version.');
            return;
        }
        const result = await policiesV2Api.createAttachment({ policy_id: policyID, policy_version: library.latest_published_version, protected_app_id: appID, path: this.formValue(form, 'path') || '/*', methods: this.splitList(this.formValue(form, 'methods')).map(value => value.toUpperCase()), auth_channels: [], deployment_state: 'active', enabled: true });
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Policy could not be attached.');
            return;
        }
        SectionUI.closeModal();
        SectionUI.showToast('Policy attached as candidate configuration. Review deployment from the App.', 'success');
        this.state.policies.appDetail.value = null;
        await this.loadPolicyApp(appID, true);
    }
    async openLibraryPolicyAttach(policyID) {
        await this.loadPolicyLibrary();
        const libraryItem = this.state.policies.library.value?.find(item => item.policy.id === policyID);
        if (!libraryItem?.latest_published_version || libraryItem.policy.archived) {
            this.showIdentityError('Choose an active, published policy before attaching it.');
            return;
        }
        const appsResult = await policiesV2Api.apps();
        if (!appsResult.data) {
            this.showIdentityError(appsResult.error?.message || 'Applications could not be loaded.');
            return;
        }
        if (!appsResult.data.apps.length) {
            this.showIdentityError('Create an Application before attaching a Policy.');
            return;
        }
        const appOptions = appsResult.data.apps.map(app => {
            const address = app.public_addresses[0] || app.route_id;
            return `<option value="${escapeHTML(app.id)}">${escapeHTML(app.name)}${address ? ` — ${escapeHTML(address)}` : ''}</option>`;
        }).join('');
        SectionUI.showModal(`
      <div class="section-modal-head">
        <div>
          <h3 class="section-modal-title">Attach policy</h3>
          <p class="section-modal-sub">Attach <strong>${escapeHTML(libraryItem.policy.name)}</strong> v${libraryItem.latest_published_version} to an application.</p>
        </div>
        <button type="button" class="section-modal-close" data-section-action="close-modal" aria-label="Close dialog">&times;</button>
      </div>
      <form class="section-modal-form" data-edge-access-v2-library-policy-attach="true">
        <div class="section-modal-body section-modal-stack-body">
          <input type="hidden" name="policy_id" value="${escapeHTML(policyID)}">
          <input type="hidden" name="policy_version" value="${libraryItem.latest_published_version}">
          <div class="section-form-group">
            <label class="section-form-label" for="edge-access-v2-library-attach-app">Application</label>
            <select id="edge-access-v2-library-attach-app" class="section-input w-100" name="protected_app_id">${appOptions}</select>
          </div>
          <p class="edge-access-v2-field-help">The policy will initially match all paths, methods, and authentication channels. You can narrow it later from the Application.</p>
        </div>
        <div class="section-modal-footer">
          <button class="operator-btn operator-btn-secondary" type="button" data-section-action="close-modal">Cancel</button>
          <button class="operator-btn operator-btn-primary" type="button" data-edge-access-v2-action="policy-library-attach-save">Attach policy</button>
        </div>
      </form>
    `, { panelClass: 'modal-content section-modal-panel-md flow-operator-modal' });
    }
    async saveLibraryPolicyAttachment(target) {
        const form = target.closest('form[data-edge-access-v2-library-policy-attach]');
        if (!form)
            return;
        const policyID = this.formValue(form, 'policy_id');
        const appID = this.formValue(form, 'protected_app_id');
        const policyVersion = Number(this.formValue(form, 'policy_version'));
        if (!policyID || !appID || !Number.isInteger(policyVersion) || policyVersion < 1) {
            this.showIdentityError('Choose an Application and a published Policy Version.');
            return;
        }
        const authChannels = Array.from(form.elements.namedItem('auth_channels')?.selectedOptions || []).map(option => option.value).filter((value) => value === 'oidc' || value === 'jwt' || value === 'api_key' || value === 'mtls');
        const result = await policiesV2Api.createAttachment({ policy_id: policyID, policy_version: policyVersion, protected_app_id: appID, path: this.formValue(form, 'path') || '/*', methods: this.splitList(this.formValue(form, 'methods')).map(value => value.toUpperCase()), auth_channels: authChannels, deployment_state: 'active', enabled: true });
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Policy could not be attached.');
            return;
        }
        SectionUI.closeModal();
        SectionUI.showToast('Policy attached as candidate configuration. Review deployment from the Application.', 'success');
        this.state.policies.library.value = null;
        this.state.policies.appDetail.value = null;
        await this.loadPolicyLibrary(true);
    }
    attachment(id) { return this.state.policies.appDetail.value?.attachments.find(item => item.attachment.id === id)?.attachment; }
    currentPolicyAppID() {
        if (this.state.route.policyAppID)
            return this.state.route.policyAppID;
        return this.state.route.appSubpage === 'access-policies' ? this.state.route.appID : undefined;
    }
    openAttachmentEditor(id) {
        const attachment = this.attachment(id);
        if (!attachment) {
            this.showIdentityError('Attachment details are no longer available. Reload and try again.');
            return;
        }
        SectionUI.showModal(`
      <div class="section-modal-head">
        <div>
          <h3 class="section-modal-title">Change attachment</h3>
          <p class="section-modal-sub">Update where this policy applies before the next deployment.</p>
        </div>
        <button type="button" class="section-modal-close" data-section-action="close-modal" aria-label="Close dialog">&times;</button>
      </div>
      <form class="section-modal-form" data-edge-access-v2-attachment-form="true">
        <div class="section-modal-body section-modal-stack-body">
          <div class="section-panel-soft section-panel-soft--stacked">
            <div class="section-form-label">Attachment scope</div>
            <div class="grid-2">
              <div class="section-form-group">
                <label class="section-form-label" for="edge-access-v2-change-attachment-path">Path</label>
                <input id="edge-access-v2-change-attachment-path" class="section-input w-100" name="path" value="${escapeHTML(attachment.path)}">
              </div>
              <div class="section-form-group">
                <label class="section-form-label" for="edge-access-v2-change-attachment-methods">Methods <span class="text-note text-11">Optional</span></label>
                <input id="edge-access-v2-change-attachment-methods" class="section-input w-100" name="methods" value="${escapeHTML(attachment.methods.join(', '))}" placeholder="All methods">
              </div>
            </div>
          </div>
          <label class="edge-access-v2-inline-check">
            <input type="checkbox" name="enabled"${attachment.enabled ? ' checked' : ''}>
            <span><strong>Enable for the next deployment</strong><small>Keep this attachment active when the Application is deployed.</small></span>
          </label>
        </div>
        <div class="section-modal-footer">
          <button class="operator-btn operator-btn-secondary" type="button" data-section-action="close-modal">Cancel</button>
          <button class="operator-btn operator-btn-primary" type="button" data-edge-access-v2-action="policy-attachment-save" data-edge-access-v2-attachment-id="${escapeHTML(id)}">Save Changes</button>
        </div>
      </form>
    `, { panelClass: 'modal-content section-modal-panel-md flow-operator-modal' });
    }
    async saveAttachmentScope(target, id) {
        const attachment = this.attachment(id);
        const form = target.closest('form[data-edge-access-v2-attachment-form]');
        if (!attachment || !form)
            return;
        const enabled = form.elements.namedItem('enabled')?.checked === true;
        const result = await policiesV2Api.updateAttachment(id, { revision: attachment.revision, path: this.formValue(form, 'path') || '/*', methods: this.splitList(this.formValue(form, 'methods')).map(value => value.toUpperCase()), auth_channels: attachment.auth_channels, deployment_state: enabled ? 'active' : 'disabled' });
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Attachment scope could not be saved.');
            return;
        }
        SectionUI.closeModal();
        SectionUI.showToast('Attachment candidate updated. Deployment review is required.', 'success');
        const appID = this.currentPolicyAppID();
        if (appID)
            await this.loadPolicyApp(appID, true);
    }
    async upgradeAttachment(id) {
        const attachment = this.attachment(id);
        if (!attachment)
            return;
        const versions = await policiesV2Api.versions(attachment.policy_id);
        if (!versions.data) {
            this.showIdentityError(versions.error?.message || 'Policy Versions could not be loaded.');
            return;
        }
        const latest = versions.data.filter(version => version.state === 'published').sort((left, right) => right.version - left.version)[0];
        if (!latest || latest.version <= attachment.policy_version) {
            this.showIdentityError('No newer published Version is available.');
            return;
        }
        SectionUI.openConfirmModal('Upgrade Attachment', `Pin this Attachment to <strong>v${latest.version}</strong>? It becomes candidate configuration and needs App deployment review.`, 'Upgrade Attachment', 'var(--primary)', async () => {
            const result = await policiesV2Api.upgradeAttachment(id, attachment.revision, latest.version);
            if (!result.data) {
                this.showIdentityError(result.error?.message || 'Attachment could not be upgraded.');
                return;
            }
            SectionUI.closeModal();
            SectionUI.showToast('Attachment upgrade is ready for deployment review.', 'success');
            const appID = this.currentPolicyAppID();
            if (appID)
                await this.loadPolicyApp(appID, true);
        });
    }
    confirmDetachAttachment(id) {
        const attachment = this.attachment(id);
        if (!attachment)
            return;
        SectionUI.openConfirmModal('Detach Policy', 'Detach this Policy from the App? The reusable Policy and its Version history remain available.', 'Detach', 'danger', async () => {
            const result = await policiesV2Api.detachAttachment(id, attachment.revision);
            if (!result.data) {
                this.showIdentityError(result.error?.message || 'Attachment could not be detached.');
                return;
            }
            SectionUI.closeModal();
            SectionUI.showToast('Policy detached. Review App deployment before traffic changes.', 'success');
            const appID = this.currentPolicyAppID();
            if (appID)
                await this.loadPolicyApp(appID, true);
        });
    }
    confirmArchivePolicy(id) {
        const policy = this.findPolicyForArchive(id);
        if (!policy) {
            this.showIdentityError('Policy details are no longer available. Reload and try again.');
            return;
        }
        SectionUI.openConfirmModal('Archive policy', 'Archive this reusable Policy? Active Attachments must be detached first, and immutable Version history will remain available.', 'Archive policy', 'danger', async () => {
            const result = await policiesV2Api.updatePolicy(id, { ...policy, archived: true });
            if (!result.data) {
                this.showIdentityError(result.error?.message || 'Policy could not be archived.');
                return;
            }
            SectionUI.closeModal();
            this.state.policies.policy.value = this.state.policies.policy.value?.id === id ? result.data : null;
            this.state.policies.library.value = null;
            SectionUI.showToast('Policy archived.', 'success');
            this.navigatePolicy({ policyView: 'library', policyAppID: undefined, policyID: undefined, policyMode: 'list', policyFirstAttachment: false });
        });
    }
    findPolicyForArchive(id) {
        const current = this.state.policies.policy.value;
        if (current?.id === id)
            return current;
        return this.state.policies.library.value?.find(item => item.policy.id === id)?.policy || null;
    }
    async loadDecisions(force = false) {
        const resource = this.state.decisions.list;
        if (resource.loading || (!force && resource.value))
            return;
        resource.loading = true;
        resource.error = null;
        this.render();
        const filter = this.state.decisions.filter;
        const result = await policiesV2Api.decisions({ q: filter.q || undefined, result: filter.result || undefined, identity: filter.identity || undefined, channel: filter.channel || undefined, hostname: filter.hostname || undefined, policy_attachment_id: filter.attachmentID || undefined, policy_version: filter.policyVersion || undefined, from: filter.from || undefined, to: filter.to || undefined, protected_app_id: this.state.route.decisionAppID, policy_id: this.state.route.decisionPolicyID });
        resource.loading = false;
        if (result.data) {
            resource.value = result.data.decisions;
            resource.page = result.data.page;
        }
        else
            resource.error = result.error?.message || 'Decisions could not be loaded.';
        if (this.state.route.destination === 'decisions')
            this.render();
    }
    applyDecisionFilters(target) {
        const form = target.closest('form[data-edge-access-v2-decision-filters]');
        if (!form)
            return;
        const data = new FormData(form);
        const filter = { q: String(data.get('q') || '').trim(), result: String(data.get('result') || '').trim(), identity: String(data.get('identity') || '').trim(), channel: String(data.get('channel') || '').trim(), hostname: String(data.get('hostname') || '').trim(), attachmentID: String(data.get('policy_attachment_id') || '').trim(), policyVersion: String(data.get('policy_version') || '').trim(), from: String(data.get('from') || '').trim(), to: String(data.get('to') || '').trim() };
        this.navigateDecisions({ appID: this.state.route.decisionAppID, policyID: this.state.route.decisionPolicyID, filter });
    }
    async loadDecisionDetail(id) {
        const resource = this.state.decisions.detail;
        resource.loading = true;
        resource.error = null;
        this.render();
        const result = await policiesV2Api.decision(id);
        resource.loading = false;
        if (result.data)
            resource.value = result.data;
        else
            resource.error = result.error?.message || 'Decision explanation could not be loaded.';
        if (this.state.route.destination === 'decisions')
            this.render();
    }
    applyAppFilters(target) {
        const form = target.closest('form[data-edge-access-v2-app-filters]');
        if (!form)
            return;
        const data = new FormData(form);
        this.state.apps.filter = {
            q: String(data.get('q') || '').trim(), status: String(data.get('status') || '').trim(),
            trustChannel: String(data.get('trust_channel') || '').trim(), noActiveAllow: data.get('no_active_allow') === 'on'
        };
        this.state.apps.catalog.value = null;
        void this.loadAppCatalog(true);
    }
    trustSourcesFromForm(form) {
        const oidcProviderID = this.formValue(form, 'oidc_provider_id');
        const browserToggle = form.querySelector('input[name="trust_browser"]');
        const jwtToggle = form.querySelector('input[name="trust_jwt"]');
        const browserEnabled = browserToggle ? browserToggle.checked : Boolean(oidcProviderID);
        const jwtEnabled = jwtToggle ? jwtToggle.checked : Boolean(this.formValue(form, 'jwt_issuer_url') || this.formValue(form, 'jwt_audience'));
        const jwtProviderID = this.formValue(form, 'jwt_provider_id');
        const selectedJWTProvider = jwtProviderID ? this.findProvider(jwtProviderID) : undefined;
        let jwtIssuerURL = this.formValue(form, 'jwt_issuer_url');
        let jwtAudience = this.formValue(form, 'jwt_audience');
        if (browserEnabled && !oidcProviderID) {
            this.showIdentityError('Select an OIDC provider for browser sign-in.');
            return null;
        }
        if (browserEnabled && this.state.identity.providers.value && (!this.findProvider(oidcProviderID) || this.findProvider(oidcProviderID)?.type !== 'oidc')) {
            this.showIdentityError('Select a valid OIDC provider for browser sign-in.');
            return null;
        }
        if (jwtEnabled && jwtProviderID) {
            if (!selectedJWTProvider || selectedJWTProvider.type !== 'jwt') {
                this.showIdentityError('Select a valid JWT issuer.');
                return null;
            }
            jwtIssuerURL = selectedJWTProvider.issuer;
            jwtAudience = selectedJWTProvider.audience || '';
        }
        if (jwtEnabled && (!jwtIssuerURL || !jwtAudience)) {
            this.showIdentityError(jwtProviderID ? 'The selected JWT issuer needs a configured audience.' : 'Select a JWT issuer for bearer-token access.');
            return null;
        }
        const sources = [];
        if (browserEnabled)
            sources.push({ channel: 'browser_session', reference_mode: 'explicit', oidc_provider_id: oidcProviderID });
        if (jwtEnabled)
            sources.push({ channel: 'bearer_jwt', reference_mode: 'explicit', jwt_issuer_url: jwtIssuerURL, jwt_audience: jwtAudience });
        const apiKey = form.elements.namedItem('api_key');
        const mtls = form.elements.namedItem('mtls');
        if (apiKey?.checked)
            sources.push({ channel: 'api_key' });
        if (mtls?.checked)
            sources.push({ channel: 'mtls' });
        return sources;
    }
    appInputFromForm(form, deploymentState, app) {
        const sources = this.trustSourcesFromForm(form);
        if (!sources)
            return null;
        const name = this.formValue(form, 'name') || app?.protected_app.name || '';
        const routeID = this.formValue(form, 'route_id') || app?.protected_app.route_id || '';
        const usesRouteShortcut = this.formValue(form, 'route_mode') === 'new';
        if (!name) {
            this.showIdentityError('An App name is required.');
            return null;
        }
        if (!routeID && !usesRouteShortcut) {
            this.showIdentityError('Select a canonical Route.');
            return null;
        }
        return {
            revision: app?.protected_app.revision, name, route_id: routeID || undefined, auth_method: app?.protected_app.auth_method,
            default_action: app?.protected_app.default_action || 'deny', authorization_mode: 'policy_attachments', deployment_state: deploymentState, accepted_trust_sources: sources
        };
    }
    async saveNewApp(target, deployAfterSave) {
        const form = target.closest('form[data-edge-access-v2-app-form="new"]');
        if (!form)
            return;
        const mode = this.formValue(form, 'route_mode');
        const input = this.appInputFromForm(form, 'draft');
        if (!input)
            return;
        let result;
        if (mode === 'new') {
            const routeName = this.formValue(form, 'route_name');
            const host = this.formValue(form, 'route_host');
            const path = this.formValue(form, 'route_path') || '/*';
            const origin = this.formValue(form, 'origin_url');
            if (!routeName || !host || !origin) {
                this.showIdentityError('Route name, hostname, and origin are required for the shortcut.');
                return;
            }
            result = await appsV2Api.createWithRoute({ name: routeName, hosts: [host], paths: [path], origin_url: origin, priority: Number(this.formValue(form, 'route_priority') || '100'), enabled: false }, { ...input, route_id: undefined });
        }
        else
            result = await appsV2Api.create(input);
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'App draft could not be saved.');
            return;
        }
        SectionUI.showToast('Application saved.', 'success');
        this.state.apps.catalog.value = null;
        this.navigateApp({ appID: result.data.id, appSubpage: 'overview', creatingApp: false });
        if (deployAfterSave)
            await this.deployApp(result.data.id);
    }
    async saveAppTrustSources(target, id) {
        const form = target.closest('form[data-edge-access-v2-app-form="trust"]');
        const app = this.state.apps.detail.value;
        if (!form || !app || app.protected_app.id !== id)
            return;
        const input = this.appInputFromForm(form, app.protected_app.deployment_state, app);
        if (!input)
            return;
        const result = await appsV2Api.update(id, input);
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Trust sources could not be saved.');
            return;
        }
        SectionUI.showToast('Trust sources saved. Any candidate change requires a new reviewed deployment.', 'success');
        this.state.apps.detail.value = null;
        this.state.apps.catalog.value = null;
        await this.loadAppDetail(id, true);
    }
    async deployApp(id) {
        const impact = await appsV2Api.impact(id);
        if (!impact.data) {
            this.showIdentityError(impact.error?.message || 'Impact review could not be created.');
            return;
        }
        if (!impact.data.valid) {
            this.showIdentityError(impact.data.issues.join('; ') || 'The policy candidate is not deployable.');
            return;
        }
        const deployReviewedCandidate = async () => {
            SectionUI.openConfirmModal('Review policy deployment', "Confirm that you reviewed this candidate's policy impact before deployment. Candidate changes invalidate this confirmation.", 'Acknowledge and deploy', 'var(--warning)', async () => {
                const deployment = await appsV2Api.deploy(id, impact.data.candidate_fingerprint, impact.data.confirmation_token);
                if (!deployment.data) {
                    this.showIdentityError(deployment.error?.message || 'App deployment could not be completed. Enable the Route in Routing first.');
                    return;
                }
                SectionUI.closeModal();
                SectionUI.showToast(deployment.data.access_health.state === 'deny_only' ? 'App deployed as Deny-only. Add an Allow policy in Access policies before users can enter.' : 'App deployment completed.', 'success');
                this.state.apps.detail.value = null;
                this.state.apps.catalog.value = null;
                await this.loadAppDetail(id, true);
            });
        };
        if (impact.data.broad_public_bypass) {
            SectionUI.openConfirmModal('Confirm broad Public bypass', 'This candidate allows unauthenticated access across the App. Confirm this exact impact review before deployment; any candidate change requires a new confirmation.', 'Confirm Public bypass', 'var(--danger)', async () => {
                SectionUI.closeModal();
                await deployReviewedCandidate();
            });
            return;
        }
        await deployReviewedCandidate();
    }
    confirmDeleteApp(id) {
        const app = this.state.apps.detail.value;
        if (!app || app.protected_app.id !== id)
            return;
        if (app.protected_app.deployment_state !== 'disabled') {
            this.showIdentityError('Disable the App before deleting it.');
            return;
        }
        SectionUI.openConfirmModal('Delete App', `Delete <strong>${escapeHTML(app.protected_app.name)}</strong>? App-scoped candidate attachments and runtime snapshots are removed. The canonical Route, reusable Policies, and audit evidence are preserved.`, 'Delete App', 'danger', async () => {
            const result = await appsV2Api.delete(id, app.protected_app.revision);
            if (!result.data) {
                this.showIdentityError(result.error?.message || 'App could not be deleted.');
                return;
            }
            SectionUI.closeModal();
            SectionUI.showToast('App deleted. Its Route was preserved in Routing.', 'success');
            this.state.apps.catalog.value = null;
            this.navigateApp({ appID: undefined, appSubpage: 'overview', creatingApp: false });
        });
    }
    confirmRollbackDeployment(id, deploymentID) {
        const app = this.state.apps.detail.value;
        if (!app || app.protected_app.id !== id || app.access_summary.active_deployment_id !== deploymentID) {
            this.showIdentityError('The active deployment changed. Reload the App before rolling back.');
            return;
        }
        SectionUI.openConfirmModal('Rollback policy deployment', 'Restore the prior immutable policy deployment for this App. Candidate policy changes and historical evidence are retained.', 'Rollback to prior deployment', 'var(--warning)', async () => {
            const result = await appsV2Api.rollback(id, deploymentID);
            if (!result.data) {
                this.showIdentityError(result.error?.message || 'App rollback could not be completed.');
                return;
            }
            SectionUI.closeModal();
            SectionUI.showToast('App rolled back to its prior policy deployment.', 'success');
            this.state.apps.detail.value = null;
            this.state.apps.catalog.value = null;
            await this.loadAppDetail(id, true);
        });
    }
    confirmDisableApp(id) {
        const app = this.state.apps.detail.value;
        if (!app || app.protected_app.id !== id)
            return;
        SectionUI.openConfirmModal('Disable App', `Disable <strong>${escapeHTML(app.protected_app.name)}</strong>? Edge Access will stop using this App configuration, while the Route and reusable Policies remain unchanged.`, 'Disable App', 'var(--warning)', async () => {
            const input = {
                revision: app.protected_app.revision, name: app.protected_app.name, route_id: app.protected_app.route_id, auth_method: app.protected_app.auth_method,
                default_action: app.protected_app.default_action, authorization_mode: 'policy_attachments', deployment_state: 'disabled', accepted_trust_sources: app.protected_app.accepted_trust_sources
            };
            const result = await appsV2Api.update(id, input);
            if (!result.data) {
                this.showIdentityError(result.error?.message || 'App could not be disabled.');
                return;
            }
            SectionUI.closeModal();
            SectionUI.showToast('App disabled.', 'success');
            this.state.apps.detail.value = null;
            this.state.apps.catalog.value = null;
            await this.loadAppDetail(id, true);
        });
    }
    findProvider(providerID) {
        return this.state.identity.providers.value?.find(provider => provider.provider_id === providerID);
    }
    async loadRoles(force = false) {
        const resource = this.state.roles.catalog;
        if (resource.loading || (!force && resource.value))
            return;
        resource.loading = true;
        resource.error = null;
        this.render();
        const result = await rolesV2Api.list();
        resource.loading = false;
        if (result.data)
            resource.value = result.data;
        else
            resource.error = result.error?.message || 'Roles could not be loaded.';
        if (['roles', 'identity', 'policies'].includes(this.state.route.destination))
            this.render();
    }
    async saveRole(form) {
        if (!form.reportValidity())
            return;
        const previousID = form.dataset.edgeAccessV2RoleId;
        const existing = previousID ? this.state.roles.catalog.value?.find(role => role.id === previousID) : undefined;
        if (existing?.is_builtin) {
            this.showIdentityError('System roles are protected and cannot be edited.');
            return;
        }
        const input = {
            id: existing?.id || this.formValue(form, 'id'),
            name: this.formValue(form, 'name'),
            description: this.formValue(form, 'description'),
            permissions: this.formValues(form, 'permissions'),
            inherits: this.formValues(form, 'inherits'),
            is_builtin: false
        };
        if (!input.id || !input.name) {
            this.showIdentityError('Role ID and display name are required.');
            return;
        }
        if (!input.permissions.length) {
            this.showIdentityError('Add at least one permission.');
            return;
        }
        if (input.inherits.includes(input.id)) {
            this.showIdentityError('A role cannot inherit itself.');
            return;
        }
        const rolesByID = new Map((this.state.roles.catalog.value || []).map(role => [role.id, role]));
        const reachesRole = (candidateID, visited = new Set()) => {
            if (candidateID === input.id)
                return true;
            if (visited.has(candidateID))
                return false;
            visited.add(candidateID);
            return (rolesByID.get(candidateID)?.inherits || []).some(parentID => reachesRole(parentID, visited));
        };
        if (input.inherits.some(parentID => reachesRole(parentID))) {
            this.showIdentityError('This inheritance selection would create a role cycle.');
            return;
        }
        const result = existing
            ? await rolesV2Api.update(existing.id, input)
            : await rolesV2Api.create(input);
        if (!result.data) {
            this.showIdentityError(result.error?.message || `Role could not be ${existing ? 'updated' : 'created'}.`);
            return;
        }
        await this.loadRoles(true);
        this.navigateRole('list');
        SectionUI.showToast(existing ? 'Role updated.' : 'Role created.', 'success');
    }
    confirmDeleteRole(roleID) {
        const role = this.state.roles.catalog.value?.find(item => item.id === roleID);
        if (!role) {
            this.showIdentityError('Role details are no longer available. Reload and try again.');
            return;
        }
        if (role.is_builtin) {
            this.showIdentityError('System roles are protected and cannot be deleted.');
            return;
        }
        SectionUI.openConfirmModal('Delete role', `Delete <strong>${escapeHTML(role.name)}</strong>? Identities or policies that still reference <span class="text-mono">${escapeHTML(role.id)}</span> may stop matching.`, 'Delete role', 'danger', async () => {
            const result = await rolesV2Api.remove(role.id);
            if (!result.data) {
                this.showIdentityError(result.error?.message || 'Role could not be deleted.');
                return;
            }
            SectionUI.closeModal();
            await this.loadRoles(true);
            SectionUI.showToast('Role deleted.', 'success');
        });
    }
    findMapping(providerID) {
        return this.state.identity.mappings.value?.find(mapping => mapping.provider_id === providerID);
    }
    findServiceIdentity(id) {
        return this.state.identity.serviceIdentities.value?.find(identity => identity.id === id);
    }
    async loadIdentityTab(tab, force = false) {
        if (tab === 'providers') {
            const resource = this.state.identity.providers;
            if (resource.loading || (!force && resource.value))
                return;
            resource.loading = true;
            resource.error = null;
            this.render();
            const result = await identityV2Api.listProviders();
            resource.loading = false;
            if (result.data) {
                resource.value = result.data.providers;
                resource.page = result.data.page;
                this.state.identity.identityRevision = result.data.identityRevision;
            }
            else
                resource.error = result.error?.message || 'Identity providers could not be loaded.';
        }
        else if (tab === 'mappings') {
            const resource = this.state.identity.mappings;
            if (resource.loading || (!force && resource.value))
                return;
            resource.loading = true;
            resource.error = null;
            this.render();
            const result = await identityV2Api.listMappings();
            resource.loading = false;
            if (result.data) {
                resource.value = result.data.mappings;
                resource.page = result.data.page;
                this.state.identity.identityRevision = result.data.identityRevision;
            }
            else
                resource.error = result.error?.message || 'Claim mappings could not be loaded.';
        }
        else {
            const resource = this.state.identity.serviceIdentities;
            if (resource.loading || (!force && resource.value))
                return;
            resource.loading = true;
            resource.error = null;
            this.render();
            const result = await identityV2Api.listServiceIdentities();
            resource.loading = false;
            if (result.data) {
                resource.value = result.data.credentials;
                resource.page = result.data.page;
            }
            else
                resource.error = result.error?.message || 'Machine identities could not be loaded.';
        }
        if (this.state.route.destination === 'identity')
            this.render();
    }
    identityModal(title, body) {
        return `<form class="edge-access-v2-identity-form" data-edge-access-v2-identity-form="true">
      <div class="section-confirm-head"><div class="section-confirm-title-block"><h3 class="section-confirm-title">${escapeHTML(title)}</h3></div><button type="button" class="section-confirm-close" data-section-action="close-modal" aria-label="Close dialog">×</button></div>
      <div class="section-confirm-body">${body}</div>
      <div class="section-confirm-footer"><button type="button" class="btn btn-outline" data-section-action="close-modal">Cancel</button><button type="submit" class="btn btn-primary">Save</button></div>
    </form>`;
    }
    input(label, name, value = '', options = {}) {
        const type = options.type || 'text';
        return `<label class="edge-access-v2-field"><span class="edge-access-v2-field-label">${escapeHTML(label)}</span><input class="edge-access-v2-field-input" name="${escapeHTML(name)}" type="${escapeHTML(type)}" value="${escapeHTML(value)}"${options.required ? ' required' : ''}${options.readonly ? ' readonly' : ''}>${options.hint ? `<span class="edge-access-v2-field-hint">${escapeHTML(options.hint)}</span>` : ''}</label>`;
    }
    textArea(label, name, value = '', options = {}) {
        return `<label class="edge-access-v2-field"><span class="edge-access-v2-field-label">${escapeHTML(label)}</span><textarea class="edge-access-v2-field-input" name="${escapeHTML(name)}" rows="5"${options.required ? ' required' : ''}${options.readonly ? ' readonly' : ''}>${escapeHTML(value)}</textarea>${options.hint ? `<span class="edge-access-v2-field-hint">${escapeHTML(options.hint)}</span>` : ''}</label>`;
    }
    formValue(form, name) {
        return String(new FormData(form).get(name) || '').trim();
    }
    formValues(form, name) {
        return new FormData(form).getAll(name)
            .flatMap(value => this.splitList(String(value)))
            .filter((value, index, values) => values.indexOf(value) === index);
    }
    listValue(value) {
        return value.split(',').map(item => item.trim()).filter(Boolean);
    }
    showIdentityError(message) {
        SectionUI.showToast(message, 'error');
    }
    async refreshIdentity(tab) {
        const resource = tab === 'providers' ? this.state.identity.providers : tab === 'mappings' ? this.state.identity.mappings : this.state.identity.serviceIdentities;
        resource.value = null;
        await this.loadIdentityTab(tab, true);
    }
    async saveProvider(form, previous) {
        if (!form.reportValidity())
            return;
        const type = previous?.type || this.formValue(form, 'type');
        const input = {
            identity_revision: this.state.identity.identityRevision,
            provider_id: previous?.provider_id || this.formValue(form, 'provider_id'), type,
            name: this.formValue(form, 'name'), issuer: this.formValue(form, 'issuer'),
            client_id: this.formValue(form, 'client_id') || undefined, client_secret: this.formValue(form, 'client_secret') || undefined,
            redirect_url: this.formValue(form, 'redirect_url') || undefined, scopes: this.listValue(this.formValue(form, 'scopes')),
            jwks_url: this.formValue(form, 'jwks_url') || undefined, audience: this.formValue(form, 'audience') || undefined,
            algorithms: this.listValue(this.formValue(form, 'algorithms')), secret_key: this.formValue(form, 'secret_key') || undefined
        };
        const result = previous ? await identityV2Api.updateProvider(previous.provider_id, input) : await identityV2Api.createProvider(input);
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Identity provider could not be saved.');
            return;
        }
        this.state.identity.identityRevision = result.data.identityRevision;
        SectionUI.showToast('Identity provider saved.', 'success');
        this.state.identity.mappings.value = null;
        this.state.identity.providers.value = null;
        this.navigateIdentityProvider('list');
    }
    async validateProvider(providerID) {
        const provider = this.findProvider(providerID);
        if (!provider) {
            this.showIdentityError('Provider details are no longer available. Reload and try again.');
            return;
        }
        const result = await identityV2Api.validateProvider(providerID, this.state.identity.identityRevision);
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Provider validation could not be completed.');
            return;
        }
        this.state.identity.identityRevision = result.data.identityRevision;
        const checks = result.data.provider.validation.checks.map(check => `<li><strong>${escapeHTML(check.label)}:</strong> ${escapeHTML(check.message)}</li>`).join('') || '<li>No validation details were returned.</li>';
        SectionUI.showModal(`<div class="section-confirm-head"><div class="section-confirm-title-block"><h3 class="section-confirm-title">Validation: ${escapeHTML(result.data.provider.name)}</h3></div><button type="button" class="section-confirm-close" data-section-action="close-modal" aria-label="Close dialog">×</button></div><div class="section-confirm-body"><p class="section-confirm-message">${escapeHTML(result.data.provider.validation.status)}</p><ul>${checks}</ul></div><div class="section-confirm-footer"><button type="button" class="btn btn-primary" data-section-action="close-modal">Done</button></div>`, { panelClass: 'modal-content' });
        await this.refreshIdentity('providers');
    }
    async confirmProviderDelete(providerID) {
        const provider = this.findProvider(providerID);
        if (!provider) {
            this.showIdentityError('Provider details are no longer available. Reload and try again.');
            return;
        }
        const apps = provider.usage.protected_app_ids.length ? `<ul>${provider.usage.protected_app_ids.map(id => `<li>${escapeHTML(id)}</li>`).join('')}</ul>` : '<p>No explicit App dependency is currently listed.</p>';
        SectionUI.openConfirmModal('Delete identity provider', `Deleting <strong>${escapeHTML(provider.name)}</strong> is blocked if Apps still depend on it. Affected Apps:${apps}`, 'Delete provider', 'danger', async () => {
            const result = await identityV2Api.deleteProvider(providerID, this.state.identity.identityRevision);
            if (!result.data) {
                this.showIdentityError(result.error?.message || 'Provider could not be deleted.');
                return;
            }
            this.state.identity.identityRevision = result.data.identityRevision;
            SectionUI.closeModal();
            SectionUI.showToast('Identity provider deleted.', 'success');
            this.state.identity.mappings.value = null;
            await this.refreshIdentity('providers');
        });
    }
    openMappingEditor(record) {
        if (!record) {
            this.showIdentityError('Mapping details are no longer available. Reload and try again.');
            return;
        }
        const mapping = record.mapping;
        const body = `
      <p class="section-confirm-message">${escapeHTML(record.provider_name)} maps verified claims to the shared Edge identity. Use synthetic JSON only—never a real bearer token.</p>
      ${this.input('Subject claim', 'subject', mapping.subject, { required: true })}
      ${this.input('Email claim', 'email', mapping.email, { required: true })}
      ${this.input('Roles claim', 'roles', mapping.roles, { required: true })}
      ${this.input('Groups claim', 'groups', mapping.groups, { required: true })}
      ${this.textArea('Synthetic claims JSON', 'claims', '{}', { hint: 'Use non-production claim values only.' })}
      <div id="edge-access-v2-preview" aria-live="polite"></div>
      <button type="button" class="btn btn-outline" data-edge-access-v2-dialog-action="preview-mapping">Preview identity</button>`;
        SectionUI.showModal(this.identityModal(`Edit mapping: ${record.provider_name}`, body), { panelClass: 'modal-content' });
        const form = AdminDOM.query('[data-edge-access-v2-identity-form="true"]');
        if (!form)
            return;
        form.addEventListener('submit', event => { event.preventDefault(); void this.saveMapping(form, record.provider_id); });
        form.querySelector('[data-edge-access-v2-dialog-action="preview-mapping"]')?.addEventListener('click', () => { void this.previewMapping(form, record.provider_id); });
    }
    async saveMapping(form, providerID) {
        const mapping = { subject: this.formValue(form, 'subject'), email: this.formValue(form, 'email'), roles: this.formValue(form, 'roles'), groups: this.formValue(form, 'groups') };
        const result = await identityV2Api.updateMapping(providerID, this.state.identity.identityRevision, mapping);
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Mapping could not be saved.');
            return;
        }
        this.state.identity.identityRevision = result.data.identityRevision;
        SectionUI.closeModal();
        SectionUI.showToast('Claim mapping saved.', 'success');
        await this.refreshIdentity('mappings');
    }
    async previewMapping(form, providerID) {
        let claims;
        try {
            const parsed = JSON.parse(this.formValue(form, 'claims'));
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
                throw new Error('invalid claims');
            claims = parsed;
        }
        catch {
            this.showIdentityError('Synthetic claims must be a JSON object.');
            return;
        }
        const result = await identityV2Api.previewMapping(providerID, claims);
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Identity preview could not be generated.');
            return;
        }
        const target = form.querySelector('#edge-access-v2-preview');
        if (!target)
            return;
        const preview = result.data;
        target.textContent = `Subject: ${preview.subject}\nEmail: ${preview.email}\nRoles: ${preview.roles.join(', ') || '—'}\nGroups: ${preview.groups.join(', ') || '—'}${preview.diagnostics.length ? `\nWarnings: ${preview.diagnostics.map(item => `${item.field}: ${item.message}`).join('; ')}` : ''}`;
    }
    openServiceIdentityEditor(identity) {
        const editing = Boolean(identity);
        const type = identity?.type || 'api_key';
        const typeLabel = type === 'api_key' ? 'API key' : 'mTLS certificate';
        const body = `
      <label class="edge-access-v2-field"><span class="edge-access-v2-field-label">Identity type</span><input class="edge-access-v2-field-input" value="${typeLabel}" readonly><input type="hidden" name="type" value="${type}"></label>
      ${this.input('Name', 'name', identity?.name || '', { required: true })}
      ${renderManagedRolePicker(this.state.roles.catalog, identity?.roles || [], { name: 'roles', label: 'Assigned roles' })}
      ${this.input('Groups', 'groups', identity?.groups.join(', ') || '', { hint: 'Comma-separated.' })}
      ${this.input('Expires in', 'expires_in', '', { hint: 'Optional duration.' })}
      <div data-edge-access-v2-service-type="mtls"${type === 'mtls' ? '' : ' hidden'}>${this.textArea('Certificate PEM', 'certificate_pem', '', { hint: editing ? 'Leave empty to retain the existing certificate.' : 'Required for a new mTLS identity.' })}</div>`;
        SectionUI.showModal(this.identityModal(editing ? 'Edit machine identity' : `Create ${typeLabel}`, body), { panelClass: 'modal-content' });
        const form = AdminDOM.query('[data-edge-access-v2-identity-form="true"]');
        if (!form)
            return;
        form.addEventListener('submit', event => { event.preventDefault(); void this.saveServiceIdentity(form, identity); });
    }
    async saveServiceIdentity(form, previous, returnToInventory = false) {
        const name = this.formValue(form, 'name');
        const roles = this.formValues(form, 'roles');
        const groups = this.listValue(this.formValue(form, 'groups'));
        const expiresIn = this.formValue(form, 'expires_in') || undefined;
        const certificatePEM = this.formValue(form, 'certificate_pem') || undefined;
        const result = previous
            ? await identityV2Api.updateServiceIdentity(previous.id, { revision: previous.revision, name, roles, groups, expires_in: expiresIn, certificate_pem: certificatePEM })
            : await identityV2Api.createServiceIdentity({ type: this.formValue(form, 'type'), name, roles, groups, expires_in: expiresIn, certificate_pem: certificatePEM });
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Machine identity could not be saved.');
            return;
        }
        if (!returnToInventory)
            SectionUI.closeModal();
        await this.refreshIdentity('service-identities');
        if (returnToInventory)
            this.navigateIdentityProvider('list');
        if (result.data.secret)
            this.showOneTimeSecret(result.data.secret, result.data.warning || 'Save this secret now. It cannot be retrieved later.');
        else
            SectionUI.showToast('Machine identity saved.', 'success');
    }
    showOneTimeSecret(secret, warning) {
        SectionUI.showModal(`<div class="section-confirm-head"><div class="section-confirm-title-block"><h3 class="section-confirm-title">Save the secret now</h3></div></div><div class="section-confirm-body"><p class="section-confirm-message">${escapeHTML(warning)}</p>${this.textArea('Secret', 'one_time_secret', secret, { readonly: true })}</div><div class="section-confirm-footer"><button type="button" class="btn btn-primary" data-section-action="close-modal">I saved it</button></div>`, { panelClass: 'modal-content', closeOnBackdrop: false });
    }
    async showServiceIdentityUsage(id) {
        const result = await identityV2Api.getServiceIdentityUsage(id);
        if (!result.data) {
            this.showIdentityError(result.error?.message || 'Usage could not be loaded.');
            return;
        }
        const usage = result.data;
        const list = (items) => items.length ? `<ul>${items.map(item => `<li>${escapeHTML(item)}</li>`).join('')}</ul>` : '<p>None</p>';
        SectionUI.showModal(`<div class="section-confirm-head"><div class="section-confirm-title-block"><h3 class="section-confirm-title">Machine identity usage</h3></div><button type="button" class="section-confirm-close" data-section-action="close-modal" aria-label="Close dialog">×</button></div><div class="section-confirm-body"><h4>Protected Apps</h4>${list(usage.protected_app_ids)}<h4>Policy versions</h4>${list(usage.policy_versions)}<h4>Active deployments</h4>${list(usage.policy_deployment_ids)}</div><div class="section-confirm-footer"><button type="button" class="btn btn-primary" data-section-action="close-modal">Done</button></div>`, { panelClass: 'modal-content' });
    }
    async confirmServiceIdentityRotate(id) {
        const identity = this.findServiceIdentity(id);
        if (!identity) {
            this.showIdentityError('Machine identity details are no longer available. Reload and try again.');
            return;
        }
        SectionUI.openConfirmModal('Rotate machine identity', `A replacement credential will be created for <strong>${escapeHTML(identity.name)}</strong>. Any new secret is shown once.`, 'Rotate identity', 'var(--primary)', async () => {
            const result = await identityV2Api.rotateServiceIdentity(id, identity.revision);
            if (!result.data) {
                this.showIdentityError(result.error?.message || 'Machine identity could not be rotated.');
                return;
            }
            SectionUI.closeModal();
            await this.refreshIdentity('service-identities');
            if (result.data.secret)
                this.showOneTimeSecret(result.data.secret, result.data.warning || 'Save this replacement secret now. It cannot be retrieved later.');
            else
                SectionUI.showToast('Machine identity rotated.', 'success');
        });
    }
    async confirmServiceIdentityRevoke(id) {
        const identity = this.findServiceIdentity(id);
        if (!identity) {
            this.showIdentityError('Machine identity details are no longer available. Reload and try again.');
            return;
        }
        const usageResult = await identityV2Api.getServiceIdentityUsage(id);
        if (!usageResult.data) {
            this.showIdentityError(usageResult.error?.message || 'Dependencies could not be loaded.');
            return;
        }
        const usage = usageResult.data;
        const dependencies = [...usage.protected_app_ids, ...usage.policy_versions, ...usage.policy_deployment_ids];
        const detail = dependencies.length ? `<ul>${dependencies.map(item => `<li>${escapeHTML(item)}</li>`).join('')}</ul>` : '<p>No active references were reported.</p>';
        SectionUI.openConfirmModal('Revoke machine identity', `Revocation immediately causes authentication to fail closed for <strong>${escapeHTML(identity.name)}</strong>. Review affected resources before continuing:${detail}`, 'Revoke identity', 'danger', async () => {
            const result = await identityV2Api.revokeServiceIdentity(id, identity.revision, true);
            if (!result.data) {
                this.showIdentityError(result.error?.message || 'Machine identity could not be revoked.');
                return;
            }
            SectionUI.closeModal();
            SectionUI.showToast('Machine identity revoked. Affected authentication now fails closed.', 'success');
            await this.refreshIdentity('service-identities');
        });
    }
}
