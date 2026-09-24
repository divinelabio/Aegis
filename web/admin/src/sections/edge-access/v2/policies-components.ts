import { SectionUI } from '../../ui-components.js';
import { escapeHTML, formatDateTime, statusTone } from '../view-helpers.js';
import type { PolicyAuthChannel, PolicyDecision, PolicyWorkspaceAttachment } from './policies-contract.js';
import { renderAdvancedDisclosure, renderCreateBack, renderSetupCheckboxRow, renderSetupChoiceCard, renderSetupHeading } from './setup-components.js';
import { renderManagedRolePicker } from './roles-components.js';
import type { EdgeAccessV2ShellState } from './types.js';

function action(label: string, name: string, attributes = '', primary = false, icon = ''): string {
  return `<button type="button" class="btn ${primary ? 'btn-primary' : 'btn-outline'}" data-edge-access-v2-action="${name}" ${attributes}>${icon ? `<span class="edge-access-v2-button-icon" aria-hidden="true">${icon}</span>` : ''}${escapeHTML(label)}</button>`;
}
function pending(loading: boolean, error: string | null, retry: string, label: string): string | null {
  if (loading) return SectionUI.renderLoading(`Loading ${label}...`);
  if (error) return `<div class="section-error" role="alert"><div class="error-message">${escapeHTML(error)}</div>${action('Retry', retry)}</div>`;
  return null;
}
function decisionLabel(value?: PolicyDecision): string { return value === 'public_bypass' ? 'Public bypass' : value ? value[0].toUpperCase() + value.slice(1) : 'Not published'; }
function policyStatus(value: string): string { return SectionUI.renderStatusPill(value === 'deny_only' ? 'Deny-only' : value.replace(/_/g, ' '), statusTone(value === 'deny_only' ? 'warning' : value)); }
function policyDecisionStatus(value?: PolicyDecision): string {
  const tone = value === 'allow' ? 'success' : value === 'deny' ? 'danger' : 'neutral';
  return SectionUI.renderStatusPill(escapeHTML(decisionLabel(value)), tone);
}

function attachmentScope(item: PolicyWorkspaceAttachment): string {
  return `<span class="text-mono">${escapeHTML(item.attachment.path)}</span>`;
}
function principalSummary(item: PolicyWorkspaceAttachment): string {
  if (item.decision === 'public_bypass') return 'Identity not required';
  if (item.principals.any_authenticated) return 'Any authenticated identity';
  const constraints = [item.principals.roles.length ? `Roles: ${item.principals.roles.join(', ')}` : '', item.principals.groups.length ? `Groups: ${item.principals.groups.join(', ')}` : '', item.principals.permissions.length ? `Permissions: ${item.principals.permissions.join(', ')}` : '', item.principals.service_identity_ids.length ? `Service identities: ${item.principals.service_identity_ids.length}` : '', item.principals.claims.length ? `${item.principals.claims.length} claim condition${item.principals.claims.length === 1 ? '' : 's'}` : ''].filter(Boolean);
  return escapeHTML(constraints.join(' · ') || 'No identity restriction');
}
export function renderAttachedPolicySummary(state: EdgeAccessV2ShellState): string {
  const resource = state.policies.appDetail;
  const appID = resource.value?.app.id || state.route.appID || '';
  const manageAction = action('Manage policies', 'app-manage-policies', `data-edge-access-v2-app-id="${escapeHTML(appID)}"`);
  const wait = pending(resource.loading, resource.error, 'policy-app-retry', 'attached policies');
  if (wait) return SectionUI.renderOperatorSection('Attached policies', wait, {
    subtitle: 'Read-only attachment summary.',
    actions: manageAction,
    className: 'edge-access-v2-overview-card edge-access-v2-policy-summary'
  });
  const attachments = resource.value?.attachments || [];
  const rows = attachments.slice(0, 3).map(item => {
    const deploymentStatus = !item.deployed
      ? SectionUI.renderStatusPill('Review required', 'warning')
      : policyStatus(item.attachment.deployment_state);
    return [
      `<div class="edge-access-v2-policy-summary-name"><span class="edge-access-v2-library-policy-icon" aria-hidden="true">${SectionUI.icons.fileText}</span><strong>${escapeHTML(item.policy_name)}</strong></div>`,
      policyDecisionStatus(item.decision),
      deploymentStatus
    ];
  });
  const tableContent = rows.length
    ? SectionUI.renderEnterpriseTable({
      columns: ['Policy', 'Decision', 'Status'],
      rows,
      className: 'edge-access-v2-policy-table edge-access-v2-policy-summary-table'
    })
    : `<div class="edge-access-v2-overview-empty"><span aria-hidden="true">${SectionUI.icons.shield}</span><div><strong>No policies attached</strong><small>Use Manage policies to attach a reusable access policy.</small></div></div>`;
  const remainder = attachments.length > rows.length
    ? `<div class="edge-access-v2-policy-summary-foot">Showing ${rows.length} of ${attachments.length} attached policies.</div>`
    : '';
  const tableSurface = `<div class="edge-access-v2-policy-table-surface edge-access-v2-policy-summary-surface">${tableContent}${remainder}</div>`;
  return SectionUI.renderOperatorSection('Attached policies', tableSurface, {
    subtitle: 'Policy configuration is managed from Access policies.',
    actions: manageAction,
    className: 'edge-access-v2-overview-card edge-access-v2-policy-summary'
  });
}

export function renderAttachedPolicies(state: EdgeAccessV2ShellState): string {
  const resource = state.policies.appDetail;
  const wait = pending(resource.loading, resource.error, 'policy-app-retry', 'policy attachments');
  if (wait) return SectionUI.renderOperatorSection('Attached policies', wait, { subtitle: 'Reusable policies assigned to this application.', className: 'edge-access-v2-app-page-section edge-access-v2-policies-section' });
  const value = resource.value;
  if (!value) return SectionUI.renderOperatorSection('Attached policies', SectionUI.renderEmptyState('Policies unavailable', 'This application policy data could not be loaded.', 'shield'), { subtitle: 'Reusable policies assigned to this application.', className: 'edge-access-v2-app-page-section edge-access-v2-policies-section' });
  const rows = value.attachments.map(item => {
    const attachmentID = escapeHTML(item.attachment.id);
    const policyID = escapeHTML(item.attachment.policy_id);
    const deploymentStatus = item.update_available
      ? SectionUI.renderStatusPill('Update available', 'warning')
      : item.deployed ? SectionUI.renderStatusPill('Deployed', 'primary') : SectionUI.renderStatusPill('Review required', 'warning');
    const rowActions = [
      { label: 'Open policy', attrs: `data-edge-access-v2-action="policy-open" data-edge-access-v2-policy-id="${policyID}"` },
      { label: 'Change attachment', attrs: `data-edge-access-v2-action="policy-change-attachment" data-edge-access-v2-attachment-id="${attachmentID}"` },
      ...(item.update_available ? [{ label: 'Upgrade attachment', attrs: `data-edge-access-v2-action="policy-upgrade-attachment" data-edge-access-v2-attachment-id="${attachmentID}"` }] : []),
      { label: 'Detach policy', attrs: `data-edge-access-v2-action="policy-detach-attachment" data-edge-access-v2-attachment-id="${attachmentID}"`, tone: 'danger' as const }
    ];
    return [
      `<div class="edge-access-v2-library-policy"><span class="edge-access-v2-library-policy-icon" aria-hidden="true">${SectionUI.icons.fileText}</span><div><div class="edge-access-v2-library-policy-title"><button type="button" class="btn-link" data-edge-access-v2-action="policy-open" data-edge-access-v2-policy-id="${policyID}">${escapeHTML(item.policy_name)}</button></div><span>Version v${item.attachment.policy_version}</span></div></div>`,
      policyDecisionStatus(item.decision),
      attachmentScope(item),
      principalSummary(item),
      deploymentStatus,
      `<div class="operator-control-actions edge-access-v2-library-actions">${SectionUI.renderActionMenu({ id: `edge-access-v2-policy-actions-${item.attachment.id}`, label: 'More', ariaLabel: `Actions for ${item.policy_name}`, items: rowActions, className: 'edge-access-v2-table-actions' })}</div>`
    ];
  });
  const table = SectionUI.renderEnterpriseTable({ columns: ['Policy', 'Decision', 'Scope', 'Identity', 'Status', 'Actions'], rows, emptyTitle: 'No policies attached', emptyMessage: 'Attach a published reusable policy to protect this application.', className: 'edge-access-v2-policy-table edge-access-v2-attached-policy-table' });
  const tableSurface = `<div class="edge-access-v2-policy-table-surface edge-access-v2-attached-policy-surface">${table}${SectionUI.renderTableScrollHint()}</div>`;
  const count = value.attachments.length;
  return SectionUI.renderOperatorSection('Attached policies', tableSurface, {
    subtitle: `${count} ${count === 1 ? 'policy' : 'policies'} assigned to this application.`,
    className: 'edge-access-v2-app-page-section edge-access-v2-policies-section'
  });
}

function renderLibrary(state: EdgeAccessV2ShellState): string {
  const resource = state.policies.library;
  const wait = pending(resource.loading, resource.error, 'policy-library-retry', 'Policies');
  const filter = state.policies.filter;
  const controls = `<form class="edge-access-v2-app-filters edge-access-v2-policy-library-filters" data-edge-access-v2-policy-filters="library">
    <label class="edge-access-v2-filter-search"><span class="edge-access-v2-sr-only">Search policies</span><span class="edge-access-v2-filter-search-icon" aria-hidden="true">${SectionUI.icons.search}</span><input class="input" name="q" aria-label="Search policies" placeholder="Search policies by name or description" value="${escapeHTML(filter.q)}"></label>
    <label class="edge-access-v2-filter-status"><span class="edge-access-v2-sr-only">Filter by status</span><select class="input" name="status" aria-label="Filter policies by status"><option value="">All statuses</option><option value="active"${filter.status === 'active' ? ' selected' : ''}>Active</option><option value="archived"${filter.status === 'archived' ? ' selected' : ''}>Archived</option></select></label>
  </form>`;
  const rows = (resource.value || []).map(item => {
    const appCount = item.protected_app_ids.length;
    const policyAttrs = `data-edge-access-v2-policy-id="${escapeHTML(item.policy.id)}"`;
    const status = item.policy.archived
      ? SectionUI.renderStatusPill('Archived', 'neutral')
      : item.update_available_count
        ? SectionUI.renderStatusPill(`${item.update_available_count} update${item.update_available_count === 1 ? '' : 's'}`, 'warning')
        : SectionUI.renderStatusPill('Current', 'success');
    const rowActions = [
      ...(!item.policy.archived && item.latest_published_version
        ? [{ label: 'Attach policy', attrs: `data-edge-access-v2-action="policy-library-attach" ${policyAttrs}` }]
        : []),
      { label: 'Open policy', attrs: `data-edge-access-v2-action="policy-open" ${policyAttrs}` },
      { label: 'View decisions', attrs: `data-edge-access-v2-action="policy-view-policy-decisions" ${policyAttrs}` },
      ...(!item.policy.archived
        ? [{ label: 'Archive policy', attrs: `data-edge-access-v2-action="policy-archive" ${policyAttrs}`, tone: 'danger' as const }]
        : [])
    ];
    return [
      `<div class="edge-access-v2-library-policy"><span class="edge-access-v2-library-policy-icon" aria-hidden="true">${SectionUI.icons.fileText}</span><div><div class="edge-access-v2-library-policy-title"><button type="button" class="btn-link" data-edge-access-v2-action="policy-open" ${policyAttrs}>${escapeHTML(item.policy.name)}</button></div>${item.policy.description ? `<span>${escapeHTML(item.policy.description)}</span>` : ''}</div></div>`,
      policyDecisionStatus(item.latest_published_decision),
      `<span class="edge-access-v2-library-apps">${appCount ? `${appCount} application${appCount === 1 ? '' : 's'}` : 'Not attached'}</span>`,
      status,
      `<div class="operator-control-actions edge-access-v2-library-actions">${SectionUI.renderActionMenu({
        id: `edge-access-v2-policy-library-actions-${item.policy.id}`,
        ariaLabel: `Actions for ${item.policy.name}`,
        label: 'More',
        items: rowActions,
        className: 'edge-access-v2-table-actions'
      })}</div>`
    ];
  });
  const table = wait || SectionUI.renderEnterpriseTable({
    columns: ['Policy', 'Decision', 'Applications', 'Status', 'Actions'],
    rows,
    emptyTitle: 'No reusable policies',
    emptyMessage: 'Create a policy to reuse authorization logic across applications.',
    className: 'edge-access-v2-policy-library-table'
  });
  return SectionUI.renderOperatorSection('Policy library', `<div class="edge-access-v2-policy-library-surface">${controls}${table}${wait ? '' : SectionUI.renderTableScrollHint()}</div>`, {
    subtitle: 'Create and maintain reusable authorization rules, then attach published versions from an application.',
    actions: action('New policy', 'policy-new', '', true, SectionUI.icons.fileText),
    className: 'edge-access-v2-policy-library-section'
  });
}

function valueList(values: string[]): string { return values.join(', '); }
function renderPolicyEditor(state: EdgeAccessV2ShellState): string {
  const isNew = state.route.policyMode === 'new';
  const policy = isNew ? null : state.policies.policy.value;
  const versions = isNew ? [] : state.policies.versions.value || [];
  const draft = versions.find(version => version.state === 'draft');
  const initial = draft || versions.filter(version => version.state === 'published').sort((left, right) => right.version - left.version)[0];
  const appID = state.route.policyFirstAttachment ? state.route.policyAppID || '' : '';
  const pendingFirstAttachment = state.policies.pendingFirstAttachment?.protectedAppID === appID ? state.policies.pendingFirstAttachment : null;
  const firstAttachment: { path: string; methods: string[]; channels: PolicyAuthChannel[] } = pendingFirstAttachment || { path: '/*', methods: [], channels: [] };
  const capability = state.policyCapabilities.value;
  const requirements = initial?.requirements;
  const principals = initial?.principals;
  const publicBypass = initial?.decision === 'public_bypass';
  const identityMode = !initial || principals?.any_authenticated ? 'any' : 'specific';
  const decisionCards = [
    renderSetupChoiceCard({ type: 'radio', name: 'decision', value: 'allow', checked: !initial || initial.decision === 'allow', title: 'Allow', description: 'Permit requests when identity and security requirements match.', icon: SectionUI.icons.shieldCheck }),
    renderSetupChoiceCard({ type: 'radio', name: 'decision', value: 'deny', checked: initial?.decision === 'deny', title: 'Deny', description: 'Explicitly block and deny matching requests.', icon: SectionUI.icons.ban }),
    renderSetupChoiceCard({ type: 'radio', name: 'decision', value: 'public_bypass', checked: initial?.decision === 'public_bypass', title: 'Public bypass', description: 'Allow matched scope publicly without requiring authentication (e.g. webhooks, public assets).', icon: SectionUI.icons.unlock })
  ].join('');
  const requirementControls = [
    capability?.mfa_satisfied
      ? renderSetupCheckboxRow({ name: 'mfa_satisfied', checked: requirements?.mfa_satisfied, title: 'Require MFA', description: 'Enforce verified multi-factor authentication (MFA) in the active session.' })
      : '',
    capability?.source_cidrs
      ? `<label class="edge-access-v2-setup-field"><span>Source CIDRs</span><input class="input" name="source_cidrs" value="${escapeHTML(valueList(requirements?.source_cidrs || []))}" placeholder="e.g. 203.0.113.0/24, 2001:db8::/32"><small>Separate multiple network ranges with commas.</small></label>`
      : ''
  ].filter(Boolean).join('');
  const capabilityNote = state.policyCapabilities.error
    ? `<div class="edge-access-v2-inline-note">${SectionUI.icons.info}<span>${escapeHTML(state.policyCapabilities.error)}</span></div>`
    : '';
  const firstAttachmentSection = appID ? `<section class="edge-access-v2-setup-section">
      ${renderSetupHeading('Attach to the application', 'Define the initial scope. The most-specific matching scope wins; broader denies do not cascade. Use an organization deny guardrail for a cross-scope absolute deny.')}
      <input type="hidden" name="protected_app_id" value="${escapeHTML(appID)}">
      <div class="edge-access-v2-policy-attachment-grid">
        <label class="edge-access-v2-setup-field"><span>Path</span><input class="input" name="path" value="${escapeHTML(firstAttachment.path)}"></label>
        <label class="edge-access-v2-setup-field"><span>Methods</span><input class="input" name="methods" value="${escapeHTML(valueList(firstAttachment.methods))}" placeholder="Leave blank for every method"></label>
        <label class="edge-access-v2-setup-field"><span>Authentication channels</span><select class="input edge-access-v2-policy-channel-select" name="auth_channels" multiple><option value="oidc"${firstAttachment.channels.includes('oidc') ? ' selected' : ''}>Browser session</option><option value="jwt"${firstAttachment.channels.includes('jwt') ? ' selected' : ''}>Bearer JWT</option><option value="api_key"${firstAttachment.channels.includes('api_key') ? ' selected' : ''}>API key</option><option value="mtls"${firstAttachment.channels.includes('mtls') ? ' selected' : ''}>mTLS</option></select></label>
      </div>
    </section>` : '';
  const input = `<form class="edge-access-v2-policy-form edge-access-v2-new-app-form edge-access-v2-policy-create-form" data-edge-access-v2-policy-form="true">
    <section class="edge-access-v2-setup-section">
      ${renderSetupHeading('Policy details', 'Give the reusable authorization rule a clear name and purpose.')}
      <div class="edge-access-v2-policy-details-grid">
        <label class="edge-access-v2-setup-field edge-access-v2-setup-field--wide"><span>Policy name</span><input class="input" name="name" required autocomplete="off" value="${escapeHTML(policy?.name || '')}" placeholder="e.g. Support team access"></label>
        <label class="edge-access-v2-setup-field edge-access-v2-setup-field--wide"><span>Description</span><textarea class="input edge-access-v2-policy-description" name="description" rows="3" placeholder="Describe what this policy authorizes">${escapeHTML(policy?.description || '')}</textarea></label>
      </div>
    </section>

    <section class="edge-access-v2-setup-section">
      ${renderSetupHeading('Choose a decision', 'Select the outcome when this policy matches a request.')}
      <div class="edge-access-v2-choice-grid edge-access-v2-policy-decision-grid">${decisionCards}</div>
    </section>

    <section class="edge-access-v2-setup-section" data-edge-access-v2-policy-identity-section>
      ${renderSetupHeading('Match identities', 'Choose who can satisfy this policy. Authentication is always required unless the decision is Public bypass.')}
      <div data-edge-access-v2-policy-identity-controls${publicBypass ? ' hidden' : ''}>
        <div class="edge-access-v2-choice-grid edge-access-v2-policy-identity-mode-grid" role="radiogroup" aria-label="Identity matching mode">
          ${renderSetupChoiceCard({ type: 'radio', name: 'identity_mode', value: 'any', checked: identityMode === 'any', title: 'Any authenticated identity', description: 'Grant access to any user authenticated by your Identity Provider.', icon: SectionUI.icons.users })}
          ${renderSetupChoiceCard({ type: 'radio', name: 'identity_mode', value: 'specific', checked: identityMode === 'specific', title: 'Specific identities', description: 'Restrict access to identities matching roles, groups, permissions, or claim conditions.', icon: SectionUI.icons.key })}
        </div>
        <div data-edge-access-v2-policy-specific-identities${identityMode === 'specific' ? '' : ' hidden'}>
          <div class="edge-access-v2-policy-principal-grid">
            <label class="edge-access-v2-setup-field"><span>Groups</span><input class="input" name="groups" value="${escapeHTML(valueList(principals?.groups || []))}" placeholder="e.g. operations, incident-response"><small>Separate multiple groups with commas.</small></label>
          </div>
          ${renderManagedRolePicker(state.roles.catalog, principals?.roles || [], { name: 'roles', label: 'Managed roles' })}
          ${renderAdvancedDisclosure({
            title: 'Advanced identity matching',
            description: 'RBAC permissions, service identities, and claim conditions',
            className: 'edge-access-v2-policy-advanced',
            body: `
              <div class="edge-access-v2-policy-principal-grid">
                <label class="edge-access-v2-setup-field"><span>RBAC permissions</span><input class="input" name="permissions" value="${escapeHTML(valueList(principals?.permissions || []))}" placeholder="Enter required permissions"><small>Every listed permission must match.</small></label>
                <label class="edge-access-v2-setup-field"><span>Service identity IDs</span><input class="input" name="service_identity_ids" value="${escapeHTML(valueList(principals?.service_identity_ids || []))}" placeholder="Enter service identity IDs"><small>Separate multiple IDs with commas.</small></label>
              </div>
              <label class="edge-access-v2-setup-field edge-access-v2-setup-field--wide"><span>Claim conditions (JSON)</span><textarea class="input edge-access-v2-policy-claims" name="claims" rows="4" spellcheck="false" placeholder="Valid JSON claim conditions">${escapeHTML(JSON.stringify(principals?.claims || []))}</textarea><small>Provide a JSON array of claim-condition objects. <code>eq</code>, <code>in</code>, and <code>contains</code> require exact value membership; <code>contains</code> is never a substring match. Missing claims never satisfy <code>neq</code>.</small></label>
            `
          })}
        </div>
      </div>
      <div class="edge-access-v2-inline-note edge-access-v2-policy-bypass-note" data-edge-access-v2-policy-bypass-note${publicBypass ? '' : ' hidden'}>${SectionUI.icons.info}<span>Identity matching is not evaluated for Public bypass. Choose Allow or Deny to configure identity criteria.</span></div>
    </section>

    <section class="edge-access-v2-setup-section">
      ${renderSetupHeading('Add requirements', 'Apply runtime-supported checks in addition to identity matching.')}
      ${requirementControls ? `<div class="edge-access-v2-policy-requirement-grid">${requirementControls}</div>` : ''}
      ${capabilityNote}
      <p class="edge-access-v2-policy-runtime-note">Only requirements enforced by the current runtime are shown.</p>
    </section>

    ${firstAttachmentSection}
    <footer class="edge-access-v2-create-actions"><div class="operator-control-actions">${action('Save draft', 'policy-save-draft', '', true, SectionUI.icons.fileText)}${policy && draft ? action('Review and publish', 'policy-publish') : ''}</div></footer>
  </form>`;
  const title = isNew ? 'Create policy' : draft ? `Edit ${policy?.name || 'policy'} draft` : `Create a new ${policy?.name || 'policy'} version`;
  const formSection = SectionUI.renderOperatorSection(title, input, {
    subtitle: 'Define reusable authorization logic. Application scope is managed separately.',
    className: 'edge-access-v2-new-app-section edge-access-v2-policy-editor-section'
  });
  return `<div class="edge-access-v2-create-shell edge-access-v2-policy-editor-shell">
    ${renderCreateBack('Access policies', 'Back to policy library', 'policy-back')}
    ${formSection}
  </div>`;
}

function decisionStatus(result: string): string { return SectionUI.renderStatusPill(result, statusTone(result === 'allow' ? 'active' : result === 'deny' ? 'error' : 'warning')); }
function renderDecisions(state: EdgeAccessV2ShellState): string {
  const resource = state.decisions.list; const wait = pending(resource.loading, resource.error, 'decisions-refresh', 'decisions'); const filter = state.decisions.filter;
  const controls = `<form class="edge-access-v2-decision-filters" data-edge-access-v2-decision-filters="true"><input class="input" name="q" aria-label="Search decisions" placeholder="Search request, reason, App, or identity" value="${escapeHTML(filter.q)}"><select class="input" name="result" aria-label="Filter result"><option value="">All results</option><option value="allow"${filter.result === 'allow' ? ' selected' : ''}>Allow</option><option value="deny"${filter.result === 'deny' ? ' selected' : ''}>Deny</option></select><input class="input" name="hostname" aria-label="Filter hostname" placeholder="Hostname" value="${escapeHTML(filter.hostname)}"><input class="input" name="identity" aria-label="Filter identity" placeholder="Identity" value="${escapeHTML(filter.identity)}"><select class="input" name="channel" aria-label="Filter channel"><option value="">All channels</option>${['oidc', 'jwt', 'api_key', 'mtls', 'public'].map(channel => `<option value="${channel}"${filter.channel === channel ? ' selected' : ''}>${channel}</option>`).join('')}</select><input class="input" name="policy_attachment_id" aria-label="Filter attachment" placeholder="Attachment ID" value="${escapeHTML(filter.attachmentID)}"><input class="input" type="number" min="1" name="policy_version" aria-label="Filter policy version" placeholder="Version" value="${escapeHTML(filter.policyVersion)}"><input class="input" type="datetime-local" name="from" aria-label="From time" value="${escapeHTML(filter.from)}"><input class="input" type="datetime-local" name="to" aria-label="To time" value="${escapeHTML(filter.to)}">${action('Apply', 'decisions-filter')}</form>`;
  if (wait) return SectionUI.renderOperatorSection('View decisions', `${controls}${wait}`, { subtitle: 'Read-only operational evidence for authorization outcomes.' });
  const rows = (resource.value || []).map(decision => [formatDateTime(decision.timestamp), `<button type="button" class="btn-link" data-edge-access-v2-action="decision-open" data-edge-access-v2-decision-id="${escapeHTML(decision.id)}">${escapeHTML(decision.protected_app_name || decision.protected_app_id || decision.route_id || 'Unbound')}</button>`, `<span class="text-mono">${escapeHTML(decision.host || '')}${escapeHTML(decision.path || '')}</span>`, decisionStatus(decision.result), escapeHTML(decision.identity_id || 'Unauthenticated'), escapeHTML(decision.reason_code || '—'), decision.policy_id ? `${escapeHTML(decision.policy_id)} v${decision.policy_version || '—'}` : '<span class="text-muted">Unavailable</span>']);
  const table = SectionUI.renderEnterpriseTable({ columns: ['Time', 'App / Route', 'Request', 'Result', 'Identity', 'Reason', 'Policy version'], rows, emptyTitle: 'No decisions', emptyMessage: 'Authorization outcomes appear after protected traffic is evaluated.' });
  const detail = state.decisions.detail.value;
  const traceItems = detail?.explanation.trace.length ? detail.explanation.trace.map(step => `<li><strong>${escapeHTML(step.stage.replace(/_/g, ' '))} · ${escapeHTML(step.outcome.replace(/_/g, ' '))}</strong><span>${escapeHTML(step.detail)}</span>${step.policy_id ? `<small>${escapeHTML(step.policy_id)} v${escapeHTML(String(step.policy_version || '—'))}</small>` : ''}</li>`).join('') : detail?.explanation.steps.map(step => `<li>${escapeHTML(step)}</li>`).join('');
  const explanation = detail ? `<section class="edge-access-v2-app-section"><h2>Decision explanation</h2><p>${escapeHTML(detail.explanation.reason || 'No explanation is available.')}</p>${detail.explanation.available ? `<ol class="edge-access-v2-decision-trace">${traceItems}</ol>` : '<div class="section-warning-inline">This decision predates persisted policy-evaluation trace data.</div>'}</section>` : '';
  return SectionUI.renderOperatorSection('View decisions', `${controls}${table}${explanation}`, { subtitle: 'Route → App → Attachment scope → authentication → Policy Version → requirement → outcome. This explorer is read-only.' });
}

export function renderV2Policies(state: EdgeAccessV2ShellState): string {
  if (state.route.policyMode !== 'list') return renderPolicyEditor(state);
  return renderLibrary(state);
}
export function renderV2Decisions(state: EdgeAccessV2ShellState): string { return renderDecisions(state); }
