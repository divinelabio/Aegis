import { SectionUI } from '../../ui-components.js';
import { escapeHTML, formatDateTime } from '../view-helpers.js';
import { renderSetupCheckboxRow } from './setup-components.js';
function action(label, name, attributes = '', primary = false) {
    return `<button type="button" class="btn ${primary ? 'btn-primary' : 'btn-outline'}" data-edge-access-v2-action="${name}" ${attributes}>${escapeHTML(label)}</button>`;
}
function pending(loading, error, retry, label) {
    if (loading)
        return SectionUI.renderLoading(`Loading ${label}...`);
    if (error)
        return `<div class="section-error" role="alert"><div class="error-message">${escapeHTML(error)}</div>${action('Retry', retry)}</div>`;
    return null;
}
function renderRuntimeControls(state) {
    const resource = state.runtime.settings;
    const wait = pending(resource.loading, resource.error, 'runtime-retry', 'runtime settings');
    if (wait)
        return SectionUI.renderOperatorSection('Runtime settings', wait, { subtitle: 'Global controls for platform operators.', className: 'edge-access-v2-runtime-section' });
    const settings = resource.value;
    if (!settings)
        return SectionUI.renderOperatorSection('Runtime settings', SectionUI.renderEmptyState('Runtime settings unavailable', 'Retry loading the runtime configuration.', 'settings'), { subtitle: 'Global controls for platform operators.', className: 'edge-access-v2-runtime-section' });
    const reload = state.runtime.reload.value;
    const reloadText = reload ? `Revision ${reload.loaded_revision}/${reload.revision}${reload.last_reload_at ? ` · last reload ${formatDateTime(reload.last_reload_at)}` : ''}` : 'Reload status unavailable';
    return SectionUI.renderOperatorSection('Runtime settings', `
    <div class="edge-access-v2-runtime-layout">
      <form class="edge-access-v2-runtime-form" data-edge-access-v2-runtime-form="true">
        <div class="edge-access-v2-runtime-grid">

          <div class="edge-access-v2-runtime-col">
            <section class="edge-access-v2-runtime-panel">
              <div class="edge-access-v2-runtime-panel-head">
                <h3>Protection</h3>
                <p>Global controls applied before App-level policy evaluation.</p>
              </div>
              <div class="edge-access-v2-runtime-panel-body">
                ${renderSetupCheckboxRow({
        name: 'enabled',
        checked: settings.enabled,
        title: 'Enable Edge Access runtime',
        description: 'Apply Edge Access policies to protected application traffic.'
    })}
              </div>
            </section>

            <section class="edge-access-v2-runtime-panel">
              <div class="edge-access-v2-runtime-panel-head">
                <h3>Verified identity headers</h3>
                <p>Pass trusted identity attributes to upstream applications.</p>
              </div>
              <div class="edge-access-v2-runtime-panel-body">
                ${renderSetupCheckboxRow({
        name: 'identity_headers_enabled',
        checked: settings.identity_headers.enabled,
        title: 'Inject verified headers',
        description: 'Add verified identity context to requests.'
    })}
                ${renderSetupCheckboxRow({
        name: 'identity_headers_overwrite',
        checked: settings.identity_headers.overwrite_existing,
        title: 'Overwrite inbound headers',
        description: 'Replace untrusted incoming identity values.'
    })}
                <p class="edge-access-v2-field-hint">Spoofed identity headers remain stripped by the runtime.</p>
              </div>
            </section>
          </div>

          <div class="edge-access-v2-runtime-col">
            <section class="edge-access-v2-runtime-panel edge-access-v2-runtime-panel--fill">
              <div class="edge-access-v2-runtime-panel-head">
                <h3>Sessions & retention</h3>
                <p>Set session lifetime and audit history windows.</p>
              </div>
              <div class="edge-access-v2-runtime-panel-body">
                <div class="edge-access-v2-runtime-field-grid">
                  <label class="edge-access-v2-field">
                    <span class="edge-access-v2-field-label">Session TTL</span>
                    <input class="input edge-access-v2-field-input" name="token_ttl" value="${escapeHTML(settings.session_cookie.token_ttl || '')}">
                  </label>
                  <label class="edge-access-v2-field">
                    <span class="edge-access-v2-field-label">Idle timeout</span>
                    <input class="input edge-access-v2-field-input" name="idle_timeout" value="${escapeHTML(settings.session_cookie.idle_timeout || '')}">
                  </label>
                  <label class="edge-access-v2-field edge-access-v2-field--wide">
                    <span class="edge-access-v2-field-label">Max sessions</span>
                    <input class="input edge-access-v2-field-input" name="max_sessions" type="number" min="0" value="${settings.session_cookie.max_sessions}">
                  </label>
                  <label class="edge-access-v2-field">
                    <span class="edge-access-v2-field-label">Decision retention</span>
                    <input class="input edge-access-v2-field-input" name="activity_retention" type="number" min="0" value="${settings.activity.retention_days}">
                  </label>
                  <label class="edge-access-v2-field">
                    <span class="edge-access-v2-field-label">Audit retention</span>
                    <input class="input edge-access-v2-field-input" name="audit_retention" type="number" min="0" value="${settings.audit.retention_days}">
                  </label>
                </div>
              </div>
            </section>
          </div>

        </div>

        <div class="edge-access-v2-runtime-actions">
          <div>
            <strong>Runtime revision</strong>
            <span>${escapeHTML(reloadText)}</span>
          </div>
          <div class="section-actions">
            ${action('Save settings', 'runtime-save', '', true)}
            ${action('Reload runtime', 'runtime-reload')}
          </div>
        </div>
      </form>
    </div>
  `, { subtitle: 'Global controls for platform operators.', className: 'edge-access-v2-runtime-section' });
}
export function renderV2Runtime(state) {
    return renderRuntimeControls(state);
}
