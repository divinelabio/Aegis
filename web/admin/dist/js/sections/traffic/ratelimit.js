/**
 * Traffic Control - Rate Limiting (Rule-Driven Architecture)
 * Clean, enterprise-grade, rule-driven rate limiting UI.
 * Standardized with Aegis console table patterns and tooltip descriptors.
 */
import { escapeTrafficAttr, escapeTrafficHtml } from '../traffic-runtime-helpers.js';
import { SectionUI } from '../ui-components.js';
export function renderRateLimitTab(config, arg2, arg3, arg4, arg5) {
    let renderSaveButtons;
    let icons = {};
    let viewMode = 'table';
    let editingIndex = null;
    if (typeof arg2 === 'function' && typeof arg3 !== 'function') {
        renderSaveButtons = arg2;
        icons = arg3 || {};
        viewMode = arg4 === 'editor' ? 'editor' : 'table';
        editingIndex = typeof arg5 === 'number' ? arg5 : null;
    }
    else {
        renderSaveButtons = typeof arg3 === 'function' ? arg3 : () => '';
        icons = arg4 || {};
        viewMode = arg5 === 'editor' ? 'editor' : 'table';
        editingIndex = null;
    }
    const cfg = config || {};
    const pathOverrides = Array.isArray(cfg.path_overrides) ? cfg.path_overrides : [];
    if (viewMode === 'editor') {
        const editingRule = editingIndex !== null && editingIndex >= 0 && editingIndex < pathOverrides.length
            ? pathOverrides[editingIndex]
            : null;
        return renderRateLimitRuleEditor(editingRule, editingIndex, icons);
    }
    return renderRateLimitRulesTable(pathOverrides, renderSaveButtons, icons);
}
function renderRateLimitRulesTable(rules, renderSaveButtons, _icons) {
    const iconPlus = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>';
    const totalRules = rules.length;
    const blockCount = rules.filter(r => r.action === 'block' || (!r.action && !r.dry_run)).length;
    const challengeCount = rules.filter(r => r.action === 'challenge').length;
    const dryRunCount = rules.filter(r => r.action === 'dry_run' || r.dry_run).length;
    const tableRows = rules.map((rule, idx) => {
        const pattern = escapeTrafficHtml(rule.pattern || '/');
        const ruleName = rule.name ? escapeTrafficHtml(rule.name) : '';
        const matchType = escapeTrafficHtml((rule.match || 'glob').toUpperCase());
        const methods = Array.isArray(rule.methods) && rule.methods.length > 0
            ? rule.methods.map(m => `<span class="config-status-pill tone-neutral font-mono font-600" style="font-size:10px;padding:2px 6px;">${escapeTrafficHtml(m)}</span>`).join(' ')
            : '<span class="config-status-pill tone-neutral font-mono font-600" style="font-size:10px;padding:2px 6px;">ALL</span>';
        const hosts = Array.isArray(rule.hosts) && rule.hosts.length > 0
            ? `<div class="config-table-sub font-mono" style="font-size:11px;color:var(--text-muted);margin-top:2px;">${escapeTrafficHtml(rule.hosts.join(', '))}</div>`
            : '';
        const actionTone = rule.action === 'challenge' ? 'warning' : (rule.action === 'dry_run' || rule.dry_run) ? 'info' : 'danger';
        const actionLabel = rule.action === 'challenge' ? 'Smart Challenge' : (rule.action === 'dry_run' || rule.dry_run) ? 'Observe Only' : 'Strict Block (429)';
        const algoLabel = rule.algorithm === 'sliding_window' ? 'Sliding Window' : rule.algorithm === 'fixed_window' ? 'Fixed Window' : 'Token Bucket';
        const keyLabel = rule.key_by === 'ip_ua' ? 'IP+UA' : rule.key_by === 'cookie' ? 'Cookie' : rule.key_by === 'token' ? 'Token' : 'IP';
        // 1. Target Route (standard primary path + sub-text description)
        const colRoute = `
            <div class="config-table-primary font-mono" style="font-size:13px;font-weight:700;letter-spacing:-0.01em;">${pattern}</div>
            ${ruleName ? `<div class="config-table-sub" style="font-size:11px;color:var(--text-muted);margin-top:2px;">${ruleName}</div>` : ''}
        `;
        // 2. Scope & Match
        const colMatch = `
            <div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap;">
                <span class="config-status-pill tone-neutral font-mono font-600" style="font-size:10px;text-transform:uppercase;">${matchType}</span>
                ${methods}
            </div>
            ${hosts}
        `;
        // 3. Rate & Burst (compact, unified)
        const colRate = `
            <div><strong class="font-mono" style="font-size:13px;color:var(--text-main);">${rule.rate}</strong> <span class="text-muted" style="font-size:11px;">req / ${escapeTrafficHtml(rule.window || '1m')}</span></div>
            <div class="config-table-sub font-mono" style="font-size:11px;color:var(--text-muted);">+${rule.burst} burst req</div>
        `;
        // 4. Mitigation Action (standard status pill)
        const colAction = SectionUI.renderStatusPill(actionLabel, actionTone);
        // 5. Engine Tuning
        const colEngine = `
            <div style="font-size:12px;font-weight:600;color:var(--text-main);">${algoLabel}</div>
            <div class="config-table-sub font-mono" style="font-size:11px;color:var(--text-muted);">Key: ${keyLabel}${rule.bypass_static ? ' • No Static' : ''}</div>
        `;
        // 6. Priority (centered badge)
        const colPriority = `
            <span class="config-status-pill tone-neutral font-mono font-600" style="font-size:11px;">#${rule.priority ?? 100}</span>
        `;
        // 7. Actions (standard ghost buttons)
        const colActions = `
            <div class="config-table-actions" style="justify-content:flex-end;">
                <button type="button" class="btn btn-ghost btn-sm"
                    data-traffic-action="open-edit-rate-rule" data-traffic-value="${idx}"
                    aria-label="Edit rule ${escapeTrafficAttr(rule.pattern)}">
                    Edit
                </button>
                <button type="button" class="operator-btn operator-btn-secondary btn-xs flow-rate-remove-rule"
                                                data-traffic-action="remove-rate-rule" data-traffic-value="${idx}"
                                                aria-label="Remove rule ${escapeTrafficAttr(rule.pattern)}">
                    Delete
                </button>
            </div>
        `;
        return [colRoute, colMatch, colRate, colAction, colEngine, colPriority, colActions];
    });
    const rulesTable = SectionUI.renderEnterpriseTable({
        columns: ['Target Route', 'Scope & Match', 'Rate & Burst', 'Mitigation', 'Engine Tuning', 'Priority', 'Actions'],
        rows: tableRows,
        className: 'rate-limit-rules-table',
        emptyTitle: 'No rate limit rules defined',
        emptyMessage: 'Add your first rate limit rule to enforce route-specific request quotas, burst allowances, and mitigation actions.',
        emptyAction: `
            <button type="button" class="btn btn-primary btn-sm" data-traffic-action="open-add-rate-rule" style="margin-top:12px;">
                ${iconPlus} <span>Create First Rule</span>
            </button>
        `
    });
    const toolbar = totalRules > 0 ? `
        <div class="rate-rules-table-toolbar" aria-label="Rate limit rules summary">
            <div class="rate-rules-table-metrics">
                <span><strong>${totalRules}</strong> ${totalRules === 1 ? 'rule' : 'rules'}</span>
                ${blockCount > 0 ? `<span><strong>${blockCount}</strong> block</span>` : ''}
                ${challengeCount > 0 ? `<span><strong>${challengeCount}</strong> challenge</span>` : ''}
                ${dryRunCount > 0 ? `<span><strong>${dryRunCount}</strong> dry run</span>` : ''}
            </div>
            <div style="display:flex;align-items:center;gap:12px;">
                <span class="rate-rules-table-note">Rules evaluated in priority order from highest to lowest.</span>
                <button type="button" class="operator-btn operator-btn-primary flow-rate-add-rule" data-traffic-action="open-add-rate-rule-modal">
                    ${iconPlus} <span>Add Rule</span>
                </button>
            </div>
        </div>
    ` : '';
    return `
        <div class="flow-rate-table-surface">
            ${toolbar}
            ${rulesTable}
        </div>

        ${renderSaveButtons()}
    `;
}
function renderRateLimitRuleEditor(rule, editingIndex, icons) {
    const isEdit = rule !== null;
    const nameVal = rule?.name || '';
    const patternVal = rule?.pattern || '';
    const matchVal = rule?.match || 'glob';
    const priorityVal = rule?.priority ?? 100;
    const methodsVal = Array.isArray(rule?.methods) ? rule.methods.join(', ') : '';
    const hostsVal = Array.isArray(rule?.hosts) ? rule.hosts.join(', ') : '';
    const rateVal = rule?.rate || 60;
    const burstVal = rule?.burst || 10;
    const windowVal = rule?.window === '1s' || rule?.window === '1m' || rule?.window === '1h' ? rule.window : '1m';
    const actionVal = rule?.action || (rule?.dry_run ? 'dry_run' : 'block');
    const algoVal = rule?.algorithm || 'token_bucket';
    const keyByVal = rule?.key_by || 'ip';
    const bypassStaticVal = rule?.bypass_static !== false;
    const graceVal = rule?.verified_grace_multiplier || 2;
    const iconBan = icons.ban || '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>';
    const iconShield = icons.shield || '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
    const iconEye = icons.eye || '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    return `
        <div class="flow-rate-rule-editor">
            <!-- Back Navigation -->
            <div style="margin-bottom:16px;">
                ${SectionUI.renderOperatorBackButton({
        label: 'Back to Rate Limit Rules',
        attrs: 'data-traffic-action="cancel-rate-rule-editor"'
    })}
            </div>

            <!-- Hidden Action Input for Syncing Button-Group Value -->
            <input type="hidden" id="rl-rule-action" value="${escapeTrafficAttr(actionVal)}">

            <!-- Card 1: Route Target & Scope -->
            <div class="card section-panel mb-16" style="padding:20px;border-radius:8px;background:var(--surface-base);border:1px solid var(--border-subtle);margin-bottom:16px;">
                <div class="grid-2 gap-16" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:16px;margin-bottom:16px;">
                    <div class="section-form-group">
                        <label class="section-form-label font-600" for="rl-rule-name">
                            Rule Name (Optional)
                            ${SectionUI.renderInfoTooltip('A friendly descriptor to identify this rule in the policies table.')}
                        </label>
                        <input type="text" id="rl-rule-name" class="section-input" value="${escapeTrafficAttr(nameVal)}" placeholder="e.g. Auth Login Throttling">
                    </div>

                    <div class="section-form-group">
                        <label class="section-form-label font-600" for="rl-rule-pattern">
                            Target Path Pattern <span class="text-danger">*</span>
                            ${SectionUI.renderInfoTooltip('Must start with "/". Supports wildcards (e.g. /checkout/*, /api/**).')}
                        </label>
                        <input type="text" id="rl-rule-pattern" class="section-input font-mono" value="${escapeTrafficAttr(patternVal)}" placeholder="/api/v1/auth/login*">
                    </div>
                </div>

                <div class="grid-2 gap-16" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:16px;margin-bottom:16px;">
                    <div class="section-form-group">
                        <label class="section-form-label font-600" for="rl-rule-match">
                            Match Type
                            ${SectionUI.renderInfoTooltip('Pattern matching strategy: Glob wildcard, Path Prefix, or Exact URI match.')}
                        </label>
                        <select id="rl-rule-match" class="section-input">
                            <option value="glob" ${matchVal === 'glob' ? 'selected' : ''}>Glob Wildcard (*) - Matches paths with wildcards</option>
                            <option value="prefix" ${matchVal === 'prefix' ? 'selected' : ''}>Path Prefix - Matches all sub-paths under prefix</option>
                            <option value="exact" ${matchVal === 'exact' ? 'selected' : ''}>Exact Match - Matches exact URI path only</option>
                        </select>
                    </div>

                    <div class="section-form-group">
                        <label class="section-form-label font-600" for="rl-rule-priority">
                            Evaluation Priority
                            ${SectionUI.renderInfoTooltip('Rules with lower numbers are evaluated first (e.g. #10 before #100).')}
                        </label>
                        <input type="number" id="rl-rule-priority" class="section-input font-mono" value="${priorityVal}" min="0" placeholder="100">
                    </div>
                </div>

                <div class="grid-2 gap-16" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:16px;">
                    <div class="section-form-group">
                        <label class="section-form-label font-600" for="rl-rule-methods">
                            HTTP Methods
                            ${SectionUI.renderInfoTooltip('Comma-separated methods (e.g. POST, PUT). Leave blank to apply to all HTTP methods.')}
                        </label>
                        <input type="text" id="rl-rule-methods" class="section-input font-mono" value="${escapeTrafficAttr(methodsVal)}" placeholder="POST, PUT (leave blank for ALL)">
                    </div>

                    <div class="section-form-group">
                        <label class="section-form-label font-600" for="rl-rule-hosts">
                            Host Constraint (Optional)
                            ${SectionUI.renderInfoTooltip('Restrict this policy to specific virtual hosts or domains (e.g. api.example.com). Leave blank for ANY host.')}
                        </label>
                        <input type="text" id="rl-rule-hosts" class="section-input font-mono" value="${escapeTrafficAttr(hostsVal)}" placeholder="api.example.com (leave blank for ANY)">
                    </div>
                </div>
            </div>

            <!-- Card 2: Request Allowance & Burst Capacity (The Sliders) -->
            <div class="card section-panel mb-16" style="padding:20px;border-radius:8px;background:var(--surface-base);border:1px solid var(--border-subtle);margin-bottom:16px;">
                <div class="flow-ddos-threshold-grid" style="margin:0;">
                    <!-- Request Allowance Box -->
                    <div class="flow-ddos-threshold">
                        <div class="flow-ddos-control-head">
                            <div>
                                <strong style="font-size: 12px; font-weight: 700; display: inline-flex; align-items: center;">
                                    Request Allowance
                                    ${SectionUI.renderInfoTooltip('Maximum allowed requests on this route within the selected rolling window.')}
                                </strong>
                            </div>
                            <div class="flow-ddos-value">
                                <input type="number" id="rl-rule-rate" value="${rateVal}" min="1" max="100000" step="10"
                                    data-traffic-sync-target="rl-rule-rate-slider" aria-label="Request allowance">
                                <select id="rl-rule-window" aria-label="Rate window unit">
                                    <option value="1s" ${windowVal === '1s' ? 'selected' : ''}>/ sec</option>
                                    <option value="1m" ${windowVal === '1m' ? 'selected' : ''}>/ min</option>
                                    <option value="1h" ${windowVal === '1h' ? 'selected' : ''}>/ hr</option>
                                </select>
                            </div>
                        </div>
                        <input type="range" id="rl-rule-rate-slider" class="flow-ddos-range" value="${Math.min(rateVal, 5000)}" min="1" max="5000" step="10"
                            data-traffic-sync-target="rl-rule-rate" aria-label="Request allowance slider">
                        <div class="flow-ddos-range-scale" aria-hidden="true">
                            <span>1 req</span><span>1,000</span><span>2,500</span><span>5,000 req</span>
                        </div>
                    </div>

                    <!-- Burst Headroom Box -->
                    <div class="flow-ddos-threshold">
                        <div class="flow-ddos-control-head">
                            <div>
                                <strong style="font-size: 12px; font-weight: 700; display: inline-flex; align-items: center;">
                                    Burst Headroom
                                    ${SectionUI.renderInfoTooltip('Spike capacity above the allowance before mitigation actions trigger.')}
                                </strong>
                            </div>
                            <div class="flow-ddos-value">
                                <input type="number" id="rl-rule-burst" value="${burstVal}" min="0" max="5000" step="5"
                                    data-traffic-sync-target="rl-rule-burst-slider" aria-label="Burst capacity">
                                <span>burst req</span>
                            </div>
                        </div>
                        <input type="range" id="rl-rule-burst-slider" class="flow-ddos-range" value="${Math.min(burstVal, 1000)}" min="0" max="1000" step="5"
                            data-traffic-sync-target="rl-rule-burst" aria-label="Burst capacity slider">
                        <div class="flow-ddos-range-scale" aria-hidden="true">
                            <span>0</span><span>250</span><span>500</span><span>1,000 burst</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Card 3: Mitigation Action & Engine Parameters -->
            <div class="card section-panel mb-24" style="padding:20px;border-radius:8px;background:var(--surface-base);border:1px solid var(--border-subtle);margin-bottom:24px;">
                <!-- Mitigation Action Options -->
                <div style="margin-bottom:20px;">
                    <strong style="font-size:12px;font-weight:700;display:flex;align-items:center;gap:6px;margin-bottom:10px;">
                        Mitigation Action when Limit Exceeded
                        ${SectionUI.renderInfoTooltip('Response triggered when request rate or burst capacity is exceeded.')}
                    </strong>
                    <div class="flow-ddos-actions" role="radiogroup" aria-label="Mitigation Action when Limit Exceeded" style="padding:0;margin:0;">
                        <button type="button" class="flow-ddos-action flow-rate-action-btn ${actionVal === 'block' ? 'is-active' : ''}"
                            data-traffic-action="set-rule-action" data-traffic-value="block"
                            role="radio" aria-checked="${actionVal === 'block'}">
                            <span class="flow-ddos-action-icon">${iconBan}</span>
                            <span><strong>Strict Block (HTTP 429)</strong><small>Return 429 Too Many Requests with Retry-After header.</small></span>
                            <i aria-hidden="true"></i>
                        </button>
                        <button type="button" class="flow-ddos-action flow-rate-action-btn ${actionVal === 'challenge' ? 'is-active' : ''}"
                            data-traffic-action="set-rule-action" data-traffic-value="challenge"
                            role="radio" aria-checked="${actionVal === 'challenge'}">
                            <span class="flow-ddos-action-icon">${iconShield}</span>
                            <span><strong>Smart Challenge</strong><small>Serve interactive browser challenge before dropping.</small></span>
                            <i aria-hidden="true"></i>
                        </button>
                        <button type="button" class="flow-ddos-action flow-rate-action-btn ${actionVal === 'dry_run' ? 'is-active' : ''}"
                            data-traffic-action="set-rule-action" data-traffic-value="dry_run"
                            role="radio" aria-checked="${actionVal === 'dry_run'}">
                            <span class="flow-ddos-action-icon">${iconEye}</span>
                            <span><strong>Observe Only (Dry Run)</strong><small>Log violations in threat logs without blocking requests.</small></span>
                            <i aria-hidden="true"></i>
                        </button>
                    </div>
                </div>

                <!-- Engine Parameters Grid -->
                <div class="grid-2 gap-16" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:16px;margin-bottom:16px;">
                    <div class="section-form-group">
                        <label class="section-form-label font-600" for="rl-rule-algorithm">
                            Measurement Algorithm
                            ${SectionUI.renderInfoTooltip('Mathematical model used to meter and replenish request budgets: Token Bucket, Sliding Window, or Fixed Window.')}
                        </label>
                        <select id="rl-rule-algorithm" class="section-input">
                            <option value="token_bucket" ${algoVal === 'token_bucket' ? 'selected' : ''}>Token Bucket (Smooth refill &amp; burst)</option>
                            <option value="sliding_window" ${algoVal === 'sliding_window' ? 'selected' : ''}>Sliding Window (Rolling time window)</option>
                            <option value="fixed_window" ${algoVal === 'fixed_window' ? 'selected' : ''}>Fixed Window (Clock interval counters)</option>
                        </select>
                    </div>

                    <div class="section-form-group">
                        <label class="section-form-label font-600" for="rl-rule-key-by">
                            Client Tracking Key
                            ${SectionUI.renderInfoTooltip('Identifier used to isolate distinct client request counters (IP, IP + User Agent, Session Cookie, or Authorization Token).')}
                        </label>
                        <select id="rl-rule-key-by" class="section-input">
                            <option value="ip" ${keyByVal === 'ip' ? 'selected' : ''}>Client IP address</option>
                            <option value="ip_ua" ${keyByVal === 'ip_ua' ? 'selected' : ''}>Client IP + User Agent</option>
                            <option value="cookie" ${keyByVal === 'cookie' ? 'selected' : ''}>Session Cookie (session_id)</option>
                            <option value="token" ${keyByVal === 'token' ? 'selected' : ''}>Bearer API Token (Authorization)</option>
                        </select>
                    </div>
                </div>

                <!-- Exemptions & Grace in 2 columns -->
                <div class="grid-2 gap-16" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:16px;align-items:center;">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:var(--surface-subtle);border-radius:6px;border:1px solid var(--border-subtle);">
                        <div>
                            <strong style="font-size:13px;font-weight:600;display:inline-flex;align-items:center;gap:6px;">
                                Bypass Static Assets
                                ${SectionUI.renderInfoTooltip('Exclude images, CSS, JS, and fonts from consuming quota tokens.')}
                            </strong>
                        </div>
                        <label class="section-switch">
                            <input type="checkbox" id="rl-rule-bypass-static" aria-label="Bypass static assets" ${bypassStaticVal ? 'checked' : ''}>
                            <span class="switch-slider"></span>
                        </label>
                    </div>

                    <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:var(--surface-subtle);border-radius:6px;border:1px solid var(--border-subtle);">
                        <div>
                            <strong style="font-size:13px;font-weight:600;display:inline-flex;align-items:center;gap:6px;">
                                Verified-Client Grace
                                ${SectionUI.renderInfoTooltip('Budget multiplier for verified search engine bots and authenticated users.')}
                            </strong>
                        </div>
                        <div style="display:flex;align-items:center;gap:6px;">
                            <input type="number" id="rl-rule-grace" value="${graceVal}" min="1" max="10" step="0.5" class="section-input font-mono" style="width:72px;text-align:right;">
                            <span style="font-size:12px;font-weight:600;color:var(--text-muted);">&times; rate</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Editor Bottom Action Bar -->
            <div class="section-editor-footer" style="display:flex;align-items:center;justify-content:flex-end;gap:12px;padding:16px 0;border-top:1px solid var(--border-subtle);">
                <button type="button" class="operator-btn operator-btn-secondary" data-traffic-action="cancel-rate-rule-editor">
                    Cancel
                </button>
                <button type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-rate-rule">
                    ${isEdit ? 'Update Rule' : 'Create Rule'}
                </button>
            </div>
        </div>
    `;
}
