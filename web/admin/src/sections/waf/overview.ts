/**
 * WAF Overview Tab (Community)
 * Live protection statistics, sensitivity sliders, profile selection, and inspection limits.
 */
import { SectionUI } from '../ui-components.js';
import { escapeWafHtml } from '../waf-runtime-helpers.js';
import {
    WAFConfigDashboardStats,
    WAFCustomRule,
    WAFExclusion,
    WAFManagedRuleFile,
    WAFProfile,
    WAFSectionConfig
} from './types.js';
import { formatWafMebibytes } from './leak-protection.js';

export function renderOverviewTab(
    config: WAFSectionConfig,
    profiles: WAFProfile[],
    crsRules: WAFManagedRuleFile[],
    rules: WAFCustomRule[],
    exclusions: WAFExclusion[],
    stats: WAFConfigDashboardStats,
    health: Record<string, any>,
    isExclusionExpired: (e: WAFExclusion) => boolean,
    getIcon: (name: string) => string
): string {
    const activeProfile = config.active_profile_id ? profiles.find(p => p.id === config.active_profile_id) : null;
    const wafMode = config.mode || 'off';
    const failureMode = config.failure_mode || 'fail_open';
    const modeLabel = wafMode === 'blocking' ? 'Blocking' : (wafMode === 'detection' ? 'Detection' : 'Off');
    const activeManagedRules = crsRules.filter(r => r.enabled !== false).length;
    const activeCustomRules = rules.filter(r => r.enabled !== false).length;
    const activeExclusions = exclusions.filter(e => e.enabled !== false && !isExclusionExpired(e)).length;
    const reloadFailed = health.reload?.status === 'failed';
    const telemetry = health.telemetry;
    const telemetryDropped = telemetry?.dropped_events || 0;
    const telemetryUnhealthy = telemetry?.db_available === false
        || telemetryDropped > 0
        || telemetry?.freshness_status === 'delayed'
        || telemetry?.freshness_status === 'stale';
    const telemetryWarning = telemetryDropped > 0 ? `
        <div class="section-warning-box">
            <div class="section-warning-icon">${SectionUI.icons.alertTriangle}</div>
            <div>
                <div class="section-warning-title">Security activity may be incomplete</div>
                <div class="section-warning-text">${escapeWafHtml(`${telemetryDropped.toLocaleString()} request events could not be recorded. Dashboard totals may be incomplete.`)}</div>
            </div>
        </div>
    ` : '';
    const totalReq = stats.total_requests || 0;
    const blockedReq = stats.blocked_requests || 0;
    const blockRate = totalReq > 0 ? (blockedReq / totalReq) * 100 : 0;
    const threshold = config.anomaly_threshold || 5;
    const paranoiaLevel = Number(config.rule_strictness || 1);
    const loadedManagedRules = health.rules?.crs_rules_loaded ?? activeManagedRules;
    const loadedCustomRules = health.rules?.custom_rules_loaded ?? activeCustomRules;
    const loadedRules = loadedManagedRules + loadedCustomRules;
    const requestBodyLimit = typeof config.max_request_body_size === 'number' && config.max_request_body_size > 0
        ? Math.trunc(config.max_request_body_size)
        : 10 * 1024 * 1024;
    const responseBodyLimit = typeof config.max_response_body_size === 'number' && config.max_response_body_size > 0
        ? Math.trunc(config.max_response_body_size)
        : 1024 * 1024;
    const profileDescription = activeProfile?.description || 'Customize the protection sensitivity and action threshold for your application.';
    const profileOptions = [
        `<option value="" ${activeProfile ? '' : 'selected'}>Custom Profile</option>`,
        ...profiles.map(profile => `<option value="${escapeWafHtml(profile.id)}" ${config.active_profile_id === profile.id ? 'selected' : ''}>${escapeWafHtml(profile.name)}</option>`)
    ].join('');
    const paranoiaWarning = paranoiaLevel >= 3 ? `
        <div class="section-warning-box">
            <div class="section-warning-icon">${SectionUI.icons.alertTriangle}</div>
            <div>
                <div class="section-warning-title">${paranoiaLevel === 4 ? 'Paranoid mode can block valid traffic' : 'Strict mode may increase false positives'}</div>
                <div class="section-warning-text">Test important application journeys and review exceptions before using this level.</div>
            </div>
            <button type="button" class="btn btn-outline btn-sm" data-waf-action="switch-tab" data-waf-value="exclusions">Review</button>
        </div>
    ` : '';
    const highProfileWarning = activeProfile && paranoiaLevel > (activeProfile.paranoia_level || 1) + 1 ? `
        <div class="section-warning-box">
            <div class="section-warning-icon">${SectionUI.icons.alertTriangle}</div>
            <div>
                <div class="section-warning-title">High false-positive risk</div>
                <div class="section-warning-text">The selected sensitivity is much higher than recommended for <strong>${escapeWafHtml(activeProfile.name)}</strong>.</div>
            </div>
        </div>
    ` : '';

    const modeChoices = [
        { value: 'off', label: 'Off' },
        { value: 'detection', label: 'Detect' },
        { value: 'blocking', label: 'Block' }
    ];
    const metrics = SectionUI.renderOperatorMetricStrip([
        {
            label: 'Protection mode',
            value: `<span data-waf-kpi-value="mode">${escapeWafHtml(modeLabel)}</span>`,
            sub: `<span data-waf-kpi-note="mode">${escapeWafHtml(wafMode === 'blocking' ? 'Enforcing matches' : wafMode === 'detection' ? 'Observation only' : 'Inspection bypassed')}</span>`,
            tone: wafMode === 'blocking' ? 'danger' : wafMode === 'detection' ? 'warning' : 'neutral'
        },
        {
            label: 'Requests inspected',
            value: `<span data-waf-kpi-value="requests">${totalReq.toLocaleString()}</span>`,
            sub: '<span data-waf-kpi-note="requests">Last 24 hours</span>',
            tone: 'neutral'
        },
        {
            label: 'Requests blocked',
            value: `<span data-waf-kpi-value="blocked">${blockedReq.toLocaleString()}</span>`,
            sub: `<span data-waf-kpi-note="blocked">${blockRate.toFixed(1)}% block rate</span>`,
            tone: blockedReq > 0 ? 'danger' : 'neutral'
        },
        {
            label: 'Loaded rules',
            value: `<span data-waf-kpi-value="loaded-rules">${loadedRules.toLocaleString()}</span>`,
            sub: `<span data-waf-kpi-note="loaded-rules">${escapeWafHtml(reloadFailed ? 'Update failed' : 'Managed and custom protections')}</span>`,
            tone: reloadFailed ? 'danger' : loadedRules > 0 ? 'success' : 'neutral'
        }
    ], 'firewall-overview-metrics');
    const ruleLinks = [
        { tab: 'managed', label: 'Managed rules', value: activeManagedRules, note: 'Built-in protections', icon: 'folder' },
        { tab: 'custom', label: 'Custom rules', value: activeCustomRules, note: 'Rules for your applications', icon: 'list' },
        { tab: 'exclusions', label: 'Exclusions', value: activeExclusions, note: 'Exceptions currently in use', icon: 'filter' }
    ];

    return `
        <div class="firewall-overview-stack">
            ${reloadFailed ? `<div class="section-warning-box"><div class="section-warning-icon">${SectionUI.icons.alertTriangle}</div><div><div class="section-warning-title">The latest protection update was not applied</div><div class="section-warning-text">Your previous protection settings remain active. Review the configuration and try again.</div></div></div>` : ''}
            ${telemetryWarning}
            ${SectionUI.renderOperatorSection('Protection statistics', metrics, {
                subtitle: 'Live inspection activity and the currently loaded rule set.'
            })}

            ${SectionUI.renderOperatorSection('Protection configuration', `
                ${highProfileWarning}
                ${paranoiaWarning}

                <div class="operator-control-list">
                    ${SectionUI.renderOperatorControlRow({
                        title: 'Protection mode',
                        description: 'Choose whether suspicious requests are bypassed (Off), logged for evaluation (Detect), or actively dropped (Block).',
                        icon: getIcon('shield'),
                        enabled: wafMode !== 'off',
                        actions: `<select class="select-sm" aria-label="WAF protection mode" data-waf-field="mode">
                            ${modeChoices.map(option => `<option value="${option.value}" ${wafMode === option.value ? 'selected' : ''}>${escapeWafHtml(option.label)}</option>`).join('')}
                        </select>`
                    })}
                    ${SectionUI.renderOperatorControlRow({
                        title: 'Protection profile',
                        description: escapeWafHtml(profileDescription),
                        icon: getIcon('layers'),
                        enabled: Boolean(activeProfile),
                        actions: `<select class="select-sm" aria-label="WAF protection profile" data-waf-field="active_profile_id">
                            ${profileOptions}
                        </select>`
                    })}
                    ${SectionUI.renderOperatorControlRow({
                        title: 'Rule sensitivity',
                        description: 'Higher levels inspect for more attack patterns and sensitive endpoints, but increase false-positive risk.',
                        icon: getIcon('sliders'),
                        enabled: paranoiaLevel > 1,
                        actions: `<select class="select-sm" aria-label="WAF rule sensitivity" data-waf-field="rule_strictness" data-waf-value-type="number">
                            <option value="1" ${paranoiaLevel === 1 ? 'selected' : ''}>Standard (PL1)</option>
                            <option value="2" ${paranoiaLevel === 2 ? 'selected' : ''}>Balanced (PL2)</option>
                            <option value="3" ${paranoiaLevel === 3 ? 'selected' : ''}>Strict (PL3)</option>
                            <option value="4" ${paranoiaLevel === 4 ? 'selected' : ''}>Paranoid (PL4)</option>
                        </select>`
                    })}
                    ${SectionUI.renderOperatorControlRow({
                        title: 'Anomaly threshold',
                        description: 'Cumulative threat score required before taking action. Lower scores block sooner; higher scores tolerate more signals.',
                        icon: getIcon('activity'),
                        enabled: true,
                        actions: `<label class="operator-number"><input type="number" min="1" max="20" value="${threshold}" aria-label="WAF anomaly threshold" data-waf-field="anomaly_threshold" data-waf-value-type="number"><span>score</span></label>`
                    })}
                </div>
            `, {
                subtitle: 'Choose how Aegis responds to suspicious requests, select a protection profile, then tune sensitivity and the action threshold.'
            })}

            ${SectionUI.renderOperatorSection('Rules and inspection limits', `
                <div class="operator-control-list">
                    ${ruleLinks.map(item => SectionUI.renderOperatorControlRow({
                        title: escapeWafHtml(item.label),
                        description: escapeWafHtml(item.note),
                        icon: getIcon(item.icon),
                        enabled: item.value > 0,
                        actions: `<button type="button" class="btn btn-outline btn-sm" data-waf-action="switch-tab" data-waf-value="${item.tab}">Manage</button>`
                    })).join('')}
                </div>

                <div class="operator-control-list mt-16">
                    ${SectionUI.renderOperatorControlRow({
                        title: 'Inspection failure behavior',
                        description: 'Fallback action when request inspection times out, exceeds parser constraints, or encounters engine errors.',
                        icon: getIcon('alertTriangle'),
                        enabled: failureMode !== 'fail_open',
                        actions: `<select class="select-sm" aria-label="WAF inspection failure behavior" data-waf-field="failure_mode" data-waf-render="true">
                            <option value="fail_open" ${failureMode === 'fail_open' ? 'selected' : ''}>Continue traffic</option>
                            <option value="fail_closed" ${failureMode === 'fail_closed' ? 'selected' : ''}>Block request</option>
                            <option value="service_unavailable" ${failureMode === 'service_unavailable' ? 'selected' : ''}>Show service unavailable</option>
                        </select>`
                    })}
                    ${SectionUI.renderOperatorControlRow({
                        title: 'Request body inspection limit',
                        description: 'Maximum request payload size evaluated by inspection rules. Payload data exceeding this threshold bypasses deep inspection to preserve throughput (up to 64 MiB).',
                        icon: getIcon('file'),
                        enabled: true,
                        actions: `<label class="operator-number"><input type="number" min="0.5" max="64" step="0.5" value="${formatWafMebibytes(requestBodyLimit)}" inputmode="decimal" aria-label="Request body inspection limit in MiB" data-waf-field="max_request_body_size" data-waf-value-type="number" data-waf-value-scale="1048576"><span>MiB</span></label>`
                    })}
                    ${SectionUI.renderOperatorControlRow({
                        title: 'Response body inspection limit',
                        description: 'Maximum response payload size evaluated for outbound threat detection and data leakage. Larger thresholds provide deeper inspection with slight latency overhead (up to 64 MiB).',
                        icon: getIcon('fileText'),
                        enabled: config.response_inspection === true,
                        actions: `<label class="operator-number"><input type="number" min="0.5" max="64" step="0.5" value="${formatWafMebibytes(responseBodyLimit)}" inputmode="decimal" aria-label="Response body inspection limit in MiB" data-waf-field="max_response_body_size" data-waf-value-type="number" data-waf-value-scale="1048576"><span>MiB</span></label>`
                    })}
                </div>
            `, {
                subtitle: 'Choose what the firewall inspects and set limits that fit your application request and response sizes.'
            })}

        </div>
        ${SectionUI.renderSaveButton('WAFConfig')}
    `;
}
