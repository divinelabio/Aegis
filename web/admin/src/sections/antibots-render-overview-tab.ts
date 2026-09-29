import type {
    AntibotConfigState,
    AntibotAnalyticsEvent,
    AntibotAnalyticsState,
    AntibotOverrideRule,
    AntibotRule
} from './antibots-config-shared.js';
import { SectionUI } from './ui-components.js';

type FormatNumberFn = (value: number | string) => string;

const actionLabels: Record<string, string> = {
    log: 'Observed',
    allow: 'Allowed',
    challenge: 'Challenged',
    challenge_passed: 'Challenge Passed',
    challenge_failed: 'Challenge Failed',
    block: 'Blocked',
    rate_limit: 'Rate Limited'
};

export function renderAntibotOverviewTab(
    config: AntibotConfigState,
    analytics: AntibotAnalyticsState,
    rules: AntibotRule[],
    formatNumber: FormatNumberFn
): string {
    const actions = analytics.summary.by_action || {};
    const empty = !analytics.loading && !analytics.error && analytics.events.length === 0;
    const challengeOutcomes = (actions.challenge_passed || 0) + (actions.challenge_failed || 0);
    const protectedSignals = countProtectedSignals(config);
    const metrics = SectionUI.renderOperatorMetricStrip([
        { label: 'Recent Events', value: formatNumber(analytics.summary.total || 0), sub: 'Observed decisions', tone: 'neutral' },
        { label: 'Blocked', value: formatNumber(actions.block || 0), sub: 'Stopped requests', tone: 'danger' },
        { label: 'Challenged', value: formatNumber(actions.challenge || challengeOutcomes), sub: 'Verification flows', tone: 'warning' },
        { label: 'Active Signals', value: formatNumber(protectedSignals), sub: 'Detection coverage', tone: 'success' }
    ]);

    return `
        <div class="bot-analytics-shell bot-operator-overview">
            ${analytics.loading ? '<div class="section-loading"><div class="spinner"></div><div class="mt-12">Loading bot analytics...</div></div>' : ''}
            ${analytics.error ? `<div class="section-error"><div class="error-message">${escapeHtml(analytics.error)}</div><button type="button" class="btn btn-sm" data-antibot-action="refresh-analytics">Try Again</button></div>` : ''}
            ${!analytics.loading && !analytics.error ? `
                ${SectionUI.renderOperatorSection('Protection statistics', metrics, {
                    subtitle: 'Managed scoring, rule overrides, challenge policy, and bot identity coverage.'
                })}

                ${renderProtectionModules(config, rules, formatNumber)}

                ${empty ? renderEmptyState() : `
                    ${SectionUI.renderOperatorSection('Operational intelligence', renderCompactOperatorIntelligence(config, analytics, formatNumber), {
                        subtitle: 'Recent bot decisions, tuning pressure, and challenge outcomes.'
                    })}
                    ${SectionUI.renderOperatorSection('Security events', renderCompactRecentEvents(analytics.events, analytics.expandedEventId), {
                        subtitle: 'Latest Bot Protection decisions from the analytics stream.'
                    })}
                `}
            ` : ''}
        </div>
    `;
}

function countProtectedSignals(config: AntibotConfigState): number {
    const signals = [
        config.detection?.enabled,
        config.enabled,
        config.behavioralEnabled,
        config.classification?.block_bad_bots,
        config.classification?.verify_search_engines,
        config.tls?.enabled,
        config.tls?.ja3_enabled,
        config.tls?.ja4_enabled,
        config.anti_evasion?.fp_rotation_detection,
        config.anti_evasion?.session_anomaly
    ];
    return signals.filter(Boolean).length;
}

function renderCompactOperatorIntelligence(
    config: AntibotConfigState,
    analytics: AntibotAnalyticsState,
    formatNumber: FormatNumberFn
): string {
    const recommendations = buildTuningRecommendations(config, analytics.events).slice(0, 2);
    const actions = analytics.summary.by_action || {};
    const challengeOutcomes = Number(actions.challenge_passed || 0) + Number(actions.challenge_failed || 0);
    return `
        <div class="grid cols-2 gap-16">
            <div class="card bot-analytics-card">
                <div class="card-header"><strong>Operational Tuning</strong></div>
                <div class="card-body bot-recommendation-list">
                    ${recommendations.length ? recommendations.map(renderRecommendation).join('') : `
                        <div class="bot-recommendation-empty">
                            <strong>No tuning pressure detected</strong>
                            <span>Recent bot decisions match the current ${escapeHtml(formatMode(String(config.risk_profile || 'balanced')))} profile.</span>
                        </div>
                    `}
                </div>
            </div>
            <div class="card bot-analytics-card">
                <div class="card-header"><strong>Decision Snapshot</strong></div>
                <div class="card-body bot-aggregate-grid">
                    ${decisionSnapshotItem('Observed', formatNumber(actions.log || actions.allow || 0))}
                    ${decisionSnapshotItem('Challenged', formatNumber(actions.challenge || challengeOutcomes))}
                    ${decisionSnapshotItem('Blocked', formatNumber(actions.block || 0))}
                    ${decisionSnapshotItem('Avg score', formatNumber(Math.round(analytics.summary.avg_score || 0)))}
                    ${decisionSnapshotItem('Block rate', `${formatPercent(analytics.summary.block_rate)}%`)}
                    ${decisionSnapshotItem('Challenge rate', `${formatPercent(analytics.summary.challenge_rate)}%`)}
                </div>
            </div>
        </div>
    `;
}

function decisionSnapshotItem(label: string, value: string): string {
    return `<div class="bot-aggregate-list"><div class="text-xs text-muted text-uc">${escapeHtml(label)}</div><strong>${escapeHtml(value)}</strong></div>`;
}

function renderCompactRecentEvents(events: AntibotAnalyticsEvent[], expandedId: string | null): string {
    const visible = events.slice(0, 6);
    return `
        <div class="card bot-analytics-card">
            <div class="card-header flex justify-between align-center gap-12">
                <strong>Security Events</strong>
            </div>
            <div class="table-container bot-events-table bot-events-table-compact">
                <table>
                    <thead><tr><th>Time</th><th>Action</th><th>Rule</th><th>Source</th><th>Request</th><th>Score</th></tr></thead>
                    <tbody>${visible.length ? visible.map(event => renderCompactEventRows(event, expandedId === event.id)).join('') : '<tr><td colspan="6" class="text-center text-muted py-24">No recent bot protection events</td></tr>'}</tbody>
                </table>
            </div>
        </div>
    `;
}

function renderCompactEventRows(event: AntibotAnalyticsEvent, expanded: boolean): string {
    const fields = event.matched_fields || {};
    const decisionSource = fields.decision_source || '-';
    const challengeType = fields.challenge_type || '-';
    const formattedTimestamp = formatDate(event.timestamp);
    const detailId = `bot-event-detail-${encodeURIComponent(event.id)}`;
    const detailAction = expanded ? 'Hide' : 'Show';
    return `
        <tr class="bot-event-row">
            <td class="text-muted text-xs"><button type="button" class="bot-event-toggle" data-antibot-action="toggle-analytics-event" data-antibot-value="${escapeAttr(event.id)}" aria-expanded="${expanded}" aria-controls="${escapeAttr(detailId)}" aria-label="${escapeAttr(`${detailAction} details for bot security event at ${formattedTimestamp}`)}"><span aria-hidden="true">${escapeHtml(formattedTimestamp)}</span></button></td>
            <td><span class="status-pill ${escapeAttr(event.action)}">${escapeHtml(actionLabels[event.action] || event.action)}</span></td>
            <td>${escapeHtml(event.rule_name || event.section || '-')}</td>
            <td class="text-mono">${escapeHtml(event.client_ip || '-')}</td>
            <td class="text-mono truncate-200">${escapeHtml(`${event.method || '-'} ${event.path || '-'}`)}</td>
            <td>${event.score ?? '-'}</td>
        </tr>
        ${expanded ? `<tr class="bot-event-detail-row"><td colspan="6">
            <div id="${escapeAttr(detailId)}" class="bot-event-detail compact">
                <div><span>Decision Source</span><strong>${escapeHtml(formatDecisionValue(decisionSource))}</strong></div>
                <div><span>Challenge Type</span><strong>${escapeHtml(formatDecisionValue(challengeType))}</strong></div>
                <div><span>User Agent</span><strong>${escapeHtml(event.user_agent || '-')}</strong></div>
                <div><span>Reason</span><strong>${escapeHtml(fields.reason || '-')}</strong></div>
            </div>
        </td></tr>` : ''}
    `;
}







type TuningRecommendation = {
    tone: 'success' | 'warning' | 'danger' | 'primary';
    title: string;
    detail: string;
    actions: string[];
};

type ChallengeSolveTrend = {
    key: string;
    label: string;
    passed: number;
    failed: number;
    total: number;
    solveRate: number;
};

function buildTuningRecommendations(config: AntibotConfigState, events: AntibotAnalyticsEvent[]): TuningRecommendation[] {
    const recommendations: TuningRecommendation[] = [];
    const pathTrends = challengeTrendBy(events, (event) => event.path || '');
    const ipTrends = challengeTrendBy(events, (event) => event.client_ip || '');
    const uaTrends = challengeTrendBy(events, (event) => event.user_agent || '');
    const challengeEvents = events.filter((event) => event.action === 'challenge' || event.action === 'challenge_passed' || event.action === 'challenge_failed');
    const blocked = events.filter((event) => event.action === 'block').length;
    const total = Math.max(events.length, 1);

    for (const trend of pathTrends.slice(0, 3)) {
        if (trend.total >= 3 && trend.solveRate >= 80) {
            recommendations.push({
                tone: 'warning',
                title: `High solve rate on ${trend.label}`,
                detail: `${trend.passed}/${trend.total} recent challenges passed. This path may be safe to bypass or soften.`,
                actions: [
                    exceptionAction('Add path exception', 'paths', trend.key),
                    quickRuleAction('Challenge path rule', 'challenge_path', trend.key, 'challenge')
                ]
            });
        }
    }

    for (const trend of ipTrends.slice(0, 3)) {
        if (trend.total >= 2 && trend.solveRate <= 25) {
            recommendations.push({
                tone: 'danger',
                title: `Repeated failed challenges from ${trend.label}`,
                detail: `${trend.failed}/${trend.total} recent challenges failed. This source is a strong block candidate.`,
                actions: [
                    quickRuleAction('Block IP', 'block_ip', trend.key, 'block'),
                    quickRuleAction('Challenge IP', 'challenge_ip', trend.key, 'challenge')
                ]
            });
        }
    }

    for (const trend of uaTrends.slice(0, 2)) {
        if (trend.total >= 3 && trend.solveRate >= 85) {
            recommendations.push({
                tone: 'primary',
                title: `Trusted automation candidate`,
                detail: `${trend.label} is repeatedly solving challenges. Review whether it belongs in trusted user agents.`,
                actions: [
                    exceptionAction('Trust user agent', 'user_agents', trend.key),
                    quickRuleAction('Block user agent', 'block_ua', trend.key, 'block')
                ]
            });
        }
    }

    const challengePressure = challengeEvents.length / total * 100;
    const blockPressure = blocked / total * 100;
    if (challengePressure > 45 && String(config.risk_profile || 'balanced') !== 'permissive') {
        recommendations.push({
            tone: 'warning',
            title: 'Challenge pressure is elevated',
            detail: `${challengePressure.toFixed(0)}% of recent bot events involve challenges. Consider permissive tuning on high-solve paths.`,
            actions: [tabAction('Review thresholds', 'overview'), tabAction('Open exceptions', 'exceptions')]
        });
    }
    if (blockPressure < 5 && challengePressure > 25 && String(config.risk_profile || 'balanced') === 'permissive') {
        recommendations.push({
            tone: 'primary',
            title: 'Permissive mode may be too soft',
            detail: 'Recent traffic is mostly challenged rather than blocked. Balanced mode may improve enforcement without jumping to aggressive.',
            actions: [tabAction('Review thresholds', 'overview')]
        });
    }

    return recommendations.slice(0, 5);
}


function challengeTrendBy(events: AntibotAnalyticsEvent[], keyFn: (event: AntibotAnalyticsEvent) => string): ChallengeSolveTrend[] {
    const trends = new Map<string, ChallengeSolveTrend>();
    for (const event of events) {
        const fields = event.matched_fields || {};
        const outcome = fields.challenge_outcome || (event.action === 'challenge_passed' ? 'passed' : event.action === 'challenge_failed' ? 'failed' : '');
        if (outcome !== 'passed' && outcome !== 'failed') continue;
        const key = keyFn(event).trim();
        if (!key) continue;
        const current = trends.get(key) || { key, label: key, passed: 0, failed: 0, total: 0, solveRate: 0 };
        if (outcome === 'passed') current.passed += 1;
        if (outcome === 'failed') current.failed += 1;
        current.total = current.passed + current.failed;
        current.solveRate = current.total ? current.passed / current.total * 100 : 0;
        trends.set(key, current);
    }
    return Array.from(trends.values()).sort((a, b) => b.total - a.total || b.solveRate - a.solveRate);
}

function renderRecommendation(recommendation: TuningRecommendation): string {
    return `
        <div class="bot-recommendation ${recommendation.tone}">
            <div>
                <strong>${escapeHtml(recommendation.title)}</strong>
                <span>${escapeHtml(recommendation.detail)}</span>
            </div>
            <div class="flex-row gap-8 flex-wrap">
                ${recommendation.actions.join('')}
            </div>
        </div>
    `;
}


function exceptionAction(label: string, key: string, target: string): string {
    return `<button type="button" class="btn btn-outline btn-sm"
        data-antibot-action="add-exception-value"
        data-antibot-exception-key="${escapeAttr(key)}"
        data-antibot-exception-value="${escapeAttr(target)}">${escapeHtml(label)}</button>`;
}

function quickRuleAction(label: string, kind: string, target: string, action: string): string {
    return quickRuleButton(label, kind, target, action);
}

function tabAction(label: string, tab: string): string {
    return `<button type="button" class="btn btn-outline btn-sm" data-antibot-action="switch-tab" data-antibot-value="${escapeAttr(tab)}">${escapeHtml(label)}</button>`;
}

function renderProtectionModules(config: AntibotConfigState, rules: AntibotRule[], formatNumber: FormatNumberFn): string {
    const detection = config.detection || {};
    const classification = config.classification || {};
    const aiCrawlers = config.ai_crawlers || {};
    const strictness = normalizeMode(config.strictness || config.mode || detection.mode || 'balanced');
    const responseMode = normalizeMode(config.response_mode || config.enforcement_mode || 'challenge');
    const aiRuleCount = countActiveRules(aiCrawlers.rules);
    const exceptionCount = countExceptions(config);
    const modules = [
        { title: 'Managed Protection', description: `${formatStrictness(strictness)} strictness / ${formatResponseMode(responseMode)}`, enabled: config.enabled !== false && detection.enabled !== false, icon: 'activity', tab: 'managed' },
        { title: 'Classification', description: formatClassificationSummary(classification), enabled: classification.enabled !== false, icon: 'tag', tab: 'classification' },
        { title: 'AI Crawlers', description: `${formatNumber(aiRuleCount)} crawler policies`, enabled: aiCrawlers.enabled !== false && aiRuleCount > 0, icon: 'bot', tab: 'ai' },
        { title: 'Custom Rules', description: `${formatNumber(rules.length)} custom rules`, enabled: rules.length > 0, icon: 'list', tab: 'rules' },
        { title: 'Exceptions', description: `${formatNumber(exceptionCount)} bypass entries`, enabled: exceptionCount > 0, icon: 'shield', tab: 'exceptions' }
    ];

    return SectionUI.renderOperatorSection('Security functions', `
        <div class="operator-control-list bot-operator-function-list">
            ${modules.map(module => SectionUI.renderOperatorControlRow({
        title: module.title,
        description: module.description,
        icon: SectionUI.icons[module.icon as keyof typeof SectionUI.icons] || SectionUI.icons.shield,
        enabled: module.enabled,
        actions: SectionUI.icons.arrowRight,
        className: 'bot-overview-module-row',
        attrs: `role="button" tabindex="0" aria-label="Configure ${escapeAttr(module.title)}" data-antibot-action="switch-tab" data-antibot-value="${escapeAttr(module.tab)}"`
    })).join('')}
        </div>
    `, {
        subtitle: 'Open a focused configuration page for each Bot Protection function.'
    });
}

function renderManagedProtectionSettings(config: AntibotConfigState, rules: AntibotRule[], _formatNumber: FormatNumberFn): string {
    const detection = config.detection || {};
    const strictness = normalizeMode(config.strictness || config.mode || detection.mode || 'balanced');
    const responseMode = normalizeMode(config.response_mode || config.enforcement_mode || 'challenge');
    const modeCard = (active: boolean, title: string, desc: string, attrs: string): string => `
        <button type="button" class="httpsec-mode-card ${active ? 'is-active' : ''}" aria-pressed="${active}" ${attrs}>
            <span class="httpsec-choice-check" aria-hidden="true">${active ? '&#10003;' : ''}</span>
            <strong>${escapeHtml(title)}</strong>
            <small>${escapeHtml(desc)}</small>
        </button>`;
    const overviewControls = `
        <div class="bot-operator-control-grid">
            <div class="bot-operator-control-card">
                <div>
                    <div class="bot-overview-setting-label">Strictness</div>
                    <div class="bot-overview-setting-value">${escapeHtml(formatStrictness(strictness))}</div>
                </div>
                <div class="httpsec-mode-cards httpsec-mode-cards-4" role="group" aria-label="Detection strictness">
                    ${[
        ['low', 'Low', 'Permissive: Minimizes verification challenges for regular visitors.'],
        ['balanced', 'Balanced', 'Recommended: Optimal security with low false-positive rates.'],
        ['high', 'High', 'Strict: Applies aggressive behavioral scoring for high-risk assets.'],
        ['under_attack', 'Under attack', 'Emergency: Enforces verification challenges on all non-verified traffic.']
    ].map(([value, label, desc]) => modeCard(strictness === value, label, desc, `data-antibot-action="set-field" data-antibot-field-path="strictness" data-antibot-value="${escapeAttr(value)}" data-antibot-render="true"`)).join('')}
                </div>
            </div>
            <div class="bot-operator-control-card">
                <div>
                    <div class="bot-overview-setting-label">Response mode</div>
                    <div class="bot-overview-setting-value">${escapeHtml(formatResponseMode(responseMode))}</div>
                </div>
                <div class="httpsec-mode-cards httpsec-mode-cards-3" role="group" aria-label="Response mode">
                    ${[
        ['log', 'Log only', 'Observe and record bot findings in analytics without mitigation.'],
        ['challenge', 'Challenge', 'Present interactive JavaScript or Captcha challenges to verify suspicious clients.'],
        ['block', 'Block', 'Instantly terminate connections from confirmed automated bots.']
    ].map(([value, label, desc]) => modeCard(responseMode === value, label, desc, `data-antibot-action="set-field" data-antibot-field-path="response_mode" data-antibot-value="${escapeAttr(value)}" data-antibot-render="true"`)).join('')}
                </div>
            </div>
        </div>
    `;
    const ruleAndChallengeControls = `
        <div class="operator-control-list bot-operator-action-list">
            ${SectionUI.renderOperatorControlRow({
        title: 'Custom rules',
        description: 'Use exact IP, ASN, country, path, user-agent, or score conditions.',
        icon: SectionUI.icons.list,
        enabled: rules.length > 0,
        actions: `<button type="button" class="btn btn-sm" data-antibot-action="show-add-rule-modal">Create Rule</button><button type="button" class="btn btn-outline btn-sm" data-antibot-action="switch-tab" data-antibot-value="rules">Manage Rules</button>`
    })}
            ${SectionUI.renderOperatorControlRow({
        title: 'Smart Challenge',
        description: 'Bot Protection decides when to challenge. Smart Challenge owns tiering, captcha, theme, and solve policy.',
        icon: SectionUI.icons.shieldCheck,
        enabled: responseMode === 'challenge',
        actions: '<button type="button" class="btn btn-outline btn-sm" data-nav-target="module_challenge">Open Smart Challenge</button>'
    })}
        </div>
    `;

    return `
        ${SectionUI.renderOperatorSection('Managed protection', overviewControls, {
        subtitle: 'Set scoring sensitivity and the response for suspicious traffic.'
    })}

        ${SectionUI.renderOperatorSection('Rules and challenge flow', ruleAndChallengeControls, {
        subtitle: 'Create exact matching rules or open Smart Challenge for the challenge experience.'
    })}

        ${SectionUI.renderSaveActionBar({
            actionAttr: 'data-antibot-action',
            resetAction: 'reset-config',
            saveAction: 'save-config'
        })}
    `;
}

export function renderAntibotManagedProtectionTab(
    config: AntibotConfigState,
    rules: AntibotRule[],
    formatNumber: FormatNumberFn
): string {
    return `<div class="bot-operator-managed">${renderManagedProtectionSettings(config, rules, formatNumber)}</div>`;
}

function renderEmptyState(): string {
    return `
            <div class="card bot-analytics-empty">
            <h4>No bot security events yet</h4>
            <p class="section-overview-sub">Aegis is ready to collect bot signals. Create bot rules to log, challenge, or block matching traffic, then events will appear here.</p>
            <div class="flex-row gap-8 justify-center">
                <button type="button" class="btn btn-sm" data-antibot-action="show-add-rule-modal">Create Rule</button>
            </div>
        </div>
    `;
}












function quickRuleButton(label: string, kind: string, target: string, action: string): string {
    return `<button type="button" class="btn btn-outline btn-sm"
        data-antibot-action="create-rule-from-event"
        data-antibot-rule-kind="${escapeAttr(kind)}"
        data-antibot-rule-action="${escapeAttr(action)}"
        data-antibot-rule-target="${escapeAttr(target)}">${escapeHtml(label)}</button>`;
}


function selectField(label: string, path: string, value: string, options: Array<[string, string]>): string {
    return `<label class="bot-overview-field">${escapeHtml(label)}
        <select class="select-sm" data-antibot-field-path="${escapeAttr(path)}" data-antibot-render="true">
            ${options.map(([optionValue, optionLabel]) => `<option value="${escapeAttr(optionValue)}" ${optionValue === value ? 'selected' : ''}>${escapeHtml(optionLabel)}</option>`).join('')}
        </select>
    </label>`;
}

function numberField(label: string, path: string, value: number, min: number, max: number): string {
    return `<label class="bot-overview-field">${escapeHtml(label)}
        <input class="input-sm" type="number" min="${min}" max="${max}" value="${escapeAttr(String(value))}" data-antibot-field-path="${escapeAttr(path)}" data-antibot-value-type="number">
    </label>`;
}




function normalizeMode(mode: string): string {
    const value = mode.trim().toLowerCase();
    return value || 'custom';
}

function formatMode(mode: string): string {
    return mode.charAt(0).toUpperCase() + mode.slice(1);
}

function formatStrictness(mode: string): string {
    const labels: Record<string, string> = {
        low: 'Low',
        balanced: 'Balanced',
        high: 'High',
        under_attack: 'Under Attack'
    };
    return labels[mode] || formatDecisionValue(mode);
}

function formatResponseMode(mode: string): string {
    const labels: Record<string, string> = {
        log: 'Log only',
        challenge: 'Challenge suspicious',
        block: 'Block high confidence'
    };
    return labels[mode] || formatDecisionValue(mode);
}

function formatThresholdLabel(label: string, value: unknown): string {
    return `${label} ${Number.isFinite(Number(value)) ? Number(value) : '-'}`;
}

function formatClassificationSummary(classification: AntibotConfigState['classification']): string {
    const parts: string[] = [];
    parts.push(classification?.block_bad_bots === false ? 'Bad bots not auto-blocked' : 'Bad bots blocked');
    parts.push(classification?.verify_search_engines ? 'search engines verified' : 'search engines not verified');
    parts.push(classification?.treat_unknown_as_bot ? 'unknowns treated as bots' : 'unknowns stay neutral');
    return parts.join(' · ');
}

function countActiveRules(rules: Record<string, AntibotOverrideRule> | undefined): number {
    if (!rules) return 0;
    return Object.values(rules).filter((value) => value.action.trim()).length;
}

function countExceptions(config: AntibotConfigState): number {
    const whitelist = config.whitelist || {};
    return [
        whitelist.ips,
        whitelist.paths,
        whitelist.user_agents,
        whitelist.headers,
        whitelist.methods
    ].reduce((total, entries) => total + (Array.isArray(entries) ? entries.length : 0), 0);
}

function formatPercent(value: number): string {
    return Number.isFinite(value) ? value.toFixed(1) : '0.0';
}

function formatDate(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}


function formatDecisionValue(value: string): string {
    if (!value || value === '-') return '-';
    return value
        .split('_')
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(' ');
}



function escapeHtml(value: string): string {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function escapeAttr(value: string): string {
    return escapeHtml(value);
}
