// Bot Protection Configuration Interface
// Maps to internal/sections/bot/config.go
// Runtime logic. Shared types/constants/helpers live in antibots-config-shared.ts.

import { SectionUI } from './ui-components.js';
import { api } from '../api.js';
import { FEATURES, renderUpgradeBanner } from '../core/features.js';
import { openSecurityRuleModal, type SecurityRule } from '../security.js';
import * as AdminDOM from '../core/dom.js';
import { AntibotsHelpers } from './antibots-helpers.js';
import { renderAntibotAiCrawlersTab } from './antibots-render-ai-tab.js';
import { getAntibotBotIconChar } from './antibots-icons.js';
import { createAntibotsComposition } from './antibots-config-composition.js';
import {
    formatAntibotNumber,
    getAntibotIcon,
    renderAntibotSaveButton,
    showAntibotToast
} from './antibots-runtime-helpers.js';
import {
    closeAntibotRuleModal,
    confirmDeleteAntibotRuleAt,
    moveAntibotRule,
    promptDeleteAntibotRule,
    toggleAntibotRuleStatus
} from './antibots-rules-lifecycle.js';
import {
    readNewAntibotRuleFromForm,
    selectAntibotRuleAction,
    toggleAntibotRuleFields
} from './antibots-rules-form.js';
import { renderAntibotClassificationTab } from './antibots-render-classification-tab.js';
import { renderAntibotExceptionsTab } from './antibots-render-exceptions-tab.js';
import { renderAntibotManagedProtectionTab, renderAntibotOverviewTab } from './antibots-render-overview-tab.js';
import { renderAntibotRulesTab } from './antibots-render-rules-tab.js';
import {
    ANTIBOT_GOOD_BOTS,
    ANTIBOT_MODE_PRESETS,
    ANTIBOT_TABS,
    antibotControl,
    antibotErrorMessage,
    antibotInput,
    antibotSelect,
    antibotValue,
    asAntibotConfigState,
    botConfigForSave,
    asAntibotRules,
    asAntibotStatsState,
    createDefaultAntibotAnalyticsState,
    createDefaultAntibotConfigState,
    isAntibotModeName,
    setAntibotField,
    type AntibotAnalyticsEvent,
    type AntibotAnalyticsItem,
    type AntibotAnalyticsState,
    type AntibotAnalyticsSummary,
    type AntibotModeName,
    type AntibotRule,
    type AntibotTab
} from './antibots-config-shared.js';
import { parseDatasetBoundValue } from './field-value-parser.js';

function antibotNode(id: string): HTMLElement | null {
    const element = antibotControl(id);
    return element instanceof HTMLElement ? element : null;
}

function parseAntibotDatasetValue(target: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement): unknown {
    return parseDatasetBoundValue(target, target.dataset.antibotValueType);
}

function createInitialAntibotLoadError(): string | null {
    return null;
}

function withLimit(params: URLSearchParams, limit: number): URLSearchParams {
    const copy = new URLSearchParams(params);
    copy.set('limit', String(limit));
    return copy;
}

function readAnalyticsFilters(state: AntibotAnalyticsState) {
    return {
        range: AdminDOM.selectValue('bot-analytics-range', state.filters.range),
        action: AdminDOM.selectValue('bot-analytics-action', ''),
        rule: AdminDOM.selectValue('bot-analytics-rule', ''),
        country: AdminDOM.inputValue('bot-analytics-country', ''),
        ip: AdminDOM.inputValue('bot-analytics-ip', ''),
        path: AdminDOM.inputValue('bot-analytics-path', ''),
        method: AdminDOM.inputValue('bot-analytics-method', ''),
        userAgent: AdminDOM.inputValue('bot-analytics-user-agent', ''),
        ja3: AdminDOM.inputValue('bot-analytics-ja3', ''),
        ja4: AdminDOM.inputValue('bot-analytics-ja4', ''),
        decisionSource: AdminDOM.selectValue('bot-analytics-decision-source', ''),
        challengeType: AdminDOM.selectValue('bot-analytics-challenge-type', ''),
        challengeOutcome: AdminDOM.selectValue('bot-analytics-challenge-outcome', ''),
        ruleOverride: AdminDOM.selectValue('bot-analytics-rule-override', ''),
        since: AdminDOM.inputValue('bot-analytics-since', ''),
        until: AdminDOM.inputValue('bot-analytics-until', '')
    };
}

function localDateTimeToISOString(value: string): string {
    if (!value) return '';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '' : date.toISOString();
}

function normalizeAntibotRuleAction(action: unknown): string {
    const actionMap: Record<string, string> = { '0': 'allow', '1': 'block', '2': 'challenge', '5': 'log' };
    const raw = String(action ?? 'block');
    return actionMap[raw] || raw;
}

function normalizeEventRuleAction(action: string): SecurityRule['action'] {
    const value = action.toLowerCase();
    if (value === 'allow' || value === 'challenge' || value === 'log' || value === 'rate_limit') return value;
    return 'block';
}

function buildEventSecurityRule(kind: string, target: string, action: SecurityRule['action']): SecurityRule | null {
    const expression = eventRuleExpression(kind, target);
    if (!expression) return null;
    return {
        name: eventRuleName(kind, target, action),
        description: 'Created from Bot Protection event investigation',
        enabled: true,
        priority: 80,
        type: 'bot',
        section: 'bot',
        source: 'bot_protection',
        phase: 'bot',
        mode: 'visual',
        expression,
        action,
        tags: ['bot', 'quick-action', 'event']
    };
}

function eventRuleExpression(kind: string, target: string): string {
    const quoted = JSON.stringify(target);
    switch (kind) {
        case 'block_ip':
        case 'challenge_ip':
            return `ip.src eq ${quoted}`;
        case 'block_ua':
            return `http.user_agent contains ${quoted}`;
        case 'challenge_path':
            return `http.request.uri.path eq ${quoted}`;
        default:
            return '';
    }
}

function eventRuleName(kind: string, target: string, action: SecurityRule['action']): string {
    const noun = kind.includes('ua') ? 'user agent' : kind.includes('path') ? 'path' : 'IP';
    return `${action.charAt(0).toUpperCase() + action.slice(1)} ${noun}: ${target.length > 64 ? `${target.slice(0, 61)}...` : target}`;
}

function toSecurityRuleFromAntibot(rule: AntibotRule): SecurityRule {
    return {
        id: rule.id || '',
        name: rule.name || 'Custom bot rule',
        description: rule.description || '',
        enabled: rule.enabled !== false,
        priority: Number(rule.priority || 100),
        type: rule.type || 'bot',
        section: rule.section || 'bot',
        source: String(rule.source || 'bot_protection'),
        phase: String(rule.phase || 'bot'),
        mode: rule.mode || 'visual',
        expression: rule.expression || 'aegis.bot.score lt 30',
        action: normalizeAntibotRuleAction(rule.action),
        action_params: rule.action_params as Record<string, string> | undefined,
        tags: Array.isArray(rule.tags) ? rule.tags.map(String) : undefined,
        sync_status: typeof rule.sync_status === 'string' ? rule.sync_status : undefined,
        match_count: typeof rule.match_count === 'number' ? rule.match_count : undefined
    };
}

async function quietAntibotGet<T>(endpoint: string): Promise<T | null> {
    try {
        const response = await fetch(`/api/${endpoint}`, { headers: { Accept: 'application/json' } });
        if (!response.ok) return null;
        return await response.json() as T;
    } catch (error) {
        console.warn('[Aegis Bot Protection] optional request failed:', endpoint, error);
        return null;
    }
}

const getAntibotLogo = AntibotsHelpers.getBotLogo.bind(AntibotsHelpers);
const renderAntibotSectionHeader = (
    runtime: { renderSectionHeader(icon: string, title: string, desc: string, toggleField?: string | null, toggleValue?: boolean): string }
): ((icon: string, title: string, desc: string, toggleField?: string | null, toggleValue?: boolean) => string) =>
    runtime.renderSectionHeader.bind(runtime);

const AntibotsConfig = {
    currentTab: 'overview',
    config: createDefaultAntibotConfigState(),
    rules: asAntibotRules(undefined),
    stats: asAntibotStatsState(undefined),
    analytics: createDefaultAntibotAnalyticsState(),
    isLoading: false,
    loadError: createInitialAntibotLoadError(),
    isGoodBotModalOpen: false,
    isAddExceptionModalOpen: false,
    goodBotFilter: '',

    goodBots: ANTIBOT_GOOD_BOTS,

    tabs: ANTIBOT_TABS,

    async init() {
        ensureAntibotBindings();
        if (!api.hasFeature(FEATURES.BOT_PROTECTION)) {
            this.render();
            return;
        }
        if (this.config && this.config.enabled !== undefined) {
            this.render();
            void Promise.all([this.loadConfig(), this.loadRules(), this.loadStats(), this.loadAnalytics()]).then(() => this.render());
            return;
        }
        this.isLoading = true;
        this.loadError = null;
        this.render(); // Show loading state

        try {
            await Promise.all([this.loadConfig(), this.loadRules(), this.loadStats(), this.loadAnalytics()]);
        } catch (err) {
            this.loadError = antibotErrorMessage(err, 'Failed to load configuration');
            console.error('Init error:', err);
        } finally {
            this.isLoading = false;
            this.render();
        }
    },

    async loadConfig() {
        try {
            const data = await quietAntibotGet('sections/bot_protection/config');
            this.config = asAntibotConfigState(data);
            return true;
        } catch (e) {
            console.error('Config load error', e);
            return false;
        }
    },

    async loadRules() {
        try {
            const data = await quietAntibotGet<{ rules?: unknown[] }>('v2/security/bot/rules?section=bot');
            this.rules = asAntibotRules(data?.rules || []);
        } catch (e) { console.error(e); }
    },

    async loadStats() {
        try {
            const data = await quietAntibotGet('sections/bot_protection/stats');
            this.stats = asAntibotStatsState(data);
        } catch (e) { console.error(e); }
    },

    async loadAnalytics() {
        this.analytics.loading = true;
        this.analytics.error = null;
        try {
            const base = this.buildAnalyticsParams();
            const [summary, events, timeline, rules, ips, countries, paths, categories, userAgents, decisionSources, decisionStates, challengeTypes, challengeOutcomes, ruleOverrides] = await Promise.all([
                quietAntibotGet<{ summary?: AntibotAnalyticsSummary }>(`v2/analytics/summary?${base.toString()}`),
                quietAntibotGet<{ events?: AntibotAnalyticsEvent[] }>(`v2/analytics/events?${withLimit(base, 100).toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/timeline?${base.toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/rules?${withLimit(base, 8).toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/top-ips?${withLimit(base, 8).toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/geo?${withLimit(base, 8).toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/top-paths?${withLimit(base, 8).toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/top-bot-categories?${withLimit(base, 8).toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/top-user-agents?${withLimit(base, 8).toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/top-decision-sources?${withLimit(base, 8).toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/top-decision-states?${withLimit(base, 8).toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/top-challenge-types?${withLimit(base, 8).toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/top-challenge-outcomes?${withLimit(base, 8).toString()}`),
                quietAntibotGet<{ items?: AntibotAnalyticsItem[] }>(`v2/analytics/top-rule-overrides?${withLimit(base, 8).toString()}`)
            ]);
            this.analytics.summary = summary?.summary || createDefaultAntibotAnalyticsState().summary;
            this.analytics.events = events?.events || [];
            this.analytics.timeline = timeline?.items || [];
            this.analytics.topRules = rules?.items || [];
            this.analytics.topIps = ips?.items || [];
            this.analytics.topCountries = countries?.items || [];
            this.analytics.topPaths = paths?.items || [];
            this.analytics.topCategories = categories?.items || [];
            this.analytics.topUserAgents = userAgents?.items || [];
            this.analytics.topDecisionSources = decisionSources?.items || [];
            this.analytics.topDecisionStates = decisionStates?.items || [];
            this.analytics.topChallengeTypes = challengeTypes?.items || [];
            this.analytics.topChallengeOutcomes = challengeOutcomes?.items || [];
            this.analytics.topRuleOverrides = ruleOverrides?.items || [];
        } catch (e) {
            this.analytics.error = antibotErrorMessage(e, 'Failed to load bot analytics');
            console.error('Analytics load error', e);
        } finally {
            this.analytics.loading = false;
        }
    },

    buildAnalyticsParams() {
        const params = new URLSearchParams({ section: 'bot_protection' });
        const filters = this.analytics.filters;
        const set = (key: string, value: string): void => {
            if (value.trim()) params.set(key, value.trim());
        };
        set('action', filters.action);
        set('rule_id', filters.rule);
        set('country', filters.country.toUpperCase());
        set('ip', filters.ip);
        set('path', filters.path);
        set('method', filters.method.toUpperCase());
        set('user_agent', filters.userAgent);
        set('ja3', filters.ja3);
        set('ja4', filters.ja4);
        set('decision_source', filters.decisionSource);
        set('challenge_type', filters.challengeType);
        set('challenge_outcome', filters.challengeOutcome);
        set('rule_override', filters.ruleOverride);
        if (filters.range === 'custom') {
            const since = localDateTimeToISOString(filters.since);
            const until = localDateTimeToISOString(filters.until);
            if (since) params.set('since', since);
            if (until) params.set('until', until);
        } else {
            params.set('since', filters.range);
        }
        return params;
    },

    async applyAnalyticsFilters() {
        this.analytics.filters = readAnalyticsFilters(this.analytics);
        this.analytics.expandedEventId = null;
        await this.loadAnalytics();
        this.render();
    },

    async resetAnalyticsFilters() {
        this.analytics.filters = createDefaultAntibotAnalyticsState().filters;
        this.analytics.expandedEventId = null;
        await this.loadAnalytics();
        this.render();
    },

    async refreshAnalytics() {
        await this.loadAnalytics();
        this.render();
    },

    async createRuleFromEvent(kind: string, target: string, action: string) {
        const cleanTarget = target.trim();
        if (!cleanTarget) {
            showAntibotToast('Missing event value for rule', 'error');
            return;
        }
        const ruleAction = normalizeEventRuleAction(action);
        const rule = buildEventSecurityRule(kind, cleanTarget, ruleAction);
        if (!rule) {
            showAntibotToast('Unsupported quick action', 'error');
            return;
        }
        const created = await api.post<SecurityRule>('v2/security/bot/rules', rule);
        if (!created) {
            showAntibotToast('Failed to create rule from event', 'error');
            return;
        }
        await this.loadRules();
        showAntibotToast('Bot rule created from event', 'success');
        this.currentTab = 'rules';
        this.render();
    },

    toggleAnalyticsEvent(eventId: string) {
        this.analytics.expandedEventId = this.analytics.expandedEventId === eventId ? null : eventId;
        this.render();
    },

    render() {
        const container = antibotNode('antibots-config-content');
        if (!container) return;

        if (!api.hasFeature(FEATURES.BOT_PROTECTION)) {
            container.innerHTML = renderUpgradeBanner('professional', 'Bot Protection');
            return;
        }

        // Show loading state
        if (this.isLoading) {
            container.innerHTML = SectionUI.renderLoading('Loading Bot Protection configuration...');
            return;
        }

        // Show error state
        if (this.loadError) {
            container.innerHTML = SectionUI.renderError(this.loadError, 'AntibotsConfig.init()');
            return;
        }

        const botSwitch = SectionUI.renderSwitch({
            checked: this.config.enabled === true,
            attrs: 'title="Enable or disable Bot Protection" data-antibot-field-path="enabled" data-antibot-value-type="checkbox" data-antibot-render="true" aria-label="Enable Bot Protection"'
        });

        const consoleMetaMap: Record<string, { title: string; kicker: string; subtitle: string; actions?: string }> = {
            overview: {
                title: 'Overview',
                kicker: 'Bot Defense',
                subtitle: 'Autonomous threat intelligence, anomaly scores, automated challenge rates, and live crawler mitigation.',
                actions: botSwitch
            },
            classification: {
                title: 'Classification',
                kicker: 'Bot Defense',
                subtitle: 'Directory of verified search engine crawlers, commercial bots, and automated categorization policies.'
            },
            managed: {
                title: 'Managed Protection',
                kicker: 'Bot Defense',
                subtitle: 'TLS client fingerprinting, JA3/JA4 signature heuristics, and passive behavioral profiling.'
            },
            rules: {
                title: 'Custom Rules',
                kicker: 'Bot Defense',
                subtitle: 'Wire-speed bot mitigation rules using expression matching, JA3/JA4 filters, and custom mitigation pipelines.'
            },
            ai: {
                title: 'AI Crawlers',
                kicker: 'Bot Defense',
                subtitle: 'Block, allow, or monitor AI search bots, LLM crawlers, and automated content scrapers.'
            },
            exceptions: {
                title: 'Exceptions',
                kicker: 'Bot Defense',
                subtitle: 'Path-scoped bypasses, user-agent exemptions, and IP whitelist policies for automated integrations.'
            }
        };

        const currentMeta = consoleMetaMap[this.currentTab] || consoleMetaMap.overview;

        container.innerHTML = SectionUI.renderOperatorFrame({
            title: currentMeta.title,
            kicker: currentMeta.kicker,
            subtitle: currentMeta.subtitle,
            actions: currentMeta.actions,
            tabs: [],
            activeTab: this.currentTab,
            content: `<div id="bot-tab-content">${this.renderTabContent()}</div>`,
            className: 'botdefense-operator-frame'
        });
        this.syncDynamicStyles(container);
    },

    syncDynamicStyles(root: ParentNode = document) {
        const logoEls = root.querySelectorAll<HTMLElement>('.section-logo[data-logo-bg]');
        logoEls.forEach((el) => {
            const raw = el.dataset.logoBg ? decodeURIComponent(el.dataset.logoBg) : '';
            if (raw) el.style.setProperty('--section-logo-bg', raw);
        });

        const zoneEls = root.querySelectorAll<HTMLElement>('.section-threshold-zones-bar[data-challenge][data-block]');
        zoneEls.forEach((el) => {
            const challengeRaw = Number(el.dataset.challenge || 0);
            const blockRaw = Number(el.dataset.block || 100);
            const challenge = Number.isFinite(challengeRaw) ? Math.max(0, Math.min(100, challengeRaw)) : 0;
            const block = Number.isFinite(blockRaw) ? Math.max(challenge, Math.min(100, blockRaw)) : 100;
            el.style.setProperty('--challenge', `${challenge}`);
            el.style.setProperty('--block', `${block}`);
        });
    },

    switchTab(id: string) {
        this.currentTab = this.tabs.some((tab: AntibotTab) => tab.id === id) ? id : 'overview';
        this.render();

        const targetMap: Record<string, string> = {
            overview: 'antibots_config',
            classification: 'bot_classification',
            managed: 'bot_fingerprinting',
            rules: 'bot_rules',
            ai: 'bot_ai',
            exceptions: 'bot_exceptions'
        };
        const activeNavTarget = targetMap[this.currentTab];
        if (activeNavTarget) {
            AdminDOM.queryAll<HTMLElement>('.nav-link').forEach(el => el.classList.remove('active'));
            const matchedLink = AdminDOM.query<HTMLElement>(`.nav-link[data-nav-target="${activeNavTarget}"]`);
            if (matchedLink) matchedLink.classList.add('active');
        }
    },

    renderTabContent() {
        switch (this.currentTab) {
            case 'overview': return this.renderOverview();
            case 'managed': return this.renderManagedProtection();
            case 'rules': return this.renderRules();
            case 'classification': return this.renderClassification();
            case 'ai': return this.renderAICrawlers();
            case 'exceptions': return this.renderExceptions();
            default: return '<div>Loading...</div>';
        }
    },

    // ========== OVERVIEW TAB ==========
    renderOverview() {
        return renderAntibotOverviewTab(
            this.config,
            this.analytics,
            this.rules,
            formatAntibotNumber
        );
    },

    renderManagedProtection() {
        return renderAntibotManagedProtectionTab(
            this.config,
            this.rules,
            formatAntibotNumber
        );
    },

    // Mode Presets - Define all settings for each mode
    MODE_PRESETS: ANTIBOT_MODE_PRESETS,

    // Check if current config matches any preset
    isCustomMode() {
        const current = this.config;
        for (const [modeName, preset] of Object.entries(this.MODE_PRESETS)) {
            let matches = true;
            // Check detection thresholds
            if (current.detection?.block_threshold !== preset.detection.block_threshold ||
                current.detection?.challenge_threshold !== preset.detection.challenge_threshold) {
                matches = false;
            }


            if (matches && current.mode === modeName) return false;
        }
        return true;
    },

    // Apply a mode preset to all config sections
    applyModePreset(modeName: AntibotModeName) {
        if (modeName === 'custom') return; // Don't apply anything for custom

        const preset = this.MODE_PRESETS[modeName];
        if (!preset) return;

        // Apply all preset values
        this.config.mode = modeName;
        this.config.detection = { ...this.config.detection, ...preset.detection };
        this.config.classification = { ...this.config.classification, ...preset.classification };

        this.render();
        SectionUI.markSaveActionBarDirty('data-antibot-action');
    },

    // Unified Bot Protection section header.
    renderSectionHeader(_icon: string, _title: string, _desc: string, _toggleField: string | null = null, _toggleValue = false) {
        return '';
    },

    // ========== RULES TAB ==========
    renderRules() {
        return renderAntibotRulesTab(this.rules, AntibotsHelpers.escapeHTML, renderAntibotSectionHeader(this));
    },

    toggleRuleFields() {
        toggleAntibotRuleFields({
            getSelect: antibotSelect,
            getNode: antibotNode,
            getInput: antibotInput
        });
    },

    selectAction(action: string) {
        selectAntibotRuleAction(action, {
            getNode: antibotNode,
            getInput: antibotInput
        });
    },

    // ========== CLASSIFICATION TAB ==========
    renderClassification() {
        return renderAntibotClassificationTab(
            this.config,
            this.goodBots,
            this.goodBotFilter,
            this.isGoodBotModalOpen,
            {
                escapeHTML: AntibotsHelpers.escapeHTML,
                escapeAttr: AntibotsHelpers.escapeAttr,
                getBotIconChar: getAntibotBotIconChar,
                renderSaveButton: renderAntibotSaveButton,
                renderSectionHeader: renderAntibotSectionHeader(this)
            }
        );
    },



    showGoodBotsModal() {
        this.isGoodBotModalOpen = true;
        this.render();
    },

    closeGoodBotsModal() {
        this.isGoodBotModalOpen = false;
        this.goodBotFilter = ''; // Reset filter on close
        this.render();
    },

    toggleGoodBot(botName: string) {
        if (!this.config.classification) this.config.classification = {};
        if (!this.config.classification.good_bot_rules) this.config.classification.good_bot_rules = {};

        const current = this.config.classification.good_bot_rules[botName];
        if (current?.action === 'disabled') {
            delete this.config.classification.good_bot_rules[botName];
        } else {
            this.config.classification.good_bot_rules[botName] = { action: 'disabled' };
        }
        this.render();
        SectionUI.markSaveActionBarDirty('data-antibot-action');
    },

    filterGoodBots(val: string) {
        this.goodBotFilter = val.toLowerCase();
        this.render();
    },


    renderAICrawlers() {
        return renderAntibotAiCrawlersTab(this.config, {
            escapeHTML: AntibotsHelpers.escapeHTML,
            escapeAttr: AntibotsHelpers.escapeAttr,
            getBotLogo: getAntibotLogo,
            renderSaveButton: renderAntibotSaveButton,
            renderSectionHeader: renderAntibotSectionHeader(this)
        });
    },

    renderExceptions() {
        return renderAntibotExceptionsTab(
            this.config,
            renderAntibotSectionHeader(this),
            renderAntibotSaveButton,
            this.isAddExceptionModalOpen
        );
    },

    updateField(path: string, value: unknown) {
        setAntibotField(this.config, path, value);
    },

    updateAIRule(botName: string, action: string) {
        if (!this.config.ai_crawlers) this.config.ai_crawlers = {};
        if (!this.config.ai_crawlers.rules) this.config.ai_crawlers.rules = {};
        this.config.ai_crawlers.rules[botName] = { action };
    },

    applyExceptionList(key: string, value: string) {
        if (!['ips', 'user_agents', 'paths', 'methods', 'headers'].includes(key)) return;
        if (!this.config.whitelist) this.config.whitelist = {};
        this.config.whitelist[key] = value
            .split(/\r?\n/)
            .map((entry) => entry.trim())
            .filter(Boolean);
        this.render();
    },

    showAddExceptionModal() {
        this.isAddExceptionModalOpen = true;
        this.render();
    },

    closeExceptionModal() {
        this.isAddExceptionModalOpen = false;
        this.render();
    },

    async addExceptionValue(key: string, value: string) {
        const clean = value.trim();
        if (!clean || !['ips', 'user_agents', 'paths', 'methods', 'headers'].includes(key)) return;
        if (!this.config.whitelist) this.config.whitelist = {};
        const current = Array.isArray(this.config.whitelist[key]) ? [...this.config.whitelist[key]] : [];
        if (current.includes(clean)) {
            showAntibotToast('Exception already exists', 'info');
            this.isAddExceptionModalOpen = false;
            this.currentTab = 'exceptions';
            this.render();
            return;
        }
        current.push(clean);
        this.config.whitelist[key] = current;
        showAntibotToast('Exception staged', 'success');
        this.isAddExceptionModalOpen = false;
        this.currentTab = 'exceptions';
        this.render();
        SectionUI.markSaveActionBarDirty('data-antibot-action');
    },

    async saveExceptionFromModal() {
        const typeEl = document.querySelector<HTMLInputElement>('input[name="bot-exception-type"]:checked');
        const valueEl = antibotControl('bot-exception-value');
        const key = typeEl instanceof HTMLInputElement ? typeEl.value : '';
        const value = valueEl instanceof HTMLInputElement ? valueEl.value : '';
        if (!value.trim()) {
            showAntibotToast('Exception value is required', 'error');
            return;
        }
        await this.addExceptionValue(key, value);
    },

    async removeExceptionValue(key: string, value: string) {
        const clean = value.trim();
        if (!clean || !['ips', 'user_agents', 'paths', 'methods', 'headers'].includes(key)) return;
        if (!this.config.whitelist) this.config.whitelist = {};
        const current = Array.isArray(this.config.whitelist[key]) ? [...this.config.whitelist[key]] : [];
        this.config.whitelist[key] = current.filter((entry) => entry !== clean);
        showAntibotToast('Exception removal staged', 'success');
        this.render();
        SectionUI.markSaveActionBarDirty('data-antibot-action');
    },



    openRuleBuilder(rule?: SecurityRule) {
        const editing = Boolean(rule?.id);
        openSecurityRuleModal(rule, {
            containerId: 'bot-tab-content',
            apiBase: 'v2/security/bot/rules',
            lockType: true,
            hideLockedType: true,
            blankCreate: !editing,
            requireExplicitName: true,
            title: editing ? rule?.name || 'Edit Bot Rule' : 'Create Bot Rule',
            eyebrow: editing ? 'Edit Bot Protection rule' : 'Bot Rule Builder',
            scopeLabel: 'Bot Protection',
            editorClass: 'security-rule-builder-bot',
            // Keep this in lockstep with rules.BotRuleFields on the API. Bot
            // rules run in the Bot phase, so fields owned by WAF, API Security,
            // or Access cannot have been populated yet.
            allowedFieldNames: [
                'ip.src',
                'ip.geoip.country',
                'ip.reputation.score',
                'http.host',
                'http.request.uri.path',
                'http.request.method',
                'http.user_agent',
                'http.request.headers["content-type"]',
                'http.cookie["session"]',
                'http.request.query["q"]',
                'aegis.bot.score',
                'aegis.bot.category',
                'aegis.bot.verified',
                'aegis.bot.headless',
                'tls.version',
                'tls.ja3',
                'tls.ja4'
            ],
            defaults: {
                type: 'bot',
                section: 'bot',
                source: 'bot_protection',
                phase: 'bot',
                action: 'block',
                priority: 100
            },
            onCancel: () => {
                this.render();
            },
            onSaved: async () => {
                await this.loadRules();
                this.render();
            }
        });
    },

    showAddRuleModal() {
        this.openRuleBuilder();
    },

    editRule(idx: number) {
        const rule = this.rules[idx];
        if (!rule) return;
        this.openRuleBuilder(toSecurityRuleFromAntibot(rule));
    },

    closeRuleModal() {
        closeAntibotRuleModal(antibotNode);
    },

    async saveNewRule() {
        const parsed = readNewAntibotRuleFromForm(antibotValue);
        if (!parsed.ok) {
            if (parsed.error === 'missing-key') {
                showAntibotToast('Please specify the key name (e.g., X-API-Key)', 'error');
            } else {
                showAntibotToast('Please fill all required fields', 'error');
            }
            return;
        }

        const created = await api.post('v2/security/bot/rules', parsed.rule);
        if (!created) {
            showAntibotToast('Failed to create rule', 'error');
            return;
        }
        await this.loadRules();
        this.closeRuleModal();
        this.render();
        showAntibotToast('Rule created successfully', 'success');
    },

    deleteRule(idx: number) {
        const name = this.rules[idx]?.name || '';
        promptDeleteAntibotRule(name, () => {
            this.confirmDeleteRule(idx);
        });
    },

    async confirmDeleteRule(idx: number) {
        const id = this.rules[idx]?.id;
        if (id) {
            const deleted = await api.delete(`v2/security/bot/rules/${id}`);
            if (!deleted && deleted !== null) {
                showAntibotToast('Failed to delete rule', 'error');
                return;
            }
        }
        if (!confirmDeleteAntibotRuleAt(this.rules, idx)) return;
        this.render();
    },

    moveRule(idx: number, direction: number) {
        if (!moveAntibotRule(this.rules, idx, direction)) return;
        this.render();
        this.saveRules();
    },

    toggleRuleStatus(idx: number) {
        if (!toggleAntibotRuleStatus(this.rules, idx)) return;
        this.saveRules();
    },

    async saveRules() {
        try {
            for (const rule of this.rules) {
                const payload = { ...rule, type: 'bot', section: 'bot', phase: 'bot' };
                const success = rule.id
                    ? await api.put(`v2/security/bot/rules/${rule.id}`, payload)
                    : await api.post('v2/security/bot/rules', payload);
                if (!success) {
                    showAntibotToast('Failed to save rules', 'error');
                    return;
                }
            }
            await this.loadRules();
            showAntibotToast('Rules saved', 'success');
            this.render();
        } catch (e) {
            showAntibotToast('Error saving rules', 'error');
        }
    },

    async saveConfig(options?: { successMessage?: string | null; errorMessage?: string }) {
        const successMessage = options?.successMessage === undefined ? 'Configuration saved' : options.successMessage;
        const errorMessage = options?.errorMessage || 'Failed to save config';

        try {
            const success = await api.put('sections/bot_protection/config', botConfigForSave(this.config));
            if (success) {
                const response = success as { config?: unknown };
                this.config = asAntibotConfigState(response.config ?? success);
                this.render();
                if (successMessage) showAntibotToast(successMessage, 'success');
                return true;
            } else {
                showAntibotToast(errorMessage, 'error');
            }
        } catch (e) {
            showAntibotToast('Error saving config', 'error');
        }

        return false;
    },

    async applyAdvancedPreset(scope: string, preset: string) {
        const signalWeights = { ...(this.config.signal_weights || {}) };
        if (scope === 'scoring') {
            if (preset === 'strict') {
                this.config.scoring_profile = 'aggressive';
                this.config.risk_profile = 'aggressive';
                this.config.managed_thresholds = { ...(this.config.managed_thresholds || {}), observe: 15, challenge: 40, block: 70, repeat_offender: 2 };
                Object.assign(signalWeights, { identity: 1.2, network: 1.1, behavior: 1.0, tls: 0.9, velocity: 0.9 });
            } else if (preset === 'balanced') {
                this.config.scoring_profile = 'default';
                this.config.risk_profile = 'balanced';
                this.config.managed_thresholds = { ...(this.config.managed_thresholds || {}), observe: 20, challenge: 55, block: 85, repeat_offender: 3 };
                Object.assign(signalWeights, { identity: 1.0, network: 0.8, behavior: 0.9, fingerprint: 0.7, session: 0.6, header: 0.5, tls: 0.6, challenge: 0.8, velocity: 0.7, profile: 0.3 });
            } else if (preset === 'api') {
                this.config.scoring_profile = 'api';
                this.config.risk_profile = 'balanced';
                this.config.managed_thresholds = { ...(this.config.managed_thresholds || {}), observe: 25, challenge: 55, block: 80, repeat_offender: 2 };
                Object.assign(signalWeights, { identity: 0.7, network: 1.2, behavior: 0.1, fingerprint: 0.1, session: 0.9, header: 0.8, tls: 1.1, challenge: 0.5, velocity: 1.2, profile: 0.3 });
            } else if (preset === 'adaptive') {
                const challengeRate = Number(this.analytics.summary.challenge_rate || 0);
                const blockRate = Number(this.analytics.summary.block_rate || 0);
                this.config.scoring_profile = challengeRate > 35 ? 'permissive' : blockRate < 3 ? 'aggressive' : 'default';
                this.config.risk_profile = this.config.scoring_profile === 'permissive' ? 'permissive' : this.config.scoring_profile === 'aggressive' ? 'aggressive' : 'balanced';
                this.config.managed_thresholds = {
                    ...(this.config.managed_thresholds || {}),
                    observe: 20,
                    challenge: challengeRate > 35 ? 65 : 50,
                    block: blockRate < 3 ? 75 : 85,
                    repeat_offender: challengeRate > 35 ? 4 : 3
                };
            }
            this.config.signal_weights = signalWeights;
        }

        if (scope === 'tls') {
            if (preset === 'observe') {
                this.config.tls = { ...(this.config.tls || {}), enabled: true, ja3_enabled: true, ja4_enabled: true, header_order_enabled: true, mismatch_action: 'log' };
                this.config.anti_evasion = { ...(this.config.anti_evasion || {}), fp_rotation_detection: true, session_anomaly: true, rate_pattern_analysis: false, credential_stuffing: false };
            } else if (preset === 'balanced') {
                this.config.tls = { ...(this.config.tls || {}), enabled: true, ja3_enabled: true, ja4_enabled: true, header_order_enabled: true, mismatch_action: 'challenge' };
                this.config.anti_evasion = { ...(this.config.anti_evasion || {}), fp_rotation_detection: true, session_anomaly: true, rate_pattern_analysis: true, credential_stuffing: false };
            } else if (preset === 'strict') {
                this.config.tls = { ...(this.config.tls || {}), enabled: true, ja3_enabled: true, ja4_enabled: true, header_order_enabled: true, mismatch_action: 'block' };
                this.config.anti_evasion = { ...(this.config.anti_evasion || {}), fp_rotation_detection: true, session_anomaly: true, rate_pattern_analysis: true, credential_stuffing: true };
            }
        }

        this.render();
        SectionUI.markSaveActionBarDirty('data-antibot-action');
        showAntibotToast(`${scope.charAt(0).toUpperCase() + scope.slice(1)} preset staged`, 'success');
    },

};

const antibotsComposition = createAntibotsComposition(AntibotsConfig, {
    isModeName: (value): value is AntibotModeName => isAntibotModeName(value),
    parseDatasetValue: parseAntibotDatasetValue,
    getNode: antibotNode
});

const ensureAntibotBindings = antibotsComposition.ensureBindings;
export const AntibotsConfigFacade = antibotsComposition.facade;
