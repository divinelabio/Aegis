// Bot Protection Configuration Interface
// Shared types, constants, and DOM helpers for antibots-config.ts.
import * as AdminDOM from '../core/dom.js';
export const ANTIBOT_GOOD_BOTS = [
    'Googlebot', 'Bingbot', 'DuckDuckBot', 'Yandex', 'Applebot', 'FacebookExternalHit',
    'Twitterbot', 'WhatsApp', 'Telegram', 'LinkedInBot', 'Pinterestbot', 'Amazonbot',
    'Slackbot', 'ZoomBot', 'Zapier', 'Stripe', 'PayPal', 'Datadog Agent', 'UptimeRobot', 'Pingdom',
    'AhrefsBot', 'SemrushBot', 'DotBot', 'MJ12bot', 'Exabot', 'SeznamBot', 'CocCocBot',
    'PetalBot', 'MojeekBot', 'TurnitinBot', 'Archive.org_bot', 'OracleBot', 'Salesforce', 'GrapeshotCrawler'
];
export const ANTIBOT_TABS = [
    { id: 'overview', name: 'Overview', icon: 'shield' },
    { id: 'managed', name: 'Managed Protection', icon: 'activity' },
    { id: 'rules', name: 'Custom Rules', icon: 'list' },
    { id: 'classification', name: 'Classification', icon: 'tag' },
    { id: 'ai', name: 'AI Crawlers', icon: 'bot' },
    { id: 'exceptions', name: 'Exceptions', icon: 'shield' }
];
export const ANTIBOT_ICONS = {
    shield: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>',
    radar: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" /><line x1="12" y1="2" x2="12" y2="12" /></svg>',
    list: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6" /><line x1="8" y1="12" x2="21" y2="12" /><line x1="8" y1="18" x2="21" y2="18" /><line x1="3" y1="6" x2="3.01" y2="6" /><line x1="3" y1="12" x2="3.01" y2="12" /><line x1="3" y1="18" x2="3.01" y2="18" /></svg>',
    tag: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z" /><line x1="7" y1="7" x2="7.01" y2="7" /></svg>',
    puzzle: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19.439 7.85c-.049.322.059.648.289.878l1.568 1.568c.47.47.706 1.087.706 1.704s-.235 1.233-.706 1.704l-1.611 1.611a.98.98 0 0 1-.837.276c-.47-.07-.802-.48-.968-.925a2.501 2.501 0 1 0-3.214 3.214c.446.166.855.497.925.968a.979.979 0 0 1-.276.837l-1.61 1.61a2.404 2.404 0 0 1-1.705.707 2.402 2.402 0 0 1-1.704-.706l-1.568-1.568a1.026 1.026 0 0 0-.878-.29c-.493.074-.84.504-1.017.968a2.5 2.5 0 1 1-3.214-3.214c.464-.177.894-.524.967-1.017a1.026 1.026 0 0 0-.289-.878l-1.568-1.568A2.402 2.402 0 0 1 1.998 12c0-.617.236-1.234.706-1.704L4.315 8.68c.24-.239.4-.59.353-.984-.052-.436-.406-.8-.87-.996a2.5 2.5 0 1 1 3.173-3.173c.196.464.56.818.996.87.395.048.745-.114.984-.353l1.61-1.61A2.403 2.403 0 0 1 12.265 1.7a2.4 2.4 0 0 1 1.704.706l1.57 1.57c.231.229.557.337.879.288.436-.052.8-.406.996-.87a2.5 2.5 0 1 1 3.173 3.173c-.464.196-.818.56-.87.996z" /></svg>',
    bot: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="10" rx="2" /><circle cx="12" cy="5" r="2" /><path d="M12 7v4" /><line x1="8" y1="16" x2="8" y2="16" /><line x1="16" y1="16" x2="16" y2="16" /></svg>',
    zap: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>',
    activity: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>',
    fingerprint: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 0 0 8 11a4 4 0 1 1 8 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0 0 15.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 0 0 8 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" /></svg>',
    search: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>',
    database: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" /><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" /></svg>',
    globe: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /></svg>',
    check: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12" /></svg>'
};
export const ANTIBOT_MODE_PRESETS = {
    strict: {
        detection: { enabled: true, block_threshold: 50, challenge_threshold: 20 },
        classification: { treat_unknown_as_bot: true, allow_good_bots: true, block_bad_bots: true, verify_search_engines: true }
    },
    balanced: {
        detection: { enabled: true, block_threshold: 80, challenge_threshold: 40 },
        classification: { treat_unknown_as_bot: false, allow_good_bots: true, block_bad_bots: true, verify_search_engines: true }
    },
    permissive: {
        detection: { enabled: true, block_threshold: 95, challenge_threshold: 60 },
        classification: { treat_unknown_as_bot: false, allow_good_bots: true, block_bad_bots: true, verify_search_engines: false }
    }
};
export function createDefaultAntibotConfigState() {
    return {
        enabled: true,
        mode: 'balanced',
        strictness: 'balanced',
        response_mode: 'challenge',
        expert_settings_enabled: false,
        enforcement_mode: 'managed',
        risk_profile: 'balanced',
        scoring_profile: 'default',
        default_action: 'log',
        signal_weights: {
            identity: 1.0,
            network: 0.8,
            behavior: 0.9,
            fingerprint: 0.7,
            session: 0.6,
            header: 0.5,
            tls: 0.6,
            challenge: 0.8,
            velocity: 0.7,
            profile: 0.3
        },
        managed_thresholds: {
            observe: 20,
            challenge: 55,
            block: 85,
            repeat_offender: 3
        },
        challenge_ladder: {
            enabled: true,
            js_challenge_enabled: true,
            managed_challenge_enabled: true,
            interactive_enabled: true,
            cooldown_seconds: 1800,
            failure_action: 'block'
        },
        challenges: {
            invisible_enabled: true,
            managed_enabled: true,
            interactive_enabled: true,
            captcha_enabled: true,
            escalation_policy: 'progressive',
            cooldown_seconds: 1800,
            max_failures: 3,
            failure_action: 'block',
            theme: 'dark',
            custom_branding: false,
            branding_logo: '',
            branding_color: ''
        },
        tls: {
            enabled: true,
            ja3_enabled: true,
            ja4_enabled: true,
            header_order_enabled: true,
            known_bot_ja3_hashes: [],
            known_bot_ja4_hashes: [],
            mismatch_action: 'challenge'
        },
        anti_evasion: {
            fp_rotation_detection: true,
            credential_stuffing: false,
            session_anomaly: true,
            rate_pattern_analysis: true,
            max_fps_per_ip: 10
        },
        hmac_secret: '',
        detection: {},
        classification: {
            good_bot_rules: {}
        },
        ai_crawlers: {
            rules: {}
        },
        whitelist: {
            ips: [],
            user_agents: [],
            paths: [],
            methods: [],
            headers: []
        }
    };
}
export function createDefaultAntibotAnalyticsState() {
    return {
        loading: false,
        error: null,
        filters: {
            range: '1h',
            action: '',
            rule: '',
            country: '',
            ip: '',
            path: '',
            method: '',
            userAgent: '',
            ja3: '',
            ja4: '',
            decisionSource: '',
            challengeType: '',
            challengeOutcome: '',
            ruleOverride: '',
            since: '',
            until: ''
        },
        summary: {
            total: 0,
            by_action: {},
            block_rate: 0,
            challenge_rate: 0,
            avg_score: 0
        },
        events: [],
        timeline: [],
        topRules: [],
        topIps: [],
        topCountries: [],
        topPaths: [],
        topCategories: [],
        topUserAgents: [],
        topDecisionSources: [],
        topDecisionStates: [],
        topChallengeTypes: [],
        topChallengeOutcomes: [],
        topRuleOverrides: [],
        expandedEventId: null
    };
}
export function isAntibotRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
export function asAntibotRecord(value) {
    return isAntibotRecord(value) ? value : {};
}
export function asAntibotOverrideRecord(value) {
    const record = asAntibotRecord(value);
    const out = {};
    for (const [key, entry] of Object.entries(record)) {
        const override = asAntibotRecord(entry);
        if (typeof override.action === 'string') {
            out[key] = {
                action: override.action,
                ...(typeof override.verify_dns === 'boolean' ? { verify_dns: override.verify_dns } : {})
            };
        }
    }
    return out;
}
export function asAntibotStringArray(value) {
    return Array.isArray(value)
        ? value.map((entry) => String(entry).trim()).filter(Boolean)
        : [];
}
export function asAntibotNumberRecord(value) {
    const record = asAntibotRecord(value);
    const out = {};
    for (const [key, entry] of Object.entries(record)) {
        if (typeof entry === 'number' && Number.isFinite(entry)) {
            out[key] = entry;
        }
    }
    return out;
}
export function isAntibotModeName(value) {
    return value === 'strict' || value === 'balanced' || value === 'permissive' || value === 'custom';
}
export function asAntibotPresetDefinition(value) {
    if (!isAntibotRecord(value))
        return undefined;
    const detection = asAntibotRecord(value.detection);
    const classification = asAntibotRecord(value.classification);
    if (typeof detection.enabled !== 'boolean' ||
        typeof detection.block_threshold !== 'number' ||
        typeof detection.challenge_threshold !== 'number' ||
        typeof classification.treat_unknown_as_bot !== 'boolean' ||
        typeof classification.allow_good_bots !== 'boolean' ||
        typeof classification.block_bad_bots !== 'boolean' ||
        typeof classification.verify_search_engines !== 'boolean') {
        return undefined;
    }
    return {
        detection: {
            enabled: detection.enabled,
            block_threshold: detection.block_threshold,
            challenge_threshold: detection.challenge_threshold
        },
        classification: {
            treat_unknown_as_bot: classification.treat_unknown_as_bot,
            allow_good_bots: classification.allow_good_bots,
            block_bad_bots: classification.block_bad_bots,
            verify_search_engines: classification.verify_search_engines
        }
    };
}
export function asAntibotRuleCondition(value) {
    if (!isAntibotRecord(value))
        return null;
    const rawValue = value.value;
    const parsedValue = typeof rawValue === 'string' || typeof rawValue === 'number' || typeof rawValue === 'boolean' || rawValue === null
        ? rawValue
        : undefined;
    return {
        field: typeof value.field === 'string' ? value.field : undefined,
        operator: typeof value.operator === 'string' ? value.operator : undefined,
        value: parsedValue
    };
}
export function asAntibotRuleConditions(value) {
    return Array.isArray(value) ? value.map(asAntibotRuleCondition).filter((item) => Boolean(item)) : [];
}
export function asAntibotRule(value) {
    if (!isAntibotRecord(value))
        return null;
    const parsedAction = typeof value.action === 'string' || typeof value.action === 'number' ? value.action : undefined;
    return {
        ...value,
        id: typeof value.id === 'string' ? value.id : undefined,
        name: typeof value.name === 'string' ? value.name : undefined,
        description: typeof value.description === 'string' ? value.description : undefined,
        enabled: typeof value.enabled === 'boolean' ? value.enabled : undefined,
        action: parsedAction,
        priority: typeof value.priority === 'number' ? value.priority : undefined,
        type: typeof value.type === 'string' ? value.type : undefined,
        section: typeof value.section === 'string' ? value.section : undefined,
        expression: typeof value.expression === 'string' ? value.expression : undefined,
        mode: typeof value.mode === 'string' ? value.mode : undefined,
        conditions: asAntibotRuleConditions(value.conditions)
    };
}
export function asAntibotRules(value) {
    return Array.isArray(value) ? value.map(asAntibotRule).filter((rule) => Boolean(rule)) : [];
}
export function asAntibotStatsState(value) {
    const record = asAntibotRecord(value);
    const customRecord = asAntibotRecord(record.custom);
    const custom = Object.keys(customRecord).length > 0
        ? {
            ...customRecord,
            allowed_requests: typeof customRecord.allowed_requests === 'number' ? customRecord.allowed_requests : 0,
            blocked_requests: typeof customRecord.blocked_requests === 'number' ? customRecord.blocked_requests : 0,
            challenged_requests: typeof customRecord.challenged_requests === 'number' ? customRecord.challenged_requests : 0,
            verified_humans: typeof customRecord.verified_humans === 'number' ? customRecord.verified_humans : 0
        }
        : undefined;
    return {
        ...record,
        custom
    };
}
export function asAntibotFingerprintIdentities(value) {
    if (!Array.isArray(value))
        return [];
    return value.map((item) => {
        const record = asAntibotRecord(item);
        const ips = Array.isArray(record.ips) ? record.ips.filter((ip) => typeof ip === 'string') : [];
        return {
            hash: typeof record.hash === 'string' ? record.hash : '',
            tenant_id: typeof record.tenant_id === 'string' ? record.tenant_id : undefined,
            first_seen: typeof record.first_seen === 'string' ? record.first_seen : undefined,
            last_seen: typeof record.last_seen === 'string' ? record.last_seen : undefined,
            request_count: typeof record.request_count === 'number' ? record.request_count : 0,
            suspicion_score: typeof record.suspicion_score === 'number' ? record.suspicion_score : 0,
            ips,
            metadata: asAntibotRecord(record.metadata)
        };
    }).filter((identity) => identity.hash);
}
function strictnessFromLegacy(mode, risk) {
    if (risk === 'permissive' || mode === 'permissive')
        return 'low';
    if (risk === 'aggressive' || mode === 'strict')
        return 'high';
    return 'balanced';
}
function normalizeResponseMode(value, fallback) {
    return value === 'log' || value === 'challenge' || value === 'block' ? value : fallback;
}
function normalizeEnforcementMode(value, fallback) {
    return value === 'managed' || value === 'hybrid' || value === 'observe' || value === 'preset' ? value : fallback;
}
export function asAntibotConfigState(value) {
    const record = asAntibotRecord(value);
    const defaults = createDefaultAntibotConfigState();
    const detection = asAntibotRecord(record.detection);
    const classification = asAntibotRecord(record.classification);
    const aiCrawlers = asAntibotRecord(record.ai_crawlers);
    const whitelist = asAntibotRecord(record.whitelist);
    const managedThresholds = asAntibotRecord(record.managed_thresholds);
    const challengeLadder = asAntibotRecord(record.challenge_ladder);
    const challenges = asAntibotRecord(record.challenges);
    const tls = asAntibotRecord(record.tls);
    const antiEvasion = asAntibotRecord(record.anti_evasion);
    const signalWeights = asAntibotRecord(record.signal_weights);
    const hasDetection = Object.keys(detection).length > 0;
    const hasClassification = Object.keys(classification).length > 0;
    const hasAiCrawlers = Object.keys(aiCrawlers).length > 0;
    const hasWhitelist = Object.keys(whitelist).length > 0;
    const hasManagedThresholds = Object.keys(managedThresholds).length > 0;
    const hasChallengeLadder = Object.keys(challengeLadder).length > 0;
    const hasChallenges = Object.keys(challenges).length > 0;
    const hasTLS = Object.keys(tls).length > 0;
    const hasAntiEvasion = Object.keys(antiEvasion).length > 0;
    return {
        ...defaults,
        ...record,
        enabled: typeof record.enabled === 'boolean' ? record.enabled : undefined,
        mode: typeof record.mode === 'string' ? record.mode : undefined,
        strictness: typeof record.strictness === 'string' ? record.strictness : strictnessFromLegacy(record.mode, record.risk_profile),
        response_mode: normalizeResponseMode(record.response_mode, defaults.response_mode || 'challenge'),
        expert_settings_enabled: typeof record.expert_settings_enabled === 'boolean' ? record.expert_settings_enabled : false,
        enforcement_mode: normalizeEnforcementMode(record.enforcement_mode, defaults.enforcement_mode || 'managed'),
        risk_profile: typeof record.risk_profile === 'string' ? record.risk_profile : defaults.risk_profile,
        scoring_profile: typeof record.scoring_profile === 'string' ? record.scoring_profile : defaults.scoring_profile,
        auto_thresholds_enabled: typeof record.auto_thresholds_enabled === 'boolean' ? record.auto_thresholds_enabled : undefined,
        default_action: typeof record.default_action === 'string' ? record.default_action : defaults.default_action,
        hmac_secret: typeof record.hmac_secret === 'string' ? record.hmac_secret : defaults.hmac_secret,
        signal_weights: {
            ...(defaults.signal_weights || {}),
            ...asAntibotNumberRecord(signalWeights)
        },
        managed_thresholds: {
            ...defaults.managed_thresholds,
            ...(hasManagedThresholds ? managedThresholds : {}),
            observe: typeof managedThresholds.observe === 'number' ? managedThresholds.observe : defaults.managed_thresholds?.observe,
            challenge: typeof managedThresholds.challenge === 'number' ? managedThresholds.challenge : defaults.managed_thresholds?.challenge,
            block: typeof managedThresholds.block === 'number' ? managedThresholds.block : defaults.managed_thresholds?.block,
            repeat_offender: typeof managedThresholds.repeat_offender === 'number' ? managedThresholds.repeat_offender : defaults.managed_thresholds?.repeat_offender
        },
        challenge_ladder: {
            ...defaults.challenge_ladder,
            ...(hasChallengeLadder ? challengeLadder : {}),
            enabled: typeof challengeLadder.enabled === 'boolean' ? challengeLadder.enabled : defaults.challenge_ladder?.enabled,
            js_challenge_enabled: typeof challengeLadder.js_challenge_enabled === 'boolean' ? challengeLadder.js_challenge_enabled : defaults.challenge_ladder?.js_challenge_enabled,
            managed_challenge_enabled: typeof challengeLadder.managed_challenge_enabled === 'boolean' ? challengeLadder.managed_challenge_enabled : defaults.challenge_ladder?.managed_challenge_enabled,
            interactive_enabled: typeof challengeLadder.interactive_enabled === 'boolean' ? challengeLadder.interactive_enabled : defaults.challenge_ladder?.interactive_enabled,
            cooldown_seconds: typeof challengeLadder.cooldown_seconds === 'number' ? challengeLadder.cooldown_seconds : defaults.challenge_ladder?.cooldown_seconds,
            failure_action: typeof challengeLadder.failure_action === 'string' ? challengeLadder.failure_action : defaults.challenge_ladder?.failure_action
        },
        challenges: {
            ...defaults.challenges,
            ...(hasChallenges ? challenges : {}),
            invisible_enabled: typeof challenges.invisible_enabled === 'boolean' ? challenges.invisible_enabled : defaults.challenges?.invisible_enabled,
            managed_enabled: typeof challenges.managed_enabled === 'boolean' ? challenges.managed_enabled : defaults.challenges?.managed_enabled,
            interactive_enabled: typeof challenges.interactive_enabled === 'boolean' ? challenges.interactive_enabled : defaults.challenges?.interactive_enabled,
            captcha_enabled: typeof challenges.captcha_enabled === 'boolean' ? challenges.captcha_enabled : defaults.challenges?.captcha_enabled,
            escalation_policy: typeof challenges.escalation_policy === 'string' ? challenges.escalation_policy : defaults.challenges?.escalation_policy,
            cooldown_seconds: typeof challenges.cooldown_seconds === 'number' ? challenges.cooldown_seconds : defaults.challenges?.cooldown_seconds,
            max_failures: typeof challenges.max_failures === 'number' ? challenges.max_failures : defaults.challenges?.max_failures,
            failure_action: typeof challenges.failure_action === 'string' ? challenges.failure_action : defaults.challenges?.failure_action,
            theme: typeof challenges.theme === 'string' ? challenges.theme : defaults.challenges?.theme,
            custom_branding: typeof challenges.custom_branding === 'boolean' ? challenges.custom_branding : defaults.challenges?.custom_branding,
            branding_logo: typeof challenges.branding_logo === 'string' ? challenges.branding_logo : defaults.challenges?.branding_logo,
            branding_color: typeof challenges.branding_color === 'string' ? challenges.branding_color : defaults.challenges?.branding_color
        },
        tls: {
            ...defaults.tls,
            ...(hasTLS ? tls : {}),
            enabled: typeof tls.enabled === 'boolean' ? tls.enabled : defaults.tls?.enabled,
            ja3_enabled: typeof tls.ja3_enabled === 'boolean' ? tls.ja3_enabled : defaults.tls?.ja3_enabled,
            ja4_enabled: typeof tls.ja4_enabled === 'boolean' ? tls.ja4_enabled : defaults.tls?.ja4_enabled,
            header_order_enabled: typeof tls.header_order_enabled === 'boolean' ? tls.header_order_enabled : defaults.tls?.header_order_enabled,
            known_bot_ja3_hashes: asAntibotStringArray(tls.known_bot_ja3_hashes),
            known_bot_ja4_hashes: asAntibotStringArray(tls.known_bot_ja4_hashes),
            mismatch_action: typeof tls.mismatch_action === 'string' ? tls.mismatch_action : defaults.tls?.mismatch_action
        },
        anti_evasion: {
            ...defaults.anti_evasion,
            ...(hasAntiEvasion ? antiEvasion : {}),
            fp_rotation_detection: typeof antiEvasion.fp_rotation_detection === 'boolean' ? antiEvasion.fp_rotation_detection : defaults.anti_evasion?.fp_rotation_detection,
            credential_stuffing: typeof antiEvasion.credential_stuffing === 'boolean' ? antiEvasion.credential_stuffing : defaults.anti_evasion?.credential_stuffing,
            session_anomaly: typeof antiEvasion.session_anomaly === 'boolean' ? antiEvasion.session_anomaly : defaults.anti_evasion?.session_anomaly,
            rate_pattern_analysis: typeof antiEvasion.rate_pattern_analysis === 'boolean' ? antiEvasion.rate_pattern_analysis : defaults.anti_evasion?.rate_pattern_analysis,
            max_fps_per_ip: typeof antiEvasion.max_fps_per_ip === 'number' ? antiEvasion.max_fps_per_ip : defaults.anti_evasion?.max_fps_per_ip
        },
        detection: {
            ...defaults.detection,
            ...(hasDetection ? detection : {}),
            enabled: typeof detection.enabled === 'boolean' ? detection.enabled : undefined,
            mode: isAntibotModeName(detection.mode) ? detection.mode : undefined,
            block_threshold: typeof detection.block_threshold === 'number' ? detection.block_threshold : undefined,
            challenge_threshold: typeof detection.challenge_threshold === 'number' ? detection.challenge_threshold : undefined,
            dynamic_challenge: typeof detection.dynamic_challenge === 'boolean' ? detection.dynamic_challenge : undefined,
            sensitivity: typeof detection.sensitivity === 'number' ? detection.sensitivity : undefined,
            custom: asAntibotPresetDefinition(detection.custom)
        },
        classification: {
            ...defaults.classification,
            ...(hasClassification ? classification : {}),
            treat_unknown_as_bot: typeof classification.treat_unknown_as_bot === 'boolean' ? classification.treat_unknown_as_bot : undefined,
            allow_good_bots: typeof classification.allow_good_bots === 'boolean' ? classification.allow_good_bots : undefined,
            block_bad_bots: typeof classification.block_bad_bots === 'boolean' ? classification.block_bad_bots : undefined,
            verify_search_engines: typeof classification.verify_search_engines === 'boolean' ? classification.verify_search_engines : undefined,
            good_bot_rules: asAntibotOverrideRecord(classification.good_bot_rules)
        },
        ai_crawlers: {
            ...defaults.ai_crawlers,
            ...(hasAiCrawlers ? aiCrawlers : {}),
            enabled: typeof aiCrawlers.enabled === 'boolean' ? aiCrawlers.enabled : undefined,
            rules: asAntibotOverrideRecord(aiCrawlers.rules)
        },
        whitelist: {
            ...defaults.whitelist,
            ...(hasWhitelist ? whitelist : {}),
            ips: asAntibotStringArray(whitelist.ips),
            user_agents: asAntibotStringArray(whitelist.user_agents),
            paths: asAntibotStringArray(whitelist.paths),
            methods: asAntibotStringArray(whitelist.methods),
            headers: asAntibotStringArray(whitelist.headers)
        }
    };
}
// Public Bot Protection controls intentionally omit retired client collection,
// SDK build, evidence-lifetime, and per-section proxy switches. Keep this
// filter at the API edge so older stored documents cannot reintroduce them.
export function botConfigForSave(config) {
    const { hmac_secret_configured: _hmacSecretConfigured, revision: _revision, sdk_version: _sdkVersion, sdk_obfuscate: _sdkObfuscate, network: _network, fingerprint: _fingerprint, ...payload } = config;
    return payload;
}
export function antibotErrorMessage(error, fallback) {
    return error instanceof Error ? error.message : fallback;
}
export function antibotControl(id) {
    return AdminDOM.getById(id);
}
export function antibotInput(id) {
    const control = antibotControl(id);
    return control instanceof HTMLInputElement ? control : null;
}
export function antibotSelect(id) {
    const control = antibotControl(id);
    return control instanceof HTMLSelectElement ? control : null;
}
export function antibotValue(id) {
    return antibotControl(id)?.value ?? '';
}
export function setAntibotField(config, path, value) {
    const parts = path.split('.');
    let target = config;
    for (let i = 0; i < parts.length - 1; i++) {
        const part = parts[i];
        const current = target[part];
        if (!isAntibotRecord(current)) {
            const next = {};
            target[part] = next;
            target = next;
        }
        else {
            target = current;
        }
    }
    target[parts[parts.length - 1]] = value;
}
