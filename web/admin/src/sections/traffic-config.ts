// Traffic Control Configuration - Standard UI
// Aligned with internal/infra/config patterns and console.css
import { SectionUI } from './ui-components.js';
import { api } from '../api.js';
import * as AdminDOM from '../core/dom.js';
import * as AdminEvents from '../core/events.js';
import { showSectionToast } from './section-toast-helpers.js';
import { saveSectionConfig, type SectionMutationError } from './section-mutation-helpers.js';
import { renderTrafficSaveButtons } from './traffic-render-helpers.js';
import { FEATURES, renderUpgradeBanner } from '../core/features.js';
import {
    buildTrafficBlacklistPageData,
    escapeTrafficAttr,
    escapeTrafficHtml,
    formatTrafficNumber,
    getTrafficBlacklistEntries,
    getTrafficBlacklistTotalCount
} from './traffic-runtime-helpers.js';
import { renderBlacklistTab } from './traffic/blacklist.js';
import { renderReputationTab } from './traffic/reputation.js';
import { renderRateLimitTab } from './traffic/ratelimit.js';
import { renderGeoTab } from './traffic/geo.js';
import { renderDDoSTab } from './traffic/ddos.js';
import { renderPriorityTab } from './traffic/priority.js';
import {
    ThreatFeedPaginationState,
    UnifiedThreatFeedData,
    UnifiedThreatIndicator
} from './traffic/types.js';

type TrafficTabId = 'overview' | 'blacklist' | 'reputation' | 'ratelimit' | 'geo' | 'ddos' | 'priority';

interface TrafficTab {
    id: TrafficTabId;
    name: string;
    icon: string;
}

interface TrafficStats {
    total_requests?: number;
    blocked_requests?: number;
    active_connections?: number;
    in_flight_requests?: number;
    custom?: {
        active_connections?: number;
        in_flight_requests?: number;
        [key: string]: unknown;
    };
    [key: string]: unknown;
}

interface TrafficBlacklistEntry {
    target: string;
    expires_at?: string | null;
    note?: string;
    [key: string]: unknown;
}

interface TrafficBlacklistConfig {
    enabled?: boolean;
    ips?: string[];
    cidrs?: string[];
    entries?: TrafficBlacklistEntry[];
    [key: string]: unknown;
}

interface TrafficGeoConfig {
    enabled?: boolean;
    mode?: 'blocklist' | 'allowlist';
    db_path?: string;
    auto_update?: boolean;
    update_interval?: string;
    update_url?: string;
    countries?: string[];
    regions?: string[];
    exceptions?: string[];
    allow_countries?: string[];
    block_countries?: string[];
    groups?: string[];
    /** Explicit policy for a request whose country cannot be resolved. */
    unknown_action?: 'allow' | 'block' | 'challenge';
    cache_ttl?: string;
    [key: string]: unknown;
}

interface TrafficGeoStatus {
    enabled?: boolean;
    mode?: string;
    db_path?: string;
    db_loaded?: boolean;
    lookup_mode?: string;
    auto_update?: boolean;
    unknown_action?: 'allow' | 'block' | 'challenge';
    countries?: number;
    regions?: number;
    exceptions?: number;
    last_loaded_at?: string;
    last_error?: string;
    fail_open?: boolean;
    provider?: string;
    attribution_url?: string;
    policy?: {
        enabled?: boolean;
        allow_countries?: string[];
        block_countries?: string[];
        groups?: string[];
        exceptions?: number;
        fail_open?: boolean;
    };
    database?: {
        path?: string;
        loaded?: boolean;
        generation?: string;
        database_type?: string;
        loaded_at?: string;
        last_error?: string;
        cache_entries?: number;
        cache_hits?: number;
        cache_misses?: number;
        unknown?: number;
    };
    [key: string]: unknown;
}

interface TrafficReputationProviderConfig {
    enabled?: boolean;
    api_key?: string;
	api_key_configured?: boolean;
	clear_api_key?: boolean;
    confidence_score?: number;
    source?: string;
    drop_list_url?: string;
    [key: string]: unknown;
}

interface TrafficReputationConfig {
    enabled?: boolean;
    block_datacenter?: boolean;
    block_tor?: boolean;
    sensitivity?: number | string;
    action?: string;
    cti?: {
        enabled?: boolean;
        url?: string;
        api_key?: string;
        min_score?: number;
    };
    [key: string]: unknown;
}

interface TrafficRateLimitRule {
    id?: string;
    name?: string;
    priority?: number;
    hosts?: string[];
    methods?: string[];
    pattern: string;
    match?: 'exact' | 'prefix' | 'glob';
    rate: number;
    burst: number;
    window?: string;
    action?: 'block' | 'challenge' | 'dry_run' | string;
    algorithm?: 'token_bucket' | 'fixed_window' | 'sliding_window' | string;
    key_by?: 'ip' | 'ip_ua' | 'cookie' | 'token' | string;
    bypass_static?: boolean;
    dry_run?: boolean;
    verified_grace_multiplier?: number;
    [key: string]: unknown;
}

interface TrafficRateLimitConfig {
    enabled?: boolean;
    default_rate?: number;
    window?: string;
    default_burst?: number;
    algorithm?: string;
    key_by?: string;
    action?: string;
    bypass_static?: boolean;
    bypass_known_bots?: boolean;
	verified_grace_multiplier?: number;
	dry_run?: boolean;
	max_states?: number;
	state_idle_ttl?: string;
    path_overrides?: TrafficRateLimitRule[];
    [key: string]: unknown;
}

interface TrafficDDoSConfig {
    enabled?: boolean;
    max_rps?: number;
    max_connections?: number;
    burst_multiplier?: number;
    action?: string;
    challenge?: TrafficChallengeConfig;
    auto_ban?: boolean;
    ban_duration?: number;
    objects?: Array<{ id: string; hosts?: string[]; methods?: string[]; path?: string; path_match?: string; max_rps?: number; max_concurrency?: number; burst_multiplier?: number; action?: string; auto_ban?: boolean; ban_duration?: number; verified_grace_multiplier?: number; }>;
    [key: string]: unknown;
}

interface TrafficChallengeConfig {
    enabled?: boolean;
    threshold?: number;
    mode?: string;
    [key: string]: unknown;
}

interface TrafficPriorityConfig {
    enabled?: boolean;
    vip_ips?: string[];
    [key: string]: unknown;
}

interface TrafficControlState {
	control?: {
		schema_version?: number;
		revision?: string;
		checksum?: string;
		updated_at?: string;
		updated_by?: string;
		[key: string]: unknown;
	};
    blacklist?: TrafficBlacklistConfig;
    geo?: TrafficGeoConfig;
    reputation?: TrafficReputationConfig;
    rate_limit?: TrafficRateLimitConfig;
    ratelimit?: TrafficRateLimitConfig;
    ddos?: TrafficDDoSConfig;
    application_flood?: TrafficDDoSConfig;
    challenge?: TrafficChallengeConfig;
    priority?: TrafficPriorityConfig;
    trusted_exceptions?: TrafficTrustedException[];
    conn_stats?: { enabled?: boolean; [key: string]: unknown };
    connstats?: { enabled?: boolean; [key: string]: unknown };
    [key: string]: unknown;
}

export function normalizeTrafficConfigForUI(config: TrafficControlState): TrafficControlState {
    const normalized: TrafficControlState = { ...config };
    normalized.rate_limit = normalized.rate_limit || normalized.ratelimit || {};
    normalized.ratelimit = normalized.rate_limit;
    normalized.conn_stats = normalized.conn_stats || normalized.connstats || {};
    normalized.connstats = normalized.conn_stats;
    normalized.challenge = normalized.challenge || {};
    normalized.application_flood = normalized.application_flood || normalized.ddos || {};
    normalized.ddos = normalized.application_flood;
    normalized.trusted_exceptions = normalized.trusted_exceptions || [];
    normalized.blacklist = syncTrafficBlacklistEnabled(normalized.blacklist || {});
    normalized.geo = normalizeTrafficGeoPolicy(normalized.geo || {});
    return normalized;
}

export function normalizeTrafficConfigForSave(config: TrafficControlState): TrafficControlState {
    const payload: TrafficControlState = { ...config };
    payload.ratelimit = payload.rate_limit || payload.ratelimit || {};
    payload.conn_stats = payload.conn_stats || payload.connstats || {};
    delete payload.rate_limit;
    delete payload.connstats;
    payload.blacklist = syncTrafficBlacklistEnabled(payload.blacklist || {});
    payload.geo = normalizeTrafficGeoPolicy(payload.geo || {});
    if (payload.application_flood && typeof payload.application_flood === 'object') {
        const flood = { ...payload.application_flood };
        delete flood.challenge;
        delete flood.emergency;
        delete flood.panic_enabled;
        delete flood.panic_threshold;
        payload.application_flood = flood;
    }
    delete payload.ddos;
    delete payload.priority;
    if (payload.reputation && typeof payload.reputation === 'object') {
        delete (payload.reputation as Record<string, unknown>).api_key_configured;
        delete (payload.reputation as Record<string, unknown>).rules;
        if (payload.reputation.cti && typeof payload.reputation.cti === 'object') {
            delete (payload.reputation.cti as Record<string, unknown>).api_key_configured;
        }
    }
    return payload;
}

function syncTrafficBlacklistEnabled(blacklist: TrafficBlacklistConfig = {}): TrafficBlacklistConfig {
    const normalized: TrafficBlacklistConfig = {
        ...blacklist,
        ips: blacklist.ips || [],
        cidrs: blacklist.cidrs || [],
        entries: blacklist.entries || []
    };
    const now = Date.now();
    normalized.enabled = getTrafficBlacklistEntries(normalized).some(entry => {
        if (!entry.expires_at) return true;
        const expiresAt = new Date(entry.expires_at).getTime();
        return Number.isNaN(expiresAt) || expiresAt >= now;
    });
    return normalized;
}

interface TrafficTrustedException {
    id: string;
    targets: string[];
    controls: Array<'flood' | 'rate' | 'geo' | 'reputation'>;
    hosts?: string[];
    methods?: string[];
    path?: string;
    path_match?: 'exact' | 'prefix' | 'glob';
    expires_at?: string;
    note?: string;
}

interface TrafficConfigSaveResponse {
    status: 'ok';
    revision: string;
    checksum: string;
}

function normalizeTrafficGeoPolicy(geo: TrafficGeoConfig): TrafficGeoConfig {
    const normalized: TrafficGeoConfig = { ...geo };
    const mode = normalized.mode === 'allowlist' ? 'allowlist' : 'blocklist';
    let allowCountries = normalizeTrafficCountryCodes(normalized.allow_countries || []);
    let blockCountries = normalizeTrafficCountryCodes(normalized.block_countries || []);
    const legacyCountries = normalizeTrafficCountryCodes(normalized.countries || []);
    const groups = normalizeTrafficGroups([...(normalized.groups || []), ...(normalized.regions || [])]);

    if (allowCountries.length === 0 && blockCountries.length === 0 && legacyCountries.length > 0) {
        if (mode === 'allowlist') {
            allowCountries = legacyCountries;
        } else {
            blockCountries = legacyCountries;
        }
    }

    normalized.allow_countries = allowCountries;
    normalized.block_countries = blockCountries;
    normalized.groups = groups;
    normalized.regions = groups;
    normalized.mode = allowCountries.length > 0 ? 'allowlist' : 'blocklist';
    normalized.countries = allowCountries.length > 0 ? allowCountries : blockCountries;
    normalized.enabled = normalized.countries.length > 0 || groups.length > 0;
    return normalized;
}

function normalizeTrafficCountryCodes(values: string[]): string[] {
    return Array.from(new Set(values
        .map(value => String(value || '').trim().toUpperCase())
        .filter(value => /^[A-Z]{2}$/.test(value))))
        .sort();
}

function normalizeTrafficGroups(values: string[]): string[] {
    return Array.from(new Set(values
        .map(value => String(value || '').trim().replace(/^@/, '').toUpperCase())
        .filter(Boolean)))
        .sort();
}

function trafficCountryFlag(code: string): string {
    const normalized = String(code || '').trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(normalized)) return normalized;

    return Array.from(normalized)
        .map(letter => String.fromCodePoint(0x1F1E6 + letter.charCodeAt(0) - 65))
        .join('');
}

interface TrafficBlacklistPagination {
    page: number;
    pageSize: number;
    search: string;
}

interface TrafficCapability {
    available?: boolean;
    configurable?: boolean;
    tier?: string;
}

interface TrafficCapabilities {
    schema_version?: number;
    edition?: string;
    features?: Record<string, TrafficCapability>;
}

interface TrafficOperationsStatus {
    health?: { status?: 'healthy' | 'degraded' | 'unhealthy'; message?: string; checked_at?: string; };
    revision?: { active?: string; updated_at?: string; updated_by?: string; [key: string]: unknown; };
    state?: { ratelimit_entries?: number; ratelimit_capacity?: number; ratelimit_evictions?: number; flood_entries?: number; flood_capacity?: number; [key: string]: unknown; };
    telemetry?: { storage_available?: boolean; ingestion_lag_seconds?: number; storage_dropped_events?: number; traffic_decision_drops?: number; freshness?: string; message?: string; [key: string]: unknown; };
	freshness?: { geo_database_age_seconds?: number; reputation_feeds?: Record<string, { age_seconds?: number; last_error?: string }>; [key: string]: unknown; };
	persistence?: { [key: string]: unknown; };
    latency?: { samples?: number; average_ms?: number; p50_ms?: number; p95_ms?: number; p99_ms?: number; };
    modules?: Record<string, unknown>;
	module_readiness?: Record<string, 'ready' | 'degraded' | 'unhealthy' | 'disabled'>;
    [key: string]: unknown;
}

type TrafficConfigRuntime = {
    currentTab: TrafficTabId;
    config: TrafficControlState;
    stats: TrafficStats;
    geoStatus: TrafficGeoStatus | null;
    capabilities: TrafficCapabilities | null;
	operations: TrafficOperationsStatus | null;
    blacklistPagination: TrafficBlacklistPagination;
    blacklistSelected: Set<string>;
    threatFeedPage: boolean;
    threatFeedData: UnifiedThreatFeedData | null;
    threatFeedPagination: ThreatFeedPaginationState;
    pendingTarget: string | null;
    pendingVipTarget: string | null;
    rateLimitView: 'table' | 'editor';
    editingRateRuleIndex: number | null;
    rateEngineSettingsOpen?: boolean;
    map: JsVectorMapInstance | null;
    countries: Record<string, string>;
    regions: Record<string, string>;
    regionMembers: Record<string, string[]>;
    tabs: TrafficTab[];
    icons: Record<string, string>;
    init(): Promise<void>;
    loadConfig(): Promise<void>;
    loadStats(): Promise<void>;
    loadGeoStatus(): Promise<void>;
    loadCapabilities(): Promise<void>;
	loadOperations(): Promise<void>;
    loadThreatFeed(): Promise<void>;
    refreshThreatFeed(): Promise<void>;
    buildMergedThreatFeedData(): UnifiedThreatFeedData;
    render(): void;
    switchTab(id: TrafficTabId): void;
    renderTabContent(): string;
	renderOverview(): string;
    renderOverviewMetricCard(label: string, value: unknown, unit: string, tone: string): string;
    renderSectionHeader(icon: string, title: string, desc: string, toggleField?: string | null, toggleValue?: boolean): string;
    renderModuleStatusCard(title: string, description: string, icon: string, configKey: string): string;
    renderWAFStyleModuleCard(key: string, title: string, subtitle: string, cfg: { enabled?: boolean } | undefined, icon: string): string;
    toggleProtection(key: string): void;
    renderBlacklist(): string;
    openAddIPModal(editTarget?: string | null, editExpiresLegacy?: string | null): void;
    saveAddedIPs(editingTarget?: string): void;
    openImportBlacklistCSV(): void;
    importBlacklistCSV(file: File): Promise<void>;
    removeIP(entry: string): void;
    confirmRemoveIP(): void;
    removeLocalEntry(target: string): void;
    areBlacklistTargetsSelected(targets: string[]): boolean;
    updateBlacklistSelection(targets: string[], selectAll: boolean): void;
    removeLocalEntries(targets: Iterable<string>): void;
    getBlacklistTargets(entries: Array<{ target: string }>): string[];
    toggleBlacklistSelection(target: string): void;
    toggleSelectAllBlacklist(selectAll: boolean): void;
    deleteSelectedBlacklist(): void;
    confirmDeleteSelected(): void;
    flushBlacklist(): void;
    confirmFlushBlacklist(total: number): void;
    renderGeo(): string;
    openGeoModal(): void;
    filterGeoModal(query: string): void;
    getCheckedTrafficValues(selector: string): string[];
    removeTrafficTooltips(): void;
    getGeoPolicyCountries(cfg?: TrafficGeoConfig): string[];
    getGeoPolicyGroups(cfg?: TrafficGeoConfig): string[];
    setGeoMode(mode: string): void;
    getGeoHighlightedCountries(cfg?: TrafficGeoConfig): string[];
    saveGeoSelection(): void;
    removeCountry(code: string): void;
    removeRegion(code: string): void;
    renderReputation(): string;
    renderRateLimit(): string;

    renderDDoS(): string;
    openAddFloodObjectModal(): void;
    saveFloodObject(): void;
    removeFloodObject(id: string): void;
    renderPriority(): string;
    openAddVIPModal(): void;
    saveAddedVIPs(): void;
    removeVIP(ip: string): void;
    confirmRemoveVIP(): void;
    openAddRateRule(): void;
    openEditRateRule(idx: number): void;
    cancelRateRuleEditor(): void;
    openAddRateRuleModal(): void;
    openEditRateRuleModal(idx: number): void;
    toggleRateEngineSettings(): void;
    renderRateRuleModal(rule?: any): void;
    saveRateRule(): void;
    removeRateRule(idx: number): void;
    openAddReputationRuleModal(): void;
    saveReputationRule(): void;
    removeReputationRule(ruleId: string): void;
    initGeoMap(): Promise<void>;
    toggleCountry(code: string): void;
    loadMapLibs(): Promise<void>;
    updateNestedField(p: string, f: string, v: unknown): void;
    updateNestedArrayFieldNewlines(p: string, f: string, v: string): void;
    saveConfig(): Promise<void>;
};

let trafficBindingsInitialized = false;
let trafficSaveInFlight = false;

function encodeTrafficValue(value: string): string {
    return encodeURIComponent(value);
}

function decodeTrafficValue(value: string | undefined): string {
    return value ? decodeURIComponent(value) : '';
}

function isValidTrafficBlacklistTarget(entry: string): boolean {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const cidrV4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[12][0-9]|3[0-2])$/;
    const cidrV6Regex = /^([0-9a-fA-F:]+)\/([0-9]{1,3})$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^::$/;
    const cidrV6Match = cidrV6Regex.exec(entry);
    const isValidCidrV6 = Boolean(cidrV6Match && Number.parseInt(cidrV6Match[2], 10) >= 1 && Number.parseInt(cidrV6Match[2], 10) <= 128);

    return cidrV4Regex.test(entry) || isValidCidrV6 || ipv4Regex.test(entry) || ipv6Regex.test(entry);
}

type TrafficBlacklistImportEntry = Pick<TrafficBlacklistEntry, 'target' | 'expires_at' | 'note'>;

function parseTrafficCsvRows(content: string): string[][] | null {
    const rows: string[][] = [];
    let row: string[] = [];
    let cell = '';
    let quoted = false;

    const finishRow = (): void => {
        row.push(cell);
        if (row.some(value => value.trim() !== '')) rows.push(row);
        row = [];
        cell = '';
    };

    for (let index = 0; index < content.length; index++) {
        const character = content[index];
        if (character === '"') {
            if (quoted && content[index + 1] === '"') {
                cell += '"';
                index++;
            } else {
                quoted = !quoted;
            }
        } else if (character === ',' && !quoted) {
            row.push(cell);
            cell = '';
        } else if (character === '\n' && !quoted) {
            finishRow();
        } else if (character !== '\r') {
            cell += character;
        }
    }

    if (quoted) return null;
    if (cell !== '' || row.length > 0) finishRow();
    return rows;
}

function parseTrafficBlacklistCSV(content: string): { entries: TrafficBlacklistImportEntry[]; invalidRows: number; malformed: boolean } {
    const rows = parseTrafficCsvRows(content.replace(/^\uFEFF/, ''));
    if (!rows) return { entries: [], invalidRows: 0, malformed: true };
    if (rows.length === 0) return { entries: [], invalidRows: 0, malformed: false };

    const header = rows[0].map(value => value.trim().toLowerCase().replace(/[\s-]+/g, '_'));
    const headerIndex = (...names: string[]): number => header.findIndex(value => names.includes(value));
    const headerTarget = headerIndex('target', 'ip', 'ip_address', 'address');
    const headerExpiration = headerIndex('expiration', 'expires', 'expires_at');
    const headerNote = headerIndex('note', 'notes', 'comment');
    const hasHeader = headerTarget >= 0 || headerExpiration >= 0 || headerNote >= 0;
    const targetIndex = headerTarget >= 0 ? headerTarget : 0;
    const sourceRows = hasHeader ? rows.slice(1) : rows;
    const entries = new Map<string, TrafficBlacklistImportEntry>();
    let invalidRows = 0;

    for (const row of sourceRows) {
        const target = (row[targetIndex] || '').trim();
        if (!target) continue;
        if (!isValidTrafficBlacklistTarget(target)) {
            invalidRows++;
            continue;
        }

        const expiration = headerExpiration >= 0 ? (row[headerExpiration] || '').trim() : '';
        let expiresAt: string | null = null;
        if (expiration && !/^permanent$/i.test(expiration)) {
            const timestamp = Date.parse(expiration);
            if (Number.isNaN(timestamp)) {
                invalidRows++;
                continue;
            }
            expiresAt = new Date(timestamp).toISOString();
        }

        entries.set(target, {
            target,
            expires_at: expiresAt,
            note: headerNote >= 0 ? (row[headerNote] || '').trim() : ''
        });
    }

    return { entries: Array.from(entries.values()), invalidRows, malformed: false };
}

function trafficDoc(): Document {
    return globalThis['document'];
}

function trafficElementById<T extends HTMLElement = HTMLElement>(id: string): T | null {
    const element = trafficDoc().getElementById(id);
    return element instanceof HTMLElement ? (element as T) : null;
}

function trafficQuery<T extends Element = Element>(selector: string, root: ParentNode = trafficDoc()): T | null {
    const element = root.querySelector(selector);
    return element instanceof Element ? (element as T) : null;
}

function trafficQueryAll<T extends Element = Element>(selector: string, root: ParentNode = trafficDoc()): T[] {
    return Array.from(root.querySelectorAll(selector)).filter((element): element is T => element instanceof Element);
}

function setTrafficMirrorValue(targetId: string | undefined, value: string): void {
    if (!targetId) return;
    const element = trafficElementById(targetId);
    if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement) {
        element.value = value;
    } else if (element instanceof HTMLElement) {
        element.textContent = value;
    }
}

function parseTrafficDatasetValue(
    target: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement | HTMLElement
): unknown {
    const valueType = target.dataset.trafficValueType || 'string';
    const rawValue =
        target instanceof HTMLInputElement || target instanceof HTMLSelectElement || target instanceof HTMLTextAreaElement
            ? target.value
            : decodeTrafficValue(target.dataset.trafficValue);

    switch (valueType) {
        case 'checkbox':
            return target instanceof HTMLInputElement ? target.checked : rawValue === 'true';
        case 'number': {
            const parsed = Number.parseInt(rawValue, 10);
            return Number.isFinite(parsed) ? parsed : 0;
        }
        case 'float': {
            const parsed = Number.parseFloat(rawValue);
            return Number.isFinite(parsed) ? parsed : 0;
        }
        default:
            return rawValue;
    }
}

function applyTrafficNestedField(target: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement | HTMLElement): void {
    const parent = target.dataset.trafficParent;
    const field = target.dataset.trafficField;
    if (!parent || !field) return;
    TrafficConfig.updateNestedField(parent, field, parseTrafficDatasetValue(target));
    if (target.dataset.trafficRender === 'true') TrafficConfig.render();
}

const trafficReadOnlyActions = new Set([
    'switch-tab',
    'clear-blacklist-selection',
    'blacklist-prev-page',
    'blacklist-next-page',
    'open-tor-feed-page',
    'close-tor-feed-page',
    'refresh-tor-feed',
    'tor-feed-prev-page',
    'tor-feed-next-page',
    'open-threat-feed-page',
    'close-threat-feed-page',
    'refresh-threat-feed',
    'threat-feed-prev-page',
    'threat-feed-next-page',
    'threat-feed-sort',
    'threat-feed-severity-filter',
    'open-add-rate-rule',
    'open-edit-rate-rule',
    'cancel-rate-rule-editor',
    'set-rule-action',
    'open-add-rate-rule-modal',
    'open-edit-rate-rule-modal',
    'toggle-rate-engine-settings',
    'close-modal',
    'reset'
]);

// Traffic's visible editor writes the whole revisioned control-plane document,
// including source/provider settings. The API deliberately requires
// traffic:admin for that boundary, so the UI must not let a read-only or
// traffic:write-only operator stage a change they cannot safely commit.
function trafficCanMutate(): boolean {
    return api.hasPermission('traffic:admin');
}

function trafficReadOnlyWarning(): void {
    showSectionToast('Traffic Control policy changes require traffic:admin.', 'warning');
}

function applyTrafficPermissionState(root: HTMLElement): void {
    if (trafficCanMutate()) {
        root.removeAttribute('data-traffic-read-only');
        return;
    }
    root.setAttribute('data-traffic-read-only', 'true');
    root.querySelectorAll<HTMLElement>('[data-traffic-action]').forEach(control => {
        if (trafficReadOnlyActions.has(control.dataset.trafficAction || '')) return;
        control.setAttribute('aria-disabled', 'true');
        if (control instanceof HTMLButtonElement || control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement) {
            control.disabled = true;
        } else {
            control.setAttribute('tabindex', '-1');
        }
    });
    root.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>('[data-traffic-parent][data-traffic-field]').forEach(control => {
        control.disabled = true;
        control.setAttribute('aria-disabled', 'true');
    });
}

function ensureTrafficBindings(): void {
    if (trafficBindingsInitialized) return;
    trafficBindingsInitialized = true;
    const dirtyActions = new Set([
        'delete-selected-blacklist',
        'save-added-ips',
        'set-geo-mode',
        'remove-region',
        'remove-country',
        'save-geo-selection',
        'save-rep-provider',
        'save-rate-rule',
        'remove-rate-rule',
        'save-added-vips',
        'remove-vip',
		'save-flood-object',
		'remove-flood-object',
        'set-nested-field'
    ]);

    AdminEvents.delegateEvent<HTMLElement>(document, 'click', '[data-traffic-action]', (event, target) => {
        const action = target.dataset.trafficAction;
        const tab = target.dataset.trafficTab as TrafficTabId | undefined;
        const value = decodeTrafficValue(target.dataset.trafficValue);
        const render = target.dataset.trafficRender === 'true';

        if (action && !trafficReadOnlyActions.has(action) && !trafficCanMutate()) {
            event.preventDefault();
            trafficReadOnlyWarning();
            return;
        }

        switch (action) {
            case 'switch-tab':
                if (tab) TrafficConfig.switchTab(tab);
                break;
            case 'clear-blacklist-selection':
                TrafficConfig.blacklistSelected.clear();
                TrafficConfig.render();
                break;
            case 'delete-selected-blacklist':
                TrafficConfig.deleteSelectedBlacklist();
                break;
            case 'open-import-blacklist-csv':
                TrafficConfig.openImportBlacklistCSV();
                break;
            case 'open-add-ip-modal':
                TrafficConfig.openAddIPModal(value || null);
                break;
            case 'remove-ip':
                TrafficConfig.removeIP(value);
                break;
            case 'blacklist-prev-page':
                TrafficConfig.blacklistPagination.page--;
                TrafficConfig.render();
                break;
            case 'blacklist-next-page':
                TrafficConfig.blacklistPagination.page++;
                TrafficConfig.render();
                break;
            case 'close-modal':
                SectionUI.closeModal();
                break;
            case 'save-added-ips':
                TrafficConfig.saveAddedIPs(value);
                break;
            case 'set-geo-mode':
                TrafficConfig.setGeoMode(value);
                TrafficConfig.render();
                break;
            case 'open-geo-modal':
                TrafficConfig.openGeoModal();
                break;
            case 'remove-region':
                TrafficConfig.removeRegion(value);
                break;
            case 'remove-country':
                TrafficConfig.removeCountry(value);
                break;
            case 'save-geo-selection':
                TrafficConfig.saveGeoSelection();
                break;
            case 'open-reputation-module':
                if (typeof (window as any).router?.navigate === 'function') {
                    (window as any).router.navigate('module_reputation');
                }
                break;
            case 'open-threat-feed-page':
                if (typeof (window as any).router?.navigate === 'function') {
                    (window as any).router.navigate('module_reputation');
                } else {
                    TrafficConfig.threatFeedPage = true;
                    void TrafficConfig.loadThreatFeed().then(() => TrafficConfig.render());
                }
                break;
            case 'close-threat-feed-page':
                TrafficConfig.threatFeedPage = false;
                TrafficConfig.render();
                break;
            case 'refresh-threat-feed':
                void TrafficConfig.refreshThreatFeed();
                break;
            case 'threat-feed-prev-page':
                TrafficConfig.threatFeedPagination.page--;
                TrafficConfig.render();
                break;
            case 'threat-feed-next-page':
                TrafficConfig.threatFeedPagination.page++;
                TrafficConfig.render();
                break;
            case 'threat-feed-sort': {
                const sortField = (target.dataset.sortBy || 'score') as 'indicator' | 'score' | 'severity' | 'category' | 'protocol' | 'confidence';
                if (TrafficConfig.threatFeedPagination.sortBy === sortField) {
                    TrafficConfig.threatFeedPagination.sortOrder = TrafficConfig.threatFeedPagination.sortOrder === 'asc' ? 'desc' : 'asc';
                } else {
                    TrafficConfig.threatFeedPagination.sortBy = sortField;
                    TrafficConfig.threatFeedPagination.sortOrder = sortField === 'score' ? 'desc' : 'asc';
                }
                TrafficConfig.render();
                break;
            }
            case 'open-add-rate-rule':
            case 'open-add-rate-rule-modal':
                TrafficConfig.openAddRateRule();
                break;
            case 'open-edit-rate-rule':
            case 'open-edit-rate-rule-modal': {
                const idx = Number.parseInt(value, 10);
                if (Number.isFinite(idx)) TrafficConfig.openEditRateRule(idx);
                break;
            }
            case 'cancel-rate-rule-editor':
                TrafficConfig.cancelRateRuleEditor();
                break;
            case 'set-rule-action': {
                const hiddenInput = trafficElementById('rl-rule-action');
                if (hiddenInput instanceof HTMLInputElement) hiddenInput.value = value;
                trafficDoc().querySelectorAll('.flow-rate-action-btn').forEach(btn => {
                    const isActive = btn.getAttribute('data-traffic-value') === value;
                    btn.classList.toggle('is-active', isActive);
                    btn.setAttribute('aria-checked', String(isActive));
                });
                break;
            }
            case 'toggle-rate-engine-settings':
                TrafficConfig.toggleRateEngineSettings();
                break;
            case 'save-rate-rule':
                TrafficConfig.saveRateRule();
                break;
            case 'remove-rate-rule': {
                const idx = Number.parseInt(value, 10);
                if (Number.isFinite(idx)) TrafficConfig.removeRateRule(idx);
                break;
            }
            case 'open-add-reputation-rule':
                TrafficConfig.openAddReputationRuleModal();
                break;
            case 'save-reputation-rule':
                TrafficConfig.saveReputationRule();
                break;
            case 'delete-reputation-rule':
                TrafficConfig.removeReputationRule(value);
                break;
            case 'open-add-vip-modal':
                TrafficConfig.openAddVIPModal();
                break;
			case 'open-add-flood-object':
				TrafficConfig.openAddFloodObjectModal();
				break;
			case 'save-flood-object':
				TrafficConfig.saveFloodObject();
				break;
			case 'remove-flood-object':
				TrafficConfig.removeFloodObject(value);
				break;
            case 'save-added-vips':
                TrafficConfig.saveAddedVIPs();
                break;
            case 'remove-vip':
                TrafficConfig.removeVIP(value);
                break;
            case 'reset':
                void TrafficConfig.init().then(() => SectionUI.markSaveActionBarClean('data-traffic-action')).catch(() => undefined);
                break;
            case 'save-config':
                if (trafficSaveInFlight) break;
                trafficSaveInFlight = true;
                target.setAttribute('aria-busy', 'true');
                target.setAttribute('disabled', '');
                void TrafficConfig.saveConfig()
                    .then(() => SectionUI.markSaveActionBarClean('data-traffic-action'))
                    .catch(() => undefined)
                    .finally(() => {
                        trafficSaveInFlight = false;
                        target.removeAttribute('aria-busy');
                        target.removeAttribute('disabled');
                    });
                break;
            case 'set-nested-field':
                applyTrafficNestedField(target);
                break;
            default:
                break;
        }

        if (render && action !== 'set-nested-field') {
            TrafficConfig.render();
        }

        if (action && dirtyActions.has(action)) {
            SectionUI.markSaveActionBarDirty('data-traffic-action');
        }
    });

    AdminEvents.delegateEvent<HTMLElement>(
        document,
        'keydown', '[data-traffic-action="switch-tab"][role="button"]',
        (event, target) => {
            if (!(event instanceof KeyboardEvent) || (event.key !== 'Enter' && event.key !== ' ')) return;
            event.preventDefault();
            target.click();
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(
        document,
        'change',
        '[data-traffic-parent][data-traffic-field]',
        (event, target) => {
            if (!trafficCanMutate()) {
                event.preventDefault();
                TrafficConfig.render();
                trafficReadOnlyWarning();
                return;
            }
            applyTrafficNestedField(target);
            SectionUI.markSaveActionBarDirty('data-traffic-action');
        }
    );

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'input', '[data-traffic-sync-target]', (event, target) => {
        if (!trafficCanMutate()) {
            event.preventDefault();
            TrafficConfig.render();
            trafficReadOnlyWarning();
            return;
        }
        setTrafficMirrorValue(target.dataset.trafficSyncTarget, target.value);

        if (target.dataset.trafficParent && target.dataset.trafficField) {
            applyTrafficNestedField(target);
            SectionUI.markSaveActionBarDirty('data-traffic-action');
        }

        if (target.dataset.trafficSensitivityDisplay === 'true') {
            const sensitivity = Number(target.value);
            const display = trafficElementById('reputation-sensitivity-display');
            const summary = trafficElementById('reputation-summary-threshold');
            const marker = trafficElementById('reputation-threshold-marker');
            const fill = trafficElementById('reputation-threshold-fill');
            if (display) display.textContent = `${sensitivity}`;
            if (summary) summary.textContent = `${sensitivity}/100`;
            if (marker) marker.style.left = `${sensitivity}%`;
            if (fill) fill.style.width = `${sensitivity}%`;
            const action = trafficQuery<HTMLElement>(
                '[data-traffic-parent="reputation"][data-traffic-field="action"].is-active'
            )?.dataset.trafficValue === 'challenge'
                ? 'challenged'
                : 'blocked';
            const text = trafficElementById('reputation-sensitivity-text');
            if (text) {
                text.textContent = `Requests scoring below ${sensitivity} will be ${action}.`;
            }
        }
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'input', '[data-traffic-pagination-search]', (_event, target) => {
        TrafficConfig.blacklistPagination.search = target.value;
        TrafficConfig.blacklistPagination.page = 1;
        TrafficConfig.render();
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'input', '[data-traffic-threat-search]', (_event, target) => {
        TrafficConfig.threatFeedPagination.search = target.value;
        TrafficConfig.threatFeedPagination.page = 1;
        TrafficConfig.render();
    });

    AdminEvents.delegateEvent<HTMLSelectElement>(document, 'change', '[data-traffic-threat-source-filter], [data-traffic-action="threat-feed-severity-filter"]', (_event, target) => {
        TrafficConfig.threatFeedPagination.severityFilter = target.value;
        TrafficConfig.threatFeedPagination.page = 1;
        TrafficConfig.render();
    });

    AdminEvents.delegateEvent<HTMLSelectElement>(document, 'change', '[data-traffic-threat-pagesize], [data-traffic-threat-page-size]', (_event, target) => {
        TrafficConfig.threatFeedPagination.pageSize = Number.parseInt(target.value, 10) || 25;
        TrafficConfig.threatFeedPagination.page = 1;
        TrafficConfig.render();
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'input', '[data-traffic-tor-search]', (_event, target) => {
        TrafficConfig.threatFeedPagination.search = target.value;
        TrafficConfig.threatFeedPagination.page = 1;
        TrafficConfig.render();
    });

    AdminEvents.delegateEvent<HTMLSelectElement>(document, 'change', '[data-traffic-tor-pagesize]', (_event, target) => {
        TrafficConfig.threatFeedPagination.pageSize = Number.parseInt(target.value, 10) || 25;
        TrafficConfig.threatFeedPagination.page = 1;
        TrafficConfig.render();
    });


    AdminEvents.delegateEvent<HTMLInputElement>(document, 'change', '[data-traffic-blacklist-import]', (_event, target) => {
        const file = target.files?.[0];
        target.value = '';
        if (!file) return;
        if (!trafficCanMutate()) {
            trafficReadOnlyWarning();
            return;
        }
        void TrafficConfig.importBlacklistCSV(file);
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'change', '[data-traffic-blacklist-select]', (_event, target) => {
        const entry = decodeTrafficValue(target.dataset.trafficBlacklistSelect);
        if (!entry) return;
        TrafficConfig.toggleBlacklistSelection(entry);
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'change', '[data-traffic-blacklist-select-all]', (_event, target) => {
        TrafficConfig.toggleSelectAllBlacklist(target.checked);
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'change', '[data-traffic-section-enabled]', (_event, target) => {
        if (!trafficCanMutate()) {
            TrafficConfig.render();
            trafficReadOnlyWarning();
            return;
        }
        TrafficConfig.config.enabled = target.checked;
        TrafficConfig.render();
        SectionUI.markSaveActionBarDirty('data-traffic-action');
    });


    AdminEvents.delegateEvent<HTMLInputElement>(document, 'change', '.section-region-checkbox', (_event, target) => {
        target.parentElement?.classList.toggle('active', target.checked);
    });

    AdminEvents.delegateEvent<HTMLElement>(document, 'click', '.section-select-card', (event, target) => {
        if (event.target instanceof HTMLInputElement) return;
        const checkbox = target.querySelector<HTMLInputElement>('input.section-region-checkbox');
        if (!checkbox) return;
        checkbox.checked = !checkbox.checked;
        target.classList.toggle('active', checkbox.checked);
    });

    AdminEvents.delegateEvent<HTMLInputElement>(document, 'keyup', '.section-input-search', (_event, target) => {
        TrafficConfig.filterGeoModal(target.value);
    });

    // ===== Scrubby dial drag interaction =====
    // Allows user to drag [data-rl-scrubby] elements up/down to change numeric values
    let scrubbyState: {
        el: HTMLElement;
        field: string;
        startY: number;
        startValue: number;
        step: number;
        min: number;
        max: number;
    } | null = null;

    function applyScrubbValue(el: HTMLElement, newValue: number): void {
        const field = el.dataset.rlScrubby;
        if (!field) return;

        // Update display
        const displayEl = trafficDoc().getElementById(`rl-${field}-display`);
        if (displayEl instanceof HTMLInputElement) displayEl.value = String(newValue);
        else if (displayEl) displayEl.textContent = String(newValue);

        // Update aria
        el.setAttribute('aria-valuenow', String(newValue));
        el.dataset.rlValue = String(newValue);

        // Update fill bar — rate fills to 10000 max, burst fills to 5000 max
        const fillMax = field === 'rate' ? 10000 : 5000;
        const fillEl = trafficDoc().getElementById(`rl-${field}-fill`);
        if (fillEl) (fillEl as HTMLElement).style.height = `${Math.min(100, (newValue / fillMax) * 100)}%`;

        // Mirror to hidden input
        const mirrorInput = trafficDoc().querySelector<HTMLInputElement>(`[data-rl-mirror="${field}"]`);
        if (mirrorInput) {
            mirrorInput.value = String(newValue);
        }

        // Update config
        const trafficField = field === 'rate' ? 'default_rate' : 'default_burst';
        TrafficConfig.updateNestedField('rate_limit', trafficField, newValue);
        updatePeakCapacity();

        // Update gauge if rate changed
        if (field === 'rate') {
            updateGauge(newValue);
        }

        // Update summary stats display
        if (field === 'burst') {
            const summaryEl = trafficDoc().getElementById('rl-summary-burst');
            if (summaryEl) summaryEl.textContent = String(newValue);
            const summaryVisual = trafficDoc().getElementById('rl-summary-burst-visual');
            if (summaryVisual) {
                summaryVisual.style.height = `${Math.max(20, Math.min(100, (newValue / 50) * 100))}%`;
            }
        }
    }

    function updatePeakCapacity(): void {
        const rateLimit = TrafficConfig.config.rate_limit || {};
        const rate = Number(rateLimit.default_rate) || 60;
        const burst = Number(rateLimit.default_burst) || 10;
        const peak = rate + burst;
        const scale = Math.max(100, Math.ceil(peak / 100) * 100);
        const baseWidth = Math.min(100, (rate / scale) * 100);
        const burstWidth = Math.min(100 - baseWidth, (burst / scale) * 100);

        const peakValue = trafficDoc().getElementById('rl-summary-peak');
        if (peakValue) peakValue.textContent = formatTrafficNumber(peak);

        const baseVisual = trafficDoc().getElementById('rl-summary-peak-base');
        if (baseVisual) baseVisual.style.width = `${baseWidth}%`;

        const burstVisual = trafficDoc().getElementById('rl-summary-peak-burst');
        if (burstVisual) burstVisual.style.width = `${burstWidth}%`;

        const scaleLabel = trafficDoc().getElementById('rl-summary-peak-scale');
        if (scaleLabel) scaleLabel.textContent = `${formatTrafficNumber(scale)} requests`;
    }

    function updateGauge(rateVal: number): void {
        // Read window from the checked radio button in the DOM first, then fallback to config
        const winRadio = trafficDoc().querySelector<HTMLInputElement>('input[name="rl_window"]:checked');
        const win = winRadio?.value || (TrafficConfig.config.rate_limit || {}).window || '1s';
        const windowSec: number = win === '1s' ? 1 : win === '1h' ? 3600 : 60;
        const rps = rateVal / windowSec;
        const rpsDisplay = rps >= 1 ? rps.toFixed(0) : rps.toFixed(2);
        const gaugeValue = trafficDoc().getElementById('rl-gauge-value');
        if (gaugeValue) gaugeValue.textContent = rpsDisplay;
        const gaugeFill = trafficDoc().getElementById('rl-gauge-fill') as SVGPathElement | null;
        if (gaugeFill) {
            // Scale: full arc = 10x current rate (so moving the dial is visually dramatic)
            const fullScale = Math.max(rateVal * 2, 10);
            const pct = Math.min(1, rps / (fullScale / windowSec));
            gaugeFill.setAttribute('stroke-dashoffset', String(188.5 - pct * 188.5));
        }
    }

    AdminEvents.delegateEvent<HTMLElement>(document, 'mousedown', '[data-rl-scrubby]', (event, target) => {
        if ((event.target as Element | null)?.closest('.rl-scrubby-value')) return;
        event.preventDefault();
        const field = target.dataset.rlScrubby;
        if (!field) return;
        const startValue = Number.parseInt(target.dataset.rlValue || '0', 10);
        const step = Number.parseInt(target.dataset.rlStep || '1', 10);
        const min = Number.parseInt(target.dataset.rlMin || '0', 10);
        const max = Number.parseInt(target.dataset.rlMax || '100000', 10);
        scrubbyState = { el: target, field, startY: (event as MouseEvent).clientY, startValue, step, min, max };
        target.classList.add('is-dragging');
        trafficDoc().body.style.cursor = 'ns-resize';
    });

    trafficDoc().addEventListener('mousemove', (event: Event) => {
        if (!scrubbyState) return;
        const me = event as MouseEvent;
        const dy = scrubbyState.startY - me.clientY; // drag up = positive
        const steps = Math.round(dy / 4); // 4px per step
        const raw = scrubbyState.startValue + steps * scrubbyState.step;
        const clamped = Math.min(scrubbyState.max, Math.max(scrubbyState.min, raw));
        applyScrubbValue(scrubbyState.el, clamped);
    });

    trafficDoc().addEventListener('mouseup', () => {
        if (!scrubbyState) return;
        scrubbyState.el.classList.remove('is-dragging');
        trafficDoc().body.style.cursor = '';
        scrubbyState = null;
    });

    // Keyboard support for scrubby dials
    AdminEvents.delegateEvent<HTMLElement>(document, 'keydown', '[data-rl-scrubby]', (event, target) => {
        const ke = event as KeyboardEvent;
        if (!['ArrowUp', 'ArrowDown', 'PageUp', 'PageDown'].includes(ke.key)) return;
        ke.preventDefault();
        const field = target.dataset.rlScrubby;
        if (!field) return;
        const current = Number.parseInt(target.dataset.rlValue || '0', 10);
        const step = Number.parseInt(target.dataset.rlStep || '1', 10);
        const min = Number.parseInt(target.dataset.rlMin || '0', 10);
        const max = Number.parseInt(target.dataset.rlMax || '100000', 10);
        let delta = 0;
        if (ke.key === 'ArrowUp') delta = step;
        else if (ke.key === 'ArrowDown') delta = -step;
        else if (ke.key === 'PageUp') delta = step * 10;
        else if (ke.key === 'PageDown') delta = -step * 10;
        const clamped = Math.min(max, Math.max(min, current + delta));
        applyScrubbValue(target, clamped);
    });

    // Inline input sync back to scrubby dial
    AdminEvents.delegateEvent<HTMLInputElement>(document, 'input', '[data-rl-mirror]', (_event, target) => {
        const field = target.dataset.rlMirror;
        if (!field) return;
        const val = Number.parseInt(target.value, 10);
        if (!Number.isFinite(val)) return;
        const dialEl = trafficDoc().querySelector<HTMLElement>(`[data-rl-scrubby="${field}"]`);
        if (dialEl) applyScrubbValue(dialEl, val);
    });

    // Segmented window picker — update gauge on change
    AdminEvents.delegateEvent<HTMLInputElement>(document, 'change', '[data-rl-window]', (_event, _target) => {
        const rateVal = Number.parseInt((TrafficConfig.config.rate_limit || {}).default_rate as unknown as string || '60', 10);
        updateGauge(rateVal);
    });
}

const TrafficConfig: TrafficConfigRuntime = {
    currentTab: 'overview',
    config: {} as TrafficControlState,
    stats: { total_requests: 0, blocked_requests: 0, in_flight_requests: 0 } as TrafficStats,
    geoStatus: null,
    capabilities: null,
	operations: null,
    blacklistPagination: { page: 1, pageSize: 10, search: '' },
    threatFeedPage: false,
    threatFeedData: null as UnifiedThreatFeedData | null,
    threatFeedPagination: { page: 1, pageSize: 25, search: '', sourceFilter: 'all' } as ThreatFeedPaginationState,
    pendingTarget: null,
    pendingVipTarget: null,
    rateLimitView: 'table',
    editingRateRuleIndex: null,
    rateEngineSettingsOpen: false,
    map: null,

    // Country Mapping (ISO Alpha-2)
    // Country Mapping (ISO Alpha-2) - Full List
    countries: {
        "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AS": "American Samoa", "AD": "Andorra", "AO": "Angola", "AI": "Anguilla", "AQ": "Antarctica", "AG": "Antigua and Barbuda", "AR": "Argentina", "AM": "Armenia", "AW": "Aruba", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan",
        "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize", "BJ": "Benin", "BM": "Bermuda", "BT": "Bhutan", "BO": "Bolivia", "BA": "Bosnia and Herzegovina", "BW": "Botswana", "BV": "Bouvet Island", "BR": "Brazil", "IO": "British Indian Ocean Territory", "BN": "Brunei Darussalam", "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi",
        "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada", "CV": "Cape Verde", "KY": "Cayman Islands", "CF": "Central African Republic", "TD": "Chad", "CL": "Chile", "CN": "China", "CX": "Christmas Island", "CC": "Cocos (Keeling) Islands", "CO": "Colombia", "KM": "Comoros", "CG": "Congo", "CD": "Congo, Democratic Republic", "CK": "Cook Islands", "CR": "Costa Rica", "CI": "Cote D'Ivoire", "HR": "Croatia", "CU": "Cuba", "CY": "Cyprus", "CZ": "Czech Republic",
        "DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica", "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea", "ER": "Eritrea", "EE": "Estonia", "ET": "Ethiopia", "FK": "Falkland Islands", "FO": "Faroe Islands", "FJ": "Fiji", "FI": "Finland", "FR": "France", "GF": "French Guiana", "PF": "French Polynesia", "TF": "French Southern Territories",
        "GA": "Gabon", "GM": "Gambia", "GE": "Georgia", "DE": "Germany", "GH": "Ghana", "GI": "Gibraltar", "GR": "Greece", "GL": "Greenland", "GD": "Grenada", "GP": "Guadeloupe", "GU": "Guam", "GT": "Guatemala", "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana", "HT": "Haiti", "HM": "Heard Island and Mcdonald Islands", "VA": "Holy See (Vatican City State)", "HN": "Honduras", "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland", "IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq", "IE": "Ireland", "IL": "Israel", "IT": "Italy",
        "JM": "Jamaica", "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya", "KI": "Kiribati", "KP": "Korea, North", "KR": "Korea, South", "KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Lao People's Democratic Republic", "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia", "LY": "Libyan Arab Jamahiriya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg",
        "MO": "Macao", "MK": "Macedonia", "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia", "MV": "Maldives", "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands", "MQ": "Martinique", "MR": "Mauritania", "MU": "Mauritius", "YT": "Mayotte", "MX": "Mexico", "FM": "Micronesia", "MD": "Moldova", "MC": "Monaco", "MN": "Mongolia", "MS": "Montserrat", "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar",
        "NA": "Namibia", "NR": "Nauru", "NP": "Nepal", "NL": "Netherlands", "AN": "Netherlands Antilles", "NC": "New Caledonia", "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria", "NU": "Niue", "NF": "Norfolk Island", "MP": "Northern Mariana Islands", "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PW": "Palau", "PS": "Palestinian Territory", "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru", "PH": "Philippines", "PN": "Pitcairn", "PL": "Poland", "PT": "Portugal", "PR": "Puerto Rico",
        "QA": "Qatar", "RE": "Reunion", "RO": "Romania", "RU": "Russia", "RW": "Rwanda", "SH": "Saint Helena", "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia", "PM": "Saint Pierre and Miquelon", "VC": "Saint Vincent and the Grenadines", "WS": "Samoa", "SM": "San Marino", "ST": "Sao Tome and Principe", "SA": "Saudi Arabia", "SN": "Senegal", "CS": "Serbia and Montenegro", "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa", "GS": "South Georgia and the South Sandwich Islands", "ES": "Spain", "LK": "Sri Lanka", "SD": "Sudan", "SR": "Suriname", "SJ": "Svalbard and Jan Mayen", "SZ": "Swaziland", "SE": "Sweden", "CH": "Switzerland", "SY": "Syria",
        "TW": "Taiwan", "TJ": "Tajikistan", "TZ": "Tanzania", "TH": "Thailand", "TL": "Timor-Leste", "TG": "Togo", "TK": "Tokelau", "TO": "Tonga", "TT": "Trinidad and Tobago", "TN": "Tunisia", "TR": "Turkey", "TM": "Turkmenistan", "TC": "Turks and Caicos Islands", "TV": "Tuvalu", "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States", "UM": "United States Minor Outlying Islands", "UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu", "VE": "Venezuela", "VN": "Vietnam", "VG": "Virgin Islands, British", "VI": "Virgin Islands, U.S.",
        "WF": "Wallis and Futuna", "EH": "Western Sahara", "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe"
    },

    // Region Definitions matching backend
    regions: {
        "EU": "European Union",
        "EEA": "European Economic Area",
        "SCHENGEN": "Schengen Area",
        "BENELUX": "Benelux",
        "DACH": "Germany, Austria & Switzerland",
        "NORDICS": "Nordic Countries",
        "USMCA": "United States, Mexico & Canada",
        "FIVE_EYES": "Five Eyes",
        "ASEAN": "ASEAN",
        "GCC": "Gulf Cooperation Council",
        "G7": "Group of Seven",
        "APAC": "Asia-Pacific",
        "LATAM": "Latin America",
        "MENA": "Middle East & North Africa",
        "AFRICA": "Africa",
        "CIS": "CIS (Former Soviet)"
    },

    // Region to Country Mapping (for Map Highlighting)
    regionMembers: {
        "EU": ["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"],
        "EEA": ["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO"],
        "SCHENGEN": ["AT", "BE", "BG", "HR", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IS", "IT", "LV", "LI", "LT", "LU", "MT", "NL", "NO", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "CH"],
        "BENELUX": ["BE", "NL", "LU"],
        "DACH": ["DE", "AT", "CH"],
        "NORDICS": ["DK", "FI", "IS", "NO", "SE"],
        "USMCA": ["US", "CA", "MX"],
        "FIVE_EYES": ["AU", "CA", "NZ", "GB", "US"],
        "ASEAN": ["BN", "KH", "ID", "LA", "MY", "MM", "PH", "SG", "TH", "VN"],
        "GCC": ["BH", "KW", "OM", "QA", "SA", "AE"],
        "G7": ["CA", "FR", "DE", "IT", "JP", "GB", "US"],
        "APAC": ["AU", "BD", "BN", "KH", "CN", "HK", "IN", "ID", "JP", "KP", "KR", "LA", "MY", "MV", "MN", "MM", "NP", "NZ", "PK", "PH", "SG", "LK", "TW", "TH", "TL", "VN"],
        "LATAM": ["AR", "BO", "BR", "CL", "CO", "CR", "CU", "DO", "EC", "SV", "GT", "HN", "MX", "NI", "PA", "PY", "PE", "UY", "VE"],
        "MENA": ["DZ", "BH", "EG", "IQ", "IL", "JO", "KW", "LB", "LY", "MA", "OM", "PS", "QA", "SA", "SY", "TN", "AE", "YE"],
        "AFRICA": ["AO", "BJ", "BW", "BF", "BI", "CM", "CV", "CF", "TD", "KM", "CG", "CD", "CI", "DJ", "GQ", "ER", "ET", "GA", "GM", "GH", "GN", "GW", "KE", "LS", "LR", "MG", "MW", "ML", "MR", "MU", "MZ", "NA", "NE", "NG", "RW", "ST", "SN", "SC", "SL", "SO", "ZA", "SS", "SD", "SZ", "TZ", "TG", "UG", "ZM", "ZW"],
        "CIS": ["RU", "BY", "KZ", "KG", "TJ", "TM", "UZ", "AM", "AZ", "GE", "MD", "UA"]
    },

    tabs: [
        { id: 'overview', name: 'Overview', icon: 'activity' },
        { id: 'blacklist', name: 'IP Blacklist', icon: 'ban' },
        { id: 'reputation', name: 'IP Reputation', icon: 'database' },
        { id: 'ratelimit', name: 'Rate Limiting', icon: 'clock' },
        { id: 'geo', name: 'Geo-Blocking', icon: 'globe' },
        { id: 'ddos', name: 'Application Flood', icon: 'shield' },
        { id: 'priority', name: 'Trusted Exceptions', icon: 'star' }
    ],

    icons: {
        activity: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
        ban: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',
        database: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
        clock: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
        globe: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1 4-10z"/></svg>',
        shield: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        star: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>',
        sliders: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>',
        zap: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
        info: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        check: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>'
    },

    async init(): Promise<void> {
        ensureTrafficBindings();
        if (this.config && Object.keys(this.config).length > 0) {
            this.render();
            void Promise.all([this.loadConfig(), this.loadCapabilities(), this.loadStats(), this.loadGeoStatus(), this.loadOperations()]).then(() => this.render());
            return;
        }
        await this.loadConfig();
        await this.loadCapabilities();
		await Promise.all([this.loadStats(), this.loadGeoStatus(), this.loadOperations()]);
        this.render();
    },

    async loadConfig(): Promise<void> {
        try {
            const data = await api.get<TrafficControlState>('sections/traffic_control/config');
            if (data) {
                this.config = normalizeTrafficConfigForUI(data);
                if (!this.config.blacklist) this.config.blacklist = { enabled: true, ips: [] };
            } else {
                throw new Error('Failed to load');
            }
        } catch (err) {
            console.error('Config load error', err);
            showSectionToast('Failed to load configuration', 'error');
			throw err;
        }
    },

    async loadStats(): Promise<void> {
        try {
            const data = await api.get<TrafficStats>('sections/traffic_control/stats');
            if (data) this.stats = data;
        } catch (e) { console.error('Failed to load stats:', e); }
    },

    async loadGeoStatus(): Promise<void> {
        try {
            const data = await api.get<TrafficGeoStatus>('sections/traffic_control/geo/status');
            this.geoStatus = data || null;
        } catch (e) {
            console.error('Failed to load geo status:', e);
            this.geoStatus = null;
        }
    },

    async loadCapabilities(): Promise<void> {
        try {
            this.capabilities = await api.get<TrafficCapabilities>('sections/traffic_control/capabilities');
        } catch (error) {
            console.error('Traffic capabilities load error', error);
            this.capabilities = null;
        }
    },

	async loadOperations(): Promise<void> {
		try {
			this.operations = await api.get<TrafficOperationsStatus>('sections/traffic_control/operations');
		} catch (error) {
			console.error('Traffic operations load error', error);
			this.operations = null;
		}
	},

    buildMergedThreatFeedData(): UnifiedThreatFeedData {
        const indicators = this.threatFeedData?.indicators || [];
        const rep = this.config?.reputation as TrafficReputationConfig | undefined;
        const cti = rep?.cti;
        const ctiEnabled = cti ? cti.enabled !== false : true;
        const ctiUrl = cti?.url || 'http://localhost:8090';
        return {
            status: this.threatFeedData?.status || 'ok',
            total_indicators: this.threatFeedData?.total_indicators ?? indicators.length,
            sources: {
                cti: {
                    enabled: ctiEnabled,
                    url: ctiUrl,
                    entry_count: indicators.length,
                    status: this.threatFeedData?.sources?.cti?.status
                }
            },
            indicators
        };
    },

    async loadThreatFeed(): Promise<void> {
        const rep = this.config?.reputation as TrafficReputationConfig | undefined;
        const cti = rep?.cti;
        const ctiEnabled = cti ? cti.enabled !== false : true;
        const ctiUrl = cti?.url || 'http://localhost:8090';
        try {
            const resp = await fetch('/api/sections/traffic_control/reputation/feed', {
                headers: { Accept: 'application/json' }
            });
            if (resp.ok) {
                const data = await resp.json() as UnifiedThreatFeedData;
                if (data) {
                    this.threatFeedData = data;
                    return;
                }
            }
            this.threatFeedData = {
                status: 'ok',
                total_indicators: 0,
                sources: {
                    cti: {
                        enabled: ctiEnabled,
                        url: ctiUrl,
                        entry_count: 0
                    }
                },
                indicators: []
            };
        } catch (e) {
            console.warn('Threat feed endpoint unavailable:', e);
            this.threatFeedData = {
                status: 'ok',
                total_indicators: 0,
                sources: {
                    cti: {
                        enabled: ctiEnabled,
                        url: ctiUrl,
                        entry_count: 0
                    }
                },
                indicators: []
            };
        }
    },

    async refreshThreatFeed(): Promise<void> {
        const btn = trafficQuery<HTMLButtonElement>('[data-traffic-action="refresh-threat-feed"]');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Refreshing...';
        }
        try {
            const data = await api.post<UnifiedThreatFeedData>('sections/traffic_control/reputation/feed/refresh', {});
            if (data) {
                this.threatFeedData = data;
                showSectionToast('Threat intelligence feeds synchronized', 'success');
            } else {
                await this.loadThreatFeed();
                showSectionToast('Threat feeds refreshed', 'info');
            }
            this.render();
        } catch (e) {
            console.error('Failed to refresh threat feed:', e);
            await this.loadThreatFeed();
            this.render();
            showSectionToast('Failed to refresh threat feeds', 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Refresh all feeds';
            }
        }
    },



    render(): void {
        const container = trafficElementById('traffic-config-content');
        if (!container) return;

        const capability = (id: string, sessionFeature: string): boolean => {
            const reported = this.capabilities?.features?.[id]?.available;
            return typeof reported === 'boolean' ? reported && api.hasFeature(sessionFeature) : api.hasFeature(sessionFeature);
        };
        const hasGeo        = capability('geo', FEATURES.TRAFFIC_GEO);
        const hasDDoS       = capability('application_flood', FEATURES.TRAFFIC_APPLICATION_FLOOD);
        const hasPriority   = capability('trusted_exceptions', FEATURES.TRAFFIC_TRUSTED_EXCEPTIONS);
        const hasReputation = capability('reputation', FEATURES.TRAFFIC_REPUTATION);
		const readOnlyNotice = trafficCanMutate()
			? ''
			: `<div class="section-warning-box" data-traffic-read-only-notice="true" role="status"><div><strong>Read-only Traffic Control access</strong><p>Inspect runtime status. Policy changes require the traffic:admin permission.</p></div></div>`;

        const visibleTabs = this.tabs.filter(tab =>
            (tab.id !== 'geo'        || hasGeo        || this.currentTab === 'geo')        &&
            (tab.id !== 'ddos'       || hasDDoS       || this.currentTab === 'ddos')       &&
            (tab.id !== 'priority'   || hasPriority   || this.currentTab === 'priority')   &&
            (tab.id !== 'reputation' || hasReputation || this.currentTab === 'reputation')
        );

        // If current tab was hidden, reset to first visible
        if (!visibleTabs.find(t => t.id === this.currentTab)) {
            this.currentTab = (visibleTabs[0]?.id ?? 'overview') as TrafficTabId;
        }

        interface TrafficConsoleMeta {
            title: string;
            kicker: string;
            subtitle: string;
            actions?: string;
        }

        const trafficSwitch = SectionUI.renderSwitch({
            checked: this.config.enabled === true,
            attrs: 'title="Enable or disable Traffic Control" data-traffic-section-enabled="true" aria-label="Enable Traffic Control"'
        });

        const consoleMetaMap: Record<TrafficTabId, TrafficConsoleMeta> = {
            overview: {
                title: 'Overview',
                kicker: 'Traffic Control',
                subtitle: 'Real-time traffic admission, active connections, in-flight requests, and edge engine readiness.',
                actions: trafficSwitch
            },
            ddos: {
                title: 'Application Flood',
                kicker: 'Traffic Control',
                subtitle: 'Automated Layer 7 application flood defense, HTTP flood mitigations, and adaptive burst multipliers.'
            },
            ratelimit: this.rateLimitView === 'editor'
                ? {
                    title: this.editingRateRuleIndex !== null ? 'Edit Rate Limit Rule' : 'New Rate Limit Rule',
                    kicker: 'Traffic Control',
                    subtitle: this.editingRateRuleIndex !== null
                        ? 'Update endpoint match criteria, request quotas, burst capacity, and enforcement behavior.'
                        : 'Configure endpoint match criteria, request capacity thresholds, and rate-limiting enforcement for this route.',
                    actions: `
                        <div style="display:flex;align-items:center;gap:8px;">
                            <button type="button" class="operator-btn operator-btn-secondary" data-traffic-action="cancel-rate-rule-editor">
                                Cancel
                            </button>
                            <button type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-rate-rule">
                                ${this.editingRateRuleIndex !== null ? 'Update Rule' : 'Save Rule'}
                            </button>
                        </div>
                    `
                }
                : {
                    title: 'Rate Limiting',
                    kicker: 'Traffic Control',
                    subtitle: 'Enforce route-specific request quotas, burst headroom, and mitigation policies per endpoint.',
                    actions: `
                        <button type="button" class="operator-btn operator-btn-primary" data-traffic-action="open-add-rate-rule">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                            <span>Add Rate Limit Rule</span>
                        </button>
                    `
                },
            blacklist: {
                title: 'IP Blacklist',
                kicker: 'Traffic Control',
                subtitle: 'Edge admission control using CIDR IP blacklists and whitelist exemptions.'
            },
            geo: {
                title: 'Geo-Blocking',
                kicker: 'Traffic Control',
                subtitle: 'Enforce geographic access restrictions, ISO country policies, continent-level traffic rules, and interactive map enforcement.'
            },
            reputation: {
                title: 'IP Reputation',
                kicker: 'Traffic Control',
                subtitle: 'Client IP reputation scoring, automated CTI threat feeds, Tor exit node detection, and sensitivity tuning.',
                actions: `
                    <label class="section-switch">
                        <input type="checkbox" ${this.config?.reputation?.enabled !== false ? 'checked' : ''} data-traffic-parent="reputation" data-traffic-field="enabled" data-traffic-value-type="checkbox" data-traffic-render="true" aria-label="Enable IP Reputation Engine">
                        <span class="switch-slider"></span>
                    </label>
                `
            },
            priority: {
                title: 'Trusted Exceptions',
                kicker: 'Traffic Control',
                subtitle: 'Bypass rate limits and security controls for verified infrastructure, partners, and internal systems.'
            }
        };

        const activeConsole = consoleMetaMap[this.currentTab] || consoleMetaMap.overview;

        container.innerHTML = SectionUI.renderOperatorFrame({
            title: activeConsole.title,
            kicker: activeConsole.kicker,
            subtitle: activeConsole.subtitle,
            actions: activeConsole.actions,
            tabs: [],
            content: `
				${readOnlyNotice}
                <div id="traffic-tab-content">${this.renderTabContent()}</div>
                <div id="modal-container"></div>
            `,
            className: 'flow-operator-frame'
        });
		applyTrafficPermissionState(container);
    },

    switchTab(id: TrafficTabId): void {
        if (id === 'reputation' && (!api.hasFeature(FEATURES.TRAFFIC_REPUTATION) || this.capabilities?.features?.reputation?.available === false)) {
            id = 'overview';
        } else if (id === 'ddos' && (!api.hasFeature(FEATURES.TRAFFIC_APPLICATION_FLOOD) || this.capabilities?.features?.application_flood?.available === false)) {
            id = 'overview';
        } else if (id === 'priority' && (!api.hasFeature(FEATURES.TRAFFIC_TRUSTED_EXCEPTIONS) || this.capabilities?.features?.trusted_exceptions?.available === false)) {
            id = 'overview';
        } else if (id === 'geo' && (!api.hasFeature(FEATURES.TRAFFIC_GEO) || this.capabilities?.features?.geo?.available === false)) {
            id = 'overview';
        }
        this.currentTab = id;
        this.threatFeedPage = false;
        this.rateLimitView = 'table';
        this.editingRateRuleIndex = null;
        this.render();

        const targetMap: Record<string, string> = {
            overview: 'traffic_config',
            ddos: 'ddos_config',
            ratelimit: 'ratelimit_config',
            blacklist: 'traffic_access_geo',
            reputation: 'threat_intel',
            geo: 'traffic_geo',
            priority: 'traffic_priority'
        };
        const activeNavTarget = targetMap[id];
        if (activeNavTarget) {
            AdminDOM.queryAll<HTMLElement>('.nav-link').forEach(el => el.classList.remove('active'));
            const matchedLink = AdminDOM.query<HTMLElement>(`.nav-link[data-nav-target="${activeNavTarget}"]`);
            if (matchedLink) matchedLink.classList.add('active');
        }
    },

    renderTabContent(): string {
        switch (this.currentTab) {
            case 'overview':    return this.renderOverview();
            case 'blacklist':   return this.renderBlacklist();
            case 'reputation':  return this.capabilities?.features?.reputation?.available !== false && api.hasFeature(FEATURES.TRAFFIC_REPUTATION)
                ? this.renderReputation()
                : renderUpgradeBanner('professional', 'IP Reputation');
            case 'ratelimit':   return this.renderRateLimit();
            case 'geo':         return this.capabilities?.features?.geo?.available !== false && api.hasFeature(FEATURES.TRAFFIC_GEO)
                ? this.renderGeo()
                : renderUpgradeBanner('professional', 'Geo-Blocking');
            case 'ddos':        return this.capabilities?.features?.application_flood?.available !== false && api.hasFeature(FEATURES.TRAFFIC_APPLICATION_FLOOD)
                ? this.renderDDoS()
                : renderUpgradeBanner('professional', 'Application Flood Protection');
            case 'priority':    return this.capabilities?.features?.trusted_exceptions?.available !== false && api.hasFeature(FEATURES.TRAFFIC_TRUSTED_EXCEPTIONS)
                ? this.renderPriority()
                : renderUpgradeBanner('professional', 'Trusted Exceptions');
            default: return '';
        }
    },

    // ========== OVERVIEW ==========
    renderOverview(): string {
        // Safe access to config objects
        const ddos = this.config.ddos || {};
        const ratelimit = this.config.rate_limit || {};
        const geo = this.config.geo || {};
        const reputation = this.config.reputation || {};
        const blacklist = this.config.blacklist || {};
		const trustedExceptions = this.config.trusted_exceptions || [];

        const hasGeo = this.capabilities?.features?.geo?.available !== false && api.hasFeature(FEATURES.TRAFFIC_GEO);
        const hasDDoS = this.capabilities?.features?.application_flood?.available !== false && api.hasFeature(FEATURES.TRAFFIC_APPLICATION_FLOOD);
        const hasPriority = this.capabilities?.features?.trusted_exceptions?.available !== false && api.hasFeature(FEATURES.TRAFFIC_TRUSTED_EXCEPTIONS);
        const hasReputation = this.capabilities?.features?.reputation?.available !== false && api.hasFeature(FEATURES.TRAFFIC_REPUTATION);

        // Calculate active modules count (only entitled modules)
        const modules = [
            blacklist,
            ratelimit,
            ...(hasDDoS ? [ddos] : []),
            ...(hasGeo ? [geo] : []),
            ...(hasReputation ? [reputation] : [])
        ];
        const activeCount = modules.filter(m => m && m.enabled !== false).length;
        const totalCount = modules.length;
        const healthPercent = totalCount > 0 ? Math.round((activeCount / totalCount) * 100) : 0;

        return `
            <div class="flow-operator-stack">
				${SectionUI.renderOperatorSection('Protection statistics', SectionUI.renderOperatorMetricStrip([
                    { label: 'Modules', value: `${activeCount}/${totalCount}`, sub: hasPriority ? `${trustedExceptions.length} scoped exceptions` : `${activeCount} of ${totalCount} active`, tone: 'neutral' },
                    { label: 'Rate Limit', value: `${ratelimit.default_rate || 60}`, sub: `req/${ratelimit.window || '1s'}`, tone: 'neutral' },
                    { label: 'In-flight requests', value: formatTrafficNumber(this.stats?.in_flight_requests ?? this.stats?.custom?.in_flight_requests ?? 0), sub: 'HTTP requests now', tone: 'neutral' },
                    { label: 'Coverage', value: `${healthPercent}%`, sub: 'Traffic posture', tone: 'neutral' }
                ]), {
                    subtitle: 'Coverage and live traffic limits across traffic protection modules.'
                })}

                ${SectionUI.renderOperatorSection('Protection modules', `
                    <div class="operator-control-list">
                        ${this.renderWAFStyleModuleCard('blacklist', 'IP Blacklist', 'Blocked IP addresses and CIDR ranges at the edge', blacklist, 'ban')}
                        ${this.renderWAFStyleModuleCard('ratelimit', 'Rate Limiting', 'Request throttling and request shape controls', ratelimit, 'clock')}
                        ${hasDDoS ? this.renderWAFStyleModuleCard('ddos', 'Application Flood Protection', 'HTTP flood thresholds, in-flight requests, and verification grace', ddos, 'shield') : ''}
                        ${hasGeo ? this.renderWAFStyleModuleCard('geo', 'Geo-Blocking', 'Country and region based access control', geo, 'globe') : ''}
                        ${hasReputation ? this.renderWAFStyleModuleCard('reputation', 'IP Reputation Policy', 'Evaluate client trust using local intelligence and threat feeds', reputation, 'database') : ''}
                        ${hasPriority ? this.renderWAFStyleModuleCard('priority', 'Trusted Exceptions', 'Least-privilege rate and flood exceptions', { enabled: trustedExceptions.length > 0 }, 'star') : ''}
                    </div>
                `, {
					subtitle: 'Open a module to tune its protection behavior.'
				})}
            </div>
            ${renderTrafficSaveButtons()}
        `;
    },

    renderOverviewMetricCard(label: string, value: unknown, unit: string, tone: string): string {
        const safeValue = typeof value === 'number' ? value.toLocaleString() : String(value ?? '');
        const unitMarkup = unit ? `<span class="section-metric-unit">${unit}</span>` : '';
        return `
            <div class="section-overview-stat ${tone}">
                <div class="section-overview-stat-value">${safeValue}${unitMarkup}</div>
                <div class="section-overview-stat-label">${label}</div>
            </div>
        `;
    },

    renderSectionHeader(_icon: string, _title: string, _desc: string, _toggleField: string | null = null, _toggleValue = false): string {
        return '';
    },

    renderModuleStatusCard(_title: string, _description: string, _icon: string, _configKey: string): string {
        return '';
    },

    renderWAFStyleModuleCard(key: string, title: string, subtitle: string, cfg: { enabled?: boolean } | undefined, icon: string): string {
        const isActive = cfg ? (cfg.enabled !== false) : false;
        return SectionUI.renderOperatorControlRow({
            title,
            description: subtitle,
            icon: this.icons[icon] || SectionUI.icons[icon as keyof typeof SectionUI.icons] || SectionUI.icons.shield,
            enabled: isActive,
            actions: SectionUI.icons.arrowRight,
            className: 'flow-module-row',
            attrs: `role="button" tabindex="0" data-traffic-action="switch-tab" data-traffic-tab="${key}" aria-label="Configure ${escapeTrafficAttr(title)}"`
        });
    },

    toggleProtection(key: string): void {
        const current = this.config[key];
        if (typeof current !== 'object' || current === null || Array.isArray(current)) {
            this.config[key] = { enabled: true };
        } else {
            const section = current as { enabled?: boolean };
            section.enabled = !section.enabled;
        }
        this.render();
        SectionUI.markSaveActionBarDirty('data-traffic-action');
    },

    // ========== BLACKLIST ==========
    blacklistSelected: new Set(), // Track selected entries for batch operations
    renderBlacklist(): string {
        const pageData = buildTrafficBlacklistPageData(
            this.config.blacklist,
            this.blacklistPagination.search,
            this.blacklistPagination.page,
            this.blacklistPagination.pageSize
        );
        const searchQuery = this.blacklistPagination.search.trim().toLowerCase();
        const totalCount = pageData.totalCount;
        const filteredCount = pageData.filteredCount;
        const totalPages = pageData.totalPages;
        this.blacklistPagination.page = pageData.page;
        const pageSize = this.blacklistPagination.pageSize;
        const pageEntries = pageData.pageEntries;
        const selectedCount = this.blacklistSelected.size;
        const allEntries = getTrafficBlacklistEntries(this.config.blacklist);
        const now = new Date();
        const activeEntries = allEntries.filter(entry => !entry.expires_at || new Date(entry.expires_at) >= now);
        const ipCount = activeEntries.filter(entry => !entry.target.includes('/')).length;
        const cidrCount = activeEntries.filter(entry => entry.target.includes('/')).length;
        const temporaryCount = activeEntries.filter(entry => Boolean(entry.expires_at)).length;

        // Check if all page entries are selected
        const allPageSelected = this.areBlacklistTargetsSelected(this.getBlacklistTargets(pageEntries));

        return `
            <input id="traffic-blacklist-import" type="file" accept=".csv,text/csv" class="hidden" data-traffic-blacklist-import>

            ${this.renderModuleStatusCard('IP Blacklist', 'Manage blocked IP addresses and CIDR ranges. Traffic is dropped at the edge.', 'ban', 'blacklist')}

            <div class="flow-blacklist-console">
                <section class="flow-blacklist-inventory">
                    <div class="flow-blacklist-head">
                        <div>
                            <div class="flow-rate-eyebrow">Block inventory</div>
                            <h3>Blocked targets</h3>
                            <p>Review, search, and maintain the IP addresses and network ranges denied at the edge.</p>
                        </div>
                        <div class="flow-blacklist-head-actions">
                            <button class="operator-btn operator-btn-secondary" type="button" data-traffic-action="open-import-blacklist-csv">
                                <span aria-hidden="true">↓</span> Import CSV
                            </button>
                            <button class="operator-btn operator-btn-primary" type="button" data-traffic-action="open-add-ip-modal">
                                <span aria-hidden="true">+</span> Add entry
                            </button>
                        </div>
                    </div>

                    ${selectedCount > 0 ? `
                        <div class="flow-blacklist-selection" role="status">
                            <span><strong>${selectedCount}</strong> ${selectedCount === 1 ? 'target' : 'targets'} selected</span>
                            <div>
                                <button class="operator-btn operator-btn-secondary btn-xs" type="button"
                                    data-traffic-action="clear-blacklist-selection">Clear selection</button>
                                <button class="operator-btn operator-btn-danger btn-xs" type="button"
                                    data-traffic-action="delete-selected-blacklist">Delete selected</button>
                            </div>
                        </div>
                    ` : ''}

                    <div class="flow-blacklist-toolbar">
                        <div class="flow-blacklist-count">
                            <strong>${searchQuery ? filteredCount : totalCount}</strong>
                            <span>${searchQuery ? `matching ${filteredCount === 1 ? 'entry' : 'entries'} of ${totalCount}` : totalCount === 1 ? 'entry' : 'entries'}</span>
                        </div>
                        <div class="flow-blacklist-tools">
                            <label class="flow-blacklist-search">
                                <span aria-hidden="true">
                                    <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>
                                </span>
                                <input type="search" class="flow-search-input"
                                    aria-label="Search blocked targets"
                                    placeholder="Search IP or CIDR"
                                    value="${escapeTrafficAttr(this.blacklistPagination.search)}"
                                    data-traffic-pagination-search="true">
                            </label>
                            <select class="flow-page-size-select"
                                    aria-label="Entries per page"
                                    data-traffic-parent="blacklistPagination" data-traffic-field="pageSize" data-traffic-value-type="number">
                                <option value="10" ${pageSize === 10 ? 'selected' : ''}>10 rows</option>
                                <option value="25" ${pageSize === 25 ? 'selected' : ''}>25 rows</option>
                                <option value="100" ${pageSize === 100 ? 'selected' : ''}>100 rows</option>
                            </select>
                        </div>
                    </div>

                    <div class="flow-blacklist-table-wrap">
                        <table class="flow-blacklist-table">
                            <thead>
                                <tr>
                                    <th class="flow-check-cell">
                                        <input type="checkbox" ${allPageSelected ? 'checked' : ''}
                                            data-traffic-blacklist-select-all="true" title="Select all on page"
                                            aria-label="Select all visible targets">
                                    </th>
                                    <th>Target</th>
                                    <th>Type</th>
                                    <th>Expiration</th>
                                    <th class="flow-blacklist-actions-head">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="blacklist-table-body">
                                ${pageEntries.length ? pageEntries.map(entry => {
            const isCidr = entry.target.includes('/');
            const expiresAt = entry.expires_at ? new Date(entry.expires_at) : null;
            const isExpired = Boolean(expiresAt && expiresAt < now);
            const expiresLabel = expiresAt
                ? expiresAt.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
                : 'Permanent';
            const isSelected = this.blacklistSelected.has(entry.target);
            const safeTarget = escapeTrafficHtml(entry.target);

            return `
                                    <tr class="section-blacklist-row ${isExpired ? 'is-expired' : ''} ${isSelected ? 'is-selected' : ''}">
                                    <td class="flow-check-cell">
                                        <input type="checkbox" ${isSelected ? 'checked' : ''}
                                            data-traffic-blacklist-select="${encodeTrafficValue(entry.target)}"
                                            aria-label="Select ${escapeTrafficAttr(entry.target)}">
                                    </td>
                                    <td>
                                        <div class="flow-target-cell">
                                            <span class="flow-target-icon ${isExpired ? 'is-muted' : ''}">${this.icons.ban}</span>
                                            <div class="flow-target-copy">
                                                <span class="flow-target-value">${safeTarget}</span>
                                                <small>${isCidr ? 'Network range' : 'Single address'}</small>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="tag-pill flow-type-pill">
                                            ${isCidr ? 'CIDR' : 'IP'}
                                        </span>
                                    </td>
                                    <td>
                                        <span class="flow-expiry-pill ${isExpired ? 'is-expired' : ''}">
                                            ${isExpired ? 'EXPIRED' : expiresLabel}
                                        </span>
                                    </td>
                                    <td class="flow-blacklist-actions">
                                        <div class="flow-blacklist-row-actions">
                                            <button class="flow-blacklist-row-action" type="button"
                                                data-traffic-action="open-add-ip-modal"
                                                data-traffic-value="${encodeTrafficValue(entry.target)}">Edit</button>
                                            <button class="flow-blacklist-row-action is-danger" type="button"
                                                data-traffic-action="remove-ip"
                                                data-traffic-value="${encodeTrafficValue(entry.target)}">Delete</button>
                                        </div>
                                    </td>
                                </tr>`;
        }).join('') : `
                                    <tr>
                                    <td colspan="5">
                                        <div class="flow-blacklist-empty">
                                            <span class="flow-blacklist-empty-icon">
                                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                                <circle cx="12" cy="12" r="10"/>
                                                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                                                </svg>
                                            </span>
                                            <strong>${searchQuery ? 'No matching targets' : 'No blocks active'}</strong>
                                            <span>${searchQuery ? 'Try a different IP address or network range.' : 'Add an IP address or CIDR range to deny traffic at the edge.'}</span>
                                            ${searchQuery ? '' : `
                                                <button class="operator-btn operator-btn-primary" type="button" data-traffic-action="open-add-ip-modal">
                                                    <span aria-hidden="true">+</span> Add first entry
                                                </button>
                                            `}
                                        </div>
                                    </td>
                                </tr>`}
                            </tbody>
                        </table>
                    </div>

                    ${totalPages > 1 ? `
                        <div class="flow-blacklist-pagination">
                            <span>Page <strong>${this.blacklistPagination.page}</strong> of ${totalPages}</span>
                            <div>
                                <button type="button" class="operator-btn operator-btn-secondary btn-xs"
                                    ${this.blacklistPagination.page === 1 ? 'disabled' : ''}
                                    data-traffic-action="blacklist-prev-page">&larr; Previous</button>
                                <button type="button" class="operator-btn operator-btn-secondary btn-xs"
                                    ${this.blacklistPagination.page >= totalPages ? 'disabled' : ''}
                                    data-traffic-action="blacklist-next-page">Next &rarr;</button>
                            </div>
                        </div>
                    ` : ''}
                </section>
            </div>
            
            ${renderTrafficSaveButtons()}
        `;
    },

    openAddIPModal(editTarget: string | null = null, _editExpiresLegacy: string | null = null): void {
        const isEdit = !!editTarget;
        const title = isEdit ? 'Edit Block Entry' : 'Block New Targets';
        const btnText = isEdit ? 'Save Changes' : 'Block Targets';
        const existingEntry = editTarget
            ? getTrafficBlacklistEntries(this.config.blacklist).find(entry => entry.target === editTarget)
            : null;
        const initialValue = editTarget || '';
        const existingExpiryLabel = existingEntry?.expires_at
            ? new Date(existingEntry.expires_at).toLocaleString()
            : '';
        const enforcementNotice = this.config.enabled === true
            ? `<div class="section-alert-danger-soft text-13" data-traffic-blacklist-impact="enabled" role="status"><strong>After you save changes:</strong> matching requests are rejected before they reach protected services.</div>`
            : `<div class="section-panel-soft section-panel-soft--stacked text-13" data-traffic-blacklist-impact="disabled" role="status"><strong>Traffic Control is disabled.</strong><div class="text-11 text-muted mt-4">Block entries are staged and do not reject traffic until you enable Traffic Control and save changes.</div></div>`;

        SectionUI.showModal(`
            <div class="section-modal-head">
                <h3 class="section-modal-title">${title}</h3>
                <button type="button" class="section-modal-close" data-traffic-action="close-modal" aria-label="Close dialog">&times;</button>
            </div>
            <div class="section-modal-body section-modal-blacklist-form">
                ${enforcementNotice}

                <div class="section-form-group">
                    <label class="section-form-label">Duration</label>
                    <select id="modal-duration-input" class="section-input w-100">
                        ${existingEntry?.expires_at ? `<option value="existing" selected>Keep current expiry (${escapeTrafficHtml(existingExpiryLabel)})</option>` : ''}
                        <option value="permanent">Permanent</option>
                        <option value="1h">1 Hour</option>
                        <option value="24h">24 Hours</option>
                        <option value="7d">7 Days</option>
                        <option value="30d">30 Days</option>
                    </select>
                    <div class="text-11 text-note mt-8">Choose how long the block should remain active at the edge.</div>
                </div>

                <div class="section-form-group">
                    <label class="section-form-label">Target Identifier</label>
                    <textarea id="modal-ip-input" rows="${isEdit ? 3 : 4}" class="section-input w-100 text-mono"
                              placeholder="203.0.113.1&#10;198.51.100.0/24">${escapeTrafficHtml(initialValue)}</textarea>
                    <div class="text-11 text-note mt-8">
                        ${isEdit ? 'Update the IP or CIDR and adjust its duration if needed.' : 'Enter one IP address or CIDR range per line.'}
                    </div>
                </div>
            </div>
            <div class="section-modal-footer">
                <button type="button" class="operator-btn operator-btn-secondary" data-traffic-action="close-modal">Cancel</button>
                <button type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-added-ips" data-traffic-value="${encodeTrafficValue(editTarget || '')}">${btnText}</button>
            </div>
        `, { panelClass: 'modal-content section-modal-panel-md flow-operator-modal' });
    },

    saveAddedIPs(editingTarget = ''): void {
        const txtElement = trafficElementById('modal-ip-input');
        const durationElement = trafficElementById('modal-duration-input');
        if (!(txtElement instanceof HTMLTextAreaElement) || !(durationElement instanceof HTMLSelectElement)) return;

        const txt = txtElement.value;
        const durationStr = durationElement.value;
        if (!txt) return;

        const existingEntry = editingTarget
            ? getTrafficBlacklistEntries(this.config.blacklist).find(entry => entry.target === editingTarget)
            : null;

        // Calculate Expiration Time
        let expiresAt = null; // null = Permanent
        if (durationStr === 'existing' && existingEntry?.expires_at) {
            expiresAt = existingEntry.expires_at;
        } else if (durationStr !== 'permanent') {
            const now = new Date();
            let addMs = 0;
            switch (durationStr) {
                case '1h': addMs = 3600 * 1000; break;
                case '24h': addMs = 24 * 3600 * 1000; break;
                case '7d': addMs = 7 * 24 * 3600 * 1000; break;
                case '30d': addMs = 30 * 24 * 3600 * 1000; break;
            }
            expiresAt = new Date(now.getTime() + addMs).toISOString();
        }

        const entries = txt.split('\n').map((s: string) => s.trim()).filter((s: string) => s);
        const validEntries: string[] = [];
        const invalid: string[] = [];

        entries.forEach((entry: string) => {
            if (isValidTrafficBlacklistTarget(entry)) {
                validEntries.push(entry);
            } else {
                invalid.push(entry);
            }
        });

        if (invalid.length > 0) {
            showSectionToast(`Skipped ${invalid.length} invalid entries`, 'warning');
            if (validEntries.length === 0) return;
        }

        // Initialize config objects if missing
        if (!this.config.blacklist) this.config.blacklist = { enabled: true, ips: [], cidrs: [], entries: [] };
        if (!this.config.blacklist.entries) this.config.blacklist.entries = [];

        if (editingTarget) {
            this.removeLocalEntry(editingTarget); // Helper to remove from all lists
        }

        validEntries.forEach(target => {
            // Remove any existing exact match to avoid duplicates
            this.removeLocalEntry(target);
            if (!this.config.blacklist?.entries) return;

            this.config.blacklist.entries.push({
                target: target,
                expires_at: expiresAt,
                note: 'Added via Web Admin'
            });
        });
        this.config.blacklist = syncTrafficBlacklistEnabled(this.config.blacklist);

        SectionUI.closeModal();
        this.render();
        SectionUI.markSaveActionBarDirty('data-traffic-action');
        showSectionToast(editingTarget ? 'Entry staged' : `Staged ${validEntries.length} blocks`, 'info');
    },

    removeIP(entry: string): void {
        this.pendingTarget = entry;
        const safeEntry = escapeTrafficHtml(entry);
        SectionUI.openConfirmModal(
            'Remove Block Entry',
            `Target: <strong>${safeEntry}</strong><br><br>This will immediately allow traffic from this identifier.`,
            'Remove',
            'var(--danger)',
            () => { TrafficConfig.confirmRemoveIP(); }
        );
    },

    confirmRemoveIP(): void {
        if (!this.pendingTarget) return;
        this.removeLocalEntry(this.pendingTarget);
        this.blacklistSelected.delete(this.pendingTarget);
        this.pendingTarget = null;
        SectionUI.closeModal();
        this.render();
        SectionUI.markSaveActionBarDirty('data-traffic-action');
        showSectionToast('Block removal staged', 'info');
    },



    removeLocalEntry(target: string): void {
        if (!this.config.blacklist) return;

        // Remove from legacy lists
        if (this.config.blacklist.ips) {
            this.config.blacklist.ips = this.config.blacklist.ips.filter(ip => ip !== target);
        }
        if (this.config.blacklist.cidrs) {
            this.config.blacklist.cidrs = this.config.blacklist.cidrs.filter(c => c !== target);
        }

        // Remove from new entries list
        if (this.config.blacklist.entries) {
            this.config.blacklist.entries = this.config.blacklist.entries.filter(e => e.target !== target);
        }
        this.config.blacklist = syncTrafficBlacklistEnabled(this.config.blacklist);
    },

    areBlacklistTargetsSelected(targets: string[]): boolean {
        if (targets.length === 0) return false;
        for (const target of targets) {
            if (!this.blacklistSelected.has(target)) return false;
        }
        return true;
    },

    updateBlacklistSelection(targets: string[], selectAll: boolean): void {
        for (const target of targets) {
            if (selectAll) {
                this.blacklistSelected.add(target);
            } else {
                this.blacklistSelected.delete(target);
            }
        }
    },

    removeLocalEntries(targets: Iterable<string>): void {
        for (const target of targets) {
            this.removeLocalEntry(target);
        }
    },

    getBlacklistTargets(entries: Array<{ target: string }>): string[] {
        const targets: string[] = [];
        for (const entry of entries) {
            targets.push(entry.target);
        }
        return targets;
    },

    // Batch Operations
    toggleBlacklistSelection(target: string): void {
        if (this.blacklistSelected.has(target)) {
            this.blacklistSelected.delete(target);
        } else {
            this.blacklistSelected.add(target);
        }
        this.render();
    },

    toggleSelectAllBlacklist(selectAll: boolean): void {
        const pageEntries = buildTrafficBlacklistPageData(
            this.config.blacklist,
            this.blacklistPagination.search,
            this.blacklistPagination.page,
            this.blacklistPagination.pageSize
        ).pageEntries;
        const pageTargets = this.getBlacklistTargets(pageEntries);

        this.updateBlacklistSelection(pageTargets, selectAll);
        this.render();
    },

    deleteSelectedBlacklist(): void {
        const count = this.blacklistSelected.size;
        if (count === 0) return;

        SectionUI.openConfirmModal(
            'Delete Selected Entries',
            `Are you sure you want to remove <strong>${count}</strong> block${count > 1 ? 's' : ''}?<br><br>Traffic from these identifiers will be allowed immediately.`,
            'Delete Selected',
            'var(--danger)',
            () => { TrafficConfig.confirmDeleteSelected(); }
        );
    },

    confirmDeleteSelected(): void {
        const count = this.blacklistSelected.size;
        this.removeLocalEntries(this.blacklistSelected);
        this.blacklistSelected.clear();
        SectionUI.closeModal();
        this.render();
        SectionUI.markSaveActionBarDirty('data-traffic-action');
        showSectionToast(`Staged deletion of ${count} entries`, 'info');
    },

    flushBlacklist(): void {
        const total = getTrafficBlacklistTotalCount(this.config.blacklist);

        if (total === 0) {
            showSectionToast('ℹ️ List is already empty', 'info');
            return;
        }

        SectionUI.openConfirmModal(
            '⚠️ FLUSH ALL BLACKLIST ENTRIES',
            `You are about to delete <strong>ALL ${total}</strong> blocked IPs and CIDRs.<br><br>
             This action <strong>CANNOT</strong> be undone.<br>
             All currently blocked traffic will be immediately allowed.`,
            'FLUSH EVERYTHING',
            'var(--danger)',
            () => { TrafficConfig.confirmFlushBlacklist(total); }
        );
    },

    confirmFlushBlacklist(total: number): void {
        if (!this.config.blacklist) this.config.blacklist = { enabled: true, ips: [], cidrs: [], entries: [] };
        this.config.blacklist.entries = [];
        this.config.blacklist.ips = [];
        this.config.blacklist.cidrs = [];
        this.config.blacklist = syncTrafficBlacklistEnabled(this.config.blacklist);
        this.blacklistSelected.clear();

        SectionUI.closeModal();

        this.render();
        SectionUI.markSaveActionBarDirty('data-traffic-action');
        showSectionToast(`Staged flush of ${total} entries`, 'warning');
    },

    openImportBlacklistCSV(): void {
        const input = trafficElementById<HTMLInputElement>('traffic-blacklist-import');
        if (!(input instanceof HTMLInputElement)) return;
        input.value = '';
        input.click();
    },

    async importBlacklistCSV(file: File): Promise<void> {
        const isCsv = file.name.toLowerCase().endsWith('.csv') || file.type === 'text/csv';
        if (!isCsv) {
            showSectionToast('Choose a CSV file containing blacklist targets.', 'warning');
            return;
        }
        if (file.size === 0) {
            showSectionToast('The selected CSV file is empty.', 'warning');
            return;
        }
        if (file.size > 2 * 1024 * 1024) {
            showSectionToast('CSV imports are limited to 2 MB.', 'warning');
            return;
        }

        try {
            const parsed = parseTrafficBlacklistCSV(await file.text());
            if (parsed.malformed) {
                showSectionToast('The CSV has an unclosed quoted value.', 'warning');
                return;
            }
            if (parsed.entries.length === 0) {
                showSectionToast('No valid IP addresses or CIDR ranges were found in the CSV.', 'warning');
                return;
            }

            if (!this.config.blacklist) this.config.blacklist = { enabled: true, ips: [], cidrs: [], entries: [] };
            if (!this.config.blacklist.entries) this.config.blacklist.entries = [];

            for (const entry of parsed.entries) {
                this.removeLocalEntry(entry.target);
                this.config.blacklist.entries.push(entry);
            }
            this.config.blacklist = syncTrafficBlacklistEnabled(this.config.blacklist);

            this.blacklistSelected.clear();
            this.blacklistPagination.page = 1;
            this.blacklistPagination.search = '';
            this.render();
            SectionUI.markSaveActionBarDirty('data-traffic-action');

            const skipped = parsed.invalidRows > 0 ? ` Skipped ${parsed.invalidRows} invalid row${parsed.invalidRows === 1 ? '' : 's'}.` : '';
            showSectionToast(`Staged ${parsed.entries.length} imported block${parsed.entries.length === 1 ? '' : 's'}.${skipped}`, 'info');
        } catch (error) {
            console.error('Blacklist CSV import failed', error);
            showSectionToast('Unable to read the selected CSV file.', 'error');
        }
    },

    // ========== GEO-BLOCKING ==========
    renderGeo() {
        return renderGeoTab(
            this.config.geo,
            this.countries,
            this.regions,
            this.getGeoPolicyCountries.bind(this),
            this.getGeoPolicyGroups.bind(this),
            this.renderModuleStatusCard.bind(this),
            this.icons,
            renderTrafficSaveButtons,
            this.initGeoMap.bind(this)
        );
    },

    openGeoModal() {
        const currentCountries = new Set(this.getGeoPolicyCountries(this.config.geo || {}));
        const currentRegions = new Set(this.getGeoPolicyGroups(this.config.geo || {}));

        const regionIcons: Record<string, string> = {
            "EU": "🇪🇺", "APAC": "🌏", "LATAM": "🌎",
            "MENA": "🕌", "AFRICA": "🌍", "CIS": "❄️"
        };

        // Generate Region List - Styled as Cards
        const regionsHTML = Object.entries(this.regions).map(([code, name]) => {
            const checked = currentRegions.has(code) ? 'checked' : '';
            const isActive = currentRegions.has(code);
            return `
                <label class="section-select-card ${isActive ? 'active' : ''}" data-search="${escapeTrafficAttr(code.toLowerCase() + ' ' + name.toLowerCase())}" 
                       >
                    <input type="checkbox" value="${escapeTrafficAttr(code)}" class="section-region-checkbox hidden" ${checked}>
                    <div class="section-select-icon">${regionIcons[code] || '🌐'}</div>
                    <div class="section-select-info">
                        <div class="section-select-name">${escapeTrafficHtml(name)}</div>
                        <div class="section-select-code">${escapeTrafficHtml(code)}</div>
                    </div>
                    <div class="section-select-check">${this.icons.check}</div>
                </label>
            `;
        }).join('');

        // Generate Country List - Styled as List Items
        const listHTML = Object.entries(this.countries).map(([code, name]) => {
            const checked = currentCountries.has(code) ? 'checked' : '';
            return `
                <label class="section-modal-list-item section-geo-item" data-search="${escapeTrafficAttr(code.toLowerCase() + ' ' + name.toLowerCase())}">
                    <input type="checkbox" value="${escapeTrafficAttr(code)}" class="section-country-checkbox" ${checked}>
                    <span class="code-chip code-chip-sm text-note">${escapeTrafficHtml(code)}</span>
                    <span class="flex-1">${escapeTrafficHtml(name)}</span>
                </label>
            `;
        }).join('');

        SectionUI.showModal(`
            <div class="section-modal-head">
                <h3 class="section-modal-title">Select Regions & Countries</h3>
                <button type="button" class="section-modal-close" data-traffic-action="close-modal" aria-label="Close dialog">&times;</button>
            </div>
            <div class="section-modal-body section-modal-geo">
                <div class="section-modal-toolbar">
                    <input type="text" class="section-input-search" placeholder="Search regions or countries..." autofocus
                           >
                </div>
                <div id="geo-list-container" class="section-modal-list">
                    <div class="section-label">Global Regions</div>
                    <div class="section-select-grid">
                        ${regionsHTML}
                    </div>
                    
                    <div class="divider-row">
                        <div class="divider-line"></div>
                        <div class="section-label m-0">Individual Countries</div>
                        <div class="divider-line"></div>
                    </div>
                    
                    <div class="section-modal-list-stack">
                        ${listHTML}
                    </div>
                </div>
            </div>
            <div class="section-modal-footer section-modal-footer-bar">
                <button type="button" class="operator-btn operator-btn-secondary" data-traffic-action="close-modal">Cancel</button>
                <button type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-geo-selection">Save Changes</button>
            </div>
        `, { panelClass: 'modal-content section-modal-panel-md section-modal-panel-wide flow-operator-modal' });
    },

    filterGeoModal(query: string): void {
        const q = query.toLowerCase();
        trafficQueryAll<HTMLElement>('.section-geo-item').forEach((el) => {
            const search = el.getAttribute('data-search');
            el.classList.toggle('hidden', !search?.includes(q));
        });
    },

    getCheckedTrafficValues(selector: string): string[] {
        const values: string[] = [];
        const checkedInputs = trafficQueryAll<HTMLInputElement>(selector);
        for (const input of checkedInputs) {
            values.push(input.value);
        }
        return values;
    },

    removeTrafficTooltips(): void {
        const tooltips = trafficQueryAll<HTMLElement>('.jvm-tooltip');
        for (const tooltip of tooltips) {
            tooltip.remove();
        }
    },

    getGeoPolicyCountries(cfg: TrafficGeoConfig = {}): string[] {
        if ((cfg.allow_countries || []).length > 0) return cfg.allow_countries || [];
        if ((cfg.block_countries || []).length > 0) return cfg.block_countries || [];
        return cfg.countries || [];
    },

    getGeoPolicyGroups(cfg: TrafficGeoConfig = {}): string[] {
        return (cfg.groups || cfg.regions || []).map(group => group.replace(/^@/, '').toUpperCase());
    },

    setGeoMode(mode: string): void {
        if (!this.config.geo) this.config.geo = {};
        const selected = this.getGeoPolicyCountries(this.config.geo);
        this.config.geo.mode = mode === 'allowlist' ? 'allowlist' : 'blocklist';
        this.config.geo.countries = selected;
        if (this.config.geo.mode === 'allowlist') {
            this.config.geo.allow_countries = selected;
            this.config.geo.block_countries = [];
        } else {
            this.config.geo.block_countries = selected;
            this.config.geo.allow_countries = [];
        }
    },

    getGeoHighlightedCountries(cfg: TrafficGeoConfig = {}): string[] {
        const highlighted = new Set(this.getGeoPolicyCountries(cfg));
        for (const region of this.getGeoPolicyGroups(cfg)) {
            const members = this.regionMembers[region] || [];
            for (const code of members) {
                highlighted.add(code);
            }
        }
        return Array.from(highlighted);
    },

    saveGeoSelection(): void {
        const selectedCountries = this.getCheckedTrafficValues('.section-country-checkbox:checked');
        const selectedRegions = this.getCheckedTrafficValues('.section-region-checkbox:checked');

        if (!this.config.geo) this.config.geo = {};
        this.config.geo.countries = selectedCountries;
        this.config.geo.regions = selectedRegions;
        this.config.geo.groups = selectedRegions;
        if ((this.config.geo.mode || 'blocklist') === 'allowlist') {
            this.config.geo.allow_countries = selectedCountries;
            this.config.geo.block_countries = [];
        } else {
            this.config.geo.block_countries = selectedCountries;
            this.config.geo.allow_countries = [];
        }
        this.config.geo = normalizeTrafficGeoPolicy(this.config.geo);

        SectionUI.closeModal();
        this.render();
        SectionUI.markSaveActionBarDirty('data-traffic-action');
        showSectionToast('Geo selection staged', 'info');
    },

    removeCountry(code: string): void {
        if (!this.config.geo) return;
        this.config.geo.countries = (this.config.geo.countries || []).filter(c => c !== code);
        this.config.geo.allow_countries = (this.config.geo.allow_countries || []).filter(c => c !== code);
        this.config.geo.block_countries = (this.config.geo.block_countries || []).filter(c => c !== code);
        this.config.geo = normalizeTrafficGeoPolicy(this.config.geo);
        this.render();
    },

    removeRegion(code: string): void {
        if (!this.config.geo) return;
        this.config.geo.regions = (this.config.geo.regions || []).filter(region => region !== code);
        this.config.geo.groups = (this.config.geo.groups || []).filter(region => region !== code);
        this.config.geo = normalizeTrafficGeoPolicy(this.config.geo);
        this.render();
    },

    renderReputation(): string {
        return renderReputationTab(
            this.config.reputation,
            (title, desc, icon, configKey) => this.renderModuleStatusCard(title, desc, icon, configKey),
            this.icons,
            () => renderTrafficSaveButtons(),
            this.threatFeedPage,
            this.threatFeedData,
            this.threatFeedPagination
        );
    },

    // ========== RATELIMIT ==========
    renderRateLimit(): string {
        return renderRateLimitTab(
            this.config.rate_limit as any,
            () => renderTrafficSaveButtons(),
            this.icons,
            this.rateLimitView || 'table',
            this.editingRateRuleIndex
        );
    },
    // ========== DDOS (Advanced) ==========
    renderDDoS(): string {
        return renderDDoSTab(
            this.config.application_flood || this.config.ddos,
            this.config.challenge,
            this.renderModuleStatusCard.bind(this),
            this.icons,
            renderTrafficSaveButtons
        );
    },

    openAddFloodObjectModal(): void {
        SectionUI.showModal(`
            <div class="section-modal-head"><h3 class="section-modal-title">Add protected HTTP object</h3><button type="button" class="section-modal-close" data-traffic-action="close-modal" aria-label="Close dialog">&times;</button></div>
            <div class="section-modal-body section-modal-stack-body">
                <div class="operator-control-desc mb-16"><strong>Scoped policy:</strong> object matching is deterministic by priority, then ID. Use the narrowest host, method, and path that protects the endpoint.</div>
                <div class="grid-2 gap-16">
                    <label class="section-form-group"><span class="section-form-label">Object ID</span><input id="flood-object-id" class="section-input" placeholder="checkout-payments"></label>
                    <label class="section-form-group"><span class="section-form-label">Methods (comma separated)</span><input id="flood-object-methods" class="section-input" value="POST" placeholder="POST, PUT"></label>
                </div>
                <div class="grid-2 gap-16">
                    <label class="section-form-group"><span class="section-form-label">Host (optional)</span><input id="flood-object-host" class="section-input" placeholder="shop.example.com"></label>
                    <label class="section-form-group"><span class="section-form-label">Path</span><input id="flood-object-path" class="section-input" value="/" placeholder="/checkout/pay"></label>
                </div>
                <div class="grid-2 gap-16">
                    <label class="section-form-group"><span class="section-form-label">Path matching</span><select id="flood-object-match" class="section-input"><option value="exact">Exact</option><option value="prefix" selected>Prefix</option><option value="glob">Glob</option></select></label>
                    <label class="section-form-group"><span class="section-form-label">Action</span><select id="flood-object-action" class="section-input"><option value="block">HTTP 429 block</option><option value="challenge">Browser challenge</option><option value="http_reject">HTTP 503 reject</option></select></label>
                </div>
                <div class="grid-3 gap-16">
                    <label class="section-form-group"><span class="section-form-label">Rate / second</span><input id="flood-object-rate" type="number" min="1" value="100" class="section-input"></label>
                    <label class="section-form-group"><span class="section-form-label">In-flight limit</span><input id="flood-object-concurrency" type="number" min="1" value="50" class="section-input"></label>
                    <label class="section-form-group"><span class="section-form-label">Burst multiplier</span><input id="flood-object-burst" type="number" min="1" step="0.1" value="2" class="section-input"></label>
                </div>
            </div>
            <div class="section-modal-footer"><button type="button" class="operator-btn operator-btn-secondary" data-traffic-action="close-modal">Cancel</button><button type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-flood-object">Add object</button></div>
        `, { panelClass: 'modal-content section-modal-panel-lg flow-operator-modal' });
    },

    saveFloodObject(): void {
        const read = (id: string): string => (trafficElementById<HTMLInputElement | HTMLSelectElement>(id)?.value || '').trim();
        const id = read('flood-object-id').toLowerCase();
        const path = read('flood-object-path');
        const rate = Number.parseInt(read('flood-object-rate'), 10);
        const concurrency = Number.parseInt(read('flood-object-concurrency'), 10);
        const burst = Number.parseFloat(read('flood-object-burst'));
        if (!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(id) || id === 'default' || !path.startsWith('/') || !Number.isFinite(rate) || rate < 1 || !Number.isFinite(concurrency) || concurrency < 1 || !Number.isFinite(burst) || burst < 1) {
            showSectionToast('Provide a valid non-default ID, path, positive rate, in-flight limit, and burst multiplier.', 'error');
            return;
        }
        const cfg = this.config.application_flood || (this.config.application_flood = {});
        const objects = cfg.objects || (cfg.objects = []);
        if (objects.some(object => object.id === id)) { showSectionToast('Object IDs must be unique.', 'error'); return; }
        const split = (value: string): string[] => value.split(',').map(item => item.trim()).filter(Boolean);
        const host = read('flood-object-host');
        objects.push({ id, hosts: host ? [host] : [], methods: split(read('flood-object-methods')).map(method => method.toUpperCase()), path, path_match: read('flood-object-match') || 'prefix', max_rps: rate, max_concurrency: concurrency, burst_multiplier: burst, action: read('flood-object-action') || 'block', verified_grace_multiplier: 2 });
        this.config.ddos = cfg;
        SectionUI.closeModal(); this.render(); SectionUI.markSaveActionBarDirty('data-traffic-action');
        showSectionToast(`Staged protected object ${id}`, 'info');
    },

    removeFloodObject(id: string): void {
        const cfg = this.config.application_flood || this.config.ddos;
        if (!cfg?.objects) return;
        cfg.objects = cfg.objects.filter(object => object.id !== id);
        this.config.application_flood = cfg;
        this.config.ddos = cfg;
        this.render(); SectionUI.markSaveActionBarDirty('data-traffic-action');
        showSectionToast('Protected object removal staged', 'info');
    },

    // ========== PRIORITY ==========
    renderPriority() {
        return renderPriorityTab(
            this.config.trusted_exceptions,
            this.renderSectionHeader.bind(this),
            this.icons,
            renderTrafficSaveButtons
        );
    },

    openAddVIPModal() {
        SectionUI.showModal(`
            <div class="section-modal-head">
                <h3 class="section-modal-title">Add Trusted Exceptions</h3>
                <button type="button" class="section-modal-close" data-traffic-action="close-modal" aria-label="Close dialog">&times;</button>
            </div>
            <div class="section-modal-body section-modal-stack-body">
                <div class="operator-control-desc mb-16">
                    <strong>Default scope:</strong> These sources receive exceptions only for Application Flood Protection and Rate Limiting. They never bypass blacklist, Geo, or reputation policy.
                </div>
                
                <div class="section-form-group">
                    <label class="section-form-label">IP Addresses or CIDRs</label>
                    <textarea id="modal-vip-input" class="section-input w-100 text-mono" rows="6"
                              placeholder="192.168.1.50 (Uptime Monitor)&#10;10.20.0.0/24 (Internal VPN)"></textarea>
                    <div class="text-11 text-note mt-8">One source per line. Optional comments in parentheses are ignored.</div>
                </div>
            </div>
            <div class="section-modal-footer">
                <button type="button" class="operator-btn operator-btn-secondary" data-traffic-action="close-modal">Cancel</button>
                <button type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-added-vips">Add scoped exceptions</button>
            </div>
        `, { panelClass: 'modal-content section-modal-panel-md flow-operator-modal' });
    },

    saveAddedVIPs(): void {
        const txtElement = trafficElementById('modal-vip-input');
        if (!(txtElement instanceof HTMLTextAreaElement)) return;
        const txt = txtElement.value;
        if (!txt) return;

        const lines = txt.split('\n');
        const validEntries: string[] = [];
        const invalid: string[] = [];

        // Validation Regex (Same as Blacklist for consistency)
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        // CIDR: IPv4/prefix (1-32) or IPv6/prefix (1-128)
        const cidrV4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[12][0-9]|3[0-2])$/;
        const cidrV6Regex = /^([0-9a-fA-F:]+)\/([0-9]{1,3})$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^::$/;

        // Helper to validate IPv6 CIDR prefix (1-128)
        const isValidCidrV6 = (entry: string): boolean => {
            const match = cidrV6Regex.exec(entry);
            if (!match) return false;
            const prefix = parseInt(match[2], 10);
            return prefix >= 1 && prefix <= 128;
        };

        lines.forEach((line: string) => {
            // Strip comments in parens and whitespace
            const clean = line.split('(')[0].trim().split(' ')[0];
            if (!clean) return;

            if (cidrV4Regex.test(clean) || isValidCidrV6(clean) || ipv4Regex.test(clean) || ipv6Regex.test(clean)) {
                validEntries.push(clean);
            } else {
                invalid.push(clean);
            }
        });

        if (invalid.length > 0) {
            showSectionToast(`Skipped ${invalid.length} invalid entries`, 'warning');
            if (validEntries.length === 0) return;
        }

        if (!this.config.trusted_exceptions) this.config.trusted_exceptions = [];
        const existingTargets = new Set(this.config.trusted_exceptions.flatMap(exception => exception.targets || []));
        for (const target of validEntries) {
            if (existingTargets.has(target)) continue;
            const identifier = `trusted-${target.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')}`;
            this.config.trusted_exceptions.push({
                id: identifier,
                targets: [target],
                controls: ['flood', 'rate'],
                note: 'Operator-created scoped exception'
            });
        }

        SectionUI.closeModal();
        this.render();
        SectionUI.markSaveActionBarDirty('data-traffic-action');
        showSectionToast(`Staged ${validEntries.length} scoped exceptions`, 'info');
    },

    removeVIP(ip: string): void {
        this.pendingVipTarget = ip;
        SectionUI.openConfirmModal(
            'Remove trusted exception',
            `Are you sure you want to remove trusted exception <strong>${escapeTrafficHtml(ip)}</strong>?`,
            'Remove',
            'var(--danger)',
            'TrafficConfig.confirmRemoveVIP'
        );
    },

    confirmRemoveVIP(): void {
        if (!this.pendingVipTarget) return;
        if (this.config.trusted_exceptions) {
            this.config.trusted_exceptions = this.config.trusted_exceptions.filter(exception => exception.id !== this.pendingVipTarget);
            this.pendingVipTarget = null;
            SectionUI.closeModal();
            this.render();
            SectionUI.markSaveActionBarDirty('data-traffic-action');
            showSectionToast('Trusted exception removal staged', 'info');
        }
    },


    // ========== RATE LIMIT HELPERS ==========
    toggleRateEngineSettings(): void {
        this.render();
    },

    openAddRateRule(): void {
        this.rateLimitView = 'editor';
        this.editingRateRuleIndex = null;
        this.render();
    },

    openEditRateRule(idx: number): void {
        const rules = this.config.rate_limit?.path_overrides || [];
        if (idx < 0 || idx >= rules.length) return;
        this.rateLimitView = 'editor';
        this.editingRateRuleIndex = idx;
        this.render();
    },

    cancelRateRuleEditor(): void {
        this.rateLimitView = 'table';
        this.editingRateRuleIndex = null;
        this.render();
    },

    openAddRateRuleModal(): void {
        this.openAddRateRule();
    },

    openEditRateRuleModal(idx: number): void {
        this.openEditRateRule(idx);
    },

    renderRateRuleModal(_rule?: any): void {
        this.openAddRateRule();
    },

    saveRateRule(): void {
        const nameElement = trafficElementById('rl-rule-name');
        const patternElement = trafficElementById('rl-rule-pattern');
        const matchElement = trafficElementById('rl-rule-match');
        const priorityElement = trafficElementById('rl-rule-priority');
        const methodsElement = trafficElementById('rl-rule-methods');
        const hostsElement = trafficElementById('rl-rule-hosts');
        const rateElement = trafficElementById('rl-rule-rate');
        const burstElement = trafficElementById('rl-rule-burst');
        const windowElement = trafficElementById('rl-rule-window');
        const algoElement = trafficElementById('rl-rule-algorithm');
        const keyByElement = trafficElementById('rl-rule-key-by');
        const bypassStaticElement = trafficElementById('rl-rule-bypass-static');
        const graceElement = trafficElementById('rl-rule-grace');

        if (!(patternElement instanceof HTMLInputElement)) {
            return;
        }

        const name = nameElement instanceof HTMLInputElement ? nameElement.value.trim() : '';
        const pattern = patternElement.value.trim();
        const matchVal = (matchElement instanceof HTMLSelectElement ? matchElement.value : 'glob') as 'exact' | 'prefix' | 'glob';
        const priorityVal = priorityElement instanceof HTMLInputElement ? Number.parseInt(priorityElement.value, 10) || 100 : 100;
        const methodsVal = methodsElement instanceof HTMLInputElement ? methodsElement.value : '';
        const hostsVal = hostsElement instanceof HTMLInputElement ? hostsElement.value : '';
        const rateVal = rateElement instanceof HTMLInputElement ? Number.parseInt(rateElement.value, 10) : 60;
        const burstVal = burstElement instanceof HTMLInputElement ? Number.parseInt(burstElement.value, 10) : 10;
        const windowVal = windowElement instanceof HTMLSelectElement ? windowElement.value : '1m';
        const actionInput = trafficElementById('rl-rule-action');
        const checkedActionRadio = trafficDoc().querySelector('input[name="rl-rule-action"]:checked');
        const actionVal = (actionInput instanceof HTMLInputElement && actionInput.value)
            ? actionInput.value
            : (checkedActionRadio instanceof HTMLInputElement ? checkedActionRadio.value : 'block');
        const algoVal = algoElement instanceof HTMLSelectElement ? algoElement.value : 'token_bucket';
        const keyByVal = keyByElement instanceof HTMLSelectElement ? keyByElement.value : 'ip';
        const bypassStaticVal = bypassStaticElement instanceof HTMLInputElement ? bypassStaticElement.checked : true;
        const graceVal = graceElement instanceof HTMLInputElement ? Number.parseFloat(graceElement.value) || 2 : 2;

        if (!pattern.startsWith('/')) {
            showSectionToast('Target path pattern must start with "/" (e.g. /api/*).', 'error');
            return;
        }
        if (!Number.isFinite(rateVal) || rateVal < 1) {
            showSectionToast('Request allowance must be at least 1.', 'error');
            return;
        }
        if (!Number.isFinite(burstVal) || burstVal < 0) {
            showSectionToast('Burst headroom cannot be negative.', 'error');
            return;
        }

        const values = (val: string, normalize: (item: string) => string): string[] =>
            val.split(',').map(item => normalize(item.trim())).filter(Boolean);

        if (!this.config.rate_limit) this.config.rate_limit = {};
        if (!Array.isArray(this.config.rate_limit.path_overrides)) {
            this.config.rate_limit.path_overrides = [];
        }

        const currentOverrides = this.config.rate_limit.path_overrides;
        const editIdx = this.editingRateRuleIndex;
        const isEdit = typeof editIdx === 'number' && editIdx >= 0 && editIdx < currentOverrides.length;
        const validIdx = isEdit ? (editIdx as number) : -1;
        const ruleId = isEdit && currentOverrides[validIdx]?.id
            ? currentOverrides[validIdx].id
            : `rule-${Date.now().toString(36)}`;

        const rulePayload: any = {
            id: ruleId,
            name: name || undefined,
            pattern: pattern,
            match: matchVal,
            priority: priorityVal,
            methods: values(methodsVal, item => item.toUpperCase()),
            hosts: values(hostsVal, item => item.toLowerCase()),
            rate: rateVal,
            burst: burstVal,
            window: windowVal,
            action: actionVal,
            algorithm: algoVal,
            key_by: keyByVal,
            bypass_static: bypassStaticVal,
            dry_run: actionVal === 'dry_run',
            verified_grace_multiplier: graceVal
        };

        this.config.rate_limit.enabled = true;

        if (isEdit && typeof editIdx === 'number') {
            currentOverrides[editIdx] = rulePayload;
            showSectionToast(`Rate limit rule for ${pattern} updated.`, 'success');
        } else {
            currentOverrides.push(rulePayload);
            showSectionToast(`Rate limit rule for ${pattern} created.`, 'success');
        }

        this.rateLimitView = 'table';
        this.editingRateRuleIndex = null;
        SectionUI.markSaveActionBarDirty('data-traffic-action');
        this.render();
    },

    removeRateRule(idx: number): void {
        if (!Array.isArray(this.config.rate_limit?.path_overrides)) return;
        const removed = this.config.rate_limit.path_overrides.splice(idx, 1);
        SectionUI.markSaveActionBarDirty('data-traffic-action');
        if (removed.length > 0) {
            showSectionToast(`Rule for ${removed[0].pattern} removed.`, 'info');
        }
        this.render();
    },

    // ========== REPUTATION RULE HELPERS ==========
    openAddReputationRuleModal(): void {
        SectionUI.showModal(`
            <div class="section-modal-head">
                <h3 class="section-modal-title">Add IP Reputation Override Rule</h3>
                <button type="button" class="section-modal-close" data-traffic-action="close-modal" aria-label="Close dialog">&times;</button>
            </div>
            <div class="section-modal-body section-modal-blacklist-form">
                <div class="section-form-group">
                    <label class="section-form-label font-600 mb-6">IP Address or CIDR block</label>
                    <input type="text" id="modal-rep-rule-target" class="section-input w-100 font-mono" placeholder="198.51.100.1 or 203.0.113.0/24" required>
                    <div class="text-11 text-note mt-4">Target client IPv4, IPv6, or subnet.</div>
                </div>
                <div class="section-form-group">
                    <label class="section-form-label font-600 mb-6">Action Override</label>
                    <select id="modal-rep-rule-action" class="section-input w-100">
                        <option value="allow">Allow (Trusted Whitelist)</option>
                        <option value="block">Block (Strict Drop)</option>
                        <option value="challenge">Challenge (Smart PoW)</option>
                        <option value="bypass">Bypass Reputation</option>
                    </select>
                </div>
                <div class="section-form-group">
                    <label class="section-form-label font-600 mb-6">Custom Trust Score (0 - 100)</label>
                    <input type="number" id="modal-rep-rule-score" class="section-input w-100" min="0" max="100" value="100">
                </div>
                <div class="section-form-group">
                    <label class="section-form-label font-600 mb-6">Comment / Description</label>
                    <input type="text" id="modal-rep-rule-comment" class="section-input w-100" placeholder="E.g., Corporate egress proxy">
                </div>
            </div>
            <div class="section-modal-footer">
                <button type="button" class="operator-btn operator-btn-secondary" data-traffic-action="close-modal">Cancel</button>
                <button type="button" class="operator-btn operator-btn-primary" data-traffic-action="save-reputation-rule">Add Override Rule</button>
            </div>
        `, { panelClass: 'modal-content section-modal-panel-md flow-operator-modal' });
    },

    saveReputationRule(): void {
        const targetInput = trafficElementById<HTMLInputElement>('modal-rep-rule-target');
        const actionInput = trafficElementById<HTMLSelectElement>('modal-rep-rule-action');
        const scoreInput = trafficElementById<HTMLInputElement>('modal-rep-rule-score');
        const commentInput = trafficElementById<HTMLInputElement>('modal-rep-rule-comment');

        const target = targetInput?.value?.trim() || '';
        if (!target) {
            showSectionToast('Please enter a valid IP address or CIDR', 'error');
            return;
        }
        if (!this.config.reputation) {
            this.config.reputation = {};
        }
        const existingRules = (this.config.reputation.rules as any[]) || [];
        const newRule = {
            id: `rule-${Date.now()}`,
            ip_or_cidr: target,
            action: actionInput?.value || 'allow',
            score: Number.parseInt(scoreInput?.value || '100', 10),
            comment: commentInput?.value?.trim() || ''
        };
        this.config.reputation.rules = [...existingRules, newRule];
        SectionUI.closeModal();
        this.render();
        SectionUI.markSaveActionBarDirty('data-traffic-action');
    },

    removeReputationRule(ruleId: string): void {
        if (!this.config.reputation || !this.config.reputation.rules) return;
        this.config.reputation.rules = (this.config.reputation.rules as any[]).filter(r => r.id !== ruleId);
        this.render();
        SectionUI.markSaveActionBarDirty('data-traffic-action');
    },

    async initGeoMap(): Promise<void> {
        let container = trafficElementById('jvm-map');
        if (!container) return;
        let state = trafficElementById('geo-map-state');

        try {
            await this.loadMapLibs();
            if (!window.jsVectorMap) throw new Error('Map library did not initialize');

            container = trafficElementById('jvm-map');
            if (!container) return;
            state = trafficElementById('geo-map-state');

            this.map?.destroy?.();
            this.map = null;
            this.removeTrafficTooltips();
            container.innerHTML = '';

            const cfg = this.config.geo || {};
            const selected = this.getGeoHighlightedCountries(cfg);
            const isBlock = (cfg.mode || 'blocklist') === 'blocklist';
            const isDark = document.documentElement.dataset.theme !== 'light';
            const defaultFill = isDark ? '#1e293b' : '#cbd5e1';
            const defaultStroke = isDark ? 'rgba(255, 255, 255, 0.08)' : '#ffffff';
            const hoverFill = isDark ? '#334155' : '#94a3b8';
            const color = isBlock ? '#ef4444' : '#10b981';
            const selectedHoverColor = isBlock ? '#f87171' : '#34d399';

            this.map = new window.jsVectorMap({
                selector: '#jvm-map',
                map: 'world',
                backgroundColor: 'transparent',
                draggable: true,
                zoomButtons: true,
                zoomOnScroll: false,
                zoomAnimate: true,
                regionStyle: {
                    initial: { fill: defaultFill, stroke: defaultStroke, strokeWidth: 0.75 },
                    hover: { fill: hoverFill, cursor: 'pointer' },
                    selected: { fill: color, stroke: color, strokeWidth: 1 },
                    selectedHover: { fill: selectedHoverColor, stroke: selectedHoverColor }
                },
                selectedRegions: selected,
                onLoaded: (map: JsVectorMapInstance) => {
                    map.updateSize?.();
                    state?.classList.add('is-hidden');
                    container?.classList.add('is-ready');
                },
                onRegionClick: trafficHandleRegionClick
            });

            state?.classList.add('is-hidden');
            container.classList.add('is-ready');
            this.map.updateSize?.();
        } catch (error) {
            console.error('Geo map failed to load:', error);
            state?.classList.add('is-error');
            if (state) {
                state.innerHTML = '<strong>Map unavailable</strong><span>Country selection is still available through Manage zones.</span>';
            }
        }
    },

    toggleCountry(code: string): void {
        if (!this.config.geo) this.config.geo = { countries: [] };
        const target = (this.config.geo.mode || 'blocklist') === 'allowlist' ? 'allow_countries' : 'block_countries';
        const values = this.config.geo[target] || [];
        const idx = values.indexOf(code);
        if (idx > -1) values.splice(idx, 1);
        else values.push(code);
        this.config.geo[target] = values;
        this.config.geo.countries = values;
        this.config.geo = normalizeTrafficGeoPolicy(this.config.geo);
        this.render();
        SectionUI.markSaveActionBarDirty('data-traffic-action');
    },

    async loadMapLibs(): Promise<void> {
        const worldScript = AdminDOM.query<HTMLScriptElement>('script[src*="maps/world.js"]');
        if (window.jsVectorMap && worldScript?.dataset.loaded === 'true') return;
        const loadCSS = (href: string): void => {
            if (AdminDOM.query(`link[href="${href}"]`)) return;
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = href;
            document.head.appendChild(link);
        };
        const loadJS = (src: string): Promise<void> => new Promise((resolve, reject) => {
            const existing = AdminDOM.query<HTMLScriptElement>(`script[src="${src}"]`);
            if (existing?.dataset.loaded === 'true') {
                resolve();
                return;
            }
            if (existing) existing.remove();
            const script = document.createElement('script');
            script.src = src;
            script.onload = () => {
                script.dataset.loaded = 'true';
                resolve();
            };
            script.onerror = () => reject(new Error(`Failed to load ${src}`));
            document.head.appendChild(script);
        });
        loadCSS('https://cdn.jsdelivr.net/npm/jsvectormap/dist/css/jsvectormap.min.css');
        await loadJS('https://cdn.jsdelivr.net/npm/jsvectormap');
        await loadJS('https://cdn.jsdelivr.net/npm/jsvectormap/dist/maps/world.js');
    },

    updateNestedField(p: string, f: string, v: unknown): void {
        const current = this.config[p];
        if (typeof current !== 'object' || current === null || Array.isArray(current)) {
            this.config[p] = {};
        }
        const root = this.config[p] as Record<string, unknown>;
        if (!f.includes('.')) {
            root[f] = v;
            return;
        }

        const parts = f.split('.');
        let cursor: Record<string, unknown> = root;
        for (let i = 0; i < parts.length - 1; i++) {
            const key = parts[i];
            const next = cursor[key];
            if (typeof next !== 'object' || next === null || Array.isArray(next)) {
                cursor[key] = {};
            }
            cursor = cursor[key] as Record<string, unknown>;
        }
        cursor[parts[parts.length - 1]] = v;
    },
    updateNestedArrayFieldNewlines(p: string, f: string, v: string): void {
        const current = this.config[p];
        if (typeof current !== 'object' || current === null || Array.isArray(current)) {
            this.config[p] = {};
        }
        (this.config[p] as Record<string, unknown>)[f] = v.split('\n').map(s => s.trim()).filter(s => s);
    },

    async saveConfig(): Promise<void> {
        try {
            await saveSectionConfig<TrafficConfigSaveResponse>({
                endpoint: 'sections/traffic_control/config',
                config: normalizeTrafficConfigForSave(this.config),
                successMessage: 'Saved successfully',
                failureMessage: 'Failed to save',
                errorLogMessage: 'Save config error:',
                errorToastPrefix: 'Save failed: ',
                onSuccess: response => {
                    this.config.control = {
                        ...(this.config.control || {}),
                        revision: response.revision,
                        checksum: response.checksum
                    };
                }
            });
        } catch (error) {
            const mutationError = error as SectionMutationError;
            if (mutationError.status === 409 || mutationError.code === 'traffic_revision_conflict') {
                SectionUI.openConfirmModal(
                    'Configuration changed',
                    'Another operator saved Traffic Control changes. Keep this staged version open to review it, or reload the active server revision and discard the staged changes.',
                    'Reload server revision',
                    'var(--primary)',
                    () => {
                        SectionUI.closeModal();
                        void this.init()
                            .then(() => SectionUI.markSaveActionBarClean('data-traffic-action'))
                            .catch(() => showSectionToast('Could not reload the active Traffic Control revision.', 'error'));
                    }
                );
            }
            throw error;
        }
    },

};

const TrafficConfigState = {
    get currentTab(): TrafficTabId { return TrafficConfig.currentTab; },
    set currentTab(value: TrafficTabId) { TrafficConfig.currentTab = value; },
    get config(): TrafficControlState { return TrafficConfig.config; },
    set config(value: TrafficControlState) { TrafficConfig.config = value; },
    get stats(): TrafficStats { return TrafficConfig.stats; },
    set stats(value: TrafficStats) { TrafficConfig.stats = value; },
    get blacklistPagination(): TrafficBlacklistPagination { return TrafficConfig.blacklistPagination; },
    set blacklistPagination(value: TrafficBlacklistPagination) { TrafficConfig.blacklistPagination = value; },
    get blacklistSelected(): Set<string> { return TrafficConfig.blacklistSelected; },
    set blacklistSelected(value: Set<string>) { TrafficConfig.blacklistSelected = value; },
    get pendingTarget(): string | null { return TrafficConfig.pendingTarget; },
    set pendingTarget(value: string | null) { TrafficConfig.pendingTarget = value; },
    get pendingVipTarget(): string | null { return TrafficConfig.pendingVipTarget; },
    set pendingVipTarget(value: string | null) { TrafficConfig.pendingVipTarget = value; },
    get map(): JsVectorMapInstance | null { return TrafficConfig.map; },
    set map(value: JsVectorMapInstance | null) { TrafficConfig.map = value; }
};

const trafficInitGeoMap = TrafficConfig.initGeoMap.bind(TrafficConfig);
const trafficHandleRegionClick = (_event: unknown, code: string): void => {
    TrafficConfig.toggleCountry(code);
};

const TrafficConfigService = {
    init: (): Promise<void> => TrafficConfig.init(),
    loadConfig: (): Promise<void> => TrafficConfig.loadConfig(),
    loadStats: (): Promise<void> => TrafficConfig.loadStats(),
    loadMapLibs: (): Promise<void> => TrafficConfig.loadMapLibs(),
    saveConfig: (): Promise<void> => TrafficConfig.saveConfig()
};

const TrafficConfigView = {
    render: (): void => TrafficConfig.render(),
    renderTabContent: (): string => TrafficConfig.renderTabContent(),
    renderOverview: (): string => TrafficConfig.renderOverview(),
    renderBlacklist: (): string => TrafficConfig.renderBlacklist(),
    renderGeo: (): string => TrafficConfig.renderGeo(),
    renderReputation: (): string => TrafficConfig.renderReputation(),
    renderRateLimit: (): string => TrafficConfig.renderRateLimit(),
    renderDDoS: (): string => TrafficConfig.renderDDoS(),
    renderPriority: (): string => TrafficConfig.renderPriority(),
    renderSectionHeader: (icon: string, title: string, desc: string, toggleField?: string | null, toggleValue?: boolean): string => TrafficConfig.renderSectionHeader(icon, title, desc, toggleField, toggleValue),
    renderModuleStatusCard: (title: string, description: string, icon: string, configKey: string): string => TrafficConfig.renderModuleStatusCard(title, description, icon, configKey),
    renderSaveButtons: renderTrafficSaveButtons,
    initGeoMap: (): Promise<void> => TrafficConfig.initGeoMap(),
    showToast: showSectionToast
};

const TrafficConfigController = {
    switchTab: (id: TrafficTabId): void => TrafficConfig.switchTab(id),
    toggleProtection: (key: string): void => TrafficConfig.toggleProtection(key),
    openAddIPModal: (editTarget?: string | null, editExpiresLegacy?: string | null): void => TrafficConfig.openAddIPModal(editTarget, editExpiresLegacy),
    saveAddedIPs: (editingTarget?: string): void => TrafficConfig.saveAddedIPs(editingTarget),
    removeIP: (entry: string): void => TrafficConfig.removeIP(entry),
    confirmRemoveIP: (): void => TrafficConfig.confirmRemoveIP(),
    removeLocalEntry: (target: string): void => TrafficConfig.removeLocalEntry(target),
    toggleBlacklistSelection: (target: string): void => TrafficConfig.toggleBlacklistSelection(target),
    toggleSelectAllBlacklist: (selectAll: boolean): void => TrafficConfig.toggleSelectAllBlacklist(selectAll),
    deleteSelectedBlacklist: (): void => TrafficConfig.deleteSelectedBlacklist(),
    confirmDeleteSelected: (): void => TrafficConfig.confirmDeleteSelected(),
    flushBlacklist: (): void => TrafficConfig.flushBlacklist(),
    confirmFlushBlacklist: (total: number): void => TrafficConfig.confirmFlushBlacklist(total),
    openImportBlacklistCSV: (): void => TrafficConfig.openImportBlacklistCSV(),
    importBlacklistCSV: (file: File): Promise<void> => TrafficConfig.importBlacklistCSV(file),
    openGeoModal: (): void => TrafficConfig.openGeoModal(),
    filterGeoModal: (query: string): void => TrafficConfig.filterGeoModal(query),
    saveGeoSelection: (): void => TrafficConfig.saveGeoSelection(),
    removeCountry: (code: string): void => TrafficConfig.removeCountry(code),
    removeRegion: (code: string): void => TrafficConfig.removeRegion(code),
    openAddVIPModal: (): void => TrafficConfig.openAddVIPModal(),
    saveAddedVIPs: (): void => TrafficConfig.saveAddedVIPs(),
    removeVIP: (ip: string): void => TrafficConfig.removeVIP(ip),
    confirmRemoveVIP: (): void => TrafficConfig.confirmRemoveVIP(),
    openAddRateRule: (): void => TrafficConfig.openAddRateRule(),
    openEditRateRule: (idx: number): void => TrafficConfig.openEditRateRule(idx),
    cancelRateRuleEditor: (): void => TrafficConfig.cancelRateRuleEditor(),
    openAddRateRuleModal: (): void => TrafficConfig.openAddRateRuleModal(),
    openEditRateRuleModal: (idx: number): void => TrafficConfig.openEditRateRuleModal(idx),
    toggleRateEngineSettings: (): void => TrafficConfig.toggleRateEngineSettings(),
    saveRateRule: (): void => TrafficConfig.saveRateRule(),
    removeRateRule: (idx: number): void => TrafficConfig.removeRateRule(idx),
    openAddReputationRuleModal: (): void => TrafficConfig.openAddReputationRuleModal(),
    saveReputationRule: (): void => TrafficConfig.saveReputationRule(),
    removeReputationRule: (ruleId: string): void => TrafficConfig.removeReputationRule(ruleId),
    toggleCountry: (code: string): void => TrafficConfig.toggleCountry(code),
    updateNestedField: (path: string, field: string, value: unknown): void => TrafficConfig.updateNestedField(path, field, value),
    updateNestedArrayFieldNewlines: (path: string, field: string, value: string): void => TrafficConfig.updateNestedArrayFieldNewlines(path, field, value),
    formatNumber: formatTrafficNumber,
    escapeHtml: escapeTrafficHtml,
    escapeAttr: escapeTrafficAttr
};

const trafficServiceMethods = new Set<keyof typeof TrafficConfigService>(['init', 'loadConfig', 'loadStats', 'loadMapLibs', 'saveConfig']);
const trafficViewMethods = new Set<keyof typeof TrafficConfigView>([
    'render',
    'renderTabContent',
    'renderOverview',
    'renderBlacklist',
    'renderGeo',
    'renderReputation',
    'renderRateLimit',
    'renderDDoS',
    'renderPriority',
    'renderSectionHeader',
    'renderModuleStatusCard',
    'renderSaveButtons',
    'initGeoMap',
    'showToast'
]);

export const TrafficConfigFacade = new Proxy({} as TrafficConfigRuntime & { state: typeof TrafficConfigState }, {
    get(_target, prop: string | symbol): unknown {
        if (prop === 'state') return TrafficConfigState;
        if (typeof prop !== 'string') return undefined;

        if (trafficServiceMethods.has(prop as keyof typeof TrafficConfigService)) {
            return TrafficConfigService[prop as keyof typeof TrafficConfigService];
        }
        if (trafficViewMethods.has(prop as keyof typeof TrafficConfigView)) {
            return TrafficConfigView[prop as keyof typeof TrafficConfigView];
        }
        if (prop in TrafficConfigController) {
            return TrafficConfigController[prop as keyof typeof TrafficConfigController];
        }

        const value = TrafficConfig[prop as keyof TrafficConfigRuntime];
        return typeof value === 'function' ? value.bind(TrafficConfig) : value;
    },
    set(_target, prop: string | symbol, value: unknown): boolean {
        if (typeof prop === 'string' && prop in TrafficConfig) {
            (TrafficConfig as Record<string, unknown>)[prop] = value;
            return true;
        }
        return false;
    }
});
