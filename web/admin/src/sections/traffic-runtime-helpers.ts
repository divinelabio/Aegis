import { escapeSectionHtml, formatSectionCompactNumber } from './section-runtime-helpers.js';

export function escapeTrafficAttr(value: unknown): string {
    return escapeSectionHtml(value).replace(/'/g, "\\'");
}

export function escapeTrafficHtml(value: unknown): string {
    return escapeSectionHtml(value);
}

export function formatTrafficNumber(value: number): string {
    if (!value) return '0';
    return formatSectionCompactNumber(value, { millionDecimals: 2, thousandSuffix: 'k' });
}

export function encodeTrafficValue(value: string): string {
    return encodeURIComponent(value);
}

export function decodeTrafficValue(value: string | undefined): string {
    return value ? decodeURIComponent(value) : '';
}

export function trafficCountryFlag(code: string): string {
    const normalized = String(code || '').trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(normalized)) return normalized;

    return Array.from(normalized)
        .map(letter => String.fromCodePoint(0x1F1E6 + letter.charCodeAt(0) - 65))
        .join('');
}

type TrafficBlacklistSourceEntry = {
    target: string;
    expires_at?: string | null;
    note?: string;
};

type TrafficBlacklistSource = {
    ips?: string[];
    cidrs?: string[];
    entries?: TrafficBlacklistSourceEntry[];
} | undefined;

export type TrafficBlacklistEntry = {
    target: string;
    expires_at: string | null;
    note: string;
    type: 'IP' | 'CIDR';
    legacy: boolean;
};

export type TrafficBlacklistPageData = {
    totalCount: number;
    filteredCount: number;
    totalPages: number;
    page: number;
    pageEntries: TrafficBlacklistEntry[];
};

export function getTrafficBlacklistEntries(blacklist: TrafficBlacklistSource): TrafficBlacklistEntry[] {
    const legacyIps = (blacklist?.ips || []).map((ip) => ({
        target: ip,
        expires_at: null,
        note: 'Existing entry',
        type: 'IP' as const,
        legacy: true
    }));
    const legacyCidrs = (blacklist?.cidrs || []).map((cidr) => ({
        target: cidr,
        expires_at: null,
        note: 'Existing entry',
        type: 'CIDR' as const,
        legacy: true
    }));
    const richEntries = (blacklist?.entries || []).map((entry) => ({
        target: entry.target,
        expires_at: entry.expires_at ?? null,
        note: entry.note || '',
        type: entry.target.includes('/') ? ('CIDR' as const) : ('IP' as const),
        legacy: false
    }));
    return [...legacyIps, ...legacyCidrs, ...richEntries];
}

export function getTrafficBlacklistTotalCount(blacklist: TrafficBlacklistSource): number {
    return (blacklist?.ips?.length || 0) + (blacklist?.cidrs?.length || 0) + (blacklist?.entries?.length || 0);
}

export function buildTrafficBlacklistPageData(
    blacklist: TrafficBlacklistSource,
    search: string,
    page: number,
    pageSize: number
): TrafficBlacklistPageData {
    const allEntries = getTrafficBlacklistEntries(blacklist);
    const totalCount = allEntries.length;
    const searchQuery = search.trim().toLowerCase();
    const filteredEntries = searchQuery
        ? allEntries.filter((entry) => entry.target.toLowerCase().includes(searchQuery))
        : allEntries;
    const sortedEntries = [...filteredEntries].sort((a, b) => a.target.localeCompare(b.target));
    const totalPages = Math.max(1, Math.ceil(sortedEntries.length / pageSize));
    const safePage = Math.min(Math.max(page, 1), totalPages);
    const start = (safePage - 1) * pageSize;
    return {
        totalCount,
        filteredCount: sortedEntries.length,
        totalPages,
        page: safePage,
        pageEntries: sortedEntries.slice(start, start + pageSize)
    };
}
