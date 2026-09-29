import { escapeSectionHtml, formatSectionCompactNumber } from './section-runtime-helpers.js';
export function escapeTrafficAttr(value) {
    return escapeSectionHtml(value).replace(/'/g, "\\'");
}
export function escapeTrafficHtml(value) {
    return escapeSectionHtml(value);
}
export function formatTrafficNumber(value) {
    if (!value)
        return '0';
    return formatSectionCompactNumber(value, { millionDecimals: 2, thousandSuffix: 'k' });
}
export function encodeTrafficValue(value) {
    return encodeURIComponent(value);
}
export function decodeTrafficValue(value) {
    return value ? decodeURIComponent(value) : '';
}
export function trafficCountryFlag(code) {
    const normalized = String(code || '').trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(normalized))
        return normalized;
    return Array.from(normalized)
        .map(letter => String.fromCodePoint(0x1F1E6 + letter.charCodeAt(0) - 65))
        .join('');
}
export function getTrafficBlacklistEntries(blacklist) {
    const legacyIps = (blacklist?.ips || []).map((ip) => ({
        target: ip,
        expires_at: null,
        note: 'Existing entry',
        type: 'IP',
        legacy: true
    }));
    const legacyCidrs = (blacklist?.cidrs || []).map((cidr) => ({
        target: cidr,
        expires_at: null,
        note: 'Existing entry',
        type: 'CIDR',
        legacy: true
    }));
    const richEntries = (blacklist?.entries || []).map((entry) => ({
        target: entry.target,
        expires_at: entry.expires_at ?? null,
        note: entry.note || '',
        type: entry.target.includes('/') ? 'CIDR' : 'IP',
        legacy: false
    }));
    return [...legacyIps, ...legacyCidrs, ...richEntries];
}
export function getTrafficBlacklistTotalCount(blacklist) {
    return (blacklist?.ips?.length || 0) + (blacklist?.cidrs?.length || 0) + (blacklist?.entries?.length || 0);
}
export function buildTrafficBlacklistPageData(blacklist, search, page, pageSize) {
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
