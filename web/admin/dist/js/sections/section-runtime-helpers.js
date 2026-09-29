export function escapeSectionHtml(value) {
    if (!value)
        return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
export function escapeSectionAttr(value) {
    return escapeSectionHtml(value).replace(/'/g, '&#39;');
}
export function parseSectionCSVList(raw) {
    if (!raw)
        return [];
    return [...new Set(raw.split(',').map((entry) => entry.trim()).filter(Boolean))];
}
export function formatSectionCompactNumber(value, options = {}) {
    const numeric = typeof value === 'number' ? value : Number(value);
    if (!Number.isFinite(numeric))
        return String(value);
    const millionDecimals = options.millionDecimals ?? 1;
    const thousandSuffix = options.thousandSuffix ?? 'K';
    if (numeric >= 1000000)
        return (numeric / 1000000).toFixed(millionDecimals) + 'M';
    if (numeric >= 1000)
        return (numeric / 1000).toFixed(1) + thousandSuffix;
    return numeric.toString();
}
