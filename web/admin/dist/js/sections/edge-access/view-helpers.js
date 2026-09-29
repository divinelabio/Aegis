export function escapeHTML(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
export function formatDateTime(value) {
    if (!value)
        return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime()))
        return escapeHTML(value);
    return escapeHTML(date.toLocaleString());
}
export function statusTone(value) {
    if (value === 'enabled' || value === 'allow' || value === 'ready' || value === 'passed' || value === 'active')
        return 'success';
    if (value === 'misconfigured' || value === 'deny' || value === 'failed' || value === 'expired')
        return 'danger';
    if (value === 'setup_only' || value === 'future' || value === 'preview_only' || value === 'warning' || value === 'expiring_soon')
        return 'warning';
    return 'neutral';
}
