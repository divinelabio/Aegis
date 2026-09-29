import { escapeSectionHtml } from './section-runtime-helpers.js';

export function escapeHTTPSecurityHtml(value: unknown): string {
    return escapeSectionHtml(value);
}

export function formatHTTPSecurityHeaderMap(map: Record<string, unknown> | null | undefined): string {
    if (!map || typeof map !== 'object') return '';
    return Object.entries(map).map(([key, value]) => `${key}: ${value}`).join('\n');
}

export function parseHTTPSecurityHeaderMap(text: string): Record<string, string> {
    const out: Record<string, string> = {};
    text.split('\n').forEach((line) => {
        const idx = line.indexOf(':');
        if (idx <= 0) return;
        const key = line.substring(0, idx).trim();
        const value = line.substring(idx + 1).trim();
        if (key) out[key] = value;
    });
    return out;
}
