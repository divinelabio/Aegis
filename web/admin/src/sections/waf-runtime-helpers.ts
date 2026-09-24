import { escapeSectionAttr, parseSectionCSVList } from './section-runtime-helpers.js';

export function escapeWafHtml(value: unknown): string {
    return escapeSectionAttr(value);
}

export function parseWafCSVList(raw: string | undefined): string[] {
    return parseSectionCSVList(raw);
}
