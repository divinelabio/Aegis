import { escapeSectionAttr, parseSectionCSVList } from './section-runtime-helpers.js';
export function escapeWafHtml(value) {
    return escapeSectionAttr(value);
}
export function parseWafCSVList(raw) {
    return parseSectionCSVList(raw);
}
