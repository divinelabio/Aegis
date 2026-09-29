export function getById(id) {
    const element = document.getElementById(id);
    return element instanceof Element ? element : null;
}
export function resolveElement(target) {
    if (!target)
        return null;
    if (typeof target === 'string') {
        const el = getById(target);
        return el instanceof HTMLElement ? el : null;
    }
    return target instanceof HTMLElement ? target : null;
}
export function query(selector, root = document) {
    const element = root.querySelector(selector);
    return element instanceof Element ? element : null;
}
export function queryAll(selector, root = document) {
    return Array.from(root.querySelectorAll(selector)).filter((element) => element instanceof Element);
}
export function getInput(id) {
    const element = document.getElementById(id);
    return element instanceof HTMLInputElement ? element : null;
}
export function getSelect(id) {
    const element = document.getElementById(id);
    return element instanceof HTMLSelectElement ? element : null;
}
export function getTextarea(id) {
    const element = document.getElementById(id);
    return element instanceof HTMLTextAreaElement ? element : null;
}
export function inputValue(id, fallback = '') {
    return getInput(id)?.value || fallback;
}
export function textareaValue(id, fallback = '') {
    return getTextarea(id)?.value || fallback;
}
export function selectValue(id, fallback = '') {
    return getSelect(id)?.value || fallback;
}
export function checkboxValue(id, fallback = false) {
    const input = getInput(id);
    return input ? input.checked : fallback;
}
export function numberValue(id, fallback = 0) {
    const parsed = Number.parseInt(inputValue(id), 10);
    return Number.isFinite(parsed) ? parsed : fallback;
}
export function firstFile(id) {
    return getInput(id)?.files?.[0] || null;
}
export function focusById(id) {
    getById(id)?.focus();
}
