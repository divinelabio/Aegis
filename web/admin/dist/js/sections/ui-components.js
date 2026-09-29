/**
 * Shared UI Components for Section Configuration Pages
 * Source of truth: web/admin/src/sections/ui-components.ts
 * Runtime output: web/admin/dist/js/sections/ui-components.js
 */
/// <reference path="../types/globals.d.ts" />
import { queryAll, resolveElement } from '../core/dom.js';
import { escapeSectionAttr } from './section-runtime-helpers.js';
import { showSectionToast } from './section-toast-helpers.js';
let sectionUIEventsBound = false;
let pendingActionMenuTrigger = null;
const modalFocusableSelector = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
const actionMenuSelector = '[data-section-action-menu]';
const actionMenuTriggerSelector = '[data-section-action-menu-toggle]';
function actionMenuItems(menu) {
    return Array.from(menu.querySelectorAll('[role="menuitem"]:not([disabled])'));
}
function closeActionMenus(except, restoreFocus = false) {
    queryAll(actionMenuSelector).forEach(menu => {
        if (menu === except || menu.hidden)
            return;
        menu.hidden = true;
        const trigger = document.querySelector(`${actionMenuTriggerSelector}[aria-controls="${escapeSectionAttr(menu.id)}"]`);
        trigger?.setAttribute('aria-expanded', 'false');
        if (restoreFocus)
            trigger?.focus();
    });
}
function positionActionMenu(trigger, menu) {
    const gap = 6;
    const viewportPadding = 8;
    const triggerRect = trigger.getBoundingClientRect();
    menu.style.position = 'fixed';
    menu.style.inset = 'auto';
    menu.style.visibility = 'hidden';
    const menuRect = menu.getBoundingClientRect();
    const left = Math.min(Math.max(viewportPadding, triggerRect.right - menuRect.width), Math.max(viewportPadding, window.innerWidth - menuRect.width - viewportPadding));
    const below = triggerRect.bottom + gap;
    const above = triggerRect.top - menuRect.height - gap;
    const top = below + menuRect.height <= window.innerHeight - viewportPadding || above < viewportPadding
        ? below
        : above;
    menu.style.left = `${Math.round(left)}px`;
    menu.style.top = `${Math.round(Math.max(viewportPadding, top))}px`;
    menu.style.visibility = '';
}
function openActionMenu(trigger, focusFirst = false) {
    const menuID = trigger.getAttribute('aria-controls');
    if (!menuID)
        return;
    const menu = document.getElementById(menuID);
    if (!(menu instanceof HTMLElement))
        return;
    closeActionMenus(menu);
    menu.hidden = false;
    positionActionMenu(trigger, menu);
    trigger.setAttribute('aria-expanded', 'true');
    if (focusFirst)
        actionMenuItems(menu)[0]?.focus();
}
function modalFocusableElements(panel) {
    return Array.from(panel.querySelectorAll(modalFocusableSelector)).filter(element => !element.hasAttribute('hidden') && element.getClientRects().length > 0);
}
function setSaveActionBarDirty(actionAttr, dirty) {
    const selector = actionAttr
        ? `.operator-sticky-actions[data-save-action-attr="${escapeSectionAttr(actionAttr)}"]`
        : '.operator-sticky-actions[data-save-action-bar="true"]';
    queryAll(selector).forEach(bar => {
        bar.classList.toggle('is-hidden', !dirty);
        bar.toggleAttribute('data-dirty', dirty);
        bar.setAttribute('aria-hidden', dirty ? 'false' : 'true');
    });
}
function markSaveActionBarDirty(actionAttr) {
    setSaveActionBarDirty(actionAttr, true);
}
function markSaveActionBarClean(actionAttr) {
    setSaveActionBarDirty(actionAttr || null, false);
}
function getWindowObject(path) {
    const root = window;
    const value = path.split('.').reduce((acc, key) => {
        if (!acc || typeof acc !== 'object')
            return null;
        return acc[key];
    }, root);
    return value && typeof value === 'object' ? value : null;
}
function runWindowAction(expression) {
    if (!expression.trim())
        return;
    try {
        new Function('window', `with(window){ ${expression}; }`)(window);
    }
    catch (error) {
        console.error('SectionUI action failed:', error);
    }
}
function bindSectionUIEvents() {
    if (sectionUIEventsBound)
        return;
    sectionUIEventsBound = true;
    document.addEventListener('change', event => {
        const target = event.target;
        if (!(target instanceof HTMLInputElement))
            return;
        if (target.dataset.sectionValueType !== 'checkbox')
            return;
        const configName = target.dataset.sectionConfigName;
        const field = target.dataset.sectionField;
        if (!configName || !field)
            return;
        const config = getWindowObject(configName);
        const updateField = config?.updateField;
        let didUpdate = false;
        if (typeof updateField === 'function') {
            updateField.call(config, field, target.checked);
            didUpdate = true;
        }
        const render = config?.render;
        if (typeof render === 'function') {
            render.call(config);
        }
        if (didUpdate) {
            markSaveActionBarDirty('data-section-action');
        }
    });
    document.addEventListener('click', event => {
        if (!(event.target instanceof Element))
            return;
        const actionMenuTrigger = event.target.closest(actionMenuTriggerSelector);
        if (actionMenuTrigger) {
            const menuID = actionMenuTrigger.getAttribute('aria-controls');
            const menu = menuID ? document.getElementById(menuID) : null;
            const shouldOpen = menu instanceof HTMLElement && menu.hidden;
            closeActionMenus();
            if (shouldOpen) {
                pendingActionMenuTrigger = actionMenuTrigger;
                window.requestAnimationFrame(() => {
                    if (pendingActionMenuTrigger !== actionMenuTrigger || !actionMenuTrigger.isConnected)
                        return;
                    pendingActionMenuTrigger = null;
                    openActionMenu(actionMenuTrigger);
                });
            }
            return;
        }
        const actionMenuItem = event.target.closest('[role="menuitem"]');
        if (actionMenuItem) {
            pendingActionMenuTrigger = null;
            closeActionMenus();
        }
        else if (!event.target.closest('.operator-action-menu')) {
            pendingActionMenuTrigger = null;
            closeActionMenus();
        }
        const target = event.target.closest('[data-section-action]');
        if (!target)
            return;
        const action = target.dataset.sectionAction || '';
        if (action === 'close-on-backdrop') {
            if (event.target === target)
                SectionUI.closeModal();
            return;
        }
        if (action === 'close-modal') {
            SectionUI.closeModal();
            return;
        }
        if (action === 'save-config') {
            const configName = target.dataset.sectionConfigName;
            if (!configName)
                return;
            const config = getWindowObject(configName);
            const saveConfig = config?.saveConfig;
            if (typeof saveConfig === 'function') {
                void Promise.resolve(saveConfig.call(config)).finally(() => {
                    markSaveActionBarClean('data-section-action');
                });
            }
            return;
        }
        if (action === 'reset-config') {
            const configName = target.dataset.sectionConfigName;
            if (!configName)
                return;
            const config = getWindowObject(configName);
            const resetConfig = config?.resetConfig;
            const loadConfig = config?.loadConfig;
            const render = config?.render;
            const resetResult = typeof resetConfig === 'function'
                ? resetConfig.call(config)
                : typeof loadConfig === 'function'
                    ? loadConfig.call(config)
                    : undefined;
            void Promise.resolve(resetResult).then(() => {
                if (typeof render === 'function') {
                    render.call(config);
                }
                markSaveActionBarClean('data-section-action');
            });
            return;
        }
        if (action === 'run-expression') {
            const expression = target.dataset.sectionExpression || '';
            runWindowAction(expression);
        }
    });
    document.addEventListener('keydown', event => {
        if (!(event.target instanceof HTMLElement))
            return;
        const trigger = event.target.closest(actionMenuTriggerSelector);
        if (trigger && event.key === 'ArrowDown') {
            event.preventDefault();
            openActionMenu(trigger, true);
            return;
        }
        const menu = event.target.closest(actionMenuSelector);
        if (!menu)
            return;
        const items = actionMenuItems(menu);
        const index = items.indexOf(event.target);
        if (event.key === 'Escape') {
            event.preventDefault();
            pendingActionMenuTrigger = null;
            closeActionMenus(null, true);
            return;
        }
        if (!items.length || !['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key))
            return;
        event.preventDefault();
        const nextIndex = event.key === 'Home'
            ? 0
            : event.key === 'End'
                ? items.length - 1
                : event.key === 'ArrowDown'
                    ? (index + 1) % items.length
                    : (index - 1 + items.length) % items.length;
        items[nextIndex]?.focus();
    });
    window.addEventListener('resize', () => {
        pendingActionMenuTrigger = null;
        closeActionMenus();
    });
    document.addEventListener('scroll', () => closeActionMenus(), true);
}
export const SectionUI = {
    icons: {
        shield: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        shieldCheck: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3v8z"/><path d="m9 12 2 2 4-4"/></svg>',
        activity: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
        radar: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
        globe: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
        route: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="19" r="3"/><circle cx="18" cy="5" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7H6.5a3.5 3.5 0 0 1 0-7H15"/></svg>',
        users: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
        userCheck: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><path d="m17 11 2 2 4-4"/></svg>',
        unlock: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>',
        ban: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 14.14 14.14"/></svg>',
        asterisk: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 6v12"/><path d="m17.2 9-10.4 6"/><path d="m6.8 9 10.4 6"/></svg>',
        key: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>',
        list: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>',
        tag: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>',
        puzzle: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19.439 7.85c-.049.322.059.648.289.878l1.568 1.568c.47.47.706 1.087.706 1.704s-.235 1.233-.706 1.704l-1.611 1.611a.98.98 0 0 1-.837.276c-.47-.07-.802-.48-.968-.925a2.501 2.501 0 1 0-3.214 3.214c.446.166.855.497.925.968a.979.979 0 0 1-.276.837l-1.61 1.61a2.404 2.404 0 0 1-1.705.707 2.402 2.402 0 0 1-1.704-.706l-1.568-1.568a1.026 1.026 0 0 0-.878-.29c-.493.074-.84.504-1.017.968a2.5 2.5 0 1 1-3.214-3.214c.464-.177.894-.524.967-1.017a1.026 1.026 0 0 0-.289-.878l-1.568-1.568A2.402 2.402 0 0 1 1.998 12c0-.617.236-1.234.706-1.704L4.315 8.68c.24-.239.4-.59.353-.984-.052-.436-.406-.80-.87-.996a2.5 2.5 0 1 1 3.173-3.173c.196.465.56.818.996.87.395.048.745-.114.984-.353l1.61-1.61a2.403 2.403 0 0 1 1.704-.706A2.4 2.4 0 0 1 13.97 2.44l1.57 1.57c.231.229.557.337.879.288.436-.052.8-.406.996-.87a2.5 2.5 0 1 1 3.173 3.173c-.464.196-.818.56-.87.996-.049.395.114.746.353.984l.002.002-.632.63"/></svg>',
        bot: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/></svg>',
        alertCircle: '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
        clock: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
        settings: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
        file: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>',
        sliders: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>',
        alertTriangle: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        check: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
        search: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
        book: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>',
        x: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
        arrowRight: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>',
        pause: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>',
        eye: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
        info: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        chevronDown: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>',
        trash: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
        edit: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>',
        folder: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>',
        filter: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>',
        fileText: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
        upload: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
        database: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3"/></svg>'
    },
    modalKeyHandler: null,
    modalFocusReturnTarget: null,
    renderModuleHeader(icon, title, desc, toggleField, enabled, configName) {
        bindSectionUIEvents();
        const iconSvg = this.icons[icon] || this.icons.shield;
        const hasToggle = toggleField !== null;
        const accentClass = enabled || !hasToggle ? 'card-accent-primary' : 'card-accent-muted';
        const iconClass = enabled || !hasToggle ? 'hero-icon hero-icon-primary' : 'hero-icon';
        const statusClass = enabled ? 'text-success' : 'text-note';
        return `
        <div class="card section-hero-pattern card-hero ${accentClass}">
            <div class="hero-header">
                <div class="flex align-center gap-16">
                    <div class="${iconClass}">
                        ${iconSvg}
                    </div>
                    <div>
                        <h4 class="hero-title">${title}</h4>
                        <p class="hero-desc">${desc}</p>
                    </div>
                </div>
                ${hasToggle ? `
                <div class="flex align-center gap-12">
                    <span class="hero-status ${statusClass}">${enabled ? 'Active' : 'Disabled'}</span>
                    ${this.renderSwitch({
            checked: enabled,
            attrs: `data-section-value-type="checkbox" data-section-config-name="${configName}" data-section-field="${toggleField}"`
        })}
                </div>
                ` : ''}
            </div>
        </div>`;
    },
    renderSwitch(options) {
        const isChecked = options.checked ? 'checked' : '';
        const idAttr = options.id ? `id="${options.id}"` : '';
        const cleanClass = (options.className || '')
            .split(/\s+/)
            .filter(c => c && c !== 'section-switch-module' && c !== 'section-switch')
            .join(' ');
        const extraClass = cleanClass ? ` ${cleanClass}` : '';
        if (options.label) {
            const labelIdAttr = options.labelId ? `id="${options.labelId}"` : '';
            return `
        <label class="settings-toggle">
            <div class="section-switch${extraClass}" style="display:inline-block; vertical-align:middle;">
                <input type="checkbox" ${idAttr} ${isChecked} ${options.attrs || ''}>
                <span class="switch-slider"></span>
            </div>
            <span class="toggle-label" ${labelIdAttr}>${options.label}</span>
        </label>
      `;
        }
        return `
      <label class="section-switch${extraClass}">
          <input type="checkbox" ${idAttr} ${isChecked} ${options.attrs || ''}>
          <span class="switch-slider"></span>
      </label>
    `;
    },
    renderStatCard(label, value, color) {
        const formattedValue = typeof value === 'number' ? (value >= 1000 ? `${(value / 1000).toFixed(1)}k` : value.toString()) : value;
        return `
            <div class="stat-card accent-${color}">
                <div class="stat-value">${formattedValue}</div>
                <div class="stat-label">${label}</div>
            </div>
        `;
    },
    renderSaveButton(configName) {
        bindSectionUIEvents();
        const escapedConfigName = escapeSectionAttr(configName);
        return this.renderSaveActionBar({
            actionAttr: 'data-section-action',
            resetAction: 'reset-config',
            saveAction: 'save-config',
            resetAttrs: `data-section-config-name="${escapedConfigName}"`,
            saveAttrs: `data-section-config-name="${escapedConfigName}"`
        });
    },
    renderSaveActionBar(options) {
        bindSectionUIEvents();
        const resetLabel = options.resetLabel || 'Reset';
        const saveLabel = options.saveLabel || 'Save Changes';
        const className = options.className ? ` ${options.className}` : '';
        const escapedActionAttr = escapeSectionAttr(options.actionAttr);
        const resetAttrs = options.resetAttrs ? ` ${options.resetAttrs}` : '';
        const saveAttrs = options.saveAttrs ? ` ${options.saveAttrs}` : '';
        return `
            <div class="operator-sticky-actions${className} is-hidden" data-save-action-bar="true" data-save-action-attr="${escapedActionAttr}" aria-hidden="true">
                <div class="section-save-actions">
                    <button type="button" class="operator-btn operator-btn-secondary" ${options.actionAttr}="${options.resetAction}"${resetAttrs}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"></polyline><path d="M3.51 15a9 9 0 1 0 .49-9"></path></svg>
                        ${resetLabel}
                    </button>
                    <button type="button" class="operator-btn operator-btn-primary" ${options.actionAttr}="${options.saveAction}"${saveAttrs}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg>
                        ${saveLabel}
                    </button>
                </div>
            </div>
        `;
    },
    markSaveActionBarDirty(actionAttr) {
        markSaveActionBarDirty(actionAttr);
    },
    markSaveActionBarClean(actionAttr) {
        markSaveActionBarClean(actionAttr);
    },
    renderLoading(message = 'Loading configuration...') {
        return `
            <div class="section-loading">
                <div class="spinner"></div>
                <p class="mt-16">${message}</p>
            </div>
        `;
    },
    renderError(message, retryFunc) {
        bindSectionUIEvents();
        const retryExpression = escapeSectionAttr(retryFunc);
        return `
            <div class="section-error">
                <div class="error-icon">${this.icons.alertCircle}</div>
                <div class="error-message">${message}</div>
                <button type="button" class="btn btn-outline" data-section-action="run-expression" data-section-expression="${retryExpression}">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                    Retry
                </button>
            </div>
        `;
    },
    showToast(message, type = 'info') {
        showSectionToast(message, type);
    },
    getElement(target) {
        return resolveElement(target);
    },
    setHidden(target, hidden = true) {
        const element = this.getElement(target);
        if (!element)
            return null;
        element.classList.toggle('hidden', hidden);
        return element;
    },
    toggleHidden(target) {
        const element = this.getElement(target);
        if (!element)
            return false;
        const nextHidden = !element.classList.contains('hidden');
        this.setHidden(element, nextHidden);
        return !nextHidden;
    },
    setOpen(target, isOpen = true, options = {}) {
        const { openClass = 'is-open', hiddenClass = 'hidden', expandedTarget = null } = options;
        const element = this.getElement(target);
        if (!element)
            return null;
        element.classList.toggle(openClass, isOpen);
        if (hiddenClass) {
            element.classList.toggle(hiddenClass, !isOpen);
        }
        const expandedElement = this.getElement(expandedTarget || target);
        if (expandedElement) {
            expandedElement.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        }
        return element;
    },
    closeAll(selector, exceptId = null, options = {}) {
        const { openClass = 'is-open', hiddenClass = 'hidden' } = options;
        queryAll(selector).forEach(element => {
            if (exceptId && element.id === exceptId)
                return;
            element.classList.remove(openClass);
            if (hiddenClass) {
                element.classList.add(hiddenClass);
            }
        });
    },
    renderPageHeader(title, subtitle = '', actions = '') {
        return `
            <div class="page-header">
                <div class="page-header-copy">
                    <div class="page-title">${title}</div>
                    ${subtitle ? `<div class="page-subtitle text-mono">${subtitle}</div>` : ''}
                </div>
                ${actions ? `<div class="page-actions">${actions}</div>` : ''}
            </div>
        `;
    },
    renderConfigPageHero(title, subtitle = '', kicker = '', actions = '') {
        return `
            <div class="config-page-hero ${actions ? 'config-page-hero-bar' : ''}">
                <div class="config-page-hero-main">
                    ${kicker ? `<div class="config-page-hero-kicker">${kicker}</div>` : ''}
                    <h2 class="config-page-hero-title">${title}</h2>
                    ${subtitle ? `<p class="config-page-hero-subtitle">${subtitle}</p>` : ''}
                </div>
                ${actions ? `<div class="config-page-hero-actions">${actions}</div>` : ''}
            </div>
        `;
    },
    renderConfigConsoleHeader(options) {
        const status = options.status || [];
        return `
            <div class="config-console-header">
                <div class="config-console-heading">
                    <div class="config-console-title-row">
                        <h2 class="config-console-title">${options.title}</h2>
                        ${options.category ? `<span class="config-console-category">${options.category}</span>` : ''}
                    </div>
                    ${options.meta ? `<div class="config-console-meta">${options.meta}</div>` : ''}
                </div>
                <div class="config-console-right">
                    ${status.length ? `<div class="config-console-status">${status.map(item => this.renderStatusPill(item.label, item.tone)).join('')}</div>` : ''}
                    ${options.actions ? `<div class="config-console-actions">${options.actions}</div>` : ''}
                </div>
            </div>
        `;
    },
    renderConfigSectionNav(tabs, activeId, action, actionAttr = 'data-waf-action', valueAttr = 'data-waf-value') {
        return `
            <nav class="config-section-nav" aria-label="Configuration sections">
                ${tabs.map(tab => `
                    <button type="button" class="config-section-nav-item ${tab.id === activeId ? 'is-active' : ''}"
                            ${actionAttr}="${action}" ${valueAttr}="${tab.id}" ${tab.id === activeId ? 'aria-current="page"' : ''}>
                        ${tab.name}
                    </button>
                `).join('')}
            </nav>
        `;
    },
    renderMetricStrip(metrics) {
        return `
            <div class="config-metric-strip">
                ${metrics.map(metric => `
                    <div class="config-metric-item tone-${metric.tone || 'neutral'}">
                        <div class="config-metric-value">${metric.value}</div>
                        <div class="config-metric-label">${metric.label}</div>
                    </div>
                `).join('')}
            </div>
        `;
    },
    renderOperatorFrame(options) {
        const tabs = options.tabs || [];
        const status = options.status || [];
        const className = options.className || '';
        const tabNav = tabs.length
            ? this.renderLineTabs(tabs, options.activeTab || tabs[0].id, {
                action: options.tabAction || 'switch-tab',
                actionAttr: options.tabActionAttr,
                valueAttr: options.tabValueAttr,
                ariaLabel: `${options.title} sections`
            })
            : '';
        return `
            <section class="operator-frame ${className}">
                <header class="operator-frame-header">
                    <div class="operator-frame-title-block">
                        ${options.kicker ? `<div class="operator-frame-kicker">${options.kicker}</div>` : ''}
                        <h2 class="operator-frame-title">${options.title}</h2>
                        ${options.subtitle ? `<p class="operator-frame-subtitle">${options.subtitle}</p>` : ''}
                    </div>
                    <div class="operator-frame-meta">
                        ${status.length ? `<div class="operator-frame-status">${status.map(item => this.renderStatusPill(item.label, item.tone)).join('')}</div>` : ''}
                        ${options.actions ? `<div class="operator-frame-actions">${options.actions}</div>` : ''}
                    </div>
                </header>
                ${tabNav}
                <div class="operator-frame-body">
                    ${options.content}
                </div>
            </section>
        `;
    },
    renderResourceWorkspace(options) {
        bindSectionUIEvents();
        const tabs = options.tabs || [];
        const tabNav = tabs.length
            ? this.renderLineTabs(tabs, options.activeTab || tabs[0].id, {
                action: options.tabAction || 'switch-tab',
                actionAttr: options.tabActionAttr,
                valueAttr: options.tabValueAttr,
                ariaLabel: `${options.title} sections`
            })
            : '';
        return `
            <section class="operator-resource-workspace ${tabs.length ? '' : 'operator-resource-workspace--no-tabs'} ${options.className || ''}">
                <nav class="operator-resource-breadcrumbs" aria-label="Breadcrumb">
                    <button type="button" class="operator-resource-breadcrumb-link" ${options.breadcrumbAttrs}>${options.breadcrumbLabel}</button>
                    <span class="operator-resource-breadcrumb-separator" aria-hidden="true">/</span>
                    <span aria-current="page">${options.breadcrumbCurrent}</span>
                </nav>
                <header class="operator-resource-header">
                    <div class="operator-resource-title-block">
                        <div class="operator-resource-title-line">
                            <h2>${options.title}</h2>
                            ${options.status || ''}
                        </div>
                        ${options.metadata ? `<div class="operator-resource-metadata">${options.metadata}</div>` : ''}
                    </div>
                    ${options.actions ? `<div class="operator-resource-actions">${options.actions}</div>` : ''}
                </header>
                ${tabNav ? `<div class="operator-resource-tabs">${tabNav}</div>` : ''}
                <div class="operator-resource-body">
                    ${options.content}
                </div>
            </section>
        `;
    },
    renderLineTabs(tabs, activeId, options) {
        const actionAttr = options.actionAttr || 'data-section-action';
        const valueAttr = options.valueAttr || 'data-section-value';
        const ariaLabel = options.ariaLabel || 'Sections';
        return `
            <nav class="operator-line-tabs" data-scrollable-tabs="true" aria-label="${ariaLabel}">
                ${tabs.map(tab => `
                    <button type="button" class="operator-line-tab ${tab.id === activeId ? 'is-active' : ''}"
                            ${actionAttr}="${options.action}" ${valueAttr}="${tab.id}"${tab.id === activeId ? ' aria-current="page"' : ''}>
                        ${tab.icon ? `<span class="operator-line-tab-icon">${tab.icon}</span>` : ''}
                        <span>${tab.name}</span>
                    </button>
                `).join('')}
                <span class="operator-line-tabs-scroll-hint" aria-hidden="true">&#8594;</span>
            </nav>
        `;
    },
    renderOperatorMetricStrip(metrics, className = '') {
        return `
            <div class="operator-metric-strip ${className}">
                ${metrics.map(metric => `
                    <div class="operator-metric-item tone-${metric.tone || 'neutral'}">
                        <div class="operator-metric-label">${metric.label}</div>
                        <div class="operator-metric-value">${metric.value}</div>
                        ${metric.sub ? `<div class="operator-metric-sub">${metric.sub}</div>` : ''}
                    </div>
                `).join('')}
            </div>
        `;
    },
    renderOperatorBackButton(options) {
        const className = options.className ? ` ${escapeSectionAttr(options.className)}` : '';
        const label = escapeSectionAttr(options.label);
        const ariaLabel = escapeSectionAttr(options.ariaLabel || options.label);
        return `
            <button type="button" class="operator-back-button${className}" ${options.attrs} aria-label="${ariaLabel}">
                <span class="operator-back-button-icon" aria-hidden="true">${this.icons.arrowRight}</span>
                <span class="operator-back-button-label">${label}</span>
            </button>
        `;
    },
    renderOperatorSection(title, content, options = {}) {
        return `
            <section class="operator-section ${options.className || ''}">
                <div class="operator-section-head">
                    <div>
                        <h3>${title}</h3>
                        ${options.subtitle ? `<p>${options.subtitle}</p>` : ''}
                    </div>
                    ${options.actions ? `<div class="operator-section-actions">${options.actions}</div>` : ''}
                </div>
                <div class="operator-section-body">
                    ${content}
                </div>
            </section>
        `;
    },
    renderOperatorControlRow(options) {
        const requestedHeadingLevel = Number(options.titleHeadingLevel);
        const isTitleHeading = Number.isInteger(requestedHeadingLevel) && requestedHeadingLevel >= 2 && requestedHeadingLevel <= 6;
        const titleTag = isTitleHeading ? `h${requestedHeadingLevel}` : 'span';
        const titleClass = `operator-control-title${isTitleHeading ? ' operator-control-title--heading' : ''}`;
        return `
            <div class="operator-control-row ${options.enabled ? 'is-active' : ''} ${options.className || ''}" ${options.attrs || ''}>
                <div class="operator-control-main">
                    ${options.icon ? `<span class="operator-control-icon">${options.icon}</span>` : ''}
                    <div class="operator-control-copy">
                        <${titleTag} class="${titleClass}">${options.title}</${titleTag}>
                        ${options.description ? `<span class="operator-control-desc">${options.description}</span>` : ''}
                    </div>
                </div>
                ${options.actions ? `<div class="operator-control-actions">${options.actions}</div>` : ''}
                ${options.content ? `<div class="operator-control-content">${options.content}</div>` : ''}
            </div>
        `;
    },
    renderStickyActionBar(content, className = '') {
        return `<div class="operator-sticky-actions ${className}">${content}</div>`;
    },
    renderConfigPanel(title, content, options = {}) {
        const className = options.className || '';
        return `
            <section class="config-panel ${className}">
                <div class="config-panel-head">
                    <h3 class="config-panel-title">${title}</h3>
                    ${options.actions ? `<div class="config-panel-actions">${options.actions}</div>` : ''}
                </div>
                <div class="config-panel-body">
                    ${content}
                </div>
            </section>
        `;
    },
    renderStatusPill(label, tone = 'neutral') {
        return `<span class="config-status-pill tone-${tone}">${label}</span>`;
    },
    renderActionMenu(options) {
        bindSectionUIEvents();
        const className = options.className ? ` ${options.className}` : '';
        return `
            <div class="operator-action-menu${className}">
                <button type="button" class="btn btn-outline btn-sm operator-action-menu-trigger"
                        data-section-action-menu-toggle="${escapeSectionAttr(options.id)}"
                        aria-controls="${escapeSectionAttr(options.id)}"
                        aria-expanded="false"
                        aria-haspopup="menu"
                        aria-label="${escapeSectionAttr(options.ariaLabel)}">
                    <span>${options.label || 'Actions'}</span>
                    ${this.icons.chevronDown}
                </button>
                <div id="${escapeSectionAttr(options.id)}" class="operator-action-menu-panel" data-section-action-menu role="menu" hidden>
                    ${options.items.map(item => `
                        <button type="button" class="operator-action-menu-item${item.tone === 'danger' ? ' is-danger' : ''}"
                                role="menuitem" ${item.attrs}${item.disabled ? ' disabled' : ''}>${item.label}</button>
                    `).join('')}
                </div>
            </div>
        `;
    },
    renderEnterpriseTable(options) {
        const empty = `
        <tr>
            <td colspan="${options.columns.length}" class="config-table-empty-cell">
                ${this.renderEmptyState(options.emptyTitle || 'No records', options.emptyMessage || 'Nothing to show yet.', 'info', options.emptyAction || '')}
            </td>
        </tr>`;
        return `
            <div class="config-table-wrap ${options.className || ''}">
                <table class="config-enterprise-table">
                    <thead>
                        <tr>${options.columns.map(column => `<th>${column}</th>`).join('')}</tr>
                    </thead>
                    <tbody>
                        ${options.rows.length ? options.rows.map(row => `<tr>${row.map(cell => `<td>${cell}</td>`).join('')}</tr>`).join('') : empty}
                    </tbody>
                </table>
            </div>
        `;
    },
    renderTableScrollHint() {
        return `<p class="operator-table-scroll-hint"><span aria-hidden="true">&harr;</span>Swipe horizontally to view all columns</p>`;
    },
    renderInfoTooltip(text, options = {}) {
        const placementClass = options.placement ? ` is-${options.placement}` : '';
        const extraClass = options.className ? ` ${options.className}` : '';
        const safeText = escapeSectionAttr(text);
        return `<span class="operator-info-tooltip${placementClass}${extraClass}" data-tooltip="${safeText}" tabindex="0" role="tooltip" aria-label="${safeText}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg></span>`;
    },
    renderEmptyState(title, message, icon = 'info', action = '') {
        const iconSvg = this.icons[icon] || this.icons.info || '';
        return `
            <div class="empty-state">
                <div class="empty-state-icon">${iconSvg}</div>
                <h3>${title}</h3>
                <p>${message}</p>
                ${action || ''}
            </div>
        `;
    },
    showModal(content, options = {}) {
        bindSectionUIEvents();
        const { panelClass = 'modal-content', overlayClass = 'modal-overlay', closeOnBackdrop = true } = options;
        let container = this.getElement('modal-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'modal-container';
            document.body.appendChild(container);
        }
        if (this.modalKeyHandler) {
            document.removeEventListener('keydown', this.modalKeyHandler);
            this.modalKeyHandler = null;
        }
        const activeElement = document.activeElement;
        if (activeElement instanceof HTMLElement && !container.contains(activeElement))
            this.modalFocusReturnTarget = activeElement;
        container.innerHTML = `
            <div class="${overlayClass}" ${closeOnBackdrop ? 'data-section-action="close-on-backdrop"' : ''}>
                <div class="${panelClass}" role="dialog" aria-modal="true" tabindex="-1">
                    ${content}
                </div>
            </div>
            `;
        const panel = container.firstElementChild?.firstElementChild;
        if (!(panel instanceof HTMLElement))
            return;
        const title = panel.querySelector('h1, h2, h3, h4, h5, h6');
        if (title) {
            if (!title.id)
                title.id = 'section-modal-title';
            panel.setAttribute('aria-labelledby', title.id);
        }
        else
            panel.setAttribute('aria-label', 'Dialog');
        this.modalKeyHandler = (event) => {
            if (event.key === 'Escape') {
                this.closeModal();
                return;
            }
            if (event.key !== 'Tab')
                return;
            const focusable = modalFocusableElements(panel);
            if (!focusable.length) {
                event.preventDefault();
                panel.focus();
                return;
            }
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (event.shiftKey && (document.activeElement === first || document.activeElement === panel)) {
                event.preventDefault();
                last.focus();
            }
            else if (!event.shiftKey && (document.activeElement === last || document.activeElement === panel)) {
                event.preventDefault();
                first.focus();
            }
        };
        document.addEventListener('keydown', this.modalKeyHandler);
        window.setTimeout(() => {
            if (!container?.isConnected || !panel.isConnected)
                return;
            (modalFocusableElements(panel)[0] || panel).focus();
        }, 0);
    },
    closeModal() {
        const container = this.getElement('modal-container');
        if (container)
            container.innerHTML = '';
        if (this.modalKeyHandler) {
            document.removeEventListener('keydown', this.modalKeyHandler);
            this.modalKeyHandler = null;
        }
        const returnTarget = this.modalFocusReturnTarget;
        this.modalFocusReturnTarget = null;
        if (returnTarget?.isConnected)
            returnTarget.focus();
    },
    openConfirmModal(title, message, btnText, btnColor, callback) {
        const confirmBtnId = 'modal-confirm-btn';
        const isDanger = btnColor.includes('danger') || /#?(dc2626|ef4444|b91c1c|991b1b)/i.test(btnColor);
        const confirmStyle = btnColor ? ` style="--section-confirm-accent:${escapeSectionAttr(btnColor)}"` : '';
        this.showModal(`
            <div class="section-confirm-head ${isDanger ? 'is-danger' : ''}"${confirmStyle}>
                <div class="section-confirm-icon">
                    ${isDanger ? this.icons.trash : this.icons.alertTriangle}
                </div>
                <div class="section-confirm-title-block">
                    <h3 class="section-confirm-title">${title}</h3>
                    <p class="section-confirm-sub">${isDanger ? 'This action requires confirmation.' : 'Review this action before continuing.'}</p>
                </div>
                <button type="button" class="section-confirm-close" data-section-action="close-modal" aria-label="Close dialog">${this.icons.x}</button>
            </div>
            <div class="section-confirm-body">
                <div class="section-confirm-message">${message}</div>
            </div>
            <div class="section-confirm-footer">
                <button type="button" class="btn btn-outline section-confirm-cancel" data-section-action="close-modal">Cancel</button>
                <button type="button" id="${confirmBtnId}" class="btn btn-primary section-confirm-primary ${isDanger ? 'is-danger' : ''}"${confirmStyle}>${btnText}</button>
            </div>
        `, { panelClass: 'modal-content section-confirm-modal', closeOnBackdrop: true });
        const confirmButton = this.getElement(confirmBtnId);
        if (!confirmButton)
            return;
        if (typeof callback === 'function') {
            confirmButton.addEventListener('click', () => {
                confirmButton.setAttribute('disabled', 'true');
                void Promise.resolve(callback()).finally(() => {
                    confirmButton.removeAttribute('disabled');
                });
            });
        }
        else if (typeof callback === 'string') {
            confirmButton.addEventListener('click', () => {
                runWindowAction(`${callback}()`);
            });
        }
    }
};
